// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Encrypted Secrets Module
//!
//! Provides secure secret management with support for multiple providers:
//! - AWS KMS (Key Management Service)
//! - HashiCorp Vault
//! - 1Password CLI
//! - Local encrypted files (AES-256-GCM)
//!
//! Secrets are never stored in memory longer than necessary and are
//! securely zeroed when freed.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const secret = @import("secret.zig");

// ============================================================================
// Sensitive String Type (#50 - Credential Wrapper)
// ============================================================================

/// A wrapper type for sensitive strings (credentials, tokens, keys).
/// Provides protection against accidental exposure through:
/// - Custom format function that redacts content
/// - Secure zeroing on deinitialization
/// - No direct printing without explicit unwrapping
///
/// Security: Prevents credential exposure in logs (CWE-532)
pub const SensitiveString = struct {
    value: []const u8,
    /// Whether this instance owns the memory and should zero/free it
    owned: bool = false,
    allocator: ?Allocator = null,

    const Self = @This();

    /// Create a non-owning reference to a sensitive string
    pub fn init(value: []const u8) Self {
        return .{ .value = value, .owned = false, .allocator = null };
    }

    /// Create an owned copy of a sensitive string
    pub fn initOwned(allocator: Allocator, value: []const u8) !Self {
        const copy = try allocator.dupe(u8, value);
        return .{ .value = copy, .owned = true, .allocator = allocator };
    }

    /// Securely clear and free the memory if owned
    pub fn deinit(self: *Self) void {
        if (self.owned) {
            if (self.allocator) |alloc| {
                // Secure zero before freeing
                const mutable = @constCast(self.value);
                secret.secureZero(mutable);
                alloc.free(mutable);
            }
        }
        self.value = "";
        self.owned = false;
    }

    /// Get the raw value (use with caution)
    /// Only use when actually needed to send to external systems
    pub fn expose(self: Self) []const u8 {
        return self.value;
    }

    /// Custom format function - always redacts
    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = self;
        _ = fmt;
        _ = options;
        try writer.writeAll("***REDACTED***");
    }

    /// Check if the value is set (non-empty)
    pub fn isSet(self: Self) bool {
        return self.value.len > 0;
    }

    /// Get length without exposing content
    pub fn len(self: Self) usize {
        return self.value.len;
    }
};

// ============================================================================
// Security Validation Functions
// ============================================================================

/// Validate a path/item name for use in CLI commands.
/// Only allows safe characters to prevent command injection (CWE-78).
/// Safe characters: alphanumeric, underscore, hyphen, dot, forward slash
pub fn isValidSecretIdentifier(input: []const u8) bool {
    if (input.len == 0) return false;

    for (input) |c| {
        const is_safe = std.ascii.isAlphanumeric(c) or
            c == '_' or
            c == '-' or
            c == '.' or
            c == '/';
        if (!is_safe) return false;
    }

    // Additionally reject path traversal
    if (mem.indexOf(u8, input, "..") != null) return false;

    return true;
}

/// Validate a path component does not contain traversal sequences (CWE-22).
pub fn isPathSafe(path: []const u8) bool {
    return secret.isPathSafe(path);
}

/// Allowlist of valid op binary paths (CWE-78, #66)
/// Security: Prevents arbitrary binary execution via op_path configuration
const op_path_allowlist = [_][]const u8{
    "op", // Default - uses PATH lookup
    "/usr/bin/op",
    "/usr/local/bin/op",
    "/opt/1password/op",
    "/opt/1password-cli/op",
    "/home/linuxbrew/.linuxbrew/bin/op",
    "/snap/bin/op",
};

/// Validate the 1Password CLI binary path against an allowlist (CWE-78, #66).
/// Security: Prevents arbitrary binary execution by restricting op_path to known safe locations.
/// Returns true if the path is in the allowlist or matches a safe pattern.
pub fn isValidOpPath(path: []const u8) bool {
    if (path.len == 0) return false;

    // Check against explicit allowlist
    for (op_path_allowlist) |allowed| {
        if (mem.eql(u8, path, allowed)) return true;
    }

    // Allow paths in home directories: ~/.local/bin/op or ~/bin/op
    // These must end with /op and not contain traversal
    if (mem.endsWith(u8, path, "/op")) {
        // Reject path traversal
        if (mem.indexOf(u8, path, "..") != null) return false;

        // Allow ~/bin/op or ~/.local/bin/op patterns
        if (mem.startsWith(u8, path, "/home/") or mem.startsWith(u8, path, "/Users/")) {
            // Ensure it's a bin directory
            if (mem.indexOf(u8, path, "/bin/op") != null) {
                return true;
            }
        }
    }

    return false;
}

/// Secret provider types
pub const Provider = enum {
    /// Local file-based secrets (plaintext, for development)
    file,
    /// Local encrypted file (AES-256-GCM)
    encrypted_file,
    /// AWS Key Management Service
    aws_kms,
    /// HashiCorp Vault
    vault,
    /// 1Password CLI (op command)
    onepassword,
    /// Environment variable (not recommended for secrets)
    env,

    pub fn format(self: Provider) []const u8 {
        return switch (self) {
            .file => "file",
            .encrypted_file => "encrypted_file",
            .aws_kms => "aws_kms",
            .vault => "vault",
            .onepassword => "1password",
            .env => "env",
        };
    }
};

/// Error types for secret operations
pub const SecretError = error{
    ProviderNotConfigured,
    ProviderNotAvailable,
    SecretNotFound,
    DecryptionFailed,
    AuthenticationFailed,
    NetworkError,
    InvalidConfiguration,
    CommandFailed,
    OutOfMemory,
    IoError,
    Timeout,
    /// Path traversal attempt detected (security violation, CWE-22)
    PathTraversalDetected,
    /// Invalid characters in input that could enable injection (CWE-78)
    InvalidInputCharacters,
    /// Feature not implemented - use alternative
    FeatureNotImplemented,
};

/// AWS KMS configuration
/// Security: Credential fields use SensitiveString to prevent logging exposure (CWE-532)
pub const KmsConfig = struct {
    /// AWS region (e.g., "us-east-1")
    region: []const u8 = "us-east-1",
    /// KMS key ID or alias (e.g., "alias/my-key")
    key_id: ?[]const u8 = null,
    /// AWS access key ID (optional, uses default credentials if not set)
    /// Security: Uses SensitiveString to prevent accidental logging (#59)
    access_key_id: ?SensitiveString = null,
    /// AWS secret access key (optional)
    /// Security: Uses SensitiveString to prevent accidental logging (#59)
    secret_access_key: ?SensitiveString = null,
    /// AWS session token (optional, for temporary credentials)
    /// Security: Uses SensitiveString to prevent accidental logging (#59)
    session_token: ?SensitiveString = null,
    /// Endpoint override (for testing with LocalStack)
    endpoint: ?[]const u8 = null,

    /// Clean up any owned sensitive strings
    pub fn deinit(self: *KmsConfig) void {
        if (self.access_key_id) |*key| key.deinit();
        if (self.secret_access_key) |*sak| sak.deinit();
        if (self.session_token) |*tok| tok.deinit();
    }
};

/// HashiCorp Vault configuration
/// Security: Token field uses SensitiveString to prevent logging exposure (CWE-532)
pub const VaultConfig = struct {
    /// Vault server address (e.g., "https://vault.example.com:8200")
    /// SECURITY: Defaults to HTTPS. Use HTTP only for local development.
    address: []const u8 = "https://127.0.0.1:8200",
    /// Authentication token (consider using VAULT_TOKEN env var instead)
    /// Security: Uses SensitiveString to prevent accidental logging (#59)
    token: ?SensitiveString = null,
    /// Path prefix for secrets (e.g., "secret/data/myapp")
    path_prefix: []const u8 = "secret/data",
    /// Namespace (for Vault Enterprise)
    namespace: ?[]const u8 = null,
    /// Request timeout in milliseconds
    timeout_ms: u32 = 30000,
    /// Skip TLS verification (INSECURE - for development only)
    tls_skip_verify: bool = false,

    /// Clean up any owned sensitive strings
    pub fn deinit(self: *VaultConfig) void {
        if (self.token) |*t| t.deinit();
    }
};

/// 1Password configuration
/// Security: Token field uses SensitiveString to prevent logging exposure (CWE-532)
pub const OnePasswordConfig = struct {
    /// 1Password account (e.g., "my-team.1password.com")
    account: ?[]const u8 = null,
    /// Vault name (default: "Private")
    vault: []const u8 = "Private",
    /// Service account token (for CI/CD)
    /// Security: Uses SensitiveString to prevent accidental logging (#59)
    service_account_token: ?SensitiveString = null,
    /// Path to op CLI binary
    op_path: []const u8 = "op",

    /// Clean up any owned sensitive strings
    pub fn deinit(self: *OnePasswordConfig) void {
        if (self.service_account_token) |*t| t.deinit();
    }
};

/// Encrypted file configuration
pub const EncryptedFileConfig = struct {
    /// Path to the key file (32 bytes for AES-256)
    key_file: ?[]const u8 = null,
    /// Base directory for encrypted secrets
    base_path: []const u8 = "/etc/secrets",
    /// File extension for encrypted files
    extension: []const u8 = ".enc",
};

/// Secret reference for deferred loading
pub const SecretRef = struct {
    /// Provider to use
    provider: Provider,
    /// Path or identifier for the secret
    path: []const u8,
    /// Optional field within the secret (for structured secrets)
    field: ?[]const u8 = null,
    /// Optional version (for versioned secrets)
    version: ?[]const u8 = null,
};

/// Secret manager for handling encrypted secrets
pub const SecretManager = struct {
    allocator: Allocator,
    kms_config: ?KmsConfig = null,
    vault_config: ?VaultConfig = null,
    onepassword_config: ?OnePasswordConfig = null,
    encrypted_file_config: ?EncryptedFileConfig = null,

    const Self = @This();

    /// Initialize a new secret manager
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Configure AWS KMS provider
    pub fn configureKms(self: *Self, config: KmsConfig) void {
        self.kms_config = config;
    }

    /// Configure HashiCorp Vault provider
    pub fn configureVault(self: *Self, config: VaultConfig) void {
        self.vault_config = config;
    }

    /// Configure 1Password provider
    pub fn configureOnePassword(self: *Self, config: OnePasswordConfig) void {
        self.onepassword_config = config;
    }

    /// Configure encrypted file provider
    pub fn configureEncryptedFile(self: *Self, config: EncryptedFileConfig) void {
        self.encrypted_file_config = config;
    }

    /// Load a secret from a reference
    pub fn loadSecret(self: *Self, ref: SecretRef) SecretError![]u8 {
        return switch (ref.provider) {
            .file => self.loadFromFile(ref.path),
            .encrypted_file => self.loadFromEncryptedFile(ref.path),
            .aws_kms => self.loadFromKms(ref.path),
            .vault => self.loadFromVault(ref.path, ref.field),
            .onepassword => self.loadFromOnePassword(ref.path, ref.field),
            .env => self.loadFromEnv(ref.path),
        };
    }

    /// Load a secret from a file
    fn loadFromFile(self: *Self, path: []const u8) SecretError![]u8 {
        return secret.readFromFile(path, self.allocator) catch {
            return SecretError.SecretNotFound;
        };
    }

    /// Load from encrypted file
    /// SECURITY NOTE: AES-256-GCM encryption is NOT YET IMPLEMENTED.
    /// This function returns FeatureNotImplemented to avoid giving a false
    /// sense of security. Use the `file` provider with proper file permissions
    /// or external encryption tools until this is implemented.
    fn loadFromEncryptedFile(self: *Self, path: []const u8) SecretError![]u8 {
        _ = self;
        _ = path;
        // SECURITY: Return error rather than silently returning unencrypted data.
        // AES-256-GCM implementation requires careful cryptographic review.
        // See: https://gitlab.com/devnw/zig/config/-/issues/47
        return SecretError.FeatureNotImplemented;
    }

    /// Load from AWS KMS
    /// SECURITY NOTE: AWS KMS integration is NOT YET IMPLEMENTED.
    /// This function returns FeatureNotImplemented. Use environment variables
    /// with AWS credentials and the AWS CLI directly, or use Vault with AWS
    /// auth backend until this is implemented.
    fn loadFromKms(self: *Self, secret_id: []const u8) SecretError![]u8 {
        _ = self;
        _ = secret_id;
        // SECURITY: Return clear error rather than misleading ProviderNotAvailable.
        // AWS KMS implementation requires AWS SDK integration.
        // See: https://gitlab.com/devnw/zig/config/-/issues/57
        return SecretError.FeatureNotImplemented;
    }

    /// Load from HashiCorp Vault
    /// Security: Validates path and path_prefix to prevent injection (CWE-78, #67)
    fn loadFromVault(self: *Self, path: []const u8, field: ?[]const u8) SecretError![]u8 {
        const config = self.vault_config orelse return SecretError.ProviderNotConfigured;

        // Security: Validate path_prefix to prevent injection attacks (#67)
        if (!isValidSecretIdentifier(config.path_prefix)) {
            return SecretError.InvalidInputCharacters;
        }

        // Security: Validate path to prevent command injection
        if (!isValidSecretIdentifier(path)) {
            return SecretError.InvalidInputCharacters;
        }
        if (field) |f| {
            if (!isValidSecretIdentifier(f)) {
                return SecretError.InvalidInputCharacters;
            }
        }

        // Build vault CLI command
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        args.append("vault") catch return SecretError.OutOfMemory;
        args.append("kv") catch return SecretError.OutOfMemory;
        args.append("get") catch return SecretError.OutOfMemory;
        args.append("-format=json") catch return SecretError.OutOfMemory;

        const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            config.path_prefix,
            path,
        }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(full_path);
        args.append(full_path) catch return SecretError.OutOfMemory;

        return self.execCommand(args.items, field);
    }

    /// Load from 1Password
    /// Security: Validates item, field, vault, and op_path to prevent injection (CWE-78, #66, #67)
    fn loadFromOnePassword(self: *Self, item: []const u8, field: ?[]const u8) SecretError![]u8 {
        const config = self.onepassword_config orelse return SecretError.ProviderNotConfigured;

        // Security: Validate op_path against allowlist to prevent arbitrary binary execution (#66)
        if (!isValidOpPath(config.op_path)) {
            return SecretError.InvalidInputCharacters;
        }

        // Security: Validate vault name to prevent injection attacks (#67)
        if (!isValidSecretIdentifier(config.vault)) {
            return SecretError.InvalidInputCharacters;
        }

        // Security: Validate item name to prevent command injection
        if (!isValidSecretIdentifier(item)) {
            return SecretError.InvalidInputCharacters;
        }
        if (field) |f| {
            if (!isValidSecretIdentifier(f)) {
                return SecretError.InvalidInputCharacters;
            }
        }

        // Build op CLI command
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        args.append(config.op_path) catch return SecretError.OutOfMemory;
        args.append("read") catch return SecretError.OutOfMemory;

        // Build reference: op://vault/item/field
        const ref = if (field) |f|
            std.fmt.allocPrint(self.allocator, "op://{s}/{s}/{s}", .{ config.vault, item, f }) catch return SecretError.OutOfMemory
        else
            std.fmt.allocPrint(self.allocator, "op://{s}/{s}/password", .{ config.vault, item }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(ref);

        args.append(ref) catch return SecretError.OutOfMemory;

        return self.execCommand(args.items, null);
    }

    /// Load from environment variable (not recommended)
    fn loadFromEnv(self: *Self, name: []const u8) SecretError![]u8 {
        const value = std.posix.getenv(name) orelse return SecretError.SecretNotFound;
        return self.allocator.dupe(u8, value) catch return SecretError.OutOfMemory;
    }

    /// Execute a command and return its output
    fn execCommand(self: *Self, args: []const []const u8, json_field: ?[]const u8) SecretError![]u8 {
        _ = json_field;

        var child = std.process.Child.init(args, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch return SecretError.CommandFailed;

        const stdout = child.stdout orelse return SecretError.CommandFailed;
        const result = stdout.reader().readAllAlloc(self.allocator, 1024 * 1024) catch {
            return SecretError.IoError;
        };

        const term = child.wait() catch return SecretError.CommandFailed;
        if (term.Exited != 0) {
            self.allocator.free(result);
            return SecretError.CommandFailed;
        }

        // Trim trailing newline
        const trimmed = mem.trimRight(u8, result, "\n\r");
        if (trimmed.len < result.len) {
            const final = self.allocator.dupe(u8, trimmed) catch return SecretError.OutOfMemory;
            self.allocator.free(result);
            return final;
        }

        return result;
    }

    /// Parse a secret reference string
    /// Format: provider://path[#field][@version]
    /// Examples:
    ///   file:///etc/secrets/db_password
    ///   vault://secret/myapp/db#password
    ///   1password://Database/PostgreSQL#password
    ///   kms://alias/mykey/encrypted_secret
    pub fn parseRef(ref_str: []const u8) ?SecretRef {
        // Find provider separator
        const sep_idx = mem.indexOf(u8, ref_str, "://") orelse return null;
        const provider_str = ref_str[0..sep_idx];
        var rest = ref_str[sep_idx + 3 ..];

        // Parse provider
        const provider: Provider = if (mem.eql(u8, provider_str, "file"))
            .file
        else if (mem.eql(u8, provider_str, "encrypted"))
            .encrypted_file
        else if (mem.eql(u8, provider_str, "kms"))
            .aws_kms
        else if (mem.eql(u8, provider_str, "vault"))
            .vault
        else if (mem.eql(u8, provider_str, "1password") or mem.eql(u8, provider_str, "op"))
            .onepassword
        else if (mem.eql(u8, provider_str, "env"))
            .env
        else
            return null;

        // Parse version (@version at end)
        var version: ?[]const u8 = null;
        if (mem.lastIndexOf(u8, rest, "@")) |at_idx| {
            version = rest[at_idx + 1 ..];
            rest = rest[0..at_idx];
        }

        // Parse field (#field)
        var field: ?[]const u8 = null;
        if (mem.lastIndexOf(u8, rest, "#")) |hash_idx| {
            field = rest[hash_idx + 1 ..];
            rest = rest[0..hash_idx];
        }

        return SecretRef{
            .provider = provider,
            .path = rest,
            .field = field,
            .version = version,
        };
    }

    /// Securely free a secret value
    pub fn freeSecret(self: *Self, value: []u8) void {
        secret.secureZero(value);
        self.allocator.free(value);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Provider format" {
    try std.testing.expectEqualStrings("file", Provider.file.format());
    try std.testing.expectEqualStrings("vault", Provider.vault.format());
    try std.testing.expectEqualStrings("1password", Provider.onepassword.format());
    try std.testing.expectEqualStrings("aws_kms", Provider.aws_kms.format());
}

test "SecretManager init" {
    const manager = SecretManager.init(std.testing.allocator);
    _ = manager;
}

test "SecretManager configure providers" {
    var manager = SecretManager.init(std.testing.allocator);

    manager.configureKms(.{ .region = "us-west-2" });
    try std.testing.expect(manager.kms_config != null);
    try std.testing.expectEqualStrings("us-west-2", manager.kms_config.?.region);

    manager.configureVault(.{ .address = "https://vault.example.com" });
    try std.testing.expect(manager.vault_config != null);

    manager.configureOnePassword(.{ .vault = "Work" });
    try std.testing.expect(manager.onepassword_config != null);
    try std.testing.expectEqualStrings("Work", manager.onepassword_config.?.vault);
}

test "parseRef file" {
    const ref = SecretManager.parseRef("file:///etc/secrets/password").?;
    try std.testing.expectEqual(Provider.file, ref.provider);
    try std.testing.expectEqualStrings("/etc/secrets/password", ref.path);
    try std.testing.expect(ref.field == null);
}

test "parseRef vault with field" {
    const ref = SecretManager.parseRef("vault://secret/myapp/db#password").?;
    try std.testing.expectEqual(Provider.vault, ref.provider);
    try std.testing.expectEqualStrings("secret/myapp/db", ref.path);
    try std.testing.expectEqualStrings("password", ref.field.?);
}

test "parseRef 1password with field and version" {
    const ref = SecretManager.parseRef("1password://Database/PostgreSQL#password@v2").?;
    try std.testing.expectEqual(Provider.onepassword, ref.provider);
    try std.testing.expectEqualStrings("Database/PostgreSQL", ref.path);
    try std.testing.expectEqualStrings("password", ref.field.?);
    try std.testing.expectEqualStrings("v2", ref.version.?);
}

test "parseRef kms" {
    const ref = SecretManager.parseRef("kms://alias/mykey/secret").?;
    try std.testing.expectEqual(Provider.aws_kms, ref.provider);
    try std.testing.expectEqualStrings("alias/mykey/secret", ref.path);
}

test "parseRef env" {
    const ref = SecretManager.parseRef("env://MY_SECRET").?;
    try std.testing.expectEqual(Provider.env, ref.provider);
    try std.testing.expectEqualStrings("MY_SECRET", ref.path);
}

test "parseRef invalid" {
    try std.testing.expect(SecretManager.parseRef("invalid") == null);
    try std.testing.expect(SecretManager.parseRef("unknown://path") == null);
}

test "loadFromEnv" {
    var manager = SecretManager.init(std.testing.allocator);

    // PATH should exist on most systems
    if (manager.loadSecret(.{ .provider = .env, .path = "PATH" })) |value| {
        defer manager.freeSecret(value);
        try std.testing.expect(value.len > 0);
    } else |_| {
        // PATH might not exist on some systems, that's ok
    }
}

test "loadSecret unconfigured provider" {
    var manager = SecretManager.init(std.testing.allocator);

    // Vault not configured
    const result = manager.loadSecret(.{ .provider = .vault, .path = "secret/test" });
    try std.testing.expectError(SecretError.ProviderNotConfigured, result);
}

// ============================================================================
// Security Validation Tests
// ============================================================================

test "isValidSecretIdentifier allows safe characters" {
    try std.testing.expect(isValidSecretIdentifier("secret/myapp/db"));
    try std.testing.expect(isValidSecretIdentifier("my-secret"));
    try std.testing.expect(isValidSecretIdentifier("my_secret"));
    try std.testing.expect(isValidSecretIdentifier("secret.key"));
    try std.testing.expect(isValidSecretIdentifier("abc123"));
}

test "isValidSecretIdentifier rejects dangerous characters" {
    // Shell metacharacters
    try std.testing.expect(!isValidSecretIdentifier("secret; rm -rf /"));
    try std.testing.expect(!isValidSecretIdentifier("secret`whoami`"));
    try std.testing.expect(!isValidSecretIdentifier("secret$(cmd)"));
    try std.testing.expect(!isValidSecretIdentifier("secret|cat"));
    try std.testing.expect(!isValidSecretIdentifier("secret&bg"));
    try std.testing.expect(!isValidSecretIdentifier("secret\nnewline"));
    try std.testing.expect(!isValidSecretIdentifier("secret\ttab"));
    try std.testing.expect(!isValidSecretIdentifier("secret with space"));

    // Path traversal
    try std.testing.expect(!isValidSecretIdentifier("../etc/passwd"));
    try std.testing.expect(!isValidSecretIdentifier("foo/../bar"));

    // Empty input
    try std.testing.expect(!isValidSecretIdentifier(""));
}

test "loadFromVault rejects command injection" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureVault(.{});

    // Should reject dangerous paths
    const result = manager.loadSecret(.{ .provider = .vault, .path = "secret; rm -rf /" });
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

test "loadFromOnePassword rejects command injection" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureOnePassword(.{});

    // Should reject dangerous item names
    const result = manager.loadSecret(.{ .provider = .onepassword, .path = "Database`whoami`" });
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

test "isValidOpPath allows safe paths (#66)" {
    // Default path (uses PATH lookup)
    try std.testing.expect(isValidOpPath("op"));

    // Allowlisted system paths
    try std.testing.expect(isValidOpPath("/usr/bin/op"));
    try std.testing.expect(isValidOpPath("/usr/local/bin/op"));
    try std.testing.expect(isValidOpPath("/opt/1password/op"));
    try std.testing.expect(isValidOpPath("/opt/1password-cli/op"));
    try std.testing.expect(isValidOpPath("/snap/bin/op"));

    // Home directory bin paths
    try std.testing.expect(isValidOpPath("/home/user/bin/op"));
    try std.testing.expect(isValidOpPath("/home/user/.local/bin/op"));
    try std.testing.expect(isValidOpPath("/Users/developer/bin/op"));
}

test "isValidOpPath rejects malicious paths (#66)" {
    // Empty path
    try std.testing.expect(!isValidOpPath(""));

    // Arbitrary binaries
    try std.testing.expect(!isValidOpPath("/tmp/malicious"));
    try std.testing.expect(!isValidOpPath("/bin/sh"));
    try std.testing.expect(!isValidOpPath("./local_script"));
    try std.testing.expect(!isValidOpPath("/etc/passwd"));

    // Path traversal attempts
    try std.testing.expect(!isValidOpPath("/usr/bin/../../../tmp/evil"));
    try std.testing.expect(!isValidOpPath("/home/user/../../etc/op"));

    // Paths not ending in /op
    try std.testing.expect(!isValidOpPath("/usr/bin/op2"));
    try std.testing.expect(!isValidOpPath("/usr/bin/op.bak"));
    try std.testing.expect(!isValidOpPath("/home/user/bin/notop"));
}

test "loadFromOnePassword rejects invalid op_path (#66)" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureOnePassword(.{ .op_path = "/tmp/malicious_binary" });

    // Should reject the malicious op_path
    const result = manager.loadSecret(.{ .provider = .onepassword, .path = "Database" });
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

test "loadFromVault rejects invalid path_prefix (#67)" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureVault(.{ .path_prefix = "secret`rm -rf`" });

    // Should reject the malicious path_prefix
    const result = manager.loadSecret(.{ .provider = .vault, .path = "database/creds" });
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

test "loadFromOnePassword rejects invalid vault name (#67)" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureOnePassword(.{ .vault = "Private`whoami`" });

    // Should reject the malicious vault name
    const result = manager.loadSecret(.{ .provider = .onepassword, .path = "Database" });
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

test "encrypted_file provider returns not implemented" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureEncryptedFile(.{});

    const result = manager.loadSecret(.{ .provider = .encrypted_file, .path = "test" });
    try std.testing.expectError(SecretError.FeatureNotImplemented, result);
}

test "aws_kms provider returns not implemented" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.configureKms(.{});

    const result = manager.loadSecret(.{ .provider = .aws_kms, .path = "alias/mykey" });
    try std.testing.expectError(SecretError.FeatureNotImplemented, result);
}

test "VaultConfig defaults to HTTPS" {
    const config = VaultConfig{};
    try std.testing.expect(std.mem.startsWith(u8, config.address, "https://"));
}

// ============================================================================
// SensitiveString Tests (#50)
// ============================================================================

test "SensitiveString redacts on format" {
    const sensitive = SensitiveString.init("super-secret-token");

    var buf: [100]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{}", .{sensitive}) catch unreachable;

    // Should never expose the actual value
    try std.testing.expectEqualStrings("***REDACTED***", result);
    try std.testing.expect(std.mem.indexOf(u8, result, "super-secret") == null);
}

test "SensitiveString expose returns value" {
    const sensitive = SensitiveString.init("my-api-key");

    // Explicit expose is required to get the value
    try std.testing.expectEqualStrings("my-api-key", sensitive.expose());
}

test "SensitiveString isSet and len" {
    const empty = SensitiveString.init("");
    const set = SensitiveString.init("value");

    try std.testing.expect(!empty.isSet());
    try std.testing.expect(set.isSet());
    try std.testing.expectEqual(@as(usize, 0), empty.len());
    try std.testing.expectEqual(@as(usize, 5), set.len());
}

test "SensitiveString owned copy and deinit" {
    var sensitive = try SensitiveString.initOwned(std.testing.allocator, "secret-value");
    defer sensitive.deinit();

    try std.testing.expectEqualStrings("secret-value", sensitive.expose());
    try std.testing.expect(sensitive.owned);
}

// ============================================================================
// Config Struct Credential Protection Tests (#59)
// ============================================================================

test "KmsConfig credentials use SensitiveString for redaction" {
    var config = KmsConfig{
        .region = "us-east-1",
        .access_key_id = SensitiveString.init("AKIAIOSFODNN7EXAMPLE"),
        .secret_access_key = SensitiveString.init("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        .session_token = SensitiveString.init("session-token-value"),
    };
    defer config.deinit();

    // Verify SensitiveString redacts credentials when formatted
    var buf: [200]u8 = undefined;
    const key_str = std.fmt.bufPrint(&buf, "{}", .{config.access_key_id.?}) catch unreachable;
    try std.testing.expectEqualStrings("***REDACTED***", key_str);

    // But expose() returns actual values
    try std.testing.expectEqualStrings("AKIAIOSFODNN7EXAMPLE", config.access_key_id.?.expose());
}

test "VaultConfig token uses SensitiveString for redaction" {
    var config = VaultConfig{
        .token = SensitiveString.init("hvs.CAESIAE-super-secret-vault-token"),
    };
    defer config.deinit();

    // Verify token is redacted when formatted
    var buf: [100]u8 = undefined;
    const token_str = std.fmt.bufPrint(&buf, "{}", .{config.token.?}) catch unreachable;
    try std.testing.expectEqualStrings("***REDACTED***", token_str);

    // But expose() returns actual value
    try std.testing.expectEqualStrings("hvs.CAESIAE-super-secret-vault-token", config.token.?.expose());
}

test "OnePasswordConfig token uses SensitiveString for redaction" {
    var config = OnePasswordConfig{
        .service_account_token = SensitiveString.init("ops_1password_service_token"),
    };
    defer config.deinit();

    // Verify token is redacted when formatted
    var buf: [100]u8 = undefined;
    const token_str = std.fmt.bufPrint(&buf, "{}", .{config.service_account_token.?}) catch unreachable;
    try std.testing.expectEqualStrings("***REDACTED***", token_str);
}
