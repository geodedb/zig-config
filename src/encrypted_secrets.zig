// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Encrypted Secrets Module
//!
//! Provides secure secret management with support for multiple providers:
//! - AWS KMS (Key Management Service)
//! - HashiCorp Vault
//! - 1Password CLI
//! - Local encrypted files (AES-256-GCM)
//! - Environment variables (DEPRECATED -- insecure, disabled by default)
//!
//! Secrets are never stored in memory longer than necessary and are
//! securely zeroed when freed.
//!
//! ## Security Note on env:// Provider
//!
//! The `env://` provider is disabled by default and should not be used in
//! production. Environment variables are insecure for secret storage: they
//! are visible via /proc, inherited by child processes, and commonly
//! captured in crash reports and CI logs (CWE-214). To opt in, call
//! `SecretManager.allowEnvProvider(true)`. See #84 for details.

const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");
const Allocator = mem.Allocator;
const environ = @import("environ.zig");
const secret = @import("secret.zig");
const process = std.process;

/// Scoped logger for provider subprocess diagnostics.
/// Security: only ever logs bounded, non-secret diagnostics (e.g. a truncated
/// prefix of a failed provider's stderr); secret material in stdout/stderr is
/// secureZero'd and never logged (CWE-532).
const log = std.log.scoped(.encrypted_secrets);

/// Upper bound on captured stderr from a provider subprocess. Stderr is drained
/// concurrently with stdout so a child cannot deadlock by filling the stderr
/// pipe buffer (CWE-833) while the parent blocks reading stdout (AS-04).
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Upper bound on the stderr prefix surfaced to the log on command failure.
/// Keeps diagnostics useful without flooding logs.
const MAX_STDERR_LOG_BYTES: usize = 1024;

const DEFAULT_COMMAND_TIMEOUT_MS: u32 = 30_000;

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

    /// Custom format function - always redacts.
    /// Conforms to the Zig 0.15 std.fmt {f} protocol so that
    /// `std.fmt.bufPrint(&buf, "{f}", .{sensitive})` produces "[REDACTED]".
    /// Security: Prevents credential exposure in logs (CWE-532).
    pub fn format(self: Self, w: *std.Io.Writer) !void {
        _ = self;
        try w.writeAll("[REDACTED]");
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

/// Allowlist of valid Vault CLI binary paths (CWE-426)
const vault_path_allowlist = [_][]const u8{
    "/usr/bin/vault",
    "/usr/local/bin/vault",
    "/usr/local/sbin/vault",
    "/opt/hashicorp/vault",
    "/opt/homebrew/bin/vault",
    "/home/linuxbrew/.linuxbrew/bin/vault",
    "/snap/bin/vault",
    "C:\\Program Files\\HashiCorp\\Vault\\vault.exe",
};

// R-03/R-04: Parameterized provider path validation (shared by op and vault).
// Security: Validates a CLI binary path against an explicit allowlist and
// a restricted home-directory pattern to prevent arbitrary binary execution
// (CWE-78, CWE-426, #66, SEC-07, SEC-17).
fn isValidProviderPath(path: []const u8, allowlist: []const []const u8, binary_suffix: []const u8) bool {
    if (path.len == 0) return false;

    // Check against explicit allowlist
    for (allowlist) |allowed| {
        if (mem.eql(u8, path, allowed)) return true;
    }

    // Allow paths in home directories: ~/bin/<tool> or ~/.local/bin/<tool> only.
    // Security (SEC-07): Restrict to exactly /home/<user>/bin/<tool> or
    // /home/<user>/.local/bin/<tool> to prevent matches like
    // /home/user/projects/evil/bin/<tool>.
    if (mem.indexOf(u8, path, "..") != null) return false;
    const prefixes = [_][]const u8{ "/home/", "/Users/" };
    for (prefixes) |prefix| {
        if (mem.startsWith(u8, path, prefix)) {
            const after_prefix = path[prefix.len..];
            const user_end = mem.indexOf(u8, after_prefix, "/") orelse continue;
            if (user_end == 0) continue;
            const after_user = after_prefix[user_end..];

            // Build expected suffixes: "/bin/<tool>" and "/.local/bin/<tool>"
            var bin_suffix_buf: [64]u8 = undefined;
            const bin_suffix = std.fmt.bufPrint(&bin_suffix_buf, "/bin/{s}", .{binary_suffix}) catch continue;
            var local_suffix_buf: [64]u8 = undefined;
            const local_suffix = std.fmt.bufPrint(&local_suffix_buf, "/.local/bin/{s}", .{binary_suffix}) catch continue;

            if (mem.eql(u8, after_user, bin_suffix) or
                mem.eql(u8, after_user, local_suffix))
            {
                return true;
            }
        }
    }

    return false;
}

/// Validate the 1Password CLI binary path against an allowlist (CWE-78, #66).
/// Security: Prevents arbitrary binary execution by restricting op_path to known safe locations.
/// Returns true if the path is in the allowlist or matches a safe pattern.
pub fn isValidOpPath(path: []const u8) bool {
    return isValidProviderPath(path, &op_path_allowlist, "op");
}

/// Validate the Vault CLI binary path against an allowlist (CWE-426).
/// Security (SEC-07, SEC-17): Uses strict suffix matching identical to isValidOpPath
/// to prevent matches like /home/user/projects/evil/bin/vault.
pub fn isValidVaultPath(path: []const u8) bool {
    return isValidProviderPath(path, &vault_path_allowlist, "vault");
}

fn findExecutableInPath(allocator: Allocator, name: []const u8) ?[]u8 {
    const path_env = environ.getenv("PATH") orelse return null;
    const io = std.Io.Threaded.global_single_threaded.io();
    var it = mem.splitScalar(u8, path_env, std.Io.Dir.path.delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const full = std.Io.Dir.path.join(allocator, &.{ dir, name }) catch continue;
        if (std.Io.Dir.accessAbsolute(io, full, .{})) {
            return full;
        } else |_| {
            allocator.free(full);
        }
    }
    return null;
}

// R-03/R-04: Parameterized provider path resolution (shared by op and vault).
// Security: Prevents PATH hijack by ensuring resolved binary is in allowlist (CWE-426, #77).
fn resolveProviderPath(allocator: Allocator, path: []const u8, comptime validator_fn: fn ([]const u8) bool) SecretError![]u8 {
    const has_separator = mem.indexOfAny(u8, path, "/\\") != null;
    if (!has_separator) {
        const resolved = findExecutableInPath(allocator, path) orelse return SecretError.ProviderNotAvailable;
        if (!validator_fn(resolved)) {
            allocator.free(resolved);
            return SecretError.InvalidInputCharacters;
        }
        return resolved;
    }

    if (!validator_fn(path)) return SecretError.InvalidInputCharacters;
    return allocator.dupe(u8, path) catch return SecretError.OutOfMemory;
}

pub fn resolveVaultPath(allocator: Allocator, path: []const u8) SecretError![]u8 {
    return resolveProviderPath(allocator, path, isValidVaultPath);
}

/// Resolve the 1Password CLI binary path, analogous to resolveVaultPath.
/// If the path has no directory separator (bare name like "op"), resolve it
/// against PATH and validate against the op allowlist. Otherwise, validate
/// the absolute/relative path directly against the allowlist.
/// Security: Prevents PATH hijack by ensuring resolved binary is in allowlist (CWE-426, #77)
pub fn resolveOpPath(allocator: Allocator, path: []const u8) SecretError![]u8 {
    return resolveProviderPath(allocator, path, isValidOpPath);
}

/// Handle process termination status safely, covering all Term variants.
/// Security: Prevents undefined behavior from accessing wrong union field (#103).
pub fn handleTermination(term: process.Child.Term) SecretError!void {
    switch (term) {
        .exited => |code| {
            if (code != 0) return SecretError.CommandFailed;
        },
        .signal => return SecretError.CommandFailed,
        .stopped => return SecretError.CommandFailed,
        .unknown => return SecretError.CommandFailed,
    }
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
    /// Environment variable provider (DEPRECATED -- security risk).
    ///
    /// WARNING: Storing secrets in environment variables is insecure and
    /// contradicts best-practice secret management policy (CWE-214, #84).
    /// Environment variables are visible via /proc, inherited by child
    /// processes, and often logged by crash reporters or debugging tools.
    ///
    /// This provider is disabled by default. To opt in, call
    /// `SecretManager.allowEnvProvider(true)` -- but prefer file://, vault://,
    /// or 1password:// providers for any sensitive data.
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
    /// Path to vault CLI binary
    vault_path: []const u8 = "vault",
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
    /// Allow loading secrets from environment variables.
    ///
    /// SECURITY: Defaults to false. Environment variables are insecure for
    /// secret storage (CWE-214, #84): they leak via /proc, child processes,
    /// and crash dumps. Enable only for local development or migration from
    /// legacy systems; never in production.
    allow_env_provider: bool = false,

    const Self = @This();

    /// Initialize a new secret manager
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Explicitly allow or disallow environment variable secrets.
    ///
    /// SECURITY: The env:// provider is deprecated and insecure (CWE-214, #84).
    /// Calling `allowEnvProvider(true)` acknowledges the risk that environment
    /// variables are visible via /proc, inherited by child processes, and
    /// commonly captured in crash reports. Prefer vault://, 1password://, or
    /// file:// providers for production workloads.
    pub fn allowEnvProvider(self: *Self, allow: bool) void {
        self.allow_env_provider = allow;
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

    /// Load a secret from a reference.
    ///
    /// The env:// provider returns `InvalidConfiguration` unless
    /// `allow_env_provider` has been explicitly set to true via
    /// `allowEnvProvider(true)`. See CWE-214 / #84.
    pub fn loadSecret(self: *Self, ref: SecretRef) SecretError![]u8 {
        return switch (ref.provider) {
            .file => self.loadFromFile(ref.path),
            .encrypted_file => self.loadFromEncryptedFile(ref.path),
            .aws_kms => self.loadFromKms(ref.path),
            .vault => self.loadFromVault(ref.path, ref.field),
            .onepassword => self.loadFromOnePassword(ref.path, ref.field),
            .env => if (self.allow_env_provider) self.loadFromEnv(ref.path) else SecretError.InvalidConfiguration,
        };
    }

    /// Load a secret from a file
    /// Security (SEC-09): Uses allocator.dupe instead of @constCast to avoid
    /// UB on potentially read-only memory returned by readFromFile.
    fn loadFromFile(self: *Self, path: []const u8) SecretError![]u8 {
        const content = secret.readFromFile(path, self.allocator) catch {
            return SecretError.SecretNotFound;
        };
        const mutable = self.allocator.dupe(u8, content) catch {
            self.allocator.free(content);
            return SecretError.OutOfMemory;
        };
        self.allocator.free(content);
        return mutable;
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

        // Security: Validate inputs BEFORE resolving provider path to ensure
        // injection is caught even when the provider binary is not installed.
        if (!isValidSecretIdentifier(config.path_prefix)) {
            return SecretError.InvalidInputCharacters;
        }
        if (!isValidSecretIdentifier(path)) {
            return SecretError.InvalidInputCharacters;
        }
        if (field) |f| {
            if (!isValidSecretIdentifier(f)) {
                return SecretError.InvalidInputCharacters;
            }
        }

        const vault_path = try resolveVaultPath(self.allocator, config.vault_path);
        defer self.allocator.free(vault_path);

        // Build vault CLI command
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        args.append(self.allocator, vault_path) catch return SecretError.OutOfMemory;
        args.append(self.allocator, "kv") catch return SecretError.OutOfMemory;
        args.append(self.allocator, "get") catch return SecretError.OutOfMemory;
        args.append(self.allocator, "-format=json") catch return SecretError.OutOfMemory;

        const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            config.path_prefix,
            path,
        }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(full_path);
        args.append(self.allocator, full_path) catch return SecretError.OutOfMemory;

        var env_map = try buildVaultEnvMap(self.allocator, config);
        defer env_map.deinit();

        return self.execCommand(args.items, field, &env_map, config.timeout_ms);
    }

    /// Load from 1Password
    /// Security: Validates item, field, vault, and op_path to prevent injection (CWE-78, #66, #67)
    fn loadFromOnePassword(self: *Self, item: []const u8, field: ?[]const u8) SecretError![]u8 {
        const config = self.onepassword_config orelse return SecretError.ProviderNotConfigured;

        // Security: Validate inputs BEFORE resolving provider path to ensure
        // injection is caught even when the provider binary is not installed.
        if (!isValidSecretIdentifier(config.vault)) {
            return SecretError.InvalidInputCharacters;
        }
        if (!isValidSecretIdentifier(item)) {
            return SecretError.InvalidInputCharacters;
        }
        if (field) |f| {
            if (!isValidSecretIdentifier(f)) {
                return SecretError.InvalidInputCharacters;
            }
        }

        // Security: Resolve and validate op_path against allowlist (#66, #77)
        const op_path = try resolveOpPath(self.allocator, config.op_path);
        defer self.allocator.free(op_path);

        // Build op CLI command
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        args.append(self.allocator, op_path) catch return SecretError.OutOfMemory;
        args.append(self.allocator, "read") catch return SecretError.OutOfMemory;

        // Build reference: op://vault/item/field
        const ref = if (field) |f|
            std.fmt.allocPrint(self.allocator, "op://{s}/{s}/{s}", .{ config.vault, item, f }) catch return SecretError.OutOfMemory
        else
            std.fmt.allocPrint(self.allocator, "op://{s}/{s}/password", .{ config.vault, item }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(ref);

        args.append(self.allocator, ref) catch return SecretError.OutOfMemory;

        var env_map = try buildOnePasswordEnvMap(self.allocator, config);
        defer env_map.deinit();

        return self.execCommand(args.items, null, &env_map, DEFAULT_COMMAND_TIMEOUT_MS);
    }

    /// Load a secret from an environment variable.
    ///
    /// DEPRECATED (CWE-214, #84): Environment variables are an insecure secret
    /// storage mechanism. Values are visible in /proc/<pid>/environ, inherited by
    /// all child processes, and frequently captured in crash dumps and CI logs.
    /// This function is only reachable when `allow_env_provider` is explicitly
    /// set to true. Prefer vault://, 1password://, or file:// providers.
    fn loadFromEnv(self: *Self, name: []const u8) SecretError![]u8 {
        const value = environ.getenv(name) orelse return SecretError.SecretNotFound;
        return self.allocator.dupe(u8, value) catch return SecretError.OutOfMemory;
    }

    /// Build a minimal environment for Vault child processes (#117).
    /// Only includes required Vault variables plus PATH and HOME.
    /// Security: Prevents leaking the full process environment to child processes.
    fn buildVaultEnvMap(allocator: Allocator, config: VaultConfig) SecretError!process.Environ.Map {
        return buildMinimalVaultEnvMap(allocator, config);
    }

    /// Builds a minimal Vault env map with only required variables.
    pub fn buildMinimalVaultEnvMap(allocator: Allocator, config: VaultConfig) SecretError!process.Environ.Map {
        var env_map = process.Environ.Map.init(allocator);
        errdefer env_map.deinit();

        // Required system variables for binary resolution and tool operation
        if (environ.getenv("PATH")) |path_val| {
            env_map.put("PATH", path_val) catch return SecretError.OutOfMemory;
        }
        if (environ.getenv("HOME")) |home_val| {
            env_map.put("HOME", home_val) catch return SecretError.OutOfMemory;
        }

        // Vault-specific variables
        env_map.put("VAULT_ADDR", config.address) catch return SecretError.OutOfMemory;
        if (config.token) |token| env_map.put("VAULT_TOKEN", token.expose()) catch return SecretError.OutOfMemory;
        if (config.namespace) |ns| env_map.put("VAULT_NAMESPACE", ns) catch return SecretError.OutOfMemory;
        if (config.tls_skip_verify) env_map.put("VAULT_SKIP_VERIFY", "true") catch return SecretError.OutOfMemory;
        if (config.timeout_ms > 0) {
            const timeout_val = std.fmt.allocPrint(allocator, "{d}ms", .{config.timeout_ms}) catch return SecretError.OutOfMemory;
            defer allocator.free(timeout_val);
            env_map.put("VAULT_CLIENT_TIMEOUT", timeout_val) catch return SecretError.OutOfMemory;
        }

        return env_map;
    }

    /// Build a minimal environment for 1Password child processes (#117).
    /// Only includes required 1Password variables plus PATH and HOME.
    /// Security: Prevents leaking the full process environment to child processes.
    fn buildOnePasswordEnvMap(allocator: Allocator, config: OnePasswordConfig) SecretError!process.Environ.Map {
        return buildMinimalOnePasswordEnvMap(allocator, config);
    }

    /// Builds a minimal 1Password env map with only required variables.
    pub fn buildMinimalOnePasswordEnvMap(allocator: Allocator, config: OnePasswordConfig) SecretError!process.Environ.Map {
        var env_map = process.Environ.Map.init(allocator);
        errdefer env_map.deinit();

        // Required system variables for binary resolution and tool operation
        if (environ.getenv("PATH")) |path_val| {
            env_map.put("PATH", path_val) catch return SecretError.OutOfMemory;
        }
        if (environ.getenv("HOME")) |home_val| {
            env_map.put("HOME", home_val) catch return SecretError.OutOfMemory;
        }

        // 1Password-specific variables
        if (config.account) |acct| env_map.put("OP_ACCOUNT", acct) catch return SecretError.OutOfMemory;
        if (config.service_account_token) |token| env_map.put("OP_SERVICE_ACCOUNT_TOKEN", token.expose()) catch return SecretError.OutOfMemory;

        return env_map;
    }

    /// Shared signal flag between `execCommand` and its watchdog/drainer threads.
    ///
    /// Modeled as a 4-byte atomic so it can be used directly as a futex word
    /// (`io.futexWaitTimeout`/`io.futexWake`). The main thread stores `1` and
    /// wakes the watchdog the instant the child finishes, so a successful fast
    /// exec returns promptly instead of blocking for the full `timeout_ms`
    /// (Q-NEW-04). 0 = child still running, 1 = main thread done with the child.
    const DoneFlag = enum(u32) { running = 0, done = 1 };

    /// Signal completion to the watchdog and wake it immediately.
    /// Security/reliability (Q-NEW-04): the futex wake means the watchdog's
    /// `futexWaitTimeout` returns at once on success instead of sleeping out
    /// the whole timeout.
    fn signalDone(io: std.Io, done: *std.atomic.Value(DoneFlag)) void {
        done.store(.done, .release);
        io.futexWake(DoneFlag, &done.raw, 1);
    }

    /// Concurrently drains a child's stderr pipe into an owned, bounded buffer.
    ///
    /// Security/reliability (AS-04, CWE-833/CWE-400): stderr MUST be drained
    /// concurrently with stdout, and MUST be drained *completely*. If stderr
    /// were left undrained (or drained only after stdout), a child that writes
    /// more than the OS pipe buffer (~64 KB) to stderr would block on the stderr
    /// write while the parent blocks reading stdout — a classic two-pipe
    /// deadlock. Running this on its own thread breaks the cycle. The drainer
    /// keeps at most `MAX_STDERR_BYTES` for diagnostics but continues reading
    /// (discarding the overflow) to EOF so the child can never block.
    ///
    /// IO note: the drainer creates its own `std.Io.Threaded` instance. Two
    /// independent threads performing blocking pipe reads through the *same*
    /// `Io.Threaded` interrupt each other's syscalls (it uses `SIG.IO` to
    /// interrupt blocking operations), which corrupts the streamed read. A
    /// dedicated io per draining thread avoids that.
    ///
    /// Allocation note: the drainer uses `std.heap.page_allocator` (thread-safe)
    /// rather than the manager's allocator. The stdout read on the main thread
    /// allocates from `self.allocator` at the same time, and that allocator is
    /// not guaranteed to be thread-safe; sharing it across the two threads would
    /// be a data race. stderr is only ever used as a bounded log diagnostic
    /// (never returned to the caller), so an independent allocator is sufficient.
    const StderrDrainCtx = struct {
        file: std.Io.File,
        /// Drained stderr bytes (owned by `page_allocator`, capped at
        /// `MAX_STDERR_BYTES`). Read only after the thread is joined; freed via
        /// `deinit`.
        data: []u8 = &.{},

        fn run(ctx: *@This()) void {
            // Dedicated io for this thread's blocking reads (see IO note above).
            var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
            defer threaded.deinit();
            const dio = threaded.io();

            var read_buf: [4096]u8 = undefined;
            var reader = ctx.file.readerStreaming(dio, &read_buf);

            var kept: std.ArrayListUnmanaged(u8) = .empty;
            var scratch: [4096]u8 = undefined;
            // Fully drain the pipe to EOF so the child never blocks writing to
            // stderr, but retain only a bounded prefix for diagnostics.
            while (true) {
                const n = reader.interface.readSliceShort(&scratch) catch break;
                if (n == 0) break; // EOF
                if (kept.items.len < MAX_STDERR_BYTES) {
                    const room = MAX_STDERR_BYTES - kept.items.len;
                    const take = @min(room, n);
                    kept.appendSlice(std.heap.page_allocator, scratch[0..take]) catch break;
                }
                // Beyond the cap: keep reading to drain, but discard.
            }
            ctx.data = kept.toOwnedSlice(std.heap.page_allocator) catch &.{};
        }

        /// Securely zero then free the drained stderr buffer.
        /// Security (SEC-08/CWE-316): provider diagnostics may echo secret
        /// material, so zero before freeing.
        fn deinit(ctx: *@This()) void {
            if (ctx.data.len > 0) {
                secret.secureZero(ctx.data);
                std.heap.page_allocator.free(ctx.data);
                ctx.data = &.{};
            }
        }
    };

    /// Execute a command and return its output
    fn execCommand(
        self: *Self,
        args: []const []const u8,
        json_field: ?[]const u8,
        env_map: ?*process.Environ.Map,
        timeout_ms: u32,
    ) SecretError![]u8 {
        // A real, initialized Threaded io is required: process spawning must
        // allocate the child's argv/env before fork(), and the statically
        // initialized `global_single_threaded` io carries a `.failing`
        // allocator, so spawning through it always fails. Back this io with the
        // thread-safe SMP allocator since the io is shared with the watchdog
        // thread (futex + kill).
        var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        defer threaded.deinit();
        const eio = threaded.io();

        const is_posix = builtin.os.tag != .windows;
        var child = process.spawn(eio, .{
            .argv = args,
            .stdout = .pipe,
            .stderr = .pipe,
            .environ_map = if (env_map) |m| m else null,
            // POSIX: make the child its own process-group leader so the watchdog
            // can terminate the *entire* group on timeout. Without this, a
            // grandchild (e.g. a shell's `sleep`) can keep the stdout pipe open
            // after the direct child is killed, leaving the parent blocked on
            // its stdout read for the grandchild's full lifetime (Q-NEW-04).
            .pgid = if (is_posix) 0 else null,
        }) catch return SecretError.CommandFailed;
        // Group id equals the child pid because it leads its own group (pgid=0).
        const child_pgid: ?std.posix.pid_t = if (is_posix) child.id else null;

        // Read stdout from its pipe; stderr is drained concurrently on a
        // separate thread (see StderrDrainCtx) so a large-stderr child cannot
        // deadlock the caller (AS-04, CWE-833).
        var stdout_data: []u8 = &.{};
        // Security (SEC-08): Zero buffers before freeing to prevent secret
        // leakage (CWE-316). stderr can contain provider diagnostics that may
        // echo secret material, so it is zeroed on the same footing as stdout.
        defer {
            if (stdout_data.len > 0) secret.secureZero(stdout_data);
            self.allocator.free(stdout_data);
        }

        // Start draining stderr immediately and concurrently with the stdout
        // read below. If the drainer thread cannot be spawned, fall back to
        // discarding stderr (.ignore-equivalent) by closing the pipe so the
        // child still cannot block writing to it.
        var stderr_ctx: ?StderrDrainCtx = null;
        var stderr_thread: ?std.Thread = null;
        if (child.stderr) |stderr_file| {
            stderr_ctx = .{
                .file = stderr_file,
            };
            stderr_thread = std.Thread.spawn(.{}, StderrDrainCtx.run, .{&stderr_ctx.?}) catch null;
            if (stderr_thread == null) {
                // Could not spawn a drainer: close stderr so the child cannot
                // deadlock writing to an unread pipe. Diagnostics are lost but
                // correctness/availability is preserved.
                stderr_file.close(eio);
                child.stderr = null;
                stderr_ctx = null;
            }
        }
        // Drained stderr is owned by the ctx; secureZero + free on every exit
        // path. Safe to read/free only after the drainer thread is joined
        // (handled by `quiesceReaders` below before any use of
        // `stderr_ctx.data` and before this defer can run).
        defer {
            if (stderr_ctx) |*sctx| sctx.deinit();
        }

        var done = std.atomic.Value(DoneFlag).init(.running);
        var timed_out = std.atomic.Value(bool).init(false);
        var watchdog: ?std.Thread = null;

        // F-01 teardown invariant (CWE-362 race / CWE-416-adjacent fd reuse):
        // the child's stdout/stderr descriptors are closed by exactly ONE
        // operation -- the main thread's single `child.wait` (which reaps and,
        // via stdlib `childCleanupPosix`, closes+nulls the pipes) -- and that
        // close happens ONLY AFTER both reader threads have been joined. The
        // main thread reads stdout, then joins the stderr drainer and the
        // watchdog (`quiesceReaders` below), and ONLY THEN reaps. No other
        // thread ever closes these fds. Reads are unblocked by EOF (the child
        // exiting closes the pipe write-ends; on timeout, SIGKILL forces it),
        // never by closing the fd out from under an active reader. Because the
        // main thread is the sole reaper, no reaper CAS is needed.
        const TimeoutCtx = struct {
            child_pgid: ?std.posix.pid_t,
            done: *std.atomic.Value(DoneFlag),
            timed_out: *std.atomic.Value(bool),
            timeout_ms: u32,
            io: std.Io,

            fn run(ctx: *@This()) void {
                // Wait until either the child completes (main thread stores
                // `.done` and wakes us via futexWake) or the timeout elapses.
                // Unlike a plain sleep-then-check, futexWaitTimeout returns the
                // instant the child finishes, so a fast successful exec no
                // longer stalls for the full timeout (Q-NEW-04). Spurious
                // wakeups are handled by re-checking `done` against the fixed
                // deadline.
                const deadline = std.Io.Clock.Timestamp.fromNow(ctx.io, .{
                    .clock = .awake,
                    .raw = .{ .nanoseconds = @as(i96, ctx.timeout_ms) * std.time.ns_per_ms },
                });
                while (ctx.done.load(.acquire) == .running) {
                    ctx.io.futexWaitTimeout(
                        DoneFlag,
                        &ctx.done.raw,
                        .running,
                        .{ .deadline = deadline },
                    ) catch {};
                    if (ctx.done.load(.acquire) != .running) return;
                    // Timed out if the deadline has passed and the child is
                    // still running.
                    const now = std.Io.Clock.Timestamp.now(ctx.io, .awake);
                    if (now.raw.nanoseconds >= deadline.raw.nanoseconds) {
                        ctx.timed_out.store(true, .release);
                        // POSIX: SIGKILL the whole process group so the child
                        // AND any grandchildren holding the stdout/stderr pipes
                        // die. That closes the pipe write-ends, forcing EOF on
                        // both reader threads so they return on their own --
                        // WITHOUT this thread touching the descriptors (F-01).
                        // The main thread remains the sole reaper/closer once
                        // its read returns and the drainer is joined. SIGKILL is
                        // best-effort; the child is still reaped by the main
                        // thread's `child.wait`, which never blocks because the
                        // process is already dead.
                        if (ctx.child_pgid) |pgid| {
                            std.posix.kill(-pgid, .KILL) catch {};
                        }
                        return;
                    }
                }
            }
        };

        var timeout_ctx: TimeoutCtx = undefined;
        if (timeout_ms > 0) {
            timeout_ctx = .{
                .child_pgid = child_pgid,
                .done = &done,
                .timed_out = &timed_out,
                .timeout_ms = timeout_ms,
                .io = eio,
            };
            // daemon (one-shot): process-termination watchdog. Wakes the moment
            // the child exits (futexWake) and otherwise fires once at the
            // timeout to bound a hang. Thread-pool would impose submission
            // overhead on a one-off blocking wait — not worth it.
            watchdog = std.Thread.spawn(.{}, TimeoutCtx.run, .{&timeout_ctx}) catch null;
        }

        // Quiesce the reader/watchdog threads: signal completion (so the
        // watchdog wakes immediately instead of sleeping out the timeout --
        // Q-NEW-04) and JOIN both threads. This MUST run before any path closes
        // the child's descriptors (i.e. before `child.wait`/the reap), so that
        // no thread is mid-`read()` on an fd that another thread closes (F-01).
        // Both reader threads always reach EOF first: the child exiting closes
        // the pipe write-ends on success/normal exit, and the watchdog's
        // SIGKILL closes them on timeout -- so this join never deadlocks.
        const quiesceReaders = struct {
            fn run(io: std.Io, d: *std.atomic.Value(DoneFlag), wd: ?std.Thread, st: ?std.Thread) void {
                signalDone(io, d);
                if (st) |t| t.join();
                if (wd) |t| t.join();
            }
        }.run;

        // Read stdout pipe (stderr is being drained concurrently). The read
        // returns on EOF: the child's exit closes the pipe write-end on the
        // normal path, and the watchdog's SIGKILL closes it on the timeout
        // path. Nothing closes this fd under the active read (F-01).
        if (child.stdout) |stdout_file| {
            var read_buf: [4096]u8 = undefined;
            var reader = stdout_file.readerStreaming(eio, &read_buf);
            stdout_data = reader.interface.allocRemaining(self.allocator, std.Io.Limit.limited(1024 * 1024)) catch {
                // Join readers BEFORE reaping so the reap's fd close cannot race
                // an active read. The drainer has EOF'd (child exit / SIGKILL).
                quiesceReaders(eio, &done, watchdog, stderr_thread);
                // Reap (closes the pipes) so we don't leak the child; the term
                // is irrelevant on this read-failure path.
                if (child.wait(eio)) |_| {} else |_| {}
                if (timed_out.load(.acquire)) return SecretError.Timeout;
                return SecretError.IoError;
            };
        }

        // Reader threads are now joined; the descriptors have NOT yet been
        // closed (only `child.wait` below closes them). This ordering is the
        // F-01 fix: close-after-join, single reaper, no fd touched under a
        // reader.
        quiesceReaders(eio, &done, watchdog, stderr_thread);

        // Single reaper (main thread): `child.wait` reaps the child and closes
        // its stdout/stderr pipes. Safe now that both readers are joined. On
        // the timeout path the child was already SIGKILL'd, so this returns
        // immediately.
        const term = child.wait(eio) catch {
            if (timed_out.load(.acquire)) return SecretError.Timeout;
            return SecretError.CommandFailed;
        };

        if (timed_out.load(.acquire)) {
            return SecretError.Timeout;
        }

        handleTermination(term) catch |err| {
            // Surface a bounded, non-secret prefix of the provider's stderr to
            // aid debugging of failed secret loads. The full buffer is
            // secureZero'd by the defer above.
            if (stderr_ctx) |sctx| {
                if (sctx.data.len > 0) {
                    const diag = mem.trimEnd(u8, sctx.data[0..@min(sctx.data.len, MAX_STDERR_LOG_BYTES)], "\n\r");
                    if (diag.len > 0) {
                        log.warn("provider command failed (argv[0]={s}): {s}", .{ args[0], diag });
                    }
                }
            }
            return err;
        };

        const trimmed = mem.trimEnd(u8, stdout_data, "\n\r");
        if (json_field) |field| {
            return extractJsonField(self.allocator, trimmed, field);
        }

        return self.allocator.dupe(u8, trimmed) catch return SecretError.OutOfMemory;
    }

    /// TEST-ONLY: drive `execCommand` with a caller-supplied argv so the
    /// stderr-draining (AS-04) and wakeable-watchdog (Q-NEW-04) logic can be
    /// exercised against a controlled child process in CI (where no real
    /// `vault`/`op` binary exists). Not part of the supported public API; only
    /// reachable from the test build.
    pub fn execCommandTestHook(
        self: *Self,
        args: []const []const u8,
        timeout_ms: u32,
    ) SecretError![]u8 {
        if (!builtin.is_test) @compileError("execCommandTestHook is test-only");
        return self.execCommand(args, null, null, timeout_ms);
    }

    fn extractJsonField(allocator: Allocator, json_bytes: []const u8, field: []const u8) SecretError![]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch {
            return SecretError.InvalidConfiguration;
        };
        defer parsed.deinit();

        const root = parsed.value;
        var target = root;

        if (root == .object) {
            if (root.object.get("data")) |data_val| {
                if (data_val == .object) {
                    if (data_val.object.get("data")) |inner| {
                        target = inner;
                    } else {
                        target = data_val;
                    }
                }
            }
        }

        if (target != .object) {
            return SecretError.InvalidConfiguration;
        }

        const value = target.object.get(field) orelse return SecretError.SecretNotFound;
        return jsonValueToString(allocator, value);
    }

    fn jsonValueToString(allocator: Allocator, value: std.json.Value) SecretError![]u8 {
        return switch (value) {
            .string => |s| allocator.dupe(u8, s) catch SecretError.OutOfMemory,
            .integer => |i| blk: {
                var buf: [32]u8 = undefined;
                const str = std.fmt.bufPrint(&buf, "{d}", .{i}) catch return SecretError.OutOfMemory;
                break :blk allocator.dupe(u8, str) catch SecretError.OutOfMemory;
            },
            .float => |f| blk: {
                var buf: [64]u8 = undefined;
                const str = std.fmt.bufPrint(&buf, "{d}", .{f}) catch return SecretError.OutOfMemory;
                break :blk allocator.dupe(u8, str) catch SecretError.OutOfMemory;
            },
            .bool => |b| allocator.dupe(u8, if (b) "true" else "false") catch SecretError.OutOfMemory,
            .null => SecretError.SecretNotFound,
            else => SecretError.InvalidConfiguration,
        };
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

test {
    _ = @import("encrypted_secrets_test.zig");
}
