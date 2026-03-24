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
const Allocator = mem.Allocator;
const environ = @import("environ.zig");
const secret = @import("secret.zig");
const process = std.process;

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
    pub fn format(self: Self, w: *std.io.Writer) !void {
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

/// Validate the 1Password CLI binary path against an allowlist (CWE-78, #66).
/// Security: Prevents arbitrary binary execution by restricting op_path to known safe locations.
/// Returns true if the path is in the allowlist or matches a safe pattern.
pub fn isValidOpPath(path: []const u8) bool {
    if (path.len == 0) return false;

    // Check against explicit allowlist
    for (op_path_allowlist) |allowed| {
        if (mem.eql(u8, path, allowed)) return true;
    }

    // Allow paths in home directories: ~/bin/op or ~/.local/bin/op only.
    // Security (SEC-07): Restrict to exactly /home/<user>/bin/op or
    // /home/<user>/.local/bin/op to prevent matches like
    // /home/user/projects/evil/bin/op.
    if (mem.indexOf(u8, path, "..") != null) return false;
    const prefixes = [_][]const u8{ "/home/", "/Users/" };
    for (prefixes) |prefix| {
        if (mem.startsWith(u8, path, prefix)) {
            const after_prefix = path[prefix.len..];
            const user_end = mem.indexOf(u8, after_prefix, "/") orelse continue;
            if (user_end == 0) continue;
            const after_user = after_prefix[user_end..];
            if (mem.eql(u8, after_user, "/bin/op") or
                mem.eql(u8, after_user, "/.local/bin/op"))
            {
                return true;
            }
        }
    }

    return false;
}

/// Validate the Vault CLI binary path against an allowlist (CWE-426).
/// Security (SEC-07, SEC-17): Uses strict suffix matching identical to isValidOpPath
/// to prevent matches like /home/user/projects/evil/bin/vault.
pub fn isValidVaultPath(path: []const u8) bool {
    if (path.len == 0) return false;

    for (vault_path_allowlist) |allowed| {
        if (mem.eql(u8, path, allowed)) return true;
    }

    // Allow paths in home directories: ~/bin/vault or ~/.local/bin/vault only.
    // Security (SEC-07): Restrict to exactly /home/<user>/bin/vault or
    // /home/<user>/.local/bin/vault to prevent matches like
    // /home/user/projects/evil/bin/vault.
    if (mem.indexOf(u8, path, "..") != null) return false;
    const prefixes = [_][]const u8{ "/home/", "/Users/" };
    for (prefixes) |prefix| {
        if (mem.startsWith(u8, path, prefix)) {
            const after_prefix = path[prefix.len..];
            const user_end = mem.indexOf(u8, after_prefix, "/") orelse continue;
            if (user_end == 0) continue;
            const after_user = after_prefix[user_end..];
            if (mem.eql(u8, after_user, "/bin/vault") or
                mem.eql(u8, after_user, "/.local/bin/vault"))
            {
                return true;
            }
        }
    }

    return false;
}

fn findExecutableInPath(allocator: Allocator, name: []const u8) ?[]u8 {
    const path_env = environ.getenv("PATH") orelse return null;
    var it = mem.splitScalar(u8, path_env, std.fs.path.delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const full = std.fs.path.join(allocator, &.{ dir, name }) catch continue;
        if (std.fs.accessAbsolute(full, .{})) {
            return full;
        } else |_| {
            allocator.free(full);
        }
    }
    return null;
}

fn resolveVaultPath(allocator: Allocator, path: []const u8) SecretError![]u8 {
    const has_separator = mem.indexOfAny(u8, path, "/\\") != null;
    if (!has_separator) {
        const resolved = findExecutableInPath(allocator, path) orelse return SecretError.ProviderNotAvailable;
        if (!isValidVaultPath(resolved)) {
            allocator.free(resolved);
            return SecretError.InvalidInputCharacters;
        }
        return resolved;
    }

    if (!isValidVaultPath(path)) return SecretError.InvalidInputCharacters;
    return allocator.dupe(u8, path) catch return SecretError.OutOfMemory;
}

/// Resolve the 1Password CLI binary path, analogous to resolveVaultPath.
/// If the path has no directory separator (bare name like "op"), resolve it
/// against PATH and validate against the op allowlist. Otherwise, validate
/// the absolute/relative path directly against the allowlist.
/// Security: Prevents PATH hijack by ensuring resolved binary is in allowlist (CWE-426, #77)
fn resolveOpPath(allocator: Allocator, path: []const u8) SecretError![]u8 {
    const has_separator = mem.indexOfAny(u8, path, "/\\") != null;
    if (!has_separator) {
        const resolved = findExecutableInPath(allocator, path) orelse return SecretError.ProviderNotAvailable;
        if (!isValidOpPath(resolved)) {
            allocator.free(resolved);
            return SecretError.InvalidInputCharacters;
        }
        return resolved;
    }

    if (!isValidOpPath(path)) return SecretError.InvalidInputCharacters;
    return allocator.dupe(u8, path) catch return SecretError.OutOfMemory;
}

/// Handle process termination status safely, covering all Term variants.
/// Security: Prevents undefined behavior from accessing wrong union field (#103).
fn handleTermination(term: process.Child.Term) SecretError!void {
    switch (term) {
        .Exited => |code| {
            if (code != 0) return SecretError.CommandFailed;
        },
        .Signal => return SecretError.CommandFailed,
        .Stopped => return SecretError.CommandFailed,
        .Unknown => return SecretError.CommandFailed,
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

        const vault_path = try resolveVaultPath(self.allocator, config.vault_path);
        defer self.allocator.free(vault_path);

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

        // Security: Resolve and validate op_path against allowlist (#66, #77)
        const op_path = try resolveOpPath(self.allocator, config.op_path);
        defer self.allocator.free(op_path);

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
    fn buildVaultEnvMap(allocator: Allocator, config: VaultConfig) SecretError!process.EnvMap {
        return buildMinimalVaultEnvMap(allocator, config);
    }

    /// Builds a minimal Vault env map with only required variables.
    fn buildMinimalVaultEnvMap(allocator: Allocator, config: VaultConfig) SecretError!process.EnvMap {
        var env_map = process.EnvMap.init(allocator);
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
    fn buildOnePasswordEnvMap(allocator: Allocator, config: OnePasswordConfig) SecretError!process.EnvMap {
        return buildMinimalOnePasswordEnvMap(allocator, config);
    }

    /// Builds a minimal 1Password env map with only required variables.
    fn buildMinimalOnePasswordEnvMap(allocator: Allocator, config: OnePasswordConfig) SecretError!process.EnvMap {
        var env_map = process.EnvMap.init(allocator);
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

    /// Execute a command and return its output
    fn execCommand(
        self: *Self,
        args: []const []const u8,
        json_field: ?[]const u8,
        env_map: ?*process.EnvMap,
        timeout_ms: u32,
    ) SecretError![]u8 {
        var child = process.Child.init(args, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.env_map = env_map;

        child.spawn() catch return SecretError.CommandFailed;

        var stdout_buf: std.ArrayList(u8) = .empty;
        var stderr_buf: std.ArrayList(u8) = .empty;
        // Security (SEC-08): Zero buffers before freeing to prevent secret leakage (CWE-316)
        defer {
            if (stdout_buf.items.len > 0) secret.secureZero(stdout_buf.items);
            stdout_buf.deinit(self.allocator);
        }
        defer {
            if (stderr_buf.items.len > 0) secret.secureZero(stderr_buf.items);
            stderr_buf.deinit(self.allocator);
        }

        var done = std.atomic.Value(bool).init(false);
        var timed_out = std.atomic.Value(bool).init(false);
        var watchdog: ?std.Thread = null;

        const TimeoutCtx = struct {
            child: *process.Child,
            done: *std.atomic.Value(bool),
            timed_out: *std.atomic.Value(bool),
            timeout_ms: u32,

            fn run(ctx: *@This()) void {
                std.Thread.sleep(@as(u64, ctx.timeout_ms) * std.time.ns_per_ms);
                if (!ctx.done.load(.acquire)) {
                    ctx.timed_out.store(true, .release);
                    _ = ctx.child.kill() catch {};
                }
            }
        };

        var timeout_ctx: TimeoutCtx = undefined;
        if (timeout_ms > 0) {
            timeout_ctx = .{
                .child = &child,
                .done = &done,
                .timed_out = &timed_out,
                .timeout_ms = timeout_ms,
            };
            watchdog = std.Thread.spawn(.{}, TimeoutCtx.run, .{&timeout_ctx}) catch null;
        }

        process.Child.collectOutput(child, self.allocator, &stdout_buf, &stderr_buf, 1024 * 1024) catch {
            done.store(true, .release);
            if (watchdog) |t| t.join();
            return SecretError.IoError;
        };

        const term = child.wait() catch {
            done.store(true, .release);
            if (watchdog) |t| t.join();
            return SecretError.CommandFailed;
        };
        done.store(true, .release);
        if (watchdog) |t| t.join();

        if (timed_out.load(.acquire)) {
            return SecretError.Timeout;
        }

        try handleTermination(term);

        const trimmed = mem.trimRight(u8, stdout_buf.items, "\n\r");
        if (json_field) |field| {
            return extractJsonField(self.allocator, trimmed, field);
        }

        return self.allocator.dupe(u8, trimmed) catch return SecretError.OutOfMemory;
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

test "env provider is denied by default (CWE-214, #84)" {
    var manager = SecretManager.init(std.testing.allocator);

    // With allow_env_provider = false (the default), env:// must return
    // InvalidConfiguration even for variables that exist (e.g. PATH).
    const result = manager.loadSecret(.{ .provider = .env, .path = "PATH" });
    try std.testing.expectError(SecretError.InvalidConfiguration, result);
}

test "env provider works when explicitly opted in (#84)" {
    var manager = SecretManager.init(std.testing.allocator);
    manager.allowEnvProvider(true);

    // PATH should exist on most systems
    if (manager.loadSecret(.{ .provider = .env, .path = "PATH" })) |value| {
        defer manager.freeSecret(value);
        try std.testing.expect(value.len > 0);
    } else |_| {
        // PATH might not exist on some systems, that's ok
    }
}

test "env provider can be re-disabled after opt-in (#84)" {
    var manager = SecretManager.init(std.testing.allocator);

    // Enable then disable
    manager.allowEnvProvider(true);
    manager.allowEnvProvider(false);

    // Should be denied again
    const result = manager.loadSecret(.{ .provider = .env, .path = "PATH" });
    try std.testing.expectError(SecretError.InvalidConfiguration, result);
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

    // Verify {f} format specifier triggers redaction (NEW-09)
    var buf: [100]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{f}", .{sensitive}) catch unreachable;

    // Should never expose the actual value
    try std.testing.expectEqualStrings("[REDACTED]", result);
    try std.testing.expect(std.mem.indexOf(u8, result, "super-secret") == null);
}

test "SensitiveString redacts via allocPrint" {
    const sensitive = SensitiveString.init("super-secret-token");

    // Verify std.fmt.allocPrint also triggers redaction (NEW-09)
    const result = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{sensitive});
    defer std.testing.allocator.free(result);

    try std.testing.expectEqualStrings("[REDACTED]", result);
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
    const key_str = std.fmt.bufPrint(&buf, "{f}", .{config.access_key_id.?}) catch unreachable;
    try std.testing.expectEqualStrings("[REDACTED]", key_str);

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
    const token_str = std.fmt.bufPrint(&buf, "{f}", .{config.token.?}) catch unreachable;
    try std.testing.expectEqualStrings("[REDACTED]", token_str);

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
    const token_str = std.fmt.bufPrint(&buf, "{f}", .{config.service_account_token.?}) catch unreachable;
    try std.testing.expectEqualStrings("[REDACTED]", token_str);
}

// ============================================================================
// Gap Closure Tests: term.Exited UB (#103)
// ============================================================================

test "handleTermination returns success for Exited 0" {
    const term = process.Child.Term{ .Exited = 0 };
    try handleTermination(term);
}

test "handleTermination returns CommandFailed for non-zero exit" {
    const term = process.Child.Term{ .Exited = 1 };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

test "handleTermination returns CommandFailed for Signal" {
    const term = process.Child.Term{ .Signal = 9 };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

test "handleTermination returns CommandFailed for Stopped" {
    const term = process.Child.Term{ .Stopped = 19 };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

test "handleTermination returns CommandFailed for Unknown" {
    const term = process.Child.Term{ .Unknown = 0 };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

// ============================================================================
// Gap Closure Tests: op PATH hijack mitigation (#77)
// ============================================================================

test "resolveOpPath rejects paths outside allowlist" {
    const allocator = std.testing.allocator;
    // A bare name "op" will try PATH lookup; it should either resolve to a valid
    // path or fail with ProviderNotAvailable. It should never return an invalid path.
    if (resolveOpPath(allocator, "op")) |resolved| {
        defer allocator.free(resolved);
        // If resolved, it must be in the allowlist
        try std.testing.expect(isValidOpPath(resolved));
    } else |err| {
        // ProviderNotAvailable is acceptable (op not installed)
        try std.testing.expect(err == SecretError.ProviderNotAvailable or err == SecretError.InvalidInputCharacters);
    }
}

test "resolveOpPath rejects malicious bare name" {
    const allocator = std.testing.allocator;
    // A bare name that does not resolve should fail
    const result = resolveOpPath(allocator, "op_fake_nonexistent_binary_xyz");
    try std.testing.expectError(SecretError.ProviderNotAvailable, result);
}

test "resolveOpPath rejects invalid absolute path" {
    const allocator = std.testing.allocator;
    const result = resolveOpPath(allocator, "/tmp/malicious_op");
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

test "resolveOpPath accepts valid absolute path" {
    const allocator = std.testing.allocator;
    // /usr/bin/op is in the allowlist; resolveOpPath should accept it
    const result = resolveOpPath(allocator, "/usr/bin/op");
    if (result) |resolved| {
        defer allocator.free(resolved);
        try std.testing.expectEqualStrings("/usr/bin/op", resolved);
    } else |_| {
        // This is OK -- the path is valid but the binary may not exist
    }
}

test "resolveVaultPath rejects paths outside allowlist" {
    const allocator = std.testing.allocator;
    const result = resolveVaultPath(allocator, "/tmp/evil_vault");
    try std.testing.expectError(SecretError.InvalidInputCharacters, result);
}

// ============================================================================
// Gap Closure Tests: isValidVaultPath strict suffix matching (SEC-07, SEC-17)
// ============================================================================

test "isValidVaultPath allows safe paths" {
    // Allowlisted system paths
    try std.testing.expect(isValidVaultPath("/usr/bin/vault"));
    try std.testing.expect(isValidVaultPath("/usr/local/bin/vault"));
    try std.testing.expect(isValidVaultPath("/opt/hashicorp/vault"));
    try std.testing.expect(isValidVaultPath("/opt/homebrew/bin/vault"));
    try std.testing.expect(isValidVaultPath("/snap/bin/vault"));

    // Home directory bin paths (strict suffix matching)
    try std.testing.expect(isValidVaultPath("/home/user/bin/vault"));
    try std.testing.expect(isValidVaultPath("/home/user/.local/bin/vault"));
    try std.testing.expect(isValidVaultPath("/Users/developer/bin/vault"));
    try std.testing.expect(isValidVaultPath("/Users/developer/.local/bin/vault"));
}

test "isValidVaultPath rejects malicious paths (SEC-07, SEC-17)" {
    // Empty path
    try std.testing.expect(!isValidVaultPath(""));

    // Arbitrary binaries
    try std.testing.expect(!isValidVaultPath("/tmp/malicious"));
    try std.testing.expect(!isValidVaultPath("/bin/sh"));

    // Nested evil paths that the old permissive check would have accepted
    try std.testing.expect(!isValidVaultPath("/home/user/projects/evil/bin/vault"));
    try std.testing.expect(!isValidVaultPath("/home/user/code/malicious/bin/vault"));
    try std.testing.expect(!isValidVaultPath("/Users/dev/work/exploit/bin/vault"));

    // Path traversal attempts
    try std.testing.expect(!isValidVaultPath("/home/user/../../../tmp/bin/vault"));
    try std.testing.expect(!isValidVaultPath("/usr/bin/../../../tmp/evil"));

    // Paths not ending exactly in /vault
    try std.testing.expect(!isValidVaultPath("/home/user/bin/vault2"));
    try std.testing.expect(!isValidVaultPath("/home/user/bin/vault.bak"));
    try std.testing.expect(!isValidVaultPath("/home/user/bin/notvault"));
}

// ============================================================================
// Gap Closure Tests: Minimal environment for child processes (#117)
// ============================================================================

test "buildMinimalVaultEnvMap contains only expected keys" {
    const allocator = std.testing.allocator;
    const config = VaultConfig{
        .address = "https://vault.example.com:8200",
        .token = SensitiveString.init("test-token"),
        .namespace = "test-ns",
        .tls_skip_verify = true,
        .timeout_ms = 5000,
    };

    var env_map = try SecretManager.buildMinimalVaultEnvMap(allocator, config);
    defer env_map.deinit();

    // Should contain the Vault-specific keys
    try std.testing.expect(env_map.get("VAULT_ADDR") != null);
    try std.testing.expect(env_map.get("VAULT_TOKEN") != null);
    try std.testing.expect(env_map.get("VAULT_NAMESPACE") != null);
    try std.testing.expect(env_map.get("VAULT_SKIP_VERIFY") != null);
    try std.testing.expect(env_map.get("VAULT_CLIENT_TIMEOUT") != null);
    try std.testing.expect(env_map.get("PATH") != null);
    try std.testing.expect(env_map.get("HOME") != null);

    // Count total keys - should be exactly the ones we expect
    var count: usize = 0;
    var it = env_map.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    // PATH + HOME + VAULT_ADDR + VAULT_TOKEN + VAULT_NAMESPACE + VAULT_SKIP_VERIFY + VAULT_CLIENT_TIMEOUT = 7
    try std.testing.expectEqual(@as(usize, 7), count);
}

test "buildMinimalVaultEnvMap omits optional fields when not set" {
    const allocator = std.testing.allocator;
    const config = VaultConfig{
        .address = "https://127.0.0.1:8200",
        .timeout_ms = 0,
    };

    var env_map = try SecretManager.buildMinimalVaultEnvMap(allocator, config);
    defer env_map.deinit();

    // Should have only PATH + HOME + VAULT_ADDR
    try std.testing.expect(env_map.get("VAULT_ADDR") != null);
    try std.testing.expect(env_map.get("PATH") != null);
    try std.testing.expect(env_map.get("HOME") != null);
    try std.testing.expect(env_map.get("VAULT_TOKEN") == null);
    try std.testing.expect(env_map.get("VAULT_NAMESPACE") == null);
    try std.testing.expect(env_map.get("VAULT_SKIP_VERIFY") == null);
    try std.testing.expect(env_map.get("VAULT_CLIENT_TIMEOUT") == null);

    var count: usize = 0;
    var it = env_map.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "buildMinimalOnePasswordEnvMap contains only expected keys" {
    const allocator = std.testing.allocator;
    const config = OnePasswordConfig{
        .account = "team.1password.com",
        .service_account_token = SensitiveString.init("ops_test_token"),
    };

    var env_map = try SecretManager.buildMinimalOnePasswordEnvMap(allocator, config);
    defer env_map.deinit();

    try std.testing.expect(env_map.get("OP_ACCOUNT") != null);
    try std.testing.expect(env_map.get("OP_SERVICE_ACCOUNT_TOKEN") != null);
    try std.testing.expect(env_map.get("PATH") != null);
    try std.testing.expect(env_map.get("HOME") != null);

    var count: usize = 0;
    var it = env_map.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    // PATH + HOME + OP_ACCOUNT + OP_SERVICE_ACCOUNT_TOKEN = 4
    try std.testing.expectEqual(@as(usize, 4), count);
}

test "buildMinimalOnePasswordEnvMap omits optional fields when not set" {
    const allocator = std.testing.allocator;
    const config = OnePasswordConfig{};

    var env_map = try SecretManager.buildMinimalOnePasswordEnvMap(allocator, config);
    defer env_map.deinit();

    // Should have only PATH + HOME
    try std.testing.expect(env_map.get("PATH") != null);
    try std.testing.expect(env_map.get("HOME") != null);
    try std.testing.expect(env_map.get("OP_ACCOUNT") == null);
    try std.testing.expect(env_map.get("OP_SERVICE_ACCOUNT_TOKEN") == null);

    var count: usize = 0;
    var it = env_map.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}
