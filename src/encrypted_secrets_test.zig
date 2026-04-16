// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Companion tests for encrypted_secrets.zig.
//! Extracted to reduce encrypted_secrets.zig to production code only (Q-NEW-6).

const std = @import("std");
const process = std.process;
const es = @import("encrypted_secrets.zig");

// Re-export types used in tests so test bodies stay unchanged.
const Provider = es.Provider;
const SecretManager = es.SecretManager;
const SecretError = es.SecretError;
const SensitiveString = es.SensitiveString;
const KmsConfig = es.KmsConfig;
const VaultConfig = es.VaultConfig;
const OnePasswordConfig = es.OnePasswordConfig;
const isValidSecretIdentifier = es.isValidSecretIdentifier;
const isValidOpPath = es.isValidOpPath;
const isValidVaultPath = es.isValidVaultPath;
const resolveOpPath = es.resolveOpPath;
const resolveVaultPath = es.resolveVaultPath;
const handleTermination = es.handleTermination;

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
    const term = process.Child.Term{ .exited = 0 };
    try handleTermination(term);
}

test "handleTermination returns CommandFailed for non-zero exit" {
    const term = process.Child.Term{ .exited = 1 };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

test "handleTermination returns CommandFailed for Signal" {
    const term = process.Child.Term{ .signal = .KILL };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

test "handleTermination returns CommandFailed for Stopped" {
    const term = process.Child.Term{ .stopped = .STOP };
    try std.testing.expectError(SecretError.CommandFailed, handleTermination(term));
}

test "handleTermination returns CommandFailed for Unknown" {
    const term = process.Child.Term{ .unknown = 0 };
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
