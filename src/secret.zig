// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Secret Module
//!
//! Secure handling of secrets - enforces reading from files or stdin only.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;
const environ = @import("environ.zig");

/// Secret loading errors
pub const SecretError = error{
    /// Secret was provided via flag or environment (not allowed)
    SecretInFlagOrEnv,
    /// Secret file not found
    FileNotFound,
    /// Secret file read error
    ReadError,
    /// Invalid secret format
    InvalidFormat,
    /// Stdin not available
    StdinNotAvailable,
    /// Path traversal attempt detected (security violation)
    PathTraversalDetected,
    /// Symlink detected when follow_symlinks is false (security violation, CWE-59, #69)
    SymlinkNotAllowed,
};

/// Check if a path is a symbolic link.
/// Security: Used to prevent symlink following attacks (CWE-59, #69)
/// Note: Uses fstatat with SYMLINK_NOFOLLOW to detect symlinks without following them.
pub fn isSymlink(path: []const u8) bool {
    if (comptime builtin.os.tag == .windows) {
        // Windows: use std.fs to check for symlinks.
        // Security (SEC-06): This stat-then-open pattern has a TOCTOU race window
        // on Windows. Between the stat check here and the subsequent file open in
        // openFileReadNoFollow/createFileNoFollow, the file could be replaced with
        // a symlink. POSIX avoids this via O_NOFOLLOW which is atomic, but Windows
        // lacks an equivalent. Accepted risk: the window is narrow and exploitation
        // requires local filesystem access. For high-security deployments, consider
        // placing secret files on a dedicated volume with restricted permissions.
        const md = std.Io.Dir.cwd().statFile(path) catch return false;
        return md.kind == .sym_link;
    }
    const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch {
        return false; // If we can't stat, assume not a symlink (file may not exist)
    };
    return stat.mode & std.posix.S.IFMT == std.posix.S.IFLNK;
}

/// Validate a path does not contain path traversal sequences.
/// Returns true if path is safe, false if traversal detected.
/// Security: Prevents CWE-22 path traversal attacks.
/// Note: The ".." check covers both POSIX "../" and Windows "..\\" traversal
/// patterns since ".." is a common prefix of both (SEC-05).
pub fn isPathSafe(path: []const u8) bool {
    // Check for ".." anywhere in the path (covers both "../" and "..\" variants)
    if (mem.indexOf(u8, path, "..") != null) {
        return false;
    }

    // Check for null bytes (path truncation attack)
    if (mem.indexOf(u8, path, "\x00") != null) {
        return false;
    }

    return true;
}

/// Stricter path safety check that rejects both `..` traversal **and**
/// absolute paths.
///
/// Returns `true` only when all of the following hold:
///   1. No `..` traversal sequences (delegated to `isPathSafe`).
///   2. No null bytes (delegated to `isPathSafe`).
///   3. Path does not start with `/` (POSIX absolute).
///   4. Path does not match a Windows drive-letter prefix (e.g., `C:\`).
///
/// **Difference from `isPathSafe`:** `isPathSafe` permits absolute paths
/// such as `/etc/config.toml`; this function rejects them so that only
/// relative, non-traversal paths are accepted.
///
/// **Use case:** Contexts where configuration paths must be confined to a
/// subtree and absolute paths should not be trusted (e.g., user-supplied
/// include directives).
///
/// Security: Prevents CWE-22 path traversal and restricts to relative paths only.
pub fn isPathSafeStrict(path: []const u8) bool {
    if (!isPathSafe(path)) {
        return false;
    }

    // Reject absolute paths (Unix-style leading '/' or Windows-style like C:\)
    if (path.len > 0 and path[0] == '/') {
        return false;
    }

    // Reject Windows-style absolute paths (e.g., "C:\", "D:/")
    if (path.len >= 3 and std.ascii.isAlphabetic(path[0]) and path[1] == ':' and (path[2] == '\\' or path[2] == '/')) {
        return false;
    }

    return true;
}

/// Errors returned by no-follow file helpers.
pub const OpenNoFollowError = error{SymlinkNotAllowed} || std.posix.OpenError || std.Io.File.OpenError;

/// Open a file for read-only access without following symlinks when supported.
/// On Windows, falls back to an explicit symlink check.
/// Security (SEC-06): On Windows, the stat-then-open pattern used here has a
/// TOCTOU race window. See isSymlink documentation for details. POSIX uses
/// O_NOFOLLOW for atomic symlink rejection.
pub fn openFileReadNoFollow(path: []const u8) OpenNoFollowError!std.Io.File {
    if (builtin.os.tag == .windows) {
        // Security (SEC-06): TOCTOU window between isSymlink check and openFile.
        // See isSymlink for full risk assessment and mitigations.
        if (isSymlink(path)) return error.SymlinkNotAllowed;
        return std.Io.Dir.cwd().openFile(path, .{});
    }

    const fd = std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    ) catch |err| switch (err) {
        error.SymLinkLoop => return error.SymlinkNotAllowed,
        else => return err,
    };
    return std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
}

/// Create a file without following symlinks when supported.
/// When `exclusive` is true, fail if the path already exists.
/// Security (SEC-06): On Windows, same TOCTOU caveat as openFileReadNoFollow.
pub fn createFileNoFollow(path: []const u8, mode: std.posix.mode_t, exclusive: bool) OpenNoFollowError!std.Io.File {
    if (builtin.os.tag == .windows) {
        // Security (SEC-06): TOCTOU window between isSymlink check and createFile.
        // See isSymlink for full risk assessment and mitigations.
        if (isSymlink(path)) return error.SymlinkNotAllowed;
        return std.Io.Dir.cwd().createFile(path, .{ .mode = mode, .exclusive = exclusive });
    }

    var flags = std.posix.O{ .ACCMODE = .WRONLY, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true };
    if (exclusive) {
        flags.EXCL = true;
    } else {
        flags.TRUNC = true;
    }

    const fd = std.posix.openat(std.posix.AT.FDCWD, path, flags, mode) catch |err| switch (err) {
        error.SymLinkLoop => return error.SymlinkNotAllowed,
        else => return err,
    };
    return std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
}

/// Read a secret from a file
/// Security: Validates path to prevent directory traversal (CWE-22)
pub fn readFromFile(path: []const u8, allocator: Allocator) SecretError![]const u8 {
    return readFromFileWithOptions(path, allocator, .{});
}

/// Options for secure file reading
pub const ReadOptions = struct {
    /// Skip path traversal validation (use with extreme caution)
    skip_traversal_check: bool = false,
    /// Allow following symlinks (SECURITY: disabled by default to prevent symlink attacks, CWE-59, #69)
    follow_symlinks: bool = false,
};

/// Read a secret from a file with options
/// Security: Validates path to prevent directory traversal (CWE-22)
pub fn readFromFileWithOptions(path: []const u8, allocator: Allocator, options: ReadOptions) SecretError![]const u8 {
    // Security: Validate path does not contain traversal sequences
    if (!options.skip_traversal_check) {
        if (!isPathSafe(path)) {
            return SecretError.PathTraversalDetected;
        }
    }

    const file = if (options.follow_symlinks)
        std.Io.Dir.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return SecretError.FileNotFound,
            else => return SecretError.ReadError,
        }
    else
        openFileReadNoFollow(path) catch |err| switch (err) {
            error.SymlinkNotAllowed => return SecretError.SymlinkNotAllowed,
            error.FileNotFound => return SecretError.FileNotFound,
            else => return SecretError.ReadError,
        };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 64 * 1024) catch {
        return SecretError.ReadError;
    };

    // Trim trailing newlines -- mem.trim returns a sub-slice of the original,
    // so we must dupe the trimmed result and free the original to avoid a
    // pointer-mismatch leak (the caller cannot free the original allocation
    // through the trimmed sub-slice).
    const trimmed = mem.trim(u8, content, "\n\r");
    const result = allocator.dupe(u8, trimmed) catch {
        allocator.free(content);
        return SecretError.ReadError;
    };

    // Security: zero out the original buffer before freeing to prevent
    // secret data from lingering in freed memory.
    secureZero(content);
    allocator.free(content);

    return result;
}

/// Read a secret from stdin
pub fn readFromStdin(allocator: Allocator) SecretError![]const u8 {
    const stdin = std.io.getStdIn();

    // Check if stdin is a pipe or has data
    if (stdin.isTty()) {
        // Interactive mode - prompt for input
        const stderr = std.io.getStdErr().writer();
        stderr.print("Enter secret: ", .{}) catch {};

        const content = stdin.reader().readUntilDelimiterAlloc(allocator, '\n', 64 * 1024) catch {
            return SecretError.StdinNotAvailable;
        };

        // Security: Same trim-dupe-zero pattern as the pipe path.
        // Zero the original buffer to prevent secret data lingering in freed memory.
        const trimmed = mem.trim(u8, content, "\n\r");
        const result = allocator.dupe(u8, trimmed) catch {
            secureZero(content);
            allocator.free(content);
            return SecretError.StdinNotAvailable;
        };

        secureZero(content);
        allocator.free(content);

        return result;
    } else {
        // Pipe mode - read all
        const content = stdin.readToEndAlloc(allocator, 64 * 1024) catch {
            return SecretError.StdinNotAvailable;
        };

        // Same mem.trim fix as readFromFileWithOptions: dupe the trimmed
        // result and free the original to avoid pointer-mismatch leak.
        const trimmed = mem.trim(u8, content, "\n\r");
        const result = allocator.dupe(u8, trimmed) catch {
            allocator.free(content);
            return SecretError.StdinNotAvailable;
        };

        secureZero(content);
        allocator.free(content);

        return result;
    }
}

/// Validate that a secret was not provided via flag or environment
pub fn validateNotInFlagOrEnv(flag_value: ?[]const u8, env_name: []const u8) SecretError!void {
    if (flag_value != null) {
        return SecretError.SecretInFlagOrEnv;
    }

    if (environ.getenv(env_name) != null) {
        return SecretError.SecretInFlagOrEnv;
    }
}

/// Redact a secret value for display (e.g., in logs)
pub fn redact(value: []const u8) []const u8 {
    _ = value;
    return "***REDACTED***";
}

/// Securely zero memory containing a secret
pub fn secureZero(buffer: []u8) void {
    // Use volatile write to prevent optimization
    for (buffer) |*byte| {
        @as(*volatile u8, byte).* = 0;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "redact hides secret" {
    const redacted = redact("super-secret-password");
    try std.testing.expectEqualStrings("***REDACTED***", redacted);
}

test "secureZero clears buffer" {
    var buffer = [_]u8{ 's', 'e', 'c', 'r', 'e', 't' };
    secureZero(&buffer);

    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "secureZero clears heap-allocated buffer (readFromStdin pattern)" {
    // Validates the same trim-dupe-zero pattern used in readFromStdin
    // for both interactive and pipe paths: allocate, dupe trimmed result,
    // secureZero original, then free original.
    const allocator = std.testing.allocator;
    const original = try allocator.dupe(u8, "my-secret\n\r");

    // Simulate the trim-dupe-zero pattern from readFromStdin
    const trimmed = mem.trim(u8, original, "\n\r");
    const result = try allocator.dupe(u8, trimmed);
    defer allocator.free(result);

    // Zero original before freeing (the security-critical step)
    secureZero(original);

    // Verify every byte of the original is zeroed before freeing
    for (original) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }

    allocator.free(original);

    // Verify the duped result still holds the trimmed secret
    try std.testing.expectEqualStrings("my-secret", result);
}

test "isPathSafe rejects path traversal" {
    // Should reject paths with ".."
    try std.testing.expect(!isPathSafe("../etc/passwd"));
    try std.testing.expect(!isPathSafe("foo/../bar"));
    try std.testing.expect(!isPathSafe("foo/bar/.."));
    try std.testing.expect(!isPathSafe(".."));
    try std.testing.expect(!isPathSafe("/etc/../passwd"));

    // Should reject null bytes
    try std.testing.expect(!isPathSafe("foo\x00bar"));

    // Should allow safe paths
    try std.testing.expect(isPathSafe("/etc/secrets/db_password"));
    try std.testing.expect(isPathSafe("secrets/password.txt"));
    try std.testing.expect(isPathSafe("/run/secrets/token"));
    try std.testing.expect(isPathSafe("./config.toml"));
}

test "readFromFile rejects path traversal" {
    const result = readFromFile("../../../etc/passwd", std.testing.allocator);
    try std.testing.expectError(SecretError.PathTraversalDetected, result);
}

test "readFromFile rejects null byte injection" {
    const result = readFromFile("/etc/passwd\x00.txt", std.testing.allocator);
    try std.testing.expectError(SecretError.PathTraversalDetected, result);
}

test "isSymlink detects regular files as non-symlinks" {
    // Test with a regular file that exists
    const result = isSymlink("/etc/passwd");
    try std.testing.expect(!result); // /etc/passwd is typically a regular file
}

test "isSymlink returns false for non-existent files" {
    const result = isSymlink("/nonexistent/path/that/does/not/exist");
    try std.testing.expect(!result);
}

test "readFromFile returned slice can be freed without leak (mem.trim fix)" {
    // Create a temporary file with trailing newlines
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content_with_newlines = "my-secret-value\n\r\n";
    const file = try tmp_dir.dir.createFile("secret.txt", .{});
    try file.writeAll(content_with_newlines);
    file.close();

    // Use the real path so readFromFileWithOptions can open it
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "secret.txt");
    defer std.testing.allocator.free(path);

    // Read the secret -- std.testing.allocator will detect leaks if the
    // original readToEndAlloc buffer is not properly freed.
    const secret = try readFromFileWithOptions(path, std.testing.allocator, .{
        .skip_traversal_check = true,
        .follow_symlinks = true,
    });
    defer std.testing.allocator.free(secret);

    // The trimmed result should not contain trailing newlines
    try std.testing.expectEqualStrings("my-secret-value", secret);
}

test "readFromFile trims and returns correct content for file without trailing newlines" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content_no_newlines = "exact-secret";
    const file = try tmp_dir.dir.createFile("secret2.txt", .{});
    try file.writeAll(content_no_newlines);
    file.close();

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "secret2.txt");
    defer std.testing.allocator.free(path);

    const secret = try readFromFileWithOptions(path, std.testing.allocator, .{
        .skip_traversal_check = true,
        .follow_symlinks = true,
    });
    defer std.testing.allocator.free(secret);

    try std.testing.expectEqualStrings("exact-secret", secret);
}

test "isPathSafe allows absolute paths (backward compatibility)" {
    // isPathSafe should still allow absolute paths for backward compatibility
    try std.testing.expect(isPathSafe("/etc/passwd"));
    try std.testing.expect(isPathSafe("/run/secrets/token"));
    try std.testing.expect(isPathSafe("/home/user/.config/secret"));
}

test "isPathSafeStrict rejects absolute paths" {
    // Unix-style absolute paths
    try std.testing.expect(!isPathSafeStrict("/etc/passwd"));
    try std.testing.expect(!isPathSafeStrict("/run/secrets/token"));
    try std.testing.expect(!isPathSafeStrict("/home/user/.config/secret"));

    // Windows-style absolute paths
    try std.testing.expect(!isPathSafeStrict("C:\\Windows\\System32"));
    try std.testing.expect(!isPathSafeStrict("D:/data/config"));

    // Should still reject traversal and null bytes
    try std.testing.expect(!isPathSafeStrict("../etc/passwd"));
    try std.testing.expect(!isPathSafeStrict("foo\x00bar"));

    // Should allow safe relative paths
    try std.testing.expect(isPathSafeStrict("secrets/password.txt"));
    try std.testing.expect(isPathSafeStrict("./config.toml"));
    try std.testing.expect(isPathSafeStrict("data/secret.key"));
}

test "isPathSafe rejects Windows-style backslash traversal (SEC-05)" {
    // Windows-style "..\\" traversal is caught by the ".." check
    try std.testing.expect(!isPathSafe("..\\Windows\\System32"));
    try std.testing.expect(!isPathSafe("foo\\..\\bar"));
    try std.testing.expect(!isPathSafe("foo\\bar\\.."));
    // Mixed separators
    try std.testing.expect(!isPathSafe("foo/..\\bar"));
    try std.testing.expect(!isPathSafe("foo\\../bar"));
}

test "readFromFile rejects Windows-style backslash traversal (SEC-05)" {
    const result = readFromFile("..\\..\\..\\Windows\\System32\\config\\SAM", std.testing.allocator);
    try std.testing.expectError(SecretError.PathTraversalDetected, result);
}
