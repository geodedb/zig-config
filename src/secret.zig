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
    const stat = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch {
        return false; // If we can't stat, assume not a symlink (file may not exist)
    };
    return stat.mode & std.posix.S.IFMT == std.posix.S.IFLNK;
}

/// Validate a path does not contain path traversal sequences.
/// Returns true if path is safe, false if traversal detected.
/// Security: Prevents CWE-22 path traversal attacks.
pub fn isPathSafe(path: []const u8) bool {
    // Check for ".." anywhere in the path
    if (mem.indexOf(u8, path, "..") != null) {
        return false;
    }

    // Check for null bytes (path truncation attack)
    if (mem.indexOf(u8, path, "\x00") != null) {
        return false;
    }

    return true;
}

/// Errors returned by no-follow file helpers.
pub const OpenNoFollowError = error{SymlinkNotAllowed} || std.posix.OpenError || fs.File.OpenError;

/// Open a file for read-only access without following symlinks when supported.
/// On Windows, falls back to an explicit symlink check.
pub fn openFileReadNoFollow(path: []const u8) OpenNoFollowError!fs.File {
    if (builtin.os.tag == .windows) {
        if (isSymlink(path)) return error.SymlinkNotAllowed;
        return fs.cwd().openFile(path, .{});
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
    return fs.File{ .handle = fd };
}

/// Create a file without following symlinks when supported.
/// When `exclusive` is true, fail if the path already exists.
pub fn createFileNoFollow(path: []const u8, mode: std.posix.mode_t, exclusive: bool) OpenNoFollowError!fs.File {
    if (builtin.os.tag == .windows) {
        if (isSymlink(path)) return error.SymlinkNotAllowed;
        return fs.cwd().createFile(path, .{ .mode = mode, .exclusive = exclusive });
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
    return fs.File{ .handle = fd };
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
        fs.cwd().openFile(path, .{}) catch |err| switch (err) {
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

    // Trim trailing newlines
    return mem.trim(u8, content, "\n\r");
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

        return content;
    } else {
        // Pipe mode - read all
        const content = stdin.readToEndAlloc(allocator, 64 * 1024) catch {
            return SecretError.StdinNotAvailable;
        };

        return mem.trim(u8, content, "\n\r");
    }
}

/// Validate that a secret was not provided via flag or environment
pub fn validateNotInFlagOrEnv(flag_value: ?[]const u8, env_name: []const u8) SecretError!void {
    if (flag_value != null) {
        return SecretError.SecretInFlagOrEnv;
    }

    if (std.posix.getenv(env_name) != null) {
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
