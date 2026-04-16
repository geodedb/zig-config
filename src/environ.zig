// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Cross-Platform Environment Variable Module
//!
//! Provides cross-platform wrappers for reading environment variables.
//!
//! On POSIX systems, `getenv` returns a borrowed slice directly from the
//! C environment block (zero allocation). On Windows, `std.posix.getenv`
//! does not exist, so an allocating `getEnvOwned` must be used instead.
//!
//! ## Functions
//!
//! - `getenv` -- Zero-allocation lookup (POSIX only; compile error on Windows)
//! - `getEnvOwned` -- Allocating lookup that works on all platforms
//!
//! ## Usage
//!
//! ```zig
//! const environ = @import("environ.zig");
//!
//! // Preferred: works everywhere, caller must free
//! if (environ.getEnvOwned(allocator, "HOME")) |home| {
//!     defer allocator.free(home);
//!     // use home
//! }
//!
//! // POSIX-only: zero allocation
//! if (comptime !environ.is_windows) {
//!     if (environ.getenv("HOME")) |home| {
//!         // use home (borrowed, do not free)
//!     }
//! }
//! ```

const std = @import("std");
const builtin = @import("builtin");

/// True when compiling for Windows.
pub const is_windows = builtin.os.tag == .windows;

/// Look up an environment variable without allocating.
///
/// Returns a borrowed slice that points into the process environment block.
/// **POSIX only** -- calling this on Windows is a compile error because
/// `std.posix.getenv` does not exist on Windows.
///
/// For a cross-platform alternative, use `getEnvOwned`.
pub fn getenv(key: []const u8) ?[]const u8 {
    if (comptime is_windows) {
        @compileError("environ.getenv is not available on Windows; use environ.getEnvOwned instead");
    }
    // Zig 0.16 compat: std.posix.getenv was removed; use std.c.getenv with
    // null-terminated key. Stack buffer avoids allocation for typical env names.
    var buf: [256]u8 = undefined;
    if (key.len >= buf.len) return null;
    @memcpy(buf[0..key.len], key);
    buf[key.len] = 0;
    const key_z: [*:0]const u8 = buf[0..key.len :0];
    return if (std.c.getenv(key_z)) |p| std.mem.span(p) else null;
}

/// Look up an environment variable and return an owned copy.
///
/// Works on all platforms:
/// - **POSIX**: calls `std.posix.getenv` and duplicates the result
/// - **Windows**: calls `std.process.getEnvVarOwned`
///
/// Returns `null` if the variable is not set.
/// Caller is responsible for freeing the returned slice with `allocator`.
pub fn getEnvOwned(allocator: std.mem.Allocator, key: []const u8) ?[]u8 {
    if (comptime is_windows) {
        return std.process.getEnvVarOwned(allocator, key) catch null;
    } else {
        const val = getenv(key) orelse return null;
        return allocator.dupe(u8, val) catch null;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "getenv returns PATH on POSIX" {
    if (comptime is_windows) return error.SkipZigTest;
    // PATH should exist on any POSIX system
    const path = getenv("PATH");
    try std.testing.expect(path != null);
    try std.testing.expect(path.?.len > 0);
}

test "getenv returns null for undefined variable" {
    if (comptime is_windows) return error.SkipZigTest;
    const result = getenv("ZIGCONFIG_UNDEFINED_TEST_VARIABLE_99999");
    try std.testing.expect(result == null);
}

test "getEnvOwned returns PATH" {
    const path = getEnvOwned(std.testing.allocator, "PATH");
    if (path) |p| {
        defer std.testing.allocator.free(p);
        try std.testing.expect(p.len > 0);
    }
}

test "getEnvOwned returns null for undefined variable" {
    const result = getEnvOwned(std.testing.allocator, "ZIGCONFIG_UNDEFINED_TEST_VARIABLE_99999");
    try std.testing.expect(result == null);
}

test "getEnvOwned returns owned copy" {
    if (comptime is_windows) return error.SkipZigTest;
    // Verify the returned slice is a copy, not the same pointer as getenv
    const borrowed = getenv("PATH") orelse return;
    const owned = getEnvOwned(std.testing.allocator, "PATH") orelse return;
    defer std.testing.allocator.free(owned);

    // Same content
    try std.testing.expectEqualStrings(borrowed, owned);
    // Different pointers (owned is a copy)
    try std.testing.expect(borrowed.ptr != owned.ptr);
}
