// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Dotenv Module
//!
//! Loads environment variables from .env files.
//! Note: This is for convenience only and should not be used for secrets.

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;
const environ = @import("environ.zig");
const secret = @import("secret.zig");
const limits = @import("limits.zig");

// Security: Import helpers for symlink and path traversal protection (CWE-59, CWE-22, #72, #74)
const isPathSafe = secret.isPathSafe;
const openFileReadNoFollow = secret.openFileReadNoFollow;

/// Environment variable entry.
/// When returned by `load()`, the `.key` and `.value` slices are independently
/// allocated and must be freed via `freeEntries()`.
/// When returned by `parseContent()`, the slices borrow from the `content`
/// parameter and are only valid for the lifetime of that buffer.
pub const EnvEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// Free an owned `EnvEntry` slice returned by `load()`.
/// This frees each entry's `.key` and `.value` allocations, then frees the
/// slice itself. Do **not** call this on slices returned by `parseContent()`,
/// whose entries borrow from the caller-supplied content buffer.
pub fn freeEntries(entries: []const EnvEntry, allocator: Allocator) void {
    for (entries) |entry| {
        allocator.free(entry.key);
        allocator.free(entry.value);
    }
    allocator.free(entries);
}

/// Load environment variables from a .env file.
/// The caller owns the returned slice and every `.key`/`.value` within it.
/// Free with `freeEntries(entries, allocator)` when done.
/// Security: Validates path and rejects symlinks (CWE-22, CWE-59, #72, #74)
pub fn load(path: []const u8, allocator: Allocator) ![]EnvEntry {
    // Security: Validate path does not contain traversal sequences (CWE-22, #74)
    if (!isPathSafe(path)) {
        return try allocator.alloc(EnvEntry, 0);
    }

    const file = openFileReadNoFollow(path) catch {
        return try allocator.alloc(EnvEntry, 0);
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, limits.MAX_DOTENV_FILE_SIZE) catch {
        return try allocator.alloc(EnvEntry, 0);
    };
    defer allocator.free(content);

    // Delegate parsing to the canonical parseContent implementation (NEW-01).
    // The returned entries borrow from `content`, which is about to be freed,
    // so we must dupe every key and value into owned allocations (NEW-12).
    const borrowed = try parseContent(content, allocator);
    defer allocator.free(borrowed);

    var owned: std.ArrayList(EnvEntry) = .empty;
    errdefer {
        // On error, free any entries we already duped.
        for (owned.items) |entry| {
            allocator.free(entry.key);
            allocator.free(entry.value);
        }
        owned.deinit(allocator);
    }
    // INFO-5: Pre-allocate capacity since borrowed entry count is known
    try owned.ensureTotalCapacity(allocator, @intCast(borrowed.len));

    for (borrowed) |entry| {
        const owned_key = try allocator.dupe(u8, entry.key);
        errdefer allocator.free(owned_key);
        const owned_value = try allocator.dupe(u8, entry.value);
        try owned.append(allocator, .{
            .key = owned_key,
            .value = owned_value,
        });
    }

    return owned.toOwnedSlice(allocator);
}

/// Environment map for looking up dotenv values
/// Use this to apply dotenv values to your application
pub const EnvMap = struct {
    entries: std.StringHashMap([]const u8),
    allocator: Allocator,

    const Self = @This();

    /// Create an EnvMap from parsed entries
    pub fn init(allocator: Allocator) Self {
        return .{
            .entries = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Deinitialize the map, freeing all allocated keys and values
    pub fn deinit(self: *Self) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit();
    }

    /// Get a value by key
    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        return self.entries.get(key);
    }

    /// Get a value, falling back to actual environment variable
    pub fn getOrEnv(self: *const Self, key: []const u8) ?[]const u8 {
        if (self.entries.get(key)) |value| {
            return value;
        }
        return environ.getenv(key);
    }

    /// Check if a key exists
    pub fn has(self: *const Self, key: []const u8) bool {
        return self.entries.contains(key);
    }

    /// Get number of entries
    pub fn count(self: *const Self) usize {
        return self.entries.count();
    }

    /// Iterator over all entries
    pub fn iterator(self: *const Self) std.StringHashMap([]const u8).Iterator {
        return self.entries.iterator();
    }
};

/// Load and apply dotenv file, returning an EnvMap for lookups
/// This is the recommended way to use dotenv values
/// Security: Validates path and rejects symlinks (CWE-22, CWE-59, #72, #74)
pub fn loadAndApply(path: []const u8, allocator: Allocator) !EnvMap {
    var map = EnvMap.init(allocator);
    errdefer map.deinit();

    // Security: Validate path does not contain traversal sequences (CWE-22, #74)
    if (!isPathSafe(path)) {
        return map; // Return empty map for security violations
    }

    const file = openFileReadNoFollow(path) catch {
        return map; // Return empty map if file doesn't exist
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, limits.MAX_DOTENV_FILE_SIZE);
    defer allocator.free(content);

    try applyContent(&map, content);
    return map;
}

/// Apply parsed content to an EnvMap.
/// Delegates to `parseContent()` for the actual line parsing, then dupes
/// each entry's key and value into owned allocations stored in the map.
pub fn applyContent(map: *EnvMap, content: []const u8) !void {
    // Delegate to the canonical parser (NEW-01: single source of truth).
    const entries = try parseContent(content, map.allocator);
    defer map.allocator.free(entries);

    for (entries) |entry| {
        const owned_key = try map.allocator.dupe(u8, entry.key);
        errdefer map.allocator.free(owned_key);
        const owned_value = try map.allocator.dupe(u8, entry.value);
        try map.entries.put(owned_key, owned_value);
    }
}

/// Apply loaded entries to an EnvMap
/// This creates a lookup map from parsed entries
pub fn apply(entries: []const EnvEntry, allocator: Allocator) !EnvMap {
    var map = EnvMap.init(allocator);
    errdefer map.deinit();

    for (entries) |entry| {
        const owned_key = try allocator.dupe(u8, entry.key);
        const owned_value = try allocator.dupe(u8, entry.value);
        try map.entries.put(owned_key, owned_value);
    }

    return map;
}

/// Parse .env content directly (useful for testing and internal delegation).
///
/// **Lifetime:** The returned `EnvEntry` slices (`.key` and `.value`) are
/// sub-slices of `content`. They do **not** own their memory and are only
/// valid for as long as `content` remains alive and unmodified. If you need
/// entries that outlive the content buffer, use `load()` (which returns owned
/// copies) or dupe the slices yourself.
///
/// The caller owns the returned slice itself (allocated via `allocator`) and
/// must free it with `allocator.free(entries)`. Do **not** use `freeEntries()`
/// on the result of this function -- that is only for slices from `load()`.
pub fn parseContent(content: []const u8, allocator: Allocator) ![]EnvEntry {
    var entries: std.ArrayList(EnvEntry) = .empty;

    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Skip export prefix if present
        var key_start: usize = 0;
        if (mem.startsWith(u8, trimmed, "export ")) {
            key_start = 7;
        }

        const eq_pos = mem.indexOf(u8, trimmed[key_start..], "=") orelse continue;
        const key = mem.trim(u8, trimmed[key_start .. key_start + eq_pos], " \t");
        var value = mem.trim(u8, trimmed[key_start + eq_pos + 1 ..], " \t");

        // Remove quotes
        if (value.len >= 2) {
            if ((value[0] == '"' and value[value.len - 1] == '"') or
                (value[0] == '\'' and value[value.len - 1] == '\''))
            {
                value = value[1 .. value.len - 1];
            }
        }

        try entries.append(allocator, .{
            .key = key,
            .value = value,
        });
    }

    return entries.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "dotenv: load nonexistent file returns empty" {
    const entries = try load("nonexistent.env", std.testing.allocator);
    defer freeEntries(entries, std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "dotenv: parse simple key-value pairs" {
    const content =
        \\HOST=localhost
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
    try std.testing.expectEqualStrings("PORT", entries[1].key);
    try std.testing.expectEqualStrings("8080", entries[1].value);
}

test "dotenv: parse double quoted values" {
    const content =
        \\NAME="Hello World"
        \\PATH="/usr/local/bin"
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("Hello World", entries[0].value);
    try std.testing.expectEqualStrings("/usr/local/bin", entries[1].value);
}

test "dotenv: parse single quoted values" {
    const content =
        \\NAME='literal string'
        \\REGEX='[a-z]+'
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("literal string", entries[0].value);
    try std.testing.expectEqualStrings("[a-z]+", entries[1].value);
}

test "dotenv: skip comments" {
    const content =
        \\# This is a comment
        \\HOST=localhost
        \\# Another comment
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "dotenv: skip empty lines" {
    const content =
        \\HOST=localhost
        \\
        \\
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "dotenv: handle export prefix" {
    const content =
        \\export HOST=localhost
        \\export PORT=8080
        \\NAME=test
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
    try std.testing.expectEqualStrings("PORT", entries[1].key);
    try std.testing.expectEqualStrings("NAME", entries[2].key);
}

test "dotenv: handle whitespace around equals" {
    const content =
        \\HOST = localhost
        \\PORT=8080
        \\NAME  =  test
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
}

test "dotenv: parse empty content returns empty" {
    const content = "";

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "dotenv: only comments returns empty" {
    const content =
        \\# Comment 1
        \\# Comment 2
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "dotenv: skip lines without equals" {
    const content =
        \\HOST=localhost
        \\invalid line without equals
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "dotenv: parse real-world .env file" {
    const content =
        \\# Database configuration
        \\DB_HOST=localhost
        \\DB_PORT=5432
        \\DB_NAME="myapp_production"
        \\DB_USER=admin
        \\DB_PASSWORD='super$ecret!'
        \\
        \\# Application settings
        \\export APP_ENV=production
        \\export DEBUG=false
        \\LOG_LEVEL=info
        \\
        \\# API keys
        \\API_KEY="abc123def456"
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 9), entries.len);

    // Check some specific values
    try std.testing.expectEqualStrings("DB_HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
    try std.testing.expectEqualStrings("DB_NAME", entries[2].key);
    try std.testing.expectEqualStrings("myapp_production", entries[2].value);
    try std.testing.expectEqualStrings("DB_PASSWORD", entries[4].key);
    try std.testing.expectEqualStrings("super$ecret!", entries[4].value);
}

test "dotenv: apply creates EnvMap" {
    const entries = [_]EnvEntry{
        .{ .key = "HOST", .value = "localhost" },
        .{ .key = "PORT", .value = "8080" },
    };

    var map = try apply(&entries, std.testing.allocator);
    defer map.deinit();

    try std.testing.expectEqual(@as(usize, 2), map.count());
    try std.testing.expectEqualStrings("localhost", map.get("HOST").?);
    try std.testing.expectEqualStrings("8080", map.get("PORT").?);
}

test "dotenv: loadAndApply with missing file returns empty map" {
    var map = try loadAndApply("nonexistent.env", std.testing.allocator);
    defer map.deinit();

    try std.testing.expectEqual(@as(usize, 0), map.count());
}

test "dotenv: EnvMap getOrEnv falls back to environment" {
    var map = EnvMap.init(std.testing.allocator);
    defer map.deinit();

    // Should return null if not in map and not in env
    try std.testing.expect(map.getOrEnv("NONEXISTENT_VAR_12345") == null);

    // PATH should exist in environment on most systems
    if (map.getOrEnv("PATH")) |_| {
        // PATH exists in environment, test passed
    }
}

test "dotenv: load returns owned entries that survive content deallocation" {
    // NEW-12 regression test: load() used to return entries whose .key/.value
    // were sub-slices of the file content buffer.  A `defer allocator.free(content)`
    // freed that buffer before the caller could use the entries, producing a
    // use-after-free.  After the fix, entries own their strings and remain
    // valid after load() returns.
    //
    // Strategy: write a temp .env file, call load(), then verify the returned
    // strings match expected values.  With the testing allocator (safety GPA),
    // freed memory is poisoned to 0xaa, so comparing against known values will
    // fail if the entries still point into the freed content buffer.
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write a .env file into the temp directory
    const env_content = "MY_KEY=my_value\nexport OTHER_KEY=\"quoted_value\"\n";
    tmp_dir.dir.writeFile(.{
        .sub_path = "test_load.env",
        .data = env_content,
    }) catch unreachable;

    // Obtain the real path for load()
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_path = tmp_dir.dir.realpath("test_load.env", &path_buf) catch unreachable;

    const entries = try load(real_path, std.testing.allocator);
    defer freeEntries(entries, std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("MY_KEY", entries[0].key);
    try std.testing.expectEqualStrings("my_value", entries[0].value);
    try std.testing.expectEqualStrings("OTHER_KEY", entries[1].key);
    try std.testing.expectEqualStrings("quoted_value", entries[1].value);
}

test "dotenv: freeEntries releases all owned memory" {
    // Verify that freeEntries correctly frees keys and values allocated by load().
    // This test complements the above by ensuring no leaks (the testing allocator
    // will report leaks if freeEntries is incorrect).
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    tmp_dir.dir.writeFile(.{
        .sub_path = "test_free.env",
        .data = "A=1\nB=2\nC=3\n",
    }) catch unreachable;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_path = tmp_dir.dir.realpath("test_free.env", &path_buf) catch unreachable;

    const entries = try load(real_path, std.testing.allocator);
    // If freeEntries is wrong, the testing allocator will flag a leak.
    freeEntries(entries, std.testing.allocator);
}

test "dotenv: applyContent delegates to parseContent (no code duplication)" {
    // NEW-01 regression test: after refactoring, applyContent should produce
    // identical results to manually parsing with parseContent and applying.
    const content =
        \\# Comment
        \\export HOST=localhost
        \\PORT=8080
        \\NAME="quoted"
        \\PLAIN='single'
    ;

    // Via applyContent
    var map1 = EnvMap.init(std.testing.allocator);
    defer map1.deinit();
    try applyContent(&map1, content);

    // Via parseContent + apply
    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);
    var map2 = try apply(entries, std.testing.allocator);
    defer map2.deinit();

    // Both maps must have identical contents
    try std.testing.expectEqual(map1.count(), map2.count());
    var iter = map1.iterator();
    while (iter.next()) |entry| {
        const v2 = map2.get(entry.key_ptr.*) orelse {
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqualStrings(entry.value_ptr.*, v2);
    }
}

test "dotenv: load and parseContent propagate OutOfMemory" {
    // Verify that the error sets of load and parseContent include OutOfMemory.
    // Before the fix, append errors were silently swallowed via `catch {}`.
    // We confirm by checking that error.OutOfMemory can be cast into each
    // function's error set, which is only valid if OutOfMemory is a member.
    const LoadReturnType = @typeInfo(@TypeOf(load)).@"fn".return_type.?;
    const LoadErrorSet = @typeInfo(LoadReturnType).error_union.error_set;
    const load_oom: LoadErrorSet = error.OutOfMemory;
    try std.testing.expect(load_oom == error.OutOfMemory);

    const ParseReturnType = @typeInfo(@TypeOf(parseContent)).@"fn".return_type.?;
    const ParseErrorSet = @typeInfo(ParseReturnType).error_union.error_set;
    const parse_oom: ParseErrorSet = error.OutOfMemory;
    try std.testing.expect(parse_oom == error.OutOfMemory);
}
