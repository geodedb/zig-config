// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Provenance Module
//!
//! Tracks the source of configuration values for debugging
//! and transparency.

const std = @import("std");

/// Configuration value source
pub const Source = enum {
    /// Value from explicit Set() call (highest precedence)
    override,
    /// Value from command-line flag
    flag,
    /// Value from environment variable
    env,
    /// Value from project-level config (CWD)
    project,
    /// Value from user-level config (~/.config)
    user,
    /// Value from system-level config (/etc)
    system,
    /// Runtime default set via SetDefault()
    runtime_default,
    /// Default value from code (lowest precedence)
    default,

    pub fn format(self: Source) []const u8 {
        return switch (self) {
            .override => "override",
            .flag => "flag",
            .env => "env",
            .project => "project",
            .user => "user",
            .system => "system",
            .runtime_default => "runtime_default",
            .default => "default",
        };
    }

    /// Get precedence (lower = higher priority)
    pub fn precedence(self: Source) u8 {
        return switch (self) {
            .override => 0,
            .flag => 1,
            .env => 2,
            .project => 3,
            .user => 4,
            .system => 5,
            .runtime_default => 6,
            .default => 7,
        };
    }
};

/// Tracked configuration value
pub const TrackedValue = struct {
    /// The key name
    key: []const u8,
    /// The value as string
    value: []const u8,
    /// Where this value came from
    source: Source,
    /// Optional source path (file path or env var name)
    source_path: ?[]const u8 = null,
};

/// Configuration provenance tracker
pub const ProvenanceTracker = struct {
    allocator: std.mem.Allocator,
    values: std.StringHashMap(TrackedValue),

    const Self = @This();

    /// Initialize a new tracker
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .values = std.StringHashMap(TrackedValue).init(allocator),
        };
    }

    /// Deinitialize the tracker
    pub fn deinit(self: *Self) void {
        self.values.deinit();
    }

    /// Set a value with source tracking (respects precedence)
    pub fn set(
        self: *Self,
        key: []const u8,
        value: []const u8,
        source: Source,
        source_path: ?[]const u8,
    ) !void {
        // Check if we already have a value with higher precedence
        if (self.values.get(key)) |existing| {
            if (existing.source.precedence() <= source.precedence()) {
                // Existing value has higher or equal precedence, don't override
                return;
            }
        }

        try self.values.put(key, .{
            .key = key,
            .value = value,
            .source = source,
            .source_path = source_path,
        });
    }

    /// Get a tracked value
    pub fn get(self: *const Self, key: []const u8) ?TrackedValue {
        return self.values.get(key);
    }

    /// Get all tracked values
    pub fn getAll(self: *const Self) ![]TrackedValue {
        var list: std.ArrayList(TrackedValue) = .empty;
        // INFO-5: Pre-allocate capacity since value count is known
        try list.ensureTotalCapacity(self.allocator, @intCast(self.values.count()));
        var iter = self.values.valueIterator();
        while (iter.next()) |val| {
            try list.append(self.allocator, val.*);
        }
        return try list.toOwnedSlice(self.allocator);
    }

    /// Print JSON provenance report
    pub fn printJson(self: *const Self, writer: anytype) !void {
        try writer.writeAll("[");
        var first = true;
        var iter = self.values.valueIterator();
        while (iter.next()) |val| {
            if (!first) try writer.writeAll(",");
            first = false;
            try writer.writeAll("{\"key\":");
            try writeJsonString(writer, val.key);
            try writer.writeAll(",\"value\":");
            try writeJsonString(writer, val.value);
            try writer.writeAll(",\"source\":");
            try writeJsonString(writer, val.source.format());
            try writer.writeAll("}");
        }
        try writer.writeAll("]\n");
    }
};

/// Write a JSON-escaped string (with surrounding quotes) to the writer.
/// Escapes `"`, `\`, and control characters (U+0000 through U+001F)
/// per RFC 8259.
fn writeJsonString(writer: anytype, string: []const u8) !void {
    try writer.writeByte('"');
    for (string) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            // Other control characters (U+0000..U+001F) excluding the ones above
            0x00...0x07, 0x0B, 0x0E...0x1F => {
                try writer.writeAll("\\u00");
                try writer.writeByte(hexDigit(@truncate(c >> 4)));
                try writer.writeByte(hexDigit(@truncate(c & 0x0F)));
            },
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

fn hexDigit(nibble: u4) u8 {
    const n: u8 = nibble;
    return if (n < 10) '0' + n else 'a' + n - 10;
}

// ============================================================================
// Tests
// ============================================================================

test "Source precedence" {
    try std.testing.expect(Source.flag.precedence() < Source.env.precedence());
    try std.testing.expect(Source.env.precedence() < Source.project.precedence());
    try std.testing.expect(Source.project.precedence() < Source.user.precedence());
    try std.testing.expect(Source.user.precedence() < Source.system.precedence());
    try std.testing.expect(Source.system.precedence() < Source.default.precedence());
}

test "ProvenanceTracker respects precedence" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Set from system
    try tracker.set("port", "8080", .system, "/etc/app/config.toml");

    // Try to override from user (higher precedence)
    try tracker.set("port", "9000", .user, "~/.config/app/config.toml");

    // Value should be from user
    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("9000", val.value);
    try std.testing.expectEqual(Source.user, val.source);

    // Try to override from system again (lower precedence) - should not change
    try tracker.set("port", "7000", .system, "/etc/app2/config.toml");
    const val2 = tracker.get("port").?;
    try std.testing.expectEqualStrings("9000", val2.value);
}

test "provenance: Source format returns correct string" {
    try std.testing.expectEqualStrings("flag", Source.flag.format());
    try std.testing.expectEqualStrings("env", Source.env.format());
    try std.testing.expectEqualStrings("project", Source.project.format());
    try std.testing.expectEqualStrings("user", Source.user.format());
    try std.testing.expectEqualStrings("system", Source.system.format());
    try std.testing.expectEqualStrings("default", Source.default.format());
}

test "provenance: ProvenanceTracker init and deinit" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Initial state should be empty
    try std.testing.expect(tracker.get("nonexistent") == null);
}

test "provenance: ProvenanceTracker set and get" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, "./config.toml");

    const val = tracker.get("host").?;
    try std.testing.expectEqualStrings("host", val.key);
    try std.testing.expectEqualStrings("localhost", val.value);
    try std.testing.expectEqual(Source.project, val.source);
    try std.testing.expectEqualStrings("./config.toml", val.source_path.?);
}

test "provenance: ProvenanceTracker set without source path" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("debug", "true", .default, null);

    const val = tracker.get("debug").?;
    try std.testing.expectEqualStrings("debug", val.key);
    try std.testing.expectEqualStrings("true", val.value);
    try std.testing.expectEqual(Source.default, val.source);
    try std.testing.expect(val.source_path == null);
}

test "provenance: flag precedence overrides all" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Set from various sources
    try tracker.set("port", "default", .default, null);
    try tracker.set("port", "system", .system, null);
    try tracker.set("port", "user", .user, null);
    try tracker.set("port", "project", .project, null);
    try tracker.set("port", "env", .env, null);
    try tracker.set("port", "flag", .flag, null);

    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("flag", val.value);
    try std.testing.expectEqual(Source.flag, val.source);
}

test "provenance: flag cannot be overridden" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Set from flag first
    try tracker.set("port", "flag_value", .flag, null);

    // Try to override with other sources - should not change
    try tracker.set("port", "env_value", .env, null);
    try tracker.set("port", "default_value", .default, null);

    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("flag_value", val.value);
    try std.testing.expectEqual(Source.flag, val.source);
}

test "provenance: multiple keys tracked independently" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, null);
    try tracker.set("port", "8080", .env, null);
    try tracker.set("debug", "true", .flag, null);

    try std.testing.expectEqualStrings("localhost", tracker.get("host").?.value);
    try std.testing.expectEqualStrings("8080", tracker.get("port").?.value);
    try std.testing.expectEqualStrings("true", tracker.get("debug").?.value);

    try std.testing.expectEqual(Source.project, tracker.get("host").?.source);
    try std.testing.expectEqual(Source.env, tracker.get("port").?.source);
    try std.testing.expectEqual(Source.flag, tracker.get("debug").?.source);
}

test "provenance: getAll returns all tracked values" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, null);
    try tracker.set("port", "8080", .env, null);
    try tracker.set("debug", "true", .flag, null);

    const all = try tracker.getAll();
    defer std.testing.allocator.free(all);

    try std.testing.expectEqual(@as(usize, 3), all.len);
}

test "provenance: printJson outputs valid format" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, null);

    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try tracker.printJson(writer);
    const output = stream.getWritten();

    // Verify JSON structure
    try std.testing.expect(std.mem.startsWith(u8, output, "["));
    try std.testing.expect(std.mem.indexOf(u8, output, "\"key\":\"host\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"value\":\"localhost\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"source\":\"project\"") != null);
}

test "provenance: printJson empty tracker" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try tracker.printJson(writer);
    const output = stream.getWritten();

    try std.testing.expectEqualStrings("[]\n", output);
}

test "provenance: equal precedence does not override" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("port", "first", .user, "/path/1");
    try tracker.set("port", "second", .user, "/path/2");

    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("first", val.value);
}

test "provenance: getAll returns error union (GAP-0007)" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("a", "1", .default, null);
    try tracker.set("b", "2", .env, null);

    // getAll() must return an error union -- verify with try
    const all = try tracker.getAll();
    defer std.testing.allocator.free(all);

    try std.testing.expectEqual(@as(usize, 2), all.len);

    // Verify return type is an error union at comptime
    const ReturnType = @typeInfo(@TypeOf(ProvenanceTracker.getAll)).@"fn".return_type.?;
    const is_error_union = @typeInfo(ReturnType) == .error_union;
    try std.testing.expect(is_error_union);
}

test "provenance: printJson escapes special characters (GAP-0024)" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Value with quotes, backslashes, newlines, and tabs
    try tracker.set("special", "test\"value\\with\nnew\tlines", .env, null);

    var buffer: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try tracker.printJson(writer);
    const output = stream.getWritten();

    // Verify the output is parseable as valid JSON
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        output,
        .{},
    ) catch |err| {
        std.debug.print("JSON parse error: {}\nOutput was: {s}\n", .{ err, output });
        return err;
    };
    defer parsed.deinit();

    // Verify the parsed JSON has the expected structure
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);

    const obj = arr.items[0].object;
    try std.testing.expectEqualStrings("special", obj.get("key").?.string);
    // The parsed value should have the original unescaped content
    try std.testing.expectEqualStrings("test\"value\\with\nnew\tlines", obj.get("value").?.string);
    try std.testing.expectEqualStrings("env", obj.get("source").?.string);
}

test "provenance: printJson escapes control characters (GAP-0024)" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Value with various control characters
    const ctrl_value = "before\x00\x01\x02\x1fafter";
    try tracker.set("ctrl", ctrl_value, .default, null);

    var buffer: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try tracker.printJson(writer);
    const output = stream.getWritten();

    // Must be parseable as valid JSON
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        output,
        .{},
    ) catch |err| {
        std.debug.print("JSON parse error: {}\nOutput was: {s}\n", .{ err, output });
        return err;
    };
    defer parsed.deinit();

    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);

    const obj = arr.items[0].object;
    try std.testing.expectEqualStrings(ctrl_value, obj.get("value").?.string);
}

test "provenance: writeJsonString escapes correctly" {
    var buffer: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try writeJsonString(writer, "hello\"world");
    try std.testing.expectEqualStrings("\"hello\\\"world\"", stream.getWritten());

    stream.reset();
    try writeJsonString(writer, "back\\slash");
    try std.testing.expectEqualStrings("\"back\\\\slash\"", stream.getWritten());

    stream.reset();
    try writeJsonString(writer, "new\nline");
    try std.testing.expectEqualStrings("\"new\\nline\"", stream.getWritten());

    stream.reset();
    try writeJsonString(writer, "tab\there");
    try std.testing.expectEqualStrings("\"tab\\there\"", stream.getWritten());

    stream.reset();
    try writeJsonString(writer, "cr\rhere");
    try std.testing.expectEqualStrings("\"cr\\rhere\"", stream.getWritten());

    stream.reset();
    try writeJsonString(writer, "\x00\x1f");
    try std.testing.expectEqualStrings("\"\\u0000\\u001f\"", stream.getWritten());

    // Normal string should pass through unchanged
    stream.reset();
    try writeJsonString(writer, "normal");
    try std.testing.expectEqualStrings("\"normal\"", stream.getWritten());
}
