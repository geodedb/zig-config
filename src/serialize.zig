// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Serialization Module
//!
//! Provides utilities for serializing configuration structs to various formats.
//! Supports YAML, JSON, and TOML output formats.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const secret = @import("secret.zig");
const createFileNoFollow = secret.createFileNoFollow;

/// MED-2: Escape mode for writeEscapedString. Each serialization format
/// requires different escape rules:
/// - json: Full RFC 8259 (\\, ", \n, \r, \t, \b, \f, \uXXXX for control chars)
/// - yaml: Minimal (\\, ", \n)
/// - toml: Extended (\\, ", \n, \t)
/// - env:  Bare minimum (\\, ")
const EscapeMode = enum { json, yaml, toml, env };

/// MED-2: Write a string with format-appropriate escaping.
/// Shared helper that replaces duplicated escape switch statements in
/// JSON, YAML, TOML, and ENV serializers.
fn writeEscapedString(writer: anytype, value: []const u8, mode: EscapeMode) !void {
    for (value) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => switch (mode) {
                .env => try writer.writeByte(c),
                else => try writer.writeAll("\\n"),
            },
            '\r' => switch (mode) {
                .json => try writer.writeAll("\\r"),
                else => try writer.writeByte(c),
            },
            '\t' => switch (mode) {
                .json, .toml => try writer.writeAll("\\t"),
                else => try writer.writeByte(c),
            },
            0x08 => switch (mode) {
                .json => try writer.writeAll("\\b"),
                else => try writer.writeByte(c),
            },
            0x0C => switch (mode) {
                .json => try writer.writeAll("\\f"),
                else => try writer.writeByte(c),
            },
            else => {
                // ADV-04: JSON escapes remaining control chars < 0x20 as \uXXXX (RFC 8259 section 7)
                if (mode == .json and c < 0x20) {
                    try writer.print("\\u{X:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// Output format for serialization
pub const OutputFormat = enum {
    json,
    json_pretty,
    yaml,
    toml,
    env,
};

/// Serialization options
pub const SerializeOptions = struct {
    /// Output format
    format: OutputFormat = .json_pretty,
    /// Include null/default values
    include_defaults: bool = true,
    /// Prefix for env format (e.g., "MYAPP_")
    env_prefix: []const u8 = "",
    /// Indent string for pretty printing
    indent: []const u8 = "  ",
};

/// Serialize a struct to a string
pub fn serialize(comptime T: type, value: T, allocator: Allocator, options: SerializeOptions) ![]u8 {
    return switch (options.format) {
        .json => serializeJson(T, value, allocator, false),
        .json_pretty => serializeJson(T, value, allocator, true),
        .yaml => serializeYaml(T, value, allocator, options),
        .toml => serializeToml(T, value, allocator, options),
        .env => serializeEnv(T, value, allocator, options),
    };
}

/// Serialize to JSON format
fn serializeJson(comptime T: type, value: T, allocator: Allocator, pretty: bool) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeJsonValue(T, value, writer, 0, pretty);

    if (pretty) {
        try writer.writeByte('\n');
    }

    return list.toOwnedSlice();
}

/// Write a JSON value
fn writeJsonValue(comptime T: type, value: T, writer: anytype, depth: usize, pretty: bool) !void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => {
            try writer.writeByte('{');
            if (pretty) try writer.writeByte('\n');

            var first = true;
            inline for (info.@"struct".fields) |field| {
                if (!first) {
                    try writer.writeByte(',');
                    if (pretty) try writer.writeByte('\n');
                }
                first = false;

                if (pretty) {
                    try writeIndent(writer, depth + 1);
                }

                try writer.print("\"{s}\":", .{field.name});
                if (pretty) try writer.writeByte(' ');

                const field_value = @field(value, field.name);
                try writeJsonValue(field.type, field_value, writer, depth + 1, pretty);
            }

            if (pretty) {
                try writer.writeByte('\n');
                try writeIndent(writer, depth);
            }
            try writer.writeByte('}');
        },
        .optional => {
            if (value) |v| {
                try writeJsonValue(info.optional.child, v, writer, depth, pretty);
            } else {
                try writer.writeAll("null");
            }
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // MED-2: Use shared escape helper (JSON mode, RFC 8259)
                try writer.writeByte('"');
                try writeEscapedString(writer, value, .json);
                try writer.writeByte('"');
            } else if (ptr.size == .Slice) {
                // Array
                try writer.writeByte('[');
                if (pretty) try writer.writeByte('\n');
                for (value, 0..) |item, i| {
                    if (i > 0) {
                        try writer.writeByte(',');
                        if (pretty) try writer.writeByte('\n');
                    }
                    if (pretty) try writeIndent(writer, depth + 1);
                    try writeJsonValue(ptr.child, item, writer, depth + 1, pretty);
                }
                if (pretty) {
                    try writer.writeByte('\n');
                    try writeIndent(writer, depth);
                }
                try writer.writeByte(']');
            }
        },
        .@"enum" => {
            try writer.print("\"{s}\"", .{@tagName(value)});
        },
        else => {
            try writer.writeAll("null");
        },
    }
}

/// Write indentation
fn writeIndent(writer: anytype, depth: usize) !void {
    for (0..depth) |_| {
        try writer.writeAll("  ");
    }
}

/// Serialize to YAML format
fn serializeYaml(comptime T: type, value: T, allocator: Allocator, options: SerializeOptions) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeYamlValue(T, value, writer, 0, options);

    return list.toOwnedSlice();
}

/// Write a YAML value
fn writeYamlValue(comptime T: type, value: T, writer: anytype, depth: usize, options: SerializeOptions) !void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => {
            inline for (info.@"struct".fields, 0..) |field, i| {
                if (i > 0 or depth > 0) {
                    try writer.writeByte('\n');
                }
                for (0..depth) |_| {
                    try writer.writeAll(options.indent);
                }
                try writer.print("{s}:", .{field.name});

                const field_value = @field(value, field.name);
                const field_info = @typeInfo(field.type);

                if (field_info == .@"struct") {
                    try writeYamlValue(field.type, field_value, writer, depth + 1, options);
                } else {
                    try writer.writeByte(' ');
                    try writeYamlScalar(field.type, field_value, writer);
                }
            }
            try writer.writeByte('\n');
        },
        else => {
            try writeYamlScalar(T, value, writer);
        },
    }
}

/// Write a YAML scalar value
fn writeYamlScalar(comptime T: type, value: T, writer: anytype) !void {
    const info = @typeInfo(T);

    switch (info) {
        .optional => {
            if (value) |v| {
                try writeYamlScalar(info.optional.child, v, writer);
            } else {
                try writer.writeAll("null");
            }
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // Check if we need quotes
                const needs_quotes = value.len == 0 or
                    mem.indexOf(u8, value, ":") != null or
                    mem.indexOf(u8, value, "#") != null or
                    mem.indexOf(u8, value, "\n") != null or
                    value[0] == ' ' or
                    value[value.len - 1] == ' ';

                if (needs_quotes) {
                    // MED-2: Use shared escape helper (YAML mode)
                    try writer.writeByte('"');
                    try writeEscapedString(writer, value, .yaml);
                    try writer.writeByte('"');
                } else {
                    try writer.writeAll(value);
                }
            }
        },
        .@"enum" => {
            try writer.writeAll(@tagName(value));
        },
        else => {
            try writer.writeAll("null");
        },
    }
}

/// Serialize to TOML format
fn serializeToml(comptime T: type, value: T, allocator: Allocator, _: SerializeOptions) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeTomlValue(T, value, writer, "");

    return list.toOwnedSlice();
}

/// Write a TOML value
fn writeTomlValue(comptime T: type, value: T, writer: anytype, section: []const u8) !void {
    const info = @typeInfo(T);

    if (info != .@"struct") return;

    // First pass: write simple values
    inline for (info.@"struct".fields) |field| {
        const field_info = @typeInfo(field.type);
        if (field_info != .@"struct") {
            try writer.print("{s} = ", .{field.name});
            try writeTomlScalar(field.type, @field(value, field.name), writer);
            try writer.writeByte('\n');
        }
    }

    // Second pass: write nested sections
    inline for (info.@"struct".fields) |field| {
        const field_info = @typeInfo(field.type);
        if (field_info == .@"struct") {
            try writer.writeByte('\n');
            if (section.len > 0) {
                try writer.print("[{s}.{s}]\n", .{ section, field.name });
            } else {
                try writer.print("[{s}]\n", .{field.name});
            }
            const new_section = if (section.len > 0)
                section ++ "." ++ field.name
            else
                field.name;
            try writeTomlValue(field.type, @field(value, field.name), writer, new_section);
        }
    }
}

/// Write a TOML scalar value
fn writeTomlScalar(comptime T: type, value: T, writer: anytype) !void {
    const info = @typeInfo(T);

    switch (info) {
        .optional => {
            if (value) |v| {
                try writeTomlScalar(info.optional.child, v, writer);
            } else {
                // TOML doesn't have null, so we skip or use empty string
                try writer.writeAll("\"\"");
            }
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // MED-2: Use shared escape helper (TOML mode)
                try writer.writeByte('"');
                try writeEscapedString(writer, value, .toml);
                try writer.writeByte('"');
            }
        },
        .@"enum" => {
            try writer.print("\"{s}\"", .{@tagName(value)});
        },
        else => {
            try writer.writeAll("\"\"");
        },
    }
}

/// Serialize to environment variable format
fn serializeEnv(comptime T: type, value: T, allocator: Allocator, options: SerializeOptions) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeEnvValue(T, value, writer, options.env_prefix);

    return list.toOwnedSlice();
}

/// Write environment variables
fn writeEnvValue(comptime T: type, value: T, writer: anytype, prefix: []const u8) !void {
    const info = @typeInfo(T);

    if (info != .@"struct") return;

    inline for (info.@"struct".fields) |field| {
        const field_info = @typeInfo(field.type);
        const field_value = @field(value, field.name);

        if (field_info == .@"struct") {
            // Nested struct: add field name to prefix
            var new_prefix_buf: [256]u8 = undefined;
            const new_prefix = std.fmt.bufPrint(&new_prefix_buf, "{s}{s}_", .{ prefix, toUpperCase(field.name) }) catch continue;
            try writeEnvValue(field.type, field_value, writer, new_prefix);
        } else {
            // Simple value
            try writer.writeAll(prefix);
            try writer.writeAll(toUpperCase(field.name));
            try writer.writeByte('=');
            try writeEnvScalar(field.type, field_value, writer);
            try writer.writeByte('\n');
        }
    }
}

/// Convert to uppercase
fn toUpperCase(comptime s: []const u8) []const u8 {
    comptime {
        var result: [s.len]u8 = undefined;
        for (s, 0..) |c, i| {
            result[i] = std.ascii.toUpper(c);
        }
        return &result;
    }
}

/// Write an env scalar value
fn writeEnvScalar(comptime T: type, value: T, writer: anytype) !void {
    const info = @typeInfo(T);

    switch (info) {
        .optional => {
            if (value) |v| {
                try writeEnvScalar(info.optional.child, v, writer);
            }
            // Skip null values
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // Quote if contains spaces or special chars
                const needs_quotes = mem.indexOf(u8, value, " ") != null or
                    mem.indexOf(u8, value, "\"") != null or
                    mem.indexOf(u8, value, "'") != null;

                if (needs_quotes) {
                    // MED-2: Use shared escape helper (ENV mode)
                    try writer.writeByte('"');
                    try writeEscapedString(writer, value, .env);
                    try writer.writeByte('"');
                } else {
                    try writer.writeAll(value);
                }
            }
        },
        .@"enum" => {
            try writer.writeAll(@tagName(value));
        },
        else => {},
    }
}

/// Write a config struct to a file
/// Security: Validates path to prevent path traversal attacks (CWE-22, #62)
/// Write a config struct directly to a file (non-atomic).
///
/// P3-A1: Error contract -- this function may return:
/// - `SecretError.PathTraversalDetected` -- path contains `..` or similar
/// - `error.OutOfMemory` -- serialization or I/O buffer allocation failed
/// - Any `std.fs.File` open/write error (e.g., `AccessDenied`, `FileNotFound`)
///
/// For crash-safe writes, prefer `safeWriteToFile` which uses atomic rename.
pub fn writeToFile(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !void {
    // Security: Validate path does not contain traversal sequences
    if (!secret.isPathSafe(path)) {
        return secret.SecretError.PathTraversalDetected;
    }

    const content = try serialize(T, value, allocator, options);
    defer allocator.free(content);

    const wf_io = std.Io.Threaded.global_single_threaded.io();
    const file = try createFileNoFollow(path, 0o600, false);
    defer file.close(wf_io);

    try file.writeStreamingAll(wf_io, content);
}

/// Atomically write a config struct to a file (safe write).
/// This writes to a temporary file first, syncs to disk, then atomically
/// renames to the target path.  This prevents corruption if the write is
/// interrupted (power failure, crash, etc.)
///
/// P3-A1: Error contract -- this function may return:
/// - `SecretError.PathTraversalDetected` -- path contains `..` or similar
/// - `error.OutOfMemory` -- serialization or path allocation failed
/// - `error.PathAlreadyExists` -- temp file collision after 5 retries
/// - Any `std.fs.File` open/write/sync/rename error
///
/// Security: Validates path to prevent path traversal attacks (CWE-22, #62).
///
/// A-01: This function always uses atomic write (temp + rename) with sync.
/// `config.zig` provides two related functions with different semantics:
///   - `safeWriteConfig`: prevents overwrite (returns FileExists), optionally atomic
///   - `safeWriteConfigWithBackup`: allows overwrite with backup, optionally atomic
/// Both share the same safety guarantees (sync, errdefer, path validation)
/// but take raw content instead of typed values and use `SafeWriteError`.
pub fn safeWriteToFile(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !void {
    // Security: Validate path does not contain traversal sequences
    if (!secret.isPathSafe(path)) {
        return secret.SecretError.PathTraversalDetected;
    }

    const content = try serialize(T, value, allocator, options);
    defer allocator.free(content);

    // Create temp file path with cryptographically secure random suffix
    // Security: Uses crypto random instead of predictable timestamp (CWE-377, #61)
    var temp_path: []u8 = &.{};
    const sio = std.Io.Threaded.global_single_threaded.io();
    var temp_file: std.Io.File = undefined;
    var attempt: u8 = 0;
    while (attempt < 5) : (attempt += 1) {
        var random_bytes: [8]u8 = undefined;
        sio.randomSecure(&random_bytes) catch return error.EntropyUnavailable;
        const random_suffix = std.fmt.bytesToHex(random_bytes, .lower);
        temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp.{s}", .{ path, &random_suffix });
        temp_file = createFileNoFollow(temp_path, 0o600, true) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(temp_path);
                continue;
            },
            else => return err,
        };
        break;
    }
    if (attempt == 5) return error.PathAlreadyExists;
    defer allocator.free(temp_path);
    errdefer std.Io.Dir.cwd().deleteFile(sio, temp_path) catch {};
    // P3-R5: Ensure the temp file handle is closed on write/sync failure
    // so the fd is not leaked before the errdefer cleanup deletes the file.
    errdefer temp_file.close(sio);

    try temp_file.writeStreamingAll(sio, content);
    try temp_file.sync(sio); // Ensure data is flushed to disk
    temp_file.close(sio);

    // Atomically rename temp file to target path
    std.Io.Dir.cwd().rename(temp_path, std.Io.Dir.cwd(), path, sio) catch |err| {
        // If rename fails, try to clean up temp file
        std.Io.Dir.cwd().deleteFile(sio, temp_path) catch {};
        return err;
    };
}

/// Write config only if the file doesn't exist (safe write, no overwrite)
/// Security: Validates path to prevent path traversal attacks (CWE-22, #62)
pub fn writeToFileIfNotExists(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !bool {
    // Security: Validate path does not contain traversal sequences
    if (!secret.isPathSafe(path)) {
        return secret.SecretError.PathTraversalDetected;
    }

    const wio = std.Io.Threaded.global_single_threaded.io();
    // Check if file exists
    std.Io.Dir.cwd().access(wio, path, .{}) catch {
        // File doesn't exist, write it
        try safeWriteToFile(T, value, path, allocator, options);
        return true;
    };
    // File exists, don't overwrite
    return false;
}

/// Write config with backup of existing file
/// Security: Validates path to prevent path traversal attacks (CWE-22, #62)
pub fn writeToFileWithBackup(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !void {
    // Security: Validate path does not contain traversal sequences
    if (!secret.isPathSafe(path)) {
        return secret.SecretError.PathTraversalDetected;
    }

    const bio = std.Io.Threaded.global_single_threaded.io();
    // Check if file exists and create backup
    std.Io.Dir.cwd().access(bio, path, .{}) catch {
        // File doesn't exist, just write it
        try safeWriteToFile(T, value, path, allocator, options);
        return;
    };

    // Create backup path
    const backup_path = try std.fmt.allocPrint(allocator, "{s}.bak", .{path});
    defer allocator.free(backup_path);

    // ADV-05: Refuse to copy if source is a symlink to prevent symlink-following attacks (CWE-59)
    // This matches the no-follow policy used by safeWriteToFile/createFileNoFollow.
    if (secret.isSymlink(path)) {
        return secret.SecretError.SymlinkNotAllowed;
    }

    // ADV-05: Also refuse if the backup target is a symlink (prevents overwriting arbitrary files)
    if (secret.isSymlink(backup_path)) {
        return secret.SecretError.SymlinkNotAllowed;
    }

    // Copy existing file to backup (delete old backup first if exists)
    std.Io.Dir.cwd().deleteFile(bio, backup_path) catch {};
    std.Io.Dir.cwd().copyFile(path, std.Io.Dir.cwd(), backup_path, bio, .{}) catch |err| {
        // If copy fails due to source not existing, ignore and proceed
        if (err != error.FileNotFound) return err;
    };

    // Now safe write the new config
    try safeWriteToFile(T, value, path, allocator, options);
}

// ============================================================================
// Tests
// ============================================================================

test "serialize JSON" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    const config = Config{ .host = "example.com", .port = 443, .debug = true };
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json });
    defer std.testing.allocator.free(json);

    try std.testing.expect(mem.indexOf(u8, json, "\"host\":\"example.com\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"port\":443") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"debug\":true") != null);
}

test "serialize JSON pretty" {
    const Config = struct {
        name: []const u8 = "test",
    };

    const config = Config{};
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json_pretty });
    defer std.testing.allocator.free(json);

    // Pretty should have newlines
    try std.testing.expect(mem.indexOf(u8, json, "\n") != null);
}

test "serialize YAML" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{ .host = "myhost" };
    const yaml = try serialize(Config, config, std.testing.allocator, .{ .format = .yaml });
    defer std.testing.allocator.free(yaml);

    try std.testing.expect(mem.indexOf(u8, yaml, "host: myhost") != null);
    try std.testing.expect(mem.indexOf(u8, yaml, "port: 8080") != null);
}

test "serialize TOML" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{};
    const toml_str = try serialize(Config, config, std.testing.allocator, .{ .format = .toml });
    defer std.testing.allocator.free(toml_str);

    try std.testing.expect(mem.indexOf(u8, toml_str, "host = \"localhost\"") != null);
    try std.testing.expect(mem.indexOf(u8, toml_str, "port = 8080") != null);
}

test "serialize env" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{};
    const env = try serialize(Config, config, std.testing.allocator, .{
        .format = .env,
        .env_prefix = "APP_",
    });
    defer std.testing.allocator.free(env);

    try std.testing.expect(mem.indexOf(u8, env, "APP_HOST=localhost") != null);
    try std.testing.expect(mem.indexOf(u8, env, "APP_PORT=8080") != null);
}

test "serialize optional fields" {
    const Config = struct {
        name: ?[]const u8 = null,
        count: ?u32 = null,
    };

    const config = Config{ .name = "test" };
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json });
    defer std.testing.allocator.free(json);

    try std.testing.expect(mem.indexOf(u8, json, "\"name\":\"test\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"count\":null") != null);
}

test "safeWriteToFile atomic write" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{};
    const test_path = "/tmp/zigconfig_test_safe_write.json";

    // Write config atomically
    try safeWriteToFile(Config, config, test_path, std.testing.allocator, .{ .format = .json });

    const tst_io = std.Io.Threaded.global_single_threaded.io();

    // Verify file was created
    const file = try std.Io.Dir.cwd().openFile(tst_io, test_path, .{});
    defer file.close(tst_io);

    const content = try secret.readFileToEnd(file, std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);

    try std.testing.expect(mem.indexOf(u8, content, "localhost") != null);

    // Clean up
    std.Io.Dir.cwd().deleteFile(tst_io, test_path) catch {};
}

test "writeToFileIfNotExists" {
    const Config = struct {
        value: []const u8 = "original",
    };

    const tst_io2 = std.Io.Threaded.global_single_threaded.io();
    const test_path = "/tmp/zigconfig_test_if_not_exists.json";

    // Ensure file doesn't exist
    std.Io.Dir.cwd().deleteFile(tst_io2, test_path) catch {};

    // First write should succeed
    const written = try writeToFileIfNotExists(Config, .{}, test_path, std.testing.allocator, .{ .format = .json });
    try std.testing.expect(written);

    // Second write should return false (file exists)
    const written2 = try writeToFileIfNotExists(Config, .{ .value = "modified" }, test_path, std.testing.allocator, .{ .format = .json });
    try std.testing.expect(!written2);

    // Clean up
    std.Io.Dir.cwd().deleteFile(tst_io2, test_path) catch {};
}

// ============================================================================
// Path Traversal Protection Tests (#62)
// ============================================================================

test "writeToFile rejects path traversal" {
    const Config = struct { value: []const u8 = "test" };

    // Should reject path traversal attempts
    const result1 = writeToFile(Config, .{}, "../etc/passwd", std.testing.allocator, .{});
    try std.testing.expectError(secret.SecretError.PathTraversalDetected, result1);

    const result2 = writeToFile(Config, .{}, "foo/../bar/config.json", std.testing.allocator, .{});
    try std.testing.expectError(secret.SecretError.PathTraversalDetected, result2);

    // Should reject null bytes
    const result3 = writeToFile(Config, .{}, "config\x00.json", std.testing.allocator, .{});
    try std.testing.expectError(secret.SecretError.PathTraversalDetected, result3);
}

test "safeWriteToFile rejects path traversal" {
    const Config = struct { value: []const u8 = "test" };

    const result = safeWriteToFile(Config, .{}, "../tmp/malicious.json", std.testing.allocator, .{});
    try std.testing.expectError(secret.SecretError.PathTraversalDetected, result);
}

test "writeToFileIfNotExists rejects path traversal" {
    const Config = struct { value: []const u8 = "test" };

    const result = writeToFileIfNotExists(Config, .{}, "../../escape.json", std.testing.allocator, .{});
    try std.testing.expectError(secret.SecretError.PathTraversalDetected, result);
}

test "writeToFileWithBackup rejects path traversal" {
    const Config = struct { value: []const u8 = "test" };

    const result = writeToFileWithBackup(Config, .{}, "../backup_escape.json", std.testing.allocator, .{});
    try std.testing.expectError(secret.SecretError.PathTraversalDetected, result);
}

test "ADV-04: JSON escapes control characters per RFC 8259" {
    const Config = struct {
        value: []const u8 = "",
    };

    // String with backspace (0x08), form-feed (0x0C), and other control chars
    const config = Config{ .value = "a\x08b\x0Cc\x01d\x1Fe" };
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json });
    defer std.testing.allocator.free(json);

    // Backspace should be escaped as \b
    try std.testing.expect(mem.indexOf(u8, json, "\\b") != null);
    // Form-feed should be escaped as \f
    try std.testing.expect(mem.indexOf(u8, json, "\\f") != null);
    // 0x01 should be escaped as \u0001
    try std.testing.expect(mem.indexOf(u8, json, "\\u0001") != null);
    // 0x1F should be escaped as \u001F
    try std.testing.expect(mem.indexOf(u8, json, "\\u001F") != null);
    // Regular chars should not be escaped
    try std.testing.expect(mem.indexOf(u8, json, "a") != null);
    try std.testing.expect(mem.indexOf(u8, json, "e") != null);
}

test "ADV-05: writeToFileWithBackup rejects symlink source" {
    const builtin = @import("builtin");

    // Symlink tests only applicable on POSIX (isSymlink uses fstatat)
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const Config = struct { value: []const u8 = "test" };
    const allocator = std.testing.allocator;

    // Create a real file and a symlink pointing to it
    const real_path = "test_adv05_real.json";
    const link_path = "test_adv05_link.json";

    const tst_io3 = std.Io.Threaded.global_single_threaded.io();

    // Write something to the real file
    {
        const f = try std.Io.Dir.cwd().createFile(tst_io3, real_path, .{});
        try f.writeStreamingAll(tst_io3, "{\"value\":\"old\"}");
        f.close(tst_io3);
    }
    defer std.Io.Dir.cwd().deleteFile(tst_io3, real_path) catch {};

    // Create symlink
    std.Io.Dir.cwd().symLink(tst_io3, real_path, link_path, .{}) catch return; // skip if symlinks not supported
    defer std.Io.Dir.cwd().deleteFile(tst_io3, link_path) catch {};

    // writeToFileWithBackup should reject the symlink source
    const result = writeToFileWithBackup(Config, .{}, link_path, allocator, .{});
    try std.testing.expectError(secret.SecretError.SymlinkNotAllowed, result);
}
