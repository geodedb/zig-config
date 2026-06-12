// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Diff and Comparison Module
//!
//! Provides utilities for comparing configuration values and detecting changes.
//! Useful for:
//! - Hot-reload change detection
//! - Configuration auditing
//! - Migration validation
//!
//! Example usage:
//! ```zig
//! const diff = @import("diff");
//!
//! var old_config = std.StringHashMap([]const u8).init(allocator);
//! var new_config = std.StringHashMap([]const u8).init(allocator);
//!
//! // ... populate configs ...
//!
//! var result = try diff.compare(allocator, old_config, new_config);
//! defer allocator.free(result.changes);
//!
//! for (result.changes) |c| {
//!     std.debug.print("{s}: {s} -> {s}\n", .{
//!         c.key,
//!         c.old_value orelse "(null)",
//!         c.new_value orelse "(null)",
//!     });
//! }
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Type of change detected
pub const ChangeType = enum {
    added,
    removed,
    modified,
    unchanged,
};

/// A single configuration change
pub const Change = struct {
    key: []const u8,
    change_type: ChangeType,
    old_value: ?[]const u8,
    new_value: ?[]const u8,

    pub fn format(self: Change, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.change_type) {
            .added => try writer.print("+ {s}: {s}", .{ self.key, self.new_value orelse "(null)" }),
            .removed => try writer.print("- {s}: {s}", .{ self.key, self.old_value orelse "(null)" }),
            .modified => try writer.print("~ {s}: {s} -> {s}", .{
                self.key,
                self.old_value orelse "(null)",
                self.new_value orelse "(null)",
            }),
            .unchanged => try writer.print("  {s}: {s}", .{ self.key, self.old_value orelse "(null)" }),
        }
    }
};

/// Result of a diff operation
pub const DiffResult = struct {
    changes: []Change,
    added_count: usize,
    removed_count: usize,
    modified_count: usize,
    unchanged_count: usize,

    pub fn hasChanges(self: DiffResult) bool {
        return self.added_count > 0 or self.removed_count > 0 or self.modified_count > 0;
    }

    pub fn totalChanges(self: DiffResult) usize {
        return self.added_count + self.removed_count + self.modified_count;
    }
};

/// Compare two configuration maps and return all changes
pub fn compare(
    allocator: Allocator,
    old_config: std.StringHashMap([]const u8),
    new_config: std.StringHashMap([]const u8),
) !DiffResult {
    return compareWithOptions(allocator, old_config, new_config, .{});
}

/// Comparison options
pub const CompareOptions = struct {
    /// Include unchanged keys in result
    include_unchanged: bool = false,
    /// Case-insensitive key comparison
    case_insensitive: bool = false,
    /// Ignore whitespace differences in values
    ignore_whitespace: bool = false,
};

/// Compare two configuration maps with options
pub fn compareWithOptions(
    allocator: Allocator,
    old_config: std.StringHashMap([]const u8),
    new_config: std.StringHashMap([]const u8),
    options: CompareOptions,
) !DiffResult {
    var changes: std.ArrayListUnmanaged(Change) = .empty;
    errdefer changes.deinit(allocator);

    var added_count: usize = 0;
    var removed_count: usize = 0;
    var modified_count: usize = 0;
    var unchanged_count: usize = 0;

    // PERF-15: In case-insensitive mode, build a lowered-key index of
    // new_config upfront so pass-1 lookups are O(1) instead of O(n).
    // This changes the overall algorithm from O(N*M) to O(N+M).
    var new_lower_index = std.StringHashMap([]const u8).init(allocator);
    defer {
        if (options.case_insensitive) {
            var ki = new_lower_index.keyIterator();
            while (ki.next()) |k| allocator.free(k.*);
        }
        new_lower_index.deinit();
    }
    if (options.case_insensitive) {
        // PERF-54: Pre-allocate capacity to avoid incremental resizing
        try new_lower_index.ensureTotalCapacity(@intCast(new_config.count()));

        var ni = new_config.iterator();
        while (ni.next()) |entry| {
            const lowered = try std.ascii.allocLowerString(allocator, entry.key_ptr.*);
            new_lower_index.put(lowered, entry.value_ptr.*) catch {
                allocator.free(lowered);
                return error.OutOfMemory;
            };
        }
    }

    // Track which keys from new_config we've seen.
    // In case-insensitive mode, store lowered keys for O(1) lookup;
    // each lowered key is allocated once and freed at the end.
    var seen_keys = std.StringHashMap(void).init(allocator);
    // PERF-54: Pre-allocate capacity to avoid incremental resizing
    try seen_keys.ensureTotalCapacity(@intCast(old_config.count() + new_config.count()));
    defer {
        if (options.case_insensitive) {
            var key_iter = seen_keys.keyIterator();
            while (key_iter.next()) |k| {
                allocator.free(k.*);
            }
        }
        seen_keys.deinit();
    }

    // Check old keys
    var old_iter = old_config.iterator();
    while (old_iter.next()) |old_entry| {
        const key = old_entry.key_ptr.*;
        const old_value = old_entry.value_ptr.*;

        // PERF-15: Use the pre-built index for O(1) case-insensitive lookup
        if (getValueForKeyIndexed(new_config, &new_lower_index, key, options.case_insensitive)) |new_value| {
            // Mark this key as seen. In case-insensitive mode, store the
            // lowered form so the "added keys" pass can do O(1) lookups.
            if (options.case_insensitive) {
                const lowered = try std.ascii.allocLowerString(allocator, key);
                try seen_keys.put(lowered, {});
            } else {
                try seen_keys.put(key, {});
            }

            const values_equal = if (options.ignore_whitespace)
                trimmedEqual(old_value, new_value)
            else
                mem.eql(u8, old_value, new_value);

            if (values_equal) {
                unchanged_count += 1;
                if (options.include_unchanged) {
                    try changes.append(allocator, .{
                        .key = key,
                        .change_type = .unchanged,
                        .old_value = old_value,
                        .new_value = new_value,
                    });
                }
            } else {
                modified_count += 1;
                try changes.append(allocator, .{
                    .key = key,
                    .change_type = .modified,
                    .old_value = old_value,
                    .new_value = new_value,
                });
            }
        } else {
            removed_count += 1;
            try changes.append(allocator, .{
                .key = key,
                .change_type = .removed,
                .old_value = old_value,
                .new_value = null,
            });
        }
    }

    // Check for added keys.
    // In case-insensitive mode, lower the key once and use O(1) hash lookup
    // against the lowered seen_keys map, instead of O(n) linear scan.
    var new_iter = new_config.iterator();
    while (new_iter.next()) |new_entry| {
        const key = new_entry.key_ptr.*;

        const was_seen = if (options.case_insensitive) blk: {
            // PERF-60: Use stack buffer to avoid heap alloc per key; heap fallback for oversized keys
            var lower_buf: [512]u8 = undefined;
            if (key.len <= lower_buf.len) {
                const lowered = lower_buf[0..key.len];
                for (key, 0..) |c, idx| {
                    lowered[idx] = std.ascii.toLower(c);
                }
                break :blk seen_keys.contains(lowered);
            }
            const lowered = try std.ascii.allocLowerString(allocator, key);
            defer allocator.free(lowered);
            break :blk seen_keys.contains(lowered);
        } else seen_keys.contains(key);

        // PERF-48: If the key was not seen in pass 1, it cannot exist in
        // old_config, so the previous getValueForKey(old_config, ...) call
        // here was redundant.  The seen_keys check is sufficient.
        if (!was_seen) {
            added_count += 1;
            try changes.append(allocator, .{
                .key = key,
                .change_type = .added,
                .old_value = null,
                .new_value = new_entry.value_ptr.*,
            });
        }
    }

    return .{
        .changes = try changes.toOwnedSlice(allocator),
        .added_count = added_count,
        .removed_count = removed_count,
        .modified_count = modified_count,
        .unchanged_count = unchanged_count,
    };
}

/// PERF-15: O(1) lookup using the pre-built lowered-key index when
/// case_insensitive is true; direct HashMap.get otherwise.
fn getValueForKeyIndexed(
    map: std.StringHashMap([]const u8),
    lower_index: *const std.StringHashMap([]const u8),
    key: []const u8,
    case_insensitive: bool,
) ?[]const u8 {
    if (!case_insensitive) {
        return map.get(key);
    }
    // Use stack buffer for lowering to avoid allocation in the hot path
    var buf: [512]u8 = undefined;
    if (key.len <= buf.len) {
        const lowered = buf[0..key.len];
        for (key, 0..) |c, idx| {
            lowered[idx] = std.ascii.toLower(c);
        }
        return lower_index.get(lowered);
    }
    // Key longer than stack buffer -- fall back to linear scan
    var iter = map.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, key)) {
            return entry.value_ptr.*;
        }
    }
    return null;
}

fn trimmedEqual(a: []const u8, b: []const u8) bool {
    const trimmed_a = mem.trim(u8, a, " \t\r\n");
    const trimmed_b = mem.trim(u8, b, " \t\r\n");
    return mem.eql(u8, trimmed_a, trimmed_b);
}

/// S-NEW-05: redaction mask written in place of a sensitive value.
pub const redaction_mask = "***REDACTED***";

/// S-NEW-05: options controlling how a diff is rendered, including opt-in
/// value redaction (CWE-532/CWE-200).
pub const DiffFormatOptions = struct {
    /// When true, mask the old/new values of keys judged sensitive. Default
    /// false preserves the historical verbatim behavior of `formatDiff`.
    redact: bool = false,
    /// Explicit list of sensitive key names (case-insensitive exact match).
    /// When null and `redact` is true, the built-in heuristic is used: keys
    /// containing `password`/`secret`/`token`/`key`/`credential`
    /// (case-insensitive) are masked.
    sensitive_keys: ?[]const []const u8 = null,
};

/// S-NEW-05: decide whether a key's value should be redacted. When
/// `sensitive_keys` is provided, only keys in that list (case-insensitive
/// exact match) are sensitive; otherwise the default substring heuristic
/// applies.
pub fn isSensitiveKey(key: []const u8, sensitive_keys: ?[]const []const u8) bool {
    if (sensitive_keys) |list| {
        for (list) |k| {
            if (std.ascii.eqlIgnoreCase(key, k)) return true;
        }
        return false;
    }
    const needles = [_][]const u8{ "password", "secret", "token", "key", "credential" };
    for (needles) |needle| {
        if (containsIgnoreCase(key, needle)) return true;
    }
    return false;
}

/// Case-insensitive substring search (ASCII).
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    const last = haystack.len - needle.len;
    while (i <= last) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Render a value for the diff report, masking it when redaction is enabled
/// and the key is sensitive.
fn renderValue(value: []const u8, key: []const u8, options: DiffFormatOptions) []const u8 {
    if (options.redact and isSensitiveKey(key, options.sensitive_keys)) {
        return redaction_mask;
    }
    return value;
}

/// Generate a human-readable diff report.
///
/// **Security (S-NEW-05):** this prints config values verbatim. If a diff may
/// contain resolved secrets, use `formatDiffWithOptions` with `redact = true`
/// to mask sensitive values before writing to logs/CI output.
pub fn formatDiff(allocator: Allocator, result: DiffResult) ![]u8 {
    return formatDiffWithOptions(allocator, result, .{});
}

/// Generate a human-readable diff report with formatting options.
///
/// **Security (S-NEW-05):** set `options.redact = true` to mask the values of
/// sensitive keys (default heuristic, or an explicit `options.sensitive_keys`
/// list) so plaintext secrets are not written to logs/CI output. With the
/// default `redact = false`, output is identical to `formatDiff`.
pub fn formatDiffWithOptions(allocator: Allocator, result: DiffResult, options: DiffFormatOptions) ![]u8 {
    var output: std.ArrayListUnmanaged(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.appendSlice(allocator, "Configuration Diff Report\n");
    try output.appendSlice(allocator, "========================\n\n");

    if (!result.hasChanges()) {
        try output.appendSlice(allocator, "No changes detected.\n");
    } else {
        const summary = try std.fmt.allocPrint(allocator, "Summary: {d} added, {d} removed, {d} modified\n\n", .{
            result.added_count,
            result.removed_count,
            result.modified_count,
        });
        defer allocator.free(summary);
        try output.appendSlice(allocator, summary);

        // Single pass: collect formatted lines into per-type buffers
        var added_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer added_buf.deinit(allocator);
        var removed_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer removed_buf.deinit(allocator);
        var modified_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer modified_buf.deinit(allocator);

        for (result.changes) |change| {
            switch (change.change_type) {
                .added => {
                    const line = try std.fmt.allocPrint(allocator, "  + {s} = {s}\n", .{
                        change.key,
                        renderValue(change.new_value orelse "", change.key, options),
                    });
                    defer allocator.free(line);
                    try added_buf.appendSlice(allocator, line);
                },
                .removed => {
                    const line = try std.fmt.allocPrint(allocator, "  - {s} = {s}\n", .{
                        change.key,
                        renderValue(change.old_value orelse "", change.key, options),
                    });
                    defer allocator.free(line);
                    try removed_buf.appendSlice(allocator, line);
                },
                .modified => {
                    const line = try std.fmt.allocPrint(allocator, "  ~ {s}: {s} -> {s}\n", .{
                        change.key,
                        renderValue(change.old_value orelse "", change.key, options),
                        renderValue(change.new_value orelse "", change.key, options),
                    });
                    defer allocator.free(line);
                    try modified_buf.appendSlice(allocator, line);
                },
                .unchanged => {},
            }
        }

        // Write grouped sections in order
        if (added_buf.items.len > 0) {
            try output.appendSlice(allocator, "Added:\n");
            try output.appendSlice(allocator, added_buf.items);
            try output.appendSlice(allocator, "\n");
        }

        if (removed_buf.items.len > 0) {
            try output.appendSlice(allocator, "Removed:\n");
            try output.appendSlice(allocator, removed_buf.items);
            try output.appendSlice(allocator, "\n");
        }

        if (modified_buf.items.len > 0) {
            try output.appendSlice(allocator, "Modified:\n");
            try output.appendSlice(allocator, modified_buf.items);
        }
    }

    return output.toOwnedSlice(allocator);
}

/// Check if two configs are equivalent
pub fn isEquivalent(
    old_config: std.StringHashMap([]const u8),
    new_config: std.StringHashMap([]const u8),
) bool {
    if (old_config.count() != new_config.count()) return false;

    var iter = old_config.iterator();
    while (iter.next()) |entry| {
        if (new_config.get(entry.key_ptr.*)) |new_value| {
            if (!mem.eql(u8, entry.value_ptr.*, new_value)) {
                return false;
            }
        } else {
            return false;
        }
    }

    return true;
}

/// Get keys that exist in both configs
pub fn intersection(
    allocator: Allocator,
    config1: std.StringHashMap([]const u8),
    config2: std.StringHashMap([]const u8),
) ![]const []const u8 {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer result.deinit(allocator);

    var iter = config1.keyIterator();
    while (iter.next()) |key| {
        if (config2.contains(key.*)) {
            try result.append(allocator, key.*);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Get keys that exist only in config1
pub fn difference(
    allocator: Allocator,
    config1: std.StringHashMap([]const u8),
    config2: std.StringHashMap([]const u8),
) ![]const []const u8 {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer result.deinit(allocator);

    var iter = config1.keyIterator();
    while (iter.next()) |key| {
        if (!config2.contains(key.*)) {
            try result.append(allocator, key.*);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Merge two configs with conflict resolution
pub const MergeStrategy = enum {
    /// Keep old value on conflict
    keep_old,
    /// Use new value on conflict
    use_new,
    /// Fail on conflict
    fail,
};

pub const MergeError = error{
    Conflict,
    OutOfMemory,
};

/// Merge two configs
pub fn merge(
    allocator: Allocator,
    base: std.StringHashMap([]const u8),
    overlay: std.StringHashMap([]const u8),
    strategy: MergeStrategy,
) MergeError!std.StringHashMap([]const u8) {
    var result = std.StringHashMap([]const u8).init(allocator);
    // PERF-54: Pre-allocate capacity to avoid incremental resizing
    result.ensureTotalCapacity(@intCast(base.count() + overlay.count())) catch return MergeError.OutOfMemory;
    errdefer result.deinit();

    // Copy base
    var base_iter = base.iterator();
    while (base_iter.next()) |entry| {
        result.put(entry.key_ptr.*, entry.value_ptr.*) catch return MergeError.OutOfMemory;
    }

    // Apply overlay
    var overlay_iter = overlay.iterator();
    while (overlay_iter.next()) |entry| {
        const key = entry.key_ptr.*;
        const new_value = entry.value_ptr.*;

        if (result.get(key)) |_| {
            // Conflict
            switch (strategy) {
                .keep_old => {}, // Do nothing
                .use_new => {
                    result.put(key, new_value) catch return MergeError.OutOfMemory;
                },
                .fail => return MergeError.Conflict,
            }
        } else {
            result.put(key, new_value) catch return MergeError.OutOfMemory;
        }
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "compare detects added keys" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try new.put("host", "localhost");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 1), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
}

test "compare detects removed keys" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("host", "localhost");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 1), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
}

test "compare detects modified keys" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("host", "localhost");
    try new.put("host", "example.com");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 1), result.modified_count);
}

test "compare with unchanged" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("host", "localhost");
    try new.put("host", "localhost");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{ .include_unchanged = true });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 1), result.unchanged_count);
    try std.testing.expectEqual(@as(usize, 1), result.changes.len);
}

test "isEquivalent" {
    var config1 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config1.deinit();

    var config2 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config2.deinit();

    try config1.put("host", "localhost");
    try config1.put("port", "8080");

    try config2.put("host", "localhost");
    try config2.put("port", "8080");

    try std.testing.expect(isEquivalent(config1, config2));

    try config2.put("debug", "true");
    try std.testing.expect(!isEquivalent(config1, config2));
}

test "intersection" {
    var config1 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config1.deinit();

    var config2 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config2.deinit();

    try config1.put("host", "localhost");
    try config1.put("port", "8080");
    try config1.put("debug", "true");

    try config2.put("host", "example.com");
    try config2.put("timeout", "30");

    const common = try intersection(std.testing.allocator, config1, config2);
    defer std.testing.allocator.free(common);

    try std.testing.expectEqual(@as(usize, 1), common.len);
    try std.testing.expectEqualStrings("host", common[0]);
}

test "difference" {
    var config1 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config1.deinit();

    var config2 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config2.deinit();

    try config1.put("host", "localhost");
    try config1.put("port", "8080");

    try config2.put("host", "example.com");

    const diff_keys = try difference(std.testing.allocator, config1, config2);
    defer std.testing.allocator.free(diff_keys);

    try std.testing.expectEqual(@as(usize, 1), diff_keys.len);
    try std.testing.expectEqualStrings("port", diff_keys[0]);
}

test "merge with use_new strategy" {
    var base = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer base.deinit();

    var overlay = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer overlay.deinit();

    try base.put("host", "localhost");
    try base.put("port", "8080");

    try overlay.put("host", "example.com");
    try overlay.put("debug", "true");

    var result = try merge(std.testing.allocator, base, overlay, .use_new);
    defer result.deinit();

    try std.testing.expectEqualStrings("example.com", result.get("host").?);
    try std.testing.expectEqualStrings("8080", result.get("port").?);
    try std.testing.expectEqualStrings("true", result.get("debug").?);
}

test "merge with fail strategy" {
    var base = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer base.deinit();

    var overlay = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer overlay.deinit();

    try base.put("host", "localhost");
    try overlay.put("host", "example.com");

    const result = merge(std.testing.allocator, base, overlay, .fail);
    try std.testing.expectError(MergeError.Conflict, result);
}

test "DiffResult hasChanges" {
    const no_changes = DiffResult{
        .changes = &.{},
        .added_count = 0,
        .removed_count = 0,
        .modified_count = 0,
        .unchanged_count = 5,
    };

    try std.testing.expect(!no_changes.hasChanges());

    const has_changes = DiffResult{
        .changes = &.{},
        .added_count = 1,
        .removed_count = 0,
        .modified_count = 0,
        .unchanged_count = 5,
    };

    try std.testing.expect(has_changes.hasChanges());
}

test "formatDiff" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("removed_key", "old_value");
    try new.put("added_key", "new_value");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const report = try formatDiff(std.testing.allocator, result);
    defer std.testing.allocator.free(report);

    try std.testing.expect(mem.indexOf(u8, report, "Configuration Diff Report") != null);
    try std.testing.expect(mem.indexOf(u8, report, "1 added") != null);
    try std.testing.expect(mem.indexOf(u8, report, "1 removed") != null);
}

test "case-insensitive compare matches keys with different casing" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("Host", "localhost");
    try new.put("HOST", "localhost");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{ .case_insensitive = true });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
    try std.testing.expectEqual(@as(usize, 1), result.unchanged_count);
}

test "case-insensitive compare detects modifications across casing" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("Host", "localhost");
    try new.put("HOST", "example.com");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{ .case_insensitive = true });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 1), result.modified_count);
    try std.testing.expectEqual(@as(usize, 0), result.unchanged_count);
}

test "case-insensitive compare detects additions correctly" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("Host", "localhost");
    try new.put("HOST", "localhost");
    try new.put("PORT", "8080");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{ .case_insensitive = true });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 1), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
    try std.testing.expectEqual(@as(usize, 1), result.unchanged_count);
}

test "case-insensitive compare detects removals correctly" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("Host", "localhost");
    try old.put("Port", "8080");
    try new.put("HOST", "localhost");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{ .case_insensitive = true });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 1), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
    try std.testing.expectEqual(@as(usize, 1), result.unchanged_count);
}

// ---------------------------------------------------------------------------
// S-NEW-05: opt-in value redaction for diff reports (CWE-532/CWE-200)
// ---------------------------------------------------------------------------

test "S-NEW-05: formatDiff (default) still prints values verbatim" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();
    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("db_password", "hunter2");
    try new.put("db_password", "swordfish");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const report = try formatDiff(std.testing.allocator, result);
    defer std.testing.allocator.free(report);

    // Default behavior unchanged: secret values present in output.
    try std.testing.expect(mem.indexOf(u8, report, "hunter2") != null);
    try std.testing.expect(mem.indexOf(u8, report, "swordfish") != null);
}

test "S-NEW-05: formatDiffWithOptions redacts sensitive keys by heuristic" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();
    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("db_password", "hunter2");
    try new.put("db_password", "swordfish");
    try old.put("host", "localhost");
    try new.put("host", "example.com");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const report = try formatDiffWithOptions(std.testing.allocator, result, .{ .redact = true });
    defer std.testing.allocator.free(report);

    // Secret values masked.
    try std.testing.expect(mem.indexOf(u8, report, "hunter2") == null);
    try std.testing.expect(mem.indexOf(u8, report, "swordfish") == null);
    try std.testing.expect(mem.indexOf(u8, report, "***REDACTED***") != null);
    // Non-sensitive values preserved.
    try std.testing.expect(mem.indexOf(u8, report, "localhost") != null);
    try std.testing.expect(mem.indexOf(u8, report, "example.com") != null);
}

test "S-NEW-05: formatDiffWithOptions redacts added and removed entries" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();
    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("api_token", "removed_secret");
    try new.put("vault_secret", "added_secret");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const report = try formatDiffWithOptions(std.testing.allocator, result, .{ .redact = true });
    defer std.testing.allocator.free(report);

    try std.testing.expect(mem.indexOf(u8, report, "removed_secret") == null);
    try std.testing.expect(mem.indexOf(u8, report, "added_secret") == null);
    try std.testing.expect(mem.indexOf(u8, report, "***REDACTED***") != null);
}

test "S-NEW-05: formatDiffWithOptions explicit sensitive_keys list" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();
    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    // "custom_field" does NOT match the default heuristic; only the explicit
    // list should mask it. "host" stays visible.
    try old.put("custom_field", "topsecret");
    try new.put("custom_field", "changed");
    try old.put("host", "localhost");
    try new.put("host", "example.com");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const report = try formatDiffWithOptions(
        std.testing.allocator,
        result,
        .{ .redact = true, .sensitive_keys = &.{"custom_field"} },
    );
    defer std.testing.allocator.free(report);

    try std.testing.expect(mem.indexOf(u8, report, "topsecret") == null);
    try std.testing.expect(mem.indexOf(u8, report, "changed") == null);
    try std.testing.expect(mem.indexOf(u8, report, "***REDACTED***") != null);
    try std.testing.expect(mem.indexOf(u8, report, "localhost") != null);
}

test "S-NEW-05: formatDiffWithOptions redact=false matches formatDiff" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();
    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("db_password", "hunter2");
    try new.put("db_password", "swordfish");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const a = try formatDiff(std.testing.allocator, result);
    defer std.testing.allocator.free(a);
    const b = try formatDiffWithOptions(std.testing.allocator, result, .{ .redact = false });
    defer std.testing.allocator.free(b);

    try std.testing.expectEqualStrings(a, b);
}

test "S-NEW-05: isSensitiveKey heuristic" {
    try std.testing.expect(isSensitiveKey("db_password", null));
    try std.testing.expect(isSensitiveKey("API_SECRET", null));
    try std.testing.expect(isSensitiveKey("auth_token", null));
    try std.testing.expect(isSensitiveKey("private_key", null));
    try std.testing.expect(isSensitiveKey("aws_credential", null));
    try std.testing.expect(!isSensitiveKey("host", null));
    try std.testing.expect(!isSensitiveKey("port", null));
    // Explicit list overrides heuristic membership.
    try std.testing.expect(isSensitiveKey("custom", &.{"custom"}));
    try std.testing.expect(!isSensitiveKey("password", &.{"custom"}));
}

test "case-insensitive compare with mixed adds, removes, and modifications" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    // Matched (modified): Host/HOST
    try old.put("Host", "localhost");
    try new.put("HOST", "example.com");

    // Removed: only in old
    try old.put("Debug", "true");

    // Added: only in new
    try new.put("TIMEOUT", "30");

    // Matched (unchanged): Port/port
    try old.put("Port", "8080");
    try new.put("port", "8080");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{
        .case_insensitive = true,
        .include_unchanged = true,
    });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 1), result.added_count);
    try std.testing.expectEqual(@as(usize, 1), result.removed_count);
    try std.testing.expectEqual(@as(usize, 1), result.modified_count);
    try std.testing.expectEqual(@as(usize, 1), result.unchanged_count);
    try std.testing.expectEqual(@as(usize, 4), result.changes.len);
}
