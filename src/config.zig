// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Config Module
//!
//! Configuration management with:
//! - Multiple format support (TOML, JSON, YAML)
//! - XDG Base Directory compliance
//! - Precedence: flags > env > project > user > system > defaults
//! - Secret handling (file/stdin only, not flags/env)
//! - Validation hooks
//!
//! ## Unified Configuration API
//!
//! The config module provides a unified API for reading configuration files
//! regardless of format (JSON, YAML, TOML). Use the `parseFile` or `parseContent`
//! functions for format-agnostic parsing:
//!
//! ```zig
//! const config = @import("config");
//!
//! // Parse any config file - format is auto-detected from extension
//! var value = try config.parseFile(allocator, "config.yaml");
//! defer value.deinit();
//!
//! // Access nested values with dot notation
//! const host = value.getString("server.host") orelse "localhost";
//! const port = value.getInt("server.port") orelse 8080;
//! ```

// Zig 0.16.0 compat: StringArrayHashMap was removed
fn StringArrayHashMap(comptime V: type) type {
    return std.array_hash_map.ArrayHashMap([]const u8, V, struct {
        pub fn hash(_: @This(), key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(_: @This(), a: []const u8, b: []const u8, _: usize) bool {
            return std.mem.eql(u8, a, b);
        }
    }, true);
}

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// External library imports
pub const yaml = @import("yaml");
pub const toml = @import("toml");
pub const json = @import("json");

// Internal module imports
pub const environ = @import("environ.zig");
pub const loader = @import("loader.zig");
pub const provenance = @import("provenance.zig");
pub const xdg = @import("xdg.zig");
pub const dotenv = @import("dotenv.zig");
pub const secret = @import("secret.zig");
const createFileNoFollow = secret.createFileNoFollow;
pub const flags = @import("flags.zig");
pub const merge = @import("merge.zig");
pub const encrypted_secrets = @import("encrypted_secrets.zig");
pub const serialize = @import("serialize.zig");
pub const expand = @import("expand.zig");
pub const ini = @import("ini.zig");
pub const properties = @import("properties.zig");
pub const watch = @import("watch.zig");
pub const remote = @import("remote.zig");
pub const validation = @import("validation.zig");
// GAP-NEW-01: Non-breaking alias so the documented `config.validate.*` API
// (README.md, docs/API.md) compiles. `validation` remains the canonical name.
pub const validate = validation;
pub const async_load = @import("async.zig");
pub const diff = @import("diff.zig");

/// Parallel operations (requires `thread_pool`).
pub const parallel = @import("parallel");

// File Size Limits - re-exported from limits.zig (CWE-400, #64, #101)
pub const limits = @import("limits.zig");
pub const MAX_CONFIG_FILE_SIZE = limits.MAX_CONFIG_FILE_SIZE;
pub const MAX_REMOTE_RESPONSE_SIZE = limits.MAX_REMOTE_RESPONSE_SIZE;
pub const MAX_SECRET_FILE_SIZE = limits.MAX_SECRET_FILE_SIZE;
pub const MAX_CLI_OUTPUT_SIZE = limits.MAX_CLI_OUTPUT_SIZE;
pub const MAX_DOTENV_FILE_SIZE = limits.MAX_DOTENV_FILE_SIZE;

// Re-export commonly used types from loader
pub const Loader = loader.Loader;
pub const LoadError = loader.LoadError;
pub const LoadOptions = loader.LoadOptions;
pub const Format = loader.Format;
pub const load = loader.load;

// Re-export provenance types
pub const Source = provenance.Source;
pub const TrackedValue = provenance.TrackedValue;
pub const ProvenanceTracker = provenance.ProvenanceTracker;

// Re-export XDG types
pub const XdgPaths = xdg.XdgPaths;
pub const Platform = xdg.Platform;
pub const getPaths = xdg.getPaths;
pub const getPathsForPlatform = xdg.getPathsForPlatform;
pub const getConfigDir = xdg.getConfigDir;
pub const getConfigDirForPlatform = xdg.getConfigDirForPlatform;
pub const getDataDir = xdg.getDataDir;
pub const getDataDirForPlatform = xdg.getDataDirForPlatform;
pub const getCacheDir = xdg.getCacheDir;
pub const getCacheDirForPlatform = xdg.getCacheDirForPlatform;
pub const getSystemConfigDir = xdg.getSystemConfigDir;
pub const getSystemConfigDirForPlatform = xdg.getSystemConfigDirForPlatform;

// Re-export secret types
pub const SecretError = secret.SecretError;
pub const readFromFile = secret.readFromFile;
pub const readFromStdin = secret.readFromStdin;

// Re-export validation types
pub const ValidationError = validation.ValidationError;

// Re-export flag types
pub const FlagParser = flags.FlagParser;
pub const Flag = flags.Flag;
pub const FlagValue = flags.FlagValue;
pub const FlagError = flags.FlagError;

// Re-export dotenv types
pub const EnvEntry = dotenv.EnvEntry;
pub const EnvMap = dotenv.EnvMap;
pub const loadDotenv = dotenv.load;
pub const loadAndApplyDotenv = dotenv.loadAndApply;
pub const applyDotenvContent = dotenv.applyContent;
pub const applyDotenvEntries = dotenv.apply;
pub const parseDotenvContent = dotenv.parseContent;

// Re-export merge types
pub const MergeStrategy = merge.MergeStrategy;
pub const MergeOptions = merge.MergeOptions;
pub const mergeMaps = merge.mergeMaps;
pub const mergeStructs = merge.mergeStructs;
pub const mergeMany = merge.mergeMany;
pub const mergePreferOverlay = merge.mergePreferOverlay;

// Re-export encrypted secrets types
pub const SecretProvider = encrypted_secrets.Provider;
pub const SecretRef = encrypted_secrets.SecretRef;
pub const SecretManager = encrypted_secrets.SecretManager;
pub const KmsConfig = encrypted_secrets.KmsConfig;
pub const VaultConfig = encrypted_secrets.VaultConfig;
pub const OnePasswordConfig = encrypted_secrets.OnePasswordConfig;
pub const EncryptedFileConfig = encrypted_secrets.EncryptedFileConfig;

// Re-export serialization types
pub const OutputFormat = serialize.OutputFormat;
pub const SerializeOptions = serialize.SerializeOptions;
pub const serializeConfig = serialize.serialize;
pub const writeConfigToFile = serialize.writeToFile;

// Re-export expansion types
pub const ExpandOptions = expand.ExpandOptions;
pub const ExpandError = expand.ExpandError;
pub const expandEnv = expand.expand;
pub const expandEnvWithOptions = expand.expandWithOptions;
pub const expandStruct = expand.expandStruct;
pub const containsVariables = expand.containsVariables;

// Re-export validation types (#10, #11)
pub const Validator = validation.Validator;
pub const ValidatorFn = validation.ValidatorFn;
pub const ValidationResult = validation.ValidationResult;
pub const matchPattern = validation.matchPattern;
pub const isEmail = validation.isEmail;
pub const isUrl = validation.isUrl;
pub const isIPv4 = validation.isIPv4;
pub const isPort = validation.isPort;
pub const isHostname = validation.isHostname;

// Re-export async loading types (#16)
pub const AsyncLoader = async_load.AsyncLoader;
pub const AsyncLoaderWithCallback = async_load.AsyncLoaderWithCallback;
pub const AsyncState = async_load.AsyncState;
pub const AsyncError = async_load.AsyncError;
pub const loadAsync = async_load.loadAsync;
pub const loadParallel = async_load.loadParallel;
/// Owned result of `loadParallel`; caller must call `.deinit()` (S-NEW-01).
pub const OwnedConfig = async_load.OwnedConfig;

// Re-export diff types (#20)
pub const Change = diff.Change;
pub const ChangeType = diff.ChangeType;
pub const DiffResult = diff.DiffResult;
pub const CompareOptions = diff.CompareOptions;
pub const compareConfigs = diff.compare;
pub const compareConfigsWithOptions = diff.compareWithOptions;
pub const formatDiff = diff.formatDiff;
pub const isEquivalent = diff.isEquivalent;
pub const configIntersection = diff.intersection;
pub const configDifference = diff.difference;
pub const mergeConfigs = diff.merge;

// ============================================================================
// Unified Configuration Value API
// ============================================================================

/// Internal value representation for unified API
pub const ValueType = enum {
    null,
    bool,
    int,
    float,
    string,
    list,
    map,
};

/// Key-value pair for maps
pub const MapEntry = struct {
    key: []const u8,
    value: *const Value,
};

/// Unified configuration value that works across all formats
/// This is the recommended way to work with configuration files
pub const Value = struct {
    allocator: Allocator,
    data: ValueData,
    /// Arena for allocations - managed by the value
    arena: ?std.heap.ArenaAllocator = null,

    const Self = @This();

    const ValueData = union(ValueType) {
        null: void,
        bool: bool,
        int: i64,
        float: f64,
        string: []const u8,
        list: []Self,
        map: StringArrayHashMap(Self),
    };

    /// Free all memory associated with this value
    pub fn deinit(self: *Self) void {
        if (self.arena) |*arena| {
            arena.deinit();
        }
    }

    /// Get a string value by key or dot-separated path
    pub fn getString(self: Self, path: []const u8) ?[]const u8 {
        const val = self.getPath(path) orelse return null;
        return switch (val.data) {
            .string => |s| s,
            else => null,
        };
    }

    /// Get an integer value by key or dot-separated path
    pub fn getInt(self: Self, path: []const u8) ?i64 {
        const val = self.getPath(path) orelse return null;
        return switch (val.data) {
            .int => |i| i,
            else => null,
        };
    }

    /// Get a float value by key or dot-separated path
    pub fn getFloat(self: Self, path: []const u8) ?f64 {
        const val = self.getPath(path) orelse return null;
        return switch (val.data) {
            .float => |f| f,
            else => null,
        };
    }

    /// Get a boolean value by key or dot-separated path
    pub fn getBool(self: Self, path: []const u8) ?bool {
        const val = self.getPath(path) orelse return null;
        return switch (val.data) {
            .bool => |b| b,
            else => null,
        };
    }

    /// Check if a path exists
    pub fn has(self: Self, path: []const u8) bool {
        return self.getPath(path) != null;
    }

    /// Get a nested value by key or dot-separated path
    pub fn getPath(self: Self, path: []const u8) ?Self {
        var current = self;
        var parts = mem.splitScalar(u8, path, '.');

        while (parts.next()) |part| {
            switch (current.data) {
                .map => |map| {
                    current = map.get(part) orelse return null;
                },
                else => return null,
            }
        }

        return current;
    }

    /// Get list items at a path
    pub fn getList(self: Self, path: []const u8) ?[]Self {
        const val = self.getPath(path) orelse return null;
        return switch (val.data) {
            .list => |l| l,
            else => null,
        };
    }

    /// Get map entries at current value
    pub fn getMap(self: Self) ?StringArrayHashMap(Self) {
        return switch (self.data) {
            .map => |m| m,
            else => null,
        };
    }

    /// Check if value is null
    pub fn isNull(self: Self) bool {
        return self.data == .null;
    }
};

/// Parse configuration from file content with auto-detected or specified format
pub fn parseContent(allocator: Allocator, content: []const u8, format: Format) !Value {
    const resolved_format: Format = if (format == .auto)
        loader.detectFormatFromContent(content)
    else
        format;

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    const arena_alloc = arena.allocator();

    const data: Value.ValueData = switch (resolved_format) {
        .yaml => try parseYamlContent(arena_alloc, content),
        .json => try parseJsonContent(arena_alloc, content),
        .toml => try parseTomlContent(arena_alloc, content),
        .ini => try parseIniContent(arena_alloc, content),
        .properties => try parsePropertiesContent(arena_alloc, content),
        // ADV-01: Return a proper error instead of unreachable (UB in ReleaseFast)
        .auto => return error.UnsupportedFormat,
    };

    return Value{
        .allocator = allocator,
        .data = data,
        .arena = arena,
    };
}

/// Parse configuration file with format auto-detected from extension
/// Security: Validates path and rejects symlinks (CWE-22, CWE-59, #72, #74)
pub fn parseFile(allocator: Allocator, path: []const u8) !Value {
    // Security: Validate path does not contain traversal sequences (CWE-22, #74)
    if (!secret.isPathSafe(path)) {
        return error.PathTraversalDetected;
    }

    // INFO-4: Removed redundant isSymlink() stat check. openFileReadNoFollow()
    // uses O_NOFOLLOW which atomically rejects symlinks at the kernel level,
    // eliminating the TOCTOU window from the prior stat+open sequence.
    const pf_io = std.Io.Threaded.global_single_threaded.io();
    // Q-NEW-07: Propagate the real open error instead of collapsing every
    // failure into FileNotFound. The previous catch-all masked AccessDenied,
    // IsDir, SystemResources, NameTooLong, etc. as FileNotFound, hiding the
    // true cause from callers.
    const file = secret.openFileReadNoFollow(path) catch |err| switch (err) {
        error.SymlinkNotAllowed => return error.SymlinkNotAllowed,
        error.FileNotFound => return error.FileNotFound,
        else => |e| return e,
    };
    defer file.close(pf_io);

    const content = try secret.readFileToEnd(file, allocator, MAX_CONFIG_FILE_SIZE);
    defer allocator.free(content);

    const format = Format.fromExtension(path);
    return parseContent(allocator, content, format);
}

fn parseYamlContent(allocator: Allocator, content: []const u8) !Value.ValueData {
    // Use the external yaml library
    var docs = yaml.loadAll(allocator, content, .{}) catch {
        return error.ParseError;
    };
    defer {
        for (docs) |*d| d.deinit();
        allocator.free(docs);
    }

    if (docs.len == 0) {
        return .{ .null = {} };
    }

    // Resolve the first document to a value
    const resolved = yaml.resolveToValue(allocator, &docs[0], .{}) catch {
        return error.ParseError;
    };

    return convertYamlValue(allocator, resolved);
}

fn convertYamlValue(allocator: Allocator, val: yaml.Value) !Value.ValueData {
    return switch (val) {
        .null => .{ .null = {} },
        .bool => |b| .{ .bool = b },
        .int => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .str => |s| .{ .string = try allocator.dupe(u8, s) },
        .inf_pos => .{ .float = std.math.inf(f64) },
        .inf_neg => .{ .float = -std.math.inf(f64) },
        .nan => .{ .float = std.math.nan(f64) },
        .big_int => |s| .{ .string = try allocator.dupe(u8, s) }, // Store as string
        .seq => |items| {
            var list = try allocator.alloc(Value, items.len);
            for (items, 0..) |item, i| {
                list[i] = Value{
                    .allocator = allocator,
                    .data = try convertYamlValue(allocator, item),
                };
            }
            return .{ .list = list };
        },
        .map => |pairs| {
            var map = StringArrayHashMap(Value).empty;
            // INFO-5: Pre-allocate capacity since pair count is known
            try map.ensureTotalCapacity(allocator, @intCast(pairs.len));
            for (pairs) |pair| {
                // pair.k and pair.v are yaml.Value
                const key = switch (pair.k) {
                    .str => |s| try allocator.dupe(u8, s),
                    else => continue, // Skip non-string keys
                };
                try map.put(allocator, key, Value{
                    .allocator = allocator,
                    .data = try convertYamlValue(allocator, pair.v),
                });
            }
            return .{ .map = map };
        },
    };
}

fn parseJsonContent(allocator: Allocator, content: []const u8) !Value.ValueData {
    // Use std.json for parsing (the external json library is for JSON Schema validation)
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch {
        return error.ParseError;
    };
    defer parsed.deinit();

    return convertStdJsonValue(allocator, parsed.value);
}

fn convertStdJsonValue(allocator: Allocator, val: std.json.Value) !Value.ValueData {
    return switch (val) {
        .null => .{ .null = {} },
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| {
            var list = try allocator.alloc(Value, arr.items.len);
            for (arr.items, 0..) |item, i| {
                list[i] = Value{
                    .allocator = allocator,
                    .data = try convertStdJsonValue(allocator, item),
                };
            }
            return .{ .list = list };
        },
        .object => |obj| {
            var map = StringArrayHashMap(Value).empty;
            // INFO-5: Pre-allocate capacity since object entry count is known
            try map.ensureTotalCapacity(allocator, @intCast(obj.count()));
            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                try map.put(allocator, key, Value{
                    .allocator = allocator,
                    .data = try convertStdJsonValue(allocator, entry.value_ptr.*),
                });
            }
            return .{ .map = map };
        },
        .number_string => |s| {
            // Try to parse as integer first, then float
            if (std.fmt.parseInt(i64, s, 10)) |i| {
                return .{ .int = i };
            } else |_| {}
            if (std.fmt.parseFloat(f64, s)) |f| {
                return .{ .float = f };
            } else |_| {}
            return .{ .string = try allocator.dupe(u8, s) };
        },
    };
}

fn parseTomlContent(allocator: Allocator, content: []const u8) !Value.ValueData {
    // Use the external toml library
    var doc = toml.parse(allocator, content, .{}) catch {
        return error.ParseError;
    };
    defer doc.deinit();

    return convertTomlValue(allocator, doc.root.*);
}

fn convertTomlValue(allocator: Allocator, val: toml.Value) error{OutOfMemory}!Value.ValueData {
    return switch (val) {
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .integer => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .bool => |b| .{ .bool = b },
        .array => |arr| {
            const items = arr.items.items;
            var list = try allocator.alloc(Value, items.len);
            for (items, 0..) |item, i| {
                list[i] = Value{
                    .allocator = allocator,
                    .data = try convertTomlValue(allocator, item),
                };
            }
            return .{ .list = list };
        },
        .table => |tbl| {
            var map = StringArrayHashMap(Value).empty;
            try map.ensureTotalCapacity(allocator, @intCast(tbl.map.count()));
            var it = tbl.map.iterator();
            while (it.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                try map.put(allocator, key, Value{
                    .allocator = allocator,
                    .data = try convertTomlValue(allocator, entry.value_ptr.*.*),
                });
            }
            return .{ .map = map };
        },
        .datetime => |dt| {
            // Convert datetime to string representation
            var buf: [64]u8 = undefined;
            const len = formatTomlDatetime(&buf, dt);
            return .{ .string = try allocator.dupe(u8, buf[0..len]) };
        },
        .datetime_local => |dt| {
            var buf: [64]u8 = undefined;
            const len = formatTomlDatetimeLocal(&buf, dt);
            return .{ .string = try allocator.dupe(u8, buf[0..len]) };
        },
        .date_local => |d| {
            var buf: [16]u8 = undefined;
            const len = formatTomlDateLocal(&buf, d);
            return .{ .string = try allocator.dupe(u8, buf[0..len]) };
        },
        .time_local => |t| {
            var buf: [16]u8 = undefined;
            const len = formatTomlTimeLocal(&buf, t);
            return .{ .string = try allocator.dupe(u8, buf[0..len]) };
        },
    };
}

// R-02: Generic datetime formatter shared by DateTime and DateTimeLocal.
// Both types have the same year/month/day/hour/minute/second fields.
fn formatTomlDatetimeFields(comptime T: type, val: T, buf: []u8) usize {
    return (std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        val.year,
        val.month,
        val.day,
        val.hour,
        val.minute,
        val.second,
    }) catch @as([]u8, buf[0..0])).len;
}

fn formatTomlDatetime(buf: []u8, dt: toml.DateTime) usize {
    return formatTomlDatetimeFields(toml.DateTime, dt, buf);
}

fn formatTomlDatetimeLocal(buf: []u8, dt: toml.DateTimeLocal) usize {
    return formatTomlDatetimeFields(toml.DateTimeLocal, dt, buf);
}

fn formatTomlDateLocal(buf: []u8, d: toml.DateLocal) usize {
    return (std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        d.year,
        d.month,
        d.day,
    }) catch @as([]u8, buf[0..0])).len;
}

fn formatTomlTimeLocal(buf: []u8, t: toml.TimeLocal) usize {
    return (std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{
        t.hour,
        t.minute,
        t.second,
    }) catch @as([]u8, buf[0..0])).len;
}

fn parseIniContent(allocator: Allocator, content: []const u8) !Value.ValueData {
    var doc = ini.parse(allocator, content) catch {
        return error.ParseError;
    };
    defer doc.deinit();

    var map = StringArrayHashMap(Value).empty;
    errdefer map.deinit(allocator);
    // INFO-5: Pre-allocate capacity since global + section count is known
    try map.ensureTotalCapacity(allocator, @intCast(doc.global.count() + doc.sections.count()));

    // Add global values
    var global_iter = doc.global.iterator();
    while (global_iter.next()) |entry| {
        const key = try allocator.dupe(u8, entry.key_ptr.*);
        try map.put(allocator, key, Value{
            .allocator = allocator,
            .data = .{ .string = try allocator.dupe(u8, entry.value_ptr.*) },
        });
    }

    // Add section values as nested maps
    var section_iter = doc.sections.iterator();
    while (section_iter.next()) |section_entry| {
        var section_map = StringArrayHashMap(Value).empty;
        // INFO-5: Pre-allocate capacity since section value count is known
        try section_map.ensureTotalCapacity(allocator, @intCast(section_entry.value_ptr.values.count()));
        var value_iter = section_entry.value_ptr.values.iterator();
        while (value_iter.next()) |value_entry| {
            const key = try allocator.dupe(u8, value_entry.key_ptr.*);
            try section_map.put(allocator, key, Value{
                .allocator = allocator,
                .data = .{ .string = try allocator.dupe(u8, value_entry.value_ptr.*) },
            });
        }
        const section_name = try allocator.dupe(u8, section_entry.key_ptr.*);
        try map.put(allocator, section_name, Value{
            .allocator = allocator,
            .data = .{ .map = section_map },
        });
    }

    return .{ .map = map };
}

fn parsePropertiesContent(allocator: Allocator, content: []const u8) !Value.ValueData {
    var props = properties.parse(allocator, content) catch {
        return error.ParseError;
    };
    defer props.deinit();

    var map = StringArrayHashMap(Value).empty;
    errdefer map.deinit(allocator);
    // INFO-5: Pre-allocate capacity since property count is known
    try map.ensureTotalCapacity(allocator, @intCast(props.values.count()));

    var iter = props.values.iterator();
    while (iter.next()) |entry| {
        const key = try allocator.dupe(u8, entry.key_ptr.*);
        try map.put(allocator, key, Value{
            .allocator = allocator,
            .data = .{ .string = try allocator.dupe(u8, entry.value_ptr.*) },
        });
    }

    return .{ .map = map };
}

// ============================================================================
// Safe Write Config (#29)
// ============================================================================

/// Error for safe write operations
pub const SafeWriteError = error{
    FileExists,
    IoError,
    OutOfMemory,
    /// Security: Path contains traversal sequences (CWE-22, #62)
    PathTraversalDetected,
    /// Security: Source or backup target is a symlink (CWE-59, CWE-200, AS-02).
    /// Backing up a symlinked path would follow the link and leak the link
    /// target's contents into the `.bak` file (or overwrite an arbitrary file).
    SymlinkNotAllowed,
};

/// Options for safe write operations
pub const SafeWriteOptions = struct {
    /// Create backup before overwriting
    create_backup: bool = false,
    /// Backup file suffix
    backup_suffix: []const u8 = ".bak",
    /// Use atomic write (write to temp file, then rename)
    atomic: bool = true,
};

/// Q-NEW-18: Shared write step for `safeWriteConfig` and
/// `safeWriteConfigWithBackup`. Each public function keeps only its distinct
/// pre-step (existence check vs. backup copy); this helper performs the
/// content write identically for both.
///
/// When `atomic` is true the content is written to a randomized, exclusive
/// temp file, synced to disk, then renamed over `path` (atomic temp+rename).
/// Otherwise it is written directly with restrictive (0o600) permissions.
///
/// Safety: closes the temp fd and deletes the temp file on any write/sync/
/// rename failure (errdefer), and frees `temp_path` on every exit path —
/// including the non-EEXIST create error (Q-NEW-05).
fn writeAtomic(
    allocator: Allocator,
    path: []const u8,
    content: []const u8,
    atomic: bool,
) SafeWriteError!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    if (atomic) {
        // Write to temp file first (randomized, exclusive)
        var temp_path: []u8 = &.{};
        var temp_file: std.Io.File = undefined;
        var attempt: u8 = 0;
        while (attempt < 5) : (attempt += 1) {
            var random_bytes: [8]u8 = undefined;
            io.randomSecure(&random_bytes) catch return SafeWriteError.IoError;
            const random_suffix = std.fmt.bytesToHex(random_bytes, .lower);
            temp_path = std.fmt.allocPrint(allocator, "{s}.tmp.{s}", .{ path, &random_suffix }) catch return SafeWriteError.OutOfMemory;
            temp_file = createFileNoFollow(temp_path, 0o600, true) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(temp_path);
                    continue;
                },
                // Q-NEW-05: Free temp_path before returning. This error path is
                // reached before the post-loop `defer allocator.free(temp_path)`
                // is registered, so any non-EEXIST create error would otherwise
                // leak the allocation.
                else => {
                    allocator.free(temp_path);
                    return SafeWriteError.IoError;
                },
            };
            break;
        }
        if (attempt == 5) return SafeWriteError.IoError;
        defer allocator.free(temp_path);
        errdefer cwd.deleteFile(io, temp_path) catch {};
        // R-01/T-01: Ensure temp file handle is closed on write/sync failure
        // so the fd is not leaked before errdefer cleanup deletes the file.
        errdefer temp_file.close(io);

        temp_file.writeStreamingAll(io, content) catch return SafeWriteError.IoError;
        // R-01/T-01: Flush data to disk before rename to guarantee durability
        temp_file.sync(io) catch return SafeWriteError.IoError;
        temp_file.close(io);

        // Rename temp to target
        cwd.rename(temp_path, cwd, path, io) catch {
            cwd.deleteFile(io, temp_path) catch {};
            return SafeWriteError.IoError;
        };
    } else {
        // Security: Use restrictive file permissions (CWE-732, #75)
        const file = createFileNoFollow(path, 0o600, false) catch return SafeWriteError.IoError;
        defer file.close(io);
        file.writeStreamingAll(io, content) catch return SafeWriteError.IoError;
    }
}

/// Safely write configuration to a file without overwriting existing files.
/// Use this to prevent accidental data loss. Returns `FileExists` if the
/// target path already exists.
///
/// A-01: Uses the same safety guarantees as `serialize.safeWriteToFile`
/// (atomic temp+rename, sync before close, errdefer cleanup), but takes
/// raw content instead of a typed value. See `safeWriteConfigWithBackup`
/// for a variant that allows overwriting with backup.
///
/// Security: Validates path to prevent path traversal attacks (CWE-22, #62)
pub fn safeWriteConfig(
    allocator: Allocator,
    path: []const u8,
    content: []const u8,
    options: SafeWriteOptions,
) SafeWriteError!void {
    // Security: Validate path does not contain traversal sequences
    if (!secret.isPathSafe(path)) {
        return SafeWriteError.PathTraversalDetected;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Check if file exists
    if (cwd.access(io, path, .{})) {
        return SafeWriteError.FileExists;
    } else |_| {}

    // Q-NEW-18: Shared atomic/direct write step.
    try writeAtomic(allocator, path, content, options.atomic);
}

/// Write config, creating a backup of any existing file first.
/// Unlike `safeWriteConfig`, this function allows overwriting (after backup).
///
/// A-01: Shares the same atomic-write safety guarantees (sync, errdefer,
/// path validation) as `safeWriteConfig` and `serialize.safeWriteToFile`.
///
/// Security: Validates path to prevent path traversal attacks (CWE-22, #62)
pub fn safeWriteConfigWithBackup(
    allocator: Allocator,
    path: []const u8,
    content: []const u8,
    options: SafeWriteOptions,
) SafeWriteError!void {
    // Security: Validate path does not contain traversal sequences
    if (!secret.isPathSafe(path)) {
        return SafeWriteError.PathTraversalDetected;
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Check if file exists and create backup if requested
    if (cwd.access(io, path, .{})) {
        if (options.create_backup) {
            const backup_path = std.fmt.allocPrint(allocator, "{s}{s}", .{ path, options.backup_suffix }) catch return SafeWriteError.OutOfMemory;
            defer allocator.free(backup_path);

            // AS-02: Refuse to back up a symlinked source. `Dir.copyFile` opens
            // the source following symlinks, so a symlinked `path` would leak
            // the link target's contents into the `.bak` (CWE-59, CWE-200).
            // This mirrors serialize.zig:writeToFileWithBackup (ADV-05).
            if (secret.isSymlink(path)) {
                return SafeWriteError.SymlinkNotAllowed;
            }
            // AS-02: Also refuse if the backup target is itself a symlink, to
            // avoid overwriting an arbitrary file through the link.
            if (secret.isSymlink(backup_path)) {
                return SafeWriteError.SymlinkNotAllowed;
            }

            cwd.copyFile(path, cwd, backup_path, io, .{}) catch return SafeWriteError.IoError;
        }
    } else |_| {}

    // Q-NEW-18: Shared atomic/direct write step.
    try writeAtomic(allocator, path, content, options.atomic);
}

// ============================================================================
// Custom Format Decoders (#39)
// ============================================================================

/// Custom format decoder function type
pub const FormatDecoder = *const fn (allocator: Allocator, content: []const u8) anyerror!Value.ValueData;

/// Registry for custom format decoders
pub const FormatRegistry = struct {
    allocator: Allocator,
    decoders: std.StringHashMap(FormatDecoder),

    pub fn init(allocator: Allocator) FormatRegistry {
        return .{
            .allocator = allocator,
            .decoders = std.StringHashMap(FormatDecoder).init(allocator),
        };
    }

    pub fn deinit(self: *FormatRegistry) void {
        self.decoders.deinit();
    }

    /// Register a custom format decoder
    /// Extension should include the dot (e.g., ".hcl", ".conf")
    pub fn register(self: *FormatRegistry, extension: []const u8, decoder: FormatDecoder) !void {
        try self.decoders.put(extension, decoder);
    }

    /// Unregister a format decoder
    pub fn unregister(self: *FormatRegistry, extension: []const u8) bool {
        return self.decoders.remove(extension);
    }

    /// Check if a format is registered
    pub fn hasFormat(self: *const FormatRegistry, extension: []const u8) bool {
        return self.decoders.contains(extension);
    }

    /// Get decoder for a format
    pub fn getDecoder(self: *const FormatRegistry, extension: []const u8) ?FormatDecoder {
        return self.decoders.get(extension);
    }

    /// Parse content using a registered decoder
    pub fn parse(self: *const FormatRegistry, allocator: Allocator, content: []const u8, extension: []const u8) !Value {
        const decoder = self.decoders.get(extension) orelse return error.UnknownFormat;

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const data = try decoder(arena.allocator(), content);

        return Value{
            .allocator = allocator,
            .data = data,
            .arena = arena,
        };
    }

    /// Parse file with auto-detection from extension
    pub fn parseFile(self: *const FormatRegistry, allocator: Allocator, path: []const u8) !Value {
        // Get extension
        const ext = getExtension(path) orelse return error.UnknownFormat;

        // Check custom decoders first
        if (self.decoders.get(ext)) |decoder| {
            const cfg_io = std.Io.Threaded.global_single_threaded.io();
            const file = secret.openFileReadNoFollow(path) catch |err| switch (err) {
                error.SymlinkNotAllowed => return error.SymlinkNotAllowed,
                error.FileNotFound => return error.FileNotFound,
                else => return error.FileNotFound,
            };
            defer file.close(cfg_io);

            const content = try secret.readFileToEnd(file, allocator, MAX_CONFIG_FILE_SIZE);
            defer allocator.free(content);

            var arena = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            const data = try decoder(arena.allocator(), content);

            return Value{
                .allocator = allocator,
                .data = data,
                .arena = arena,
            };
        }

        // Fall back to built-in formats
        return config_parseFile(allocator, path);
    }
};

fn getExtension(path: []const u8) ?[]const u8 {
    const last_dot = mem.lastIndexOfScalar(u8, path, '.') orelse return null;
    return path[last_dot..];
}

// Alias for the public parseFile to avoid naming conflict
const config_parseFile = parseFile;

/// Global format registry (for convenience)
/// WARNING: Thread Safety (#51)
/// This global registry uses a mutex for thread-safe initialization,
/// but the underlying FormatRegistry operations are not fully thread-safe.
/// For multi-threaded applications, prefer creating and managing your own
/// FormatRegistry instance per-thread or use external synchronization.
var global_registry: ?FormatRegistry = null;
var global_registry_mutex: std.Io.Mutex = .init;

/// Get or create global format registry
/// Thread-safe initialization using mutex (#51 fix)
pub fn getGlobalRegistry(allocator: Allocator) *FormatRegistry {
    const io = std.Io.Threaded.global_single_threaded.io();
    global_registry_mutex.lockUncancelable(io);
    defer global_registry_mutex.unlock(io);

    if (global_registry == null) {
        global_registry = FormatRegistry.init(allocator);
    }
    return &global_registry.?;
}

/// Register a custom format in the global registry
/// Note: Uses mutex for thread-safe access to global registry
pub fn registerFormat(allocator: Allocator, extension: []const u8, decoder: FormatDecoder) !void {
    const registry = getGlobalRegistry(allocator);
    // Note: register() itself is not thread-safe; callers should ensure
    // all registrations happen before concurrent reads, or use external sync
    try registry.register(extension, decoder);
}

/// Reset the global registry (mainly for testing)
/// Thread-safe: Uses mutex
pub fn resetGlobalRegistry() void {
    const io = std.Io.Threaded.global_single_threaded.io();
    global_registry_mutex.lockUncancelable(io);
    defer global_registry_mutex.unlock(io);

    if (global_registry) |*reg| {
        reg.deinit();
    }
    global_registry = null;
}

// ============================================================================
// Tests
// ============================================================================

test {
    _ = loader;
    _ = provenance;
    _ = xdg;
    _ = dotenv;
    _ = secret;
    _ = flags;
    _ = ini;
    _ = properties;
    _ = watch;
    _ = remote;
    _ = validation;
    _ = async_load;
    _ = diff;
    _ = @import("integration_test.zig");
}

test "FormatRegistry custom decoder" {
    var registry = FormatRegistry.init(std.testing.allocator);
    defer registry.deinit();

    // Register a custom decoder for .custom format
    const customDecoder = struct {
        fn decode(allocator: Allocator, content: []const u8) anyerror!Value.ValueData {
            var map = StringArrayHashMap(Value).empty;
            // Simple parser: treat each line as key=value
            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                if (mem.indexOf(u8, line, "=")) |eq| {
                    const key = try allocator.dupe(u8, line[0..eq]);
                    try map.put(allocator, key, Value{
                        .allocator = allocator,
                        .data = .{ .string = try allocator.dupe(u8, line[eq + 1 ..]) },
                    });
                }
            }
            return .{ .map = map };
        }
    }.decode;

    try registry.register(".custom", customDecoder);
    try std.testing.expect(registry.hasFormat(".custom"));
}

test "SafeWriteOptions defaults" {
    const opts = SafeWriteOptions{};
    try std.testing.expect(opts.atomic);
    try std.testing.expect(!opts.create_backup);
    try std.testing.expectEqualStrings(".bak", opts.backup_suffix);
}

test "unified config: parse YAML content" {
    // Simple flat structure
    const content =
        \\host: localhost
        \\port: 8080
        \\debug: true
    ;

    var config = try parseContent(std.testing.allocator, content, .yaml);
    defer config.deinit();

    try std.testing.expectEqualStrings("localhost", config.getString("host").?);
    try std.testing.expectEqual(@as(i64, 8080), config.getInt("port").?);
    try std.testing.expectEqual(true, config.getBool("debug").?);
}

test "unified config: parse YAML nested content" {
    // Nested structure
    const content =
        \\server:
        \\  host: localhost
        \\  port: 8080
    ;

    var config = try parseContent(std.testing.allocator, content, .yaml);
    defer config.deinit();

    try std.testing.expectEqualStrings("localhost", config.getString("server.host").?);
    try std.testing.expectEqual(@as(i64, 8080), config.getInt("server.port").?);
}

test "unified config: parse JSON content" {
    const content =
        \\{"server": {"host": "localhost", "port": 8080}, "debug": true}
    ;

    var config = try parseContent(std.testing.allocator, content, .json);
    defer config.deinit();

    try std.testing.expectEqualStrings("localhost", config.getString("server.host").?);
    try std.testing.expectEqual(@as(i64, 8080), config.getInt("server.port").?);
    try std.testing.expectEqual(true, config.getBool("debug").?);
}

test "unified config: parse TOML content" {
    // Simple flat TOML content
    const content =
        \\host = "localhost"
        \\port = 8080
        \\debug = true
    ;

    var config = try parseContent(std.testing.allocator, content, .toml);
    defer config.deinit();

    try std.testing.expectEqualStrings("localhost", config.getString("host").?);
    try std.testing.expectEqual(@as(i64, 8080), config.getInt("port").?);
    try std.testing.expectEqual(true, config.getBool("debug").?);
}

// ============================================================================
// GAP-0010: Config.parseContent with .auto should use content detection
// ============================================================================

test "unified config: parseContent with .auto detects JSON (GAP-0010)" {
    // GAP-0010: When .auto is specified, Config.parseContent should detect
    // the format from content instead of blindly defaulting to YAML.
    const json_content =
        \\{"host": "json-host", "port": 3000}
    ;

    var config = try parseContent(std.testing.allocator, json_content, .auto);
    defer config.deinit();

    try std.testing.expectEqualStrings("json-host", config.getString("host").?);
    try std.testing.expectEqual(@as(i64, 3000), config.getInt("port").?);
}

test "unified config: parseContent with .auto detects TOML (GAP-0010)" {
    const toml_content =
        \\host = "toml-host"
        \\port = 4000
    ;

    var config = try parseContent(std.testing.allocator, toml_content, .auto);
    defer config.deinit();

    try std.testing.expectEqualStrings("toml-host", config.getString("host").?);
    try std.testing.expectEqual(@as(i64, 4000), config.getInt("port").?);
}

// ============================================================================
// R-01/T-01: Atomic write tests (sync, errdefer, path traversal, backup)
// ============================================================================

test "R-01/T-01: safeWriteConfig creates correct file with atomic write" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tst_io = std.Io.Threaded.global_single_threaded.io();

    // Get real path for the temp dir
    const dir_path = tmp_dir.dir.realPathFileAlloc(tst_io, ".", std.testing.allocator) catch return;
    defer std.testing.allocator.free(dir_path);

    const file_path = std.fmt.allocPrint(std.testing.allocator, "{s}/test_write.json", .{dir_path}) catch return;
    defer std.testing.allocator.free(file_path);

    const content = "{\"key\": \"value\"}";
    try safeWriteConfig(std.testing.allocator, file_path, content, .{ .atomic = true });

    // Verify file content is correct
    const read_content = std.Io.Dir.cwd().readFileAlloc(tst_io, file_path, std.testing.allocator, std.Io.Limit.limited(4096)) catch return;
    defer std.testing.allocator.free(read_content);
    try std.testing.expectEqualStrings(content, read_content);
}

test "R-01/T-01: safeWriteConfig rejects path traversal" {
    try std.testing.expectError(
        SafeWriteError.PathTraversalDetected,
        safeWriteConfig(std.testing.allocator, "../etc/passwd", "bad", .{}),
    );
    try std.testing.expectError(
        SafeWriteError.PathTraversalDetected,
        safeWriteConfig(std.testing.allocator, "/tmp/../../etc/passwd", "bad", .{}),
    );
}

test "R-01/T-01: safeWriteConfigWithBackup creates backup file" {
    const tst_io2 = std.Io.Threaded.global_single_threaded.io();
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const dir_path = tmp_dir.dir.realPathFileAlloc(tst_io2, ".", std.testing.allocator) catch return;
    defer std.testing.allocator.free(dir_path);

    const file_path = std.fmt.allocPrint(std.testing.allocator, "{s}/config.json", .{dir_path}) catch return;
    defer std.testing.allocator.free(file_path);

    // Create original file
    const original = "original content";
    {
        const f = std.Io.Dir.cwd().createFile(tst_io2, file_path, .{}) catch return;
        f.writeStreamingAll(tst_io2, original) catch {};
        f.close(tst_io2);
    }

    // Write with backup
    const updated = "updated content";
    try safeWriteConfigWithBackup(std.testing.allocator, file_path, updated, .{ .create_backup = true, .atomic = true });

    // Verify updated content
    const read_content = std.Io.Dir.cwd().readFileAlloc(tst_io2, file_path, std.testing.allocator, std.Io.Limit.limited(4096)) catch return;
    defer std.testing.allocator.free(read_content);
    try std.testing.expectEqualStrings(updated, read_content);

    // Verify backup exists
    const backup_path = std.fmt.allocPrint(std.testing.allocator, "{s}.bak", .{file_path}) catch return;
    defer std.testing.allocator.free(backup_path);
    const backup_content = std.Io.Dir.cwd().readFileAlloc(tst_io2, backup_path, std.testing.allocator, std.Io.Limit.limited(4096)) catch return;
    defer std.testing.allocator.free(backup_content);
    try std.testing.expectEqualStrings(original, backup_content);
}

test "R-01/T-01: safeWriteConfigWithBackup rejects path traversal" {
    try std.testing.expectError(
        SafeWriteError.PathTraversalDetected,
        safeWriteConfigWithBackup(std.testing.allocator, "../etc/shadow", "bad", .{}),
    );
}

test "AS-02: safeWriteConfigWithBackup rejects symlinked source" {
    const builtin = @import("builtin");
    // Symlink detection (isSymlink) is POSIX-specific in this test setup.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const tst_io = std.Io.Threaded.global_single_threaded.io();
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const dir_path = tmp_dir.dir.realPathFileAlloc(tst_io, ".", std.testing.allocator) catch return;
    defer std.testing.allocator.free(dir_path);

    const real_path = std.fmt.allocPrint(std.testing.allocator, "{s}/as02_real.json", .{dir_path}) catch return;
    defer std.testing.allocator.free(real_path);
    const link_path = std.fmt.allocPrint(std.testing.allocator, "{s}/as02_link.json", .{dir_path}) catch return;
    defer std.testing.allocator.free(link_path);

    // Create a real file with sensitive content that must not leak into a .bak.
    {
        const f = std.Io.Dir.cwd().createFile(tst_io, real_path, .{}) catch return;
        f.writeStreamingAll(tst_io, "{\"secret\":\"do-not-leak\"}") catch {};
        f.close(tst_io);
    }

    // Point a symlink at the real file; skip if symlinks are unsupported.
    std.Io.Dir.cwd().symLink(tst_io, real_path, link_path, .{}) catch return;

    // Backing up the symlinked source must be rejected, not followed.
    const result = safeWriteConfigWithBackup(
        std.testing.allocator,
        link_path,
        "{\"new\":\"value\"}",
        .{ .create_backup = true, .atomic = true },
    );
    try std.testing.expectError(SafeWriteError.SymlinkNotAllowed, result);

    // No backup file should have been created from the symlinked source.
    const backup_path = std.fmt.allocPrint(std.testing.allocator, "{s}.bak", .{link_path}) catch return;
    defer std.testing.allocator.free(backup_path);
    std.Io.Dir.cwd().access(tst_io, backup_path, .{}) catch {
        return; // expected: backup absent
    };
    return error.TestUnexpectedResult; // backup was created -> symlink was followed
}

test "Q-NEW-05: safeWriteConfig does not leak temp_path on create error" {
    // A path whose parent directory does not exist makes the temp-file create
    // fail with FileNotFound (a non-EEXIST error), exercising the `else` arm of
    // the create switch. Before the fix, temp_path leaked there; the testing
    // allocator fails the test on any leak.
    const bad_path = "no_such_dir_qnew05/config.json";
    try std.testing.expectError(
        SafeWriteError.IoError,
        safeWriteConfig(std.testing.allocator, bad_path, "{\"k\":1}", .{ .atomic = true }),
    );
}

test "Q-NEW-05: safeWriteConfigWithBackup does not leak temp_path on create error" {
    const bad_path = "no_such_dir_qnew05b/config.json";
    try std.testing.expectError(
        SafeWriteError.IoError,
        safeWriteConfigWithBackup(std.testing.allocator, bad_path, "{\"k\":1}", .{ .atomic = true }),
    );
}

// ============================================================================
// ADV-01: .auto format returns error instead of unreachable
// ============================================================================

test "ADV-01: parseContent with .auto format detects JSON correctly" {
    // Verify that .auto resolves to the correct format via content detection
    const json_content =
        \\{"key": "value"}
    ;
    var config = try parseContent(std.testing.allocator, json_content, .auto);
    defer config.deinit();
    try std.testing.expectEqualStrings("value", config.getString("key").?);
}

test "ADV-01: parseContent with .auto format detects YAML correctly" {
    const yaml_content =
        \\key: value
    ;
    var config = try parseContent(std.testing.allocator, yaml_content, .auto);
    defer config.deinit();
    try std.testing.expectEqualStrings("value", config.getString("key").?);
}

test "parallel re-export is reachable" {
    // Smoke test: verify parallel.zig is reachable through the public
    // config module. Parallel config ops need file IO state that's fiddly
    // to stand up in a unit test, so we just assert the pool lifecycle
    // entry points are exposed and `deinitPool()` is safely callable.
    _ = @TypeOf(parallel.getPool);
    parallel.deinitPool();
}

test "Q-NEW-07: parseFile propagates real open error instead of FileNotFound" {
    const builtin = @import("builtin");
    // O_NOFOLLOW / fchmod semantics are POSIX-specific.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // A chmod 0o000 file is still readable as root, so the AccessDenied path
    // would not trigger. Skip rather than assert the wrong error.
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;

    const tst_io = std.Io.Threaded.global_single_threaded.io();
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const dir_path = tmp_dir.dir.realPathFileAlloc(tst_io, ".", std.testing.allocator) catch return;
    defer std.testing.allocator.free(dir_path);

    const file_path = std.fmt.allocPrint(std.testing.allocator, "{s}/noperm.json", .{dir_path}) catch return;
    defer std.testing.allocator.free(file_path);

    // Create a file with no permissions so opening it fails with AccessDenied.
    {
        const f = std.Io.Dir.cwd().createFile(tst_io, file_path, .{}) catch return;
        f.setPermissions(tst_io, std.Io.File.Permissions.fromMode(0o000)) catch {
            f.close(tst_io);
            return; // Filesystem does not honor permissions; skip.
        };
        f.close(tst_io);
    }

    // The real open error (AccessDenied) must be propagated, not masked as
    // FileNotFound. A FileNotFound here would be the regression.
    const result = parseFile(std.testing.allocator, file_path);
    try std.testing.expectError(error.AccessDenied, result);
}

test "GAP-NEW-01: config.validate alias matches documented API" {
    // README.md / docs/API.md document `config.validate.*`. Prove the alias
    // resolves to the same validation functions.
    try std.testing.expect(validate == validation);

    // Exercise a documented entry point through the alias.
    try validate.required("non-empty");
    try std.testing.expectError(ValidationError.Required, validate.required(null));
    try std.testing.expectError(ValidationError.Required, validate.required(""));
}

// External dependency namespaces re-exported from this module. They are
// skipped by the recursive reference guard below because their own cold
// public-API paths are the upstream projects' responsibility to migrate, and
// `config`'s actual usage of them is already covered by the rest of the suite.
const refall_skip_namespaces = [_][]const u8{ "yaml", "toml", "json" };

/// Recursively reference every in-repo public declaration so the compiler is
/// forced to semantically analyze it. Without this, uncalled `pub fn`s are
/// never compile-checked (Zig only analyzes reached code), which previously
/// hid an incomplete Zig 0.15->0.16 migration in cold public-API paths. Keep
/// this guard green: a new compile error here means a public symbol regressed.
fn refAllInRepo(comptime T: type) void {
    inline for (comptime std.meta.declarations(T)) |decl| {
        comptime var skip = false;
        inline for (refall_skip_namespaces) |name| {
            if (comptime std.mem.eql(u8, name, decl.name)) skip = true;
        }
        if (!skip) {
            const field = @field(T, decl.name);
            if (@TypeOf(field) == type) {
                switch (@typeInfo(field)) {
                    .@"struct", .@"enum", .@"union", .@"opaque" => refAllInRepo(field),
                    else => {},
                }
            } else {
                _ = &@field(T, decl.name);
            }
        }
    }
}

test "all in-repo public declarations compile (latent-compile-error guard)" {
    @setEvalBranchQuota(200000);
    refAllInRepo(@This());
}
