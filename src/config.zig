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
pub const async_load = @import("async.zig");
pub const diff = @import("diff.zig");

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
        map: std.StringArrayHashMap(Self),
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
    pub fn getMap(self: Self) ?std.StringArrayHashMap(Self) {
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
        .auto => unreachable,
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

    // Security: Check for symlinks before opening to prevent symlink attacks (CWE-59, #72)
    if (secret.isSymlink(path)) {
        return error.SymlinkNotAllowed;
    }

    const file = secret.openFileReadNoFollow(path) catch |err| switch (err) {
        error.SymlinkNotAllowed => return error.SymlinkNotAllowed,
        error.FileNotFound => return error.FileNotFound,
        else => return error.FileNotFound,
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, MAX_CONFIG_FILE_SIZE);
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
            var map = std.StringArrayHashMap(Value).init(allocator);
            for (pairs) |pair| {
                // pair.k and pair.v are yaml.Value
                const key = switch (pair.k) {
                    .str => |s| try allocator.dupe(u8, s),
                    else => continue, // Skip non-string keys
                };
                try map.put(key, Value{
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
            var map = std.StringArrayHashMap(Value).init(allocator);
            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                try map.put(key, Value{
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
            var list = try allocator.alloc(Value, arr.items.len);
            for (arr.items, 0..) |item, i| {
                list[i] = Value{
                    .allocator = allocator,
                    .data = try convertTomlValue(allocator, item.*),
                };
            }
            return .{ .list = list };
        },
        .table => |tbl| {
            var map = std.StringArrayHashMap(Value).init(allocator);
            for (tbl.entries) |entry| {
                const key = try allocator.dupe(u8, entry.key);
                try map.put(key, Value{
                    .allocator = allocator,
                    .data = try convertTomlValue(allocator, entry.value.*),
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

fn formatTomlDatetime(buf: []u8, dt: toml.DateTime) usize {
    return (std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
    }) catch buf[0..0]).len;
}

fn formatTomlDatetimeLocal(buf: []u8, dt: toml.DateTimeLocal) usize {
    return (std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
    }) catch buf[0..0]).len;
}

fn formatTomlDateLocal(buf: []u8, d: toml.DateLocal) usize {
    return (std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        d.year,
        d.month,
        d.day,
    }) catch buf[0..0]).len;
}

fn formatTomlTimeLocal(buf: []u8, t: toml.TimeLocal) usize {
    return (std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{
        t.hour,
        t.minute,
        t.second,
    }) catch buf[0..0]).len;
}

fn parseIniContent(allocator: Allocator, content: []const u8) !Value.ValueData {
    var doc = ini.parse(allocator, content) catch {
        return error.ParseError;
    };
    defer doc.deinit();

    var map = std.StringArrayHashMap(Value).init(allocator);
    errdefer map.deinit();

    // Add global values
    var global_iter = doc.global.iterator();
    while (global_iter.next()) |entry| {
        const key = try allocator.dupe(u8, entry.key_ptr.*);
        try map.put(key, Value{
            .allocator = allocator,
            .data = .{ .string = try allocator.dupe(u8, entry.value_ptr.*) },
        });
    }

    // Add section values as nested maps
    var section_iter = doc.sections.iterator();
    while (section_iter.next()) |section_entry| {
        var section_map = std.StringArrayHashMap(Value).init(allocator);
        var value_iter = section_entry.value_ptr.values.iterator();
        while (value_iter.next()) |value_entry| {
            const key = try allocator.dupe(u8, value_entry.key_ptr.*);
            try section_map.put(key, Value{
                .allocator = allocator,
                .data = .{ .string = try allocator.dupe(u8, value_entry.value_ptr.*) },
            });
        }
        const section_name = try allocator.dupe(u8, section_entry.key_ptr.*);
        try map.put(section_name, Value{
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

    var map = std.StringArrayHashMap(Value).init(allocator);
    errdefer map.deinit();

    var iter = props.values.iterator();
    while (iter.next()) |entry| {
        const key = try allocator.dupe(u8, entry.key_ptr.*);
        try map.put(key, Value{
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

/// Safely write configuration to a file without overwriting existing files
/// Use this to prevent accidental data loss
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

    const fs = std.fs;
    const cwd = fs.cwd();

    // Check if file exists
    if (cwd.access(path, .{})) {
        return SafeWriteError.FileExists;
    } else |_| {}

    if (options.atomic) {
        // Write to temp file first (randomized, exclusive)
        var temp_path: []u8 = &.{};
        var temp_file: std.fs.File = undefined;
        var attempt: u8 = 0;
        while (attempt < 5) : (attempt += 1) {
            var random_bytes: [8]u8 = undefined;
            std.crypto.random.bytes(&random_bytes);
            const random_suffix = std.fmt.fmtSliceHexLower(&random_bytes);
            temp_path = std.fmt.allocPrint(allocator, "{s}.tmp.{s}", .{ path, random_suffix }) catch return SafeWriteError.OutOfMemory;
            temp_file = createFileNoFollow(temp_path, 0o600, true) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(temp_path);
                    continue;
                },
                else => return SafeWriteError.IoError,
            };
            break;
        }
        if (attempt == 5) return SafeWriteError.IoError;
        defer allocator.free(temp_path);
        temp_file.writeAll(content) catch {
            temp_file.close();
            cwd.deleteFile(temp_path) catch {};
            return SafeWriteError.IoError;
        };
        temp_file.close();

        // Rename temp to target
        cwd.rename(temp_path, path) catch {
            cwd.deleteFile(temp_path) catch {};
            return SafeWriteError.IoError;
        };
    } else {
        // Security: Use restrictive file permissions (CWE-732, #75)
        const file = createFileNoFollow(path, 0o600, false) catch return SafeWriteError.IoError;
        defer file.close();
        file.writeAll(content) catch return SafeWriteError.IoError;
    }
}

/// Write config with backup if file exists
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

    const fs = std.fs;
    const cwd = fs.cwd();

    // Check if file exists and create backup if requested
    if (cwd.access(path, .{})) {
        if (options.create_backup) {
            const backup_path = std.fmt.allocPrint(allocator, "{s}{s}", .{ path, options.backup_suffix }) catch return SafeWriteError.OutOfMemory;
            defer allocator.free(backup_path);

            cwd.copyFile(path, cwd, backup_path, .{}) catch return SafeWriteError.IoError;
        }
    } else |_| {}

    if (options.atomic) {
        var temp_path: []u8 = &.{};
        var temp_file: std.fs.File = undefined;
        var attempt: u8 = 0;
        while (attempt < 5) : (attempt += 1) {
            var random_bytes: [8]u8 = undefined;
            std.crypto.random.bytes(&random_bytes);
            const random_suffix = std.fmt.fmtSliceHexLower(&random_bytes);
            temp_path = std.fmt.allocPrint(allocator, "{s}.tmp.{s}", .{ path, random_suffix }) catch return SafeWriteError.OutOfMemory;
            temp_file = createFileNoFollow(temp_path, 0o600, true) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(temp_path);
                    continue;
                },
                else => return SafeWriteError.IoError,
            };
            break;
        }
        if (attempt == 5) return SafeWriteError.IoError;
        defer allocator.free(temp_path);
        temp_file.writeAll(content) catch {
            temp_file.close();
            cwd.deleteFile(temp_path) catch {};
            return SafeWriteError.IoError;
        };
        temp_file.close();

        cwd.rename(temp_path, path) catch {
            cwd.deleteFile(temp_path) catch {};
            return SafeWriteError.IoError;
        };
    } else {
        // Security: Use restrictive file permissions (CWE-732, #75)
        const file = createFileNoFollow(path, 0o600, false) catch return SafeWriteError.IoError;
        defer file.close();
        file.writeAll(content) catch return SafeWriteError.IoError;
    }
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
            const file = secret.openFileReadNoFollow(path) catch |err| switch (err) {
                error.SymlinkNotAllowed => return error.SymlinkNotAllowed,
                error.FileNotFound => return error.FileNotFound,
                else => return error.FileNotFound,
            };
            defer file.close();

            const content = try file.readToEndAlloc(allocator, MAX_CONFIG_FILE_SIZE);
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
var global_registry_mutex: std.Thread.Mutex = .{};

/// Get or create global format registry
/// Thread-safe initialization using mutex (#51 fix)
pub fn getGlobalRegistry(allocator: Allocator) *FormatRegistry {
    global_registry_mutex.lock();
    defer global_registry_mutex.unlock();

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
    global_registry_mutex.lock();
    defer global_registry_mutex.unlock();

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
            var map = std.StringArrayHashMap(Value).init(allocator);
            // Simple parser: treat each line as key=value
            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                if (mem.indexOf(u8, line, "=")) |eq| {
                    const key = try allocator.dupe(u8, line[0..eq]);
                    try map.put(key, Value{
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
