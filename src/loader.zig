// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Config Loader Module
//!
//! Configuration loading with XDG support, precedence rules,
//! and multiple format support. Provides Viper-like features including:
//! - Runtime Set() and SetDefault()
//! - Key aliases
//! - Case-insensitive key access
//! - Environment variable binding (BindEnv, AutomaticEnv)
//! - IsSet() to check explicit values
//!
//! ## Security Considerations
//!
//! **Parser Limits (CWE-400):** This module imposes the following limits to
//! prevent resource exhaustion from malicious configuration files:
//!
//! - **File size limit:** 1 MB maximum per configuration file
//! - **Nesting depth:** Limited by underlying parser (JSON/TOML/YAML)
//! - **String length:** No explicit limit; bounded by file size limit
//! - **Array elements:** No explicit limit; bounded by memory allocation
//!
//! The underlying Zig standard library parsers (std.json) have their own
//! recursion limits. For untrusted configuration sources, consider:
//!
//! - Validating file sizes before loading
//! - Using schema validation after parsing
//! - Running config loading in a separate process with resource limits
//!
//! This limitation is documented per security review (#54).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const xdg = @import("xdg.zig");
const environ = @import("environ.zig");
const provenance = @import("provenance.zig");
const flags_mod = @import("flags.zig");
const ini_mod = @import("ini.zig");
const properties_mod = @import("properties.zig");
const secret = @import("secret.zig");
const limits = @import("limits.zig");
const dotenv_mod = @import("dotenv.zig");

// Security: Import no-follow open helper for symlink attack prevention (CWE-59, #69)
const openFileReadNoFollow = secret.openFileReadNoFollow;
const Source = provenance.Source;
const ProvenanceTracker = provenance.ProvenanceTracker;

// Re-export flags types
pub const FlagParser = flags_mod.FlagParser;
pub const Flag = flags_mod.Flag;
pub const FlagValue = flags_mod.FlagValue;
pub const FlagError = flags_mod.FlagError;

/// Configuration loading errors
pub const LoadError = error{
    FileNotFound,
    ParseError,
    InvalidValue,
    MissingRequired,
    IoError,
    OutOfMemory,
};

/// Supported configuration formats
pub const Format = enum {
    json,
    toml,
    yaml,
    ini,
    properties,
    auto,

    pub fn fromExtension(path: []const u8) Format {
        if (mem.endsWith(u8, path, ".json")) return .json;
        if (mem.endsWith(u8, path, ".toml")) return .toml;
        if (mem.endsWith(u8, path, ".yaml") or mem.endsWith(u8, path, ".yml")) return .yaml;
        if (mem.endsWith(u8, path, ".ini")) return .ini;
        if (mem.endsWith(u8, path, ".properties")) return .properties;
        return .auto; // Unknown extension: use auto-detection rather than silent .toml default
    }
};

/// Configuration loading options
pub const LoadOptions = struct {
    /// Application name (for XDG paths)
    app_name: []const u8,
    /// Configuration filename (e.g., "config.toml")
    filename: []const u8 = "config.toml",
    /// Environment variable prefix (e.g., "MYAPP_")
    env_prefix: []const u8 = "",
    /// Whether to use XDG directories
    use_xdg: bool = true,
    /// Whether missing config files are allowed
    optional: bool = true,
    /// Specific config file path (overrides auto-discovery)
    config_path: ?[]const u8 = null,
    /// Enable case-insensitive key access (Viper-like)
    case_insensitive: bool = false,
    /// Key delimiter for nested keys (default: ".")
    /// Set to null to disable nested key support (#40)
    key_delimiter: ?[]const u8 = ".",
    /// Try loading extensionless config file (#44)
    /// If true, will try to detect format from content
    allow_extensionless: bool = false,
};

/// Environment key replacement rule
pub const KeyReplacement = struct {
    from: []const u8,
    to: []const u8,
};

/// Environment key replacer configuration
pub const EnvKeyReplacer = struct {
    /// Replacement rules (e.g., "." -> "_")
    replacements: []const KeyReplacement = &.{},
    /// Convert to uppercase
    to_upper: bool = true,
};

/// Configuration loader with Viper-like features.
///
/// `T` must be a struct type where every field has a default value.  The loader
/// populates fields from configuration files, environment variables, flags, and
/// runtime overrides using Viper-like precedence rules (overrides > flags > env
/// > config file > defaults).  Field types supported: `bool`, integer types,
/// float types, `[]const u8` (strings), and `?T` optionals wrapping any of
/// these.  Struct fields without defaults will cause a compile error when the
/// loader is instantiated.
pub fn Loader(comptime T: type) type {
    return struct {
        allocator: Allocator,
        tracker: ProvenanceTracker,
        config: T,
        /// Whether case-insensitive mode is enabled
        case_insensitive: bool = false,
        /// Key aliases (alias -> canonical key)
        aliases: std.StringHashMap([]const u8),
        /// Explicit env bindings (key -> env var names)
        env_bindings: std.StringHashMap([]const []const u8),
        /// Whether automatic env discovery is enabled
        automatic_env_enabled: bool = false,
        /// Prefix for automatic env discovery
        automatic_env_prefix: []const u8 = "",
        /// Environment key replacer
        env_key_replacer: ?EnvKeyReplacer = null,
        /// Runtime overrides (Set values)
        overrides: std.StringHashMap([]const u8),
        /// Runtime defaults (SetDefault values)
        runtime_defaults: std.StringHashMap([]const u8),
        /// Arena for string allocations
        arena: std.heap.ArenaAllocator,
        /// Search paths for config files (Viper's AddConfigPath)
        search_paths: std.ArrayListUnmanaged([]const u8),
        /// Config file name without extension (Viper's SetConfigName)
        config_name: ?[]const u8 = null,
        /// Key delimiter for nested keys (#40)
        key_delimiter: []const u8 = ".",

        const Self = @This();

        /// Initialize a new loader
        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .tracker = ProvenanceTracker.init(allocator),
                .config = .{},
                .aliases = std.StringHashMap([]const u8).init(allocator),
                .env_bindings = std.StringHashMap([]const []const u8).init(allocator),
                .overrides = std.StringHashMap([]const u8).init(allocator),
                .runtime_defaults = std.StringHashMap([]const u8).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
                .search_paths = .empty,
            };
        }

        /// Deinitialize the loader
        pub fn deinit(self: *Self) void {
            self.tracker.deinit();
            self.aliases.deinit();
            self.env_bindings.deinit();
            self.overrides.deinit();
            self.runtime_defaults.deinit();
            self.search_paths.deinit(self.allocator);
            self.arena.deinit();
        }

        /// Reset the loader to initial state, freeing all loaded values
        /// This allows reloading configuration without creating a new loader
        pub fn reset(self: *Self) void {
            // Free arena memory and reinitialize
            _ = self.arena.reset(.free_all);
            // Clear tracker
            self.tracker.values.clearAndFree();
            // Reset config to defaults
            self.config = .{};
            // Clear overrides and defaults (they used arena memory)
            self.overrides.clearRetainingCapacity();
            self.runtime_defaults.clearRetainingCapacity();
            // Clear search paths (they used arena memory)
            self.search_paths.clearRetainingCapacity();
            self.config_name = null;
            // Keep aliases and env bindings as they are configuration
        }

        // =====================================================================
        // Viper-like Value Management
        // =====================================================================

        /// Set a value explicitly (highest precedence - like Viper's Set)
        /// This value will override all other sources including flags and env vars.
        pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
            const norm_key = self.normalizeKey(key);
            const owned_value = try self.arena.allocator().dupe(u8, value);
            try self.overrides.put(norm_key, owned_value);
            try self.tracker.set(norm_key, owned_value, .override, "set()");
        }

        /// Set a default value at runtime (lowest precedence - like Viper's SetDefault)
        /// This is lower precedence than struct defaults and will only apply
        /// if no other source provides a value.
        pub fn setDefault(self: *Self, key: []const u8, value: []const u8) !void {
            const norm_key = self.normalizeKey(key);
            const owned_value = try self.arena.allocator().dupe(u8, value);
            try self.runtime_defaults.put(norm_key, owned_value);
            // Only set in tracker if no value exists yet
            if (self.tracker.get(norm_key) == null) {
                try self.tracker.set(norm_key, owned_value, .runtime_default, "setDefault()");
            }
        }

        /// Register a key alias (like Viper's RegisterAlias)
        /// After registration, both keys reference the same value.
        pub fn registerAlias(self: *Self, alias: []const u8, canonical: []const u8) !void {
            const norm_alias = self.normalizeKey(alias);
            const norm_canonical = self.normalizeKey(canonical);
            const owned_canonical = try self.arena.allocator().dupe(u8, norm_canonical);
            try self.aliases.put(norm_alias, owned_canonical);
        }

        /// Check if a key has been explicitly set (not just default)
        /// Returns true if the key was set from any source other than default.
        pub fn isSet(self: *const Self, key: []const u8) bool {
            const norm_key = self.normalizeKey(key);
            const resolved_key = self.resolveAlias(norm_key);

            if (self.tracker.get(resolved_key)) |tracked| {
                return tracked.source != .default and tracked.source != .runtime_default;
            }
            return false;
        }

        /// Check if a key exists (including defaults)
        pub fn has(self: *const Self, key: []const u8) bool {
            const norm_key = self.normalizeKey(key);
            const resolved_key = self.resolveAlias(norm_key);
            return self.tracker.get(resolved_key) != null;
        }

        /// Get a string value by key
        pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
            const norm_key = self.normalizeKey(key);
            const resolved_key = self.resolveAlias(norm_key);

            if (self.tracker.get(resolved_key)) |tracked| {
                return tracked.value;
            }
            return null;
        }

        /// Look up a configuration value by a dot-delimited or bracket-notation path.
        ///
        /// Supports two notations:
        ///   - Dot-delimited:  `"servers.0.host"` (native storage format)
        ///   - Bracket:        `"servers[0].host"` (normalized to dot form before lookup)
        ///
        /// Returns `null` if the path does not match any stored key. Paths longer
        /// than 512 bytes in bracket notation also return `null`.
        ///
        /// GAP-0041: JSON arrays are flattened into dot-delimited numeric-index
        /// keys by applyJsonValue (e.g., "ports.0", "servers.1.host"), so a
        /// direct `get()` call already matches the stored format.
        pub fn getPath(self: *const Self, path: []const u8) ?[]const u8 {
            // Direct lookup (handles dot-delimited paths natively)
            if (self.get(path)) |value| {
                return value;
            }

            // Normalize bracket notation: "a[0].b" -> "a.0.b"
            if (mem.indexOf(u8, path, "[")) |_| {
                var norm_buf: [512]u8 = undefined;
                var len: usize = 0;
                for (path) |c| {
                    if (len >= norm_buf.len) return null; // Path too long
                    if (c == '[') {
                        norm_buf[len] = '.';
                        len += 1;
                    } else if (c == ']') {
                        // skip closing bracket
                    } else {
                        norm_buf[len] = c;
                        len += 1;
                    }
                }
                return self.get(norm_buf[0..len]);
            }

            return null;
        }

        /// Get all keys that have been set (Viper's AllKeys)
        /// Returns a slice of all configuration keys
        pub fn allKeys(self: *const Self) ![]const []const u8 {
            var keys: std.ArrayListUnmanaged([]const u8) = .empty;
            errdefer keys.deinit(self.allocator);
            // INFO-5: Pre-allocate capacity since tracker value count is known
            try keys.ensureTotalCapacity(self.allocator, @intCast(self.tracker.values.count()));

            // Get keys from tracker
            var iter = self.tracker.values.keyIterator();
            while (iter.next()) |key| {
                try keys.append(self.allocator, key.*);
            }

            return keys.toOwnedSlice(self.allocator);
        }

        /// Get all settings as a string hashmap (Viper's AllSettings)
        /// Returns all configuration key-value pairs
        pub fn allSettings(self: *const Self) !std.StringHashMap([]const u8) {
            var settings = std.StringHashMap([]const u8).init(self.allocator);
            errdefer settings.deinit();
            // INFO-5: Pre-allocate capacity since tracker value count is known
            try settings.ensureTotalCapacity(@intCast(self.tracker.values.count()));

            var iter = self.tracker.values.iterator();
            while (iter.next()) |entry| {
                try settings.put(entry.key_ptr.*, entry.value_ptr.value);
            }

            return settings;
        }

        /// Extract a sub-configuration by prefix (Viper's Sub)
        /// Returns a new map containing only keys with the given prefix,
        /// with the prefix stripped from key names
        pub fn sub(self: *const Self, prefix: []const u8) !std.StringHashMap([]const u8) {
            var result = std.StringHashMap([]const u8).init(self.allocator);
            errdefer result.deinit();

            // R-06: Use shared buildPrefixWithDot helper (stack buffer + heap fallback)
            var dot_buf: [256]u8 = undefined;
            const pwd = try buildPrefixWithDot(self.allocator, &dot_buf, prefix);
            defer if (pwd.heap_alloc) |h| self.allocator.free(h);
            const prefix_with_dot = pwd.slice;

            var iter = self.tracker.values.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                if (mem.startsWith(u8, key, prefix_with_dot)) {
                    const sub_key = key[prefix_with_dot.len..];
                    if (sub_key.len > 0) {
                        try result.put(sub_key, entry.value_ptr.value);
                    }
                }
            }

            return result;
        }

        /// Check if a sub-configuration exists
        pub fn hasSub(self: *const Self, prefix: []const u8) bool {
            // R-06: Use shared buildPrefixWithDot helper (stack buffer + heap fallback)
            var dot_buf: [256]u8 = undefined;
            const pwd = buildPrefixWithDot(self.allocator, &dot_buf, prefix) catch return false;
            defer if (pwd.heap_alloc) |h| self.allocator.free(h);
            const prefix_with_dot = pwd.slice;

            var iter = self.tracker.values.keyIterator();
            while (iter.next()) |key| {
                if (mem.startsWith(u8, key.*, prefix_with_dot)) {
                    return true;
                }
            }
            return false;
        }

        // =====================================================================
        // Config Path Management (Viper's AddConfigPath/SetConfigName)
        // =====================================================================

        /// Add a path to search for config files (Viper's AddConfigPath)
        /// Paths are searched in the order they are added.
        pub fn addConfigPath(self: *Self, path: []const u8) !void {
            const owned_path = try self.arena.allocator().dupe(u8, path);
            try self.search_paths.append(self.allocator, owned_path);
        }

        /// Set the config file name without extension (Viper's SetConfigName)
        /// When searching, the loader will try this name with supported extensions
        /// (.json, .yaml, .yml, .toml)
        pub fn setConfigName(self: *Self, name: []const u8) !void {
            self.config_name = try self.arena.allocator().dupe(u8, name);
        }

        /// Set the key delimiter for nested keys (#40)
        /// Use "/" for path-like keys, ":" for namespace-style, etc.
        /// Set to "" to disable nested key parsing
        pub fn setKeyDelimiter(self: *Self, delimiter: []const u8) !void {
            self.key_delimiter = try self.arena.allocator().dupe(u8, delimiter);
        }

        /// Get current key delimiter
        pub fn getKeyDelimiter(self: *const Self) []const u8 {
            return self.key_delimiter;
        }

        /// Get all configured search paths
        pub fn getSearchPaths(self: *const Self) []const []const u8 {
            return self.search_paths.items;
        }

        /// Search for a config file in all configured paths
        /// Returns the first found file path, or null if none found
        fn findConfigFile(self: *Self, filename: []const u8) ?[]const u8 {
            return self.findConfigFileWithOptions(filename, false);
        }

        /// Search for a config file with extensionless support (#44)
        /// T-04: Check file existence using a stack buffer for path construction,
        /// falling back to heap only when the path exceeds the buffer size.
        fn tryAccessPath(self: *Self, comptime fmt: []const u8, args: anytype) ?[]const u8 {
            var path_buf: [1024]u8 = undefined;
            var heap_path: ?[]u8 = null;
            defer if (heap_path) |h| self.allocator.free(h);
            const full_path = std.fmt.bufPrint(&path_buf, fmt, args) catch blk: {
                const h = std.fmt.allocPrint(self.allocator, fmt, args) catch return null;
                heap_path = h;
                break :blk h;
            };
            if (std.Io.Dir.cwd().access(std.Io.Threaded.global_single_threaded.io(), full_path, .{})) {
                return self.arena.allocator().dupe(u8, full_path) catch null;
            } else |_| {}
            return null;
        }

        fn findConfigFileWithOptions(self: *Self, filename: []const u8, allow_extensionless: bool) ?[]const u8 {
            const extensions = [_][]const u8{ ".toml", ".yaml", ".yml", ".json", ".ini", ".properties" };

            // If we have a config name set, use it with extensions
            if (self.config_name) |name| {
                for (self.search_paths.items) |search_path| {
                    // Try with extensions first
                    for (extensions) |ext| {
                        if (self.tryAccessPath("{s}/{s}{s}", .{ search_path, name, ext })) |p| return p;
                    }

                    // Try extensionless if allowed (#44)
                    if (allow_extensionless) {
                        if (self.tryAccessPath("{s}/{s}", .{ search_path, name })) |p| return p;
                    }
                }
            }

            // Otherwise, use the provided filename
            for (self.search_paths.items) |search_path| {
                if (self.tryAccessPath("{s}/{s}", .{ search_path, filename })) |p| return p;
            }

            // Try extensionless in search paths (#44)
            if (allow_extensionless) {
                // Extract base name without extension from filename
                const base_name = getBaseName(filename);
                for (self.search_paths.items) |search_path| {
                    if (self.tryAccessPath("{s}/{s}", .{ search_path, base_name })) |p| return p;
                }
            }

            return null;
        }

        // =====================================================================
        // Environment Variable Binding (Viper-like)
        // =====================================================================

        /// Bind a config key to specific environment variable(s)
        /// Like Viper's BindEnv - explicitly maps a key to env vars.
        pub fn bindEnv(self: *Self, key: []const u8, env_vars: []const []const u8) !void {
            const norm_key = self.normalizeKey(key);

            // Copy env var names
            const owned_vars = try self.arena.allocator().alloc([]const u8, env_vars.len);
            for (env_vars, 0..) |env_var, i| {
                owned_vars[i] = try self.arena.allocator().dupe(u8, env_var);
            }

            try self.env_bindings.put(norm_key, owned_vars);
        }

        /// Bind a config key to a single environment variable
        pub fn bindEnvSingle(self: *Self, key: []const u8, env_var: []const u8) !void {
            try self.bindEnv(key, &.{env_var});
        }

        /// Enable automatic environment variable discovery with prefix
        /// Like Viper's AutomaticEnv - auto-discovers all prefixed env vars.
        pub fn automaticEnv(self: *Self, prefix: []const u8) !void {
            self.automatic_env_enabled = true;
            self.automatic_env_prefix = try self.arena.allocator().dupe(u8, prefix);
        }

        /// Set the environment key replacer
        /// Like Viper's SetEnvKeyReplacer - transforms key names for env lookup.
        pub fn setEnvKeyReplacer(self: *Self, replacer: EnvKeyReplacer) void {
            self.env_key_replacer = replacer;
        }

        // =====================================================================
        // Command-Line Flag Integration (Viper-like BindPFlag)
        // =====================================================================

        /// Apply parsed flags to configuration
        /// Flags have second-highest precedence (after override/set)
        pub fn applyFlags(self: *Self, parser: *const FlagParser) LoadError!void {
            for (parser.getValues()) |fv| {
                self.setField(fv.key, fv.value, .flag, fv.from_flag) catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // Non-matching fields or parse errors are expected for flags
                };
            }
        }

        /// Create a flag parser pre-configured for this config type
        /// Returns a parser with flags for each struct field
        pub fn createFlagParser(self: *Self) !FlagParser {
            var parser = FlagParser.init(self.allocator);
            errdefer parser.deinit();

            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (field.type == bool) {
                    try parser.boolean(field.name, null, "");
                } else {
                    try parser.string(field.name, null, "", null);
                }
            }

            return parser;
        }

        // =====================================================================
        // Key Normalization and Alias Resolution
        // =====================================================================

        /// Normalize a key based on case sensitivity setting.
        /// When case_insensitive is true, converts the key to lowercase
        /// using the arena allocator so the normalized key outlives the call.
        /// Returns the original key unchanged when case_insensitive is false.
        pub fn normalizeKey(self: *const Self, key: []const u8) []const u8 {
            if (!self.case_insensitive) {
                return key;
            }

            // Check if the key is already lowercase to avoid unnecessary allocation
            var needs_lower = false;
            for (key) |c| {
                if (c >= 'A' and c <= 'Z') {
                    needs_lower = true;
                    break;
                }
            }
            if (!needs_lower) {
                return key;
            }

            // Allocate a lowercase copy on the arena.
            // Safety: The Loader is always created as `var`, so the arena is
            // inherently mutable. The *const Self is just a calling-convention
            // restriction for read-only methods, not a true const object.
            const arena_ptr = @constCast(&self.arena);
            const lower = arena_ptr.allocator().alloc(u8, key.len) catch return key;
            for (key, 0..) |c, i| {
                lower[i] = std.ascii.toLower(c);
            }
            return lower;
        }

        /// Resolve an alias to its canonical key
        pub fn resolveAlias(self: *const Self, key: []const u8) []const u8 {
            return self.aliases.get(key) orelse key;
        }

        // =====================================================================
        // Configuration Loading
        // =====================================================================

        /// Load configuration with the given options
        pub fn load(self: *Self, options: LoadOptions) LoadError!T {
            self.case_insensitive = options.case_insensitive;

            // 1. Apply runtime defaults first (lowest precedence)
            try self.applyRuntimeDefaults();

            // 2. Apply struct defaults
            try self.applyDefaults();

            // 3. Load from system config (/etc/APP)
            if (options.use_xdg) {
                const system_path = std.fmt.allocPrint(self.allocator, "/etc/{s}/{s}", .{ options.app_name, options.filename }) catch return LoadError.OutOfMemory;
                defer self.allocator.free(system_path);
                self.loadFromPath(system_path, .system) catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // File not found or parse errors are expected for optional system config
                };
            }

            // 4. Load from user config (~/.config/APP)
            if (options.use_xdg) {
                if (xdg.getConfigDir(self.allocator, options.app_name)) |dir| {
                    defer self.allocator.free(dir);
                    const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, options.filename }) catch return LoadError.OutOfMemory;
                    defer self.allocator.free(path);
                    self.loadFromPath(path, .user) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // File not found or parse errors are expected for optional user config
                    };
                } else |_| {
                    // XDG config dir not available (e.g., HOME not set) -- not an error
                }
            }

            // 5. Load from configured search paths (AddConfigPath)
            if (self.search_paths.items.len > 0) {
                if (self.findConfigFile(options.filename)) |found_path| {
                    self.loadFromPath(found_path, .project) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Parse errors are non-fatal for optional project config
                    };
                }
            } else {
                // 5b. Fallback to project config (CWD) if no search paths configured
                self.loadFromPath(options.filename, .project) catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // File not found is expected when CWD has no config
                };
            }

            // 6. Load .env file (non-secret values only)
            self.loadDotEnv(".env", .project) catch |err| switch (err) {
                LoadError.OutOfMemory => return LoadError.OutOfMemory,
                else => {}, // .env file is optional
            };

            // 7. Apply bound environment variables
            try self.applyBoundEnvVars();

            // 8. Apply automatic environment variables
            if (self.automatic_env_enabled) {
                try self.applyAutomaticEnv(self.automatic_env_prefix);
            }

            // 9. Apply prefix-based environment variables
            try self.applyEnv(options.env_prefix);

            // 10. Apply specific config path if provided
            if (options.config_path) |path| {
                try self.loadFromPath(path, .flag);
            }

            // 11. Apply runtime overrides (highest precedence)
            try self.applyOverrides();

            return self.config;
        }

        fn applyRuntimeDefaults(self: *Self) LoadError!void {
            var iter = self.runtime_defaults.iterator();
            while (iter.next()) |entry| {
                self.setField(entry.key_ptr.*, entry.value_ptr.*, .runtime_default, "setDefault()") catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // Non-matching keys or invalid values are expected for runtime defaults
                };
            }
        }

        fn applyDefaults(self: *Self) LoadError!void {
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (field.default_value_ptr != null) {
                    // Set provenance for default value
                    self.tracker.set(
                        field.name,
                        "(default)",
                        .default,
                        null,
                    ) catch return LoadError.OutOfMemory;
                }
            }
        }

        fn applyOverrides(self: *Self) LoadError!void {
            var iter = self.overrides.iterator();
            while (iter.next()) |entry| {
                // Force set with override source (highest precedence)
                self.setFieldForce(entry.key_ptr.*, entry.value_ptr.*, .override, "set()") catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // Non-matching keys are silently ignored for overrides
                };
            }
        }

        fn applyBoundEnvVars(self: *Self) LoadError!void {
            var iter = self.env_bindings.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                const env_vars = entry.value_ptr.*;

                // Try each bound env var in order
                for (env_vars) |env_var| {
                    if (environ.getenv(env_var)) |value| {
                        self.setField(key, value, .env, env_var) catch |err| switch (err) {
                            LoadError.OutOfMemory => return LoadError.OutOfMemory,
                            else => {}, // Value type mismatch or unknown key is non-fatal
                        };
                        break;
                    }
                }
            }
        }

        fn applyAutomaticEnv(self: *Self, prefix: []const u8) LoadError!void {
            // Get all environment variables and find ones with our prefix
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                // A-02: Build env var name with heap fallback for long names
                var env_name_buf: [256]u8 = undefined;
                var heap_env_name: ?[]u8 = null;
                defer if (heap_env_name) |h| self.allocator.free(h);
                const env_name = buildEnvVarNameAlloc(&env_name_buf, prefix, field.name, self.env_key_replacer, self.allocator, &heap_env_name);

                if (environ.getenv(env_name)) |value| {
                    self.setField(field.name, value, .env, env_name) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Value type mismatch is non-fatal for env vars
                    };
                }
            }
        }

        pub fn loadFromPath(self: *Self, path: []const u8, source: Source) LoadError!void {
            // Security: Validate path does not contain traversal sequences (CWE-22, #107)
            if (!secret.isPathSafe(path)) return LoadError.FileNotFound;

            const ldr_io = std.Io.Threaded.global_single_threaded.io();
            const file = openFileReadNoFollow(path) catch {
                return LoadError.FileNotFound;
            };
            defer file.close(ldr_io);

            const content = secret.readFileToEnd(file, self.allocator, limits.MAX_CONFIG_FILE_SIZE) catch {
                return LoadError.IoError;
            };
            defer self.allocator.free(content);

            const format = Format.fromExtension(path);
            try self.parseContent(content, format, source, path);
        }

        /// Parse raw configuration content in the given format and apply the
        /// resulting key/value pairs to this loader's field store.
        ///
        /// **Parameters**
        /// - `content` -- Raw bytes to parse (e.g. the body of a config file).
        /// - `format`  -- `Format` enum that selects the parser:
        ///     - `.json`       -> `std.json` (via `parseSimpleJson`)
        ///     - `.toml`       -> `parseSimpleToml`
        ///     - `.yaml`       -> `parseSimpleYaml`
        ///     - `.ini`        -> `parseIni`
        ///     - `.properties` -> `parseProperties`
        ///     - `.auto`       -> calls `detectFormatFromContent` and recurses
        /// - `source`  -- `ConfigSource` tag used for provenance tracking.
        /// - `path`    -- File path (or identifier) used in error messages.
        ///
        /// **Errors**
        /// Returns `LoadError.OutOfMemory` on allocation failure, or the parse
        /// error produced by the selected format-specific parser.
        pub fn parseContent(self: *Self, content: []const u8, format: Format, source: Source, path: []const u8) LoadError!void {
            switch (format) {
                .json => try self.parseSimpleJson(content, source, path),
                .toml => try self.parseSimpleToml(content, source, path),
                .yaml => try self.parseSimpleYaml(content, source, path),
                .ini => try self.parseIni(content, source, path),
                .properties => try self.parseProperties(content, source, path),
                .auto => {
                    const detected = detectFormatFromContent(content);
                    return self.parseContent(content, detected, source, path);
                },
            }
        }

        fn parseSimpleJson(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch {
                return LoadError.ParseError;
            };
            defer parsed.deinit();

            try self.applyJsonValue("", parsed.value, source, path);
        }

        fn applyJsonValue(self: *Self, prefix: []const u8, value: std.json.Value, source: Source, path: []const u8) LoadError!void {
            switch (value) {
                .object => |obj| {
                    var iter = obj.iterator();
                    while (iter.next()) |entry| {
                        if (prefix.len > 0) {
                            // PERF-26: Use stack buffer for key construction, heap fallback for oversized keys
                            var key_buf: [512]u8 = undefined;
                            var heap_key: ?[]u8 = null;
                            defer if (heap_key) |h| self.allocator.free(h);
                            const full_key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ prefix, entry.key_ptr.* }) catch blk: {
                                const h = self.allocator.alloc(u8, prefix.len + 1 + entry.key_ptr.*.len) catch return LoadError.OutOfMemory;
                                @memcpy(h[0..prefix.len], prefix);
                                h[prefix.len] = '.';
                                @memcpy(h[prefix.len + 1 ..], entry.key_ptr.*);
                                heap_key = h;
                                break :blk @as([]u8, h);
                            };
                            try self.applyJsonValue(full_key, entry.value_ptr.*, source, path);
                        } else {
                            try self.applyJsonValue(entry.key_ptr.*, entry.value_ptr.*, source, path);
                        }
                    }
                },
                .string => |s| {
                    self.setField(prefix, s, source, path) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Unknown key or type mismatch is non-fatal during parsing
                    };
                },
                .integer => |i| {
                    var buf: [32]u8 = undefined;
                    const str = std.fmt.bufPrint(&buf, "{d}", .{i}) catch return;
                    self.setField(prefix, str, source, path) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Unknown key or type mismatch is non-fatal during parsing
                    };
                },
                .float => |f| {
                    var buf: [64]u8 = undefined;
                    const str = std.fmt.bufPrint(&buf, "{d}", .{f}) catch return;
                    self.setField(prefix, str, source, path) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Unknown key or type mismatch is non-fatal during parsing
                    };
                },
                .bool => |b| {
                    self.setField(prefix, if (b) "true" else "false", source, path) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Unknown key or type mismatch is non-fatal during parsing
                    };
                },
                // GAP-0042: Flatten JSON arrays into dot-delimited numeric-index keys
                // e.g. {"ports":[80,443]} -> "ports.0" = "80", "ports.1" = "443"
                .array => |arr| {
                    for (arr.items, 0..) |elem, idx| {
                        var idx_buf: [20]u8 = undefined;
                        const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch continue;
                        var key_buf: [512]u8 = undefined;
                        var heap_key: ?[]u8 = null;
                        defer if (heap_key) |h| self.allocator.free(h);
                        const full_key = if (prefix.len > 0)
                            std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ prefix, idx_str }) catch blk: {
                                const h = self.allocator.alloc(u8, prefix.len + 1 + idx_str.len) catch return LoadError.OutOfMemory;
                                @memcpy(h[0..prefix.len], prefix);
                                h[prefix.len] = '.';
                                @memcpy(h[prefix.len + 1 ..], idx_str);
                                heap_key = h;
                                break :blk @as([]u8, h);
                            }
                        else
                            idx_str;
                        try self.applyJsonValue(full_key, elem, source, path);
                    }
                },
                else => {},
            }
        }

        fn parseSimpleToml(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var current_section: ?[]const u8 = null;
            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                const trimmed = mem.trim(u8, line, " \t\r");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;

                if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                    current_section = trimmed[1 .. trimmed.len - 1];
                    continue;
                }

                if (mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                    const key = mem.trim(u8, trimmed[0..eq_pos], " \t");
                    var value = mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                    if (value.len >= 2) {
                        if ((value[0] == '"' and value[value.len - 1] == '"') or
                            (value[0] == '\'' and value[value.len - 1] == '\''))
                        {
                            value = value[1 .. value.len - 1];
                        }
                    }

                    if (current_section) |section| {
                        // PERF-27: Use stack buffer for key construction, heap fallback for oversized keys
                        var key_buf: [512]u8 = undefined;
                        var heap_key: ?[]u8 = null;
                        defer if (heap_key) |h| self.allocator.free(h);
                        const full_key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ section, key }) catch blk: {
                            const h = self.allocator.alloc(u8, section.len + 1 + key.len) catch return LoadError.OutOfMemory;
                            @memcpy(h[0..section.len], section);
                            h[section.len] = '.';
                            @memcpy(h[section.len + 1 ..], key);
                            heap_key = h;
                            break :blk @as([]u8, h);
                        };
                        self.setField(full_key, value, source, path) catch |err| switch (err) {
                            LoadError.OutOfMemory => return LoadError.OutOfMemory,
                            else => {}, // Unknown key or type mismatch is non-fatal during TOML parsing
                        };
                    } else {
                        self.setField(key, value, source, path) catch |err| switch (err) {
                            LoadError.OutOfMemory => return LoadError.OutOfMemory,
                            else => {}, // Unknown key or type mismatch is non-fatal during TOML parsing
                        };
                    }
                }
            }
        }

        fn parseSimpleYaml(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                const trimmed = mem.trim(u8, line, " \t\r");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;

                if (mem.indexOf(u8, trimmed, ":")) |colon_pos| {
                    const key = mem.trim(u8, trimmed[0..colon_pos], " \t");
                    var value = mem.trim(u8, trimmed[colon_pos + 1 ..], " \t");

                    if (value.len >= 2) {
                        if ((value[0] == '"' and value[value.len - 1] == '"') or
                            (value[0] == '\'' and value[value.len - 1] == '\''))
                        {
                            value = value[1 .. value.len - 1];
                        }
                    }

                    self.setField(key, value, source, path) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Unknown key or type mismatch is non-fatal during YAML parsing
                    };
                }
            }
        }

        fn parseIni(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var doc = ini_mod.parse(self.allocator, content) catch {
                return LoadError.ParseError;
            };
            defer doc.deinit();

            // Apply global values
            var global_iter = doc.global.iterator();
            while (global_iter.next()) |entry| {
                self.setField(entry.key_ptr.*, entry.value_ptr.*, source, path) catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // Unknown key or type mismatch is non-fatal during INI parsing
                };
            }

            // Apply section values with "section.key" format
            var section_iter = doc.sections.iterator();
            while (section_iter.next()) |section_entry| {
                const section_name = section_entry.key_ptr.*;
                var value_iter = section_entry.value_ptr.values.iterator();
                while (value_iter.next()) |value_entry| {
                    // PERF-28: Use stack buffer for key construction, heap fallback for oversized keys
                    var key_buf: [512]u8 = undefined;
                    var heap_key: ?[]u8 = null;
                    defer if (heap_key) |h| self.allocator.free(h);
                    const full_key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ section_name, value_entry.key_ptr.* }) catch blk: {
                        const h = self.allocator.alloc(u8, section_name.len + 1 + value_entry.key_ptr.*.len) catch return LoadError.OutOfMemory;
                        @memcpy(h[0..section_name.len], section_name);
                        h[section_name.len] = '.';
                        @memcpy(h[section_name.len + 1 ..], value_entry.key_ptr.*);
                        heap_key = h;
                        break :blk @as([]u8, h);
                    };
                    self.setField(full_key, value_entry.value_ptr.*, source, path) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Unknown key or type mismatch is non-fatal during INI parsing
                    };
                }
            }
        }

        fn parseProperties(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var props = properties_mod.parse(self.allocator, content) catch {
                return LoadError.ParseError;
            };
            defer props.deinit();

            // Apply all properties
            var iter = props.values.iterator();
            while (iter.next()) |entry| {
                self.setField(entry.key_ptr.*, entry.value_ptr.*, source, path) catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // Unknown key or type mismatch is non-fatal during properties parsing
                };
            }
        }

        pub fn loadDotEnv(self: *Self, path: []const u8, source: Source) LoadError!void {
            // Security: Validate path does not contain traversal sequences (CWE-22, #108)
            if (!secret.isPathSafe(path)) return;

            // Security: Use openFileReadNoFollow to prevent symlink attacks (CWE-59, #108)
            const de_io = std.Io.Threaded.global_single_threaded.io();
            const file = openFileReadNoFollow(path) catch {
                return LoadError.FileNotFound;
            };
            defer file.close(de_io);

            const content = secret.readFileToEnd(file, self.allocator, limits.MAX_DOTENV_FILE_SIZE) catch {
                return LoadError.IoError;
            };
            defer self.allocator.free(content);

            // QUAL-12: Delegate to dotenv.zig's canonical parser which handles
            // export prefixes, quoted values, and whitespace around '='.
            const entries = dotenv_mod.parseContent(content, self.allocator) catch {
                return LoadError.ParseError;
            };
            defer self.allocator.free(entries);

            for (entries) |entry| {
                self.setFieldFromEnvKey(entry.key, entry.value, source, path) catch |err| switch (err) {
                    LoadError.OutOfMemory => return LoadError.OutOfMemory,
                    else => {}, // Unknown key or type mismatch is non-fatal for .env entries
                };
            }
        }

        fn applyEnv(self: *Self, prefix: []const u8) LoadError!void {
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                // A-02: Build env var name with heap fallback for long names
                var env_name_buf: [256]u8 = undefined;
                var heap_env_name: ?[]u8 = null;
                defer if (heap_env_name) |h| self.allocator.free(h);
                const env_name = buildEnvVarNameAlloc(&env_name_buf, prefix, field.name, self.env_key_replacer, self.allocator, &heap_env_name);

                if (environ.getenv(env_name)) |value| {
                    self.setField(field.name, value, .env, env_name) catch |err| switch (err) {
                        LoadError.OutOfMemory => return LoadError.OutOfMemory,
                        else => {}, // Value type mismatch is non-fatal for env vars
                    };
                }
            }
        }

        fn setField(self: *Self, name: []const u8, value: []const u8, source: Source, path: []const u8) LoadError!void {
            const resolved_name = self.resolveAlias(name);
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (matchFieldName(field.name, resolved_name, self.case_insensitive)) {
                    try self.setFieldValue(field.type, field.name, value);
                    // Copy key and path onto arena for provenance tracking so
                    // they outlive transient stack/heap buffers from callers.
                    const owned_key = self.arena.allocator().dupe(u8, resolved_name) catch return LoadError.OutOfMemory;
                    // T-02: For []const u8 fields, setFieldValue already duped the value
                    // into the arena (stored in the config struct). Reuse that pointer
                    // instead of duping a second time.
                    const owned_value_for_tracker = blk: {
                        const FieldType = field.type;
                        const finfo = @typeInfo(FieldType);
                        if (FieldType == []const u8) {
                            break :blk @field(self.config, field.name);
                        } else if (finfo == .optional) {
                            if (finfo.optional.child == []const u8) {
                                if (@field(self.config, field.name)) |v| {
                                    break :blk v;
                                }
                            }
                        }
                        break :blk self.arena.allocator().dupe(u8, value) catch return LoadError.OutOfMemory;
                    };
                    const owned_path = self.arena.allocator().dupe(u8, path) catch return LoadError.OutOfMemory;
                    self.tracker.set(owned_key, owned_value_for_tracker, source, owned_path) catch return LoadError.OutOfMemory;
                    return;
                }
            }
        }

        /// Set a field value with proper type conversion
        fn setFieldValue(self: *Self, comptime FieldType: type, comptime field_name: []const u8, value: []const u8) LoadError!void {
            const field_info = @typeInfo(FieldType);

            // Handle optional types
            if (field_info == .optional) {
                const ChildType = field_info.optional.child;
                // Empty value means null for optionals
                if (value.len == 0) {
                    @field(self.config, field_name) = null;
                    return;
                }
                // Recursively handle the child type
                var temp_config: ChildType = undefined;
                try self.setNonOptionalValue(ChildType, &temp_config, value);
                @field(self.config, field_name) = temp_config;
                return;
            }

            try self.setNonOptionalValue(FieldType, &@field(self.config, field_name), value);
        }

        /// Set a non-optional field value
        fn setNonOptionalValue(self: *Self, comptime FieldType: type, ptr: *FieldType, value: []const u8) LoadError!void {
            const field_info = @typeInfo(FieldType);

            if (FieldType == bool) {
                ptr.* = parseBool(value);
            } else if (FieldType == []const u8) {
                // Copy string into arena to outlive the source buffer
                const owned_value = self.arena.allocator().dupe(u8, value) catch {
                    return LoadError.OutOfMemory;
                };
                ptr.* = owned_value;
            } else if (field_info == .int) {
                ptr.* = std.fmt.parseInt(FieldType, value, 10) catch {
                    return LoadError.InvalidValue;
                };
            } else if (field_info == .float) {
                ptr.* = std.fmt.parseFloat(FieldType, value) catch {
                    return LoadError.InvalidValue;
                };
            }
        }

        /// Force set a field value, bypassing precedence checks
        fn setFieldForce(self: *Self, name: []const u8, value: []const u8, source: Source, path: []const u8) LoadError!void {
            const resolved_name = self.resolveAlias(name);
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (matchFieldName(field.name, resolved_name, self.case_insensitive)) {
                    try self.setFieldValue(field.type, field.name, value);
                    // Force update tracker by removing existing and re-adding
                    // Copy key, value and path onto arena for long-term storage
                    const owned_key = self.arena.allocator().dupe(u8, resolved_name) catch return LoadError.OutOfMemory;
                    const owned_value_for_tracker = self.arena.allocator().dupe(u8, value) catch return LoadError.OutOfMemory;
                    const owned_path = self.arena.allocator().dupe(u8, path) catch return LoadError.OutOfMemory;
                    _ = self.tracker.values.remove(resolved_name);
                    self.tracker.values.put(owned_key, .{
                        .key = owned_key,
                        .value = owned_value_for_tracker,
                        .source = source,
                        .source_path = owned_path,
                    }) catch return LoadError.OutOfMemory;
                    return;
                }
            }
        }

        fn setFieldFromEnvKey(self: *Self, env_key: []const u8, value: []const u8, source: Source, path: []const u8) LoadError!void {
            // GAP-0067: Env keys from .env files are conventionally UPPERCASE
            // while struct fields are lowercase. Instead of unconditionally
            // lowercasing (which loses information for mixed-case field names),
            // always use case-insensitive matching for env keys. This correctly
            // maps HOST -> host, MYHOST -> myHost, etc. regardless of the global
            // case_insensitive flag.
            const resolved_name = self.resolveAlias(env_key);
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                // Always case-insensitive for env keys (convention: ENV=UPPER, fields=lower)
                if (matchFieldName(field.name, resolved_name, true)) {
                    try self.setFieldValue(field.type, field.name, value);
                    const owned_key = self.arena.allocator().dupe(u8, resolved_name) catch return LoadError.OutOfMemory;
                    const owned_value_for_tracker = self.arena.allocator().dupe(u8, value) catch return LoadError.OutOfMemory;
                    const owned_path = self.arena.allocator().dupe(u8, path) catch return LoadError.OutOfMemory;
                    self.tracker.set(owned_key, owned_value_for_tracker, source, owned_path) catch return LoadError.OutOfMemory;
                    return;
                }
            }
        }

        /// Get provenance tracker for reporting
        pub fn getTracker(self: *const Self) *const ProvenanceTracker {
            return &self.tracker;
        }

        /// Get the current configuration
        pub fn getConfig(self: *const Self) T {
            return self.config;
        }
    };
}

/// Match field name with optional case insensitivity
pub fn matchFieldName(field_name: []const u8, key: []const u8, case_insensitive: bool) bool {
    if (case_insensitive) {
        return std.ascii.eqlIgnoreCase(field_name, key);
    }
    return mem.eql(u8, field_name, key);
}

/// R-06: Build "prefix." string using stack buffer with heap fallback.
/// Returns the prefix-with-dot slice and an optional heap allocation
/// that the caller must free. If `prefix` already ends with '.', it
/// is returned as-is (no allocation).
const PrefixWithDot = struct {
    slice: []const u8,
    heap_alloc: ?[]u8,
};

fn buildPrefixWithDot(allocator: Allocator, buf: []u8, prefix: []const u8) error{OutOfMemory}!PrefixWithDot {
    if (prefix.len > 0 and prefix[prefix.len - 1] == '.') {
        return .{ .slice = prefix, .heap_alloc = null };
    }
    const result = std.fmt.bufPrint(buf, "{s}.", .{prefix}) catch {
        const h = try allocator.alloc(u8, prefix.len + 1);
        @memcpy(h[0..prefix.len], prefix);
        h[prefix.len] = '.';
        return .{ .slice = h, .heap_alloc = h };
    };
    return .{ .slice = result, .heap_alloc = null };
}

/// Build environment variable name from prefix and field name
/// Produces PREFIX_FIELD format (e.g., "MYAPP" + "host" = "MYAPP_HOST")
///
/// Writes into `buf` when the result fits. The caller may pass a separate
/// allocator via `buildEnvVarNameAlloc` when the name could exceed the
/// buffer (A-02 fix).
pub fn buildEnvVarName(buf: []u8, prefix: []const u8, field: []const u8, replacer: ?EnvKeyReplacer) []const u8 {
    return buildEnvVarNameInto(buf, prefix, field, replacer) orelse buf[0..0];
}

/// Build environment variable name with heap fallback for long names (A-02).
/// Returns the name in `buf` when it fits, or heap-allocated memory otherwise.
/// Caller must free the heap slice (returned via `heap_out`) if non-null.
pub fn buildEnvVarNameAlloc(
    buf: []u8,
    prefix: []const u8,
    field: []const u8,
    replacer: ?EnvKeyReplacer,
    allocator: Allocator,
    heap_out: *?[]u8,
) []const u8 {
    if (buildEnvVarNameInto(buf, prefix, field, replacer)) |result| {
        return result;
    }
    // A-02: Stack buffer too small -- fall back to heap
    const sep: usize = if (prefix.len > 0 and prefix[prefix.len - 1] != '_') 1 else 0;
    const total = prefix.len + sep + field.len;
    const heap_buf = allocator.alloc(u8, total) catch return buf[0..0];
    _ = buildEnvVarNameInto(heap_buf, prefix, field, replacer);
    heap_out.* = heap_buf;
    return heap_buf[0..total];
}

/// Internal: build env var name into the given buffer.
/// Returns null if the buffer is too small to hold the full result.
fn buildEnvVarNameInto(buf: []u8, prefix: []const u8, field: []const u8, replacer: ?EnvKeyReplacer) ?[]u8 {
    var pos: usize = 0;

    // Add prefix (converted to uppercase)
    for (prefix) |c| {
        if (pos >= buf.len) return null;
        buf[pos] = std.ascii.toUpper(c);
        pos += 1;
    }

    // Add underscore separator if prefix is non-empty and doesn't end with underscore
    if (prefix.len > 0 and prefix[prefix.len - 1] != '_') {
        if (pos >= buf.len) return null;
        buf[pos] = '_';
        pos += 1;
    }

    // Add field name with transformations
    for (field) |c| {
        if (pos >= buf.len) return null;

        var char_to_add = c;

        // Apply replacements if configured
        if (replacer) |r| {
            for (r.replacements) |replacement| {
                if (replacement.from.len == 1 and replacement.from[0] == c) {
                    if (replacement.to.len > 0) {
                        char_to_add = replacement.to[0];
                    }
                    break;
                }
            }

            if (r.to_upper) {
                char_to_add = std.ascii.toUpper(char_to_add);
            }
        } else {
            char_to_add = std.ascii.toUpper(c);
        }

        buf[pos] = char_to_add;
        pos += 1;
    }

    return buf[0..pos];
}

/// Parse boolean from string
pub fn parseBool(value: []const u8) bool {
    return mem.eql(u8, value, "true") or
        mem.eql(u8, value, "1") or
        mem.eql(u8, value, "yes") or
        mem.eql(u8, value, "on");
}

/// Get base name without extension (#44)
pub fn getBaseName(filename: []const u8) []const u8 {
    if (mem.lastIndexOfScalar(u8, filename, '.')) |dot| {
        return filename[0..dot];
    }
    return filename;
}

/// Detect format from file content for extensionless files (#44)
pub fn detectFormatFromContent(content: []const u8) Format {
    const trimmed = mem.trimStart(u8, content, " \t\r\n");
    if (trimmed.len == 0) return .toml;

    // JSON starts with { or [
    if (trimmed[0] == '{' or trimmed[0] == '[') return .json;

    // Check for YAML indicators
    if (mem.startsWith(u8, trimmed, "---")) return .yaml;
    if (mem.startsWith(u8, trimmed, "%YAML")) return .yaml;

    // Check for INI section [section]
    if (trimmed[0] == '[') {
        // Could be JSON array or INI section
        if (mem.indexOf(u8, trimmed, "]")) |end| {
            const bracket_content = trimmed[1..end];
            // If it contains =, it's more likely INI
            if (mem.indexOf(u8, bracket_content, "=") == null and
                mem.indexOf(u8, bracket_content, ":") == null)
            {
                // Check if next non-whitespace after ] is a newline (INI style)
                const after_bracket = trimmed[end + 1 ..];
                const after_trimmed = mem.trimStart(u8, after_bracket, " \t");
                if (after_trimmed.len == 0 or after_trimmed[0] == '\n' or after_trimmed[0] == '\r') {
                    return .ini;
                }
            }
        }
    }

    // Check for Properties-style (key=value without sections, and special escapes)
    var lines = mem.splitScalar(u8, trimmed, '\n');
    var yaml_indicators: u32 = 0;
    var toml_indicators: u32 = 0;
    var properties_indicators: u32 = 0;

    while (lines.next()) |line| {
        const line_trimmed = mem.trim(u8, line, " \t\r");
        if (line_trimmed.len == 0) continue;
        if (line_trimmed[0] == '#' or line_trimmed[0] == ';') continue;

        // YAML uses colon with space
        if (mem.indexOf(u8, line_trimmed, ": ")) |_| yaml_indicators += 1;

        // TOML uses = with quotes
        if (mem.indexOf(u8, line_trimmed, " = \"")) |_| toml_indicators += 1;
        if (mem.indexOf(u8, line_trimmed, "= \"")) |_| toml_indicators += 1;

        // Properties uses = or : without quotes typically
        if (mem.indexOf(u8, line_trimmed, "=")) |_| {
            if (mem.indexOf(u8, line_trimmed, "\"") == null) properties_indicators += 1;
        }

        // Only check first 10 lines
        if (yaml_indicators + toml_indicators + properties_indicators > 10) break;
    }

    if (yaml_indicators > toml_indicators and yaml_indicators > properties_indicators) return .yaml;
    if (toml_indicators > yaml_indicators and toml_indicators > properties_indicators) return .toml;
    if (properties_indicators > 3) return .properties;

    // Default to TOML
    return .toml;
}

/// Load configuration with options
pub fn load(comptime T: type, options: LoadOptions, allocator: Allocator) LoadError!T {
    var loader = Loader(T).init(allocator);
    defer loader.deinit();
    return loader.load(options);
}

test {
    _ = @import("loader_test.zig");
}
