// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Companion tests for loader.zig.
//! Extracted to reduce loader.zig to production code only (Q-NEW-6).

const std = @import("std");
const loader_mod = @import("loader.zig");

// Re-export types used in tests so test bodies stay unchanged.
const Loader = loader_mod.Loader;
const Format = loader_mod.Format;
const LoadError = loader_mod.LoadError;
const LoadOptions = loader_mod.LoadOptions;
const parseBool = loader_mod.parseBool;
const matchFieldName = loader_mod.matchFieldName;
const buildEnvVarName = loader_mod.buildEnvVarName;
const buildEnvVarNameAlloc = loader_mod.buildEnvVarNameAlloc;
const getBaseName = loader_mod.getBaseName;
const detectFormatFromContent = loader_mod.detectFormatFromContent;

// ============================================================================
// Tests
// ============================================================================

test "Loader initialization" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try std.testing.expectEqualStrings("localhost", loader.config.host);
    try std.testing.expectEqual(@as(u16, 8080), loader.config.port);
}

test "Format.fromExtension" {
    try std.testing.expectEqual(Format.json, Format.fromExtension("config.json"));
    try std.testing.expectEqual(Format.toml, Format.fromExtension("config.toml"));
    try std.testing.expectEqual(Format.yaml, Format.fromExtension("config.yaml"));
    try std.testing.expectEqual(Format.yaml, Format.fromExtension("config.yml"));
}

test "parseBool" {
    try std.testing.expect(parseBool("true"));
    try std.testing.expect(parseBool("1"));
    try std.testing.expect(parseBool("yes"));
    try std.testing.expect(parseBool("on"));
    try std.testing.expect(!parseBool("false"));
    try std.testing.expect(!parseBool("0"));
    try std.testing.expect(!parseBool("no"));
}

test "Set() overrides all sources" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set an override value
    try loader.set("host", "override.example.com");

    // The override should be stored
    try std.testing.expectEqualStrings("override.example.com", loader.overrides.get("host").?);
}

test "SetDefault() sets runtime defaults" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set a runtime default
    try loader.setDefault("timeout", "30");

    // The default should be stored
    try std.testing.expectEqualStrings("30", loader.runtime_defaults.get("timeout").?);
}

test "RegisterAlias creates key alias" {
    const Config = struct {
        verbose: bool = false,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Register alias
    try loader.registerAlias("loud", "verbose");

    // Alias should resolve to canonical key
    try std.testing.expectEqualStrings("verbose", loader.resolveAlias("loud"));
    try std.testing.expectEqualStrings("verbose", loader.resolveAlias("verbose"));
}

test "IsSet returns false for defaults" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Before loading, isSet should be false
    try std.testing.expect(!loader.isSet("host"));
}

test "BindEnv stores env bindings" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Bind to multiple env vars
    try loader.bindEnv("host", &.{ "SERVICE_HOST", "HOST" });

    // Binding should be stored
    const bindings = loader.env_bindings.get("host").?;
    try std.testing.expectEqual(@as(usize, 2), bindings.len);
    try std.testing.expectEqualStrings("SERVICE_HOST", bindings[0]);
    try std.testing.expectEqualStrings("HOST", bindings[1]);
}

test "AutomaticEnv enables auto discovery" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.automaticEnv("MYAPP_");

    try std.testing.expect(loader.automatic_env_enabled);
    try std.testing.expectEqualStrings("MYAPP_", loader.automatic_env_prefix);
}

test "SetEnvKeyReplacer configures replacer" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    loader.setEnvKeyReplacer(.{
        .replacements = &.{
            .{ .from = ".", .to = "_" },
        },
        .to_upper = true,
    });

    try std.testing.expect(loader.env_key_replacer != null);
    try std.testing.expect(loader.env_key_replacer.?.to_upper);
}

test "buildEnvVarName constructs correct name" {
    var buf: [256]u8 = undefined;

    // Prefix with trailing underscore
    const result1 = buildEnvVarName(&buf, "MYAPP_", "host", null);
    try std.testing.expectEqualStrings("MYAPP_HOST", result1);

    // Empty prefix
    const result2 = buildEnvVarName(&buf, "", "port", null);
    try std.testing.expectEqualStrings("PORT", result2);

    // Prefix without trailing underscore (should add one)
    const result3 = buildEnvVarName(&buf, "MYAPP", "host", null);
    try std.testing.expectEqualStrings("MYAPP_HOST", result3);

    // Lowercase prefix (should be uppercased)
    const result4 = buildEnvVarName(&buf, "myapp", "debug", null);
    try std.testing.expectEqualStrings("MYAPP_DEBUG", result4);

    // Snake_case field name
    const result5 = buildEnvVarName(&buf, "APP", "pool_size", null);
    try std.testing.expectEqualStrings("APP_POOL_SIZE", result5);
}

test "matchFieldName with case sensitivity" {
    // Case sensitive (default)
    try std.testing.expect(matchFieldName("host", "host", false));
    try std.testing.expect(!matchFieldName("host", "HOST", false));
    try std.testing.expect(!matchFieldName("host", "Host", false));

    // Case insensitive
    try std.testing.expect(matchFieldName("host", "host", true));
    try std.testing.expect(matchFieldName("host", "HOST", true));
    try std.testing.expect(matchFieldName("host", "Host", true));
}

test "Loader supports float types" {
    const Config = struct {
        rate: f32 = 1.0,
        timeout: f64 = 30.5,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("rate", "2.5");
    try loader.set("timeout", "60.25");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    try std.testing.expectApproxEqAbs(@as(f32, 2.5), loader.config.rate, 0.001);
    try std.testing.expectApproxEqAbs(@as(f64, 60.25), loader.config.timeout, 0.001);
}

test "Loader supports optional types" {
    const Config = struct {
        host: []const u8 = "localhost",
        callback_url: ?[]const u8 = null,
        max_retries: ?u32 = null,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("callback_url", "http://example.com");
    try loader.set("max_retries", "5");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    try std.testing.expectEqualStrings("http://example.com", loader.config.callback_url.?);
    try std.testing.expectEqual(@as(u32, 5), loader.config.max_retries.?);
}

test "Loader reset clears state" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "myhost.com");
    try loader.set("port", "9000");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    // Verify values were set
    try std.testing.expectEqualStrings("myhost.com", loader.config.host);

    // Reset
    loader.reset();

    // Verify config is back to defaults
    try std.testing.expectEqualStrings("localhost", loader.config.host);
    try std.testing.expectEqual(@as(u16, 8080), loader.config.port);

    // Verify tracker is cleared
    try std.testing.expect(loader.tracker.get("host") == null);
}

test "Loader string memory safety" {
    // Test that strings loaded from content are properly copied
    const Config = struct {
        name: []const u8 = "default",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set a value from a temporary string
    {
        var temp_buf: [32]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "temp_value_{d}", .{42}) catch unreachable;
        try loader.set("name", temp_str);
    }
    // temp_buf is now out of scope but loader.config.name should still be valid

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    // The value should still be accessible (it was copied to arena)
    try std.testing.expectEqualStrings("temp_value_42", loader.config.name);
}

test "allKeys returns all configuration keys" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "example.com");
    try loader.set("port", "3000");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    const keys = try loader.allKeys();
    defer std.testing.allocator.free(keys);

    // Should have at least the keys we set
    try std.testing.expect(keys.len >= 2);
}

test "allSettings returns all key-value pairs" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "example.com");
    try loader.set("port", "3000");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    var settings = try loader.allSettings();
    defer settings.deinit();

    // Should have at least the keys we set
    try std.testing.expect(settings.count() >= 2);
    try std.testing.expectEqualStrings("example.com", settings.get("host").?);
    try std.testing.expectEqualStrings("3000", settings.get("port").?);
}

test "sub extracts sub-configuration by prefix" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Manually set some prefixed values in the tracker
    try loader.tracker.set("database.host", "db.example.com", .project, "test");
    try loader.tracker.set("database.port", "5432", .project, "test");
    try loader.tracker.set("cache.host", "cache.example.com", .project, "test");

    var db_config = try loader.sub("database");
    defer db_config.deinit();

    try std.testing.expectEqual(@as(usize, 2), db_config.count());
    try std.testing.expectEqualStrings("db.example.com", db_config.get("host").?);
    try std.testing.expectEqualStrings("5432", db_config.get("port").?);
}

test "hasSub checks for sub-configuration existence" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set some prefixed values
    try loader.tracker.set("database.host", "db.example.com", .project, "test");

    try std.testing.expect(loader.hasSub("database"));
    try std.testing.expect(!loader.hasSub("nonexistent"));
}

test "addConfigPath adds search paths" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.addConfigPath("/etc/myapp");
    try loader.addConfigPath("/home/user/.config/myapp");
    try loader.addConfigPath(".");

    const paths = loader.getSearchPaths();
    try std.testing.expectEqual(@as(usize, 3), paths.len);
    try std.testing.expectEqualStrings("/etc/myapp", paths[0]);
    try std.testing.expectEqualStrings("/home/user/.config/myapp", paths[1]);
    try std.testing.expectEqualStrings(".", paths[2]);
}

test "setConfigName sets config file name" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.setConfigName("myconfig");

    try std.testing.expectEqualStrings("myconfig", loader.config_name.?);
}

test "getPath returns value for direct key" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "example.com");
    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    try std.testing.expectEqualStrings("example.com", loader.getPath("host").?);
}

test "reset clears search paths" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.addConfigPath("/etc/myapp");
    try loader.setConfigName("config");

    try std.testing.expectEqual(@as(usize, 1), loader.search_paths.items.len);
    try std.testing.expect(loader.config_name != null);

    loader.reset();

    try std.testing.expectEqual(@as(usize, 0), loader.search_paths.items.len);
    try std.testing.expect(loader.config_name == null);
}

test "setKeyDelimiter changes delimiter (#40)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Default delimiter
    try std.testing.expectEqualStrings(".", loader.getKeyDelimiter());

    // Change to path-style
    try loader.setKeyDelimiter("/");
    try std.testing.expectEqualStrings("/", loader.getKeyDelimiter());

    // Change to namespace-style
    try loader.setKeyDelimiter("::");
    try std.testing.expectEqualStrings("::", loader.getKeyDelimiter());
}

test "getBaseName extracts filename without extension" {
    try std.testing.expectEqualStrings("config", getBaseName("config.toml"));
    try std.testing.expectEqualStrings("my.config", getBaseName("my.config.yaml"));
    try std.testing.expectEqualStrings("config", getBaseName("config"));
    try std.testing.expectEqualStrings("path/to/config", getBaseName("path/to/config.json"));
}

test "detectFormatFromContent JSON" {
    try std.testing.expectEqual(Format.json, detectFormatFromContent("{\"key\": \"value\"}"));
    try std.testing.expectEqual(Format.json, detectFormatFromContent("[1, 2, 3]"));
    try std.testing.expectEqual(Format.json, detectFormatFromContent("  { \"nested\": {} }"));
}

test "detectFormatFromContent YAML" {
    try std.testing.expectEqual(Format.yaml, detectFormatFromContent("---\nkey: value"));
    try std.testing.expectEqual(Format.yaml, detectFormatFromContent("key: value\nother: data"));
}

test "detectFormatFromContent TOML" {
    try std.testing.expectEqual(Format.toml, detectFormatFromContent("key = \"value\""));
    try std.testing.expectEqual(Format.toml, detectFormatFromContent("name = \"test\"\nport = 8080"));
}

test "LoadOptions key_delimiter default" {
    const opts = LoadOptions{ .app_name = "test" };
    try std.testing.expectEqualStrings(".", opts.key_delimiter.?);
    try std.testing.expect(!opts.allow_extensionless);
}

test "LoadOptions allow_extensionless" {
    const opts = LoadOptions{
        .app_name = "test",
        .allow_extensionless = true,
    };
    try std.testing.expect(opts.allow_extensionless);
}

// ============================================================================
// Gap closure tests (Batch 2a)
// ============================================================================

test "loadFromPath rejects path traversal (GAP: isPathSafe #107)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Paths with ".." traversal must return FileNotFound
    try std.testing.expectError(LoadError.FileNotFound, loader.loadFromPath("../../etc/passwd", .project));
    try std.testing.expectError(LoadError.FileNotFound, loader.loadFromPath("../secret.toml", .project));
    try std.testing.expectError(LoadError.FileNotFound, loader.loadFromPath("foo/../../../etc/shadow", .system));
}

test "loadDotEnv rejects path traversal (GAP: isPathSafe + openFileReadNoFollow #108)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // loadDotEnv with ".." paths should silently return (not crash or load)
    // After the fix it returns early due to isPathSafe check
    try loader.loadDotEnv("../../.env", .project);
    try loader.loadDotEnv("../.env", .project);

    // Verify no values were loaded from traversal paths
    try std.testing.expect(!loader.isSet("host"));
}

// ============================================================================
// Gap closure tests (GAP-113: normalizeKey case-insensitive)
// ============================================================================

test "normalizeKey returns original key when case_insensitive is false" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    // case_insensitive defaults to false

    const result = ldr.normalizeKey("MyKey");
    try std.testing.expectEqualStrings("MyKey", result);
}

test "normalizeKey lowercases key when case_insensitive is true" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    ldr.case_insensitive = true;

    const result = ldr.normalizeKey("MyKey");
    try std.testing.expectEqualStrings("mykey", result);
}

test "normalizeKey returns original key when already lowercase in case_insensitive mode" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    ldr.case_insensitive = true;

    const original = "alreadylower";
    const result = ldr.normalizeKey(original);
    // Should return the exact same pointer (no allocation)
    try std.testing.expectEqual(@intFromPtr(original.ptr), @intFromPtr(result.ptr));
    try std.testing.expectEqualStrings("alreadylower", result);
}

test "case-insensitive set and get round-trip" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    ldr.case_insensitive = true;

    // Set with mixed case
    try ldr.set("HOST", "example.com");

    // Get with different case variations
    try std.testing.expectEqualStrings("example.com", ldr.get("HOST").?);
    try std.testing.expectEqualStrings("example.com", ldr.get("host").?);
    try std.testing.expectEqualStrings("example.com", ldr.get("Host").?);
}

test "case-insensitive isSet works across cases" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    ldr.case_insensitive = true;

    try ldr.set("HOST", "example.com");

    try std.testing.expect(ldr.isSet("HOST"));
    try std.testing.expect(ldr.isSet("host"));
    try std.testing.expect(ldr.isSet("Host"));
}

test "case-insensitive alias resolution" {
    const Config = struct {
        verbose: bool = false,
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    ldr.case_insensitive = true;

    try ldr.registerAlias("LOUD", "verbose");

    // Alias should resolve regardless of case
    try std.testing.expectEqualStrings("verbose", ldr.resolveAlias("loud"));
}

test "Format.fromExtension returns .auto for unknown extension (GAP: silent .toml default)" {
    // Unknown extensions must not silently default to .toml
    try std.testing.expectEqual(Format.auto, Format.fromExtension("config.cfg"));
    try std.testing.expectEqual(Format.auto, Format.fromExtension("config.xml"));
    try std.testing.expectEqual(Format.auto, Format.fromExtension("config.unknown"));
    try std.testing.expectEqual(Format.auto, Format.fromExtension("noextension"));

    // Known extensions still work
    try std.testing.expectEqual(Format.json, Format.fromExtension("config.json"));
    try std.testing.expectEqual(Format.toml, Format.fromExtension("config.toml"));
    try std.testing.expectEqual(Format.yaml, Format.fromExtension("config.yaml"));
    try std.testing.expectEqual(Format.yaml, Format.fromExtension("config.yml"));
    try std.testing.expectEqual(Format.ini, Format.fromExtension("config.ini"));
    try std.testing.expectEqual(Format.properties, Format.fromExtension("config.properties"));
}

// ============================================================================
// GAP-0010: Unified .auto format handling
// ============================================================================

test "Loader.parseContent with .auto uses content detection, not hardcoded TOML" {
    // GAP-0010: When .auto is specified, the Loader should detect format from
    // content rather than defaulting to TOML. A JSON string should parse
    // correctly even when format is .auto.
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    // This is valid JSON, not TOML. With .auto, it should be detected as JSON.
    const json_content =
        \\{"host": "json-host.example.com", "port": "3000"}
    ;

    // If .auto blindly defaults to TOML, this will either fail to parse
    // or produce incorrect results.
    try ldr.parseContent(json_content, .auto, .project, "config");

    try std.testing.expectEqualStrings("json-host.example.com", ldr.config.host);
    try std.testing.expectEqual(@as(u16, 3000), ldr.config.port);
}

test "Loader.parseContent with .auto detects YAML content" {
    const Config = struct {
        host: []const u8 = "localhost",
        debug: bool = false,
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    // YAML content with colon-space separator
    const yaml_content =
        \\host: yaml-host.example.com
        \\debug: true
    ;

    try ldr.parseContent(yaml_content, .auto, .project, "config");

    try std.testing.expectEqualStrings("yaml-host.example.com", ldr.config.host);
    try std.testing.expect(ldr.config.debug);
}

// ============================================================================
// GAP-0026: Normalize dotenv keys in case-insensitive mode
// ============================================================================

test "loadDotEnv normalizes keys when case_insensitive is true (GAP-0026)" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();
    ldr.case_insensitive = true;

    // Simulate dotenv content with mixed-case keys. When case_insensitive
    // is true, keys should be normalized so that "HOST" matches field "host".
    // The dotenv parser should delegate to dotenv.zig, which handles
    // export prefixes and quoted values properly.
    const content =
        \\HOST=dotenv-host.example.com
        \\PORT=9090
    ;

    // We cannot call loadDotEnv directly with content, so we test through
    // setFieldFromEnvKey which loadDotEnv delegates to, and verify
    // the normalized keys in the tracker.
    // Actually, we test by writing a temp file and calling loadDotEnv.
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    tmp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = ".env", .data = content }) catch return;

    const tmp_path = tmp_dir.dir.realPathFileAlloc(std.Io.Threaded.global_single_threaded.io(), ".env", std.testing.allocator) catch return;
    defer std.testing.allocator.free(tmp_path);

    try ldr.loadDotEnv(tmp_path, .project);

    // The key should be accessible through case-insensitive lookup
    try std.testing.expectEqualStrings("dotenv-host.example.com", ldr.config.host);
    try std.testing.expectEqual(@as(u16, 9090), ldr.config.port);
}

// ============================================================================
// QUAL-12: Deduplicate dotenv parsing (loader delegates to dotenv)
// ============================================================================

test "loadDotEnv handles export prefix via dotenv delegation (QUAL-12)" {
    // QUAL-12: loader.loadDotEnv should handle 'export' prefix and quoted
    // values because it delegates to dotenv.zig's canonical parser.
    const Config = struct {
        host: []const u8 = "localhost",
        name: []const u8 = "default",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    const content =
        \\export HOST=exported-host.example.com
        \\NAME="quoted name"
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    tmp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = ".env", .data = content }) catch return;

    const tmp_path = tmp_dir.dir.realPathFileAlloc(std.Io.Threaded.global_single_threaded.io(), ".env", std.testing.allocator) catch return;
    defer std.testing.allocator.free(tmp_path);

    try ldr.loadDotEnv(tmp_path, .project);

    // If loader has its own parser (which doesn't handle export/quotes),
    // these will fail. With dotenv delegation, they should pass.
    try std.testing.expectEqualStrings("exported-host.example.com", ldr.config.host);
    try std.testing.expectEqualStrings("quoted name", ldr.config.name);
}

test "loadDotEnv handles whitespace around equals via dotenv delegation (QUAL-12)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    const content =
        \\HOST = spaced-host.example.com
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    tmp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = ".env", .data = content }) catch return;

    const tmp_path = tmp_dir.dir.realPathFileAlloc(std.Io.Threaded.global_single_threaded.io(), ".env", std.testing.allocator) catch return;
    defer std.testing.allocator.free(tmp_path);

    try ldr.loadDotEnv(tmp_path, .project);

    // The old inline parser didn't trim whitespace around keys/values.
    // dotenv.zig's parser does.
    try std.testing.expectEqualStrings("spaced-host.example.com", ldr.config.host);
}

// ============================================================================
// GAP-0042: JSON array flattening into dot-delimited numeric-index keys
// ============================================================================

test "GAP-0042: applyJsonValue flattens JSON arrays to dot-delimited keys" {
    const Config = struct {
        @"tags.0": []const u8 = "",
        @"tags.1": []const u8 = "",
        @"tags.2": []const u8 = "",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    const json_content =
        \\{"tags": ["web", "api", "prod"]}
    ;

    try ldr.parseContent(json_content, .json, .project, "test.json");

    try std.testing.expectEqualStrings("web", ldr.config.@"tags.0");
    try std.testing.expectEqualStrings("api", ldr.config.@"tags.1");
    try std.testing.expectEqualStrings("prod", ldr.config.@"tags.2");
}

// ============================================================================
// GAP-0041: getPath() dot-delimited traversal and bracket normalization
// ============================================================================

test "GAP-0041: getPath returns value for dot-delimited array paths" {
    const Config = struct {
        @"servers.0.host": []const u8 = "",
        @"servers.1.host": []const u8 = "",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    const json_content =
        \\{"servers": [{"host": "a.example.com"}, {"host": "b.example.com"}]}
    ;

    try ldr.parseContent(json_content, .json, .project, "test.json");

    // Verify struct fields were set correctly
    try std.testing.expectEqualStrings("a.example.com", ldr.config.@"servers.0.host");
    try std.testing.expectEqualStrings("b.example.com", ldr.config.@"servers.1.host");

    // get() should find tracker-stored values
    const v0 = ldr.get("servers.0.host");
    try std.testing.expect(v0 != null);
    try std.testing.expectEqualStrings("a.example.com", v0.?);

    // getPath() should also work (delegates to get())
    try std.testing.expectEqualStrings("a.example.com", ldr.getPath("servers.0.host").?);
    try std.testing.expectEqualStrings("b.example.com", ldr.getPath("servers.1.host").?);
}

test "GAP-0041: getPath normalizes bracket notation to dot notation" {
    const Config = struct {
        @"ports.0": u16 = 0,
        @"ports.1": u16 = 0,
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    const json_content =
        \\{"ports": [80, 443]}
    ;

    try ldr.parseContent(json_content, .json, .project, "test.json");

    // Bracket notation "ports[0]" should resolve to "ports.0"
    try std.testing.expectEqualStrings("80", ldr.getPath("ports[0]").?);
    try std.testing.expectEqualStrings("443", ldr.getPath("ports[1]").?);

    // Dot notation also works
    try std.testing.expectEqualStrings("80", ldr.getPath("ports.0").?);
}

test "GAP-0041: getPath returns null for non-existent paths" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    _ = ldr.load(.{ .app_name = "test", .use_xdg = false, .optional = true }) catch {};

    try std.testing.expect(ldr.getPath("nonexistent.path") == null);
}

// ============================================================================
// A-02: buildEnvVarName heap fallback for long names
// ============================================================================

test "A-02: buildEnvVarName fits in stack buffer" {
    var buf: [256]u8 = undefined;
    const result = buildEnvVarName(&buf, "APP", "host", null);
    try std.testing.expectEqualStrings("APP_HOST", result);
}

test "A-02: buildEnvVarName truncates to empty on overflow without alloc" {
    // With a tiny buffer the old API returns empty (no silent partial match)
    var buf: [4]u8 = undefined;
    const result = buildEnvVarName(&buf, "MYAPP", "host", null);
    // Buffer is too small for "MYAPP_HOST" (10 chars) so returns empty
    try std.testing.expectEqualStrings("", result);
}

test "A-02: buildEnvVarNameAlloc uses heap fallback for long names" {
    // Use a tiny stack buffer that cannot hold the result
    var buf: [4]u8 = undefined;
    var heap_out: ?[]u8 = null;
    defer if (heap_out) |h| std.testing.allocator.free(h);
    const result = buildEnvVarNameAlloc(&buf, "MYAPP", "host", null, std.testing.allocator, &heap_out);
    try std.testing.expectEqualStrings("MYAPP_HOST", result);
    // Verify it was heap allocated
    try std.testing.expect(heap_out != null);
}

// ============================================================================
// GAP-0067: setFieldFromEnvKey uses case-insensitive matching for env keys
// ============================================================================

test "GAP-0067: setFieldFromEnvKey matches uppercase env keys to lowercase fields" {
    // Env keys are conventionally UPPERCASE. setFieldFromEnvKey should always
    // use case-insensitive matching so HOST matches 'host' field.
    const Config = struct {
        host: []const u8 = "default",
        name: []const u8 = "default",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    tmp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = ".env", .data = "HOST=env-host\nNAME=env-name\n" }) catch return;
    const tmp_path = tmp_dir.dir.realPathFileAlloc(std.Io.Threaded.global_single_threaded.io(), ".env", std.testing.allocator) catch return;
    defer std.testing.allocator.free(tmp_path);

    try ldr.loadDotEnv(tmp_path, .project);

    // Always matches regardless of case_insensitive flag (which defaults to false)
    try std.testing.expectEqualStrings("env-host", ldr.config.host);
    try std.testing.expectEqualStrings("env-name", ldr.config.name);
}

test "GAP-0067: setFieldFromEnvKey matches mixed-case env keys" {
    // Mixed-case field names should match case-insensitively with env keys
    const Config = struct {
        myHost: []const u8 = "default",
    };

    var ldr = Loader(Config).init(std.testing.allocator);
    defer ldr.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    tmp_dir.dir.writeFile(std.Io.Threaded.global_single_threaded.io(), .{ .sub_path = ".env", .data = "MYHOST=mixed-case-value\n" }) catch return;
    const tmp_path = tmp_dir.dir.realPathFileAlloc(std.Io.Threaded.global_single_threaded.io(), ".env", std.testing.allocator) catch return;
    defer std.testing.allocator.free(tmp_path);

    try ldr.loadDotEnv(tmp_path, .project);

    // MYHOST should match myHost via case-insensitive comparison
    try std.testing.expectEqualStrings("mixed-case-value", ldr.config.myHost);
}
