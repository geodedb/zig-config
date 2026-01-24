//! Basic Configuration Parsing Example
//!
//! This example demonstrates how to parse configuration files
//! using the unified Value API. Format is auto-detected from
//! file extension.

const std = @import("std");
const config = @import("config");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Example 1: Parse YAML content
    const yaml_content =
        \\server:
        \\  host: localhost
        \\  port: 8080
        \\database:
        \\  url: postgres://localhost/mydb
        \\  pool_size: 10
        \\debug: true
    ;

    var yaml_config = try config.parseContent(allocator, yaml_content, .yaml);
    defer yaml_config.deinit();

    // Access nested values with dot notation
    const host = yaml_config.getString("server.host") orelse "127.0.0.1";
    const port = yaml_config.getInt("server.port") orelse 3000;
    const debug = yaml_config.getBool("debug") orelse false;

    std.debug.print("Server: {s}:{d} (debug: {})\n", .{ host, port, debug });

    // Example 2: Parse JSON content
    const json_content =
        \\{"api": {"key": "secret123", "timeout": 30}}
    ;

    var json_config = try config.parseContent(allocator, json_content, .json);
    defer json_config.deinit();

    const api_key = json_config.getString("api.key") orelse "";
    const timeout = json_config.getInt("api.timeout") orelse 60;

    std.debug.print("API: key={s}, timeout={d}s\n", .{ api_key, timeout });

    // Example 3: Parse TOML content
    const toml_content =
        \\[server]
        \\host = "0.0.0.0"
        \\port = 9000
        \\
        \\[logging]
        \\level = "info"
        \\format = "json"
    ;

    var toml_config = try config.parseContent(allocator, toml_content, .toml);
    defer toml_config.deinit();

    const log_level = toml_config.getString("logging.level") orelse "warn";
    std.debug.print("Log level: {s}\n", .{log_level});

    // Check if a path exists
    if (yaml_config.has("database.url")) {
        std.debug.print("Database URL is configured\n", .{});
    }
}
