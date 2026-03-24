//! Command-Line Flag Parsing Example
//!
//! This example demonstrates how to integrate command-line
//! flags with the configuration system.

const std = @import("std");
const config = @import("config");

const AppConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    debug: bool = false,
    config_file: []const u8 = "config.toml",
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Method 1: Manual flag parser setup
    var parser = config.FlagParser.init(allocator);
    defer parser.deinit();

    // Define flags
    try parser.string("host", 'h', "Server hostname", "localhost");
    try parser.string("port", 'p', "Server port", "8080");
    try parser.boolean("debug", 'd', "Enable debug mode");
    try parser.bind("config", "config_file", 'c', "Config file path");

    // Parse command-line arguments
    // In a real app: try parser.parseArgs();
    // For demo, parse hardcoded args:
    try parser.parse(&.{
        "--host",          "0.0.0.0",
        "-p",              "9000",
        "--debug",         "-c",
        "production.toml",
    });

    // Initialize loader and apply flags
    var loader = config.Loader(AppConfig).init(allocator);
    defer loader.deinit();

    // Apply parsed flags (flag source has high precedence)
    loader.applyFlags(&parser);

    // Load from all sources
    const cfg = try loader.load(.{
        .app_name = "myapp",
        .env_prefix = "MYAPP",
    });

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  host: {s}\n", .{cfg.host});
    std.debug.print("  port: {d}\n", .{cfg.port});
    std.debug.print("  debug: {}\n", .{cfg.debug});
    std.debug.print("  config_file: {s}\n", .{cfg.config_file});

    // Check provenance
    const tracker = loader.getTracker();
    if (tracker.get("host")) |tracked| {
        std.debug.print("\nhost was set from: {s}\n", .{tracked.source.format()});
    }

    // Method 2: Auto-generate parser from struct
    var loader2 = config.Loader(AppConfig).init(allocator);
    defer loader2.deinit();

    var auto_parser = try loader2.createFlagParser();
    defer auto_parser.deinit();

    // auto_parser now has --host, --port, --debug, --config_file flags
    try auto_parser.parse(&.{ "--port", "3000" });

    loader2.applyFlags(&auto_parser);
    const cfg2 = try loader2.load(.{ .app_name = "myapp" });

    std.debug.print("\nAuto-generated parser result:\n", .{});
    std.debug.print("  port: {d}\n", .{cfg2.port});
}
