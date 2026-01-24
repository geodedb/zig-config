//! Typed Configuration Loader Example
//!
//! This example demonstrates how to use the generic Loader
//! for type-safe configuration with compile-time struct validation.

const std = @import("std");
const config = @import("config");

/// Application configuration struct with default values
const AppConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    debug: bool = false,
    max_connections: u32 = 100,
    timeout_ms: u32 = 30000,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize the typed loader
    var loader = config.Loader(AppConfig).init(allocator);
    defer loader.deinit();

    // Set runtime overrides (highest precedence)
    try loader.set("port", "9000");
    try loader.set("debug", "true");

    // Set runtime defaults (lowest precedence, below struct defaults)
    try loader.setDefault("max_connections", "200");

    // Register key aliases
    try loader.registerAlias("timeout", "timeout_ms");

    // Bind environment variables
    try loader.bindEnvSingle("host", "APP_HOST");
    try loader.automaticEnv("MYAPP"); // MYAPP_PORT, MYAPP_DEBUG, etc.

    // Load configuration from all sources
    const cfg = try loader.load(.{
        .app_name = "myapp",
        .filename = "config.toml",
        .env_prefix = "MYAPP_",
        .case_insensitive = true,
    });

    std.debug.print("Configuration loaded:\n", .{});
    std.debug.print("  host: {s}\n", .{cfg.host});
    std.debug.print("  port: {d}\n", .{cfg.port});
    std.debug.print("  debug: {}\n", .{cfg.debug});
    std.debug.print("  max_connections: {d}\n", .{cfg.max_connections});
    std.debug.print("  timeout_ms: {d}\n", .{cfg.timeout_ms});

    // Check provenance - where did each value come from?
    const tracker = loader.getTracker();
    if (tracker.get("port")) |tracked| {
        std.debug.print("\nport = {s} (source: {s})\n", .{
            tracked.value,
            tracked.source.format(),
        });
    }

    // Check if values were explicitly set
    if (loader.isSet("debug")) {
        std.debug.print("debug was explicitly configured\n", .{});
    }
}
