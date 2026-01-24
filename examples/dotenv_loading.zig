//! Dotenv File Loading Example
//!
//! This example demonstrates how to load and parse
//! .env files for local development configuration.

const std = @import("std");
const config = @import("config");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Example .env content
    const dotenv_content =
        \\# Database configuration
        \\DATABASE_URL=postgres://localhost:5432/mydb
        \\DATABASE_POOL_SIZE=10
        \\
        \\# API settings
        \\API_KEY=development_key_12345
        \\API_TIMEOUT=30
        \\
        \\# Feature flags
        \\ENABLE_DEBUG=true
        \\ENABLE_CACHE=false
    ;

    // Parse dotenv content
    const entries = try config.dotenv.parseContent(dotenv_content, allocator);
    defer allocator.free(entries);

    std.debug.print("Parsed .env entries:\n", .{});
    for (entries) |entry| {
        std.debug.print("  {s} = {s}\n", .{ entry.key, entry.value });
    }

    // In a real application, you would load from a file:
    // const entries = try config.dotenv.load(".env", allocator);

    // Find specific values
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, "DATABASE_URL")) {
            std.debug.print("\nDatabase URL: {s}\n", .{entry.value});
        }
        if (std.mem.eql(u8, entry.key, "ENABLE_DEBUG")) {
            const is_debug = std.mem.eql(u8, entry.value, "true");
            std.debug.print("Debug mode: {}\n", .{is_debug});
        }
    }
}
