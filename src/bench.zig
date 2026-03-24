// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Benchmark Suite
//!
//! Measures key operations in the config library: JSON/TOML/YAML parsing,
//! diff comparison, and map merging.  Run with `zig build bench`.

const std = @import("std");
const config = @import("config");

// ---------------------------------------------------------------------------
// Sample data (inline literals -- no file I/O dependency)
// ---------------------------------------------------------------------------

const sample_json =
    \\{
    \\  "host": "localhost",
    \\  "port": 8080,
    \\  "debug": false,
    \\  "database_url": "postgres://db:5432/app",
    \\  "max_connections": 100,
    \\  "timeout_ms": 5000,
    \\  "features": {
    \\    "enable_cache": true,
    \\    "cache_ttl": 3600,
    \\    "log_level": "info"
    \\  }
    \\}
;

const sample_toml =
    \\[server]
    \\host = "localhost"
    \\port = 8080
    \\debug = false
    \\
    \\[database]
    \\url = "postgres://db:5432/app"
    \\max_connections = 100
    \\timeout_ms = 5000
    \\
    \\[features]
    \\enable_cache = true
    \\cache_ttl = 3600
    \\log_level = "info"
;

const sample_yaml =
    \\server:
    \\  host: localhost
    \\  port: 8080
    \\  debug: false
    \\database:
    \\  url: "postgres://db:5432/app"
    \\  max_connections: 100
    \\  timeout_ms: 5000
    \\features:
    \\  enable_cache: true
    \\  cache_ttl: 3600
    \\  log_level: info
;

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

const BenchResult = struct {
    min_ns: u64,
    max_ns: u64,
    total_ns: u64,
    iterations: u64,

    fn mean(self: BenchResult) u64 {
        return self.total_ns / self.iterations;
    }
};

fn runBench(comptime name: []const u8, iterations: u32, comptime benchFn: fn (std.mem.Allocator) anyerror!void) !BenchResult {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Warm-up: one untimed run.
    benchFn(allocator) catch |err| {
        std.debug.print("SKIP  {s}: {s}\n", .{ name, @errorName(err) });
        return error.BenchSkipped;
    };

    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;
    var total_ns: u64 = 0;

    for (0..iterations) |_| {
        var timer = try std.time.Timer.start();
        try benchFn(allocator);
        const elapsed = timer.read();

        if (elapsed < min_ns) min_ns = elapsed;
        if (elapsed > max_ns) max_ns = elapsed;
        total_ns += elapsed;
    }

    const result = BenchResult{
        .min_ns = min_ns,
        .max_ns = max_ns,
        .total_ns = total_ns,
        .iterations = iterations,
    };

    std.debug.print("{s:<24} iters={d:<6} min={d:<10} mean={d:<10} max={d} ns/op\n", .{
        name,
        iterations,
        result.min_ns,
        result.mean(),
        result.max_ns,
    });

    return result;
}

// ---------------------------------------------------------------------------
// Individual benchmarks
// ---------------------------------------------------------------------------

fn benchJsonParse(allocator: std.mem.Allocator) !void {
    var v = try config.parseContent(allocator, sample_json, .json);
    v.deinit();
}

fn benchTomlParse(allocator: std.mem.Allocator) !void {
    var v = try config.parseContent(allocator, sample_toml, .toml);
    v.deinit();
}

fn benchYamlParse(allocator: std.mem.Allocator) !void {
    var v = try config.parseContent(allocator, sample_yaml, .yaml);
    v.deinit();
}

fn benchDiffCompare(allocator: std.mem.Allocator) !void {
    var old_cfg = std.StringHashMap([]const u8).init(allocator);
    defer old_cfg.deinit();
    var new_cfg = std.StringHashMap([]const u8).init(allocator);
    defer new_cfg.deinit();

    try old_cfg.put("host", "localhost");
    try old_cfg.put("port", "8080");
    try old_cfg.put("debug", "false");
    try old_cfg.put("database_url", "postgres://db:5432/app");
    try old_cfg.put("max_connections", "100");
    try old_cfg.put("timeout_ms", "5000");

    try new_cfg.put("host", "example.com");
    try new_cfg.put("port", "9090");
    try new_cfg.put("debug", "true");
    try new_cfg.put("database_url", "postgres://db:5432/app");
    try new_cfg.put("max_connections", "200");
    try new_cfg.put("log_level", "info");

    const result = try config.diff.compare(allocator, old_cfg, new_cfg);
    allocator.free(result.changes);
}

fn benchMergeMaps(allocator: std.mem.Allocator) !void {
    var base = std.StringHashMap([]const u8).init(allocator);
    defer base.deinit();
    var overlay = std.StringHashMap([]const u8).init(allocator);
    defer overlay.deinit();

    try base.put("host", "localhost");
    try base.put("port", "8080");
    try base.put("debug", "false");
    try base.put("database_url", "postgres://db:5432/app");
    try base.put("max_connections", "100");

    try overlay.put("host", "example.com");
    try overlay.put("debug", "true");
    try overlay.put("log_level", "info");
    try overlay.put("timeout_ms", "5000");

    var result = try config.merge.mergeMaps([]const u8, allocator, base, overlay, .{});
    // Free owned keys allocated by mergeMaps.
    var it = result.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    result.deinit();
}

fn benchMergeStructs(_: std.mem.Allocator) !void {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
        database_url: []const u8 = "",
        max_connections: u32 = 100,
        timeout_ms: u32 = 5000,
    };

    const base = Config{ .host = "basehost", .port = 9000, .database_url = "postgres://db:5432/app" };
    const overlay = Config{ .port = 3000, .debug = true, .timeout_ms = 3000 };

    const result = config.merge.mergeStructs(Config, base, overlay);
    // Prevent the compiler from optimising the merge away.
    std.mem.doNotOptimizeAway(&result);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main() !void {
    const iterations: u32 = 100;

    std.debug.print("\n--- Config Library Benchmarks ({d} iterations) ---\n\n", .{iterations});

    _ = runBench("json_parse", iterations, benchJsonParse) catch {};
    _ = runBench("toml_parse", iterations, benchTomlParse) catch {};
    _ = runBench("yaml_parse", iterations, benchYamlParse) catch {};
    _ = runBench("diff_compare", iterations, benchDiffCompare) catch {};
    _ = runBench("merge_maps", iterations, benchMergeMaps) catch {};
    _ = runBench("merge_structs", 1000, benchMergeStructs) catch {};

    std.debug.print("\n--- Done ---\n", .{});
}
