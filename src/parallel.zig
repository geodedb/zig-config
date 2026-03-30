// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Parallel config operations using spice heartbeat scheduling.
//!
//! Provides high-performance parallel implementations for configuration
//! operations including file loading, merge operations, and validation.
//!
//! ## Overview
//!
//! This module enables parallel processing of configuration operations
//! using the spice thread pool. Ideal for loading multiple config files
//! or validating large configuration structures.
//!
//! ## Build Configuration
//!
//! Enable: `-Dspice=true` (default)
//! Disable: `-Dspice=false`
//!
//! ## Usage Example
//!
//! ```zig
//! const parallel = @import("parallel.zig");
//!
//! // Load multiple config files in parallel
//! var inputs: [3]parallel.FileLoadInput = .{
//!     .{ .path = "/etc/app/system.yaml", .format = .yaml },
//!     .{ .path = "~/.config/app/user.yaml", .format = .yaml },
//!     .{ .path = "./config.yaml", .format = .yaml },
//! };
//! var results: [3]parallel.FileLoadResult = undefined;
//!
//! parallel.parallelFileLoad(allocator, &inputs, &results);
//! ```
//!
//! ## Allocator Guidance
//!
//! The global thread pool accepts a caller-provided allocator via `initPool()`.
//! For best performance with small config files (< 4KB), pass a
//! `std.heap.GeneralPurposeAllocator` instead of `std.heap.page_allocator`.
//! The page allocator rounds up to 4KB pages, wasting up to 75% memory for
//! small file reads. If `initPool()` is not called before `getPool()`, the
//! pool lazily initializes with `std.heap.page_allocator` as a safe default.
//!
//! ```zig
//! var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//! defer _ = gpa.deinit();
//! parallel.initPool(gpa.allocator());
//! defer parallel.deinitPool();
//! ```
//!
//! ## Performance Thresholds
//!
//! | Operation      | Threshold | Sequential Below |
//! |----------------|-----------|------------------|
//! | File Load      | 4 files   | Yes              |
//! | Validation     | 8 rules   | Yes              |
//! | Serialization  | 4 formats | Yes              |

const std = @import("std");
const build_options = @import("config_build_options");

const spice = if (build_options.enable_spice) @import("spice") else struct {
    pub const ThreadPool = void;
    pub const Task = void;
    pub fn Future(comptime I: type, comptime O: type) type {
        _ = I;
        _ = O;
        return void;
    }
};

// ============================================================================
// Global Thread Pool
// ============================================================================

/// Minimum number of items before spawning the thread pool for file loads
/// and serialization. Below this threshold, sequential execution avoids
/// the overhead of OS thread creation (PERF-42).
const parallel_file_threshold: usize = 4;

/// Minimum number of items before spawning the thread pool for serialization.
const parallel_serialize_threshold: usize = 4;

var global_pool: if (build_options.enable_spice) ?spice.ThreadPool else void = if (build_options.enable_spice) null else {};

/// Allocator stored by `initPool()` for use during lazy initialization.
/// Defaults to `page_allocator`; callers should call `initPool()` with a
/// `GeneralPurposeAllocator` for better memory efficiency on small files
/// (PERF-40).
var pool_allocator: std.mem.Allocator = std.heap.page_allocator;

/// Guards `deinitPool` against concurrent access with the once-init path.
var pool_deinit_mutex: std.Thread.Mutex = .{};

/// One-shot initializer -- the mutex inside `std.once` is only contended on
/// the very first call; subsequent calls use a lock-free atomic check
/// (PERF-41).
var pool_once = if (build_options.enable_spice)
    std.once(doInitPool)
else {};

fn doInitPool() void {
    global_pool = spice.ThreadPool.init(pool_allocator);
    global_pool.?.start(.{});
}

/// Pre-configure the thread pool allocator before first use.
///
/// For small config files (< 4KB), pass a `GeneralPurposeAllocator` to
/// avoid page-granularity waste from `std.heap.page_allocator` (PERF-40).
///
/// **Thread-safety contract (PERF-52):** This function must be called
/// before any parallel operation triggers `getPool()`.  If `initPool`
/// and `getPool` are called from different threads, the sequential
/// fence below ensures the allocator write is visible to the thread
/// that executes `doInitPool` inside `pool_once.call()`.
///
/// Calling after the pool is already initialized has no effect.
pub fn initPool(allocator: std.mem.Allocator) void {
    if (!build_options.enable_spice) return;
    pool_allocator = allocator;
    // PERF-52: Ensure the allocator write is globally visible before any
    // thread calls getPool() -> pool_once.call() -> doInitPool().
    @fence(.seq_cst);
}

/// Return a pointer to the lazily-initialized global thread pool.
///
/// Uses `std.once` so the initialization mutex is only held on the first
/// call; all subsequent calls are a single atomic load (PERF-41).
pub fn getPool() if (build_options.enable_spice) *spice.ThreadPool else void {
    if (!build_options.enable_spice) return;

    pool_once.call();
    return &global_pool.?;
}

/// Shut down and release the global thread pool.
///
/// Safe to call even if the pool was never initialized.
pub fn deinitPool() void {
    if (!build_options.enable_spice) return;

    pool_deinit_mutex.lock();
    defer pool_deinit_mutex.unlock();

    if (global_pool) |*pool| {
        pool.deinit();
        global_pool = null;
    }
}

// ============================================================================
// Parallel File Loading
// ============================================================================

/// File load input
pub const FileLoadInput = struct {
    path: []const u8,
    format: ConfigFormat,
};

/// Config format
pub const ConfigFormat = enum {
    yaml,
    json,
    toml,
    ini,
    auto,
};

/// File load result
pub const FileLoadResult = struct {
    success: bool,
    content: ?[]const u8,
    error_msg: ?[]const u8,
};

/// Context for parallel file loading
pub const FileLoadContext = struct {
    inputs: []const FileLoadInput,
    results: []FileLoadResult,
    allocator: std.mem.Allocator,
};

/// Load multiple configuration files in parallel.
///
/// Each file is loaded and parsed independently, useful for
/// loading project, user, and system configs simultaneously.
///
/// Parameters:
/// - allocator: Memory allocator
/// - inputs: Array of (path, format) pairs
/// - results: Array to store load results
///
/// Threshold: Uses parallel processing for 4+ files (PERF-42).
/// Below 4 files the overhead of OS thread creation exceeds the
/// benefit of parallelism for typical config file sizes.
pub fn parallelFileLoad(
    allocator: std.mem.Allocator,
    inputs: []const FileLoadInput,
    results: []FileLoadResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < parallel_file_threshold) {
        for (inputs, 0..) |input, i| {
            results[i] = loadFile(allocator, input);
        }
        return;
    }

    const pool = getPool();
    const ctx = FileLoadContext{
        .inputs = inputs,
        .results = results,
        .allocator = allocator,
    };
    _ = pool.call(void, parallelFileLoadTask, ctx);
}

fn parallelFileLoadTask(t: *spice.Task, ctx: FileLoadContext) void {
    const inputs = ctx.inputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = loadFile(ctx.allocator, input);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = FileLoadContext{
        .inputs = inputs[0..mid],
        .results = results[0..mid],
        .allocator = ctx.allocator,
    };
    const right_ctx = FileLoadContext{
        .inputs = inputs[mid..],
        .results = results[mid..],
        .allocator = ctx.allocator,
    };

    var fut = spice.Future(FileLoadContext, void).init();
    fut.fork(t, parallelFileLoadTask, right_ctx);

    t.call(void, parallelFileLoadTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelFileLoadTask, right_ctx);
    }
}

fn loadFile(allocator: std.mem.Allocator, input: FileLoadInput) FileLoadResult {
    _ = allocator;
    // Actual file loading would read and parse file
    if (input.path.len == 0) {
        return .{ .success = false, .content = null, .error_msg = "empty path" };
    }
    return .{ .success = true, .content = null, .error_msg = null };
}

// ============================================================================
// Parallel Validation
// ============================================================================

/// Validation rule
pub const ValidationRule = struct {
    field: []const u8,
    rule_type: RuleType,
    param: ?[]const u8,
};

/// Rule types
pub const RuleType = enum {
    required,
    min_length,
    max_length,
    pattern,
    range,
};

/// Validation result
pub const ValidationResult = struct {
    valid: bool,
    field: []const u8,
    error_msg: ?[]const u8,
};

/// Context for parallel validation
pub const ValidationContext = struct {
    rules: []const ValidationRule,
    values: []const []const u8,
    results: []ValidationResult,
};

/// Validate multiple configuration fields in parallel.
///
/// Each field validation is independent, allowing for
/// concurrent validation of complex configurations.
///
/// Parameters:
/// - rules: Array of validation rules
/// - values: Array of field values (matching rules)
/// - results: Array to store validation results
///
/// Threshold: Uses parallel processing for 8+ rules
pub fn parallelValidate(
    rules: []const ValidationRule,
    values: []const []const u8,
    results: []ValidationResult,
) void {
    std.debug.assert(rules.len == values.len);
    std.debug.assert(rules.len == results.len);

    if (!build_options.enable_spice or rules.len < 8) {
        for (rules, 0..) |rule, i| {
            results[i] = validateField(rule, values[i]);
        }
        return;
    }

    const pool = getPool();
    const ctx = ValidationContext{
        .rules = rules,
        .values = values,
        .results = results,
    };
    _ = pool.call(void, parallelValidateTask, ctx);
}

fn parallelValidateTask(t: *spice.Task, ctx: ValidationContext) void {
    const rules = ctx.rules;
    const values = ctx.values;
    const results = ctx.results;

    if (rules.len < 4) {
        for (rules, 0..) |rule, i| {
            results[i] = validateField(rule, values[i]);
        }
        return;
    }

    const mid = rules.len / 2;
    const left_ctx = ValidationContext{
        .rules = rules[0..mid],
        .values = values[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = ValidationContext{
        .rules = rules[mid..],
        .values = values[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(ValidationContext, void).init();
    fut.fork(t, parallelValidateTask, right_ctx);

    t.call(void, parallelValidateTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelValidateTask, right_ctx);
    }
}

fn validateField(rule: ValidationRule, value: []const u8) ValidationResult {
    switch (rule.rule_type) {
        .required => {
            if (value.len == 0) {
                return .{ .valid = false, .field = rule.field, .error_msg = "required field is empty" };
            }
        },
        .min_length => {
            if (rule.param) |param| {
                const min = std.fmt.parseInt(usize, param, 10) catch 0;
                if (value.len < min) {
                    return .{ .valid = false, .field = rule.field, .error_msg = "value too short" };
                }
            }
        },
        .max_length => {
            if (rule.param) |param| {
                const max = std.fmt.parseInt(usize, param, 10) catch std.math.maxInt(usize);
                if (value.len > max) {
                    return .{ .valid = false, .field = rule.field, .error_msg = "value too long" };
                }
            }
        },
        .pattern, .range => {
            // Pattern and range validation would go here
        },
    }
    return .{ .valid = true, .field = rule.field, .error_msg = null };
}

// ============================================================================
// Parallel Serialization
// ============================================================================

/// Serialization format
pub const SerializeFormat = enum {
    json,
    yaml,
    toml,
};

/// Serialization input
pub const SerializeInput = struct {
    format: SerializeFormat,
    data: []const u8,
};

/// Serialization result
pub const SerializeResult = struct {
    success: bool,
    output: ?[]const u8,
};

/// Context for parallel serialization
pub const SerializeContext = struct {
    inputs: []const SerializeInput,
    results: []SerializeResult,
    allocator: std.mem.Allocator,
};

/// Serialize configuration to multiple formats in parallel.
///
/// Useful for generating JSON, YAML, and TOML outputs simultaneously.
///
/// Parameters:
/// - allocator: Memory allocator
/// - inputs: Array of (format, data) pairs
/// - results: Array to store serialization results
///
/// Threshold: Uses parallel processing for 4+ formats (PERF-42).
/// Below 4 formats the overhead of OS thread creation exceeds the
/// benefit of parallelism.
pub fn parallelSerialize(
    allocator: std.mem.Allocator,
    inputs: []const SerializeInput,
    results: []SerializeResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < parallel_serialize_threshold) {
        for (inputs, 0..) |input, i| {
            results[i] = serializeData(allocator, input);
        }
        return;
    }

    const pool = getPool();
    const ctx = SerializeContext{
        .inputs = inputs,
        .results = results,
        .allocator = allocator,
    };
    _ = pool.call(void, parallelSerializeTask, ctx);
}

fn parallelSerializeTask(t: *spice.Task, ctx: SerializeContext) void {
    const inputs = ctx.inputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = serializeData(ctx.allocator, input);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = SerializeContext{
        .inputs = inputs[0..mid],
        .results = results[0..mid],
        .allocator = ctx.allocator,
    };
    const right_ctx = SerializeContext{
        .inputs = inputs[mid..],
        .results = results[mid..],
        .allocator = ctx.allocator,
    };

    var fut = spice.Future(SerializeContext, void).init();
    fut.fork(t, parallelSerializeTask, right_ctx);

    t.call(void, parallelSerializeTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelSerializeTask, right_ctx);
    }
}

fn serializeData(allocator: std.mem.Allocator, input: SerializeInput) SerializeResult {
    _ = allocator;
    if (input.data.len == 0) {
        return .{ .success = false, .output = null };
    }
    return .{ .success = true, .output = null };
}

// ============================================================================
// Tests
// ============================================================================

test "parallel file load" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]FileLoadInput = undefined;
    var results: [4]FileLoadResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .path = "/path/to/config.yaml",
            .format = .yaml,
        };
    }

    parallelFileLoad(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
    }
}

test "parallel validate" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var rules: [16]ValidationRule = undefined;
    var values: [16][]const u8 = undefined;
    var results: [16]ValidationResult = undefined;

    for (&rules, 0..) |*rule, i| {
        rule.* = .{
            .field = "field",
            .rule_type = .required,
            .param = null,
        };
        values[i] = "value";
    }

    parallelValidate(&rules, &values, &results);

    for (results) |result| {
        try std.testing.expect(result.valid);
    }
}

test "parallel file load - empty path" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]FileLoadInput = undefined;
    var results: [4]FileLoadResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .path = "", // Empty path
            .format = .yaml,
        };
    }

    parallelFileLoad(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(!result.success);
        try std.testing.expect(result.error_msg != null);
    }
}

test "parallel file load - single item" {
    var inputs: [1]FileLoadInput = undefined;
    var results: [1]FileLoadResult = undefined;

    inputs[0] = .{
        .path = "/path/to/config.yaml",
        .format = .yaml,
    };

    parallelFileLoad(std.testing.allocator, &inputs, &results);
    try std.testing.expect(results[0].success);
}

test "parallel validate - required empty value" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var rules: [8]ValidationRule = undefined;
    var values: [8][]const u8 = undefined;
    var results: [8]ValidationResult = undefined;

    for (&rules, 0..) |*rule, i| {
        rule.* = .{
            .field = "required_field",
            .rule_type = .required,
            .param = null,
        };
        values[i] = ""; // Empty value for required field
    }

    parallelValidate(&rules, &values, &results);

    for (results) |result| {
        try std.testing.expect(!result.valid);
        try std.testing.expect(result.error_msg != null);
    }
}

test "parallel validate - min_length" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var rules: [8]ValidationRule = undefined;
    var values: [8][]const u8 = undefined;
    var results: [8]ValidationResult = undefined;

    for (&rules, 0..) |*rule, i| {
        rule.* = .{
            .field = "name",
            .rule_type = .min_length,
            .param = "5",
        };
        values[i] = if (i % 2 == 0) "ab" else "abcdef";
    }

    parallelValidate(&rules, &values, &results);

    for (results, 0..) |result, i| {
        if (i % 2 == 0) {
            try std.testing.expect(!result.valid);
        } else {
            try std.testing.expect(result.valid);
        }
    }
}

test "parallel validate - max_length" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var rules: [8]ValidationRule = undefined;
    var values: [8][]const u8 = undefined;
    var results: [8]ValidationResult = undefined;

    for (&rules, 0..) |*rule, i| {
        rule.* = .{
            .field = "code",
            .rule_type = .max_length,
            .param = "5",
        };
        values[i] = if (i % 2 == 0) "ab" else "abcdefghij";
    }

    parallelValidate(&rules, &values, &results);

    for (results, 0..) |result, i| {
        if (i % 2 == 0) {
            try std.testing.expect(result.valid);
        } else {
            try std.testing.expect(!result.valid);
        }
    }
}

test "parallel serialize - basic" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]SerializeInput = undefined;
    var results: [4]SerializeResult = undefined;

    inputs[0] = .{ .format = .json, .data = "test" };
    inputs[1] = .{ .format = .yaml, .data = "test" };
    inputs[2] = .{ .format = .toml, .data = "test" };
    inputs[3] = .{ .format = .json, .data = "test" };

    parallelSerialize(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
    }
}

test "parallel serialize - empty data" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]SerializeInput = undefined;
    var results: [4]SerializeResult = undefined;

    for (&inputs) |*input| {
        input.* = .{ .format = .json, .data = "" };
    }

    parallelSerialize(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(!result.success);
    }
}

// ---------------------------------------------------------------------------
// PERF-42: Sequential fallback for small file counts
// ---------------------------------------------------------------------------

test "parallel file load - 2 files uses sequential fallback (PERF-42)" {
    // With threshold at 4, 2 files should use sequential path regardless
    // of whether spice is enabled. This test verifies correct results
    // via the sequential path.
    var inputs: [2]FileLoadInput = undefined;
    var results: [2]FileLoadResult = undefined;

    inputs[0] = .{ .path = "/path/a.yaml", .format = .yaml };
    inputs[1] = .{ .path = "/path/b.yaml", .format = .yaml };

    parallelFileLoad(std.testing.allocator, &inputs, &results);

    try std.testing.expect(results[0].success);
    try std.testing.expect(results[1].success);
}

test "parallel file load - 3 files uses sequential fallback (PERF-42)" {
    // 3 < 4, so sequential path is used.
    var inputs: [3]FileLoadInput = undefined;
    var results: [3]FileLoadResult = undefined;

    for (&inputs) |*input| {
        input.* = .{ .path = "/path/config.yaml", .format = .yaml };
    }

    parallelFileLoad(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
    }
}

test "parallel serialize - 2 formats uses sequential fallback (PERF-42)" {
    // With threshold at 4, 2 formats should use sequential path.
    var inputs: [2]SerializeInput = undefined;
    var results: [2]SerializeResult = undefined;

    inputs[0] = .{ .format = .json, .data = "test" };
    inputs[1] = .{ .format = .yaml, .data = "test" };

    parallelSerialize(std.testing.allocator, &inputs, &results);

    try std.testing.expect(results[0].success);
    try std.testing.expect(results[1].success);
}

test "parallel serialize - 3 formats uses sequential fallback (PERF-42)" {
    // 3 < 4, so sequential path is used.
    var inputs: [3]SerializeInput = undefined;
    var results: [3]SerializeResult = undefined;

    inputs[0] = .{ .format = .json, .data = "data" };
    inputs[1] = .{ .format = .yaml, .data = "data" };
    inputs[2] = .{ .format = .toml, .data = "data" };

    parallelSerialize(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
    }
}

// ---------------------------------------------------------------------------
// PERF-42: Verify thresholds are set correctly
// ---------------------------------------------------------------------------

test "parallel file threshold is 4 (PERF-42)" {
    try std.testing.expectEqual(@as(usize, 4), parallel_file_threshold);
}

test "parallel serialize threshold is 4 (PERF-42)" {
    try std.testing.expectEqual(@as(usize, 4), parallel_serialize_threshold);
}

// ---------------------------------------------------------------------------
// PERF-40: initPool accepts caller-provided allocator
// ---------------------------------------------------------------------------

test "initPool sets pool allocator (PERF-40)" {
    // Verify initPool compiles and can be called with testing allocator.
    // After calling initPool, the allocator should be stored for use by
    // the next pool initialization. We cannot easily observe the stored
    // allocator from the public API, but we verify it does not panic.
    initPool(std.testing.allocator);

    // Reset to page_allocator to avoid affecting other tests.
    pool_allocator = std.heap.page_allocator;
}

// ---------------------------------------------------------------------------
// PERF-41: getPool uses std.once (lock-free after init)
// ---------------------------------------------------------------------------

test "getPool returns consistent pointer across calls (PERF-41)" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    // Two calls to getPool should return the same pointer, confirming
    // the once-init produces a stable singleton.
    const p1 = getPool();
    const p2 = getPool();
    try std.testing.expectEqual(p1, p2);
}
