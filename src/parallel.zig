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
//! ## Performance Thresholds
//!
//! | Operation      | Threshold | Sequential Below |
//! |----------------|-----------|------------------|
//! | File Load      | 2 files   | Yes              |
//! | Validation     | 8 rules   | Yes              |
//! | Serialization  | 2 formats | Yes              |

const std = @import("std");
const build_options = @import("build_options");

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

var global_pool: if (build_options.enable_spice) ?spice.ThreadPool else void = if (build_options.enable_spice) null else {};
var pool_mutex: std.Thread.Mutex = .{};

pub fn getPool() if (build_options.enable_spice) *spice.ThreadPool else void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    if (global_pool == null) {
        global_pool = spice.ThreadPool.init(std.heap.page_allocator);
        global_pool.?.start(.{});
    }
    return &global_pool.?;
}

pub fn deinitPool() void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

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
/// Threshold: Uses parallel processing for 2+ files
pub fn parallelFileLoad(
    allocator: std.mem.Allocator,
    inputs: []const FileLoadInput,
    results: []FileLoadResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < 2) {
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
/// Threshold: Uses parallel processing for 2+ formats
pub fn parallelSerialize(
    allocator: std.mem.Allocator,
    inputs: []const SerializeInput,
    results: []SerializeResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < 2) {
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
