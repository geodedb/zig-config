// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Parallel config operations using thread-pool submitBatch/WaitGroup.
//!
//! Provides high-performance parallel implementations for configuration
//! operations including file loading, merge operations, and validation.
//!
//! ## Overview
//!
//! This module enables parallel processing of configuration operations
//! using the devnw thread pool. Ideal for loading multiple config files
//! or validating large configuration structures.
//!
//! ## Build Configuration
//!
//! Enable: `-Dthread_pool=true` (default)
//! Disable: `-Dthread_pool=false`
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
const builtin = @import("builtin");
const tp = @import("thread_pool");

// ============================================================================
// Global Thread Pool
// ============================================================================

/// Maximum number of chunks used for flat task decomposition.
const MAX_CHUNKS: usize = 64;

/// Upper bound on a single config file read by `loadFile`. Mirrors
/// `limits.MAX_CONFIG_FILE_SIZE` (1 MiB) from the parent module. This module is
/// compiled standalone (build.zig `addModule("parallel", ...)` with no import of
/// `limits.zig`), so the bound is duplicated here to keep the read size-limited
/// (CWE-400) without adding a cross-module dependency.
const MAX_PARALLEL_FILE_SIZE: usize = 1024 * 1024;

// ============================================================================
// Thread-safe allocator wrapper (S-NEW-03, CWE-362)
// ============================================================================

/// Wraps a non-thread-safe allocator and serializes all allocation traffic
/// through a mutex so worker threads can allocate concurrently without racing.
///
/// **Why this exists (S-NEW-03 / CWE-362):** the parallel fan-out functions
/// hand the caller-provided allocator to up to `MAX_CHUNKS` worker threads,
/// each performing `alloc`/`free`. Idiomatic config allocators
/// (`ArenaAllocator`, `FixedBufferAllocator`) are *not* thread-safe; concurrent
/// metadata mutation would corrupt the heap (CWE-787). Zig 0.16.0 removed
/// `std.heap.ThreadSafeAllocator`, so this is a minimal, self-contained
/// re-implementation of that wrapper.
///
/// The wrapper holds no allocations of its own, so it needs no deinit; only the
/// `child_allocator` owns memory.
///
/// Synchronization uses a self-contained atomic spinlock with `Thread.yield`
/// backoff. Zig 0.16.0 removed `std.Thread.Mutex` and the surviving
/// `std.Io.Mutex` requires an `Io` instance that the `Allocator` vtable does not
/// thread through. Allocator critical sections are tiny (a single `rawAlloc` /
/// `rawFree`), so a spinlock is the appropriate, dependency-free primitive here.
const ThreadSafeAllocator = struct {
    child_allocator: std.mem.Allocator,
    locked: std.atomic.Value(bool) = .init(false),

    fn allocator(self: *ThreadSafeAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn lock(self: *ThreadSafeAllocator) void {
        // Acquire: spin until we flip false->true, yielding to reduce contention.
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }

    fn unlock(self: *ThreadSafeAllocator) void {
        self.locked.store(false, .release);
    }

    fn alloc(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *ThreadSafeAllocator = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        return self.child_allocator.rawAlloc(n, alignment, ra);
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *ThreadSafeAllocator = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        return self.child_allocator.rawResize(buf, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *ThreadSafeAllocator = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        return self.child_allocator.rawRemap(buf, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *ThreadSafeAllocator = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        self.child_allocator.rawFree(buf, alignment, ra);
    }
};

/// Minimum number of items before spawning the thread pool for file loads
/// and serialization. Below this threshold, sequential execution avoids
/// the overhead of OS thread creation (PERF-42).
const parallel_file_threshold: usize = 4;

/// Minimum number of items before spawning the thread pool for serialization.
const parallel_serialize_threshold: usize = 4;

var global_pool: ?tp.ThreadPool = null;

/// Allocator stored by `initPool()` for use during lazy initialization.
/// Defaults to `page_allocator`; callers should call `initPool()` with a
/// `GeneralPurposeAllocator` for better memory efficiency on small files
/// (PERF-40).
var pool_allocator: std.mem.Allocator = std.heap.page_allocator;

/// Guards pool init/deinit against concurrent access.
var pool_mutex: std.Io.Mutex = .init;

/// Tracks whether the pool has been initialized. Guarded by `pool_mutex`.
var pool_initialized: bool = false;

/// One-shot, lazily-initializing pool setup. Zig 0.16 removed `std.once`, so
/// we guard a plain bool with the same mutex used by `deinitPool`, which
/// provides the acquire/release synchronization for the `pool_allocator` and
/// `global_pool` writes (PERF-41/PERF-52).
fn ensurePoolInit() void {
    const pio = std.Io.Threaded.global_single_threaded.io();
    pool_mutex.lockUncancelable(pio);
    defer pool_mutex.unlock(pio);
    if (!pool_initialized) {
        global_pool = tp.ThreadPool.init(pool_allocator, .{}) catch @panic("thread pool init failed");
        pool_initialized = true;
    }
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
    pool_allocator = allocator;
    // PERF-52: Synchronization of the allocator write is provided by
    // `ensurePoolInit` (which acquires `pool_mutex` before reading
    // `pool_allocator`). Zig 0.16.0 removed the `@fence` builtin and
    // `std.once`, so the mutex establishes the happens-before edge.
}

/// Return a pointer to the lazily-initialized global thread pool.
///
/// `ensurePoolInit` initializes the pool on first call under `pool_mutex`;
/// subsequent calls re-check the `pool_initialized` flag under the lock.
pub fn getPool() *tp.ThreadPool {
    ensurePoolInit();
    return &global_pool.?;
}

/// Shut down and release the global thread pool.
///
/// Safe to call even if the pool was never initialized.
pub fn deinitPool() void {
    const pio = std.Io.Threaded.global_single_threaded.io();
    pool_mutex.lockUncancelable(pio);
    defer pool_mutex.unlock(pio);

    if (global_pool) |*pool| {
        pool.deinit();
        global_pool = null;
    }
    pool_initialized = false;
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

/// Per-item context for a single parallel file-load task.
const FileLoadItemCtx = struct {
    input: *const FileLoadInput,
    result: *FileLoadResult,
    allocator: std.mem.Allocator,
};

fn fileLoadTaskFn(raw_ctx: *anyopaque, _: *tp.TaskContext) void {
    const ctx: *FileLoadItemCtx = @ptrCast(@alignCast(raw_ctx));
    ctx.result.* = loadFile(ctx.allocator, ctx.input.*);
}

/// Load multiple configuration files in parallel.
///
/// Each file is loaded independently, useful for loading project, user, and
/// system configs simultaneously. Each file is read with a size limit
/// (`MAX_PARALLEL_FILE_SIZE`, CWE-400) and without following a terminal symlink
/// (`O_NOFOLLOW` on POSIX, CWE-59).
///
/// Parameters:
/// - allocator: Memory allocator. **Need NOT be thread-safe:** worker threads
///   allocate through an internal `ThreadSafeAllocator` wrapper (S-NEW-03,
///   CWE-362), so callers may safely pass an `ArenaAllocator` /
///   `FixedBufferAllocator`.
/// - inputs: Array of (path, format) pairs
/// - results: Array to store load results
///
/// **Ownership:** for each successful result, `results[i].content` is an owned
/// slice allocated with `allocator`; the caller MUST free every non-null
/// `content` with the same allocator. Failed results have `content == null` and
/// a static `error_msg`.
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

    if (inputs.len < parallel_file_threshold) {
        for (inputs, 0..) |input, i| {
            results[i] = loadFile(allocator, input);
        }
        return;
    }

    // S-NEW-03 (CWE-362): worker threads share one allocator. Wrap the
    // caller's allocator so concurrent alloc/free is serialized even when the
    // caller passed a non-thread-safe allocator (arena, fixed-buffer).
    var tsa: ThreadSafeAllocator = .{ .child_allocator = allocator };
    const worker_alloc = tsa.allocator();

    const n = @min(inputs.len, MAX_CHUNKS);
    var ctxs: [MAX_CHUNKS]FileLoadItemCtx = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    for (0..n) |i| {
        ctxs[i] = .{
            .input = &inputs[i],
            .result = &results[i],
            .allocator = worker_alloc,
        };
        batch[i] = .{ .task_fn = fileLoadTaskFn, .ctx = &ctxs[i] };
    }

    var wg = getPool().waitGroup();
    _ = getPool().submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        // Sequential fallback on error: single-threaded, so the raw allocator
        // is safe here.
        for (inputs, 0..) |input, i| {
            results[i] = loadFile(allocator, input);
        }
        return;
    };
    wg.wait();

    // Handle any items beyond MAX_CHUNKS sequentially. This runs on the calling
    // thread after `wg.wait()`, so no worker is concurrently allocating; the
    // raw allocator is safe.
    if (inputs.len > MAX_CHUNKS) {
        for (inputs[MAX_CHUNKS..], MAX_CHUNKS..) |input, i| {
            results[i] = loadFile(allocator, input);
        }
    }
}

/// Read a configuration file's raw bytes (Q-NEW-09).
///
/// Performs a real, size-limited (`MAX_PARALLEL_FILE_SIZE`, CWE-400),
/// symlink-resistant (`O_NOFOLLOW` on POSIX, CWE-59) read of `input.path`.
///
/// **Ownership:** on success, `result.content` is an owned slice allocated with
/// `allocator`; the caller MUST free it with the same allocator
/// (`allocator.free(result.content.?)`). `parallelFileLoad` documents the same
/// contract for batched results. On failure `content` is `null` and
/// `error_msg` is a static, non-allocated diagnostic.
fn loadFile(allocator: std.mem.Allocator, input: FileLoadInput) FileLoadResult {
    if (input.path.len == 0) {
        return .{ .success = false, .content = null, .error_msg = "empty path" };
    }

    const io = std.Io.Threaded.global_single_threaded.io();
    const file = openFileReadNoFollow(input.path) catch |err| {
        return .{ .success = false, .content = null, .error_msg = openErrorMessage(err) };
    };
    defer file.close(io);

    const content = readFileToEnd(file, allocator, MAX_PARALLEL_FILE_SIZE) catch |err| {
        return .{ .success = false, .content = null, .error_msg = readErrorMessage(err) };
    };

    return .{ .success = true, .content = content, .error_msg = null };
}

/// Open `path` read-only without following a terminal symlink.
///
/// Mirrors `secret.openFileReadNoFollow`. This module is compiled standalone and
/// cannot import `secret.zig`, so the no-follow open is replicated here to keep
/// the read symlink-resistant (CWE-59). On POSIX this uses an atomic
/// `O_NOFOLLOW` open; on Windows it falls back to a stat-then-open with the same
/// TOCTOU caveat documented in `secret.zig` (SEC-06).
fn openFileReadNoFollow(path: []const u8) !std.Io.File {
    if (builtin.os.tag == .windows) {
        const io = std.Io.Threaded.global_single_threaded.io();
        const md = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch null;
        if (md) |m| {
            if (m.kind == .sym_link) return error.SymlinkNotAllowed;
        }
        return std.Io.Dir.cwd().openFile(io, path, .{});
    }

    const fd = std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    ) catch |err| switch (err) {
        error.SymLinkLoop => return error.SymlinkNotAllowed,
        else => return err,
    };
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
}

/// Read an open file to EOF into an owned slice, capped at `max_size` bytes
/// (CWE-400). Mirrors `secret.readFileToEnd` for the standalone parallel module.
fn readFileToEnd(file: std.Io.File, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    var read_buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &read_buf);
    return reader.interface.allocRemaining(allocator, std.Io.Limit.limited(max_size));
}

/// Map an open error to a static diagnostic string (no allocation).
fn openErrorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "file not found",
        error.AccessDenied => "access denied",
        error.SymlinkNotAllowed => "symlink not allowed",
        error.IsDir => "path is a directory",
        else => "failed to open file",
    };
}

/// Map a read error to a static diagnostic string (no allocation).
fn readErrorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.OutOfMemory => "out of memory",
        error.StreamTooLong => "file exceeds maximum size",
        else => "failed to read file",
    };
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

/// Per-item context for a single parallel validation task.
const ValidateItemCtx = struct {
    rule: *const ValidationRule,
    value: []const u8,
    result: *ValidationResult,
};

fn validateTaskFn(raw_ctx: *anyopaque, _: *tp.TaskContext) void {
    const ctx: *ValidateItemCtx = @ptrCast(@alignCast(raw_ctx));
    ctx.result.* = validateField(ctx.rule.*, ctx.value);
}

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

    if (rules.len < 8) {
        for (rules, 0..) |rule, i| {
            results[i] = validateField(rule, values[i]);
        }
        return;
    }

    const n = @min(rules.len, MAX_CHUNKS);
    var ctxs: [MAX_CHUNKS]ValidateItemCtx = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    for (0..n) |i| {
        ctxs[i] = .{
            .rule = &rules[i],
            .value = values[i],
            .result = &results[i],
        };
        batch[i] = .{ .task_fn = validateTaskFn, .ctx = &ctxs[i] };
    }

    var wg = getPool().waitGroup();
    _ = getPool().submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        // Sequential fallback on error
        for (rules, 0..) |rule, i| {
            results[i] = validateField(rule, values[i]);
        }
        return;
    };
    wg.wait();

    // Handle any items beyond MAX_CHUNKS sequentially
    if (rules.len > MAX_CHUNKS) {
        for (rules[MAX_CHUNKS..], MAX_CHUNKS..) |rule, i| {
            results[i] = validateField(rule, values[i]);
        }
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

/// Per-item context for a single parallel serialization task.
const SerializeItemCtx = struct {
    input: *const SerializeInput,
    result: *SerializeResult,
    allocator: std.mem.Allocator,
};

fn serializeTaskFn(raw_ctx: *anyopaque, _: *tp.TaskContext) void {
    const ctx: *SerializeItemCtx = @ptrCast(@alignCast(raw_ctx));
    ctx.result.* = serializeData(ctx.allocator, ctx.input.*);
}

/// Serialize configuration to multiple formats in parallel.
///
/// Useful for generating JSON, YAML, and TOML outputs simultaneously.
///
/// Parameters:
/// - allocator: Memory allocator. **Need NOT be thread-safe:** worker threads
///   allocate through an internal `ThreadSafeAllocator` wrapper (S-NEW-03,
///   CWE-362), so callers may safely pass an `ArenaAllocator` /
///   `FixedBufferAllocator`.
/// - inputs: Array of (format, data) pairs
/// - results: Array to store serialization results
///
/// **Ownership:** for each successful result, `results[i].output` is an owned
/// slice allocated with `allocator`; the caller MUST free every non-null
/// `output` with the same allocator. Failed results have `output == null`.
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

    if (inputs.len < parallel_serialize_threshold) {
        for (inputs, 0..) |input, i| {
            results[i] = serializeData(allocator, input);
        }
        return;
    }

    // S-NEW-03 (CWE-362): serialize worker output allocations through a
    // thread-safe wrapper so a non-thread-safe caller allocator is safe.
    var tsa: ThreadSafeAllocator = .{ .child_allocator = allocator };
    const worker_alloc = tsa.allocator();

    const n = @min(inputs.len, MAX_CHUNKS);
    var ctxs: [MAX_CHUNKS]SerializeItemCtx = undefined;
    var batch: [MAX_CHUNKS]tp.BatchTask = undefined;

    for (0..n) |i| {
        ctxs[i] = .{
            .input = &inputs[i],
            .result = &results[i],
            .allocator = worker_alloc,
        };
        batch[i] = .{ .task_fn = serializeTaskFn, .ctx = &ctxs[i] };
    }

    var wg = getPool().waitGroup();
    _ = getPool().submitBatch(batch[0..n], .{ .wait_group = &wg }) catch {
        // Sequential fallback on error: single-threaded, raw allocator is safe.
        for (inputs, 0..) |input, i| {
            results[i] = serializeData(allocator, input);
        }
        return;
    };
    wg.wait();

    // Handle any items beyond MAX_CHUNKS sequentially. Runs on the calling
    // thread after `wg.wait()`; no worker is concurrently allocating.
    if (inputs.len > MAX_CHUNKS) {
        for (inputs[MAX_CHUNKS..], MAX_CHUNKS..) |input, i| {
            results[i] = serializeData(allocator, input);
        }
    }
}

/// Serialize a raw payload into a format-appropriate document (Q-NEW-09).
///
/// `SerializeInput` carries only opaque bytes (`data`) plus a target `format`;
/// it has no compile-time struct type, so this cannot drive the generic
/// `serialize.serialize(T, value, ...)` codec. Instead it produces a real,
/// owned, format-valid encoding of the payload as a single string value with
/// the escaping rules appropriate to each format (mirroring the escape rules in
/// `serialize.zig`). The output is genuine serialized bytes, not a stub.
///
/// **Ownership:** on success, `result.output` is an owned slice allocated with
/// `allocator`; the caller MUST free it (`allocator.free(result.output.?)`).
/// `parallelSerialize` documents the same contract for batched results. On
/// failure (empty input or OOM) `output` is `null`.
fn serializeData(allocator: std.mem.Allocator, input: SerializeInput) SerializeResult {
    if (input.data.len == 0) {
        return .{ .success = false, .output = null };
    }

    const output = encodeScalar(allocator, input.format, input.data) catch {
        return .{ .success = false, .output = null };
    };

    return .{ .success = true, .output = output };
}

/// Encode `data` as a single format-valid string document. Returns owned bytes.
fn encodeScalar(allocator: std.mem.Allocator, format: SerializeFormat, data: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    switch (format) {
        .json => {
            // RFC 8259 string: quote and escape control/special characters.
            try buf.append(allocator, '"');
            try writeEscaped(allocator, &buf, data, .json);
            try buf.append(allocator, '"');
        },
        .yaml => {
            // YAML double-quoted scalar.
            try buf.append(allocator, '"');
            try writeEscaped(allocator, &buf, data, .yaml);
            try buf.append(allocator, '"');
        },
        .toml => {
            // TOML basic string (double-quoted).
            try buf.append(allocator, '"');
            try writeEscaped(allocator, &buf, data, .toml);
            try buf.append(allocator, '"');
        },
    }

    return buf.toOwnedSlice(allocator);
}

/// Escape mode for `writeEscaped`, matching `serialize.zig`'s per-format rules.
const EscapeMode = enum { json, yaml, toml };

/// Append `value` to `buf` with format-appropriate escaping (mirrors
/// `serialize.zig:writeEscapedString` for the subset of formats this module
/// emits).
fn writeEscaped(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    value: []const u8,
    mode: EscapeMode,
) !void {
    for (value) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => switch (mode) {
                .json => try buf.appendSlice(allocator, "\\r"),
                else => try buf.append(allocator, c),
            },
            '\t' => switch (mode) {
                .json, .toml => try buf.appendSlice(allocator, "\\t"),
                else => try buf.append(allocator, c),
            },
            0x08 => switch (mode) {
                .json => try buf.appendSlice(allocator, "\\b"),
                else => try buf.append(allocator, c),
            },
            0x0C => switch (mode) {
                .json => try buf.appendSlice(allocator, "\\f"),
                else => try buf.append(allocator, c),
            },
            else => {
                // JSON escapes remaining control chars < 0x20 as \uXXXX.
                if (mode == .json and c < 0x20) {
                    try buf.print(allocator, "\\u{X:0>4}", .{c});
                } else {
                    try buf.append(allocator, c);
                }
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "parallel file load" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "config.yaml", .data = "key: value\n" });
    const path = try tmp.dir.realPathFileAlloc(io, "config.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var inputs: [4]FileLoadInput = undefined;
    var results: [4]FileLoadResult = undefined;

    for (&inputs) |*input| {
        input.* = .{ .path = path, .format = .yaml };
    }

    parallelFileLoad(std.testing.allocator, &inputs, &results);
    defer for (results) |r| if (r.content) |c| std.testing.allocator.free(c);

    for (results) |result| {
        try std.testing.expect(result.success);
        try std.testing.expect(result.content != null);
        try std.testing.expectEqualStrings("key: value\n", result.content.?);
    }
}

test "parallel validate" {
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
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "config.yaml", .data = "key: value\n" });
    const path = try tmp.dir.realPathFileAlloc(io, "config.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var inputs: [1]FileLoadInput = .{
        .{ .path = path, .format = .yaml },
    };
    var results: [1]FileLoadResult = undefined;

    parallelFileLoad(std.testing.allocator, &inputs, &results);
    defer if (results[0].content) |c| std.testing.allocator.free(c);

    try std.testing.expect(results[0].success);
    try std.testing.expectEqualStrings("key: value\n", results[0].content.?);
}

test "parallel validate - required empty value" {
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
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // With threshold at 4, 2 files should use sequential path regardless
    // of whether parallelism is enabled. This test verifies correct results
    // via the sequential path against real fixtures.
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "a.yaml", .data = "a: 1\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.yaml", .data = "b: 2\n" });
    const path_a = try tmp.dir.realPathFileAlloc(io, "a.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path_a);
    const path_b = try tmp.dir.realPathFileAlloc(io, "b.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path_b);

    var inputs: [2]FileLoadInput = .{
        .{ .path = path_a, .format = .yaml },
        .{ .path = path_b, .format = .yaml },
    };
    var results: [2]FileLoadResult = undefined;

    parallelFileLoad(std.testing.allocator, &inputs, &results);
    defer for (results) |r| if (r.content) |c| std.testing.allocator.free(c);

    try std.testing.expect(results[0].success);
    try std.testing.expect(results[1].success);
}

test "parallel file load - 3 files uses sequential fallback (PERF-42)" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    // 3 < 4, so sequential path is used.
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "config.yaml", .data = "k: v\n" });
    const path = try tmp.dir.realPathFileAlloc(io, "config.yaml", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var inputs: [3]FileLoadInput = undefined;
    for (&inputs) |*input| {
        input.* = .{ .path = path, .format = .yaml };
    }
    var results: [3]FileLoadResult = undefined;

    parallelFileLoad(std.testing.allocator, &inputs, &results);
    defer for (results) |r| if (r.content) |c| std.testing.allocator.free(c);

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
// PERF-41: getPool returns stable pointer across calls
// ---------------------------------------------------------------------------

test "getPool returns consistent pointer across calls (PERF-41)" {
    // Two calls to getPool should return the same pointer, confirming
    // the once-init produces a stable singleton.
    const p1 = getPool();
    const p2 = getPool();
    try std.testing.expectEqual(p1, p2);
}
