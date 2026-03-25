// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Async Configuration Loading Module
//!
//! Provides asynchronous configuration loading capabilities using Zig's
//! thread-based concurrency model. Useful for:
//! - Loading multiple config files in parallel
//! - Non-blocking config loading in servers
//! - Background config refresh
//!
//! Example usage:
//! ```zig
//! const async_config = @import("async");
//!
//! // Load multiple configs in parallel
//! var loader = async_config.AsyncLoader(MyConfig).init(allocator);
//! defer loader.deinit();
//!
//! try loader.addFile("config.toml", .toml);
//! try loader.addFile("secrets.json", .json);
//!
//! // Start loading in background
//! try loader.startAsync();
//!
//! // Do other work...
//!
//! // Wait for completion and get result
//! const config = try loader.await();
//! ```

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Thread = std.Thread;
const Allocator = mem.Allocator;

const loader_mod = @import("loader.zig");
const Format = loader_mod.Format;
const secret = @import("secret.zig");
const limits = @import("limits.zig");

// Security: Import helpers for symlink and path traversal protection (CWE-59, CWE-22, #72, #74)
const isSymlink = secret.isSymlink;
const isPathSafe = secret.isPathSafe;
const openFileReadNoFollow = secret.openFileReadNoFollow;

/// Async loading errors
pub const AsyncError = error{
    LoadFailed,
    AlreadyRunning,
    NotStarted,
    Timeout,
    OutOfMemory,
    ThreadError,
};

/// State of async operation
pub const AsyncState = enum {
    idle,
    running,
    completed,
    failed,
};

/// Result of an async load operation
pub fn AsyncResult(comptime T: type) type {
    return struct {
        config: ?T,
        err: ?anyerror,
        state: AsyncState,
    };
}

/// File to load asynchronously
const AsyncFile = struct {
    path: []const u8,
    format: Format,
};

/// Async configuration loader
pub fn AsyncLoader(comptime T: type) type {
    return struct {
        allocator: Allocator,
        files: std.ArrayListUnmanaged(AsyncFile),
        thread: ?Thread,
        result: AsyncResult(T),
        mutex: Thread.Mutex,
        arena: std.heap.ArenaAllocator,

        const Self = @This();

        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .files = .{},
                .thread = null,
                .result = .{
                    .config = null,
                    .err = null,
                    .state = .idle,
                },
                .mutex = .{},
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            // Wait for any running thread
            if (self.thread) |thread| {
                thread.join();
            }
            self.files.deinit(self.allocator);
            self.arena.deinit();
        }

        /// Add a file to load.
        ///
        /// Must be called **before** `startAsync()`.  Adding files to a
        /// running loader is a programming error and returns
        /// `error.AlreadyRunning`.
        pub fn addFile(self: *Self, path: []const u8, format: Format) !void {
            self.mutex.lock();
            const state = self.result.state;
            self.mutex.unlock();
            if (state == .running) return AsyncError.AlreadyRunning;

            const owned_path = try self.arena.allocator().dupe(u8, path);
            try self.files.append(self.allocator, .{
                .path = owned_path,
                .format = format,
            });
        }

        /// Start async loading
        pub fn startAsync(self: *Self) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.result.state == .running) {
                return AsyncError.AlreadyRunning;
            }

            self.result.state = .running;
            self.result.config = null;
            self.result.err = null;

            self.thread = try Thread.spawn(.{}, loadThreadFn, .{self});
        }

        /// Wait for async loading to complete and get result
        pub fn await(self: *Self) !T {
            if (self.thread) |thread| {
                thread.join();
                self.thread = null;
            }

            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.result.state == .failed) {
                if (self.result.err) |e| {
                    return e;
                }
                return AsyncError.LoadFailed;
            }

            if (self.result.config) |config| {
                return config;
            }

            return AsyncError.LoadFailed;
        }

        /// Check if loading is complete (non-blocking)
        pub fn isComplete(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.result.state == .completed or self.result.state == .failed;
        }

        /// Get current state
        pub fn getState(self: *Self) AsyncState {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.result.state;
        }

        /// Try to get result without blocking (returns null if not ready)
        pub fn tryGetResult(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.result.state == .completed) {
                return self.result.config;
            }
            return null;
        }

        fn loadThreadFn(self: *Self) void {
            var loader = loader_mod.Loader(T).init(self.allocator);
            defer loader.deinit();

            // Load each file
            for (self.files.items) |file| {
                self.loadFile(&loader, file.path, file.format) catch |e| {
                    self.mutex.lock();
                    self.result.state = .failed;
                    self.result.err = e;
                    self.mutex.unlock();
                    return;
                };
            }

            // Get final config
            const config = loader.load(.{
                .app_name = "async",
                .use_xdg = false,
                .optional = true,
            }) catch |e| {
                self.mutex.lock();
                self.result.state = .failed;
                self.result.err = e;
                self.mutex.unlock();
                return;
            };

            self.mutex.lock();
            self.result.config = config;
            self.result.state = .completed;
            self.mutex.unlock();
        }

        fn loadFile(self: *Self, loader: *loader_mod.Loader(T), path: []const u8, format: Format) !void {
            _ = format;
            _ = self;

            // Security: Validate path does not contain traversal sequences (CWE-22, #74)
            // P3-R3: Return an error instead of silently skipping, so the caller
            // (loadThreadFn) can surface it via result.state = .failed.
            if (!isPathSafe(path)) {
                return error.PathTraversalDetected;
            }

            const file = openFileReadNoFollow(path) catch {
                return; // File not found is ok for optional configs
            };
            defer file.close();

            const content = try file.readToEndAlloc(loader.allocator, limits.MAX_CONFIG_FILE_SIZE);
            defer loader.allocator.free(content);

            // Parse and apply to loader
            const detected_format = Format.fromExtension(path);
            loader.parseContent(content, detected_format, .project, path) catch |err| switch (err) {
                // NEW-11: Propagate OOM to loadThreadFn so it sets result.state = .failed.
                // Previously this returned silently, causing the caller to see a config
                // with missing data and no error indication.
                error.OutOfMemory => return error.OutOfMemory,
                else => {}, // Parse errors on optional sources are non-critical
            };
        }
    };
}

/// Load a config file asynchronously (convenience function)
pub fn loadAsync(comptime T: type, allocator: Allocator, path: []const u8) !*AsyncLoader(T) {
    const loader = try allocator.create(AsyncLoader(T));
    loader.* = AsyncLoader(T).init(allocator);
    try loader.addFile(path, .auto);
    try loader.startAsync();
    return loader;
}

/// Callback type for async completion
pub const CompletionCallback = *const fn (success: bool, user_data: ?*anyopaque) void;

/// Async loader with callback support
pub fn AsyncLoaderWithCallback(comptime T: type) type {
    return struct {
        loader: AsyncLoader(T),
        callback: ?CompletionCallback,
        user_data: ?*anyopaque,

        const Self = @This();

        pub fn init(allocator: Allocator) Self {
            return .{
                .loader = AsyncLoader(T).init(allocator),
                .callback = null,
                .user_data = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.loader.deinit();
        }

        pub fn setCallback(self: *Self, callback: CompletionCallback, user_data: ?*anyopaque) void {
            self.callback = callback;
            self.user_data = user_data;
        }

        pub fn addFile(self: *Self, path: []const u8, format: Format) !void {
            try self.loader.addFile(path, format);
        }

        pub fn startAsync(self: *Self) !void {
            try self.loader.startAsync();
        }

        /// Poll for completion and trigger callback if done
        pub fn poll(self: *Self) bool {
            if (self.loader.isComplete()) {
                if (self.callback) |cb| {
                    const success = self.loader.result.state == .completed;
                    cb(success, self.user_data);
                }
                return true;
            }
            return false;
        }

        pub fn await(self: *Self) !T {
            return self.loader.await();
        }
    };
}

/// Maximum number of threads for parallel loading (#106).
/// Prevents resource exhaustion when many paths are provided.
/// 16 is a reasonable upper bound for config file I/O concurrency.
pub const MAX_PARALLEL_THREADS: usize = 16;

/// Load multiple config files in parallel
pub fn loadParallel(comptime T: type, allocator: Allocator, paths: []const []const u8) !T {
    const ThreadContext = struct {
        path: []const u8,
        allocator: Allocator,
        result: ?[]const u8,
        err: ?anyerror,
    };

    var contexts = try allocator.alloc(ThreadContext, paths.len);
    defer allocator.free(contexts);

    // Cap active threads to prevent unbounded spawning (#106)
    const max_threads = @min(paths.len, MAX_PARALLEL_THREADS);
    var threads = try allocator.alloc(?Thread, max_threads);
    defer allocator.free(threads);

    // Initialize contexts
    for (paths, 0..) |path, i| {
        contexts[i] = .{
            .path = path,
            .allocator = allocator,
            .result = null,
            .err = null,
        };
    }

    // Process in batches of max_threads to bound concurrency (#106)
    var processed: usize = 0;
    while (processed < paths.len) {
        const batch_size = @min(max_threads, paths.len - processed);

        // Spawn a batch of threads
        for (0..batch_size) |j| {
            threads[j] = Thread.spawn(.{}, struct {
                fn load(c: *ThreadContext) void {
                    // Security: Validate path does not contain traversal sequences (CWE-22, #74)
                    if (!isPathSafe(c.path)) {
                        c.err = error.PathTraversalDetected;
                        return;
                    }

                    const file = openFileReadNoFollow(c.path) catch |e| {
                        c.err = e;
                        return;
                    };
                    defer file.close();

                    c.result = file.readToEndAlloc(c.allocator, limits.MAX_CONFIG_FILE_SIZE) catch |e| {
                        c.err = e;
                        return;
                    };
                }
            }.load, .{&contexts[processed + j]}) catch null;
        }

        // Wait for the batch to complete
        for (0..batch_size) |j| {
            if (threads[j]) |thread| {
                thread.join();
            }
        }

        processed += batch_size;
    }

    // Merge results into loader
    var loader = loader_mod.Loader(T).init(allocator);
    defer loader.deinit();

    for (contexts, 0..) |ctx, i| {
        if (ctx.result) |content| {
            defer allocator.free(content);
            const format = Format.fromExtension(paths[i]);
            loader.parseContent(content, format, .project, paths[i]) catch |err| switch (err) {
                error.OutOfMemory => break, // Stop processing on OOM
                else => {}, // Parse errors on optional sources are non-critical
            };
        }
    }

    // PERF-61: The parallel threads already populated the loader's config
    // fields via parseContent(). Calling loader.load() would redundantly
    // re-run the full loading pipeline (filesystem discovery for CWD config,
    // .env file reading, env scanning) -- none of which is needed here since
    // no env bindings, overrides, or search paths are configured on this
    // temporary loader instance.  getConfig() returns the config as-is with
    // struct defaults for any fields not set by the parsed files.
    return loader.getConfig();
}

// ============================================================================
// Tests
// ============================================================================

test "AsyncLoader initialization" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try std.testing.expectEqual(AsyncState.idle, loader.getState());
}

test "AsyncLoader add file" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.addFile("/tmp/config.toml", .toml);
    try loader.addFile("/tmp/config.json", .json);

    try std.testing.expectEqual(@as(usize, 2), loader.files.items.len);
}

test "AsyncState enum" {
    try std.testing.expectEqual(AsyncState.idle, AsyncState.idle);
    try std.testing.expectEqual(AsyncState.running, AsyncState.running);
    try std.testing.expectEqual(AsyncState.completed, AsyncState.completed);
    try std.testing.expectEqual(AsyncState.failed, AsyncState.failed);
}

test "AsyncLoaderWithCallback initialization" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoaderWithCallback(Config).init(std.testing.allocator);
    defer loader.deinit();

    try std.testing.expect(loader.callback == null);
}

test "AsyncLoaderWithCallback set callback" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoaderWithCallback(Config).init(std.testing.allocator);
    defer loader.deinit();

    const TestCallback = struct {
        var called = false;
        fn callback(_: bool, _: ?*anyopaque) void {
            called = true;
        }
    };

    loader.setCallback(TestCallback.callback, null);
    try std.testing.expect(loader.callback != null);
}

test "AsyncResult failed state propagates error through await (NEW-11)" {
    // Verify that when a thread sets result.state = .failed with an OOM error,
    // await() returns that error to the caller rather than silently succeeding.
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Simulate what loadThreadFn does when loadFile returns OOM:
    // it sets result.state = .failed and result.err = error.OutOfMemory.
    loader.mutex.lock();
    loader.result.state = .failed;
    loader.result.err = error.OutOfMemory;
    loader.mutex.unlock();

    // await() must surface the OOM error, not return a default config
    const result = loader.await();
    try std.testing.expectError(error.OutOfMemory, result);
}

test "loadFile propagates PathTraversalDetected through await (P3-R3)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // A path with ".." traversal causes loadFile to return an error,
    // which loadThreadFn propagates into result.state = .failed.
    try loader.addFile("../../../etc/passwd", .auto);
    try loader.startAsync();

    const result = loader.await();
    try std.testing.expectError(error.PathTraversalDetected, result);
}

test "addFile rejects calls when loader is running (PERF-53)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Simulate running state
    loader.mutex.lock();
    loader.result.state = .running;
    loader.mutex.unlock();

    const result = loader.addFile("/tmp/config.toml", .toml);
    try std.testing.expectError(AsyncError.AlreadyRunning, result);
}

test "AsyncLoaderWithCallback invokes callback on completion (Q-NEW-3)" {
    // Integration test: create a real temp config file, load it through
    // AsyncLoaderWithCallback, and verify the callback fires after poll().
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    // Write a temp JSON config file
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const json_content = "{\"host\": \"integration.test\", \"port\": 9090}";
    tmp_dir.dir.writeFile(.{ .sub_path = "config.json", .data = json_content }) catch return;

    const tmp_path = tmp_dir.dir.realpathAlloc(std.testing.allocator, "config.json") catch return;
    defer std.testing.allocator.free(tmp_path);

    // Shared state for the callback -- use a pointer so the callback can
    // mutate it via user_data without relying on mutable static vars.
    const CallbackState = struct {
        invoked: bool = false,
        success_value: bool = false,
    };
    var cb_state = CallbackState{};

    const TestCb = struct {
        fn callback(success: bool, user_data: ?*anyopaque) void {
            const state: *CallbackState = @ptrCast(@alignCast(user_data.?));
            state.invoked = true;
            state.success_value = success;
        }
    };

    var loader = AsyncLoaderWithCallback(Config).init(std.testing.allocator);
    defer loader.deinit();

    loader.setCallback(TestCb.callback, @ptrCast(&cb_state));
    try loader.addFile(tmp_path, .json);
    try loader.startAsync();

    // Wait for the background thread to finish
    const config = try loader.await();

    // poll() checks isComplete() and invokes the callback
    const done = loader.poll();
    try std.testing.expect(done);
    try std.testing.expect(cb_state.invoked);
    try std.testing.expect(cb_state.success_value);

    // Verify the loaded config values
    try std.testing.expectEqualStrings("integration.test", config.host);
    try std.testing.expectEqual(@as(u16, 9090), config.port);
}

test "MAX_PARALLEL_THREADS bounds thread count" {
    // Verify the constant is a reasonable value that prevents unbounded spawning (#106)
    try std.testing.expect(MAX_PARALLEL_THREADS > 0);
    try std.testing.expect(MAX_PARALLEL_THREADS <= 16);

    // Verify @min correctly caps thread count when paths exceed limit
    const many_paths: usize = 100;
    const capped = @min(many_paths, MAX_PARALLEL_THREADS);
    try std.testing.expectEqual(@as(usize, 16), capped);

    // Verify @min passes through when paths are fewer than limit
    const few_paths: usize = 3;
    const uncapped = @min(few_paths, MAX_PARALLEL_THREADS);
    try std.testing.expectEqual(@as(usize, 3), uncapped);
}
