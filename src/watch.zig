// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Watch/Hot-Reload Module
//!
//! Provides file watching and hot-reload capabilities for configuration files.
//! Supports polling-based watching for cross-platform compatibility.
//!
//! ## Security Considerations
//!
//! **TOCTOU Warning (CWE-367):** This module uses a polling-based approach that
//! has an inherent time-of-check-time-of-use race condition. Between when the
//! watcher detects a file change and when your application reads the file,
//! the file contents may have changed again. For security-critical configuration:
//!
//! - Validate configuration after loading, not based on change detection
//! - Consider file locking for critical configuration updates
//! - Use atomic file replacement (write to temp, rename) for updates
//! - Implement configuration validation in your reload callback
//!
//! This limitation is documented per security review (#52).
//!
//! Example usage:
//! ```zig
//! const watch = @import("watch");
//!
//! var watcher = watch.Watcher.init(allocator, .{
//!     .poll_interval_ms = 1000,
//! });
//! defer watcher.deinit();
//!
//! try watcher.addPath("config.toml", onConfigChanged);
//! try watcher.start();
//!
//! // Later...
//! watcher.stop();
//! ```

const std = @import("std");
const secret = @import("secret.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const Thread = std.Thread;

// Security: Import no-follow open helper for symlink attack prevention (CWE-59, #69)
const openFileReadNoFollow = secret.openFileReadNoFollow;
const posix = std.posix;

/// Zig 0.16.0 compat: std.Thread.sleep was removed; use posix nanosleep directly.
fn nanosleep(nanoseconds: u64) void {
    const ns_per_s = std.time.ns_per_s;
    var req: posix.timespec = .{
        .sec = @intCast(nanoseconds / ns_per_s),
        .nsec = @intCast(nanoseconds % ns_per_s),
    };
    var rem: posix.timespec = undefined;
    while (true) {
        const rc = posix.system.nanosleep(&req, &rem);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => {
                req = rem;
                continue;
            },
            else => return,
        }
    }
}

/// Zig 0.16.0 compat: std.Thread.Mutex was removed; wrap std.Io.Mutex
/// with uncancelable lock so callers keep the zero-arg lock()/unlock() API.
const Mutex = struct {
    inner: std.Io.Mutex = .init,

    fn io() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(io());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(io());
    }
};

/// Convert a poll interval in milliseconds to nanoseconds.
///
/// `poll_interval_ms` is a `u32`; `std.time.ns_per_ms` is 1_000_000, so the
/// product overflows a `u32` for any interval >= 4295 ms. Widen to `u64`
/// before multiplying so large intervals neither panic (Debug/ReleaseSafe)
/// nor silently wrap into a busy-loop (ReleaseFast).
fn pollIntervalNs(poll_interval_ms: u32) u64 {
    return @as(u64, poll_interval_ms) * std.time.ns_per_ms;
}

/// Watch errors
pub const WatchError = error{
    FileNotFound,
    AccessDenied,
    WatcherAlreadyRunning,
    WatcherNotRunning,
    TooManyWatches,
    OutOfMemory,
};

/// Type of file change event
pub const ChangeEvent = enum {
    modified,
    deleted,
    created,
};

/// Callback function type for file changes
pub const ChangeCallback = *const fn (path: []const u8, event: ChangeEvent, user_data: ?*anyopaque) void;

/// Watch options
pub const WatchOptions = struct {
    /// Polling interval in milliseconds (for polling mode)
    poll_interval_ms: u32 = 1000,
    /// Whether to trigger callback on initial add
    trigger_on_add: bool = false,
    /// Maximum number of paths to watch
    max_watches: usize = 100,
};

/// Information about a watched file
const WatchedFile = struct {
    path: []const u8,
    callback: ChangeCallback,
    user_data: ?*anyopaque,
    last_mtime: std.Io.Timestamp,
    last_size: u64,
    exists: bool,
};

/// File watcher with hot-reload support
///
/// ## Concurrency contract (CWE-362)
///
/// The background poll thread and the public API mutate the same `watches`
/// list, so all access is serialized by `watches_mutex`. As a consequence:
///
/// - `ChangeCallback` invocations are performed **while `watches_mutex` is
///   held**. Callbacks for a given `Watcher` are therefore never invoked
///   concurrently with each other.
/// - A callback MUST NOT call back into the same `Watcher`'s `addPath`,
///   `addPathWithData`, `removePath`, `checkNow`, or `watchCount` — the mutex
///   is non-reentrant and doing so would deadlock.
/// - `start`, `stop`, and `deinit` do not hold `watches_mutex` while
///   joining the poll thread, so they cannot deadlock against an in-flight
///   `checkForChanges` (the loop releases the lock before re-checking the
///   `running` flag and sleeping).
pub const Watcher = struct {
    allocator: Allocator,
    options: WatchOptions,
    watches: std.ArrayListUnmanaged(WatchedFile),
    /// Guards all reads/writes of `watches` (and the per-element fields that
    /// `checkForChanges` mutates) against the background poll thread.
    watches_mutex: Mutex,
    running: std.atomic.Value(bool),
    thread: ?Thread,
    /// Arena for path storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator, options: WatchOptions) Watcher {
        return .{
            .allocator = allocator,
            .options = options,
            .watches = .empty,
            .watches_mutex = .{},
            .running = std.atomic.Value(bool).init(false),
            .thread = null,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Watcher) void {
        self.stop();
        self.watches.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Add a file to watch
    pub fn addPath(self: *Watcher, path: []const u8, callback: ChangeCallback) !void {
        try self.addPathWithData(path, callback, null);
    }

    /// Add a file to watch with user data
    pub fn addPathWithData(self: *Watcher, path: []const u8, callback: ChangeCallback, user_data: ?*anyopaque) !void {
        // Hold the lock across the capacity check + append so the poll thread
        // cannot reallocate/iterate `watches` concurrently (CWE-362).
        self.watches_mutex.lock();

        if (self.watches.items.len >= self.options.max_watches) {
            self.watches_mutex.unlock();
            return WatchError.TooManyWatches;
        }

        const owned_path = self.arena.allocator().dupe(u8, path) catch |err| {
            self.watches_mutex.unlock();
            return err;
        };

        // Get initial file state
        const stat = getFileStat(path);
        const exists = stat != null;

        self.watches.append(self.allocator, .{
            .path = owned_path,
            .callback = callback,
            .user_data = user_data,
            .last_mtime = if (stat) |s| s.mtime else std.Io.Timestamp.zero,
            .last_size = if (stat) |s| s.size else 0,
            .exists = exists,
        }) catch |err| {
            self.watches_mutex.unlock();
            return err;
        };

        self.watches_mutex.unlock();

        // Trigger callback on add if requested. Fired after releasing the lock:
        // the entry is already committed and `owned_path`/`user_data` are
        // captured locally, so this is race-free and keeps the add path from
        // holding the lock across arbitrary user code.
        if (self.options.trigger_on_add and exists) {
            callback(owned_path, .modified, user_data);
        }
    }

    /// Remove a watched path
    pub fn removePath(self: *Watcher, path: []const u8) bool {
        self.watches_mutex.lock();
        defer self.watches_mutex.unlock();

        for (self.watches.items, 0..) |watch, i| {
            if (mem.eql(u8, watch.path, path)) {
                _ = self.watches.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Start watching (spawns background thread)
    pub fn start(self: *Watcher) !void {
        if (self.running.load(.acquire)) {
            return WatchError.WatcherAlreadyRunning;
        }

        self.running.store(true, .release);
        self.thread = try Thread.spawn(.{}, watchLoop, .{self});
    }

    /// Stop watching
    pub fn stop(self: *Watcher) void {
        if (!self.running.load(.acquire)) {
            return;
        }

        self.running.store(false, .release);

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    /// Check if watcher is running
    pub fn isRunning(self: *const Watcher) bool {
        return self.running.load(.acquire);
    }

    /// Get number of watched paths
    ///
    /// Takes a mutable receiver because it acquires `watches_mutex` to read the
    /// length safely while the poll thread may be mutating `watches`.
    pub fn watchCount(self: *Watcher) usize {
        self.watches_mutex.lock();
        defer self.watches_mutex.unlock();
        return self.watches.items.len;
    }

    /// Manually trigger a check (for testing or immediate updates)
    pub fn checkNow(self: *Watcher) void {
        self.checkForChanges();
    }

    fn watchLoop(self: *Watcher) void {
        while (self.running.load(.acquire)) {
            self.checkForChanges();
            nanosleep(pollIntervalNs(self.options.poll_interval_ms));
        }
    }

    fn checkForChanges(self: *Watcher) void {
        // Hold the lock for the whole iteration so a concurrent append (which
        // may reallocate the backing array) or orderedRemove cannot invalidate
        // the slice we are walking (CWE-362). User callbacks therefore run
        // under the lock; see the `Watcher` concurrency contract.
        self.watches_mutex.lock();
        defer self.watches_mutex.unlock();

        for (self.watches.items) |*watch| {
            const current_stat = getFileStat(watch.path);
            const currently_exists = current_stat != null;

            if (watch.exists and !currently_exists) {
                // File was deleted
                watch.exists = false;
                watch.callback(watch.path, .deleted, watch.user_data);
            } else if (!watch.exists and currently_exists) {
                // File was created
                watch.exists = true;
                if (current_stat) |stat| {
                    watch.last_mtime = stat.mtime;
                    watch.last_size = stat.size;
                }
                watch.callback(watch.path, .created, watch.user_data);
            } else if (currently_exists) {
                // Check for modification
                if (current_stat) |stat| {
                    if (stat.mtime.nanoseconds != watch.last_mtime.nanoseconds or stat.size != watch.last_size) {
                        watch.last_mtime = stat.mtime;
                        watch.last_size = stat.size;
                        watch.callback(watch.path, .modified, watch.user_data);
                    }
                }
            }
        }
    }
};

/// File stat information
const FileStat = struct {
    mtime: std.Io.Timestamp,
    size: u64,
};

fn getFileStat(path: []const u8) ?FileStat {
    // Zig 0.16.0: fstatat was removed from posix; use Dir.statFile with
    // follow_symlinks=false which maps to a single fstatat syscall on POSIX.
    const io = std.Io.Threaded.global_single_threaded.io();
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return null;
    return .{
        .mtime = stat.mtime,
        .size = stat.size,
    };
}

/// Simple config reloader that wraps a Loader
pub fn ConfigReloader(comptime T: type) type {
    const loader_mod = @import("loader.zig");

    return struct {
        loader: *loader_mod.Loader(T),
        watcher: Watcher,
        on_reload: ?*const fn (*loader_mod.Loader(T)) void,

        const Self = @This();

        pub fn init(allocator: Allocator, loader: *loader_mod.Loader(T), options: WatchOptions) Self {
            return .{
                .loader = loader,
                .watcher = Watcher.init(allocator, options),
                .on_reload = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.watcher.deinit();
        }

        /// Set callback for after reload
        pub fn onReload(self: *Self, callback: *const fn (*loader_mod.Loader(T)) void) void {
            self.on_reload = callback;
        }

        /// Watch a config file and auto-reload on changes
        pub fn watchConfig(self: *Self, path: []const u8) !void {
            try self.watcher.addPathWithData(path, reloadCallback, self);
        }

        /// Start watching
        pub fn start(self: *Self) !void {
            try self.watcher.start();
        }

        /// Stop watching
        pub fn stop(self: *Self) void {
            self.watcher.stop();
        }

        fn reloadCallback(path: []const u8, event: ChangeEvent, user_data: ?*anyopaque) void {
            _ = path;
            if (event == .deleted) return;

            if (user_data) |ptr| {
                const self: *Self = @ptrCast(@alignCast(ptr));
                self.loader.reset();

                if (self.on_reload) |callback| {
                    callback(self.loader);
                }
            }
        }
    };
}

/// Watch a single file and call callback on changes (convenience function)
pub fn watchFile(
    allocator: Allocator,
    path: []const u8,
    callback: ChangeCallback,
    options: WatchOptions,
) !Watcher {
    var watcher = Watcher.init(allocator, options);
    errdefer watcher.deinit();

    try watcher.addPath(path, callback);
    try watcher.start();

    return watcher;
}

// ============================================================================
// Tests
// ============================================================================

test "Watcher initialization" {
    var watcher = Watcher.init(std.testing.allocator, .{});
    defer watcher.deinit();

    try std.testing.expect(!watcher.isRunning());
    try std.testing.expectEqual(@as(usize, 0), watcher.watchCount());
}

test "Watcher add and remove path" {
    var watcher = Watcher.init(std.testing.allocator, .{});
    defer watcher.deinit();

    const dummy_callback = struct {
        fn cb(_: []const u8, _: ChangeEvent, _: ?*anyopaque) void {}
    }.cb;

    // Add a path (doesn't need to exist for adding)
    try watcher.addPath("/tmp/test_config.toml", dummy_callback);
    try std.testing.expectEqual(@as(usize, 1), watcher.watchCount());

    // Remove the path
    try std.testing.expect(watcher.removePath("/tmp/test_config.toml"));
    try std.testing.expectEqual(@as(usize, 0), watcher.watchCount());

    // Remove non-existent path
    try std.testing.expect(!watcher.removePath("/tmp/nonexistent"));
}

test "Watcher max watches limit" {
    var watcher = Watcher.init(std.testing.allocator, .{ .max_watches = 2 });
    defer watcher.deinit();

    const dummy_callback = struct {
        fn cb(_: []const u8, _: ChangeEvent, _: ?*anyopaque) void {}
    }.cb;

    try watcher.addPath("/tmp/file1", dummy_callback);
    try watcher.addPath("/tmp/file2", dummy_callback);

    // Third should fail
    try std.testing.expectError(WatchError.TooManyWatches, watcher.addPath("/tmp/file3", dummy_callback));
}

test "Watcher double start error" {
    var watcher = Watcher.init(std.testing.allocator, .{ .poll_interval_ms = 100 });
    defer watcher.deinit();

    try watcher.start();
    defer watcher.stop();

    try std.testing.expectError(WatchError.WatcherAlreadyRunning, watcher.start());
}

test "Watcher stop when not running" {
    var watcher = Watcher.init(std.testing.allocator, .{});
    defer watcher.deinit();

    // Should not panic or error
    watcher.stop();
}

test "getFileStat returns null for nonexistent" {
    const stat = getFileStat("/nonexistent/path/to/file");
    try std.testing.expect(stat == null);
}

test "pollIntervalNs does not overflow for large intervals (Q-NEW-03)" {
    // Regression: poll_interval_ms is u32; multiplying by ns_per_ms (1_000_000)
    // in u32 overflows for any interval >= 4295 ms (4295 * 1e6 > u32 max),
    // which is a checked-overflow panic in Debug/ReleaseSafe and a silent
    // busy-loop wrap in ReleaseFast. The widened computation must be exact.
    try std.testing.expectEqual(@as(u64, 10_000_000_000), pollIntervalNs(10_000));
    try std.testing.expectEqual(@as(u64, 4_295_000_000), pollIntervalNs(4295));
    // Boundary just under the old overflow point still matches a u64 reference.
    try std.testing.expectEqual(@as(u64, 4_294_000_000), pollIntervalNs(4294));
    // Maximum u32 interval must not overflow.
    try std.testing.expectEqual(
        @as(u64, std.math.maxInt(u32)) * std.time.ns_per_ms,
        pollIntervalNs(std.math.maxInt(u32)),
    );
}

test "Watcher with large poll interval starts/stops without panic (Q-NEW-03)" {
    // Constructing and starting a watcher with a large interval must not
    // trigger an integer-overflow panic in watchLoop's sleep computation.
    var watcher = Watcher.init(std.testing.allocator, .{ .poll_interval_ms = 10_000 });
    defer watcher.deinit();

    try watcher.start();
    // The first checkForChanges happens before the sleep; stop() joins the
    // thread. If the multiply overflowed, the thread would panic before/at
    // the sleep and the join would observe a crashed process under the test
    // runner. Reaching here cleanly is the assertion.
    watcher.stop();
    try std.testing.expect(!watcher.isRunning());
}

test "Watcher concurrent add/remove while running is data-race safe (S-NEW-02/Q-NEW-11)" {
    // Stress test: the poll thread iterates `self.watches` (doing a statFile
    // syscall per element, which widens the race window) while the main thread
    // repeatedly grows the list past its capacity (forcing the backing array to
    // be reallocated and freed) and shrinks it again. Without the mutex this
    // reallocation invalidates the slice the poll thread is walking -> the poll
    // thread dereferences freed memory (use-after-free / OOB). With the mutex
    // the run completes cleanly, the count returns to baseline, and the testing
    // allocator reports no leaks on deinit.
    //
    // `poll_interval_ms = 0` keeps the poll thread iterating back-to-back with
    // no sleep, maximizing overlap with the mutating main thread.
    var watcher = Watcher.init(std.testing.allocator, .{
        .poll_interval_ms = 0,
        .max_watches = 100_000,
    });
    defer watcher.deinit();

    const noop = struct {
        fn cb(_: []const u8, _: ChangeEvent, _: ?*anyopaque) void {}
    }.cb;

    // Seed a non-trivial number of watches so each checkForChanges pass spends
    // real time iterating (and the array has a real backing allocation to free
    // when it grows).
    const seed = 64;
    var s: usize = 0;
    while (s < seed) : (s += 1) {
        try watcher.addPath("/nonexistent/race_seed", noop);
    }

    try watcher.start();

    var iter: usize = 0;
    while (iter < 200) : (iter += 1) {
        // Grow well past current capacity to force repeated realloc+free of the
        // backing array while the poll thread is mid-iteration.
        var g: usize = 0;
        while (g < 256) : (g += 1) {
            try watcher.addPath("/nonexistent/race_grow", noop);
        }
        // Shrink back down via orderedRemove, which shifts elements while the
        // poll thread may be reading them.
        while (watcher.watchCount() > seed) {
            if (!watcher.removePath("/nonexistent/race_grow")) break;
        }
        // Interleave a caller-thread check with the background poll thread;
        // both acquire the mutex.
        watcher.checkNow();
    }

    watcher.stop();
    try std.testing.expectEqual(@as(usize, seed), watcher.watchCount());
}
