//! XDG Base Directory Example
//!
//! This example demonstrates how to use XDG-compliant
//! directory paths for configuration, data, and cache files.

const std = @import("std");
const config = @import("config");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const app_name = "myapp";

    // Get XDG base directory paths (without app name)
    var xdg_paths = try config.xdg.getPaths(allocator);
    defer xdg_paths.deinit();

    std.debug.print("XDG Base Directories:\n", .{});
    std.debug.print("  Config Home: {s}\n", .{xdg_paths.config_home});
    std.debug.print("  Data Home:   {s}\n", .{xdg_paths.data_home});
    std.debug.print("  Cache Home:  {s}\n", .{xdg_paths.cache_home});
    std.debug.print("  State Home:  {s}\n", .{xdg_paths.state_home});

    // Get application-specific directories
    const config_dir = try config.getConfigDir(allocator, app_name);
    defer allocator.free(config_dir);

    const data_dir = try config.getDataDir(allocator, app_name);
    defer allocator.free(data_dir);

    const cache_dir = try config.getCacheDir(allocator, app_name);
    defer allocator.free(cache_dir);

    std.debug.print("\nApplication paths for '{s}':\n", .{app_name});
    std.debug.print("  Config dir: {s}\n", .{config_dir});
    std.debug.print("  Data dir:   {s}\n", .{data_dir});
    std.debug.print("  Cache dir:  {s}\n", .{cache_dir});

    // These respect XDG environment variables:
    // - $XDG_CONFIG_HOME (default: ~/.config)
    // - $XDG_DATA_HOME   (default: ~/.local/share)
    // - $XDG_CACHE_HOME  (default: ~/.cache)
}
