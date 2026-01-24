//! Secure Secret Handling Example
//!
//! This example demonstrates how to securely handle secrets
//! using zigconfig. Secrets are NEVER read from environment
//! variables or command-line flags to prevent leakage.

const std = @import("std");
const config = @import("config");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Method 1: Read secret from a file
    // This is the recommended approach for production
    // Files should be mounted from a secrets manager (Vault, K8s secrets, etc.)
    const db_password = config.readFromFile("/run/secrets/db_password", allocator) catch |err| {
        std.debug.print("Could not read DB password: {}\n", .{err});
        std.debug.print("Using placeholder for demo...\n", .{});
        return;
    };
    defer allocator.free(db_password);

    // Method 2: Read secret from stdin (for interactive or piped input)
    // Useful for: echo "secret" | ./myapp
    // const api_token = try config.readFromStdin(allocator);
    // defer allocator.free(api_token);

    // Safe logging - redact secrets
    std.debug.print("DB Password: {s}\n", .{config.secret.redact(db_password)});
    // Output: DB Password: ***REDACTED***

    // Use the secret for database connection
    connectToDatabase(db_password);

    // Securely zero the memory when done
    // This prevents the secret from lingering in memory
    config.secret.secureZero(@constCast(db_password));
}

fn connectToDatabase(password: []const u8) void {
    _ = password;
    std.debug.print("Connected to database successfully\n", .{});
}
