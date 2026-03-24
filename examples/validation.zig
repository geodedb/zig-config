//! Configuration Validation Example
//!
//! This example demonstrates how to validate configuration
//! values using the built-in validators.

const std = @import("std");
const config = @import("config");
const validate = config.validation;

const ServerConfig = struct {
    host: []const u8,
    port: u16,
    admin_email: []const u8,
    api_url: []const u8,
    log_level: []const u8,
    max_retries: i32,
    password: []const u8,
};

pub fn main() !void {
    // Example configuration to validate
    const cfg = ServerConfig{
        .host = "api.example.com",
        .port = 8080,
        .admin_email = "admin@example.com",
        .api_url = "https://api.example.com/v1",
        .log_level = "info",
        .max_retries = 3,
        .password = "securepassword123",
    };

    // Validate all configuration values
    validateConfig(cfg) catch |err| {
        std.debug.print("Configuration validation failed: {}\n", .{err});
        return;
    };

    std.debug.print("Configuration is valid!\n", .{});
}

fn validateConfig(cfg: ServerConfig) !void {
    // Required field check
    try validate.required(cfg.host);
    try validate.required(cfg.admin_email);

    // Hostname validation
    try validate.hostname(cfg.host);

    // Port validation (1-65535)
    try validate.port(cfg.port);

    // Email validation
    try validate.email(cfg.admin_email);

    // URL validation
    try validate.url(cfg.api_url);

    // Enum-like validation (one of allowed values)
    try validate.oneOf(cfg.log_level, &.{ "debug", "info", "warn", "error" });

    // Range validation
    try validate.intRange(cfg.max_retries, 1, 10);

    // Length validation
    try validate.minLength(cfg.password, 8);
    try validate.maxLength(cfg.password, 128);

    std.debug.print("All validations passed\n", .{});
}
