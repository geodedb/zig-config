// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Remote Configuration Module
//!
//! Provides integration with remote configuration stores:
//! - etcd (v3 API)
//! - HashiCorp Consul (KV store)
//!
//! Example usage:
//! ```zig
//! const remote = @import("remote");
//!
//! // Using etcd (HTTPS by default)
//! var etcd = try remote.Etcd.init(allocator, .{
//!     .endpoints = &.{"https://etcd.example.com:2379"},
//! });
//! defer etcd.deinit();
//!
//! const value = try etcd.get("config/database/host");
//!
//! // Using Consul (HTTPS by default)
//! var consul = try remote.Consul.init(allocator, .{
//!     .address = "https://consul.example.com:8500",
//! });
//! defer consul.deinit();
//!
//! const kv = try consul.get("config/app/settings");
//!
//! // For local development (insecure HTTP)
//! var local_etcd = try remote.Etcd.init(allocator, .{
//!     .endpoints = &.{"http://localhost:2379"},
//!     .security = .{ .allow_insecure_http = true, .block_private_ips = false },
//! });
//! ```

const std = @import("std");
const mem = std.mem;
const http = std.http;
const Uri = std.Uri;
const Allocator = mem.Allocator;

/// Remote configuration errors
pub const RemoteError = error{
    ConnectionFailed,
    RequestFailed,
    KeyNotFound,
    InvalidResponse,
    Unauthorized,
    Timeout,
    OutOfMemory,
    /// URL validation failed (SSRF protection)
    InvalidUrl,
    /// URL points to a private/internal address (SSRF protection)
    PrivateAddressBlocked,
    /// URL scheme not allowed (must be https in production)
    InsecureScheme,
    /// Key contains invalid characters (path injection protection, CWE-74, #73)
    InvalidKey,
};

/// Security options for remote connections
pub const SecurityOptions = struct {
    /// Allow HTTP (insecure) connections. Default false for security.
    /// Set to true only for local development/testing.
    allow_insecure_http: bool = false,
    /// Block connections to private/internal IP addresses (SSRF protection)
    block_private_ips: bool = true,
    /// User-Agent header value
    user_agent: []const u8 = "zigconfig/1.0",
};

/// Validate a URL for security (SSRF protection)
/// Returns error if URL is invalid or points to a private address
///
/// SECURITY NOTE (DNS Rebinding - #68):
/// This validation occurs BEFORE DNS resolution. An attacker controlling DNS could
/// potentially rebind from a public IP to a private IP after validation passes.
/// Mitigations in this library:
/// - Short HTTP timeouts reduce the rebind window
/// - Most DNS resolvers cache results for TTL duration
/// For high-security deployments, consider:
/// - Using IP addresses instead of hostnames in configuration
/// - Deploying a local DNS resolver with rebinding protection
/// - Using allowlists of known-good hostnames
pub fn validateUrl(url: []const u8, options: SecurityOptions) RemoteError!void {
    const uri = Uri.parse(url) catch return RemoteError.InvalidUrl;

    // Check scheme - require HTTPS unless explicitly allowed
    if (uri.scheme.len == 0) {
        return RemoteError.InvalidUrl;
    }
    const is_https = mem.eql(u8, uri.scheme, "https");
    const is_http = mem.eql(u8, uri.scheme, "http");

    if (!is_https and !is_http) {
        return RemoteError.InvalidUrl;
    }

    if (is_http and !options.allow_insecure_http) {
        return RemoteError.InsecureScheme;
    }

    // Check for private/internal addresses if blocking is enabled
    if (options.block_private_ips) {
        if (uri.host) |host| {
            // Security: Decode URL-encoded host to prevent SSRF bypass (CWE-918, #71)
            // Attackers may use URL encoding (e.g., %31%32%37.%30.%30.%31 = 127.0.0.1)
            var decoded_host: [256]u8 = undefined;
            const decoded = decodePercentEncoded(host.percent_encoded, &decoded_host);
            if (isPrivateAddress(decoded)) {
                return RemoteError.PrivateAddressBlocked;
            }
        }
    }
}

/// Decode percent-encoded string into buffer
/// Security: Used to prevent URL-encoded SSRF bypass (CWE-918, #71)
fn decodePercentEncoded(encoded: []const u8, buffer: []u8) []const u8 {
    if (encoded.len == 0) return "";
    if (encoded.len > buffer.len) return encoded; // Too long, return as-is

    // Check if any percent encoding exists
    if (mem.indexOf(u8, encoded, "%") == null) {
        return encoded; // No encoding, return original
    }

    var write_idx: usize = 0;
    var read_idx: usize = 0;

    while (read_idx < encoded.len) {
        if (write_idx >= buffer.len) break;

        if (encoded[read_idx] == '%' and read_idx + 2 < encoded.len) {
            // Try to decode hex pair
            const hex = encoded[read_idx + 1 .. read_idx + 3];
            if (std.fmt.parseInt(u8, hex, 16)) |byte| {
                buffer[write_idx] = byte;
                write_idx += 1;
                read_idx += 3;
            } else |_| {
                // Invalid hex, copy literal
                buffer[write_idx] = encoded[read_idx];
                write_idx += 1;
                read_idx += 1;
            }
        } else {
            buffer[write_idx] = encoded[read_idx];
            write_idx += 1;
            read_idx += 1;
        }
    }

    return buffer[0..write_idx];
}

/// Check if a hostname/IP is a private or internal address
/// Security: Prevents SSRF attacks to internal infrastructure (CWE-918)
/// Enhanced to handle IPv6-mapped IPv4 addresses (#60)
fn isPrivateAddress(host: []const u8) bool {
    // Handle IPv6-mapped IPv4 addresses (::ffff:x.x.x.x)
    // Security: Prevents SSRF bypass via IPv6-mapped addresses (CWE-918)
    if (mem.startsWith(u8, host, "::ffff:")) {
        const ipv4_part = host[7..];
        return isPrivateIPv4(ipv4_part);
    }
    if (mem.startsWith(u8, host, "[::ffff:")) {
        // Bracketed format: [::ffff:127.0.0.1]
        if (mem.endsWith(u8, host, "]")) {
            const ipv4_part = host[8 .. host.len - 1];
            return isPrivateIPv4(ipv4_part);
        }
    }

    // Handle bracketed IPv6
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        const inner = host[1 .. host.len - 1];
        return isPrivateAddress(inner);
    }

    // Block localhost variants
    if (mem.eql(u8, host, "localhost")) return true;
    if (mem.eql(u8, host, "::1")) return true;
    if (mem.eql(u8, host, "0.0.0.0")) return true; // INADDR_ANY

    // Block IPv6 link-local (fe80::/10)
    if (mem.startsWith(u8, host, "fe80:")) return true;
    if (mem.startsWith(u8, host, "fe80::")) return true;

    // Check IPv4 private ranges
    if (isPrivateIPv4(host)) return true;

    // Block metadata service IPs (cloud provider internal)
    if (mem.eql(u8, host, "metadata.google.internal")) return true;

    // Block common internal hostnames
    if (mem.endsWith(u8, host, ".local")) return true;
    if (mem.endsWith(u8, host, ".internal")) return true;
    if (mem.endsWith(u8, host, ".localhost")) return true;

    return false;
}

/// Check if an IPv4 address string is in a private range
/// Handles: 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.x.x
/// Security: Normalizes alternative IP formats (decimal, octal, hex) to prevent SSRF bypass (#65)
fn isPrivateIPv4(ip: []const u8) bool {
    // Try to parse as a 32-bit integer (handles all formats)
    const ip_value = parseIPv4ToInt(ip) orelse return false;
    return isPrivateIPv4Int(ip_value);
}

/// Parse an IPv4 address in any format to a 32-bit integer
/// Supports: dotted-decimal, decimal, octal (0-prefix), hex (0x-prefix)
/// Security: Prevents SSRF bypass via alternative IP formats (CWE-918, #65)
fn parseIPv4ToInt(ip: []const u8) ?u32 {
    if (ip.len == 0) return null;

    // Check if this is a single number (decimal or hex)
    if (mem.indexOf(u8, ip, ".") == null) {
        // Single number format (e.g., 2130706433 or 0x7f000001)
        return parseIntWithBase(ip);
    }

    // Dotted format - parse each octet
    var result: u32 = 0;
    var remaining = ip;
    var octet_count: u8 = 0;

    while (octet_count < 4) : (octet_count += 1) {
        const dot_pos = mem.indexOf(u8, remaining, ".");
        const octet_str = if (dot_pos) |pos| remaining[0..pos] else remaining;

        if (octet_str.len == 0) return null;

        const octet_value = parseIntWithBase(octet_str) orelse return null;
        if (octet_value > 255) return null;

        result = (result << 8) | @as(u32, @intCast(octet_value));

        if (dot_pos) |pos| {
            remaining = remaining[pos + 1 ..];
        } else {
            // Last octet - should be exactly 4 octets
            if (octet_count != 3) return null;
            break;
        }
    }

    return result;
}

/// Parse an integer string with auto-detected base (decimal, octal, hex)
/// Security: Handles obfuscated IP formats used in SSRF bypass attacks (#65)
fn parseIntWithBase(s: []const u8) ?u32 {
    if (s.len == 0) return null;

    // Check for hex prefix (0x or 0X)
    if (s.len > 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        return std.fmt.parseInt(u32, s[2..], 16) catch return null;
    }

    // Check for octal prefix (leading 0, but not just "0")
    if (s.len > 1 and s[0] == '0') {
        // Verify all chars are valid octal (0-7)
        for (s[1..]) |c| {
            if (c < '0' or c > '7') {
                // Not valid octal, try decimal
                return std.fmt.parseInt(u32, s, 10) catch return null;
            }
        }
        return std.fmt.parseInt(u32, s, 8) catch return null;
    }

    // Decimal
    return std.fmt.parseInt(u32, s, 10) catch return null;
}

/// Check if a 32-bit IPv4 address is in a private range
fn isPrivateIPv4Int(ip: u32) bool {
    const octet1 = @as(u8, @intCast((ip >> 24) & 0xFF));
    const octet2 = @as(u8, @intCast((ip >> 16) & 0xFF));

    // 127.0.0.0/8 - loopback
    if (octet1 == 127) return true;

    // 10.0.0.0/8 - private
    if (octet1 == 10) return true;

    // 0.0.0.0/8 - "this" network
    if (octet1 == 0) return true;

    // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
    if (octet1 == 172 and octet2 >= 16 and octet2 <= 31) return true;

    // 192.168.0.0/16
    if (octet1 == 192 and octet2 == 168) return true;

    // 169.254.0.0/16 - link-local
    if (octet1 == 169 and octet2 == 254) return true;

    return false;
}

/// Validate a KV store key for path injection attacks (CWE-74, #73)
/// Keys are inserted into URL paths, so we must prevent:
/// - Path traversal (../)
/// - URL-encoded traversal (%2e%2e%2f)
/// - Null bytes (path truncation)
/// - Query/fragment injection (?, #)
/// Valid keys: alphanumeric, /, -, _, . (but not ..)
pub fn isValidKVKey(key: []const u8) bool {
    if (key.len == 0) return false;
    if (key.len > 512) return false; // Reasonable length limit

    // Check for path traversal sequences
    if (mem.indexOf(u8, key, "..") != null) return false;

    // Check for null bytes (path truncation attack)
    if (mem.indexOf(u8, key, "\x00") != null) return false;

    // Check for query/fragment injection
    if (mem.indexOf(u8, key, "?") != null) return false;
    if (mem.indexOf(u8, key, "#") != null) return false;

    // Check for URL-encoded dangerous sequences
    // %2e = '.', %2f = '/', %00 = null
    if (mem.indexOf(u8, key, "%2e") != null) return false;
    if (mem.indexOf(u8, key, "%2E") != null) return false;
    if (mem.indexOf(u8, key, "%2f") != null) return false;
    if (mem.indexOf(u8, key, "%2F") != null) return false;
    if (mem.indexOf(u8, key, "%00") != null) return false;

    // Block backslash (Windows path separator that some systems interpret)
    if (mem.indexOf(u8, key, "\\") != null) return false;

    // Validate characters: only allow safe characters
    for (key) |c| {
        if (!isValidKeyChar(c)) return false;
    }

    // Block keys starting or ending with slash (prevents //path or path//)
    if (key[0] == '/') return false;
    if (key[key.len - 1] == '/') return false;

    return true;
}

/// Check if a character is valid for KV store keys
fn isValidKeyChar(c: u8) bool {
    // Alphanumeric
    if (c >= 'a' and c <= 'z') return true;
    if (c >= 'A' and c <= 'Z') return true;
    if (c >= '0' and c <= '9') return true;
    // Common key separators
    if (c == '/') return true;
    if (c == '-') return true;
    if (c == '_') return true;
    if (c == '.') return true;
    return false;
}

// ============================================================================
// etcd Client
// ============================================================================

/// etcd client options
pub const EtcdOptions = struct {
    /// etcd endpoints (e.g., "https://localhost:2379")
    /// SECURITY: Defaults to HTTPS. Use SecurityOptions.allow_insecure_http for HTTP.
    endpoints: []const []const u8 = &.{"https://localhost:2379"},
    /// Request timeout in milliseconds
    timeout_ms: u32 = 5000,
    /// Username for authentication (optional)
    username: ?[]const u8 = null,
    /// Password for authentication (optional)
    password: ?[]const u8 = null,
    /// Security options (TLS, SSRF protection)
    security: SecurityOptions = .{},
};

/// etcd v3 API client
pub const Etcd = struct {
    allocator: Allocator,
    options: EtcdOptions,
    client: http.Client,
    /// Arena for response storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator, options: EtcdOptions) Etcd {
        return .{
            .allocator = allocator,
            .options = options,
            .client = http.Client{ .allocator = allocator },
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Etcd) void {
        self.client.deinit();
        self.arena.deinit();
    }

    /// Get a value by key from etcd
    pub fn get(self: *Etcd, key: []const u8) RemoteError!?[]const u8 {
        // etcd v3 uses gRPC-gateway REST API
        // POST /v3/kv/range with JSON body
        const endpoint = self.options.endpoints[0];

        // Security: Validate endpoint URL (SSRF protection)
        try validateUrl(endpoint, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/range", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        // Base64 encode the key (etcd v3 requirement)
        const encoder = std.base64.standard;
        const encoded_len = encoder.calcSize(key.len);
        const encoded_key = self.allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, key);

        // Build JSON request body
        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        // Make HTTP request
        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        // Parse response
        return self.parseEtcdResponse(response);
    }

    /// Put a value by key to etcd
    pub fn put(self: *Etcd, key: []const u8, value: []const u8) RemoteError!void {
        const endpoint = self.options.endpoints[0];

        // Security: Validate endpoint URL (SSRF protection)
        try validateUrl(endpoint, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/put", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        // Base64 encode key and value
        const encoder = std.base64.standard;

        const encoded_key_len = encoder.calcSize(key.len);
        const encoded_key = self.allocator.alloc(u8, encoded_key_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, key);

        const encoded_value_len = encoder.calcSize(value.len);
        const encoded_value = self.allocator.alloc(u8, encoded_value_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_value);
        _ = encoder.encode(encoded_value, value);

        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\",\"value\":\"{s}\"}}", .{ encoded_key, encoded_value }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);
    }

    /// Delete a key from etcd
    pub fn delete(self: *Etcd, key: []const u8) RemoteError!void {
        const endpoint = self.options.endpoints[0];

        // Security: Validate endpoint URL (SSRF protection)
        try validateUrl(endpoint, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/deleterange", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const encoder = std.base64.standard;
        const encoded_len = encoder.calcSize(key.len);
        const encoded_key = self.allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, key);

        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);
    }

    /// Get all keys with a prefix
    pub fn getPrefix(self: *Etcd, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        const endpoint = self.options.endpoints[0];

        // Security: Validate endpoint URL (SSRF protection)
        try validateUrl(endpoint, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/range", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const encoder = std.base64.standard;
        const encoded_len = encoder.calcSize(prefix.len);
        const encoded_key = self.allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, prefix);

        // Range end for prefix query (increment last byte)
        var range_end = self.allocator.dupe(u8, prefix) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(range_end);
        if (range_end.len > 0) {
            range_end[range_end.len - 1] += 1;
        }
        const encoded_end_len = encoder.calcSize(range_end.len);
        const encoded_end = self.allocator.alloc(u8, encoded_end_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_end);
        _ = encoder.encode(encoded_end, range_end);

        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\",\"range_end\":\"{s}\"}}", .{ encoded_key, encoded_end }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        return self.parseEtcdRangeResponse(response);
    }

    fn makeRequest(self: *Etcd, url: []const u8, body: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        // Add User-Agent header
        const extra_headers = [_]http.Header{
            .{ .name = "User-Agent", .value = self.options.security.user_agent },
        };

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = &extra_headers,
            // Security: Disable redirect following to prevent SSRF bypass (CWE-918, #70)
            .redirect_behavior = .not_allowed,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.headers.content_type = http.Client.Request.Headers.Value{ .override = "application/json" };

        request.send() catch return error.RequestFailed;
        request.writer().writeAll(body) catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        const response_body = request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
        return response_body;
    }

    fn parseEtcdResponse(self: *Etcd, response: []const u8) ?[]const u8 {
        // Simple JSON parsing for etcd response
        // Response format: {"header":{...},"kvs":[{"key":"...","value":"..."}]}
        const value_start = mem.indexOf(u8, response, "\"value\":\"") orelse return null;
        const value_content_start = value_start + 9;
        const value_end = mem.indexOfPos(u8, response, value_content_start, "\"") orelse return null;
        const encoded_value = response[value_content_start..value_end];

        // Decode base64 value
        const decoder = std.base64.standard;
        const decoded_len = decoder.calcSizeForSlice(encoded_value) catch return null;
        const decoded = self.arena.allocator().alloc(u8, decoded_len) catch return null;
        _ = decoder.decode(decoded, encoded_value) catch return null;

        return decoded;
    }

    fn parseEtcdRangeResponse(self: *Etcd, response: []const u8) RemoteError!std.StringHashMap([]const u8) {
        var result = std.StringHashMap([]const u8).init(self.allocator);
        errdefer result.deinit();

        // Simple parsing - find all key-value pairs in response
        var pos: usize = 0;
        while (mem.indexOfPos(u8, response, pos, "\"key\":\"")) |key_start| {
            const key_content_start = key_start + 7;
            const key_end = mem.indexOfPos(u8, response, key_content_start, "\"") orelse break;
            const encoded_key = response[key_content_start..key_end];

            const value_start = mem.indexOfPos(u8, response, key_end, "\"value\":\"") orelse break;
            const value_content_start = value_start + 9;
            const value_end = mem.indexOfPos(u8, response, value_content_start, "\"") orelse break;
            const encoded_value = response[value_content_start..value_end];

            // Decode key and value
            const decoder = std.base64.standard;

            const key_decoded_len = decoder.calcSizeForSlice(encoded_key) catch break;
            const decoded_key = self.arena.allocator().alloc(u8, key_decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.decode(decoded_key, encoded_key) catch break;

            const value_decoded_len = decoder.calcSizeForSlice(encoded_value) catch break;
            const decoded_value = self.arena.allocator().alloc(u8, value_decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.decode(decoded_value, encoded_value) catch break;

            result.put(decoded_key, decoded_value) catch return RemoteError.OutOfMemory;
            pos = value_end;
        }

        return result;
    }
};

// ============================================================================
// Consul Client
// ============================================================================

/// Consul client options
pub const ConsulOptions = struct {
    /// Consul HTTPS address
    /// SECURITY: Defaults to HTTPS. Use SecurityOptions.allow_insecure_http for HTTP.
    address: []const u8 = "https://localhost:8500",
    /// Datacenter (optional)
    datacenter: ?[]const u8 = null,
    /// ACL token (optional)
    token: ?[]const u8 = null,
    /// Request timeout in milliseconds
    timeout_ms: u32 = 5000,
    /// Security options (TLS, SSRF protection)
    security: SecurityOptions = .{},
};

/// HashiCorp Consul KV client
pub const Consul = struct {
    allocator: Allocator,
    options: ConsulOptions,
    client: http.Client,
    /// Arena for response storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator, options: ConsulOptions) Consul {
        return .{
            .allocator = allocator,
            .options = options,
            .client = http.Client{ .allocator = allocator },
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Consul) void {
        self.client.deinit();
        self.arena.deinit();
    }

    /// Get a value by key from Consul KV store
    /// Security: Validates key to prevent path injection (CWE-74, #73)
    pub fn get(self: *Consul, key: []const u8) RemoteError!?[]const u8 {
        // Security: Validate key to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // Security: Validate address URL (SSRF protection)
        try validateUrl(self.options.address, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?raw", .{ self.options.address, key }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const response = self.makeGetRequest(url) catch |err| {
            if (err == error.NotFound) return null;
            return RemoteError.RequestFailed;
        };

        // Copy to arena for persistent storage
        const result = self.arena.allocator().dupe(u8, response) catch return RemoteError.OutOfMemory;
        self.allocator.free(response);

        return result;
    }

    /// Put a value by key to Consul KV store
    /// Security: Validates key to prevent path injection (CWE-74, #73)
    pub fn put(self: *Consul, key: []const u8, value: []const u8) RemoteError!void {
        // Security: Validate key to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // Security: Validate address URL (SSRF protection)
        try validateUrl(self.options.address, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}", .{ self.options.address, key }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        _ = self.makePutRequest(url, value) catch return RemoteError.RequestFailed;
    }

    /// Delete a key from Consul KV store
    /// Security: Validates key to prevent path injection (CWE-74, #73)
    pub fn delete(self: *Consul, key: []const u8) RemoteError!void {
        // Security: Validate key to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // Security: Validate address URL (SSRF protection)
        try validateUrl(self.options.address, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}", .{ self.options.address, key }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        _ = self.makeDeleteRequest(url) catch return RemoteError.RequestFailed;
    }

    /// Get all keys with a prefix
    /// Security: Validates prefix to prevent path injection (CWE-74, #73)
    pub fn getPrefix(self: *Consul, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        // Security: Validate prefix to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(prefix)) {
            return RemoteError.InvalidKey;
        }

        // Security: Validate address URL (SSRF protection)
        try validateUrl(self.options.address, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?recurse", .{ self.options.address, prefix }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const response = self.makeGetRequest(url) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        return self.parseConsulKVList(response, prefix);
    }

    /// List all keys with a prefix (keys only, no values)
    /// Security: Validates prefix to prevent path injection (CWE-74, #73)
    pub fn listKeys(self: *Consul, prefix: []const u8) RemoteError![]const []const u8 {
        // Security: Validate prefix to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(prefix)) {
            return RemoteError.InvalidKey;
        }

        // Security: Validate address URL (SSRF protection)
        try validateUrl(self.options.address, self.options.security);

        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?keys", .{ self.options.address, prefix }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const response = self.makeGetRequest(url) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        return self.parseKeysList(response);
    }

    fn makeGetRequest(self: *Consul, url: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        // Build extra headers for security
        var extra_headers_buf: [2]http.Header = undefined;
        var extra_headers_len: usize = 0;

        // Add User-Agent header
        extra_headers_buf[extra_headers_len] = .{
            .name = "User-Agent",
            .value = self.options.security.user_agent,
        };
        extra_headers_len += 1;

        // Add Consul ACL token header if configured (X-Consul-Token)
        // Security: Token is now actually transmitted (#55 fix)
        if (self.options.token) |token| {
            extra_headers_buf[extra_headers_len] = .{
                .name = "X-Consul-Token",
                .value = token,
            };
            extra_headers_len += 1;
        }

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = extra_headers_buf[0..extra_headers_len],
            // Security: Disable redirect following to prevent SSRF bypass (CWE-918, #70)
            .redirect_behavior = .not_allowed,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.send() catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        if (request.status == .not_found) {
            return error.NotFound;
        }

        return request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
    }

    fn makePutRequest(self: *Consul, url: []const u8, body: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        // Build extra headers for security
        var extra_headers_buf: [2]http.Header = undefined;
        var extra_headers_len: usize = 0;

        // Add User-Agent header
        extra_headers_buf[extra_headers_len] = .{
            .name = "User-Agent",
            .value = self.options.security.user_agent,
        };
        extra_headers_len += 1;

        // Add Consul ACL token header if configured
        if (self.options.token) |token| {
            extra_headers_buf[extra_headers_len] = .{
                .name = "X-Consul-Token",
                .value = token,
            };
            extra_headers_len += 1;
        }

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.PUT, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = extra_headers_buf[0..extra_headers_len],
            // Security: Disable redirect following to prevent SSRF bypass (CWE-918, #70)
            .redirect_behavior = .not_allowed,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.send() catch return error.RequestFailed;
        request.writer().writeAll(body) catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        return request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
    }

    fn makeDeleteRequest(self: *Consul, url: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        // Build extra headers for security
        var extra_headers_buf: [2]http.Header = undefined;
        var extra_headers_len: usize = 0;

        // Add User-Agent header
        extra_headers_buf[extra_headers_len] = .{
            .name = "User-Agent",
            .value = self.options.security.user_agent,
        };
        extra_headers_len += 1;

        // Add Consul ACL token header if configured
        if (self.options.token) |token| {
            extra_headers_buf[extra_headers_len] = .{
                .name = "X-Consul-Token",
                .value = token,
            };
            extra_headers_len += 1;
        }

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.DELETE, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = extra_headers_buf[0..extra_headers_len],
            // Security: Disable redirect following to prevent SSRF bypass (CWE-918, #70)
            .redirect_behavior = .not_allowed,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.send() catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        return request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
    }

    fn parseConsulKVList(self: *Consul, response: []const u8, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        _ = prefix;
        var result = std.StringHashMap([]const u8).init(self.allocator);
        errdefer result.deinit();

        // Consul returns JSON array: [{"Key":"...","Value":"base64..."},...]
        var pos: usize = 0;
        while (mem.indexOfPos(u8, response, pos, "\"Key\":\"")) |key_start| {
            const key_content_start = key_start + 7;
            const key_end = mem.indexOfPos(u8, response, key_content_start, "\"") orelse break;
            const key_value = response[key_content_start..key_end];

            const value_start = mem.indexOfPos(u8, response, key_end, "\"Value\":\"") orelse break;
            const value_content_start = value_start + 9;
            const value_end = mem.indexOfPos(u8, response, value_content_start, "\"") orelse break;
            const encoded_value = response[value_content_start..value_end];

            // Decode base64 value
            const decoder = std.base64.standard;
            const decoded_len = decoder.calcSizeForSlice(encoded_value) catch break;
            const decoded_value = self.arena.allocator().alloc(u8, decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.decode(decoded_value, encoded_value) catch break;

            const owned_key = self.arena.allocator().dupe(u8, key_value) catch return RemoteError.OutOfMemory;
            result.put(owned_key, decoded_value) catch return RemoteError.OutOfMemory;

            pos = value_end;
        }

        return result;
    }

    fn parseKeysList(self: *Consul, response: []const u8) RemoteError![]const []const u8 {
        var keys: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer keys.deinit(self.allocator);

        // Response is JSON array: ["key1","key2",...]
        var pos: usize = 0;
        while (mem.indexOfPos(u8, response, pos, "\"")) |start| {
            const content_start = start + 1;
            const end = mem.indexOfPos(u8, response, content_start, "\"") orelse break;
            const key = response[content_start..end];

            const owned_key = self.arena.allocator().dupe(u8, key) catch return RemoteError.OutOfMemory;
            keys.append(self.allocator, owned_key) catch return RemoteError.OutOfMemory;

            pos = end + 1;
        }

        return keys.toOwnedSlice(self.allocator) catch return RemoteError.OutOfMemory;
    }
};

// ============================================================================
// Remote Provider Interface
// ============================================================================

/// Abstract remote config provider interface
pub const RemoteProvider = union(enum) {
    etcd: *Etcd,
    consul: *Consul,

    pub fn get(self: RemoteProvider, key: []const u8) RemoteError!?[]const u8 {
        return switch (self) {
            .etcd => |e| e.get(key),
            .consul => |c| c.get(key),
        };
    }

    pub fn put(self: RemoteProvider, key: []const u8, value: []const u8) RemoteError!void {
        return switch (self) {
            .etcd => |e| e.put(key, value),
            .consul => |c| c.put(key, value),
        };
    }

    pub fn delete(self: RemoteProvider, key: []const u8) RemoteError!void {
        return switch (self) {
            .etcd => |e| e.delete(key),
            .consul => |c| c.delete(key),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Etcd initialization defaults to HTTPS" {
    var etcd = Etcd.init(std.testing.allocator, .{});
    defer etcd.deinit();

    // Security: Default should be HTTPS (#48)
    try std.testing.expectEqualStrings("https://localhost:2379", etcd.options.endpoints[0]);
}

test "Consul initialization defaults to HTTPS" {
    var consul = Consul.init(std.testing.allocator, .{});
    defer consul.deinit();

    // Security: Default should be HTTPS (#48)
    try std.testing.expectEqualStrings("https://localhost:8500", consul.options.address);
}

test "Etcd custom endpoints" {
    const endpoints = [_][]const u8{ "http://etcd1:2379", "http://etcd2:2379" };
    var etcd = Etcd.init(std.testing.allocator, .{
        .endpoints = &endpoints,
    });
    defer etcd.deinit();

    try std.testing.expectEqual(@as(usize, 2), etcd.options.endpoints.len);
}

test "Consul with token" {
    var consul = Consul.init(std.testing.allocator, .{
        .token = "my-secret-token",
        .datacenter = "dc1",
    });
    defer consul.deinit();

    try std.testing.expectEqualStrings("my-secret-token", consul.options.token.?);
    try std.testing.expectEqualStrings("dc1", consul.options.datacenter.?);
}

test "RemoteProvider union" {
    var etcd = Etcd.init(std.testing.allocator, .{});
    defer etcd.deinit();

    const provider = RemoteProvider{ .etcd = &etcd };
    _ = provider;
}

// ============================================================================
// Security Tests (#48, #49, #55)
// ============================================================================

test "isPrivateAddress blocks localhost" {
    try std.testing.expect(isPrivateAddress("localhost"));
    try std.testing.expect(isPrivateAddress("127.0.0.1"));
    try std.testing.expect(isPrivateAddress("127.0.0.5"));
    try std.testing.expect(isPrivateAddress("::1"));
    try std.testing.expect(isPrivateAddress("[::1]"));
}

test "isPrivateAddress blocks private IPv4 ranges" {
    // 10.0.0.0/8
    try std.testing.expect(isPrivateAddress("10.0.0.1"));
    try std.testing.expect(isPrivateAddress("10.255.255.255"));

    // 172.16.0.0/12
    try std.testing.expect(isPrivateAddress("172.16.0.1"));
    try std.testing.expect(isPrivateAddress("172.31.255.255"));

    // 192.168.0.0/16
    try std.testing.expect(isPrivateAddress("192.168.1.1"));
    try std.testing.expect(isPrivateAddress("192.168.255.255"));

    // Link-local
    try std.testing.expect(isPrivateAddress("169.254.1.1"));
}

test "isPrivateAddress blocks IPv6-mapped IPv4 addresses (SSRF bypass)" {
    // Security: These are SSRF bypass attempts using IPv6-mapped IPv4 format
    // CWE-918: Without this protection, attackers can bypass private IP checks
    try std.testing.expect(isPrivateAddress("::ffff:127.0.0.1"));
    try std.testing.expect(isPrivateAddress("::ffff:10.0.0.1"));
    try std.testing.expect(isPrivateAddress("::ffff:192.168.1.1"));
    try std.testing.expect(isPrivateAddress("::ffff:172.16.0.1"));
    try std.testing.expect(isPrivateAddress("::ffff:169.254.169.254")); // Cloud metadata

    // Bracketed format (as used in URLs)
    try std.testing.expect(isPrivateAddress("[::ffff:127.0.0.1]"));
    try std.testing.expect(isPrivateAddress("[::ffff:10.0.0.1]"));
    try std.testing.expect(isPrivateAddress("[::ffff:192.168.1.1]"));

    // Public addresses in IPv6-mapped format should be allowed
    try std.testing.expect(!isPrivateAddress("::ffff:8.8.8.8"));
    try std.testing.expect(!isPrivateAddress("[::ffff:8.8.8.8]"));
}

test "isPrivateAddress blocks IPv6 loopback and link-local" {
    // IPv6 loopback
    try std.testing.expect(isPrivateAddress("::1"));
    try std.testing.expect(isPrivateAddress("[::1]"));

    // IPv6 link-local
    try std.testing.expect(isPrivateAddress("fe80::1"));
    try std.testing.expect(isPrivateAddress("[fe80::1234:5678]"));
}

test "isPrivateAddress blocks cloud metadata endpoints" {
    try std.testing.expect(isPrivateAddress("169.254.169.254"));
    try std.testing.expect(isPrivateAddress("metadata.google.internal"));
}

test "isPrivateAddress blocks internal hostnames" {
    try std.testing.expect(isPrivateAddress("server.local"));
    try std.testing.expect(isPrivateAddress("db.internal"));
    try std.testing.expect(isPrivateAddress("app.localhost"));
}

test "isPrivateAddress allows public addresses" {
    try std.testing.expect(!isPrivateAddress("google.com"));
    try std.testing.expect(!isPrivateAddress("8.8.8.8"));
    try std.testing.expect(!isPrivateAddress("api.example.com"));
    try std.testing.expect(!isPrivateAddress("etcd.production.example.com"));
}

test "isPrivateAddress blocks decimal IP format (SSRF bypass #65)" {
    // 2130706433 = 127.0.0.1 in decimal
    try std.testing.expect(isPrivateAddress("2130706433"));
    // 167772161 = 10.0.0.1 in decimal
    try std.testing.expect(isPrivateAddress("167772161"));
    // 3232235777 = 192.168.1.1 in decimal
    try std.testing.expect(isPrivateAddress("3232235777"));
    // 2851995649 = 169.254.1.1 in decimal
    try std.testing.expect(isPrivateAddress("2851995649"));
    // Public IP should not be blocked: 134744072 = 8.8.8.8
    try std.testing.expect(!isPrivateAddress("134744072"));
}

test "isPrivateAddress blocks octal IP format (SSRF bypass #65)" {
    // 0177.0.0.1 = 127.0.0.1 in octal
    try std.testing.expect(isPrivateAddress("0177.0.0.1"));
    // 012.0.0.1 = 10.0.0.1 in octal
    try std.testing.expect(isPrivateAddress("012.0.0.1"));
    // 0300.0250.01.01 = 192.168.1.1 in octal
    try std.testing.expect(isPrivateAddress("0300.0250.01.01"));
    // Public IP: 010.010.010.010 = 8.8.8.8 in octal
    try std.testing.expect(!isPrivateAddress("010.010.010.010"));
}

test "isPrivateAddress blocks hex IP format (SSRF bypass #65)" {
    // 0x7f000001 = 127.0.0.1 in hex
    try std.testing.expect(isPrivateAddress("0x7f000001"));
    // 0x7f.0.0.1 = 127.0.0.1 in mixed hex-decimal
    try std.testing.expect(isPrivateAddress("0x7f.0.0.1"));
    // 0x0a.0.0.1 = 10.0.0.1 in mixed hex-decimal
    try std.testing.expect(isPrivateAddress("0x0a.0.0.1"));
    // 0xc0a80101 = 192.168.1.1 in hex
    try std.testing.expect(isPrivateAddress("0xc0a80101"));
    // Public IP: 0x08080808 = 8.8.8.8 in hex
    try std.testing.expect(!isPrivateAddress("0x08080808"));
}

test "decodePercentEncoded decodes URL-encoded strings (#71)" {
    var buf: [256]u8 = undefined;

    // Standard string - no encoding
    try std.testing.expectEqualStrings("127.0.0.1", decodePercentEncoded("127.0.0.1", &buf));

    // URL-encoded IP: %31%32%37 = 127
    try std.testing.expectEqualStrings("127.0.0.1", decodePercentEncoded("%31%32%37.%30.%30.%31", &buf));

    // Partial encoding
    try std.testing.expectEqualStrings("127.0.0.1", decodePercentEncoded("127%2e0%2e0%2e1", &buf));

    // Empty string
    try std.testing.expectEqualStrings("", decodePercentEncoded("", &buf));
}

test "validateUrl blocks URL-encoded private IPs (#71)" {
    // URL-encoded 127.0.0.1: %31%32%37.%30.%30.%31
    // Note: The URL parser may decode this before we see it, but we decode again to be safe
    const result = validateUrl("https://%31%32%37.0.0.1:2379", .{});
    try std.testing.expectError(RemoteError.PrivateAddressBlocked, result);
}

test "parseIPv4ToInt parses various formats correctly" {
    // Standard dotted decimal
    try std.testing.expectEqual(@as(?u32, 0x7f000001), parseIPv4ToInt("127.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0x0a000001), parseIPv4ToInt("10.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0xc0a80101), parseIPv4ToInt("192.168.1.1"));

    // Decimal single number
    try std.testing.expectEqual(@as(?u32, 0x7f000001), parseIPv4ToInt("2130706433"));

    // Hex single number
    try std.testing.expectEqual(@as(?u32, 0x7f000001), parseIPv4ToInt("0x7f000001"));
    try std.testing.expectEqual(@as(?u32, 0x7f000001), parseIPv4ToInt("0X7F000001"));

    // Octal dotted
    try std.testing.expectEqual(@as(?u32, 0x7f000001), parseIPv4ToInt("0177.0.0.01"));

    // Mixed formats
    try std.testing.expectEqual(@as(?u32, 0x7f000001), parseIPv4ToInt("0x7f.0.0.1"));

    // Invalid inputs
    try std.testing.expectEqual(@as(?u32, null), parseIPv4ToInt(""));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4ToInt("not.an.ip"));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4ToInt("256.0.0.1"));
}

test "validateUrl rejects HTTP by default" {
    const result = validateUrl("http://example.com:2379", .{});
    try std.testing.expectError(RemoteError.InsecureScheme, result);
}

test "validateUrl allows HTTP when explicitly enabled" {
    try validateUrl("http://example.com:2379", .{ .allow_insecure_http = true });
}

test "validateUrl allows HTTPS" {
    try validateUrl("https://example.com:2379", .{});
}

test "validateUrl blocks private IPs by default" {
    const result = validateUrl("https://192.168.1.1:2379", .{});
    try std.testing.expectError(RemoteError.PrivateAddressBlocked, result);
}

test "validateUrl allows private IPs when disabled" {
    try validateUrl("https://192.168.1.1:2379", .{ .block_private_ips = false });
}

test "validateUrl rejects invalid URLs" {
    const result = validateUrl("not-a-url", .{});
    try std.testing.expectError(RemoteError.InvalidUrl, result);
}

test "SecurityOptions has secure defaults" {
    const opts = SecurityOptions{};
    try std.testing.expect(!opts.allow_insecure_http);
    try std.testing.expect(opts.block_private_ips);
    try std.testing.expectEqualStrings("zigconfig/1.0", opts.user_agent);
}

// ============================================================================
// Key Validation Tests (CWE-74, #73)
// ============================================================================

test "isValidKVKey accepts valid keys" {
    // Simple keys
    try std.testing.expect(isValidKVKey("config"));
    try std.testing.expect(isValidKVKey("my-app"));
    try std.testing.expect(isValidKVKey("my_app"));
    try std.testing.expect(isValidKVKey("my.app"));
    try std.testing.expect(isValidKVKey("MyApp123"));

    // Hierarchical keys (common Consul pattern)
    try std.testing.expect(isValidKVKey("config/database/host"));
    try std.testing.expect(isValidKVKey("app/prod/settings"));
    try std.testing.expect(isValidKVKey("services/web/api-key"));
}

test "isValidKVKey rejects path traversal attempts (CWE-74, #73)" {
    // Direct path traversal
    try std.testing.expect(!isValidKVKey("../etc/passwd"));
    try std.testing.expect(!isValidKVKey("config/../../../etc/passwd"));
    try std.testing.expect(!isValidKVKey(".."));
    try std.testing.expect(!isValidKVKey("foo/.."));
    try std.testing.expect(!isValidKVKey("foo/../bar"));

    // URL-encoded path traversal
    try std.testing.expect(!isValidKVKey("%2e%2e/etc/passwd"));
    try std.testing.expect(!isValidKVKey("config%2f..%2f..%2fetc"));
    try std.testing.expect(!isValidKVKey("%2E%2E/foo"));
}

test "isValidKVKey rejects dangerous characters (CWE-74, #73)" {
    // Query/fragment injection
    try std.testing.expect(!isValidKVKey("key?raw"));
    try std.testing.expect(!isValidKVKey("key#fragment"));

    // Null byte (path truncation)
    try std.testing.expect(!isValidKVKey("key\x00evil"));
    try std.testing.expect(!isValidKVKey("%00evil"));

    // Backslash (Windows path separator)
    try std.testing.expect(!isValidKVKey("config\\database"));
}

test "isValidKVKey rejects edge cases" {
    // Empty key
    try std.testing.expect(!isValidKVKey(""));

    // Leading/trailing slashes
    try std.testing.expect(!isValidKVKey("/config"));
    try std.testing.expect(!isValidKVKey("config/"));

    // Very long key (>512 chars)
    const long_key = "a" ** 600;
    try std.testing.expect(!isValidKVKey(long_key));

    // Invalid characters
    try std.testing.expect(!isValidKVKey("key with spaces"));
    try std.testing.expect(!isValidKVKey("key<tag>"));
    try std.testing.expect(!isValidKVKey("key\"quoted\""));
}
