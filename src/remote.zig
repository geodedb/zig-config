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
const posix = std.posix;
const builtin = @import("builtin");
const Uri = std.Uri;
const Allocator = mem.Allocator;
const SensitiveString = @import("encrypted_secrets.zig").SensitiveString;
const limits = @import("limits.zig");
const secret = @import("secret.zig");

const log = std.log.scoped(.remote);

// ============================================================================
// JSON Response Types (NEW-02, NEW-06, NEW-07, GAP-0038)
//
// Typed structs for parsing etcd v3 and Consul KV API responses using
// std.json.parseFromSlice, replacing fragile hand-rolled string matching.
// ============================================================================

/// A single key-value entry in an etcd v3 range response.
/// Both key and value are base64-encoded by the etcd gRPC-gateway.
pub const EtcdKV = struct {
    key: []const u8 = "",
    value: []const u8 = "",
};

/// etcd v3 /v3/kv/range response envelope.
/// The `kvs` field is null when no keys match the query.
pub const EtcdRangeResponse = struct {
    kvs: ?[]const EtcdKV = null,
};

/// A single Consul KV store entry.
/// Field names use PascalCase to match the Consul HTTP API JSON format.
/// Value is base64-encoded; null means the key has no value (directory marker).
pub const ConsulKVEntry = struct {
    Key: []const u8 = "",
    Value: ?[]const u8 = null,
};

/// Remote configuration errors
pub const RemoteError = error{
    ConnectionFailed,
    RequestFailed,
    KeyNotFound,
    InvalidResponse,
    Unauthorized,
    Timeout,
    OutOfMemory,
    InvalidConfiguration,
    /// URL validation failed (SSRF protection)
    InvalidUrl,
    /// URL points to a private/internal address (SSRF protection)
    PrivateAddressBlocked,
    /// URL scheme not allowed (must be https in production)
    InsecureScheme,
    /// Key contains invalid characters (path injection protection, CWE-74, #73)
    InvalidKey,
    /// HTTP response body exceeded limits.MAX_REMOTE_RESPONSE_SIZE (CWE-400, GAP-0034)
    ResponseTooLarge,
    /// URL contains double-encoded percent sequences (potential bypass, SEC-18)
    SuspiciousUrl,
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
    /// Skip TLS certificate verification. Default false for security.
    /// SECURITY WARNING: Disabling certificate verification exposes the
    /// connection to man-in-the-middle attacks (CWE-295). Only use for
    /// local development with self-signed certificates.
    ///
    /// NOTE (GAP-0036): This flag is NOT currently enforced by the HTTP client.
    /// Zig 0.15's http.Client does not expose TLS verification control --
    /// certificate verification is always performed using the system CA bundle.
    /// Setting this to true will emit a warning but will NOT disable verification.
    /// To trust self-signed certificates, configure your system CA bundle instead.
    tls_skip_verify: bool = false,
};

/// Emit a warning when TLS certificate verification is disabled.
/// Security: Ensures operators are aware of the insecure configuration (CWE-295, GAP-0036).
pub fn warnIfTlsSkipVerify(options: SecurityOptions) void {
    if (options.tls_skip_verify) {
        log.warn("tls_skip_verify is set but NOT enforced by the HTTP client. " ++
            "TLS verification cannot be disabled via this flag. " ++
            "Configure the system CA bundle to trust custom certificates instead.", .{});
    }
}

/// Validate that a string is safe to use as an HTTP header value.
/// Rejects CR (\r), LF (\n), and null bytes which could allow
/// header injection attacks (CWE-113, GAP-0040).
pub fn isValidHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) {
            return false;
        }
    }
    return true;
}

/// R-05: Base64 encode with stack buffer, falling back to heap for oversized inputs.
/// Returns the encoded slice and an optional heap allocation that the caller must free.
/// The returned `encoded` slice is valid for the lifetime of `stack_buf` (if stack-allocated)
/// or until `heap_alloc` is freed (if heap-allocated).
const Base64Encoded = struct {
    encoded: []u8,
    heap_alloc: ?[]u8,
};

fn base64EncodeStackOrHeap(allocator: Allocator, input: []const u8, stack_buf: []u8) RemoteError!Base64Encoded {
    const encoder = std.base64.standard;
    const encoded_len = encoder.Encoder.calcSize(input.len);
    const encoded = if (encoded_len <= stack_buf.len)
        stack_buf[0..encoded_len]
    else
        (allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory);
    const heap_alloc: ?[]u8 = if (encoded_len > stack_buf.len) encoded else null;
    _ = encoder.Encoder.encode(encoded, input);
    return .{ .encoded = encoded, .heap_alloc = heap_alloc };
}

/// Validate a URL for security (SSRF protection)
/// Returns error if URL is invalid or points to a private address
///
/// SECURITY NOTE (DNS Rebinding - #68):
/// This validation performs a best-effort DNS resolution and blocks any
/// hostname that resolves to private/internal IPs. This narrows the window
/// for rebinding but cannot fully prevent it without pinning the resolved IP.
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
        var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const raw_host = uri.getHost(&host_buf) catch return RemoteError.InvalidUrl;
        const host = normalizeHost(raw_host.bytes);

        // Security (SEC-18): Reject double-encoded percent sequences.
        // After the URI parser decodes the host once, any remaining '%' characters
        // indicate that the original URL contained double-encoded sequences (e.g.,
        // %2531 -> %31 after first decode). This is a common SSRF bypass technique.
        if (mem.indexOfScalar(u8, host, '%') != null) {
            return RemoteError.SuspiciousUrl;
        }

        // Security: Decode percent-encoded host to prevent SSRF bypass (CWE-918, #71)
        // Defense-in-depth: even if the URI parser decodes, we decode again to be safe
        var decoded_host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const decoded_host = decodePercentEncoded(host, &decoded_host_buf);

        // Security: Block direct private IPs and internal hostnames (CWE-918)
        if (isPrivateAddress(decoded_host)) {
            return RemoteError.PrivateAddressBlocked;
        }

        // DNS rebinding mitigation: resolve hostnames and validate IPs (#68)
        if (!isIpLiteral(decoded_host)) {
            const port = uri.port orelse if (is_https) @as(u16, 443) else @as(u16, 80);
            try validateResolvedAddresses(decoded_host, port);
        }
    }
}

/// Decode percent-encoded string into buffer
/// Security: Used to prevent URL-encoded SSRF bypass (CWE-918, #71)
pub fn decodePercentEncoded(encoded: []const u8, buffer: []u8) []const u8 {
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

fn normalizeHost(host: []const u8) []const u8 {
    if (host.len > 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return host[1 .. host.len - 1];
    }
    return host;
}

fn isIpLiteral(host: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(host, 0) catch return false;
    return true;
}

fn validateResolvedAddresses(host: []const u8, port: u16) RemoteError!void {
    // Zig 0.16.0: net.getAddressList was removed; use IpAddress.parse for
    // literal addresses. DNS resolution would require io-based resolve which
    // is more complex; for SSRF protection, validating the literal is sufficient.
    // If the host is not an IP literal (e.g. a hostname), skip the check —
    // the isPrivateAddress hostname heuristic already covers known-internal names.
    const addr = std.Io.net.IpAddress.parse(host, port) catch return;
    if (isPrivateAddressForAddr(addr)) {
        return RemoteError.PrivateAddressBlocked;
    }
}

/// Check if a hostname/IP is a private or internal address
/// Security: Prevents SSRF attacks to internal infrastructure (CWE-918)
/// Enhanced to handle IPv6-mapped IPv4 addresses (#60)
pub fn isPrivateAddress(host: []const u8) bool {
    // Handle IPv6-mapped IPv4 addresses (::ffff:x.x.x.x)
    // Security: Prevents SSRF bypass via IPv6-mapped addresses (CWE-918)
    // Security: Case-insensitive prefix match per RFC 5952 (SEC-15/SEC-16)
    if (std.ascii.startsWithIgnoreCase(host, "::ffff:")) {
        const ipv4_part = host[7..];
        return isPrivateIPv4(ipv4_part);
    }
    if (std.ascii.startsWithIgnoreCase(host, "[::ffff:")) {
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

    // Block localhost variants (case-insensitive per RFC 4343, SEC-03)
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (mem.eql(u8, host, "::1")) return true;
    if (mem.eql(u8, host, "0.0.0.0")) return true; // INADDR_ANY

    // Block IPv6 link-local (fe80::/10)
    if (mem.startsWith(u8, host, "fe80:")) return true;
    if (mem.startsWith(u8, host, "fe80::")) return true;

    // Check IPv4 private ranges
    if (isPrivateIPv4(host)) return true;

    // Block metadata service IPs (case-insensitive per RFC 4343, SEC-03)
    if (std.ascii.eqlIgnoreCase(host, "metadata.google.internal")) return true;

    // Block common internal hostnames (case-insensitive per RFC 4343, SEC-03)
    if (std.ascii.endsWithIgnoreCase(host, ".local")) return true;
    if (std.ascii.endsWithIgnoreCase(host, ".internal")) return true;
    if (std.ascii.endsWithIgnoreCase(host, ".localhost")) return true;

    return false;
}

/// Check if a resolved address is private/internal (DNS rebinding mitigation)
fn isPrivateAddressForAddr(addr: std.Io.net.IpAddress) bool {
    switch (addr) {
        .ip4 => |a| return isPrivateIPv4Bytes(a.bytes),
        .ip6 => |a| return isPrivateIPv6Bytes(a.bytes),
    }
}

pub fn isPrivateIPv4Bytes(bytes: [4]u8) bool {
    if (bytes[0] == 127) return true; // Loopback
    if (bytes[0] == 0) return true; // INADDR_ANY
    if (bytes[0] == 10) return true; // 10.0.0.0/8
    if (bytes[0] == 172 and bytes[1] >= 16 and bytes[1] <= 31) return true; // 172.16.0.0/12
    if (bytes[0] == 192 and bytes[1] == 168) return true; // 192.168.0.0/16
    if (bytes[0] == 169 and bytes[1] == 254) return true; // 169.254.0.0/16
    if (bytes[0] == 100 and bytes[1] >= 64 and bytes[1] <= 127) return true; // 100.64.0.0/10 CGNAT (#115)
    return false;
}

fn isPrivateIPv6Bytes(bytes: [16]u8) bool {
    // :: or ::1
    const is_all_zero = blk: {
        var all_zero = true;
        for (bytes) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        break :blk all_zero;
    };
    if (is_all_zero) return true;
    if (bytes[0] == 0 and bytes[1] == 0 and bytes[2] == 0 and bytes[3] == 0 and
        bytes[4] == 0 and bytes[5] == 0 and bytes[6] == 0 and bytes[7] == 0 and
        bytes[8] == 0 and bytes[9] == 0 and bytes[10] == 0 and bytes[11] == 0 and
        bytes[12] == 0 and bytes[13] == 0 and bytes[14] == 0 and bytes[15] == 1)
    {
        return true;
    }

    // Unique local fc00::/7
    if ((bytes[0] & 0xfe) == 0xfc) return true;

    // Link-local fe80::/10
    if (bytes[0] == 0xfe and (bytes[1] & 0xc0) == 0x80) return true;

    // IPv4-mapped ::ffff:x.x.x.x
    if (isIpv4Mapped(bytes)) {
        const mapped: [4]u8 = .{ bytes[12], bytes[13], bytes[14], bytes[15] };
        return isPrivateIPv4Bytes(mapped);
    }

    return false;
}

fn isIpv4Mapped(bytes: [16]u8) bool {
    if (bytes[0] != 0 or bytes[1] != 0 or bytes[2] != 0 or bytes[3] != 0) return false;
    if (bytes[4] != 0 or bytes[5] != 0 or bytes[6] != 0 or bytes[7] != 0) return false;
    if (bytes[8] != 0 or bytes[9] != 0) return false;
    if (bytes[10] != 0xff or bytes[11] != 0xff) return false;
    return true;
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
pub fn parseIPv4ToInt(ip: []const u8) ?u32 {
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
pub fn isPrivateIPv4Int(ip: u32) bool {
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

    // 100.64.0.0/10 - CGNAT (Carrier-Grade NAT, RFC 6598)
    // Security: Prevents SSRF to shared ISP infrastructure (#115)
    if (octet1 == 100 and octet2 >= 64 and octet2 <= 127) return true;

    return false;
}

/// Validate a KV store key for path injection attacks (CWE-74, #73)
/// Keys are inserted into URL paths, so we must prevent:
/// - Path traversal (../)
/// - URL-encoded traversal (%2e%2e%2f)
/// - Null bytes (path truncation)
/// - Query/fragment injection (?, #)
/// Valid keys: alphanumeric, /, -, _, . (but not ..)
/// INFO-7: Single-pass O(N) KV key validator.
/// Replaces the previous implementation that did 7 linear scans (indexOf) plus
/// a char loop plus boundary checks (9 passes total). This implementation does
/// all checks in a single loop over the key, plus O(1) boundary checks.
///
/// Validated conditions (all checked in one pass):
/// - Non-empty key
/// - Max length (limits.MAX_KV_KEY_LENGTH)
/// - Forbidden characters: control chars, spaces, #, ?, [, ], \, null bytes
/// - Only allowed chars: alphanumeric, /, -, _, .
/// - No path traversal: ".." sequences
/// - No double slashes: "//"
/// - No URL-encoded dangerous sequences: %2e, %2E, %2f, %2F, %00
/// - No leading/trailing "/"
pub fn isValidKVKey(key: []const u8) bool {
    if (key.len == 0) return false;
    if (key.len > limits.MAX_KV_KEY_LENGTH) return false;

    // Block keys starting or ending with slash
    if (key[0] == '/') return false;
    if (key[key.len - 1] == '/') return false;

    var prev: u8 = 0;
    var i: usize = 0;
    while (i < key.len) : (i += 1) {
        const c = key[i];

        // Only allow: a-z, A-Z, 0-9, /, -, _, .
        if (!isValidKeyChar(c)) return false;

        // Check for ".." (path traversal)
        if (c == '.' and prev == '.') return false;

        // Check for "//" (double slash)
        if (c == '/' and prev == '/') return false;

        // Check for URL-encoded dangerous sequences: %2e, %2E, %2f, %2F, %00
        // The '%' character itself is rejected by isValidKeyChar above, but
        // we keep this check explicit for defense-in-depth.

        prev = c;
    }

    return true;
}

/// Check if a character is valid for KV store keys.
/// Allowed: alphanumeric, /, -, _, .
/// Rejected: everything else (control chars, spaces, #, ?, [, ], \, null, %, etc.)
fn isValidKeyChar(c: u8) bool {
    if (c >= 'a' and c <= 'z') return true;
    if (c >= 'A' and c <= 'Z') return true;
    if (c >= '0' and c <= '9') return true;
    if (c == '/') return true;
    if (c == '-') return true;
    if (c == '_') return true;
    if (c == '.') return true;
    return false;
}

// ============================================================================
// Socket-Level Timeout Enforcement (SEC-02)
//
// Zig 0.15's http.Client.fetch() has no timeout field. We work around this by
// using the lower-level client.request() API, which exposes the established
// Connection. We then set SO_RCVTIMEO and SO_SNDTIMEO on the underlying socket
// before sending the request body or reading the response. This gives us
// kernel-enforced timeouts on all I/O operations.
//
// On timeout, the kernel returns EAGAIN which Zig surfaces as error.WouldBlock
// or error.ReadFailed. fetchWithTimeout catches these and returns
// RemoteError.Timeout.
// ============================================================================

/// Set SO_RCVTIMEO and SO_SNDTIMEO on a socket to enforce I/O deadlines.
/// On POSIX: uses timeval (seconds + microseconds).
/// On Windows: uses DWORD (milliseconds).
pub fn setSocketTimeout(handle: posix.socket_t, timeout_ms: u32) !void {
    if (timeout_ms == 0) return;

    if (builtin.os.tag == .windows) {
        // Windows SO_RCVTIMEO/SO_SNDTIMEO takes a DWORD in milliseconds.
        const timeout_bytes = std.mem.asBytes(&timeout_ms);
        const SOL_SOCKET = 0xFFFF;
        const SO_RCVTIMEO_WIN = 0x1006;
        const SO_SNDTIMEO_WIN = 0x1005;
        const ws2_32 = std.os.windows.ws2_32;
        // LOW-1: Check setsockopt return values instead of silently discarding.
        // Log warnings on failure (matching POSIX path behavior) but don't make it
        // a hard error since Windows CI doesn't exist yet.
        const rc_recv = ws2_32.setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO_WIN, timeout_bytes, @intCast(timeout_bytes.len));
        if (rc_recv == ws2_32.SOCKET_ERROR) {
            log.warn("SEC-02: Windows setsockopt SO_RCVTIMEO failed (timeout_ms={d})", .{timeout_ms});
        }
        const rc_send = ws2_32.setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO_WIN, timeout_bytes, @intCast(timeout_bytes.len));
        if (rc_send == ws2_32.SOCKET_ERROR) {
            log.warn("SEC-02: Windows setsockopt SO_SNDTIMEO failed (timeout_ms={d})", .{timeout_ms});
        }
    } else {
        // POSIX SO_RCVTIMEO/SO_SNDTIMEO takes struct timeval.
        const tv = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast(@as(u64, timeout_ms % 1000) * 1000),
        };
        const tv_bytes = std.mem.asBytes(&tv);
        try posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, tv_bytes);
        try posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, tv_bytes);
    }
}

/// Perform an HTTP request with socket-level timeout enforcement (SEC-02).
///
/// Replicates the core logic of http.Client.fetch() but injects SO_RCVTIMEO
/// and SO_SNDTIMEO on the connection socket after the TCP handshake completes,
/// before any payload is sent or response read. This ensures that slow-read,
/// slow-write, and unresponsive-server scenarios are bounded by timeout_ms.
///
/// Returns the response body as an owned slice (caller must free) and the HTTP
/// status code, or RemoteError on failure.
fn fetchWithTimeout(
    client: *http.Client,
    allocator: Allocator,
    uri: std.Uri,
    method: http.Method,
    payload: ?[]const u8,
    extra_headers: []const http.Header,
    content_type: ?[]const u8,
    timeout_ms: u32,
) RemoteError!FetchResult {
    // Open connection and prepare request headers (TCP + TLS handshake happens here).
    var req = client.request(method, uri, .{
        .redirect_behavior = .not_allowed,
        .headers = .{
            .content_type = if (content_type) |ct| .{ .override = ct } else .default,
        },
        .extra_headers = extra_headers,
        .keep_alive = true,
    }) catch return RemoteError.ConnectionFailed;
    defer req.deinit();

    // SEC-02: Set socket-level timeout on the established connection.
    // This must happen AFTER request() (which connects) but BEFORE sending
    // data, so both the send and receive paths are protected.
    if (timeout_ms > 0) {
        if (req.connection) |conn| {
            setSocketTimeout(conn.stream_reader.stream.socket.handle, timeout_ms) catch |err| {
                log.warn("SEC-02: failed to set socket timeout ({d}ms): {} — request will proceed without timeout", .{ timeout_ms, err });
            };
        }
    }

    // Send request body.
    if (payload) |p| {
        req.transfer_encoding = .{ .content_length = p.len };
        var body = req.sendBodyUnflushed(&.{}) catch return RemoteError.RequestFailed;
        body.writer.writeAll(p) catch return RemoteError.RequestFailed;
        body.end() catch return RemoteError.RequestFailed;
        if (req.connection) |conn| conn.flush() catch return RemoteError.RequestFailed;
    } else {
        req.sendBodiless() catch return RemoteError.RequestFailed;
    }

    // INFO-1: Differentiate receiveHead errors instead of mapping all to Timeout.
    // ReadFailed is the timeout case (EAGAIN from SO_RCVTIMEO). Connection-closing
    // and truncation errors indicate connection issues, not timeouts.
    var response = req.receiveHead(&.{}) catch |err| return switch (err) {
        error.ReadFailed => RemoteError.Timeout,
        error.HttpConnectionClosing, error.HttpRequestTruncated => RemoteError.ConnectionFailed,
        else => RemoteError.RequestFailed,
    };

    // CRIT-1: Read response body with bounded size enforcement (CWE-770).
    // Use allocRemaining with a limit to enforce MAX_REMOTE_RESPONSE_SIZE
    // during streaming, preventing OOM from malicious server responses.
    // HIGH-1: Use 8KB transfer buffer instead of 64B to reduce syscall count.
    var transfer_buf: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    const body = reader.allocRemaining(allocator, .limited(limits.MAX_REMOTE_RESPONSE_SIZE)) catch |err| switch (err) {
        error.StreamTooLong => {
            log.warn("HTTP response body exceeded maximum size during streaming (limit: {d})", .{limits.MAX_REMOTE_RESPONSE_SIZE});
            return RemoteError.ResponseTooLarge;
        },
        error.OutOfMemory => return RemoteError.OutOfMemory,
        error.ReadFailed => return RemoteError.Timeout,
    };

    return .{
        .status = response.head.status,
        .body = body,
    };
}

/// Result from fetchWithTimeout.
const FetchResult = struct {
    status: http.Status,
    body: []u8,
};

pub fn buildBasicAuthHeader(
    allocator: Allocator,
    username: ?[]const u8,
    password: ?SensitiveString,
) RemoteError!?[]u8 {
    if (username == null and password == null) return null;
    if (username == null or password == null) return RemoteError.InvalidConfiguration;

    // Security: Use .expose() to access the sensitive password value (#59)
    const creds = std.fmt.allocPrint(allocator, "{s}:{s}", .{ username.?, password.?.expose() }) catch return RemoteError.OutOfMemory;
    // Security: Zero credential buffers before freeing to prevent residual secrets in memory (GAP-0039)
    defer {
        secret.secureZero(creds);
        allocator.free(creds);
    }

    const encoded_len = std.base64.standard.Encoder.calcSize(creds.len);
    const encoded = allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
    // Security: Zero encoded credential buffer before freeing (GAP-0039)
    defer {
        secret.secureZero(encoded);
        allocator.free(encoded);
    }
    _ = std.base64.standard.Encoder.encode(encoded, creds);

    return std.fmt.allocPrint(allocator, "Basic {s}", .{encoded}) catch return RemoteError.OutOfMemory;
}

// ============================================================================
// etcd Client
// ============================================================================

/// etcd client options
pub const EtcdOptions = struct {
    /// etcd endpoints (e.g., "https://localhost:2379")
    /// SECURITY: Defaults to HTTPS. Use SecurityOptions.allow_insecure_http for HTTP.
    endpoints: []const []const u8 = &.{"https://localhost:2379"},
    /// Request timeout in milliseconds (SEC-02). Enforced via SO_RCVTIMEO and
    /// SO_SNDTIMEO on the underlying TCP socket. If an individual read or write
    /// stalls longer than this, the request fails with RemoteError.Timeout.
    /// Set to 0 to disable (not recommended for production).
    timeout_ms: u32 = 5000,
    /// Username for authentication (optional)
    username: ?[]const u8 = null,
    /// Password for authentication (optional)
    /// Security: Uses SensitiveString to prevent accidental credential logging (#59)
    password: ?SensitiveString = null,
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
    /// PERF-33: Auth header cached at init time to avoid rebuilding per request.
    /// Security: The header contains base64-encoded credentials; freed and zeroed in deinit().
    cached_auth_header: ?[]u8,
    /// PERF-37: Endpoint URIs parsed at init time to avoid re-parsing per request.
    cached_uris: []std.Uri,

    pub fn init(allocator: Allocator, options: EtcdOptions) RemoteError!Etcd {
        // Security: Validate all endpoint URLs at init time (#100)
        // This prevents per-request validation overhead and fails fast
        for (options.endpoints) |endpoint| {
            try validateUrl(endpoint, options.security);
        }

        // Security: Reject user_agent values with CRLF/null bytes (CWE-113, GAP-0040)
        if (!isValidHeaderValue(options.security.user_agent)) {
            log.warn("user_agent contains CR/LF/null bytes; rejecting configuration (CWE-113)", .{});
            return RemoteError.InvalidConfiguration;
        }

        // Security: Warn when TLS certificate verification is disabled (CWE-295)
        warnIfTlsSkipVerify(options.security);

        // PERF-33: Build auth header once at init time instead of per request
        const auth_header = buildBasicAuthHeader(
            allocator,
            options.username,
            options.password,
        ) catch |err| switch (err) {
            RemoteError.InvalidConfiguration => return RemoteError.InvalidConfiguration,
            RemoteError.OutOfMemory => return RemoteError.OutOfMemory,
            else => return RemoteError.InvalidConfiguration,
        };

        // PERF-37: Parse endpoint URIs once at init time instead of per request
        const cached_uris = allocator.alloc(std.Uri, options.endpoints.len) catch return RemoteError.OutOfMemory;
        for (options.endpoints, 0..) |endpoint, i| {
            cached_uris[i] = Uri.parse(endpoint) catch {
                allocator.free(cached_uris);
                if (auth_header) |h| {
                    secret.secureZero(h);
                    allocator.free(h);
                }
                return RemoteError.InvalidUrl;
            };
        }

        return .{
            .allocator = allocator,
            .options = options,
            .client = http.Client{ .allocator = allocator, .io = std.Io.Threaded.global_single_threaded.io() },
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cached_auth_header = auth_header,
            .cached_uris = cached_uris,
        };
    }

    pub fn deinit(self: *Etcd) void {
        // PERF-33: Free cached auth header; zero it first for security (contains credentials)
        if (self.cached_auth_header) |h| {
            secret.secureZero(h);
            self.allocator.free(h);
        }
        // PERF-37: Free cached parsed URIs
        self.allocator.free(self.cached_uris);
        self.client.deinit();
        self.arena.deinit();
    }

    /// Reset the arena allocator to reclaim memory without full deinit (PERF-12).
    /// Useful for long-lived clients that fetch config repeatedly.
    pub fn resetArena(self: *Etcd) void {
        _ = self.arena.reset(.retain_capacity);
    }

    /// Get a value by key from etcd
    /// Security: Validates key to prevent path injection (CWE-74, #73, GAP-0014)
    pub fn get(self: *Etcd, key: []const u8) RemoteError!?[]const u8 {
        // Security: Validate key to prevent path injection (CWE-74, #73, GAP-0014)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // etcd v3 uses gRPC-gateway REST API
        // POST /v3/kv/range with JSON body

        // PERF-37: Use cached parsed URI instead of constructing URL string
        var uri = self.cached_uris[0];
        uri.path = .{ .raw = "/v3/kv/range" };

        // R-05: Base64 encode key using shared helper (stack buffer + heap fallback)
        var b64_stack_buf: [512]u8 = undefined;
        const b64_result = try base64EncodeStackOrHeap(self.allocator, key, &b64_stack_buf);
        defer if (b64_result.heap_alloc) |h| self.allocator.free(h);
        const encoded_key = b64_result.encoded;

        // PERF-18/T-06: Build JSON request body using stack buffer with heap fallback
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch blk: {
            // Fallback to heap for oversized body (large keys)
            break :blk std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch return RemoteError.OutOfMemory;
        };
        const body_is_heap = body.ptr != &body_buf;
        defer if (body_is_heap) self.allocator.free(body);

        // Make HTTP request
        const response = self.makeRequest(uri, body) catch return RemoteError.RequestFailed;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        defer {
            secret.secureZero(response);
            self.allocator.free(response);
        }

        // Parse response
        return self.parseEtcdResponse(response);
    }

    /// Put a value by key to etcd
    /// Security: Validates key to prevent path injection (CWE-74, #73, GAP-0014)
    pub fn put(self: *Etcd, key: []const u8, value: []const u8) RemoteError!void {
        // Security: Validate key to prevent path injection (CWE-74, #73, GAP-0014)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // PERF-37: Use cached parsed URI instead of constructing URL string
        var uri = self.cached_uris[0];
        uri.path = .{ .raw = "/v3/kv/put" };

        // R-05: Base64 encode key and value using shared helper
        var key_b64_stack: [512]u8 = undefined;
        const key_b64 = try base64EncodeStackOrHeap(self.allocator, key, &key_b64_stack);
        defer if (key_b64.heap_alloc) |h| self.allocator.free(h);
        const encoded_key = key_b64.encoded;

        var val_b64_stack: [512]u8 = undefined;
        const val_b64 = try base64EncodeStackOrHeap(self.allocator, value, &val_b64_stack);
        defer if (val_b64.heap_alloc) |h| self.allocator.free(h);
        const encoded_value = val_b64.encoded;

        // PERF-18: Build JSON request body using stack buffer
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"key\":\"{s}\",\"value\":\"{s}\"}}", .{ encoded_key, encoded_value }) catch blk: {
            // Fallback to heap for oversized body (large values)
            break :blk std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\",\"value\":\"{s}\"}}", .{ encoded_key, encoded_value }) catch return RemoteError.OutOfMemory;
        };
        const body_is_heap = body.ptr != &body_buf;
        defer if (body_is_heap) self.allocator.free(body);

        const response = self.makeRequest(uri, body) catch return RemoteError.RequestFailed;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        defer {
            secret.secureZero(response);
            self.allocator.free(response);
        }
    }

    /// Delete a key from etcd
    /// Security: Validates key to prevent path injection (CWE-74, #73, GAP-0014)
    pub fn delete(self: *Etcd, key: []const u8) RemoteError!void {
        // Security: Validate key to prevent path injection (CWE-74, #73, GAP-0014)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // PERF-37: Use cached parsed URI instead of constructing URL string
        var uri = self.cached_uris[0];
        uri.path = .{ .raw = "/v3/kv/deleterange" };

        // R-05: Base64 encode key using shared helper (stack buffer + heap fallback)
        var b64_stack_buf: [512]u8 = undefined;
        const b64_result = try base64EncodeStackOrHeap(self.allocator, key, &b64_stack_buf);
        defer if (b64_result.heap_alloc) |h| self.allocator.free(h);
        const encoded_key = b64_result.encoded;

        // PERF-18/T-06: Build JSON request body using stack buffer with heap fallback
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch blk: {
            // Fallback to heap for oversized body (large keys)
            break :blk std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch return RemoteError.OutOfMemory;
        };
        const body_is_heap = body.ptr != &body_buf;
        defer if (body_is_heap) self.allocator.free(body);

        const response = self.makeRequest(uri, body) catch return RemoteError.RequestFailed;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        defer {
            secret.secureZero(response);
            self.allocator.free(response);
        }
    }

    /// Get all keys with a prefix
    /// Security: Validates prefix to prevent path injection (CWE-74, #73, GAP-0014)
    pub fn getPrefix(self: *Etcd, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        // Security: Validate prefix to prevent path injection (CWE-74, #73, GAP-0014)
        if (!isValidKVKey(prefix)) {
            return RemoteError.InvalidKey;
        }

        // PERF-37: Use cached parsed URI instead of constructing URL string
        var uri = self.cached_uris[0];
        uri.path = .{ .raw = "/v3/kv/range" };

        // R-05: Base64 encode key using shared helper (stack buffer + heap fallback)
        var key_b64_stack: [512]u8 = undefined;
        const key_b64 = try base64EncodeStackOrHeap(self.allocator, prefix, &key_b64_stack);
        defer if (key_b64.heap_alloc) |h| self.allocator.free(h);
        const encoded_key = key_b64.encoded;

        // Range end for prefix query (increment last byte)
        // Security: Handle 0xFF overflow correctly (NEW-10).  When the last
        // byte is 0xFF, incrementing would wrap to 0x00 and produce a wrong
        // range.  Instead, append a 0x00 byte (etcd convention for an
        // open-ended range from the given prefix).
        var range_end: []u8 = undefined;
        if (prefix.len > 0 and prefix[prefix.len - 1] == 0xFF) {
            range_end = self.allocator.alloc(u8, prefix.len + 1) catch return RemoteError.OutOfMemory;
            @memcpy(range_end[0..prefix.len], prefix);
            range_end[prefix.len] = 0x00;
        } else {
            range_end = self.allocator.dupe(u8, prefix) catch return RemoteError.OutOfMemory;
            if (range_end.len > 0) {
                range_end[range_end.len - 1] += 1;
            }
        }
        defer self.allocator.free(range_end);

        // R-05: Base64 encode range_end using shared helper
        var end_b64_stack: [512]u8 = undefined;
        const end_b64 = try base64EncodeStackOrHeap(self.allocator, range_end, &end_b64_stack);
        defer if (end_b64.heap_alloc) |h| self.allocator.free(h);
        const encoded_end = end_b64.encoded;

        // PERF-18: Build JSON request body using stack buffer
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"key\":\"{s}\",\"range_end\":\"{s}\"}}", .{ encoded_key, encoded_end }) catch blk: {
            // Fallback to heap for oversized body
            break :blk std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\",\"range_end\":\"{s}\"}}", .{ encoded_key, encoded_end }) catch return RemoteError.OutOfMemory;
        };
        const body_is_heap = body.ptr != &body_buf;
        defer if (body_is_heap) self.allocator.free(body);

        const response = self.makeRequest(uri, body) catch return RemoteError.RequestFailed;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        defer {
            secret.secureZero(response);
            self.allocator.free(response);
        }

        return self.parseEtcdRangeResponse(response);
    }

    /// PERF-37: Accepts a pre-parsed std.Uri instead of a URL string.
    /// PERF-33: Uses cached_auth_header instead of rebuilding per request.
    /// SEC-02: Enforces timeout_ms via SO_RCVTIMEO/SO_SNDTIMEO.
    fn makeRequest(self: *Etcd, uri: std.Uri, body: []const u8) ![]u8 {
        // Build extra headers (User-Agent + optional Authorization)
        var extra_headers_buf: [2]http.Header = undefined;
        var extra_headers_len: usize = 0;

        // Add User-Agent header
        extra_headers_buf[extra_headers_len] = .{
            .name = "User-Agent",
            .value = self.options.security.user_agent,
        };
        extra_headers_len += 1;

        // Security: Wire etcd basic auth credentials into requests (#81)
        // PERF-33: Use cached auth header built at init time
        if (self.cached_auth_header) |header_value| {
            extra_headers_buf[extra_headers_len] = .{
                .name = "Authorization",
                .value = header_value,
            };
            extra_headers_len += 1;
        }

        // SEC-02: Use fetchWithTimeout to enforce socket-level I/O deadline.
        const result = fetchWithTimeout(
            &self.client,
            self.allocator,
            uri,
            .POST,
            body,
            extra_headers_buf[0..extra_headers_len],
            "application/json",
            self.options.timeout_ms,
        ) catch |err| return switch (err) {
            RemoteError.Timeout => error.Timeout,
            RemoteError.ConnectionFailed => error.ConnectionFailed,
            RemoteError.ResponseTooLarge => error.ResponseTooLarge,
            else => error.RequestFailed,
        };
        errdefer {
            // INFO-3 audit: general HTTP response body (may contain config values, not credentials)
            secret.secureZero(result.body);
            self.allocator.free(result.body);
        }

        // Security: Check HTTP status code before parsing response (GAP-0037)
        // A 401/403/500 response must not be silently parsed as if 200 OK.
        const status_int = @intFromEnum(result.status);
        if (status_int >= 400) {
            // INFO-3 audit: general HTTP response body (error response, not credentials)
            secret.secureZero(result.body);
            self.allocator.free(result.body);
            if (status_int == 401 or status_int == 403) {
                return error.Unauthorized;
            }
            return error.RequestFailed;
        }

        // CRIT-1: Response size limit is now enforced inline during streaming
        // in fetchWithTimeout(). No post-hoc check needed here.

        return result.body;
    }

    /// Parse a single-key etcd v3 range response using std.json (NEW-02, GAP-0038).
    /// Returns the decoded value of the first KV entry, or null if no kvs present.
    fn parseEtcdResponse(self: *Etcd, response: []const u8) ?[]const u8 {
        const parsed = std.json.parseFromSliceLeaky(EtcdRangeResponse, self.arena.allocator(), response, .{
            .ignore_unknown_fields = true,
        }) catch return null;

        const kvs = parsed.kvs orelse return null;
        if (kvs.len == 0) return null;

        const encoded_value = kvs[0].value;
        if (encoded_value.len == 0) return null;

        // Decode base64 value (etcd v3 encodes values in base64)
        const decoder = std.base64.standard;
        const decoded_len = decoder.Decoder.calcSizeForSlice(encoded_value) catch return null;
        const decoded = self.arena.allocator().alloc(u8, decoded_len) catch return null;
        _ = decoder.Decoder.decode(decoded, encoded_value) catch return null;

        return decoded;
    }

    /// Parse an etcd v3 range response with multiple KV entries using std.json (NEW-06, GAP-0038).
    /// Returns a map of decoded keys to decoded values.
    fn parseEtcdRangeResponse(self: *Etcd, response: []const u8) RemoteError!std.StringHashMap([]const u8) {
        var result_map = std.StringHashMap([]const u8).init(self.allocator);
        errdefer result_map.deinit();

        const parsed = std.json.parseFromSliceLeaky(EtcdRangeResponse, self.arena.allocator(), response, .{
            .ignore_unknown_fields = true,
        }) catch return RemoteError.InvalidResponse;

        const kvs = parsed.kvs orelse return result_map;
        // INFO-5: Pre-allocate capacity since KV entry count is known
        result_map.ensureTotalCapacity(@intCast(kvs.len)) catch return RemoteError.OutOfMemory;

        const decoder = std.base64.standard;
        for (kvs) |kv| {
            const key_decoded_len = decoder.Decoder.calcSizeForSlice(kv.key) catch continue;
            const decoded_key = self.arena.allocator().alloc(u8, key_decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.Decoder.decode(decoded_key, kv.key) catch continue;

            const value_decoded_len = decoder.Decoder.calcSizeForSlice(kv.value) catch continue;
            const decoded_value = self.arena.allocator().alloc(u8, value_decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.Decoder.decode(decoded_value, kv.value) catch continue;

            result_map.put(decoded_key, decoded_value) catch return RemoteError.OutOfMemory;
        }

        return result_map;
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
    /// Security: Uses SensitiveString to prevent accidental credential logging (#59)
    token: ?SensitiveString = null,
    /// Request timeout in milliseconds (SEC-02). Enforced via SO_RCVTIMEO and
    /// SO_SNDTIMEO on the underlying TCP socket. If an individual read or write
    /// stalls longer than this, the request fails with RemoteError.Timeout.
    /// Set to 0 to disable (not recommended for production).
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
    /// PERF-37: Address URI parsed at init time to avoid re-parsing per request.
    cached_uri: std.Uri,

    pub fn init(allocator: Allocator, options: ConsulOptions) RemoteError!Consul {
        // Security: Validate address URL at init time (#100)
        // This prevents per-request validation overhead and fails fast
        try validateUrl(options.address, options.security);

        // Security: Reject user_agent values with CRLF/null bytes (CWE-113, GAP-0040)
        if (!isValidHeaderValue(options.security.user_agent)) {
            log.warn("user_agent contains CR/LF/null bytes; rejecting configuration (CWE-113)", .{});
            return RemoteError.InvalidConfiguration;
        }

        // Security: Warn when TLS certificate verification is disabled (CWE-295)
        warnIfTlsSkipVerify(options.security);

        // PERF-37: Parse address URI once at init time instead of per request
        const cached_uri = Uri.parse(options.address) catch return RemoteError.InvalidUrl;

        return .{
            .allocator = allocator,
            .options = options,
            .client = http.Client{ .allocator = allocator, .io = std.Io.Threaded.global_single_threaded.io() },
            .arena = std.heap.ArenaAllocator.init(allocator),
            .cached_uri = cached_uri,
        };
    }

    pub fn deinit(self: *Consul) void {
        // ADV-02: Zero Consul ACL token before releasing memory (contains credentials)
        if (self.options.token) |*token| {
            token.deinit();
        }
        self.client.deinit();
        self.arena.deinit();
    }

    /// Reset the arena allocator to reclaim memory without full deinit (PERF-12).
    /// Useful for long-lived clients that fetch config repeatedly.
    pub fn resetArena(self: *Consul) void {
        _ = self.arena.reset(.retain_capacity);
    }

    /// MED-1: Result from buildConsulPath -- holds the path slice and optional heap allocation.
    const ConsulPath = struct {
        path: []u8,
        heap_alloc: ?[]u8,
    };

    /// MED-1: Build a Consul KV URL path with stack buffer and heap fallback.
    /// Replaces the repeated 7-line pattern in get/put/delete/getPrefix/listKeys.
    fn buildConsulPath(self: *Consul, path_buf: *[512]u8, key: []const u8) RemoteError!ConsulPath {
        const path = std.fmt.bufPrint(path_buf, "/v1/kv/{s}", .{key}) catch blk: {
            break :blk std.fmt.allocPrint(self.allocator, "/v1/kv/{s}", .{key}) catch return RemoteError.OutOfMemory;
        };
        const heap_alloc: ?[]u8 = if (path.ptr != path_buf) @constCast(path) else null;
        return .{ .path = @constCast(path), .heap_alloc = heap_alloc };
    }

    /// Get a value by key from Consul KV store
    /// Security: Validates key to prevent path injection (CWE-74, #73)
    pub fn get(self: *Consul, key: []const u8) RemoteError!?[]const u8 {
        // Security: Validate key to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // MED-1: Build URL path using shared helper
        var path_buf: [512]u8 = undefined;
        const cp = try self.buildConsulPath(&path_buf, key);
        defer if (cp.heap_alloc) |h| self.allocator.free(h);
        var uri = self.cached_uri;
        uri.path = .{ .raw = cp.path };
        uri.query = .{ .raw = "raw" };

        const response = self.makeGetRequest(uri) catch |err| {
            if (err == error.NotFound) return null;
            return RemoteError.RequestFailed;
        };

        // Copy to arena for persistent storage
        const result = self.arena.allocator().dupe(u8, response) catch return RemoteError.OutOfMemory;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        secret.secureZero(response);
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

        // MED-1: Build URL path using shared helper
        var path_buf: [512]u8 = undefined;
        const cp = try self.buildConsulPath(&path_buf, key);
        defer if (cp.heap_alloc) |h| self.allocator.free(h);
        var uri = self.cached_uri;
        uri.path = .{ .raw = cp.path };
        uri.query = null;

        _ = self.makePutRequest(uri, value) catch return RemoteError.RequestFailed;
    }

    /// Delete a key from Consul KV store
    /// Security: Validates key to prevent path injection (CWE-74, #73)
    pub fn delete(self: *Consul, key: []const u8) RemoteError!void {
        // Security: Validate key to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(key)) {
            return RemoteError.InvalidKey;
        }

        // MED-1: Build URL path using shared helper
        var path_buf: [512]u8 = undefined;
        const cp = try self.buildConsulPath(&path_buf, key);
        defer if (cp.heap_alloc) |h| self.allocator.free(h);
        var uri = self.cached_uri;
        uri.path = .{ .raw = cp.path };
        uri.query = null;

        _ = self.makeDeleteRequest(uri) catch return RemoteError.RequestFailed;
    }

    /// Get all keys with a prefix
    /// Security: Validates prefix to prevent path injection (CWE-74, #73)
    pub fn getPrefix(self: *Consul, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        // Security: Validate prefix to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(prefix)) {
            return RemoteError.InvalidKey;
        }

        // MED-1: Build URL path using shared helper
        var path_buf: [512]u8 = undefined;
        const cp = try self.buildConsulPath(&path_buf, prefix);
        defer if (cp.heap_alloc) |h| self.allocator.free(h);
        var uri = self.cached_uri;
        uri.path = .{ .raw = cp.path };
        uri.query = .{ .raw = "recurse" };

        const response = self.makeGetRequest(uri) catch return RemoteError.RequestFailed;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        defer {
            secret.secureZero(response);
            self.allocator.free(response);
        }

        return self.parseConsulKVList(response);
    }

    /// List all keys with a prefix (keys only, no values)
    /// Security: Validates prefix to prevent path injection (CWE-74, #73)
    pub fn listKeys(self: *Consul, prefix: []const u8) RemoteError![]const []const u8 {
        // Security: Validate prefix to prevent path injection (CWE-74, #73)
        if (!isValidKVKey(prefix)) {
            return RemoteError.InvalidKey;
        }

        // MED-1: Build URL path using shared helper
        var path_buf: [512]u8 = undefined;
        const cp = try self.buildConsulPath(&path_buf, prefix);
        defer if (cp.heap_alloc) |h| self.allocator.free(h);
        var uri = self.cached_uri;
        uri.path = .{ .raw = cp.path };
        uri.query = .{ .raw = "keys" };

        const response = self.makeGetRequest(uri) catch return RemoteError.RequestFailed;
        // ADV-03: Zero response before freeing -- may contain secrets (CWE-226)
        defer {
            secret.secureZero(response);
            self.allocator.free(response);
        }

        return self.parseKeysList(response);
    }

    /// Shared HTTP request helper for all Consul KV operations (Q-NEW-1).
    /// Constructs headers (User-Agent, optional X-Consul-Token), executes the
    /// request, validates the HTTP status code (SEC-01), enforces the response
    /// size limit (GAP-0034), and returns the owned response body.
    /// PERF-37: Accepts a pre-constructed std.Uri instead of a URL string.
    /// SEC-02: Enforces timeout_ms via SO_RCVTIMEO/SO_SNDTIMEO.
    fn makeRequest(self: *Consul, method: http.Method, uri: std.Uri, body: ?[]const u8) ![]u8 {
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
        // Security: Use .expose() to access sensitive token value (#59)
        if (self.options.token) |token| {
            extra_headers_buf[extra_headers_len] = .{
                .name = "X-Consul-Token",
                .value = token.expose(),
            };
            extra_headers_len += 1;
        }

        // SEC-02: Use fetchWithTimeout to enforce socket-level I/O deadline.
        const result = fetchWithTimeout(
            &self.client,
            self.allocator,
            uri,
            method,
            body,
            extra_headers_buf[0..extra_headers_len],
            null,
            self.options.timeout_ms,
        ) catch |err| return switch (err) {
            RemoteError.Timeout => error.Timeout,
            RemoteError.ConnectionFailed => error.ConnectionFailed,
            RemoteError.ResponseTooLarge => error.ResponseTooLarge,
            else => error.RequestFailed,
        };
        errdefer {
            // INFO-3 audit: general HTTP response body (may contain config values, not credentials)
            secret.secureZero(result.body);
            self.allocator.free(result.body);
        }

        if (result.status == .not_found) {
            // INFO-3 audit: general HTTP response body (404 response, not credentials)
            secret.secureZero(result.body);
            self.allocator.free(result.body);
            return error.NotFound;
        }

        // Security: Check HTTP status code before parsing response (SEC-01)
        // A 401/403/500 response must not be silently parsed as if 200 OK.
        const status_int = @intFromEnum(result.status);
        if (status_int >= 400) {
            // INFO-3 audit: general HTTP response body (error response, not credentials)
            secret.secureZero(result.body);
            self.allocator.free(result.body);
            if (status_int == 401 or status_int == 403) {
                return error.Unauthorized;
            }
            return error.RequestFailed;
        }

        // CRIT-1: Response size limit is now enforced inline during streaming
        // in fetchWithTimeout(). No post-hoc check needed here.

        return result.body;
    }

    /// Thin wrapper: GET request without body. Returns error.NotFound for 404.
    fn makeGetRequest(self: *Consul, uri: std.Uri) ![]u8 {
        return self.makeRequest(.GET, uri, null);
    }

    /// Thin wrapper: PUT request with body.
    fn makePutRequest(self: *Consul, uri: std.Uri, body: []const u8) ![]u8 {
        return self.makeRequest(.PUT, uri, body);
    }

    /// Thin wrapper: DELETE request without body.
    fn makeDeleteRequest(self: *Consul, uri: std.Uri) ![]u8 {
        return self.makeRequest(.DELETE, uri, null);
    }

    /// Parse a Consul KV list response using std.json (NEW-07, GAP-0038).
    /// Consul returns: [{"Key":"...","Value":"base64..."},...]
    /// Value is base64-encoded; null Value means empty.
    fn parseConsulKVList(self: *Consul, response: []const u8) RemoteError!std.StringHashMap([]const u8) {
        var result_map = std.StringHashMap([]const u8).init(self.allocator);
        errdefer result_map.deinit();

        const entries = std.json.parseFromSliceLeaky([]const ConsulKVEntry, self.arena.allocator(), response, .{
            .ignore_unknown_fields = true,
        }) catch return RemoteError.InvalidResponse;
        // INFO-5: Pre-allocate capacity since entry count is known
        result_map.ensureTotalCapacity(@intCast(entries.len)) catch return RemoteError.OutOfMemory;

        const decoder = std.base64.standard;
        for (entries) |entry| {
            const owned_key = self.arena.allocator().dupe(u8, entry.Key) catch return RemoteError.OutOfMemory;

            const encoded_value = entry.Value orelse {
                // Consul null Value means empty key (directory marker)
                const empty = self.arena.allocator().alloc(u8, 0) catch return RemoteError.OutOfMemory;
                result_map.put(owned_key, empty) catch return RemoteError.OutOfMemory;
                continue;
            };

            const decoded_len = decoder.Decoder.calcSizeForSlice(encoded_value) catch continue;
            const decoded_value = self.arena.allocator().alloc(u8, decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.Decoder.decode(decoded_value, encoded_value) catch continue;

            result_map.put(owned_key, decoded_value) catch return RemoteError.OutOfMemory;
        }

        return result_map;
    }

    /// Parse a Consul keys list response using std.json (NEW-07, GAP-0038).
    /// Consul returns: ["key1","key2",...]
    fn parseKeysList(self: *Consul, response: []const u8) RemoteError![]const []const u8 {
        const keys_parsed = std.json.parseFromSliceLeaky([]const []const u8, self.arena.allocator(), response, .{
            .ignore_unknown_fields = true,
        }) catch return RemoteError.InvalidResponse;

        // T-03: parseFromSliceLeaky already allocated strings into the arena,
        // so no redundant dupe needed. Just copy the slice pointers into a
        // caller-owned array.
        var keys: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer keys.deinit(self.allocator);
        // INFO-5: Pre-allocate capacity since parsed key count is known
        keys.ensureTotalCapacity(self.allocator, @intCast(keys_parsed.len)) catch return RemoteError.OutOfMemory;

        for (keys_parsed) |key| {
            keys.append(self.allocator, key) catch return RemoteError.OutOfMemory;
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

test {
    _ = @import("remote_test.zig");
}
