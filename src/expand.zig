// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Environment Variable Expansion Module
//!
//! Provides utilities for expanding environment variable references in strings.
//! Supports multiple syntaxes:
//! - `${VAR}` - Standard shell-style
//! - `$VAR` - Simple shell-style
//! - `${VAR:-default}` - With default value
//! - `${VAR:+alternate}` - Alternate value if set
//!
//! Example:
//! ```zig
//! const expanded = try expand("${HOME}/config", allocator);
//! // Result: "/home/user/config"
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const environ = @import("environ.zig");

/// Expansion options
///
/// ## Security (S-NEW-04, CWE-200/CWE-610)
///
/// By default, expansion resolves **any** referenced name straight from the
/// process environment. **NEVER apply expansion to untrusted input** (committed
/// config, remote KV values, tenant-supplied fields): an attacker can embed
/// `${AWS_SECRET_ACCESS_KEY}`, `${VAULT_TOKEN}`, etc. to exfiltrate process-env
/// secrets into the resulting value.
///
/// For lower-trust input, restrict which names may expand:
/// - `allowed_vars` (allowlist): when non-null, ONLY these names expand; all
///   other references resolve to `undefined_value`.
/// - `denied_vars` (denylist): listed names never expand.
/// - `deny_secret_looking`: convenience denylist that also blocks names that
///   look like secrets (containing `TOKEN`/`SECRET`/`KEY`/`PASSWORD`/
///   `CREDENTIAL`, case-insensitive).
///
/// **Precedence: deny overrides allow.** A name blocked by `denied_vars` or by
/// `deny_secret_looking` never expands, even if it also appears in
/// `allowed_vars`. A blocked name is treated exactly as an undefined variable
/// (yields `undefined_value`, or errors under `strict`).
pub const ExpandOptions = struct {
    /// Whether to fail on undefined variables
    strict: bool = false,
    /// Default value for undefined variables (when not strict)
    undefined_value: []const u8 = "",
    /// Whether to expand nested variables
    recursive: bool = true,
    /// Maximum recursion depth (to prevent infinite loops)
    max_depth: u8 = 10,
    /// Allowlist of environment variable names that may be expanded.
    /// When non-null, ONLY names in this list expand; every other reference
    /// resolves to `undefined_value`. `null` (default) means "no allowlist".
    allowed_vars: ?[]const []const u8 = null,
    /// Denylist of environment variable names that must never expand.
    /// Takes precedence over `allowed_vars`. Default: empty (nothing denied).
    denied_vars: []const []const u8 = &.{},
    /// When true, also deny any name that looks like a secret (case-insensitive
    /// substring `TOKEN`/`SECRET`/`KEY`/`PASSWORD`/`CREDENTIAL`). Opt-in; off by
    /// default to preserve existing behavior. Takes precedence over allow.
    deny_secret_looking: bool = false,
};

/// Error types for expansion
pub const ExpandError = error{
    UndefinedVariable,
    MalformedExpression,
    RecursionLimitExceeded,
    OutOfMemory,
};

/// Expand environment variables in a string.
///
/// **Security (S-NEW-04):** resolves any referenced name from the process
/// environment with no restriction. Do NOT call this on untrusted input -- use
/// `expandWithOptions` with `allowed_vars`/`denied_vars` instead. See
/// `ExpandOptions` and `docs/SECURITY.md`.
pub fn expand(input: []const u8, allocator: Allocator) ExpandError![]u8 {
    return expandWithOptions(input, allocator, .{});
}

/// Expand environment variables with custom options.
///
/// **Security (S-NEW-04):** when expanding lower-trust input, set
/// `options.allowed_vars` (allowlist) and/or `options.denied_vars` (denylist,
/// which overrides allow) to prevent exfiltration of process-env secrets via
/// crafted `${VAR}`/`$VAR` references. See `ExpandOptions` and
/// `docs/SECURITY.md`.
pub fn expandWithOptions(input: []const u8, allocator: Allocator, options: ExpandOptions) ExpandError![]u8 {
    return expandRecursive(input, allocator, options, 0);
}

/// Recursive expansion with depth tracking
fn expandRecursive(input: []const u8, allocator: Allocator, options: ExpandOptions, depth: u8) ExpandError![]u8 {
    if (depth > options.max_depth) {
        return ExpandError.RecursionLimitExceeded;
    }

    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    // PERF-51: Track start of literal runs so we can flush with a single
    // appendSlice instead of one append per character.
    var literal_start: usize = 0;
    while (i < input.len) {
        if (input[i] == '$') {
            // Flush any accumulated literal characters
            if (i > literal_start) {
                try result.appendSlice(allocator, input[literal_start..i]);
            }

            if (i + 1 < input.len and input[i + 1] == '{') {
                // ${VAR} syntax
                const start = i + 2;
                const end = findClosingBrace(input, start) orelse {
                    return ExpandError.MalformedExpression;
                };

                const var_expr = input[start..end];
                const expanded_value = try expandVariable(var_expr, allocator, options);
                defer allocator.free(expanded_value);

                // Recursive expansion if enabled
                if (options.recursive and mem.indexOf(u8, expanded_value, "$") != null) {
                    const recursed = try expandRecursive(expanded_value, allocator, options, depth + 1);
                    defer allocator.free(recursed);
                    try result.appendSlice(allocator, recursed);
                } else {
                    try result.appendSlice(allocator, expanded_value);
                }

                i = end + 1;
                literal_start = i;
            } else if (i + 1 < input.len and isVarStartChar(input[i + 1])) {
                // $VAR syntax
                const start = i + 1;
                var end = start;
                while (end < input.len and isVarChar(input[end])) {
                    end += 1;
                }

                const var_name = input[start..end];
                const value = getEnvValue(var_name, options);
                try result.appendSlice(allocator, value);
                i = end;
                literal_start = i;
            } else if (i + 1 < input.len and input[i + 1] == '$') {
                // $$ escape sequence - literal $
                try result.append(allocator, '$');
                i += 2;
                literal_start = i;
            } else {
                // Just a $ character
                try result.append(allocator, '$');
                i += 1;
                literal_start = i;
            }
        } else {
            i += 1;
        }
    }

    // Flush remaining literal characters
    if (i > literal_start) {
        try result.appendSlice(allocator, input[literal_start..i]);
    }

    return result.toOwnedSlice(allocator);
}

/// Find the closing brace for a variable expression
fn findClosingBrace(input: []const u8, start: usize) ?usize {
    var depth: usize = 1;
    var i = start;

    while (i < input.len) {
        if (input[i] == '{') {
            depth += 1;
        } else if (input[i] == '}') {
            depth -= 1;
            if (depth == 0) {
                return i;
            }
        }
        i += 1;
    }

    return null;
}

/// Check if character can start a variable name
fn isVarStartChar(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_';
}

/// Check if character can be in a variable name
fn isVarChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Expand a variable expression (handles modifiers)
fn expandVariable(expr: []const u8, allocator: Allocator, options: ExpandOptions) ExpandError![]u8 {
    // Check for modifiers
    if (mem.indexOf(u8, expr, ":-")) |idx| {
        // ${VAR:-default} - use default if unset or empty
        const var_name = expr[0..idx];
        const default_value = expr[idx + 2 ..];

        if (lookupEnv(var_name, options)) |value| {
            if (value.len > 0) {
                return allocator.dupe(u8, value) catch return ExpandError.OutOfMemory;
            }
        }
        return allocator.dupe(u8, default_value) catch return ExpandError.OutOfMemory;
    } else if (mem.indexOf(u8, expr, ":+")) |idx| {
        // ${VAR:+alternate} - use alternate if set and non-empty
        const var_name = expr[0..idx];
        const alternate_value = expr[idx + 2 ..];

        if (lookupEnv(var_name, options)) |value| {
            if (value.len > 0) {
                return allocator.dupe(u8, alternate_value) catch return ExpandError.OutOfMemory;
            }
        }
        return allocator.dupe(u8, "") catch return ExpandError.OutOfMemory;
    } else if (mem.indexOf(u8, expr, "-")) |idx| {
        // ${VAR-default} - use default if unset (empty is ok)
        const var_name = expr[0..idx];
        const default_value = expr[idx + 1 ..];

        if (lookupEnv(var_name, options)) |value| {
            return allocator.dupe(u8, value) catch return ExpandError.OutOfMemory;
        }
        return allocator.dupe(u8, default_value) catch return ExpandError.OutOfMemory;
    } else if (mem.indexOf(u8, expr, "+")) |idx| {
        // ${VAR+alternate} - use alternate if set (even if empty)
        const var_name = expr[0..idx];
        const alternate_value = expr[idx + 1 ..];

        if (lookupEnv(var_name, options)) |_| {
            return allocator.dupe(u8, alternate_value) catch return ExpandError.OutOfMemory;
        }
        return allocator.dupe(u8, "") catch return ExpandError.OutOfMemory;
    } else {
        // Simple ${VAR}
        const value = getEnvValue(expr, options);
        // S-NEW-04: a blocked var is treated as undefined under strict mode.
        if (options.strict and lookupEnv(expr, options) == null) {
            return ExpandError.UndefinedVariable;
        }
        return allocator.dupe(u8, value) catch return ExpandError.OutOfMemory;
    }
}

/// S-NEW-04: gated environment lookup. Returns `null` (treated as "unset")
/// when the name is blocked by the allow/deny policy; otherwise returns the
/// process-environment value. Routing every env read through this function
/// ensures `${VAR}`, `$VAR`, modifier branches, and recursive expansion all
/// honor the same policy.
fn lookupEnv(name: []const u8, options: ExpandOptions) ?[]const u8 {
    if (isVarBlocked(name, options)) return null;
    return environ.getenv(name);
}

/// S-NEW-04: decide whether a variable name is blocked from expansion.
/// Precedence: deny overrides allow.
///   1. If denied (explicit denylist or secret-looking heuristic) -> blocked.
///   2. Else if an allowlist is set and the name is absent -> blocked.
///   3. Else -> allowed.
fn isVarBlocked(name: []const u8, options: ExpandOptions) bool {
    // Deny first (highest precedence).
    for (options.denied_vars) |denied| {
        if (mem.eql(u8, name, denied)) return true;
    }
    if (options.deny_secret_looking and isSecretLooking(name)) return true;

    // Then enforce the allowlist, if present.
    if (options.allowed_vars) |allowed| {
        for (allowed) |a| {
            if (mem.eql(u8, name, a)) return false;
        }
        return true; // allowlist set but name not present -> blocked
    }
    return false;
}

/// S-NEW-04: case-insensitive heuristic for secret-looking names. Matches any
/// name containing `TOKEN`, `SECRET`, `KEY`, `PASSWORD`, or `CREDENTIAL`.
fn isSecretLooking(name: []const u8) bool {
    const needles = [_][]const u8{ "TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL" };
    for (needles) |needle| {
        if (containsIgnoreCase(name, needle)) return true;
    }
    return false;
}

/// Case-insensitive substring search (ASCII).
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    const last = haystack.len - needle.len;
    while (i <= last) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/// Get environment variable value with fallback. Honors the S-NEW-04
/// allow/deny policy via `lookupEnv`.
fn getEnvValue(name: []const u8, options: ExpandOptions) []const u8 {
    return lookupEnv(name, options) orelse options.undefined_value;
}

/// Expand environment variables in all string fields of a struct
pub fn expandStruct(comptime T: type, value: *T, allocator: Allocator, options: ExpandOptions) ExpandError!void {
    const info = @typeInfo(T);

    inline for (info.@"struct".fields) |field| {
        if (field.type == []const u8) {
            const current = @field(value, field.name);
            if (mem.indexOf(u8, current, "$") != null) {
                const expanded = try expandWithOptions(current, allocator, options);
                @field(value, field.name) = expanded;
            }
        } else if (field.type == ?[]const u8) {
            if (@field(value, field.name)) |current| {
                if (mem.indexOf(u8, current, "$") != null) {
                    const expanded = try expandWithOptions(current, allocator, options);
                    @field(value, field.name) = expanded;
                }
            }
        }
    }
}

/// Check if a string contains any variable references
pub fn containsVariables(input: []const u8) bool {
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '$') {
            if (i + 1 < input.len) {
                if (input[i + 1] == '{' or isVarStartChar(input[i + 1])) {
                    return true;
                }
                if (input[i + 1] == '$') {
                    // Escaped $, skip
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "expand simple variable" {
    // PATH should exist on most systems
    if (environ.getenv("PATH")) |_| {
        const result = try expand("$PATH", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expect(result.len > 0);
    }
}

test "expand ${VAR} syntax" {
    if (environ.getenv("HOME")) |home| {
        const result = try expand("${HOME}/config", std.testing.allocator);
        defer std.testing.allocator.free(result);

        try std.testing.expect(mem.startsWith(u8, result, home));
        try std.testing.expect(mem.endsWith(u8, result, "/config"));
    }
}

test "expand undefined variable returns empty" {
    const result = try expand("${UNDEFINED_VAR_12345}", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "expand with default value" {
    const result = try expand("${UNDEFINED_VAR:-default_value}", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("default_value", result);
}

test "expand with existing default" {
    // PATH exists so default should not be used
    if (environ.getenv("PATH")) |path| {
        const result = try expand("${PATH:-unused}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualStrings(path, result);
    }
}

test "expand escape sequence" {
    const result = try expand("price is $$5", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("price is $5", result);
}

test "expand no variables" {
    const result = try expand("no variables here", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("no variables here", result);
}

test "expand strict mode" {
    const result = expandWithOptions("${UNDEFINED_12345}", std.testing.allocator, .{ .strict = true });
    try std.testing.expectError(ExpandError.UndefinedVariable, result);
}

test "containsVariables" {
    try std.testing.expect(containsVariables("${HOME}/path"));
    try std.testing.expect(containsVariables("$HOME/path"));
    try std.testing.expect(!containsVariables("no variables"));
    try std.testing.expect(!containsVariables("$$escaped"));
}

test "expand malformed expression" {
    const result = expand("${UNCLOSED", std.testing.allocator);
    try std.testing.expectError(ExpandError.MalformedExpression, result);
}

test "expand multiple variables" {
    if (environ.getenv("HOME")) |_| {
        const result = try expand("${HOME}:${HOME}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expect(mem.indexOf(u8, result, ":") != null);
    }
}

test "expand alternate value if set" {
    // PATH is set, so alternate should be used
    if (environ.getenv("PATH")) |_| {
        const result = try expand("${PATH:+alternate}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualStrings("alternate", result);
    }

    // UNDEFINED is not set, so empty string
    const result2 = try expand("${UNDEFINED_12345:+alternate}", std.testing.allocator);
    defer std.testing.allocator.free(result2);
    try std.testing.expectEqualStrings("", result2);
}

// ---------------------------------------------------------------------------
// S-NEW-04: opt-in allow/deny list for environment expansion (CWE-200/CWE-610)
// ---------------------------------------------------------------------------

test "S-NEW-04: denied_vars blocks ${VAR} expansion" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    // PATH is guaranteed set on POSIX; deny it explicitly. The denied var
    // must NOT substitute the env value; it falls back to undefined_value.
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    const result = try expandWithOptions(
        "[${PATH}]",
        std.testing.allocator,
        .{ .denied_vars = &.{"PATH"} },
    );
    defer std.testing.allocator.free(result);
    // Denied -> undefined_value (empty by default), so the real PATH is absent.
    try std.testing.expectEqualStrings("[]", result);
    try std.testing.expect(mem.indexOf(u8, result, "/") == null);
}

test "S-NEW-04: denied_vars blocks $VAR (unbraced) expansion" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    const result = try expandWithOptions(
        "x=$PATH;",
        std.testing.allocator,
        .{ .denied_vars = &.{"PATH"} },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("x=;", result);
}

test "S-NEW-04: non-denied var still expands while another is denied" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    const home = environ.getenv("HOME") orelse return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    // Deny PATH but HOME is not denied, so HOME still expands.
    const result = try expandWithOptions(
        "${PATH}${HOME}",
        std.testing.allocator,
        .{ .denied_vars = &.{"PATH"} },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(home, result);
}

test "S-NEW-04: allowed_vars allowlist only expands listed names" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    const home = environ.getenv("HOME") orelse return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    // Only HOME is allowed; PATH (not listed) must not expand.
    const result = try expandWithOptions(
        "${PATH}${HOME}",
        std.testing.allocator,
        .{ .allowed_vars = &.{"HOME"} },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(home, result);
}

test "S-NEW-04: deny overrides allow (precedence)" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    // PATH is both allowed and denied -> deny wins.
    const result = try expandWithOptions(
        "[${PATH}]",
        std.testing.allocator,
        .{ .allowed_vars = &.{"PATH"}, .denied_vars = &.{"PATH"} },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("[]", result);
}

test "S-NEW-04: blocked var honors undefined_value" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    const result = try expandWithOptions(
        "${PATH}",
        std.testing.allocator,
        .{ .denied_vars = &.{"PATH"}, .undefined_value = "BLOCKED" },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("BLOCKED", result);
}

test "S-NEW-04: blocked var with modifier uses default branch" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    // PATH is set but denied, so ${PATH:-fallback} must yield the default,
    // never the real PATH value.
    const result = try expandWithOptions(
        "${PATH:-fallback}",
        std.testing.allocator,
        .{ .denied_vars = &.{"PATH"} },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("fallback", result);
}

test "S-NEW-04: strict mode treats denied var as undefined" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    const result = expandWithOptions(
        "${PATH}",
        std.testing.allocator,
        .{ .denied_vars = &.{"PATH"}, .strict = true },
    );
    try std.testing.expectError(ExpandError.UndefinedVariable, result);
}

test "S-NEW-04: default (no allow/deny) expansion unchanged" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH")) |path| {
        const result = try expand("${PATH}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualStrings(path, result);
    }
}

test "S-NEW-04: secret-name heuristic blocks token/secret/key/password" {
    // The convenience heuristic is opt-in via deny_secret_looking; it must
    // block secret-looking names even when otherwise allowed.
    try std.testing.expect(isSecretLooking("AWS_SECRET_ACCESS_KEY"));
    try std.testing.expect(isSecretLooking("VAULT_TOKEN"));
    try std.testing.expect(isSecretLooking("DB_PASSWORD"));
    try std.testing.expect(isSecretLooking("api_key"));
    try std.testing.expect(isSecretLooking("MY_CREDENTIAL"));
    try std.testing.expect(!isSecretLooking("PATH"));
    try std.testing.expect(!isSecretLooking("HOME"));
}

test "S-NEW-04: deny_secret_looking blocks secret-named env vars" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    // PATH does not look secret, so it expands; a secret-looking ref does not.
    const result = try expandWithOptions(
        "${PATH}|${MY_SECRET_TOKEN}",
        std.testing.allocator,
        .{ .deny_secret_looking = true },
    );
    defer std.testing.allocator.free(result);
    try std.testing.expect(mem.endsWith(u8, result, "|"));
}

test "S-NEW-04: expandStruct honors denied_vars" {
    if (comptime environ.is_windows) return error.SkipZigTest;
    if (environ.getenv("PATH") == null) return error.SkipZigTest;

    const S = struct { value: []const u8 };
    var s = S{ .value = "p=${PATH}" };
    try expandStruct(S, &s, std.testing.allocator, .{ .denied_vars = &.{"PATH"} });
    defer std.testing.allocator.free(s.value);
    try std.testing.expectEqualStrings("p=", s.value);
}
