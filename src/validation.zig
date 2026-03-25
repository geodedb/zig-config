// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Validation Module
//!
//! Provides validation utilities for configuration values including:
//! - Regex pattern validation (#10)
//! - Custom validation functions (#11)
//! - Common validators (email, URL, IP, etc.)
//!
//! Example usage:
//! ```zig
//! const validation = @import("validation");
//!
//! var validator = validation.Validator.init(allocator);
//! defer validator.deinit();
//!
//! // Add regex pattern validation
//! try validator.pattern("email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
//!
//! // Add custom validation function
//! try validator.custom("port", struct {
//!     fn validate(value: []const u8) bool {
//!         const port = std.fmt.parseInt(u16, value, 10) catch return false;
//!         return port >= 1 and port <= 65535;
//!     }
//! }.validate);
//!
//! // Validate a value
//! const result = validator.validate("email", "test@example.com");
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Validation errors (unified from validate.zig and validation.zig, #110)
pub const ValidationError = error{
    // Pattern/framework errors (from validation.zig)
    InvalidPattern,
    ValidationFailed,
    UnknownField,
    OutOfMemory,
    // Simple validator errors (from validate.zig)
    /// Value is required but missing
    Required,
    /// Value is too short
    TooShort,
    /// Value is too long
    TooLong,
    /// Value is not in allowed range
    OutOfRange,
    /// Value does not match pattern
    PatternMismatch,
    /// Value is not in allowed set
    NotInSet,
    /// Custom validation failed
    CustomFailed,
};

/// Result of a validation check
pub const ValidationResult = struct {
    valid: bool,
    field: []const u8,
    message: ?[]const u8,

    pub fn ok(field: []const u8) ValidationResult {
        return .{ .valid = true, .field = field, .message = null };
    }

    pub fn fail(field: []const u8, message: []const u8) ValidationResult {
        return .{ .valid = false, .field = field, .message = message };
    }
};

/// Custom validation function type
pub const ValidatorFn = *const fn (value: []const u8) bool;

/// Custom validation function with context
pub const ValidatorWithContextFn = *const fn (value: []const u8, context: ?*anyopaque) bool;

/// Rule type enum
const RuleType = enum {
    pattern,
    custom,
    custom_with_context,
    range,
    length,
    one_of,
    required,
};

/// Validation rule
const ValidationRule = struct {
    field: []const u8,
    rule_type: RuleType,
    /// Pattern string for regex validation (simplified pattern matching)
    pattern: ?[]const u8 = null,
    /// Custom validation function
    custom_fn: ?ValidatorFn = null,
    /// Custom validation function with context
    custom_with_context_fn: ?ValidatorWithContextFn = null,
    /// Context for custom_with_context_fn
    context: ?*anyopaque = null,
    /// Min value for range validation
    min: ?i64 = null,
    /// Max value for range validation
    max: ?i64 = null,
    /// Min length for length validation
    min_len: ?usize = null,
    /// Max length for length validation
    max_len: ?usize = null,
    /// Allowed values for one_of validation
    allowed_values: ?[]const []const u8 = null,
    /// Error message
    message: []const u8 = "Validation failed",
};

/// Configuration validator with support for patterns and custom functions
pub const Validator = struct {
    allocator: Allocator,
    rules: std.ArrayListUnmanaged(ValidationRule),
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator) Validator {
        return .{
            .allocator = allocator,
            .rules = .{},
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Validator) void {
        self.rules.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Add a regex pattern validation rule
    /// Note: This uses simplified pattern matching, not full regex
    pub fn pattern(self: *Validator, field: []const u8, pat: []const u8) !void {
        try self.patternWithMessage(field, pat, "Value does not match required pattern");
    }

    /// Add a regex pattern validation rule with custom message
    pub fn patternWithMessage(self: *Validator, field: []const u8, pat: []const u8, message: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_pattern = try self.arena.allocator().dupe(u8, pat);
        const owned_message = try self.arena.allocator().dupe(u8, message);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .pattern,
            .pattern = owned_pattern,
            .message = owned_message,
        });
    }

    /// Add a custom validation function
    pub fn custom(self: *Validator, field: []const u8, validator_fn: ValidatorFn) !void {
        try self.customWithMessage(field, validator_fn, "Custom validation failed");
    }

    /// Add a custom validation function with message
    pub fn customWithMessage(self: *Validator, field: []const u8, validator_fn: ValidatorFn, message: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_message = try self.arena.allocator().dupe(u8, message);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .custom,
            .custom_fn = validator_fn,
            .message = owned_message,
        });
    }

    /// Add a custom validation function with context
    pub fn customWithContext(self: *Validator, field: []const u8, validator_fn: ValidatorWithContextFn, context: ?*anyopaque) !void {
        try self.customWithContextAndMessage(field, validator_fn, context, "Custom validation failed");
    }

    /// Add a custom validation function with context and message
    pub fn customWithContextAndMessage(self: *Validator, field: []const u8, validator_fn: ValidatorWithContextFn, context: ?*anyopaque, message: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_message = try self.arena.allocator().dupe(u8, message);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .custom_with_context,
            .custom_with_context_fn = validator_fn,
            .context = context,
            .message = owned_message,
        });
    }

    /// Add a numeric range validation rule
    pub fn range(self: *Validator, field: []const u8, min: ?i64, max: ?i64) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .range,
            .min = min,
            .max = max,
            .message = "Value out of range",
        });
    }

    /// Add a string length validation rule
    pub fn length(self: *Validator, field: []const u8, min_len: ?usize, max_len: ?usize) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .length,
            .min_len = min_len,
            .max_len = max_len,
            .message = "Invalid length",
        });
    }

    /// Add an enumeration validation rule (value must be one of the allowed values)
    pub fn oneOf(self: *Validator, field: []const u8, allowed: []const []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_allowed = try self.arena.allocator().alloc([]const u8, allowed.len);
        for (allowed, 0..) |val, i| {
            owned_allowed[i] = try self.arena.allocator().dupe(u8, val);
        }

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .one_of,
            .allowed_values = owned_allowed,
            .message = "Value not in allowed set",
        });
    }

    /// Add a required field validation rule
    pub fn required(self: *Validator, field: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .required,
            .message = "Field is required",
        });
    }

    /// Validate a single field value
    pub fn validate(self: *const Validator, field: []const u8, value: []const u8) ValidationResult {
        for (self.rules.items) |rule| {
            if (mem.eql(u8, rule.field, field)) {
                if (!self.checkRule(&rule, value)) {
                    return ValidationResult.fail(field, rule.message);
                }
            }
        }
        return ValidationResult.ok(field);
    }

    /// Validate all fields in a map
    pub fn validateAll(self: *const Validator, values: std.StringHashMap([]const u8)) ![]ValidationResult {
        var results: std.ArrayListUnmanaged(ValidationResult) = .{};
        errdefer results.deinit(self.allocator);

        // Check each rule
        for (self.rules.items) |rule| {
            if (rule.rule_type == .required) {
                if (values.get(rule.field) == null) {
                    try results.append(self.allocator, ValidationResult.fail(rule.field, rule.message));
                    continue;
                }
            }

            if (values.get(rule.field)) |value| {
                if (!self.checkRule(&rule, value)) {
                    try results.append(self.allocator, ValidationResult.fail(rule.field, rule.message));
                }
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Check if all validations pass
    pub fn isValid(self: *const Validator, values: std.StringHashMap([]const u8)) bool {
        for (self.rules.items) |rule| {
            if (rule.rule_type == .required) {
                if (values.get(rule.field) == null) {
                    return false;
                }
            }

            if (values.get(rule.field)) |value| {
                if (!self.checkRule(&rule, value)) {
                    return false;
                }
            }
        }
        return true;
    }

    fn checkRule(self: *const Validator, rule: *const ValidationRule, value: []const u8) bool {
        _ = self;
        switch (rule.rule_type) {
            .pattern => {
                if (rule.pattern) |pat| {
                    return matchPattern(pat, value);
                }
                return true;
            },
            .custom => {
                if (rule.custom_fn) |func| {
                    return func(value);
                }
                return true;
            },
            .custom_with_context => {
                if (rule.custom_with_context_fn) |func| {
                    return func(value, rule.context);
                }
                return true;
            },
            .range => {
                const num = std.fmt.parseInt(i64, value, 10) catch return false;
                if (rule.min) |min| {
                    if (num < min) return false;
                }
                if (rule.max) |max| {
                    if (num > max) return false;
                }
                return true;
            },
            .length => {
                if (rule.min_len) |min| {
                    if (value.len < min) return false;
                }
                if (rule.max_len) |max| {
                    if (value.len > max) return false;
                }
                return true;
            },
            .one_of => {
                if (rule.allowed_values) |allowed| {
                    for (allowed) |allowed_value| {
                        if (mem.eql(u8, value, allowed_value)) return true;
                    }
                    return false;
                }
                return true;
            },
            .required => {
                return value.len > 0;
            },
        }
    }
};

// ============================================================================
// Pattern Matching Sub-Functions (QUAL-11 refactoring)
// ============================================================================

/// Result of a character matcher operation -- contains how many pattern
/// bytes to advance and a function to test whether a given input byte matches.
const CharMatchResult = struct {
    /// Number of pattern bytes consumed by this construct
    advance: usize,
    /// Closure context for the match function
    context: MatchContext,

    const MatchContext = union(enum) {
        escape: u8,
        char_class: struct {
            content: []const u8,
            negated: bool,
        },
        dot: void,
        literal: u8,
    };

    /// Test whether the given input byte matches this pattern construct
    fn matcher(self: CharMatchResult, input_char: u8) bool {
        return switch (self.context) {
            .escape => |escape_char| matchEscapeChar(escape_char, input_char),
            .char_class => |cc| blk: {
                const raw = matchCharClass(cc.content, input_char);
                break :blk if (cc.negated) !raw else raw;
            },
            .dot => true,
            .literal => |c| c == input_char,
        };
    }
};

/// Quantifier types recognized by the pattern engine
const QuantifierType = enum {
    star, // *
    plus, // +
    question, // ?
};

/// Result of parsing a quantifier at a given position
const QuantifierResult = struct {
    quantifier: QuantifierType,
    /// Number of pattern bytes consumed (always 1)
    advance: usize,
};

/// Handle escape sequences in the pattern starting at `pos`.
/// Returns a CharMatchResult if pattern[pos] == '\\' and pos+1 < pattern.len,
/// or null if this position is not an escape sequence.
///
/// Supported escape classes:
///   \d → digit, \D → non-digit
///   \w → word char, \W → non-word char
///   \s → whitespace, \S → non-whitespace
///   \\ → literal backslash, \. → literal dot
///   \X → literal X (for any other X)
fn handleEscape(pattern: []const u8, pos: usize) ?CharMatchResult {
    if (pos >= pattern.len or pattern[pos] != '\\') return null;
    if (pos + 1 >= pattern.len) return null;

    return CharMatchResult{
        .advance = 2,
        .context = .{ .escape = pattern[pos + 1] },
    };
}

/// Match a single input character against an escape class character.
fn matchEscapeChar(escape_char: u8, input_char: u8) bool {
    return switch (escape_char) {
        'd' => std.ascii.isDigit(input_char),
        'D' => !std.ascii.isDigit(input_char),
        'w' => std.ascii.isAlphanumeric(input_char) or input_char == '_',
        'W' => !(std.ascii.isAlphanumeric(input_char) or input_char == '_'),
        's' => std.ascii.isWhitespace(input_char),
        'S' => !std.ascii.isWhitespace(input_char),
        else => input_char == escape_char,
    };
}

/// Handle character class `[...]` or `[^...]` starting at `pos`.
/// Returns a CharMatchResult if pattern[pos] == '[' and a closing ']' is found,
/// or null otherwise.
fn handleCharClass(pattern: []const u8, pos: usize) ?CharMatchResult {
    if (pos >= pattern.len or pattern[pos] != '[') return null;

    const class_end = findClassEnd(pattern[pos..]) orelse return null;
    const class_end_abs = pos + class_end;

    const negated = (pos + 1 < pattern.len and pattern[pos + 1] == '^');
    const class_start = if (negated) pos + 2 else pos + 1;
    const class_content = pattern[class_start..class_end_abs];

    return CharMatchResult{
        .advance = class_end + 1, // skip past ']'
        .context = .{ .char_class = .{
            .content = class_content,
            .negated = negated,
        } },
    };
}

/// Check whether `pattern[pos]` is a quantifier (`*`, `+`, or `?`).
/// Returns a QuantifierResult or null.
fn handleQuantifier(pattern: []const u8, pos: usize) ?QuantifierResult {
    if (pos >= pattern.len) return null;
    const q: ?QuantifierType = switch (pattern[pos]) {
        '*' => .star,
        '+' => .plus,
        '?' => .question,
        else => null,
    };
    if (q) |quantifier| {
        return QuantifierResult{ .quantifier = quantifier, .advance = 1 };
    }
    return null;
}

/// Simplified pattern matching (not full regex, but covers common cases)
/// Supports:
/// - ^ (start anchor)
/// - $ (end anchor)
/// - . (any single char)
/// - * (zero or more of previous)
/// - + (one or more of previous)
/// - ? (zero or one of previous)
/// - [...] (character class)
/// - [^...] (negated character class)
/// - \d (digit)
/// - \w (word char)
/// - \s (whitespace)
///
/// Security: Uses bounded iterations to prevent ReDoS attacks (CWE-1333).
/// Maximum iterations: 10000 (configurable via matchPatternBounded)
pub fn matchPattern(pattern: []const u8, input: []const u8) bool {
    return matchPatternBounded(pattern, input, 10000);
}

/// Pattern matching with explicit iteration bound.
/// Returns false if iteration limit is exceeded (prevents ReDoS).
pub fn matchPatternBounded(pattern: []const u8, input: []const u8, max_iterations: usize) bool {
    var iterations: usize = 0;
    return matchPatternImpl(pattern, input, 0, 0, max_iterations, &iterations);
}

fn matchPatternImpl(pattern: []const u8, input: []const u8, pat_idx: usize, input_idx: usize, max_iterations: usize, iterations: *usize) bool {
    var pi = pat_idx;
    var ii = input_idx;

    while (pi < pattern.len) {
        // Security: Check iteration limit to prevent ReDoS (CWE-1333)
        iterations.* += 1;
        if (iterations.* > max_iterations) {
            return false; // Iteration limit exceeded - fail safe
        }

        // Handle anchors
        if (pattern[pi] == '$') {
            if (pi + 1 == pattern.len) return ii == input.len;
            pi += 1;
            continue;
        }
        if (pattern[pi] == '^') {
            if (pi == 0 and ii != 0) return false;
            pi += 1;
            continue;
        }

        // Parse the current atom (char class, escape, dot, or literal)
        const atom = parseAtom(pattern, pi) orelse return false;
        const after_atom = pi + atom.advance;

        // Check for a quantifier following the atom
        if (handleQuantifier(pattern, after_atom)) |q| {
            const after_q = after_atom + q.advance;
            switch (q.quantifier) {
                .plus => return applyPlus(pattern, input, atom, after_q, ii, max_iterations, iterations),
                .star => return applyStar(pattern, input, atom, after_q, &ii, max_iterations, iterations),
                .question => return applyQuestion(pattern, input, atom, after_q, ii, max_iterations, iterations),
            }
        }

        // No quantifier -- single match
        if (ii >= input.len) return false;
        if (!atom.matcher(input[ii])) return false;
        pi = after_atom;
        ii += 1;
    }

    // Pattern exhausted - check if input is also exhausted
    return ii == input.len;
}

/// Parse the next atom at `pi` in the pattern.
/// An atom is a character class, escape sequence, dot, or literal character.
fn parseAtom(pattern: []const u8, pi: usize) ?CharMatchResult {
    if (pi >= pattern.len) return null;

    // Character class [...]
    if (handleCharClass(pattern, pi)) |cc| return cc;

    // Escape sequence \d, \w, \s, etc.
    if (handleEscape(pattern, pi)) |esc| return esc;

    // Dot (any character)
    if (pattern[pi] == '.') {
        return CharMatchResult{ .advance = 1, .context = .dot };
    }

    // Literal character
    return CharMatchResult{ .advance = 1, .context = .{ .literal = pattern[pi] } };
}

/// Apply the `+` (one or more) quantifier: greedy match then try continuation.
fn applyPlus(pattern: []const u8, input: []const u8, atom: CharMatchResult, after_q: usize, input_idx: usize, max_iterations: usize, iterations: *usize) bool {
    var ii = input_idx;
    // Must match at least once
    if (ii >= input.len or !atom.matcher(input[ii])) return false;
    ii += 1;
    // Greedy match more
    while (ii < input.len and atom.matcher(input[ii])) {
        ii += 1;
    }
    return matchPatternImpl(pattern, input, after_q, ii, max_iterations, iterations);
}

/// Apply the `*` (zero or more) quantifier: try zero first, then greedy with bounded backtracking.
fn applyStar(pattern: []const u8, input: []const u8, atom: CharMatchResult, after_q: usize, ii: *usize, max_iterations: usize, iterations: *usize) bool {
    // Try zero matches first
    if (matchPatternImpl(pattern, input, after_q, ii.*, max_iterations, iterations)) return true;
    // Try more with bounded backtracking
    var backtrack_count: usize = 0;
    const max_backtrack: usize = 100;
    while (ii.* < input.len and atom.matcher(input[ii.*]) and backtrack_count < max_backtrack) {
        ii.* += 1;
        backtrack_count += 1;
        if (matchPatternImpl(pattern, input, after_q, ii.*, max_iterations, iterations)) return true;
    }
    return false;
}

/// Apply the `?` (zero or one) quantifier.
fn applyQuestion(pattern: []const u8, input: []const u8, atom: CharMatchResult, after_q: usize, input_idx: usize, max_iterations: usize, iterations: *usize) bool {
    // Try zero
    if (matchPatternImpl(pattern, input, after_q, input_idx, max_iterations, iterations)) return true;
    // Try one
    if (input_idx < input.len and atom.matcher(input[input_idx])) {
        return matchPatternImpl(pattern, input, after_q, input_idx + 1, max_iterations, iterations);
    }
    return false;
}

fn findClassEnd(pattern: []const u8) ?usize {
    if (pattern.len == 0 or pattern[0] != '[') return null;

    var i: usize = 1;
    while (i < pattern.len) {
        if (pattern[i] == ']' and i > 1) {
            return i;
        }
        i += 1;
    }
    return null;
}

fn matchCharClass(class: []const u8, char: u8) bool {
    var i: usize = 0;
    while (i < class.len) {
        // Range a-z
        if (i + 2 < class.len and class[i + 1] == '-') {
            if (char >= class[i] and char <= class[i + 2]) {
                return true;
            }
            i += 3;
            continue;
        }

        // Single character
        if (class[i] == char) {
            return true;
        }
        i += 1;
    }
    return false;
}

// ============================================================================
// Common Pre-built Validators
// ============================================================================

/// Validates that a string looks like an email address
pub fn isEmail(value: []const u8) bool {
    // Simple email validation: something@something.something
    const at_pos = mem.indexOf(u8, value, "@") orelse return false;
    if (at_pos == 0 or at_pos >= value.len - 1) return false;

    const domain = value[at_pos + 1 ..];
    const dot_pos = mem.indexOf(u8, domain, ".") orelse return false;
    if (dot_pos == 0 or dot_pos >= domain.len - 1) return false;

    return true;
}

/// Validates that a string is a valid URL
pub fn isUrl(value: []const u8) bool {
    return mem.startsWith(u8, value, "http://") or
        mem.startsWith(u8, value, "https://") or
        mem.startsWith(u8, value, "ftp://");
}

/// Validates that a string is a valid IPv4 address
pub fn isIPv4(value: []const u8) bool {
    var parts: usize = 0;
    var current: u32 = 0;
    var digits: u8 = 0;

    for (value) |c| {
        if (c == '.') {
            if (digits == 0 or current > 255) return false;
            parts += 1;
            current = 0;
            digits = 0;
        } else if (std.ascii.isDigit(c)) {
            current = current * 10 + (c - '0');
            digits += 1;
            if (digits > 3) return false;
        } else {
            return false;
        }
    }

    // Check last part
    if (digits == 0 or current > 255) return false;
    parts += 1;

    return parts == 4;
}

/// Validates that a string is a valid port number (1-65535)
pub fn isPort(value: []const u8) bool {
    const port_num = std.fmt.parseInt(u16, value, 10) catch return false;
    return port_num >= 1;
}

/// Validates that a string contains only alphanumeric characters
pub fn isAlphanumeric(value: []const u8) bool {
    for (value) |c| {
        if (!std.ascii.isAlphanumeric(c)) return false;
    }
    return value.len > 0;
}

/// Validates that a string is a valid hostname
pub fn isHostname(value: []const u8) bool {
    if (value.len == 0 or value.len > 253) return false;

    // Hostname cannot start with a dash
    if (value[0] == '-') return false;

    var label_len: usize = 0;
    var prev_char: u8 = 0;
    for (value) |c| {
        if (c == '.') {
            // Label cannot be empty or end with dash
            if (label_len == 0 or label_len > 63 or prev_char == '-') return false;
            label_len = 0;
        } else if (std.ascii.isAlphanumeric(c) or c == '-') {
            // Label cannot start with dash
            if (label_len == 0 and c == '-') return false;
            label_len += 1;
        } else {
            return false;
        }
        prev_char = c;
    }

    // Last label cannot be empty or end with dash
    if (label_len == 0 or label_len > 63 or prev_char == '-') return false;

    return true;
}

/// Validates that a string is not empty
pub fn notEmpty(value: []const u8) bool {
    return value.len > 0;
}

/// Validates that a string is a valid boolean representation
pub fn isBool(value: []const u8) bool {
    return mem.eql(u8, value, "true") or
        mem.eql(u8, value, "false") or
        mem.eql(u8, value, "1") or
        mem.eql(u8, value, "0") or
        mem.eql(u8, value, "yes") or
        mem.eql(u8, value, "no");
}

// ============================================================================
// Simple Error-Returning Validators (merged from validate.zig, #110)
// ============================================================================

/// Simple validation result (from validate.zig).
/// For field-level validation results, use ValidationResult instead.
pub const SimpleValidationResult = struct {
    valid: bool,
    errors: []const []const u8,

    pub fn ok() SimpleValidationResult {
        return .{ .valid = true, .errors = &.{} };
    }

    pub fn fail(errors: []const []const u8) SimpleValidationResult {
        return .{ .valid = false, .errors = errors };
    }
};

/// Validate that a string is not empty
pub fn required(value: ?[]const u8) ValidationError!void {
    if (value == null or value.?.len == 0) {
        return ValidationError.Required;
    }
}

/// Validate string minimum length
pub fn minLength(value: []const u8, min: usize) ValidationError!void {
    if (value.len < min) {
        return ValidationError.TooShort;
    }
}

/// Validate string maximum length
pub fn maxLength(value: []const u8, max: usize) ValidationError!void {
    if (value.len > max) {
        return ValidationError.TooLong;
    }
}

/// Validate integer range
pub fn intRange(value: i64, min: i64, max: i64) ValidationError!void {
    if (value < min or value > max) {
        return ValidationError.OutOfRange;
    }
}

/// Validate value is in allowed set
pub fn oneOf(value: []const u8, allowed: []const []const u8) ValidationError!void {
    for (allowed) |a| {
        if (mem.eql(u8, value, a)) {
            return;
        }
    }
    return ValidationError.NotInSet;
}

/// Validate port number
pub fn port(value: u16) ValidationError!void {
    if (value == 0) {
        return ValidationError.OutOfRange;
    }
}

/// Validate hostname.
/// P3-M6: Delegates to the thorough `isHostname` validator so both
/// the bool-returning and error-returning APIs apply identical rules
/// (label length, leading/trailing dash, etc.).
pub fn hostname(value: []const u8) ValidationError!void {
    if (!isHostname(value)) {
        if (value.len == 0 or value.len > 253) {
            return ValidationError.TooLong;
        }
        return ValidationError.PatternMismatch;
    }
}

/// Validate URL.
/// P3-M6: Delegates to the thorough `isUrl` validator so both the
/// bool-returning and error-returning APIs apply identical rules.
pub fn url(value: []const u8) ValidationError!void {
    if (!isUrl(value)) {
        return ValidationError.PatternMismatch;
    }
}

/// Validate email address.
/// P3-M6: Delegates to the thorough `isEmail` validator so both the
/// bool-returning and error-returning APIs apply identical rules
/// (local part, domain with dot, etc.).
pub fn email(value: []const u8) ValidationError!void {
    if (!isEmail(value)) {
        return ValidationError.PatternMismatch;
    }
}

/// Validate file path exists
pub fn pathExists(path: []const u8) ValidationError!void {
    std.fs.cwd().access(path, .{}) catch {
        return ValidationError.CustomFailed;
    };
}

// D-02: Tests extracted to validation_test.zig to reduce file size.
test {
    _ = @import("validation_test.zig");
}
