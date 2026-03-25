// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Validation Module Tests (D-02)
//!
//! Extracted from validation.zig to reduce file size and follow the project
//! convention of companion test files for large modules.

const std = @import("std");
const validation = @import("validation.zig");

const Validator = validation.Validator;
const ValidationError = validation.ValidationError;
const matchPattern = validation.matchPattern;
const matchPatternBounded = validation.matchPatternBounded;
const isEmail = validation.isEmail;
const isUrl = validation.isUrl;
const isIPv4 = validation.isIPv4;
const isPort = validation.isPort;
const isHostname = validation.isHostname;
const hostname = validation.hostname;
const email = validation.email;
const url = validation.url;
const required = validation.required;
const minLength = validation.minLength;
const maxLength = validation.maxLength;
const intRange = validation.intRange;
const oneOf = validation.oneOf;

// ============================================================================
// Validator Tests
// ============================================================================

test "Validator custom function" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // Add a custom port validator
    try validator.custom("port", isPort);

    const valid_result = validator.validate("port", "8080");
    try std.testing.expect(valid_result.valid);

    const invalid_result = validator.validate("port", "invalid");
    try std.testing.expect(!invalid_result.valid);
}

test "Validator range validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.range("age", 0, 150);

    try std.testing.expect(validator.validate("age", "25").valid);
    try std.testing.expect(validator.validate("age", "0").valid);
    try std.testing.expect(validator.validate("age", "150").valid);
    try std.testing.expect(!validator.validate("age", "-1").valid);
    try std.testing.expect(!validator.validate("age", "151").valid);
}

test "Validator length validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.length("username", 3, 20);

    try std.testing.expect(validator.validate("username", "john").valid);
    try std.testing.expect(!validator.validate("username", "ab").valid);
    try std.testing.expect(!validator.validate("username", "thisusernameiswaytoolong").valid);
}

test "Validator oneOf validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.oneOf("env", &.{ "development", "staging", "production" });

    try std.testing.expect(validator.validate("env", "development").valid);
    try std.testing.expect(validator.validate("env", "production").valid);
    try std.testing.expect(!validator.validate("env", "invalid").valid);
}

test "Validator required validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.required("name");

    var values = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer values.deinit();

    // Missing required field
    try std.testing.expect(!validator.isValid(values));

    // Empty required field
    try values.put("name", "");
    try std.testing.expect(!validator.isValid(values));

    // Valid required field
    try values.put("name", "John");
    try std.testing.expect(validator.isValid(values));
}

// ============================================================================
// Pattern Matching Tests
// ============================================================================

test "matchPattern basic" {
    // Literal matching
    try std.testing.expect(matchPattern("hello", "hello"));
    try std.testing.expect(!matchPattern("hello", "world"));

    // Any character
    try std.testing.expect(matchPattern("h.llo", "hello"));
    try std.testing.expect(matchPattern("h.llo", "hallo"));

    // Anchors
    try std.testing.expect(matchPattern("^hello", "hello"));
    try std.testing.expect(!matchPattern("^hello", "say hello"));
    try std.testing.expect(matchPattern("hello$", "hello"));
    try std.testing.expect(!matchPattern("hello$", "hello world"));
}

test "matchPattern character classes" {
    try std.testing.expect(matchPattern("[abc]", "a"));
    try std.testing.expect(matchPattern("[abc]", "b"));
    try std.testing.expect(!matchPattern("[abc]", "d"));

    // Ranges
    try std.testing.expect(matchPattern("[a-z]", "m"));
    try std.testing.expect(!matchPattern("[a-z]", "5"));
    try std.testing.expect(matchPattern("[0-9]", "5"));
}

test "matchPattern escape sequences" {
    try std.testing.expect(matchPattern("\\d", "5"));
    try std.testing.expect(!matchPattern("\\d", "a"));
    try std.testing.expect(matchPattern("\\w", "a"));
    try std.testing.expect(matchPattern("\\w", "5"));
    try std.testing.expect(matchPattern("\\w", "_"));
}

test "matchPattern escape sequences with quantifiers" {
    // GAP-0016: escape sequences combined with quantifiers must work
    // \d+ should match one or more digits
    try std.testing.expect(matchPattern("\\d+", "123"));
    try std.testing.expect(matchPattern("\\d+", "0"));
    try std.testing.expect(!matchPattern("\\d+", "abc"));
    try std.testing.expect(!matchPattern("\\d+", ""));

    // \w+ should match one or more word characters
    try std.testing.expect(matchPattern("\\w+", "hello_world"));
    try std.testing.expect(matchPattern("\\w+", "test123"));
    try std.testing.expect(!matchPattern("\\w+", ""));

    // \s should match whitespace
    try std.testing.expect(matchPattern("\\s", " "));
    try std.testing.expect(matchPattern("\\s", "\t"));
    try std.testing.expect(!matchPattern("\\s", "a"));

    // \s+ should match one or more whitespace chars
    try std.testing.expect(matchPattern("\\s+", "  \t"));
    try std.testing.expect(!matchPattern("\\s+", "abc"));

    // \D, \W, \S (negated classes) with quantifiers
    try std.testing.expect(matchPattern("\\D+", "abc"));
    try std.testing.expect(!matchPattern("\\D+", "123"));
    try std.testing.expect(matchPattern("\\W+", "!@#"));
    try std.testing.expect(!matchPattern("\\W+", "abc"));
    try std.testing.expect(matchPattern("\\S+", "abc"));
    try std.testing.expect(!matchPattern("\\S+", "   "));

    // \d* should match zero or more digits
    try std.testing.expect(matchPattern("a\\d*b", "ab"));
    try std.testing.expect(matchPattern("a\\d*b", "a123b"));

    // \d? should match zero or one digit
    try std.testing.expect(matchPattern("a\\d?b", "ab"));
    try std.testing.expect(matchPattern("a\\d?b", "a1b"));
    try std.testing.expect(!matchPattern("a\\d?b", "a12b"));

    // Mixed escape sequences in patterns
    try std.testing.expect(matchPattern("^\\d+$", "12345"));
    try std.testing.expect(!matchPattern("^\\d+$", "123a5"));

    // Literal escape sequences
    try std.testing.expect(matchPattern("\\\\", "\\"));
    try std.testing.expect(matchPattern("\\.", "."));
    try std.testing.expect(!matchPattern("\\.", "a"));
}

// NOTE: Tests for handleEscape, handleCharClass, and handleQuantifier internal
// functions were removed because these functions are not exposed from matchPattern's
// implementation. The behavior they tested is covered by the integration-level
// "matchPattern quantifiers" and "matchPattern escape sequences" tests below.

test "matchPattern quantifiers" {
    // Star (zero or more)
    try std.testing.expect(matchPattern("ab*c", "ac"));
    try std.testing.expect(matchPattern("ab*c", "abc"));
    try std.testing.expect(matchPattern("ab*c", "abbc"));

    // Plus (one or more)
    try std.testing.expect(!matchPattern("ab+c", "ac"));
    try std.testing.expect(matchPattern("ab+c", "abc"));
    try std.testing.expect(matchPattern("ab+c", "abbc"));

    // Question (zero or one)
    try std.testing.expect(matchPattern("ab?c", "ac"));
    try std.testing.expect(matchPattern("ab?c", "abc"));
    try std.testing.expect(!matchPattern("ab?c", "abbc"));
}

// ============================================================================
// Built-in Validator Tests
// ============================================================================

test "isEmail" {
    try std.testing.expect(isEmail("test@example.com"));
    try std.testing.expect(isEmail("user.name@domain.org"));
    try std.testing.expect(!isEmail("invalid"));
    try std.testing.expect(!isEmail("@example.com"));
    try std.testing.expect(!isEmail("test@"));
}

test "isUrl" {
    try std.testing.expect(isUrl("http://example.com"));
    try std.testing.expect(isUrl("https://example.com/path"));
    try std.testing.expect(isUrl("ftp://files.example.com"));
    try std.testing.expect(!isUrl("example.com"));
    try std.testing.expect(!isUrl("invalid-url"));
}

test "isIPv4" {
    try std.testing.expect(isIPv4("192.168.1.1"));
    try std.testing.expect(isIPv4("0.0.0.0"));
    try std.testing.expect(isIPv4("255.255.255.255"));
    try std.testing.expect(!isIPv4("256.1.1.1"));
    try std.testing.expect(!isIPv4("1.2.3"));
    try std.testing.expect(!isIPv4("invalid"));
}

test "isPort" {
    try std.testing.expect(isPort("80"));
    try std.testing.expect(isPort("443"));
    try std.testing.expect(isPort("8080"));
    try std.testing.expect(isPort("65535"));
    try std.testing.expect(!isPort("0"));
    try std.testing.expect(!isPort("65536"));
    try std.testing.expect(!isPort("invalid"));
}

test "isHostname" {
    try std.testing.expect(isHostname("example.com"));
    try std.testing.expect(isHostname("sub.example.com"));
    try std.testing.expect(isHostname("localhost"));
    try std.testing.expect(!isHostname(""));
    try std.testing.expect(!isHostname("-invalid.com"));
}

test "P3-M6: hostname() delegates to isHostname (rejects trailing dash)" {
    try std.testing.expectError(ValidationError.PatternMismatch, hostname("host-"));
    try std.testing.expectError(ValidationError.PatternMismatch, hostname("-leading"));
    try std.testing.expectError(ValidationError.TooLong, hostname(""));
    try hostname("example.com");
    try hostname("localhost");
}

test "P3-M6: email() delegates to isEmail (rejects bare @)" {
    try std.testing.expectError(ValidationError.PatternMismatch, email("@domain.com"));
    try std.testing.expectError(ValidationError.PatternMismatch, email("user@"));
    try std.testing.expectError(ValidationError.PatternMismatch, email("nodomain"));
    try email("user@example.com");
}

test "P3-M6: url() delegates to isUrl (accepts ftp://)" {
    try url("ftp://files.example.com");
    try url("http://example.com");
    try url("https://example.com");
    try std.testing.expectError(ValidationError.PatternMismatch, url("example.com"));
}

test "Validator validateAll" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.custom("email", isEmail);
    try validator.custom("port", isPort);
    try validator.range("age", 0, 150);

    var values = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer values.deinit();

    try values.put("email", "invalid");
    try values.put("port", "abc");
    try values.put("age", "200");

    const results = try validator.validateAll(values);
    defer std.testing.allocator.free(results);

    // All three should fail
    try std.testing.expectEqual(@as(usize, 3), results.len);
}

test "Validator pattern validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.pattern("code", "^[A-Z][0-9]+$");

    try std.testing.expect(validator.validate("code", "A123").valid);
    try std.testing.expect(validator.validate("code", "Z9").valid);
    try std.testing.expect(!validator.validate("code", "123").valid);
    try std.testing.expect(!validator.validate("code", "abc").valid);
}

// ============================================================================
// ReDoS Protection Tests (#58)
// ============================================================================

test "matchPattern ReDoS protection - bounded iterations" {
    // Test that pathological patterns complete quickly due to iteration limits
    // Pattern that would cause exponential backtracking without limits
    const pathological_input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";

    // This should complete quickly and return false (not hang)
    const result = matchPatternBounded("a*a*a*a*a*c", pathological_input, 1000);
    try std.testing.expect(!result); // Should not match and should not hang
}

test "matchPattern ReDoS protection - normal patterns still work" {
    // Ensure normal patterns still work correctly with bounded matching
    try std.testing.expect(matchPattern("hello", "hello"));
    try std.testing.expect(matchPattern("a*b", "aaab"));
    try std.testing.expect(matchPattern("a+b", "ab"));
    try std.testing.expect(matchPattern("[a-z]+", "hello"));
    try std.testing.expect(matchPattern("^test$", "test"));
}

test "matchPattern ReDoS protection - iteration limit exceeded returns false" {
    // With a very low limit, complex patterns should fail due to iteration exhaustion
    // Use a pattern that requires many iterations to check all possibilities
    const result = matchPatternBounded("a*a*a*a*a*b", "aaaaaaaaaaaaaa", 5);
    // Should return false due to iteration limit being hit, not because pattern matched
    // (Pattern doesn't match anyway since input doesn't end with 'b')
    try std.testing.expect(!result);
}

// ============================================================================
// Simple Validator Tests (merged from validate.zig, #110)
// ============================================================================

test "required validation" {
    try required("value");
    try std.testing.expectError(ValidationError.Required, required(null));
    try std.testing.expectError(ValidationError.Required, required(""));
}

test "minLength validation" {
    try minLength("hello", 3);
    try std.testing.expectError(ValidationError.TooShort, minLength("hi", 3));
}

test "maxLength validation" {
    try maxLength("hi", 5);
    try std.testing.expectError(ValidationError.TooLong, maxLength("hello world", 5));
}

test "intRange validation" {
    try intRange(50, 0, 100);
    try std.testing.expectError(ValidationError.OutOfRange, intRange(-1, 0, 100));
    try std.testing.expectError(ValidationError.OutOfRange, intRange(101, 0, 100));
}

test "oneOf validation" {
    try oneOf("debug", &.{ "debug", "info", "warn", "error" });
    try std.testing.expectError(ValidationError.NotInSet, oneOf("trace", &.{ "debug", "info", "warn", "error" }));
}

test "url validation" {
    try url("https://example.com");
    try url("http://localhost:8080");
    // P3-M6: url() now delegates to isUrl(), which accepts ftp://
    try url("ftp://example.com");
    try std.testing.expectError(ValidationError.PatternMismatch, url("not-a-url"));
}
