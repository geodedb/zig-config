// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # File Size Limits (CWE-400 - Resource Exhaustion Prevention, #64)
//!
//! Centralized size-limit constants used across the config library to prevent
//! resource exhaustion from malicious or corrupted files.
//!
//! Different limits apply to different use cases based on security requirements.
//!
//! Rationale:
//! - Config files: 1 MB - Reasonable upper bound for configuration data (#111)
//! - Remote responses: 1 MB - Network responses should be bounded tightly
//! - Secret files: 64 KB - Secrets should be small; larger files are suspicious
//! - CLI output: 1 MB - Reasonable bound for tool output
//!
//! To override these limits, use the explicit readToEndAlloc parameter.

/// Maximum size for configuration files (1 MB)
/// Reduced from 10 MB to prevent excessive memory allocation (#111).
/// Config files over 1 MB are extremely unusual; this limit prevents
/// resource exhaustion from malicious or corrupted files.
pub const MAX_CONFIG_FILE_SIZE: usize = 1024 * 1024;

/// Maximum size for remote API responses (1 MB)
pub const MAX_REMOTE_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum size for secret files (64 KB)
/// Security: Secrets should be small; larger files may indicate misuse
pub const MAX_SECRET_FILE_SIZE: usize = 64 * 1024;

/// Maximum size for CLI command output (1 MB)
pub const MAX_CLI_OUTPUT_SIZE: usize = 1024 * 1024;

/// Maximum size for .env files (1 MB)
/// .env files are typically small; 1 MB is generous
pub const MAX_DOTENV_FILE_SIZE: usize = 1024 * 1024;
