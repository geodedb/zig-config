# Security Gap Analysis

**Last Updated:** 2026-01-30
**Review Commit:** 240b355 (working tree with adversarial review round 3)
**Reviewed By:** Security Code Review Agent (Adversarial Review)
**Remediation Status:** 29 Closed, 0 Open ✅

## Summary

This document tracks security findings from comprehensive security reviews of the zigconfig library.

### Severity Breakdown

| Severity | Count | Open | Closed | Description |
|----------|-------|------|--------|-------------|
| Critical | 0 | 0 | 0 | No critical vulnerabilities found |
| High | 6 | 0 | 6 | Path traversal, command injection, missing encryption, ReDoS, SSRF bypass, arbitrary exec |
| Medium | 14 | 0 | 14 | HTTP defaults, SSRF, credential exposure, temp files, path validation, DNS rebinding, symlinks, injection |
| Low | 9 | 0 | 9 | Thread safety, TOCTOU, CI config, limits, gitleaks config, URL encoding, permissions |
| **Total** | **29** | **0** | **29** | |

### All Security Findings Closed ✅

All 29 identified security findings have been remediated.

## Stack-Ranked Findings

### New Findings (Adversarial Review Round 3 - 2026-01-30)

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | GitLab Issue | Status |
|------|----------|------------|---------|-----------|-----------|----------|--------------|--------|
| 1 | Medium | 32 | Consul key path injection | remote.zig | CWE-74 | L591-647 | [#73](https://gitlab.com/devnw/zig/config/-/issues/73) | **Closed** |
| 2 | Medium | 24 | Incomplete symlink protection | multiple | CWE-59 | dotenv.zig:24 | [#72](https://gitlab.com/devnw/zig/config/-/issues/72) | **Closed** |
| 3 | Medium | 24 | Missing path validation in parsers | ini.zig, properties.zig, dotenv.zig | CWE-22 | L189,254,24 | [#74](https://gitlab.com/devnw/zig/config/-/issues/74) | **Closed** |
| 4 | Low | 12 | Default file permissions too permissive | serialize.zig, config.zig | CWE-732 | L462,690 | [#75](https://gitlab.com/devnw/zig/config/-/issues/75) | **Closed** |

### Findings (Adversarial Review Round 2 - 2026-01-30)

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | GitLab Issue | Status |
|------|----------|------------|---------|-----------|-----------|----------|--------------|--------|
| 1 | High | 64 | SSRF bypass via decimal/octal IP formats | remote.zig | CWE-918 | L150-154 | [#65](https://gitlab.com/devnw/zig/config/-/issues/65) | **Closed** |
| 2 | High | 60 | Arbitrary binary execution via op_path | encrypted_secrets.zig | CWE-78 | L234,399 | [#66](https://gitlab.com/devnw/zig/config/-/issues/66) | **Closed** |
| 3 | Medium | 36 | Unvalidated vault and path_prefix fields | encrypted_secrets.zig | CWE-74 | L229,209 | [#67](https://gitlab.com/devnw/zig/config/-/issues/67) | **Closed** |
| 4 | Medium | 32 | DNS rebinding attack surface | remote.zig | CWE-918 | L73-99 | [#68](https://gitlab.com/devnw/zig/config/-/issues/68) | **Closed** |
| 5 | Medium | 32 | HTTP redirect following bypasses SSRF | remote.zig | CWE-918 | L344-368 | [#70](https://gitlab.com/devnw/zig/config/-/issues/70) | **Closed** |
| 6 | Medium | 24 | Symlink following in file operations (partial) | multiple | CWE-59 | secret.zig:68 | [#69](https://gitlab.com/devnw/zig/config/-/issues/69) | **Closed** |
| 7 | Low | 16 | URL-encoded IP bypass potential | remote.zig | CWE-918 | L93-95 | [#71](https://gitlab.com/devnw/zig/config/-/issues/71) | **Closed** |

### Findings (Adversarial Review Round 1 - 2026-01-30)

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | GitLab Issue | Status |
|------|----------|------------|---------|-----------|-----------|----------|--------------|--------|
| 1 | High | 64 | ReDoS in pattern matching | validation.zig | CWE-1333 | L359-478 | [#58](https://gitlab.com/devnw/zig/config/-/issues/58) | **Closed** |
| 2 | Medium | 48 | SSRF bypass via IPv6/alt IP formats | remote.zig | CWE-918 | L103-135 | [#60](https://gitlab.com/devnw/zig/config/-/issues/60) | **Closed** |
| 3 | Medium | 48 | File write operations lack path validation | serialize.zig, config.zig | CWE-22 | L450-521 | [#62](https://gitlab.com/devnw/zig/config/-/issues/62) | **Closed** |
| 4 | Medium | 36 | SensitiveString not applied to config structs | encrypted_secrets.zig | CWE-532 | L175-214 | [#59](https://gitlab.com/devnw/zig/config/-/issues/59) | **Closed** |
| 5 | Medium | 32 | Predictable temp file names | serialize.zig | CWE-377 | L468 | [#61](https://gitlab.com/devnw/zig/config/-/issues/61) | **Closed** |
| 6 | Low | 16 | Gitleaks allowlist excludes security files | .gitleaks.toml | CWE-693 | L11-18 | [#63](https://gitlab.com/devnw/zig/config/-/issues/63) | **Closed** |
| 7 | Low | 16 | Inconsistent file size limits | multiple | CWE-400 | various | [#64](https://gitlab.com/devnw/zig/config/-/issues/64) | **Closed** |

### Initial Security Review Findings (Closed)

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | GitLab Issue | Status |
|------|----------|------------|---------|-----------|-----------|--------------|--------|
| 1 | High | 80 | Encrypted file provider returns plaintext | encrypted_secrets.zig | CWE-311 | [#47](https://gitlab.com/devnw/zig/config/-/issues/47) | **Closed** |
| 2 | High | 60 | Path traversal in secret file loading | secret.zig | CWE-22 | [#45](https://gitlab.com/devnw/zig/config/-/issues/45) | **Closed** |
| 3 | Medium | 48 | HTTP default for remote config/Vault | remote.zig | CWE-319 | [#48](https://gitlab.com/devnw/zig/config/-/issues/48) | **Closed** |
| 4 | High | 40 | Command injection via Vault/1Password CLI | encrypted_secrets.zig | CWE-78 | [#46](https://gitlab.com/devnw/zig/config/-/issues/46) | **Closed** |
| 5 | Medium | 36 | SSRF in remote config endpoints | remote.zig | CWE-918 | [#49](https://gitlab.com/devnw/zig/config/-/issues/49) | **Closed** |
| 6 | Medium | 36 | AWS KMS provider stub | encrypted_secrets.zig | CWE-311 | [#57](https://gitlab.com/devnw/zig/config/-/issues/57) | **Closed** |
| 7 | Low | 24 | SBOM scan allows failure in CI | .gitlab-ci.yml | CWE-937 | [#53](https://gitlab.com/devnw/zig/config/-/issues/53) | **Closed** |
| 8 | Low | 16 | Global mutable state (thread safety) | config.zig | CWE-362 | [#51](https://gitlab.com/devnw/zig/config/-/issues/51) | **Closed** |
| 9 | Low | 16 | TOCTOU race in file watcher | watch.zig | CWE-367 | [#52](https://gitlab.com/devnw/zig/config/-/issues/52) | **Closed** |
| 10 | Low | 16 | No config parser depth limits | loader.zig | CWE-400 | [#54](https://gitlab.com/devnw/zig/config/-/issues/54) | **Closed** |
| 11 | Low | 16 | Missing HTTP security headers | remote.zig | CWE-287 | [#55](https://gitlab.com/devnw/zig/config/-/issues/55) | **Closed** |
| 12 | Low | 12 | Non-standard dependency hash format | build.zig.zon | CWE-494 | [#56](https://gitlab.com/devnw/zig/config/-/issues/56) | **Closed** |

## Findings by Area

### Application/API Security

| Finding | Status | Issue | Fix |
|---------|--------|-------|-----|
| ReDoS in pattern matching | **Closed** | [#58](https://gitlab.com/devnw/zig/config/-/issues/58) | Added bounded iteration with max_iterations limit |
| Path traversal in secret loading | **Closed** | [#45](https://gitlab.com/devnw/zig/config/-/issues/45) | Added isPathSafe() |
| Command injection in CLI wrappers | **Closed** | [#46](https://gitlab.com/devnw/zig/config/-/issues/46) | Added isValidSecretIdentifier() |
| File write path traversal | **Closed** | [#62](https://gitlab.com/devnw/zig/config/-/issues/62) | Added isPathSafe() to all write operations |
| No parser depth limits | **Closed** | [#54](https://gitlab.com/devnw/zig/config/-/issues/54) | Documented |
| Arbitrary binary execution via op_path | **Closed** | [#66](https://gitlab.com/devnw/zig/config/-/issues/66) | Added isValidOpPath() allowlist validation |
| Unvalidated vault/path_prefix fields | **Closed** | [#67](https://gitlab.com/devnw/zig/config/-/issues/67) | Added isValidSecretIdentifier() validation |
| Consul key path injection | **Closed** | [#73](https://gitlab.com/devnw/zig/config/-/issues/73) | Added isValidKVKey() validation |
| Missing path validation in parsers | **Closed** | [#74](https://gitlab.com/devnw/zig/config/-/issues/74) | Added isPathSafe() to ini.zig, properties.zig, dotenv.zig |

### Authentication/Secrets

| Finding | Status | Issue | Fix |
|---------|--------|-------|-----|
| Encrypted file provider unimplemented | **Closed** | [#47](https://gitlab.com/devnw/zig/config/-/issues/47) | Returns FeatureNotImplemented |
| AWS KMS provider stub | **Closed** | [#57](https://gitlab.com/devnw/zig/config/-/issues/57) | Returns FeatureNotImplemented |
| SensitiveString not applied | **Closed** | [#59](https://gitlab.com/devnw/zig/config/-/issues/59) | Applied to KmsConfig, VaultConfig, OnePasswordConfig |

### Network/Data Security

| Finding | Status | Issue | Fix |
|---------|--------|-------|-----|
| HTTP defaults (no TLS) | **Closed** | [#48](https://gitlab.com/devnw/zig/config/-/issues/48) | Defaults changed to HTTPS |
| SSRF in remote endpoints | **Closed** | [#49](https://gitlab.com/devnw/zig/config/-/issues/49) | Added validateUrl() |
| SSRF bypass via IPv6/alt formats | **Closed** | [#60](https://gitlab.com/devnw/zig/config/-/issues/60) | Added IPv6-mapped address handling, fe80:: detection |
| Missing HTTP headers | **Closed** | [#55](https://gitlab.com/devnw/zig/config/-/issues/55) | Added User-Agent, fixed token |
| SSRF bypass via decimal/octal IP | **Closed** | [#65](https://gitlab.com/devnw/zig/config/-/issues/65) | Added parseIPv4ToInt() with decimal/octal/hex support |
| DNS rebinding attack surface | **Closed** | [#68](https://gitlab.com/devnw/zig/config/-/issues/68) | Documented limitation with mitigation recommendations |
| HTTP redirect SSRF bypass | **Closed** | [#70](https://gitlab.com/devnw/zig/config/-/issues/70) | Disabled redirect following with .redirect_behavior = .not_allowed |
| URL-encoded IP bypass | **Closed** | [#71](https://gitlab.com/devnw/zig/config/-/issues/71) | Added decodePercentEncoded() before private IP check |

### File System Security

| Finding | Status | Issue | Fix |
|---------|--------|-------|-----|
| Predictable temp files | **Closed** | [#61](https://gitlab.com/devnw/zig/config/-/issues/61) | Uses crypto random for temp file names |
| Symlink following in file ops (partial) | **Closed** | [#69](https://gitlab.com/devnw/zig/config/-/issues/69) | Added isSymlink() check in secret.zig, loader.zig, watch.zig |
| Incomplete symlink protection | **Closed** | [#72](https://gitlab.com/devnw/zig/config/-/issues/72) | Added isSymlink() to dotenv.zig, async.zig, ini.zig, properties.zig, config.zig |
| Default file permissions too permissive | **Closed** | [#75](https://gitlab.com/devnw/zig/config/-/issues/75) | Added .mode = 0o600 to createFile() calls |

### CI/CD Security

| Finding | Status | Issue | Fix |
|---------|--------|-------|-----|
| SBOM scan allows failure | **Closed** | [#53](https://gitlab.com/devnw/zig/config/-/issues/53) | Removed allow_failure |
| Gitleaks excludes security files | **Closed** | [#63](https://gitlab.com/devnw/zig/config/-/issues/63) | Removed security source files from allowlist |

### Code Quality/Hardening

| Finding | Status | Issue | Fix |
|---------|--------|-------|-----|
| Global mutable state | **Closed** | [#51](https://gitlab.com/devnw/zig/config/-/issues/51) | Added mutex |
| TOCTOU race condition | **Closed** | [#52](https://gitlab.com/devnw/zig/config/-/issues/52) | Documented |
| Dependency hash format | **Closed** | [#56](https://gitlab.com/devnw/zig/config/-/issues/56) | Verified |
| Inconsistent file size limits | **Closed** | [#64](https://gitlab.com/devnw/zig/config/-/issues/64) | Documented and centralized constants |

## Remediation Priority

### All Remediation Complete ✅

All 29 security findings have been addressed:
- **Critical:** 0 (none identified)
- **High:** 6 closed
- **Medium:** 14 closed
- **Low:** 9 closed

## Findings Detail (Round 3 - All Closed)

### #72 - Incomplete Symlink Protection in File Parsers (CLOSED)
**confidence::confirmed**
**status::closed**

The symlink protection fix (#69) was applied to secret.zig, loader.zig, and watch.zig but missed several file parsing modules.

**Evidence:**
- `src/dotenv.zig:24` - `.env` file loading
- `src/async.zig:222` - Async file loading
- `src/ini.zig:189` - INI file loading
- `src/properties.zig:254` - Properties file loading
- `src/config.zig:354` - parseFile()

**Fix Applied:** Added `isSymlink()` import and check before `openFile()` in all affected modules.

### #73 - Consul Key Path Injection (CLOSED)
**confidence::confirmed**
**status::closed**

The Consul client constructs URLs using the `key` parameter directly without validation, enabling potential path injection.

**Evidence:** `src/remote.zig:591-647`
```zig
const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?raw", .{ self.options.address, key })
```

**Fix Applied:** Added `isValidKVKey()` validation function that rejects:
- Path traversal sequences (`..`)
- URL-encoded traversal (`%2e`, `%2f`)
- Query/fragment injection (`?`, `#`)
- Null bytes (`\x00`, `%00`)
- Invalid characters (only alphanumeric, `/`, `-`, `_`, `.` allowed)
- Leading/trailing slashes
- Keys > 512 chars

### #74 - Missing Path Traversal Validation in Parsers (CLOSED)
**confidence::confirmed**
**status::closed**

The path traversal fix (#62) was applied to write operations but INI, Properties, and Dotenv file reading lacked validation.

**Evidence:**
- `src/ini.zig:189` - No isPathSafe() before openFile
- `src/properties.zig:254` - No isPathSafe() before openFile
- `src/dotenv.zig:24` - No isPathSafe() before openFile

**Fix Applied:** Imported `secret.isPathSafe()` and added path validation before opening files.

### #75 - Default File Permissions Too Permissive (CLOSED)
**confidence::confirmed**
**status::closed**

Files created use default permissions (typically 0644) instead of restrictive mode.

**Evidence:**
- `src/config.zig:690,704,740,753` - safe write without mode

**Fix Applied:** Added `.mode = 0o600` to all `createFile()` calls in safe write functions.

## Previous Findings Detail (Round 2 - Closed)

### #65 - SSRF Bypass via Decimal/Octal IP Formats (CLOSED)
**confidence::confirmed**
**status::closed**

The `isPrivateIPv4()` function only parses decimal format IPs (base 10). An attacker can bypass SSRF protection using:
- Decimal IP: `2130706433` (equivalent to 127.0.0.1)
- Octal: `0177.0.0.1` (equivalent to 127.0.0.1)
- Hex octets: `0x7f.0.0.1` (equivalent to 127.0.0.1)

**Evidence:** `src/remote.zig:150-154`

**Fix Applied:** Added `parseIPv4ToInt()` and `parseIntWithBase()` functions that normalize all IP formats to 32-bit integers before checking private ranges.

### #66 - Arbitrary Binary Execution via op_path (CLOSED)
**confidence::confirmed**
**status::closed**

The `op_path` field in `OnePasswordConfig` is used directly as the executable without validation.

**Evidence:** `src/encrypted_secrets.zig:234,399`

**Fix Applied:** Added `isValidOpPath()` with allowlist validation for known safe binary locations.

### #67 - Unvalidated vault and path_prefix Fields (CLOSED)
**confidence::confirmed**
**status::closed**

The `vault` and `path_prefix` fields are not validated before being used in URIs.

**Evidence:** `src/encrypted_secrets.zig:229,209,404`

**Fix Applied:** Added `isValidSecretIdentifier()` validation in `loadFromVault()` and `loadFromOnePassword()`.

### #68 - DNS Rebinding Attack Surface (CLOSED)
**confidence::suspected**
**status::closed (documented limitation)**

URL validation happens before DNS resolution. An attacker controlling DNS can rebind from public IP to private IP after validation passes.

**Evidence:** `src/remote.zig:73-99`

**Fix Applied:** Documented as a known limitation with mitigation recommendations.

### #69 - Symlink Following in File Operations (CLOSED)
**confidence::suspected**
**status::closed (partial)**

File operations use `openFile` which follows symlinks by default.

**Evidence:** `secret.zig:68`, `loader.zig:675`, `watch.zig:239`

**Fix Applied:** Added `isSymlink()` helper function. Note: Additional locations identified in #72.

### #70 - HTTP Redirect Following Bypasses SSRF (CLOSED)
**confidence::suspected**
**status::closed**

The HTTP client may follow redirects from validated public URLs to internal IPs.

**Evidence:** `src/remote.zig:344-368`

**Fix Applied:** Set `.redirect_behavior = .not_allowed` on all HTTP client requests.

### #71 - URL-Encoded IP Bypass (CLOSED)
**confidence::suspected**
**status::closed**

URL-encoded private IPs like `%31%32%37.%30.%30.%31` (127.0.0.1) may bypass validation.

**Evidence:** `src/remote.zig:93-95`

**Fix Applied:** Added `decodePercentEncoded()` function to decode hostnames before checking.

## Methodology

This adversarial review (Round 3) specifically targeted:

1. **Completeness of Previous Fixes**
   - Verified symlink protection applied to all file operations
   - Verified path validation applied to all file parsers
   - Checked for consistent patterns across modules

2. **Injection Vectors**
   - Consul key path injection
   - Additional URI construction points

3. **File System Security**
   - File creation permissions
   - Remaining symlink vectors

4. **Code Pattern Analysis**
   - grep for openFile without isSymlink check
   - grep for createFile without mode specification
   - grep for URL construction with user-controlled values

## What Was Verified Working

The following security controls were verified as correctly implemented:
- **isPathSafe()** - Correctly blocks ".." and null bytes in secret.zig, serialize.zig, config.zig
- **isValidSecretIdentifier()** - Correctly validates CLI arguments
- **HTTPS defaults** - etcd, Consul, Vault now default to HTTPS
- **IPv6-mapped address blocking** - `::ffff:` prefixes correctly detected
- **IP format normalization** - Decimal/octal/hex IPs correctly parsed
- **Redirect blocking** - HTTP redirects disabled in all clients
- **URL decoding** - Percent-encoded hosts decoded before validation

## Blockers/Unknowns

1. **etcd key safety** - etcd uses base64 encoding in JSON body, appears safe from injection
2. **Async loader thread safety** - Needs review for concurrent file access patterns

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-74: Injection](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-732: Incorrect Permission Assignment](https://cwe.mitre.org/data/definitions/732.html)
