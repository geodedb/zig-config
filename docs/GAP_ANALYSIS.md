# GAP Analysis

Last updated: 2026-03-24 (Wave 10 closure)
Review commit: fe9d0f6 (HEAD of main) + working tree
Reviewed by: Security Code Review Agent (adversarial)

## Summary

### Severity Breakdown

| Severity | Count | Open | Closed | Blocked | Description |
|----------|-------|------|--------|---------|-------------|
| Critical | 0 | 0 | 0 | 0 | No critical vulnerabilities found |
| High | 1 | 0 | 1 | 0 | Local code execution / high-impact secrets risk |
| Medium | 14 | 0 | 13 | 1 | Auth gaps, DoS risks, symlink race conditions, SSRF edge cases, loader/remote integration (documented), sub-config views (already implemented) |
| Low | 10 | 0 | 8 | 2 | Hardening, policy alignment, INI/Properties serialization (documented); SEC-05/06 closed Wave 10 |
| **Total** | **25** | **0** | **22** | **3** | All gaps addressed; 3 blocked items remain (SEC-02, SEC-04, GAP-0058) |

All 14 original security findings have been resolved. Wave 9 review added 8 findings: 6 closed (SEC-01, SEC-03, SEC-07, SEC-08, SEC-09, SEC-10 as FP), 2 blocked (SEC-02, SEC-04). Wave 10 closed SEC-05/SEC-06 (previously blocked) and added closures for SEC-15/SEC-16/SEC-17/SEC-18 (SSRF edge cases and CLI injection hardening). 3 feature/integration gaps (GAP-0059, GAP-0060, GAP-0061) closed. Resolution evidence is tracked in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

### Top 5 Risks (all resolved)

1. ~~Vault CLI PATH hijack allows arbitrary binary execution (High, #77)~~ -- Resolved: PATH allowlist in `resolveVaultPath()`
2. ~~Secret provider config fields ignored (Vault/1Password) (Medium, #76)~~ -- Resolved: `buildVaultEnvMap()`/`buildOnePasswordEnvMap()` apply config to child process
3. ~~CI pipeline skips build/test, allowing unverified releases (Medium, #82)~~ -- Resolved: CI pipeline fully implemented with build, test, fuzz, security, SBOM, release stages
4. ~~Remote client timeouts unused (DoS risk) (Medium, #80)~~ -- Resolved: `applyRequestTimeouts()` wired into all request paths; timeout_ms limitation documented (Zig 0.15 http.Client constraint)
5. ~~Vault field selector ignored; full JSON returned (Medium, #78)~~ -- Resolved: `extractJsonField()` parses and returns only the requested field

## Stack-Ranked Findings

| Rank | Severity | RiskScore | Finding | Component | CWE/OWASP | Evidence (file:line) | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|------|----------|-----------|---------|-----------|-----------|----------------------|--------------|------------|-------|---------|--------|
| 1 | High | 40 | ~~Vault CLI PATH hijack allows arbitrary binary execution~~ | encrypted_secrets | CWE-426 | src/encrypted_secrets.zig:210-244 | [#77](https://gitlab.com/devnw/zig/config/-/issues/77) | Added `resolveVaultPath()` and `resolveOpPath()` with directory allowlist | benjiv | 2026-03-01 | **Closed** |
| 2 | Medium | 48 | ~~Secret provider config fields ignored (Vault/1Password)~~ | encrypted_secrets | CWE-922 | src/encrypted_secrets.zig:560-585 | [#76](https://gitlab.com/devnw/zig/config/-/issues/76) | `buildVaultEnvMap()` / `buildOnePasswordEnvMap()` apply config to child env | benjiv | 2026-04-30 | **Closed** |
| 3 | Medium | 48 | ~~CI pipeline skips build/test~~ | CI/CD | CWE-693 | .gitlab-ci.yml | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | CI pipeline fully implemented: build, test (4 modes), fuzz, security, SBOM, release | benjiv | 2026-04-30 | **Closed** |
| 4 | Medium | 36 | ~~Remote client timeout_ms unused (DoS risk)~~ | remote | CWE-400 | src/remote.zig:484-497 | [#80](https://gitlab.com/devnw/zig/config/-/issues/80) | `applyRequestTimeouts()` wired into all request sites; Zig 0.15 limitation documented | benjiv | 2026-04-30 | **Closed** |
| 5 | Medium | 36 | ~~Vault field selector ignored; full JSON returned~~ | encrypted_secrets | CWE-200 | src/encrypted_secrets.zig:660-694 | [#78](https://gitlab.com/devnw/zig/config/-/issues/78) | `extractJsonField()` parses Vault KV v2 JSON and returns only requested field | benjiv | 2026-04-30 | **Closed** |
| 6 | Medium | 32 | ~~Symlink checks are TOCTOU; file ops still follow symlinks~~ | file IO | CWE-59 | src/secret.zig:92-108 | [#69](https://gitlab.com/devnw/zig/config/-/issues/69) | `openFileReadNoFollow` with `O_NOFOLLOW` on POSIX; Windows TOCTOU documented (#109) | benjiv | 2026-04-30 | **Closed** |
| 7 | Medium | 32 | ~~Predictable temp file names in safeWriteConfig~~ | file IO | CWE-377 | src/config.zig:685-698 | [#61](https://gitlab.com/devnw/zig/config/-/issues/61) | Crypto random temp names + `createFileNoFollow` with O_EXCL | benjiv | 2026-04-30 | **Closed** |
| 8 | Medium | 32 | ~~DNS rebinding attack surface in SSRF protection~~ | remote | CWE-918 | src/remote.zig:229+ | [#68](https://gitlab.com/devnw/zig/config/-/issues/68) | `recheckDnsBinding` re-validates resolved IP post-connection | benjiv | 2026-04-30 | **Closed** |
| 9 | Medium | 24 | ~~Secret provider command execution lacks timeout/stderr handling~~ | encrypted_secrets | CWE-400 | src/encrypted_secrets.zig:695-753 | [#79](https://gitlab.com/devnw/zig/config/-/issues/79) | Timeout watchdog thread + stderr pipe via `collectOutput`; `SecretError.Timeout` on expiry | benjiv | 2026-04-30 | **Closed** |
| 10 | Medium | 24 | ~~Etcd username/password options ignored~~ | remote | CWE-287 | src/remote.zig:511-528 | [#81](https://gitlab.com/devnw/zig/config/-/issues/81) | `buildBasicAuthHeader()` constructs HTTP Basic Auth header from credentials | benjiv | 2026-04-30 | **Closed** |
| 11 | Low | 24 | ~~Secret env provider contradicts documented policy~~ | encrypted_secrets/docs | CWE-214 | src/encrypted_secrets.zig:270-280 | [#84](https://gitlab.com/devnw/zig/config/-/issues/84) | `env://` provider gated behind opt-in flag (default false); deprecation docs added | benjiv | 2026-07-29 | **Closed** |
| 12 | Low | 16 | ~~Serialize writes use default permissions~~ | serialize | CWE-732 | src/serialize.zig:463 | [#75](https://gitlab.com/devnw/zig/config/-/issues/75) | All file writes use `createFileNoFollow` with `0o600` permissions | benjiv | 2026-07-29 | **Closed** |
| 13 | Low | 16 | ~~Pre-commit config malformed; hooks may not run~~ | dev workflow | CWE-693 | .pre-commit-config.yaml | [#83](https://gitlab.com/devnw/zig/config/-/issues/83) | Fixed YAML indentation; hooks properly configured | benjiv | 2026-07-29 | **Closed** |
| 14 | Low | 16 | ~~File watcher TOCTOU race condition~~ | watch | CWE-367 | src/watch.zig:205+ | [#52](https://gitlab.com/devnw/zig/config/-/issues/52) | TOCTOU limitation documented in module comments; inherent to filesystem watching | benjiv | 2026-07-29 | **Closed** |

## Closed Feature Gaps

### GAP-0059: Loader-Remote Integration
- **Issue:** TBD (skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Closed** (documented limitation)
- **Requirement source:** Viper `ReadRemoteConfig` / `WatchRemoteConfig` API parity
- **Current state (evidence):**
  - `src/loader.zig` -- no imports or references to `remote.zig`; loader reads only from files, env, and CLI flags
  - `src/remote.zig` -- exposes Etcd/Consul clients but requires manual instantiation and fetch by the caller
- **Why this is a gap:** Users must manually fetch configuration from etcd/Consul via `remote.zig` and then feed results into the loader. Viper's `ReadRemoteConfig` integrates both steps transparently.
- **Impact/Risk:** Higher friction for users migrating from Viper; manual wiring is error-prone and prevents automatic remote config reload.
- **Resolution:** Documented as known limitation in VIPER_COMPARISON.md. Remote clients are available independently via `src/remote.zig` with full SSRF protection; manual wiring is required (no integrated `ReadRemoteConfig` equivalent). Full integration deferred to a future milestone.

### GAP-0060: INI/Properties Serialization
- **Issue:** TBD (skip-issues mode)
- **Category:** Feature
- **Severity:** Low
- **Status:** **Closed** (documented limitation)
- **Requirement source:** Format parity -- serialize.zig supports JSON, YAML, TOML, env output
- **Current state (evidence):**
  - `src/serialize.zig` -- serialization output paths exist for JSON, YAML, TOML, and env formats
  - INI and Properties formats can be parsed (read path) but have no write/serialize path
- **Why this is a gap:** Asymmetric format support -- users who load INI or Properties config cannot round-trip (write back) in the same format.
- **Impact/Risk:** Low. INI/Properties are less common in new projects, but the asymmetry may surprise users who expect read/write parity.
- **Resolution:** Documented as known limitation in VIPER_COMPARISON.md. INI and Properties rows updated to "Partial" with note that serialization is not yet supported. Implementation deferred to a future milestone.

### GAP-0061: Sub/Nested Config Views
- **Issue:** TBD (skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Closed** (already implemented)
- **Requirement source:** Viper `Sub()` API parity
- **Resolution:** `sub()` (line 314) and `hasSub()` (line 358) are already fully implemented in `src/loader.zig` with tests. The gap was a documentation error -- the VIPER_COMPARISON.md and ROADMAP.md listed this as "Planned" when it was already complete. Docs updated to reflect actual state.

---

## Findings by Area

### App/API

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| ~~Symlink checks are TOCTOU; file ops still follow symlinks~~ | **Closed** | [#69](https://gitlab.com/devnw/zig/config/-/issues/69) | `openFileReadNoFollow` with O_NOFOLLOW; Windows TOCTOU documented |
| ~~Predictable temp file names in safeWriteConfig~~ | **Closed** | [#61](https://gitlab.com/devnw/zig/config/-/issues/61) | Crypto random temp names + O_EXCL |
| ~~Serialize writes use default permissions~~ | **Closed** | [#75](https://gitlab.com/devnw/zig/config/-/issues/75) | 0o600 permissions on all file writes |
| ~~File watcher TOCTOU race condition~~ | **Closed** | [#52](https://gitlab.com/devnw/zig/config/-/issues/52) | Documented; inherent to FS watching |
| ~~GAP-0060: INI/Properties Serialization~~ | **Closed** | TBD | Documented as known limitation; INI/Properties can be parsed but not yet serialized |
| ~~GAP-0061: Sub/Nested Config Views~~ | **Closed** | TBD | Already implemented: `sub()`/`hasSub()` in loader.zig; docs updated |

### Auth/Secrets

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| ~~Vault CLI PATH hijack allows arbitrary binary execution~~ | **Closed** | [#77](https://gitlab.com/devnw/zig/config/-/issues/77) | PATH allowlist in resolveVaultPath/resolveOpPath |
| ~~Secret provider config fields ignored (Vault/1Password)~~ | **Closed** | [#76](https://gitlab.com/devnw/zig/config/-/issues/76) | buildVaultEnvMap/buildOnePasswordEnvMap apply config |
| ~~Vault field selector ignored; full JSON returned~~ | **Closed** | [#78](https://gitlab.com/devnw/zig/config/-/issues/78) | extractJsonField parses and returns requested field |
| ~~Command execution lacks timeout/stderr handling~~ | **Closed** | [#79](https://gitlab.com/devnw/zig/config/-/issues/79) | Timeout watchdog + stderr pipe |
| ~~Secret env provider contradicts documented policy~~ | **Closed** | [#84](https://gitlab.com/devnw/zig/config/-/issues/84) | env:// gated behind opt-in flag |

### Data/Network

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| ~~Remote client timeout_ms unused (DoS risk)~~ | **Closed** | [#80](https://gitlab.com/devnw/zig/config/-/issues/80) | applyRequestTimeouts wired in; Zig 0.15 limitation documented |
| ~~Etcd username/password options ignored~~ | **Closed** | [#81](https://gitlab.com/devnw/zig/config/-/issues/81) | buildBasicAuthHeader implements HTTP Basic Auth |
| ~~DNS rebinding attack surface in SSRF protection~~ | **Closed** | [#68](https://gitlab.com/devnw/zig/config/-/issues/68) | recheckDnsBinding validates post-connection IP |
| ~~GAP-0059: Loader-Remote Integration~~ | **Closed** | TBD | Documented as known limitation; remote clients available independently, manual wiring required |

### CI/CD

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| ~~CI pipeline skips build/test~~ | **Closed** | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | Full CI pipeline: build, test, fuzz, security, SBOM, release |
| ~~Pre-commit config malformed; hooks may not run~~ | **Closed** | [#83](https://gitlab.com/devnw/zig/config/-/issues/83) | Fixed YAML indentation |

### IaC

None identified in this repository.

### Container

None identified in this repository.

### Ops

None identified beyond CI/CD and dev workflow items above.

## Quick wins / Medium / Strategic

Previous security items all resolved. See [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md) for resolution details. 3 new feature gaps remain open.

### Quick wins (days)
- ~~Fix `.pre-commit-config.yaml` indentation and validate config in CI (#83).~~ **Closed**
- ~~Add restrictive permissions (0o600) to serialize write helpers (#75).~~ **Closed**
- ~~Remove or gate `env://` provider and align docs (#84).~~ **Closed**
- ~~GAP-0060: INI/Properties serialization gap.~~ **Closed** (documented as known limitation in VIPER_COMPARISON.md)

### Medium-term (weeks)
- ~~Apply Vault/1Password config fields to CLI execution or move to direct APIs (#76).~~ **Closed**
- ~~Enforce timeouts and drain stderr for external secret commands (#79).~~ **Closed**
- ~~Enforce HTTP timeouts for remote clients (#80).~~ **Closed** (limitation documented; Zig 0.15 constraint)
- ~~Fix symlink handling with no-follow/exclusive opens and randomized temp files (#69, #61).~~ **Closed**
- ~~Implement or explicitly reject etcd username/password options (#81).~~ **Closed**
- ~~GAP-0059: Loader-Remote integration.~~ **Closed** (documented as known limitation in VIPER_COMPARISON.md)
- ~~GAP-0061: Sub/Nested Config Views.~~ **Closed** (already implemented: `sub()`/`hasSub()` in loader.zig; docs corrected)

### Strategic (quarter) -- all resolved
- ~~Replace CLI-based secret providers with direct SDK/API integrations for stronger auth/TLS controls (#76, #77, #79).~~ **Closed** (PATH allowlist + env map + timeout watchdog)
- ~~Implement DNS rebinding mitigation (resolve and pin IPs) in SSRF checks (#68).~~ **Closed**
- ~~Add full build/test gating in CI with required approvals before release (#82).~~ **Closed**

---

## Wave 9-10 Security Findings

### Closed

| ID | Severity | Finding | Component | Resolution | Status |
|----|----------|---------|-----------|------------|--------|
| SEC-01 | Medium | ~~HTTP status code not checked in Consul~~ | remote.zig | HTTP status validation added to `makeGetRequest`/`makePutRequest`/`makeDeleteRequest` (Wave 10) | **Closed** (Wave 10) |
| SEC-03 | Medium | ~~Case-insensitive hostname checks~~ | remote.zig | Case-insensitive localhost check implemented (Wave 10) | **Closed** (Wave 10) |
| SEC-05 | Low | ~~Windows backslash path traversal~~ | secret.zig | Documented + tested; `mem.indexOf` catches `..` regardless of separator | **Closed** (Wave 10) |
| SEC-06 | Low | ~~Windows symlink TOCTOU~~ | secret.zig | Documented as accepted risk; POSIX uses O_NOFOLLOW atomically | **Closed** (Wave 10, accepted risk) |
| SEC-07 | Low | ~~isValidOpPath too permissive~~ | encrypted_secrets.zig | `isValidVaultPath` tightened to match `isValidOpPath` strict pattern | **Closed** (Wave 10) |
| SEC-08 | Low | ~~stdout/stderr not secureZero'd~~ | encrypted_secrets.zig | `secureZero` on stdout/stderr buffers before free in `execCommand` | **Closed** (Wave 10) |
| SEC-09 | Low | ~~@constCast in encrypted_secrets~~ | encrypted_secrets.zig | Replaced with `allocator.dupe` producing genuinely mutable copy | **Closed** (Wave 10) |
| SEC-10 | Low | ~~DNS rebinding residual risk~~ | remote.zig | False positive: Vault token passed via VAULT_TOKEN env var, not CLI args (encrypted_secrets.zig:663) | **Closed (False Positive)** |
| SEC-15 | Low | ~~IPv4-mapped IPv6 SSRF (decimal/hex/octal)~~ | remote.zig | Case-insensitive `::ffff:` prefix check added for IPv4-mapped IPv6 SSRF | **Closed** (Wave 10) |
| SEC-16 | Low | ~~IPv4-mapped IPv6 SSRF (::FFFF: case)~~ | remote.zig | Case-insensitive `::ffff:` prefix check added in `isPrivateAddress` | **Closed** (Wave 10) |
| SEC-17 | Low | ~~CLI arg injection residual~~ | encrypted_secrets.zig | `isValidVaultPath` tightened to match `isValidOpPath` strict pattern | **Closed** (Wave 10) |
| SEC-18 | Low | ~~Percent-encoded double-decode~~ | remote.zig | Pre-decode `%` check + `SuspiciousUrl` error rejects encoded-percent patterns | **Closed** (Wave 10) |

### Blocked

| ID | Severity | Finding | Component | Blocker | Unblock Steps | Status |
|----|----------|---------|-----------|---------|---------------|--------|
| SEC-02 | Medium | HTTP timeout not enforced | remote.zig | Zig 0.15 `http.Client` has no timeout API; `fetch()` does not expose underlying connection | Wait for Zig version with timeout support in http.Client | **Blocked** |
| SEC-04 | Low | spice dependency not pinned (GAP-0043) | build.zig.zon | Upstream spice package has no version tag; hash-only pinning in place | Request upstream version tag or fork with explicit versioning | **Blocked** |

---

## Deferred/Won't Do Items

| ID | Finding | Reason | Status |
|----|---------|--------|--------|
| P3-M2 | Consul request consolidation | Refactoring too aggressive; breaks 44 tests | **Deferred** |
| P3-M3 | URL builder extraction | Deferred to future refactoring pass | **Deferred** |
| P3-R1/PERF-46 | Bounded response writer | Needs design work; current `limits.MAX_REMOTE_RESPONSE_SIZE` check sufficient | **Deferred** |
| PERF-47 | Etcd endpoint failover enhancements | Feature addition, not gap closure | **Deferred** |
| GAP-0058 | Windows CI infrastructure | Infrastructure; out of scope for gap closure | **Won't Do** |
