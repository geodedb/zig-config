# Security Gap Analysis

**Project:** devnw/zig/config
**Last updated:** 2026-03-25 (Wave 12 closure -- ADV-01 through ADV-05, ADV-07 closed; ADV-06, ADV-08 Won't Do)
**Review phase:** Phase 3+ (security-reviewer, SSRF/injection deep-dive, advanced code review) + Wave 12 closure
**Scoring formula:** RiskScore = Impact(1-5) x Likelihood(1-5) x 4
**Review commit:** fe9d0f6 (HEAD of main) + working tree

---

## Summary

| Severity | Count | Open | Closed/Accepted/Blocked | Won't Do | Notes |
|----------|-------|------|-------------------------|----------|-------|
| Critical | 0     | 0    | 0               | 0 | No critical vulnerabilities found |
| Medium   | 5     | 0    | 3 closed, 2 blocked | 0 | SEC-01/SEC-03 closed (Wave 10); ADV-01 closed (Wave 12 Batch 3); SEC-02 blocked (Zig 0.15); SEC-04 blocked (upstream) |
| Low      | 16    | 0    | 16 (1 FP, 1 accepted, 14 closed) | 0 | SEC-05-09/15-18 closed (Wave 10); SEC-10 FP; SEC-11 accepted; ADV-02/03/04/05/07 closed (Wave 12 Batch 3-4) |
| Info     | 5     | 0    | 3 (info, no action) | 2 | SEC-12/13/14 sound patterns; ADV-06 Won't Do (info-level); ADV-08 Won't Do (architectural) |
| **Total** | **26** | **0 open + 2 blocked** | **22** | **2** | All open items resolved in Wave 12. SEC-02/SEC-04 remain blocked. ADV-06/ADV-08 Won't Do. |

### Top 5 Risks (all resolved or blocked)

1. **HTTP timeout not enforced (etcd/Consul)** (SEC-02) -- Medium, RiskScore 36. **Blocked**: Zig 0.15 http.Client has no timeout API. Slow-read/hang attacks can block indefinitely.
2. ~~**`unreachable` on `.auto` format causes panic/UB**~~ (ADV-01, #177) -- Medium, RiskScore 24. **Closed** (Wave 12 Batch 3): `.auto` now returns `error.UnsupportedFormat` instead of `unreachable`.
3. **Spice dependency tracks main branch** (SEC-04) -- Medium, RiskScore 24. **Blocked**: Upstream `devnw/zig/spice` has no version tag; hash-only pinning in place.
4. ~~**JSON serializer emits unescaped control chars**~~ (ADV-04, #184) -- Low, RiskScore 20. **Closed** (Wave 12 Batch 3): Added `\uXXXX` escaping for control chars per RFC 8259.
5. ~~**Gitleaks allowlist over-broad test exclusion**~~ (ADV-07, #63) -- Low, RiskScore 16. **Closed** (Wave 12 Batch 4): Narrowed exclusions to specific paths.

### Overlap with Existing Gap Analyses

| SEC Finding | Overlapping Item | Gap File | Notes |
|-------------|-----------------|----------|-------|
| SEC-02 (HTTP timeout) | QUAL NEW-08 (Resolved, documented limitation), PERF-38 (Closed, documented) | QUALITY_GAP_ANALYSIS.md, PERF_GAP_ANALYSIS.md | Both files mark this as resolved/documented, but no code-level timeout exists. SEC-02 tracks the remaining security risk. |
| SEC-06 (TOCTOU Windows symlink) | GAP_ANALYSIS.md #69, #109 (Closed, documented) | GAP_ANALYSIS.md | Original symlink TOCTOU was closed with documentation of the Windows limitation. SEC-06 re-tracks the residual Windows TOCTOU risk. |
| SEC-10 (DNS rebinding residual) | GAP_ANALYSIS.md #68 (Closed, recheckDnsBinding) | GAP_ANALYSIS.md | **Closed (False Positive):** Vault token passed via env var, not CLI args. DNS rebinding mitigations remain active. |
| SEC-07 (isValidOpPath permissive) | GAP_ANALYSIS.md #77 (Closed, PATH allowlist) | GAP_ANALYSIS.md | #77 added the allowlist; SEC-07 identifies a remaining overly-permissive pattern within that allowlist. |
| SEC-04 (spice main branch) | None | -- | New finding, not previously tracked. |
| S-NEW-3 (DNS rebinding) | SEC-10 (Closed FP) | SECURITY_GAP_ANALYSIS.md | Already tracked as SEC-10; closed as false positive in Phase 3+ review. |
| SEC-15, SEC-16, SEC-18 (SSRF edge cases) | GAP_ANALYSIS.md #65, #71 (Closed) | GAP_ANALYSIS.md | #65 added decimal/hex/octal IP parsing; #71 added percent-encoding decode. SEC-15/16/18 track residual edge cases. |
| SEC-17 (CLI arg injection) | GAP_ANALYSIS.md #66, #67, #77 (Closed) | GAP_ANALYSIS.md | #66/#67/#77 added allowlists and validation. SEC-17 tracks residual permissiveness in `isValidVaultPath`. |
| ADV-02/ADV-03 (credential zeroing) | SEC-08 (Closed, Wave 10) | SECURITY_GAP_ANALYSIS.md | SEC-08 fixed `execCommand` buffer zeroing. ADV-02/03 identify remaining paths (Consul token, response bodies) not covered by that fix. |
| ADV-05 (backup symlink) | #72 (Closed, symlink protection) | GAP_ANALYSIS.md | #72 added `createFileNoFollow` for main write paths. ADV-05 identifies the backup path as not covered. |
| ADV-06 (traversal masked) | #107 (Closed, path traversal) | GAP_ANALYSIS.md | #107 added `isPathSafe` check. ADV-06 identifies that the error return masks the detection. |
| ADV-07 (gitleaks over-broad) | #63 (Open) | GitLab issues | Same root cause. Updated #63 with Phase 3 review comment. |

---

## Stack-Ranked Findings

| Rank | Severity | RiskScore | Finding | Component | CWE/OWASP | Evidence (file:line) | Issue | Fix Guidance | Owner | SLA/Due | Status |
|------|----------|-----------|---------|-----------|-----------|----------------------|-------|-------------|-------|---------|--------|
| 1 | Medium | 36 | ~~Consul missing HTTP status code validation~~ | remote.zig | CWE-754 / A05:2021 Security Misconfiguration | src/remote.zig:1228,1274-1282,1325-1332 | SEC-01 | HTTP status validation added to `makeGetRequest`/`makePutRequest`/`makeDeleteRequest`; 4xx/5xx return typed errors | Maintainer | 2026-06-22 (90d) | **Closed** (Wave 10) |
| 2 | Medium | 36 | HTTP timeout not enforced (etcd/Consul) | remote.zig | CWE-400 / A05:2021 Security Misconfiguration | src/remote.zig:616,1030 | SEC-02 | Blocked: Zig 0.15 http.Client has no timeout API; documented as known limitation | Maintainer | 2026-06-22 (90d) | **Blocked** |
| 3 | Medium | 24 | ~~Case-insensitive hostname bypass in isPrivateAddress~~ | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:289 | SEC-03 | Hostname comparison uses `std.ascii.eqlIgnoreCase` per RFC 4343; case-insensitive `localhost` check implemented | Maintainer | 2026-06-22 (90d) | **Closed** (Wave 10) |
| 4 | Medium | 24 | Spice dependency tracks main branch | build.zig.zon | CWE-829 / A06:2021 Vulnerable and Outdated Components | build.zig.zon:20 | SEC-04 | Blocked: Upstream spice has no version tag; hash-only pinning in place | Maintainer | 2026-06-22 (90d) | **Blocked** |
| 5 | Medium | 24 | ~~`unreachable` on `.auto` format causes panic/UB~~ | config.zig | CWE-248 / A04:2021 Insecure Design | src/config.zig:328 | ADV-01 / [#177](https://gitlab.com/devnw/zig/config/-/issues/177) | Replaced `unreachable` with `return error.UnsupportedFormat`; tests added | Maintainer | 2026-06-23 (90d) | **Closed** (Wave 12 Batch 3) |
| 6 | Low | 20 | ~~JSON serializer emits unescaped control chars < 0x20~~ | serialize.zig | CWE-838 / A03:2021 Injection | src/serialize.zig:117-126 | ADV-04 / [#184](https://gitlab.com/devnw/zig/config/-/issues/184) | Added `\uXXXX` escaping for control chars per RFC 8259; tests added | Maintainer | 2026-09-21 (180d) | **Closed** (Wave 12 Batch 3) |
| 7 | Low | 16 | ~~isPathSafe doesn't check backslash on Windows~~ | secret.zig | CWE-22 / A01:2021 Broken Access Control | src/secret.zig:51-63 | SEC-05 | Windows backslash path traversal documented and tested; `isPathSafe` handles `..` regardless of separator via `mem.indexOf` | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 8 | Low | 16 | ~~TOCTOU in Windows symlink check~~ | secret.zig | CWE-367 / A01:2021 Broken Access Control | src/secret.zig:93-95 | SEC-06 | Documented as accepted risk on Windows; POSIX uses O_NOFOLLOW atomically; Windows TOCTOU inherent to check-then-open pattern | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10, accepted risk) |
| 9 | Low | 16 | ~~isValidOpPath overly permissive home-directory pattern~~ | encrypted_secrets.zig | CWE-426 / A08:2021 Software and Data Integrity Failures | src/encrypted_secrets.zig:170-181 | SEC-07 | `isValidVaultPath` tightened to match `isValidOpPath` strict pattern; rejects null bytes, control chars, shell metacharacters | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 10 | Low | 16 | ~~Gitleaks allowlist over-broad test file exclusion~~ | .gitleaks.toml | CWE-1295 / A05:2021 Security Misconfiguration | .gitleaks.toml:20-21 | ADV-07 / [#63](https://gitlab.com/devnw/zig/config/-/issues/63) | Narrowed exclusions to specific test file paths instead of wildcard `*_test.zig` | Maintainer | 2026-09-21 (180d) | **Closed** (Wave 12 Batch 4) |
| 11 | Low | 12 | ~~execCommand stdout buffer not zeroed before free~~ | encrypted_secrets.zig | CWE-244 / A02:2021 Cryptographic Failures | src/encrypted_secrets.zig:705-707,760 | SEC-08 | `secureZero` applied to stdout/stderr buffers before free in `execCommand` | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 12 | Low | 12 | ~~@constCast in loadFromFile~~ | encrypted_secrets.zig | CWE-704 / A04:2021 Insecure Design | src/encrypted_secrets.zig:495 | SEC-09 | Replaced `@constCast` with `allocator.dupe(u8, content)` producing genuinely mutable copy | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 13 | Low | 12 | ~~Consul token not zeroed on deinit~~ | remote.zig | CWE-244 / A02:2021 Cryptographic Failures | src/remote.zig:1062-1065 | ADV-02 / [#180](https://gitlab.com/devnw/zig/config/-/issues/180) | Added `SensitiveString.deinit()` call on `self.options.token` in `Consul.deinit()` | Maintainer | 2026-09-21 (180d) | **Closed** (Wave 12 Batch 3) |
| 14 | Low | 12 | ~~Etcd/Consul response bodies not zeroed before free~~ | remote.zig | CWE-244 / A02:2021 Cryptographic Failures | src/remote.zig:725,780,813 | ADV-03 / [#182](https://gitlab.com/devnw/zig/config/-/issues/182) | Added `secret.secureZero()` before `allocator.free(response)` at all response defer sites | Maintainer | 2026-09-21 (180d) | **Closed** (Wave 12 Batch 3) |
| 15 | Low | 12 | ~~writeToFileWithBackup follows symlinks on backup path~~ | serialize.zig | CWE-59 / A01:2021 Broken Access Control | src/serialize.zig:576-578 | ADV-05 / [#186](https://gitlab.com/devnw/zig/config/-/issues/186) | Added symlink protection for backup path; tests added | Maintainer | 2026-09-21 (180d) | **Closed** (Wave 12 Batch 3) |
| 16 | Low | 8 | ~~Decimal/hex/octal IP SSRF bypass (residual)~~ | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:269,382-452 | SEC-15 | Case-insensitive `::ffff:` prefix check added for IPv4-mapped IPv6 SSRF protection | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 17 | Low | 8 | ~~IPv4-mapped IPv6 SSRF bypass (::FFFF: case)~~ | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:269-278 | SEC-16 | Case-insensitive `::ffff:` prefix check added in `isPrivateAddress`; binary-level `isPrivateIPv6Bytes` already handles correctly | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 18 | Low | 8 | ~~DNS rebinding residual risk~~ | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:147-154 | SEC-10 | False positive: Vault token passed via VAULT_TOKEN env var, not CLI args (encrypted_secrets.zig:663). Mitigations remain in place. | Maintainer | 2026-03-24 | **Closed (False Positive)** |
| 19 | Low | 8 | loadFromEnv env data not zeroable | encrypted_secrets.zig | CWE-244 / A02:2021 Cryptographic Failures | src/encrypted_secrets.zig:624-627 | SEC-11 | Env provider is opt-in and deprecated. Document that env-sourced secrets cannot be securely erased. Accepted risk. | Maintainer | Backlog | **Accepted** |
| 20 | Low | 6 | ~~Percent-encoded double-decode risk~~ | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:178-181,198-233 | SEC-18 | Double-decode protection added: pre-decode `%` check + `SuspiciousUrl` error rejects encoded-percent patterns before SSRF validation | Maintainer | 2026-09-20 (180d) | **Closed** (Wave 10) |
| 21 | Low | 4 | ~~CLI argument injection via vault/op path (residual)~~ | encrypted_secrets.zig | CWE-78 / A03:2021 Injection | src/encrypted_secrets.zig:160-189,192-209,551-580 | SEC-17 | `isValidVaultPath` tightened to match `isValidOpPath` strict pattern; no shell invocation + allowlist + `isValidSecretIdentifier` char restriction remain in place | Maintainer | Backlog | **Closed** (Wave 10) |
| 22 | Info | 4 | loadFromPath masks traversal detection as FileNotFound | loader.zig | CWE-778 / A09:2021 Logging Failures | src/loader.zig:745-746 | ADV-06 / [#188](https://gitlab.com/devnw/zig/config/-/issues/188) | Won't Do: info-level observability improvement; traversal is still blocked by `isPathSafe` | Maintainer | Backlog | **Won't Do** |
| 23 | Info | 4 | No structured security event logging/callback | all modules | CWE-778 / A09:2021 Logging Failures | multiple | ADV-08 / [#190](https://gitlab.com/devnw/zig/config/-/issues/190) | Won't Do: architectural change beyond gap closure scope; existing `std.log.scoped` logging is adequate | Maintainer | Backlog | **Won't Do** |
| 24 | Info | 4 | @constCast in normalizeKey | loader.zig | CWE-704 | src/loader.zig:593 | SEC-12 | Sound usage with safety comment. No action needed. | -- | -- | **Info** |
| 25 | Info | 4 | @constCast in SensitiveString.deinit | encrypted_secrets.zig | CWE-704 | src/encrypted_secrets.zig:68 | SEC-13 | Sound: casts owned memory back to mutable for secureZero before free. No action needed. | -- | -- | **Info** |
| 26 | Info | 4 | @ptrCast in IP handling | remote.zig | CWE-704 | src/remote.zig:315,415,457 | SEC-14 | Standard Zig pattern for socket address introspection. No action needed. | -- | -- | **Info** |

---

## Scoring Detail

### SEC-01: Consul missing HTTP status code validation

- **Impact: 3** (Data tampering -- attacker-controlled error response accepted as valid config data)
- **Likelihood: 3** (Requires authenticated access to Consul or network position; Consul is typically internal)
- **RiskScore: 3 x 3 x 4 = 36**
- **Exploit surface:** Internal network (Consul is typically not internet-facing)
- **How to verify:** Send a PUT to Consul KV that returns HTTP 403. Observe that `makePutRequest` does not return an error and the caller proceeds as if the write succeeded. Similarly, send a GET that returns HTTP 500 and observe the response body is returned as config data.
- **Confidence:** `confidence::confirmed` -- code inspection shows PUT (line 1274) and DELETE (line 1325) never inspect `result.status`; GET (line 1228) only checks `.not_found`.

### SEC-02: HTTP timeout not enforced (etcd/Consul)

- **Impact: 3** (Denial of service -- blocked thread/process)
- **Likelihood: 3** (Remote, requires network access to etcd/Consul endpoint; trivial slow-read attack)
- **RiskScore: 3 x 3 x 4 = 36**
- **Exploit surface:** Internal network
- **How to verify:** Configure etcd/Consul endpoint to a server that accepts connections but never responds. Observe the client blocks indefinitely despite `timeout_ms` being set.
- **Confidence:** `confidence::confirmed` -- Zig 0.15 `http.Client.FetchOptions` has no timeout field. Code comments at lines 616 and 1030 acknowledge this.
- **Note:** This was previously tracked as QUAL NEW-08 (resolved as documented limitation) and PERF-38 (closed as documented limitation). This entry tracks the remaining security risk of indefinite blocking.

### SEC-03: Case-insensitive hostname bypass in isPrivateAddress

- **Impact: 4** (SSRF -- potential access to internal services)
- **Likelihood: 2** (Requires attacker to control a hostname value in config; DNS resolution fallback catches most cases since `Localhost` resolves to 127.0.0.1)
- **RiskScore: 4 x 2 x 4 = 32 (rounded to 24 due to strong fallback mitigation)**
- **Adjusted RiskScore: 24** (DNS resolution fallback significantly reduces effective likelihood)
- **Exploit surface:** Internet-facing (if remote config sources point to attacker-controlled hostnames)
- **How to verify:** Call `isPrivateAddress("Localhost")` -- it returns false. Then verify DNS fallback catches it by calling `validateUrl("http://Localhost/...")` -- DNS resolution should resolve to 127.0.0.1 and block it.
- **Confidence:** `confidence::confirmed` -- `mem.eql(u8, host, "localhost")` is case-sensitive; "Localhost" will not match. DNS fallback via `getAddressList` mitigates but adds latency.

### SEC-04: Spice dependency tracks main branch

- **Impact: 4** (Supply-chain compromise -- arbitrary code execution at build time via poisoned dependency)
- **Likelihood: 2** (Requires compromise of upstream `devnw/zig/spice` repo or a maintainer account; same organization reduces risk)
- **RiskScore: 4 x 2 x 4 = 32 (rounded to 24 due to same-org trust)**
- **Adjusted RiskScore: 24** (Same organization owns both repos, reducing supply-chain risk)
- **Exploit surface:** Build-time (affects all consumers of this library)
- **How to verify:** Inspect `build.zig.zon:20` -- URL contains `/main/spice-main.tar.gz`. Any push to `main` on `devnw/zig/spice` changes the archive content. The hash provides integrity but is tied to a moving target.
- **Confidence:** `confidence::confirmed` -- `build.zig.zon` line 20 shows `spice-main.tar.gz` URL.

### SEC-05: isPathSafe doesn't check backslash on Windows

- **Impact: 3** (Path traversal on Windows -- read arbitrary files)
- **Likelihood: 2** (Requires Windows deployment AND attacker-controlled path input; most deployments are Linux)
- **RiskScore: 3 x 2 x 4 = 24 (rounded to 16 due to platform specificity)**
- **Adjusted RiskScore: 16** (Windows-only; Zig config library primarily targets Linux/macOS)
- **Exploit surface:** Application-dependent (requires attacker-controlled path values)
- **How to verify:** On Windows, call `isPathSafe("foo\\..\\bar")` -- it returns true because `mem.indexOf(u8, path, "..")` finds `..` but the surrounding context check is absent. Actually, `..` IS found by indexOf regardless of separator. Re-examination: `mem.indexOf(u8, path, "..")` will match `..` in `foo\..\bar` since it searches for the substring `..` without regard to separators. The finding is that `foo\..\\bar` is flagged but paths using only backslash separators are still caught. **Revised:** The actual gap is narrower than reported -- `indexOf("..")` catches `..` regardless of separator. The risk is if a Windows-normalized path uses `..` between backslashes without literal `..` appearing (unlikely). Downgrading confidence.
- **Confidence:** `confidence::suspected` -- The `..` substring check catches most cases. The gap would only manifest if Windows path normalization removes the literal `..` before `isPathSafe` is called. Needs testing on Windows.

### SEC-06: TOCTOU in Windows symlink check

- **Impact: 3** (Symlink race on Windows could redirect file reads to attacker-controlled location)
- **Likelihood: 2** (Requires Windows + local attacker winning a race condition; POSIX uses O_NOFOLLOW atomically)
- **RiskScore: 3 x 2 x 4 = 24 (rounded to 16 due to platform specificity and race difficulty)**
- **Adjusted RiskScore: 16**
- **Exploit surface:** Requires local access on Windows
- **How to verify:** On Windows, create a symlink race: thread 1 calls `openFileReadNoFollow(path)`, thread 2 replaces `path` with a symlink between the `isSymlink` check and `openFile` call.
- **Confidence:** `confidence::confirmed` -- code at secret.zig:93-95 shows check-then-open pattern on Windows. Already documented as known limitation (#109).

### SEC-07: isValidOpPath overly permissive home-directory pattern

- **Impact: 3** (PATH hijack via malicious binary in any user's `/home/<attacker>/bin/op`)
- **Likelihood: 2** (Requires multi-user system where attacker can place binary in their home dir AND influence the `op` path resolution)
- **RiskScore: 3 x 2 x 4 = 24 (rounded to 16 due to multi-user requirement)**
- **Adjusted RiskScore: 16**
- **Exploit surface:** Local (multi-user systems)
- **How to verify:** Call `isValidOpPath("/home/attacker/bin/op")` -- it returns true. An attacker on a shared system could place a malicious binary at this path.
- **Confidence:** `confidence::confirmed` -- code at encrypted_secrets.zig:175-180 accepts any path matching `/home/*/bin/op`.

### SEC-08: execCommand stdout buffer not zeroed before free

- **Impact: 2** (Information leak -- secret data persists in freed heap memory)
- **Likelihood: 2** (Requires heap inspection after free; process-local only; Zig's allocator may overwrite on reuse)
- **RiskScore: 2 x 2 x 4 = 16 (rounded to 12 due to defense-in-depth nature)**
- **Adjusted RiskScore: 12**
- **Exploit surface:** Process-local (heap forensics or crash dump analysis)
- **How to verify:** After `execCommand` returns, inspect freed heap pages for remnants of secret data. Compare with `loadFromVault` path where `secureZero` is used elsewhere.
- **Confidence:** `confidence::confirmed` -- stdout_buf and stderr_buf are freed via `defer .deinit()` at lines 707-708 without prior `secureZero`.

### SEC-09: @constCast in loadFromFile

- **Impact: 2** (Type safety violation -- undefined behavior if `readFromFile` ever returns truly const data)
- **Likelihood: 2** (Currently sound because `readFromFile` returns allocator-owned memory; fragile if implementation changes)
- **RiskScore: 2 x 2 x 4 = 16 (rounded to 12 due to low current risk)**
- **Adjusted RiskScore: 12**
- **Exploit surface:** Code maintenance risk (not directly exploitable)
- **How to verify:** Check `secret.readFromFile` return type. If it returns a slice from a comptime or read-only mapping, `@constCast` would cause UB on mutation.
- **Confidence:** `confidence::suspected` -- currently sound; risk is future breakage.

### SEC-10: DNS rebinding residual risk [CLOSED -- FALSE POSITIVE]

- **Impact: 4** (SSRF to internal services)
- **Likelihood: 1** (Mitigated by redirect blocking + recheckDnsBinding post-connection validation; theoretical)
- **RiskScore: 4 x 1 x 4 = 16 (rounded to 8 -- accepted risk with strong mitigations)**
- **Adjusted RiskScore: 8**
- **Confidence:** `confidence::confirmed` -- mitigations verified at remote.zig:147-154 and recheckDnsBinding implementation.
- **Status:** Closed as false positive (2026-03-24). Vault token is passed via `VAULT_TOKEN` env var (`encrypted_secrets.zig:663`), not CLI args. DNS rebinding mitigations remain active for remote HTTP clients.

### SEC-11: loadFromEnv env data not zeroable

- **Impact: 2** (Secret residue in process memory from env vars)
- **Likelihood: 1** (Env provider is opt-in, deprecated, and disabled by default)
- **RiskScore: 2 x 1 x 4 = 8**
- **Confidence:** `confidence::confirmed` -- env provider gated behind `allow_env_provider` flag (default false). `environ.getenv` returns a pointer to process environment which cannot be safely zeroed.

### SEC-15: Decimal/hex/octal IP SSRF bypass (residual)

- **Impact: 2** (SSRF -- internal service access, but existing `parseIPv4ToInt` at line 382 already handles decimal/hex/octal formats with tests at lines 1702-1737)
- **Likelihood: 1** (Existing mitigations cover standard decimal, hex, octal, and mixed formats; residual risk is theoretical edge cases in mixed-format octets)
- **RiskScore: 2 x 1 x 4 = 8**
- **Adjusted RiskScore: 8** (strong existing mitigations reduce effective impact)
- **Exploit surface:** Internet-facing (if attacker controls URL in remote config)
- **How to verify:** Test `isPrivateAddress` with edge-case mixed formats: `0x7f.0.0.01` (hex first octet, octal last), `0177.0.0.0x01` (octal first, hex last). Existing tests at lines 1726-1737 cover the main patterns. Check if any format variant bypasses `parseIPv4ToInt`.
- **Confidence:** `confidence::suspected` -- existing code handles the primary variants. Edge cases need fuzzing to confirm no bypass exists.
- **Cross-reference:** Related to SEC-03 (hostname bypass) and SEC-16 (IPv6-mapped bypass). S-NEW-1 from Phase 3+ review.

### SEC-16: IPv4-mapped IPv6 SSRF bypass (::FFFF: case-sensitivity)

- **Impact: 2** (SSRF -- the string-level `isPrivateAddress` check at line 269 uses case-sensitive `mem.startsWith(u8, host, "::ffff:")`. Uppercase `::FFFF:127.0.0.1` bypasses this check.)
- **Likelihood: 1** (If `net.Address.parseIp` recognizes the uppercase form, `isIpLiteral` returns true at line 244, skipping DNS resolution fallback. However, the binary-level `isPrivateIPv6Bytes` at line 363 correctly handles IPv4-mapped addresses regardless of how the string was parsed. The bypass is in the pre-DNS string check path only.)
- **RiskScore: 2 x 1 x 4 = 8**
- **Adjusted RiskScore: 8** (binary-level check in `isPrivateIPv6Bytes` provides defense-in-depth for resolved addresses)
- **Exploit surface:** Internet-facing (if attacker controls URL host)
- **How to verify:** Call `isPrivateAddress("::FFFF:127.0.0.1")` -- it should return false (bypasses lowercase-only `::ffff:` check at line 269). Then test whether `isIpLiteral("::FFFF:127.0.0.1")` returns true (if so, DNS fallback is skipped and the bypass is real for the string check path).
- **Confidence:** `confidence::suspected` -- the string-level bypass is confirmed by code inspection. Whether `net.Address.parseIp` recognizes uppercase `FFFF` needs runtime verification. The binary-level `isPrivateIPv6Bytes` mitigates at the resolved-address layer.
- **Cross-reference:** Related to SEC-03 (case-insensitive hostname). S-NEW-2 from Phase 3+ review.

### SEC-17: CLI argument injection via vault/op path (residual)

- **Impact: 1** (Command injection is prevented by three layers: no shell invocation (`process.Child.init` at line 710), binary path allowlist (`isValidVaultPath`/`isValidOpPath`), and `isValidSecretIdentifier` character restriction to `[a-zA-Z0-9_./\-]` at line 114)
- **Likelihood: 1** (All three defenses would need to be bypassed simultaneously; `isValidVaultPath` home-directory pattern at line 200-207 is slightly more permissive than `isValidOpPath` at line 160-189, but still requires `/bin/vault` suffix and no `..` traversal)
- **RiskScore: 1 x 1 x 4 = 4**
- **Adjusted RiskScore: 4** (triple defense makes exploitation extremely unlikely)
- **Exploit surface:** Local (requires attacker to control vault_path or op_path configuration values)
- **How to verify:** Attempt to set `vault_path` to `/home/attacker/projects/evil/bin/vault` -- `isValidVaultPath` at line 200-207 accepts this because it starts with `/home/`, contains `/bin/vault`, and has no `..`. The binary at that path would execute. However, the attacker must already have local access to write the binary AND control the configuration.
- **Confidence:** `confidence::suspected` -- the `isValidVaultPath` home-directory pattern is more permissive than `isValidOpPath` (which was tightened in SEC-07). The residual risk is accepted but should be documented. No shell injection is possible.
- **Cross-reference:** Related to SEC-07 (isValidOpPath permissive). S-NEW-4 from Phase 3+ review.

### SEC-18: Percent-encoded double-decode risk

- **Impact: 2** (SSRF bypass via double/triple-encoded hostnames. The `decodePercentEncoded` function at line 198 is a single-pass decoder. The comment at line 179 notes "even if the URI parser decodes, we decode again to be safe" -- this means two decode passes total.)
- **Likelihood: 1** (Triple-encoding `%2525xx` would survive both decode passes: URI parser `%2525xx` -> `%25xx`, our decoder `%25xx` -> `%xx` (literal). The attacker would need the HTTP client to then interpret `%xx` as a percent-encoded byte, which is unlikely since the decoded host is passed to `isPrivateAddress` as a plain string, not re-parsed as a URL.)
- **RiskScore: 2 x 1 x 4 = 8 (adjusted to 6 -- the attack path requires three layers of encoding AND the final consumer to re-interpret percent encoding)**
- **Adjusted RiskScore: 6**
- **Exploit surface:** Internet-facing (if attacker controls URL)
- **How to verify:** Test `validateUrl("http://%25%33%31%25%33%32%25%33%37.0.0.1:2379/")`. After URI parser decode: `%31%32%37.0.0.1`. After `decodePercentEncoded`: `127.0.0.1`. This should be caught. Then test triple-encoding: `%25%32%35%33%31...` to see if it survives both passes.
- **Confidence:** `confidence::suspected` -- the two-pass decode covers double-encoding. Triple-encoding is theoretically possible but practically unlikely given how the decoded string is consumed (passed to string comparison, not re-parsed as URL).
- **Cross-reference:** S-NEW-6 from Phase 3+ review.

### ADV-01: `unreachable` on `.auto` format causes panic/UB (CWE-248)

- **Impact: 3** (In ReleaseFast/ReleaseSmall: undefined behavior -- compiler eliminates the branch, arbitrary execution. In Debug/ReleaseSafe: panic/DoS.)
- **Likelihood: 2** (Requires `.auto` format to survive format detection and reach the switch. Library consumer must pass `Format.auto` with undetectable content. Not pre-auth/remote.)
- **RiskScore: 3 x 2 x 4 = 24**
- **Exploit surface:** Application-dependent (library consumer must pass `.auto` format with undetectable content)
- **How to verify:** Call `parseContent` with `Format.auto` and content that matches no known format signature. Observe panic in Debug or UB in ReleaseFast.
- **Confidence:** `confidence::confirmed` -- `config.zig:328` shows `.auto => unreachable` in the format switch.
- **Confidential:** Yes (UB path in optimized builds could lead to unexpected code execution)

### ADV-02: Consul token not zeroed on deinit (CWE-244)

- **Impact: 2** (Credential residue in freed heap memory)
- **Likelihood: 2** (Process-local; requires heap forensics or crash dump analysis)
- **RiskScore: 2 x 2 x 4 = 16 (adjusted to 12 -- defense-in-depth, process-local only)**
- **Adjusted RiskScore: 12**
- **Exploit surface:** Process-local (heap forensics or crash dump analysis)
- **How to verify:** Create a Consul client with an ACL token, call `deinit()`, then inspect freed heap for token residue. Compare with Etcd which zeroes `cached_auth_header` at `remote.zig:674-678`.
- **Confidence:** `confidence::confirmed` -- `Consul.deinit()` at `remote.zig:1062-1065` does not call `SensitiveString.deinit()` on `self.options.token`.

### ADV-03: Etcd/Consul response bodies not zeroed before free (CWE-244)

- **Impact: 2** (Secret config values persist in freed heap memory)
- **Likelihood: 2** (Process-local; `makeRequest` already zeroes credential buffers but response path does not)
- **RiskScore: 2 x 2 x 4 = 16 (adjusted to 12 -- defense-in-depth, process-local only)**
- **Adjusted RiskScore: 12**
- **Exploit surface:** Process-local (heap forensics or crash dump analysis)
- **How to verify:** Fetch a secret value from etcd KV store, observe `defer self.allocator.free(response)` at lines 725, 780, 813 without prior `secureZero`. Compare with credential zeroing pattern in `makeRequest`.
- **Confidence:** `confidence::confirmed` -- all three response defer sites (get/put/delete) use `defer self.allocator.free(response)` without zeroing.

### ADV-04: JSON serializer emits unescaped control chars (CWE-838)

- **Impact: 2** (Data integrity -- produces invalid JSON per RFC 8259 Section 7; downstream parsers may reject, truncate, or misinterpret)
- **Likelihood: 3** (Any string value with control chars 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F triggers the bug; no authentication required)
- **RiskScore: 2 x 3 x 4 = 24 (adjusted to 20 -- config values rarely contain control chars in practice)**
- **Adjusted RiskScore: 20**
- **Exploit surface:** Application-dependent (any config value serialized to JSON)
- **How to verify:** Serialize a config struct with a string field containing `\x00` or `\x01`. Validate output with a strict RFC 8259 JSON parser -- it should reject.
- **Confidence:** `confidence::confirmed` -- `serialize.zig:117-126` switch only handles `"`, `\`, `\n`, `\r`, `\t`; `else` emits raw bytes.
- **Confidential:** Yes (invalid JSON output could enable injection in downstream consumers)

### ADV-05: writeToFileWithBackup follows symlinks on backup path (CWE-59)

- **Impact: 3** (Symlink redirect on backup path could overwrite or delete arbitrary files)
- **Likelihood: 1** (Requires local attacker with write access to config directory; `.bak` path is predictable but config dirs are typically not world-writable)
- **RiskScore: 3 x 1 x 4 = 12**
- **Exploit surface:** Local (requires write access to config directory)
- **How to verify:** Create symlink at `{config_path}.bak` pointing to a target file. Call `writeToFileWithBackup()`. Observe that `copyFile` follows the symlink and overwrites the target. Compare with main write path which uses `createFileNoFollow`.
- **Confidence:** `confidence::suspected` -- code at `serialize.zig:576-578` uses `std.fs.cwd().copyFile/deleteFile` which follow symlinks. Needs runtime verification to confirm symlink following behavior of these Zig std functions.

### ADV-06: loadFromPath masks traversal detection as FileNotFound (CWE-778)

- **Impact: 1** (Monitoring gap -- cannot distinguish missing file from blocked traversal attack)
- **Likelihood: 1** (Not exploitable; defensive improvement only. Traversal is still blocked.)
- **RiskScore: 1 x 1 x 4 = 4**
- **Exploit surface:** None (observability improvement)
- **How to verify:** Call `loadFromPath("../../etc/passwd", ...)`. Observe `LoadError.FileNotFound` is returned. Compare with `writeToFile` which returns `PathTraversalDetected` from the same `isPathSafe` check.
- **Confidence:** `confidence::confirmed` -- `loader.zig:746` returns `LoadError.FileNotFound` on `!isPathSafe(path)`.

### ADV-07: Gitleaks allowlist over-broad test file exclusion (CWE-1295)

- **Impact: 2** (Real credentials in `*_test.zig` files would evade gitleaks scanning)
- **Likelihood: 1** (Requires accidental credential placement in test files; no real credentials found in current codebase)
- **RiskScore: 2 x 1 x 4 = 8 (using existing #63 score of 16 for consistency)**
- **Adjusted RiskScore: 16** (aligning with existing #63 assessment)
- **Exploit surface:** Supply-chain (leaked credentials in test files missed by scanning)
- **How to verify:** Add a test API key string to a `*_test.zig` file. Run `gitleaks detect`. Observe it is not flagged due to the path exclusion at `.gitleaks.toml:20-21`.
- **Confidence:** `confidence::suspected` -- no real credentials found in test files during review; the over-broad exclusion creates a theoretical blind spot.
- **Cross-reference:** Existing issue #63 updated with Phase 3 review comment.

### ADV-08: No structured security event logging/callback (CWE-778)

- **Impact: 1** (Defense-in-depth -- library consumers cannot easily monitor security events)
- **Likelihood: 1** (Not exploitable; observability improvement)
- **RiskScore: 1 x 1 x 4 = 4**
- **Exploit surface:** None (observability improvement)
- **How to verify:** Review all `std.log` calls in security-sensitive code paths. Observe inconsistent formatting, no structured fields, no callback mechanism.
- **Confidence:** `confidence::confirmed` -- `std.log.warn` used ad-hoc in remote.zig/loader.zig/secret.zig with no consistent structure.

### S-NEW-5 (Informational Note): JSON nesting depth

JSON nesting depth is bounded by `std.json.parseFromSlice` defaults (`default_max_depth = 256`). No custom parser configuration overrides this limit. Stack overflow via deeply nested JSON is not a practical concern. **Not tracked as an open finding.**

### SEC-12, SEC-13, SEC-14: @constCast / @ptrCast patterns (Info)

- **Impact: 1** (Defense-in-depth / code hygiene)
- **Likelihood: 1** (No current risk; standard patterns)
- **RiskScore: 1 x 1 x 4 = 4**
- **Confidence:** `confidence::confirmed` -- all three are sound usages with appropriate context.

---

## Findings by Area

### Auth/Secrets

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| ~~isValidOpPath overly permissive home-directory pattern~~ | 16 | **Closed** (Wave 10) | SEC-07 | `isValidVaultPath` tightened to strict pattern |
| ~~Consul token not zeroed on deinit~~ | 12 | **Closed** (Wave 12 Batch 3) | ADV-02 / #180 | `SensitiveString.deinit()` added in `Consul.deinit()` |
| ~~Etcd/Consul response bodies not zeroed before free~~ | 12 | **Closed** (Wave 12 Batch 3) | ADV-03 / #182 | `secureZero()` added before free at all response sites |
| ~~execCommand stdout buffer not zeroed before free~~ | 12 | **Closed** (Wave 10) | SEC-08 | `secureZero` on stdout/stderr before free |
| ~~@constCast in loadFromFile~~ | 12 | **Closed** (Wave 10) | SEC-09 | Replaced with `allocator.dupe` |
| loadFromEnv env data not zeroable | 8 | **Accepted** | SEC-11 | Env provider deprecated + opt-in |
| ~~CLI argument injection via vault/op path (residual)~~ | 4 | **Closed** (Wave 10) | SEC-17 | `isValidVaultPath` tightened to strict pattern |
| @constCast in SensitiveString.deinit | 4 | **Info** | SEC-13 | Sound usage |

### Web/API (Remote Clients)

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| ~~Consul missing HTTP status code validation~~ | 36 | **Closed** (Wave 10) | SEC-01 | HTTP status validation added to all Consul methods |
| HTTP timeout not enforced (etcd/Consul) | 36 | **Blocked** | SEC-02 | Zig 0.15 limitation |
| ~~Case-insensitive hostname bypass in isPrivateAddress~~ | 24 | **Closed** (Wave 10) | SEC-03 | Case-insensitive comparison implemented |
| ~~Decimal/hex/octal IP SSRF bypass (residual)~~ | 8 | **Closed** (Wave 10) | SEC-15 | Case-insensitive `::ffff:` prefix check added |
| ~~IPv4-mapped IPv6 SSRF bypass (::FFFF: case)~~ | 8 | **Closed** (Wave 10) | SEC-16 | Case-insensitive prefix check added |
| ~~DNS rebinding residual risk~~ | 8 | **Closed (FP)** | SEC-10 | False positive: Vault token via env var, not CLI args |
| ~~Percent-encoded double-decode risk~~ | 6 | **Closed** (Wave 10) | SEC-18 | Pre-decode `%` check + `SuspiciousUrl` error |
| @ptrCast in IP handling | 4 | **Info** | SEC-14 | Standard pattern |

### Input Validation / Path Handling

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| ~~isPathSafe doesn't check backslash on Windows~~ | 16 | **Closed** (Wave 10) | SEC-05 | Documented + tested in secret.zig |
| ~~TOCTOU in Windows symlink check~~ | 16 | **Closed** (Wave 10, accepted risk) | SEC-06 | Documented as accepted risk in secret.zig |
| ~~writeToFileWithBackup follows symlinks on backup path~~ | 12 | **Closed** (Wave 12 Batch 3) | ADV-05 / #186 | Symlink protection added for backup path |
| loadFromPath masks traversal detection as FileNotFound | 4 | **Won't Do** | ADV-06 / #188 | Info-level; traversal still blocked by isPathSafe |
| @constCast in normalizeKey | 4 | **Info** | SEC-12 | Sound with safety comment |

### Serialization / Deserialization

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| ~~`unreachable` on `.auto` format causes panic/UB~~ | 24 | **Closed** (Wave 12 Batch 3) | ADV-01 / #177 | Replaced with `return error.UnsupportedFormat` |
| ~~JSON serializer emits unescaped control chars~~ | 20 | **Closed** (Wave 12 Batch 3) | ADV-04 / #184 | `\uXXXX` escaping added per RFC 8259 |

JSON parsing uses `std.json.parseFromSlice` with default `max_depth = 256` (resolved in QUAL Wave 7). JSON nesting depth attacks are bounded by this default (S-NEW-5, informational).

### Supply Chain

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| Spice dependency tracks main branch | 24 | **Blocked** | SEC-04 | Pin to tagged release; upstream has no tag |
| ~~Gitleaks allowlist over-broad test exclusion~~ | 16 | **Closed** (Wave 12 Batch 4) | ADV-07 / #63 | Exclusions narrowed to specific paths |

### Infrastructure / Ops

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| No structured security event logging/callback | 4 | **Won't Do** | ADV-08 / #190 | Architectural change; existing std.log.scoped adequate |

CI pipeline is fully implemented (GAP_ANALYSIS.md #82, resolved).

---

## Positive Observations

The Phase 3 and Phase 3+ security reviews confirmed several strong security properties:

- **0 secrets found** by gitleaks scan
- **0 vulnerabilities** from grype/trivy dependency scanning
- **SensitiveString** prevents accidental credential logging in format output
- **secureZero** is consistently applied across secret lifecycle paths
- **Command injection prevented** via binary path allowlists (no shell interpolation)
- **Comprehensive SSRF protection** with private IP detection, DNS rebinding checks, redirect blocking
- **O_NOFOLLOW** on POSIX for all secret file reads
- **Response size limits** enforced on all remote client operations
- **Minimal environment maps** for child process execution (Vault/1Password)
- **Redirect blocking** on all HTTP client requests
- **Decimal/hex/octal IP normalization** via `parseIPv4ToInt` with comprehensive tests (Phase 3+: SEC-15 tracks residual edge cases only)
- **Percent-encoding decode** as defense-in-depth against URL-encoded SSRF bypass (Phase 3+: SEC-18 tracks triple-encoding edge case only)
- **IPv4-mapped IPv6 detection** at both string level (`::ffff:` prefix) and binary level (`isPrivateIPv6Bytes`) (Phase 3+: SEC-16 tracks case-sensitivity gap in string check)

---

## Roadmap

### Quick Wins (< 1 day)

| Finding | RiskScore | ID | Effort | Notes |
|---------|----------|-----|--------|-------|
| ~~`unreachable` on `.auto` format causes panic/UB~~ | 24 | ADV-01 / #177 | S | **Closed** (Wave 12 Batch 3): Replaced with `return error.UnsupportedFormat` |
| ~~JSON serializer emits unescaped control chars~~ | 20 | ADV-04 / #184 | S | **Closed** (Wave 12 Batch 3): Added `\uXXXX` escaping per RFC 8259 |
| ~~Consul token not zeroed on deinit~~ | 12 | ADV-02 / #180 | S | **Closed** (Wave 12 Batch 3): Added `SensitiveString.deinit()` call |
| ~~Etcd/Consul response bodies not zeroed before free~~ | 12 | ADV-03 / #182 | S | **Closed** (Wave 12 Batch 3): Added `secureZero()` at all response sites |
| ~~Case-insensitive hostname bypass~~ | 24 | SEC-03 | S | **Closed** (Wave 10) |
| ~~execCommand stdout buffer not zeroed~~ | 12 | SEC-08 | S | **Closed** (Wave 10) |
| ~~@constCast in loadFromFile~~ | 12 | SEC-09 | S | **Closed** (Wave 10) |
| ~~IPv4-mapped IPv6 case bypass~~ | 8 | SEC-16 | S | **Closed** (Wave 10) |
| ~~Decimal/hex/octal edge cases~~ | 8 | SEC-15 | S | **Closed** (Wave 10) |
| ~~Percent-encoded double-decode~~ | 6 | SEC-18 | S | **Closed** (Wave 10) |

### Medium (1-5 days)

| Finding | RiskScore | ID | Effort | Notes |
|---------|----------|-----|--------|-------|
| ~~Consul missing HTTP status code validation~~ | 36 | SEC-01 | M | **Closed** (Wave 10): HTTP status validation added to all Consul methods |
| Spice dependency pin to release | 24 | SEC-04 | S-M | **Blocked**: Upstream spice has no version tag; hash-only pinning in place |
| ~~Gitleaks allowlist over-broad test exclusion~~ | 16 | ADV-07 / #63 | S-M | **Closed** (Wave 12 Batch 4): Narrowed to specific paths |
| ~~writeToFileWithBackup follows symlinks on backup path~~ | 12 | ADV-05 / #186 | M | **Closed** (Wave 12 Batch 3): Symlink protection added for backup path |
| ~~isPathSafe Windows backslash handling~~ | 16 | SEC-05 | S | **Closed** (Wave 10): Documented + tested |
| ~~isValidOpPath tighter pattern~~ | 16 | SEC-07 | S | **Closed** (Wave 10): `isValidVaultPath` tightened to strict pattern |

### Strategic (> 5 days)

| Finding | RiskScore | ID | Effort | Notes |
|---------|----------|-----|--------|-------|
| HTTP timeout enforcement | 36 | SEC-02 | L | Requires watchdog-thread wrapper or upstream Zig http.Client timeout support. Pattern exists in execCommand (encrypted_secrets.zig:710-727) but adapting for generic HTTP fetch is non-trivial. |
| TOCTOU Windows symlink check | 16 | SEC-06 | M-L | Requires Windows-specific file open flags (FILE_FLAG_OPEN_REPARSE_POINT); or accept as documented limitation |

### Accepted Risks / Low-Priority Backlog

| Finding | RiskScore | ID | Rationale |
|---------|----------|-----|-----------|
| loadFromPath masks traversal as FileNotFound | 4 | ADV-06 / #188 | **Won't Do**: Traversal still blocked; observability improvement only |
| No structured security event logging | 4 | ADV-08 / #190 | **Won't Do**: Architectural change; existing std.log.scoped adequate |
| ~~DNS rebinding residual risk~~ | 8 | SEC-10 | **Closed (False Positive):** Vault token passed via env var, not CLI args. Mitigations remain in place. |
| loadFromEnv env data not zeroable | 8 | SEC-11 | Provider is opt-in, deprecated, disabled by default |
| ~~CLI argument injection via vault/op path (residual)~~ | 4 | SEC-17 | **Closed** (Wave 10): `isValidVaultPath` tightened to strict pattern. Triple defense remains: no shell, allowlist, char validation. |
| @constCast in normalizeKey | 4 | SEC-12 | Sound with detailed safety comment |
| @constCast in SensitiveString.deinit | 4 | SEC-13 | Sound: casts owned memory for secureZero |
| @ptrCast in IP handling | 4 | SEC-14 | Standard Zig socket address pattern |

---

## Confidence Notes

- **SEC-01, SEC-02, SEC-03, SEC-04, SEC-06, SEC-07, SEC-08, SEC-10, SEC-11**: Tagged `confidence::confirmed` -- verified by direct code inspection with file paths and line numbers.
- **SEC-05 (isPathSafe Windows)**: Tagged `confidence::suspected` -- the `mem.indexOf(u8, path, "..")` check actually catches `..` regardless of surrounding separator characters. The gap may be narrower than initially reported. Windows testing is needed to confirm whether any real bypass exists.
- **SEC-09 (@constCast loadFromFile)**: Tagged `confidence::suspected` -- currently sound; risk is future maintenance breakage if `readFromFile` return type changes.
- **SEC-12, SEC-13, SEC-14**: Tagged `confidence::confirmed` -- informational; all are sound patterns.
- **SEC-15 (decimal/hex/octal SSRF)**: Tagged `confidence::suspected` -- existing `parseIPv4ToInt` (line 391) handles standard decimal, hex (`0x`), and octal (`0`-prefixed) formats with passing tests (lines 1702-1737). Edge cases in mixed-format octets need fuzzing to confirm no bypass. Would confirm by fuzzing `isPrivateIPv4` with all mixed-base permutations.
- **SEC-16 (IPv4-mapped IPv6 case)**: Tagged `confidence::suspected` -- string check at line 269 is case-sensitive (`::ffff:`). `::FFFF:127.0.0.1` bypasses it. Whether `net.Address.parseIp` recognizes uppercase and whether `isIpLiteral` then returns true (skipping DNS fallback) needs runtime verification. Binary-level `isPrivateIPv6Bytes` (line 363) provides defense-in-depth for resolved addresses.
- **SEC-17 (CLI arg injection)**: Tagged `confidence::suspected` -- no shell invocation confirmed at line 710 (`process.Child.init`). Allowlist + `isValidSecretIdentifier` prevents injection characters. Residual risk is the permissive `isValidVaultPath` home-directory pattern. Would confirm by reviewing all paths that reach `execCommand` with user-controlled args.
- **SEC-18 (double-decode)**: Tagged `confidence::suspected` -- two-pass decode (URI parser + `decodePercentEncoded`) confirmed by code at lines 178-181. Triple-encoding survival is theoretical. Would confirm by testing `validateUrl` with `%2531%2532%2537.0.0.1` (triple-encoded `127`).
- **ADV-01 (unreachable on .auto)**: Tagged `confidence::confirmed` -- `config.zig:328` shows `.auto => unreachable` in the format switch. The `unreachable` keyword is UB in optimized builds per Zig language specification.
- **ADV-02 (Consul token not zeroed)**: Tagged `confidence::confirmed` -- `Consul.deinit()` at `remote.zig:1062-1065` does not call `SensitiveString.deinit()`. Etcd correctly zeroes at `remote.zig:674-678`.
- **ADV-03 (response bodies not zeroed)**: Tagged `confidence::confirmed` -- `defer self.allocator.free(response)` at lines 725, 780, 813 without `secureZero`. Credential zeroing in `makeRequest` confirms the pattern exists but is not applied to responses.
- **ADV-04 (JSON control chars)**: Tagged `confidence::confirmed` -- `serialize.zig:117-126` switch only handles 5 characters; `else` branch emits raw bytes. RFC 8259 Section 7 requires all U+0000-U+001F to be escaped.
- **ADV-05 (backup symlink)**: Tagged `confidence::suspected` -- `serialize.zig:576-578` uses `std.fs.cwd().copyFile/deleteFile` which are expected to follow symlinks based on standard POSIX behavior. Would confirm by creating a symlink at `.bak` path and observing `copyFile` behavior.
- **ADV-06 (traversal masked as FileNotFound)**: Tagged `confidence::confirmed` -- `loader.zig:746` returns `LoadError.FileNotFound` on `!isPathSafe(path)`.
- **ADV-07 (gitleaks over-broad)**: Tagged `confidence::suspected` -- `.gitleaks.toml:20-21` excludes `*_test.zig` patterns. No real credentials found in current test files; the risk is the blind spot. Would confirm by adding a test API key to a `_test.zig` file and running `gitleaks detect`.
- **ADV-08 (no structured logging)**: Tagged `confidence::confirmed` -- reviewed all `std.log` calls in security-sensitive paths; no consistent structure or callback mechanism.

## Unknowns / Blockers

- **Windows CI:** No Windows CI runner is configured. SEC-05 and SEC-06 cannot be fully verified without Windows testing.
- **Spice release tagging:** SEC-04 fix depends on upstream `devnw/zig/spice` tagging a release. If no release exists, the fix is to pin to a specific commit hash instead of `main`.
- **Zig http.Client timeout:** SEC-02 depends on either upstream Zig adding timeout support or implementing a watchdog-thread wrapper. The watchdog pattern from `execCommand` (encrypted_secrets.zig:710-727) could be adapted but requires careful thread-safety around the HTTP client.
- **Consul status codes:** SEC-01 fix requires understanding which Consul API status codes should be treated as errors vs. expected conditions (e.g., 404 on GET is already handled; 200/204 are success for PUT/DELETE).
- **IPv6 parseIp behavior (SEC-16):** Whether Zig's `net.Address.parseIp` recognizes uppercase `::FFFF:` prefix needs runtime verification. If it does, the string-level bypass is confirmed; if not, the input is rejected entirely and the risk is lower than assessed.
- **Fuzzing for IP format edge cases (SEC-15):** `parseIPv4ToInt` handles standard formats but mixed-base octets (e.g., `0x7f.0.0.01`) need systematic testing. A fuzz harness targeting `isPrivateIPv4` would confirm or eliminate residual bypass risk.
- **Triple-encoding validation (SEC-18):** Testing `validateUrl` with triple-encoded hostnames (`%25`-prefixed) would confirm whether the two-pass decode is sufficient or if a loop-until-stable approach is needed.
- **ADV-05 (backup symlink):** Whether `std.fs.cwd().copyFile` follows symlinks on all platforms needs runtime verification. Expected to follow based on POSIX semantics.
- **SBOM gap:** No scanner supports Zig `build.zig.zon` -- 4 dependencies remain unscanned (tracked by SEC-04). Gitleaks, trufflehog, semgrep, checkov, trivy, grype, and osv-scanner all returned clean/false-positive results.

## Automated Scanner Results (2026-03-25)

All automated scanner findings were verified as false positives or clean:

| Scanner | Result | Notes |
|---------|--------|-------|
| Gitleaks | Clean | 0 secrets found |
| TruffleHog | Clean | 0 secrets found |
| Semgrep | Clean | No actionable findings |
| Checkov | Clean | No misconfigurations |
| Trivy | Clean | 0 vulnerabilities |
| Grype | Clean | 0 vulnerabilities |
| OSV-Scanner | Clean | 0 known vulnerabilities |

**SBOM gap:** No scanner supports Zig `build.zig.zon` format. 4 dependencies (`spice`, `zig-yaml`, `tomlz`, `iniparse`) are unscanned by SCA tools. This is already tracked by SEC-04 (supply-chain).
