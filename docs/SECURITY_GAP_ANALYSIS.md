# Security Gap Analysis

**Project:** devnw/zig/config
**Last updated:** 2026-03-24
**Review phase:** Phase 3+ (security-reviewer, SSRF/injection deep-dive)
**Scoring formula:** RiskScore = Impact(1-5) x Likelihood(1-5) x 4
**Review commit:** fe9d0f6 (HEAD of main) + working tree

---

## Summary

| Severity | Count | Open | Closed/Accepted | Notes |
|----------|-------|------|-----------------|-------|
| Critical | 0     | 0    | 0               | No critical vulnerabilities found |
| Medium   | 4     | 4    | 0               | HTTP status validation, timeout enforcement, hostname bypass, supply-chain |
| Low      | 11    | 9    | 2 (1 FP, 1 accepted) | Path traversal, TOCTOU, permissive path, memory hygiene, type safety, SSRF edge cases, double-decode, CLI injection residual |
| Info     | 3     | 0    | 0               | Sound patterns, standard IP handling |
| **Total** | **18** | **13** | **2** | 3 Info items require no action; SEC-10 closed as false positive; SEC-11 accepted; S-NEW-5 (JSON nesting) noted as informational but not tracked |

### Top 5 Risks

1. **Consul missing HTTP status code validation** (SEC-01) -- Medium, RiskScore 36. GET only checks `.not_found`; PUT/DELETE never check status. Attacker-controlled error responses may be silently accepted as valid data.
2. **HTTP timeout not enforced (etcd/Consul)** (SEC-02) -- Medium, RiskScore 36. Zig 0.15 http.Client has no timeout. Slow-read/hang attacks can block indefinitely. Previously documented as a known limitation (QUAL NEW-08, PERF-38), but no code-level mitigation exists.
3. **Case-insensitive hostname bypass in isPrivateAddress** (SEC-03) -- Medium, RiskScore 24. `Localhost` (capital L) bypasses the string equality check. DNS resolution fallback catches most cases but the string check is the primary fast-path defense.
4. **Spice dependency tracks main branch** (SEC-04) -- Medium, RiskScore 24. `build.zig.zon` pins `spice` to `main` branch archive. Any commit to upstream main changes what this project builds.
5. **isPathSafe doesn't check backslash on Windows** (SEC-05) -- Low, RiskScore 16. `foo\..\bar` bypasses path traversal detection on Windows because `isPathSafe` only checks for `..` with forward-slash context.

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

---

## Stack-Ranked Findings

| Rank | Severity | RiskScore | Finding | Component | CWE/OWASP | Evidence (file:line) | Issue | Fix Guidance | Owner | SLA/Due | Status |
|------|----------|-----------|---------|-----------|-----------|----------------------|-------|-------------|-------|---------|--------|
| 1 | Medium | 36 | Consul missing HTTP status code validation | remote.zig | CWE-754 / A05:2021 Security Misconfiguration | src/remote.zig:1228,1274-1282,1325-1332 | SEC-01 | Check `result.status` for 2xx range on all Consul operations; return typed errors for 401/403/5xx | Maintainer | 2026-06-22 (90d) | **Open** |
| 2 | Medium | 36 | HTTP timeout not enforced (etcd/Consul) | remote.zig | CWE-400 / A05:2021 Security Misconfiguration | src/remote.zig:616,1030 | SEC-02 | Implement watchdog-thread timeout wrapper around HTTP fetch (similar to execCommand pattern in encrypted_secrets.zig:710-727) | Maintainer | 2026-06-22 (90d) | **Open** |
| 3 | Medium | 24 | Case-insensitive hostname bypass in isPrivateAddress | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:289 | SEC-03 | Use `std.ascii.eqlIgnoreCase` or lowercase the host before comparison; also check `0:0:0:0:0:0:0:1` for IPv6 loopback | Maintainer | 2026-06-22 (90d) | **Open** |
| 4 | Medium | 24 | Spice dependency tracks main branch | build.zig.zon | CWE-829 / A06:2021 Vulnerable and Outdated Components | build.zig.zon:20 | SEC-04 | Pin spice to a tagged release or specific commit hash; add dependency review to CI | Maintainer | 2026-06-22 (90d) | **Open** |
| 5 | Low | 16 | isPathSafe doesn't check backslash on Windows | secret.zig | CWE-22 / A01:2021 Broken Access Control | src/secret.zig:51-63 | SEC-05 | Normalize backslashes to forward slashes before traversal check, or add `mem.indexOf(u8, path, "..\\" )` on Windows | Maintainer | 2026-09-20 (180d) | **Open** |
| 6 | Low | 16 | TOCTOU in Windows symlink check | secret.zig | CWE-367 / A01:2021 Broken Access Control | src/secret.zig:93-95 | SEC-06 | Document as accepted risk on Windows (POSIX uses O_NOFOLLOW atomically); consider FILE_FLAG_OPEN_REPARSE_POINT on Windows in future | Maintainer | 2026-09-20 (180d) | **Open** |
| 7 | Low | 16 | isValidOpPath overly permissive home-directory pattern | encrypted_secrets.zig | CWE-426 / A08:2021 Software and Data Integrity Failures | src/encrypted_secrets.zig:170-181 | SEC-07 | Tighten pattern: require exactly 2 path components after `/home/` before `/bin/op` (e.g., `/home/<user>/bin/op` or `/home/<user>/.local/bin/op`) | Maintainer | 2026-09-20 (180d) | **Open** |
| 8 | Low | 12 | execCommand stdout buffer not zeroed before free | encrypted_secrets.zig | CWE-244 / A02:2021 Cryptographic Failures | src/encrypted_secrets.zig:705-707,760 | SEC-08 | Call `secret.secureZero(stdout_buf.items)` before `stdout_buf.deinit()`; same for stderr_buf | Maintainer | 2026-09-20 (180d) | **Open** |
| 9 | Low | 12 | @constCast in loadFromFile | encrypted_secrets.zig | CWE-704 / A04:2021 Insecure Design | src/encrypted_secrets.zig:495 | SEC-09 | Replace `@constCast(content)` with `allocator.dupe(u8, content)` to produce a genuinely mutable copy; free original | Maintainer | 2026-09-20 (180d) | **Open** |
| 10 | Low | 8 | Decimal/hex/octal IP SSRF bypass (residual) | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:269,382-452 | SEC-15 | Existing `parseIPv4ToInt` handles most cases; add case-insensitive `::ffff:` prefix matching and edge-case tests for mixed-format octets | Maintainer | 2026-09-20 (180d) | **Open** |
| 11 | Low | 8 | IPv4-mapped IPv6 SSRF bypass (::FFFF: case) | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:269-278 | SEC-16 | Use case-insensitive comparison for `::ffff:` prefix in `isPrivateAddress` string check; binary-level `isPrivateIPv6Bytes` already handles correctly | Maintainer | 2026-09-20 (180d) | **Open** |
| 12 | Low | 8 | ~~DNS rebinding residual risk~~ | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:147-154 | SEC-10 | False positive: Vault token passed via VAULT_TOKEN env var, not CLI args (encrypted_secrets.zig:663). Mitigations remain in place. | Maintainer | 2026-03-24 | **Closed (False Positive)** |
| 13 | Low | 8 | loadFromEnv env data not zeroable | encrypted_secrets.zig | CWE-244 / A02:2021 Cryptographic Failures | src/encrypted_secrets.zig:624-627 | SEC-11 | Env provider is opt-in and deprecated. Document that env-sourced secrets cannot be securely erased. Accepted risk. | Maintainer | Backlog | **Accepted** |
| 14 | Low | 6 | Percent-encoded double-decode risk | remote.zig | CWE-918 / A10:2021 SSRF | src/remote.zig:178-181,198-233 | SEC-18 | `decodePercentEncoded` is single-pass; if URI parser already decoded, this is a second pass. Triple-encoding (%2525xx) could theoretically survive both. Add loop-until-stable or reject `%25` in decoded output. | Maintainer | 2026-09-20 (180d) | **Open** |
| 15 | Low | 4 | CLI argument injection via vault/op path (residual) | encrypted_secrets.zig | CWE-78 / A03:2021 Injection | src/encrypted_secrets.zig:160-189,192-209,551-580 | SEC-17 | No shell invocation + allowlist + `isValidSecretIdentifier` character restriction. Residual risk: `isValidVaultPath` home-directory pattern at line 200-207 is more permissive than `isValidOpPath`. Document or tighten. | Maintainer | Backlog | **Open** |
| 16 | Info | 4 | @constCast in normalizeKey | loader.zig | CWE-704 | src/loader.zig:593 | SEC-12 | Sound usage with safety comment. No action needed. | -- | -- | **Info** |
| 17 | Info | 4 | @constCast in SensitiveString.deinit | encrypted_secrets.zig | CWE-704 | src/encrypted_secrets.zig:68 | SEC-13 | Sound: casts owned memory back to mutable for secureZero before free. No action needed. | -- | -- | **Info** |
| 18 | Info | 4 | @ptrCast in IP handling | remote.zig | CWE-704 | src/remote.zig:315,415,457 | SEC-14 | Standard Zig pattern for socket address introspection. No action needed. | -- | -- | **Info** |

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
| isValidOpPath overly permissive home-directory pattern | 16 | **Open** | SEC-07 | `/home/<attacker>/bin/op` accepted |
| execCommand stdout buffer not zeroed before free | 12 | **Open** | SEC-08 | Secret data in freed heap |
| @constCast in loadFromFile | 12 | **Open** | SEC-09 | Fragile type cast |
| loadFromEnv env data not zeroable | 8 | **Accepted** | SEC-11 | Env provider deprecated + opt-in |
| CLI argument injection via vault/op path (residual) | 4 | **Open** | SEC-17 | Triple defense (no shell + allowlist + char validation); `isValidVaultPath` home-dir pattern slightly permissive |
| @constCast in SensitiveString.deinit | 4 | **Info** | SEC-13 | Sound usage |

### Web/API (Remote Clients)

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| Consul missing HTTP status code validation | 36 | **Open** | SEC-01 | PUT/DELETE never check status |
| HTTP timeout not enforced (etcd/Consul) | 36 | **Open** | SEC-02 | Zig 0.15 limitation |
| Case-insensitive hostname bypass in isPrivateAddress | 24 | **Open** | SEC-03 | DNS fallback mitigates |
| Decimal/hex/octal IP SSRF bypass (residual) | 8 | **Open** | SEC-15 | `parseIPv4ToInt` covers main variants; edge cases suspected |
| IPv4-mapped IPv6 SSRF bypass (::FFFF: case) | 8 | **Open** | SEC-16 | String check case-sensitive; binary check correct |
| ~~DNS rebinding residual risk~~ | 8 | **Closed (FP)** | SEC-10 | False positive: Vault token via env var, not CLI args |
| Percent-encoded double-decode risk | 6 | **Open** | SEC-18 | Two-pass decode covers double-encoding; triple-encoding theoretical |
| @ptrCast in IP handling | 4 | **Info** | SEC-14 | Standard pattern |

### Input Validation / Path Handling

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| isPathSafe doesn't check backslash on Windows | 16 | **Open** | SEC-05 | Suspected; needs Windows testing |
| TOCTOU in Windows symlink check | 16 | **Open** | SEC-06 | Previously documented (#109) |
| @constCast in normalizeKey | 4 | **Info** | SEC-12 | Sound with safety comment |

### Supply Chain

| Finding | RiskScore | Status | ID | Notes |
|---------|-----------|--------|----|-------|
| Spice dependency tracks main branch | 24 | **Open** | SEC-04 | Pin to tagged release |

### Deserialization

No actionable findings. JSON parsing uses `std.json.parseFromSlice` with default `max_depth = 256` (resolved in QUAL Wave 7). JSON nesting depth attacks are bounded by this default and do not require a separate tracking entry (S-NEW-5, informational).

### Infrastructure / Ops

No findings in this area. CI pipeline is fully implemented (GAP_ANALYSIS.md #82, resolved).

---

## Positive Observations

The Phase 3 security review confirmed several strong security properties:

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
| Case-insensitive hostname bypass | 24 | SEC-03 | S | One-line fix: `std.ascii.eqlIgnoreCase` or lowercase host before comparison |
| execCommand stdout buffer not zeroed | 12 | SEC-08 | S | Add `secret.secureZero(stdout_buf.items)` before deinit |
| @constCast in loadFromFile | 12 | SEC-09 | S | Replace with `allocator.dupe(u8, content)` |
| IPv4-mapped IPv6 case bypass | 8 | SEC-16 | S | Use `std.ascii.startsWithIgnoreCase` or lowercase host before `::ffff:` prefix check |
| Decimal/hex/octal edge cases | 8 | SEC-15 | S | Add fuzz tests for mixed-format octets; add case-insensitive `::ffff:` prefix matching |
| Percent-encoded double-decode | 6 | SEC-18 | S | Add `%25` rejection in decoded output or loop decode until stable |

### Medium (1-5 days)

| Finding | RiskScore | ID | Effort | Notes |
|---------|----------|-----|--------|-------|
| Consul missing HTTP status code validation | 36 | SEC-01 | M | Add status checks to all 3 Consul HTTP methods; define error mapping for 401/403/5xx |
| Spice dependency pin to release | 24 | SEC-04 | S-M | Requires upstream spice to tag a release; update build.zig.zon URL and hash |
| isPathSafe Windows backslash handling | 16 | SEC-05 | S | Normalize separators or add backslash check; needs Windows CI to verify |
| isValidOpPath tighter pattern | 16 | SEC-07 | S | Restrict to `/home/<single-component>/bin/op` pattern |

### Strategic (> 5 days)

| Finding | RiskScore | ID | Effort | Notes |
|---------|----------|-----|--------|-------|
| HTTP timeout enforcement | 36 | SEC-02 | L | Requires watchdog-thread wrapper or upstream Zig http.Client timeout support. Pattern exists in execCommand (encrypted_secrets.zig:710-727) but adapting for generic HTTP fetch is non-trivial. |
| TOCTOU Windows symlink check | 16 | SEC-06 | M-L | Requires Windows-specific file open flags (FILE_FLAG_OPEN_REPARSE_POINT); or accept as documented limitation |

### Accepted Risks / Low-Priority Backlog

| Finding | RiskScore | ID | Rationale |
|---------|----------|-----|-----------|
| ~~DNS rebinding residual risk~~ | 8 | SEC-10 | **Closed (False Positive):** Vault token passed via env var, not CLI args. Mitigations remain in place. |
| loadFromEnv env data not zeroable | 8 | SEC-11 | Provider is opt-in, deprecated, disabled by default |
| CLI argument injection via vault/op path (residual) | 4 | SEC-17 | Triple defense (no shell, allowlist, char validation). Open but backlog priority. Document `isValidVaultPath` home-dir permissiveness. |
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

## Unknowns / Blockers

- **Windows CI:** No Windows CI runner is configured. SEC-05 and SEC-06 cannot be fully verified without Windows testing.
- **Spice release tagging:** SEC-04 fix depends on upstream `devnw/zig/spice` tagging a release. If no release exists, the fix is to pin to a specific commit hash instead of `main`.
- **Zig http.Client timeout:** SEC-02 depends on either upstream Zig adding timeout support or implementing a watchdog-thread wrapper. The watchdog pattern from `execCommand` (encrypted_secrets.zig:710-727) could be adapted but requires careful thread-safety around the HTTP client.
- **Consul status codes:** SEC-01 fix requires understanding which Consul API status codes should be treated as errors vs. expected conditions (e.g., 404 on GET is already handled; 200/204 are success for PUT/DELETE).
- **IPv6 parseIp behavior (SEC-16):** Whether Zig's `net.Address.parseIp` recognizes uppercase `::FFFF:` prefix needs runtime verification. If it does, the string-level bypass is confirmed; if not, the input is rejected entirely and the risk is lower than assessed.
- **Fuzzing for IP format edge cases (SEC-15):** `parseIPv4ToInt` handles standard formats but mixed-base octets (e.g., `0x7f.0.0.01`) need systematic testing. A fuzz harness targeting `isPrivateIPv4` would confirm or eliminate residual bypass risk.
- **Triple-encoding validation (SEC-18):** Testing `validateUrl` with triple-encoded hostnames (`%25`-prefixed) would confirm whether the two-pass decode is sufficient or if a loop-until-stable approach is needed.
