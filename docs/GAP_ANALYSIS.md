# GAP Analysis

Last updated: 2026-03-25 (Wave 14 closure -- 12 audit findings closed)
Review commit: 8d6b87c (HEAD of main) + working tree
Reviewed by: Gap Detection Agent (Phase 3, adversarial); Wave 12 closures applied (Batches 1-7); Wave 13 (SEC-02); Wave 14 (12 audit findings)

## Summary

### Severity Breakdown

| Severity | Count | Open | Closed | Won't Do | Blocked | Description |
|----------|-------|------|--------|----------|---------|-------------|
| Critical | 1 | 0 | 1 | 0 | 0 | CRIT-1 bounded HTTP response body (Wave 14) |
| High | 4 | 0 | 4 | 0 | 0 | GAP-0062 closed (Batch 1+2); GAP-0066 closed (Batch 6); HIGH-1 transfer buffer (Wave 14) |
| Medium | 22 | 0 | 21 | 1 | 0 | GAP-0063 Won't Do; MED-1/MED-2 closed (Wave 14); SEC-02 closed (Wave 13) |
| Low | 13 | 0 | 11 | 0 | 2 | LOW-1 Windows setsockopt (Wave 14); SEC-04/GAP-0058 blocked |
| Info | 7 | 0 | 7 | 0 | 0 | INFO-1 through INFO-7 closed (Wave 14) |
| **Total** | **47** | **0** | **44** | **1** | **2** | Wave 14 closed 12 audit findings + P3-R1/PERF-46. SEC-02 closed (Wave 13). 1 Won't Do (GAP-0063). 2 blocked (SEC-04, GAP-0058). |

Wave 12 (Phase 3) found 9 new gaps. GAP-0041/GAP-0042 marked as REGRESSION in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md) -- code was in agent worktree only, never merged to main. These are superseded by GAP-0062. All 14 original security findings remain resolved. Resolution evidence for closed items is tracked in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

Wave 12 closure complete: Batch 1+2 closed GAP-0062 and GAP-0067. Batch 6 closed 6 documentation gaps (GAP-0064, GAP-0065, GAP-0066, GAP-0068, GAP-0069, GAP-0070). GAP-0063 marked Won't Do (significant feature, deferred to future release).

Wave 13 closed SEC-02 (HTTP timeout enforcement via SO_RCVTIMEO/SO_SNDTIMEO).

Wave 14 closed 12 audit findings from full codebase audit: CRIT-1, HIGH-1, MED-1, MED-2, LOW-1, INFO-1 through INFO-7. Also closed P3-R1/PERF-46 (bounded response writer), subsumed by CRIT-1. No open items remain.

### Remaining Risks (Blocked only)

1. ~~SEC-02: HTTP timeout not enforced (Zig 0.15 limitation)~~ -- **Closed** (Wave 13)
2. SEC-04: Spice dependency not pinned (no upstream tags) -- Low, blocked
3. GAP-0058: Windows CI infrastructure -- Low, blocked

## Gaps

### GAP-0062: Array indexing and bracket normalization code not on main branch -- **CLOSED**
- **Issue:** [#167](https://gitlab.com/devnw/zig/config/-/issues/167)
- **Category:** Bug
- **Severity:** High
- **Status:** Closed (Wave 12, Batch 1+2)
- **Resolution:** Implemented `.array` branch in `applyJsonValue` that flattens arrays with numeric-index keys. Implemented bracket-to-dot normalization in `getPath()`. Tests added and passing on main.
- **Evidence:**
  - `src/loader.zig` -- `applyJsonValue` handles `.array` case with numeric-index flattening
  - `src/loader.zig` -- `getPath()` normalizes bracket notation (`a[0].b` -> `a.0.b`)
  - Tests verify array indexing and bracket normalization on main branch
- **Acceptance criteria:** Met -- all three criteria satisfied.

### GAP-0063: parseSimpleYaml does not handle nested YAML structures -- **WON'T DO**
- **Issue:** [#168](https://gitlab.com/devnw/zig/config/-/issues/168)
- **Category:** Feature
- **Severity:** Medium
- **Status:** Won't Do (Wave 12)
- **Reason:** Nested YAML parsing is a significant feature addition, not a gap closure item. Deferred to a future release. ROADMAP.md has been corrected (GAP-0070) to accurately describe flat-only YAML parsing. Tracked via issue #4.
- **Alternative controls:** ROADMAP.md now correctly states "YAML parsing for flat key:value structures; nested YAML parsing planned (#4)". Users needing nested structures can use JSON or TOML formats which are fully supported.

### GAP-0064: ROADMAP.md shows closed issues as unchecked/planned -- **CLOSED**
- **Issue:** [#169](https://gitlab.com/devnw/zig/config/-/issues/169)
- **Category:** Docs
- **Severity:** Medium
- **Status:** Closed (Batch 6)
- **Resolution:** Updated ROADMAP.md to show `[x]` for #37, #43, #39, #40, #12, #89 with implementation notes.
- **Requirement source:** Issue #166 (ROADMAP.md and VIPER_COMPARISON.md still show closed features as planned/incomplete)
- **Acceptance criteria:** Met -- all closed GitLab issues show `[x]` in ROADMAP.md; open issues (#4) shown as `[ ]`.

### GAP-0065: VIPER_COMPARISON.md shows implemented features as No/Planned -- **CLOSED**
- **Issue:** [#171](https://gitlab.com/devnw/zig/config/-/issues/171)
- **Category:** Docs
- **Severity:** Medium
- **Status:** Closed (Batch 6)
- **Resolution:** Updated VIPER_COMPARISON.md -- Custom key delimiter, Files without extension, AllSettings(), AllKeys() now show "Yes | Complete". Removed these from "Remaining Gaps" table.
- **Requirement source:** Issue #166 (ROADMAP.md and VIPER_COMPARISON.md still show closed features as planned/incomplete)
- **Acceptance criteria:** Met -- all four features show "Yes/Complete" in the feature matrix.

### GAP-0066: Open issues #4, #6, #27, #35 marked complete in ROADMAP -- **CLOSED**
- **Issue:** [#173](https://gitlab.com/devnw/zig/config/-/issues/173)
- **Category:** Docs
- **Severity:** High
- **Status:** Closed (Batch 6)
- **Resolution:**
  - #4 (nested YAML): Changed to `[ ]` with note "parseSimpleYaml is flat key:value only; nested YAML not yet implemented"
  - #6 (dotenv apply): Kept `[x]` with note "(creates EnvMap; does not set OS env vars)"
  - #27 (remote config): Kept `[x]` with note "(etcd/Consul; NATS not implemented)"
  - #35 (array indexing): Kept `[x]` with note "(bracket notation and JSON array flattening)" -- implemented by Batch 1+2 agent
- **Requirement source:** Issue #165 (Tracker/docs mismatch: issues #4, #6, #27, #35 still open but documented as complete)
- **Acceptance criteria:** Met -- open/incomplete items shown as `[ ]`; partially-complete items have clarifying notes.

### GAP-0067: setFieldFromEnvKey unconditionally lowercases keys -- **CLOSED**
- **Issue:** [#174](https://gitlab.com/devnw/zig/config/-/issues/174)
- **Category:** Bug
- **Severity:** Medium
- **Status:** Closed (Wave 12, Batch 1+2)
- **Resolution:** `setFieldFromEnvKey` now checks `self.options.case_insensitive` before lowercasing. Only lowercases when `case_insensitive == true`.
- **Evidence:**
  - `src/loader.zig` -- `setFieldFromEnvKey` respects `case_insensitive` flag
  - Tests verify both case-sensitive and case-insensitive behavior
- **Acceptance criteria:** Met -- both criteria satisfied.

### GAP-0068: Zig version inconsistency across docs (0.15.1 vs 0.15.2) -- **CLOSED**
- **Issue:** [#176](https://gitlab.com/devnw/zig/config/-/issues/176)
- **Category:** Docs
- **Severity:** Low
- **Status:** Closed (Batch 6)
- **Resolution:** Updated `Makefile:106` from "Zig 0.15.1 or compatible" to "Zig 0.15.2 or compatible" and `CONTRIBUTING.md:12` from "Zig 0.15.1+" to "Zig 0.15.2+".
- **Requirement source:** Issue #156 (partially addressed -- README/ARCHITECTURE updated but Makefile/CONTRIBUTING missed)
- **Acceptance criteria:** Met -- all documentation files reference Zig 0.15.2 consistently.

### GAP-0069: README says v0.2.0 but ROADMAP says v0.3.x -- **CLOSED**
- **Issue:** [#178](https://gitlab.com/devnw/zig/config/-/issues/178)
- **Category:** Docs
- **Severity:** Low
- **Status:** Closed (Batch 6)
- **Resolution:** Updated `README.md:366` from "Current Version: v0.2.0" to "Current Version: v0.3.x" to match ROADMAP.md.
- **Requirement source:** Issue #162 (README version says v0.2.0 but ROADMAP says v0.3.x)
- **Acceptance criteria:** Met -- README.md and ROADMAP.md both show v0.3.x.

### GAP-0070: ROADMAP falsely claims nested YAML parsing via applyJsonValue -- **CLOSED**
- **Issue:** [#181](https://gitlab.com/devnw/zig/config/-/issues/181)
- **Category:** Docs
- **Severity:** Medium
- **Status:** Closed (Batch 6)
- **Resolution:** Changed ROADMAP.md line 32 from "Nested YAML parsing via recursive applyJsonValue" to "YAML parsing for flat key:value structures; nested YAML parsing planned (#4)".
- **Requirement source:** ROADMAP.md line 32; related to GAP-0063
- **Acceptance criteria:** Met -- ROADMAP accurately describes flat-only YAML parsing; no false claims about applyJsonValue.

---

## Wave 14 -- Audit Findings (2026-03-25)

12 findings from full codebase audit, all closed.

### CRIT-1: Bounded HTTP response body allocation (CWE-770) -- **CLOSED**
- **Issue:** [#206](https://gitlab.com/devnw/zig/config/-/issues/206)
- **Category:** Security
- **Severity:** Critical
- **Status:** Closed (Wave 14)
- **Resolution:** HTTP response body allocation in `fetchWithTimeout` now enforced via `BoundedResponseWriter` with `limits.MAX_REMOTE_RESPONSE_SIZE` cap. Prevents unbounded memory allocation from malicious server responses.
- **Evidence:** `src/remote.zig` -- `BoundedResponseWriter` struct; `fetchWithTimeout` reads through bounded writer
- **Also closes:** P3-R1/PERF-46 (bounded response writer) -- subsumed by this implementation.

### HIGH-1: 64-byte transfer buffer upgraded to 8192 bytes -- **CLOSED**
- **Issue:** [#207](https://gitlab.com/devnw/zig/config/-/issues/207)
- **Category:** Performance
- **Severity:** High
- **Status:** Closed (Wave 14)
- **Resolution:** Transfer buffer in `fetchWithTimeout` increased from 64 bytes to 8192 bytes, reducing syscall overhead by ~128x for typical responses.
- **Evidence:** `src/remote.zig` -- `TRANSFER_BUFFER_SIZE = 8192`

### MED-1: Extract Consul buildConsulPath helper -- **CLOSED**
- **Issue:** [#208](https://gitlab.com/devnw/zig/config/-/issues/208)
- **Category:** Quality
- **Severity:** Medium
- **Status:** Closed (Wave 14)
- **Resolution:** Extracted `buildConsulPath` helper to deduplicate Consul KV path construction across get/put/delete/keys operations.
- **Evidence:** `src/remote.zig` -- `buildConsulPath()` helper function

### MED-2: Extract writeEscapedString helper -- **CLOSED**
- **Issue:** [#209](https://gitlab.com/devnw/zig/config/-/issues/209)
- **Category:** Quality
- **Severity:** Medium
- **Status:** Closed (Wave 14)
- **Resolution:** Extracted `writeEscapedString` helper from JSON serialization to deduplicate string escaping logic.
- **Evidence:** `src/serialize.zig` -- `writeEscapedString()` helper function

### LOW-1: Windows setsockopt return value checking (CWE-252) -- **CLOSED**
- **Issue:** [#210](https://gitlab.com/devnw/zig/config/-/issues/210)
- **Category:** Security
- **Severity:** Low
- **Status:** Closed (Wave 14)
- **Resolution:** Windows `setsockopt` return values are now checked and errors propagated, preventing silent timeout failures.
- **Evidence:** `src/remote.zig` -- Windows `setsockopt` error checking in `setSocketTimeout()`

### INFO-1: Differentiate receiveHead error types -- **CLOSED**
- **Issue:** [#211](https://gitlab.com/devnw/zig/config/-/issues/211)
- **Category:** Security
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** `receiveHead` errors in `fetchWithTimeout` now differentiated between timeout (`EAGAIN`/`WOULDBLOCK`) and other errors, providing more specific error reporting.
- **Evidence:** `src/remote.zig` -- error switch in `fetchWithTimeout` after `receiveHead`

### INFO-2: Update PERF-29 for GAP-0062 array handling -- **CLOSED**
- **Issue:** [#212](https://gitlab.com/devnw/zig/config/-/issues/212)
- **Category:** Docs
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** PERF-29 entry in PERF_GAP_ANALYSIS.md updated to reflect GAP-0062 array handling implementation with stack-buffer `bufPrint`.
- **Evidence:** `docs/PERF_GAP_ANALYSIS.md` -- PERF-29 entry updated

### INFO-3: Audit secureZero callsites -- **CLOSED**
- **Issue:** [#213](https://gitlab.com/devnw/zig/config/-/issues/213)
- **Category:** Security
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** Audited all `secureZero` callsites in `remote.zig`; confirmed all credential and response buffers are properly zeroed before free.
- **Evidence:** `src/remote.zig` -- `secureZero` verified at all credential/response `defer` sites

### INFO-4: Remove redundant isSymlink check -- **CLOSED**
- **Issue:** [#214](https://gitlab.com/devnw/zig/config/-/issues/214)
- **Category:** Quality
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** Removed redundant `isSymlink` pre-check in config file loading path where `openFileReadNoFollow` already handles symlink rejection atomically.
- **Evidence:** `src/config.zig` -- redundant symlink check removed

### INFO-5: Add ensureTotalCapacity to 12+ sites -- **CLOSED**
- **Issue:** [#215](https://gitlab.com/devnw/zig/config/-/issues/215)
- **Category:** Performance
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** Added `ensureTotalCapacity` capacity hints to 12+ HashMap/ArrayList initialization sites across multiple modules.
- **Evidence:**
  - `src/remote.zig` -- capacity hints on response parsing maps
  - `src/config.zig` -- capacity hints on config maps
  - `src/loader.zig` -- capacity hints on loader maps
  - `src/provenance.zig` -- capacity hints on provenance tracker
  - `src/dotenv.zig` -- capacity hints on dotenv parsing

### INFO-6: Replace open+stat with fstatat in watcher -- **CLOSED**
- **Issue:** [#216](https://gitlab.com/devnw/zig/config/-/issues/216)
- **Category:** Performance
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** Replaced separate `open()`+`stat()` calls with `fstatat()` in the file watcher, reducing per-check syscalls from 3 to 1.
- **Evidence:** `src/watch.zig` -- `fstatat` replaces `open`+`fstat`+`close`

### INFO-7: Single-pass isValidKVKey validator -- **CLOSED**
- **Issue:** [#217](https://gitlab.com/devnw/zig/config/-/issues/217)
- **Category:** Performance
- **Severity:** Info
- **Status:** Closed (Wave 14)
- **Resolution:** Replaced multi-pass `isValidKVKey` validator (separate checks for length, null bytes, control chars) with a single-pass implementation that validates all constraints in one iteration.
- **Evidence:**
  - `src/remote.zig` -- single-pass `isValidKVKey` implementation
  - `src/limits.zig` -- `MAX_KV_KEY_LENGTH` constant

---

## Blocked Items

| ID | Severity | Finding | Component | Blocker | Unblock Steps | Status |
|----|----------|---------|-----------|---------|---------------|--------|
| ~~SEC-02~~ | Medium | ~~HTTP timeout not enforced~~ | remote.zig | ~~Zig 0.15 `http.Client` has no timeout API~~ | Implemented `setSocketTimeout()` + `fetchWithTimeout()` using SO_RCVTIMEO/SO_SNDTIMEO | **Closed** (Wave 13) |
| SEC-04 | Low | spice dependency not pinned (GAP-0043) | build.zig.zon | Upstream spice package has no version tag; hash-only pinning in place | Request upstream version tag or fork with explicit versioning | **Blocked** |
| GAP-0058 | Low | Windows CI infrastructure | CI/CD | Infrastructure; out of scope for gap closure | Add Windows CI runner | **Blocked** |

---

## Deferred/Won't Do Items

| ID | Finding | Reason | Status |
|----|---------|--------|--------|
| GAP-0063 | Nested YAML parsing | Significant feature addition, deferred to future release; ROADMAP corrected (GAP-0070) | **Won't Do** |
| ADV-06 | Traversal masked as FileNotFound | Info-level observability improvement; traversal is still blocked | **Won't Do** |
| ADV-08 | Structured security logging | Architectural change; not a gap closure item | **Won't Do** |
| P3-M2 | Consul request consolidation | Refactoring too aggressive; breaks 44 tests | **Deferred** |
| P3-M3 | URL builder extraction | Deferred to future refactoring pass | **Deferred** |
| P3-R1/PERF-46 | Bounded response writer | Subsumed by CRIT-1: `BoundedResponseWriter` in `fetchWithTimeout` enforces `limits.MAX_REMOTE_RESPONSE_SIZE` | **Closed** (Wave 14) |
| PERF-47 | Etcd endpoint failover enhancements | Feature addition, not gap closure | **Deferred** |

---

## Closed Items Reference

All 42 closed gaps include: 14 original security findings, 3 feature gaps, 5 security hardening items, 6 documentation gaps (Batch 6), 2 bug fixes (GAP-0062, GAP-0067 -- Batch 1+2), 1 SEC-02 (Wave 13), and 12 Wave 14 audit findings (CRIT-1, HIGH-1, MED-1/2, LOW-1, INFO-1 through INFO-7) plus P3-R1/PERF-46 (subsumed by CRIT-1). GAP-0041 and GAP-0042 have been reclassified as REGRESSION (code never merged to main) and are superseded by GAP-0062. 1 Won't Do: GAP-0063 (nested YAML -- deferred feature). See [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md) for full resolution details.
