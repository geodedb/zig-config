# GAP Analysis

Last updated: 2026-03-25 (Wave 12 closure -- all batches complete)
Review commit: fe9d0f6 (HEAD of main) + working tree
Reviewed by: Gap Detection Agent (Phase 3, adversarial); Wave 12 closures applied (Batches 1-7)

## Summary

### Severity Breakdown

| Severity | Count | Open | Closed | Won't Do | Blocked | Description |
|----------|-------|------|--------|----------|---------|-------------|
| Critical | 0 | 0 | 0 | 0 | 0 | No critical vulnerabilities found |
| High | 3 | 0 | 3 | 0 | 0 | GAP-0062 closed (Batch 1+2); GAP-0066 closed (Batch 6) |
| Medium | 20 | 0 | 17 | 1 | 2 | GAP-0063 Won't Do (deferred feature); GAP-0067 closed (Batch 1+2); SEC-02 blocked |
| Low | 12 | 0 | 10 | 0 | 2 | Version inconsistency (GAP-0068/0069) closed (Batch 6); SEC-04/GAP-0058 blocked |
| **Total** | **35** | **0** | **30** | **1** | **4** | Wave 12 closed all open items. 1 Won't Do (GAP-0063). 3 blocked (SEC-02, SEC-04, GAP-0058). |

Wave 12 (Phase 3) found 9 new gaps. GAP-0041/GAP-0042 marked as REGRESSION in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md) -- code was in agent worktree only, never merged to main. These are superseded by GAP-0062. All 14 original security findings remain resolved. Resolution evidence for closed items is tracked in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

Wave 12 closure complete: Batch 1+2 closed GAP-0062 and GAP-0067. Batch 6 closed 6 documentation gaps (GAP-0064, GAP-0065, GAP-0066, GAP-0068, GAP-0069, GAP-0070). GAP-0063 marked Won't Do (significant feature, deferred to future release). No open items remain.

### Remaining Risks (Blocked only)

1. SEC-02: HTTP timeout not enforced (Zig 0.15 limitation) -- Medium, blocked
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

## Blocked Items (unchanged)

| ID | Severity | Finding | Component | Blocker | Unblock Steps | Status |
|----|----------|---------|-----------|---------|---------------|--------|
| SEC-02 | Medium | HTTP timeout not enforced | remote.zig | Zig 0.15 `http.Client` has no timeout API; `fetch()` does not expose underlying connection | Wait for Zig version with timeout support in http.Client | **Blocked** |
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
| P3-R1/PERF-46 | Bounded response writer | Needs design work; current `limits.MAX_REMOTE_RESPONSE_SIZE` check sufficient | **Deferred** |
| PERF-47 | Etcd endpoint failover enhancements | Feature addition, not gap closure | **Deferred** |

---

## Closed Items Reference

All 30 closed gaps include: 14 security findings, 3 feature gaps, 5 security hardening items, 6 documentation gaps (Batch 6), and 2 bug fixes (GAP-0062, GAP-0067 -- Batch 1+2). GAP-0041 and GAP-0042 have been reclassified as REGRESSION (code never merged to main) and are superseded by GAP-0062. 1 Won't Do: GAP-0063 (nested YAML -- deferred feature). See [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md) for full resolution details.
