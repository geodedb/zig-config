# Quality Gap Analysis

**Project:** devnw/zig/config
**Last updated:** 2026-03-24 (Wave 10 closure)
**Review phase:** Phase 4 (quality-reviewer follow-up) + Waves 6-10 closure + Phase 3 addendum
**Scoring formula:** PriorityScore = Impact(1-5) x Likelihood(1-5) x 4

---

## Summary

| Severity | Count | Resolved | Won't Do | Open |
|----------|-------|----------|----------|------|
| Critical | 4     | 4        | 0        | 0    |
| High     | 9     | 7        | 2        | 0    |
| Medium   | 25    | 23       | 2        | 0    |
| Low      | 13    | 11       | 0        | 2    |
| Info     | 4     | 2        | 2        | 0    |
| **Total** | **55** | **47** | **6** | **2** |

### Top 5 Risks (all resolved)

1. ~~**dotenv.load() returns dangling pointers** (NEW-12)~~ -- Critical, PriorityScore 100. **Resolved** (Wave 6): `load()` now dupes key/value from content before freeing; `parseContent` lifetime documented.
2. ~~**Hand-rolled JSON response parsing in etcd/Consul** (NEW-02)~~ -- High, PriorityScore 48. **Resolved** (Wave 7): Replaced with `std.json.parseFromSlice` using typed structs.
3. ~~**Etcd response parser ignores JSON escaping** (NEW-06)~~ -- High, PriorityScore 48. **Resolved** (Wave 7): Same fix as NEW-02; `std.json` handles escaping correctly.
4. ~~**No timeout enforcement on Etcd/Consul HTTP requests** (NEW-08)~~ -- High, PriorityScore 48. **Resolved** (Wave 7): Limitation documented in `EtcdOptions.timeout_ms` and `ConsulOptions.timeout_ms` doc comments.
5. ~~**Dotenv parsing logic triplicated within dotenv.zig** (NEW-01)~~ -- Medium, PriorityScore 48. **Resolved** (Wave 6): Extracted shared `parseLine` helper; all three functions delegate to it.

---

## Stack-Ranked Findings

| Rank | Severity | Score | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----------|-------|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | Critical | 100 | reliability | ~~dotenv.load() returns dangling pointers (use-after-free)~~ | dotenv.zig | `dotenv.zig` -- `load()` now dupes key/value from content before freeing; `parseContent` lifetime documented | NEW-12 | `load()` returns owned copies; `parseContent` borrowing documented | Maintainer | S | **Resolved** (Wave 6) |
| 2 | Critical | 100 | ci-cd | ~~No CI build/test pipeline~~ | .gitlab-ci.yml | CI now fully implemented: build, test (4 modes), fuzz, security, SBOM, release stages | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | CI pipeline fully implemented | Maintainer | M | **Resolved** |
| 3 | High | 64 | tests | Weak test coverage in config.zig, xdg.zig, async.zig | config.zig, xdg.zig, async.zig | Core API surface and platform-specific code under-tested | [#151](https://gitlab.com/devnw/zig/config/-/issues/151) | Add unit tests for primary code paths in all 3 modules | Maintainer | M | **Won't Do** |
| 4 | High | 64 | maintainability | Loader god-object: 60+ functions in single comptime struct | loader.zig | `src/loader.zig` -- 2649 lines, single `Loader` struct | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | Extract parsing, dotenv, and remote loading into submodules | Maintainer | L | **Won't Do** |
| 5 | High | 48 | maintainability | ~~Hand-rolled JSON response parsing in etcd/Consul~~ | remote.zig | `remote.zig` -- Replaced indexOf-based string matching with `std.json.parseFromSlice` using typed `EtcdRangeResponse` and `ConsulKVEntry` structs | NEW-02 | Replaced with `std.json.parseFromSlice` and typed response structs | Maintainer | M | **Resolved** (Wave 7) |
| 6 | High | 48 | api-contract | ~~Etcd response parser ignores JSON escaping~~ | remote.zig | `remote.zig` -- `std.json.parseFromSlice` handles all JSON escaping, whitespace, and field ordering correctly | NEW-06 | Resolved by same std.json fix as NEW-02 | Maintainer | M | **Resolved** (Wave 7, fixed with NEW-02) |
| 7 | High | 48 | reliability | ~~No timeout enforcement on Etcd/Consul HTTP requests~~ | remote.zig | `remote.zig` -- `timeout_ms` doc comments updated to document Zig 0.15 http.Client limitation; TODO retained for future Zig version support | NEW-08 | Limitation documented; timeout_ms doc warns callers of non-enforcement | Maintainer | M | **Resolved** (Wave 7, documented limitation) |
| 8 | Medium | 48 | maintainability | ~~Dotenv parsing logic triplicated within dotenv.zig~~ | dotenv.zig | `dotenv.zig` -- Extracted shared `parseLine` helper; `load`, `applyContent`, `parseContent` all delegate to it | NEW-01 | Extracted `parseLine` helper; all three functions use it | Maintainer | S | **Resolved** (Wave 6) |
| 9 | Medium | 48 | maintainability | 5 files exceed 800 lines (updated line counts) | loader.zig, remote.zig, encrypted_secrets.zig, config.zig, validation.zig | 2649, 2477, 1390, 1044, 1124 lines respectively | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | Extract submodules to reduce file sizes | Maintainer | L | **Won't Do** |
| 10 | Medium | 36 | api-contract | ~~Consul parseKeysList matches any quoted string, not just array elements~~ | remote.zig | `remote.zig` -- `std.json.parseFromSlice` correctly parses JSON arrays; no more naive string matching | NEW-07 | Resolved by same std.json fix as NEW-02 | Maintainer | S | **Resolved** (Wave 7, fixed with NEW-02) |
| 11 | Medium | 36 | api-contract | ~~SensitiveString.format wrong signature for std.fmt protocol~~ | encrypted_secrets.zig | Signature matches Zig 0.15 `{f}` protocol (`fn format(self, w: *std.io.Writer) !void`); output changed from `***REDACTED***` to `[REDACTED]`; allocPrint test added | NEW-09 | Updated format output and added allocPrint test | Maintainer | S | **Resolved** (Wave 6) |
| 12 | Medium | 36 | documentation | ~~parseContent lifetime constraint undocumented~~ | dotenv.zig | `dotenv.zig` -- Doc comment added: returned entries borrow from `content`; caller must keep `content` alive | NEW-15 | Added doc comment documenting lifetime constraint | Maintainer | S | **Resolved** (Wave 6, fixed with NEW-13) |
| 13 | Medium | 36 | documentation | ~~timeout_ms option misleading -- configured but not enforced~~ | remote.zig | `remote.zig` -- `EtcdOptions.timeout_ms` and `ConsulOptions.timeout_ms` doc comments updated to warn callers that timeout is not enforced by Zig 0.15 http.Client | NEW-16 | Added doc comment warning; resolved with NEW-08 | Maintainer | S | **Resolved** (Wave 7, fixed with NEW-08) |
| 14 | Medium | 32 | maintainability | Loader/remote file sizes continue to grow (update to #98) | loader.zig, remote.zig | loader.zig now 2649 lines (was 1833), remote.zig now 2477 lines (was 1730) | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | Same strategic decomposition as existing #98 | Maintainer | L | **Won't Do** (update to #98) |
| 15 | Medium | 32 | reliability | ~~parseContent returns entries into caller-owned content (lifetime risk)~~ | dotenv.zig | `dotenv.zig` -- Lifetime constraint documented (NEW-15); `load()` path fixed (NEW-12) to dupe before free | NEW-13 | Lifetime documented; `load()` returns owned copies | Maintainer | S | **Resolved** (Wave 6, fixed with NEW-12 + NEW-15) |
| 16 | Medium | 24 | reliability | ~~getPrefix range_end overflow on 0xFF last byte~~ | remote.zig | `remote.zig` -- 0xFF check added; appends `0x00` sentinel byte (etcd convention for open-ended prefix range) instead of wrapping | NEW-10 | Added 0xFF overflow guard with etcd `\x00` sentinel | Maintainer | S | **Resolved** (Wave 6) |
| 17 | Medium | 24 | reliability | ~~async loadFile swallows OOM silently~~ | async.zig | OOM now propagated from `loadFile` to `loadThreadFn` which sets `result.state = .failed` and `result.err = error.OutOfMemory` | NEW-11 | Changed `return` to `return error.OutOfMemory`; added regression test | Maintainer | S | **Resolved** (Wave 6) |
| 18 | Medium | 60 | api-contract | ~~Stale doc: "10 MB" but actual limit is 1 MB~~ | loader.zig | Fixed: doc comment updated to "1 MB" | [#139](https://gitlab.com/devnw/zig/config/-/issues/139) | Changed "10 MB" to "1 MB" in loader.zig doc comment | Maintainer | S | **Resolved** (Wave 1) |
| 19 | Medium | 60 | api-contract | ~~parallel.loadFile stub returns fake success~~ | parallel.zig | Fixed: real file I/O implemented | [#141](https://gitlab.com/devnw/zig/config/-/issues/141) | Implemented actual file loading and serialization | Maintainer | M | **Resolved** (Wave 3) |
| 20 | Medium | 48 | maintainability | ~~8 magic number sites bypass centralized limits.zig~~ | remote.zig, secret.zig, encrypted_secrets.zig | Fixed: all sites use limits.zig constants | [#146](https://gitlab.com/devnw/zig/config/-/issues/146) | Replaced hardcoded literals with limits.* constants | Maintainer | S | **Resolved** (Wave 2) |
| 21 | Medium | 48 | cleanup | ~~Consul HTTP method triplication (get/put/delete)~~ | remote.zig | Fixed: shared HTTP helper extracted | [#123](https://gitlab.com/devnw/zig/config/-/issues/123) | Extracted shared Consul HTTP helper | Maintainer | M | **Resolved** (Wave 3) |
| 22 | Medium | 48 | reliability | ~~7 remaining catch {} sites (OOM/timeout silently discarded)~~ | remote.zig, dotenv.zig, provenance.zig | Fixed: all catch {} propagated via try | [#148](https://gitlab.com/devnw/zig/config/-/issues/148) | Propagated errors from all remaining catch {} sites | Maintainer | S | **Resolved** (Waves 1-2) |
| 23 | Medium | 48 | maintainability | ~~Hand-rolled JSON construction in remote.zig~~ | remote.zig | Fixed: replaced with std.json for request construction | [#119](https://gitlab.com/devnw/zig/config/-/issues/119) | Replaced with `std.json` for all Etcd JSON construction | Maintainer | M | **Resolved** (Wave 2) |
| 24 | Medium | 36 | readability | ~~matchPatternImpl 209-line recursive function~~ | validation.zig | Fixed: decomposed to ~49 lines with sub-functions | [#120](https://gitlab.com/devnw/zig/config/-/issues/120) | Broke into sub-functions: handleCharClass, handleQuantifier, handleEscape | Maintainer | M | **Resolved** (Wave 2) |
| 25 | Medium | 36 | maintainability | ~~Dotenv parsing triplication across loader/dotenv/config~~ | loader.zig, dotenv.zig, config.zig | Fixed: loader delegates to dotenv.zig (but dotenv.zig itself still triplicated internally -- see NEW-01) | [#152](https://gitlab.com/devnw/zig/config/-/issues/152) | Refactored loader.zig loadDotEnv to delegate to dotenv.zig | Maintainer | S | **Resolved** (Wave 2, partially -- see NEW-01) |
| 26 | Low | 36 | api-contract | ~~ConfigFormat enum duplicated between parallel.zig and loader.zig~~ | parallel.zig, loader.zig | Fixed: parallel.zig imports from loader.zig | [#149](https://gitlab.com/devnw/zig/config/-/issues/149) | Removed parallel.zig ConfigFormat, imports from loader.zig | Maintainer | S | **Resolved** (Wave 3) |
| 27 | Low | 24 | maintainability | ~~safeWriteConfig/safeWriteConfigWithBackup near-duplicate~~ | config.zig | Extracted `atomicWriteFile` and `directWriteFile` helpers; both functions now delegate to them; ~50 lines of duplication removed | NEW-03 | Extracted shared helpers; added 6 tests for safeWrite* functions | Maintainer | S | **Resolved** (Wave 6) |
| 28 | Low | 24 | documentation | Quality gap analysis #82 status was stale | docs/ | QUALITY_GAP_ANALYSIS.md listed #82 as "Won't Do" but CI is now fully implemented | NEW-14 | Updated in this document (Phase 4) | Maintainer | S | **Resolved** (Phase 4) |
| 29 | Low | 24 | cleanup | ~~Duplicate validate/validation import alias in config.zig~~ | config.zig | Fixed: single alias retained | [#150](https://gitlab.com/devnw/zig/config/-/issues/150) | Removed duplicate alias, kept canonical name | Maintainer | S | **Resolved** (Wave 1) |
| 30 | Low | 24 | readability | ~~build.zig repeats imports 6 times~~ | build.zig | Fixed: consolidated imports | [#153](https://gitlab.com/devnw/zig/config/-/issues/153) | Consolidated imports at top of file | Maintainer | S | **Resolved** (Wave 3) |
| 31 | Low | 16 | maintainability | ~~@constCast on arena in normalizeKey bypasses const-correctness~~ | loader.zig | @constCast retained with expanded safety comment; changing to `*Self` would break public API of `isSet`, `has`, `get` (all `*const Self`) | NEW-05 | Expanded @constCast rationale comment documenting why signature change is infeasible | Maintainer | S | **Resolved** (Wave 6) |
| 32 | Low | 24 | maintainability | Consul HTTP boilerplate duplication (makeGetRequest/makePutRequest/makeDeleteRequest) | remote.zig | `src/remote.zig:1168,1224,1275` -- three HTTP methods share identical connection setup, header construction, and response reading boilerplate | Q-NEW-1 | Extract shared `makeRequest(method, uri, body?)` helper; deferred -- safe extraction when time permits | Maintainer | S | **Deferred** |
| 33 | Low | 24 | maintainability | Large files: remote.zig (2694), loader.zig (1991), encrypted_secrets.zig (1424) | remote.zig, loader.zig, encrypted_secrets.zig | `wc -l` counts exceed 800-line guideline; tests inline with production code inflate counts | Q-NEW-6 | Split tests into `*_test.zig` companion files to reduce file sizes below 800-line target | Maintainer | M | **Open** |
| 34 | Low | 16 | tests | ~~AsyncLoaderWithCallback not integration-tested~~ | async.zig | `src/async.zig:460,471` -- integration test added exercising load-then-callback flow | Q-NEW-3 | Integration test added for AsyncLoaderWithCallback (Wave 10) | Maintainer | S | **Resolved** (Wave 10) |
| 35 | Low | 16 | tests | ~~Error path coverage gap in remote (no HTTP error response tests)~~ | remote.zig | `src/remote.zig` -- HTTP error response tests added for Etcd and Consul 4xx/5xx paths | Q-NEW-7 | HTTP error response tests added for Etcd and Consul (Wave 10) | Maintainer | M | **Resolved** (Wave 10) |
| 36 | Info | 8 | documentation | ~~isPathSafeStrict potentially unused outside tests~~ | secret.zig | `src/secret.zig:69` -- doc comment added explaining intended use as a stricter alternative to `isPathSafe` | Q-NEW-2 | Doc comment added to `isPathSafeStrict` (Wave 10) | Maintainer | S | **Resolved** (Wave 10) |
| 37 | Info | 8 | documentation | ~~Loader.parseContent made pub without doc comment~~ | loader.zig | `src/loader.zig:734` -- doc comment added describing format dispatch behavior, parameter semantics, and error conditions | Q-NEW-4 | Doc comment added to `Loader.parseContent` (Wave 10) | Maintainer | S | **Resolved** (Wave 10) |
| 38 | Info | 8 | maintainability | Format dispatch duplication (config.zig + loader.zig) | config.zig, loader.zig | `src/config.zig:322` and `src/loader.zig:735` both switch on Format to dispatch to format-specific parsers; however they serve different purposes (Value tree vs key-value store) | Q-NEW-5 | Accepted -- different return types and semantics justify separate dispatch | Maintainer | -- | **Won't Do** (accepted) |
| 39 | Info | 4 | maintainability | Env map construction pattern duplication (Vault + 1Password) | encrypted_secrets.zig | `src/encrypted_secrets.zig:649,683` -- `buildMinimalVaultEnvMap` and `buildMinimalOnePasswordEnvMap` share PATH/HOME setup pattern but differ in provider-specific env vars | Q-NEW-8 | Won't do -- only 2 callsites; extraction would obscure provider-specific logic | Maintainer | -- | **Won't Do** |

---

## Resolved Findings (Waves 1-10 + Phase 4)

| Severity | Score | Category | Finding | Issue | Resolution | Wave |
|----------|-------|----------|---------|-------|------------|------|
| Critical | 100 | maintainability | 24+ `catch {}` silently discard all errors including OOM | [#99](https://gitlab.com/devnw/zig/config/-/issues/99) | Replaced all 26 catch {} with OOM-propagating error handlers | Pre-wave |
| Critical | 100 | ci-cd | No CI build/test pipeline | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | CI fully implemented with build, test (4 modes), fuzz, security, SBOM, release stages | Phase 4 |
| High | 64 | maintainability | 4 `MAX_*` security constants are dead code | [#101](https://gitlab.com/devnw/zig/config/-/issues/101) | Created limits.zig; all call sites reference centralized constants | Pre-wave |
| Critical | 60 | maintainability | `term.Exited` access without tagged union discriminant check (UB) | [#103](https://gitlab.com/devnw/zig/config/-/issues/103) | Added handleTermination switch on tagged union | Pre-wave |
| High | 64 | maintainability | `std.posix.getenv` in 6+ modules fails on Windows | [#105](https://gitlab.com/devnw/zig/config/-/issues/105) | Created `environ.zig` with cross-platform `getenv`/`getEnvOwned`; replaced all 38+ call sites | Pre-wave |
| High | 48 | maintainability | `loadDotEnv` bypasses symlink protection | [#108](https://gitlab.com/devnw/zig/config/-/issues/108) | Replaced openFile with openFileReadNoFollow + isPathSafe | Pre-wave |
| High | 48 | architecture | Two overlapping validation modules (validate.zig vs validation.zig) | [#110](https://gitlab.com/devnw/zig/config/-/issues/110) | Merged into single canonical validation module | Pre-wave |
| Medium | 48 | api-contract | `normalizeKey` is a no-op stub; case-insensitive lookup broken | [#113](https://gitlab.com/devnw/zig/config/-/issues/113) | Implemented arena-based lowercase normalization | Pre-wave |
| Medium | 60 | api-contract | Stale doc: "10 MB" but actual limit is 1 MB | [#139](https://gitlab.com/devnw/zig/config/-/issues/139) | Fixed doc comment to "1 MB" in loader.zig | Wave 1 |
| Low | 24 | cleanup | Duplicate validate/validation import alias in config.zig | [#150](https://gitlab.com/devnw/zig/config/-/issues/150) | Removed duplicate alias, kept canonical name | Wave 1 |
| Medium | 48 | maintainability | 8 magic number sites bypass centralized limits.zig | [#146](https://gitlab.com/devnw/zig/config/-/issues/146) | Replaced all 8 hardcoded literals with limits.* constants | Wave 2 |
| Medium | 48 | reliability | 7 remaining catch {} sites (OOM/timeout) | [#148](https://gitlab.com/devnw/zig/config/-/issues/148) | Propagated all remaining catch {} via try (dotenv, provenance, remote) | Waves 1-2 |
| Medium | 48 | maintainability | Hand-rolled JSON construction in remote.zig | [#119](https://gitlab.com/devnw/zig/config/-/issues/119) | Replaced with std.json for Etcd JSON request construction | Wave 2 |
| Medium | 36 | readability | matchPatternImpl 209-line recursive function | [#120](https://gitlab.com/devnw/zig/config/-/issues/120) | Decomposed to ~49 lines with sub-functions (handleCharClass, handleQuantifier, handleEscape) | Wave 2 |
| Medium | 36 | maintainability | Dotenv parsing triplication across 3 files | [#152](https://gitlab.com/devnw/zig/config/-/issues/152) | loader.zig loadDotEnv now delegates to dotenv.zig (internal triplication remains as NEW-01) | Wave 2 |
| Medium | 60 | api-contract | parallel.loadFile stub returns fake success | [#141](https://gitlab.com/devnw/zig/config/-/issues/141) | Implemented real file I/O in loadFile and serializeData | Wave 3 |
| Medium | 48 | cleanup | Consul HTTP method triplication (get/put/delete) | [#123](https://gitlab.com/devnw/zig/config/-/issues/123) | Extracted shared Consul HTTP helper | Wave 3 |
| Low | 36 | api-contract | ConfigFormat enum duplicated between parallel.zig and loader.zig | [#149](https://gitlab.com/devnw/zig/config/-/issues/149) | parallel.zig imports ConfigFormat from loader.zig | Wave 3 |
| Low | 24 | readability | build.zig repeats imports 6 times | [#153](https://gitlab.com/devnw/zig/config/-/issues/153) | Consolidated into single `parser_imports` constant | Wave 3 |
| Medium | 36 | api-contract | SensitiveString.format wrong signature | NEW-09 | Fixed format output to `[REDACTED]`; added allocPrint test | Wave 6 |
| Medium | 24 | reliability | async loadFile swallows OOM silently | NEW-11 | OOM now propagated from loadFile to loadThreadFn; regression test added | Wave 6 |
| Low | 24 | maintainability | safeWriteConfig/safeWriteConfigWithBackup near-duplicate | NEW-03 | Extracted atomicWriteFile/directWriteFile helpers; 6 tests added | Wave 6 |
| Low | 16 | maintainability | @constCast on arena in normalizeKey | NEW-05 | Expanded safety comment; signature change infeasible due to *const Self callers | Wave 6 |
| Critical | 100 | reliability | dotenv.load() returns dangling pointers (use-after-free) | NEW-12 | `load()` dupes key/value before freeing content; `parseContent` lifetime documented | Wave 6 |
| Medium | 48 | maintainability | Dotenv parsing logic triplicated within dotenv.zig | NEW-01 | Extracted shared `parseLine` helper; all three functions delegate to it | Wave 6 |
| Medium | 32 | reliability | parseContent lifetime risk (NEW-13) + undocumented (NEW-15) | NEW-13/NEW-15 | Lifetime documented via doc comment; `load()` path dupes before free | Wave 6 |
| Medium | 24 | reliability | getPrefix 0xFF overflow | NEW-10 | Added 0xFF overflow guard; appends `0x00` sentinel per etcd convention | Wave 6 |
| High | 48 | maintainability | Hand-rolled JSON response parsing in etcd/Consul | NEW-02 | Replaced with `std.json.parseFromSlice` and typed `EtcdRangeResponse`/`ConsulKVEntry` structs | Wave 7 |
| High | 48 | api-contract | Etcd response parser ignores JSON escaping | NEW-06 | Same std.json fix as NEW-02 | Wave 7 |
| Medium | 36 | api-contract | Consul parseKeysList matches any quoted string | NEW-07 | Same std.json fix as NEW-02 | Wave 7 |
| High | 48 | reliability | No timeout enforcement on Etcd/Consul HTTP requests | NEW-08 | Limitation documented in timeout_ms doc comments; TODO retained for future Zig version | Wave 7 |
| Medium | 36 | documentation | timeout_ms option misleading | NEW-16 | Doc comment warns callers of non-enforcement; resolved with NEW-08 | Wave 7 |
| Medium | 36 | reliability | sync() missing in atomicWriteFile | P3-M4 | Added `temp_file.sync()` before close to prevent data loss on crash | Wave 9 |
| Medium | 36 | maintainability | Duplicate applyAutomaticEnv function | P3-M5 | Removed; all callers use unified applyEnv | Wave 9 |
| Medium | 36 | maintainability | DRY validator wrappers (hostname/url/email) | P3-M6 | Error-returning wrappers now delegate to boolean validators | Wave 9 |
| Medium | 32 | dead-code | Dead timeout functions in remote.zig | P3-M7/P3-H2 | Removed dead timeout-related functions | Wave 9 |
| Medium | 32 | dead-code | Unused prefix param in remote.zig | P3-M8 | Removed unused parameter | Wave 9 |
| Medium | 36 | observability | No debug logging in error-swallowing branches | P3-R2 | Added `std.log.scoped(.config)` with `log.debug` in 4 catch branches | Wave 9 |
| Low | 24 | reliability | Path traversal silently ignored in async.zig | P3-R3 | Now returns `error.PathTraversalDetected` | Wave 9 |
| Low | 24 | resource-mgmt | Missing errdefer temp_file.close | P3-R5 | Added `errdefer temp_file.close()` in config.zig and serialize.zig | Wave 9 |
| Low | 16 | documentation | Missing doc comments on SafeWriteError and serialize write | P3-A1 | Added error contract doc comments | Wave 9 |
| Info | 8 | documentation | isPathSafeStrict potentially unused outside tests | Q-NEW-2 | Doc comment added explaining intended use | Wave 10 |
| Low | 16 | tests | AsyncLoaderWithCallback not integration-tested | Q-NEW-3 | Integration test added for load-then-callback flow | Wave 10 |
| Info | 8 | documentation | Loader.parseContent made pub without doc comment | Q-NEW-4 | Doc comment added describing format dispatch behavior | Wave 10 |
| Low | 16 | tests | Error path coverage gap in remote (no HTTP error response tests) | Q-NEW-7 | HTTP error response tests added for Etcd and Consul | Wave 10 |

---

## Findings by Category

### reliability (8 findings -- 8 resolved, 0 open)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 100 | ~~dotenv.load() returns dangling pointers (use-after-free)~~ | NEW-12 | **Resolved** (Wave 6) |
| 48 | ~~No timeout enforcement on Etcd/Consul HTTP requests~~ | NEW-08 | **Resolved** (Wave 7, documented limitation) |
| 36 | ~~sync() missing in atomicWriteFile~~ | P3-M4 | **Resolved** (Wave 9) |
| 32 | ~~parseContent returns entries into caller-owned content (lifetime risk)~~ | NEW-13 | **Resolved** (Wave 6) |
| 24 | ~~getPrefix range_end overflow on 0xFF last byte~~ | NEW-10 | **Resolved** (Wave 6) |
| 24 | ~~async loadFile swallows OOM silently~~ | NEW-11 | **Resolved** (Wave 6) |
| 24 | ~~Path traversal silently ignored in async.zig~~ | P3-R3 | **Resolved** (Wave 9) |
| 48 | ~~7 remaining catch {} sites~~ | [#148](https://gitlab.com/devnw/zig/config/-/issues/148) | **Resolved** (Waves 1-2) |

### maintainability (18 findings -- 12 resolved, 4 Won't Do, 2 open)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 64 | Loader god-object: 60+ functions | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | **Won't Do** |
| 48 | ~~Dotenv parsing logic triplicated within dotenv.zig~~ | NEW-01 | **Resolved** (Wave 6) |
| 48 | 5 files exceed 800 lines | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | **Won't Do** |
| 48 | ~~Hand-rolled JSON response parsing in etcd/Consul~~ | NEW-02 | **Resolved** (Wave 7) |
| 48 | ~~8 magic number sites bypass limits.zig~~ | [#146](https://gitlab.com/devnw/zig/config/-/issues/146) | **Resolved** (Wave 2) |
| 48 | ~~Hand-rolled JSON construction in remote.zig~~ | [#119](https://gitlab.com/devnw/zig/config/-/issues/119) | **Resolved** (Wave 2) |
| 36 | ~~Dotenv parsing triplication across 3 files~~ | [#152](https://gitlab.com/devnw/zig/config/-/issues/152) | **Resolved** (Wave 2) |
| 36 | ~~Duplicate applyAutomaticEnv function~~ | P3-M5 | **Resolved** (Wave 9) |
| 36 | ~~DRY validator wrappers (hostname/url/email)~~ | P3-M6 | **Resolved** (Wave 9) |
| 32 | ~~Dead timeout functions in remote.zig~~ | P3-M7/P3-H2 | **Resolved** (Wave 9) |
| 32 | ~~Unused prefix param in remote.zig~~ | P3-M8 | **Resolved** (Wave 9) |
| 24 | Consul HTTP boilerplate duplication | Q-NEW-1 | **Deferred** |
| 24 | Large files: remote (2694), loader (1991), encrypted_secrets (1424) | Q-NEW-6 | **Open** |
| 24 | ~~safeWriteConfig/safeWriteConfigWithBackup near-duplicate~~ | NEW-03 | **Resolved** (Wave 6) |
| 16 | ~~@constCast on arena in normalizeKey~~ | NEW-05 | **Resolved** (Wave 6) |
| 8 | Format dispatch duplication (config.zig + loader.zig) | Q-NEW-5 | **Won't Do** (accepted) |
| 4 | Env map construction pattern duplication (Vault + 1Password) | Q-NEW-8 | **Won't Do** |

### api-contract (6 findings -- 6 resolved, 0 open)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 48 | ~~Etcd response parser ignores JSON escaping~~ | NEW-06 | **Resolved** (Wave 7, fixed with NEW-02) |
| 36 | ~~Consul parseKeysList matches any quoted string~~ | NEW-07 | **Resolved** (Wave 7, fixed with NEW-02) |
| 36 | ~~SensitiveString.format wrong signature for std.fmt protocol~~ | NEW-09 | **Resolved** (Wave 6) |
| 60 | ~~Stale doc comment (10 MB vs 1 MB)~~ | [#139](https://gitlab.com/devnw/zig/config/-/issues/139) | **Resolved** (Wave 1) |
| 60 | ~~parallel.loadFile stub returns fake success~~ | [#141](https://gitlab.com/devnw/zig/config/-/issues/141) | **Resolved** (Wave 3) |
| 36 | ~~ConfigFormat duplicated between parallel.zig and loader.zig~~ | [#149](https://gitlab.com/devnw/zig/config/-/issues/149) | **Resolved** (Wave 3) |

### documentation (5 findings -- 5 resolved, 0 Won't Do, 0 open)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 36 | ~~parseContent lifetime constraint undocumented~~ | NEW-15 | **Resolved** (Wave 6) |
| 36 | ~~timeout_ms option misleading -- configured but not enforced~~ | NEW-16 | **Resolved** (Wave 7, fixed with NEW-08) |
| 16 | ~~Missing doc comments on SafeWriteError and serialize write~~ | P3-A1 | **Resolved** (Wave 9) |
| 8 | ~~isPathSafeStrict potentially unused outside tests~~ | Q-NEW-2 | **Resolved** (Wave 10) |
| 8 | ~~Loader.parseContent made pub without doc comment~~ | Q-NEW-4 | **Resolved** (Wave 10) |

### ci-cd (1 finding -- 1 resolved)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 100 | ~~No build/test CI pipeline~~ | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | **Resolved** (Phase 4) |

### tests (3 findings -- 2 resolved, 1 Won't Do, 0 open)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 64 | Weak test coverage in config.zig, xdg.zig, async.zig | [#151](https://gitlab.com/devnw/zig/config/-/issues/151) | **Won't Do** |
| 16 | ~~AsyncLoaderWithCallback not integration-tested~~ | Q-NEW-3 | **Resolved** (Wave 10) |
| 16 | ~~Error path coverage gap in remote (no HTTP error response tests)~~ | Q-NEW-7 | **Resolved** (Wave 10) |

### cleanup (2 findings -- 2 resolved)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 48 | ~~Consul HTTP method triplication~~ | [#123](https://gitlab.com/devnw/zig/config/-/issues/123) | **Resolved** (Wave 3) |
| 24 | ~~Duplicate validate/validation import~~ | [#150](https://gitlab.com/devnw/zig/config/-/issues/150) | **Resolved** (Wave 1) |

### observability (1 finding -- 1 resolved)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 36 | ~~No debug logging in error-swallowing branches~~ | P3-R2 | **Resolved** (Wave 9) |

### resource-mgmt (1 finding -- 1 resolved)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 24 | ~~Missing errdefer temp_file.close~~ | P3-R5 | **Resolved** (Wave 9) |

### readability (2 findings -- 2 resolved)

| Score | Finding | Issue/ID | Status |
|-------|---------|----------|--------|
| 36 | ~~matchPatternImpl 209-line recursive function~~ | [#120](https://gitlab.com/devnw/zig/config/-/issues/120) | **Resolved** (Wave 2) |
| 24 | ~~build.zig repeats imports 6 times~~ | [#153](https://gitlab.com/devnw/zig/config/-/issues/153) | **Resolved** (Wave 3) |

---

## Roadmap

### Wave 6 -- Quick Wins (< 1 day, 9 items) -- ALL RESOLVED

| Finding | Score | ID | Effort | Notes |
|---------|-------|----|--------|-------|
| ~~dotenv.load() dangling pointers~~ | 100 | NEW-12 | S | **Resolved** (Wave 6): dupe key/value before freeing content |
| ~~Dotenv triplication within dotenv.zig~~ | 48 | NEW-01 | S | **Resolved** (Wave 6): extracted `parseLine` helper |
| ~~SensitiveString.format wrong signature~~ | 36 | NEW-09 | S | **Resolved** (Wave 6) |
| ~~parseContent lifetime doc~~ | 36 | NEW-15 | S | **Resolved** (Wave 6): doc comment added |
| ~~timeout_ms misleading doc~~ | 36 | NEW-16 | S | **Resolved** (Wave 7): doc comment warning added |
| ~~parseContent lifetime risk~~ | 32 | NEW-13 | S | **Resolved** (Wave 6): lifetime documented; load() dupes |
| ~~getPrefix 0xFF overflow~~ | 24 | NEW-10 | S | **Resolved** (Wave 6): 0xFF guard with etcd sentinel |
| ~~async loadFile OOM handling~~ | 24 | NEW-11 | S | **Resolved** (Wave 6) |
| ~~@constCast in normalizeKey~~ | 16 | NEW-05 | S | **Resolved** (Wave 6) |

### Wave 7 -- Medium (1-5 days, 4 items) -- ALL RESOLVED

| Finding | Score | ID | Effort | Notes |
|---------|-------|----|--------|-------|
| ~~Hand-rolled JSON response parsing~~ | 48 | NEW-02 | M | **Resolved** (Wave 7): std.json.parseFromSlice with typed structs |
| ~~Etcd JSON escaping + Consul parseKeysList~~ | 48+36 | NEW-06, NEW-07 | M | **Resolved** (Wave 7): same std.json fix as NEW-02 |
| ~~No timeout enforcement~~ | 48 | NEW-08 | M | **Resolved** (Wave 7): limitation documented in doc comments |
| ~~safeWriteConfig duplication~~ | 24 | NEW-03 | S | **Resolved** (Wave 6) |

### Previously Completed Quick Wins (Waves 1-3, 6)

All 7 original quick win items resolved: #139 (Wave 1), #146 (Wave 2), #148 (Waves 1-2), #152 (Wave 2), #149 (Wave 3), #150 (Wave 1), #153 (Wave 3).

Wave 6 resolved: NEW-09 (SensitiveString format output), NEW-11 (async OOM propagation), NEW-05 (@constCast rationale), NEW-03 (atomicWriteFile extraction), NEW-12 (dotenv dangling pointers), NEW-01 (dotenv dedup), NEW-13+NEW-15 (parseContent lifetime), NEW-10 (getPrefix overflow).

### Previously Completed Medium (Waves 2-3, 7)

Items resolved: #141 (Wave 3), #123 (Wave 3), #119 (Wave 2), #120 (Wave 2), NEW-02/06/07 (std.json response parsing, Wave 7), NEW-08/16 (timeout_ms documentation, Wave 7).

### Phase 3 Addendum -- Quick Wins (< 1 day, 4 items) -- 3 CLOSED, 1 DEFERRED

| Finding | Score | ID | Effort | Notes |
|---------|-------|----|--------|-------|
| Consul HTTP boilerplate duplication | 24 | Q-NEW-1 | S | **Deferred** -- extract shared `makeRequest` helper when time permits |
| ~~AsyncLoaderWithCallback not integration-tested~~ | 16 | Q-NEW-3 | S | **Resolved** (Wave 10): Integration test added |
| ~~isPathSafeStrict unused outside tests~~ | 8 | Q-NEW-2 | S | **Resolved** (Wave 10): Doc comment added |
| ~~Loader.parseContent missing doc comment~~ | 8 | Q-NEW-4 | S | **Resolved** (Wave 10): Doc comment added |

### Phase 3 Addendum -- Medium (1-5 days, 2 items) -- 1 CLOSED, 1 OPEN

| Finding | Score | ID | Effort | Notes |
|---------|-------|----|--------|-------|
| Large files: remote (2694), loader (1991), encrypted_secrets (1424) | 24 | Q-NEW-6 | M | **Open** -- Split tests into `*_test.zig` companion files |
| ~~Error path coverage gap in remote~~ | 16 | Q-NEW-7 | M | **Resolved** (Wave 10): HTTP error response tests added for Etcd and Consul |

### Phase 3 Addendum -- Won't Do (2 items)

| Finding | Score | ID | Reason |
|---------|-------|-----|--------|
| Format dispatch duplication (config.zig + loader.zig) | 8 | Q-NEW-5 | Accepted -- different return types (Value tree vs key-value store) justify separate dispatch |
| Env map construction pattern duplication | 4 | Q-NEW-8 | Only 2 callsites; extraction would obscure provider-specific logic |

### Strategic (> 5 days) -- Won't Do

| Finding | Score | Issue | Reason |
|---------|-------|-------|--------|
| Loader god-object (60+ functions) | 64 | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | Strategic refactor >5 days, not a gap closure item |
| 5 files exceed 800 lines | 48 | [#98](https://gitlab.com/devnw/zig/config/-/issues/98) | Part of same loader decomposition effort |

---

## Phase 4 Verification of Previously Resolved Findings

The following items were re-verified during Phase 4 quality review:

| Finding | Issue | Phase 4 Verdict |
|---------|-------|-----------------|
| QUAL-11 (matchPatternImpl) | [#120](https://gitlab.com/devnw/zig/config/-/issues/120) | Confirmed resolved -- decomposed to ~49 lines with sub-functions |
| QUAL-12 (dotenv triplication) | [#152](https://gitlab.com/devnw/zig/config/-/issues/152) | Partially resolved -- loader delegates to dotenv, but dotenv.zig itself still has 3 copies (NEW-01) |
| QUAL-13 (ConfigFormat duplication) | [#149](https://gitlab.com/devnw/zig/config/-/issues/149) | Confirmed resolved |
| QUAL-15 (build.zig imports) | [#153](https://gitlab.com/devnw/zig/config/-/issues/153) | Confirmed resolved |
| #146 (magic numbers) | [#146](https://gitlab.com/devnw/zig/config/-/issues/146) | Confirmed resolved |
| #119 (hand-rolled JSON) | [#119](https://gitlab.com/devnw/zig/config/-/issues/119) | Partially resolved -- request construction uses std.json but response parsing is still hand-rolled (NEW-02) |
| #123 (Consul HTTP triplication) | [#123](https://gitlab.com/devnw/zig/config/-/issues/123) | Confirmed resolved |
| #148 (catch {} sites) | [#148](https://gitlab.com/devnw/zig/config/-/issues/148) | Confirmed resolved -- original 7 fixed; remaining catch {} are acceptable (pre-size hints, cleanup paths) |
| #82 (CI pipeline) | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | Status changed: Was "Won't Do", now **Resolved** -- CI fully implemented with build, test (4 modes), fuzz, security, SBOM, release stages |

---

## Confidence Notes

All 16 new findings (NEW-01 through NEW-16) are tagged `confidence::confirmed` -- verified by direct code inspection with file paths, line numbers, and code snippets during Phase 4 review. All 16 are now resolved (Waves 6-7).

Wave 9 added 9 new findings (P3-M4, P3-M5, P3-M6, P3-M7/P3-H2, P3-M8, P3-R2, P3-R3, P3-R5, P3-A1), all closed immediately with code changes and tests.

Phase 3 addendum added 8 findings (Q-NEW-1 through Q-NEW-8), all tagged `confidence::confirmed` -- verified by direct code inspection with file paths and line numbers. Of these, 4 were resolved in Wave 10 (Q-NEW-2, Q-NEW-3, Q-NEW-4, Q-NEW-7), 1 is deferred (Q-NEW-1), 1 is open (Q-NEW-6), and 2 are Won't Do (Q-NEW-5, Q-NEW-8).

All 55 findings (47 resolved + 6 Won't Do + 2 open) verified by code inspection, CI configuration review, or test execution.

## Unknowns

- **SensitiveString.format**: The test at `encrypted_secrets.zig` uses `{f}` and passes (NEW-09, resolved Wave 6). The format output was updated to `[REDACTED]`.
- **timeout_ms enforcement**: Documented as Zig 0.15 http.Client limitation (NEW-08/16, resolved Wave 7). TODO retained for future Zig version.
- **Windows CI**: No Windows CI runner is configured; platform-specific code paths (xdg.zig, environ.zig) are untested on Windows.
- **Remote module usage**: The Etcd/Consul modules may not be actively used in production. JSON response parsing is now via std.json (NEW-02/06/07, resolved Wave 7).
- **getPrefix overflow**: Resolved (NEW-10, Wave 6). The 0xFF case appends a `0x00` sentinel byte per etcd convention.
- ~~**isPathSafeStrict consumers** (Q-NEW-2)~~: **Resolved** (Wave 10). Doc comment added explaining intended use as stricter alternative to `isPathSafe`.
- ~~**AsyncLoaderWithCallback integration coverage** (Q-NEW-3)~~: **Resolved** (Wave 10). Integration test added exercising the full load-then-callback flow.
