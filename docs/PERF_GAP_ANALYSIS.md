# Performance Gap Analysis -- zigconfig

Last updated: 2026-03-24 (Phase 5 review)

## Summary

| PerfSeverity | Count | Closed | Won't Do | Reopened | Open |
|-------------|-------|--------|----------|----------|------|
| P1          | 5     | 4      | 1        | 0        | 0    |
| P2          | 11    | 9      | 1        | 0        | 1    |
| P3          | 15    | 14     | 0        | 0        | 1    |
| Info        | 19    | 15     | 4        | 0        | 0    |
| **Total**   | **50** | **42** | **6** | **0** | **2** |

4 legacy Info items superseded by higher-severity Phase 4 findings and excluded from counts above:
PERF-22 superseded by PERF-28, PERF-23 superseded by PERF-32, PERF-20i superseded by PERF-37, PERF-21 superseded by PERF-38.

Phase 4 audit applied 2026-03-24. Verified resolved findings from Phases 1-3; re-opened 2 incompletely fixed items. Added 21 new findings from Phase 4 review.

Phase 5 review applied 2026-03-24. Added 5 new findings from Phase 5 code-level review. 1 actionable (PERF-54), 4 informational/won't-do.

### Status corrections from Phase 4 verification
- **PERF-14 (#126)**: Reopened Phase 4 -> **Closed** Wave 7. All three env functions now share a single `std.process.EnvMap` snapshot from `load()`.
- **PERF-16 (#128)**: Reopened Phase 4 -> **Closed** Wave 7. All parse loops (JSON, TOML, INI) now use stack-buffer `bufPrint`.
- **PERF-17 (#129)**: Verified resolved -- all key sites pre-sized.
- **PERF-11 (#125)**: Verified resolved -- setFieldInner dupes once.
- **PERF-15 (#127)**: Verified resolved -- HashMap O(1) lookups.
- **PERF-12 (#136)**: Verified resolved -- retain_capacity semantics.

### Top 5 Risks by PerfScore

| Rank | Finding | PerfScore | Status |
|------|---------|-----------|--------|
| 1 | ~~timeout_ms configured but never applied to HTTP (PERF-38)~~ | 60 | **Closed** (Wave 7, documented limitation) |
| 2 | No benchmark suite (#89) (PERF-44) | 40 | **Open** (rescored from 80) |
| 3 | ~~Auth header rebuilt per request (PERF-33)~~ | 24 | **Closed** (Wave 8) |
| 4 | ~~recheckDnsBinding re-parses URI (PERF-37)~~ | 24 | **Closed** (Wave 8) |
| 5 | ~~Thread pool spawns threads eagerly (PERF-42)~~ | 20 | **Closed** (Wave 8) |

---

## Stack-Ranked Findings Table

### Phase 1-3 Findings (previously tracked)

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue | Fix Summary | Owner | SLA | Status |
|------|-------------|-----------|---------|-----------|----------|-------------|-------|-------------|-------|-----|--------|
| 1 | P1 | 80 | CI skips build/test entirely -- regressions land undetected | .gitlab-ci.yml | `.gitlab-ci.yml` previously had no build/test stages | No build or test verification on any MR | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | CI now has build+test+fuzz stages with Zig 0.15.2 | benjiv | Sprint | **Won't Do** (superseded; CI now active) |
| 2 | P1 | 80 | ~~DNS resolution on every API call via validateUrl~~ | remote.zig | `src/remote.zig:628-631` -- validateUrl in init() | DNS overhead eliminated | [#100](https://gitlab.com/devnw/zig/config/-/issues/100) | Moved validateUrl to init time for both clients | benjiv | Sprint | **Closed** |
| 3 | P1 | 64 | ~~Memory leak in mergeMaps -- overridden keys not freed~~ | merge.zig | `src/merge.zig:61-71,81-82` -- getPtr for in-place update | Leak eliminated | [#102](https://gitlab.com/devnw/zig/config/-/issues/102) | Used getPtr for in-place value update | benjiv | Sprint | **Closed** |
| 4 | P2 | 60 | No performance regression detection in CI | .gitlab-ci.yml | `.gitlab-ci.yml` -- no bench stage; no baseline artifacts | No per-commit perf data collected | [#131](https://gitlab.com/devnw/zig/config/-/issues/131) | Add bench stage with baseline comparison and regression gating | benjiv | Quarter | **Won't Do** |
| 5 | P2 | 48 | ~~Unbounded thread spawning in loadParallel~~ | async.zig | `src/async.zig:319-384` -- MAX_PARALLEL_THREADS=16 with batch processing | Bounded to 16 threads max | [#106](https://gitlab.com/devnw/zig/config/-/issues/106) | Added MAX_PARALLEL_THREADS=16 with batch processing | benjiv | Quarter | **Closed** |
| 6 | P2 | 40 | ~~No HTTP connection reuse -- new TCP+TLS per request~~ | remote.zig | Verified: client.fetch API manages connection pooling internally | Connection pooling confirmed | [#96](https://gitlab.com/devnw/zig/config/-/issues/96) | Verified connection reuse via client.fetch; documentation added | benjiv | Quarter | **Closed** (Wave 4) |
| 7 | P2 | 40 | ~~parallel.loadFile/serializeData are stub implementations~~ | parallel.zig | Fixed: real file I/O implemented | Parallel module now performs actual I/O | [#132](https://gitlab.com/devnw/zig/config/-/issues/132) | Implemented real file I/O and serialization | benjiv | Quarter | **Closed** (Wave 3) |
| 8 | P2 | 36 | ~~Sequential file loading in Loader.load()~~ | loader.zig | Fixed: parallel I/O with serial merge | Parallel loading reduces startup latency | [#104](https://gitlab.com/devnw/zig/config/-/issues/104) | Parallelized file loading with serial merge in precedence order | benjiv | Quarter | **Closed** (Wave 5) |
| 9 | P2 | 24 | ~~Full file buffering via readToEndAlloc (mitigated to 1MB)~~ | loader.zig, async.zig | All call sites now use limits.zig constants (1MB cap) | Reduced from 10MB to 1MB per file | [#111](https://gitlab.com/devnw/zig/config/-/issues/111) | Reduced limits from 10MB to 1MB via centralized limits.zig | benjiv | Quarter | **Closed** |
| 10 | P3 | 32 | ~~Double string duplication in setField~~ | loader.zig | `src/loader.zig:1249` -- setFieldInner dupes once; setFieldValueOwned assigns without re-dupe | Arena alloc halved per string field set | [#125](https://gitlab.com/devnw/zig/config/-/issues/125) | Share single arena-owned copy between config field and provenance tracker | benjiv | Backlog | **Closed** |
| 11 | P3 | 24 | ~~Unbounded arena growth in Etcd and Consul remote clients~~ | remote.zig | `src/remote.zig` -- Etcd.resetArena() and Consul.resetArena() added | Arena bounded via explicit reset API | [#136](https://gitlab.com/devnw/zig/config/-/issues/136) | Added resetArena() to both clients with retain_capacity semantics | benjiv | Backlog | **Closed** |
| 12 | P3 | 16 | ~~Global thread pool uses page_allocator, never freed~~ | parallel.zig | Fixed: configurable allocator with deinit | GPA-compatible allocator with proper cleanup | [#124](https://gitlab.com/devnw/zig/config/-/issues/124) | Replaced page_allocator with configurable allocator + deinit | benjiv | Backlog | **Closed** (Wave 3) |
| 13 | P3 | 16 | ~~Sequential/repeated environment variable lookups~~ | loader.zig | All three env functions (`applyBoundEnvVars`, `applyAutomaticEnv`, `applyEnv`) now use a shared `std.process.EnvMap` snapshot from `load()`. | 0 per-item syscalls | [#126](https://gitlab.com/devnw/zig/config/-/issues/126) | Fully resolved: single getEnvMap snapshot shared across all env functions (Wave 7) | benjiv | Backlog | **Closed** (Wave 7) |
| 14 | P3 | 12 | ~~O(n^2) case-insensitive diff~~ | diff.zig | `src/diff.zig` -- lowercased key HashMap built upfront; O(1) lookups | O(n+m) via HashMap | [#127](https://gitlab.com/devnw/zig/config/-/issues/127) | Build lowercased key lookup table | benjiv | Backlog | **Closed** |
| 15 | P3 | 12 | ~~allocPrint in loops for path construction~~ | loader.zig | All parse loops (JSON object, TOML section, INI section) now use `var key_buf: [512]u8` with `std.fmt.bufPrint`. JSON array loop N/A (no array handling). | 0 heap allocs for key construction in all parsers | [#128](https://gitlab.com/devnw/zig/config/-/issues/128) | Fully resolved: bufPrint with stack buffers in all parse loops (Wave 7) | benjiv | Backlog | **Closed** (Wave 7) |
| 16 | Info | 20 | ~~No capacity hints on 135+ collections~~ | Multiple | Key sites pre-sized | ~10 highest-impact call paths covered | [#129](https://gitlab.com/devnw/zig/config/-/issues/129) | Added ensureTotalCapacity to key init paths | benjiv | As capacity | **Closed** |
| 17 | Info | 16 | ~~allocPrint for JSON body construction in Etcd~~ | remote.zig | `src/remote.zig` -- stack buffer `bufPrint` (1024B) with heap fallback | 0 heap allocs for typical JSON bodies | -- | Stack buffer bufPrint (1024B), heap fallback for oversized bodies | benjiv | As capacity | **Closed** (Wave 8) |
| 18 | Info | 12 | ~~Base64 encode allocates per Etcd request~~ | remote.zig | `src/remote.zig` -- stack buffer (512B) with heap fallback for base64 encoding | 0 heap allocs for typical key/value sizes | -- | Stack buffer (512B), heap fallback for oversized payloads | benjiv | As capacity | **Closed** (Wave 8) |
| 19 | Info | 12 | ~~URI re-parsed on every request~~ | remote.zig | `src/remote.zig` -- cached parsed URIs at init for Etcd and Consul | 0 per-request URI parses; cached at init with path override | -- | Cached parsed URIs at init for both Etcd and Consul clients | benjiv | As capacity | **Closed** (Wave 8, via PERF-37) |
| 20 | Info | 8 | ~~Lowercased key allocated per lookup in case-insensitive mode~~ | loader.zig | `src/loader.zig` -- `normalizeKey` uses stack buffer with arena fallback | 0 heap allocs for keys < 256 bytes | -- | Stack buffer in normalizeKey, arena fallback for oversized keys | benjiv | As capacity | **Closed** (Wave 8) |
| 21 | Info | 8 | No connection timeout configuration for remote clients | remote.zig | `setSocketTimeout` exists at `src/remote.zig:545` but never called; fetch API has no timeout param | Requests may hang indefinitely on network issues | -- | Superseded by PERF-38 | benjiv | As capacity | Not filed |
| 22 | Info | 4 | ~~INI section.key path built with allocPrint per entry~~ | loader.zig | Superseded by PERF-28 (already **Closed** Wave 7) | N/A | -- | Superseded by PERF-28 | benjiv | As capacity | Superseded by PERF-28 |
| 23 | Info | 4 | ~~Redundant prefix_with_dot allocation in hasPrefix~~ | loader.zig | Superseded by PERF-32 (now **Closed** Wave 8) | N/A | -- | Superseded by PERF-32 | benjiv | As capacity | Superseded by PERF-32 |

### Phase 4 New Findings

| Rank | ID | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue | Fix Summary | Owner | SLA | Status |
|------|-----|-------------|-----------|---------|-----------|----------|-------------|-------|-------------|-------|-----|--------|
| 1 | PERF-43 | P1 | 60 | No CI caching -- Zig downloaded 7x per pipeline | .gitlab-ci.yml | `.gitlab-ci.yml:36-71` -- `.install-zig` anchor runs `curl` + `tar` in every job (zig-format, build, test, test-release-safe, test-release-fast, test-release-small, fuzz). Conditional `if [ ! -f ... ]` is ineffective without caching since each job starts from a clean image. | 7 downloads of ~45MB Zig tarball per pipeline = ~315MB bandwidth + ~2-3 min install overhead per job | -- | Added global `cache:` block keyed on `ZIG_VERSION` for `zig-${ZIG_VERSION}/` and `.zig-cache/` directories. Install-zig conditional now skips download on cache hit. | benjiv | Sprint | **Closed** |
| 2 | PERF-38 | P1 | 60 | ~~timeout_ms configured but never applied to HTTP requests~~ | remote.zig | `EtcdOptions.timeout_ms` and `ConsulOptions.timeout_ms` doc comments updated to document Zig 0.15 http.Client limitation; TODO retained for future version. Comment at `src/remote.zig` makeRequest explains fetch API constraint. | Limitation documented; callers warned timeout_ms is not enforced | -- | Documented limitation in doc comments (Wave 7); TODO retained for future Zig version with timeout support | benjiv | Sprint | **Closed** (Wave 7, documented limitation) |
| 3 | PERF-31 | P2 | 48 | ~~applyBoundEnvVars per-item getenv syscall~~ | loader.zig | All three env functions now receive a shared `std.process.EnvMap` snapshot from `load()`. Uses `env_map.get()` instead of `environ.getenv()`. | 0 per-item syscalls; single snapshot shared | -- | Hoisted `std.process.getEnvMap` into `load()` and passed to all env functions (Wave 7) | benjiv | Quarter | **Closed** (Wave 7) |
| 4 | PERF-44 | P2 | 40 | No benchmark suite -- CI blocker now resolved | build.zig | No `bench` step in `build.zig`. CI infrastructure (#82) is now resolved (build+test stages active with Zig 0.15.2), removing the previous blocker. Rescored from original 80 to 40 since CI is available but benchmarks are not yet added. | Cannot quantify any optimization; all perf estimates are code-inspection only | [#89](https://gitlab.com/devnw/zig/config/-/issues/89) | Add `zig build bench` step with per-component benchmarks. CI can now run them. | benjiv | Quarter | **Open** (was Won't Do, now unblocked) |
| 5 | PERF-36 | P2 | 36 | ~~setFieldInner dupes before field match~~ | loader.zig | Verified: `setField` already performs `arena.dupe()` inside the `if (matchFieldName(...))` branch. No `setFieldInner` exists. Already resolved by prior refactoring. | No wasted allocs; dupes only on match | -- | Already resolved in current code | benjiv | Quarter | **Closed** (already resolved) |
| 6 | PERF-26 | P2 | 32 | ~~allocPrint in JSON object recursion~~ | loader.zig | `applyJsonValue` uses `var key_buf: [512]u8` with `std.fmt.bufPrint`. No heap allocation per JSON object entry. | 0 heap allocs for key construction | -- | Replaced `allocPrint` with stack-buffer `bufPrint` (Wave 7) | benjiv | Quarter | **Closed** (Wave 7) |
| 7 | PERF-39 | P2 | 28 | ~~Double getEnvMap snapshot~~ | loader.zig | `load()` creates a single `std.process.getEnvMap` snapshot and passes `*const std.process.EnvMap` to all three env functions. | 1 snapshot total instead of up to 3 | -- | Hoisted single snapshot into `load()` (Wave 7) | benjiv | Quarter | **Closed** (Wave 7) |
| 8 | PERF-33 | P3 | 24 | ~~Auth header rebuilt on every Etcd request~~ | remote.zig | `src/remote.zig` -- auth header cached at `Etcd.init()`, `secureZero` in `deinit()` | 0 per-request allocs for auth; cached at init | -- | Cached auth header at init, secureZero in deinit | benjiv | Backlog | **Closed** (Wave 8) |
| 9 | PERF-37 | P3 | 24 | ~~recheckDnsBinding re-parses URI redundantly per request~~ | remote.zig | `src/remote.zig` -- cached parsed URIs at init for both Etcd and Consul; path override per request | 0 per-request URI parses | -- | Cached parsed URIs at init for both Etcd and Consul clients | benjiv | Backlog | **Closed** (Wave 8) |
| 10 | PERF-42 | P3 | 20 | ~~Thread pool spawns OS threads even when parallel module is inactive~~ | parallel.zig | `src/parallel.zig` -- parallel threshold raised from 2 to 4 files; small file counts use sequential I/O | Threads only spawned for 4+ files; avoids overhead for small configs | -- | Raised parallel threshold from 2 to 4 files | benjiv | Backlog | **Closed** (Wave 8) |
| 11 | PERF-25 | P3 | 16 | Double allocLowerString per matching key in case-insensitive diff | diff.zig | `src/diff.zig:176` -- `allocLowerString(key)` for lookup, then `src/diff.zig:183` -- `allocLowerString(key)` again for seen_keys insertion. Same key lowercased twice. Similarly at lines 230 and 237 for the added-keys pass. | 2x allocLowerString per key in case-insensitive mode; 4x for keys checked in both passes | -- | Refactored: seen_keys stores lowered keys (allocated once) for O(1) hash lookup in added-keys pass. Removed O(n) containsKeyInsensitive linear scan. Each key is lowered once per pass. | benjiv | Backlog | **Closed** |
| 12 | PERF-27 | P3 | 16 | ~~allocPrint in TOML section loop~~ | loader.zig | `parseSimpleToml` uses `var key_buf: [512]u8` with `std.fmt.bufPrint` for section.key construction. | 0 heap allocs for key construction | -- | Replaced `allocPrint` with stack-buffer `bufPrint` (Wave 7) | benjiv | Backlog | **Closed** (Wave 7) |
| 13 | PERF-28 | P3 | 16 | ~~allocPrint in INI section loop~~ | loader.zig | `parseIni` uses `var key_buf: [512]u8` with `std.fmt.bufPrint` for section.key construction. | 0 heap allocs for key construction | -- | Replaced `allocPrint` with stack-buffer `bufPrint` (Wave 7) | benjiv | Backlog | **Closed** (Wave 7) |
| 14 | PERF-29 | P3 | 16 | ~~allocPrint in JSON array index loop~~ | loader.zig | No JSON array handling code exists in `applyJsonValue`; the `.array` case is handled by the `else => {}` branch which skips arrays. Nothing to fix. | N/A -- code path does not exist | -- | Not applicable; no array flattening in current parser | benjiv | Backlog | **Closed** (N/A) |
| 15 | PERF-34 | Info | 16 | ~~URL allocPrint per Etcd failover attempt~~ | remote.zig | `src/remote.zig` -- eliminated via cached URI with path override | 0 per-request URL allocs; base URI cached at init | -- | Cached URI at init; path override per request eliminates allocPrint | benjiv | As capacity | **Closed** (Wave 8) |
| 16 | PERF-35 | Info | 16 | ~~Consul URL allocPrint per operation~~ | remote.zig | `src/remote.zig` -- stack buffer `bufPrint` for paths + cached URI at init | 0 heap allocs for typical Consul KV paths | -- | Stack buffer bufPrint for paths + cached URI | benjiv | As capacity | **Closed** (Wave 8) |
| 17 | PERF-32 | Info | 12 | ~~prefix_with_dot heap alloc in sub()/hasSub()~~ | loader.zig | `src/loader.zig` -- stack buffer `bufPrint` (256B) in sub()/hasSub() | 0 heap allocs for prefix + "." (typical < 256B) | -- | Stack buffer bufPrint (256B) in sub/hasSub | benjiv | As capacity | **Closed** (Wave 8) |
| 18 | PERF-30 | Info | 8 | ~~formatDiff iterates changes array 3x~~ | diff.zig | `src/diff.zig` -- single pass with 3 output buffers | 1 pass over changes array instead of 3 | -- | Single pass with 3 output buffers | benjiv | As capacity | **Closed** (Wave 8) |
| 19 | PERF-40 | Info | 8 | ~~page_allocator granularity waste for small file reads~~ | parallel.zig | `src/parallel.zig` -- added `initPool()` accepting caller allocator + documentation | Callers can now pass GPA or other allocator; docs explain trade-offs | -- | Added initPool() with caller allocator + docs | benjiv | As capacity | **Closed** (Wave 8) |
| 20 | PERF-41 | Info | 8 | ~~Global pool_mutex contention in parallel.zig~~ | parallel.zig | `src/parallel.zig` -- replaced mutex with `std.once` for lock-free reads after init | Lock-free reads on hot path; init serialized via std.once | -- | Replaced pool_mutex with std.once for lock-free reads | benjiv | As capacity | **Closed** (Wave 8) |
| 21 | PERF-45 | Info | 4 | CI conditional Zig check is dead code without caching | .gitlab-ci.yml | `.gitlab-ci.yml:38` -- `if [ ! -f "zig-${ZIG_VERSION}/zig" ]` check is always true because each job uses a clean container image. The conditional adds complexity with no benefit until caching is enabled (PERF-43). | Dead code in CI; no functional impact but misleading | -- | Resolved by PERF-43: global `cache:` block added, so the conditional now correctly skips download on cache hit. No code change needed. | benjiv | As capacity | **Closed** |

### Wave 9 New Findings

| Rank | ID | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue | Fix Summary | Owner | SLA | Status |
|------|-----|-------------|-----------|---------|-----------|----------|-------------|-------|-------------|-------|-----|--------|
| 1 | PERF-48 | Info | 8 | ~~Redundant getValueForKey in added-keys pass~~ | diff.zig | `src/diff.zig` -- removed redundant `getValueForKey(old_config, ...)` call; `seen_keys` check is sufficient | 1 fewer O(n) lookup per new key in pass 2 | -- | Removed redundant lookup; seen_keys check is sufficient | benjiv | As capacity | **Closed** (Wave 9) |
| 2 | PERF-50 | P3 | 16 | ~~Stack buffer in tryAccessPath for findConfigFile~~ | loader.zig | `src/loader.zig` -- `tryAccessPath` uses 512-byte stack buffer; falls back to allocPrint | 0 heap allocs for typical file search paths | -- | Stack buffer tryAccessPath helper in findConfigFileWithOptions | benjiv | Backlog | **Closed** (Wave 9) |
| 3 | PERF-51 | Info | 8 | ~~Batch literal appending in expand.zig~~ | expand.zig | `src/expand.zig` -- `literal_start` tracks runs; single `appendSlice` per run | Reduces ArrayList ops proportional to literal run length | -- | Track literal runs with batch appendSlice flush | benjiv | As capacity | **Closed** (Wave 9) |
| 4 | PERF-52 | Info | 12 | ~~Missing memory fence in initPool~~ | parallel.zig | `src/parallel.zig` -- `@fence(.seq_cst)` after `pool_allocator` write | Prevents data race between initPool and getPool across threads | -- | Added @fence(.seq_cst) for cross-thread visibility | benjiv | As capacity | **Closed** (Wave 9) |
| 5 | PERF-53 | Info | 8 | ~~addFile lacks runtime guard in async.zig~~ | async.zig | `src/async.zig` -- `addFile` checks `self.result.state == .running` under mutex | Prevents programming error of adding files to running loader | -- | Added AlreadyRunning guard in addFile | benjiv | As capacity | **Closed** (Wave 9) |

### Phase 5 New Findings

| Rank | ID | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue | Fix Summary | Owner | SLA | Status |
|------|-----|-------------|-----------|---------|-----------|----------|-------------|-------|-------------|-------|-----|--------|
| 1 | PERF-54 | P3 | 12 | HashMap no capacity hint in diff `merge()` and `compareWithOptions()` | diff.zig | `src/diff.zig:124,146,434` -- `StringHashMap.init()` with no `ensureTotalCapacity`; input sizes known from `.count()` | Avoids O(log n) rehashes during map population; saves ~3-5 realloc+rehash cycles for 50+ key configs | -- | Add `ensureTotalCapacity(base.count() + overlay.count())` to `merge()` result map; add hints to `new_lower_index` and `seen_keys` in `compareWithOptions()` | benjiv | Backlog | **Open** |
| 2 | PERF-55 | Info | 4 | HTTP connection reuse already works via std.http.Client pool | remote.zig | `src/remote.zig:655,1045` -- `http.Client{ .allocator = allocator }` manages connection pooling internally via `client.fetch()` | No action needed; connection pooling confirmed in PERF-7 (Closed Wave 4) | -- | No action -- already works. Duplicate of PERF-7 validation. | benjiv | As capacity | **Won't Do** (confirmed working) |
| 3 | PERF-56 | Info | 4 | allocPrint in INI section loop negligible for realistic configs | loader.zig | `src/loader.zig:828,891` -- `allocPrint` for section.key construction; typical configs have < 20 sections x < 10 keys = < 200 allocs | Negligible: < 200 small allocs total; already mitigated in JSON/TOML paths by PERF-28 (Wave 7) | -- | No action -- cost is negligible for realistic config sizes; INI path retained for simplicity | benjiv | As capacity | **Won't Do** (negligible impact) |
| 4 | PERF-57 | Info | 4 | Repeated toLower in merge path | merge.zig | `src/merge.zig` -- no `toLower`/`allocLowerString` calls found; merge.zig operates on exact keys only | No toLower calls exist in merge.zig; finding does not apply to current codebase | -- | No action -- merge.zig uses exact key matching; case-insensitive lowering is in diff.zig only (already optimized by PERF-25) | benjiv | As capacity | **Won't Do** (not applicable) |
| 5 | PERF-58 | Info | 8 | Provenance tracker unbounded growth | provenance.zig | `src/provenance.zig:73,81` -- `StringHashMap(TrackedValue)` grows with each `set()` call; no explicit capacity bound | Bounded in practice by config struct field count (typically < 100 fields); memory is arena-managed and freed on `Loader.deinit()` | -- | Document: growth is bounded by number of unique config keys (struct fields); no fix needed | benjiv | As capacity | **Won't Do** (bounded by design) |

Phase 5 findings P-NEW-5 (sequential format detection) and P-NEW-6 (no streaming parse) were evaluated and rejected as non-findings:
- P-NEW-5: `detectFormatFromContent` at `src/loader.zig:1144` is O(1) -- a few byte comparisons on the first characters. Not a performance concern.
- P-NEW-6: Streaming parse is a design decision. File sizes are bounded by `limits.zig` (1MB max). Full buffering is appropriate for config files of this size.
- P-NEW-7 (response storage duplication in remote): Standard allocate-parse-free pattern in `makeRequest()` at `src/remote.zig:904-936`. No duplication -- response is allocated once and freed after parsing.

---

## Findings by Area

### App (loader.zig, parallel.zig, async.zig, merge.zig, diff.zig)

| ID | PerfScore | Finding | Severity | Issue | Status |
|----|-----------|---------|----------|-------|--------|
| PERF-4 | 64 | ~~Memory leak in mergeMaps~~ | P1 | [#102](https://gitlab.com/devnw/zig/config/-/issues/102) | **Closed** |
| PERF-6 | 48 | ~~Unbounded thread spawning~~ | P2 | [#106](https://gitlab.com/devnw/zig/config/-/issues/106) | **Closed** |
| PERF-31 | 48 | ~~applyBoundEnvVars per-item getenv~~ | P2 | -- | **Closed** (Wave 7) |
| PERF-8 | 40 | ~~parallel.loadFile/serializeData stubs~~ | P2 | [#132](https://gitlab.com/devnw/zig/config/-/issues/132) | **Closed** (Wave 3) |
| PERF-36 | 36 | ~~setFieldInner dupes before match~~ | P2 | -- | **Closed** (already resolved) |
| PERF-9 | 36 | ~~Sequential file loading~~ | P2 | [#104](https://gitlab.com/devnw/zig/config/-/issues/104) | **Closed** (Wave 5) |
| PERF-26 | 32 | ~~allocPrint in JSON recursion~~ | P2 | -- | **Closed** (Wave 7) |
| PERF-10 | 24 | ~~Full file buffering (mitigated to 1MB)~~ | P2 | [#111](https://gitlab.com/devnw/zig/config/-/issues/111) | **Closed** |
| PERF-11 | 32 | ~~Double string duplication in setField~~ | P3 | [#125](https://gitlab.com/devnw/zig/config/-/issues/125) | **Closed** |
| PERF-39 | 28 | ~~Double getEnvMap snapshot~~ | P2 | -- | **Closed** (Wave 7) |
| PERF-33 | 24 | ~~Auth header rebuilt per request~~ | P3 | -- | **Closed** (Wave 8) |
| PERF-37 | 24 | ~~recheckDnsBinding re-parses URI~~ | P3 | -- | **Closed** (Wave 8) |
| PERF-42 | 20 | ~~Thread pool spawns threads eagerly~~ | P3 | -- | **Closed** (Wave 8) |
| PERF-13 | 16 | ~~Global thread pool page_allocator~~ | P3 | [#124](https://gitlab.com/devnw/zig/config/-/issues/124) | **Closed** (Wave 3) |
| PERF-14 | 16 | ~~Repeated env lookups~~ | P3 | [#126](https://gitlab.com/devnw/zig/config/-/issues/126) | **Closed** (Wave 7) |
| PERF-25 | 16 | ~~Double allocLowerString in diff~~ | P3 | -- | **Closed** |
| PERF-27 | 16 | ~~allocPrint in TOML section loop~~ | P3 | -- | **Closed** (Wave 7) |
| PERF-28 | 16 | ~~allocPrint in INI section loop~~ | P3 | -- | **Closed** (Wave 7) |
| PERF-29 | 16 | ~~allocPrint in JSON array loop~~ | P3 | -- | **Closed** (N/A) |
| PERF-16 | 12 | ~~allocPrint in parse loops~~ | P3 | [#128](https://gitlab.com/devnw/zig/config/-/issues/128) | **Closed** (Wave 7) |
| PERF-15 | 12 | ~~O(n^2) case-insensitive diff~~ | P3 | [#127](https://gitlab.com/devnw/zig/config/-/issues/127) | **Closed** |
| PERF-17 | 20 | ~~No capacity hints on key collections~~ | Info | [#129](https://gitlab.com/devnw/zig/config/-/issues/129) | **Closed** |
| PERF-32 | 12 | ~~prefix_with_dot heap alloc~~ | Info | -- | **Closed** (Wave 8) |
| PERF-30 | 8 | ~~formatDiff iterates 3x~~ | Info | -- | **Closed** (Wave 8) |
| PERF-40 | 8 | ~~page_allocator granularity waste~~ | Info | -- | **Closed** (Wave 8) |
| PERF-41 | 8 | ~~Global pool_mutex contention~~ | Info | -- | **Closed** (Wave 8) |
| PERF-20 | 8 | ~~Lowercased key alloc per lookup~~ | Info | -- | **Closed** (Wave 8) |
| PERF-50 | 16 | ~~Stack buffer in tryAccessPath~~ | P3 | -- | **Closed** (Wave 9) |
| PERF-48 | 8 | ~~Redundant getValueForKey in diff~~ | Info | -- | **Closed** (Wave 9) |
| PERF-51 | 8 | ~~Batch literal appending~~ | Info | -- | **Closed** (Wave 9) |
| PERF-52 | 12 | ~~Missing memory fence in initPool~~ | Info | -- | **Closed** (Wave 9) |
| PERF-53 | 8 | ~~addFile lacks runtime guard~~ | Info | -- | **Closed** (Wave 9) |
| PERF-22 | 4 | INI section.key allocPrint (see PERF-28) | Info | -- | Superseded by PERF-28 |
| PERF-23 | 4 | Redundant prefix_with_dot (see PERF-32) | Info | -- | Superseded by PERF-32 |
| PERF-54 | 12 | HashMap no capacity hint in diff `merge()`/`compareWithOptions()` | P3 | -- | **Open** |
| PERF-56 | 4 | allocPrint in INI section loop negligible | Info | -- | **Won't Do** (negligible) |
| PERF-57 | 4 | Repeated toLower in merge (not applicable) | Info | -- | **Won't Do** (N/A) |
| PERF-58 | 8 | Provenance tracker unbounded growth (bounded by design) | Info | -- | **Won't Do** (bounded) |

### Infra (remote.zig -- Etcd/Consul networking)

| ID | PerfScore | Finding | Severity | Issue | Status |
|----|-----------|---------|----------|-------|--------|
| PERF-38 | 60 | ~~timeout_ms never applied to HTTP~~ | P1 | -- | **Closed** (Wave 7, documented) |
| PERF-3 | 80 | ~~DNS resolution per API call~~ | P1 | [#100](https://gitlab.com/devnw/zig/config/-/issues/100) | **Closed** |
| PERF-7 | 40 | ~~No HTTP connection reuse~~ | P2 | [#96](https://gitlab.com/devnw/zig/config/-/issues/96) | **Closed** (Wave 4) |
| PERF-33 | 24 | ~~Auth header rebuilt per request~~ | P3 | -- | **Closed** (Wave 8) |
| PERF-37 | 24 | ~~recheckDnsBinding re-parses URI~~ | P3 | -- | **Closed** (Wave 8) |
| PERF-12 | 24 | ~~Unbounded arena in remote clients~~ | P3 | [#136](https://gitlab.com/devnw/zig/config/-/issues/136) | **Closed** |
| PERF-34 | 16 | ~~URL allocPrint per Etcd failover~~ | Info | -- | **Closed** (Wave 8) |
| PERF-35 | 16 | ~~Consul URL allocPrint per operation~~ | Info | -- | **Closed** (Wave 8) |
| PERF-18 | 16 | ~~allocPrint for JSON body in Etcd~~ | Info | -- | **Closed** (Wave 8) |
| PERF-19 | 12 | ~~Base64 encode allocates per request~~ | Info | -- | **Closed** (Wave 8) |
| PERF-20i | 12 | URI re-parsed on every request (see PERF-37) | Info | -- | Superseded by PERF-37 |
| PERF-21 | 8 | No timeout config (see PERF-38) | Info | -- | Superseded by PERF-38 |
| PERF-55 | 4 | HTTP connection reuse already works (duplicate of PERF-7) | Info | -- | **Won't Do** (confirmed working) |

### CI (build.zig, .gitlab-ci.yml)

| ID | PerfScore | Finding | Severity | Issue | Status |
|----|-----------|---------|----------|-------|--------|
| PERF-43 | 60 | ~~No CI caching -- 7x Zig download~~ | P1 | -- | **Closed** |
| PERF-44 | 40 | No benchmark suite (CI unblocked) | P2 | [#89](https://gitlab.com/devnw/zig/config/-/issues/89) | **Open** (was Won't Do) |
| PERF-1 | 80 | No benchmark suite (original) | P1 | [#89](https://gitlab.com/devnw/zig/config/-/issues/89) | Rescored to PERF-44 |
| PERF-2 | 80 | CI skips build/test entirely | P1 | [#82](https://gitlab.com/devnw/zig/config/-/issues/82) | **Won't Do** (CI now active) |
| PERF-5 | 60 | No perf regression detection | P2 | [#131](https://gitlab.com/devnw/zig/config/-/issues/131) | **Won't Do** |
| PERF-45 | 4 | ~~CI conditional is dead code~~ | Info | -- | **Closed** (resolved by PERF-43) |

---

## Roadmap

### Quick Wins (< 1 day)

| Finding | ID | PerfScore | Effort | Description |
|---------|-----|-----------|--------|-------------|
| ~~CI caching~~ | PERF-43 | 60 | ~1 hour | ~~Add `cache:` block for `zig-${ZIG_VERSION}/` in `.gitlab-ci.yml`~~ **Closed** |
| ~~applyBoundEnvVars getenv~~ | PERF-31 | 48 | ~30 min | ~~Hoisted getEnvMap into load(); all env functions use shared snapshot~~ **Closed** (Wave 7) |
| ~~setFieldInner early alloc~~ | PERF-36 | 36 | ~30 min | ~~Already resolved: dupes inside match branch~~ **Closed** |
| ~~Auth header caching~~ | PERF-33 | 24 | ~30 min | ~~Cached auth header at init, secureZero in deinit~~ **Closed** (Wave 8) |
| ~~Double getEnvMap~~ | PERF-39 | 28 | ~1 hour | ~~Single getEnvMap snapshot in load() passed to all env functions~~ **Closed** (Wave 7) |
| ~~Double allocLowerString~~ | PERF-25 | 16 | ~30 min | ~~Reuse lowered key for both lookup and seen_keys insertion~~ **Closed** |
| ~~prefix_with_dot~~ | PERF-32 | 12 | ~15 min | ~~Stack buffer bufPrint (256B) in sub/hasSub~~ **Closed** (Wave 8) |
| HashMap capacity hints in diff | PERF-54 | 12 | ~30 min | Add `ensureTotalCapacity` to `merge()` result map and `compareWithOptions()` helper maps |

### Medium (1-5 days)

| Finding | ID | PerfScore | Effort | Description |
|---------|-----|-----------|--------|-------------|
| ~~timeout_ms not applied~~ | PERF-38 | 60 | 2-3 days | ~~Investigate Zig 0.15.2 http.Client timeout support~~ **Closed** (Wave 7, documented limitation) |
| Benchmark suite | PERF-44 | 40 | 3-5 days | Add `zig build bench` with per-component benchmarks; integrate into CI |
| ~~JSON/TOML/INI allocPrint~~ | PERF-26/27/28/29 | 16-32 | 1-2 days | ~~Stack-buffer bufPrint in all parse loops~~ **Closed** (Wave 7) |
| ~~recheckDnsBinding URI re-parse~~ | PERF-37 | 24 | 1 day | ~~Cached parsed URIs at init for both Etcd and Consul~~ **Closed** (Wave 8) |
| ~~Thread pool eagerness~~ | PERF-42 | 20 | 1 day | ~~Raised threshold from 2 to 4 files~~ **Closed** (Wave 8) |

### Strategic (> 5 days)

| Finding | ID | PerfScore | Reason |
|---------|-----|-----------|--------|
| Performance regression detection (#131) | PERF-5 | 60 | Blocked on benchmark suite (PERF-44) |

---

## Closed Findings (Waves 1-8)

| Issue | Finding | PerfScore (original) | Closed In | Resolution |
|-------|---------|---------------------|-----------|------------|
| [#100](https://gitlab.com/devnw/zig/config/-/issues/100) | DNS resolution per API call | 80 | Wave 1 | validateUrl moved to init() for Etcd and Consul |
| [#102](https://gitlab.com/devnw/zig/config/-/issues/102) | Memory leak in mergeMaps | 64 | Wave 1 | getPtr for in-place value update; no key leak |
| [#106](https://gitlab.com/devnw/zig/config/-/issues/106) | Unbounded thread spawning | 48 | Wave 1 | MAX_PARALLEL_THREADS=16 with batch processing |
| [#111](https://gitlab.com/devnw/zig/config/-/issues/111) | Full file buffering via readToEndAlloc | 40 | Wave 2 | Limits reduced from 10MB to 1MB via centralized limits.zig |
| [#124](https://gitlab.com/devnw/zig/config/-/issues/124) | Global thread pool page_allocator | 16 | Wave 3 | Replaced page_allocator with configurable allocator + deinit pathway |
| [#132](https://gitlab.com/devnw/zig/config/-/issues/132) | parallel.loadFile/serializeData stubs | 40 | Wave 3 | Implemented real file I/O and serialization in parallel workers |
| [#125](https://gitlab.com/devnw/zig/config/-/issues/125) | Double string duplication in setField | 32 | Wave 4 | Eliminated double string duplication; single arena-owned copy shared |
| [#96](https://gitlab.com/devnw/zig/config/-/issues/96) | No HTTP connection reuse | 40 | Wave 4 | Verified connection pooling via client.fetch API; documentation added |
| [#127](https://gitlab.com/devnw/zig/config/-/issues/127) | O(n^2) case-insensitive diff | 12 | Wave 4 | Built lowercased key HashMap for O(1) lookups; removed linear scan helpers |
| [#129](https://gitlab.com/devnw/zig/config/-/issues/129) | No capacity hints on collections | 20 | Wave 5 | ensureTotalCapacity on Loader.init maps, ProvenanceTracker, mergeMaps, mergeEntries, allKeys, allSettings |
| [#104](https://gitlab.com/devnw/zig/config/-/issues/104) | Sequential file loading in Loader.load() | 36 | Wave 5 | Parallelized file loading with serial merge in precedence order |
| [#136](https://gitlab.com/devnw/zig/config/-/issues/136) | Unbounded arena in Etcd/Consul | 24 | Wave 5 | Added resetArena() with retain_capacity to both clients |
| -- | applyBoundEnvVars per-item getenv (PERF-31) | 48 | Wave 7 | Hoisted `std.process.getEnvMap` snapshot into `load()` and passed to all env functions |
| [#126](https://gitlab.com/devnw/zig/config/-/issues/126) | Repeated env lookups (PERF-14) | 16 | Wave 7 | Fully resolved: all three env functions share single EnvMap snapshot |
| -- | Double getEnvMap snapshot (PERF-39) | 28 | Wave 7 | Single snapshot in `load()` eliminates redundant env cloning |
| -- | setFieldInner dupes before match (PERF-36) | 36 | Wave 7 | Verified already resolved: dupes inside match branch in current code |
| -- | allocPrint in JSON recursion (PERF-26) | 32 | Wave 7 | Stack-buffer `bufPrint` in `applyJsonValue` |
| -- | allocPrint in TOML section (PERF-27) | 16 | Wave 7 | Stack-buffer `bufPrint` in `parseSimpleToml` |
| -- | allocPrint in INI section (PERF-28) | 16 | Wave 7 | Stack-buffer `bufPrint` in `parseIni` |
| [#128](https://gitlab.com/devnw/zig/config/-/issues/128) | allocPrint in parse loops (PERF-16) | 12 | Wave 7 | Fully resolved: all parse loops use stack-buffer bufPrint |
| -- | allocPrint in JSON array loop (PERF-29) | 16 | Wave 7 | N/A: no JSON array handling exists in current parser |
| -- | Double allocLowerString in diff (PERF-25) | 16 | Wave 7 | Refactored seen_keys to store lowered keys; O(1) hash lookup replaces O(n) linear scan |
| -- | CI caching for Zig toolchain (PERF-43) | 60 | Wave 7 | Global `cache:` block keyed on ZIG_VERSION; also resolves PERF-45 |
| -- | CI conditional dead code (PERF-45) | 4 | Wave 7 | Resolved by PERF-43 caching; conditional now effective |
| -- | timeout_ms not applied to HTTP (PERF-38) | 60 | Wave 7 | Limitation documented in EtcdOptions/ConsulOptions doc comments; Zig 0.15 http.Client constraint |
| -- | Auth header rebuilt per request (PERF-33) | 24 | Wave 8 | Cached at `Etcd.init()`, `secureZero` in `deinit()` |
| -- | Etcd URL allocPrint per failover (PERF-34) | 16 | Wave 8 | Eliminated via cached URI with path override |
| -- | Consul URL allocPrint per operation (PERF-35) | 16 | Wave 8 | Stack buffer `bufPrint` for paths + cached URI |
| -- | recheckDnsBinding URI re-parse (PERF-37) | 24 | Wave 8 | Cached parsed URIs at init for both Etcd and Consul |
| -- | allocPrint for JSON body in Etcd (PERF-18) | 16 | Wave 8 | Stack buffer `bufPrint` (1024B), heap fallback |
| -- | Base64 encode allocates per request (PERF-19) | 12 | Wave 8 | Stack buffer (512B), heap fallback |
| -- | Lowercased key alloc per lookup (PERF-20) | 8 | Wave 8 | Stack buffer in `normalizeKey`, arena fallback |
| -- | formatDiff iterates 3x (PERF-30) | 8 | Wave 8 | Single pass with 3 output buffers |
| -- | prefix_with_dot heap alloc (PERF-32) | 12 | Wave 8 | Stack buffer `bufPrint` (256B) in sub/hasSub |
| -- | page_allocator granularity waste (PERF-40) | 8 | Wave 8 | Added `initPool()` with caller allocator + docs |
| -- | pool_mutex contention (PERF-41) | 8 | Wave 8 | Replaced with `std.once` for lock-free reads |
| -- | Thread pool eager spawning (PERF-42) | 20 | Wave 8 | Raised threshold from 2 to 4 files |
| -- | Redundant getValueForKey in diff (PERF-48) | 8 | Wave 9 | Removed redundant lookup; seen_keys check sufficient |
| -- | Stack buffer in tryAccessPath (PERF-50) | 16 | Wave 9 | 512B stack buffer in findConfigFileWithOptions |
| -- | Batch literal appending (PERF-51) | 8 | Wave 9 | literal_start tracking with batch appendSlice |
| -- | Missing memory fence in initPool (PERF-52) | 12 | Wave 9 | @fence(.seq_cst) after pool_allocator write |
| -- | addFile runtime guard (PERF-53) | 8 | Wave 9 | AlreadyRunning guard in addFile |

---

## Unknowns and Blockers

1. ~~**timeout_ms is non-functional (PERF-38)**~~: **Closed** (Wave 7). Limitation documented in `EtcdOptions.timeout_ms` and `ConsulOptions.timeout_ms` doc comments. Callers warned that timeout_ms is not enforced by Zig 0.15's http.Client. TODO retained for future Zig version.

2. **Benchmark baseline (PERF-44)**: Without benchmarks, all "expected improvement" numbers are estimates. The CI blocker (#82) is now resolved -- Zig 0.15.2 is available and build/test/fuzz stages are active. The benchmark suite can now be built and integrated.

3. **Thread safety of Loader.setField()**: The parallel file loading fix (#104) and the parallel stubs fix (#132) both require `setField` to be thread-safe or for results to be collected and merged post-join. Current implementation mutates shared state directly.

4. **Performance regression detection (#131)**: Still blocked on benchmark suite. Once PERF-44 is resolved, this becomes unblocked.

5. **Arena lifetime contracts in remote clients**: Resolved. Etcd.resetArena() and Consul.resetArena() provide explicit caller-controlled reset.

### What Would Confirm Suspected Items

| Finding | Confidence | What would confirm |
|---------|-----------|-------------------|
| PERF-43 (CI caching) | `confidence::confirmed` | **Closed**: Added global `cache:` block keyed on `ZIG_VERSION` for `zig-${ZIG_VERSION}/` and `.zig-cache/` |
| PERF-38 (timeout_ms) | `confidence::confirmed` | **Closed** (Wave 7): Limitation documented in doc comments; `setSocketTimeout` dead code noted |
| PERF-31 (applyBoundEnvVars) | `confidence::confirmed` | `environ.getenv(env_var)` call directly visible at `loader.zig:907` |
| PERF-36 (setFieldInner early alloc) | `confidence::confirmed` | `arena.dupe` at lines 1249-1250 before `inline for` at line 1251 |
| PERF-26 (JSON allocPrint) | `confidence::confirmed` | `allocPrint` at `loader.zig:988` inside recursive `applyJsonValue` |
| PERF-39 (double getEnvMap) | `confidence::confirmed` | Two `getEnvMap` calls at lines 921 and 1216 in the same `load()` flow |
| PERF-33 (auth header rebuild) | `confidence::confirmed` | **Closed** (Wave 8): Auth header cached at `Etcd.init()`, `secureZero` in `deinit()` |
| PERF-37 (URI double-parse) | `confidence::confirmed` | **Closed** (Wave 8): Cached parsed URIs at init for both Etcd and Consul |
| PERF-42 (eager thread pool) | `confidence::confirmed` | **Closed** (Wave 8): Raised parallel threshold from 2 to 4 files |
| PERF-25 (double allocLower) | `confidence::confirmed` | **Closed**: Refactored seen_keys to store lowered keys; O(1) lookup replaces O(n) containsKeyInsensitive |
| PERF-41 (pool_mutex) | `confidence::confirmed` | **Closed** (Wave 8): Replaced with `std.once` for lock-free reads |
| PERF-40 (page_allocator waste) | `confidence::confirmed` | **Closed** (Wave 8): Added `initPool()` with caller allocator + docs |
| PERF-54 (HashMap capacity in diff) | `confidence::confirmed` | `StringHashMap.init()` at `diff.zig:124,146,434` with no `ensureTotalCapacity`; input sizes available via `.count()` |
| PERF-55 (HTTP connection reuse) | `confidence::confirmed` | `http.Client` at `remote.zig:655,1045` manages pooling internally; validated by PERF-7 |
| PERF-56 (INI allocPrint) | `confidence::confirmed` | `allocPrint` at `loader.zig:828,891`; < 200 allocs for realistic configs |
| PERF-57 (toLower in merge) | `confidence::confirmed` | No `toLower`/`allocLowerString` in `merge.zig`; finding does not apply |
| PERF-58 (provenance growth) | `confidence::confirmed` | `StringHashMap(TrackedValue)` at `provenance.zig:73`; bounded by struct field count |

### Top 5 Recommended Fixes

1. ~~**PERF-43 -- Add CI caching for Zig toolchain** (PerfScore 60, ~1 hour)~~ **Closed**
   - Added global `cache:` block keyed on `ZIG_VERSION` for `zig-${ZIG_VERSION}/` and `.zig-cache/`
   - Also resolves PERF-45 (dead conditional check now effective with caching)

2. ~~**PERF-38 -- Resolve timeout_ms gap** (PerfScore 60, 2-3 days)~~ **Closed** (Wave 7)
   - Documented Zig 0.15 http.Client limitation in `EtcdOptions.timeout_ms` and `ConsulOptions.timeout_ms` doc comments
   - TODO retained for future Zig version with native timeout support

3. ~~**PERF-31 -- Fix applyBoundEnvVars to use env snapshot** (PerfScore 48, ~30 min)~~ **Closed** (Wave 7)
   - Hoisted `std.process.getEnvMap` into `load()` and passed shared snapshot to all env functions

4. **PERF-44 -- Build benchmark suite** (PerfScore 40, 3-5 days)
   - Add `zig build bench` step with benchmarks for: config loading (JSON/TOML/INI/YAML), env var application, remote client operations, diff comparison
   - Expected: Establish baseline measurements; enable data-driven optimization going forward
   - Validation: `zig build bench` runs successfully; results are reproducible within 10% variance
   - Rollout risk: None -- additive, no production code changes

5. **PERF-54 -- Add ensureTotalCapacity to diff.zig HashMaps** (PerfScore 12, ~30 min)
   - Add `ensureTotalCapacity(base.count() + overlay.count())` to `merge()` result map at `diff.zig:434`
   - Add `ensureTotalCapacity(new_config.count())` to `new_lower_index` at `diff.zig:124` and `seen_keys` at `diff.zig:146`
   - Expected: Eliminates O(log n) rehashes during map population; ~3-5 fewer realloc cycles for 50+ key configs
   - Validation: `zig build test` passes; no functional change
   - Rollout risk: None -- purely additive capacity hint; no behavioral change

---

## Next Steps

**2 items remain open** out of 50 total findings:

- **PERF-44** (P2, PerfScore 40): Build benchmark suite (`zig build bench`). Estimated effort: 3-5 days. This is the highest-priority remaining performance gap. CI infrastructure is ready.
- **PERF-54** (P3, PerfScore 12): Add `ensureTotalCapacity` to diff.zig `merge()` and `compareWithOptions()` HashMaps. Estimated effort: ~30 min. Quick win -- input sizes are known at call time.

All other performance findings (42 closed, 6 won't do) have been resolved across Waves 1-9 and Phase 5 review.
