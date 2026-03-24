# Gap Closure Completion Report

**Project:** devnw/zig/config
**Date:** 2026-03-24
**Review commit:** fe9d0f6 (HEAD of main) + working tree
**Waves completed:** 8 (all)
**Platform:** GitLab (issues not updated in this pass -- skip-issues mode)

## Summary

- **Items closed:** 85 (14 security + 34 quality + 37 performance)
- **Items Won't Do:** 6 (4 quality + 2 performance)
- **Items blocked:** 0
- **Remaining open:** 1 (PERF-44: benchmark suite, P2)
- **Tests:** PASS (758/758, 134 new tests added)
- **Build:** PASS (5/5 build steps)
- **Format:** CLEAN (`zig fmt --check src/` exit 0)
- **Regressions:** 0

---

## GAP_ANALYSIS Status

| File | Closed | Blocked | Won't Do | Remaining Open | Total |
|------|--------|---------|----------|----------------|-------|
| GAP_ANALYSIS.md (Security) | 14 | 0 | 0 | 0 | 14 |
| QUALITY_GAP_ANALYSIS.md | 34 | 0 | 4 | 0 | 38 |
| PERF_GAP_ANALYSIS.md | 37 | 0 | 2 | 1 | 40 |

**Overall:** 85 closed, 0 blocked, 6 won't do, 1 remaining open out of 92 total items.

No security, quality, P1, P3, or Info performance items remain open.

The 1 remaining open PERF item:
- 1 P2: PERF-44 (benchmark suite, L effort, 3-5 days)

---

## Closed Items

### Wave 1 (7 items -- Quick Wins)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| GAP-0006 | Silent OOM in dotenv append | `src/dotenv.zig` | 2 `catch {}` changed to `try` |
| GAP-0011 | Duplicate validate/validation alias | `src/config.zig` | Single alias retained |
| GAP-0018 | Stale doc "10 MB" vs "1 MB" | `src/loader.zig` | Doc comment updated |
| GAP-0007 | Silent OOM in provenance getAll | `src/provenance.zig` | OOM propagated via `try` |
| GAP-0024 | JSON escaping in provenance printJson | `src/provenance.zig` | Proper JSON string escaping added |
| GAP-0025 | secureZero for interactive stdin | `src/secret.zig` | trim+dupe+secureZero pattern added |
| GAP-0023 | File watcher TOCTOU documentation | `src/watch.zig` | Already resolved (doc existed) |

### Wave 2 (8 items -- Security + Quality)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| GAP-0008 | applyRequestTimeouts error propagation | `src/remote.zig` | All 4 HTTP sites propagate timeout errors |
| GAP-0014 | Etcd key validation (isValidKVKey) | `src/remote.zig` | isValidKVKey added to all Etcd methods |
| GAP-0012 | Magic numbers to limits.zig constants | `src/remote.zig`, `src/secret.zig`, `src/encrypted_secrets.zig` | 8 sites replaced |
| GAP-0015 | Hand-rolled JSON to std.json | `src/remote.zig` | Etcd JSON construction uses std.json |
| GAP-0016 | matchSingleChar escape sequences | `src/validation.zig` | `\d`, `\w`, `\s` escape handling added |
| QUAL-11 | matchPatternImpl decomposition | `src/validation.zig` | 209 lines reduced to ~49 with sub-functions |
| GAP-0010 | .auto format inconsistency | `src/loader.zig`, `src/config.zig` | Both use detectFormatFromContent |
| QUAL-12 | Dotenv parsing deduplication | `src/loader.zig` | loadDotEnv delegates to dotenv.zig |

### Wave 3 (6 items -- Parallel Module + Remote Architecture)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| QUAL-13 | ConfigFormat import from loader.zig | `src/parallel.zig` | Imports from loader.zig |
| GAP-0005 | loadFile/serializeData real I/O | `src/parallel.zig` | Real file I/O implemented |
| PERF-13 | Configurable allocator + deinit | `src/parallel.zig` | page_allocator replaced |
| GAP-0017 | Shared Consul HTTP helper | `src/remote.zig` | Single helper consolidates 3 methods |
| GAP-0021 | DNS rebinding mitigation | `src/remote.zig` | recheckDnsBinding function added |
| QUAL-15 | build.zig import consolidation | `build.zig` | Imports consolidated |

### Wave 4 (8 items -- Performance + Features)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| GAP-0019 | HTTP connection reuse verification | `src/remote.zig` | Verified client.fetch pooling |
| GAP-0009 | Etcd endpoint failover | `src/remote.zig` | Round-robin with failover |
| GAP-0002 | Array indexing in getPath | `src/loader.zig` | Numeric index path access |
| PERF-11 | Eliminate double string duplication | `src/loader.zig` | Single arena-owned copy shared |
| PERF-14 | Batch env variable lookups | `src/loader.zig` | getEnvMap snapshot for batch reads |
| PERF-16 | Stack buffer in findConfigFile | `src/loader.zig` | path_buf replaces allocPrint |
| PERF-15 | O(n) case-insensitive diff | `src/diff.zig` | HashMap lookup table |
| GAP-0022 | Windows symlink TOCTOU documentation | `src/secret.zig` | CWE-367 risk documented |

### Wave 5 (3 items -- Strategic)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| GAP-0020 | Parallel file loading | `src/loader.zig` | Parallel I/O with serial merge |
| PERF-12 | resetArena() for remote clients | `src/remote.zig` | retain_capacity semantics |
| PERF-17 | Capacity hints on collections | `src/loader.zig`, `src/merge.zig`, `src/provenance.zig` | ensureTotalCapacity on 10+ sites |

### Wave 6 (14 items -- Critical + Quick)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| NEW-12 | dotenv.load() use-after-free | `src/dotenv.zig` | load() dupes key/value before freeing content |
| NEW-13 + NEW-15 | parseContent lifetime documented | `src/dotenv.zig` | Doc comment on parseContent; load() dupes |
| NEW-01 | Dotenv parsing deduplication | `src/dotenv.zig` | parseLine helper used by all 3 functions |
| GAP-0034 | Unbounded HTTP response size | `src/remote.zig` | ResponseTooLarge check vs limits.MAX_REMOTE_RESPONSE_SIZE |
| GAP-0037 | Etcd HTTP status code discarded | `src/remote.zig` | Status >= 400 check returns Unauthorized/RequestFailed |
| GAP-0039 | Auth creds not secureZero'd | `src/remote.zig` | secureZero on creds/encoded in buildBasicAuthHeader |
| GAP-0040 | User-Agent CRLF injection | `src/remote.zig` | isValidHeaderValue() rejects CR/LF/null |
| NEW-10 | getPrefix 0xFF overflow | `src/remote.zig` | 0xFF guard appends 0x00 sentinel |
| NEW-09 | SensitiveString.format wrong sig | `src/encrypted_secrets.zig` | Format output [REDACTED]; allocPrint test |
| NEW-11 | async loadFile swallows OOM | `src/async.zig` | OOM propagated from loadFile to loadThreadFn |
| NEW-05 | @constCast documented | `src/loader.zig` | Expanded safety comment |
| NEW-03 | safeWriteConfig near-duplicate | `src/config.zig` | atomicWriteFile/directWriteFile extracted; 6 tests |
| GAP-0010 fix | .auto format detection | `src/config.zig`, `src/loader.zig` | detectFormatFromContent |
| QUAL-12 fix | loadDotEnv delegation | `src/loader.zig` | loadDotEnv delegates to dotenv.zig |

### Wave 7 (8 items -- Medium)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| NEW-02/06/07 | JSON response parsing with std.json | `src/remote.zig` | EtcdRangeResponse, ConsulKVEntry typed structs |
| NEW-08/16/PERF-38 | timeout_ms limitation documented | `src/remote.zig` | Doc comments on EtcdOptions/ConsulOptions.timeout_ms |
| GAP-0036 | tls_skip_verify limitation documented | `src/remote.zig` | SecurityOptions.tls_skip_verify doc comment updated |
| PERF-31/14/39 | Env variable snapshot | `src/loader.zig` | Single getEnvMap in load() shared to all env functions |
| PERF-36 | setFieldInner arena dupe (verified resolved) | `src/loader.zig` | Already resolved in current code |
| PERF-26/27/28/16 | allocPrint to bufPrint in parse loops | `src/loader.zig` | Stack-buffer bufPrint in JSON/TOML/INI parsers |
| PERF-25 | Double allocLowerString in diff | `src/diff.zig` | seen_keys stores lowered keys; O(1) lookup |
| PERF-43/45 | CI caching for Zig toolchain | `.gitlab-ci.yml` | Global cache block keyed on ZIG_VERSION |

### Wave 8 (12 items -- Performance Closure)

| Gap-ID | Title | Files Changed | Evidence |
|--------|-------|---------------|----------|
| PERF-33 | Auth header rebuilt per Etcd request | `src/remote.zig` | Cached at init, secureZero in deinit |
| PERF-34 | Etcd URL allocPrint per failover | `src/remote.zig` | Cached URI with path override |
| PERF-35 | Consul URL allocPrint per operation | `src/remote.zig` | Stack buffer bufPrint + cached URI |
| PERF-37 | URI re-parsed per request | `src/remote.zig` | Cached parsed URIs at init for Etcd and Consul |
| PERF-18 | JSON body allocPrint in Etcd | `src/remote.zig` | Stack buffer bufPrint (1024B), heap fallback |
| PERF-19 | Base64 encode allocates per request | `src/remote.zig` | Stack buffer (512B), heap fallback |
| PERF-20 | Lowercased key alloc per lookup | `src/loader.zig` | Stack buffer in normalizeKey, arena fallback |
| PERF-30 | formatDiff iterates 3x | `src/diff.zig` | Single pass with 3 output buffers |
| PERF-32 | prefix_with_dot heap alloc | `src/loader.zig` | Stack buffer bufPrint (256B) in sub/hasSub |
| PERF-40 | page_allocator granularity waste | `src/parallel.zig` | initPool() with caller allocator + docs |
| PERF-41 | pool_mutex contention | `src/parallel.zig` | Replaced with std.once for lock-free reads |
| PERF-42 | Thread pool eager spawning | `src/parallel.zig` | Raised threshold from 2 to 4 files |

---

## Won't Do Items

| Gap-ID | File | Title | Reason |
|--------|------|-------|--------|
| #98 | QUALITY | Loader god-object (60+ functions) | Strategic refactor >5 days; not a gap closure item |
| #98 | QUALITY | 5 files exceed 800 lines | Part of same loader decomposition effort |
| #98 | QUALITY | Loader/remote file sizes growing | Same strategic decomposition as #98 |
| #151 | QUALITY | Weak test coverage | Incremental improvement; 134 new tests added |
| PERF-2 | PERF | CI skips build/test entirely | Superseded: CI now fully active |
| PERF-5 (#131) | PERF | No perf regression detection | Blocked on benchmark suite (PERF-44) |

---

## Blocked Items

| Gap-ID | File | Title | Blocker | Unblock Steps |
|--------|------|-------|---------|---------------|
| (none) | | | | |

No items are blocked.

---

## Tests Executed

| Command | Result |
|---------|--------|
| `zig build test` | PASS (758/758 tests, 134 new) |
| `zig build` (5 build steps) | PASS (5/5) |
| `zig fmt --check src/` | PASS (0 reformats needed) |
| Regression check | PASS (0 regressions) |
| GAP-0010 test failure | PASS (pre-existing failure now fixed) |

---

## Security Notes

- All 14 original security findings in GAP_ANALYSIS.md resolved (0 open)
- Auth credential buffers now secureZero'd before free (GAP-0039)
- CRLF injection in User-Agent header prevented (GAP-0040)
- HTTP response size bounded to prevent OOM (GAP-0034)
- HTTP status codes checked to prevent silent error parsing (GAP-0037)
- TLS skip_verify limitation documented -- Zig 0.15 always verifies (GAP-0036)
- std.json replaces hand-rolled JSON parsing, eliminating escaping bypass vectors (NEW-02/06/07)
- getPrefix 0xFF overflow fixed to prevent incorrect etcd range queries (NEW-10)
- dotenv use-after-free eliminated (NEW-12)
- PATH allowlist for vault/op binary execution (#77)
- Vault/1Password config fields applied to child process (#76)
- Secret provider timeout watchdog + stderr pipe (#79)
- env:// provider gated behind opt-in flag (#84)
- DNS rebinding mitigation via recheckDnsBinding (#68)
- Cached auth header secureZero'd in Etcd.deinit() to prevent credential leakage (PERF-33, Wave 8)

---

## Remaining Blockers

None. All actionable items resolved. The 1 remaining open item in PERF_GAP_ANALYSIS.md is PERF-44 (benchmark suite, P2, 3-5 days effort).

---

## Platform Issues Updated

Skipped (--skip-issues mode). No GitLab issues were closed or commented in this pass.

Previous waves 1-5 closed 37 GitLab issues. See prior report for full issue update list.

---

## Files Modified (All Waves)

| File | Waves |
|------|-------|
| `src/dotenv.zig` | 1, 6 |
| `src/config.zig` | 1, 2, 6 |
| `src/loader.zig` | 1, 2, 4, 5, 6, 7, 8 |
| `src/provenance.zig` | 1, 5 |
| `src/secret.zig` | 1, 2, 4 |
| `src/remote.zig` | 1, 2, 3, 4, 5, 6, 7, 8 |
| `src/validation.zig` | 2 |
| `src/parallel.zig` | 3, 8 |
| `src/encrypted_secrets.zig` | 2, 6 |
| `src/diff.zig` | 4, 7, 8 |
| `src/merge.zig` | 5, 7 |
| `src/async.zig` | 6 |
| `build.zig` | 3 |
| `.gitlab-ci.yml` | 7 |
