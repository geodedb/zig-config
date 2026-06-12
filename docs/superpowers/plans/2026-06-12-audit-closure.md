# Audit Closure Implementation Plan (zigconfig)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close every actionable finding from the 2026-06-12 appsec review + full codebase audit so that re-running `/security:appsec-review` and `/codepros:audit` surfaces no new issues.

**Architecture:** Root cause is an incomplete Zig 0.15→0.16 migration hidden by partial test rooting (tests root only `config.zig`+`integration_test.zig`; no `refAllDecls` guard). Fix order: (0) install a recursive refAllDecls guard + wire examples/bench so latent compile errors are visible and gated; (1) complete the 0.16 migration until the guard is green; (2) add behavioral tests that exercise the formerly-cold code; (3) fix logic/security bugs TDD; (4) quality/dead-code; (5) perf; (6) docs/packaging; (7) re-audit loop.

**Tech Stack:** Zig 0.16.0; `zig build` / `zig build test` / `zig build check`; GitLab CI (`.gitlab-ci.yml`).

**Verification commands (run after every task):**

- `zig build check` — compiles all decls incl. refAll guard (must be exit 0 after Phase 1)
- `zig build test` — unit + integration (415+ tests)
- `zig fmt --check src/`

---

## Finding → Task crosswalk

- **0.16 migration (compiler-verified):** config.zig:971, diff.zig:48-53, expand.zig:60, flags.zig:152, remote.zig:1488, secret.zig:240, serialize.zig:98/204/298/383, xdg.zig:379, parallel.zig:90/218/323/445, bench.zig:80, examples/*.zig → Tasks 1–8
- **AS-01** SSRF host-resolution no-op → Task 12
- **AS-02 / S(config backup symlink)** → Task 13
- **AS-03 / Q-NEW-06** empty-argv panic → Task 10
- **AS-04 / Q-NEW-10** stderr pipe never drained → Task 14
- **Q-NEW-04** watchdog blocks full timeout → Task 14
- **S-NEW-01** async UAF (await/loadParallel) → Task 11
- **S-NEW-02 / Q-NEW-11** Watcher data race → Task 15
- **Q-NEW-03** watcher poll interval u32 overflow → Task 9
- **Q-NEW-09** parallel* stubs return null → Task 16
- **Q-NEW-05** temp_path leak ×3 → Task 17
- **Q-NEW-07** parseFile masks errors → Task 18
- **Q-NEW-08** dotenv.load swallows OOM/oversize → Task 18
- **Q-NEW-12** Consul.get leak on OOM → Task 17
- **Q-NEW-13** mergeMaps errdefer key leak → Task 17
- **Q-NEW-14** secret freed w/o secureZero on OOM → Task 17
- **Q-NEW-15** float buffer drop → Task 18
- **Q-NEW-20** startAsync stuck on spawn fail → Task 11
- **S-NEW-03** loadParallel non-threadsafe alloc → Task 16
- **S-NEW-04** unrestricted ${VAR} expansion → Task 19
- **S-NEW-05** diff/provenance secret leak → Task 19
- **Q-NEW-16** dead code → Task 20
- **Q-NEW-17** quote-strip dup ×4 → Task 20
- **Q-NEW-18** atomic-write dup → Task 20
- **Q-NEW-19** diff doc example → Task 21
- **P-NEW-01** normalizeKey arena growth (PERF-20 regression) → Task 22
- **P-NEW-02** INI section re-lookup → Task 22
- **P-NEW-03** properties scratch ArrayList → Task 22
- **GAP-NEW-01** config.validate alias → Task 21
- **GAP-NEW-02** Zig version mismatch (zon+docs) → Task 8/21
- **GAP-NEW-03** API.md getPaths drift → Task 21
- **GAP-NEW-04** VIPER_COMPARISON drift → Task 21

---

## Phase 0 — Guard against latent compile errors

### Task 0: Permanent recursive refAllDecls guard

**Files:** Modify `src/config.zig` (end of file).

- [ ] Replace the temporary probe with a finalized guard: a comptime recursive walker that skips external dep namespaces (`yaml`,`toml`,`json`) and refs every in-repo public decl, with `@setEvalBranchQuota(200000)`. This test FAILS to compile now (that is the point) and PASSES once Phase 1 lands.
- [ ] Verify it currently fails: `zig build check` → expect 0.16 compile errors listed in the crosswalk.

### Task 0b: Wire examples + bench into `check` and CI

**Files:** Modify `build.zig` (add an `addTest`/`addObject` over each example + bench to `check_step`, or add a `compile-all` step `check` depends on), `.gitlab-ci.yml` (ensure `zig build check` runs and now includes examples/bench/refAll).

- [ ] After Phase 1, `zig build check` must compile config + all examples + bench. (Examples currently fail on `GeneralPurposeAllocator`.)

---

## Phase 1 — Complete the Zig 0.16 migration (make the guard green)

> The "test" for Tasks 1–8 is `zig build check` going from N errors → fewer errors. Run it after each task. No behavioral change intended; keep diffs minimal.

### Task 1: serialize.zig writer migration (4 sites)

**Files:** Modify `src/serialize.zig` (lines ~98, 204, 298, 383 + helper writer params).

- [ ] Replace `var list = std.ArrayList(u8).init(allocator); ... const writer = list.writer(); ... list.toOwnedSlice()` with `var aw = std.Io.Writer.Allocating.init(allocator); errdefer aw.deinit(); const writer = &aw.writer; ... return try aw.toOwnedSlice();`. Update helper fns that take the writer to accept `*std.Io.Writer`.
- [ ] `zig build check` — serialize errors gone.

### Task 2: expand.zig + xdg.zig ArrayList migration

**Files:** `src/expand.zig:60`, `src/xdg.zig:379`.

- [ ] expand.zig:60 `std.ArrayList(u8).init(allocator)` → `std.Io.Writer.Allocating` or unmanaged `.empty` + `appendSlice(allocator,…)`/`append(allocator,…)` + `toOwnedSlice(allocator)`; fix the `errdefer result.deinit()` → `deinit(allocator)`.
- [ ] xdg.zig:379 `std.ArrayList([]const u8).init(allocator)` → `.empty`; `append(x)`→`append(allocator,x)`; `toOwnedSlice()`→`toOwnedSlice(allocator)`.
- [ ] `zig build check`.

### Task 3: diff.zig format() signature

**Files:** `src/diff.zig:48-53`.

- [ ] Replace `pub fn format(self, comptime fmt, options: std.fmt.FormatOptions, writer: anytype)` with `pub fn format(self: Change, w: *std.Io.Writer) std.Io.Writer.Error!void` and drop `_ = fmt; _ = options;`; change `writer.print` → `w.print`.
- [ ] `zig build check`.

### Task 4: flags.zig parseArgs

**Files:** `src/flags.zig:151-159`.

- [ ] Rewrite using `std.process.argsWithAllocator`: collect into an arena/owned slice of `[]const u8`, skip arg[0], call `self.parse`. Free properly.
- [ ] `zig build check`.

### Task 5: secret.zig isTty + remote.zig ArrayList literal

**Files:** `src/secret.zig:240` (and any further readFromStdin breakage), `src/remote.zig:1488`.

- [ ] secret.zig: `stdin.isTty()` → `stdin.isTty(io)` (io already in scope); fix any subsequent 0.16 File/Writer breakage in readFromStdin surfaced by check.
- [ ] remote.zig:1488 `var keys: std.ArrayListUnmanaged([]const u8) = .{};` → `= .empty;`.
- [ ] `zig build check`.

### Task 6: config.zig resetGlobalRegistry mutex

**Files:** `src/config.zig:969-977`.

- [ ] Mirror `getGlobalRegistry`: `const io = std.Io.Threaded.global_single_threaded.io(); global_registry_mutex.lockUncancelable(io); defer global_registry_mutex.unlock(io);`.
- [ ] `zig build check`.

### Task 7: parallel.zig std.once + SubmitBatchResult

**Files:** `src/parallel.zig:90, 218, 323, 445`.

- [ ] Replace `std.once(doInitPool)` with a 0.16-available one-shot: a `std.Io.Mutex`-guarded bool, or `std.Thread.Mutex` + `bool`, or atomic CAS. Keep the documented semantics (init on first `getPool()`).
- [ ] `submitBatch(...) catch {…}` returns a `SubmitBatchResult` that is now "ignored" — capture and check it (`_ = ...` is NOT acceptable since it carries partial-submit info; inspect and fall back as the existing catch does). At minimum `_ = getPool().submitBatch(...) catch …;` if the value is truly advisory; prefer handling partial submission.
- [ ] `zig build check` — parallel errors gone.

### Task 8: bench.zig + examples GeneralPurposeAllocator + zon min version

**Files:** `src/bench.zig:80`, `examples/{basic_parsing,typed_loader,flag_parsing,secret_handling,validation,xdg_paths,dotenv_loading}.zig`, `build.zig.zon:5`, parallel.zig doc comments referencing GPA.

- [ ] Replace `std.heap.GeneralPurposeAllocator(.{}){}` with `std.heap.DebugAllocator(.{}){}` (or `.init`) everywhere; update `.deinit()` usage if needed.
- [ ] `build.zig.zon` `minimum_zig_version = "0.16.0"`.
- [ ] `zig build check` (incl. examples/bench via Task 0b) → **exit 0**. `zig build test` green. `zig fmt --check src/`.
- [ ] **Commit:** `fix(zig016): complete 0.15→0.16 migration of cold public-API paths + refAllDecls guard`.

---

## Phase 2 — Behavioral tests for formerly-cold code (surface logic bugs)

### Task 9: watcher poll-interval overflow (Q-NEW-03) — TDD

**Files:** Test in `src/watch.zig` test block (ensure watch tests are rooted — add `_ = @import("watch.zig");`-style inclusion or a test in config.zig). Modify `src/watch.zig:222`.

- [ ] Failing test: a `nanosleep` duration computed from `poll_interval_ms = 10_000` must not overflow. Assert `@as(u64, interval) * std.time.ns_per_ms == 10_000_000_000`.
- [ ] Fix: `nanosleep(@as(u64, self.options.poll_interval_ms) * std.time.ns_per_ms);`.
- [ ] Tests pass. Commit.

### Task 10: empty-argv panic (AS-03/Q-NEW-06) — TDD

**Files:** `src/flags.zig:131-146`; test in flags tests.

- [ ] Failing test: `parser.parse(&.{""})` and `parser.parse(&.{"a","","--x"})` must not panic (empty treated as positional).
- [ ] Fix: add `arg.len == 0` branch (positional) and reorder to `else if (arg.len > 2 and arg[0] == '-')`.
- [ ] Tests pass. Commit.

---

## Phase 3 — Logic & security fixes (TDD; each: failing test → fix → green → commit)

### Task 11: async loader UAF + stuck-state (S-NEW-01, Q-NEW-20)

**Files:** `src/async.zig` (`loadThreadFn` ~217-249, `await` ~169-190, `loadParallel` ~421-442, `startAsync` ~161-165).

- [ ] Failing test (run under `std.testing.allocator` / debug alloc): load a string-bearing config via `await()`; after return, read a `[]const u8` field — must equal expected (no UAF). Pre-fix: dangling.
- [ ] Fix: move arena ownership into `AsyncResult` (don't `defer loader.deinit()` before returning), or deep-copy string fields into a caller-owned allocator. Document ownership + add `deinit` for the result.
- [ ] Failing test: simulate `Thread.spawn` failure path leaves state `.failed` not `.running` (or guarded). Fix `startAsync` with `errdefer state=.failed`.
- [ ] Tests pass. Commit.

### Task 12: SSRF host-resolution (AS-01)

**Files:** `src/remote.zig:170-177, 220-224, 280-290`; tests in `src/remote_test.zig`.

- [ ] Failing test: `validateUrl` with `block_private_ips=true` and a hostname that resolves to a private/loopback IP returns `PrivateAddressBlocked`. (Use an injectable resolver hook or a fail-closed allowlist contract so the test is deterministic without real DNS.)
- [ ] Fix: implement real resolution + per-address `isPrivateAddressForAddr` validation with IP pinning for the connection; OR fail-closed for non-literal hosts under `block_private_ips` unless host is on an explicit allowlist (`SecurityOptions.allowed_hosts`). Correct the misleading docstrings.
- [ ] Tests pass. Commit.

### Task 13: config backup symlink guard (AS-02)

**Files:** `src/config.zig:784-790` (`safeWriteConfigWithBackup`); test.

- [ ] Failing test: backup step over a symlinked source returns an error (mirror serialize.zig ADV-05 test).
- [ ] Fix: `if (secret.isSymlink(path)) return …; if (secret.isSymlink(backup_path)) return …;` before `copyFile` (or no-follow stream copy).
- [ ] Tests pass. Commit.

### Task 14: subprocess stderr drain + watchdog non-blocking (AS-04/Q-NEW-10, Q-NEW-04)

**Files:** `src/encrypted_secrets.zig:733-805`.

- [ ] Failing test: stub child writing >128KB stderr + small stdout with `timeout_ms=0` returns (no deadlock) under a test deadline; and a successful fast exec with default timeout returns promptly (watchdog does not block the join for the full timeout).
- [ ] Fix: drain stderr concurrently with stdout (or `.stderr=.ignore`); replace the `nanosleep`+flag watchdog with a `std.Thread.Condition`/`Futex.timedWait` on `done` so it wakes immediately; remove dead `stderr_data` or populate it. Consider rejecting/guarding `timeout_ms==0`.
- [ ] Tests pass. Commit.

### Task 15: Watcher synchronization (S-NEW-02/Q-NEW-11)

**Files:** `src/watch.zig` Watcher.

- [ ] Failing/contract test: concurrent `addPath`/`removePath` while running does not corrupt (guard with a TSan-style stress test or assert API contract).
- [ ] Fix: add `std.Thread.Mutex` guarding `watches` reads/writes in `addPathWithData`, `removePath`, `watchCount`, `checkForChanges`; document callback concurrency.
- [ ] Tests pass. Commit.

### Task 16: parallel real load/serialize + thread-safe alloc (Q-NEW-09, S-NEW-03)

**Files:** `src/parallel.zig:235-242, 462-468, 354-408`.

- [ ] Failing test: `parallelFileLoad` over a real fixture returns non-null content equal to the file; `parallelSerialize` returns real output.
- [ ] Fix: implement real load (delegate to `loader`/`secret.readFileToEnd`) and serialize (delegate to `serialize`); wrap caller allocator in `std.heap.ThreadSafeAllocator` for worker threads (or document+enforce thread-safe requirement).
- [ ] Tests pass; re-verify gap-doc #141 is genuinely closed. Commit.

### Task 17: leaks & secret-zero on error paths (Q-NEW-05, Q-NEW-12, Q-NEW-13, Q-NEW-14)

**Files:** `src/serialize.zig:543`, `src/config.zig:733,807`, `src/remote.zig:1254`, `src/merge.zig:47-86`, `src/secret.zig:221-224`.

- [ ] Tests under counting allocator / failing allocator to prove no leak and secureZero-before-free on error.
- [ ] Fixes: free `temp_path` on non-EEXIST create error (3 sites); `defer secureZero+free` in `Consul.get`; free duped keys in `mergeMaps` errdefer; `secureZero(content)` before free in `secret` OOM path.
- [ ] Tests pass. Commit.

### Task 18: error-handling correctness (Q-NEW-07, Q-NEW-08, Q-NEW-15)

**Files:** `src/config.zig:366-370`, `src/dotenv.zig:58-60`, `src/loader.zig:852-859`.

- [ ] Tests: `parseFile` on a no-permission path returns `AccessDenied` (not FileNotFound); `dotenv.load` on oversize file returns error (not empty); large float field serializes/loads without dropping siblings.
- [ ] Fixes: propagate real error (`else => |e| return e`); propagate OOM/StreamTooLong; size float buffer `[512]u8` or heap fallback, never bare `return`.
- [ ] Tests pass. Commit.

### Task 19: expansion allowlist + report redaction (S-NEW-04, S-NEW-05)

**Files:** `src/expand.zig` (ExpandOptions), `src/diff.zig`, `src/provenance.zig`; `docs/SECURITY.md`.

- [ ] Tests: expansion of a denied/secret-pattern var is not substituted when allowlist/deny configured; diff/provenance output masks values when a `sensitive_keys`/redaction option is set.
- [ ] Fixes: add opt-in allow/deny list to ExpandOptions (document untrusted-input risk; consider default-deny `*_TOKEN/*_SECRET/*_KEY/*PASSWORD*`); add redaction hook to `formatDiff`/`Change.format`/`printJson`. Document in SECURITY.md.
- [ ] Tests pass. Commit.

---

## Phase 4 — Quality / dead-code / dedup

### Task 20: dead code, quote-strip dedup, atomic-write dedup (Q-NEW-16/17/18)

**Files:** `src/validation.zig` (706/744/749/764), `src/diff.zig:370`, `src/async.zig:61`, `src/ini.zig` (38/40/41), a new small string util for `stripMatchingQuotes`, `src/config.zig` extract `writeAtomic`.

- [ ] Either re-export unused validators (if intended public) or delete; remove unused type/alias/unreachable error variants. Extract `stripMatchingQuotes` used by ini/dotenv/loader×2. Extract private `writeAtomic` shared by `safeWriteConfig`/`safeWriteConfigWithBackup`.
- [ ] `zig build test` green; refAll guard green. Commit.

---

## Phase 5 — Performance

### Task 22: read-path key normalization + parser micro-fixes (P-NEW-01/02/03)

**Files:** `src/loader.zig:563-590` (+ get/has/isSet/getPath), `src/ini.zig:181`, `src/properties.zig:172-189`.

- [ ] Test under counting allocator: 10k case-insensitive `get("MixedKey")` keeps arena bytes flat (no per-read alloc).
- [ ] Fix: add `normalizeKeyTransient(key, buf)` with stack buffer + fallback for read paths (restore PERF-20 intent); cache INI section pointer per `[section]`; hoist properties scratch buffers with `clearRetainingCapacity`.
- [ ] Tests pass. Commit.

---

## Phase 6 — Docs / packaging

### Task 21: doc & API drift (GAP-NEW-01/02/03/04, Q-NEW-19)

**Files:** `src/config.zig` (add `pub const validate = validation;`), `README.md`, `docs/API.md`, `docs/VIPER_COMPARISON.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/CONTRIBUTING.md`, `Makefile`, `src/diff.zig:21-26` doc.

- [ ] Add `validate` alias (non-breaking) so documented `config.validate.*` compiles; add a test that calls `config.validate.required(...)`.
- [ ] Update every "0.15.2"/"0.15.1" reference → "0.16.0".
- [ ] Fix API.md `getPaths` snippet (arity + field names) and VIPER_COMPARISON snippets (`diff.merge`/`mergeMany`, `expandWithOptions`, `DiffResult.changes`); fix diff.zig module doc example.
- [ ] Reconcile README "Current Version" vs `build.zig.zon` version/tags.
- [ ] `zig build test` green. Commit.

---

## Phase 7 — Re-audit loop (termination condition)

### Task 23: Update tracking docs

- [ ] Record all findings + resolutions in `docs/GAP_ANALYSIS.md` (open→closed), `docs/GAP_ANALYSIS_RESOLVED.md`, `docs/SECURITY_GAP_ANALYSIS.md`, `docs/QUALITY_GAP_ANALYSIS.md`, `docs/PERF_GAP_ANALYSIS.md`.

### Task 24: Re-run reviews until clean

- [ ] Re-run `/security:appsec-review` (full repo). Fix any NEW finding via the same TDD loop.
- [ ] Re-run `/codepros:audit`. Fix any NEW finding.
- [ ] Repeat Tasks 23–24 until both come back with zero new actionable findings. Each loop: keep `zig build check` + `zig build test` green.

---

## Self-review notes

- Spec coverage: every AS-/S-NEW-/Q-NEW-/P-NEW-/GAP-NEW- finding maps to a task (crosswalk above).
- Migration tasks use the compiler (refAll guard) as the test; logic/security/perf tasks use behavioral TDD.
- Type consistency: new symbols introduced — `validate` alias, `normalizeKeyTransient`, `stripMatchingQuotes`, `writeAtomic`, `SecurityOptions.allowed_hosts`, `ExpandOptions` allow/deny, redaction option — referenced consistently.
