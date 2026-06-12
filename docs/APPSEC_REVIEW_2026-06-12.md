# AppSec Review — zigconfig (`gitlab.com/devnw/zig/config`)

> Date: 2026-06-12 · Scope: full repository (HEAD of main + working-tree dependency bump) · Reviewer: appsec-reviewer agent (OWASP Top 10:2025 + CIS Controls v8.1.2)

## 1. Scope & Assumptions

**Reviewed (full source read, Zig 0.16.0, build verified green via `zig build`):**

- Network/SSRF/TLS/headers: `src/remote.zig` (1535 lines, full)
- Subprocess/secrets: `src/encrypted_secrets.zig`, `src/secret.zig`, `src/environ.zig`, `src/limits.zig`
- Input parsing: `src/dotenv.zig`, `src/ini.zig`, `src/properties.zig`, `src/flags.zig`, `src/serialize.zig`
- Variable expansion: `src/expand.zig`
- Path resolution: `src/xdg.zig`, file watching `src/watch.zig`
- Core store / loading / format dispatch / atomic writes: `src/config.zig`, `src/loader.zig` (targeted reads of all security-relevant paths)
- Supply chain / CI: `build.zig`, `build.zig.zon` (+ working-tree dependency bump), `docs/`
- Prior state: `docs/GAP_ANALYSIS.md`, `docs/SECURITY_GAP_ANALYSIS.md`, `docs/SECURITY.md`, `src/remote_test.zig`

**Reviewed at lower depth (no confirmed findings, noted in §6):** `parallel.zig`, `async.zig`, `diff.zig`, `merge.zig`, `validation.zig`, `provenance.zig`, transitive dependency internals (out of scope).

**Cross-checked against closed/blocked items.** SEC-04 (spice pin) and GAP-0058 (Windows CI) confirmed still blocked and not re-reported. Wave 10–14 closures (CRIT-1, HIGH-1, SEC-01/02/03/05–18, ADV-01–08) were verified as actually present in code; only items where evidence shows a closure is **incomplete/regressed** or the issue is **new** are reported.

**Assumptions:** Library consumed by Zig apps. "Attacker-influenceable input" = config files (JSON/YAML/TOML/INI/properties/dotenv), remote KV responses, environment variables, and any of the above that feed remote endpoint URLs / secret-reference strings / file paths / argv. Operator-set fields (e.g., `op_path`, `vault_path`) treated as allowlisted per project design.

**Build:** `zig build` → exit 0 on Zig 0.16.0; all reviewed code ships.

## 2. Executive Summary

- **One High-severity regression:** the SSRF "DNS rebinding mitigation" that the code and docs advertise (`block_private_ips`, default **on**) is, after the Zig 0.16 migration, a **no-op for every hostname**. `validateResolvedAddresses` only parses IP literals, but it is only ever called for non-literals, so it always returns success without resolving. A configured hostname that resolves to `169.254.169.254`/internal IPs passes validation (AS-01). The surrounding docstrings still claim resolution occurs.
- **One incomplete prior fix (Low):** the ADV-05 symlink guard was added to `serialize.zig:writeToFileWithBackup` but the parallel `config.zig:safeWriteConfigWithBackup` was missed — its backup `copyFile` follows a symlinked source, leaking an unintended file's contents into the `.bak` (AS-02).
- **One reachable panic / out-of-bounds read (Low):** `FlagParser.parse` indexes `arg[0]` before checking length, crashing on an empty argv element (AS-03).
- **One conditional availability bug (Low):** `execCommand` opens the subprocess `stderr` pipe but never drains it; with `timeout_ms == 0` (a documented option) a CLI that emits >pipe-buffer stderr deadlocks the caller indefinitely (AS-04).
- **Strong baseline.** Secret redaction, `secureZero`, `O_NOFOLLOW` file opens, bounded reads, base64-into-JSON encoding, KV key allowlisting, status-code checks, and `redirect_behavior=.not_allowed` are all implemented well. No injection, no credential-in-argv, no unbounded allocation found.

## 3. Findings Table

| ID | Title | Severity | OWASP 2025 | CWE | Location | Confidence |
|----|-------|----------|-----------|-----|----------|------------|
| AS-01 | SSRF host-resolution control is a no-op after Zig 0.16 migration; docs claim resolution that never happens | **High** | A01 Broken Access Control (SSRF) | CWE-918 | `src/remote.zig:220-224`, `280-290`, `170-177` | High |
| AS-02 | `safeWriteConfigWithBackup` missing the ADV-05 symlink guard; backup `copyFile` follows symlinked source | **Low** | A01 Broken Access Control | CWE-59 (+CWE-200) | `src/config.zig:784-790` (vs `src/serialize.zig:605-614`) | Medium-High |
| AS-03 | Out-of-bounds index / reachable panic on empty argv element in `FlagParser.parse` | **Low** | A10 Mishandling of Exceptional Conditions | CWE-125 (+CWE-248) | `src/flags.zig:140` | High |
| AS-04 | Subprocess `stderr` pipe never drained → deadlock when timeout disabled (CLI fills stderr buffer) | **Low** | A06 Insecure Design | CWE-833 (+CWE-400) | `src/encrypted_secrets.zig:736,742,749-751,789-805` | Medium |

## 4. Finding Details

### AS-01 — SSRF host-resolution control is a no-op; advertised DNS-rebinding mitigation does not run (High)

**Evidence.** `validateUrl` only resolves when the host is *not* an IP literal:

```zig
// src/remote.zig:220-224
// DNS rebinding mitigation: resolve hostnames and validate IPs (#68)
if (!isIpLiteral(decoded_host)) {
    const port = uri.port orelse if (is_https) @as(u16, 443) else @as(u16, 80);
    try validateResolvedAddresses(decoded_host, port);
}
```

But `validateResolvedAddresses` "resolves" by parsing the host **as an IP literal** — which, by the calling precondition (`!isIpLiteral`), always fails and is swallowed:

```zig
// src/remote.zig:280-290
fn validateResolvedAddresses(host: []const u8, port: u16) RemoteError!void {
    const addr = std.Io.net.IpAddress.parse(host, port) catch return;  // always `return` for hostnames
    if (isPrivateAddressForAddr(addr)) {
        return RemoteError.PrivateAddressBlocked;
    }
}
```

So for **every** hostname the function returns success without contacting DNS. The only remaining hostname defense is a static string list in `isPrivateAddress` (`localhost`, `::1`, `*.local`, `*.internal`, `*.localhost`, `metadata.google.internal`). The module docstring (lines 170-177) still asserts resolution happens. No DNS resolution exists anywhere in the module (`getAddressList`, `getaddrinfo`, `resolve` all absent). `remote_test.zig` only tests IP-literal cases (274-324), so the regression is untested.

**Impact.** With `block_private_ips = true` (default), a configured etcd/Consul endpoint whose host is an ordinary public DNS name that resolves to an internal address bypasses SSRF protection. Examples that pass validation and connect to internal targets: `169.254.169.254.nip.io` (IMDS), `imds.attacker.com` (A-record → `169.254.169.254`), or any internal name not ending in the hard-coded suffixes. Yields request forgery to cloud metadata (credential theft) and internal services.

**Remediation.** Either (a) restore real resolution and validate every resolved address against `isPrivateAddressForAddr`, pinning the resolved IP for the connection to also close the rebinding window; or (b) if io-based resolution is unavailable, **fail closed**: when `block_private_ips` is set and the host is a non-literal hostname, reject unless on an explicit operator allowlist. At minimum correct the docstrings immediately. Add hostname→private-IP regression tests.

**References.** CWE-918; OWASP 2025 A01 (SSRF).

---

### AS-02 — `safeWriteConfigWithBackup` omits the ADV-05 symlink guard; backup copy follows a symlinked source (Low)

**Evidence.** `serialize.zig:writeToFileWithBackup` (605-614) rejects symlinks on source and backup. The parallel `config.zig` function has no such check:

```zig
// src/config.zig:784-790
if (cwd.access(io, path, .{})) {
    if (options.create_backup) {
        const backup_path = std.fmt.allocPrint(allocator, "{s}{s}", .{ path, options.backup_suffix }) ...;
        defer allocator.free(backup_path);
        cwd.copyFile(path, cwd, backup_path, io, .{}) catch return SafeWriteError.IoError; // no isSymlink guard
    }
}
```

`Dir.copyFile` opens the **source** following symlinks (`/lib/std/Io/Dir.zig:1817`). Destination uses atomic temp+rename (`replace=true`), so this is an information-disclosure (source-follow), not arbitrary-write.

**Impact.** If config `path` is/becomes a symlink, the `.bak` captures the symlink target's contents readable by the app's UID. Exactly the ADV-05 class already fixed in `serialize.zig`; left unfixed in this second path — the ADV-05 closure is incomplete.

**Remediation.** Mirror the ADV-05 guard before `copyFile` (`secret.isSymlink(path)`/`secret.isSymlink(backup_path)` → error), or open the source with `secret.openFileReadNoFollow` and stream-copy. Port the existing ADV-05 test to `safeWriteConfigWithBackup`.

**References.** CWE-59, CWE-200; OWASP 2025 A01.

---

### AS-03 — Reachable out-of-bounds index / panic on empty argv element (Low)

**Evidence.**

```zig
// src/flags.zig:131-146
const arg = args[i];
if (mem.startsWith(u8, arg, "--")) { ... }
else if (arg.len == 2 and arg[0] == '-' and arg[1] != '-') { ... }   // length-guarded, safe
else if (arg[0] == '-' and arg.len > 2) {                            // arg[0] evaluated BEFORE length check
    try self.parseShortFlags(arg[1..], args, &i);
} else {
    try self.positional.append(self.allocator, arg);
}
```

Zig evaluates the left operand of `and` first, so `arg[0]` is indexed before `arg.len > 2`. For an empty argument the prior branches are false, so control reaches `arg[0]` on a zero-length slice. No `arg.len == 0` guard exists.

**Impact.** A single empty-string argv element causes index-out-of-bounds: panic in Debug/ReleaseSafe (DoS) or OOB read in ReleaseFast. `parse([]const []const u8)` is public API.

**Remediation.** Add an explicit `arg.len == 0` branch (treat as positional) and reorder so length is checked before indexing. Add `parse(&.{""})` and `&.{"a","","--flag"}` tests.

**References.** CWE-125, CWE-248; OWASP 2025 A10.

---

### AS-04 — Subprocess `stderr` pipe opened but never drained → deadlock when timeout disabled (Low)

**Evidence.** `execCommand` requests `.stderr = .pipe` (733-751) but never reads `child.stderr` (only `child.stdout`, 789-797). The watchdog that would unblock a stuck child only exists when `timeout_ms > 0` (774-786). `VaultConfig.timeout_ms` defaults to 30000 but is documented as settable to `0` to disable.

**Impact.** If a `vault`/`op`/KMS CLI writes more than the OS pipe buffer (~64 KB) to stderr before closing stdout, it blocks on stderr `write(2)` while the parent blocks reading stdout → deadlock. With watchdog (default): bounded ~`timeout_ms` stall then `Timeout`. With `timeout_ms == 0`: no watchdog → hangs indefinitely (availability DoS). Also, all stderr diagnostics are silently discarded.

**Remediation.** Either don't pipe unused stderr (`.stderr = .ignore`/inherit), or drain stderr concurrently with stdout before `wait`. Consider rejecting `timeout_ms == 0` for subprocess providers, or always installing the watchdog. Add a large-stderr deadlock test with `timeout_ms = 0`.

**References.** CWE-833 (deadlock), CWE-400; OWASP 2025 A06.

## 5. Secure Design Notes (what the codebase does well)

- **Secret hygiene strong.** `SensitiveString` redacts via `format`; `secret.secureZero` uses per-byte volatile writes; response/credential buffers zeroed before free at every audited site. Secrets read only from files/stdin, never flags/env.
- **No command injection / no credential-in-argv.** Vault/1Password run via `process.spawn` (no shell); identifiers pass `isValidSecretIdentifier`; binaries resolved through strict allowlists (`isValidProviderPath`) with PATH-hijack protection; tokens passed via minimal env map, not argv.
- **Bounded resource use.** Central `limits.zig` caps config (1 MB), dotenv (1 MB), secret (64 KB), remote responses (1 MB enforced inline). Parsers use `parseInt`/`parseFloat` (overflow → error).
- **File access no-follow by default.** `openFileReadNoFollow`/`createFileNoFollow` use `O_NOFOLLOW|O_CLOEXEC`; loaders validate `isPathSafe`; atomic writes use crypto-random temp suffixes + `0o600` + `sync` + rename.
- **Remote client hardening.** KV keys validated (`isValidKVKey`); keys/values base64-encoded before JSON embedding; HTTP status checked before parse; redirects disabled; CRLF/null rejected in `User-Agent` (CWE-113); socket-level timeouts.
- **JSON serialization** escapes control chars `< 0x20` as `\uXXXX` (RFC 8259). HTTPS-by-default for Vault/etcd/Consul.

## 6. Coverage Gaps & Questions

- **AS-01 deployment dependency.** Impact depends on whether the etcd/Consul endpoint can be influenced by lower-trust config/env. The defect (no-op control) is certain.
- **YAML/INI re-serialization (not a confirmed finding).** `serialize.zig:writeYamlScalar` quotes only on `:`,`#`,`\n`,leading/trailing space — a round-tripped value beginning with a YAML indicator could change meaning if re-parsed. Config-semantic only.
- **Watchdog kill-after-reap race (timing-only).** Narrow PID-reuse window (CWE-364); sub-microsecond, observation only.
- **INI duplicate-section leak.** `ini.zig:155` overwrites a duplicate `[section]` without `deinit`-ing the previous `Section.values` — memory leak, not a vulnerability.
- **Recursive expansion.** Depth-capped (10); bounded amplification, not a DoS.
- **Not deeply audited:** `parallel.zig`, `async.zig`, `diff.zig`, `merge.zig`, `validation.zig`, `provenance.zig`.
- **Transitive dependencies** not reviewed; pinned by commit+hash (good). SEC-04/GAP-0058 unchanged and out of scope.

## 7. Prioritized Next Actions

1. **AS-01 (High)** — restore or fail-closed the SSRF host check; pin resolved IP for the connection; fix misleading docstrings; add hostname→private-IP regression tests.
2. **AS-02 (Low)** — add `isSymlink` guards (or no-follow streaming copy) to `config.zig:safeWriteConfigWithBackup`; port the ADV-05 test.
3. **AS-03 (Low)** — guard empty argv / reorder the length check in `flags.zig`; add empty-arg tests.
4. **AS-04 (Low)** — drain or drop subprocess stderr; guard `timeout_ms == 0`; add a large-stderr deadlock test.
5. **Hygiene** — fix the INI duplicate-section leak; decide on YAML re-serialization quoting for untrusted values.
