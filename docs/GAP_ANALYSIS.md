# GAP Analysis

Last updated: 2026-01-30
Review commit: e473be6 (working tree)
Reviewed by: Security Code Review Agent (adversarial)

## Summary

### Severity Breakdown

| Severity | Count | Open | Closed | Description |
|----------|-------|------|--------|-------------|
| Critical | 0 | 0 | 0 | No critical vulnerabilities found |
| High | 1 | 1 | 0 | Local code execution / high-impact secrets risk |
| Medium | 9 | 9 | 0 | Auth gaps, DoS risks, symlink race conditions, SSRF edge cases |
| Low | 4 | 4 | 0 | Hardening and policy alignment |
| **Total** | **14** | **14** | **0** | |

### Top 5 Risks

1. Vault CLI PATH hijack allows arbitrary binary execution (High, #77)
2. Secret provider config fields ignored (Vault/1Password) (Medium, #76)
3. CI pipeline skips build/test, allowing unverified releases (Medium, #82)
4. Remote client timeouts unused (DoS risk) (Medium, #80)
5. Vault field selector ignored; full JSON returned (Medium, #78)

## Stack-Ranked Findings

| Rank | Severity | RiskScore | Finding | Component | CWE/OWASP | Evidence (file:line) | GitLab Issue | Fix Summary | Owner | SLA/Due | Status |
|------|----------|-----------|---------|-----------|-----------|----------------------|--------------|------------|-------|---------|--------|
| 1 | High | 40 | Vault CLI PATH hijack allows arbitrary binary execution | encrypted_secrets | CWE-426 | src/encrypted_secrets.zig:411 | https://gitlab.com/devnw/zig/config/-/issues/77 | Add allowlisted vault_path or verify binary | TBD | 2026-03-01 | Open (confidence::confirmed) |
| 2 | Medium | 48 | Secret provider config fields ignored (Vault/1Password) | encrypted_secrets | CWE-922 | src/encrypted_secrets.zig:240 | https://gitlab.com/devnw/zig/config/-/issues/76 | Apply config to child env or API | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 3 | Medium | 48 | CI pipeline skips build/test | CI/CD | CWE-693 | .gitlab-ci.yml:5 | https://gitlab.com/devnw/zig/config/-/issues/82 | Add build/test stages; gate release | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 4 | Medium | 36 | Remote client timeout_ms unused (DoS risk) | remote | CWE-400 | src/remote.zig:373 | https://gitlab.com/devnw/zig/config/-/issues/80 | Enforce timeouts in requests | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 5 | Medium | 36 | Vault field selector ignored; full JSON returned | encrypted_secrets | CWE-200 | src/encrypted_secrets.zig:476 | https://gitlab.com/devnw/zig/config/-/issues/78 | Parse JSON and return field only | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 6 | Medium | 32 | Symlink checks are TOCTOU; file ops still follow symlinks | file IO | CWE-59 | src/secret.zig:82 | https://gitlab.com/devnw/zig/config/-/issues/69 | Use O_NOFOLLOW/exclusive open | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 7 | Medium | 32 | Predictable temp file names in safeWriteConfig | file IO | CWE-377 | src/config.zig:697 | https://gitlab.com/devnw/zig/config/-/issues/61 | Random temp names + O_EXCL | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 8 | Medium | 32 | DNS rebinding attack surface in SSRF protection | remote | CWE-918 | src/remote.zig:73 | https://gitlab.com/devnw/zig/config/-/issues/68 | Resolve & validate IPs; pin DNS | TBD | 2026-04-30 | Open (confidence::suspected) |
| 9 | Medium | 24 | Secret provider command execution lacks timeout/stderr handling | encrypted_secrets | CWE-400 | src/encrypted_secrets.zig:480 | https://gitlab.com/devnw/zig/config/-/issues/79 | Drain stderr; enforce timeout | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 10 | Medium | 24 | Etcd username/password options ignored | remote | CWE-287 | src/remote.zig:375 | https://gitlab.com/devnw/zig/config/-/issues/81 | Implement auth or reject config | TBD | 2026-04-30 | Open (confidence::confirmed) |
| 11 | Low | 24 | Secret env provider contradicts documented policy | encrypted_secrets/docs | CWE-214 | src/encrypted_secrets.zig:177 | https://gitlab.com/devnw/zig/config/-/issues/84 | Remove or gate env provider; update docs | TBD | 2026-07-29 | Open (confidence::confirmed) |
| 12 | Low | 16 | Serialize writes use default permissions | serialize | CWE-732 | src/serialize.zig:462 | https://gitlab.com/devnw/zig/config/-/issues/75 | Use 0o600 by default | TBD | 2026-07-29 | Open (confidence::confirmed) |
| 13 | Low | 16 | Pre-commit config malformed; hooks may not run | dev workflow | CWE-693 | .pre-commit-config.yaml:11 | https://gitlab.com/devnw/zig/config/-/issues/83 | Fix YAML indentation; validate in CI | TBD | 2026-07-29 | Open (confidence::confirmed) |
| 14 | Low | 16 | File watcher TOCTOU race condition | watch | CWE-367 | src/watch.zig:205 | https://gitlab.com/devnw/zig/config/-/issues/52 | Document/mitigate TOCTOU | TBD | 2026-07-29 | Open (confidence::suspected) |

## Findings by Area

### App/API

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| Symlink checks are TOCTOU; file ops still follow symlinks | Open | https://gitlab.com/devnw/zig/config/-/issues/69 | Use no-follow/exclusive open flags |
| Predictable temp file names in safeWriteConfig | Open | https://gitlab.com/devnw/zig/config/-/issues/61 | Randomize temp names and add O_EXCL |
| Serialize writes use default permissions | Open | https://gitlab.com/devnw/zig/config/-/issues/75 | Set 0o600 by default |
| File watcher TOCTOU race condition | Open | https://gitlab.com/devnw/zig/config/-/issues/52 | Document or rework watcher |

### Auth/Secrets

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| Vault CLI PATH hijack allows arbitrary binary execution | Open | https://gitlab.com/devnw/zig/config/-/issues/77 | Allowlist vault_path or verify binary |
| Secret provider config fields ignored (Vault/1Password) | Open | https://gitlab.com/devnw/zig/config/-/issues/76 | Apply config to child env/API |
| Vault field selector ignored; full JSON returned | Open | https://gitlab.com/devnw/zig/config/-/issues/78 | Parse JSON and return field |
| Command execution lacks timeout/stderr handling | Open | https://gitlab.com/devnw/zig/config/-/issues/79 | Enforce timeout, drain stderr |
| Secret env provider contradicts documented policy | Open | https://gitlab.com/devnw/zig/config/-/issues/84 | Remove or gate env provider |

### Data/Network

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| Remote client timeout_ms unused (DoS risk) | Open | https://gitlab.com/devnw/zig/config/-/issues/80 | Enforce timeouts |
| Etcd username/password options ignored | Open | https://gitlab.com/devnw/zig/config/-/issues/81 | Implement auth or reject config |
| DNS rebinding attack surface in SSRF protection | Open | https://gitlab.com/devnw/zig/config/-/issues/68 | Resolve and validate IPs |

### CI/CD

| Finding | Status | Issue | Notes |
|---------|--------|-------|-------|
| CI pipeline skips build/test | Open | https://gitlab.com/devnw/zig/config/-/issues/82 | Add build/test stages |
| Pre-commit config malformed; hooks may not run | Open | https://gitlab.com/devnw/zig/config/-/issues/83 | Fix indentation; validate config |

### IaC

None identified in this repository.

### Container

None identified in this repository.

### Ops

None identified beyond CI/CD and dev workflow items above.

## Quick wins / Medium / Strategic

### Quick wins (days)
- Fix `.pre-commit-config.yaml` indentation and validate config in CI (#83).
- Add restrictive permissions (0o600) to serialize write helpers (#75).
- Remove or gate `env://` provider and align docs (#84).

### Medium-term (weeks)
- Apply Vault/1Password config fields to CLI execution or move to direct APIs (#76).
- Enforce timeouts and drain stderr for external secret commands (#79).
- Enforce HTTP timeouts for remote clients (#80).
- Fix symlink handling with no-follow/exclusive opens and randomized temp files (#69, #61).
- Implement or explicitly reject etcd username/password options (#81).

### Strategic (quarter)
- Replace CLI-based secret providers with direct SDK/API integrations for stronger auth/TLS controls (#76, #77, #79).
- Implement DNS rebinding mitigation (resolve and pin IPs) in SSRF checks (#68).
- Add full build/test gating in CI with required approvals before release (#82).
