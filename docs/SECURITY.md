# Security

This document describes the security considerations and practices for zigconfig.

## Secret Handling

The `secret` module enforces secure handling of sensitive configuration values.

### Design Principles

1. **Never accept secrets from command-line flags**
   - Flags are visible in process listings
   - Shell history records flag values
   - Log systems may capture full command lines

2. **Never accept secrets from environment variables**
   - Environment is visible to all processes
   - Child processes inherit environment
   - System debugging tools expose env vars

3. **Only read secrets from files or stdin**
   - File permissions control access
   - No exposure in process listings
   - Compatible with container secret mounts

### Secure API

```zig
const secret = @import("config").secret;

// Read from file (recommended)
const password = try secret.readFromFile("/run/secrets/db_password", allocator);
defer secret.secureZero(password);

// Read from stdin (for interactive use)
const token = try secret.readFromStdin(allocator);
defer secret.secureZero(token);

// Validate not passed via flag/env
try secret.validateNotInFlagOrEnv(flag_value, "DB_PASSWORD");

// Safe logging
std.log.info("Password: {s}", .{secret.redact(password)});
// Output: Password: ***REDACTED***
```

### Memory Security

```zig
// Always zero secret memory when done
defer secret.secureZero(password);
```

The `secureZero` function uses volatile writes to prevent compiler optimization from removing the zeroing operation.

### Container Integration

For Kubernetes/Docker secrets:

```yaml
# Kubernetes Secret Mount
spec:
  containers:
    - volumeMounts:
        - name: secrets
          mountPath: /run/secrets
          readOnly: true
```

```zig
// In application
const db_password = try secret.readFromFile("/run/secrets/db_password", allocator);
```

### Future Enhancements

See: [#18 - Add encrypted secrets support](https://gitlab.com/devnw/zig/config/-/issues/18)

Planned features:

- SOPS integration
- age/GPG encrypted files
- Cloud KMS integration

## Input Validation

The `validate` module provides input validation to prevent security issues.

### Path Traversal Prevention

Always validate paths before use:

```zig
// Validate path exists and is accessible
try validate.pathExists(config_path);

// Consider: additional path traversal checks
```

### Injection Prevention

Validate values that will be used in:

- Database queries (SQL injection)
- Shell commands (command injection)
- URL construction (URL injection)

```zig
// Validate URL before use
try validate.url(api_endpoint);

// Validate hostname
try validate.hostname(server_host);
```

## Environment Variable Expansion (S-NEW-04)

The `expand` module (`expandEnv` / `expandEnvWithOptions` / `expandStruct`)
resolves `${VAR}` and `$VAR` references straight from the **process
environment**, recursively by default.

> **Warning (CWE-200 / CWE-610): never expand untrusted input.**
> If you run expansion over a value that an attacker can influence -- a
> committed config file, a remote key/value value, a tenant-supplied field --
> they can embed references like `${AWS_SECRET_ACCESS_KEY}`, `${VAULT_TOKEN}`,
> or `${DB_PASSWORD}` and exfiltrate process-environment secrets into the
> resulting config value.

The default behavior is unchanged (expansion works with no restriction), but
`ExpandOptions` provides **opt-in** allow/deny controls. **Precedence: deny
overrides allow.** A blocked name is treated as undefined (yields
`undefined_value`, or errors under `strict`), and the policy applies uniformly
to `${VAR}`, `$VAR`, modifier forms (`${VAR:-default}` etc.), and recursive
expansion.

```zig
const config = @import("config");

// Allowlist: ONLY these names may expand; everything else resolves empty.
const safe = try config.expandEnvWithOptions(untrusted, allocator, .{
    .allowed_vars = &.{ "PUBLIC_BASE_URL", "REGION" },
});
defer allocator.free(safe);

// Denylist: these names never expand (overrides any allowlist).
const filtered = try config.expandEnvWithOptions(untrusted, allocator, .{
    .denied_vars = &.{ "VAULT_TOKEN", "AWS_SECRET_ACCESS_KEY" },
});
defer allocator.free(filtered);

// Convenience heuristic: block secret-looking names
// (contains TOKEN/SECRET/KEY/PASSWORD/CREDENTIAL, case-insensitive).
const hardened = try config.expandEnvWithOptions(untrusted, allocator, .{
    .deny_secret_looking = true,
});
defer allocator.free(hardened);
```

Recommendation: for any lower-trust input, prefer an explicit `allowed_vars`
allowlist of exactly the names you intend to support. Use `denied_vars` and/or
`deny_secret_looking` as defense in depth.

## Redacting Diff and Provenance Output (S-NEW-05)

The `diff` and `provenance` modules emit config **values verbatim** by default.
If a config snapshot or provenance report contains resolved secrets, dumping it
writes plaintext secrets into logs/CI output (CWE-532 / CWE-200).

Redaction is **opt-in** and backward compatible -- `formatDiff` and
`printJson` are unchanged. Use the redaction-aware variants when output may
contain secrets:

```zig
// Diff: mask sensitive keys' old/new values.
const report = try config.formatDiffWithOptions(allocator, result, .{
    .redact = true,
    // Optional explicit list; omit to use the default heuristic.
    // .sensitive_keys = &.{ "db_password", "api_token" },
});
defer allocator.free(report);

// Provenance: mask sensitive values while keeping valid JSON.
try tracker.printJsonRedacted(&writer, .{
    .redact = true,
    // .sensitive_keys = &.{ "db_password" },
});
```

When `redact` is enabled and no explicit `sensitive_keys` list is supplied, the
default heuristic masks any key containing (case-insensitive) `password`,
`secret`, `token`, `key`, or `credential`. Masked values are replaced with
`***REDACTED***`.

## Configuration Precedence Security

The precedence system has security implications:

| Source | Precedence | Security Notes |
|--------|------------|----------------|
| flag | Highest | Never for secrets |
| env | High | Never for secrets |
| project | Medium | Check file permissions |
| user | Medium | User-controlled |
| system | Low | Admin-controlled |
| default | Lowest | Hardcoded values |

### File Permission Recommendations

```bash
# System config (admin only)
chmod 644 /etc/myapp/config.toml
chown root:root /etc/myapp/config.toml

# User config (user only)
chmod 600 ~/.config/myapp/config.toml

# Project config (team accessible)
chmod 644 ./config.toml

# Secret files (owner only)
chmod 600 /run/secrets/*
```

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead:

1. Email security concerns to the maintainers
2. Include detailed description and reproduction steps
3. Allow reasonable time for fixes before disclosure

## Security Updates

Security fixes are prioritized with `priority::critical` label.

Monitor:

- GitLab releases
- CHANGELOG.md security sections
- Dependency updates

## Dependencies

External dependencies:

- `yaml` - YAML parsing library
- `toml` - TOML parsing library
- `json` - JSON utilities

Keep dependencies updated for security patches.

## Best Practices for Users

1. **Never commit secrets to version control**
2. **Use .gitignore for local config files**
3. **Validate all external input**
4. **Set appropriate file permissions**
5. **Use secret files over environment variables**
6. **Rotate secrets regularly**
7. **Audit configuration access logs**

## Acknowledgments

We appreciate responsible security research. Contributors who report security issues will be acknowledged (with permission) in release notes.
