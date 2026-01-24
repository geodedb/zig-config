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
