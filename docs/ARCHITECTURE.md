# Architecture

This document describes the architecture of the zigconfig library (Zig 0.15.2).

## Module Structure

```
src/
├── config.zig             # Main entry point and unified API (Value, Config builder, safeWriteConfig)
├── loader.zig             # Typed config loader with comptime struct reflection (Loader(T))
├── provenance.zig         # Value source tracking with JSON escaping
├── xdg.zig                # XDG Base Directory support (Linux, macOS, Windows)
├── environ.zig            # Cross-platform env var access (getenv, getEnvOwned)
├── dotenv.zig             # .env file parsing (parseLine, parseContent, load)
├── secret.zig             # Secure secret handling (file/stdin, secureZero, O_NOFOLLOW)
├── encrypted_secrets.zig  # Encrypted secret providers (Vault, 1Password CLI, SensitiveString)
├── flags.zig              # Command-line flag parsing (long, short, boolean)
├── merge.zig              # Configuration merging (mergeMaps, capacity hints)
├── diff.zig               # Configuration diff utilities (diffMaps, case-insensitive)
├── expand.zig             # Environment variable expansion (${VAR}, ${VAR:-default})
├── validation.zig         # Validation utilities (pattern matching, ReDoS hardening)
├── serialize.zig          # Configuration serialization (createFileNoFollow, 0o600)
├── watch.zig              # Hot-reload / file watching (polling-based, TOCTOU-documented)
├── remote.zig             # Remote config clients (etcd v3, Consul KV, SSRF protection)
├── async.zig              # Async/parallel loading (AsyncLoader, loadParallel)
├── parallel.zig           # Thread pool-based parallel file I/O (spice scheduler)
├── ini.zig                # INI file format parsing
├── properties.zig         # Java Properties format parsing
├── limits.zig             # Centralized size limits (CWE-400 prevention)
└── integration_test.zig   # Integration test suite
```

## Core Concepts

### Unified Value API (`config.zig`)

The `Value` type provides a format-agnostic interface for working with configuration data.
All internal modules are re-exported through `config.zig` as the single public entry point.

Supported formats (6):
- **YAML** -- External `yaml` library
- **JSON** -- External `json` library (std.json used internally for remote responses)
- **TOML** -- External `toml` library
- **INI** -- `ini.zig`
- **Properties** -- `properties.zig` (Java .properties)
- **dotenv** -- `dotenv.zig` (.env files)

Format is auto-detected from file extension, or from content when the extension is unknown.

### Typed Loader (`loader.zig`)

The `Loader(T)` generic uses comptime struct reflection to populate an arbitrary user-defined
struct from configuration sources. Key design decisions:

- **Comptime field iteration** -- No runtime reflection overhead.
- **Arena allocator** -- All loaded strings share the arena lifetime; one `deinit` frees everything.
- **Single env snapshot** -- `getEnvMap` is called once and reused across all fields.
- **Stack buffers** -- `bufPrint` with stack-allocated buffers avoids heap allocation for key normalization.
- **Case-insensitive keys** -- `normalizeKey` lowercases keys using an arena-backed buffer.

### Configuration Precedence

Values are loaded in this order (later sources override earlier):

1. **default** -- Struct field default values
2. **system** -- `/etc/APP/config.EXT`
3. **user** -- `~/.config/APP/config.EXT` (XDG)
4. **project** -- `./config.EXT`
5. **env** -- Environment variables (`PREFIX_FIELD`)
6. **flag** -- Command-line overrides (highest priority)

The provenance module additionally tracks `override` (explicit `Set()`) and `runtime_default`
(`SetDefault()`) sources for Viper-compatible precedence.

### Provenance Tracking (`provenance.zig`)

Every configuration value is annotated with its `Source` (flag, env, project, user, system,
default, override, runtime_default) and an optional source path. The `ProvenanceTracker`
records all tracked values and supports JSON-serialized output with proper escaping.

### XDG / Platform Support (`xdg.zig`)

Cross-platform configuration directory resolution:

| Platform | Config | Data | Cache |
|----------|--------|------|-------|
| Linux/BSD | `~/.config` | `~/.local/share` | `~/.cache` |
| macOS | `~/Library/Preferences` | `~/Library/Application Support` | `~/Library/Caches` |
| Windows | `%APPDATA%` | `%LOCALAPPDATA%` | `%LOCALAPPDATA%` |

Environment variables (`XDG_CONFIG_HOME`, etc.) override defaults on all platforms.
Uses `environ.zig` for cross-platform env var access.

### Secret Handling (`secret.zig`, `encrypted_secrets.zig`)

Two-tier secret architecture:

**`secret.zig`** -- Local secret operations:
- Read secrets only from files or stdin (never flags or env)
- `secureZero` for memory sanitization
- `isPathSafe` / `isPathSafeStrict` for path traversal prevention
- `openFileReadNoFollow` with `O_NOFOLLOW` to block symlink attacks (CWE-59)
- `createFileNoFollow` with 0o600 permissions for safe writes

**`encrypted_secrets.zig`** -- External secret providers:
- HashiCorp Vault (PATH allowlist via `resolveVaultPath`)
- 1Password CLI (binary allowlist via `resolveOpPath`)
- `SensitiveString` wrapper with `[REDACTED]` formatting (CWE-532)
- Timeout watchdog and `handleTermination` for tagged-union child processes
- Minimal env maps passed to child processes

### Remote Configuration (`remote.zig`)

Clients for remote configuration stores:

- **etcd v3** -- gRPC-gateway REST API, `std.json.parseFromSliceLeaky` for typed parsing
- **Consul KV** -- Standard KV API

Security hardening:
- SSRF protection: `validateUrl`, `isPrivateIPv4Bytes`, CGNAT range blocking, percent-decode normalization
- DNS rebinding mitigation
- Redirect blocking
- `isValidHeaderValue` for CRLF injection prevention
- `ResponseTooLarge` checks against `MAX_REMOTE_RESPONSE_SIZE`
- `SensitiveString` for credentials

### Validation (`validation.zig`)

Unified validation module with:
- Pattern matching via decomposed `matchPatternImpl`
- Escape sequence handling
- ReDoS hardening for user-supplied patterns
- Built-in validators: required, length, range, oneOf, port, hostname, URL, email, pathExists

### Merge and Diff (`merge.zig`, `diff.zig`)

- **merge** -- `mergeMaps` with `getPtr` for in-place updates, capacity hints, configurable strategy (override, keep_first, concat_arrays, unique_arrays)
- **diff** -- `diffMaps` with O(n) case-insensitive comparison via lowered-key HashMap

### Environment Variable Expansion (`expand.zig`)

Expands variable references in configuration values:
- `${VAR}` and `$VAR` syntax
- `${VAR:-default}` for fallback values
- `${VAR:+alternate}` for conditional substitution

### Serialization (`serialize.zig`)

Writes configuration structs to JSON, YAML, TOML, or env format. Uses `createFileNoFollow`
and 0o600 permissions. Supports `atomicWriteFile` (write-to-temp then rename) for safe updates.

### File Watching (`watch.zig`)

Polling-based hot-reload with documented TOCTOU limitations (CWE-367). Callers should
validate configuration in the reload callback, not rely on change detection alone.

### Async and Parallel Loading (`async.zig`, `parallel.zig`)

- **async.zig** -- `AsyncLoader` for loading multiple config files concurrently using Zig threads. `MAX_PARALLEL_THREADS=16`.
- **parallel.zig** -- Thread pool via the `spice` dependency for parallel file I/O and serialization. Falls back to sequential below threshold (2 files).

### Centralized Limits (`limits.zig`)

All size limits in one place to prevent resource exhaustion (CWE-400):

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_CONFIG_FILE_SIZE` | 1 MB | Configuration files |
| `MAX_REMOTE_RESPONSE_SIZE` | 1 MB | Network responses |
| `MAX_SECRET_FILE_SIZE` | 64 KB | Secret files |
| `MAX_CLI_OUTPUT_SIZE` | 1 MB | CLI tool output |
| `MAX_DOTENV_FILE_SIZE` | 1 MB | .env files |

## Data Flow

```
                        ┌──────────────┐
                        │  Config File │
                        │ (YAML/JSON/  │
                        │ TOML/INI/    │
                        │ Properties/  │
                        │ dotenv)      │
                        └──────┬───────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
       ┌─────────────┐ ┌─────────────┐  ┌──────────────┐
       │  Format     │ │ Remote      │  │ Encrypted    │
       │  Parser     │ │ (etcd/      │  │ Secrets      │
       │             │ │  Consul)    │  │ (Vault/1P)   │
       └──────┬──────┘ └──────┬──────┘  └──────┬───────┘
              │               │                 │
              └───────────────┼─────────────────┘
                              ▼
                       ┌─────────────┐
                       │   Loader    │    Precedence merge:
                       │  (comptime  │    default → system → user
                       │  reflection)│    → project → env → flag
                       └──────┬──────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
       │   Typed     │ │ Provenance  │ │ Validation  │
       │   Config    │ │  Tracker    │ │             │
       │   Struct    │ │             │ │             │
       └─────────────┘ └─────────────┘ └─────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
       │ Serialize   │ │   Watch     │ │    Diff     │
       │ (write out) │ │ (hot-reload)│ │ (compare)   │
       └─────────────┘ └─────────────┘ └─────────────┘
```

## Dependencies

External Zig libraries (declared in `build.zig.zon`):

| Library | Version | Purpose |
|---------|---------|---------|
| `yaml` | 0.1.1 | YAML parsing |
| `toml` | 0.1.0 | TOML parsing |
| `json` | 0.1.0 | JSON parsing and schema |
| `spice` | main | Thread pool for parallel operations |

Standard library usage: `std.json` for remote API response parsing (etcd/Consul),
`std.http` for remote clients, `std.Thread` for async loading.

## Key Architectural Patterns

- **Comptime struct reflection** -- Zero-overhead typed configuration loading.
- **Arena allocator** -- Single lifetime for all config values; one free releases everything.
- **Provenance tracking** -- Every value carries its source for debugging and auditing.
- **SSRF protection** -- All remote endpoints validated against private IP ranges, CGNAT, percent-encoding tricks, and DNS rebinding.
- **Centralized limits** -- `limits.zig` prevents resource exhaustion across all I/O paths.
- **Cross-platform abstraction** -- `environ.zig` and `xdg.zig` handle POSIX/Windows differences.
- **Symlink attack prevention** -- `O_NOFOLLOW` on reads, `createFileNoFollow` on writes.
- **Sensitive data protection** -- `SensitiveString` redacts credentials in logs and debug output.

## Security Considerations

The library addresses the following CWE categories:
- **CWE-59** -- Symlink following (`O_NOFOLLOW`, `isSymlink` checks)
- **CWE-214** -- Env-based secret exposure (env:// provider disabled by default)
- **CWE-367** -- TOCTOU in file watching (documented, mitigated by validation-on-reload)
- **CWE-400** -- Resource exhaustion (centralized size limits)
- **CWE-532** -- Credential logging (`SensitiveString` with `[REDACTED]`)
- **CWE-918** -- SSRF (IP validation, redirect blocking, DNS rebinding mitigation)
