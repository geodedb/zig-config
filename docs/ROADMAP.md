# Roadmap

This document outlines the development roadmap for zigconfig, a configuration
library for Zig 0.16.0.

## Current Status (v0.3.x)

The library has moved well beyond its initial foundation. Core functionality,
enhanced loading, advanced features, and security hardening are all in place.
The focus is now shifting toward API completeness, stability, and production
readiness.

### What ships today

- Multi-format parsing: YAML, JSON, TOML, INI, Java Properties, dotenv
- Typed configuration loader with precedence, merging, and serialization
- XDG Base Directory support with cross-platform environment variables
- Provenance tracking for every configuration value
- Secret handling: file/stdin, Vault, 1Password, SensitiveString redaction
- Encrypted secrets with pluggable backends
- Environment variable expansion and dotenv apply()
- Command-line flag parsing
- Custom validation with regex patterns and ReDoS hardening
- Configuration hot-reload (watch) and async loading
- Remote configuration stores (etcd, Consul) with SSRF protection
- Configuration diffing
- SafeWriteConfig to prevent overwriting
- Parallel file loading
- Array indexing in key paths (dot-notation numeric indices e.g. `servers.0.host`, bracket-to-dot normalization e.g. `servers[0].host` → `servers.0.host`; negative indexing and array slicing are not supported), case-insensitive keys, key aliases
- Multiple search paths via addConfigPath
- Files without extension (content-based format detection)
- YAML parsing for flat key:value structures; nested YAML parsing planned (#4)
- Centralized resource limits (limits.zig)
- Security hardening: SSRF protection, path traversal guards, binary allowlists
- Arena allocators for predictable memory management
- CI pipeline: build, test (4 optimization modes), fuzz, security scanning, SBOM

See [VIPER_COMPARISON.md](./VIPER_COMPARISON.md) for feature parity analysis with Viper.

---

## v0.1.0 - Foundation (Complete)

**Focus:** Core functionality and project scaffolding.

- [x] Multi-format parsing (YAML, JSON, TOML)
- [x] Unified Value API
- [x] Typed Loader with precedence
- [x] XDG directory support
- [x] Secret handling (file/stdin)
- [x] Basic validation utilities
- [x] Provenance tracking
- [x] Dotenv parsing
- [x] Unit tests

## v0.2.0 - Enhanced Loading (Complete)

**Focus:** Viper-like loading features, environment integration, and validation.

### Bug Fixes

- [x] [#6 - Implement dotenv apply() function](https://gitlab.com/devnw/zig/config/-/issues/6) -- (creates EnvMap; does not set OS env vars)
- [x] [#7 - Fix envVarName() construction](https://gitlab.com/devnw/zig/config/-/issues/7)

### Core Enhancements

- [ ] [#4 - Enhance nested YAML parsing in Loader](https://gitlab.com/devnw/zig/config/-/issues/4) -- parseSimpleYaml is flat key:value only; nested YAML not yet implemented
- [x] [#8 - Add command-line flag parsing](https://gitlab.com/devnw/zig/config/-/issues/8) -- src/flags.zig
- [x] [#9 - Improve memory management](https://gitlab.com/devnw/zig/config/-/issues/9) -- arena allocators, src/limits.zig
- [x] [#17 - Add configuration merging utilities](https://gitlab.com/devnw/zig/config/-/issues/17) -- src/merge.zig
- [x] [#19 - Add configuration serialization](https://gitlab.com/devnw/zig/config/-/issues/19) -- src/serialize.zig
- [x] [#22 - Add environment variable expansion](https://gitlab.com/devnw/zig/config/-/issues/22) -- src/expand.zig

### Validation

- [x] [#11 - Add custom validation functions](https://gitlab.com/devnw/zig/config/-/issues/11) -- src/validation.zig

### Viper Parity Features

- [x] [#26 - Runtime Set() for explicit overrides](https://gitlab.com/devnw/zig/config/-/issues/26)
- [x] [#28 - Multiple config file search paths](https://gitlab.com/devnw/zig/config/-/issues/28) -- addConfigPath
- [x] [#29 - SafeWriteConfig to prevent overwriting](https://gitlab.com/devnw/zig/config/-/issues/29) -- src/config.zig
- [x] [#30 - BindEnv for explicit env binding](https://gitlab.com/devnw/zig/config/-/issues/30)
- [x] [#31 - AutomaticEnv for prefix discovery](https://gitlab.com/devnw/zig/config/-/issues/31)
- [x] [#32 - Env key replacer/transformer](https://gitlab.com/devnw/zig/config/-/issues/32)
- [x] [#33 - Key aliases support](https://gitlab.com/devnw/zig/config/-/issues/33) -- src/loader.zig
- [x] [#34 - Case-insensitive key access](https://gitlab.com/devnw/zig/config/-/issues/34) -- normalizeKey in loader.zig
- [x] [#35 - Array indexing in paths](https://gitlab.com/devnw/zig/config/-/issues/35) -- src/loader.zig (bracket notation and JSON array flattening)
- [x] [#41 - SetDefault() for runtime defaults](https://gitlab.com/devnw/zig/config/-/issues/41)
- [x] [#42 - IsSet() to check explicit set](https://gitlab.com/devnw/zig/config/-/issues/42)

## v0.3.0 - Advanced Features (Complete)

**Focus:** Extended formats, remote configuration, async, hot-reload, encryption, and security hardening.

### Format Support

- [x] [#24 - Add INI file format support](https://gitlab.com/devnw/zig/config/-/issues/24) -- src/ini.zig
- [x] [#25 - Add Java Properties format support](https://gitlab.com/devnw/zig/config/-/issues/25) -- src/properties.zig
- [x] [#44 - Config files without extension](https://gitlab.com/devnw/zig/config/-/issues/44) -- detectFormatFromContent

### Remote Configuration

- [x] [#27 - Remote config stores (etcd, Consul)](https://gitlab.com/devnw/zig/config/-/issues/27) -- src/remote.zig with SSRF protection (etcd/Consul; NATS not implemented)

### Advanced Features

- [x] [#10 - Add regex pattern validation](https://gitlab.com/devnw/zig/config/-/issues/10) -- src/validation.zig with ReDoS hardening
- [x] [#15 - Add configuration hot-reload](https://gitlab.com/devnw/zig/config/-/issues/15) -- src/watch.zig
- [x] [#16 - Add async configuration loading](https://gitlab.com/devnw/zig/config/-/issues/16) -- src/async.zig
- [x] [#18 - Add encrypted secrets support](https://gitlab.com/devnw/zig/config/-/issues/18) -- src/encrypted_secrets.zig (Vault, 1Password)
- [x] [#20 - Add configuration diff utilities](https://gitlab.com/devnw/zig/config/-/issues/20) -- src/diff.zig

### Security and Infrastructure (not tracked by original issues)

- [x] SSRF protection for remote config backends
- [x] Path traversal guards
- [x] Binary allowlists for secret providers
- [x] SensitiveString credential redaction
- [x] Centralized resource limits -- src/limits.zig
- [x] Parallel file loading -- src/parallel.zig
- [x] Cross-platform environment variable handling -- src/environ.zig
- [x] CI pipeline: build, test (Debug + ReleaseSafe + ReleaseFast + ReleaseSmall), fuzz, security scanning, SBOM generation

---

## v0.4.0 - API Completeness

**Focus:** Fill remaining Viper parity gaps and add extensibility hooks.

### Viper Parity

- [x] [#36 - Sub() for config subset extraction](https://gitlab.com/devnw/zig/config/-/issues/36) -- `sub()`/`hasSub()` in src/loader.zig
- [x] [#37 - AllSettings() export](https://gitlab.com/devnw/zig/config/-/issues/37) -- implemented at loader.zig:299
- [ ] [#38 - parseReader() for io.Reader input](https://gitlab.com/devnw/zig/config/-/issues/38)
- [x] [#43 - AllKeys() to list keys](https://gitlab.com/devnw/zig/config/-/issues/43) -- implemented at loader.zig:284

### Extensibility

- [x] [#39 - Custom format decoders](https://gitlab.com/devnw/zig/config/-/issues/39) -- FormatRegistry in config.zig
- [x] [#40 - Configurable key delimiter](https://gitlab.com/devnw/zig/config/-/issues/40) -- implemented at loader.zig:401

### Validation

- [ ] [#5 - Add JSON Schema validation](https://gitlab.com/devnw/zig/config/-/issues/5)

### Platform Support

- [x] [#12 - Windows/macOS XDG equivalents](https://gitlab.com/devnw/zig/config/-/issues/12) -- environ.zig provides cross-platform env vars; closed in GitLab

## v0.5.0 - Extended Formats and Encryption

**Focus:** Additional configuration languages and encryption backends.

### Format Support

- [ ] [#85 - HCL format](https://gitlab.com/devnw/zig/config/-/issues/85)
- [ ] [#86 - HOCON format](https://gitlab.com/devnw/zig/config/-/issues/86)

### Encryption

- [ ] [#87 - SOPS integration](https://gitlab.com/devnw/zig/config/-/issues/87)
- [ ] [#88 - age/GPG encrypted files](https://gitlab.com/devnw/zig/config/-/issues/88)

## v1.0.0 - Stable Release

**Focus:** API stability guarantee, comprehensive documentation, and production-grade quality.

### Requirements

- [ ] API stability guarantee -- no breaking changes after this release
- [ ] [#14 - Test coverage reporting](https://gitlab.com/devnw/zig/config/-/issues/14)
- [ ] 80%+ test coverage
- [ ] [#21 - API documentation generation](https://gitlab.com/devnw/zig/config/-/issues/21)
- [x] [#89 - Performance benchmarks](https://gitlab.com/devnw/zig/config/-/issues/89) -- implemented in bench.zig
- [ ] Migration guide from v0.x
- [ ] Full Viper feature parity (core features)
- [ ] All v0.4.0 and v0.5.0 items complete or explicitly deferred

---

## Issue Summary

| Milestone | Issues | Status |
|-----------|--------|--------|
| v0.1.0 | 8 | Complete |
| v0.2.0 | 18 | Complete |
| v0.3.0 | 13 | Complete |
| v0.4.0 | 7 | Planned |
| v0.5.0 | 4 | Planned |
| v1.0.0 | 6 | Planned |

## Contributing

Want to help? See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Priority areas:

1. Viper parity gaps (v0.4.0): parseReader() (#38)
2. JSON Schema validation (#5)
3. Nested YAML parsing (#4)
4. Test coverage improvements
5. Documentation enhancements

## Feedback

We welcome feedback on this roadmap. Open an issue to discuss:

- Feature prioritization
- New feature requests
- Use cases we should support
