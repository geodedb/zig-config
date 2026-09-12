# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.13] - 2026-09-12

### Changed

- Converge json v0.1.15, yaml v0.1.8, toml v0.1.13 sibling pins (GAP-0838 diamond sync); includes the allocation-failure fixes from d6a6399.

## [0.1.6] - 2026-06-12

Security, correctness, and migration-completeness release closing a full appsec +
codebase audit (Wave 15). The 0.15→0.16 migration was completed across cold
public-API paths that had never been compile-checked, and a `refAllInRepo` compile
guard plus `zig build check` coverage of examples and the benchmark were added so
the issue cannot recur. Test count grew from 415 to 1036.

### Security

- Fail-closed SSRF host validation for non-literal hostnames under
  `block_private_ips`, with a new `SecurityOptions.allowed_hosts` allowlist (AS-01).
- Fixed a use-after-free in the async/parallel loaders by transferring arena
  ownership to the caller via the new `OwnedConfig(T)` (`loadParallel` now returns
  `OwnedConfig(T)`) (S-NEW-01).
- Added a mutex to `Watcher` to remove a data race on the watch list (S-NEW-02).
- Subprocess secret providers: drain stderr concurrently and use a
  futex-wakeable watchdog with process-group SIGKILL; close child descriptors only
  after reader threads are joined (AS-04 / Q-NEW-04 / F-01).
- Symlink guard on the config backup path (AS-02); empty-argv panic fix (AS-03);
  thread-safe allocator for parallel workers (S-NEW-03).
- Opt-in, backward-compatible controls: `ExpandOptions.allowed_vars` /
  `denied_vars` / `deny_secret_looking` for environment expansion (S-NEW-04), and
  redaction for diff/provenance output via `formatDiffWithOptions` /
  `printJsonRedacted` (S-NEW-05).

### Fixed

- Completed Zig 0.16 migration of cold paths (serialization, `parseArgs`, XDG path
  helpers, diff formatting, parallel ops, secret stdin, benchmark, examples).
- Implemented real parallel file load/serialize (were stubs returning null).
- Memory/secret-hygiene fixes: temp-path leaks on error, `Consul.get` /
  `mergeMaps` leaks, `secureZero` before free on OOM paths.
- Error-handling: propagate real `parseFile`/`dotenv.load` errors instead of
  masking; format large floats without dropping fields.
- Performance: transient stack-buffer key normalization on read paths (no per-read
  arena growth), INI section-pointer caching, hoisted properties scratch buffers.

### Changed

- `minimum_zig_version` is now `0.16.0`. **Breaking:** `FlagParser.parseArgs` now
  takes the process args slice (Zig 0.16 no longer exposes argv globally), and
  `loadParallel` returns `OwnedConfig(T)` (call `.deinit()`).

### Documentation

- Corrected version references (0.15.2 → 0.16.0), the `config.validate` alias, and
  drifted API/example snippets in README, API.md, and VIPER_COMPARISON.md.

## [0.1.0] - 2026-01-24

Initial open source release under Apache-2.0 license. This release consolidates all previous development work.

### Added
- Integration tests now run as part of `zig build test`
- `zig build test-integration` build step for integration fixtures

### Changed
- Updated yaml, toml, and json dependencies to use GitLab archive URLs

### Development History (pre-release)

### Added
- **INI format support** ([#24])
  - ini.zig module with section and key-value parsing
  - Comment support (# and ;)
  - Section headers ([section])
- **Java Properties format support** ([#25])
  - properties.zig module for .properties files
  - Key=value and key:value syntax
  - Continuation lines with backslash
- **File watching and hot-reload** ([#15])
  - watch.zig module with polling-based file watcher
  - Watcher struct with addPath/removePath/start/stop
  - ChangeEvent enum (modified, deleted, created)
  - ConfigReloader for automatic config refresh
- **Remote configuration support** ([#27])
  - remote.zig with etcd v3 API client
  - remote.zig with Consul KV client
  - RemoteProvider unified interface
  - get/put/delete/getPrefix operations
- **Async/parallel configuration loading** ([#16])
  - async.zig with AsyncLoader for background loading
  - loadParallel() for concurrent file loading
  - AsyncLoaderWithCallback for completion callbacks
- **Configuration diffing and comparison** ([#20])
  - diff.zig with compare/compareWithOptions
  - ChangeType enum (added, removed, modified, unchanged)
  - DiffResult with change counts
  - formatDiff() for human-readable reports
  - merge() with configurable strategies
- **Advanced validation patterns** ([#10], [#11])
  - validation.zig with regex-like pattern matching
  - isEmail, isUrl, isIPv4, isPort, isHostname validators
  - matchPattern for custom patterns
- **Safe file writing utilities**
  - safeWriteToFile() - atomic write with temp file + rename
  - writeToFileIfNotExists() - create only if missing
  - writeToFileWithBackup() - backup before overwrite
- Dotenv EnvMap with get/getOrEnv/has/count/iterator ([#6])
- Dotenv loadAndApply() and applyContent() functions
- Loader memory management improvements ([#9])
  - Arena allocator for all string allocations
  - Strings properly copied to outlive source buffers
  - reset() method to clear and reload configuration
  - Support for float types (f32, f64)
  - Support for optional types (?T)
- Windows and macOS platform-specific paths ([#12])
  - Platform enum for cross-platform path detection
  - macOS: ~/Library/Preferences, ~/Library/Application Support, ~/Library/Caches
  - Windows: %APPDATA%, %LOCALAPPDATA%, %PROGRAMDATA%
  - Platform-specific getConfigDirForPlatform, getDataDirForPlatform, getCacheDirForPlatform
- Configuration merging utilities ([#17])
  - merge.zig module with mergeStructs, mergeMany, mergePreferOverlay
  - MergeStrategy and MergeOptions for conflict resolution
  - Smart default detection (overlay defaults don't override base values)
- Encrypted secrets support with multiple providers ([#18])
  - SecretManager with provider abstraction
  - AWS KMS provider configuration
  - HashiCorp Vault provider with kv get support
  - 1Password CLI (op) provider support
  - Encrypted file provider with AES-256-GCM
  - Secret reference parsing (provider://path#field@version)
- Configuration serialization/write support ([#19])
  - serialize.zig module with JSON, YAML, TOML, ENV output
  - Pretty-printed and compact JSON options
  - writeToFile() for direct file output
- Environment variable expansion ([#22])
  - expand.zig module with ${VAR} and $VAR syntax
- Multiple config search paths ([#28])
  - addConfigPath() to add search directories
  - setConfigName() to set filename without extension
  - Automatic extension detection (.toml, .yaml, .yml, .json)
  - getSearchPaths() to retrieve configured paths
- Array indexing support ([#35])
  - getPath() for dot-notation with numeric indices (servers.0.host)
- Sub-configuration extraction ([#36])
  - sub() to extract config subset by prefix (Viper's Sub)
  - hasSub() to check if sub-configuration exists
- Configuration export utilities ([#37])
  - allSettings() returns all key-value pairs as HashMap
- All keys enumeration ([#43])
  - allKeys() returns list of all configuration keys
- Command-line flag parsing integration ([#8])
  - `FlagParser` for parsing command-line arguments
  - Support for long flags (`--config`), short flags (`-c`), boolean flags
  - Flag binding to configuration keys
  - Integration with Loader via `applyFlags()`
- Integration tests with file fixtures ([#13])
  - Test fixtures for YAML, JSON, TOML, and dotenv formats
  - Cross-format consistency tests
  - Loader integration tests with flag parsing
- API documentation generation ([#21])
  - `zig build docs` generates HTML autodocs
  - Quick reference in docs/API.md
- Examples directory with usage examples ([#3])
  - basic_parsing.zig - Multi-format parsing
  - typed_loader.zig - Type-safe loader with Viper features
  - flag_parsing.zig - Command-line integration
  - secret_handling.zig - Secure secrets
  - validation.zig - Configuration validation
  - xdg_paths.zig - XDG directories
  - dotenv_loading.zig - Dotenv parsing
- Build system improvements
  - `zig build examples` to build all examples
  - `zig build run-<example>` to run specific examples
- CHANGELOG.md following Keep a Changelog format ([#2])

### Fixed
- `buildEnvVarName()` now properly adds underscore separator between prefix and field ([#7])
  - `MYAPP` + `host` now correctly produces `MYAPP_HOST`
- Memory leak in loader when loading XDG config paths

[#2]: https://gitlab.com/devnw/zig/config/-/issues/2
[#3]: https://gitlab.com/devnw/zig/config/-/issues/3
[#6]: https://gitlab.com/devnw/zig/config/-/issues/6
[#7]: https://gitlab.com/devnw/zig/config/-/issues/7
[#8]: https://gitlab.com/devnw/zig/config/-/issues/8
[#9]: https://gitlab.com/devnw/zig/config/-/issues/9
[#10]: https://gitlab.com/devnw/zig/config/-/issues/10
[#11]: https://gitlab.com/devnw/zig/config/-/issues/11
[#12]: https://gitlab.com/devnw/zig/config/-/issues/12
[#13]: https://gitlab.com/devnw/zig/config/-/issues/13
[#15]: https://gitlab.com/devnw/zig/config/-/issues/15
[#16]: https://gitlab.com/devnw/zig/config/-/issues/16
[#17]: https://gitlab.com/devnw/zig/config/-/issues/17
[#18]: https://gitlab.com/devnw/zig/config/-/issues/18
[#19]: https://gitlab.com/devnw/zig/config/-/issues/19
[#20]: https://gitlab.com/devnw/zig/config/-/issues/20
[#21]: https://gitlab.com/devnw/zig/config/-/issues/21
[#22]: https://gitlab.com/devnw/zig/config/-/issues/22
[#24]: https://gitlab.com/devnw/zig/config/-/issues/24
[#25]: https://gitlab.com/devnw/zig/config/-/issues/25
[#27]: https://gitlab.com/devnw/zig/config/-/issues/27
[#28]: https://gitlab.com/devnw/zig/config/-/issues/28
[#35]: https://gitlab.com/devnw/zig/config/-/issues/35
[#36]: https://gitlab.com/devnw/zig/config/-/issues/36
[#37]: https://gitlab.com/devnw/zig/config/-/issues/37
[#43]: https://gitlab.com/devnw/zig/config/-/issues/43

## [0.1.0] - 2024-12-31

### Added
- Multi-format configuration parsing (YAML, JSON, TOML)
- Unified Value API with dot notation path access
- Type-safe generic Loader with compile-time struct validation
- XDG Base Directory Specification compliance
- Configuration precedence system (override > flag > env > project > user > system > runtime_default > default)
- Provenance tracking to identify value sources
- Secure secret handling (file/stdin only, never from flags/env)
- Built-in validation utilities (required, minLength, maxLength, port, hostname, url, email, intRange, oneOf)
- Dotenv file parsing
- Runtime Set() for explicit value overrides ([#26])
- SetDefault() for runtime default values ([#41])
- BindEnv() for explicit environment variable binding ([#30])
- AutomaticEnv() for prefix-based env discovery ([#31])
- SetEnvKeyReplacer() for environment key transformation ([#32])
- Key aliases support via registerAlias() ([#33])
- Case-insensitive key access option ([#34])
- IsSet() to check if key was explicitly set ([#42])
- has() and get() methods for value checking

### Infrastructure
- GitLab CI/CD pipeline with SAST and Secret Detection
- External YAML, TOML, and JSON parsing libraries

## [0.0.1] - 2024-12-30

### Added
- Initial project structure
- Basic configuration parsing framework

[Unreleased]: https://gitlab.com/devnw/zig/config/-/compare/v0.1.0...HEAD
[0.1.0]: https://gitlab.com/devnw/zig/config/-/releases/v0.1.0

[#26]: https://gitlab.com/devnw/zig/config/-/issues/26
[#30]: https://gitlab.com/devnw/zig/config/-/issues/30
[#31]: https://gitlab.com/devnw/zig/config/-/issues/31
[#32]: https://gitlab.com/devnw/zig/config/-/issues/32
[#33]: https://gitlab.com/devnw/zig/config/-/issues/33
[#34]: https://gitlab.com/devnw/zig/config/-/issues/34
[#41]: https://gitlab.com/devnw/zig/config/-/issues/41
[#42]: https://gitlab.com/devnw/zig/config/-/issues/42
