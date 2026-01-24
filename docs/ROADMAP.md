# Roadmap

This document outlines the development roadmap for zigconfig.

## Current Status

The library is in active development with core functionality implemented:

- YAML/JSON/TOML parsing
- Typed configuration loader
- XDG Base Directory support
- Provenance tracking
- Secret handling
- Basic validation

See [VIPER_COMPARISON.md](./VIPER_COMPARISON.md) for feature parity analysis with Viper.

## v0.1.0 - Foundation (Current)

**Focus:** Complete core functionality and documentation.

### Completed

- [x] Multi-format parsing (YAML, JSON, TOML)
- [x] Unified Value API
- [x] Typed Loader with precedence
- [x] XDG directory support
- [x] Secret handling (file/stdin)
- [x] Basic validation utilities
- [x] Provenance tracking
- [x] Dotenv parsing
- [x] Unit tests

### In Progress

- [ ] [#1 - Add LICENSE file](https://gitlab.com/devnw/zig/config/-/issues/1)
- [ ] [#2 - Add CHANGELOG.md](https://gitlab.com/devnw/zig/config/-/issues/2)
- [ ] [#3 - Create examples directory](https://gitlab.com/devnw/zig/config/-/issues/3)
- [ ] [#13 - Add integration tests](https://gitlab.com/devnw/zig/config/-/issues/13)
- [ ] [#23 - Update project metadata](https://gitlab.com/devnw/zig/config/-/issues/23)

## v0.2.0 - Enhanced Loading

**Focus:** Improve configuration loading with Viper-like features.

### Bug Fixes

- [ ] [#6 - Implement dotenv apply() function](https://gitlab.com/devnw/zig/config/-/issues/6)
- [ ] [#7 - Fix envVarName() construction](https://gitlab.com/devnw/zig/config/-/issues/7)

### Core Enhancements

- [ ] [#4 - Enhance nested YAML parsing in Loader](https://gitlab.com/devnw/zig/config/-/issues/4)
- [ ] [#8 - Add command-line flag parsing](https://gitlab.com/devnw/zig/config/-/issues/8)
- [ ] [#9 - Improve memory management](https://gitlab.com/devnw/zig/config/-/issues/9)
- [ ] [#17 - Add configuration merging utilities](https://gitlab.com/devnw/zig/config/-/issues/17)
- [ ] [#19 - Add configuration serialization](https://gitlab.com/devnw/zig/config/-/issues/19)
- [ ] [#22 - Add environment variable expansion](https://gitlab.com/devnw/zig/config/-/issues/22)

### Viper Parity Features

#### Completed
- [x] [#26 - Runtime Set() for explicit overrides](https://gitlab.com/devnw/zig/config/-/issues/26)
- [x] [#30 - BindEnv for explicit env binding](https://gitlab.com/devnw/zig/config/-/issues/30)
- [x] [#31 - AutomaticEnv for prefix discovery](https://gitlab.com/devnw/zig/config/-/issues/31)
- [x] [#32 - Env key replacer/transformer](https://gitlab.com/devnw/zig/config/-/issues/32)
- [x] [#33 - Key aliases support](https://gitlab.com/devnw/zig/config/-/issues/33)
- [x] [#34 - Case-insensitive key access](https://gitlab.com/devnw/zig/config/-/issues/34)
- [x] [#41 - SetDefault() for runtime defaults](https://gitlab.com/devnw/zig/config/-/issues/41)
- [x] [#42 - IsSet() to check explicit set](https://gitlab.com/devnw/zig/config/-/issues/42)

#### Planned
- [ ] [#28 - Multiple config file search paths](https://gitlab.com/devnw/zig/config/-/issues/28)
- [ ] [#29 - SafeWriteConfig to prevent overwriting](https://gitlab.com/devnw/zig/config/-/issues/29)
- [ ] [#35 - Array indexing in paths](https://gitlab.com/devnw/zig/config/-/issues/35)
- [ ] [#36 - Sub() for config subset extraction](https://gitlab.com/devnw/zig/config/-/issues/36)
- [ ] [#37 - AllSettings() export](https://gitlab.com/devnw/zig/config/-/issues/37)
- [ ] [#38 - parseReader() for io.Reader input](https://gitlab.com/devnw/zig/config/-/issues/38)
- [ ] [#43 - AllKeys() to list keys](https://gitlab.com/devnw/zig/config/-/issues/43)

### Validation

- [ ] [#11 - Add custom validation functions](https://gitlab.com/devnw/zig/config/-/issues/11)

## v0.3.0 - Advanced Features

**Focus:** Advanced features, cross-platform, and extended format support.

### Format Support

- [ ] [#24 - Add INI file format support](https://gitlab.com/devnw/zig/config/-/issues/24)
- [ ] [#25 - Add Java Properties format support](https://gitlab.com/devnw/zig/config/-/issues/25)
- [ ] [#39 - Custom format decoders (extensibility)](https://gitlab.com/devnw/zig/config/-/issues/39)
- [ ] [#44 - Config files without extension](https://gitlab.com/devnw/zig/config/-/issues/44)

### Remote Configuration

- [ ] [#27 - Remote config stores (etcd, Consul, NATS)](https://gitlab.com/devnw/zig/config/-/issues/27)

### Advanced Features

- [ ] [#5 - Add JSON Schema validation](https://gitlab.com/devnw/zig/config/-/issues/5)
- [ ] [#10 - Add regex pattern validation](https://gitlab.com/devnw/zig/config/-/issues/10)
- [ ] [#15 - Add configuration hot-reload](https://gitlab.com/devnw/zig/config/-/issues/15)
- [ ] [#16 - Add async configuration loading](https://gitlab.com/devnw/zig/config/-/issues/16)
- [ ] [#18 - Add encrypted secrets support](https://gitlab.com/devnw/zig/config/-/issues/18)
- [ ] [#20 - Add configuration diff utilities](https://gitlab.com/devnw/zig/config/-/issues/20)
- [ ] [#33 - Key aliases support](https://gitlab.com/devnw/zig/config/-/issues/33)
- [ ] [#40 - Configurable key delimiter](https://gitlab.com/devnw/zig/config/-/issues/40)

### Platform Support

- [ ] [#12 - Add Windows/macOS XDG equivalents](https://gitlab.com/devnw/zig/config/-/issues/12)

## v1.0.0 - Stable Release

**Focus:** API stability, comprehensive documentation, and full test coverage.

### Requirements

- [ ] [#14 - Add test coverage reporting](https://gitlab.com/devnw/zig/config/-/issues/14)
- [ ] [#21 - Add API documentation generation](https://gitlab.com/devnw/zig/config/-/issues/21)
- [ ] API stability guarantee
- [ ] 80%+ test coverage
- [ ] Performance benchmarks
- [ ] Migration guide from previous versions
- [ ] Full Viper feature parity (core features)

## Issue Summary

| Milestone | Total Issues | Priority Breakdown |
|-----------|--------------|-------------------|
| v0.1.0 | 5 | 1 critical, 3 high, 1 low |
| v0.2.0 | 23 | 3 high, 17 medium, 3 low |
| v0.3.0 | 12 | 2 medium, 10 low |
| v1.0.0 | 4 | 1 high, 3 low |

## Contributing

Want to help? See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Priority areas:
1. Issues labeled `priority::critical` or `priority::high`
2. Viper parity features (v0.2.0 milestone)
3. Test coverage improvements
4. Documentation enhancements

## Feedback

We welcome feedback on this roadmap! Open an issue to discuss:
- Feature prioritization
- New feature requests
- Use cases we should support
