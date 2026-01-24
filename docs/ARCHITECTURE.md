# Architecture

This document describes the architecture of the zigconfig library.

## Module Structure

```
src/
├── config.zig      # Main entry point and unified API
├── loader.zig      # Configuration loading with precedence
├── provenance.zig  # Value source tracking
├── xdg.zig         # XDG Base Directory support
├── dotenv.zig      # .env file parsing
├── secret.zig      # Secure secret handling
└── validate.zig    # Validation utilities
```

## Core Concepts

### Unified Value API (`config.zig`)

The `Value` type provides a format-agnostic interface for working with configuration data:

```zig
pub const Value = struct {
    pub fn getString(self: Self, path: []const u8) ?[]const u8;
    pub fn getInt(self: Self, path: []const u8) ?i64;
    pub fn getBool(self: Self, path: []const u8) ?bool;
    pub fn getPath(self: Self, path: []const u8) ?Self;
    // ...
};
```

Supported formats:
- **YAML** - Using external yaml library
- **JSON** - Using std.json for parsing
- **TOML** - Using external toml library

### Typed Loader (`loader.zig`)

The `Loader(T)` generic provides type-safe configuration loading:

```zig
pub fn Loader(comptime T: type) type {
    return struct {
        pub fn init(allocator: Allocator) Self;
        pub fn load(self: *Self, options: LoadOptions) LoadError!T;
        pub fn getTracker(self: *const Self) *const ProvenanceTracker;
    };
}
```

### Configuration Precedence

Values are loaded in this order (later sources override earlier):

1. **default** - Struct field default values
2. **system** - `/etc/APP/config.toml`
3. **user** - `~/.config/APP/config.toml`
4. **project** - `./config.toml`
5. **env** - Environment variables (`PREFIX_FIELD`)
6. **flag** - Command-line overrides (highest priority)

See: [#8 - Add command-line flag parsing](https://gitlab.com/devnw/zig/config/-/issues/8)

### Provenance Tracking (`provenance.zig`)

Every configuration value can be traced to its source:

```zig
pub const Source = enum {
    flag, env, project, user, system, default
};

pub const TrackedValue = struct {
    key: []const u8,
    value: []const u8,
    source: Source,
    source_path: ?[]const u8,
};
```

### XDG Support (`xdg.zig`)

Implements XDG Base Directory Specification:

| Directory | Default | Environment Variable |
|-----------|---------|---------------------|
| Config | `~/.config` | `XDG_CONFIG_HOME` |
| Data | `~/.local/share` | `XDG_DATA_HOME` |
| Cache | `~/.cache` | `XDG_CACHE_HOME` |
| State | `~/.local/state` | `XDG_STATE_HOME` |

See: [#12 - Add Windows and macOS XDG equivalent paths](https://gitlab.com/devnw/zig/config/-/issues/12)

### Secret Handling (`secret.zig`)

Secure handling of sensitive values:

- **Never** accept secrets from flags or environment variables
- Read secrets only from files or stdin
- Secure memory zeroing when done
- Redaction for logging

See: [#18 - Add encrypted secrets support](https://gitlab.com/devnw/zig/config/-/issues/18)

### Validation (`validate.zig`)

Built-in validators:

| Function | Description |
|----------|-------------|
| `required()` | Value must be non-empty |
| `minLength()` | Minimum string length |
| `maxLength()` | Maximum string length |
| `intRange()` | Integer within range |
| `oneOf()` | Value in allowed set |
| `port()` | Valid port number |
| `hostname()` | Valid hostname |
| `url()` | Valid HTTP(S) URL |
| `email()` | Basic email format |
| `pathExists()` | File/directory exists |

See: [#10 - Add regex pattern validation](https://gitlab.com/devnw/zig/config/-/issues/10)

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Config File │────▶│   Parser    │────▶│    Value    │
│ (YAML/JSON/ │     │  (format-   │     │  (unified   │
│   TOML)     │     │  specific)  │     │   API)      │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Typed     │◀────│   Loader    │◀────│ Precedence  │
│   Config    │     │  (generic)  │     │   Merge     │
│   Struct    │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Provenance  │
                    │  Tracker    │
                    └─────────────┘
```

## Dependencies

External Zig libraries:
- `yaml` - YAML parsing
- `toml` - TOML parsing
- `json` - JSON Schema (future validation)

## Future Enhancements

- [#5 - JSON Schema validation](https://gitlab.com/devnw/zig/config/-/issues/5)
- [#15 - Hot-reload support](https://gitlab.com/devnw/zig/config/-/issues/15)
- [#16 - Async loading](https://gitlab.com/devnw/zig/config/-/issues/16)
- [#17 - Configuration merging utilities](https://gitlab.com/devnw/zig/config/-/issues/17)
- [#19 - Configuration serialization](https://gitlab.com/devnw/zig/config/-/issues/19)
