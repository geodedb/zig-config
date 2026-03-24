# zigconfig

A comprehensive configuration management library for Zig 0.15.2, inspired by [Viper](https://github.com/spf13/viper).

[![GitLab](https://img.shields.io/badge/GitLab-devnw%2Fzig%2Fconfig-orange)](https://gitlab.com/devnw/zig/config)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Status

| Aspect | Info |
|--------|------|
| API Stability | Beta |
| Zig Version | 0.15.2 |
| Platforms | Linux, macOS, Windows |

## Features

- **Multi-format support** - YAML, JSON, TOML, INI, Properties, Dotenv with unified API
- **Type-safe loading** - Generic Loader with compile-time struct validation
- **XDG compliance** - Respects XDG Base Directory Specification
- **Cross-platform** - Native paths for Linux, macOS, and Windows
- **Precedence rules** - override > flags > env > project > user > system > runtime_default > defaults
- **Secure secrets** - File/stdin only, never flags/env (unlike Viper!)
- **Encrypted secrets** - HashiCorp Vault and 1Password CLI providers (AWS KMS, GCP KMS, and encrypted-file-at-rest are not currently supported)
- **Validation** - Built-in validators for common patterns (email, URL, IPv4, port, etc.)
- **Provenance tracking** - Know exactly where each value came from (unique to zigconfig)
- **Command-line flags** - Full flag parsing with FlagParser
- **Hot-reload** - File watching with automatic config refresh
- **Remote config** - etcd v3 and Consul KV store support
- **Async loading** - Parallel configuration file loading
- **Config diffing** - Compare configurations and detect changes
- **Serialization** - Export to JSON, YAML, TOML, or ENV format
- **Runtime overrides** - Set() and SetDefault() for runtime configuration
- **Environment binding** - BindEnv(), AutomaticEnv(), and key replacers
- **Key aliases** - Register aliases for configuration keys
- **Case-insensitive access** - Optional case-insensitive key matching

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .config = .{
        .url = "https://gitlab.com/devnw/zig/config/-/archive/main/config-main.tar.gz",
        // .hash = "...",  // Add after first fetch
    },
},
```

Then in your `build.zig`:

```zig
const config = b.dependency("config", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("config", config.module("config"));
```

## Quick Start

### Unified Value API

Parse any configuration format with a single API:

```zig
const config = @import("config");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse any config file - format is auto-detected from extension
    var value = try config.parseFile(allocator, "config.yaml");
    defer value.deinit();

    // Access nested values with dot notation
    const host = value.getString("server.host") orelse "localhost";
    const port = value.getInt("server.port") orelse 8080;
    const debug = value.getBool("debug") orelse false;

    std.debug.print("Server: {s}:{d} (debug: {})\n", .{ host, port, debug });
}
```

### Typed Configuration Loader

For type-safe configuration with defaults:

```zig
const config = @import("config");

const AppConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    debug: bool = false,
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var loader = config.Loader(AppConfig).init(allocator);
    defer loader.deinit();

    const cfg = try loader.load(.{
        .app_name = "myapp",
        .filename = "config.toml",
        .env_prefix = "MYAPP_",
    });

    // cfg is now populated from all sources with proper precedence
}
```

## API Reference

### Configuration Parsing

```zig
// Parse from file (format auto-detected from extension)
pub fn parseFile(allocator: Allocator, path: []const u8) !Value;

// Parse from content with explicit format
pub fn parseContent(allocator: Allocator, content: []const u8, format: Format) !Value;
```

### Value Access

```zig
pub const Value = struct {
    pub fn getString(self: Self, path: []const u8) ?[]const u8;
    pub fn getInt(self: Self, path: []const u8) ?i64;
    pub fn getFloat(self: Self, path: []const u8) ?f64;
    pub fn getBool(self: Self, path: []const u8) ?bool;
    pub fn has(self: Self, path: []const u8) bool;
    pub fn getList(self: Self, path: []const u8) ?[]Self;
    pub fn deinit(self: *Self) void;
};
```

### XDG Directories

```zig
const xdg = config.xdg;

// Get XDG-compliant config directory for your app
const config_dir = try xdg.getConfigDir(allocator, "myapp");
// Returns: ~/.config/myapp (or $XDG_CONFIG_HOME/myapp)

const data_dir = try xdg.getDataDir(allocator, "myapp");
// Returns: ~/.local/share/myapp

const cache_dir = try xdg.getCacheDir(allocator, "myapp");
// Returns: ~/.cache/myapp
```

### Secret Handling

```zig
const secret = config.secret;

// Read secrets only from files (never from flags/env!)
const password = try secret.readFromFile("/run/secrets/password", allocator);

// Or read from stdin (for interactive or piped input)
const token = try secret.readFromStdin(allocator);

// Safely redact for logging
std.debug.print("Password: {s}\n", .{secret.redact(password)});
// Output: Password: ***REDACTED***

// Securely zero memory when done
secret.secureZero(password);
```

### Validation

```zig
const validate = config.validate;

// Validate configuration values
try validate.required(host);
try validate.minLength(password, 8);
try validate.maxLength(username, 64);
try validate.port(port);
try validate.hostname(host);
try validate.url(endpoint);
try validate.email(contact);
try validate.intRange(timeout, 1, 3600);
try validate.oneOf(log_level, &.{ "debug", "info", "warn", "error" });
```

### Provenance Tracking

```zig
var loader = config.Loader(AppConfig).init(allocator);
defer loader.deinit();

_ = try loader.load(.{ .app_name = "myapp" });

// See where each value came from
const tracker = loader.getTracker();
if (tracker.get("port")) |tracked| {
    std.debug.print("port = {s} (from {s})\n", .{
        tracked.value,
        tracked.source.format(),
    });
}
// Output: port = 9000 (from env)
```

### Dotenv Support

```zig
const dotenv = config.dotenv;

// Load .env file
const entries = try dotenv.load(".env", allocator);
defer allocator.free(entries);

for (entries) |entry| {
    std.debug.print("{s}={s}\n", .{ entry.key, entry.value });
}
```

### Runtime Overrides

```zig
var loader = config.Loader(AppConfig).init(allocator);
defer loader.deinit();

// Set values with highest precedence (overrides everything)
try loader.set("port", "9000");
try loader.set("debug", "true");

// Set runtime defaults (lowest precedence, below struct defaults)
try loader.setDefault("host", "0.0.0.0");

const cfg = try loader.load(.{ .app_name = "myapp" });
// cfg.port == 9000 (from set())
// cfg.host == "0.0.0.0" (from setDefault(), if not set elsewhere)
```

### Key Aliases

```zig
var loader = config.Loader(AppConfig).init(allocator);
defer loader.deinit();

// Register aliases - both "hostname" and "server" resolve to "host"
try loader.registerAlias("hostname", "host");
try loader.registerAlias("server", "host");

// Now setting "hostname" or "server" affects the "host" field
try loader.set("hostname", "myserver.local");
```

### Case-Insensitive Keys

```zig
const cfg = try loader.load(.{
    .app_name = "myapp",
    .case_insensitive = true,  // Enable case-insensitive key matching
});
// Now HOST, Host, and host all match the "host" field
```

### Environment Variable Binding

```zig
var loader = config.Loader(AppConfig).init(allocator);
defer loader.deinit();

// Explicit binding: "host" reads from DATABASE_HOST or SERVICE_HOST
try loader.bindEnv("host", &.{ "DATABASE_HOST", "SERVICE_HOST" });

// Single binding shorthand
try loader.bindEnvSingle("port", "SERVICE_PORT");

// Automatic env discovery with prefix
try loader.automaticEnv("MYAPP");
// Now MYAPP_HOST -> host, MYAPP_PORT -> port, etc.

// Custom key transformation
loader.setEnvKeyReplacer(.{
    .replacements = &.{
        .{ .from = ".", .to = "_" },  // server.host -> SERVER_HOST
        .{ .from = "-", .to = "_" },  // log-level -> LOG_LEVEL
    },
    .to_upper = true,
});
```

### Value Checking

```zig
var loader = config.Loader(AppConfig).init(allocator);
defer loader.deinit();

try loader.set("port", "9000");
_ = try loader.load(.{ .app_name = "myapp" });

// Check if a key was explicitly set (via set() or loaded from sources)
if (loader.isSet("port")) {
    std.debug.print("port was explicitly configured\n", .{});
}

// Check if a key has any value (including defaults)
if (loader.has("host")) {
    const host = loader.get("host").?;
    std.debug.print("host = {s}\n", .{host});
}
```

## Supported Formats

| Format | Extensions | Description |
|--------|------------|-------------|
| YAML | `.yaml`, `.yml` | Full nested structures, lists, flow-style |
| JSON | `.json` | Standard JSON with nested objects |
| TOML | `.toml` | Section-based configuration |
| INI | `.ini` | Section-based INI configuration |
| Properties | `.properties` | Java properties format |
| Dotenv | `.env` | Environment variable files |

## Configuration Precedence

Values are loaded in this order (higher priority overrides lower):

| Priority | Source | Description |
|----------|--------|-------------|
| 0 (highest) | Override | Explicit `set()` calls |
| 1 | Flags | Command-line overrides |
| 2 | Environment | `PREFIX_FIELD` env vars |
| 3 | Project | `./config.toml` |
| 4 | User | `~/.config/APP/config.toml` |
| 5 | System | `/etc/APP/config.toml` |
| 6 | Runtime Default | `setDefault()` calls |
| 7 (lowest) | Default | Struct field default values |

## Documentation

- [API Reference](docs/API.md) - Quick API reference
- [Architecture](docs/ARCHITECTURE.md) - Module structure and design
- [Contributing](docs/CONTRIBUTING.md) - How to contribute
- [Roadmap](docs/ROADMAP.md) - Development roadmap
- [Security](docs/SECURITY.md) - Security considerations
- [Viper Comparison](docs/VIPER_COMPARISON.md) - Feature parity with Viper
- [Examples](examples/README.md) - Usage examples

### Generating API Docs

```bash
# Generate HTML documentation from source comments
zig build docs

# View in browser
open zig-out/docs/index.html
```

## Project Status

### Current Version: v0.2.0

Full feature parity with Viper plus additional features. See the [Roadmap](docs/ROADMAP.md) for planned enhancements.

### Viper Comparison

zigconfig has achieved feature parity with [Viper](https://github.com/spf13/viper). See [VIPER_COMPARISON.md](docs/VIPER_COMPARISON.md) for details.

**zigconfig advantages over Viper:**
- Provenance tracking (know where each value came from)
- Secure secret handling (never from flags/env)
- XDG Base Directory compliance
- Cross-platform paths (Linux, macOS, Windows)
- Compile-time type safety
- Configuration diffing and comparison
- Async/parallel loading

### Implemented Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Formats** | YAML, JSON, TOML | Full parsing with nested structures |
| | INI, Properties | Section-based configuration |
| | Dotenv | Environment file loading |
| **Loading** | Type-safe Loader | Generic loader with compile-time validation |
| | Runtime Set/SetDefault | Override values at runtime |
| | BindEnv/AutomaticEnv | Environment variable binding |
| | Command-line flags | Flag parsing with FlagParser |
| | Array indexing | Access `servers.0.host` |
| | Sub() extraction | Extract sub-configurations |
| | AllSettings/AllKeys | Export all configuration |
| **Directories** | XDG compliance | ~/.config, ~/.local/share, ~/.cache |
| | Platform paths | macOS ~/Library, Windows %APPDATA% |
| | Multiple search paths | Search in multiple directories |
| **Secrets** | File/stdin only | Secure secret sources |
| | Encrypted secrets | Vault, 1Password CLI providers (no AWS/GCP KMS or encrypted-file-at-rest) |
| | Secure memory | Zeroing sensitive data |
| **Validation** | Pattern matching | Email, URL, IPv4, hostname, port |
| | Custom validators | User-defined validation functions |
| | Range checking | Integer and length validation |
| **Advanced** | Hot-reload | File watching with callbacks |
| | Remote config | etcd v3, Consul KV support |
| | Async loading | Parallel config file loading |
| | Config diffing | Compare and detect changes |
| | Serialization | Export to JSON/YAML/TOML/ENV |
| | Merge strategies | Configurable conflict resolution |
| **Tracking** | Provenance | Know where each value came from |
| | Key aliases | Register alternate key names |
| | Case-insensitive | Optional case-insensitive keys |

See all issues: [GitLab Issues](https://gitlab.com/devnw/zig/config/-/issues)

## Development

### Testing

```bash
# Run all tests
zig build test

# Run with summary
make test

# Check for compilation errors
zig build check
```

### Building

```bash
# Build static library
zig build

# Build and install
zig build install
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

**Areas for contribution:**
- Additional format parsers (HCL, HOCON)
- More secret providers
- Performance optimizations
- Documentation improvements
- Additional examples

## License

Apache-2.0 License - see [LICENSE](LICENSE) file for details.

---

**Links:**
- [GitLab Repository](https://gitlab.com/devnw/zig/config)
- [Issue Tracker](https://gitlab.com/devnw/zig/config/-/issues)
- [Milestones](https://gitlab.com/devnw/zig/config/-/milestones)
- [Viper (Go)](https://github.com/spf13/viper) - Inspiration
