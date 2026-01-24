# API Reference

This document provides an overview of the zigconfig API. For full documentation, generate the autodocs using `zig build docs`.

## Quick Reference

### Main Module: `config`

```zig
const config = @import("config");
```

### Configuration Parsing

| Function | Description |
|----------|-------------|
| `parseFile(allocator, path)` | Parse config file (format auto-detected) |
| `parseContent(allocator, content, format)` | Parse config content with explicit format |

### Value API

| Method | Description |
|--------|-------------|
| `getString(path)` | Get string value at dot-separated path |
| `getInt(path)` | Get integer value at path |
| `getFloat(path)` | Get float value at path |
| `getBool(path)` | Get boolean value at path |
| `has(path)` | Check if path exists |
| `getPath(path)` | Get nested Value at path |
| `getList(path)` | Get list items at path |
| `deinit()` | Free all memory |

### Typed Loader

```zig
const MyConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    debug: bool = false,
};

var loader = config.Loader(MyConfig).init(allocator);
defer loader.deinit();

// Viper-like methods
try loader.set("port", "9000");          // Highest precedence
try loader.setDefault("host", "0.0.0.0"); // Lowest precedence
try loader.registerAlias("server", "host");
try loader.bindEnv("port", &.{"APP_PORT", "PORT"});
try loader.automaticEnv("MYAPP");

const cfg = try loader.load(.{
    .app_name = "myapp",
    .env_prefix = "MYAPP_",
    .case_insensitive = true,
});
```

### Flag Parser

```zig
var parser = config.FlagParser.init(allocator);
defer parser.deinit();

try parser.string("config", 'c', "Config file", null);
try parser.boolean("debug", 'd', "Enable debug");

try parser.parseArgs();  // Parse from process args

loader.applyFlags(&parser);  // Apply to loader
```

### XDG Directories

```zig
const paths = try config.getPaths(allocator, "myapp");
defer paths.deinit();
// paths.config = ~/.config/myapp
// paths.data = ~/.local/share/myapp
// paths.cache = ~/.cache/myapp
```

### Secret Handling

```zig
// Read secrets only from files (never env vars!)
const password = try config.readFromFile("/run/secrets/db", allocator);
defer allocator.free(password);

// Redact for logging
std.debug.print("{s}\n", .{config.secret.redact(password)});

// Secure memory cleanup
config.secret.secureZero(@constCast(password));
```

### Validation

```zig
try config.validate.required(value);
try config.validate.minLength(value, 8);
try config.validate.maxLength(value, 128);
try config.validate.port(port);
try config.validate.hostname(host);
try config.validate.url(endpoint);
try config.validate.email(email);
try config.validate.intRange(n, 1, 100);
try config.validate.oneOf(level, &.{"debug", "info", "warn"});
```

### Provenance Tracking

```zig
const tracker = loader.getTracker();
if (tracker.get("port")) |tracked| {
    // tracked.value = "9000"
    // tracked.source = .env, .flag, .project, etc.
    // tracked.source_path = "MYAPP_PORT"
}
```

## Precedence Order

| Priority | Source | Description |
|----------|--------|-------------|
| 0 | Override | `set()` calls |
| 1 | Flag | Command-line flags |
| 2 | Env | Environment variables |
| 3 | Project | `./config.toml` |
| 4 | User | `~/.config/APP/config.toml` |
| 5 | System | `/etc/APP/config.toml` |
| 6 | Runtime Default | `setDefault()` calls |
| 7 | Default | Struct field defaults |

## Generating Full Documentation

```bash
# Generate HTML documentation
zig build docs

# View documentation
open zig-out/docs/index.html
```

The generated documentation includes full API details from doc comments in the source code.
