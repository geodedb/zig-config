# zigconfig Examples

This directory contains example programs demonstrating various features of the zigconfig library.

## Examples

| Example | Description |
|---------|-------------|
| [basic_parsing.zig](basic_parsing.zig) | Parse YAML, JSON, and TOML configuration files |
| [typed_loader.zig](typed_loader.zig) | Type-safe configuration with generic Loader |
| [flag_parsing.zig](flag_parsing.zig) | Command-line flag integration |
| [secret_handling.zig](secret_handling.zig) | Secure secret management (file/stdin only) |
| [validation.zig](validation.zig) | Configuration validation utilities |
| [xdg_paths.zig](xdg_paths.zig) | XDG Base Directory compliance |
| [dotenv_loading.zig](dotenv_loading.zig) | Loading .env files |

## Building and Running Examples

```bash
# Build all examples
zig build examples

# Run a specific example
zig build run-basic_parsing
zig build run-typed_loader
zig build run-flag_parsing
zig build run-secret_handling
zig build run-validation
zig build run-xdg_paths
zig build run-dotenv_loading

# Or run the compiled binaries directly
./zig-out/bin/example-basic_parsing
./zig-out/bin/example-typed_loader
./zig-out/bin/example-flag_parsing --host myhost --port 9000 --debug
```

## Configuration File Examples

### config.yaml

```yaml
server:
  host: localhost
  port: 8080

database:
  url: postgres://localhost/mydb
  pool_size: 10

logging:
  level: info
  format: json
```

### config.json

```json
{
  "server": {
    "host": "localhost",
    "port": 8080
  },
  "database": {
    "url": "postgres://localhost/mydb",
    "pool_size": 10
  }
}
```

### config.toml

```toml
[server]
host = "localhost"
port = 8080

[database]
url = "postgres://localhost/mydb"
pool_size = 10

[logging]
level = "info"
format = "json"
```

### .env

```bash
# Server configuration
SERVER_HOST=localhost
SERVER_PORT=8080

# Database
DATABASE_URL=postgres://localhost/mydb
DATABASE_POOL_SIZE=10

# Feature flags
DEBUG=false
```

## Key Concepts

### Configuration Precedence

Values are loaded in this order (higher priority overrides lower):

1. **Override** - Explicit `set()` calls (highest)
2. **Flags** - Command-line arguments
3. **Environment** - Environment variables with prefix
4. **Project** - `./config.toml` in current directory
5. **User** - `~/.config/APP/config.toml`
6. **System** - `/etc/APP/config.toml`
7. **Runtime Default** - `setDefault()` calls
8. **Default** - Struct field default values (lowest)

### Provenance Tracking

zigconfig tracks where each configuration value came from:

```zig
const tracker = loader.getTracker();
if (tracker.get("port")) |tracked| {
    std.debug.print("port = {s} (from {s})\n", .{
        tracked.value,
        tracked.source.format(), // "env", "project", "default", etc.
    });
}
```

### Secure Secrets

Secrets are **never** read from environment variables or command-line flags:

```zig
// Read from file (recommended for production)
const password = try config.readFromFile("/run/secrets/db_password", allocator);
defer allocator.free(password);

// Securely zero memory when done
config.secret.secureZero(@constCast(password));
```
