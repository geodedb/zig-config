# Viper Feature Comparison

This document compares zigconfig features with [Viper](https://github.com/spf13/viper), the popular Go configuration library, to identify feature parity and remaining gaps.

## Feature Matrix

| Feature | Viper | zigconfig | Status | Notes |
|---------|-------|-----------|--------|-------|
| **Format Support** | | | | |
| JSON | Yes | Yes | Complete | - |
| YAML | Yes | Yes | Complete | - |
| TOML | Yes | Yes | Complete | - |
| INI | Yes | Yes | Partial | `src/ini.zig` (parse only; serialization not yet supported) |
| Java Properties | Yes | Yes | Partial | `src/properties.zig` (parse only; serialization not yet supported) |
| Envfile | Yes | Yes | Complete | `src/dotenv.zig` |
| HCL | Yes | No | Planned | [#85](https://gitlab.com/devnw/zig/config/-/issues/85) |
| HOCON | No | No | Planned | [#86](https://gitlab.com/devnw/zig/config/-/issues/86) |
| **Configuration Sources** | | | | |
| Default values | Yes | Yes | Complete | - |
| Config files | Yes | Yes | Complete | - |
| Environment variables | Yes | Yes | Complete | - |
| Command-line flags | Yes | Yes | Complete | `src/flags.zig` |
| Remote config (etcd, Consul) | Yes | Yes | Partial | `src/remote.zig` with SSRF protection; remote clients available independently; manual wiring required (no integrated `ReadRemoteConfig` equivalent) |
| **Value Management** | | | | |
| Set() explicit overrides | Yes | Yes | Complete | [#26](https://gitlab.com/devnw/zig/config/-/issues/26) |
| SetDefault() runtime defaults | Yes | Yes | Complete | [#41](https://gitlab.com/devnw/zig/config/-/issues/41) |
| Key aliases | Yes | Yes | Complete | [#33](https://gitlab.com/devnw/zig/config/-/issues/33) |
| Case-insensitive keys | Yes | Yes | Complete | `normalizeKey` with arena-based lowercase |
| IsSet() check | Yes | Yes | Complete | [#42](https://gitlab.com/devnw/zig/config/-/issues/42) |
| **Path Access** | | | | |
| Dot notation | Yes | Yes | Complete | - |
| Array indexing | Yes | Yes | Complete | e.g. `servers.0.host` via `applyJsonValue` |
| Sub() extraction | Yes | Yes | Complete | `src/loader.zig` `sub()`/`hasSub()` |
| Custom key delimiter | Yes | Yes | Complete | [#40](https://gitlab.com/devnw/zig/config/-/issues/40) -- `loader.zig` configurable delimiter |
| **Environment Variables** | | | | |
| BindEnv() | Yes | Yes | Complete | [#30](https://gitlab.com/devnw/zig/config/-/issues/30) |
| AutomaticEnv() | Yes | Yes | Complete | [#31](https://gitlab.com/devnw/zig/config/-/issues/31) |
| SetEnvPrefix() | Yes | Yes | Complete | - |
| SetEnvKeyReplacer() | Yes | Yes | Complete | [#32](https://gitlab.com/devnw/zig/config/-/issues/32) |
| Env var expansion | No | Yes | zigconfig advantage | `src/expand.zig` -- `${VAR:-default}` syntax |
| **File Operations** | | | | |
| ReadInConfig() | Yes | Yes | Complete | - |
| WriteConfig() | Yes | Yes | Complete | `writeConfigToFile` via `src/serialize.zig` |
| SafeWriteConfig() | Yes | Yes | Complete | `safeWriteConfig`, `safeWriteConfigWithBackup` |
| WatchConfig() / hot-reload | Yes | Yes | Complete | `src/watch.zig` -- polling-based, cross-platform |
| Multiple search paths | Yes | Yes | Complete | `addConfigPath` in loader; XDG multi-path support |
| Files without extension | Yes | Yes | Complete | [#44](https://gitlab.com/devnw/zig/config/-/issues/44) -- `detectFormatFromContent` |
| **Data Export** | | | | |
| AllSettings() | Yes | Yes | Complete | [#37](https://gitlab.com/devnw/zig/config/-/issues/37) -- `loader.zig:299` |
| AllKeys() | Yes | Yes | Complete | [#43](https://gitlab.com/devnw/zig/config/-/issues/43) -- `loader.zig:284` |
| **Input Sources** | | | | |
| Read from io.Reader | Yes | No | Planned | [#38](https://gitlab.com/devnw/zig/config/-/issues/38) |
| Custom format decoders | Yes | Yes | Complete | Via `Format` enum in loader; [#39](https://gitlab.com/devnw/zig/config/-/issues/39) |
| **Type Support** | | | | |
| Unmarshal to struct | Yes | Yes | Complete | - |
| Type-specific getters | Yes | Yes | Complete | - |
| **Advanced** | | | | |
| Provenance tracking | No | Yes | zigconfig advantage | - |
| Secure secrets | No | Yes | zigconfig advantage | - |
| XDG compliance | No | Yes | zigconfig advantage | - |
| Encrypted secrets (Vault, 1Password) | No | Yes | zigconfig advantage | `src/encrypted_secrets.zig` |
| Config diff / comparison | No | Yes | zigconfig advantage | `src/diff.zig` |
| Config merging | No | Yes | zigconfig advantage | `src/merge.zig` |
| Serialization | No | Yes | zigconfig advantage | `src/serialize.zig` |
| Async loading | No | Yes | zigconfig advantage | `src/async.zig` |
| Parallel loading | No | Yes | zigconfig advantage | `src/parallel.zig` |
| SSRF protection | No | Yes | zigconfig advantage | Private-IP blocking, DNS rebinding mitigation |
| Path traversal prevention | No | Yes | zigconfig advantage | `isPathSafe`, `openFileReadNoFollow` |
| Centralized size limits | No | Yes | zigconfig advantage | `src/limits.zig` (CWE-400) |
| SensitiveString redaction | No | Yes | zigconfig advantage | Credential wrapper in `encrypted_secrets.zig` |
| Binary allowlists for CLI tools | No | Yes | zigconfig advantage | CWE-78 / CWE-426 prevention |

## zigconfig Advantages

Features that zigconfig provides that Viper does not.

### Provenance Tracking

```zig
const tracker = loader.getTracker();
if (tracker.get("port")) |tracked| {
    std.debug.print("port came from: {s}\n", .{tracked.source.format()});
}
```

### Secure Secret Handling

```zig
// Viper: secrets can leak via env vars or flags
// zigconfig: secrets only from files/stdin
const password = try secret.readFromFile("/run/secrets/password", allocator);
defer secret.secureZero(password);
```

### Encrypted Secrets (Vault, 1Password CLI)

```zig
const sm = encrypted_secrets.SecretManager.init(allocator);

// HashiCorp Vault
const db_pass = try sm.resolve("vault://secret/data/db#password");

// 1Password CLI
const api_key = try sm.resolve("op://vault/item/field");
```

### XDG Base Directory Support

```zig
const config_dir = try xdg.getConfigDir(allocator, "myapp");
// ~/.config/myapp or $XDG_CONFIG_HOME/myapp
```

### Config Diff and Comparison

```zig
// compare returns a DiffResult; the changes are in result.changes.
var result = try diff.compare(allocator, old_config, new_config);
defer allocator.free(result.changes);

for (result.changes) |change| {
    // old_value / new_value are optional (null for added/removed keys).
    std.debug.print("{s}: {s} -> {s}\n", .{
        change.key,
        change.old_value orelse "(null)",
        change.new_value orelse "(null)",
    });
}
```

### Config Merging

```zig
// mergeMaps merges two string-keyed maps (V is the value type).
const merged = try merge.mergeMaps([]const u8, allocator, base, overlay, .{
    .strategy = .override,
    .deep_merge = true,
});
```

### Environment Variable Expansion

```zig
// Supports ${VAR}, $VAR, ${VAR:-default}, ${VAR:+alternate}.
// `expand` is 2-arg; use `expandWithOptions` for the options form.
const expanded = try expand.expandWithOptions("${HOME}/config", allocator, .{});
```

### SSRF Protection on Remote Endpoints

```zig
// Private IP blocking enabled by default
var etcd = try remote.Etcd.init(allocator, .{
    .endpoints = &.{"https://etcd.example.com:2379"},
    // .security.block_private_ips = true (default)
});

// For local development only
var local = try remote.Etcd.init(allocator, .{
    .endpoints = &.{"http://localhost:2379"},
    .security = .{ .allow_insecure_http = true, .block_private_ips = false },
});
```

### Path Traversal Prevention

```zig
// safeWriteConfig rejects paths containing ".." (CWE-22)
// openFileReadNoFollow prevents symlink attacks (CWE-59)
try config.safeWriteConfig(allocator, path, content, .{ .atomic = true });
```

### Centralized Size Limits

```zig
// Defined in src/limits.zig -- prevents resource exhaustion (CWE-400)
// MAX_CONFIG_FILE_SIZE:   1 MB
// MAX_REMOTE_RESPONSE_SIZE: 1 MB
// MAX_SECRET_FILE_SIZE:   64 KB
// MAX_CLI_OUTPUT_SIZE:    1 MB
```

### SensitiveString Credential Redaction

```zig
const token = SensitiveString.initOwned(allocator, raw_token);
defer token.deinit();

// Formatting automatically redacts: prints "[REDACTED]" instead of the value
std.debug.print("token: {s}\n", .{token});
```

### Binary Allowlists for External CLI Tools

```zig
// 1Password and Vault CLI binary paths are validated against allowlists
// to prevent PATH hijack attacks (CWE-78, CWE-426)
```

## Remaining Gaps

### Planned Features

| Feature | Issue | Description |
|---------|-------|-------------|
| HCL format | [#85](https://gitlab.com/devnw/zig/config/-/issues/85) | HashiCorp Configuration Language |
| HOCON format | [#86](https://gitlab.com/devnw/zig/config/-/issues/86) | Human-Optimized Config Object Notation |
| SOPS integration | [#87](https://gitlab.com/devnw/zig/config/-/issues/87) | Mozilla SOPS encrypted files |
| age/GPG encryption | [#88](https://gitlab.com/devnw/zig/config/-/issues/88) | age/GPG encrypted config files |
| JSON Schema validation | [#5](https://gitlab.com/devnw/zig/config/-/issues/5) | Schema-based config validation |
| parseReader() | [#38](https://gitlab.com/devnw/zig/config/-/issues/38) | Read from io.Reader |

## API Comparison

### Reading Configuration

**Viper (Go):**

```go
viper.SetConfigName("config")
viper.SetConfigType("yaml")
viper.AddConfigPath("/etc/myapp/")
viper.AddConfigPath("$HOME/.myapp")
viper.ReadInConfig()
```

**zigconfig (Zig):**

```zig
var loader = config.Loader(AppConfig).init(allocator);
const cfg = try loader.load(.{
    .app_name = "myapp",
    .filename = "config.yaml",
});
```

### Getting Values

**Viper (Go):**

```go
host := viper.GetString("server.host")
port := viper.GetInt("server.port")
```

**zigconfig (Zig):**

```zig
const host = value.getString("server.host") orelse "localhost";
const port = value.getInt("server.port") orelse 8080;
```

### Environment Variables

**Viper (Go):**

```go
viper.SetEnvPrefix("MYAPP")
viper.AutomaticEnv()
viper.BindEnv("host", "SERVICE_HOST")
```

**zigconfig (Zig):**

```zig
const cfg = try loader.load(.{
    .app_name = "myapp",
    .env_prefix = "MYAPP_",
});
```

### Command-Line Flags

**Viper (Go):**

```go
pflag.Int("port", 8080, "server port")
viper.BindPFlags(pflag.CommandLine)
```

**zigconfig (Zig):**

```zig
var parser = flags.FlagParser.init(allocator);
try parser.addFlag(.{ .name = "port", .short = 'p', .description = "server port" });
try parser.parse(args); // parse returns void
const values = parser.getValues(); // []const FlagValue

```

### Remote Configuration

**Viper (Go):**

```go
viper.AddRemoteProvider("etcd3", "https://etcd.example.com:2379", "/config/app")
viper.ReadRemoteConfig()
```

**zigconfig (Zig):**

```zig
var etcd = try remote.Etcd.init(allocator, .{
    .endpoints = &.{"https://etcd.example.com:2379"},
});
defer etcd.deinit();
const value = try etcd.get("config/app/host");
```

### Writing Configuration

**Viper (Go):**

```go
viper.SafeWriteConfig()
```

**zigconfig (Zig):**

```zig
// Safe write (refuses to overwrite existing files)
try config.safeWriteConfig(allocator, "config.yaml", content, .{ .atomic = true });

// Safe write with backup of existing file
try config.safeWriteConfigWithBackup(allocator, "config.yaml", content, .{
    .backup_extension = ".bak",
});

// Direct write via serialization
try config.writeConfigToFile("config.json", data, .{ .format = .json_pretty });
```

### Watching Configuration

**Viper (Go):**

```go
viper.WatchConfig()
viper.OnConfigChange(func(e fsnotify.Event) {
    fmt.Println("Config changed:", e.Name)
})
```

**zigconfig (Zig):**

```zig
var watcher = watch.Watcher.init(allocator, .{
    .poll_interval_ms = 1000,
});
defer watcher.deinit();

try watcher.addPath("config.toml", onConfigChanged);
try watcher.start();
```

## Contributing

Help us close the remaining gaps! See the issues linked above and [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Priority contributions:

1. Planned features listed in [Remaining Gaps](#remaining-gaps)
2. Tests for existing features
3. Documentation updates
