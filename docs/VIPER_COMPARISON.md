# Viper Feature Comparison

This document compares zigconfig features with [Viper](https://github.com/spf13/viper), the popular Go configuration library, to identify feature parity and gaps.

## Feature Matrix

| Feature | Viper | zigconfig | Status | Issue |
|---------|-------|-----------|--------|-------|
| **Format Support** |
| JSON | Yes | Yes | Complete | - |
| YAML | Yes | Yes | Complete | - |
| TOML | Yes | Yes | Complete | - |
| INI | Yes | No | Planned | [#24](https://gitlab.com/devnw/zig/config/-/issues/24) |
| Java Properties | Yes | No | Planned | [#25](https://gitlab.com/devnw/zig/config/-/issues/25) |
| Envfile | Yes | Yes | Complete | - |
| **Configuration Sources** |
| Default values | Yes | Yes | Complete | - |
| Config files | Yes | Yes | Complete | - |
| Environment variables | Yes | Yes | Complete | - |
| Command-line flags | Yes | No | Planned | [#8](https://gitlab.com/devnw/zig/config/-/issues/8) |
| Remote config (etcd, Consul) | Yes | No | Planned | [#27](https://gitlab.com/devnw/zig/config/-/issues/27) |
| **Value Management** |
| Set() explicit overrides | Yes | Yes | Complete | [#26](https://gitlab.com/devnw/zig/config/-/issues/26) |
| SetDefault() runtime defaults | Yes | Yes | Complete | [#41](https://gitlab.com/devnw/zig/config/-/issues/41) |
| Key aliases | Yes | Yes | Complete | [#33](https://gitlab.com/devnw/zig/config/-/issues/33) |
| Case-insensitive keys | Yes | Yes | Complete | [#34](https://gitlab.com/devnw/zig/config/-/issues/34) |
| IsSet() check | Yes | Yes | Complete | [#42](https://gitlab.com/devnw/zig/config/-/issues/42) |
| **Path Access** |
| Dot notation | Yes | Yes | Complete | - |
| Array indexing | Yes | No | Planned | [#35](https://gitlab.com/devnw/zig/config/-/issues/35) |
| Sub() extraction | Yes | No | Planned | [#36](https://gitlab.com/devnw/zig/config/-/issues/36) |
| Custom key delimiter | Yes | No | Planned | [#40](https://gitlab.com/devnw/zig/config/-/issues/40) |
| **Environment Variables** |
| BindEnv() | Yes | Yes | Complete | [#30](https://gitlab.com/devnw/zig/config/-/issues/30) |
| AutomaticEnv() | Yes | Yes | Complete | [#31](https://gitlab.com/devnw/zig/config/-/issues/31) |
| SetEnvPrefix() | Yes | Yes | Complete | - |
| SetEnvKeyReplacer() | Yes | Yes | Complete | [#32](https://gitlab.com/devnw/zig/config/-/issues/32) |
| **File Operations** |
| ReadInConfig() | Yes | Yes | Complete | - |
| WriteConfig() | Yes | No | Planned | [#19](https://gitlab.com/devnw/zig/config/-/issues/19) |
| SafeWriteConfig() | Yes | No | Planned | [#29](https://gitlab.com/devnw/zig/config/-/issues/29) |
| WatchConfig() | Yes | No | Planned | [#15](https://gitlab.com/devnw/zig/config/-/issues/15) |
| Multiple search paths | Yes | No | Planned | [#28](https://gitlab.com/devnw/zig/config/-/issues/28) |
| Files without extension | Yes | No | Planned | [#44](https://gitlab.com/devnw/zig/config/-/issues/44) |
| **Data Export** |
| AllSettings() | Yes | No | Planned | [#37](https://gitlab.com/devnw/zig/config/-/issues/37) |
| AllKeys() | Yes | No | Planned | [#43](https://gitlab.com/devnw/zig/config/-/issues/43) |
| **Input Sources** |
| Read from io.Reader | Yes | No | Planned | [#38](https://gitlab.com/devnw/zig/config/-/issues/38) |
| Custom format decoders | Yes | No | Planned | [#39](https://gitlab.com/devnw/zig/config/-/issues/39) |
| **Type Support** |
| Unmarshal to struct | Yes | Yes | Complete | - |
| Type-specific getters | Yes | Yes | Complete | - |
| **Advanced** |
| Provenance tracking | No | Yes | zigconfig advantage | - |
| Secure secrets | No | Yes | zigconfig advantage | - |
| XDG compliance | No | Yes | zigconfig advantage | - |

## zigconfig Advantages

Features that zigconfig provides that Viper doesn't:

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

### XDG Base Directory Support
```zig
const config_dir = try xdg.getConfigDir(allocator, "myapp");
// ~/.config/myapp or $XDG_CONFIG_HOME/myapp
```

## Viper Features to Implement

### Recently Completed

| Feature | Issue | Description |
|---------|-------|-------------|
| Runtime Set() | [#26](https://gitlab.com/devnw/zig/config/-/issues/26) | Explicit value overrides |
| SetDefault() | [#41](https://gitlab.com/devnw/zig/config/-/issues/41) | Runtime defaults |
| BindEnv() | [#30](https://gitlab.com/devnw/zig/config/-/issues/30) | Explicit env binding |
| AutomaticEnv() | [#31](https://gitlab.com/devnw/zig/config/-/issues/31) | Auto env discovery |
| SetEnvKeyReplacer() | [#32](https://gitlab.com/devnw/zig/config/-/issues/32) | Env key transformation |
| Key aliases | [#33](https://gitlab.com/devnw/zig/config/-/issues/33) | Multiple keys -> one value |
| Case-insensitive | [#34](https://gitlab.com/devnw/zig/config/-/issues/34) | Key normalization |
| IsSet() | [#42](https://gitlab.com/devnw/zig/config/-/issues/42) | Check explicit set |

### High Priority (v0.2.0)

| Feature | Issue | Description |
|---------|-------|-------------|
| Multiple paths | [#28](https://gitlab.com/devnw/zig/config/-/issues/28) | Search multiple directories |
| Sub() | [#36](https://gitlab.com/devnw/zig/config/-/issues/36) | Config subset extraction |
| AllSettings | [#37](https://gitlab.com/devnw/zig/config/-/issues/37) | Export all settings |
| AllKeys | [#43](https://gitlab.com/devnw/zig/config/-/issues/43) | List all keys |
| Array indexing | [#35](https://gitlab.com/devnw/zig/config/-/issues/35) | Path array access |
| parseReader | [#38](https://gitlab.com/devnw/zig/config/-/issues/38) | Read from io.Reader |

### Medium Priority (v0.3.0)

| Feature | Issue | Description |
|---------|-------|-------------|
| Remote config | [#27](https://gitlab.com/devnw/zig/config/-/issues/27) | etcd, Consul, NATS |
| INI format | [#24](https://gitlab.com/devnw/zig/config/-/issues/24) | INI file support |
| Properties format | [#25](https://gitlab.com/devnw/zig/config/-/issues/25) | Java properties |
| Safe write | [#29](https://gitlab.com/devnw/zig/config/-/issues/29) | Prevent overwrite |
| Custom formats | [#39](https://gitlab.com/devnw/zig/config/-/issues/39) | Extensible decoders |
| Key delimiter | [#40](https://gitlab.com/devnw/zig/config/-/issues/40) | Custom delimiter |
| Extensionless files | [#44](https://gitlab.com/devnw/zig/config/-/issues/44) | Files without extension |

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

**zigconfig (Zig) - Current:**
```zig
const cfg = try loader.load(.{
    .app_name = "myapp",
    .env_prefix = "MYAPP_",
});
```

**zigconfig (Zig) - Planned:**
```zig
try loader.automaticEnv(.{ .prefix = "MYAPP" });
try loader.bindEnv("host", "SERVICE_HOST");
```

## Contributing

Help us reach Viper parity! See the issues linked above and [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Priority contributions:
1. High priority issues for v0.2.0
2. Tests for new features
3. Documentation updates
