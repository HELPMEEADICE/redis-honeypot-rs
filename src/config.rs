//! Runtime configuration: bind address, hard limits, auth timing, database knobs.
//!
//! Every value here is a *trust boundary*. The parser, the command simulator and
//! the SQLite writer all read their caps from [`Limits`], never from the packet.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Hard caps applied to everything an attacker can influence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Maximum number of simultaneously accepted TCP connections.
    pub max_connections: usize,
    /// Maximum number of simultaneously accepted connections from one source IP.
    pub max_connections_per_ip: usize,
    /// Maximum bytes buffered for a single in-flight RESP message.
    pub max_message_bytes: usize,
    /// Maximum length of a single Bulk String (and of the key/value caps).
    pub max_bulk_len: usize,
    /// Maximum number of elements in one RESP Array.
    pub max_array_len: usize,
    /// Maximum RESP array nesting depth.
    pub max_depth: usize,
    /// Maximum number of arguments (command + operands) per command.
    pub max_args: usize,
    /// Maximum commands accepted on one connection before it is closed.
    pub max_commands_per_conn: u64,
    /// Maximum AUTH attempts per connection.
    pub max_auth_attempts: u32,
    /// Idle timeout: no complete command within this window closes the socket.
    pub idle_timeout_secs: u64,
    /// Slow-client timeout: a partial frame older than this closes the socket.
    pub partial_frame_timeout_secs: u64,
    /// Maximum bytes of one recorded argument preview (storage guard).
    pub max_stored_param_bytes: usize,
    /// Maximum keys in the virtual keyspace (all logical databases together).
    pub store_max_keys: usize,
    /// Maximum bytes stored in the virtual keyspace.
    pub store_max_bytes: usize,
    /// Maximum size of a single virtual value.
    pub store_max_value_bytes: usize,
    /// Maximum simulated TTL in seconds.
    pub store_max_ttl_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            max_connections_per_ip: 16,
            max_message_bytes: 512 * 1024,
            max_bulk_len: 512 * 1024,
            max_array_len: 1024,
            max_depth: 8,
            max_args: 256,
            max_commands_per_conn: 1024,
            max_auth_attempts: 64,
            idle_timeout_secs: 1800,
            partial_frame_timeout_secs: 30,
            max_stored_param_bytes: 2048,
            store_max_keys: 1024,
            store_max_bytes: 1024 * 1024,
            store_max_value_bytes: 4096,
            store_max_ttl_secs: 86_400,
        }
    }
}

/// Delays applied to simulated responses. AUTH is always 2–6 s by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Timing {
    /// Minimum AUTH delay in milliseconds.
    pub auth_min_delay_ms: u64,
    /// Maximum AUTH delay in milliseconds.
    pub auth_max_delay_ms: u64,
    /// Maximum random jitter added to non-AUTH commands (0 disables jitter).
    pub command_jitter_max_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            auth_min_delay_ms: 2_000,
            auth_max_delay_ms: 6_000,
            command_jitter_max_ms: 0,
        }
    }
}

impl Timing {
    /// Inclusive `(min, max)` AUTH delay bounds as configured.
    pub fn auth_bounds(&self) -> (u64, u64) {
        (self.auth_min_delay_ms, self.auth_max_delay_ms)
    }
}

/// SQLite persistence knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    /// Path to the SQLite file (created on demand).
    pub path: PathBuf,
    /// Soft upper bound for the database file; oldest rows are pruned above it.
    pub max_bytes: u64,
    /// Capacity of the bounded record queue between network tasks and the writer.
    pub queue_capacity: usize,
    /// Maximum records per write transaction.
    pub batch_size: usize,
    /// Maximum time to wait before flushing a partial batch.
    pub batch_interval_ms: u64,
    /// Rows older than this are pruned (0 disables time based retention).
    pub retention_days: u32,
    /// `PRAGMA wal_checkpoint(TRUNCATE)` cadence.
    pub checkpoint_interval_secs: u64,
    /// Size/retention maintenance cadence.
    pub maintenance_interval_secs: u64,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./redis-honeypot.db"),
            max_bytes: 256 * 1024 * 1024,
            queue_capacity: 8192,
            batch_size: 128,
            batch_interval_ms: 250,
            retention_days: 30,
            checkpoint_interval_secs: 300,
            maintenance_interval_secs: 60,
        }
    }
}

/// Top level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Primary listen address. Defaults to `0.0.0.0:6379`.
    pub bind: SocketAddr,
    /// Also bind the same port on `[::]` (IPv6 / dual stack).
    pub enable_ipv6: bool,
    /// Store the raw password in `auth_attempts` (explicit opt-in).
    pub record_passwords: bool,
    /// Hard resource limits.
    pub limits: Limits,
    /// Response timing simulation.
    pub timing: Timing,
    /// Database settings.
    pub database: Database,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 6379)),
            enable_ipv6: false,
            record_passwords: false,
            limits: Limits::default(),
            timing: Timing::default(),
            database: Database::default(),
        }
    }
}

/// Configuration loading / validation failure.
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read config file: {e}"),
            Self::Parse(e) => write!(f, "cannot parse config file: {e}"),
            Self::Invalid(m) => write!(f, "invalid configuration: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Load a TOML overlay on top of [`Config::default`].
    pub fn load_toml(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let cfg: Config = toml::from_str(&raw).map_err(ConfigError::Parse)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject configurations that would make the honeypot self-defeating.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;

        if l.max_connections == 0 {
            return Err(ConfigError::Invalid("max_connections must be > 0".into()));
        }
        if l.max_connections_per_ip == 0 || l.max_connections_per_ip > l.max_connections {
            return Err(ConfigError::Invalid(
                "max_connections_per_ip must be > 0 and <= max_connections".into(),
            ));
        }
        if l.max_message_bytes < 64 {
            return Err(ConfigError::Invalid(
                "max_message_bytes must be >= 64".into(),
            ));
        }
        if l.max_bulk_len == 0 || l.max_bulk_len > l.max_message_bytes {
            return Err(ConfigError::Invalid(
                "max_bulk_len must be > 0 and <= max_message_bytes".into(),
            ));
        }
        if l.max_array_len == 0 || l.max_array_len > 65536 {
            return Err(ConfigError::Invalid(
                "max_array_len must be in 1..=65536".into(),
            ));
        }
        if l.max_depth == 0 || l.max_depth > 32 {
            return Err(ConfigError::Invalid("max_depth must be in 1..=32".into()));
        }
        if l.max_args == 0 || l.max_args > l.max_array_len {
            return Err(ConfigError::Invalid(
                "max_args must be > 0 and <= max_array_len".into(),
            ));
        }
        if l.max_commands_per_conn == 0 {
            return Err(ConfigError::Invalid(
                "max_commands_per_conn must be > 0".into(),
            ));
        }
        if l.idle_timeout_secs == 0 || l.partial_frame_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "idle_timeout_secs and partial_frame_timeout_secs must be > 0".into(),
            ));
        }
        if l.max_stored_param_bytes == 0 {
            return Err(ConfigError::Invalid(
                "max_stored_param_bytes must be > 0".into(),
            ));
        }
        if l.store_max_keys == 0
            || l.store_max_bytes == 0
            || l.store_max_value_bytes == 0
            || l.store_max_value_bytes > l.store_max_bytes
        {
            return Err(ConfigError::Invalid(
                "virtual store caps must be > 0 and store_max_value_bytes <= store_max_bytes"
                    .into(),
            ));
        }

        let (min, max) = self.timing.auth_bounds();
        if min > max {
            return Err(ConfigError::Invalid(
                "auth_min_delay_ms must be <= auth_max_delay_ms".into(),
            ));
        }
        if max > 600_000 {
            return Err(ConfigError::Invalid(
                "auth_max_delay_ms must be <= 600000".into(),
            ));
        }
        if self.timing.command_jitter_max_ms > 60_000 {
            return Err(ConfigError::Invalid(
                "command_jitter_max_ms must be <= 60000".into(),
            ));
        }

        let d = &self.database;
        if d.path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "database path must not be empty".into(),
            ));
        }
        if d.queue_capacity == 0 {
            return Err(ConfigError::Invalid(
                "database queue_capacity must be > 0".into(),
            ));
        }
        if d.batch_size == 0 {
            return Err(ConfigError::Invalid(
                "database batch_size must be > 0".into(),
            ));
        }
        if d.batch_interval_ms == 0 {
            return Err(ConfigError::Invalid(
                "database batch_interval_ms must be > 0".into(),
            ));
        }
        if d.max_bytes < 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "database max_bytes must be >= 1 MiB".into(),
            ));
        }
        if d.checkpoint_interval_secs == 0 || d.maintenance_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "database maintenance intervals must be > 0".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_matches_spec() {
        let cfg = Config::default();
        cfg.validate().expect("default config must be valid");
        assert_eq!(cfg.bind.to_string(), "0.0.0.0:6379");
        assert_eq!(cfg.timing.auth_bounds(), (2_000, 6_000));
        assert_eq!(cfg.database.path, PathBuf::from("./redis-honeypot.db"));
        assert!(!cfg.record_passwords);
    }

    #[test]
    fn inverted_auth_delay_is_rejected() {
        let mut cfg = Config::default();
        cfg.timing.auth_min_delay_ms = 7_000;
        cfg.timing.auth_max_delay_ms = 6_000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn oversized_limits_are_rejected() {
        let mut cfg = Config::default();
        cfg.limits.max_bulk_len = cfg.limits.max_message_bytes * 2;
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.limits.max_depth = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn toml_overlay_roundtrip() {
        let text = r#"
bind = "127.0.0.1:16379"
record_passwords = true
[timing]
auth_min_delay_ms = 10
auth_max_delay_ms = 20
[limits]
max_connections = 8
max_connections_per_ip = 4
"#;
        let cfg: Config = toml::from_str(text).expect("parse");
        cfg.validate().expect("valid");
        assert_eq!(cfg.bind.to_string(), "127.0.0.1:16379");
        assert!(cfg.record_passwords);
        assert_eq!(cfg.timing.auth_bounds(), (10, 20));
        assert_eq!(cfg.limits.max_connections, 8);
        // untouched fields keep their defaults
        assert_eq!(cfg.limits.max_depth, Limits::default().max_depth);
    }
}
