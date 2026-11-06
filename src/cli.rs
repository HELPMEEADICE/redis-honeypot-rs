//! Command line interface.
//!
//! `serve` (or no subcommand) runs the honeypot; `stats` reads the local SQLite
//! file and starts no listener at all.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::{Config, ConfigError};

/// Redis honeypot: captures scan, brute force and unauthorised access attempts.
#[derive(Debug, Parser)]
#[command(
    name = "redis-honeypot-rs",
    version,
    about = "A tiny, high-interaction Redis honeypot",
    long_about = None,
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<CommandKind>,

    /// TOML configuration file; values are overlaid on the built-in defaults.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Console log level: error, warn, info, debug or trace.
    #[arg(long, global = true, value_name = "LEVEL", default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Subcommand)]
pub enum CommandKind {
    /// Run the honeypot (this is the default when no subcommand is given).
    Serve(ServeArgs),
    /// Query the local SQLite database. Starts no listener.
    Stats(StatsArgs),
}

/// Options for `serve`.
#[derive(Debug, Args, Default)]
pub struct ServeArgs {
    /// Listen address, e.g. `0.0.0.0:6379`.
    #[arg(long, value_name = "ADDR:PORT")]
    pub bind: Option<SocketAddr>,

    /// SQLite database path.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Minimum simulated AUTH delay in milliseconds (default 2000).
    #[arg(long, value_name = "MS")]
    pub min_delay: Option<u64>,

    /// Maximum simulated AUTH delay in milliseconds (default 6000).
    #[arg(long, value_name = "MS")]
    pub max_delay: Option<u64>,

    /// Also listen on the same port over IPv6 (`[::]`).
    #[arg(long)]
    pub ipv6: bool,

    /// Store submitted passwords verbatim (explicit opt-in).
    #[arg(long)]
    pub record_passwords: bool,

    /// Maximum concurrent connections.
    #[arg(long, value_name = "N")]
    pub max_connections: Option<usize>,

    /// Maximum concurrent connections from a single source IP.
    #[arg(long, value_name = "N")]
    pub max_per_ip: Option<usize>,
}

impl ServeArgs {
    /// Apply CLI overrides on top of a (possibly file supplied) configuration.
    pub fn apply(&self, cfg: &mut Config) {
        if let Some(bind) = self.bind {
            cfg.bind = bind;
        }
        if let Some(path) = &self.db {
            cfg.database.path = path.clone();
        }
        if let Some(ms) = self.min_delay {
            cfg.timing.auth_min_delay_ms = ms;
        }
        if let Some(ms) = self.max_delay {
            cfg.timing.auth_max_delay_ms = ms;
        }
        if self.ipv6 {
            cfg.enable_ipv6 = true;
        }
        if self.record_passwords {
            cfg.record_passwords = true;
        }
        if let Some(n) = self.max_connections {
            cfg.limits.max_connections = n;
        }
        if let Some(n) = self.max_per_ip {
            cfg.limits.max_connections_per_ip = n;
        }
    }
}

/// Options for `stats`.
#[derive(Debug, Args, Default)]
pub struct StatsArgs {
    /// SQLite database path (default `./redis-honeypot.db`).
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Rows in the source-IP leaderboard (0 hides it).
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub top_ips: usize,

    /// Rows in the command leaderboard (0 hides it).
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub top_commands: usize,

    /// Show recent authentication attempts.
    #[arg(long)]
    pub auth: bool,

    /// Show recent dangerous commands.
    #[arg(long)]
    pub dangerous: bool,
}

impl Cli {
    /// Resolve the effective configuration for this invocation.
    pub fn resolve_config(&self) -> Result<Config, ConfigError> {
        let mut cfg = match &self.config {
            Some(path) => Config::load_toml(path)?,
            None => Config::default(),
        };
        match &self.command {
            Some(CommandKind::Serve(args)) => args.apply(&mut cfg),
            Some(CommandKind::Stats(args)) => {
                if let Some(path) = &args.db {
                    cfg.database.path = path.clone();
                }
            }
            None => {}
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// True when this invocation must start a listener.
    pub fn is_serve(&self) -> bool {
        !matches!(self.command, Some(CommandKind::Stats(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("cli must parse")
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_arguments_means_serve() {
        let cli = parse(&["redis-honeypot-rs"]);
        assert!(cli.command.is_none());
        assert!(cli.is_serve());
        let cfg = cli.resolve_config().expect("default config valid");
        assert_eq!(cfg.bind.to_string(), "0.0.0.0:6379");
        assert_eq!(cfg.timing.auth_bounds(), (2_000, 6_000));
    }

    #[test]
    fn serve_flags_override_defaults() {
        let cli = parse(&[
            "redis-honeypot-rs",
            "serve",
            "--bind",
            "127.0.0.1:16379",
            "--db",
            "./honeypot.db",
            "--min-delay",
            "2000",
            "--max-delay",
            "6000",
            "--max-connections",
            "64",
            "--max-per-ip",
            "4",
            "--ipv6",
            "--record-passwords",
        ]);
        let cfg = cli.resolve_config().expect("config");
        assert_eq!(cfg.bind.to_string(), "127.0.0.1:16379");
        assert_eq!(cfg.database.path, PathBuf::from("./honeypot.db"));
        assert_eq!(cfg.timing.auth_bounds(), (2_000, 6_000));
        assert_eq!(cfg.limits.max_connections, 64);
        assert_eq!(cfg.limits.max_connections_per_ip, 4);
        assert!(cfg.enable_ipv6);
        assert!(cfg.record_passwords);
    }

    #[test]
    fn stats_subcommand_never_serves() {
        let cli = parse(&[
            "redis-honeypot-rs",
            "stats",
            "--top-ips",
            "20",
            "--top-commands",
            "5",
            "--auth",
            "--dangerous",
        ]);
        assert!(!cli.is_serve());
        match &cli.command {
            Some(CommandKind::Stats(args)) => {
                assert_eq!(args.top_ips, 20);
                assert_eq!(args.top_commands, 5);
                assert!(args.auth && args.dangerous);
            }
            other => panic!("expected stats, got {other:?}"),
        }
    }

    #[test]
    fn stats_db_flag_overrides_path() {
        let cli = parse(&["redis-honeypot-rs", "stats", "--db", "/tmp/x.db"]);
        let cfg = cli.resolve_config().expect("config");
        assert_eq!(cfg.database.path, PathBuf::from("/tmp/x.db"));
    }

    #[test]
    fn inverted_delays_are_rejected() {
        let cli = parse(&[
            "redis-honeypot-rs",
            "serve",
            "--min-delay",
            "9000",
            "--max-delay",
            "1000",
        ]);
        assert!(cli.resolve_config().is_err());
    }

    #[test]
    fn unknown_flags_are_errors() {
        assert!(Cli::try_parse_from(["redis-honeypot-rs", "serve", "--nope"]).is_err());
        assert!(Cli::try_parse_from(["redis-honeypot-rs", "bogus"]).is_err());
    }
}
