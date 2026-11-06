//! Binary entry point.
//!
//! Deliberately thin: parse the CLI, resolve configuration, start the database
//! writer, run the listener, wait for a signal, shut down in order.

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use redis_honeypot_rs::cli::{Cli, CommandKind, StatsArgs};
use redis_honeypot_rs::config::Config;
use redis_honeypot_rs::db::{self, StatsQuery};
use redis_honeypot_rs::logging;
use redis_honeypot_rs::server::{self, ServerSummary, ShutdownHandle};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Some(CommandKind::Stats(args)) => run_stats(&cli, args),
        _ => run_serve(&cli),
    }
}

/// `redis-honeypot-rs stats …` — local SQLite only, no listener.
fn run_stats(cli: &Cli, args: &StatsArgs) -> ExitCode {
    let cfg = match cli.resolve_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return ExitCode::from(2);
        }
    };
    let query = StatsQuery {
        top_ips: args.top_ips,
        top_commands: args.top_commands,
        auth: args.auth,
        dangerous: args.dangerous,
    };
    match db::stats::print_stats(&cfg.database.path, &query) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("stats failed: {err}");
            ExitCode::from(1)
        }
    }
}

/// `redis-honeypot-rs [serve] …` — the honeypot itself.
fn run_serve(cli: &Cli) -> ExitCode {
    let cfg = match cli.resolve_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return ExitCode::from(2);
        }
    };

    logging::init(&cli.log_level);
    warn_on_unusual_delay_policy(&cfg);

    // Two worker threads is plenty: the workload is socket IO plus short
    // synchronous parse steps. The SQLite writer runs on its own blocking thread.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name("honeypot")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("cannot start the async runtime: {err}");
            return ExitCode::from(1);
        }
    };

    match runtime.block_on(serve_until_shutdown(cfg)) {
        Ok(summary) => {
            logging::info(&format!(
                "stopped: {} accepted, {} rejected (global), {} rejected (per-ip), peak {} concurrent",
                summary.accepted,
                summary.rejected_global,
                summary.rejected_per_ip,
                summary.peak_concurrent
            ));
            ExitCode::SUCCESS
        }
        Err(err) => {
            logging::error(&format!("fatal: {err}"));
            ExitCode::from(1)
        }
    }
}

fn warn_on_unusual_delay_policy(cfg: &Config) {
    let (min, max) = cfg.timing.auth_bounds();
    if min < 2_000 || max > 6_000 {
        logging::warn(&format!(
            "auth delay window {min}-{max}ms is outside the recommended 2000-6000ms"
        ));
    }
}

async fn serve_until_shutdown(cfg: Config) -> Result<ServerSummary, Box<dyn std::error::Error>> {
    let db_handle = db::spawn_writer(&cfg.database)?;
    let drop_watchdog = db_handle.recorder.clone();

    let shutdown = ShutdownHandle::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let recorder = db_handle.recorder.clone();
    let server_shutdown = shutdown.clone();
    let server_cfg = cfg.clone();
    let server_task = tokio::spawn(async move {
        server::serve(server_cfg, recorder, server_shutdown, Some(ready_tx)).await
    });

    let bound = match ready_rx.await {
        Ok(bound) => bound,
        Err(_) => {
            // The listener died before it could bind: recover and surface the
            // real error instead of the generic "it stopped" message.
            return match server_task.await {
                Ok(Err(err)) => Err(err.into()),
                Ok(Ok(_)) => Err("the listener stopped before it reported its address".into()),
                Err(join) => Err(format!("listener task failed: {join}").into()),
            };
        }
    };
    for addr in &bound {
        logging::info(&format!("honeypot listening on {addr}"));
    }
    logging::info(&format!(
        "database {} (max {} bytes, retention {} days, passwords {})",
        cfg.database.path.display(),
        cfg.database.max_bytes,
        cfg.database.retention_days,
        if cfg.record_passwords {
            "recorded"
        } else {
            "masked"
        }
    ));

    // Wait for a stop signal, reporting backpressure drops as they happen.
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut signal = std::pin::pin!(wait_for_shutdown_signal());
    let mut last_dropped = 0u64;
    loop {
        tokio::select! {
            _ = &mut signal => {
                logging::info("shutdown signal received");
                break;
            }
            _ = ticker.tick() => {
                let dropped = drop_watchdog.dropped();
                if dropped > last_dropped {
                    logging::warn(&format!(
                        "record queue saturated: {dropped} records dropped so far"
                    ));
                    last_dropped = dropped;
                }
            }
        }
    }

    shutdown.trigger();
    let summary = match tokio::time::timeout(Duration::from_secs(15), server_task).await {
        Ok(Ok(Ok(summary))) => summary,
        Ok(Ok(Err(err))) => return Err(err.into()),
        Ok(Err(join)) => return Err(format!("listener task failed: {join}").into()),
        Err(_) => {
            logging::warn("listener did not stop within 15s; continuing shutdown anyway");
            ServerSummary::default()
        }
    };

    // Close the record channel and let the writer flush what is queued.
    drop(drop_watchdog);
    db_handle.shutdown().await;
    Ok(summary)
}

/// Resolve on SIGINT (all platforms) or SIGTERM (unix).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
