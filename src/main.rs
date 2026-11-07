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
use redis_honeypot_rs::server::{self, ReloadHandle, ServerSummary, ShutdownHandle};

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
    install_panic_hook();
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

    match runtime.block_on(serve_until_shutdown(cfg, cli)) {
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

/// Install a crash hook.
///
/// `panic = "abort"` means the process dies on the first panic; the hook still
/// runs first, so this is the only chance to leave a forensic line in journald
/// (which one, where, and with what message) instead of a silent exit.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_owned());
        // The payload is our own text, but it can embed attacker derived data
        // (a formatted command): escape and cap it like any other log line.
        let payload = redis_honeypot_rs::text::escape_str(&info.to_string(), 256);
        eprintln!("[PANIC] redis-honeypot-rs at {location}: {payload}");
    }));
}

fn warn_on_unusual_delay_policy(cfg: &Config) {
    let (min, max) = cfg.timing.auth_bounds();
    if min < 2_000 || max > 6_000 {
        logging::warn(&format!(
            "auth delay window {min}-{max}ms is outside the recommended 2000-6000ms"
        ));
    }
}

async fn serve_until_shutdown(
    cfg: Config,
    cli: &Cli,
) -> Result<ServerSummary, Box<dyn std::error::Error>> {
    let db_handle = db::spawn_writer(&cfg.database, &cfg.limits)?;
    let drop_watchdog = db_handle.recorder.clone();
    let writer_watchdog = db_handle.writer_stats();

    let shutdown = ShutdownHandle::new();
    let reload = ReloadHandle::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let recorder = db_handle.recorder.clone();
    let server_shutdown = shutdown.clone();
    let server_reload = reload.clone();
    let server_cfg = cfg.clone();
    let server_task = tokio::spawn(async move {
        server::serve(
            server_cfg,
            recorder,
            server_shutdown,
            Some(ready_tx),
            Some(server_reload),
        )
        .await
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

    // Wait for a stop signal or a reload, reporting backpressure drops as they
    // happen.
    let mut hangup = hangup_signal();
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut signal = std::pin::pin!(wait_for_shutdown_signal());
    let mut last_dropped = 0u64;
    let mut last_lost = 0u64;
    loop {
        tokio::select! {
            _ = &mut signal => {
                logging::info("shutdown signal received");
                break;
            }
            () = wait_for_reload_signal(&mut hangup) => {
                // A reload must never be able to kill the running service: a
                // config that no longer validates is reported and discarded.
                match cli.resolve_config() {
                    Ok(next) => {
                        if reload.apply(next) {
                            logging::info("SIGHUP received: reloading configuration");
                        } else {
                            logging::warn("SIGHUP received, but the listener is gone; ignored");
                        }
                    }
                    Err(err) => logging::warn(&format!(
                        "SIGHUP received, keeping the running configuration (the new one is invalid): {err}"
                    )),
                }
            }
            _ = ticker.tick() => {
                let dropped = drop_watchdog.dropped();
                if dropped > last_dropped {
                    logging::warn(&format!(
                        "record queue saturated: {dropped} records dropped so far"
                    ));
                    last_dropped = dropped;
                }
                // Records SQLite rejected even after the retry budget: telemetry
                // loss must be visible, never silent.
                let lost = writer_watchdog.lost();
                if lost > last_lost {
                    logging::warn(&format!(
                        "database rejected {lost} records so far ({} retried batches, {} pruned rows)",
                        writer_watchdog.retried(),
                        writer_watchdog.pruned_rows()
                    ));
                    last_lost = lost;
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

/// The signal that means "reload your configuration".
///
/// `SIGHUP` is a Unix concept; on Windows there is nothing to subscribe to and
/// the branch below stays pending forever, so the shape of the loop is the same
/// on every platform.
#[cfg(unix)]
type HangupSignal = tokio::signal::unix::Signal;
#[cfg(not(unix))]
type HangupSignal = ();

fn hangup_signal() -> Option<HangupSignal> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::hangup()) {
            Ok(signal) => Some(signal),
            Err(err) => {
                logging::warn(&format!(
                    "cannot subscribe to SIGHUP ({err}); `systemctl reload` will be a no-op"
                ));
                None
            }
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Resolve when SIGHUP arrives, or never when the platform cannot deliver it.
///
/// `Signal::recv` is cancel safe, so re-creating this future on every loop
/// iteration cannot lose a signal.
async fn wait_for_reload_signal(signal: &mut Option<HangupSignal>) {
    #[cfg(unix)]
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
    #[cfg(not(unix))]
    {
        let _ = signal;
        std::future::pending::<()>().await
    }
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
