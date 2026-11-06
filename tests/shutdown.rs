//! Admission control, timeouts and graceful shutdown.

mod support;

use std::time::{Duration, Instant};

use redis_honeypot_rs::config::Config;
use support::Harness;

#[tokio::test]
async fn graceful_shutdown_returns_promptly_and_closes_clients() {
    let server = Harness::start().await;
    let mut c = server.connect().await;
    assert_eq!(c.call(&[b"PING"]).await, b"+PONG\r\n");
    // Leave a half sent command in flight so the task is genuinely mid-frame.
    c.write_raw(b"*1\r\n").await;

    let started = Instant::now();
    let summary = server.stop().await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(8),
        "shutdown took {elapsed:?}, tasks are not cancellable"
    );
    assert!(
        summary.accepted >= 1,
        "the accepted counter must be reported"
    );
    assert!(
        c.closed().await,
        "an open client must see EOF after shutdown"
    );
}

#[tokio::test]
async fn idle_connections_time_out() {
    let mut cfg = Config::default();
    cfg.limits.idle_timeout_secs = 1;
    let server = Harness::start_with(cfg).await;

    let mut c = server.connect().await;
    let started = Instant::now();
    assert!(
        c.closed().await,
        "an idle connection must be closed by the idle timeout"
    );
    assert!(started.elapsed() < Duration::from_secs(8));

    server.stop().await;
}

#[tokio::test]
async fn slow_clients_are_reaped_by_the_partial_frame_timeout() {
    let mut cfg = Config::default();
    cfg.limits.partial_frame_timeout_secs = 1;
    let server = Harness::start_with(cfg).await;

    let mut c = server.connect().await;
    c.write_raw(b"*1\r\n").await; // valid prefix, never completed

    let started = Instant::now();
    assert!(
        c.closed().await,
        "a client dribbling a partial frame must be disconnected"
    );
    assert!(started.elapsed() < Duration::from_secs(8));

    server.stop().await;
}

#[tokio::test]
async fn global_connection_cap_rejects_the_extra_client() {
    let mut cfg = Config::default();
    cfg.limits.max_connections = 1;
    cfg.limits.max_connections_per_ip = 1;
    let server = Harness::start_with(cfg).await;

    let mut first = server.connect().await;
    assert_eq!(first.call(&[b"PING"]).await, b"+PONG\r\n");

    let mut second = server
        .try_connect()
        .await
        .expect("the TCP handshake still succeeds");
    let _ = second.try_cmd(&[b"PING"]).await;
    assert!(
        second.closed().await,
        "the over-limit client must be dropped without a reply"
    );

    // The admitted client is untouched.
    assert_eq!(first.call(&[b"PING"]).await, b"+PONG\r\n");

    let summary = server.stop().await;
    assert!(
        summary.rejected_global + summary.rejected_per_ip >= 1,
        "the rejection must be counted: {summary:?}"
    );
}

#[tokio::test]
async fn per_ip_connection_cap_rejects_the_extra_client() {
    let mut cfg = Config::default();
    cfg.limits.max_connections = 8;
    cfg.limits.max_connections_per_ip = 1;
    let server = Harness::start_with(cfg).await;

    let mut first = server.connect().await;
    assert_eq!(first.call(&[b"PING"]).await, b"+PONG\r\n");

    let mut second = server.try_connect().await.expect("handshake");
    let _ = second.try_cmd(&[b"PING"]).await;
    assert!(
        second.closed().await,
        "a second connection from the same IP must be dropped"
    );
    assert_eq!(first.call(&[b"PING"]).await, b"+PONG\r\n");

    let summary = server.stop().await;
    assert!(
        summary.rejected_per_ip >= 1,
        "the per-IP rejection must be counted: {summary:?}"
    );
    assert_eq!(
        summary.rejected_global, 0,
        "the global cap was not the limiter here"
    );
}

/// A command flood on one connection is capped, and the cap is a clean close.
#[tokio::test]
async fn per_connection_command_limit_is_enforced() {
    let mut cfg = Config::default();
    cfg.limits.max_commands_per_conn = 5;
    let server = Harness::start_with(cfg).await;

    let mut c = server.connect().await;
    let mut closed = false;
    for _ in 0..40 {
        if !c.try_cmd(&[b"PING"]).await {
            closed = true;
            break;
        }
        // A close can arrive before any client-side timeout, so this must not
        // treat EOF as a failure to read.
        if c.try_reply(Duration::from_millis(300)).await.is_none() {
            closed = true;
            break;
        }
    }
    if !closed {
        closed = c.closed().await;
    }
    assert!(
        closed,
        "the connection must be closed after the command limit"
    );

    // The listener is unharmed.
    let mut fresh = server.connect().await;
    assert_eq!(fresh.call(&[b"PING"]).await, b"+PONG\r\n");

    server.stop().await;
}
