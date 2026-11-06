//! Authentication deception: every AUTH succeeds, after a random 2–6 s delay.

mod support;

use std::time::{Duration, Instant};

use redis_honeypot_rs::config::Config;
use support::{Harness, bulk, expect_ok};

#[tokio::test]
async fn auth_always_succeeds_even_with_absurd_credentials() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 10;
    cfg.timing.auth_max_delay_ms = 30;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    expect_ok(&c.call(&[b"AUTH", b"hunter2"]).await);
    expect_ok(&c.call(&[b"AUTH", b"admin", b"hunter2"]).await);
    expect_ok(&c.call(&[b"AUTH", b"", b""]).await);
    expect_ok(&c.call(&[b"AUTH", b"default", b"\x00\xff binary"]).await);

    server.stop().await;
}

/// The headline requirement: the delay window really is 2–6 seconds, measured
/// end to end against the shipped defaults.
#[tokio::test]
async fn auth_delay_within_two_to_six_seconds_by_default() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let started = Instant::now();
    let reply = c.call(&[b"AUTH", b"whatever"]).await;
    let elapsed = started.elapsed();

    expect_ok(&reply);
    assert!(
        elapsed >= Duration::from_millis(1_900),
        "AUTH answered too fast: {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_millis(6_800),
        "AUTH answered too slow: {elapsed:?}"
    );

    server.stop().await;
}

/// The window is taken from configuration, not hardcoded.
#[tokio::test]
async fn auth_delay_follows_the_configured_window() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 50;
    cfg.timing.auth_max_delay_ms = 80;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    let started = Instant::now();
    expect_ok(&c.call(&[b"AUTH", b"x"]).await);
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(45),
        "AUTH ignored the configured minimum: {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(2),
        "AUTH did not use the configured window: {elapsed:?}"
    );

    server.stop().await;
}

/// Eight clients authenticate at once. If the delay were serialised or blocking,
/// the wall clock would be ~8x the delay; with an async sleep it is ~1x.
#[tokio::test]
async fn concurrent_auth_does_not_serialise() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 300;
    cfg.timing.auth_max_delay_ms = 400;
    let server = Harness::start_with(cfg).await;

    const CLIENTS: usize = 8;
    let mut conns = Vec::new();
    for _ in 0..CLIENTS {
        conns.push(server.connect().await);
    }

    let started = Instant::now();
    for c in conns.iter_mut() {
        c.cmd(&[b"AUTH", b"admin", b"pass"]).await;
    }
    for c in conns.iter_mut() {
        expect_ok(&c.reply().await);
    }
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(1_600),
        "{CLIENTS} concurrent AUTHs took {elapsed:?}; the delay is blocking the runtime"
    );

    // Every attempt is persisted with its own measured delay.
    let rows = server
        .wait_for_rows(
            "SELECT count(*) FROM auth_attempts WHERE username = 'admin'",
            CLIENTS as i64,
        )
        .await;
    assert!(rows >= CLIENTS as i64, "only {rows} AUTH rows recorded");

    server.stop().await;
}

/// A client that never authenticates is treated like a misconfigured instance:
/// commands work, and nothing prompts for a password.
#[tokio::test]
async fn commands_work_without_any_auth() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    expect_ok(&c.call(&[b"SET", b"k", b"v"]).await);
    assert_eq!(
        bulk(&c.call(&[b"GET", b"k"]).await).as_deref(),
        Some(b"v".as_slice())
    );
    assert_eq!(c.call(&[b"DBSIZE"]).await.first(), Some(&b':'));
    let info = bulk(&c.call(&[b"INFO"]).await).expect("INFO is a bulk string");
    assert!(info.windows(7).any(|w| w == b"redis_v"), "INFO looks wrong");

    server.stop().await;
}

#[tokio::test]
async fn auth_attempts_are_recorded_without_the_password() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 10;
    cfg.timing.auth_max_delay_ms = 20;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    expect_ok(&c.call(&[b"AUTH", b"admin", b"swordfish"]).await);
    drop(c);

    server
        .wait_for_rows("SELECT count(*) FROM auth_attempts", 1)
        .await;

    assert_eq!(
        server.query_string("SELECT username FROM auth_attempts LIMIT 1"),
        Some("admin".to_string())
    );
    assert_eq!(
        server.query_i64("SELECT password_len FROM auth_attempts LIMIT 1"),
        9,
        "password length must be recorded"
    );
    assert_eq!(
        server.query_string("SELECT password FROM auth_attempts LIMIT 1"),
        None,
        "the raw password must not be stored by default"
    );
    assert_eq!(
        server.query_i64("SELECT simulated_ok FROM auth_attempts LIMIT 1"),
        1
    );
    assert!(
        server.query_i64("SELECT delay_ms FROM auth_attempts LIMIT 1") >= 10,
        "the measured delay must be recorded"
    );

    server.stop().await;
}

#[tokio::test]
async fn password_recording_is_opt_in() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 10;
    cfg.timing.auth_max_delay_ms = 20;
    cfg.record_passwords = true;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    expect_ok(&c.call(&[b"AUTH", b"admin", b"swordfish"]).await);
    drop(c);

    server
        .wait_for_rows("SELECT count(*) FROM auth_attempts", 1)
        .await;
    assert_eq!(
        server.query_string("SELECT password FROM auth_attempts LIMIT 1"),
        Some("swordfish".to_string()),
        "opt-in recording must store the credential"
    );

    server.stop().await;
}
