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

// ---------------------------------------------------------------------------
// Disconnect handling during the simulated delay
// ---------------------------------------------------------------------------

/// A client that hangs up (`FIN`) while its AUTH is being delayed must be
/// noticed immediately: the per-IP slot is released long before the delay would
/// have elapsed, and the cancelled attempt is still recorded.
#[tokio::test]
async fn client_fin_during_auth_releases_the_slot_and_keeps_the_attempt() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 5_000;
    cfg.timing.auth_max_delay_ms = 6_000;
    // One slot per IP: if the disconnected connection kept it, the second client
    // could never get in.
    cfg.limits.max_connections_per_ip = 1;
    let server = Harness::start_with(cfg).await;

    let started = Instant::now();
    let mut first = server.connect().await;
    first.cmd(&[b"AUTH", b"admin", b"pw"]).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(first); // FIN

    let mut admitted = false;
    while started.elapsed() < Duration::from_secs(3) {
        if let Some(mut candidate) = server.try_connect().await {
            if candidate.try_cmd(&[b"PING"]).await
                && candidate
                    .try_reply(Duration::from_millis(300))
                    .await
                    .as_deref()
                    == Some(b"+PONG\r\n")
            {
                admitted = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        admitted,
        "the disconnected AUTH held its per-IP slot for the whole 5 s delay"
    );

    // The attempt itself is forensics, not garbage: it is kept, with the reason
    // and the time actually spent waiting.
    let rows = server
        .wait_for_rows(
            "SELECT count(*) FROM auth_attempts WHERE meta LIKE '%outcome=client_fin%'",
            1,
        )
        .await;
    assert!(rows >= 1, "the cancelled attempt was not recorded");
    assert_eq!(
        server.query_i64("SELECT password_len FROM auth_attempts LIMIT 1"),
        2
    );
    assert_eq!(
        server.query_string("SELECT password FROM auth_attempts LIMIT 1"),
        None,
        "the password must stay masked for a cancelled attempt too"
    );
    let meta = server
        .query_string("SELECT meta FROM auth_attempts LIMIT 1")
        .expect("meta");
    assert!(meta.contains("via=auth"), "{meta}");
    assert!(meta.contains("planned_ms="), "{meta}");
    assert!(meta.contains("waited_ms="), "{meta}");
    // The connection ended because the client left, not because of a timeout.
    // (The probe connection above also ends as `client_closed`, hence `>=`.)
    assert!(
        server.query_i64("SELECT count(*) FROM connections WHERE close_reason = 'client_closed'")
            >= 1,
        "the close reason must say the client left"
    );

    server.stop().await;
}

/// The same with an `RST` instead of a `FIN`.
#[tokio::test]
async fn client_reset_during_auth_is_detected() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 5_000;
    cfg.timing.auth_max_delay_ms = 6_000;
    let server = Harness::start_with(cfg).await;

    let mut c = server.connect().await;
    c.cmd(&[b"AUTH", b"root", b"hunter2"]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    c.abort(); // RST

    let rows = server
        .wait_for_rows(
            "SELECT count(*) FROM auth_attempts WHERE meta LIKE '%outcome=client_reset%'",
            1,
        )
        .await;
    assert!(rows >= 1, "the reset attempt was not recorded");
    assert_eq!(
        server.query_i64("SELECT password_len FROM auth_attempts LIMIT 1"),
        7
    );

    server.stop().await;
}

/// A whole AUTH delay must not stall the pipeline: the follow-up command was
/// already in the socket, and disconnect probing must not swallow it.
#[tokio::test]
async fn a_pipelined_command_survives_the_auth_delay() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 200;
    cfg.timing.auth_max_delay_ms = 300;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    let mut batch = Vec::new();
    batch.extend_from_slice(&support::encode_cmd(&[b"AUTH", b"admin", b"pw"]));
    batch.extend_from_slice(&support::encode_cmd(&[b"PING"]));
    batch.extend_from_slice(&support::encode_cmd(&[b"ECHO", b"tail"]));
    c.write_raw(&batch).await;

    // Order is exactly the order the client sent, and no reply is lost.
    expect_ok(&c.reply().await);
    assert_eq!(c.reply().await, b"+PONG\r\n");
    assert_eq!(
        support::bulk(&c.reply().await).as_deref(),
        Some(b"tail".as_slice())
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// HELLO … AUTH
// ---------------------------------------------------------------------------

/// `HELLO 3 AUTH u p` is a credential attempt and has to show up in
/// `auth_attempts`, with the negotiated protocol and the same masking rules.
#[tokio::test]
async fn hello_auth_is_recorded_as_an_attempt() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 20;
    cfg.timing.auth_max_delay_ms = 40;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    let started = Instant::now();
    let reply = c
        .call(&[b"HELLO", b"3", b"AUTH", b"default", b"hunter2"])
        .await;
    assert_eq!(
        support::type_byte(&reply),
        b'%',
        "HELLO 3 must still answer a RESP3 map"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(15),
        "HELLO AUTH was not delayed like AUTH"
    );

    server
        .wait_for_rows(
            "SELECT count(*) FROM auth_attempts WHERE username = 'default'",
            1,
        )
        .await;
    assert_eq!(
        server.query_i64("SELECT password_len FROM auth_attempts LIMIT 1"),
        7
    );
    assert_eq!(
        server.query_string("SELECT password FROM auth_attempts LIMIT 1"),
        None,
        "HELLO AUTH must not store the password by default"
    );
    let meta = server
        .query_string("SELECT meta FROM auth_attempts LIMIT 1")
        .expect("meta");
    assert!(meta.contains("via=hello"), "{meta}");
    assert!(meta.contains("proto=3"), "{meta}");
    assert!(meta.contains("outcome=ok"), "{meta}");

    // HELLO 2 negotiates down and answers a RESP2 array.
    let resp2 = c.call(&[b"HELLO", b"2", b"AUTH", b"root", b"pw"]).await;
    assert_eq!(support::type_byte(&resp2), b'*');
    server
        .wait_for_rows(
            "SELECT count(*) FROM auth_attempts WHERE username = 'root'",
            1,
        )
        .await;

    // Both attempts are also visible as commands, with the credential masked.
    let rows = server
        .wait_for_rows("SELECT count(*) FROM commands WHERE name = 'HELLO'", 2)
        .await;
    assert_eq!(rows, 2, "HELLO is a command as well as an attempt");
    assert_eq!(
        server.query_i64("SELECT count(*) FROM commands WHERE args LIKE '%hunter2%'"),
        0,
        "the HELLO preview leaked the password"
    );

    server.stop().await;
}
