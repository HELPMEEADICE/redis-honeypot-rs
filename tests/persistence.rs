//! Persistence: every interaction reaches the right table, bounded, and without
//! a single real side effect from a dangerous command.

mod support;

use std::path::Path;

use redis_honeypot_rs::config::Config;
use redis_honeypot_rs::db::{self, StatsQuery};
use support::{Harness, bulk, expect_error, expect_null, expect_ok, line};

#[tokio::test]
async fn every_record_kind_reaches_its_table() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    expect_ok(&c.call(&[b"AUTH", b"admin", b"secret"]).await);
    assert_eq!(c.call(&[b"PING"]).await, b"+PONG\r\n");
    assert_eq!(
        bulk(&c.call(&[b"ECHO", b"hi"]).await).as_deref(),
        Some(b"hi".as_slice())
    );
    drop(c); // clean disconnect

    server
        .wait_for_rows("SELECT count(*) FROM connections", 1)
        .await;
    // AUTH is captured by `auth_attempts`; `commands` holds the rest.
    server
        .wait_for_rows("SELECT count(*) FROM commands", 2)
        .await;
    server
        .wait_for_rows("SELECT count(*) FROM auth_attempts", 1)
        .await;

    // connections: source address, timing and close reason
    assert_eq!(
        server.query_string("SELECT ip FROM connections LIMIT 1"),
        Some("127.0.0.1".to_string())
    );
    assert!(server.query_i64("SELECT port FROM connections LIMIT 1") > 0);
    assert!(server.query_i64("SELECT connected_at FROM connections LIMIT 1") > 0);
    let reason_count = server
        .wait_for_rows(
            "SELECT count(*) FROM connections WHERE close_reason IS NOT NULL",
            1,
        )
        .await;
    assert!(reason_count >= 1, "close reason was never recorded");
    let reason = server
        .query_string("SELECT close_reason FROM connections WHERE close_reason IS NOT NULL LIMIT 1")
        .expect("close reason text");
    assert!(!reason.is_empty(), "close reason must be recorded");
    assert!(
        server.query_i64("SELECT duration_ms FROM connections LIMIT 1") >= 0,
        "duration must be recorded"
    );

    // commands: name, args, risk label and RESP type
    assert_eq!(
        server.query_string("SELECT name FROM commands ORDER BY id LIMIT 1"),
        Some("PING".to_string())
    );
    assert_eq!(
        server.query_string("SELECT name FROM commands ORDER BY id DESC LIMIT 1"),
        Some("ECHO".to_string())
    );
    assert_eq!(
        server.query_string("SELECT risk_label FROM commands ORDER BY id DESC LIMIT 1"),
        Some("none".to_string())
    );
    assert_eq!(
        server.query_string("SELECT resp_type FROM commands ORDER BY id DESC LIMIT 1"),
        Some("bulk_string".to_string())
    );

    server.stop().await;
}

/// The dangerous command set must answer convincingly and touch nothing.
#[tokio::test]
async fn dangerous_commands_are_recorded_and_change_nothing() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let wanted_dir = std::env::temp_dir().join("rhp-must-not-exist");
    let wanted_dir_str = wanted_dir.to_string_lossy().to_string();
    let module_path = std::env::temp_dir().join("rhp-evil-module.so");
    let module_path_str = module_path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&module_path);
    let _ = std::fs::remove_dir_all(&wanted_dir);

    // MODULE LOAD: a plausible failure reply, and no loader is ever reached.
    let module_reply = expect_error(
        &c.call(&[b"MODULE", b"LOAD", module_path_str.as_bytes()])
            .await,
    );
    assert!(module_reply.contains("ERR"), "got {module_reply:?}");
    assert!(
        !module_path.exists(),
        "MODULE LOAD must not create anything"
    );

    // CONFIG SET dir: +OK, but the directory must not be created or selected.
    expect_ok(
        &c.call(&[b"CONFIG", b"SET", b"dir", wanted_dir_str.as_bytes()])
            .await,
    );
    assert!(
        !wanted_dir.exists(),
        "CONFIG SET dir must not touch the filesystem"
    );

    // SAVE / BGSAVE: no RDB, no AOF, anywhere obvious.
    let _ = c.call(&[b"SAVE"]).await;
    let _ = c.call(&[b"BGSAVE"]).await;
    assert!(
        !Path::new("dump.rdb").exists(),
        "SAVE must not write an RDB file"
    );
    assert!(
        !Path::new("appendonly.aof").exists(),
        "BGSAVE must not write an AOF file"
    );

    // EVAL: the payload is never evaluated and never echoed back.
    let lua = "redis.call('set','pwned','1')";
    let eval_reply = c.call(&[b"EVAL", lua.as_bytes(), b"0"]).await;
    let eval_text = line(&eval_reply);
    assert!(
        !eval_text.contains("redis.call"),
        "the Lua payload must not be echoed: {eval_text:?}"
    );

    // REPLICAOF: no outbound connection is attempted.
    let replica_reply = c.call(&[b"REPLICAOF", b"203.0.113.9", b"6379"]).await;
    assert_ne!(support::type_byte(&replica_reply), b'$');

    // FLUSHALL only clears the virtual keyspace.
    expect_ok(&c.call(&[b"SET", b"keepme", b"1"]).await);
    expect_ok(&c.call(&[b"FLUSHALL"]).await);
    assert_eq!(c.call(&[b"GET", b"keepme"]).await, b"$-1\r\n");

    // SHUTDOWN ends this connection only; the honeypot keeps serving.
    expect_ok(&c.call(&[b"SHUTDOWN"]).await);
    assert!(
        c.closed().await,
        "SHUTDOWN must close the client connection"
    );
    let mut after = server.connect().await;
    assert_eq!(
        after.call(&[b"PING"]).await,
        b"+PONG\r\n",
        "SHUTDOWN must not stop the honeypot"
    );

    // All of it is on the record, at high severity.
    let risky = server
        .wait_for_rows("SELECT count(*) FROM commands WHERE risk >= 3", 5)
        .await;
    assert!(risky >= 5, "only {risky} critical/high risk rows recorded");

    let events = server
        .wait_for_rows(
            "SELECT count(*) FROM security_events WHERE kind = 'dangerous_command'",
            5,
        )
        .await;
    assert!(
        events >= 5,
        "only {events} dangerous_command events recorded"
    );

    let saved = server
        .query_string("SELECT simulated FROM commands WHERE name = 'SAVE' ORDER BY id LIMIT 1");
    assert!(
        saved.as_deref().is_some_and(|s| s.contains("simulat")),
        "the SAVE reply must be labelled as simulated, got {saved:?}"
    );

    server.stop().await;
}

#[tokio::test]
async fn oversized_and_binary_arguments_are_stored_bounded() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    // Under the virtual value cap: accepted, and the stored preview is truncated.
    let medium: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    expect_ok(&c.call(&[b"SET", b"bigkey", &medium]).await);

    // Over the virtual value cap: refused, and nothing is stored for it.
    let oversized: Vec<u8> = vec![b'Z'; 8000];
    let refused = expect_error(&c.call(&[b"SET", b"hugekey", &oversized]).await);
    assert!(
        refused.contains("too large"),
        "an oversized value must be refused, got {refused:?}"
    );
    expect_null(&c.call(&[b"GET", b"hugekey"]).await);

    server
        .wait_for_rows("SELECT count(*) FROM commands WHERE name = 'SET'", 2)
        .await;

    let stored_len = server.query_i64(
        "SELECT length(CAST(args AS BLOB)) FROM commands WHERE name = 'SET' ORDER BY id LIMIT 1",
    );
    assert!(
        stored_len > 0 && stored_len <= 2048 + 8,
        "stored args must be truncated to the configured cap, got {stored_len} bytes"
    );

    // Still valid UTF-8 text: non-UTF-8 input is escaped, never stored raw.
    let stored = server
        .query_string("SELECT args FROM commands WHERE name = 'SET' ORDER BY id LIMIT 1")
        .expect("stored args must read back as text");
    assert!(
        stored.contains("SET"),
        "preview lost the command name: {stored:?}"
    );

    server.stop().await;
}

#[tokio::test]
async fn concurrent_clients_lose_no_commands() {
    let server = Harness::start().await;

    const CLIENTS: usize = 8;
    const PER_CLIENT: usize = 20;

    let mut conns = Vec::new();
    for _ in 0..CLIENTS {
        conns.push(server.connect().await);
    }
    for c in conns.iter_mut() {
        for _ in 0..PER_CLIENT {
            c.cmd(&[b"PING"]).await;
        }
        for _ in 0..PER_CLIENT {
            assert_eq!(c.reply().await, b"+PONG\r\n");
        }
    }

    let total = server
        .wait_for_rows("SELECT count(*) FROM commands WHERE name = 'PING'", 160)
        .await;
    assert!(
        total >= (CLIENTS * PER_CLIENT) as i64,
        "expected {} PING rows, found {total}",
        CLIENTS * PER_CLIENT
    );

    let connections = server.query_i64("SELECT count(*) FROM connections");
    assert!(
        connections >= CLIENTS as i64,
        "only {connections} connection rows"
    );

    server.stop().await;
}

#[tokio::test]
async fn stats_report_reads_the_live_database() {
    let server = Harness::start().await;
    let mut c = server.connect().await;
    assert_eq!(c.call(&[b"PING"]).await, b"+PONG\r\n");
    let _ = c.call(&[b"CONFIG", b"GET", b"dir"]).await;
    drop(c);

    server
        .wait_for_rows("SELECT count(*) FROM commands", 2)
        .await;

    let query = StatsQuery {
        top_ips: 5,
        top_commands: 5,
        auth: true,
        dangerous: false,
    };
    let report = db::stats::collect(&server.db_path, &query).expect("collect stats");

    let lookup = |key: &str| -> Option<String> {
        report
            .summary
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    for key in [
        "connections.total",
        "connections.active",
        "commands.total",
        "commands.distinct_ips",
        "auth.attempts",
        "security.events",
        "dangerous.commands",
        "db.size_bytes",
    ] {
        assert!(lookup(key).is_some(), "summary is missing the key {key}");
    }

    let commands_total: i64 = lookup("commands.total").unwrap().parse().unwrap();
    assert!(commands_total >= 2, "commands.total = {commands_total}");
    assert!(lookup("connections.total").unwrap().parse::<i64>().unwrap() >= 1);

    let rendered = report.render();
    assert!(
        rendered.contains("connections.total"),
        "render lost the summary"
    );
    assert!(
        rendered.contains("Top source IPs"),
        "render lost the IP section"
    );
    assert!(
        rendered.contains("127.0.0.1"),
        "render lost the observed source address"
    );
    assert!(
        rendered.ends_with('\n'),
        "rendered report must end with a newline"
    );

    // A missing database is an error, and must not be created.
    let missing = std::env::temp_dir().join("rhp-definitely-absent.db");
    let _ = std::fs::remove_file(&missing);
    assert!(db::stats::collect(&missing, &query).is_err());
    assert!(!missing.exists(), "collect must not create the database");

    server.stop().await;
}

#[tokio::test]
async fn bulk_replies_are_recorded_with_their_resp_type() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let info = bulk(&c.call(&[b"INFO"]).await).expect("INFO is a bulk string");
    assert!(
        info.windows(13).any(|w| w == b"redis_version"),
        "INFO body looks wrong"
    );
    expect_ok(&c.call(&[b"SET", b"a", b"b"]).await);
    drop(c);

    server
        .wait_for_rows("SELECT count(*) FROM commands WHERE name = 'INFO'", 1)
        .await;
    assert_eq!(
        server.query_string("SELECT resp_type FROM commands WHERE name = 'INFO' LIMIT 1"),
        Some("bulk_string".to_string())
    );
    assert_eq!(
        server.query_string("SELECT resp_type FROM commands WHERE name = 'SET' LIMIT 1"),
        Some("simple_string".to_string())
    );

    server.stop().await;
}

/// Regression guard for the credential-leak class: the rendered preview is the
/// single string that reaches both the console and `commands.args`, so it must
/// never carry password material.
#[tokio::test]
async fn credential_material_never_reaches_the_database() {
    let mut cfg = Config::default();
    cfg.timing.auth_min_delay_ms = 10;
    cfg.timing.auth_max_delay_ms = 20;
    let server = Harness::start_with(cfg).await;
    let mut c = server.connect().await;

    const SECRET: &str = "swordfish123";
    expect_ok(&c.call(&[b"AUTH", b"admin", SECRET.as_bytes()]).await);
    let _ = c
        .call(&[b"HELLO", b"3", b"AUTH", b"default", SECRET.as_bytes()])
        .await;
    // `CONFIG SET requirepass` installs a credential the attacker chose: it must
    // be masked in the very same places ordinary commands are rendered.
    expect_ok(
        &c.call(&[b"CONFIG", b"SET", b"requirepass", SECRET.as_bytes()])
            .await,
    );
    drop(c);

    server
        .wait_for_rows("SELECT count(*) FROM auth_attempts", 1)
        .await;
    server
        .wait_for_rows("SELECT count(*) FROM commands", 1)
        .await;

    assert_eq!(
        server.query_string("SELECT password FROM auth_attempts LIMIT 1"),
        None,
        "the raw password must not be stored by default"
    );
    assert_eq!(
        server.query_i64("SELECT password_len FROM auth_attempts LIMIT 1"),
        SECRET.len() as i64
    );

    let leaked = server.query_i64("SELECT count(*) FROM commands WHERE args LIKE '%swordfish123%'");
    assert_eq!(leaked, 0, "the secret leaked into commands.args");

    // The security event detail is both printed (ALERT) and persisted, so it
    // must not carry the credential either.
    let leaked_detail = server
        .wait_for(
            "security_events rows",
            std::time::Duration::from_secs(10),
            || {
                let n = server.query_i64("SELECT count(*) FROM security_events");
                (n > 0).then_some(n)
            },
        )
        .await;
    assert!(
        leaked_detail > 0,
        "the CONFIG SET alert must be recorded at all"
    );
    assert_eq!(
        server.query_i64("SELECT count(*) FROM security_events WHERE detail LIKE '%swordfish123%'"),
        0,
        "the secret leaked into security_events.detail"
    );

    let hello = server
        .query_string("SELECT args FROM commands WHERE name = 'HELLO' LIMIT 1")
        .expect("HELLO row");
    assert!(
        !hello.contains(SECRET),
        "HELLO AUTH tokens must be masked: {hello:?}"
    );
    assert!(
        hello.contains("******"),
        "expected a masked preview: {hello:?}"
    );

    server.stop().await;
}
