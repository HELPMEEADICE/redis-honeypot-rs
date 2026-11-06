//! Wire-level protocol behaviour over real TCP sockets.
//!
//! These tests never import the crate's own decoder to check replies — see
//! `support::read_reply`.

mod support;

use support::{Harness, bulk, count, encode_cmd, expect_error, line, type_byte};

#[tokio::test]
async fn resp2_basics_over_tcp() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    assert_eq!(c.call(&[b"PING"]).await, b"+PONG\r\n");
    assert_eq!(
        bulk(&c.call(&[b"PING", b"hello"]).await).as_deref(),
        Some(b"hello".as_slice())
    );
    assert_eq!(
        bulk(&c.call(&[b"ECHO", b"binary\x00value"]).await).as_deref(),
        Some(b"binary\x00value".as_slice())
    );
    // Unknown command: a standard Redis error, not a disconnect.
    let unknown = expect_error(&c.call(&[b"NOSUCHCOMMAND", b"x"]).await);
    assert!(unknown.contains("unknown command"), "got {unknown:?}");

    server.stop().await;
}

#[tokio::test]
async fn inline_commands_are_accepted() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    c.write_raw(b"PING\r\n").await;
    assert_eq!(c.reply().await, b"+PONG\r\n");

    // Quoted inline argument containing a space.
    c.write_raw(b"ECHO \"two words\"\r\n").await;
    assert_eq!(
        bulk(&c.reply().await).as_deref(),
        Some(b"two words".as_slice())
    );

    server.stop().await;
}

#[tokio::test]
async fn pipelined_commands_share_one_connection() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let mut batch = Vec::new();
    batch.extend_from_slice(&encode_cmd(&[b"PING"]));
    batch.extend_from_slice(&encode_cmd(&[b"ECHO", b"a"]));
    batch.extend_from_slice(&encode_cmd(&[b"PING"]));
    c.write_raw(&batch).await;

    assert_eq!(c.reply().await, b"+PONG\r\n");
    assert_eq!(bulk(&c.reply().await).as_deref(), Some(b"a".as_slice()));
    assert_eq!(c.reply().await, b"+PONG\r\n");

    server.stop().await;
}

/// TCP segmentation: the payload arrives before its trailing CRLF.
///
/// This is the exact shape that used to produce a spurious
/// `-ERR Protocol error: expected CRLF` and a disconnect.
#[tokio::test]
async fn payload_and_terminator_in_separate_segments() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    c.write_raw(b"*1\r\n").await;
    c.write_raw(b"$4\r\n").await;
    c.write_raw(b"PING").await;
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    c.write_raw(b"\r\n").await;

    assert_eq!(c.reply().await, b"+PONG\r\n");

    server.stop().await;
}

/// The strongest framing test: feed a two command pipeline one byte at a time.
#[tokio::test]
async fn byte_at_a_time_delivery() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let mut batch = Vec::new();
    batch.extend_from_slice(&encode_cmd(&[b"PING"]));
    batch.extend_from_slice(&encode_cmd(&[b"ECHO", b"xy"]));

    for byte in &batch {
        c.write_raw(&[*byte]).await;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    assert_eq!(c.reply().await, b"+PONG\r\n");
    assert_eq!(bulk(&c.reply().await).as_deref(), Some(b"xy".as_slice()));

    server.stop().await;
}

#[tokio::test]
async fn hello_negotiates_resp3_map_and_resp2_array() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let resp3 = c.call(&[b"HELLO", b"3"]).await;
    assert_eq!(type_byte(&resp3), b'%', "HELLO 3 must answer a RESP3 map");
    let pairs = count(&resp3).expect("map header");
    assert!(pairs >= 5, "expected the usual hello fields, got {pairs}");
    let text = String::from_utf8_lossy(&resp3);
    assert!(text.contains("proto"), "missing proto field: {text}");
    assert!(text.contains("version"), "missing version field: {text}");
    // The connection stays usable and speaks RESP3 after the swap.
    assert_eq!(c.call(&[b"PING"]).await, b"+PONG\r\n");

    let resp2 = c.call(&[b"HELLO", b"2"]).await;
    assert_eq!(type_byte(&resp2), b'*', "HELLO 2 must answer a RESP2 array");

    let noproto = expect_error(&c.call(&[b"HELLO", b"4"]).await);
    assert!(noproto.contains("NOPROTO"), "got {noproto:?}");

    server.stop().await;
}

#[tokio::test]
async fn illegal_length_is_rejected_and_the_server_survives() {
    let server = Harness::start().await;

    let mut bad = server.connect().await;
    bad.write_raw(b"*1\r\n$abc\r\n").await;
    let err = expect_error(&bad.reply().await);
    assert!(err.contains("ERR"), "got {err:?}");
    assert!(
        bad.closed().await,
        "the offending connection must be closed"
    );

    // A fresh client is unaffected: no shared state was poisoned.
    let mut good = server.connect().await;
    assert_eq!(good.call(&[b"PING"]).await, b"+PONG\r\n");

    server.stop().await;
}

#[tokio::test]
async fn integer_overflow_length_is_rejected() {
    let server = Harness::start().await;

    let mut bad = server.connect().await;
    bad.write_raw(b"*1\r\n$99999999999999999999\r\n").await;
    let err = expect_error(&bad.reply().await);
    assert!(err.contains("ERR"), "got {err:?}");
    assert!(bad.closed().await);

    let mut good = server.connect().await;
    assert_eq!(good.call(&[b"PING"]).await, b"+PONG\r\n");

    server.stop().await;
}

/// A declared 1 GiB bulk string must be refused from the header alone, without
/// the honeypot allocating anything for it.
#[tokio::test]
async fn oversized_bulk_declaration_is_refused_fast() {
    let server = Harness::start().await;

    let started = std::time::Instant::now();
    let mut bad = server.connect().await;
    bad.write_raw(b"*2\r\n$3\r\nGET\r\n$1073741824\r\n").await;
    let err = expect_error(&bad.reply().await);
    assert!(err.contains("ERR"), "got {err:?}");
    assert!(bad.closed().await);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "rejecting an oversized declaration must be immediate"
    );

    let mut good = server.connect().await;
    assert_eq!(good.call(&[b"PING"]).await, b"+PONG\r\n");

    server.stop().await;
}

#[tokio::test]
async fn binary_safe_values_survive_a_roundtrip() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let value: &[u8] = &[0x00, 0xff, 0x0d, 0x0a, b'A', 0x80];
    assert_eq!(
        line(&c.call(&[b"SET", b"bin", value]).await),
        "+OK".to_string()
    );

    let got = bulk(&c.call(&[b"GET", b"bin"]).await).expect("bulk reply");
    assert_eq!(got, value, "binary value must round-trip byte for byte");

    server.stop().await;
}

#[tokio::test]
async fn unknown_command_error_stays_bounded() {
    let server = Harness::start().await;
    let mut c = server.connect().await;

    let big = vec![b'A'; 8192];
    let err = expect_error(&c.call(&[b"FOOBAR", &big]).await);
    assert!(
        err.to_ascii_lowercase().contains("unknown command"),
        "got {err:?}"
    );
    assert!(
        err.len() < 512,
        "the error must not echo the whole payload, got {} bytes",
        err.len()
    );

    server.stop().await;
}
