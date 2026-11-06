//! Shared harness for the integration tests.
//!
//! Every test gets a real listener on `127.0.0.1:0`, a real SQLite file in the
//! temp directory, and a raw `TcpStream`. Nothing here reuses the crate's own
//! RESP decoder to check replies: `value_end` below is an independent little
//! parser, so an encoder bug cannot hide behind a matching decoder bug.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use redis_honeypot_rs::config::Config;
use redis_honeypot_rs::db::{self, DbHandle};
use redis_honeypot_rs::server::{self, ServerError, ServerSummary, ShutdownHandle};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A unique temp database path per test, cleaned up in [`Harness::stop`].
pub fn temp_db_path() -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rhp-it-{}-{}.db", std::process::id(), n))
}

fn remove_db_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}

/// A running honeypot with a live database writer.
pub struct Harness {
    pub addr: SocketAddr,
    pub db_path: PathBuf,
    shutdown: ShutdownHandle,
    task: Option<JoinHandle<Result<ServerSummary, ServerError>>>,
    db: Option<DbHandle>,
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(Config::default()).await
    }

    /// Start with a caller-tuned config. `bind` and the database path are
    /// overwritten so tests never share a socket or a file.
    pub async fn start_with(mut cfg: Config) -> Self {
        cfg.bind = SocketAddr::from(([127, 0, 0, 1], 0));
        let db_path = temp_db_path();
        remove_db_files(&db_path);
        cfg.database.path = db_path.clone();
        cfg.validate().expect("test config must be valid");

        let db = db::spawn_writer(&cfg.database).expect("database writer");
        let recorder = db.recorder.clone();
        let shutdown = ShutdownHandle::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        let server_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            server::serve(cfg, recorder, server_shutdown, Some(ready_tx)).await
        });

        let bound = tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("listener did not bind within 10s")
            .expect("listener task died before binding");
        let addr = *bound.first().expect("at least one listener");

        Self {
            addr,
            db_path,
            shutdown,
            task: Some(task),
            db: Some(db),
        }
    }

    pub async fn connect(&self) -> Conn {
        let stream = TcpStream::connect(self.addr).await.expect("tcp connect");
        stream.set_nodelay(true).expect("nodelay");
        Conn {
            stream,
            buf: Vec::new(),
        }
    }

    /// Try to connect; used by the admission-control tests where the server may
    /// accept and immediately drop.
    pub async fn try_connect(&self) -> Option<Conn> {
        let stream = TcpStream::connect(self.addr).await.ok()?;
        stream.set_nodelay(true).ok()?;
        Some(Conn {
            stream,
            buf: Vec::new(),
        })
    }

    /// A standalone connection for reading the database while the server runs.
    fn reader(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(&self.db_path).expect("open db for read");
        conn.busy_timeout(Duration::from_secs(5))
            .expect("busy_timeout");
        conn
    }

    pub fn query_i64(&self, sql: &str) -> i64 {
        self.reader()
            .query_row(sql, [], |row| row.get::<_, i64>(0))
            .unwrap_or(0)
    }

    pub fn query_string(&self, sql: &str) -> Option<String> {
        self.reader()
            .query_row(sql, [], |row| row.get::<_, Option<String>>(0))
            .ok()
            .flatten()
    }

    /// Poll `probe` until it yields `Some`, or panic after `timeout`.
    pub async fn wait_for<F>(&self, what: &str, timeout: Duration, mut probe: F) -> i64
    where
        F: FnMut() -> Option<i64>,
    {
        let start = Instant::now();
        loop {
            if let Some(value) = probe() {
                return value;
            }
            if start.elapsed() > timeout {
                panic!("timed out after {timeout:?} waiting for {what}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Wait until at least `min` rows match, returning the count.
    pub async fn wait_for_rows(&self, sql: &'static str, min: i64) -> i64 {
        let start = Instant::now();
        loop {
            let n = self.query_i64(sql);
            if n >= min {
                return n;
            }
            if start.elapsed() > Duration::from_secs(10) {
                panic!("timed out after 10s: `{sql}` reached only {n} rows (wanted {min})");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Shut down gracefully and clean up.
    pub async fn stop(mut self) -> ServerSummary {
        self.shutdown.trigger();
        let task = self.task.take().expect("server task");
        let summary = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("server did not stop within 10s")
            .expect("server task panicked")
            .expect("server returned an error");
        if let Some(db) = self.db.take() {
            db.shutdown().await;
        }
        remove_db_files(&self.db_path);
        summary
    }
}

/// One client connection with a handful of protocol conveniences.
///
/// `buf` is essential: a single `read()` usually returns several pipelined
/// replies at once, so bytes past the first frame must survive into the next
/// call instead of being dropped.
pub struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    pub async fn write_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
        self.stream.flush().await.expect("flush");
    }

    /// Send a command as a RESP array of bulk strings.
    pub async fn cmd(&mut self, args: &[&[u8]]) {
        let encoded = encode_cmd(args);
        self.write_raw(&encoded).await;
    }

    /// Like [`Conn::cmd`] but tolerates a peer that has already been dropped.
    /// Returns `false` when the write failed (typical for a rejected client).
    pub async fn try_cmd(&mut self, args: &[&[u8]]) -> bool {
        let encoded = encode_cmd(args);
        match self.stream.write_all(&encoded).await {
            Ok(()) => self.stream.flush().await.is_ok(),
            Err(_) => false,
        }
    }

    /// Read exactly one reply (any RESP type), keeping any surplus buffered.
    pub async fn reply(&mut self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(end) = value_end(&self.buf, 0) {
                    return self.buf.drain(..end).collect::<Vec<u8>>();
                }
                let mut chunk = [0u8; 1024];
                let n = self.stream.read(&mut chunk).await.expect("socket read");
                assert!(
                    n > 0,
                    "peer closed before a complete reply; buffered {:?}",
                    String::from_utf8_lossy(&self.buf)
                );
                self.buf.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .expect("reply timed out")
    }

    /// Send `args` and return the single reply.
    pub async fn call(&mut self, args: &[&[u8]]) -> Vec<u8> {
        self.cmd(args).await;
        self.reply().await
    }

    /// True when the peer has closed (EOF or reset) within the timeout.
    pub async fn closed(&mut self) -> bool {
        if !self.buf.is_empty() {
            return false;
        }
        let mut chunk = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(8), self.stream.read(&mut chunk)).await {
            Ok(Ok(0)) => true,
            Ok(Ok(_)) => false,
            Ok(Err(_)) => true,
            Err(_) => false,
        }
    }
}

/// Encode a command the way `redis-cli` does.
pub fn encode_cmd(args: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Independent reply reader (deliberately not the crate's decoder)
// ---------------------------------------------------------------------------

/// End offset of the RESP value starting at `pos`, or `None` while incomplete.
fn value_end(buf: &[u8], pos: usize) -> Option<usize> {
    let type_byte = *buf.get(pos)?;
    match type_byte {
        b'+' | b'-' | b':' | b',' | b'#' | b'_' => line_end(buf, pos + 1),
        b'$' => {
            let (len, after) = num_line(buf, pos + 1)?;
            if len < 0 {
                return Some(after);
            }
            let end = after
                .checked_add(usize::try_from(len).ok()?)?
                .checked_add(2)?;
            (end <= buf.len()).then_some(end)
        }
        b'*' | b'~' | b'>' | b'%' => {
            let (len, mut cursor) = num_line(buf, pos + 1)?;
            if len < 0 {
                return Some(cursor);
            }
            let count = usize::try_from(len).ok()?;
            let count = if type_byte == b'%' {
                count.checked_mul(2)?
            } else {
                count
            };
            for _ in 0..count {
                cursor = value_end(buf, cursor)?;
            }
            Some(cursor)
        }
        _ => None,
    }
}

fn line_end(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

fn num_line(buf: &[u8], from: usize) -> Option<(i64, usize)> {
    let end = line_end(buf, from)?;
    let text = std::str::from_utf8(buf.get(from..end.checked_sub(2)?)?).ok()?;
    Some((text.parse().ok()?, end))
}

/// Type byte of a reply (`+ - : $ * % _`).
pub fn type_byte(reply: &[u8]) -> u8 {
    *reply.first().expect("reply is never empty")
}

/// Simple string / error / integer payload without the framing.
pub fn line(reply: &[u8]) -> String {
    String::from_utf8_lossy(reply)
        .trim_end_matches("\r\n")
        .to_string()
}

/// Payload of a bulk string reply.
pub fn bulk(reply: &[u8]) -> Option<Vec<u8>> {
    // Slice relative to the post-`$` remainder, never relative to the whole
    // reply: the type byte shifts every offset by one.
    let rest = reply.strip_prefix(b"$")?;
    let nl = rest.windows(2).position(|w| w == b"\r\n")?;
    let len: i64 = std::str::from_utf8(&rest[..nl]).ok()?.parse().ok()?;
    if len < 0 {
        return None;
    }
    let len = usize::try_from(len).ok()?;
    rest.get(nl + 2..nl + 2 + len).map(<[u8]>::to_vec)
}

/// Integer payload of a `:` reply.
pub fn integer(reply: &[u8]) -> Option<i64> {
    let rest = reply.strip_prefix(b":")?;
    std::str::from_utf8(rest).ok()?.trim_end().parse().ok()
}

/// Element count declared by an array or map header.
pub fn count(reply: &[u8]) -> Option<usize> {
    let rest = reply
        .strip_prefix(b"*")
        .or_else(|| reply.strip_prefix(b"%"))?;
    let nl = rest.windows(2).position(|w| w == b"\r\n")?;
    std::str::from_utf8(&rest[..nl]).ok()?.parse().ok()
}

/// Assert a reply is an error, returning its text.
pub fn expect_error(reply: &[u8]) -> String {
    assert_eq!(
        type_byte(reply),
        b'-',
        "expected an error reply, got {:?}",
        line(reply)
    );
    line(reply)
}

/// Assert a reply is a simple `OK`.
pub fn expect_ok(reply: &[u8]) {
    assert_eq!(reply, b"+OK\r\n", "expected +OK, got {:?}", line(reply));
}

/// Assert the reply is a null bulk string.
pub fn expect_null(reply: &[u8]) {
    assert!(
        reply == b"$-1\r\n" || reply == b"_\r\n",
        "expected a null reply, got {:?}",
        line(reply)
    );
}
