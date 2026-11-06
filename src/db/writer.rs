//! The single blocking SQLite writer.
//!
//! Everything in this module runs on one `tokio::task::spawn_blocking` thread
//! and owns the only writable [`Connection`]. The network path never waits for
//! it: it `try_send`s into a bounded channel and moves on
//! ([`crate::record::Recorder`]).
//!
//! Two rules shape the code below:
//!
//! * **Batch, then commit once.** The whole point of buffering is fewer fsyncs,
//!   so a batch of records is applied inside one transaction and committed once.
//! * **Failures are logged and survived.** A database error must never reach the
//!   listener and must never panic: telemetry loss is strictly better than a
//!   honeypot that dies with its disk.

use std::time::{Duration, Instant};

use rusqlite::Connection;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use crate::config::Database as DatabaseConfig;
use crate::record::Record;
use crate::text::truncate_str;
use crate::timeutil::unix_millis;

use super::DbError;

/// Cap for `commands.args`, `auth_attempts.meta` and `security_events.detail`.
///
/// [`crate::config::Limits::max_stored_param_bytes`] is the authority, but
/// [`super::spawn_writer`] only receives a [`DatabaseConfig`], so the writer
/// mirrors that default here. A test asserts the two stay in sync.
pub(crate) const PARAM_CAP: usize = 2_048;

/// Cap for `*.ip` (`INET6_ADDRSTRLEN` is 46, so this is generous).
const CAP_IP: usize = 64;
/// Cap for `commands.name` and `security_events.command`.
const CAP_NAME: usize = 64;
/// Cap for short enum labels: `resp_type`, `simulated`, `close_reason`, `kind`.
const CAP_LABEL: usize = 64;
/// Cap for `auth_attempts.username`.
const CAP_USERNAME: usize = 256;
/// Cap for `auth_attempts.password` (only stored when explicitly enabled).
const CAP_PASSWORD: usize = 512;

/// How long the drain loop sleeps while waiting for the batch window to close.
const POLL_SLEEP: Duration = Duration::from_millis(2);
/// Rows removed by a single retention `DELETE`.
const PRUNE_CHUNK: i64 = 5_000;
/// Upper bound on retention `DELETE` statements per table per pass.
const PRUNE_PASSES: usize = 8;
/// Upper bound on size-cap pruning passes per maintenance tick.
const SIZE_PASSES: usize = 20;
/// Fraction of each table trimmed per size-cap pass (`1 / SIZE_FRACTION`).
const SIZE_FRACTION: i64 = 20;

const SQL_OPENED: &str = "INSERT OR REPLACE INTO connections \
     (conn_id, ip, port, connected_at) VALUES (?1, ?2, ?3, ?4)";
const SQL_CLOSED: &str = "UPDATE connections SET disconnected_at = ?1, duration_ms = ?2, \
     command_count = ?3, close_reason = ?4 WHERE conn_id = ?5";
const SQL_CLOSED_ORPHAN: &str = "INSERT OR REPLACE INTO connections \
     (conn_id, ip, port, connected_at, disconnected_at, duration_ms, command_count, close_reason) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
const SQL_COMMAND: &str = "INSERT INTO commands \
     (conn_id, ts, ip, name, args, arg_count, resp_type, simulated, risk, risk_label) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
const SQL_AUTH: &str = "INSERT INTO auth_attempts \
     (conn_id, ts, ip, username, arg_count, password_len, password, simulated_ok, delay_ms, meta) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
const SQL_SECURITY: &str = "INSERT INTO security_events \
     (conn_id, ts, ip, kind, command, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

const SQL_PRUNE_COMMANDS: &str =
    "DELETE FROM commands WHERE id IN (SELECT id FROM commands WHERE ts < ?1 LIMIT ?2)";
const SQL_PRUNE_AUTH: &str =
    "DELETE FROM auth_attempts WHERE id IN (SELECT id FROM auth_attempts WHERE ts < ?1 LIMIT ?2)";
const SQL_PRUNE_SECURITY: &str = "DELETE FROM security_events WHERE id IN \
     (SELECT id FROM security_events WHERE ts < ?1 LIMIT ?2)";
const SQL_PRUNE_CONNECTIONS: &str = "DELETE FROM connections WHERE conn_id IN \
     (SELECT conn_id FROM connections WHERE connected_at < ?1 LIMIT ?2)";

const SQL_OLDEST_COMMANDS: &str =
    "DELETE FROM commands WHERE id IN (SELECT id FROM commands ORDER BY ts ASC, id ASC LIMIT ?1)";
const SQL_OLDEST_AUTH: &str = "DELETE FROM auth_attempts WHERE id IN \
     (SELECT id FROM auth_attempts ORDER BY ts ASC, id ASC LIMIT ?1)";
const SQL_OLDEST_SECURITY: &str = "DELETE FROM security_events WHERE id IN \
     (SELECT id FROM security_events ORDER BY ts ASC, id ASC LIMIT ?1)";
const SQL_OLDEST_CONNECTIONS: &str = "DELETE FROM connections WHERE conn_id IN \
     (SELECT conn_id FROM connections ORDER BY connected_at ASC, conn_id ASC LIMIT ?1)";

const SQL_COUNT_COMMANDS: &str = "SELECT count(*) FROM commands";
const SQL_COUNT_AUTH: &str = "SELECT count(*) FROM auth_attempts";
const SQL_COUNT_SECURITY: &str = "SELECT count(*) FROM security_events";
const SQL_COUNT_CONNECTIONS: &str = "SELECT count(*) FROM connections";
const SQL_PAGE_COUNT: &str = "PRAGMA page_count";
const SQL_PAGE_SIZE: &str = "PRAGMA page_size";

/// Everything the writer needs to know about scheduling and storage caps.
#[derive(Debug, Clone)]
pub(crate) struct Tuning {
    batch_size: usize,
    batch_interval: Duration,
    retention_days: u32,
    max_bytes: u64,
    checkpoint_interval: Duration,
    maintenance_interval: Duration,
    param_cap: usize,
}

impl Tuning {
    pub(crate) fn from_config(cfg: &DatabaseConfig) -> Self {
        Self {
            batch_size: cfg.batch_size.max(1),
            batch_interval: Duration::from_millis(cfg.batch_interval_ms),
            retention_days: cfg.retention_days,
            max_bytes: cfg.max_bytes,
            checkpoint_interval: Duration::from_secs(cfg.checkpoint_interval_secs.max(1)),
            maintenance_interval: Duration::from_secs(cfg.maintenance_interval_secs.max(1)),
            param_cap: PARAM_CAP,
        }
    }
}

/// Drain the record channel until it closes, then return.
///
/// Runs on a blocking thread: `blocking_recv` / `try_recv` only, never
/// `blocking_send` (the writer is the receiving end, it never produces).
pub(crate) fn run(mut conn: Connection, mut rx: mpsc::Receiver<Record>, tuning: Tuning) {
    tracing::debug!(
        batch_size = tuning.batch_size,
        batch_interval_ms = tuning.batch_interval.as_millis(),
        "sqlite writer started"
    );

    let mut last_maintenance = Instant::now();
    let mut last_checkpoint = Instant::now();
    let mut batch: Vec<Record> = Vec::with_capacity(tuning.batch_size.min(1_024));

    loop {
        batch.clear();

        // Block until there is at least one record; `None` means the channel is
        // closed *and* drained, so everything already batched is committed.
        let Some(first) = rx.blocking_recv() else {
            break;
        };
        batch.push(first);

        // Then fill the batch without waiting: up to `batch_size` records or
        // until the batch window closes, whichever comes first.
        let mut disconnected = false;
        let deadline = Instant::now() + tuning.batch_interval;
        while batch.len() < tuning.batch_size {
            match rx.try_recv() {
                Ok(record) => batch.push(record),
                Err(TryRecvError::Empty) => {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    std::thread::sleep(deadline.saturating_duration_since(now).min(POLL_SLEEP));
                }
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        // Housekeeping first: a maintenance pass that ran before this batch is
        // visible as soon as the batch itself is.
        if last_maintenance.elapsed() >= tuning.maintenance_interval {
            maintain(&mut conn, &tuning);
            last_maintenance = Instant::now();
        }
        if last_checkpoint.elapsed() >= tuning.checkpoint_interval {
            checkpoint(&conn);
            last_checkpoint = Instant::now();
        }

        match apply_batch(&mut conn, &batch, &tuning) {
            Ok(()) => {}
            Err(err) => tracing::error!(
                records = batch.len(),
                error = %err,
                "sqlite batch write failed; those records are lost"
            ),
        }

        if disconnected {
            break;
        }
    }

    tracing::debug!("sqlite writer stopped");
}

/// Apply one batch inside a single transaction and commit once.
fn apply_batch(conn: &mut Connection, batch: &[Record], tuning: &Tuning) -> Result<(), DbError> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for record in batch {
        write_one(&tx, record, tuning)?;
    }
    tx.commit()?;
    Ok(())
}

/// Map one [`Record`] onto its table. Every string is capped, every value is
/// bound as a parameter — no SQL is ever built from data.
fn write_one(conn: &Connection, record: &Record, tuning: &Tuning) -> Result<(), DbError> {
    match record {
        Record::Opened(opened) => {
            conn.execute(
                SQL_OPENED,
                rusqlite::params![
                    as_i64(opened.conn_id),
                    text(&opened.ip.to_string(), CAP_IP),
                    i64::from(opened.port),
                    unix_millis(opened.at),
                ],
            )?;
        }
        Record::Closed(closed) => {
            let ts = unix_millis(closed.at);
            let changed = conn.execute(
                SQL_CLOSED,
                rusqlite::params![
                    ts,
                    closed.duration_ms,
                    as_i64(closed.command_count),
                    text(closed.reason.as_str(), CAP_LABEL),
                    as_i64(closed.conn_id),
                ],
            )?;
            if changed == 0 {
                // The `Opened` record was dropped under load (or the row was
                // pruned). Losing the close as well would be worse than storing
                // an incomplete connection: synthesise it from what we have.
                let connected_at = ts.saturating_sub(closed.duration_ms.max(0));
                conn.execute(
                    SQL_CLOSED_ORPHAN,
                    rusqlite::params![
                        as_i64(closed.conn_id),
                        text(&closed.ip.to_string(), CAP_IP),
                        0_i64,
                        connected_at,
                        ts,
                        closed.duration_ms,
                        as_i64(closed.command_count),
                        text(closed.reason.as_str(), CAP_LABEL),
                    ],
                )?;
            }
        }
        Record::Command(command) => {
            conn.execute(
                SQL_COMMAND,
                rusqlite::params![
                    as_i64(command.conn_id),
                    unix_millis(command.at),
                    text(&command.ip.to_string(), CAP_IP),
                    text(&command.name, CAP_NAME),
                    text(&command.args, tuning.param_cap),
                    size_i64(command.arg_count),
                    text(&command.resp_type, CAP_LABEL),
                    text(&command.simulated, CAP_LABEL),
                    command.risk.as_i64(),
                    text(command.risk.as_str(), CAP_LABEL),
                ],
            )?;
        }
        Record::Auth(auth) => {
            conn.execute(
                SQL_AUTH,
                rusqlite::params![
                    as_i64(auth.conn_id),
                    unix_millis(auth.at),
                    text(&auth.ip.to_string(), CAP_IP),
                    auth.username.as_deref().map(|u| text(u, CAP_USERNAME)),
                    i64::from(auth.arg_count),
                    size_i64(auth.password_len),
                    auth.password.as_deref().map(|p| text(p, CAP_PASSWORD)),
                    if auth.simulated_ok { 1_i64 } else { 0_i64 },
                    as_i64(auth.delay_ms),
                    auth.meta.as_deref().map(|m| text(m, tuning.param_cap)),
                ],
            )?;
        }
        Record::Security(event) => {
            conn.execute(
                SQL_SECURITY,
                rusqlite::params![
                    as_i64(event.conn_id),
                    unix_millis(event.at),
                    event.ip.map(|ip| text(&ip.to_string(), CAP_IP)),
                    text(event.kind.as_str(), CAP_LABEL),
                    event.command.as_deref().map(|c| text(c, CAP_NAME)),
                    text(&event.detail, tuning.param_cap),
                ],
            )?;
        }
    }
    Ok(())
}

/// Retention, then size cap. Both are bounded so one tick cannot stall the writer.
fn maintain(conn: &mut Connection, tuning: &Tuning) {
    if tuning.retention_days > 0 {
        let lifetime = i64::from(tuning.retention_days).saturating_mul(86_400_000);
        let cutoff = crate::timeutil::now_millis().saturating_sub(lifetime);
        prune_before(conn, cutoff);
    }
    enforce_size_cap(conn, tuning.max_bytes);
}

/// Drop everything older than `cutoff`, in bounded chunks per table.
fn prune_before(conn: &Connection, cutoff: i64) {
    for sql in [
        SQL_PRUNE_COMMANDS,
        SQL_PRUNE_AUTH,
        SQL_PRUNE_SECURITY,
        SQL_PRUNE_CONNECTIONS,
    ] {
        let mut removed = 0_i64;
        for _ in 0..PRUNE_PASSES {
            match conn.execute(sql, rusqlite::params![cutoff, PRUNE_CHUNK]) {
                Ok(rows) => {
                    removed += size_i64(rows);
                    if size_i64(rows) < PRUNE_CHUNK {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "retention delete failed");
                    break;
                }
            }
        }
        if removed > 0 {
            tracing::debug!(rows = removed, cutoff, "retention pass removed rows");
        }
    }
}

/// Keep the file under `max_bytes` by trimming the oldest rows of every table.
fn enforce_size_cap(conn: &mut Connection, max_bytes: u64) {
    let Ok(cap) = i64::try_from(max_bytes) else {
        return;
    };
    for _ in 0..SIZE_PASSES {
        let Some(size) = db_size_bytes(conn) else {
            return;
        };
        if size <= cap {
            return;
        }
        let mut removed = 0_i64;
        for (sql, count_sql) in [
            (SQL_OLDEST_COMMANDS, SQL_COUNT_COMMANDS),
            (SQL_OLDEST_AUTH, SQL_COUNT_AUTH),
            (SQL_OLDEST_SECURITY, SQL_COUNT_SECURITY),
            (SQL_OLDEST_CONNECTIONS, SQL_COUNT_CONNECTIONS),
        ] {
            let rows = match conn.query_row(count_sql, [], |row| row.get::<_, i64>(0)) {
                Ok(rows) => rows,
                Err(err) => {
                    tracing::warn!(error = %err, "size cap: row count failed");
                    continue;
                }
            };
            if rows == 0 {
                continue;
            }
            // Oldest 5% of the table, at least one row so progress is guaranteed.
            let take = (rows / SIZE_FRACTION).max(1);
            match conn.execute(sql, rusqlite::params![take]) {
                Ok(n) => removed += size_i64(n),
                Err(err) => tracing::warn!(error = %err, "size cap: delete failed"),
            }
        }
        tracing::warn!(
            size,
            cap,
            rows = removed,
            "database over size cap; pruned oldest rows"
        );
        if removed == 0 {
            return;
        }
    }
}

/// `page_count * page_size`, the number the size cap is expressed in.
fn db_size_bytes(conn: &Connection) -> Option<i64> {
    let page_count: i64 = conn.query_row(SQL_PAGE_COUNT, [], |row| row.get(0)).ok()?;
    let page_size: i64 = conn.query_row(SQL_PAGE_SIZE, [], |row| row.get(0)).ok()?;
    Some(page_count.saturating_mul(page_size))
}

/// `PRAGMA wal_checkpoint(TRUNCATE)`, never on a wedged database.
fn checkpoint(conn: &Connection) {
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())) {
        Ok(()) => tracing::debug!("wal checkpoint (truncate) done"),
        Err(err) => tracing::debug!(error = %err, "wal checkpoint skipped"),
    }
}

/// Cap a string by bytes on a UTF-8 boundary, keeping the result inside `cap`.
///
/// [`truncate_str`] appends `...`, so it is asked for `cap - 3` bytes: callers
/// get a hard upper bound on what lands in SQLite, not `cap + 3`.
pub(crate) fn text(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    truncate_str(value, cap.saturating_sub(3))
}

/// Saturating `u64` -> `i64`: SQLite integers are signed.
fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Saturating `usize` -> `i64`, for counts that came from the wire.
fn size_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::db::testutil::{
        Reader, TEST_DELAY_MS, TempDb, auth, closed, command, opened, security,
    };
    use crate::record::{CloseReason, Recorder, RiskLevel, SecurityKind};

    fn now() -> SystemTime {
        SystemTime::now()
    }

    /// The busy loop must keep every record from a whole batch.
    #[tokio::test]
    async fn each_record_kind_reaches_its_table() {
        let tmp = TempDb::create();
        let handle = super::super::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let at = now();

        let _ = recorder.emit(opened(1, "198.51.100.23", at));
        let _ = recorder.emit(command(
            1,
            "198.51.100.23",
            at,
            "CONFIG",
            "GET *",
            RiskLevel::High,
        ));
        let _ = recorder.emit(auth(
            1,
            "198.51.100.23",
            at,
            Some("admin"),
            Some("hunter2"),
            true,
        ));
        let _ = recorder.emit(security(
            1,
            Some("198.51.100.23"),
            at,
            SecurityKind::DangerousCommand,
            "CONFIG SET dir /tmp",
        ));
        let _ = recorder.emit(closed(
            1,
            "198.51.100.23",
            at,
            1_500,
            CloseReason::IdleTimeout,
        ));
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let connections: i64 = reader
            .value("SELECT count(*) FROM connections")
            .expect("count");
        let commands: i64 = reader
            .value("SELECT count(*) FROM commands")
            .expect("count");
        let auths: i64 = reader
            .value("SELECT count(*) FROM auth_attempts")
            .expect("count");
        let events: i64 = reader
            .value("SELECT count(*) FROM security_events")
            .expect("count");
        assert_eq!((connections, commands, auths, events), (1, 1, 1, 1));

        let ip: String = reader.value("SELECT ip FROM commands").expect("ip");
        let name: String = reader.value("SELECT name FROM commands").expect("name");
        let args: String = reader.value("SELECT args FROM commands").expect("args");
        let risk: i64 = reader.value("SELECT risk FROM commands").expect("risk");
        let label: String = reader
            .value("SELECT risk_label FROM commands")
            .expect("label");
        assert_eq!(ip, "198.51.100.23");
        assert_eq!(name, "CONFIG");
        assert_eq!(args, "GET *");
        assert_eq!(risk, RiskLevel::High.as_i64());
        assert_eq!(label, "high");

        let user: Option<String> = reader
            .value("SELECT username FROM auth_attempts")
            .expect("user");
        let pw_len: i64 = reader
            .value("SELECT password_len FROM auth_attempts")
            .expect("len");
        let ok: i64 = reader
            .value("SELECT simulated_ok FROM auth_attempts")
            .expect("ok");
        let delay: i64 = reader
            .value("SELECT delay_ms FROM auth_attempts")
            .expect("delay");
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pw_len, 7);
        assert_eq!(ok, 1);
        assert_eq!(delay, i64::try_from(TEST_DELAY_MS).expect("delay fits"));

        let reason: String = reader
            .value("SELECT close_reason FROM connections")
            .expect("reason");
        let duration: i64 = reader
            .value("SELECT duration_ms FROM connections")
            .expect("duration");
        assert_eq!(reason, "idle_timeout");
        assert_eq!(duration, 1_500);

        let detail: String = reader
            .value("SELECT detail FROM security_events")
            .expect("detail");
        let kind: String = reader
            .value("SELECT kind FROM security_events")
            .expect("kind");
        assert_eq!(detail, "CONFIG SET dir /tmp");
        assert_eq!(kind, "dangerous_command");
    }

    /// A full batch has to be drained by the non-blocking part of the loop.
    #[tokio::test]
    async fn batching_drains_fifty_records() {
        let tmp = TempDb::create();
        let handle = super::super::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let at = now();
        for index in 0..50_u64 {
            assert!(
                recorder.emit(command(
                    1,
                    "198.51.100.23",
                    at,
                    "PING",
                    &format!("seq {index}"),
                    RiskLevel::None,
                )),
                "record {index} must be queued"
            );
        }
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let total: i64 = reader
            .value("SELECT count(*) FROM commands")
            .expect("count");
        assert_eq!(total, 50);
    }

    /// Saturation drops records and counts them; it never blocks or panics.
    #[tokio::test]
    async fn queue_saturation_is_counted_not_fatal() {
        // A channel nobody drains: capacity 1 means the 2nd and 3rd emit fail.
        let (tx, mut rx) = mpsc::channel(1);
        let recorder = Recorder::new(tx, Arc::new(crate::record::DropCounter::new(0)));
        let at = now();
        assert!(recorder.emit(command(1, "198.51.100.23", at, "PING", "", RiskLevel::None)));
        assert!(!recorder.emit(command(1, "198.51.100.23", at, "PING", "", RiskLevel::None)));
        assert!(!recorder.emit(command(1, "198.51.100.23", at, "PING", "", RiskLevel::None)));
        assert_eq!(recorder.dropped(), 2);
        assert!(rx.try_recv().is_ok(), "the queued record is still there");
        drop(rx);

        // The real writer with a 1-slot queue: nothing may be lost silently, so
        // rows + dropped must account for every emit.
        let tmp = TempDb::create();
        let mut cfg = tmp.config();
        cfg.queue_capacity = 1;
        cfg.batch_size = 8;
        let handle = super::super::spawn_writer(&cfg).expect("writer starts");
        let recorder = handle.recorder.clone();
        for index in 0..2_000_u64 {
            let _ = recorder.emit(command(
                1,
                "203.0.113.7",
                at,
                "GET",
                &format!("key:{index}"),
                RiskLevel::Low,
            ));
        }
        let dropped = recorder.dropped();
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let rows: i64 = reader
            .value("SELECT count(*) FROM commands")
            .expect("count");
        assert_eq!(
            rows + i64::try_from(dropped).expect("fits"),
            2_000,
            "every emit is either stored or counted as dropped"
        );
    }

    /// Long attacker strings are capped, on a character boundary.
    #[tokio::test]
    async fn long_args_are_truncated_to_the_cap() {
        let tmp = TempDb::create();
        let handle = super::super::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let big = "咸".repeat(3_500);
        assert!(big.len() > 10 * 1_024, "test input must exceed 10 KiB");
        let _ = recorder.emit(command(
            1,
            "198.51.100.23",
            now(),
            "SET",
            &big,
            RiskLevel::Low,
        ));
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let stored_bytes: i64 = reader
            .value("SELECT length(CAST(args AS BLOB)) FROM commands")
            .expect("byte length");
        assert!(
            stored_bytes > 0 && stored_bytes <= i64::try_from(PARAM_CAP).expect("cap fits"),
            "stored {stored_bytes} bytes"
        );
        // Reading it back as TEXT proves the truncation kept valid UTF-8.
        let stored: String = reader.value("SELECT args FROM commands").expect("args");
        assert_eq!(stored.len(), usize::try_from(stored_bytes).expect("fits"));
        assert!(
            stored.chars().all(|c| c == '咸' || c == '.'),
            "no mangled bytes"
        );
    }

    /// Control bytes arrive already escaped, and the stored form stays bounded.
    #[tokio::test]
    async fn escaped_control_bytes_are_stored_as_ascii() {
        let tmp = TempDb::create();
        let handle = super::super::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let raw: Vec<u8> = (0_u8..=255).collect();
        let escaped = crate::text::escape_bytes(&raw, 200);
        assert!(escaped.is_ascii(), "escaping must produce printable ASCII");
        let _ = recorder.emit(command(
            1,
            "198.51.100.23",
            now(),
            "EVAL",
            &escaped,
            RiskLevel::Critical,
        ));
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let stored: String = reader.value("SELECT args FROM commands").expect("args");
        assert_eq!(stored, escaped);
        let stored_bytes: i64 = reader
            .value("SELECT length(CAST(args AS BLOB)) FROM commands")
            .expect("byte length");
        assert!(stored_bytes <= i64::try_from(PARAM_CAP).expect("cap fits"));
    }

    /// A close for a connection whose open record was dropped still lands.
    #[tokio::test]
    async fn close_for_unknown_connection_is_recovered() {
        let tmp = TempDb::create();
        let handle = super::super::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let _ = recorder.emit(closed(
            4_242,
            "203.0.113.9",
            now(),
            900,
            CloseReason::ProtocolError,
        ));
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let rows: i64 = reader
            .value("SELECT count(*) FROM connections")
            .expect("count");
        assert_eq!(rows, 1, "the close must not be lost");
        let reason: String = reader
            .value("SELECT close_reason FROM connections")
            .expect("reason");
        let port: i64 = reader.value("SELECT port FROM connections").expect("port");
        let duration: i64 = reader
            .value("SELECT duration_ms FROM connections")
            .expect("duration");
        let disconnected: i64 = reader
            .value("SELECT disconnected_at FROM connections")
            .expect("disconnected_at");
        let connected: i64 = reader
            .value("SELECT connected_at FROM connections")
            .expect("connected_at");
        assert_eq!(reason, "protocol_error");
        assert_eq!(port, 0, "unknown port is recorded as 0");
        assert_eq!(duration, 900);
        assert_eq!(disconnected - connected, 900, "connected_at is derived");
    }

    /// Retention runs on the configured cadence and leaves recent rows alone.
    #[tokio::test]
    async fn maintenance_prunes_rows_past_retention() {
        let tmp = TempDb::create();
        let mut cfg = tmp.config();
        cfg.maintenance_interval_secs = 1;
        cfg.retention_days = 30;
        let handle = super::super::spawn_writer(&cfg).expect("writer starts");
        let recorder = handle.recorder.clone();

        let old = SystemTime::now() - Duration::from_secs(60 * 86_400);
        for index in 0..3_u64 {
            let _ = recorder.emit(command(
                1,
                "198.51.100.23",
                old,
                "SET",
                &format!("stale:{index}"),
                RiskLevel::Low,
            ));
        }
        drop(recorder);
        let reader = Reader::open(&tmp.path).expect("reader");
        assert_eq!(
            reader.wait_for("SELECT count(*) FROM commands", 3, 10_000),
            3,
            "stale rows must be stored before maintenance can prune them"
        );

        // One maintenance tick needs a record to wake the writer up.
        std::thread::sleep(Duration::from_millis(1_100));
        let _ = handle.recorder.emit(command(
            1,
            "198.51.100.23",
            SystemTime::now(),
            "PING",
            "fresh",
            RiskLevel::None,
        ));
        assert_eq!(
            reader.wait_for("SELECT count(*) FROM commands", 1, 10_000),
            1,
            "only the recent row may survive"
        );
        let stale: i64 = reader
            .value("SELECT count(*) FROM commands WHERE args LIKE 'stale:%'")
            .expect("count");
        assert_eq!(stale, 0);
        drop(reader);
        handle.shutdown().await;
    }

    /// Two producers, one writer, nothing lost while the queue has room.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_producers_keep_every_record() {
        let tmp = TempDb::create();
        let mut cfg = tmp.config();
        cfg.queue_capacity = 1_024;
        let handle = super::super::spawn_writer(&cfg).expect("writer starts");

        let mut tasks = Vec::new();
        for producer in 0..2_u64 {
            let recorder = handle.recorder.clone();
            tasks.push(tokio::spawn(async move {
                let at = SystemTime::now();
                for index in 0..100_u64 {
                    let _ = recorder.emit(command(
                        producer + 1,
                        "198.51.100.23",
                        at,
                        "GET",
                        &format!("p{producer}:{index}"),
                        RiskLevel::Low,
                    ));
                }
                recorder
            }));
        }
        let mut recorders = Vec::new();
        for task in tasks {
            recorders.push(task.await.expect("producer task"));
        }
        drop(recorders);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let total: i64 = reader
            .value("SELECT count(*) FROM commands")
            .expect("count");
        assert_eq!(total, 200);
        let producers: i64 = reader
            .value("SELECT count(DISTINCT conn_id) FROM commands")
            .expect("conns");
        assert_eq!(producers, 2);
    }

    /// The storage cap is documented as `Limits::max_stored_param_bytes`.
    #[test]
    fn param_cap_matches_the_configured_limit() {
        assert_eq!(
            PARAM_CAP,
            crate::config::Limits::default().max_stored_param_bytes
        );
    }

    /// `text` never exceeds the cap and never splits a character.
    #[test]
    fn text_cap_is_a_hard_bound() {
        assert_eq!(text("short", 64), "short");
        let long = "é".repeat(100);
        let capped = text(&long, 64);
        assert!(capped.len() <= 64, "len={}", capped.len());
        assert!(capped.ends_with("..."));
        assert_eq!(text("", 64), "");
    }
}
