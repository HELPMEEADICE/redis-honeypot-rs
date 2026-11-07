//! The single blocking SQLite writer.
//!
//! Everything in this module runs on one `tokio::task::spawn_blocking` thread
//! and owns the only writable [`Connection`]. The network path never waits for
//! it: it `try_send`s into a bounded channel and moves on
//! ([`crate::record::Recorder`]).
//!
//! Four rules shape the code below:
//!
//! * **Batch, then commit once.** The whole point of buffering is fewer fsyncs,
//!   so a batch of records is applied inside one transaction and committed once.
//! * **A failed batch is retried, not dropped.** Transient SQLite failures
//!   (`BUSY`, `LOCKED`, short I/O errors) are retried inside a bounded budget;
//!   the batch is rolled back and replayed as a whole, so a retry can never
//!   duplicate or half-apply a record. Records that are still lost are counted.
//! * **Maintenance runs on a clock, not on traffic.** A quiet honeypot still
//!   has to expire old rows and give free pages back to the filesystem, so the
//!   writer wakes up on its own deadline instead of waiting for the next record.
//! * **The size cap binds *used* pages, not the file size.** `DELETE` leaves
//!   free pages behind and SQLite does not shrink the file, so pruning on
//!   `page_count * page_size` used to delete the whole history while the size
//!   never moved. The cap is now enforced on `(page_count - freelist_count)`
//!   and free pages are reclaimed with `incremental_vacuum`.

use std::time::{Duration, Instant};

use rusqlite::Connection;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use crate::config::Database as DatabaseConfig;
use crate::record::DropCounter;
use crate::record::Record;
use crate::text::truncate_str;
use crate::timeutil::unix_millis;

use super::DbError;

/// Default cap for `commands.args`, `auth_attempts.meta` and
/// `security_events.detail`.
///
/// [`crate::config::Limits::max_stored_param_bytes`] is the authority and is
/// passed in at startup ([`Tuning::from_config`]); this constant only exists so
/// the compiled-in default is visible and testable.
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
/// Longest an idle writer sleeps before re-checking the queue.
///
/// Bounds how long a record can sit in the channel while the writer is waiting
/// for its housekeeping deadline, at the cost of ~10 cheap wakeups per second.
const IDLE_SLICE: Duration = Duration::from_millis(100);
/// Rows removed by a single retention `DELETE`.
const PRUNE_CHUNK: i64 = 5_000;
/// Upper bound on retention `DELETE` statements per table per pass.
const PRUNE_PASSES: usize = 8;
/// Upper bound on size-cap pruning passes per maintenance tick.
const SIZE_PASSES: usize = 4;
/// Fraction of each table trimmed per size-cap pass (`1 / SIZE_FRACTION`).
const SIZE_FRACTION: i64 = 20;
/// Pruning stops at this fraction of the cap, so the next tick does not have to
/// delete again immediately (hysteresis).
const SIZE_TARGET_NUM: i64 = 9;
const SIZE_TARGET_DEN: i64 = 10;
/// Pages released per maintenance tick by `incremental_vacuum`.
const VACUUM_PAGES_PER_TICK: i64 = 512;
/// Largest file the one-off `VACUUM` repair is allowed to rewrite (64 MiB).
///
/// A rewrite blocks the writer for its duration, so it is capped in size and
/// happens at most once per process.
const VACUUM_REBUILD_MAX_BYTES: i64 = 64 * 1024 * 1024;

/// Maximum attempts for one batch: the first try plus three retries.
const BATCH_ATTEMPTS: usize = 4;
/// First retry backoff; doubled after every failed attempt.
const BATCH_RETRY_BACKOFF: Duration = Duration::from_millis(25);
/// Hard ceiling on the time one batch may spend retrying, so a wedged disk can
/// never hold the writer thread (or a shutdown) hostage.
const BATCH_RETRY_BUDGET: Duration = Duration::from_millis(2_000);

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
/// One row, rewritten in place: the writer's own health, readable later by
/// `redis-honeypot-rs stats` from the same file.
const SQL_WRITER_STATS: &str = "INSERT OR REPLACE INTO writer_stats \
     (id, updated_at, lost, retried, retry_failed, pruned_rows, vacuum_pages, checkpoint_blocked) \
     VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)";
const SQL_PAGE_COUNT: &str = "PRAGMA page_count";
const SQL_PAGE_SIZE: &str = "PRAGMA page_size";
const SQL_FREELIST_COUNT: &str = "PRAGMA freelist_count";
const SQL_AUTO_VACUUM: &str = "PRAGMA auto_vacuum";

/// `PRAGMA auto_vacuum` value for `INCREMENTAL`.
pub(crate) const AUTO_VACUUM_INCREMENTAL: i64 = 2;

/// Everything the writer needs to know about scheduling and storage caps.
#[derive(Debug, Clone)]
pub(crate) struct Tuning {
    batch_size: usize,
    batch_interval: Duration,
    retention_days: u32,
    max_bytes: u64,
    checkpoint_interval: Duration,
    maintenance_interval: Duration,
    /// `Limits::max_stored_param_bytes`, carried into the storage layer so the
    /// network side and the database side cannot disagree about the cap.
    param_cap: usize,
}

impl Tuning {
    pub(crate) fn from_config(cfg: &DatabaseConfig, param_cap: usize) -> Self {
        Self {
            batch_size: cfg.batch_size.max(1),
            // A millisecond value from a config file must not be able to make
            // `Instant::now() + interval` overflow, nor stall the drain loop for
            // minutes on end.
            batch_interval: Duration::from_millis(cfg.batch_interval_ms.clamp(1, 60_000)),
            retention_days: cfg.retention_days,
            max_bytes: cfg.max_bytes,
            checkpoint_interval: Duration::from_secs(cfg.checkpoint_interval_secs.clamp(1, 86_400)),
            maintenance_interval: Duration::from_secs(
                cfg.maintenance_interval_secs.clamp(1, 86_400),
            ),
            // Zero would store nothing at all; fall back to the default cap.
            param_cap: if param_cap == 0 { PARAM_CAP } else { param_cap },
        }
    }

    /// The cap actually applied to stored argument previews.
    pub(crate) fn param_cap(&self) -> usize {
        self.param_cap
    }
}

/// Counters the writer publishes so loss is observable instead of silent.
///
/// A `DropCounter` is machine-word sized (see [`crate::record`]), so this keeps
/// compiling on targets without 64-bit atomics.
#[derive(Debug, Default)]
pub struct WriterStats {
    lost: DropCounter,
    retried: DropCounter,
    retry_failed: DropCounter,
    pruned_rows: DropCounter,
    vacuum_pages: DropCounter,
    checkpoint_blocked: DropCounter,
}

impl WriterStats {
    fn bump(counter: &DropCounter, by: usize) {
        #[allow(clippy::unnecessary_cast)]
        let by = by as _;
        counter.fetch_add(by, std::sync::atomic::Ordering::Relaxed);
    }

    fn get(counter: &DropCounter) -> u64 {
        #[allow(clippy::unnecessary_cast)]
        let value = counter.load(std::sync::atomic::Ordering::Relaxed) as u64;
        value
    }

    /// Records that were dropped after every retry failed.
    pub fn lost(&self) -> u64 {
        Self::get(&self.lost)
    }

    /// Batches that needed at least one retry.
    pub fn retried(&self) -> u64 {
        Self::get(&self.retried)
    }

    /// Batches whose retry budget was exhausted.
    pub fn retry_failed(&self) -> u64 {
        Self::get(&self.retry_failed)
    }

    /// Rows removed by retention and size-cap maintenance.
    pub fn pruned_rows(&self) -> u64 {
        Self::get(&self.pruned_rows)
    }

    /// Free pages handed back to the filesystem by `incremental_vacuum`.
    pub fn vacuum_pages(&self) -> u64 {
        Self::get(&self.vacuum_pages)
    }

    /// Checkpoints that could not fully truncate the WAL.
    pub fn checkpoint_blocked(&self) -> u64 {
        Self::get(&self.checkpoint_blocked)
    }
}

/// Physical storage facts, every value in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DbSize {
    /// `page_count * page_size`: what the file occupies on disk.
    pub(crate) allocated: i64,
    /// `freelist_count * page_size`: pages inside the file that are already free.
    pub(crate) free: i64,
    /// `page_size`, needed to translate a page budget into bytes.
    pub(crate) page_size: i64,
}

impl DbSize {
    /// Pages the data actually occupies: rows, indexes and SQLite metadata.
    ///
    /// This — not [`Self::allocated`] — is what the size cap bounds, because a
    /// `DELETE` frees pages without shrinking the file.
    pub(crate) fn used(&self) -> i64 {
        self.allocated.saturating_sub(self.free)
    }

    /// Free pages, as a page count.
    pub(crate) fn free_pages(&self) -> i64 {
        if self.page_size <= 0 {
            return 0;
        }
        self.free / self.page_size
    }
}

/// Which records were lost and why, for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureClass {
    /// Retrying can plausibly succeed: lock contention, `BUSY`, short I/O.
    Transient,
    /// Retrying cannot help: disk full, read-only database, corrupt file.
    Fatal,
}

/// Classify a writer failure for the retry loop and the log line.
fn classify_db(err: &DbError) -> FailureClass {
    match err {
        DbError::Sqlite(inner) => classify(inner),
        // A bare `std::io::Error` around the database file is usually a short
        // read/write failure: worth retrying inside the budget.
        DbError::Io(_) => FailureClass::Transient,
        // The writer task itself could not be started; nothing to retry.
        DbError::Spawn(_) => FailureClass::Fatal,
    }
}

/// Classify a SQLite failure for the retry loop.
fn classify(err: &rusqlite::Error) -> FailureClass {
    use rusqlite::ErrorCode;
    let rusqlite::Error::SqliteFailure(code, _) = err else {
        // A type/conversion error comes from our own binding, not the disk:
        // replaying it would fail identically.
        return FailureClass::Fatal;
    };
    match code.code {
        ErrorCode::DatabaseBusy
        | ErrorCode::DatabaseLocked
        | ErrorCode::OperationInterrupted
        | ErrorCode::SystemIoFailure
        | ErrorCode::InternalMalfunction => FailureClass::Transient,
        // `SQLITE_FULL`, `SQLITE_READONLY`, `SQLITE_CORRUPT`, `SQLITE_NOTADB`,
        // `SQLITE_CONSTRAINT`, `SQLITE_CANTOPEN`, `SQLITE_AUTH`, … stay fatal:
        // burning the retry budget on them only delays the loss report.
        _ => FailureClass::Fatal,
    }
}

/// One thing the writer woke up for.
enum Wake {
    Record(Record),
    /// The housekeeping deadline fired: nothing to write, still work to do.
    Housekeeping,
    /// The channel closed and is drained: flush and stop.
    Closed,
}

/// Drain the record channel until it closes, then return.
///
/// Runs on a blocking thread: it never `blocking_send`s (the writer is the
/// receiving end) and it never awaits a socket.
pub(crate) fn run(
    mut conn: Connection,
    mut rx: mpsc::Receiver<Record>,
    tuning: Tuning,
    stats: std::sync::Arc<WriterStats>,
) {
    tracing::debug!(
        batch_size = tuning.batch_size,
        batch_interval_ms = tuning.batch_interval.as_millis(),
        maintenance_interval_s = tuning.maintenance_interval.as_secs(),
        param_cap = tuning.param_cap(),
        "sqlite writer started"
    );

    let mut last_maintenance = Instant::now();
    let mut last_checkpoint = Instant::now();
    let mut maintenance_state = MaintenanceState::default();
    let mut batch: Vec<Record> = Vec::with_capacity(tuning.batch_size.min(1_024));

    loop {
        batch.clear();

        // Block until a record arrives *or* a housekeeping deadline is due.
        // Waiting on a timer as well as on the channel is what makes an idle
        // honeypot still expire rows and checkpoint the WAL.
        let due = next_deadline(last_maintenance, tuning.maintenance_interval)
            .min(next_deadline(last_checkpoint, tuning.checkpoint_interval));
        let first = match wait_for_work(&mut rx, due) {
            Wake::Record(record) => record,
            Wake::Housekeeping => {
                if last_maintenance.elapsed() >= tuning.maintenance_interval {
                    maintain(&mut conn, &tuning, &stats, &mut maintenance_state);
                    last_maintenance = Instant::now();
                }
                if last_checkpoint.elapsed() >= tuning.checkpoint_interval {
                    checkpoint(&conn, &stats);
                    last_checkpoint = Instant::now();
                }
                continue;
            }
            Wake::Closed => break,
        };
        batch.push(first);

        // Then fill the batch without waiting: up to `batch_size` records or
        // until the batch window closes, whichever comes first.
        let mut disconnected = false;
        let deadline = Instant::now()
            .checked_add(tuning.batch_interval)
            .unwrap_or_else(Instant::now);
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
            maintain(&mut conn, &tuning, &stats, &mut maintenance_state);
            last_maintenance = Instant::now();
        }
        if last_checkpoint.elapsed() >= tuning.checkpoint_interval {
            checkpoint(&conn, &stats);
            last_checkpoint = Instant::now();
        }

        match apply_batch_with_retry(&mut conn, &batch, &tuning, &stats) {
            Ok(()) => {}
            Err(err) => {
                tracing::error!(
                    records = batch.len(),
                    error = %err,
                    class = ?classify_db(&err),
                    lost_total = stats.lost(),
                    "sqlite batch write failed permanently; those records are lost"
                );
            }
        }

        if disconnected {
            break;
        }
    }

    // Last best effort: make the rows that did land durable, give free pages
    // back, and leave the counters behind for a later `stats` run — all without
    // letting a wedged database extend shutdown.
    checkpoint(&conn, &stats);
    persist_stats(&conn, &stats);
    tracing::debug!(lost = stats.lost(), "sqlite writer stopped");
}

/// The earlier of the two housekeeping deadlines.
fn next_deadline(last: Instant, interval: Duration) -> Instant {
    // `Instant + Duration` panics on overflow; an absurd configured interval
    // must degrade to "check again in a while", never to a crash.
    last.checked_add(interval)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(3_600))
}

/// Wait for a record, or for the nearest housekeeping deadline.
///
/// `tokio::sync::mpsc` offers no `recv_timeout` for blocking threads, so the
/// wait is a non-blocking `try_recv` plus a **bounded** `std::thread::sleep`.
/// The sleep is deliberately a plain thread sleep and not a tokio timer: this
/// code runs on a blocking thread, and housekeeping must still happen when the
/// async timer driver is busy, idle or shutting down. The slice only bounds how
/// long a fresh record may wait (`IDLE_SLICE`), which is well under the batch
/// window anyway.
fn wait_for_work(rx: &mut mpsc::Receiver<Record>, due: Instant) -> Wake {
    loop {
        match rx.try_recv() {
            Ok(record) => return Wake::Record(record),
            Err(TryRecvError::Disconnected) => return Wake::Closed,
            Err(TryRecvError::Empty) => {}
        }
        let now = Instant::now();
        if now >= due {
            return Wake::Housekeeping;
        }
        std::thread::sleep(due.saturating_duration_since(now).min(IDLE_SLICE));
    }
}

/// Apply one batch, retrying transient failures inside a bounded budget.
///
/// The retry replays the *whole* transaction after a rollback, so a batch is
/// either committed exactly once or not at all: no duplicate rows, no half
/// applied batch.
fn apply_batch_with_retry(
    conn: &mut Connection,
    batch: &[Record],
    tuning: &Tuning,
    stats: &WriterStats,
) -> Result<(), DbError> {
    if batch.is_empty() {
        return Ok(());
    }
    let started = Instant::now();
    let mut backoff = BATCH_RETRY_BACKOFF;
    let mut attempt = 1_usize;

    loop {
        match apply_batch(conn, batch, tuning) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let class = classify_db(&err);
                let elapsed = started.elapsed();
                if class == FailureClass::Fatal
                    || attempt >= BATCH_ATTEMPTS
                    || elapsed + backoff > BATCH_RETRY_BUDGET
                {
                    // Give up: count the loss here, exactly once per batch, so
                    // `lost` is the number of records that never reached SQLite.
                    WriterStats::bump(&stats.lost, batch.len());
                    WriterStats::bump(&stats.retry_failed, 1);
                    return Err(err);
                }
                WriterStats::bump(&stats.retried, 1);
                tracing::warn!(
                    attempt,
                    records = batch.len(),
                    backoff_ms = backoff.as_millis(),
                    error = %err,
                    "sqlite batch write failed; retrying"
                );
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(BATCH_RETRY_BACKOFF * 8);
                attempt += 1;
            }
        }
    }
}

/// Apply one batch inside a single transaction and commit once.
///
/// On any error the transaction is dropped (rollback) and nothing of that batch
/// is visible, which is what makes [`apply_batch_with_retry`] idempotent.
fn apply_batch(conn: &mut Connection, batch: &[Record], tuning: &Tuning) -> Result<(), DbError> {
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

/// What the writer has already tried, so a one-off repair happens once.
#[derive(Debug, Default)]
struct MaintenanceState {
    /// The single bounded `VACUUM` attempt for a bloated, non incremental file.
    rebuild_attempted: bool,
}

/// Retention, size cap, then a bounded page reclaim. Each step is bounded so
/// one tick cannot stall the writer.
fn maintain(
    conn: &mut Connection,
    tuning: &Tuning,
    stats: &WriterStats,
    state: &mut MaintenanceState,
) {
    if tuning.retention_days > 0 {
        let lifetime = i64::from(tuning.retention_days).saturating_mul(86_400_000);
        let cutoff = crate::timeutil::now_millis().saturating_sub(lifetime);
        prune_before(conn, cutoff, stats);
    }
    enforce_size_cap(conn, tuning.max_bytes, stats);
    // Free pages that retention or pruning just produced are given back here.
    // `incremental_vacuum` works page-limited, so it cannot turn into an
    // unbounded `VACUUM` on a large database.
    incremental_vacuum(conn, stats);
    // A database that is still in `auto_vacuum = NONE` can never shrink on its
    // own. If it has become mostly free space, repair it once: this is the only
    // way such a file gets smaller without an operator running `VACUUM`.
    rebuild_if_bloated(conn, state);
    persist_stats(conn, stats);
}

/// Rewrite a mostly-free, non incremental database once per process.
///
/// Guards, so this can never become a periodic full rewrite:
/// * only when `auto_vacuum` is still `NONE` (incremental databases reclaim
///   pages incrementally and never need it);
/// * only when free pages are at least 3/4 of the file;
/// * only when the file is at most [`VACUUM_REBUILD_MAX_BYTES`];
/// * at most once per writer process.
fn rebuild_if_bloated(conn: &Connection, state: &mut MaintenanceState) {
    if state.rebuild_attempted {
        return;
    }
    let Ok(mode) = conn.query_row(SQL_AUTO_VACUUM, [], |row| row.get::<_, i64>(0)) else {
        return;
    };
    if mode == AUTO_VACUUM_INCREMENTAL {
        return;
    }
    let Some(size) = db_size_bytes(conn) else {
        return;
    };
    if size.allocated <= 0 || size.allocated > VACUUM_REBUILD_MAX_BYTES {
        return;
    }
    // free >= 3/4 of allocated
    if size.free.saturating_mul(4) < size.allocated.saturating_mul(3) {
        return;
    }
    state.rebuild_attempted = true;
    // Setting the pragma first is what makes the rewrite leave an incremental
    // database behind, so this repair also enables the cheap path from now on.
    let outcome = conn
        .pragma_update(None, "auto_vacuum", AUTO_VACUUM_INCREMENTAL)
        .and_then(|()| conn.execute_batch("VACUUM"));
    match outcome {
        Ok(()) => match db_size_bytes(conn) {
            Some(after) => tracing::warn!(
                before = size.allocated,
                after = after.allocated,
                free = size.free,
                "rewrote a mostly-free database once and enabled incremental auto-vacuum"
            ),
            None => tracing::warn!("rewrote a mostly-free database once"),
        },
        Err(err) => tracing::warn!(
            error = %err,
            "one-off database rewrite failed; the file keeps its free pages"
        ),
    }
}

/// Write the writer's counters into the database, once per maintenance tick and
/// once at exit, so they outlive the process.
fn persist_stats(conn: &Connection, stats: &WriterStats) {
    let now = crate::timeutil::now_millis();
    let outcome = conn.execute(
        SQL_WRITER_STATS,
        rusqlite::params![
            now,
            as_i64(stats.lost()),
            as_i64(stats.retried()),
            as_i64(stats.retry_failed()),
            as_i64(stats.pruned_rows()),
            as_i64(stats.vacuum_pages()),
            as_i64(stats.checkpoint_blocked()),
        ],
    );
    if let Err(err) = outcome {
        // Never fatal: the counters are diagnostics, not telemetry.
        tracing::debug!(error = %err, "cannot persist writer counters");
    }
}

/// Drop everything older than `cutoff`, in bounded chunks per table.
fn prune_before(conn: &Connection, cutoff: i64, stats: &WriterStats) {
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
            WriterStats::bump(
                &stats.pruned_rows,
                usize::try_from(removed).unwrap_or(usize::MAX),
            );
            tracing::debug!(rows = removed, cutoff, "retention pass removed rows");
        }
    }
}

/// Keep the *used* space under `max_bytes` by trimming the oldest rows.
///
/// The number this compares against is `page_count - freelist_count`, i.e. the
/// pages the data actually occupies. Comparing against the file size is what
/// made the old implementation delete the entire history: `DELETE` frees pages
/// but leaves the file size unchanged, so the "over cap" condition never
/// cleared and every maintenance tick removed another slice of the table.
fn enforce_size_cap(conn: &mut Connection, max_bytes: u64, stats: &WriterStats) {
    let Ok(cap) = i64::try_from(max_bytes) else {
        return;
    };
    let target = cap.saturating_mul(SIZE_TARGET_NUM) / SIZE_TARGET_DEN;
    for _ in 0..SIZE_PASSES {
        let Some(size) = db_size_bytes(conn) else {
            return;
        };
        if size.used() <= cap {
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
        WriterStats::bump(
            &stats.pruned_rows,
            usize::try_from(removed).unwrap_or(usize::MAX),
        );
        tracing::warn!(
            used = size.used(),
            allocated = size.allocated,
            free = size.free,
            cap,
            target,
            rows = removed,
            "database over its used-space cap; pruned oldest rows"
        );
        if removed == 0 {
            // Every table is empty and the space is still above the cap: the
            // remainder is SQLite metadata plus free pages. Nothing left to
            // delete, so stop instead of looping.
            return;
        }
    }
}

/// `page_count`, `freelist_count` and `page_size`, all in bytes.
fn db_size_bytes(conn: &Connection) -> Option<DbSize> {
    let page_count: i64 = conn.query_row(SQL_PAGE_COUNT, [], |row| row.get(0)).ok()?;
    let page_size: i64 = conn.query_row(SQL_PAGE_SIZE, [], |row| row.get(0)).ok()?;
    let freelist: i64 = conn
        .query_row(SQL_FREELIST_COUNT, [], |row| row.get(0))
        .ok()?;
    if page_size <= 0 {
        return None;
    }
    Some(DbSize {
        allocated: page_count.saturating_mul(page_size),
        free: freelist.saturating_mul(page_size),
        page_size,
    })
}

/// Hand free pages back to the filesystem, a bounded number per tick.
///
/// Only meaningful when the database was created with
/// `PRAGMA auto_vacuum = INCREMENTAL` (see [`crate::db::init_db`]); on a
/// database that is still in `auto_vacuum = NONE` the statement is a cheap
/// no-op, and the caller has already logged that limitation at startup.
fn incremental_vacuum(conn: &Connection, stats: &WriterStats) {
    let Ok(mode) = conn.query_row(SQL_AUTO_VACUUM, [], |row| row.get::<_, i64>(0)) else {
        return;
    };
    if mode != AUTO_VACUUM_INCREMENTAL {
        return;
    }
    let Some(size) = db_size_bytes(conn) else {
        return;
    };
    let free = size.free_pages();
    if free <= 0 {
        return;
    }
    let take = free.min(VACUUM_PAGES_PER_TICK);
    match conn.execute_batch(&format!("PRAGMA incremental_vacuum({take})")) {
        Ok(()) => {
            WriterStats::bump(
                &stats.vacuum_pages,
                usize::try_from(take).unwrap_or(usize::MAX),
            );
            tracing::debug!(pages = take, "incremental_vacuum released pages");
        }
        // Never fatal: the pages stay free and the next tick tries again.
        Err(err) => tracing::debug!(error = %err, "incremental_vacuum skipped"),
    }
}

/// WAL checkpoint: `PASSIVE` first (never blocks), `TRUNCATE` only when it
/// succeeded, so a reader or an open write transaction cannot wedge the writer.
fn checkpoint(conn: &Connection, stats: &WriterStats) {
    match conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(0) => {}
        Ok(busy) => {
            WriterStats::bump(&stats.checkpoint_blocked, 1);
            tracing::debug!(
                busy,
                "wal checkpoint partially blocked by a reader; retrying next tick"
            );
            // Do not TRUNCATE on top of a blocked checkpoint.
            return;
        }
        Err(err) => {
            WriterStats::bump(&stats.checkpoint_blocked, 1);
            tracing::warn!(error = %err, "wal checkpoint failed; will retry");
            return;
        }
    }
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(0) => tracing::debug!("wal checkpoint (truncate) done"),
        Ok(busy) => {
            WriterStats::bump(&stats.checkpoint_blocked, 1);
            tracing::debug!(busy, "wal truncate blocked; the wal stays on disk");
        }
        Err(err) => tracing::debug!(error = %err, "wal truncate skipped"),
    }
}

/// Cap a string by bytes on a UTF-8 boundary, keeping the result inside `cap`.
///
/// [`truncate_str`] appends `...`, so it is asked for `cap - 3` bytes: callers
/// get a hard upper bound on what lands in SQLite, not `cap + 3`. A cap smaller
/// than the ellipsis itself (`cap < 3`, only reachable with a hand written
/// config) degrades to a plain character-boundary cut so the bound still holds.
pub(crate) fn text(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    if cap <= 3 {
        let mut cut = cap;
        while cut > 0 && !value.is_char_boundary(cut) {
            cut -= 1;
        }
        return value[..cut].to_owned();
    }
    truncate_str(value, cap - 3)
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
        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&cfg, &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&cfg, &crate::config::Limits::default())
            .expect("writer starts");
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
        let handle = super::super::spawn_writer(&cfg, &crate::config::Limits::default())
            .expect("writer starts");

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

    /// Even the degenerate caps (below the ellipsis length) stay inside the cap
    /// and never split a multi-byte character.
    #[test]
    fn tiny_caps_stay_inside_the_bound() {
        let multi = "咸魚".repeat(8); // 3 bytes per character
        for cap in 1..=6_usize {
            let cut = text(&multi, cap);
            assert!(cut.len() <= cap, "cap {cap} produced {} bytes", cut.len());
            if cap <= 3 {
                // No room for the ellipsis: a plain, boundary-safe cut.
                assert!(multi.starts_with(&cut), "cap {cap} cut mid-character");
            } else {
                // Room for `...`: whatever survives is a clean character
                // prefix (`""` when not even the first 3-byte character fits).
                assert!(cut.ends_with("..."), "cap {cap} produced {cut:?}");
                assert!(
                    cut == "..." || cut.starts_with('咸'),
                    "cap {cap} produced {cut:?}"
                );
            }
        }
        // A 3-byte character cannot be split: a 4- or 5-byte cap leaves only the
        // ellipsis, a 6-byte cap fits exactly one character plus the ellipsis.
        assert_eq!(text(&multi, 4), "...");
        assert_eq!(text(&multi, 6), "咸...");
        assert_eq!(text(&multi, 1), "");
    }

    // ------------------------------------------------- retry / loss (regr.)

    /// A batch that fails on lock contention is retried and then lands *exactly
    /// once*: the transaction is rolled back before each replay, so a retry can
    /// never duplicate rows.
    #[tokio::test]
    async fn transient_lock_contention_is_retried_without_duplicates() {
        let tmp = TempDb::create();
        let mut conn = crate::db::init_db(&tmp.path).expect("db");
        // Fail fast instead of waiting, so the contention is a real `SQLITE_BUSY`
        // rather than a five second block.
        conn.busy_timeout(Duration::from_millis(0))
            .expect("busy timeout");
        let tuning = Tuning::from_config(&tmp.config(), PARAM_CAP);
        let stats = WriterStats::default();
        let batch: Vec<Record> = (0..10_u32)
            .map(|index| {
                command(
                    1,
                    "198.51.100.23",
                    now(),
                    "PING",
                    &format!("k{index}"),
                    RiskLevel::None,
                )
            })
            .collect();

        // Another connection holds the write lock for 150 ms.
        let blocker = rusqlite::Connection::open(&tmp.path).expect("blocker");
        blocker
            .busy_timeout(Duration::from_millis(0))
            .expect("busy timeout");
        blocker.execute_batch("BEGIN IMMEDIATE").expect("lock");
        let unlock = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            blocker.execute_batch("COMMIT").expect("commit");
        });

        apply_batch_with_retry(&mut conn, &batch, &tuning, &stats)
            .expect("the retry must get through once the lock is released");
        unlock.join().expect("unlock thread");

        let rows: i64 = conn
            .query_row("SELECT count(*) FROM commands", [], |row| row.get(0))
            .expect("count");
        assert_eq!(rows, 10, "a retried batch must land exactly once");
        assert!(stats.retried() >= 1, "the failure was not retried");
        assert_eq!(stats.lost(), 0, "nothing was lost");
    }

    /// A failure that retrying cannot fix (`SQLITE_READONLY` here, standing in
    /// for `SQLITE_FULL` / `SQLITE_CORRUPT`) is not retried, is counted as lost,
    /// and does not hang the writer.
    #[tokio::test]
    async fn fatal_write_failure_is_counted_as_lost_and_not_retried() {
        let tmp = TempDb::create();
        let mut conn = crate::db::init_db(&tmp.path).expect("db");
        // Every write now fails with SQLITE_READONLY.
        conn.execute_batch("PRAGMA query_only = ON")
            .expect("read only");
        let tuning = Tuning::from_config(&tmp.config(), PARAM_CAP);
        let stats = WriterStats::default();
        let batch = vec![
            command(1, "198.51.100.23", now(), "PING", "a", RiskLevel::None),
            command(1, "198.51.100.23", now(), "PING", "b", RiskLevel::None),
        ];

        let started = std::time::Instant::now();
        let err = apply_batch_with_retry(&mut conn, &batch, &tuning, &stats)
            .expect_err("a read-only database cannot accept rows");
        assert_eq!(
            classify_db(&err),
            FailureClass::Fatal,
            "a read-only database is not worth retrying"
        );
        assert_eq!(stats.lost(), 2, "both records must be counted as lost");
        assert_eq!(stats.retried(), 0, "a fatal error must not burn the budget");
        assert!(
            started.elapsed() < BATCH_RETRY_BUDGET,
            "a fatal error returned after {:?}",
            started.elapsed()
        );

        // The writer keeps working: the connection is reusable once the failure
        // clears up.
        conn.execute_batch("PRAGMA query_only = OFF")
            .expect("writable");
        apply_batch_with_retry(&mut conn, &batch, &tuning, &stats).expect("recovers");
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM commands", [], |row| row.get(0))
            .expect("count");
        assert_eq!(rows, 2);
    }

    /// A database that is still `auto_vacuum = NONE` can never shrink on its
    /// own. The one-off repair rewrites it (bounded in size, once per process)
    /// and leaves it incremental, so later `DELETE`s do shrink it.
    #[test]
    fn bloat_repair_runs_once_and_enables_incremental_auto_vacuum() {
        let tmp = TempDb::create();
        // Build a "version 1" database on purpose: `init_db` would migrate it.
        let conn = rusqlite::Connection::open(&tmp.path).expect("db");
        conn.pragma_update(None, "auto_vacuum", 0_i64)
            .expect("none");
        crate::db::schema::init(&conn).expect("schema");
        conn.execute_batch("PRAGMA journal_mode = WAL")
            .expect("wal mode");
        assert_eq!(
            conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
                .expect("mode"),
            0
        );

        // Enough rows to make the file substantially larger than its content.
        conn.execute_batch(
            "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 4000)
             INSERT INTO commands (conn_id, ts, ip, name, args, arg_count, resp_type, simulated, risk, risk_label)
             SELECT 1, 1, '203.0.113.9', 'SET', 'key:' || n, 3, '+OK', 'ok', 0, 'none' FROM seq;",
        )
        .expect("fill");
        conn.execute_batch("DELETE FROM commands").expect("empty");

        let before = db_size_bytes(&conn).expect("size");
        assert!(
            before.allocated > 0 && before.free > 0,
            "deleting must leave free pages behind: {before:?}"
        );

        let mut state = MaintenanceState::default();
        rebuild_if_bloated(&conn, &mut state);
        assert!(state.rebuild_attempted, "the repair must mark itself done");

        let after = db_size_bytes(&conn).expect("size");
        assert!(
            after.allocated < before.allocated,
            "the file did not shrink: {} -> {}",
            before.allocated,
            after.allocated
        );
        assert_eq!(
            conn.query_row(SQL_AUTO_VACUUM, [], |row| row.get::<_, i64>(0))
                .expect("mode"),
            AUTO_VACUUM_INCREMENTAL,
            "the repair must leave an incremental database behind"
        );

        // A second pass in the same process must not rewrite anything again.
        let size_before_second = db_size_bytes(&conn).expect("size").allocated;
        rebuild_if_bloated(&conn, &mut state);
        assert_eq!(
            db_size_bytes(&conn).expect("size").allocated,
            size_before_second
        );
    }

    /// The retry budget is bounded even when every attempt fails, so a wedged
    /// database cannot hold the writer thread (or shutdown) hostage.
    #[test]
    fn retry_budget_is_bounded() {
        // The schedule must fit inside the overall budget: otherwise the last
        // attempt would always be cut off by the deadline instead of by the
        // attempt count.
        let mut backoff = BATCH_RETRY_BACKOFF;
        let mut total = Duration::ZERO;
        for _ in 1..BATCH_ATTEMPTS {
            total += backoff;
            backoff = (backoff * 2).min(BATCH_RETRY_BACKOFF * 8);
        }
        assert!(
            total < BATCH_RETRY_BUDGET,
            "the backoff schedule ({total:?}) must fit inside the budget"
        );
    }

    // -------------------------------------------------- maintenance (regr.)

    /// Requirement: maintenance must not depend on new records arriving. An
    /// idle writer still expires rows on its own clock.
    #[tokio::test]
    async fn maintenance_runs_on_its_own_clock_without_traffic() {
        let tmp = TempDb::create();
        let mut cfg = tmp.config();
        cfg.maintenance_interval_secs = 1;
        cfg.retention_days = 1;
        let handle = super::super::spawn_writer(&cfg, &crate::config::Limits::default())
            .expect("writer starts");
        let recorder = handle.recorder.clone();

        let old = SystemTime::now() - Duration::from_secs(10 * 86_400);
        for index in 0..5_u64 {
            let _ = recorder.emit(command(
                1,
                "198.51.100.23",
                old,
                "SET",
                &format!("old:{index}"),
                RiskLevel::Low,
            ));
        }
        let reader = Reader::open(&tmp.path).expect("reader");
        assert_eq!(
            reader.wait_for("SELECT count(*) FROM commands", 5, 10_000),
            5,
            "the stale rows must be stored first"
        );

        // From here on no record is emitted at all: only the writer's deadline
        // can remove those rows.
        assert_eq!(
            reader.wait_for("SELECT count(*) FROM commands", 0, 15_000),
            0,
            "an idle writer never ran retention"
        );
        drop(reader);
        drop(recorder);
        handle.shutdown().await;
    }

    /// The size cap is enforced on *used* pages. The old implementation compared
    /// the file size, which `DELETE` never reduces, so it deleted the whole
    /// history on every tick. History must survive now.
    #[tokio::test]
    async fn size_cap_prunes_against_used_pages_and_keeps_history() {
        let tmp = TempDb::create();
        let mut cfg = tmp.config();
        cfg.max_bytes = 256 * 1_024;
        cfg.retention_days = 0; // isolate the size cap from retention
        cfg.maintenance_interval_secs = 1;
        cfg.batch_size = 128;
        let handle = super::super::spawn_writer(&cfg, &crate::config::Limits::default())
            .expect("writer starts");
        let recorder = handle.recorder.clone();

        let padding = "p".repeat(480);
        for index in 0..2_000_u32 {
            let _ = recorder.emit(command(
                1,
                "198.51.100.23",
                now(),
                "SET",
                &format!("{padding}{index}"),
                RiskLevel::Low,
            ));
        }

        let reader = Reader::open(&tmp.path).expect("reader");
        let written = reader.wait_for("SELECT count(*) FROM commands", 2_000, 20_000);
        assert!(written > 0, "no rows were stored at all");

        // Give the writer time for several maintenance ticks. Pruning is
        // deliberately bounded per tick (a few percent of each table), so the
        // used space converges over a handful of ticks instead of one long stall.
        let cap = i64::try_from(cfg.max_bytes).expect("fits");
        let deadline = std::time::Instant::now() + Duration::from_secs(25);
        let mut used = reader.used_bytes();
        while used > cap * 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            used = reader.used_bytes();
        }
        let rows: i64 = reader.value("SELECT count(*) FROM commands").expect("rows");

        assert!(rows > 0, "the size cap deleted the entire history");
        assert!(rows < written, "the size cap never pruned anything");
        assert!(
            used <= cap * 2,
            "used space {used} ran away from the cap {cap}"
        );
        // The file itself is allowed to stay larger: `DELETE` frees pages, and
        // the free ones are reclaimed by `incremental_vacuum`, not by pruning.
        let allocated = reader.pragma("page_count") * reader.pragma("page_size");
        assert!(
            allocated >= used,
            "allocated {allocated} < used {used} is impossible"
        );

        drop(reader);
        drop(recorder);
        handle.shutdown().await;
    }

    /// A checkpoint runs on the timer too, and an idle writer truncates the WAL.
    #[tokio::test]
    async fn idle_checkpoint_truncates_the_wal() {
        let tmp = TempDb::create();
        let mut cfg = tmp.config();
        cfg.checkpoint_interval_secs = 1;
        cfg.maintenance_interval_secs = 1;
        cfg.batch_size = 64;
        let handle = super::super::spawn_writer(&cfg, &crate::config::Limits::default())
            .expect("writer starts");
        let recorder = handle.recorder.clone();

        let padding = "w".repeat(900);
        for index in 0..400_u32 {
            let _ = recorder.emit(command(
                1,
                "198.51.100.23",
                now(),
                "SET",
                &format!("{padding}{index}"),
                RiskLevel::Low,
            ));
        }
        let reader = Reader::open(&tmp.path).expect("reader");
        assert_eq!(
            reader.wait_for("SELECT count(*) FROM commands", 400, 20_000),
            400
        );
        assert!(reader.wal_bytes() > 0, "no WAL was produced");

        // Nothing else is written: the idle checkpoint must truncate it.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while reader.wal_bytes() > 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the idle WAL was never truncated (still {} bytes)",
                reader.wal_bytes()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(reader);
        drop(recorder);
        handle.shutdown().await;
    }

    /// A restart reopens the same file and keeps both the rows and the schema.
    #[tokio::test]
    async fn restart_reads_back_the_previous_rows() {
        let tmp = TempDb::create();

        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer starts");
        for index in 0..20_u32 {
            let _ = handle.recorder.emit(command(
                1,
                "198.51.100.23",
                now(),
                "PING",
                &format!("first:{index}"),
                RiskLevel::None,
            ));
        }
        handle.shutdown().await;

        let handle = super::super::spawn_writer(&tmp.config(), &crate::config::Limits::default())
            .expect("writer restarts");
        for index in 0..5_u32 {
            let _ = handle.recorder.emit(command(
                2,
                "203.0.113.7",
                now(),
                "PING",
                &format!("second:{index}"),
                RiskLevel::None,
            ));
        }
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let rows: i64 = reader
            .value("SELECT count(*) FROM commands")
            .expect("count");
        assert_eq!(rows, 25, "rows from before the restart must survive");
        let tables: i64 = reader
            .value(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .expect("tables");
        assert_eq!(tables, 5, "the schema must still be there");
    }

    /// `max_stored_param_bytes` really is what the writer applies: the constant
    /// is only the default, the configured value wins.
    #[tokio::test]
    async fn param_cap_follows_the_configured_limit() {
        let tmp = TempDb::create();
        let limits = crate::config::Limits {
            max_stored_param_bytes: 96,
            ..crate::config::Limits::default()
        };
        assert!(limits.max_stored_param_bytes < PARAM_CAP);
        let handle = super::super::spawn_writer(&tmp.config(), &limits).expect("writer starts");

        let _ = handle.recorder.emit(command(
            1,
            "198.51.100.23",
            now(),
            "SET",
            &"x".repeat(4_096),
            RiskLevel::Low,
        ));
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let stored: i64 = reader
            .value("SELECT length(CAST(args AS BLOB)) FROM commands")
            .expect("length");
        assert!(
            stored > 0 && stored <= 96,
            "stored {stored} bytes with a 96 byte cap"
        );
        // The tuning object carries the same number the writer used.
        assert_eq!(
            Tuning::from_config(&tmp.config(), limits.max_stored_param_bytes).param_cap(),
            96
        );
    }

    /// A zero cap would store nothing at all; the writer falls back to the
    /// documented default instead of silently recording empty strings.
    #[test]
    fn zero_param_cap_falls_back_to_the_default() {
        let cfg = DatabaseConfig::default();
        assert_eq!(Tuning::from_config(&cfg, 0).param_cap(), PARAM_CAP);
    }
}
