//! SQLite persistence.
//!
//! Design rules:
//!
//! * Network tasks never touch SQLite — they only `try_send` into a bounded
//!   channel ([`crate::record::Recorder`]).
//! * One writer task owns the connection, batches records into transactions and
//!   performs retention/size maintenance and WAL checkpoints.
//! * A database failure is retried within a budget, counted when it is finally
//!   lost, and never propagated to the listener.

pub mod schema;
pub mod stats;
pub mod writer;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Database as DatabaseConfig;
use crate::config::Limits;
use crate::record::Recorder;

pub use stats::StatsQuery;
pub use writer::WriterStats;

/// Largest database that is rewritten (`VACUUM`) on startup so `auto_vacuum`
/// can be switched to `INCREMENTAL`.
///
/// `auto_vacuum` can only be turned on for a database that has no pages yet, or
/// by rewriting the whole file. Rewriting an arbitrary database at startup would
/// be an unbounded pause, so the migration is bounded by size and simply logged
/// as skipped above the threshold.
const AUTO_VACUUM_MIGRATION_MAX_BYTES: i64 = 64 * 1024 * 1024;

/// Persistence failure. Never fatal to the network service.
#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    /// The writer task could not be started.
    Spawn(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Spawn(m) => write!(f, "database writer unavailable: {m}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Open a connection with the pragmas the honeypot relies on.
///
/// WAL keeps the writer from blocking readers (the `stats` subcommand), and
/// `synchronous = NORMAL` is the right durability/latency trade for telemetry.
pub fn open(path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_millis(5_000))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -2000;
         PRAGMA foreign_keys = OFF;",
    )?;
    Ok(conn)
}

/// Switch the database to `PRAGMA auto_vacuum = INCREMENTAL` where possible.
///
/// Returns whether the database now uses incremental auto-vacuum.
///
/// The pragma only takes effect on a database that has no pages yet, or after a
/// `VACUUM` rewrites the file, so this is deliberately best effort:
///
/// * already `INCREMENTAL` → nothing to do (the common case after the first
///   start);
/// * empty file → set it, it applies to the first write;
/// * existing file inside [`AUTO_VACUUM_MIGRATION_MAX_BYTES`] → set it and
///   rewrite once, which is bounded in time;
/// * existing file above the threshold → leave it alone and say so. The size cap
///   still works (it measures used pages), only the file cannot shrink on its
///   own; the operator can `VACUUM` manually.
fn ensure_incremental_auto_vacuum(conn: &Connection) -> Result<bool, DbError> {
    let mode: i64 = conn.pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
    if mode == writer::AUTO_VACUUM_INCREMENTAL {
        return Ok(true);
    }
    let pages: i64 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
    if pages == 0 {
        // Nothing has been written yet: the pragma applies to the first page.
        conn.pragma_update(None, "auto_vacuum", writer::AUTO_VACUUM_INCREMENTAL)?;
        return Ok(true);
    }
    let page_size: i64 = conn.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let size = pages.saturating_mul(page_size);
    if size > AUTO_VACUUM_MIGRATION_MAX_BYTES {
        tracing::warn!(
            size,
            limit = AUTO_VACUUM_MIGRATION_MAX_BYTES,
            "database is too large to enable incremental auto-vacuum at startup; \
             free pages will not be returned to the filesystem until it is VACUUMed"
        );
        return Ok(false);
    }
    // Setting the pragma is what changes the mode; the VACUUM is what makes it
    // apply to an existing file.
    conn.pragma_update(None, "auto_vacuum", writer::AUTO_VACUUM_INCREMENTAL)?;
    conn.execute_batch("VACUUM")?;
    let mode: i64 = conn.pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
    let migrated = mode == writer::AUTO_VACUUM_INCREMENTAL;
    if migrated {
        tracing::info!(size, "migrated the database to incremental auto-vacuum");
    } else {
        tracing::warn!(mode, "incremental auto-vacuum could not be enabled");
    }
    Ok(migrated)
}

/// Open (creating if needed) and make sure the schema exists.
pub fn init_db(path: &Path) -> Result<Connection, DbError> {
    let conn = open(path)?;
    // Order matters: the pragma has to be set before the first table exists for
    // a brand new database, and before the VACUUM for an existing one.
    ensure_incremental_auto_vacuum(&conn)?;
    schema::init(&conn)?;
    conn.pragma_update(None, "user_version", schema::SCHEMA_VERSION)?;
    Ok(conn)
}

/// Handle to the running writer task plus the recorder it feeds.
pub struct DbHandle {
    /// Clone this into the network layer.
    pub recorder: Recorder,
    stats: Arc<WriterStats>,
    join: JoinHandle<()>,
}

impl DbHandle {
    pub fn new(recorder: Recorder, stats: Arc<WriterStats>, join: JoinHandle<()>) -> Self {
        Self {
            recorder,
            stats,
            join,
        }
    }

    /// Number of telemetry records dropped so far (queue full or closed).
    pub fn dropped(&self) -> u64 {
        self.recorder.dropped()
    }

    /// Number of records lost because SQLite rejected them even after retrying.
    pub fn lost(&self) -> u64 {
        self.stats.lost()
    }

    /// Writer-side counters, for the periodic watchdog line.
    pub fn writer_stats(&self) -> Arc<WriterStats> {
        self.stats.clone()
    }

    /// Close the channel, flush what is queued, and wait for the writer.
    ///
    /// Bounded so shutdown cannot hang on a wedged disk.
    pub async fn shutdown(self) {
        let Self {
            recorder,
            stats,
            join,
        } = self;
        drop(recorder);
        if tokio::time::timeout(Duration::from_secs(5), join)
            .await
            .is_err()
        {
            tracing::warn!("sqlite writer did not stop within 5s; detaching");
        } else if stats.lost() > 0 {
            tracing::warn!(lost = stats.lost(), "sqlite writer lost records in total");
        }
    }
}

/// Start the single database writer task.
///
/// This is the only fatal database path: if the file cannot be opened or the
/// schema cannot be created, `main` must fail at startup instead of running a
/// honeypot that silently records nothing. Every *later* failure is retried,
/// counted and survived inside [`writer::run`].
///
/// `limits` is passed in so the stored-argument cap
/// ([`Limits::max_stored_param_bytes`]) travels with the writer instead of being
/// duplicated as a constant it can drift away from.
pub fn spawn_writer(cfg: &DatabaseConfig, limits: &Limits) -> Result<DbHandle, DbError> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|err| DbError::Spawn(format!("the sqlite writer needs a tokio runtime: {err}")))?;

    let conn = init_db(&cfg.path)?;

    // Bounded on purpose: a full queue drops records (and counts them) rather
    // than applying backpressure to a network task.
    let (tx, rx) = mpsc::channel(cfg.queue_capacity.max(1));
    let dropped = Arc::new(crate::record::DropCounter::new(0));
    let recorder = Recorder::new(tx, dropped);

    let tuning = writer::Tuning::from_config(cfg, limits.max_stored_param_bytes);
    let stats = Arc::new(WriterStats::default());
    let writer_stats = stats.clone();
    let join = runtime.spawn_blocking(move || writer::run(conn, rx, tuning, writer_stats));
    Ok(DbHandle::new(recorder, stats, join))
}

/// Fixtures for the `db` tests: unique temp files, record builders, a reader.
#[cfg(test)]
pub(crate) mod testutil {
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant, SystemTime};

    use rusqlite::Connection;
    use rusqlite::types::FromSql;

    use super::DbError;
    use crate::config::Database as DatabaseConfig;
    use crate::record::{
        AuthRecord, CloseReason, CommandRecord, ConnectionClosed, ConnectionOpened, Record,
        RiskLevel, SecurityEvent, SecurityKind,
    };

    /// Fixed AUTH delay used by the fixtures, so assertions can name it.
    pub(crate) const TEST_DELAY_MS: u64 = 3_821;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A database path that exists only for one test.
    ///
    /// The file (plus `-wal` and `-shm`) is removed on drop, so tests never see
    /// each other's rows and a real database is never touched.
    pub(crate) struct TempDb {
        pub(crate) path: PathBuf,
    }

    impl TempDb {
        pub(crate) fn create() -> Self {
            let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rhp-test-{}-{counter}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Self { path }
        }

        pub(crate) fn config(&self) -> DatabaseConfig {
            DatabaseConfig {
                path: self.path.clone(),
                ..DatabaseConfig::default()
            }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut raw = self.path.clone().into_os_string();
                raw.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(raw));
            }
        }
    }

    /// A second connection, used to observe what the writer committed.
    pub(crate) struct Reader {
        conn: Connection,
        path: PathBuf,
    }

    impl Reader {
        pub(crate) fn open(path: &Path) -> Result<Self, DbError> {
            Ok(Self {
                conn: super::open(path)?,
                path: path.to_path_buf(),
            })
        }

        /// First column of the first row of `sql`.
        pub(crate) fn value<T: FromSql>(&self, sql: &str) -> Result<T, DbError> {
            Ok(self.conn.query_row(sql, [], |row| row.get::<_, T>(0))?)
        }

        /// An integer pragma of the observed database.
        pub(crate) fn pragma(&self, name: &str) -> i64 {
            self.conn
                .pragma_query_value(None, name, |row| row.get::<_, i64>(0))
                .unwrap_or(-1)
        }

        /// Pages the data actually occupies, in bytes: `(page_count - freelist)`.
        pub(crate) fn used_bytes(&self) -> i64 {
            let pages = self
                .pragma("page_count")
                .saturating_sub(self.pragma("freelist_count"));
            pages.saturating_mul(self.pragma("page_size"))
        }

        /// The `-wal` sidecar size, which is what a checkpoint is meant to shrink.
        pub(crate) fn wal_bytes(&self) -> u64 {
            let mut raw = self.path.as_os_str().to_owned();
            raw.push("-wal");
            std::fs::metadata(PathBuf::from(raw))
                .map(|meta| meta.len())
                .unwrap_or(0)
        }

        /// Poll `sql` until it returns `want` or `timeout_ms` expires; the last
        /// value seen is returned either way, so failures show a real number.
        pub(crate) fn wait_for(&self, sql: &str, want: i64, timeout_ms: u64) -> i64 {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms);
            loop {
                let seen = self.value::<i64>(sql).unwrap_or(-1);
                if seen == want || Instant::now() >= deadline {
                    return seen;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn ip(raw: &str) -> IpAddr {
        raw.parse::<IpAddr>().expect("test ip must parse")
    }

    pub(crate) fn opened(conn_id: u64, addr: &str, at: SystemTime) -> Record {
        Record::Opened(ConnectionOpened {
            conn_id,
            ip: ip(addr),
            port: 63_799,
            at,
        })
    }

    pub(crate) fn closed(
        conn_id: u64,
        addr: &str,
        at: SystemTime,
        duration_ms: i64,
        reason: CloseReason,
    ) -> Record {
        Record::Closed(ConnectionClosed {
            conn_id,
            ip: ip(addr),
            at,
            duration_ms,
            command_count: 7,
            reason,
        })
    }

    pub(crate) fn command(
        conn_id: u64,
        addr: &str,
        at: SystemTime,
        name: &str,
        args: &str,
        risk: RiskLevel,
    ) -> Record {
        Record::Command(CommandRecord {
            conn_id,
            ip: ip(addr),
            at,
            name: name.to_owned(),
            args: args.to_owned(),
            arg_count: 1 + args.split_whitespace().count(),
            resp_type: "+OK".to_owned(),
            simulated: "ok".to_owned(),
            risk,
        })
    }

    pub(crate) fn auth(
        conn_id: u64,
        addr: &str,
        at: SystemTime,
        username: Option<&str>,
        password: Option<&str>,
        simulated_ok: bool,
    ) -> Record {
        Record::Auth(AuthRecord {
            conn_id,
            ip: ip(addr),
            at,
            username: username.map(str::to_owned),
            arg_count: if username.is_some() { 3 } else { 2 },
            password_len: password.map_or(0, str::len),
            password: password.map(str::to_owned),
            simulated_ok,
            delay_ms: TEST_DELAY_MS,
            meta: Some("client=redis-cli".to_owned()),
        })
    }

    pub(crate) fn security(
        conn_id: u64,
        addr: Option<&str>,
        at: SystemTime,
        kind: SecurityKind,
        detail: &str,
    ) -> Record {
        Record::Security(SecurityEvent {
            conn_id,
            ip: addr.map(ip),
            at,
            kind,
            command: Some("CONFIG".to_owned()),
            detail: detail.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::TempDb;
    use super::*;

    /// The writer relies on WAL: readers must not block the writer.
    #[test]
    fn journal_mode_is_wal() {
        let tmp = TempDb::create();
        let conn = init_db(&tmp.path).expect("init db");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("pragma journal_mode");
        println!("PRAGMA journal_mode = {mode}");
        assert_eq!(mode.to_ascii_lowercase(), "wal", "journal_mode={mode}");
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("user_version");
        assert_eq!(version, schema::SCHEMA_VERSION);
    }

    /// Startup is the one fatal database path: the writer creates the file.
    #[test]
    fn spawn_writer_creates_the_database() {
        let tmp = TempDb::create();
        assert!(!tmp.path.exists());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let handle = runtime.block_on(async { spawn_writer(&tmp.config(), &Limits::default()) });
        assert!(handle.is_ok(), "writer must create the file");
        assert!(tmp.path.exists());
    }

    /// Without a runtime we return an error instead of panicking in tokio.
    #[test]
    fn spawn_writer_without_runtime_is_an_error() {
        let tmp = TempDb::create();
        match spawn_writer(&tmp.config(), &Limits::default()) {
            Err(DbError::Spawn(message)) => assert!(!message.is_empty()),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("a runtime is required"),
        }
    }
}
