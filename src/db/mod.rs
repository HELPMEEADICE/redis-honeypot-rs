//! SQLite persistence.
//!
//! Design rules:
//!
//! * Network tasks never touch SQLite — they only `try_send` into a bounded
//!   channel ([`crate::record::Recorder`]).
//! * One writer task owns the connection, batches records into transactions and
//!   performs retention/size maintenance and WAL checkpoints.
//! * A database failure is logged and retried, never propagated to the listener.

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
use crate::record::Recorder;

pub use stats::StatsQuery;

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

/// Open (creating if needed) and make sure the schema exists.
pub fn init_db(path: &Path) -> Result<Connection, DbError> {
    let conn = open(path)?;
    schema::init(&conn)?;
    conn.pragma_update(None, "user_version", schema::SCHEMA_VERSION)?;
    Ok(conn)
}

/// Handle to the running writer task plus the recorder it feeds.
pub struct DbHandle {
    /// Clone this into the network layer.
    pub recorder: Recorder,
    join: JoinHandle<()>,
}

impl DbHandle {
    pub fn new(recorder: Recorder, join: JoinHandle<()>) -> Self {
        Self { recorder, join }
    }

    /// Number of telemetry records dropped so far (queue full or closed).
    pub fn dropped(&self) -> u64 {
        self.recorder.dropped()
    }

    /// Close the channel, flush what is queued, and wait for the writer.
    ///
    /// Bounded so shutdown cannot hang on a wedged disk.
    pub async fn shutdown(self) {
        let Self { recorder, join } = self;
        drop(recorder);
        if tokio::time::timeout(Duration::from_secs(5), join)
            .await
            .is_err()
        {
            tracing::warn!("sqlite writer did not stop within 5s; detaching");
        }
    }
}

/// Start the single database writer task.
///
/// This is the only fatal database path: if the file cannot be opened or the
/// schema cannot be created, `main` must fail at startup instead of running a
/// honeypot that silently records nothing. Every *later* failure is logged and
/// survived inside [`writer::run`].
pub fn spawn_writer(cfg: &DatabaseConfig) -> Result<DbHandle, DbError> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|err| DbError::Spawn(format!("the sqlite writer needs a tokio runtime: {err}")))?;

    let conn = init_db(&cfg.path)?;

    // Bounded on purpose: a full queue drops records (and counts them) rather
    // than applying backpressure to a network task.
    let (tx, rx) = mpsc::channel(cfg.queue_capacity.max(1));
    let dropped = Arc::new(crate::record::DropCounter::new(0));
    let recorder = Recorder::new(tx, dropped);

    let tuning = writer::Tuning::from_config(cfg);
    let join = runtime.spawn_blocking(move || writer::run(conn, rx, tuning));
    Ok(DbHandle::new(recorder, join))
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
    }

    impl Reader {
        pub(crate) fn open(path: &Path) -> Result<Self, DbError> {
            Ok(Self {
                conn: super::open(path)?,
            })
        }

        /// First column of the first row of `sql`.
        pub(crate) fn value<T: FromSql>(&self, sql: &str) -> Result<T, DbError> {
            Ok(self.conn.query_row(sql, [], |row| row.get::<_, T>(0))?)
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
        let handle = runtime.block_on(async { spawn_writer(&tmp.config()) });
        assert!(handle.is_ok(), "writer must create the file");
        assert!(tmp.path.exists());
    }

    /// Without a runtime we return an error instead of panicking in tokio.
    #[test]
    fn spawn_writer_without_runtime_is_an_error() {
        let tmp = TempDb::create();
        match spawn_writer(&tmp.config()) {
            Err(DbError::Spawn(message)) => assert!(!message.is_empty()),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("a runtime is required"),
        }
    }
}
