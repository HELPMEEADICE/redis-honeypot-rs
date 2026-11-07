//! SQLite schema. Authoritative: the stats queries and integration tests both
//! depend on these exact table and column names.

use rusqlite::Connection;

/// Current schema version, stored in `PRAGMA user_version`.
///
/// * 1 — the four telemetry tables.
/// * 2 — adds `writer_stats`, the single row that persists the writer's own
///   health counters so a later `stats` run can report them.
///
/// The DDL is additive and idempotent, so a version 1 database is upgraded in
/// place by simply running [`init`] again.
pub const SCHEMA_VERSION: i64 = 2;

/// Create tables and indexes if they do not exist, and stamp the schema version.
pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(DDL)
}

/// Idempotent DDL. All timestamps are Unix milliseconds in UTC.
pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS connections (
    conn_id         INTEGER PRIMARY KEY,
    ip              TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    connected_at    INTEGER NOT NULL,
    disconnected_at INTEGER,
    duration_ms     INTEGER,
    command_count   INTEGER NOT NULL DEFAULT 0,
    close_reason    TEXT
);
CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(ip);
CREATE INDEX IF NOT EXISTS idx_connections_connected_at ON connections(connected_at);

CREATE TABLE IF NOT EXISTS commands (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conn_id    INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    ip         TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    args       TEXT    NOT NULL,
    arg_count  INTEGER NOT NULL DEFAULT 0,
    resp_type  TEXT    NOT NULL,
    simulated  TEXT    NOT NULL,
    risk       INTEGER NOT NULL DEFAULT 0,
    risk_label TEXT    NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_commands_ip ON commands(ip);
CREATE INDEX IF NOT EXISTS idx_commands_name_ts ON commands(name, ts);
CREATE INDEX IF NOT EXISTS idx_commands_ts ON commands(ts);
CREATE INDEX IF NOT EXISTS idx_commands_risk ON commands(risk);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    conn_id      INTEGER NOT NULL,
    ts           INTEGER NOT NULL,
    ip           TEXT    NOT NULL,
    username     TEXT,
    arg_count    INTEGER NOT NULL DEFAULT 0,
    password_len INTEGER NOT NULL DEFAULT 0,
    password     TEXT,
    simulated_ok INTEGER NOT NULL DEFAULT 1,
    delay_ms     INTEGER NOT NULL DEFAULT 0,
    meta         TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(ip);
CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(ts);
CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username);

CREATE TABLE IF NOT EXISTS security_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    conn_id INTEGER NOT NULL,
    ts      INTEGER NOT NULL,
    ip      TEXT,
    kind    TEXT    NOT NULL,
    command TEXT,
    detail  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_ip ON security_events(ip);
CREATE INDEX IF NOT EXISTS idx_security_kind_ts ON security_events(kind, ts);

-- Writer health. Exactly one row (id = 1), rewritten by the writer itself, so
-- the counters survive the process that produced them and a separate `stats`
-- run can report how much telemetry was lost rather than guessing.
CREATE TABLE IF NOT EXISTS writer_stats (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    updated_at         INTEGER NOT NULL,
    lost               INTEGER NOT NULL DEFAULT 0,
    retried            INTEGER NOT NULL DEFAULT 0,
    retry_failed       INTEGER NOT NULL DEFAULT 0,
    pruned_rows        INTEGER NOT NULL DEFAULT 0,
    vacuum_pages       INTEGER NOT NULL DEFAULT 0,
    checkpoint_blocked INTEGER NOT NULL DEFAULT 0
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init(&conn).expect("schema");
        conn
    }

    #[test]
    fn init_is_idempotent() {
        let conn = memory_db();
        init(&conn).expect("second init must be a no-op");
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .expect("count tables");
        assert_eq!(count, 5, "four telemetry tables plus writer_stats");
    }

    #[test]
    fn expected_indexes_exist() {
        let conn = memory_db();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .expect("prepare");
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        for want in [
            "idx_connections_ip",
            "idx_connections_connected_at",
            "idx_commands_ip",
            "idx_commands_name_ts",
            "idx_commands_ts",
            "idx_auth_ip",
            "idx_auth_ts",
            "idx_security_ip",
            "idx_security_kind_ts",
        ] {
            assert!(names.iter().any(|n| n == want), "missing index {want}");
        }
    }

    #[test]
    fn all_required_columns_are_present() {
        let conn = memory_db();
        let cols = |table: &str| -> Vec<String> {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("pragma");
            stmt.query_map([], |r| r.get::<_, String>(1))
                .expect("query")
                .filter_map(Result::ok)
                .collect()
        };
        assert_eq!(
            cols("connections"),
            vec![
                "conn_id",
                "ip",
                "port",
                "connected_at",
                "disconnected_at",
                "duration_ms",
                "command_count",
                "close_reason"
            ]
        );
        assert_eq!(
            cols("commands"),
            vec![
                "id",
                "conn_id",
                "ts",
                "ip",
                "name",
                "args",
                "arg_count",
                "resp_type",
                "simulated",
                "risk",
                "risk_label"
            ]
        );
        assert_eq!(
            cols("auth_attempts"),
            vec![
                "id",
                "conn_id",
                "ts",
                "ip",
                "username",
                "arg_count",
                "password_len",
                "password",
                "simulated_ok",
                "delay_ms",
                "meta"
            ]
        );
        assert_eq!(
            cols("security_events"),
            vec!["id", "conn_id", "ts", "ip", "kind", "command", "detail"]
        );
        assert_eq!(
            cols("writer_stats"),
            vec![
                "id",
                "updated_at",
                "lost",
                "retried",
                "retry_failed",
                "pruned_rows",
                "vacuum_pages",
                "checkpoint_blocked"
            ]
        );
    }
}
