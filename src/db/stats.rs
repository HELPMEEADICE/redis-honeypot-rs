//! Read-only statistics for the `stats` subcommand.
//!
//! Runs in the CLI process only: it opens the database directly, never starts a
//! listener, and never touches the running honeypot's in-memory state.

use std::path::Path;

use rusqlite::{Connection, params};

use super::DbError;
use super::writer::text;
use crate::timeutil::format_utc_millis;

/// How many recent rows a detail section shows.
const RECENT_ROWS: i64 = 20;
/// `commands.args` is re-capped for display: stored rows can be 2 KiB wide.
const DISPLAY_ARGS: usize = 120;
/// Renderer column width for labels and leaderboard names.
const COLUMN_WIDTH: usize = 25;
/// Two-space indent for every data row.
const ROW_INDENT: &str = "  ";
/// Two-space gap between the cells of a detail row.
const CELL_GAP: &str = "  ";
/// Placeholder for a NULL or empty value.
const EMPTY: &str = "-";

const SQL_CONNECTIONS_TOTAL: &str = "SELECT count(*) FROM connections";
const SQL_CONNECTIONS_ACTIVE: &str =
    "SELECT count(*) FROM connections WHERE disconnected_at IS NULL";
const SQL_COMMANDS_TOTAL: &str = "SELECT count(*) FROM commands";
const SQL_COMMANDS_DISTINCT_IPS: &str = "SELECT count(DISTINCT ip) FROM commands";
const SQL_AUTH_TOTAL: &str = "SELECT count(*) FROM auth_attempts";
const SQL_AUTH_SIMULATED_OK: &str = "SELECT count(*) FROM auth_attempts WHERE simulated_ok = 1";
const SQL_SECURITY_TOTAL: &str = "SELECT count(*) FROM security_events";
const SQL_DANGEROUS_TOTAL: &str = "SELECT count(*) FROM commands WHERE risk >= 3";

const SQL_TOP_IPS: &str =
    "SELECT ip, count(*) AS hits FROM commands GROUP BY ip ORDER BY hits DESC, ip ASC LIMIT ?1";
const SQL_TOP_COMMANDS: &str = "SELECT name, count(*) AS hits FROM commands \
     GROUP BY name ORDER BY hits DESC, name ASC LIMIT ?1";
const SQL_AUTH_ROWS: &str = "SELECT ts, ip, username, password_len, delay_ms, simulated_ok \
     FROM auth_attempts ORDER BY ts DESC, id DESC LIMIT ?1";
const SQL_DANGEROUS_ROWS: &str = "SELECT ts, ip, name, args, risk_label FROM commands \
     WHERE risk >= 3 ORDER BY ts DESC, id DESC LIMIT ?1";

/// Lowest and highest timestamp seen by any table, as Unix milliseconds.
const SQL_WINDOW: &str = "SELECT min(t), max(t) FROM (
        SELECT min(ts) AS t FROM commands UNION ALL SELECT max(ts) FROM commands
        UNION ALL SELECT min(ts) FROM auth_attempts UNION ALL SELECT max(ts) FROM auth_attempts
        UNION ALL SELECT min(connected_at) FROM connections
        UNION ALL SELECT max(connected_at) FROM connections
        UNION ALL SELECT min(ts) FROM security_events UNION ALL SELECT max(ts) FROM security_events
    )";

/// Which report to build.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsQuery {
    /// How many entries to show in the source-IP leaderboard (0 omits it).
    pub top_ips: usize,
    /// How many entries to show in the command leaderboard (0 omits it).
    pub top_commands: usize,
    /// Include recent authentication attempts.
    pub auth: bool,
    /// Include recent dangerous commands.
    pub dangerous: bool,
}

/// A rendered-agnostic report: fields stay inspectable so tests can assert.
#[derive(Debug, Clone, Default)]
pub struct StatsReport {
    /// Database path as shown in the header.
    pub db_path: String,
    /// `(key, value)` pairs; keys follow `<entity>.<metric>`.
    pub summary: Vec<(String, String)>,
    /// `(ip, commands)` leaderboard, already sorted and truncated.
    pub top_ips: Vec<(String, u64)>,
    /// `(command, count)` leaderboard, already sorted and truncated.
    pub top_commands: Vec<(String, u64)>,
    /// Pre-formatted recent AUTH rows.
    pub auth_rows: Vec<Vec<String>>,
    /// Pre-formatted recent dangerous command rows.
    pub dangerous_rows: Vec<Vec<String>>,
}

impl StatsReport {
    /// Render the report as the text printed by `redis-honeypot-rs stats`.
    ///
    /// Empty sections are omitted entirely, and every line ends with `\n` so the
    /// output is stable, grep-friendly and safe to pipe.
    pub fn render(&self) -> String {
        let header = format!("Redis honeypot stats — {}", self.db_path);
        let mut out = String::with_capacity(512);
        out.push_str(&header);
        out.push('\n');
        out.push_str(&"=".repeat(header.chars().count().max(COLUMN_WIDTH)));
        out.push('\n');

        for (key, value) in &self.summary {
            push_cell(&mut out, key, COLUMN_WIDTH, false);
            out.push_str(value);
            out.push('\n');
        }

        if !self.top_ips.is_empty() {
            push_heading(&mut out, "Top source IPs");
            for (ip, count) in &self.top_ips {
                push_cell(&mut out, ip, COLUMN_WIDTH, true);
                out.push_str(&count.to_string());
                out.push('\n');
            }
        }

        if !self.top_commands.is_empty() {
            push_heading(&mut out, "Top commands");
            for (name, count) in &self.top_commands {
                push_cell(&mut out, name, COLUMN_WIDTH, true);
                out.push_str(&count.to_string());
                out.push('\n');
            }
        }

        if !self.auth_rows.is_empty() {
            push_heading(
                &mut out,
                &format!("Recent AUTH attempts ({})", self.auth_rows.len()),
            );
            push_rows(&mut out, &self.auth_rows);
        }

        if !self.dangerous_rows.is_empty() {
            push_heading(
                &mut out,
                &format!("Recent dangerous commands ({})", self.dangerous_rows.len()),
            );
            push_rows(&mut out, &self.dangerous_rows);
        }

        out
    }
}

/// Blank line, heading, newline: the only section separator we use.
fn push_heading(out: &mut String, heading: &str) {
    out.push('\n');
    out.push_str(heading);
    out.push('\n');
}

/// Label padded to `width`, ready for the value to be appended.
///
/// `indent` is only set for data rows: the summary block is flush left, exactly
/// as `stats` output is documented.
fn push_cell(out: &mut String, label: &str, width: usize, indent: bool) {
    if indent {
        out.push_str(ROW_INDENT);
    }
    out.push_str(label);
    for _ in label.chars().count()..width {
        out.push(' ');
    }
}

fn push_rows(out: &mut String, rows: &[Vec<String>]) {
    for row in rows {
        out.push_str(ROW_INDENT);
        out.push_str(&row.join(CELL_GAP));
        out.push('\n');
    }
}

/// Collect a report from the database at `path`.
///
/// `stats` is a pure reader: a missing file is an error, never something to
/// create. Nothing here prints — [`StatsReport::render`] does that.
pub fn collect(path: &Path, query: &StatsQuery) -> Result<StatsReport, DbError> {
    if let Err(err) = std::fs::metadata(path) {
        return Err(DbError::Io(std::io::Error::new(
            err.kind(),
            format!("cannot read database {}: {err}", path.display()),
        )));
    }

    let conn = super::open(path)?;
    let mut report = StatsReport {
        db_path: path.display().to_string(),
        ..StatsReport::default()
    };

    report.summary = summary(&conn)?;
    if query.top_ips > 0 {
        report.top_ips = leaderboard(&conn, SQL_TOP_IPS, query.top_ips)?;
    }
    if query.top_commands > 0 {
        report.top_commands = leaderboard(&conn, SQL_TOP_COMMANDS, query.top_commands)?;
    }
    if query.auth {
        report.auth_rows = auth_rows(&conn)?;
    }
    if query.dangerous {
        report.dangerous_rows = dangerous_rows(&conn)?;
    }
    Ok(report)
}

/// The fixed summary block, in the documented key order.
fn summary(conn: &Connection) -> Result<Vec<(String, String)>, DbError> {
    let (oldest, newest) = window(conn)?;
    let size = db_size_bytes(conn).unwrap_or(0);

    Ok(vec![
        (
            "connections.total".to_owned(),
            scalar(conn, SQL_CONNECTIONS_TOTAL)?.to_string(),
        ),
        (
            "connections.active".to_owned(),
            scalar(conn, SQL_CONNECTIONS_ACTIVE)?.to_string(),
        ),
        (
            "commands.total".to_owned(),
            scalar(conn, SQL_COMMANDS_TOTAL)?.to_string(),
        ),
        (
            "commands.distinct_ips".to_owned(),
            scalar(conn, SQL_COMMANDS_DISTINCT_IPS)?.to_string(),
        ),
        (
            "auth.attempts".to_owned(),
            scalar(conn, SQL_AUTH_TOTAL)?.to_string(),
        ),
        (
            "auth.simulated_ok".to_owned(),
            scalar(conn, SQL_AUTH_SIMULATED_OK)?.to_string(),
        ),
        (
            "security.events".to_owned(),
            scalar(conn, SQL_SECURITY_TOTAL)?.to_string(),
        ),
        (
            "dangerous.commands".to_owned(),
            scalar(conn, SQL_DANGEROUS_TOTAL)?.to_string(),
        ),
        ("db.size_bytes".to_owned(), size.to_string()),
        ("window.oldest".to_owned(), stamp(oldest)),
        ("window.newest".to_owned(), stamp(newest)),
    ])
}

/// One count. Every query in this module returns a single integer column.
fn scalar(conn: &Connection, sql: &str) -> Result<i64, DbError> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, i64>(0))?)
}

/// `page_count * page_size`, the same unit the size cap uses.
fn db_size_bytes(conn: &Connection) -> Option<i64> {
    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .ok()?;
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .ok()?;
    Some(page_count.saturating_mul(page_size))
}

fn window(conn: &Connection) -> Result<(Option<i64>, Option<i64>), DbError> {
    Ok(conn.query_row(SQL_WINDOW, [], |row| Ok((row.get(0)?, row.get(1)?)))?)
}

fn stamp(millis: Option<i64>) -> String {
    match millis {
        Some(ms) => format_utc_millis(ms),
        None => EMPTY.to_owned(),
    }
}

/// `SELECT <label>, count(*) … LIMIT ?1` — the two leaderboards share a shape.
fn leaderboard(conn: &Connection, sql: &str, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![as_limit(limit)], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (label, count) = row?;
        out.push((label, count.max(0).unsigned_abs()));
    }
    Ok(out)
}

/// Recent AUTH attempts, newest first in SQL, rendered oldest-first.
fn auth_rows(conn: &Connection) -> Result<Vec<Vec<String>>, DbError> {
    let mut stmt = conn.prepare(SQL_AUTH_ROWS)?;
    let rows = stmt.query_map(params![RECENT_ROWS], |row| {
        let ts: i64 = row.get(0)?;
        let ip: String = row.get(1)?;
        let username: Option<String> = row.get(2)?;
        let password_len: i64 = row.get(3)?;
        let delay_ms: i64 = row.get(4)?;
        let simulated_ok: i64 = row.get(5)?;
        let outcome = if simulated_ok == 0 { "fail" } else { "ok" };
        Ok(vec![
            format_utc_millis(ts),
            ip,
            username.unwrap_or_else(|| EMPTY.to_owned()),
            password_len.to_string(),
            format!("{delay_ms}ms"),
            outcome.to_owned(),
        ])
    })?;
    collect_rows(rows)
}

/// Recent high/critical commands, with `args` re-capped for the terminal.
fn dangerous_rows(conn: &Connection) -> Result<Vec<Vec<String>>, DbError> {
    let mut stmt = conn.prepare(SQL_DANGEROUS_ROWS)?;
    let rows = stmt.query_map(params![RECENT_ROWS], |row| {
        let ts: i64 = row.get(0)?;
        let ip: String = row.get(1)?;
        let name: String = row.get(2)?;
        let args: String = row.get(3)?;
        let risk_label: String = row.get(4)?;
        Ok(vec![
            format_utc_millis(ts),
            ip,
            name,
            text(&args, DISPLAY_ARGS),
            risk_label,
        ])
    })?;
    collect_rows(rows)
}

fn collect_rows<T>(rows: T) -> Result<Vec<Vec<String>>, DbError>
where
    T: Iterator<Item = rusqlite::Result<Vec<String>>>,
{
    let mut out: Vec<Vec<String>> = rows.collect::<Result<_, _>>()?;
    // SQL returns newest first; a report reads like a log, so flip it back.
    out.reverse();
    Ok(out)
}

/// `usize` from the CLI to the `LIMIT` parameter, without a wrapping cast.
fn as_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

/// Collect and print. The `stats` subcommand's only entry point.
pub fn print_stats(path: &Path, query: &StatsQuery) -> Result<(), DbError> {
    let report = collect(path, query)?;
    print!("{}", report.render());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::SystemTime;

    use super::*;
    use crate::db::testutil::{Reader, TempDb, auth, closed, command, opened, security};
    use crate::record::{CloseReason, RiskLevel, SecurityKind};

    fn full_query() -> StatsQuery {
        StatsQuery {
            top_ips: 10,
            top_commands: 10,
            auth: true,
            dangerous: true,
        }
    }

    fn summary_value<'a>(report: &'a StatsReport, key: &str) -> &'a str {
        report
            .summary
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .unwrap_or("<missing>")
    }

    /// Build one database with a known population and report on it.
    #[tokio::test]
    async fn collect_reports_known_rows() {
        let tmp = TempDb::create();
        let handle = crate::db::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let at = SystemTime::now();

        let _ = recorder.emit(opened(1, "198.51.100.23", at));
        let _ = recorder.emit(opened(2, "203.0.113.5", at));
        let _ = recorder.emit(closed(
            1,
            "198.51.100.23",
            at,
            2_000,
            CloseReason::ClientClosed,
        ));
        let _ = recorder.emit(command(
            1,
            "198.51.100.23",
            at,
            "CONFIG",
            "GET *",
            RiskLevel::Medium,
        ));
        let _ = recorder.emit(command(1, "198.51.100.23", at, "PING", "", RiskLevel::None));
        let _ = recorder.emit(command(
            2,
            "203.0.113.5",
            at,
            "MODULE",
            "LOAD /tmp/x.so",
            RiskLevel::Critical,
        ));
        let _ = recorder.emit(auth(
            1,
            "198.51.100.23",
            at,
            Some("admin"),
            Some("hunter2"),
            true,
        ));
        let _ = recorder.emit(auth(1, "198.51.100.23", at, None, None, false));
        let _ = recorder.emit(security(
            1,
            Some("198.51.100.23"),
            at,
            SecurityKind::DangerousCommand,
            "MODULE LOAD",
        ));
        drop(recorder);
        handle.shutdown().await;

        let report = collect(&tmp.path, &full_query()).expect("collect");
        assert_eq!(report.db_path, tmp.path.display().to_string());

        let keys: Vec<&str> = report.summary.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "connections.total",
                "connections.active",
                "commands.total",
                "commands.distinct_ips",
                "auth.attempts",
                "auth.simulated_ok",
                "security.events",
                "dangerous.commands",
                "db.size_bytes",
                "window.oldest",
                "window.newest",
            ],
            "summary keys and their order are part of the contract"
        );

        assert_eq!(summary_value(&report, "connections.total"), "2");
        assert_eq!(summary_value(&report, "connections.active"), "1");
        assert_eq!(summary_value(&report, "commands.total"), "3");
        assert_eq!(summary_value(&report, "commands.distinct_ips"), "2");
        assert_eq!(summary_value(&report, "auth.attempts"), "2");
        assert_eq!(summary_value(&report, "auth.simulated_ok"), "1");
        assert_eq!(summary_value(&report, "security.events"), "1");
        assert_eq!(summary_value(&report, "dangerous.commands"), "1");
        let size: i64 = summary_value(&report, "db.size_bytes")
            .parse()
            .expect("size");
        assert!(size > 0, "page_count * page_size must be positive");
        assert_ne!(summary_value(&report, "window.oldest"), EMPTY);
        assert_ne!(summary_value(&report, "window.newest"), EMPTY);

        assert_eq!(
            report
                .top_ips
                .first()
                .map(|(ip, hits)| (ip.as_str(), *hits)),
            Some(("198.51.100.23", 2))
        );
        assert_eq!(report.top_commands.len(), 3);
        assert_eq!(report.auth_rows.len(), 2);
        assert_eq!(
            report.auth_rows[0].len(),
            6,
            "ts, ip, username, len, delay, ok"
        );
        assert_eq!(report.auth_rows[1][2], EMPTY, "NULL username renders as -");
        assert_eq!(report.auth_rows[0][5], "ok");
        assert_eq!(report.auth_rows[1][5], "fail");
        assert_eq!(report.dangerous_rows.len(), 1);
        assert_eq!(report.dangerous_rows[0][2], "MODULE");
        assert_eq!(report.dangerous_rows[0][4], "critical");

        let rendered = report.render();
        // Visible with `cargo test -- --nocapture`; the assertions below pin it.
        println!("{rendered}");
        assert!(rendered.ends_with('\n'), "output must end with a newline");
        assert!(rendered.starts_with("Redis honeypot stats — "));
        assert!(rendered.contains("connections.total"));
        assert!(rendered.contains("\nTop source IPs\n"), "{rendered}");
        assert!(rendered.contains("\nTop commands\n"), "{rendered}");
        assert!(rendered.contains("Recent AUTH attempts (2)"), "{rendered}");
        assert!(
            rendered.contains("Recent dangerous commands (1)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("  198.51.100.23  admin  7  3821ms  ok\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("  198.51.100.23  -  0  3821ms  fail\n"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("  connections.total"),
            "the summary block is flush left:\n{rendered}"
        );
        assert!(!rendered.contains("hunter2"), "passwords are never printed");
    }

    /// An empty database still reports every key, and renders no sections.
    #[test]
    fn empty_database_omits_every_section() {
        let tmp = TempDb::create();
        drop(crate::db::init_db(&tmp.path).expect("init"));

        let report = collect(&tmp.path, &full_query()).expect("collect");
        assert_eq!(report.summary.len(), 11);
        assert_eq!(summary_value(&report, "connections.total"), "0");
        assert_eq!(summary_value(&report, "commands.total"), "0");
        assert_eq!(summary_value(&report, "window.oldest"), EMPTY);
        assert_eq!(summary_value(&report, "window.newest"), EMPTY);
        assert!(report.top_ips.is_empty());
        assert!(report.top_commands.is_empty());
        assert!(report.auth_rows.is_empty());
        assert!(report.dangerous_rows.is_empty());

        let rendered = report.render();
        for heading in [
            "Top source IPs",
            "Top commands",
            "Recent AUTH attempts",
            "Recent dangerous commands",
        ] {
            assert!(
                !rendered.contains(heading),
                "{heading} must be omitted:\n{rendered}"
            );
        }
        assert!(rendered.ends_with('\n'));
    }

    /// `top_ips = 0` / `top_commands = 0` skip their query and their section.
    #[tokio::test]
    async fn zero_limits_skip_the_leaderboards() {
        let tmp = TempDb::create();
        let handle = crate::db::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let _ = recorder.emit(command(
            1,
            "198.51.100.23",
            SystemTime::now(),
            "PING",
            "",
            RiskLevel::None,
        ));
        drop(recorder);
        handle.shutdown().await;

        let report = collect(
            &tmp.path,
            &StatsQuery {
                top_ips: 0,
                top_commands: 0,
                auth: false,
                dangerous: false,
            },
        )
        .expect("collect");
        assert!(report.top_ips.is_empty());
        assert!(report.top_commands.is_empty());
        assert!(report.auth_rows.is_empty());
        assert!(report.dangerous_rows.is_empty());
        assert_eq!(summary_value(&report, "commands.total"), "1");
        assert!(!report.render().contains("Top source IPs"));
    }

    /// A missing database is an error, and it stays missing.
    #[test]
    fn collect_on_missing_path_is_an_error() {
        let tmp = TempDb::create();
        let err = collect(&tmp.path, &full_query()).expect_err("must fail");
        match err {
            DbError::Io(io) => assert_eq!(io.kind(), ErrorKind::NotFound),
            other => panic!("unexpected error: {other}"),
        }
        assert!(!tmp.path.exists(), "stats must never create a database");
    }

    /// Long stored args are re-capped for display.
    #[tokio::test]
    async fn dangerous_rows_shorten_args_for_display() {
        let tmp = TempDb::create();
        let handle = crate::db::spawn_writer(&tmp.config()).expect("writer starts");
        let recorder = handle.recorder.clone();
        let long = "A".repeat(1_000);
        let _ = recorder.emit(command(
            1,
            "198.51.100.23",
            SystemTime::now(),
            "EVAL",
            &long,
            RiskLevel::Critical,
        ));
        drop(recorder);
        handle.shutdown().await;

        let reader = Reader::open(&tmp.path).expect("reader");
        let stored: i64 = reader
            .value("SELECT length(CAST(args AS BLOB)) FROM commands")
            .expect("byte length");
        assert!(stored > i64::try_from(DISPLAY_ARGS).expect("fits"));

        let report = collect(&tmp.path, &full_query()).expect("collect");
        let shown = &report.dangerous_rows[0][3];
        assert!(
            shown.chars().count() <= DISPLAY_ARGS,
            "shown={} chars",
            shown.chars().count()
        );
        assert!(shown.ends_with("..."));
    }
}
