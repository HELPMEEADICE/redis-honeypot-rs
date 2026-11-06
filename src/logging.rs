//! Console events.
//!
//! Two deliberate decisions:
//!
//! * **Everything is escaped and capped before printing.** An attacker can send
//!   CR/LF, ANSI escapes and 500 KiB of binary junk; none of it reaches the
//!   terminal raw (see [`crate::text`]).
//! * **Output is rate limited.** A scan flood must not turn into a console or
//!   journald write flood, so lines above a per-second budget are dropped and
//!   the suppressed count is reported once per window.
//!
//! Structured, lossless telemetry lives in SQLite; this module is the human
//! readable side channel.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use tracing_subscriber::EnvFilter;

use crate::text;
use crate::timeutil;

/// Console lines emitted per wall clock second before throttling kicks in.
const MAX_LINES_PER_SEC: u64 = 200;
/// Hard cap on one console line body (before the `[time] KIND ` prefix).
const MAX_BODY_LEN: usize = 512;

static WINDOW_SEC: AtomicUsize = AtomicUsize::new(0);
static WINDOW_COUNT: AtomicUsize = AtomicUsize::new(0);
static SUPPRESSED: AtomicUsize = AtomicUsize::new(0);

/// Install the global tracer. Safe to call twice (second call is ignored).
pub fn init(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("warn,redis_honeypot_rs={level},honeypot={level}"))
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_ansi(false)
        .try_init();
}

/// One console line: `[2026-11-06 12:00:00] CONNECT  198.51.100.23:54321`.
fn print_line(kind: &str, body: &str) {
    let body = scrub(body);
    let stamp = timeutil::format_utc(timeutil::now());
    tracing::info!(target: "honeypot", "[{stamp}] {kind:<9} {body}");
}

/// Strip CR/LF/NUL and cap length. Second line of defence behind the helpers in
/// [`crate::text`] — cheap insurance against a caller that forgot.
fn scrub(body: &str) -> String {
    let mut cleaned = String::with_capacity(body.len().min(MAX_BODY_LEN));
    for ch in body.chars() {
        match ch {
            '\r' | '\n' | '\0' => cleaned.push(' '),
            _ => cleaned.push(ch),
        }
        if cleaned.len() >= MAX_BODY_LEN {
            cleaned.push_str("...");
            break;
        }
    }
    cleaned
}

/// Rate gate. Returns `true` when this line may be printed.
fn admit() -> bool {
    let now = timeutil::unix_secs(timeutil::now()).max(0) as usize;
    let seen = WINDOW_SEC.load(Ordering::Relaxed);
    if seen != now
        && WINDOW_SEC
            .compare_exchange(seen, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        WINDOW_COUNT.store(0, Ordering::Relaxed);
        let suppressed = SUPPRESSED.swap(0, Ordering::Relaxed);
        if suppressed > 0 {
            print_line("RATE", &format!("suppressed {suppressed} console lines"));
        }
    }

    let count = WINDOW_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count as u64 > MAX_LINES_PER_SEC {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    } else {
        true
    }
}

fn emit(kind: &str, body: &str) {
    if admit() {
        print_line(kind, body);
    }
}

/// A new TCP connection was accepted.
pub fn connect(peer: SocketAddr) {
    emit("CONNECT", &peer.to_string());
}

/// A connection closed, with why and how much it did.
pub fn close(peer: SocketAddr, reason: &str, duration_ms: i64, commands: u64) {
    emit(
        "CLOSE",
        &format!("{peer} {reason} {duration_ms}ms {commands}cmds"),
    );
}

/// A simulated authentication. The password is never printed, only masked.
pub fn auth(peer: SocketAddr, username: &str, delay_ms: u64, ok: bool) {
    let escaped = text::escape_str(username, 64);
    let user = if escaped.is_empty() {
        "-"
    } else {
        escaped.as_str()
    };
    let status = if ok { "OK" } else { "FAIL" };
    emit(
        "AUTH",
        &format!("{peer} {user} ****** {delay_ms}ms {status}"),
    );
}

/// A recorded command, already rendered as one bounded line.
pub fn command(peer: SocketAddr, rendered: &str) {
    emit("COMMAND", &format!("{peer} {rendered}"));
}

/// A dangerous command that was simulated rather than executed.
pub fn alert(peer: SocketAddr, command: &str, detail: &str) {
    emit(
        "ALERT",
        &format!(
            "{peer} {} [{}]",
            text::escape_str(command, 64),
            text::escape_str(detail, 160)
        ),
    );
}

/// A protocol anomaly, limit hit or admission rejection.
pub fn notice(peer: SocketAddr, what: &str, detail: &str) {
    emit(
        "NOTICE",
        &format!(
            "{peer} {} {}",
            text::escape_str(what, 48),
            text::escape_str(detail, 240)
        ),
    );
}

/// A plain informational line from the server itself.
pub fn info(message: &str) {
    emit("INFO", message);
}

/// A warning. Not throttled: these are rare and must not be lost.
pub fn warn(message: &str) {
    let stamp = timeutil::format_utc(timeutil::now());
    tracing::warn!(target: "honeypot", "[{stamp}] {:<9} {}", "WARN", scrub(message));
}

/// An error. Not throttled.
pub fn error(message: &str) {
    let stamp = timeutil::format_utc(timeutil::now());
    tracing::error!(target: "honeypot", "[{stamp}] {:<9} {}", "ERROR", scrub(message));
}
