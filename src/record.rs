//! The single bounded channel between the network path and SQLite.
//!
//! Network tasks never touch SQLite. They build one of these records and
//! `try_send` it. If the queue is full the record is dropped and counted — a
//! honeypot must never block on its own logging, and losing telemetry is
//! strictly better than giving an attacker flow control over the listener.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Counter for records dropped because the bounded queue was full.
///
/// `AtomicU64` does not exist on targets without 64-bit atomics (for example
/// `mips-unknown-linux-gnu`), so the counter is machine-word sized and widened
/// to `u64` at the API boundary. Wrapping at 2^32 on such a target is
/// acceptable for a diagnostic counter.
#[cfg(target_has_atomic = "64")]
pub type DropCounter = std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
pub type DropCounter = std::sync::atomic::AtomicUsize;
use std::time::SystemTime;

use tokio::sync::mpsc;

/// Monotonic, process-local connection identifier.
pub type ConnId = u64;

/// Severity of a simulated command, mirrored into SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RiskLevel {
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_i64(value: i64) -> Self {
        match value {
            i64::MIN..=0 => Self::None,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Why a connection ended. Recorded verbatim in `connections.close_reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    ClientClosed,
    IdleTimeout,
    StuckClient,
    CommandLimit,
    AuthLimit,
    ProtocolError,
    IoError,
    ServerShutdown,
    WriteFailed,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::IdleTimeout => "idle_timeout",
            Self::StuckClient => "stuck_client",
            Self::CommandLimit => "command_limit",
            Self::AuthLimit => "auth_limit",
            Self::ProtocolError => "protocol_error",
            Self::IoError => "io_error",
            Self::ServerShutdown => "server_shutdown",
            Self::WriteFailed => "write_failed",
        }
    }
}

/// Category for `security_events.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKind {
    DangerousCommand,
    ProtocolAnomaly,
    OversizedRequest,
    AbnormalDisconnect,
    RateLimited,
    AuthBurst,
}

impl SecurityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DangerousCommand => "dangerous_command",
            Self::ProtocolAnomaly => "protocol_anomaly",
            Self::OversizedRequest => "oversized_request",
            Self::AbnormalDisconnect => "abnormal_disconnect",
            Self::RateLimited => "rate_limited",
            Self::AuthBurst => "auth_burst",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionOpened {
    pub conn_id: ConnId,
    pub ip: IpAddr,
    pub port: u16,
    pub at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct ConnectionClosed {
    pub conn_id: ConnId,
    pub ip: IpAddr,
    pub at: SystemTime,
    pub duration_ms: i64,
    pub command_count: u64,
    pub reason: CloseReason,
}

#[derive(Debug, Clone)]
pub struct CommandRecord {
    pub conn_id: ConnId,
    pub ip: IpAddr,
    pub at: SystemTime,
    pub name: String,
    pub args: String,
    pub arg_count: usize,
    pub resp_type: String,
    pub simulated: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone)]
pub struct AuthRecord {
    pub conn_id: ConnId,
    pub ip: IpAddr,
    pub at: SystemTime,
    pub username: Option<String>,
    /// Arguments of the command that carried the credentials (`AUTH`: 2 or 3,
    /// `HELLO…AUTH`: the whole option list). `u16` because
    /// [`crate::config::Limits::max_args`] allows up to 256 and `u8` would wrap.
    pub arg_count: u16,
    pub password_len: usize,
    pub password: Option<String>,
    pub simulated_ok: bool,
    /// Planned (simulated) delay in milliseconds; the measured wait and the
    /// outcome are in `meta`, so an attempt cancelled by a disconnect is still
    /// distinguishable from one that was actually delayed.
    pub delay_ms: u64,
    pub meta: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub conn_id: ConnId,
    pub ip: Option<IpAddr>,
    pub at: SystemTime,
    pub kind: SecurityKind,
    pub command: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub enum Record {
    Opened(ConnectionOpened),
    Closed(ConnectionClosed),
    Command(CommandRecord),
    Auth(AuthRecord),
    Security(SecurityEvent),
}

/// Cheap, cloneable, non-blocking writer side of the record channel.
#[derive(Debug, Clone, Default)]
pub struct Recorder {
    tx: Option<mpsc::Sender<Record>>,
    dropped: Option<Arc<DropCounter>>,
}

impl Recorder {
    pub fn new(tx: mpsc::Sender<Record>, dropped: Arc<DropCounter>) -> Self {
        Self {
            tx: Some(tx),
            dropped: Some(dropped),
        }
    }

    /// A recorder that swallows everything. Only for tests and dry runs.
    pub fn disabled() -> Self {
        Self {
            tx: None,
            dropped: None,
        }
    }

    /// Emit a record without ever awaiting. Returns `true` if it was queued.
    pub fn emit(&self, record: Record) -> bool {
        let Some(tx) = self.tx.as_ref() else {
            return false;
        };
        match tx.try_send(record) {
            Ok(()) => true,
            Err(_) => {
                if let Some(counter) = self.dropped.as_ref() {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                false
            }
        }
    }

    /// Number of records dropped so far because the queue was full or closed.
    pub fn dropped(&self) -> u64 {
        self.dropped
            .as_ref()
            .map(|counter| {
                // A no-op where `DropCounter` is already 64-bit, and required
                // where it is not (targets without 64-bit atomics).
                #[allow(clippy::unnecessary_cast)]
                let value = counter.load(Ordering::Relaxed) as u64;
                value
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_recorder_never_panics_and_never_counts() {
        let r = Recorder::disabled();
        assert!(!r.emit(Record::Security(SecurityEvent {
            conn_id: 1,
            ip: None,
            at: SystemTime::now(),
            kind: SecurityKind::ProtocolAnomaly,
            command: None,
            detail: "x".into(),
        })));
        assert_eq!(r.dropped(), 0);
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts_instead_of_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        let dropped = Arc::new(DropCounter::new(0));
        let recorder = Recorder::new(tx, dropped.clone());

        let mk = || {
            Record::Security(SecurityEvent {
                conn_id: 7,
                ip: None,
                at: SystemTime::now(),
                kind: SecurityKind::RateLimited,
                command: None,
                detail: "flood".into(),
            })
        };

        assert!(recorder.emit(mk()), "first record fits");
        assert!(!recorder.emit(mk()), "second record must be dropped");
        assert!(!recorder.emit(mk()), "third record must be dropped");
        assert_eq!(recorder.dropped(), 2);
        assert!(rx.recv().await.is_some());
    }

    #[test]
    fn risk_levels_roundtrip_and_order() {
        for lvl in [
            RiskLevel::None,
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            assert_eq!(RiskLevel::from_i64(lvl.as_i64()), lvl);
            assert!(!lvl.as_str().is_empty());
        }
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert_eq!(RiskLevel::from_i64(-5), RiskLevel::None);
        assert_eq!(RiskLevel::from_i64(99), RiskLevel::Critical);
    }

    #[test]
    fn close_reasons_are_unique_labels() {
        let all = [
            CloseReason::ClientClosed,
            CloseReason::IdleTimeout,
            CloseReason::StuckClient,
            CloseReason::CommandLimit,
            CloseReason::AuthLimit,
            CloseReason::ProtocolError,
            CloseReason::IoError,
            CloseReason::ServerShutdown,
            CloseReason::WriteFailed,
        ];
        let mut labels: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        labels.sort_unstable();
        let len_before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), len_before);
    }
}
