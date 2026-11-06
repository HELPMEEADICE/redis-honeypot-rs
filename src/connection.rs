//! Per-connection protocol state machine.
//!
//! Responsibilities, in order:
//!
//! 1. read bytes under an idle and a partial-frame deadline;
//! 2. decode RESP frames with the configured caps;
//! 3. record the raw intent (`commands` / `auth_attempts` / `security_events`);
//! 4. apply the simulated delay (AUTH only, cancellable);
//! 5. write the simulated reply.
//!
//! It owns no policy about *what* a command means — that is
//! [`crate::commands::dispatch`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::commands::{self, SessionState};
use crate::config::Config;
use crate::logging;
use crate::record::{
    AuthRecord, CloseReason, CommandRecord, ConnectionClosed, Record, Recorder, RiskLevel,
    SecurityEvent, SecurityKind,
};
use crate::resp::{ProtocolError, RespDecoder, RespFrame, encode_frame};
use crate::server::{self, SharedState, ShutdownHandle};
use crate::timeutil;

/// Bytes pulled from the socket per wakeup.
///
/// Bounded on purpose: reassembly is the decoder's job and it enforces
/// `max_message_bytes` itself, so this buffer never needs to grow.
const READ_BUF_SIZE: usize = 8 * 1024;

/// Replies larger than this are released instead of being retained, so one huge
/// command cannot pin a big buffer on a mostly idle connection.
const REPLY_BUF_RETAIN: usize = 64 * 1024;

/// How a connection finished, for `connections` and the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleOutcome {
    pub command_count: u64,
    pub reason: CloseReason,
}

/// Inclusive AUTH delay for this connection, drawn from the configured window.
///
/// `Config::validate` guarantees `min <= max`, but the connection path must not
/// trust that: an inverted window is clamped instead of panicking in the RNG.
fn auth_delay_ms(min: u64, max: u64) -> u64 {
    let lo = min.min(max);
    let hi = max.max(min);
    if hi == 0 || lo == hi {
        return lo;
    }
    rand::random_range(lo..=hi)
}

/// Random non-AUTH jitter in `0..=max`.
fn jitter_ms(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    rand::random_range(0..=max)
}

/// Everything one in-flight command needs, bundled so the per-frame helpers do
/// not grow a nine argument signature.
struct ConnCtx<'a> {
    stream: &'a mut TcpStream,
    peer: SocketAddr,
    conn_id: u64,
    session: &'a mut SessionState,
    config: &'a Config,
    recorder: &'a Recorder,
    shutdown: &'a mut watch::Receiver<bool>,
    out: &'a mut Vec<u8>,
}

impl ConnCtx<'_> {
    fn resp3(&self) -> bool {
        self.session.resp_version >= 3
    }

    /// Encode, write and flush one reply.
    ///
    /// The protocol version is read here, after the command ran: `HELLO 3` can
    /// flip it inside `dispatch`, and the reply must use the version that is in
    /// force at the moment it is encoded.
    async fn reply(&mut self, frame: &RespFrame) -> Result<(), CloseReason> {
        let resp3 = self.resp3();
        let buf = &mut *self.out;
        buf.clear();
        encode_frame(frame, resp3, buf);
        let stream = &mut *self.stream;
        stream
            .write_all(buf)
            .await
            .map_err(|_| CloseReason::WriteFailed)?;
        stream.flush().await.map_err(|_| CloseReason::WriteFailed)?;
        if self.out.capacity() > REPLY_BUF_RETAIN {
            *self.out = Vec::new();
        }
        Ok(())
    }

    fn record_security(&self, kind: SecurityKind, command: Option<String>, detail: String) {
        self.recorder.emit(Record::Security(SecurityEvent {
            conn_id: self.conn_id,
            ip: Some(self.peer.ip()),
            at: timeutil::now(),
            kind,
            command,
            detail,
        }));
    }

    /// Sleep, but wake up immediately when shutdown is triggered.
    ///
    /// Returns `true` when the wait was cut short, in which case the caller must
    /// stop without writing a reply: the peer is gone anyway.
    async fn wait_or_shutdown(&mut self, wait: Duration) -> bool {
        tokio::select! {
            biased;
            () = server::shutdown_signal(self.shutdown) => true,
            () = tokio::time::sleep(wait) => false,
        }
    }

    /// Turn a decoder/argument failure into a reply, a record and a close reason.
    async fn protocol_error(&mut self, err: ProtocolError) -> CloseReason {
        let kind = if err.is_oversized() {
            SecurityKind::OversizedRequest
        } else {
            SecurityKind::ProtocolAnomaly
        };
        self.record_security(
            kind,
            None,
            format!("{} ({})", err.as_str(), err.client_message()),
        );
        logging::notice(self.peer, kind.as_str(), err.as_str());
        let _ = self.reply(&RespFrame::error(err.client_message())).await;
        CloseReason::ProtocolError
    }

    /// Decode and handle every complete frame the decoder already holds.
    ///
    /// A single read can carry many pipelined commands, so this loop is what
    /// makes `SET a 1\r\nGET a\r\n…` behave like a real server.
    async fn drain_frames(&mut self, decoder: &mut RespDecoder) -> Option<CloseReason> {
        loop {
            let frame = match decoder.try_decode() {
                Ok(Some(frame)) => frame,
                Ok(None) => return None,
                Err(err) => return Some(self.protocol_error(err).await),
            };
            if let Some(reason) = self.handle_frame(&frame).await {
                return Some(reason);
            }
        }
    }

    /// Record, delay, reply and re-check the limits for one decoded frame.
    ///
    /// `Some(reason)` means the connection has to end now.
    async fn handle_frame(&mut self, frame: &RespFrame) -> Option<CloseReason> {
        // `self.config` is a shared reference, so copying it out keeps `limits`
        // alive independently of the mutable borrows below.
        let config = self.config;
        let limits = &config.limits;

        let args = match commands::frame_to_args(frame, limits) {
            Ok(args) => args,
            Err(err) => {
                self.record_security(
                    SecurityKind::ProtocolAnomaly,
                    None,
                    format!("args: {}", err.as_str()),
                );
                logging::notice(self.peer, "args_error", err.as_str());
                let _ = self.reply(&RespFrame::error(err.client_message())).await;
                return Some(CloseReason::ProtocolError);
            }
        };

        let result = commands::dispatch(&args, self.session, limits, config.record_passwords);

        // ------------------------------------------------- log, then act
        if result.auth.is_none() {
            self.recorder.emit(Record::Command(CommandRecord {
                conn_id: self.conn_id,
                ip: self.peer.ip(),
                at: timeutil::now(),
                name: result.name.clone(),
                args: result.args_preview.clone(),
                arg_count: args.len(),
                resp_type: result.reply.type_name().to_string(),
                simulated: result.simulated.clone(),
                risk: result.risk,
            }));
        }

        if result.security.is_some() || result.risk >= RiskLevel::High {
            let detail = match result.security.as_deref() {
                Some(security) => security.to_string(),
                None => format!("risk {}", result.risk.as_str()),
            };
            self.record_security(
                SecurityKind::DangerousCommand,
                Some(result.name.clone()),
                detail.clone(),
            );
            logging::alert(self.peer, &result.name, &detail);
        }

        // Already bounded, escaped and quoted by the command layer.
        logging::command(self.peer, result.args_preview.as_str());

        // ------------------------------------------- simulated delay
        if let Some(attempt) = result.auth.as_ref() {
            let (min, max) = config.timing.auth_bounds();
            let delay_ms = auth_delay_ms(min, max);
            if delay_ms > 0 && self.wait_or_shutdown(Duration::from_millis(delay_ms)).await {
                return Some(CloseReason::ServerShutdown);
            }
            self.recorder.emit(Record::Auth(AuthRecord {
                conn_id: self.conn_id,
                ip: self.peer.ip(),
                at: timeutil::now(),
                username: attempt.username.clone(),
                arg_count: attempt.arg_count,
                password_len: attempt.password_len,
                // Recorded only with the explicit opt-in, checked twice: the
                // command layer already masks it, and this is the seam that
                // could leak it.
                password: if config.record_passwords {
                    attempt.password.clone()
                } else {
                    None
                },
                simulated_ok: true,
                delay_ms,
                meta: None,
            }));
            logging::auth(
                self.peer,
                attempt.username.as_deref().unwrap_or(""),
                delay_ms,
                true,
            );
        } else if config.timing.command_jitter_max_ms > 0 {
            let jitter = jitter_ms(config.timing.command_jitter_max_ms);
            if jitter > 0 && self.wait_or_shutdown(Duration::from_millis(jitter)).await {
                return Some(CloseReason::ServerShutdown);
            }
        }

        // ------------------------------------------------------ reply
        if let Err(reason) = self.reply(&result.reply).await {
            return Some(reason);
        }

        // -------------------------------------------- hard per-conn limits
        if self.session.command_count > limits.max_commands_per_conn {
            let _ = self.reply(&RespFrame::error("ERR too many commands")).await;
            logging::notice(self.peer, "limit", "command limit reached");
            return Some(CloseReason::CommandLimit);
        }
        if self.session.auth_attempts >= limits.max_auth_attempts {
            logging::notice(self.peer, "limit", "auth attempt limit reached");
            return Some(CloseReason::AuthLimit);
        }
        if result.close_after {
            // `QUIT` and `SHUTDOWN` end *this* connection and nothing else: a
            // honeypot that honoured a client `SHUTDOWN` would be trivially
            // taken offline.
            return Some(CloseReason::ClientClosed);
        }
        None
    }
}

/// Drive one accepted connection to completion.
///
/// Never fails: every error path maps to a [`CloseReason`] so the caller can
/// persist the close and keep serving.
pub async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    conn_id: u64,
    shared: Arc<SharedState>,
    shutdown: ShutdownHandle,
) -> HandleOutcome {
    let config = shared.config.clone();
    let recorder = shared.recorder.clone();

    let mut session = SessionState::new(conn_id, peer.ip(), peer.port(), shared.store.clone());
    let mut decoder = RespDecoder::from_limits(&config.limits);
    let mut out: Vec<u8> = Vec::new();
    let mut shutdown_rx = shutdown.subscribe();
    let mut read_buf = [0u8; READ_BUF_SIZE];

    let idle_timeout = Duration::from_secs(config.limits.idle_timeout_secs.max(1));
    let partial_timeout = Duration::from_secs(config.limits.partial_frame_timeout_secs.max(1));
    let mut last_activity = Instant::now();
    let mut partial_since: Option<Instant> = None;
    let started = timeutil::now();

    // One exit point: the loop only decides *why* it stopped, and every path
    // afterwards records and logs the same way.
    let reason = {
        let mut ctx = ConnCtx {
            stream: &mut stream,
            peer,
            conn_id,
            session: &mut session,
            config: config.as_ref(),
            recorder: &recorder,
            shutdown: &mut shutdown_rx,
            out: &mut out,
        };

        loop {
            // --------------------------------------------- deadlines
            let now = Instant::now();
            let idle_left = (last_activity + idle_timeout).saturating_duration_since(now);
            if idle_left.is_zero() {
                break CloseReason::IdleTimeout;
            }
            let mut wait = idle_left;
            if let Some(since) = partial_since {
                // Slow-loris guard: the deadline runs from the first byte of the
                // partial frame, so dribbling cannot extend it.
                let stuck_left = (since + partial_timeout).saturating_duration_since(now);
                if stuck_left.is_zero() {
                    break CloseReason::StuckClient;
                }
                wait = wait.min(stuck_left);
            }

            // ------------------------------- read, deadline, shutdown
            let read = tokio::select! {
                biased;
                () = server::shutdown_signal(ctx.shutdown) => break CloseReason::ServerShutdown,
                result = ctx.stream.read(&mut read_buf[..READ_BUF_SIZE]) => result,
                () = tokio::time::sleep(wait) => {
                    let stuck = partial_since
                        .is_some_and(|since| Instant::now() >= since + partial_timeout);
                    if stuck {
                        break CloseReason::StuckClient;
                    }
                    break CloseReason::IdleTimeout;
                }
            };

            let read = match read {
                Ok(0) => break CloseReason::ClientClosed,
                Ok(n) => n,
                Err(_) => break CloseReason::IoError,
            };
            last_activity = Instant::now();

            // ---------------------------------------------- decode
            if let Err(err) = decoder.extend(&read_buf[..read]) {
                break ctx.protocol_error(err).await;
            }
            if let Some(reason) = ctx.drain_frames(&mut decoder).await {
                break reason;
            }

            // Remember when the first undecoded byte of a frame arrived.
            if decoder.is_empty() {
                partial_since = None;
            } else if partial_since.is_none() {
                partial_since = Some(Instant::now());
            }
        }
    };

    let command_count = session.command_count;
    let duration_ms = timeutil::elapsed_millis(started);
    recorder.emit(Record::Closed(ConnectionClosed {
        conn_id,
        ip: peer.ip(),
        at: timeutil::now(),
        duration_ms,
        command_count,
        reason,
    }));
    logging::close(peer, reason.as_str(), duration_ms, command_count);

    HandleOutcome {
        command_count,
        reason,
    }
}
