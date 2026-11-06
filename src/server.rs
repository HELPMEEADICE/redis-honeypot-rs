//! TCP listener, admission control and shutdown coordination.
//!
//! One task per accepted connection. Global and per-IP concurrency are capped
//! before a task is spawned, so a flood costs a rejected `accept`, not a task.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::task::{JoinError, JoinSet};

use crate::commands::{StoreCaps, VirtualStore};
use crate::config::Config;
use crate::connection::handle_connection;
use crate::logging;
use crate::record::{ConnectionOpened, Record, Recorder, SecurityEvent, SecurityKind};
use crate::timeutil;

/// How long a shutdown waits for live connection tasks before aborting them.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the abort pass may take once the drain timeout expired.
const ABORT_TIMEOUT: Duration = Duration::from_secs(2);

/// Pause after a transient `accept` error (e.g. `EMFILE`) instead of spinning.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Broadcast flag used to stop every connection task at once.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    /// Signal every subscriber. Idempotent.
    ///
    /// `send_replace` (not `send`) on purpose: `send` fails — and stores
    /// nothing — when the channel currently has no receivers, which would make a
    /// shutdown issued between `ShutdownHandle::new()` and the listener's
    /// `subscribe()` silently disappear while [`Self::is_triggered`] kept
    /// reporting `false`. The flag only ever moves `false -> true`, so replacing
    /// it is exactly the "sticky" semantics callers rely on.
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }

    /// Subscribe to the shutdown flag. Receivers see the current value at once.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }
}

impl Default for ShutdownHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve as soon as the shutdown flag is — or already was — set.
///
/// `watch::Receiver::changed` only reports *new* changes and a fresh
/// [`ShutdownHandle::subscribe`] marks the current value as seen, so a receiver
/// created after the trigger would otherwise wait forever. Checking the current
/// value first makes this total, which is what every cancellation point needs.
pub(crate) async fn shutdown_signal(rx: &mut watch::Receiver<bool>) {
    loop {
        let triggered = *rx.borrow_and_update();
        if triggered {
            return;
        }
        if rx.changed().await.is_err() {
            // The sender is gone: treat that as "stop", never as "keep waiting".
            return;
        }
    }
}

/// State shared by every connection task.
#[derive(Debug)]
pub struct SharedState {
    pub config: Arc<Config>,
    pub recorder: Recorder,
    /// The virtual keyspace, shared so attackers observe each other's writes.
    pub store: Arc<Mutex<VirtualStore>>,
}

impl SharedState {
    pub fn new(config: Arc<Config>, recorder: Recorder) -> Self {
        let store = Arc::new(Mutex::new(VirtualStore::new(StoreCaps::from_limits(
            &config.limits,
        ))));
        Self {
            config,
            recorder,
            store,
        }
    }
}

/// Counters reported at shutdown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerSummary {
    pub accepted: u64,
    pub rejected_global: u64,
    pub rejected_per_ip: u64,
    pub peak_concurrent: usize,
}

/// Listener failure.
#[derive(Debug)]
pub enum ServerError {
    Io(std::io::Error),
    /// No address could be bound at all.
    NoListener,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "listener io error: {e}"),
            Self::NoListener => write!(f, "no listener could be bound"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Tracked per-IP connection counts, decremented when a connection task ends.
pub(crate) type IpCounters = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Lock the per-IP table, recovering from a poisoned mutex.
///
/// A poison flag only means some other admission step observed an inconsistent
/// count; the map is still perfectly usable, and losing the whole listener over
/// it would be the worse outcome. No lock is ever held across an `await`.
fn lock_counts(counters: &IpCounters) -> MutexGuard<'_, HashMap<IpAddr, usize>> {
    match counters.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Admission ticket for one live connection from `ip`.
///
/// Dropping it (normal end, early return, task abort) decrements the count
/// exactly once. The key is removed at zero, so the table is bounded by the
/// number of *currently admitted* addresses — never by the number of addresses
/// that were ever seen.
#[derive(Debug)]
struct IpGuard {
    counters: IpCounters,
    ip: IpAddr,
}

impl IpGuard {
    /// `None` means this address already holds `limit` connections.
    fn admit(counters: &IpCounters, ip: IpAddr, limit: usize) -> Option<Self> {
        let mut table = lock_counts(counters);
        match table.get_mut(&ip) {
            Some(live) if *live >= limit => None,
            Some(live) => {
                *live += 1;
                Some(Self {
                    counters: counters.clone(),
                    ip,
                })
            }
            None => {
                table.insert(ip, 1);
                Some(Self {
                    counters: counters.clone(),
                    ip,
                })
            }
        }
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut table = lock_counts(&self.counters);
        if let Some(live) = table.get_mut(&self.ip) {
            *live = live.saturating_sub(1);
            if *live == 0 {
                table.remove(&self.ip);
            }
        }
    }
}

/// Report a connection task that did not end cleanly.
fn note_task_end(joined: Result<(), JoinError>) {
    if let Err(err) = joined {
        logging::warn(&format!("connection task ended abnormally: {err}"));
    }
}

/// Reject one connection: leave a record and a throttled console line.
///
/// The caller counts the rejection and drops the socket; nothing here can block
/// or await, so a flood costs one `try_send` per rejected `accept`.
fn reject(recorder: &Recorder, peer: SocketAddr, detail: &str) {
    recorder.emit(Record::Security(SecurityEvent {
        // No connection id exists: the socket is closed before a task exists.
        conn_id: 0,
        ip: Some(peer.ip()),
        at: timeutil::now(),
        kind: SecurityKind::RateLimited,
        command: None,
        detail: detail.to_string(),
    }));
    // `logging::notice` applies the console rate gate, so a scan flood cannot
    // turn into a console write flood.
    logging::notice(peer, SecurityKind::RateLimited.as_str(), detail);
}

/// Run the honeypot until `shutdown` is triggered.
///
/// `ready` receives the list of bound addresses (useful with `--bind …:0` and in
/// tests) as soon as every listener is up.
pub async fn serve(
    config: Config,
    recorder: Recorder,
    shutdown: ShutdownHandle,
    ready: Option<oneshot::Sender<Vec<SocketAddr>>>,
) -> Result<ServerSummary, ServerError> {
    let limits = config.limits.clone();
    let config = Arc::new(config);

    // ---------------------------------------------------------------- bind
    let primary = TcpListener::bind(config.bind)
        .await
        .map_err(ServerError::Io)?;
    let primary_addr = primary.local_addr().map_err(ServerError::Io)?;
    let mut bound = vec![primary_addr];

    let mut secondary: Option<TcpListener> = None;
    if config.enable_ipv6 {
        // `bind` may have been `…:0`; mirror the port the kernel actually chose.
        let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), primary_addr.port());
        match TcpListener::bind(v6_addr).await {
            Ok(listener) => {
                match listener.local_addr() {
                    Ok(addr) => bound.push(addr),
                    Err(err) => logging::warn(&format!("ipv6 listener has no address: {err}")),
                }
                secondary = Some(listener);
            }
            // Dual stack is a bonus, not a requirement: keep the v4 listener.
            Err(err) => logging::warn(&format!("ipv6 listen on {v6_addr} unavailable: {err}")),
        }
    }

    if let Some(ready) = ready {
        let _ = ready.send(bound);
    }

    // --------------------------------------------------------- shared state
    let shared = Arc::new(SharedState::new(config.clone(), recorder.clone()));
    let permits = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let ip_counters: IpCounters = Arc::new(Mutex::new(HashMap::new()));
    let next_conn_id = AtomicU64::new(1);
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut summary = ServerSummary::default();
    let mut shutdown_rx = shutdown.subscribe();

    // ----------------------------------------------------------- accept loop
    loop {
        if *shutdown_rx.borrow_and_update() {
            break;
        }

        // Reaping finished tasks keeps the JoinSet (and its bookkeeping) bounded
        // by the live connection count instead of the total ever accepted.
        let accepted: std::io::Result<(TcpStream, SocketAddr)> = match secondary.as_ref() {
            Some(v6) => tokio::select! {
                biased;
                () = shutdown_signal(&mut shutdown_rx) => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(outcome) = joined {
                        note_task_end(outcome);
                    }
                    continue;
                }
                res = primary.accept() => res,
                res = v6.accept() => res,
            },
            None => tokio::select! {
                biased;
                () = shutdown_signal(&mut shutdown_rx) => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(outcome) = joined {
                        note_task_end(outcome);
                    }
                    continue;
                }
                res = primary.accept() => res,
            },
        };

        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                // Transient: out of file descriptors, or a peer that vanished
                // between SYN and accept. Never count it as a connection.
                logging::warn(&format!("accept failed: {err}"));
                tokio::select! {
                    biased;
                    () = shutdown_signal(&mut shutdown_rx) => break,
                    () = tokio::time::sleep(ACCEPT_BACKOFF) => {}
                }
                continue;
            }
        };

        // ------------------------------------------------------- admission
        // Global cap first: a flood must cost one rejected accept, not a task.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            summary.rejected_global += 1;
            reject(&recorder, peer, "global connection limit reached");
            drop(stream);
            continue;
        };
        let in_flight = limits
            .max_connections
            .saturating_sub(permits.available_permits());
        summary.peak_concurrent = summary.peak_concurrent.max(in_flight);

        let Some(ip_guard) = IpGuard::admit(&ip_counters, peer.ip(), limits.max_connections_per_ip)
        else {
            summary.rejected_per_ip += 1;
            reject(&recorder, peer, "per-ip connection limit reached");
            drop(permit);
            drop(stream);
            continue;
        };

        // ------------------------------------------------------------ spawn
        summary.accepted += 1;
        let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = stream.set_nodelay(true) {
            // Not fatal: only latency simulation quality suffers.
            logging::warn(&format!("cannot set TCP_NODELAY for {peer}: {err}"));
        }
        logging::connect(peer);
        recorder.emit(Record::Opened(ConnectionOpened {
            conn_id,
            ip: peer.ip(),
            port: peer.port(),
            at: timeutil::now(),
        }));

        let task_shared = shared.clone();
        let task_shutdown = shutdown.clone();
        tasks.spawn(async move {
            // The permit and the per-IP ticket live exactly as long as this
            // task, so each is released exactly once — on normal completion,
            // on early return and on abort alike.
            let _permit = permit;
            let _ip = ip_guard;
            let _ = handle_connection(stream, peer, conn_id, task_shared, task_shutdown).await;
        });
    }

    // --------------------------------------------------------- graceful stop
    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while let Some(joined) = tasks.join_next().await {
            note_task_end(joined);
        }
    })
    .await;

    if drained.is_err() {
        logging::warn(&format!(
            "{} connection task(s) still running after {}s; aborting",
            tasks.len(),
            DRAIN_TIMEOUT.as_secs()
        ));
        tasks.abort_all();
        // Aborted tasks stop at their next yield point; the bound keeps a
        // wedged task from holding the process open.
        let _ = tokio::time::timeout(ABORT_TIMEOUT, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    use crate::config::Timing;
    use crate::record::CloseReason;

    /// Upper bound for any single client-side wait in these tests.
    const CLIENT_WAIT: Duration = Duration::from_secs(5);

    // ------------------------------------------------------------- fixtures

    fn base_config() -> Config {
        Config {
            bind: "127.0.0.1:0".parse().expect("loopback bind address"),
            // Tiny AUTH delays keep the suite fast; production uses 2–6 s.
            timing: Timing {
                auth_min_delay_ms: 10,
                auth_max_delay_ms: 20,
                command_jitter_max_ms: 0,
            },
            ..Config::default()
        }
    }

    fn config_with(mutate: impl FnOnce(&mut Config)) -> Config {
        let mut config = base_config();
        mutate(&mut config);
        config
    }

    struct Server {
        addr: SocketAddr,
        shutdown: ShutdownHandle,
        task: tokio::task::JoinHandle<Result<ServerSummary, ServerError>>,
    }

    async fn start(config: Config, recorder: Recorder) -> Server {
        let shutdown = ShutdownHandle::new();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(serve(config, recorder, shutdown.clone(), Some(tx)));
        let bound = tokio::time::timeout(CLIENT_WAIT, rx)
            .await
            .expect("the listener reports its addresses")
            .expect("the ready channel stays open");
        let addr = *bound.first().expect("at least one bound address");
        Server {
            addr,
            shutdown,
            task,
        }
    }

    impl Server {
        async fn connect(&self) -> TcpStream {
            tokio::time::timeout(CLIENT_WAIT, TcpStream::connect(self.addr))
                .await
                .expect("connect does not hang")
                .expect("connect succeeds")
        }

        /// Trigger the shutdown and wait for `serve` to return.
        async fn stop(self) -> ServerSummary {
            self.shutdown.trigger();
            match tokio::time::timeout(CLIENT_WAIT, self.task).await {
                Ok(Ok(Ok(summary))) => summary,
                Ok(Ok(Err(err))) => panic!("serve returned an error: {err}"),
                Ok(Err(err)) => panic!("serve task failed: {err}"),
                Err(_) => panic!("serve did not stop within {CLIENT_WAIT:?}"),
            }
        }
    }

    async fn send(stream: &mut TcpStream, payload: &[u8]) {
        tokio::time::timeout(CLIENT_WAIT, stream.write_all(payload))
            .await
            .expect("write does not hang")
            .expect("write succeeds");
    }

    /// Read one CRLF terminated line, byte by byte so a pipelined second reply
    /// stays in the socket.
    async fn read_one_line(stream: &mut TcpStream) -> Vec<u8> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        let deadline = Instant::now() + CLIENT_WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return line;
            }
            match tokio::time::timeout(left, stream.read_exact(&mut byte)).await {
                Ok(Ok(_)) => {
                    line.push(byte[0]);
                    if line.ends_with(b"\r\n") {
                        return line;
                    }
                }
                Ok(Err(_)) | Err(_) => return line,
            }
        }
    }

    /// Read until the peer closes (EOF, reset or timeout) and return the bytes.
    async fn read_until_eof(stream: &mut TcpStream) -> Vec<u8> {
        let mut collected = Vec::new();
        let mut chunk = [0u8; 256];
        let deadline = Instant::now() + CLIENT_WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return collected;
            }
            match tokio::time::timeout(left, stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return collected,
                Ok(Ok(n)) => collected.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Drain every record the server queued, giving up after `window`.
    async fn drain_records(rx: &mut mpsc::Receiver<Record>, window: Duration) -> Vec<Record> {
        let mut records = Vec::new();
        while let Ok(Some(record)) = tokio::time::timeout(window, rx.recv()).await {
            records.push(record);
        }
        records
    }

    fn ping() -> &'static [u8] {
        b"*1\r\n$4\r\nPING\r\n"
    }

    // ---------------------------------------------------------------- tests

    /// Scenario 1 — `PING` answers `+PONG`; `QUIT` answers `+OK` then EOF.
    #[tokio::test]
    async fn ping_replies_and_quit_closes() {
        let server = start(base_config(), Recorder::disabled()).await;
        let mut client = server.connect().await;

        send(&mut client, ping()).await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+PONG\r\n");

        send(&mut client, b"*1\r\n$4\r\nQUIT\r\n").await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+OK\r\n");
        assert!(
            read_until_eof(&mut client).await.is_empty(),
            "QUIT must close the connection after the reply"
        );

        let summary = server.stop().await;
        assert_eq!(summary.accepted, 1);
    }

    /// Scenario 2 — two commands in one write produce two replies, one socket.
    #[tokio::test]
    async fn pipelined_commands_share_one_connection() {
        let server = start(base_config(), Recorder::disabled()).await;
        let mut client = server.connect().await;

        send(&mut client, b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n").await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+PONG\r\n");
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+PONG\r\n");

        let summary = server.stop().await;
        assert_eq!(summary.accepted, 1, "both replies came from one connection");
    }

    /// Scenario 3 — a command split across four writes is reassembled.
    #[tokio::test]
    async fn split_delivery_reassembles_one_command() {
        let server = start(base_config(), Recorder::disabled()).await;
        let mut client = server.connect().await;

        // Four separate segments, each too short to decode on its own.
        for part in [
            b"*1\r\n".as_slice(),
            b"$4\r\n".as_slice(),
            b"PI".as_slice(),
            b"NG\r\n".as_slice(),
        ] {
            send(&mut client, part).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+PONG\r\n");
        server.stop().await;
    }

    /// Scenario 4 — `AUTH` is answered `+OK` after the configured delay, and the
    /// recorded `delay_ms` stays inside that window.
    #[tokio::test]
    async fn auth_is_answered_after_the_configured_delay() {
        let (tx, mut rx) = mpsc::channel(64);
        let recorder = Recorder::new(tx, Arc::new(AtomicU64::new(0)));
        // base_config: auth window 10..=20 ms.
        let server = start(base_config(), recorder).await;
        let mut client = server.connect().await;

        let started = Instant::now();
        send(&mut client, b"*2\r\n$4\r\nAUTH\r\n$1\r\nx\r\n").await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+OK\r\n");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(10),
            "AUTH answered before the minimum delay: {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(500),
            "AUTH answered far too late: {elapsed:?}"
        );

        let records = drain_records(&mut rx, Duration::from_millis(200)).await;
        let delay = records
            .iter()
            .find_map(|record| match record {
                Record::Auth(auth) => Some(auth.delay_ms),
                _ => None,
            })
            .expect("an Auth record is emitted");
        assert!(
            (10..=20).contains(&delay),
            "delay_ms left the configured window: {delay}"
        );
        server.stop().await;
    }

    /// Scenario 5 — with the production 2 s AUTH window, `PING` is immediate.
    #[tokio::test]
    async fn ping_is_not_delayed_by_the_auth_window() {
        let config = Config {
            bind: "127.0.0.1:0".parse().expect("loopback bind address"),
            ..Config::default()
        };
        assert_eq!(config.timing.auth_bounds(), (2_000, 6_000));
        let server = start(config, Recorder::disabled()).await;
        let mut client = server.connect().await;

        let started = Instant::now();
        send(&mut client, ping()).await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+PONG\r\n");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "PING waited on the AUTH delay"
        );
        server.stop().await;
    }

    /// Scenario 6 — no `AUTH` at all: the "misconfigured Redis" simulation.
    #[tokio::test]
    async fn commands_work_without_authentication() {
        let server = start(base_config(), Recorder::disabled()).await;
        let mut client = server.connect().await;

        send(&mut client, b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n").await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+OK\r\n");

        send(&mut client, b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n").await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"$1\r\n");
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"v\r\n");

        server.stop().await;
    }

    /// Scenario 7 — malformed input is answered and only closes that socket.
    #[tokio::test]
    async fn malformed_input_does_not_poison_the_listener() {
        let server = start(base_config(), Recorder::disabled()).await;

        // Raw binary junk still produces a coherent error line.
        let mut junk = server.connect().await;
        send(&mut junk, b"\xff\xff\xff\r\n").await;
        let reply = read_one_line(&mut junk).await;
        assert!(
            reply.starts_with(b"-"),
            "expected an error reply, got {reply:?}"
        );
        drop(junk);

        // A malformed bulk length is fatal for that connection only.
        let mut broken = server.connect().await;
        send(&mut broken, b"*1\r\n$abc\r\n").await;
        let reply = read_one_line(&mut broken).await;
        assert!(
            reply.starts_with(b"-ERR"),
            "expected an -ERR line, got {reply:?}"
        );
        assert!(
            read_until_eof(&mut broken).await.is_empty(),
            "a protocol error closes the connection"
        );

        // The listener is still healthy.
        let mut good = server.connect().await;
        send(&mut good, ping()).await;
        assert_eq!(read_one_line(&mut good).await.as_slice(), b"+PONG\r\n");

        server.stop().await;
    }

    /// Scenario 8 — a bulk header declaring 100 MiB is refused, not allocated.
    #[tokio::test]
    async fn oversized_bulk_header_is_refused() {
        let server = start(base_config(), Recorder::disabled()).await;

        let started = Instant::now();
        let mut client = server.connect().await;
        send(&mut client, b"*1\r\n$104857600\r\n").await;
        let reply = read_one_line(&mut client).await;
        assert!(
            reply.starts_with(b"-ERR"),
            "expected an -ERR line, got {reply:?}"
        );
        assert!(
            read_until_eof(&mut client).await.is_empty(),
            "an oversized request closes the connection"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "rejecting 100 MiB must not take seconds (nothing was allocated)"
        );

        let mut next = server.connect().await;
        send(&mut next, ping()).await;
        assert_eq!(read_one_line(&mut next).await.as_slice(), b"+PONG\r\n");

        server.stop().await;
    }

    /// Scenario 9 — a half sent frame is reaped by the partial-frame deadline.
    #[tokio::test]
    async fn partial_frame_is_reaped_as_stuck_client() {
        let (tx, mut rx) = mpsc::channel(64);
        let recorder = Recorder::new(tx, Arc::new(AtomicU64::new(0)));
        let config = config_with(|cfg| cfg.limits.partial_frame_timeout_secs = 1);
        let server = start(config, recorder).await;
        let mut client = server.connect().await;

        send(&mut client, b"*1\r\n").await;
        let started = Instant::now();
        assert!(
            read_until_eof(&mut client).await.is_empty(),
            "a stuck client gets no reply, only a close"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the partial-frame deadline did not fire: {:?}",
            started.elapsed()
        );

        let records = drain_records(&mut rx, Duration::from_millis(300)).await;
        let reason = records.iter().find_map(|record| match record {
            Record::Closed(closed) => Some(closed.reason),
            _ => None,
        });
        assert_eq!(reason, Some(CloseReason::StuckClient));

        server.stop().await;
    }

    /// Scenario 10 — the global cap rejects a second client, the first survives.
    #[tokio::test]
    async fn global_connection_cap_rejects_the_second_client() {
        let config = config_with(|cfg| {
            cfg.limits.max_connections = 1;
            cfg.limits.max_connections_per_ip = 1;
        });
        let server = start(config, Recorder::disabled()).await;

        let mut first = server.connect().await;
        send(&mut first, ping()).await;
        assert_eq!(read_one_line(&mut first).await.as_slice(), b"+PONG\r\n");

        let mut second = server.connect().await;
        assert!(
            read_until_eof(&mut second).await.is_empty(),
            "the rejected connection carries no reply"
        );

        send(&mut first, ping()).await;
        assert_eq!(
            read_one_line(&mut first).await.as_slice(),
            b"+PONG\r\n",
            "the admitted connection is untouched by the rejection"
        );

        let summary = server.stop().await;
        assert_eq!(summary.accepted, 1);
        assert!(summary.rejected_global >= 1, "the rejection is counted");
        assert_eq!(summary.peak_concurrent, 1);
    }

    /// Scenario 11 — the per-IP cap rejects a second socket from one address.
    #[tokio::test]
    async fn per_ip_connection_cap_rejects_the_second_client() {
        let config = config_with(|cfg| {
            cfg.limits.max_connections = 8;
            cfg.limits.max_connections_per_ip = 1;
        });
        let server = start(config, Recorder::disabled()).await;

        let mut first = server.connect().await;
        send(&mut first, ping()).await;
        assert_eq!(read_one_line(&mut first).await.as_slice(), b"+PONG\r\n");

        let mut second = server.connect().await;
        assert!(
            read_until_eof(&mut second).await.is_empty(),
            "the rejected connection carries no reply"
        );

        send(&mut first, ping()).await;
        assert_eq!(read_one_line(&mut first).await.as_slice(), b"+PONG\r\n");

        let summary = server.stop().await;
        assert_eq!(summary.accepted, 1);
        assert!(summary.rejected_per_ip >= 1, "the rejection is counted");
        assert_eq!(summary.rejected_global, 0, "the global cap was not hit");
    }

    /// Scenario 12 — shutdown returns promptly and closes live sockets.
    #[tokio::test]
    async fn shutdown_stops_serving_and_closes_live_connections() {
        let server = start(base_config(), Recorder::disabled()).await;
        let mut client = server.connect().await;
        send(&mut client, ping()).await;
        assert_eq!(read_one_line(&mut client).await.as_slice(), b"+PONG\r\n");

        let stopped = Instant::now();
        let summary = server.stop().await;
        assert!(
            stopped.elapsed() < Duration::from_secs(3),
            "shutdown took {:?}",
            stopped.elapsed()
        );
        assert_eq!(summary.accepted, 1);
        assert!(
            read_until_eof(&mut client).await.is_empty(),
            "the live socket reaches EOF"
        );
    }

    /// Extra — the simulated AUTH delay is an `await`, never a blocked thread,
    /// so another connection is served while it is running.
    #[tokio::test]
    async fn auth_delay_does_not_block_other_connections() {
        let config = config_with(|cfg| {
            cfg.timing.auth_min_delay_ms = 300;
            cfg.timing.auth_max_delay_ms = 400;
        });
        let server = start(config, Recorder::disabled()).await;

        let mut slow = server.connect().await;
        send(&mut slow, b"*2\r\n$4\r\nAUTH\r\n$1\r\nx\r\n").await;
        // Let the AUTH reach the delay before the second client shows up.
        tokio::time::sleep(Duration::from_millis(120)).await;

        let mut fast = server.connect().await;
        let started = Instant::now();
        send(&mut fast, ping()).await;
        assert_eq!(read_one_line(&mut fast).await.as_slice(), b"+PONG\r\n");
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "a PING waited behind another connection's AUTH delay: {:?}",
            started.elapsed()
        );

        // The delayed connection still gets its reply, inside its own window.
        assert_eq!(read_one_line(&mut slow).await.as_slice(), b"+OK\r\n");
        server.stop().await;
    }

    /// Extra — a client `SHUTDOWN` ends at most its own connection.
    #[tokio::test]
    async fn client_shutdown_does_not_stop_the_process() {
        let server = start(base_config(), Recorder::disabled()).await;
        let mut client = server.connect().await;
        send(&mut client, b"*1\r\n$8\r\nSHUTDOWN\r\n").await;
        // Whatever is simulated back, the listener must survive it.
        let _ = read_one_line(&mut client).await;

        let mut next = server.connect().await;
        send(&mut next, ping()).await;
        assert_eq!(read_one_line(&mut next).await.as_slice(), b"+PONG\r\n");

        let summary = server.stop().await;
        assert_eq!(summary.accepted, 2, "the listener kept accepting");
    }

    #[test]
    fn shutdown_handle_is_sticky_and_cloneable() {
        let h = ShutdownHandle::new();
        assert!(!h.is_triggered());
        let mut rx = h.subscribe();
        assert!(!*rx.borrow());
        let clone = h.clone();
        clone.trigger();
        assert!(h.is_triggered());
        assert!(clone.is_triggered());
        assert!(*rx.borrow_and_update());
        // idempotent
        h.trigger();
        assert!(h.is_triggered());
    }

    #[test]
    fn shared_state_derives_store_caps_from_limits() {
        let cfg = Config::default();
        let state = SharedState::new(Arc::new(cfg.clone()), Recorder::disabled());
        let caps = state.store.lock().expect("lock").caps();
        assert_eq!(caps, StoreCaps::from_limits(&cfg.limits));
    }

    #[tokio::test]
    async fn shutdown_signal_fires_for_a_receiver_created_after_the_trigger() {
        let handle = ShutdownHandle::new();
        handle.trigger();
        let mut rx = handle.subscribe();
        tokio::time::timeout(Duration::from_millis(50), shutdown_signal(&mut rx))
            .await
            .expect("an already triggered flag resolves immediately");
    }
}
