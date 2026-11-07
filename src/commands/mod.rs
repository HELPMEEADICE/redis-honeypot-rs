//! Fully virtualised Redis command simulation.
//!
//! Nothing in this module can touch the host: no filesystem, no `exec`, no
//! outbound socket. "Dangerous" commands (`MODULE LOAD`, `EVAL`, `REPLICAOF`,
//! `CONFIG SET dir`, …) are answered with plausible protocol replies and
//! recorded as [`RiskLevel::Critical`] security events, and that is all they do.

pub mod handlers;
pub mod store;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::config::Limits;
use crate::record::RiskLevel;
use crate::resp::RespFrame;
use crate::text;

pub use store::{StoreCaps, VirtualStore};

/// Per-connection state that the command simulator is allowed to see and change.
#[derive(Debug)]
pub struct SessionState {
    pub conn_id: u64,
    pub ip: IpAddr,
    pub client_port: u16,
    /// Set after the first simulated `AUTH` success.
    pub authenticated: bool,
    /// `CLIENT SETNAME` value, echoed back by `CLIENT GETNAME`.
    pub client_name: Option<Vec<u8>>,
    /// `SELECT`ed database index (0..=15).
    pub db_index: u8,
    /// Negotiated protocol version: 2 or 3.
    pub resp_version: u8,
    /// Commands accepted on this connection so far.
    pub command_count: u64,
    /// `AUTH` attempts on this connection so far.
    pub auth_attempts: u32,
    /// Shared virtual keyspace (a real Redis instance is shared by all clients).
    pub store: Arc<Mutex<VirtualStore>>,
}

impl SessionState {
    pub fn new(
        conn_id: u64,
        ip: IpAddr,
        client_port: u16,
        store: Arc<Mutex<VirtualStore>>,
    ) -> Self {
        Self {
            conn_id,
            ip,
            client_port,
            authenticated: false,
            client_name: None,
            db_index: 0,
            resp_version: 2,
            command_count: 0,
            auth_attempts: 0,
            store,
        }
    }
}

/// Which command carried the credentials.
///
/// Both spellings must be treated identically — same unconditional success, same
/// random delay, same record — so this is carried explicitly instead of being
/// inferred from the command name at the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// `AUTH <password>` / `AUTH <username> <password>`.
    Auth,
    /// `HELLO <proto> AUTH <username> <password>`.
    Hello,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Hello => "hello",
        }
    }
}

/// Credentials captured from an `AUTH`/`HELLO … AUTH` command. The connection
/// layer applies the random delay and only then answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAttempt {
    /// Which command produced this attempt.
    pub method: AuthMethod,
    pub username: Option<String>,
    /// Length of the password as submitted (always recorded).
    pub password_len: usize,
    /// Raw password, only populated when `record_passwords` is enabled.
    pub password: Option<String>,
    /// Arguments of the carrying command (`AUTH`: 2 or 3, `HELLO`: all of them).
    pub arg_count: u16,
}

/// Everything the connection layer needs after one command.
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// RESP reply to send (after any simulated delay).
    pub reply: RespFrame,
    /// Uppercased, bounded command name for logging/persistence.
    pub name: String,
    /// Bounded, escaped argument preview for logging/persistence.
    pub args_preview: String,
    /// Short label describing what was simulated (`ok`, `simulated_save`, ...).
    pub simulated: String,
    /// Risk classification for `commands.risk`.
    pub risk: RiskLevel,
    /// `QUIT`/`SHUTDOWN`-style: reply, then close this connection only.
    pub close_after: bool,
    /// Present for `AUTH`: the connection layer delays, then replies `+OK`.
    pub auth: Option<AuthAttempt>,
    /// Present for risky commands: detail text for `security_events`.
    pub security: Option<String>,
}

impl DispatchResult {
    pub fn new(
        name: impl Into<String>,
        args_preview: impl Into<String>,
        reply: RespFrame,
        simulated: impl Into<String>,
    ) -> Self {
        Self {
            reply,
            name: name.into(),
            args_preview: args_preview.into(),
            simulated: simulated.into(),
            risk: RiskLevel::None,
            close_after: false,
            auth: None,
            security: None,
        }
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk = risk;
        self
    }
}

/// A decoded frame that cannot be interpreted as a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgsError {
    /// Not an array of strings (e.g. a bare `+OK`).
    NotCommand,
    /// More arguments than `max_args`.
    TooManyArgs,
    /// An argument is not a string/integer leaf.
    NonStringArg,
}

impl ArgsError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotCommand => "not_a_command",
            Self::TooManyArgs => "too_many_args",
            Self::NonStringArg => "non_string_arg",
        }
    }

    /// The `-ERR ...` text handed back to the peer.
    pub fn client_message(self) -> &'static str {
        match self {
            Self::NotCommand => "ERR Protocol error: expected a command array",
            Self::TooManyArgs => "ERR Protocol error: too many arguments",
            Self::NonStringArg => "ERR Protocol error: invalid argument type",
        }
    }
}

/// Uppercased, length bounded command name. Never panics on binary input.
pub fn command_name(args: &[Vec<u8>]) -> String {
    const MAX_NAME_LEN: usize = 24;
    let Some(first) = args.first() else {
        return String::new();
    };
    let mut name = String::with_capacity(first.len().min(MAX_NAME_LEN));
    for &b in first.iter().take(MAX_NAME_LEN) {
        // ASCII fast path; other bytes map to Latin-1 so the result is always
        // valid UTF-8 and never carries a control byte into a log line.
        let upper = b.to_ascii_uppercase();
        name.push(char::from(upper));
    }
    name
}

/// Bounded, escaped single line preview of all arguments.
///
/// [`text::join_args`] caps the *input* bytes it renders, but escaping expands
/// a control byte to four characters, so the result still has to be truncated
/// before it can reach SQLite.
pub fn preview_args(args: &[Vec<u8>], max_total: usize) -> String {
    let joined = text::join_args(args, max_total);
    if joined.len() <= max_total {
        joined
    } else {
        text::truncate_str(&joined, max_total)
    }
}

/// What a credential looks like in a rendered preview.
const REDACTED: &str = "******";

/// Is this `CONFIG SET <key> <value>` key a credential slot?
///
/// One predicate, two consumers: the preview masking below and
/// [`render_config_pair`], which builds the security detail. They can never
/// disagree about which config value is a secret.
fn config_value_is_credential(key: &[u8]) -> bool {
    key.eq_ignore_ascii_case(b"requirepass")
}

/// Render one `CONFIG SET` pair for a human readable security detail.
///
/// The detail string reaches the console (`logging::alert`) **and** SQLite
/// (`security_events.detail`), so it obeys the same masking rule as the stored
/// preview: the value of a credential slot is hidden unless the operator opted
/// into recording raw passwords. Paths, booleans and numbers stay readable —
/// they are the useful intel.
pub(crate) fn render_config_pair(
    key: &[u8],
    value: &[u8],
    max_len: usize,
    record_passwords: bool,
) -> (String, String) {
    let rendered_key = text::escape_bytes(key, max_len);
    let rendered_value = if !record_passwords && config_value_is_credential(key) {
        REDACTED.to_string()
    } else {
        text::escape_bytes(value, max_len)
    };
    (rendered_key, rendered_value)
}

/// Argument positions of `args` that hold a credential.
///
/// Only the credential slots of `AUTH`, `HELLO … AUTH <user> <password>` and
/// `CONFIG SET requirepass <value>` qualify: ordinary data (`SET key value`)
/// is never masked, so the operator still sees what an attacker stored.
fn credential_positions(name: &str, args: &[Vec<u8>]) -> Vec<usize> {
    let mut positions = Vec::new();
    match name {
        // `AUTH <password>` hides one argument; `AUTH <user> <password>` keeps
        // the username, which is what the console sample shows. Any other
        // arity cannot be interpreted, so every operand is treated as a
        // password: guessing wrong here is exactly how a secret leaks.
        "AUTH" => match args.len() {
            0 | 1 => {}
            2 => positions.push(1),
            3 => positions.push(2),
            _ => positions.extend(1..args.len()),
        },
        // `HELLO <proto> [AUTH <user> <password>] [SETNAME <name>]`
        "HELLO" => {
            for (index, arg) in args.iter().enumerate().skip(1) {
                if arg.eq_ignore_ascii_case(b"AUTH") {
                    for position in [index + 1, index + 2] {
                        if position < args.len() {
                            positions.push(position);
                        }
                    }
                }
            }
        }
        // `CONFIG SET requirepass <value>`: the value is the password an
        // attacker is trying to install on a real server.
        "CONFIG" => {
            let set = args
                .get(1)
                .is_some_and(|subcommand| subcommand.eq_ignore_ascii_case(b"SET"));
            let requirepass = args
                .get(2)
                .is_some_and(|key| config_value_is_credential(key));
            if set && requirepass {
                positions.extend(3..args.len());
            }
        }
        _ => {}
    }
    positions
}

/// Render the preview that is stored and printed, masking credential slots
/// unless the operator explicitly opted into recording raw passwords.
///
/// This is the single place that decides what a credential looks like: the
/// connection layer prints the returned string verbatim
/// ([`crate::logging::command`]) and copies it into `commands.args`, so a
/// password that is not masked here reaches the terminal on every single
/// brute-force attempt.
fn redact_args_preview(
    name: &str,
    args: &[Vec<u8>],
    max_total: usize,
    record_passwords: bool,
) -> String {
    if record_passwords {
        return preview_args(args, max_total);
    }
    let positions = credential_positions(name, args);
    if positions.is_empty() {
        // Nothing to hide: render the original slice, no copy.
        return preview_args(args, max_total);
    }
    let mut masked: Vec<Vec<u8>> = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        if positions.contains(&index) {
            masked.push(REDACTED.as_bytes().to_vec());
        } else {
            masked.push(arg.clone());
        }
    }
    preview_args(&masked, max_total)
}

/// Lock the shared virtual keyspace and run `f` against it.
///
/// Lock poisoning is deliberately not an error: a honeypot must keep answering
/// even if a connection task panicked while holding the lock.
pub(crate) fn with_store<R>(session: &SessionState, f: impl FnOnce(&mut VirtualStore) -> R) -> R {
    let mut guard = match session.store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut guard)
}

/// Interpret a decoded frame as a command argument vector.
pub fn frame_to_args(frame: &RespFrame, limits: &Limits) -> Result<Vec<Vec<u8>>, ArgsError> {
    let items = match frame {
        RespFrame::Array(items) => items,
        _ => return Err(ArgsError::NotCommand),
    };
    if items.is_empty() {
        return Err(ArgsError::NotCommand);
    }
    if items.len() > limits.max_args {
        return Err(ArgsError::TooManyArgs);
    }
    let mut args = Vec::with_capacity(items.len());
    for item in items {
        let arg = match item {
            RespFrame::Bulk(bytes) => bytes.clone(),
            RespFrame::Simple(bytes) => bytes.clone(),
            RespFrame::Integer(i) => i.to_string().into_bytes(),
            RespFrame::Null => Vec::new(),
            _ => return Err(ArgsError::NonStringArg),
        };
        args.push(arg);
    }
    Ok(args)
}

/// Execute one command against session state and return the reply to send.
pub fn dispatch(
    args: &[Vec<u8>],
    session: &mut SessionState,
    limits: &Limits,
    record_passwords: bool,
) -> DispatchResult {
    session.command_count = session.command_count.saturating_add(1);

    let name = command_name(args);
    // Masking happens here, before the preview leaves the command layer: the
    // console line and `commands.args` are both rendered from this one string.
    let args_preview =
        redact_args_preview(&name, args, limits.max_stored_param_bytes, record_passwords);

    if args.is_empty() {
        return DispatchResult {
            reply: RespFrame::error("ERR empty command"),
            name,
            args_preview,
            simulated: "rejected".to_string(),
            risk: RiskLevel::None,
            close_after: false,
            auth: None,
            security: None,
        };
    }

    let reply = handlers::execute(&name, args, session, limits, record_passwords);
    DispatchResult {
        reply: reply.frame,
        name,
        args_preview,
        simulated: reply.simulated.to_string(),
        risk: reply.risk,
        close_after: reply.close_after,
        auth: reply.auth,
        security: reply.security,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(args: &[&str]) -> Vec<Vec<u8>> {
        args.iter().map(|arg| arg.as_bytes().to_vec()).collect()
    }

    fn new_session(limits: &Limits) -> SessionState {
        let store = Arc::new(Mutex::new(VirtualStore::new(StoreCaps::from_limits(
            limits,
        ))));
        SessionState::new(1, IpAddr::from([127, 0, 0, 1]), 40_000, store)
    }

    /// Dispatch a text command with `record_passwords` off.
    fn say(session: &mut SessionState, limits: &Limits, args: &[&str]) -> DispatchResult {
        dispatch(&text(args), session, limits, false)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn key_exists(session: &SessionState, db: u8, key: &[u8]) -> bool {
        let mut guard = session.store.lock().expect("store lock");
        guard.exists(db, key)
    }

    #[test]
    fn command_name_is_uppercased_and_bounded() {
        assert_eq!(command_name(&[b"config".to_vec()]), "CONFIG");
        assert_eq!(command_name(&[]), "");
        let long = vec![b'a'; 100];
        assert_eq!(command_name(&[long]).len(), 24);
    }

    #[test]
    fn command_name_survives_binary_arguments() {
        let name = command_name(&[vec![0xff, 0x00, b'G']]);
        assert!(name.is_ascii() || !name.is_empty());
    }

    #[test]
    fn empty_command_and_command_counts() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        let result = dispatch(&[], &mut session, &limits, false);
        assert_eq!(result.reply, RespFrame::error("ERR empty command"));
        assert_eq!(result.name, "");
        assert_eq!(result.risk, RiskLevel::None);
        assert_eq!(session.command_count, 1);

        let ping = say(&mut session, &limits, &["ping"]);
        assert_eq!(ping.name, "PING");
        assert_eq!(session.command_count, 2);
    }

    // 1 -------------------------------------------------------------------
    #[test]
    fn ping_echo_and_quit_reply_with_the_right_resp_types() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        assert_eq!(
            say(&mut session, &limits, &["PING"]).reply,
            RespFrame::Simple(b"PONG".to_vec())
        );
        assert_eq!(
            say(&mut session, &limits, &["PING", "hi"]).reply,
            RespFrame::Bulk(b"hi".to_vec())
        );
        assert_eq!(
            say(&mut session, &limits, &["ping", "hi"])
                .reply
                .type_name(),
            "bulk_string"
        );
        assert_eq!(
            say(&mut session, &limits, &["ECHO", "x"]).reply,
            RespFrame::Bulk(b"x".to_vec())
        );

        let quit = say(&mut session, &limits, &["QUIT"]);
        assert_eq!(quit.reply, RespFrame::ok());
        assert!(quit.close_after);
        assert_eq!(
            say(&mut session, &limits, &["ECHO"]).reply,
            RespFrame::error("ERR wrong number of arguments for 'echo' command")
        );
    }

    // 2 -------------------------------------------------------------------
    #[test]
    fn auth_records_credentials_only_when_enabled() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let one = say(&mut session, &limits, &["AUTH", "hunter2"]);
        assert_eq!(one.reply, RespFrame::ok());
        assert!(session.authenticated);
        let attempt = one.auth.expect("auth attempt for AUTH pass");
        assert_eq!(attempt.password_len, 7);
        assert_eq!(attempt.username, None);
        // `arg_count` counts the whole command, like `commands.arg_count` does:
        // `AUTH <password>` is two arguments, `AUTH <user> <password>` is three.
        assert_eq!(attempt.arg_count, 2);
        assert_eq!(attempt.method, super::AuthMethod::Auth);
        assert_eq!(attempt.password, None, "record_passwords is off");

        let two = say(&mut session, &limits, &["AUTH", "admin", "s3cret"]);
        assert_eq!(two.reply, RespFrame::ok());
        let attempt = two.auth.expect("auth attempt for AUTH user pass");
        assert_eq!(attempt.username.as_deref(), Some("admin"));
        assert_eq!(attempt.password_len, 6);
        assert_eq!(attempt.arg_count, 3);
        assert_eq!(attempt.password, None);
        assert_eq!(session.auth_attempts, 2);

        let recorded = dispatch(
            &text(&["AUTH", "admin", "s3cret"]),
            &mut session,
            &limits,
            true,
        );
        let attempt = recorded.auth.expect("auth attempt with recording on");
        assert_eq!(attempt.password.as_deref(), Some("s3cret"));
        assert_eq!(attempt.password_len, 6);
        assert_eq!(attempt.username.as_deref(), Some("admin"));

        let bad = say(&mut session, &limits, &["AUTH"]);
        assert_eq!(
            bad.reply,
            RespFrame::error("ERR wrong number of arguments for 'auth' command")
        );
        assert!(bad.auth.is_none(), "a wrong arity AUTH records nothing");
        let too_many = say(&mut session, &limits, &["AUTH", "a", "b", "c"]);
        assert!(too_many.auth.is_none());
        assert_eq!(session.auth_attempts, 3);
    }

    // 3 -------------------------------------------------------------------
    #[test]
    fn config_set_dir_changes_nothing_on_the_host() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        let before = std::env::current_dir().expect("current dir");

        #[cfg(windows)]
        let target = std::env::temp_dir().join("redis-honeypot-rs-must-not-exist");
        #[cfg(not(windows))]
        let target = std::path::PathBuf::from("/tmp/evil");

        let rendered = target.to_string_lossy().into_owned();
        let result = say(&mut session, &limits, &["CONFIG", "SET", "dir", &rendered]);

        assert_eq!(result.reply, RespFrame::ok());
        assert_eq!(result.risk, RiskLevel::High);
        assert!(result.security.is_some());
        assert!(
            !target.exists(),
            "CONFIG SET dir must not create {}",
            rendered
        );
        assert_eq!(std::env::current_dir().expect("current dir"), before);

        // The value is remembered in the virtual config map and nowhere else.
        let got = say(&mut session, &limits, &["CONFIG", "GET", "dir"]);
        assert_eq!(
            got.reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"dir".to_vec()),
                RespFrame::Bulk(rendered.into_bytes()),
            ])
        );
    }

    #[test]
    fn config_gets_plausible_answers_and_flags_the_rest() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let dir = say(&mut session, &limits, &["CONFIG", "GET", "dir"]);
        assert_eq!(
            dir.reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"dir".to_vec()),
                RespFrame::Bulk(b"/var/lib/redis".to_vec()),
            ])
        );

        let all = say(&mut session, &limits, &["CONFIG", "GET", "*"]);
        let RespFrame::Array(items) = &all.reply else {
            panic!("CONFIG GET * must be an array");
        };
        assert!(items.len() >= 18, "expected a full config set");
        assert_eq!(items.len() % 2, 0, "key/value pairs stay paired");

        let medium = say(&mut session, &limits, &["CONFIG", "SET", "maxmemory", "1"]);
        assert_eq!(medium.risk, RiskLevel::Medium);
        assert!(medium.security.is_some());
        let high = say(
            &mut session,
            &limits,
            &["CONFIG", "SET", "dbfilename", "evil.rdb"],
        );
        assert_eq!(high.risk, RiskLevel::High);
        for command in [
            vec!["CONFIG", "SET", "requirepass", "x"],
            vec!["CONFIG", "SET", "appendonly", "yes"],
            vec!["CONFIG", "SET", "save", ""],
        ] {
            assert_eq!(
                say(&mut session, &limits, &command).risk,
                RiskLevel::High,
                "{command:?} must be flagged"
            );
        }
    }

    // 4 -------------------------------------------------------------------
    #[test]
    fn module_load_fails_and_touches_nothing() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        let target = std::env::temp_dir().join("redis-honeypot-rs-not-a-module.so");
        let rendered = target.to_string_lossy().into_owned();

        let result = say(&mut session, &limits, &["MODULE", "LOAD", &rendered]);
        assert!(
            matches!(result.reply, RespFrame::Error(_)),
            "MODULE LOAD must fail like a real server: {:?}",
            result.reply
        );
        assert_eq!(result.risk, RiskLevel::Critical);
        assert!(result.security.is_some());
        assert!(!target.exists(), "MODULE LOAD must not touch {rendered}");
        assert!(
            result
                .security
                .as_deref()
                .is_some_and(|detail| detail.contains("redis-honeypot-rs-not-a-module.so"))
        );

        let unload = say(&mut session, &limits, &["MODULE", "UNLOAD", "pwn"]);
        assert!(matches!(unload.reply, RespFrame::Error(_)));
        assert_eq!(unload.risk, RiskLevel::Critical);

        let listed = say(&mut session, &limits, &["MODULE", "LIST"]);
        assert_eq!(listed.reply, RespFrame::Array(Vec::new()));
        assert_eq!(listed.risk, RiskLevel::None);
    }

    // 5 -------------------------------------------------------------------
    #[test]
    fn eval_never_executes_the_payload() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        let payload = "redis.call('set','pwn','1') os.execute('/bin/sh -c id')";

        for command in [
            vec!["EVAL", payload, "0"],
            vec!["EVALSHA", "0000000000000000000000000000000000000000", "0"],
            vec!["SCRIPT", "LOAD", payload],
        ] {
            let result = say(&mut session, &limits, &command);
            assert_eq!(result.risk, RiskLevel::Critical, "{command:?}");
            assert!(result.security.is_some(), "{command:?}");
            let encoded = crate::resp::encode_frame_vec(&result.reply, false);
            assert!(
                !contains(&encoded, payload.as_bytes()),
                "the payload must never reach the wire: {command:?}"
            );
        }

        // The scripted write never happened and the process is still healthy.
        assert_eq!(
            say(&mut session, &limits, &["GET", "pwn"]).reply,
            RespFrame::Null
        );
        assert_eq!(
            say(&mut session, &limits, &["PING"]).reply,
            RespFrame::Simple(b"PONG".to_vec())
        );

        // SCRIPT LOAD answers with a sha1 shaped digest of the right length.
        let loaded = say(&mut session, &limits, &["SCRIPT", "LOAD", "return 1"]);
        let RespFrame::Bulk(digest) = &loaded.reply else {
            panic!("SCRIPT LOAD must answer with a bulk digest");
        };
        assert_eq!(digest.len(), 40);
        assert!(digest.iter().all(u8::is_ascii_hexdigit));
    }

    // 6 -------------------------------------------------------------------
    #[test]
    fn shutdown_closes_the_connection_but_not_the_process() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let result = say(&mut session, &limits, &["SHUTDOWN"]);
        assert!(result.close_after);
        assert_eq!(result.risk, RiskLevel::Critical);
        assert_eq!(result.reply, RespFrame::ok());
        assert!(
            result
                .security
                .as_deref()
                .is_some_and(|detail| detail.contains("ignored"))
        );

        // Reaching this line is the assertion that nothing was shut down.
        assert_eq!(
            say(&mut session, &limits, &["PING"]).reply,
            RespFrame::Simple(b"PONG".to_vec())
        );
    }

    // 7 -------------------------------------------------------------------
    #[test]
    fn binary_values_roundtrip_and_type_tracks_them() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        let value = vec![0_u8, 0xff, b'a', b'b', 0x00, 0xfe];

        let set = dispatch(
            &[b"SET".to_vec(), b"bin".to_vec(), value.clone()],
            &mut session,
            &limits,
            false,
        );
        assert_eq!(set.reply, RespFrame::ok());
        assert_eq!(set.name, "SET");

        let got = dispatch(
            &[b"GET".to_vec(), b"bin".to_vec()],
            &mut session,
            &limits,
            false,
        );
        assert_eq!(got.reply, RespFrame::Bulk(value));
        assert_eq!(
            say(&mut session, &limits, &["TYPE", "bin"]).reply,
            RespFrame::Simple(b"string".to_vec())
        );

        assert_eq!(
            say(&mut session, &limits, &["DEL", "bin"]).reply,
            RespFrame::int(1)
        );
        assert_eq!(
            say(&mut session, &limits, &["GET", "bin"]).reply,
            RespFrame::Null
        );
        assert_eq!(
            say(&mut session, &limits, &["TYPE", "bin"]).reply,
            RespFrame::Simple(b"none".to_vec())
        );
        assert_eq!(
            say(&mut session, &limits, &["EXISTS", "bin", "bin"]).reply,
            RespFrame::int(0)
        );
    }

    #[test]
    fn wrong_type_is_reported_like_redis() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        say(&mut session, &limits, &["LPUSH", "list", "a"]);
        assert_eq!(
            say(&mut session, &limits, &["GET", "list"]).reply,
            RespFrame::error("WRONGTYPE Operation against a key holding the wrong kind of value")
        );
        assert_eq!(
            say(&mut session, &limits, &["INCR", "list"]).reply,
            RespFrame::error("WRONGTYPE Operation against a key holding the wrong kind of value")
        );
    }

    // 8 -------------------------------------------------------------------
    #[test]
    fn incr_reports_bad_values_and_overflow_without_panicking() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        say(&mut session, &limits, &["SET", "n", "abc"]);
        assert_eq!(
            say(&mut session, &limits, &["INCR", "n"]).reply,
            RespFrame::error("ERR value is not an integer or out of range")
        );

        say(&mut session, &limits, &["SET", "n", "9223372036854775807"]);
        assert_eq!(
            say(&mut session, &limits, &["INCR", "n"]).reply,
            RespFrame::error("ERR increment or decrement would overflow")
        );

        say(&mut session, &limits, &["SET", "n", "-9223372036854775808"]);
        assert_eq!(
            say(&mut session, &limits, &["DECR", "n"]).reply,
            RespFrame::error("ERR increment or decrement would overflow")
        );

        say(&mut session, &limits, &["SET", "n", "41"]);
        assert_eq!(
            say(&mut session, &limits, &["INCR", "n"]).reply,
            RespFrame::int(42)
        );
        assert_eq!(
            say(&mut session, &limits, &["DECR", "n"]).reply,
            RespFrame::int(41)
        );
        assert_eq!(
            say(&mut session, &limits, &["GET", "n"]).reply,
            RespFrame::Bulk(b"41".to_vec())
        );
    }

    // 9 -------------------------------------------------------------------
    #[test]
    fn ttl_expires_and_really_frees_the_entry() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        say(&mut session, &limits, &["SET", "k", "v"]);
        assert_eq!(
            say(&mut session, &limits, &["TTL", "k"]).reply,
            RespFrame::int(-1)
        );
        assert_eq!(
            say(&mut session, &limits, &["EXPIRE", "k", "1"]).reply,
            RespFrame::int(1)
        );
        assert_eq!(
            say(&mut session, &limits, &["TTL", "k"]).reply,
            RespFrame::int(1)
        );
        assert_eq!(
            say(&mut session, &limits, &["TTL", "absent"]).reply,
            RespFrame::int(-2)
        );

        std::thread::sleep(std::time::Duration::from_millis(1_100));

        assert_eq!(
            say(&mut session, &limits, &["TTL", "k"]).reply,
            RespFrame::int(-2)
        );
        assert_eq!(
            say(&mut session, &limits, &["GET", "k"]).reply,
            RespFrame::Null
        );
        assert!(
            !key_exists(&session, 0, b"k"),
            "the expired entry must be gone from the store, not just hidden"
        );
    }

    #[test]
    fn set_px_expires_without_a_sleep_heavy_test() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        assert_eq!(
            say(&mut session, &limits, &["SET", "fast", "v", "PX", "1"]).reply,
            RespFrame::ok()
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(
            say(&mut session, &limits, &["GET", "fast"]).reply,
            RespFrame::Null
        );
        assert!(!key_exists(&session, 0, b"fast"));
    }

    #[test]
    fn set_flags_are_parsed_and_unknown_ones_are_rejected() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        assert_eq!(
            say(&mut session, &limits, &["SET", "nx", "1", "NX"]).reply,
            RespFrame::ok()
        );
        assert_eq!(
            say(&mut session, &limits, &["SET", "nx", "2", "NX"]).reply,
            RespFrame::Null
        );
        assert_eq!(
            say(&mut session, &limits, &["GET", "nx"]).reply,
            RespFrame::Bulk(b"1".to_vec())
        );
        assert_eq!(
            say(&mut session, &limits, &["SET", "missing", "1", "XX"]).reply,
            RespFrame::Null
        );
        assert_eq!(
            say(&mut session, &limits, &["SET", "k", "v", "WAT"]).reply,
            RespFrame::error("ERR syntax error")
        );
        assert_eq!(
            say(&mut session, &limits, &["SET", "k", "v", "EX", "0"]).reply,
            RespFrame::error("ERR invalid expire time in 'set' command")
        );
        assert_eq!(
            say(&mut session, &limits, &["SET", "k", "v", "EX", "abc"]).reply,
            RespFrame::error("ERR value is not an integer or out of range")
        );
    }

    // 10 ------------------------------------------------------------------
    #[test]
    fn collections_behave_like_redis() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        // hashes
        assert_eq!(
            say(
                &mut session,
                &limits,
                &["HSET", "h", "f1", "v1", "f2", "v2"]
            )
            .reply,
            RespFrame::int(2)
        );
        assert_eq!(
            say(&mut session, &limits, &["HSET", "h", "f1", "updated"]).reply,
            RespFrame::int(0)
        );
        assert_eq!(
            say(&mut session, &limits, &["HGET", "h", "f1"]).reply,
            RespFrame::Bulk(b"updated".to_vec())
        );
        assert_eq!(
            say(&mut session, &limits, &["HGET", "h", "nope"]).reply,
            RespFrame::Null
        );
        assert_eq!(
            say(&mut session, &limits, &["HGETALL", "h"]).reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"f1".to_vec()),
                RespFrame::Bulk(b"updated".to_vec()),
                RespFrame::Bulk(b"f2".to_vec()),
                RespFrame::Bulk(b"v2".to_vec()),
            ])
        );
        assert_eq!(
            say(&mut session, &limits, &["TYPE", "h"]).reply,
            RespFrame::Simple(b"hash".to_vec())
        );

        // lists
        assert_eq!(
            say(&mut session, &limits, &["LPUSH", "l", "b", "a"]).reply,
            RespFrame::int(2)
        );
        assert_eq!(
            say(&mut session, &limits, &["RPUSH", "l", "c"]).reply,
            RespFrame::int(3)
        );
        assert_eq!(
            say(&mut session, &limits, &["LRANGE", "l", "0", "-1"]).reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"a".to_vec()),
                RespFrame::Bulk(b"b".to_vec()),
                RespFrame::Bulk(b"c".to_vec()),
            ])
        );
        assert_eq!(
            say(&mut session, &limits, &["LRANGE", "l", "-2", "-1"]).reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"b".to_vec()),
                RespFrame::Bulk(b"c".to_vec()),
            ])
        );
        assert_eq!(
            say(&mut session, &limits, &["TYPE", "l"]).reply,
            RespFrame::Simple(b"list".to_vec())
        );

        // sets
        assert_eq!(
            say(&mut session, &limits, &["SADD", "s", "x", "y", "x"]).reply,
            RespFrame::int(2)
        );
        assert_eq!(
            say(&mut session, &limits, &["SMEMBERS", "s"]).reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"x".to_vec()),
                RespFrame::Bulk(b"y".to_vec()),
            ])
        );
        assert_eq!(
            say(&mut session, &limits, &["TYPE", "s"]).reply,
            RespFrame::Simple(b"set".to_vec())
        );
    }

    #[test]
    fn keys_and_scan_are_bounded_and_patterned() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        for index in 0..6_u8 {
            let key = format!("user:{index}");
            say(&mut session, &limits, &["SET", &key, "v"]);
        }
        say(&mut session, &limits, &["SET", "other", "v"]);

        let keys = say(&mut session, &limits, &["KEYS", "user:*"]);
        let RespFrame::Array(items) = &keys.reply else {
            panic!("KEYS must answer with an array");
        };
        assert_eq!(items.len(), 6);

        let all = say(&mut session, &limits, &["KEYS", "*"]);
        let RespFrame::Array(items) = &all.reply else {
            panic!("KEYS * must answer with an array");
        };
        assert_eq!(items.len(), 7);

        let mut cursor = 0_u64;
        let mut seen = 0_usize;
        for _ in 0..16 {
            let page = say(
                &mut session,
                &limits,
                &["SCAN", &cursor.to_string(), "COUNT", "2"],
            );
            let RespFrame::Array(pair) = &page.reply else {
                panic!("SCAN must answer with a cursor and an array");
            };
            let (RespFrame::Bulk(raw_cursor), RespFrame::Array(keys)) = (&pair[0], &pair[1]) else {
                panic!("SCAN shape");
            };
            let rendered = String::from_utf8_lossy(raw_cursor).into_owned();
            seen += keys.len();
            cursor = rendered.parse::<u64>().expect("cursor");
            if cursor == 0 {
                break;
            }
        }
        assert_eq!(seen, 7, "SCAN must eventually yield every key");
    }

    // 11 ------------------------------------------------------------------
    #[test]
    fn store_caps_hold_and_oversized_writes_are_refused() {
        let limits = Limits {
            store_max_keys: 8,
            store_max_bytes: 4_096,
            store_max_value_bytes: 32,
            ..Limits::default()
        };
        let mut session = new_session(&limits);

        for index in 0..40_u8 {
            let key = format!("k{index}");
            let result = say(&mut session, &limits, &["SET", &key, "value"]);
            assert_eq!(result.reply, RespFrame::ok(), "the server keeps answering");
        }
        let held = {
            let mut guard = session.store.lock().expect("store lock");
            guard.live_keys()
        };
        assert!(held <= limits.store_max_keys, "held={held}");

        // The newest key is present, the oldest were evicted.
        assert_eq!(
            say(&mut session, &limits, &["GET", "k39"]).reply,
            RespFrame::Bulk(b"value".to_vec())
        );
        assert_eq!(
            say(&mut session, &limits, &["GET", "k0"]).reply,
            RespFrame::Null
        );

        // A single oversized value is refused and leaves the keyspace alone.
        let big = vec![b'x'; limits.store_max_value_bytes * 4];
        let refused = dispatch(
            &[b"SET".to_vec(), b"huge".to_vec(), big],
            &mut session,
            &limits,
            false,
        );
        assert!(matches!(refused.reply, RespFrame::Error(_)));
        assert_eq!(
            say(&mut session, &limits, &["GET", "k39"]).reply,
            RespFrame::Bulk(b"value".to_vec()),
            "a refused write must not evict the store"
        );
        let held = {
            let mut guard = session.store.lock().expect("store lock");
            guard.live_keys()
        };
        assert!(held > 0);
    }

    // 12 ------------------------------------------------------------------
    #[test]
    fn select_bounds_databases_and_isolates_keys() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        assert_eq!(
            say(&mut session, &limits, &["SELECT", "16"]).reply,
            RespFrame::error("ERR DB index is out of range")
        );
        assert_eq!(
            say(&mut session, &limits, &["SELECT", "abc"]).reply,
            RespFrame::error("ERR value is not an integer or out of range")
        );

        say(&mut session, &limits, &["SET", "k", "zero"]);
        assert_eq!(
            say(&mut session, &limits, &["SELECT", "3"]).reply,
            RespFrame::ok()
        );
        assert_eq!(session.db_index, 3);
        assert_eq!(
            say(&mut session, &limits, &["GET", "k"]).reply,
            RespFrame::Null
        );

        say(&mut session, &limits, &["SET", "k", "three"]);
        assert_eq!(
            say(&mut session, &limits, &["GET", "k"]).reply,
            RespFrame::Bulk(b"three".to_vec())
        );

        say(&mut session, &limits, &["SELECT", "0"]);
        assert_eq!(
            say(&mut session, &limits, &["GET", "k"]).reply,
            RespFrame::Bulk(b"zero".to_vec())
        );
    }

    // 13 ------------------------------------------------------------------
    #[test]
    fn unknown_commands_and_huge_arguments_stay_bounded() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let result = say(&mut session, &limits, &["FOOBAR", "a", "b"]);
        let RespFrame::Error(message) = &result.reply else {
            panic!("unknown commands answer with an error");
        };
        let rendered = String::from_utf8_lossy(message);
        assert!(rendered.contains("unknown command"));
        assert!(rendered.contains("foobar"));
        assert_eq!(result.risk, RiskLevel::None);
        assert_eq!(result.name, "FOOBAR");

        let mut argv = vec![b"FOOBAR".to_vec(), vec![b'A'; 8 * 1_024]];
        argv[1].extend(std::iter::repeat_n(b'\r', 64));
        let huge = dispatch(&argv, &mut session, &limits, false);
        assert!(matches!(huge.reply, RespFrame::Error(_)));
        assert!(
            huge.args_preview.len() <= limits.max_stored_param_bytes + 64,
            "preview len {}",
            huge.args_preview.len()
        );
    }

    // 14 ------------------------------------------------------------------
    #[test]
    fn hello_negotiates_the_protocol_version() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let three = say(&mut session, &limits, &["HELLO", "3"]);
        assert!(matches!(three.reply, RespFrame::Map(_)));
        assert_eq!(session.resp_version, 3);
        if let RespFrame::Map(pairs) = &three.reply {
            assert_eq!(pairs.len(), 7);
            assert_eq!(pairs[0].0, RespFrame::Bulk(b"server".to_vec()));
            assert_eq!(pairs[0].1, RespFrame::Bulk(b"redis".to_vec()));
            assert_eq!(pairs[2].1, RespFrame::int(3));
            assert_eq!(pairs[6].1, RespFrame::Array(Vec::new()));
        }

        let two = say(&mut session, &limits, &["HELLO", "2"]);
        assert!(matches!(two.reply, RespFrame::Array(_)));
        assert_eq!(session.resp_version, 2);

        let bad = say(&mut session, &limits, &["HELLO", "4"]);
        assert_eq!(
            bad.reply,
            RespFrame::error("NOPROTO unsupported protocol version")
        );
        assert_eq!(session.resp_version, 2, "a refused HELLO changes nothing");

        let bare = say(&mut session, &limits, &["HELLO"]);
        assert!(matches!(bare.reply, RespFrame::Array(_)));
    }

    // 15 ------------------------------------------------------------------
    #[test]
    fn giant_argument_never_panics_and_stays_bounded() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let giant = vec![b'Z'; 1024 * 1024];
        let result = dispatch(
            &[b"ECHO".to_vec(), giant.clone()],
            &mut session,
            &limits,
            false,
        );
        assert!(matches!(result.reply, RespFrame::Bulk(_)));
        assert!(result.args_preview.len() <= limits.max_stored_param_bytes + 64);

        let binary_giant = vec![0x01_u8; 1024 * 1024];
        let result = dispatch(
            &[b"SET".to_vec(), b"k".to_vec(), binary_giant],
            &mut session,
            &limits,
            false,
        );
        assert!(matches!(result.reply, RespFrame::Error(_)));
        assert!(result.args_preview.len() <= limits.max_stored_param_bytes + 64);

        // Binary command names and empty vectors are handled without panicking.
        for argv in [
            vec![vec![0xff_u8, 0xfe]],
            vec![Vec::new()],
            vec![Vec::new(), Vec::new()],
            vec![b"SELECT".to_vec(), vec![0xff; 8]],
        ] {
            let result = dispatch(&argv, &mut session, &limits, false);
            assert!(!result.name.is_empty() || argv[0].is_empty());
        }
    }

    #[test]
    fn info_reports_plausible_sections() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        say(&mut session, &limits, &["SET", "k", "v"]);

        let info = say(&mut session, &limits, &["INFO"]);
        let RespFrame::Bulk(body) = &info.reply else {
            panic!("INFO must answer with a bulk string");
        };
        let rendered = String::from_utf8_lossy(body);
        for needle in [
            "# Server",
            "redis_version:7.2.4",
            "# Clients",
            "# Memory",
            "# Persistence",
            "# Stats",
            "role:master",
            "# CPU",
            "# Keyspace",
            "db0:keys=",
        ] {
            assert!(rendered.contains(needle), "INFO is missing {needle}");
        }
        assert!(rendered.contains("\r\n"));

        let server = say(&mut session, &limits, &["INFO", "server"]);
        let RespFrame::Bulk(body) = &server.reply else {
            panic!("INFO server must answer with a bulk string");
        };
        let rendered = String::from_utf8_lossy(body);
        assert!(rendered.contains("redis_version:7.2.4"));
        assert!(!rendered.contains("# Clients"));

        let unknown = say(&mut session, &limits, &["INFO", "nope"]);
        assert_eq!(unknown.reply, RespFrame::Bulk(Vec::new()));
    }

    #[test]
    fn introspection_commands_answer_with_plausible_shapes() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        assert!(matches!(
            say(&mut session, &limits, &["DBSIZE"]).reply,
            RespFrame::Integer(value) if value > 0
        ));
        assert!(matches!(
            say(&mut session, &limits, &["TIME"]).reply,
            RespFrame::Array(items) if items.len() == 2
        ));
        assert_eq!(
            say(&mut session, &limits, &["ROLE"]).reply,
            RespFrame::Array(vec![
                RespFrame::Bulk(b"master".to_vec()),
                RespFrame::int(0),
                RespFrame::Array(Vec::new()),
            ])
        );
        assert!(matches!(
            say(&mut session, &limits, &["COMMAND", "COUNT"]).reply,
            RespFrame::Integer(value) if value > 20
        ));
        assert!(matches!(
            say(&mut session, &limits, &["COMMAND"]).reply,
            RespFrame::Array(items) if items.len() > 20
        ));
        assert!(matches!(
            say(&mut session, &limits, &["COMMAND", "DOCS"]).reply,
            RespFrame::Map(_)
        ));
    }

    #[test]
    fn client_name_roundtrips_and_setinfo_is_ignored() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        assert_eq!(
            say(&mut session, &limits, &["CLIENT", "GETNAME"]).reply,
            RespFrame::Null
        );
        assert_eq!(
            say(&mut session, &limits, &["CLIENT", "SETNAME", "app-1"]).reply,
            RespFrame::ok()
        );
        assert_eq!(
            say(&mut session, &limits, &["CLIENT", "GETNAME"]).reply,
            RespFrame::Bulk(b"app-1".to_vec())
        );
        assert_eq!(
            say(
                &mut session,
                &limits,
                &["CLIENT", "SETINFO", "lib-name", "redis-py"]
            )
            .reply,
            RespFrame::ok()
        );
        assert!(matches!(
            say(&mut session, &limits, &["CLIENT", "WAT"]).reply,
            RespFrame::Error(_)
        ));
    }

    #[test]
    fn flush_only_clears_the_virtual_keyspace() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        say(&mut session, &limits, &["SET", "a", "1"]);
        let flush = say(&mut session, &limits, &["FLUSHALL"]);
        assert_eq!(flush.reply, RespFrame::ok());
        assert_eq!(flush.risk, RiskLevel::Critical);
        assert_eq!(
            say(&mut session, &limits, &["GET", "a"]).reply,
            RespFrame::Null
        );

        say(&mut session, &limits, &["SET", "b", "1"]);
        let flush = say(&mut session, &limits, &["FLUSHDB", "ASYNC"]);
        assert_eq!(flush.reply, RespFrame::ok());
        assert_eq!(
            say(&mut session, &limits, &["GET", "b"]).reply,
            RespFrame::Null
        );
    }

    #[test]
    fn dangerous_commands_are_all_critical_and_side_effect_free() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let cases: &[(&[&str], &str)] = &[
            (&["SAVE"], "simulated_save"),
            (&["BGSAVE"], "simulated_save"),
            (&["BGREWRITEAOF"], "simulated_bgrewriteaof"),
            (&["REPLICAOF", "10.0.0.9", "6379"], "simulated_replicaof"),
            (&["SLAVEOF", "10.0.0.9", "6379"], "simulated_replicaof"),
            (&["DEBUG", "SLEEP", "10"], "simulated_debug"),
            (&["DEBUG", "JMAP"], "simulated_debug"),
            (&["DEBUG", "SET-ACTIVE-EXPIRE", "0"], "simulated_debug"),
            (&["EVAL", "return 1", "0"], "simulated_eval"),
            (&["FLUSHALL"], "simulated_flush"),
            (&["FLUSHDB"], "simulated_flush"),
            (&["MODULE", "LOAD", "/tmp/x.so"], "simulated_module_load"),
            (&["SHUTDOWN"], "simulated_shutdown"),
        ];
        for &(command, label) in cases {
            let result = say(&mut session, &limits, command);
            assert_eq!(result.risk, RiskLevel::Critical, "{command:?}");
            assert!(result.security.is_some(), "{command:?}");
            assert_eq!(result.simulated, label, "{command:?}");
        }

        // DEBUG SLEEP must not actually sleep.
        let started = std::time::Instant::now();
        say(&mut session, &limits, &["DEBUG", "SLEEP", "5"]);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));

        assert_eq!(
            say(&mut session, &limits, &["DEBUG", "OBJECT", "k"]).reply,
            RespFrame::error("ERR DEBUG subcommand not supported")
        );

        // REPLICAOF/PING: no outbound connection was opened, nothing changed.
        assert_eq!(
            say(&mut session, &limits, &["PING"]).reply,
            RespFrame::Simple(b"PONG".to_vec())
        );
    }

    #[test]
    fn arity_errors_name_the_lowercased_command() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        for (args, name) in [
            (vec!["GET"], "get"),
            (vec!["SET", "k"], "set"),
            (vec!["DEL"], "del"),
            (vec!["SELECT"], "select"),
            (vec!["TTL"], "ttl"),
            (vec!["HSET", "h", "f"], "hset"),
            (vec!["LRANGE", "l", "0"], "lrange"),
        ] {
            let result = say(&mut session, &limits, &args);
            assert_eq!(
                result.reply,
                RespFrame::Error(
                    format!("ERR wrong number of arguments for '{name}' command").into_bytes()
                ),
                "{args:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Credential masking: `args_preview` is printed on the console and written
    // to `commands.args`, so a password that survives it leaks on every attempt.
    // -----------------------------------------------------------------------

    #[test]
    fn auth_preview_masks_the_password() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let two = say(&mut session, &limits, &["AUTH", "admin", "swordfish"]);
        assert!(
            !two.args_preview.contains("swordfish"),
            "the password leaked into the preview: {}",
            two.args_preview
        );
        assert!(two.args_preview.contains("AUTH"), "{}", two.args_preview);
        assert!(two.args_preview.contains("admin"), "{}", two.args_preview);
        assert!(two.args_preview.contains("******"), "{}", two.args_preview);
        assert_eq!(two.args_preview, "AUTH admin ******");
        let attempt = two.auth.expect("auth attempt");
        assert_eq!(attempt.username.as_deref(), Some("admin"));
        assert_eq!(attempt.password_len, 9, "the real length is still recorded");
        assert_eq!(attempt.password, None, "record_passwords is off");

        // An arity the handler cannot interpret hides every operand: guessing
        // which one is "the username" is how a secret escapes.
        let ambiguous = say(
            &mut session,
            &limits,
            &["AUTH", "user", "swordfish", "extra"],
        );
        assert!(
            !ambiguous.args_preview.contains("swordfish"),
            "{}",
            ambiguous.args_preview
        );
        assert_eq!(ambiguous.args_preview, "AUTH ****** ****** ******");
    }

    #[test]
    fn auth_preview_masks_the_single_argument_form() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let one = say(&mut session, &limits, &["AUTH", "swordfish"]);
        assert!(
            !one.args_preview.contains("swordfish"),
            "the password leaked into the preview: {}",
            one.args_preview
        );
        assert_eq!(one.args_preview, "AUTH ******");
        assert_eq!(one.reply, RespFrame::ok());
    }

    #[test]
    fn recorded_passwords_stay_visible_to_the_operator() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        // `record_passwords` is the operator's explicit forensic opt-in: it
        // keeps the raw value in both the preview and the auth record.
        let recorded = dispatch(
            &text(&["AUTH", "admin", "swordfish"]),
            &mut session,
            &limits,
            true,
        );
        assert_eq!(recorded.args_preview, "AUTH admin swordfish");
        let attempt = recorded.auth.expect("auth attempt");
        assert_eq!(attempt.password.as_deref(), Some("swordfish"));
        assert_eq!(attempt.password_len, 9);
    }

    // ------------------------------------------------- HELLO AUTH (regr.)

    /// `HELLO 2/3 … AUTH user pass` is a credential attempt, not a decoration:
    /// it must produce the same attempt record as `AUTH`, with its own method
    /// label, and it must still succeed unconditionally.
    #[test]
    fn hello_auth_is_captured_like_auth() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        // No AUTH option: only the protocol is negotiated.
        let plain = say(&mut session, &limits, &["HELLO", "3"]);
        assert_eq!(session.resp_version, 3);
        assert!(plain.auth.is_none(), "HELLO without AUTH is not an attempt");
        assert_eq!(session.auth_attempts, 0);

        let hello3 = say(
            &mut session,
            &limits,
            &["HELLO", "3", "AUTH", "default", "hunter2"],
        );
        let attempt = hello3.auth.expect("HELLO 3 AUTH must be recorded");
        assert_eq!(attempt.method, super::AuthMethod::Hello);
        assert_eq!(attempt.username.as_deref(), Some("default"));
        assert_eq!(attempt.password_len, 7);
        assert_eq!(attempt.password, None, "record_passwords is off");
        assert_eq!(attempt.arg_count, 5, "the whole HELLO command");
        assert!(session.authenticated);
        assert_eq!(session.auth_attempts, 1);

        let hello2 = say(
            &mut session,
            &limits,
            &["HELLO", "2", "AUTH", "root", "pass"],
        );
        let attempt = hello2.auth.expect("HELLO 2 AUTH must be recorded");
        assert_eq!(attempt.username.as_deref(), Some("root"));
        assert_eq!(attempt.password_len, 4);
        assert_eq!(session.resp_version, 2);
        assert_eq!(session.auth_attempts, 2);

        // `SETNAME` is applied, in either order.
        let named = say(
            &mut session,
            &limits,
            &["HELLO", "3", "SETNAME", "scanner", "AUTH", "admin", "pw"],
        );
        assert!(named.auth.is_some(), "the options are order independent");
        assert_eq!(session.client_name.as_deref(), Some(b"scanner".as_slice()));
    }

    /// Malformed HELLO option lists are refused like a real server, and a refused
    /// HELLO must not fabricate an attempt.
    #[test]
    fn hello_option_errors_are_reported_and_not_recorded() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        for (args, needle) in [
            (vec!["HELLO", "3", "AUTH", "user"], "AUTH"),
            (vec!["HELLO", "3", "AUTH"], "AUTH"),
            (vec!["HELLO", "3", "SETNAME"], "SETNAME"),
            (vec!["HELLO", "3", "BOGUS", "x"], "BOGUS"),
        ] {
            let reply = say(&mut session, &limits, &args);
            match reply.reply {
                RespFrame::Error(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    assert!(
                        text.contains("Syntax error") && text.contains(needle),
                        "{args:?} produced {text:?}"
                    );
                }
                other => panic!("{args:?} must be a syntax error, got {other:?}"),
            }
            assert!(reply.auth.is_none(), "{args:?} must not record an attempt");
        }
        assert_eq!(session.auth_attempts, 0);
        assert!(!session.authenticated);

        // An unsupported protocol version stays NOPROTO, with or without AUTH.
        for args in [
            vec!["HELLO", "4"],
            vec!["HELLO", "4", "AUTH", "u", "p"],
            vec!["HELLO", "x"],
        ] {
            let reply = say(&mut session, &limits, &args);
            match reply.reply {
                RespFrame::Error(bytes) => assert!(
                    String::from_utf8_lossy(&bytes).contains("NOPROTO"),
                    "{args:?} must be NOPROTO"
                ),
                other => panic!("{args:?} must be NOPROTO, got {other:?}"),
            }
            assert!(reply.auth.is_none());
        }
        assert_eq!(
            session.resp_version, 2,
            "a rejected HELLO keeps the version"
        );
    }

    /// With `record_passwords` on, HELLO must store what AUTH stores — and with
    /// it off, neither may store anything.
    #[test]
    fn hello_auth_respects_the_password_recording_switch() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let masked = say(
            &mut session,
            &limits,
            &["HELLO", "3", "AUTH", "u", "secret"],
        );
        assert_eq!(masked.auth.expect("attempt").password, None);

        let recorded = dispatch(
            &text(&["HELLO", "3", "AUTH", "u", "secret"]),
            &mut session,
            &limits,
            true,
        );
        let attempt = recorded.auth.expect("attempt");
        assert_eq!(attempt.password.as_deref(), Some("secret"));
        // One switch, one meaning: with recording on, the operator asked for the
        // raw credential everywhere it is stored, preview included.
        assert!(
            recorded.args_preview.contains("secret"),
            "recording is on, so the preview may show it: {}",
            recorded.args_preview
        );
    }

    #[test]
    fn hello_auth_tokens_are_masked() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let hello = say(
            &mut session,
            &limits,
            &["HELLO", "3", "AUTH", "default", "secret"],
        );
        assert!(
            !hello.args_preview.contains("secret"),
            "HELLO leaked the password: {}",
            hello.args_preview
        );
        assert_eq!(hello.args_preview, "HELLO 3 AUTH ****** ******");
        // The protocol negotiation itself still ran.
        assert_eq!(session.resp_version, 3);

        // SETNAME after the AUTH block is ordinary data and stays readable.
        let named = say(
            &mut session,
            &limits,
            &[
                "HELLO", "3", "AUTH", "default", "secret", "SETNAME", "app-1",
            ],
        );
        assert!(
            !named.args_preview.contains("secret"),
            "{}",
            named.args_preview
        );
        assert!(
            named.args_preview.contains("app-1"),
            "{}",
            named.args_preview
        );
    }

    #[test]
    fn config_set_requirepass_masks_the_value() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        let masked = say(
            &mut session,
            &limits,
            &["CONFIG", "SET", "requirepass", "hunter2"],
        );
        assert!(
            !masked.args_preview.contains("hunter2"),
            "CONFIG SET leaked the value: {}",
            masked.args_preview
        );
        assert_eq!(masked.args_preview, "CONFIG SET requirepass ******");
        assert_eq!(masked.risk, RiskLevel::High);

        let kept = dispatch(
            &text(&["CONFIG", "SET", "requirepass", "hunter2"]),
            &mut session,
            &limits,
            true,
        );
        assert_eq!(kept.args_preview, "CONFIG SET requirepass hunter2");

        // A different CONFIG key is not a credential position.
        let plain = say(
            &mut session,
            &limits,
            &["CONFIG", "SET", "maxmemory", "hunter2"],
        );
        assert_eq!(plain.args_preview, "CONFIG SET maxmemory hunter2");
    }

    /// The security detail is printed as an ALERT and stored in
    /// `security_events.detail`, so it follows the same masking rule as the
    /// preview — while paths, booleans and numbers stay readable.
    #[test]
    fn config_detail_masks_requirepass_and_keeps_intel() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        const SECRET: &str = "swordfish123";

        let masked = say(
            &mut session,
            &limits,
            &["CONFIG", "SET", "requirepass", SECRET],
        );
        assert_eq!(masked.risk, RiskLevel::High);
        let detail = masked
            .security
            .expect("CONFIG SET carries a security detail");
        assert!(
            !detail.contains(SECRET),
            "detail leaked the secret: {detail}"
        );
        assert_eq!(
            detail,
            "CONFIG SET requirepass ****** (virtual config only, nothing was changed)"
        );

        // The operator's opt-in keeps the value here too.
        let recorded = dispatch(
            &text(&["CONFIG", "SET", "requirepass", SECRET]),
            &mut session,
            &limits,
            true,
        );
        let detail = recorded.security.expect("security detail");
        assert!(detail.contains(SECRET), "detail: {detail}");

        // Intel, not credentials: these must not change.
        for (command, needle) in [
            (
                vec!["CONFIG", "SET", "dir", "/var/lib/redis2"],
                "/var/lib/redis2",
            ),
            (vec!["CONFIG", "SET", "dbfilename", "evil.rdb"], "evil.rdb"),
            (vec!["CONFIG", "SET", "appendonly", "yes"], "yes"),
            (vec!["CONFIG", "SET", "save", "60 1"], "60 1"),
        ] {
            let result = say(&mut session, &limits, &command);
            assert_eq!(result.risk, RiskLevel::High, "{command:?}");
            let detail = result.security.expect("security detail");
            assert!(detail.contains(needle), "{command:?} -> {detail}");
        }

        // AUTH records credentials through `AuthAttempt` only.
        let auth = say(&mut session, &limits, &["AUTH", "admin", SECRET]);
        assert!(
            auth.security.is_none(),
            "AUTH must not raise a security detail"
        );
        assert_eq!(auth.risk, RiskLevel::None);
    }

    #[test]
    fn ordinary_values_are_not_masked() {
        let limits = Limits::default();
        let mut session = new_session(&limits);

        // Regression guard: only credential positions are hidden. A stored
        // value must stay readable, otherwise the telemetry is worthless.
        let data = say(&mut session, &limits, &["SET", "key", "hunter2"]);
        assert!(
            data.args_preview.contains("hunter2"),
            "{}",
            data.args_preview
        );
        assert_eq!(data.args_preview, "SET key hunter2");

        let echo = say(&mut session, &limits, &["ECHO", "hunter2"]);
        assert_eq!(echo.args_preview, "ECHO hunter2");

        // "AUTH" is only a credential position in the HELLO argument list.
        let value = say(&mut session, &limits, &["SET", "AUTH", "user", "pass"]);
        assert_eq!(value.args_preview, "SET AUTH user pass");
    }

    #[test]
    fn huge_password_never_reaches_the_preview() {
        let limits = Limits::default();
        let mut session = new_session(&limits);
        let password = "p".repeat(3_000);

        let result = dispatch(
            &text(&["AUTH", "admin", &password]),
            &mut session,
            &limits,
            false,
        );
        assert!(
            result.args_preview.len() <= limits.max_stored_param_bytes,
            "preview len {}",
            result.args_preview.len()
        );
        assert_eq!(result.args_preview, "AUTH admin ******");
        assert!(!result.args_preview.contains("pppp"));
        let attempt = result.auth.expect("auth attempt");
        assert_eq!(attempt.password_len, 3_000);
        assert_eq!(attempt.password, None);

        // Same for the single argument form, which masks the only operand.
        let single = dispatch(&text(&["AUTH", &password]), &mut session, &limits, false);
        assert_eq!(single.args_preview, "AUTH ******");
        assert!(!single.args_preview.contains("pppp"));
    }
}
