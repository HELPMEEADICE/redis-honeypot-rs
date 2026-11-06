//! The command simulation table.
//!
//! One function per command family, all pure: they return a [`RespFrame`] and a
//! risk label, mutate only [`VirtualStore`](crate::commands::VirtualStore) or
//! session state, and never touch the host.
//!
//! The dangerous half of the table (`SAVE`, `MODULE LOAD`, `EVAL`, `REPLICAOF`,
//! `CONFIG SET dir`, `SHUTDOWN`, …) is answered with a plausible protocol reply
//! and a [`RiskLevel::Critical`] security note. None of them has a side effect:
//! there is no filesystem call, no process spawn, no socket and no evaluator
//! anywhere in this module to reach.
//!
//! Security details are both printed (`logging::alert`) and persisted
//! (`security_events.detail`), so any detail that interpolates a client argument
//! must treat that argument as hostile: credential slots are rendered through
//! [`super::render_config_pair`], and no other detail quotes an operand.

use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

use crate::config::Limits;
use crate::record::RiskLevel;
use crate::resp::RespFrame;
use crate::text;
use crate::timeutil;

use super::store::{DB_COUNT, SCAN_COUNT_DEFAULT, SCAN_COUNT_MAX, StoreError, VirtualStore};
use super::{AuthAttempt, SessionState, render_config_pair, with_store};

/// Version this server claims to be. Only ever a static string.
pub const REDIS_VERSION: &str = "7.2.4";

/// `KEYS` never returns more than this many keys, whatever the keyspace holds.
const KEYS_REPLY_LIMIT: usize = 128;

/// A fresh keyspace still looks inhabited, like a real server's would.
const DB_SIZE_FLOOR: i64 = 4;

/// Hard cap on the argument text echoed back by an unknown-command error.
const UNKNOWN_ARGS_MAX: usize = 128;

/// What one simulated command produced, before [`super::dispatch`] adds the
/// name and the argument preview.
#[derive(Debug)]
pub struct Reply {
    pub frame: RespFrame,
    pub simulated: &'static str,
    pub risk: RiskLevel,
    pub security: Option<String>,
    pub close_after: bool,
    pub auth: Option<AuthAttempt>,
}

impl Reply {
    fn frame(frame: RespFrame, simulated: &'static str) -> Self {
        Self {
            frame,
            simulated,
            risk: RiskLevel::None,
            security: None,
            close_after: false,
            auth: None,
        }
    }

    fn ok() -> Self {
        Self::frame(RespFrame::ok(), "ok")
    }

    fn error(message: impl Into<Vec<u8>>, simulated: &'static str) -> Self {
        Self::frame(RespFrame::Error(message.into()), simulated)
    }

    /// `-ERR wrong number of arguments for '<command>' command`.
    fn arity(command: &str) -> Self {
        Self::error(
            format!(
                "ERR wrong number of arguments for '{}' command",
                command.to_ascii_lowercase()
            ),
            "rejected",
        )
    }

    /// Attach a security note without changing the reply.
    fn with_risk(mut self, risk: RiskLevel, detail: impl Into<String>) -> Self {
        self.risk = risk;
        self.security = Some(detail.into());
        self
    }

    /// A dangerous command: always critical, always explained.
    fn critical(frame: RespFrame, simulated: &'static str, detail: impl Into<String>) -> Self {
        Self::frame(frame, simulated).with_risk(RiskLevel::Critical, detail)
    }
}

/// Run one already-normalised command. `name` is the uppercased bounded command
/// name from [`super::command_name`]; `args[0]` is the original command token.
pub fn execute(
    name: &str,
    args: &[Vec<u8>],
    session: &mut SessionState,
    limits: &Limits,
    record_passwords: bool,
) -> Reply {
    let p: &[Vec<u8>] = args.get(1..).unwrap_or(&[]);

    match name {
        // connection / probing
        "PING" => cmd_ping(p),
        "ECHO" => cmd_echo(p),
        "QUIT" => cmd_quit(p),
        "AUTH" => cmd_auth(p, session, limits, record_passwords),
        "HELLO" => cmd_hello(p, session),
        "CLIENT" => cmd_client(p, session, limits),
        "SELECT" => cmd_select(p, session),
        // information gathering
        "INFO" => cmd_info(p, session),
        "CONFIG" => cmd_config(p, session, limits, record_passwords),
        "DBSIZE" => cmd_dbsize(p, session),
        "TIME" => cmd_time(p),
        "ROLE" => cmd_role(p),
        "COMMAND" => cmd_command(p),
        "MODULE" => cmd_module(p, limits),
        // data
        "GET" => cmd_get(p, session),
        "SET" => cmd_set(p, session),
        "DEL" => cmd_del(p, session),
        "EXISTS" => cmd_exists(p, session),
        "KEYS" => cmd_keys(p, session),
        "SCAN" => cmd_scan(p, session),
        "TYPE" => cmd_type(p, session),
        "INCR" => cmd_counter(p, session, 1, "incr"),
        "DECR" => cmd_counter(p, session, -1, "decr"),
        "EXPIRE" => cmd_expire(p, session),
        "TTL" => cmd_ttl(p, session),
        "LPUSH" => cmd_push(p, session, true, "lpush"),
        "RPUSH" => cmd_push(p, session, false, "rpush"),
        "LRANGE" => cmd_lrange(p, session),
        "SADD" => cmd_sadd(p, session),
        "SMEMBERS" => cmd_smembers(p, session),
        "HSET" => cmd_hset(p, session),
        "HGET" => cmd_hget(p, session),
        "HGETALL" => cmd_hgetall(p, session),
        // dangerous, side-effect free
        "SAVE" => cmd_save(p),
        "BGSAVE" => cmd_bgsave(p),
        "BGREWRITEAOF" => cmd_bgrewriteaof(p),
        "REPLICAOF" => cmd_replicaof(p, "replicaof"),
        "SLAVEOF" => cmd_replicaof(p, "slaveof"),
        "DEBUG" => cmd_debug(p),
        "EVAL" => cmd_eval(p, "eval"),
        "EVALSHA" => cmd_eval(p, "evalsha"),
        "SCRIPT" => cmd_script(p),
        "FLUSHALL" => cmd_flush(p, session, true),
        "FLUSHDB" => cmd_flush(p, session, false),
        "SHUTDOWN" => cmd_shutdown(p),
        _ => cmd_unknown(name, p, limits),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn bulk(bytes: impl AsRef<[u8]>) -> RespFrame {
    RespFrame::Bulk(bytes.as_ref().to_vec())
}

fn parse_i64(bytes: &[u8]) -> Option<i64> {
    std::str::from_utf8(bytes).ok()?.parse::<i64>().ok()
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    std::str::from_utf8(bytes).ok()?.parse::<u64>().ok()
}

/// Map a store refusal onto the reply real Redis would send.
fn store_error(err: StoreError) -> RespFrame {
    match err {
        StoreError::WrongType => {
            RespFrame::error("WRONGTYPE Operation against a key holding the wrong kind of value")
        }
        StoreError::NotInteger => RespFrame::error("ERR value is not an integer or out of range"),
        StoreError::Overflow => RespFrame::error("ERR increment or decrement would overflow"),
        StoreError::ValueTooLarge { size, max } => RespFrame::Error(
            format!("ERR value is too large ({size} bytes, limit {max} bytes)").into_bytes(),
        ),
    }
}

/// Reply to a store result that only needs a frame.
fn from_store<T>(
    result: Result<T, StoreError>,
    simulated: &'static str,
    on_ok: impl FnOnce(T) -> RespFrame,
) -> Reply {
    match result {
        Ok(value) => Reply::frame(on_ok(value), simulated),
        Err(err) => Reply::frame(store_error(err), "rejected"),
    }
}

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// 40 lowercase hex characters: the shape of a SHA-1, cheap to compute and
/// impossible to confuse with a real digest of a script we refuse to run.
fn hex40(seed: u64) -> String {
    let a = mix64(seed);
    let b = mix64(a ^ 0x9e37_79b9_7f4a_7c15);
    let c = mix64(b ^ seed.rotate_left(17));
    format!("{a:016x}{b:016x}{:08x}", c as u32)
}

// ---------------------------------------------------------------------------
// connection / probing
// ---------------------------------------------------------------------------

fn cmd_ping(p: &[Vec<u8>]) -> Reply {
    match p {
        [] => Reply::frame(RespFrame::simple("PONG"), "pong"),
        [message] => Reply::frame(bulk(message), "pong"),
        _ => Reply::arity("ping"),
    }
}

fn cmd_echo(p: &[Vec<u8>]) -> Reply {
    match p {
        [message] => Reply::frame(bulk(message), "echo"),
        _ => Reply::arity("echo"),
    }
}

fn cmd_quit(p: &[Vec<u8>]) -> Reply {
    if !p.is_empty() {
        return Reply::arity("quit");
    }
    let mut reply = Reply::ok();
    reply.close_after = true;
    reply.simulated = "quit";
    reply
}

fn cmd_auth(
    p: &[Vec<u8>],
    session: &mut SessionState,
    limits: &Limits,
    record_passwords: bool,
) -> Reply {
    let (username, raw_password, arg_count) = match p {
        [password] => (None, password, 1_u8),
        [user, password] => (Some(user), password, 2_u8),
        _ => return Reply::arity("auth"),
    };

    let username = username.map(|user| {
        String::from_utf8_lossy(&user[..user.len().min(limits.max_stored_param_bytes)]).into_owned()
    });
    let password = if record_passwords {
        Some(
            String::from_utf8_lossy(
                &raw_password[..raw_password.len().min(limits.max_stored_param_bytes)],
            )
            .into_owned(),
        )
    } else {
        None
    };

    session.authenticated = true;
    session.auth_attempts = session.auth_attempts.saturating_add(1);

    let mut reply = Reply::ok();
    reply.simulated = "auth";
    reply.auth = Some(AuthAttempt {
        username,
        password_len: raw_password.len(),
        password,
        arg_count,
    });
    reply
}

fn cmd_hello(p: &[Vec<u8>], session: &mut SessionState) -> Reply {
    let version = match p.first() {
        None => session.resp_version,
        Some(raw) => match parse_i64(raw) {
            Some(2) => 2,
            Some(3) => 3,
            _ => {
                return Reply::error("NOPROTO unsupported protocol version", "rejected");
            }
        },
    };
    // Trailing `AUTH`/`SETNAME` tokens are accepted and ignored: they must never
    // turn into a credentials record, which belongs to `AUTH` alone.
    session.resp_version = version;

    let pairs = hello_pairs(version, session.conn_id);
    let frame = if version >= 3 {
        RespFrame::Map(pairs)
    } else {
        let mut flat = Vec::new();
        for (key, value) in pairs {
            flat.push(key);
            flat.push(value);
        }
        RespFrame::Array(flat)
    };
    Reply::frame(frame, "hello")
}

fn hello_pairs(version: u8, conn_id: u64) -> Vec<(RespFrame, RespFrame)> {
    vec![
        (bulk("server"), bulk("redis")),
        (bulk("version"), bulk(REDIS_VERSION)),
        (bulk("proto"), RespFrame::int(i64::from(version))),
        (
            bulk("id"),
            RespFrame::int(i64::try_from(conn_id).unwrap_or(i64::MAX)),
        ),
        (bulk("mode"), bulk("standalone")),
        (bulk("role"), bulk("master")),
        (bulk("modules"), RespFrame::Array(Vec::new())),
    ]
}

fn cmd_client(p: &[Vec<u8>], session: &mut SessionState, limits: &Limits) -> Reply {
    let (subcommand, rest) = match p {
        [subcommand, rest @ ..] => (subcommand, rest),
        [] => return Reply::arity("client"),
    };

    if subcommand.eq_ignore_ascii_case(b"SETINFO") {
        return match rest {
            [_, _] => Reply::ok(),
            _ => Reply::arity("client|setinfo"),
        };
    }
    if subcommand.eq_ignore_ascii_case(b"SETNAME") {
        return match rest {
            [name] => {
                session.client_name =
                    Some(name[..name.len().min(limits.max_stored_param_bytes)].to_vec());
                Reply::ok()
            }
            _ => Reply::arity("client|setname"),
        };
    }
    if subcommand.eq_ignore_ascii_case(b"GETNAME") {
        return match rest {
            [] => Reply::frame(
                match &session.client_name {
                    Some(name) => bulk(name),
                    None => RespFrame::Null,
                },
                "client_getname",
            ),
            _ => Reply::arity("client|getname"),
        };
    }
    if subcommand.eq_ignore_ascii_case(b"ID") {
        return match rest {
            [] => Reply::frame(
                RespFrame::int(i64::try_from(session.conn_id).unwrap_or(i64::MAX)),
                "client_id",
            ),
            _ => Reply::arity("client|id"),
        };
    }
    Reply::error(
        format!(
            "ERR Unknown subcommand or wrong number of arguments for '{}'. Try CLIENT HELP.",
            text::escape_bytes(subcommand, 32)
        ),
        "rejected",
    )
}

fn cmd_select(p: &[Vec<u8>], session: &mut SessionState) -> Reply {
    match p {
        [raw] => {
            let Some(index) = parse_i64(raw) else {
                return Reply::error("ERR value is not an integer or out of range", "rejected");
            };
            if index < 0 || index >= i64::from(DB_COUNT) {
                return Reply::error("ERR DB index is out of range", "rejected");
            }
            let index = index as u8;
            session.db_index = index;
            let mut reply = Reply::ok();
            reply.simulated = "select";
            reply
        }
        _ => Reply::arity("select"),
    }
}

// ---------------------------------------------------------------------------
// information gathering
// ---------------------------------------------------------------------------

fn cmd_info(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let section = match p {
        [] => None,
        [section] => Some(section.as_slice()),
        _ => return Reply::arity("info"),
    };
    let body = with_store(session, |store| info_body(section, session, store));
    Reply::frame(RespFrame::Bulk(body.into_bytes()), "info")
}

fn cmd_config(
    p: &[Vec<u8>],
    session: &mut SessionState,
    limits: &Limits,
    record_passwords: bool,
) -> Reply {
    let (subcommand, rest) = match p {
        [subcommand, rest @ ..] => (subcommand, rest),
        [] => return Reply::arity("config"),
    };

    if subcommand.eq_ignore_ascii_case(b"GET") {
        let [pattern] = rest else {
            return Reply::arity("config|get");
        };
        let pairs = with_store(session, |store| store.config_get(pattern));
        let mut flat = Vec::new();
        for (key, value) in pairs {
            flat.push(bulk(key));
            flat.push(bulk(value));
        }
        return Reply::frame(RespFrame::Array(flat), "config_get");
    }

    if subcommand.eq_ignore_ascii_case(b"SET") {
        let [key, value] = rest else {
            return Reply::arity("config|set");
        };
        with_store(session, |store| store.config_set(key, value));
        // `dir`, `dbfilename`, `requirepass`, `appendonly` and `save` are the
        // knobs an attacker uses to take a real server over; they matter more
        // than the rest of the config surface.
        const ALARMING: &[&[u8]] = &[
            b"dir",
            b"dbfilename",
            b"requirepass",
            b"appendonly",
            b"save",
        ];
        let alarming = ALARMING
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate));
        let budget = limits.max_stored_param_bytes.min(64);
        // This detail is printed as an ALERT and stored in
        // `security_events.detail`, so the value of a credential slot is masked
        // exactly like it is in `args_preview`.
        let (rendered_key, rendered_value) =
            render_config_pair(key, value, budget, record_passwords);
        let detail = format!(
            "CONFIG SET {rendered_key} {rendered_value} (virtual config only, nothing was changed)"
        );
        let risk = if alarming {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        return Reply::ok().with_risk(risk, detail);
    }

    Reply::error(
        format!(
            "ERR Unknown subcommand or wrong number of arguments for '{}'. Try CONFIG HELP.",
            text::escape_bytes(subcommand, 32)
        ),
        "rejected",
    )
}

fn cmd_dbsize(p: &[Vec<u8>], session: &SessionState) -> Reply {
    if !p.is_empty() {
        return Reply::arity("dbsize");
    }
    let db = session.db_index;
    let keys = with_store(session, |store| store.db_size(db));
    let reported = i64::try_from(keys)
        .unwrap_or(i64::MAX)
        .saturating_add(DB_SIZE_FLOOR);
    Reply::frame(RespFrame::int(reported), "dbsize")
}

fn cmd_time(p: &[Vec<u8>]) -> Reply {
    if !p.is_empty() {
        return Reply::arity("time");
    }
    let now = timeutil::now();
    let seconds = timeutil::unix_secs(now);
    let micros = timeutil::unix_millis(now).rem_euclid(1_000) * 1_000;
    Reply::frame(
        RespFrame::Array(vec![bulk(seconds.to_string()), bulk(micros.to_string())]),
        "time",
    )
}

fn cmd_role(p: &[Vec<u8>]) -> Reply {
    if !p.is_empty() {
        return Reply::arity("role");
    }
    Reply::frame(
        RespFrame::Array(vec![
            bulk("master"),
            RespFrame::int(0),
            RespFrame::Array(Vec::new()),
        ]),
        "role",
    )
}

/// One `COMMAND` entry: `name, arity, flags, first_key, last_key, step`.
struct CommandSpec {
    name: &'static str,
    arity: i64,
    flags: &'static [&'static str],
    first_key: i64,
    last_key: i64,
    step: i64,
}

const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        name: "get",
        arity: 2,
        flags: &["readonly", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "set",
        arity: -3,
        flags: &["write", "denyoom"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "del",
        arity: -2,
        flags: &["write"],
        first_key: 1,
        last_key: -1,
        step: 1,
    },
    CommandSpec {
        name: "exists",
        arity: -2,
        flags: &["readonly", "fast"],
        first_key: 1,
        last_key: -1,
        step: 1,
    },
    CommandSpec {
        name: "keys",
        arity: 2,
        flags: &["readonly"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "scan",
        arity: -2,
        flags: &["readonly"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "type",
        arity: 2,
        flags: &["readonly", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "incr",
        arity: 2,
        flags: &["write", "denyoom", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "decr",
        arity: 2,
        flags: &["write", "denyoom", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "expire",
        arity: 3,
        flags: &["write", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "ttl",
        arity: 2,
        flags: &["readonly", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "lpush",
        arity: -3,
        flags: &["write", "denyoom", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "rpush",
        arity: -3,
        flags: &["write", "denyoom", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "lrange",
        arity: 4,
        flags: &["readonly"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "sadd",
        arity: -3,
        flags: &["write", "denyoom", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "smembers",
        arity: 2,
        flags: &["readonly"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "hset",
        arity: -4,
        flags: &["write", "denyoom", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "hget",
        arity: 3,
        flags: &["readonly", "fast"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "hgetall",
        arity: 2,
        flags: &["readonly"],
        first_key: 1,
        last_key: 1,
        step: 1,
    },
    CommandSpec {
        name: "ping",
        arity: -1,
        flags: &["fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "echo",
        arity: 2,
        flags: &["fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "auth",
        arity: -2,
        flags: &["noscript", "loading", "stale", "fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "hello",
        arity: -1,
        flags: &["noscript", "loading", "stale", "fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "select",
        arity: 2,
        flags: &["loading", "stale", "fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "info",
        arity: -1,
        flags: &["loading", "stale"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "config",
        arity: -2,
        flags: &["admin", "noscript", "loading", "stale"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "dbsize",
        arity: 1,
        flags: &["readonly", "fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "time",
        arity: 1,
        flags: &["loading", "stale", "fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "role",
        arity: 1,
        flags: &["noscript", "loading", "stale", "fast"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "save",
        arity: 1,
        flags: &["admin", "noscript"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
    CommandSpec {
        name: "eval",
        arity: -3,
        flags: &["noscript", "skip_monitor", "no-script"],
        first_key: 0,
        last_key: 0,
        step: 0,
    },
];

fn command_entry(spec: &CommandSpec) -> RespFrame {
    let mut flags = Vec::new();
    for flag in spec.flags {
        flags.push(bulk(*flag));
    }
    RespFrame::Array(vec![
        bulk(spec.name),
        RespFrame::int(spec.arity),
        RespFrame::Array(flags),
        RespFrame::int(spec.first_key),
        RespFrame::int(spec.last_key),
        RespFrame::int(spec.step),
    ])
}

fn lookup_spec(name: &[u8]) -> Option<&'static CommandSpec> {
    COMMAND_SPECS
        .iter()
        .find(|spec| spec.name.as_bytes().eq_ignore_ascii_case(name))
}

fn cmd_command(p: &[Vec<u8>]) -> Reply {
    let (subcommand, rest) = match p {
        [] => return Reply::frame(RespFrame::Array(all_command_entries()), "command"),
        [subcommand, rest @ ..] => (subcommand, rest),
    };

    if subcommand.eq_ignore_ascii_case(b"COUNT") {
        return match rest {
            [] => Reply::frame(
                RespFrame::int(i64::try_from(COMMAND_SPECS.len()).unwrap_or(i64::MAX)),
                "command_count",
            ),
            _ => Reply::arity("command|count"),
        };
    }

    if subcommand.eq_ignore_ascii_case(b"DOCS") {
        let mut pairs = Vec::new();
        for spec in COMMAND_SPECS {
            let mut doc = vec![
                (
                    bulk("summary"),
                    bulk(format!("simulated {} implementation", spec.name)),
                ),
                (bulk("since"), bulk("7.0.0")),
                (bulk("group"), bulk("generic")),
            ];
            doc.shrink_to_fit();
            pairs.push((bulk(spec.name), RespFrame::Map(doc)));
        }
        return Reply::frame(RespFrame::Map(pairs), "command_docs");
    }

    if subcommand.eq_ignore_ascii_case(b"INFO") {
        let entries = if rest.is_empty() {
            all_command_entries()
        } else {
            let mut entries = Vec::new();
            for name in rest {
                entries.push(match lookup_spec(name) {
                    Some(spec) => command_entry(spec),
                    None => RespFrame::Null,
                });
            }
            entries
        };
        return Reply::frame(RespFrame::Array(entries), "command_info");
    }

    Reply::error(
        format!(
            "ERR Unknown subcommand or wrong number of arguments for '{}'. Try COMMAND HELP.",
            text::escape_bytes(subcommand, 32)
        ),
        "rejected",
    )
}

fn all_command_entries() -> Vec<RespFrame> {
    COMMAND_SPECS.iter().map(command_entry).collect()
}

fn cmd_module(p: &[Vec<u8>], limits: &Limits) -> Reply {
    let (subcommand, rest) = match p {
        [subcommand, rest @ ..] => (subcommand, rest),
        [] => return Reply::arity("module"),
    };

    if subcommand.eq_ignore_ascii_case(b"LIST") {
        // Nothing is loaded, and nothing ever will be: this process has no
        // loader to reach.
        return match rest {
            [] => Reply::frame(RespFrame::Array(Vec::new()), "module_list"),
            _ => Reply::arity("module|list"),
        };
    }

    if subcommand.eq_ignore_ascii_case(b"LOAD") {
        let budget = limits.max_stored_param_bytes.min(UNKNOWN_ARGS_MAX);
        return match rest {
            [path] => Reply::critical(
                RespFrame::error("ERR Error loading the extension. Please check the server logs."),
                "simulated_module_load",
                format!(
                    "MODULE LOAD {} attempted; no loader exists on this server",
                    text::escape_bytes(path, budget)
                ),
            ),
            _ => Reply::arity("module|load")
                .with_risk(RiskLevel::Critical, "MODULE LOAD arity fuzzing"),
        };
    }

    if subcommand.eq_ignore_ascii_case(b"UNLOAD") {
        let budget = limits.max_stored_param_bytes.min(UNKNOWN_ARGS_MAX);
        return match rest {
            [name] => Reply::critical(
                RespFrame::error("ERR Error unloading module"),
                "simulated_module_unload",
                format!(
                    "MODULE UNLOAD {} attempted; no module registry exists on this server",
                    text::escape_bytes(name, budget)
                ),
            ),
            _ => Reply::arity("module|unload")
                .with_risk(RiskLevel::Critical, "MODULE UNLOAD arity fuzzing"),
        };
    }

    Reply::error(
        format!(
            "ERR Unknown subcommand or wrong number of arguments for '{}'. Try MODULE HELP.",
            text::escape_bytes(subcommand, 32)
        ),
        "rejected",
    )
}

// ---------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------

fn cmd_get(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key] = p else {
        return Reply::arity("get");
    };
    let db = session.db_index;
    match with_store(session, |store| store.get(db, key)) {
        Ok(Some(value)) => Reply::frame(bulk(value), "get"),
        Ok(None) => Reply::frame(RespFrame::Null, "get"),
        Err(err) => Reply::frame(store_error(err), "rejected"),
    }
}

fn cmd_set(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let (key, value, flags) = match p {
        [key, value, flags @ ..] => (key, value, flags),
        _ => return Reply::arity("set"),
    };

    let mut ttl: Option<Duration> = None;
    let mut only_if_missing = false;
    let mut only_if_present = false;
    let mut index = 0;
    while index < flags.len() {
        let flag = &flags[index];
        if flag.eq_ignore_ascii_case(b"NX") {
            only_if_missing = true;
            index += 1;
            continue;
        }
        if flag.eq_ignore_ascii_case(b"XX") {
            only_if_present = true;
            index += 1;
            continue;
        }
        let in_millis = if flag.eq_ignore_ascii_case(b"EX") {
            false
        } else if flag.eq_ignore_ascii_case(b"PX") {
            true
        } else {
            return Reply::error("ERR syntax error", "rejected");
        };
        let Some(raw) = flags.get(index + 1) else {
            return Reply::error("ERR syntax error", "rejected");
        };
        let Some(amount) = parse_i64(raw) else {
            return Reply::error("ERR value is not an integer or out of range", "rejected");
        };
        if amount <= 0 {
            return Reply::error("ERR invalid expire time in 'set' command", "rejected");
        }
        let amount = amount as u64;
        ttl = Some(if in_millis {
            Duration::from_millis(amount)
        } else {
            Duration::from_secs(amount)
        });
        index += 2;
    }

    let db = session.db_index;
    let outcome = with_store(session, |store| {
        let exists = store.exists(db, key);
        if (only_if_missing && exists) || (only_if_present && !exists) {
            return Ok(false);
        }
        store.set_ex(db, key, value.clone(), ttl).map(|()| true)
    });

    match outcome {
        Ok(true) => Reply::ok(),
        Ok(false) => Reply::frame(RespFrame::Null, "set_skipped"),
        Err(err) => Reply::frame(store_error(err), "rejected"),
    }
}

fn cmd_del(p: &[Vec<u8>], session: &SessionState) -> Reply {
    if p.is_empty() {
        return Reply::arity("del");
    }
    let db = session.db_index;
    let removed = with_store(session, |store| {
        let mut count = 0_usize;
        for key in p {
            if store.del(db, key) {
                count += 1;
            }
        }
        count
    });
    Reply::frame(
        RespFrame::int(i64::try_from(removed).unwrap_or(i64::MAX)),
        "del",
    )
}

fn cmd_exists(p: &[Vec<u8>], session: &SessionState) -> Reply {
    if p.is_empty() {
        return Reply::arity("exists");
    }
    let db = session.db_index;
    let found = with_store(session, |store| {
        let mut count = 0_usize;
        for key in p {
            if store.exists(db, key) {
                count += 1;
            }
        }
        count
    });
    Reply::frame(
        RespFrame::int(i64::try_from(found).unwrap_or(i64::MAX)),
        "exists",
    )
}

fn cmd_keys(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [pattern] = p else {
        return Reply::arity("keys");
    };
    let db = session.db_index;
    let keys = with_store(session, |store| store.keys(db, pattern, KEYS_REPLY_LIMIT));
    let mut items = Vec::new();
    for key in keys {
        items.push(bulk(key));
    }
    Reply::frame(RespFrame::Array(items), "keys")
}

fn cmd_scan(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let (raw_cursor, options) = match p {
        [cursor, options @ ..] => (cursor, options),
        [] => return Reply::arity("scan"),
    };
    let Some(cursor) = parse_u64(raw_cursor) else {
        return Reply::error("ERR invalid cursor", "rejected");
    };

    let mut pattern: Option<&[u8]> = None;
    let mut count = SCAN_COUNT_DEFAULT;
    let mut index = 0;
    while index < options.len() {
        let option = &options[index];
        if option.eq_ignore_ascii_case(b"MATCH") {
            let Some(raw_pattern) = options.get(index + 1) else {
                return Reply::error("ERR syntax error", "rejected");
            };
            pattern = Some(raw_pattern);
            index += 2;
        } else if option.eq_ignore_ascii_case(b"COUNT") {
            let Some(raw_count) = options.get(index + 1) else {
                return Reply::error("ERR syntax error", "rejected");
            };
            let Some(amount) = parse_i64(raw_count) else {
                return Reply::error("ERR value is not an integer or out of range", "rejected");
            };
            if amount <= 0 {
                return Reply::error("ERR syntax error", "rejected");
            }
            count = usize::try_from(amount)
                .unwrap_or(SCAN_COUNT_MAX)
                .min(SCAN_COUNT_MAX);
            index += 2;
        } else {
            return Reply::error("ERR syntax error", "rejected");
        }
    }

    let db = session.db_index;
    let (next, keys) = with_store(session, |store| store.scan(db, cursor, pattern, count));
    let mut items = Vec::new();
    for key in keys {
        items.push(bulk(key));
    }
    Reply::frame(
        RespFrame::Array(vec![bulk(next.to_string()), RespFrame::Array(items)]),
        "scan",
    )
}

fn cmd_type(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key] = p else {
        return Reply::arity("type");
    };
    let db = session.db_index;
    let kind = with_store(session, |store| store.type_of(db, key));
    Reply::frame(RespFrame::Simple(kind.as_bytes().to_vec()), "type")
}

fn cmd_counter(p: &[Vec<u8>], session: &SessionState, delta: i64, command: &'static str) -> Reply {
    let [key] = p else {
        return Reply::arity(command);
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.incr_by(db, key, delta));
    from_store(result, command, RespFrame::int)
}

fn cmd_expire(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key, raw_seconds] = p else {
        return Reply::arity("expire");
    };
    let Some(seconds) = parse_i64(raw_seconds) else {
        return Reply::error("ERR value is not an integer or out of range", "rejected");
    };
    let db = session.db_index;
    let changed = if seconds <= 0 {
        // Redis deletes the key for a non-positive TTL.
        with_store(session, |store| store.del(db, key))
    } else {
        with_store(session, |store| {
            store.expire(db, key, Duration::from_secs(seconds as u64))
        })
    };
    Reply::frame(RespFrame::int(i64::from(changed)), "expire")
}

fn cmd_ttl(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key] = p else {
        return Reply::arity("ttl");
    };
    let db = session.db_index;
    let ttl = with_store(session, |store| store.ttl(db, key));
    Reply::frame(RespFrame::int(ttl), "ttl")
}

fn cmd_push(p: &[Vec<u8>], session: &SessionState, left: bool, command: &'static str) -> Reply {
    let (key, values) = match p {
        [key, values @ ..] if !values.is_empty() => (key, values),
        _ => return Reply::arity(command),
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.list_push(db, key, values, left));
    from_store(result, command, |len| {
        RespFrame::int(i64::try_from(len).unwrap_or(i64::MAX))
    })
}

fn cmd_lrange(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key, raw_start, raw_stop] = p else {
        return Reply::arity("lrange");
    };
    let (Some(start), Some(stop)) = (parse_i64(raw_start), parse_i64(raw_stop)) else {
        return Reply::error("ERR value is not an integer or out of range", "rejected");
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.list_range(db, key, start, stop));
    from_store(result, "lrange", |items| {
        RespFrame::Array(items.into_iter().map(bulk).collect())
    })
}

fn cmd_sadd(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let (key, members) = match p {
        [key, members @ ..] if !members.is_empty() => (key, members),
        _ => return Reply::arity("sadd"),
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.set_add(db, key, members));
    from_store(result, "sadd", |added| {
        RespFrame::int(i64::try_from(added).unwrap_or(i64::MAX))
    })
}

fn cmd_smembers(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key] = p else {
        return Reply::arity("smembers");
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.set_members(db, key));
    from_store(result, "smembers", |members| {
        RespFrame::Array(members.into_iter().map(bulk).collect())
    })
}

fn cmd_hset(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key, fields @ ..] = p else {
        return Reply::arity("hset");
    };
    if fields.is_empty() || fields.len() % 2 != 0 {
        return Reply::arity("hset");
    }
    let mut pairs = Vec::new();
    let mut index = 0;
    while index + 1 < fields.len() {
        pairs.push((fields[index].clone(), fields[index + 1].clone()));
        index += 2;
    }
    let db = session.db_index;
    let result = with_store(session, |store| store.hash_set(db, key, &pairs));
    from_store(result, "hset", |added| {
        RespFrame::int(i64::try_from(added).unwrap_or(i64::MAX))
    })
}

fn cmd_hget(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key, field] = p else {
        return Reply::arity("hget");
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.hash_get(db, key, field));
    match result {
        Ok(Some(value)) => Reply::frame(bulk(value), "hget"),
        Ok(None) => Reply::frame(RespFrame::Null, "hget"),
        Err(err) => Reply::frame(store_error(err), "rejected"),
    }
}

fn cmd_hgetall(p: &[Vec<u8>], session: &SessionState) -> Reply {
    let [key] = p else {
        return Reply::arity("hgetall");
    };
    let db = session.db_index;
    let result = with_store(session, |store| store.hash_get_all(db, key));
    from_store(result, "hgetall", |fields| {
        let mut items = Vec::new();
        for (field, value) in fields {
            items.push(bulk(field));
            items.push(bulk(value));
        }
        RespFrame::Array(items)
    })
}

// ---------------------------------------------------------------------------
// dangerous commands: plausible replies, zero side effects
// ---------------------------------------------------------------------------

fn cmd_save(p: &[Vec<u8>]) -> Reply {
    if !p.is_empty() {
        return Reply::arity("save").with_risk(RiskLevel::Critical, "SAVE arity fuzzing");
    }
    Reply::critical(
        RespFrame::ok(),
        "simulated_save",
        "SAVE requested; no RDB snapshot was written",
    )
}

fn cmd_bgsave(p: &[Vec<u8>]) -> Reply {
    match p {
        [] => Reply::critical(
            RespFrame::simple("Background saving started"),
            "simulated_save",
            "BGSAVE requested; no RDB snapshot was written",
        ),
        [mode] if mode.eq_ignore_ascii_case(b"SCHEDULE") => Reply::critical(
            RespFrame::simple("Background saving started"),
            "simulated_save",
            "BGSAVE SCHEDULE requested; no RDB snapshot was written",
        ),
        _ => Reply::arity("bgsave").with_risk(RiskLevel::Critical, "BGSAVE arity fuzzing"),
    }
}

fn cmd_bgrewriteaof(p: &[Vec<u8>]) -> Reply {
    if !p.is_empty() {
        return Reply::arity("bgrewriteaof")
            .with_risk(RiskLevel::Critical, "BGREWRITEAOF arity fuzzing");
    }
    Reply::critical(
        RespFrame::simple("Background append only file rewriting started"),
        "simulated_bgrewriteaof",
        "BGREWRITEAOF requested; no AOF file was rewritten",
    )
}

fn cmd_replicaof(p: &[Vec<u8>], command: &'static str) -> Reply {
    let [host, port] = p else {
        return Reply::arity(command)
            .with_risk(RiskLevel::Critical, format!("{command} arity fuzzing"));
    };
    Reply::critical(
        RespFrame::ok(),
        "simulated_replicaof",
        format!(
            "REPLICAOF {} {} requested; replication request ignored, no outbound connection opened",
            text::escape_bytes(host, 64),
            text::escape_bytes(port, 16)
        ),
    )
}

fn cmd_debug(p: &[Vec<u8>]) -> Reply {
    let (subcommand, rest) = match p {
        [subcommand, rest @ ..] => (subcommand, rest),
        [] => {
            return Reply::arity("debug")
                .with_risk(RiskLevel::Critical, "DEBUG with no subcommand");
        }
    };

    // `DEBUG SLEEP` is the classic "is this thing real?" probe; answering
    // instantly is both safe and a plausible answer for a busy server.
    let accepted = if subcommand.eq_ignore_ascii_case(b"SLEEP") {
        matches!(rest, [_])
    } else if subcommand.eq_ignore_ascii_case(b"JMAP") {
        rest.is_empty()
    } else if subcommand.eq_ignore_ascii_case(b"SET-ACTIVE-EXPIRE") {
        matches!(rest, [_])
    } else {
        false
    };

    if accepted {
        return Reply::critical(
            RespFrame::ok(),
            "simulated_debug",
            format!(
                "DEBUG {} requested; handled without any effect",
                text::escape_bytes(subcommand, 32)
            ),
        );
    }

    // An unknown subcommand still gets the note: DEBUG is an administrative
    // tool and reaching for it is the signal, not the subcommand.
    if subcommand.eq_ignore_ascii_case(b"SLEEP")
        || subcommand.eq_ignore_ascii_case(b"JMAP")
        || subcommand.eq_ignore_ascii_case(b"SET-ACTIVE-EXPIRE")
    {
        return Reply::arity("debug").with_risk(
            RiskLevel::Critical,
            format!(
                "DEBUG {} with bad arguments",
                text::escape_bytes(subcommand, 32)
            ),
        );
    }

    Reply::critical(
        RespFrame::error("ERR DEBUG subcommand not supported"),
        "simulated_debug",
        format!(
            "DEBUG {} requested; subcommand not supported",
            text::escape_bytes(subcommand, 32)
        ),
    )
}

fn cmd_eval(p: &[Vec<u8>], command: &'static str) -> Reply {
    let (script, numkeys) = match p {
        [script, numkeys, ..] => (script, numkeys),
        _ => {
            return Reply::arity(command)
                .with_risk(RiskLevel::Critical, format!("{command} arity fuzzing"));
        }
    };
    if parse_i64(numkeys).is_none() {
        return Reply::error("ERR value is not an integer or out of range", "rejected").with_risk(
            RiskLevel::Critical,
            format!("{command} with a non numeric key count"),
        );
    }
    Reply::critical(
        // Static text: the submitted script never reaches the wire, the log or
        // the database, and no evaluator is ever invoked.
        RespFrame::error(
            "ERR Error compiling script (new function): user_script:1: function not available",
        ),
        "simulated_eval",
        format!(
            "{command} with a {}-byte script was refused; no script engine exists on this server",
            script.len()
        ),
    )
}

fn cmd_script(p: &[Vec<u8>]) -> Reply {
    let (subcommand, rest) = match p {
        [subcommand, rest @ ..] => (subcommand, rest),
        [] => return Reply::arity("script"),
    };

    if subcommand.eq_ignore_ascii_case(b"LOAD") {
        let [body] = rest else {
            return Reply::arity("script|load")
                .with_risk(RiskLevel::Critical, "SCRIPT LOAD arity fuzzing");
        };
        // A SHA-1 shaped answer, derived locally from the body length and
        // content so repeated loads of the same script agree. Nothing is stored.
        let digest = hex40(fnv1a(body, 0xcbf2_9ce4_8422_2325));
        return Reply::critical(
            RespFrame::Bulk(digest.into_bytes()),
            "simulated_script_load",
            format!(
                "SCRIPT LOAD of a {}-byte script was refused; no script cache exists on this server",
                body.len()
            ),
        );
    }

    if subcommand.eq_ignore_ascii_case(b"FLUSH") {
        return match rest {
            [] | [_] => Reply::critical(
                RespFrame::ok(),
                "simulated_script_load",
                "SCRIPT FLUSH requested; the (empty) script cache stayed empty",
            ),
            _ => Reply::arity("script|flush"),
        };
    }

    Reply::error(
        format!(
            "ERR Unknown subcommand or wrong number of arguments for '{}'. Try SCRIPT HELP.",
            text::escape_bytes(subcommand, 32)
        ),
        "rejected",
    )
}

fn cmd_flush(p: &[Vec<u8>], session: &SessionState, everything: bool) -> Reply {
    let command = if everything { "flushall" } else { "flushdb" };
    match p {
        [] => {}
        [mode] if mode.eq_ignore_ascii_case(b"ASYNC") || mode.eq_ignore_ascii_case(b"SYNC") => {}
        _ => {
            return Reply::arity(command)
                .with_risk(RiskLevel::Critical, format!("{command} arity fuzzing"));
        }
    }

    let db = session.db_index;
    with_store(session, |store| {
        if everything {
            store.flush_all();
        } else {
            store.flush_db(db);
        }
    });
    Reply::critical(
        RespFrame::ok(),
        "simulated_flush",
        format!("{command} requested; only the virtual keyspace was cleared"),
    )
}

fn cmd_shutdown(p: &[Vec<u8>]) -> Reply {
    match p {
        [] => {}
        [mode] if mode.eq_ignore_ascii_case(b"NOSAVE") || mode.eq_ignore_ascii_case(b"SAVE") => {}
        _ => {
            return Reply::arity("shutdown")
                .with_risk(RiskLevel::Critical, "SHUTDOWN arity fuzzing");
        }
    }
    let mut reply = Reply::critical(
        RespFrame::ok(),
        "simulated_shutdown",
        "SHUTDOWN requested; shutdown request ignored, the server keeps running",
    );
    reply.close_after = true;
    reply
}

fn cmd_unknown(name: &str, p: &[Vec<u8>], limits: &Limits) -> Reply {
    let budget = limits.max_stored_param_bytes.min(UNKNOWN_ARGS_MAX);
    let mut echoed = String::new();
    for argument in p.iter().take(4) {
        if echoed.len() >= budget {
            break;
        }
        if !echoed.is_empty() {
            echoed.push(' ');
        }
        let remaining = budget - echoed.len();
        echoed.push_str(&text::escape_bytes(argument, remaining));
    }
    Reply::error(
        format!(
            "ERR unknown command '{}', with args beginning with: '{}'",
            text::escape_bytes(name.to_ascii_lowercase().as_bytes(), 32),
            echoed
        ),
        "unknown",
    )
}

// ---------------------------------------------------------------------------
// INFO
// ---------------------------------------------------------------------------

fn kv(out: &mut String, key: &str, value: impl std::fmt::Display) {
    let _ = write!(out, "{key}:{value}\r\n");
}

fn info_body(section: Option<&[u8]>, session: &SessionState, store: &mut VirtualStore) -> String {
    let everything = match section {
        None => true,
        Some(name) => {
            name.eq_ignore_ascii_case(b"all")
                || name.eq_ignore_ascii_case(b"default")
                || name.eq_ignore_ascii_case(b"everything")
        }
    };
    let wants = |name: &str| {
        everything
            || section.is_some_and(|requested| requested.eq_ignore_ascii_case(name.as_bytes()))
    };

    let now = timeutil::now();
    let mut out = String::new();
    if wants("server") {
        info_server(&mut out, store, now);
    }
    if wants("clients") {
        info_clients(&mut out);
    }
    if wants("memory") {
        info_memory(&mut out, store);
    }
    if wants("persistence") {
        info_persistence(&mut out, now);
    }
    if wants("stats") {
        info_stats(&mut out, session);
    }
    if wants("replication") {
        info_replication(&mut out, store);
    }
    if wants("cpu") {
        info_cpu(&mut out);
    }
    if wants("keyspace") {
        info_keyspace(&mut out, session, store);
    }
    out
}

fn info_server(out: &mut String, store: &VirtualStore, now: SystemTime) {
    let uptime = store.age().as_secs();
    out.push_str("# Server\r\n");
    kv(out, "redis_version", REDIS_VERSION);
    kv(out, "redis_git_sha1", "00000000");
    kv(out, "redis_git_dirty", 0);
    kv(out, "redis_build_id", "8f1e1d2a4c6b7f30");
    kv(out, "redis_mode", "standalone");
    kv(out, "os", "Linux 5.15.0-91-generic x86_64");
    kv(out, "arch_bits", 64);
    kv(out, "monotonic_clock", "POSIX clock_gettime");
    kv(out, "multiplexing_api", "epoll");
    kv(out, "atomicvar_api", "c11-builtin");
    kv(out, "process_id", 1);
    kv(
        out,
        "run_id",
        hex40(fnv1a(b"run-id", store.caps().max_keys as u64)),
    );
    kv(out, "tcp_port", 6379);
    kv(
        out,
        "server_time_usec",
        timeutil::unix_millis(now).saturating_mul(1_000),
    );
    kv(out, "uptime_in_seconds", uptime);
    kv(out, "uptime_in_days", uptime / 86_400);
    kv(out, "hz", 10);
    kv(out, "configured_hz", 10);
    kv(
        out,
        "lru_clock",
        timeutil::unix_secs(now).rem_euclid(1_000_000),
    );
    kv(out, "executable", "/usr/local/bin/redis-server");
    kv(out, "config_file", "/etc/redis/redis.conf");
    kv(out, "io_threads_active", 0);
}

fn info_clients(out: &mut String) {
    out.push_str("# Clients\r\n");
    kv(out, "connected_clients", 1);
    kv(out, "cluster_connections", 0);
    kv(out, "maxclients", 10000);
    kv(out, "client_recent_max_input_buffer", 20_480);
    kv(out, "client_recent_max_output_buffer", 0);
    kv(out, "blocked_clients", 0);
    kv(out, "tracking_clients", 0);
    kv(out, "clients_in_timeout_table", 0);
}

fn info_memory(out: &mut String, store: &VirtualStore) {
    let used = 1_048_576_usize.saturating_add(store.total_bytes());
    out.push_str("# Memory\r\n");
    kv(out, "used_memory", used);
    kv(out, "used_memory_human", "1.00M");
    kv(out, "used_memory_rss", used.saturating_mul(2));
    kv(out, "used_memory_rss_human", "2.00M");
    kv(out, "used_memory_peak", used);
    kv(out, "used_memory_peak_human", "1.00M");
    kv(out, "used_memory_lua", 31_744);
    kv(out, "maxmemory", 1_073_741_824);
    kv(out, "maxmemory_human", "1.00G");
    kv(out, "maxmemory_policy", "noeviction");
    kv(out, "mem_fragmentation_ratio", "2.00");
    kv(out, "mem_allocator", "jemalloc-5.3.0");
}

fn info_persistence(out: &mut String, now: SystemTime) {
    out.push_str("# Persistence\r\n");
    kv(out, "loading", 0);
    kv(out, "async_loading", 0);
    kv(out, "rdb_changes_since_last_save", 0);
    kv(out, "rdb_bgsave_in_progress", 0);
    kv(out, "rdb_last_save_time", timeutil::unix_secs(now));
    kv(out, "rdb_last_bgsave_status", "ok");
    kv(out, "rdb_last_bgsave_time_sec", -1);
    kv(out, "rdb_current_bgsave_time_sec", -1);
    kv(out, "rdb_last_cow_size", 0);
    kv(out, "aof_enabled", 0);
    kv(out, "aof_rewrite_in_progress", 0);
    kv(out, "aof_last_bgrewrite_status", "ok");
    kv(out, "aof_last_write_status", "ok");
}

fn info_stats(out: &mut String, session: &SessionState) {
    out.push_str("# Stats\r\n");
    kv(out, "total_connections_received", session.conn_id + 1);
    kv(out, "total_commands_processed", session.command_count);
    kv(out, "instantaneous_ops_per_sec", 0);
    kv(out, "total_net_input_bytes", 0);
    kv(out, "total_net_output_bytes", 0);
    kv(out, "rejected_connections", 0);
    kv(out, "sync_full", 0);
    kv(out, "sync_partial_ok", 0);
    kv(out, "sync_partial_err", 0);
    kv(out, "expired_keys", 0);
    kv(out, "evicted_keys", 0);
    kv(out, "keyspace_hits", 0);
    kv(out, "keyspace_misses", 0);
    kv(out, "pubsub_channels", 0);
    kv(out, "pubsub_patterns", 0);
    kv(out, "latest_fork_usec", 0);
    kv(out, "total_forks", 0);
    kv(out, "migrate_cached_sockets", 0);
}

fn info_replication(out: &mut String, store: &VirtualStore) {
    out.push_str("# Replication\r\n");
    kv(out, "role", "master");
    kv(out, "connected_slaves", 0);
    kv(out, "master_failover_state", "no-failover");
    kv(
        out,
        "master_replid",
        hex40(fnv1a(b"replid", store.caps().max_bytes as u64)),
    );
    kv(
        out,
        "master_replid2",
        "0000000000000000000000000000000000000000",
    );
    kv(out, "master_repl_offset", 0);
    kv(out, "second_repl_offset", -1);
    kv(out, "repl_backlog_active", 0);
    kv(out, "repl_backlog_size", 1_048_576);
    kv(out, "repl_backlog_first_byte_offset", 0);
    kv(out, "repl_backlog_histlen", 0);
}

fn info_cpu(out: &mut String) {
    out.push_str("# CPU\r\n");
    kv(out, "used_cpu_sys", "0.500000");
    kv(out, "used_cpu_user", "0.300000");
    kv(out, "used_cpu_sys_children", "0.000000");
    kv(out, "used_cpu_user_children", "0.000000");
    kv(out, "used_cpu_sys_main_thread", "0.500000");
    kv(out, "used_cpu_user_main_thread", "0.300000");
}

fn info_keyspace(out: &mut String, session: &SessionState, store: &mut VirtualStore) {
    out.push_str("# Keyspace\r\n");
    for db in 0..DB_COUNT {
        let (keys, expires) = store.db_stats(db);
        if db != 0 && db != session.db_index && keys == 0 {
            continue;
        }
        let reported = i64::try_from(keys)
            .unwrap_or(i64::MAX)
            .saturating_add(DB_SIZE_FLOOR);
        let _ = write!(
            out,
            "db{db}:keys={reported},expires={expires},avg_ttl=0\r\n"
        );
    }
}
