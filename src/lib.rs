//! `redis-honeypot-rs` — a tiny, high-interaction Redis honeypot.
//!
//! The crate is split into a thin binary ([`main`](../main/index.html)) and this
//! library so that integration tests can drive the real server in-process.
//!
//! Module map:
//!
//! * [`config`] — runtime configuration and hard resource limits.
//! * [`resp`] — hand written, streaming RESP2/RESP3 codec (no external parser).
//! * [`commands`] — pure, fully virtualised Redis command simulation.
//! * [`db`] — SQLite persistence (batched, off the network path) and stats.
//! * [`server`] — listener, admission control, shutdown.
//! * [`connection`] — per-connection protocol state machine.
//! * [`record`] — the single bounded record channel feeding SQLite.
//! * [`logging`] — human readable console events on top of `tracing`.
//! * [`text`] / [`timeutil`] — bounded escaping and UTC timestamps.

pub mod cli;
pub mod commands;
pub mod config;
pub mod connection;
pub mod db;
pub mod logging;
pub mod record;
pub mod resp;
pub mod server;
pub mod text;
pub mod timeutil;
