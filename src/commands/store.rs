//! Bounded, TTL aware in-memory keyspace that stands in for real Redis data.
//!
//! Caps come from [`StoreCaps`] (derived from [`crate::config::Limits`]) and are
//! enforced on every mutation: an attacker can never grow the honeypot's RSS by
//! pushing large values or millions of keys.
//!
//! The store also owns the *virtual* `CONFIG` map. `CONFIG SET` must answer
//! plausibly while changing nothing on the host, so the value an attacker sets
//! has to live somewhere that is shared by every connection but is not the real
//! process configuration — this keyspace is exactly that place, and it keeps
//! [`super::dispatch`] a pure function with no global mutable state.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use crate::config::Limits;

/// Logical databases a client may `SELECT` (0..=15).
pub const DB_COUNT: u8 = 16;

/// Expired entries are swept on every Nth touch, so dead keys cannot pile up
/// even if nobody ever asks for them again.
const SWEEP_EVERY: u64 = 32;

/// Default and hard ceiling for `SCAN COUNT`.
pub const SCAN_COUNT_DEFAULT: usize = 10;
pub const SCAN_COUNT_MAX: usize = 512;

/// Bounds for the virtual `CONFIG` map (a client can only ever grow it a little).
const CONFIG_MAX_ENTRIES: usize = 64;
const CONFIG_MAX_KEY_BYTES: usize = 128;
const CONFIG_MAX_VALUE_BYTES: usize = 512;

/// Caps for the virtual keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreCaps {
    pub max_keys: usize,
    pub max_bytes: usize,
    pub max_value_bytes: usize,
    pub max_ttl: Duration,
}

impl StoreCaps {
    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            max_keys: limits.store_max_keys,
            max_bytes: limits.store_max_bytes,
            max_value_bytes: limits.store_max_value_bytes,
            max_ttl: Duration::from_secs(limits.store_max_ttl_secs),
        }
    }
}

impl Default for StoreCaps {
    fn default() -> Self {
        Self::from_limits(&Limits::default())
    }
}

/// Why a mutation was refused. The Redis wording lives in the command table,
/// not here, so this module stays protocol agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// A single value (or key + value) is larger than the configured cap.
    ValueTooLarge { size: usize, max: usize },
    /// The key holds a different kind of value than the command needs.
    WrongType,
    /// The value is not a base-10 `i64`.
    NotInteger,
    /// `INCR`/`DECR` would leave the `i64` range.
    Overflow,
}

/// One virtual value. Keys, members and fields are raw bytes throughout: a
/// honeypot must never lossily convert what an attacker stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreValue {
    Str(Vec<u8>),
    List(Vec<Vec<u8>>),
    Set(BTreeSet<Vec<u8>>),
    Hash(BTreeMap<Vec<u8>, Vec<u8>>),
}

impl StoreValue {
    /// RESP `TYPE` name of this value.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Str(_) => "string",
            Self::List(_) => "list",
            Self::Set(_) => "set",
            Self::Hash(_) => "hash",
        }
    }

    /// Bytes charged against [`StoreCaps::max_value_bytes`].
    fn payload_bytes(&self) -> usize {
        match self {
            Self::Str(value) => value.len(),
            Self::List(items) => items.iter().map(Vec::len).sum(),
            Self::Set(members) => members.iter().map(Vec::len).sum(),
            Self::Hash(fields) => fields.iter().map(|(f, v)| f.len() + v.len()).sum(),
        }
    }
}

#[derive(Debug)]
struct Entry {
    value: StoreValue,
    expire_at: Option<Instant>,
    /// Insertion order ticket; also the key into [`VirtualStore::order`].
    seq: u64,
    /// `key.len() + value.payload_bytes()`, the charge against `total_bytes`.
    bytes: usize,
}

/// `(db_index, key)` — the same key name in two databases is two entries.
type MapKey = (u8, Vec<u8>);

/// `HGETALL` shape: `(field, value)` pairs in stable order.
pub type FieldPairs = Vec<(Vec<u8>, Vec<u8>)>;

/// The virtual keyspace.
#[derive(Debug)]
pub struct VirtualStore {
    caps: StoreCaps,
    created: Instant,
    entries: HashMap<MapKey, Entry>,
    /// Insertion order, used for eviction under cap pressure.
    order: BTreeMap<u64, MapKey>,
    total_bytes: usize,
    next_seq: u64,
    ops: u64,
    config: Vec<(String, String)>,
}

impl VirtualStore {
    pub fn new(caps: StoreCaps) -> Self {
        Self {
            caps,
            created: Instant::now(),
            entries: HashMap::new(),
            order: BTreeMap::new(),
            total_bytes: 0,
            next_seq: 1,
            ops: 0,
            config: default_config(),
        }
    }

    pub fn caps(&self) -> StoreCaps {
        self.caps
    }

    /// How long this store has existed, used by `INFO server` uptime fields.
    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    /// Bytes currently charged against [`StoreCaps::max_bytes`].
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of live keys in every database, after sweeping expired ones.
    pub fn live_keys(&mut self) -> usize {
        self.sweep();
        self.entries.len()
    }

    /// `(live keys, keys with a TTL)` for one database, after sweeping.
    pub fn db_stats(&mut self, db: u8) -> (usize, usize) {
        self.sweep();
        let mut keys = 0;
        let mut expires = 0;
        for ((entry_db, _), entry) in &self.entries {
            if *entry_db != db {
                continue;
            }
            keys += 1;
            if entry.expire_at.is_some() {
                expires += 1;
            }
        }
        (keys, expires)
    }

    // ---------------------------------------------------------------- strings

    /// `GET`. `Ok(None)` when missing, [`StoreError::WrongType`] otherwise.
    pub fn get(&mut self, db: u8, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.touch();
        self.expire_one(db, key);
        match self.entries.get(&(db, key.to_vec())) {
            None => Ok(None),
            Some(entry) => match &entry.value {
                StoreValue::Str(value) => Ok(Some(value.clone())),
                _ => Err(StoreError::WrongType),
            },
        }
    }

    /// `SET` with no expiry: replaces the value and drops any previous TTL.
    pub fn set(&mut self, db: u8, key: &[u8], value: Vec<u8>) -> Result<(), StoreError> {
        self.set_ex(db, key, value, None)
    }

    /// `SET` with an optional TTL. A TTL above [`StoreCaps::max_ttl`] is capped.
    pub fn set_ex(
        &mut self,
        db: u8,
        key: &[u8],
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), StoreError> {
        self.touch();
        self.expire_one(db, key);
        let expire_at = ttl.and_then(|ttl| deadline_from_now(self.normalize_ttl(ttl)));
        self.store_value(db, key, StoreValue::Str(value), expire_at)
    }

    /// Append/replace a whole [`StoreValue`], preserving `expire_at`.
    fn store_value(
        &mut self,
        db: u8,
        key: &[u8],
        value: StoreValue,
        expire_at: Option<Instant>,
    ) -> Result<(), StoreError> {
        let payload = value.payload_bytes();
        if payload > self.caps.max_value_bytes {
            return Err(StoreError::ValueTooLarge {
                size: payload,
                max: self.caps.max_value_bytes,
            });
        }
        let entry_bytes = key.len().saturating_add(payload);
        if entry_bytes > self.caps.max_bytes {
            return Err(StoreError::ValueTooLarge {
                size: entry_bytes,
                max: self.caps.max_bytes,
            });
        }

        let map_key: MapKey = (db, key.to_vec());
        // Take the old entry out first: eviction must never be able to reclaim
        // the slot we are about to write, and the byte accounting stays exact.
        let previous = self.entries.remove(&map_key);
        let (seq, is_new) = match previous.as_ref() {
            Some(entry) => {
                self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
                (entry.seq, false)
            }
            None => {
                let seq = self.next_seq;
                self.next_seq = self.next_seq.wrapping_add(1).max(1);
                (seq, true)
            }
        };

        self.make_room(entry_bytes, usize::from(is_new));

        self.total_bytes = self.total_bytes.saturating_add(entry_bytes);
        self.order.insert(seq, map_key.clone());
        self.entries.insert(
            map_key,
            Entry {
                value,
                expire_at,
                seq,
                bytes: entry_bytes,
            },
        );
        Ok(())
    }

    // ------------------------------------------------------------- key space

    /// `DEL` one key. Returns whether it existed.
    pub fn del(&mut self, db: u8, key: &[u8]) -> bool {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        if !self.entries.contains_key(&map_key) {
            return false;
        }
        self.remove_key(&map_key);
        true
    }

    /// `EXISTS` for one key.
    pub fn exists(&mut self, db: u8, key: &[u8]) -> bool {
        self.touch();
        self.expire_one(db, key);
        self.entries.contains_key(&(db, key.to_vec()))
    }

    /// `TYPE`: `none` when the key is missing.
    pub fn type_of(&mut self, db: u8, key: &[u8]) -> &'static str {
        self.touch();
        self.expire_one(db, key);
        match self.entries.get(&(db, key.to_vec())) {
            None => "none",
            Some(entry) => entry.value.kind(),
        }
    }

    /// `KEYS`: every matching key in `db`, sorted, truncated to `limit`.
    pub fn keys(&mut self, db: u8, pattern: &[u8], limit: usize) -> Vec<Vec<u8>> {
        self.touch();
        self.sweep();
        let mut out = Vec::new();
        for (entry_db, key) in self.entries.keys() {
            if *entry_db == db && glob_match(pattern, key) {
                out.push(key.clone());
            }
        }
        out.sort();
        out.truncate(limit);
        out
    }

    /// `SCAN`: an index cursor over the sorted key list of one database.
    ///
    /// The cursor is opaque to the client; a returned `0` means the iteration
    /// finished, which is the only guarantee real Redis gives either.
    pub fn scan(
        &mut self,
        db: u8,
        cursor: u64,
        pattern: Option<&[u8]>,
        count: usize,
    ) -> (u64, Vec<Vec<u8>>) {
        self.touch();
        self.sweep();
        let mut all = Vec::new();
        for (entry_db, key) in self.entries.keys() {
            if *entry_db != db {
                continue;
            }
            match pattern {
                Some(pattern) if !glob_match(pattern, key) => continue,
                _ => all.push(key.clone()),
            }
        }
        all.sort();

        let count = count.clamp(1, SCAN_COUNT_MAX);
        let start = usize::try_from(cursor).unwrap_or(usize::MAX);
        if start >= all.len() {
            return (0, Vec::new());
        }
        let end = start.saturating_add(count).min(all.len());
        let next = if end >= all.len() { 0 } else { end as u64 };
        (next, all[start..end].to_vec())
    }

    /// `DBSIZE` for one logical database.
    pub fn db_size(&mut self, db: u8) -> usize {
        self.db_stats(db).0
    }

    /// `EXPIRE`. Returns whether the key existed and got a new deadline.
    pub fn expire(&mut self, db: u8, key: &[u8], ttl: Duration) -> bool {
        self.touch();
        if !self.expire_one(db, key) {
            return false;
        }
        let ttl = self.normalize_ttl(ttl);
        let map_key: MapKey = (db, key.to_vec());
        let Some(entry) = self.entries.get_mut(&map_key) else {
            return false;
        };
        entry.expire_at = deadline_from_now(ttl);
        true
    }

    /// `TTL` in whole seconds: `-2` missing, `-1` no expiry, else remaining.
    pub fn ttl(&mut self, db: u8, key: &[u8]) -> i64 {
        self.touch();
        if !self.expire_one(db, key) {
            return -2;
        }
        let map_key: MapKey = (db, key.to_vec());
        let Some(entry) = self.entries.get(&map_key) else {
            return -2;
        };
        let Some(deadline) = entry.expire_at else {
            return -1;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        // Redis rounds TTL to the nearest second, so a fresh `EXPIRE k 1`
        // reports 1 rather than 0.
        i64::try_from(remaining.as_millis().div_ceil(1_000)).unwrap_or(i64::MAX)
    }

    // ---------------------------------------------------------------- numbers

    /// `INCR`/`DECR`. Keeps any TTL already set on the key, like Redis does.
    pub fn incr_by(&mut self, db: u8, key: &[u8], delta: i64) -> Result<i64, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let (current, expire_at) = match self.entries.get(&map_key) {
            None => (0, None),
            Some(entry) => match &entry.value {
                StoreValue::Str(value) => (
                    parse_int(value).ok_or(StoreError::NotInteger)?,
                    entry.expire_at,
                ),
                _ => return Err(StoreError::WrongType),
            },
        };
        let next = current.checked_add(delta).ok_or(StoreError::Overflow)?;
        let encoded = next.to_string().into_bytes();
        self.store_value(db, key, StoreValue::Str(encoded), expire_at)?;
        Ok(next)
    }

    // ------------------------------------------------------------------ lists

    /// `LPUSH`/`RPUSH`. Returns the new list length.
    pub fn list_push(
        &mut self,
        db: u8,
        key: &[u8],
        values: &[Vec<u8>],
        left: bool,
    ) -> Result<usize, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let (mut list, expire_at) = match self.entries.get(&map_key) {
            None => (Vec::new(), None),
            Some(entry) => match &entry.value {
                StoreValue::List(items) => (items.clone(), entry.expire_at),
                _ => return Err(StoreError::WrongType),
            },
        };
        for value in values {
            if left {
                // `LPUSH k a b c` leaves the list as `c b a`.
                list.insert(0, value.clone());
            } else {
                list.push(value.clone());
            }
        }
        let len = list.len();
        // `store_value` re-checks the payload cap and leaves the store untouched
        // on failure, so an oversized push cannot corrupt the existing list.
        self.store_value(db, key, StoreValue::List(list), expire_at)?;
        Ok(len)
    }

    /// `LRANGE` with Redis' negative index handling.
    pub fn list_range(
        &mut self,
        db: u8,
        key: &[u8],
        start: i64,
        stop: i64,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let Some(entry) = self.entries.get(&map_key) else {
            return Ok(Vec::new());
        };
        let StoreValue::List(items) = &entry.value else {
            return Err(StoreError::WrongType);
        };
        let len = i64::try_from(items.len()).unwrap_or(i64::MAX);
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut first = if start < 0 {
            len.saturating_add(start)
        } else {
            start
        };
        let mut last = if stop < 0 {
            len.saturating_add(stop)
        } else {
            stop
        };
        if first < 0 {
            first = 0;
        }
        if last >= len {
            last = len - 1;
        }
        if first > last || first >= len {
            return Ok(Vec::new());
        }
        let (from, to) = (first as usize, last as usize);
        Ok(items[from..=to].to_vec())
    }

    // ------------------------------------------------------------------- sets

    /// `SADD`. Returns how many members were new.
    pub fn set_add(
        &mut self,
        db: u8,
        key: &[u8],
        members: &[Vec<u8>],
    ) -> Result<usize, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let (mut set, expire_at) = match self.entries.get(&map_key) {
            None => (BTreeSet::new(), None),
            Some(entry) => match &entry.value {
                StoreValue::Set(members) => (members.clone(), entry.expire_at),
                _ => return Err(StoreError::WrongType),
            },
        };
        let mut added = 0;
        for member in members {
            if set.insert(member.clone()) {
                added += 1;
            }
        }
        self.store_value(db, key, StoreValue::Set(set), expire_at)?;
        Ok(added)
    }

    /// `SMEMBERS`, in stable sorted order.
    pub fn set_members(&mut self, db: u8, key: &[u8]) -> Result<Vec<Vec<u8>>, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let Some(entry) = self.entries.get(&map_key) else {
            return Ok(Vec::new());
        };
        match &entry.value {
            StoreValue::Set(members) => Ok(members.iter().cloned().collect()),
            _ => Err(StoreError::WrongType),
        }
    }

    // ----------------------------------------------------------------- hashes

    /// `HSET`. Returns how many fields were new.
    pub fn hash_set(
        &mut self,
        db: u8,
        key: &[u8],
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<usize, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let (mut hash, expire_at) = match self.entries.get(&map_key) {
            None => (BTreeMap::new(), None),
            Some(entry) => match &entry.value {
                StoreValue::Hash(fields) => (fields.clone(), entry.expire_at),
                _ => return Err(StoreError::WrongType),
            },
        };
        let mut added = 0;
        for (field, value) in pairs {
            if hash.insert(field.clone(), value.clone()).is_none() {
                added += 1;
            }
        }
        self.store_value(db, key, StoreValue::Hash(hash), expire_at)?;
        Ok(added)
    }

    /// `HGET`.
    pub fn hash_get(
        &mut self,
        db: u8,
        key: &[u8],
        field: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let Some(entry) = self.entries.get(&map_key) else {
            return Ok(None);
        };
        match &entry.value {
            StoreValue::Hash(fields) => Ok(fields.get(field).cloned()),
            _ => Err(StoreError::WrongType),
        }
    }

    /// `HGETALL` as `(field, value)` pairs, in stable sorted order.
    pub fn hash_get_all(&mut self, db: u8, key: &[u8]) -> Result<FieldPairs, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());
        let Some(entry) = self.entries.get(&map_key) else {
            return Ok(Vec::new());
        };
        match &entry.value {
            StoreValue::Hash(fields) => Ok(fields
                .iter()
                .map(|(field, value)| (field.clone(), value.clone()))
                .collect()),
            _ => Err(StoreError::WrongType),
        }
    }

    // --------------------------------------------------------------- flushing

    /// `FLUSHDB`: only the virtual data of one database disappears.
    pub fn flush_db(&mut self, db: u8) {
        self.touch();
        let doomed: Vec<MapKey> = self
            .entries
            .keys()
            .filter(|(entry_db, _)| *entry_db == db)
            .cloned()
            .collect();
        for key in doomed {
            self.remove_key(&key);
        }
    }

    /// `FLUSHALL`: every virtual database is cleared. Nothing else is touched.
    pub fn flush_all(&mut self) {
        self.touch();
        self.entries.clear();
        self.order.clear();
        self.total_bytes = 0;
    }

    // ---------------------------------------------------------- virtual config

    /// `CONFIG GET <pattern>` pairs, in the order the map was seeded.
    pub fn config_get(&self, pattern: &[u8]) -> Vec<(String, String)> {
        let lowered = pattern.to_ascii_lowercase();
        self.config
            .iter()
            .filter(|(key, _)| glob_match(&lowered, key.as_bytes()))
            .cloned()
            .collect()
    }

    /// `CONFIG SET <key> <value>`: recorded in the virtual map and nowhere else.
    pub fn config_set(&mut self, key: &[u8], value: &[u8]) {
        let key = String::from_utf8_lossy(&key[..key.len().min(CONFIG_MAX_KEY_BYTES)]).into_owned();
        let value =
            String::from_utf8_lossy(&value[..value.len().min(CONFIG_MAX_VALUE_BYTES)]).into_owned();
        if let Some(slot) = self.config.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
            return;
        }
        if self.config.len() < CONFIG_MAX_ENTRIES {
            self.config.push((key, value));
        }
    }

    // ---------------------------------------------------------------- internal

    /// Bump the operation counter and sweep expired entries now and then.
    fn touch(&mut self) {
        self.ops = self.ops.wrapping_add(1);
        if self.ops % SWEEP_EVERY == 0 {
            self.sweep();
        }
    }

    /// Drop every entry whose deadline has passed.
    fn sweep(&mut self) {
        let now = Instant::now();
        let mut dead = Vec::new();
        for (key, entry) in &self.entries {
            if matches!(entry.expire_at, Some(deadline) if deadline <= now) {
                dead.push(key.clone());
            }
        }
        for key in dead {
            self.remove_key(&key);
        }
    }

    /// Lazy expiry for one key. Returns whether the key is still alive.
    fn expire_one(&mut self, db: u8, key: &[u8]) -> bool {
        let map_key: MapKey = (db, key.to_vec());
        let expired = match self.entries.get(&map_key) {
            None => return false,
            Some(entry) => matches!(entry.expire_at, Some(deadline) if deadline <= Instant::now()),
        };
        if expired {
            self.remove_key(&map_key);
        }
        !expired
    }

    fn remove_key(&mut self, key: &MapKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.order.remove(&entry.seq);
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        }
    }

    fn normalize_ttl(&self, ttl: Duration) -> Duration {
        ttl.min(self.caps.max_ttl)
    }

    /// Evict oldest-first until `extra_bytes`/`extra_keys` fit again.
    ///
    /// Simple insertion-order eviction: a honeypot must keep answering under
    /// pressure, and an exact LRU clock is not worth the bookkeeping.
    fn make_room(&mut self, extra_bytes: usize, extra_keys: usize) {
        while self.entries.len().saturating_add(extra_keys) > self.caps.max_keys {
            if !self.evict_oldest() {
                break;
            }
        }
        while self.total_bytes.saturating_add(extra_bytes) > self.caps.max_bytes {
            if !self.evict_oldest() {
                break;
            }
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let Some((&seq, key)) = self.order.iter().next() else {
            return false;
        };
        let key = key.clone();
        self.order.remove(&seq);
        if let Some(entry) = self.entries.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        }
        true
    }
}

fn deadline_from_now(ttl: Duration) -> Option<Instant> {
    Instant::now().checked_add(ttl)
}

fn parse_int(bytes: &[u8]) -> Option<i64> {
    std::str::from_utf8(bytes).ok()?.parse::<i64>().ok()
}

/// Glob match with `*` and `?`, the two wildcards `KEYS`/`SCAN`/`CONFIG GET`
/// realistically need.
///
/// Iterative on purpose: the pattern is attacker controlled, so a recursive
/// matcher would be a stack-depth bug waiting to happen.
pub fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0_usize, 0_usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p + 1, t));
            p += 1;
        } else if let Some((resume_p, resume_t)) = star {
            p = resume_p;
            t = resume_t + 1;
            star = Some((resume_p, resume_t + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// The `CONFIG GET *` seed. These are the answers a real server would give,
/// not the values this process actually runs with.
fn default_config() -> Vec<(String, String)> {
    const SEED: &[(&str, &str)] = &[
        ("dir", "/var/lib/redis"),
        ("dbfilename", "dump.rdb"),
        ("requirepass", ""),
        ("maxmemory", "1073741824"),
        ("maxmemory-policy", "noeviction"),
        ("appendonly", "no"),
        ("appendfsync", "everysec"),
        ("save", "3600 1 300 100 60 10000"),
        ("bind", "0.0.0.0"),
        ("protected-mode", "yes"),
        ("port", "6379"),
        ("databases", "16"),
        ("timeout", "0"),
        ("tcp-keepalive", "300"),
        ("maxclients", "10000"),
        ("loglevel", "notice"),
        ("logfile", ""),
        ("daemonize", "no"),
        ("hz", "10"),
        ("slowlog-log-slower-than", "10000"),
        ("slowlog-max-len", "128"),
        ("rdbcompression", "yes"),
        ("rdbchecksum", "yes"),
        ("io-threads", "1"),
    ];
    SEED.iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(max_keys: usize, max_bytes: usize, max_value_bytes: usize) -> VirtualStore {
        VirtualStore::new(StoreCaps {
            max_keys,
            max_bytes,
            max_value_bytes,
            max_ttl: Duration::from_secs(3_600),
        })
    }

    #[test]
    fn glob_supports_star_and_question_mark() {
        assert!(glob_match(b"*", b"anything"));
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"user:*", b"user:42"));
        assert!(!glob_match(b"user:*", b"session:42"));
        assert!(glob_match(b"h?llo", b"hello"));
        assert!(!glob_match(b"h?llo", b"hllo"));
        assert!(glob_match(b"a*b*c", b"aXbYc"));
        assert!(!glob_match(b"a*b*c", b"aXbY"));
        assert!(glob_match(b"", b""));
        assert!(!glob_match(b"", b"x"));
    }

    #[test]
    fn oversized_value_is_refused_without_touching_the_store() {
        let mut s = store(16, 4_096, 16);
        s.set(0, b"keep", b"v".to_vec()).expect("set");
        let err = s.set(0, b"big", vec![b'x'; 64]).expect_err("must refuse");
        assert_eq!(err, StoreError::ValueTooLarge { size: 64, max: 16 });
        assert_eq!(s.get(0, b"keep").expect("get"), Some(b"v".to_vec()));
        assert_eq!(s.live_keys(), 1);
    }

    #[test]
    fn key_cap_evicts_oldest_and_keeps_answering() {
        let mut s = store(4, 1 << 20, 64);
        for i in 0..16_u8 {
            let key = [b'k', i];
            s.set(0, &key, vec![b'v'; 8]).expect("set");
        }
        assert_eq!(s.live_keys(), 4);
        // The most recently written keys survive, the first ones are gone.
        assert!(s.exists(0, b"k\x0f"));
        assert!(!s.exists(0, b"k\x00"));
    }

    #[test]
    fn ttl_rounds_up_and_lazy_expiry_frees_memory() {
        let mut s = store(8, 4_096, 64);
        s.set_ex(0, b"k", b"v".to_vec(), Some(Duration::from_secs(1)))
            .expect("set");
        assert_eq!(s.ttl(0, b"k"), 1);
        s.set_ex(0, b"gone", b"v".to_vec(), Some(Duration::from_millis(1)))
            .expect("set");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(s.get(0, b"gone").expect("get"), None);
        assert_eq!(s.total_bytes(), 2, "the expired entry released its bytes");
        assert_eq!(s.ttl(0, b"missing"), -2);
        s.set(0, b"plain", b"v".to_vec()).expect("set");
        assert_eq!(s.ttl(0, b"plain"), -1);
    }

    #[test]
    fn scan_walks_everything_then_returns_zero() {
        let mut s = store(16, 1 << 20, 64);
        for i in 0..5_u8 {
            s.set(0, &[b'k', i], b"v".to_vec()).expect("set");
        }
        let (mut cursor, mut seen) = (0_u64, 0_usize);
        loop {
            let (next, keys) = s.scan(0, cursor, None, 2);
            seen += keys.len();
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        assert_eq!(seen, 5);
    }

    #[test]
    fn databases_are_isolated_and_flush_scoped() {
        let mut s = store(16, 1 << 20, 64);
        s.set(0, b"k", b"zero".to_vec()).expect("set");
        s.set(3, b"k", b"three".to_vec()).expect("set");
        assert_eq!(s.get(0, b"k").expect("get"), Some(b"zero".to_vec()));
        s.flush_db(0);
        assert_eq!(s.get(0, b"k").expect("get"), None);
        assert_eq!(s.get(3, b"k").expect("get"), Some(b"three".to_vec()));
        s.flush_all();
        assert_eq!(s.live_keys(), 0);
        assert_eq!(s.total_bytes(), 0);
    }

    #[test]
    fn virtual_config_never_leaves_the_store() {
        let mut s = store(8, 4_096, 64);
        assert!(s.config_get(b"*").len() >= 9);
        let dir = s.config_get(b"dir");
        assert_eq!(dir.first().map(|(k, _)| k.as_str()), Some("dir"));
        s.config_set(b"dir", b"/tmp/evil");
        assert_eq!(
            s.config_get(b"dir").first().map(|(_, v)| v.as_str()),
            Some("/tmp/evil")
        );
    }
}
