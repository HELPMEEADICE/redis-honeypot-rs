//! Bounded, TTL aware in-memory keyspace that stands in for real Redis data.
//!
//! Caps come from [`StoreCaps`] (derived from [`crate::config::Limits`]) and are
//! enforced on every mutation: an attacker can never grow the honeypot's RSS by
//! pushing large values or millions of keys.
//!
//! # The resource model
//!
//! Charging only `value.len()` per element is not enough. `RPUSH k "" "" ""`
//! carries zero payload bytes but still allocates one `Vec<u8>` header per
//! element, grows the deque's backing store and adds allocator bookkeeping. Two
//! numbers are therefore kept apart on purpose:
//!
//! * [`StoreValue::payload_bytes`] — the *logical* size, i.e. what real Redis
//!   would report for `STRLEN`/`MEMORY USAGE`-ish accounting. Bounded by
//!   [`StoreCaps::max_value_bytes`].
//! * [`StoreValue::charged_bytes`] — the *conservative heap estimate*: the
//!   payload plus [`ELEMENT_OVERHEAD`] per element. Bounded by
//!   [`StoreCaps::max_bytes`] together with the key name and [`KEY_OVERHEAD`].
//!
//! On top of that, a collection's element count is limited by
//! [`StoreCaps::max_collection_len`], so an empty-string flood hits a hard wall
//! instead of being amortised to zero.
//!
//! `charged_bytes` is a deliberate *lower bound* on real heap usage: it counts
//! one allocation per element plus the container node, not the allocator's own
//! rounding. It is conservative in the direction that matters — it never lets a
//! write through that the budget was meant to stop.
//!
//! The store also owns the *virtual* `CONFIG` map. `CONFIG SET` must answer
//! plausibly while changing nothing on the host, so the value an attacker sets
//! has to live somewhere that is shared by every connection but is not the real
//! process configuration — this keyspace is exactly that place, and it keeps
//! [`super::dispatch`] a pure function with no global mutable state.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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

/// Conservative per-element bookkeeping charged against the store budget.
///
/// One element is a `Vec<u8>` (24 B header inside the parent container), its
/// heap allocation (payload + allocator rounding) and, for the `BTreeSet` /
/// `BTreeMap` variants, the node's links and rebalancing slack. 32 bytes covers
/// the header plus node bookkeeping; the payload is charged separately. Without
/// this, a list of empty strings costs nothing while still consuming one
/// allocation per element.
pub const ELEMENT_OVERHEAD: usize = 32;

/// Per-key bookkeeping charged against the store budget.
///
/// [`Entry`] itself (value enum, deadline, sequence, byte count) plus the
/// `HashMap` bucket, the `BTreeMap` order node and the `(u8, Vec<u8>)` key with
/// its own heap allocation.
pub const KEY_OVERHEAD: usize = 64;

/// Bounds for the virtual keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreCaps {
    pub max_keys: usize,
    pub max_bytes: usize,
    pub max_value_bytes: usize,
    /// Maximum number of elements in one list, set or hash.
    pub max_collection_len: usize,
    pub max_ttl: Duration,
}

impl StoreCaps {
    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            max_keys: limits.store_max_keys,
            max_bytes: limits.store_max_bytes,
            max_value_bytes: limits.store_max_value_bytes,
            max_collection_len: limits.store_max_collection_len,
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
    /// A collection would hold more elements than the configured cap.
    TooManyElements { count: usize, max: usize },
    /// The key holds a different kind of value than the command needs.
    WrongType,
    /// The value is not a base-10 `i64`.
    NotInteger,
    /// `INCR`/`DECR` would leave the `i64` range.
    Overflow,
}

/// One virtual value. Keys, members and fields are raw bytes throughout: a
/// honeypot must never lossily convert what an attacker stored.
///
/// Lists are a [`VecDeque`] and not a [`Vec`]: `LPUSH` on a `Vec` is
/// `insert(0, …)`, which shifts the whole list, and repeating it turns a
/// thousand-element push into quadratic work. `push_front` is amortised `O(1)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreValue {
    Str(Vec<u8>),
    List(VecDeque<Vec<u8>>),
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

    /// Logical data bytes: what the attacker actually stored.
    ///
    /// Saturating throughout: an element's length always fits, but the *sum*
    /// must not be able to wrap (release builds have `overflow-checks = false`,
    /// so a wrapping sum would silently under-report and defeat the cap).
    fn payload_bytes(&self) -> usize {
        match self {
            Self::Str(value) => value.len(),
            Self::List(items) => items
                .iter()
                .fold(0_usize, |acc, item| acc.saturating_add(item.len())),
            Self::Set(members) => members
                .iter()
                .fold(0_usize, |acc, member| acc.saturating_add(member.len())),
            Self::Hash(fields) => fields.iter().fold(0_usize, |acc, (field, value)| {
                acc.saturating_add(field.len()).saturating_add(value.len())
            }),
        }
    }

    /// Number of allocated elements (always 1 for a string).
    fn element_count(&self) -> usize {
        match self {
            Self::Str(_) => 1,
            Self::List(items) => items.len(),
            Self::Set(members) => members.len(),
            Self::Hash(fields) => fields.len(),
        }
    }

    /// Conservative heap estimate: payload plus per-element bookkeeping.
    fn charged_bytes(&self) -> usize {
        charged_bytes(self.payload_bytes(), self.element_count())
    }
}

/// `payload + count * ELEMENT_OVERHEAD`, saturating.
fn charged_bytes(payload: usize, count: usize) -> usize {
    payload.saturating_add(count.saturating_mul(ELEMENT_OVERHEAD))
}

/// Total charge for one key: name, entry bookkeeping and the value itself.
fn charged_entry_bytes(key_len: usize, value: &StoreValue) -> usize {
    key_len
        .saturating_add(KEY_OVERHEAD)
        .saturating_add(value.charged_bytes())
}

#[derive(Debug)]
struct Entry {
    value: StoreValue,
    expire_at: Option<Instant>,
    /// Insertion order ticket; also the key into [`VirtualStore::order`].
    seq: u64,
    /// [`charged_entry_bytes`] for the key this entry now lives under.
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

    /// Replace the caps at runtime (hot reload).
    ///
    /// A lowered budget takes effect immediately: the oldest keys are evicted
    /// right here rather than at the next write, so `CONFIG`-time promises match
    /// what the process actually holds.
    pub fn set_caps(&mut self, caps: StoreCaps) {
        self.caps = caps;
        self.make_room(0, 0);
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
    ///
    /// Every cap is checked *before* the store is touched, so a refused write
    /// leaves the previous value, its TTL and the byte accounting exactly as
    /// they were.
    fn store_value(
        &mut self,
        db: u8,
        key: &[u8],
        value: StoreValue,
        expire_at: Option<Instant>,
    ) -> Result<(), StoreError> {
        self.check_write(key.len(), &value)?;
        let map_key: MapKey = (db, key.to_vec());
        let entry = match self.take_entry(&map_key) {
            Some(mut entry) => {
                entry.value = value;
                entry.expire_at = expire_at;
                entry
            }
            None => self.new_entry(value, expire_at),
        };
        self.put_entry(map_key, entry);
        Ok(())
    }

    // ------------------------------------------------------- write pre-flight

    /// Would `value` under `key_len` fit the caps? Nothing is mutated.
    fn check_write(&self, key_len: usize, value: &StoreValue) -> Result<(), StoreError> {
        self.check_projected(key_len, value.payload_bytes(), value.element_count())
    }

    /// The same three checks, from projected numbers, so an incremental
    /// mutation can be validated before it changes anything.
    fn check_projected(
        &self,
        key_len: usize,
        payload: usize,
        count: usize,
    ) -> Result<(), StoreError> {
        if payload > self.caps.max_value_bytes {
            return Err(StoreError::ValueTooLarge {
                size: payload,
                max: self.caps.max_value_bytes,
            });
        }
        if count > self.caps.max_collection_len {
            return Err(StoreError::TooManyElements {
                count,
                max: self.caps.max_collection_len,
            });
        }
        let charged = key_len
            .saturating_add(KEY_OVERHEAD)
            .saturating_add(charged_bytes(payload, count));
        // A value that can never fit, even with the whole store emptied, is
        // refused up front: evicting everything and *then* failing would be a
        // side effect of a write that never happened.
        if charged > self.caps.max_bytes {
            return Err(StoreError::ValueTooLarge {
                size: charged,
                max: self.caps.max_bytes,
            });
        }
        Ok(())
    }

    // ---------------------------------------------------------- entry plumbing

    /// Mint a sequence number for a brand new entry.
    fn new_entry(&mut self, value: StoreValue, expire_at: Option<Instant>) -> Entry {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1).max(1);
        Entry {
            value,
            expire_at,
            seq,
            bytes: 0,
        }
    }

    /// Take an entry out of the map so it can be mutated in place.
    ///
    /// Removing first buys three things at once: the value is moved, not
    /// cloned (`LPUSH` would otherwise copy the whole list); [`Self::make_room`]
    /// can never evict the key currently being rewritten; and the byte
    /// accounting stays exact even if the caller then gives up.
    fn take_entry(&mut self, map_key: &MapKey) -> Option<Entry> {
        let entry = self.entries.remove(map_key)?;
        self.order.remove(&entry.seq);
        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        Some(entry)
    }

    /// Re-insert an entry, evicting *other* keys until the budget fits.
    ///
    /// The charge is recomputed from the value that is actually stored, so the
    /// accounting can never drift away from the contents.
    fn put_entry(&mut self, map_key: MapKey, mut entry: Entry) {
        entry.bytes = charged_entry_bytes(map_key.1.len(), &entry.value);
        // `take_entry` already removed this key, so re-inserting always adds one.
        self.make_room(entry.bytes, 1);
        self.total_bytes = self.total_bytes.saturating_add(entry.bytes);
        self.order.insert(entry.seq, map_key.clone());
        self.entries.insert(map_key, entry);
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
    ///
    /// The existing list is mutated in place: it is moved out of the map, not
    /// cloned, and `LPUSH` uses `push_front` instead of `insert(0, …)`, so a
    /// thousand-element push stays linear instead of quadratic. Every cap is
    /// validated from the projected size *before* the first element is added.
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

        let (payload, count) = match self.entries.get(&map_key) {
            None => (0, 0),
            Some(entry) => match &entry.value {
                StoreValue::List(items) => (
                    items
                        .iter()
                        .fold(0_usize, |acc, item| acc.saturating_add(item.len())),
                    items.len(),
                ),
                _ => return Err(StoreError::WrongType),
            },
        };
        if values.is_empty() {
            return Ok(count);
        }
        let added_payload = values
            .iter()
            .fold(0_usize, |acc, value| acc.saturating_add(value.len()));
        self.check_projected(
            key.len(),
            payload.saturating_add(added_payload),
            count.saturating_add(values.len()),
        )?;

        let mut entry = match self.take_entry(&map_key) {
            Some(entry) => entry,
            None => self.new_entry(StoreValue::List(VecDeque::new()), None),
        };
        let StoreValue::List(items) = &mut entry.value else {
            // Unreachable: the type was checked above and the entry was created
            // as a list above. Restoring it unchanged keeps the store intact if
            // that ever stops being true.
            self.put_entry(map_key, entry);
            return Err(StoreError::WrongType);
        };
        for value in values {
            // `LPUSH k a b c` leaves the list as `c b a`.
            if left {
                items.push_front(value.clone());
            } else {
                items.push_back(value.clone());
            }
        }
        let len = items.len();
        self.put_entry(map_key, entry);
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
        // Cloned on purpose: the reply is serialised after the lock is released,
        // and the whole result is bounded by the per-key payload cap.
        Ok(items.range(from..=to).cloned().collect())
    }

    // ------------------------------------------------------------------- sets

    /// `SADD`. Returns how many members were new.
    ///
    /// The set is mutated in place. Membership is resolved *before* the
    /// mutation so the projected size (and therefore the cap decision) is exact
    /// rather than an over-estimate of "every argument is new".
    pub fn set_add(
        &mut self,
        db: u8,
        key: &[u8],
        members: &[Vec<u8>],
    ) -> Result<usize, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());

        let (payload, count) = match self.entries.get(&map_key) {
            None => (0, 0),
            Some(entry) => match &entry.value {
                StoreValue::Set(set) => (
                    set.iter()
                        .fold(0_usize, |acc, member| acc.saturating_add(member.len())),
                    set.len(),
                ),
                _ => return Err(StoreError::WrongType),
            },
        };

        // Exact projection: skip what is already a member and collapse repeats
        // inside `members` itself. The borrow of the stored set ends with this
        // block, before anything is mutated.
        let mut incoming: BTreeSet<&Vec<u8>> = BTreeSet::new();
        {
            let existing = match self.entries.get(&map_key) {
                Some(entry) => match &entry.value {
                    StoreValue::Set(set) => Some(set),
                    _ => None,
                },
                None => None,
            };
            for member in members {
                if !existing.is_some_and(|set| set.contains(member)) {
                    incoming.insert(member);
                }
            }
        }
        let added_payload = incoming
            .iter()
            .fold(0_usize, |acc, member| acc.saturating_add(member.len()));
        self.check_projected(
            key.len(),
            payload.saturating_add(added_payload),
            count.saturating_add(incoming.len()),
        )?;
        if incoming.is_empty() {
            return Ok(0);
        }

        let mut entry = match self.take_entry(&map_key) {
            Some(entry) => entry,
            None => self.new_entry(StoreValue::Set(BTreeSet::new()), None),
        };
        let StoreValue::Set(set) = &mut entry.value else {
            self.put_entry(map_key, entry);
            return Err(StoreError::WrongType);
        };
        let mut added = 0;
        for member in incoming {
            if set.insert(member.clone()) {
                added += 1;
            }
        }
        self.put_entry(map_key, entry);
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
    ///
    /// Same in-place contract as [`Self::set_add`]: the projected size is exact
    /// (a replaced field only changes the payload delta) and every cap is
    /// checked before the map is touched.
    pub fn hash_set(
        &mut self,
        db: u8,
        key: &[u8],
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<usize, StoreError> {
        self.touch();
        self.expire_one(db, key);
        let map_key: MapKey = (db, key.to_vec());

        let (payload, count) = match self.entries.get(&map_key) {
            None => (0, 0),
            Some(entry) => match &entry.value {
                StoreValue::Hash(fields) => (
                    fields.iter().fold(0_usize, |acc, (field, value)| {
                        acc.saturating_add(field.len()).saturating_add(value.len())
                    }),
                    fields.len(),
                ),
                _ => return Err(StoreError::WrongType),
            },
        };

        // Collapse repeats first: the last one wins, exactly like `HSET` on a
        // real server, so it must be charged once and counted once.
        let mut incoming: BTreeMap<&Vec<u8>, &Vec<u8>> = BTreeMap::new();
        for (field, value) in pairs {
            incoming.insert(field, value);
        }
        let mut new_payload = payload;
        let mut new_count = count;
        {
            let existing = match self.entries.get(&map_key) {
                Some(entry) => match &entry.value {
                    StoreValue::Hash(fields) => Some(fields),
                    _ => None,
                },
                None => None,
            };
            for (field, value) in &incoming {
                match existing.and_then(|fields| fields.get(*field)) {
                    Some(old) => {
                        new_payload = new_payload
                            .saturating_sub(old.len())
                            .saturating_add(value.len());
                    }
                    None => {
                        new_payload = new_payload
                            .saturating_add(field.len())
                            .saturating_add(value.len());
                        new_count = new_count.saturating_add(1);
                    }
                }
            }
        }
        self.check_projected(key.len(), new_payload, new_count)?;
        if incoming.is_empty() {
            return Ok(0);
        }

        let mut entry = match self.take_entry(&map_key) {
            Some(entry) => entry,
            None => self.new_entry(StoreValue::Hash(BTreeMap::new()), None),
        };
        let StoreValue::Hash(fields) = &mut entry.value else {
            self.put_entry(map_key, entry);
            return Err(StoreError::WrongType);
        };
        let mut added = 0;
        for (field, value) in incoming {
            if fields.insert(field.clone(), value.clone()).is_none() {
                added += 1;
            }
        }
        self.put_entry(map_key, entry);
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
            max_collection_len: Limits::default().store_max_collection_len,
            max_ttl: Duration::from_secs(3_600),
        })
    }

    /// A store whose collection element cap is easy to hit in a test.
    fn store_with_elements(max_elements: usize) -> VirtualStore {
        VirtualStore::new(StoreCaps {
            max_keys: 16,
            max_bytes: 1 << 20,
            max_value_bytes: 1 << 16,
            max_collection_len: max_elements,
            max_ttl: Duration::from_secs(3_600),
        })
    }

    /// The charge a single key with an empty-string list of `count` elements
    /// should carry: this is the number the empty-element flood has to move.
    fn empty_list_charge(key: &[u8], count: usize) -> usize {
        key.len()
            .saturating_add(KEY_OVERHEAD)
            .saturating_add(charged_bytes(0, count))
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
        let with_two = s.total_bytes();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(s.get(0, b"gone").expect("get"), None);
        // The surviving key is charged its own name, bookkeeping and payload.
        assert_eq!(
            s.total_bytes(),
            1 + KEY_OVERHEAD + charged_bytes(1, 1),
            "the expired entry released every byte it was charged"
        );
        assert!(s.total_bytes() < with_two);
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

    /// A lowered cap evicts immediately, and a raised one allocates nothing.
    #[test]
    fn set_caps_takes_effect_on_the_live_keyspace() {
        let mut s = store(64, 1 << 20, 64);
        for index in 0..20_u8 {
            s.set(0, &[b'k', index], vec![b'v'; 8]).expect("set");
        }
        assert_eq!(s.live_keys(), 20);
        let before = s.total_bytes();

        s.set_caps(StoreCaps {
            max_keys: 4,
            max_bytes: before / 4,
            max_value_bytes: 8,
            max_collection_len: 8,
            max_ttl: Duration::from_secs(60),
        });
        assert!(s.live_keys() <= 4, "the key cap must apply at once");
        assert!(
            s.total_bytes() <= before / 4,
            "the byte cap must apply at once"
        );

        // Raising the caps never invents data.
        let after = s.total_bytes();
        s.set_caps(StoreCaps::default());
        assert_eq!(s.total_bytes(), after);
        assert!(s.live_keys() > 0);
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

    // --------------------------------------------------- resource model (regr.)

    /// The headline bug: empty strings used to cost zero payload bytes, so a
    /// list could be grown until the process died. Now every element is charged
    /// its bookkeeping and the element count has a hard cap.
    #[test]
    fn empty_string_list_cannot_grow_past_the_element_cap() {
        let mut s = store_with_elements(8);
        let empties: Vec<Vec<u8>> = vec![Vec::new(); 8];
        assert_eq!(s.list_push(0, b"flood", &empties, false).expect("push"), 8);

        let before = s.total_bytes();
        assert_eq!(
            before,
            empty_list_charge(b"flood", 8),
            "eight empty elements must still be charged"
        );
        assert!(before > 0, "an empty-element list cannot be free");

        let err = s
            .list_push(0, b"flood", &[Vec::new()], false)
            .expect_err("the element cap must refuse the ninth element");
        assert_eq!(err, StoreError::TooManyElements { count: 9, max: 8 });
        // The refusal changed nothing.
        assert_eq!(s.total_bytes(), before);
        assert_eq!(
            s.list_range(0, b"flood", 0, -1).expect("range").len(),
            8,
            "a refused push must not truncate the list"
        );
    }

    /// Repeated identical empty elements are separate elements in a list: the
    /// charge has to move with the count, not with the (zero) payload.
    #[test]
    fn repeated_empty_elements_are_charged_each_time() {
        let mut s = store_with_elements(64);
        let mut last = 0;
        for expected in 1..=16_usize {
            let len = s
                .list_push(0, b"dup", &[Vec::new()], true)
                .expect("push empty");
            assert_eq!(len, expected);
            let now = s.total_bytes();
            assert_eq!(now, empty_list_charge(b"dup", expected));
            assert!(now > last, "the charge must grow with the element count");
            last = now;
        }
        // LPUSH order: each new element goes to the head.
        let items = s.list_range(0, b"dup", 0, -1).expect("range");
        assert_eq!(items.len(), 16);
        assert!(items.iter().all(Vec::is_empty));
    }

    /// A collection refused for its element count leaves the previous value and
    /// its TTL untouched — the write is atomic.
    #[test]
    fn refused_collection_writes_roll_back_completely() {
        let mut s = store_with_elements(4);
        s.set_ex(0, b"k", b"v".to_vec(), Some(Duration::from_secs(3_600)))
            .expect("set");
        let before_bytes = s.total_bytes();
        let before_ttl = s.ttl(0, b"k");

        // Wrong type first: adding to a string must not touch the store.
        let err = s
            .list_push(0, b"k", &[Vec::new()], false)
            .expect_err("a string is not a list");
        assert_eq!(err, StoreError::WrongType);
        assert_eq!(s.total_bytes(), before_bytes);
        assert_eq!(s.ttl(0, b"k"), before_ttl);
        assert_eq!(s.get(0, b"k").expect("get"), Some(b"v".to_vec()));

        // Then an element-cap refusal on a real list, which must keep its TTL.
        s.list_push(0, b"l", &[b"a".to_vec(), b"b".to_vec()], false)
            .expect("push");
        s.expire(0, b"l", Duration::from_secs(600));
        let bytes = s.total_bytes();
        let too_many = vec![b"c".to_vec(); 4];
        let err = s
            .list_push(0, b"l", &too_many, false)
            .expect_err("over the element cap");
        assert!(matches!(err, StoreError::TooManyElements { .. }));
        assert_eq!(s.total_bytes(), bytes);
        assert_eq!(s.ttl(0, b"l"), 600, "the TTL survived the refused write");
        assert_eq!(s.list_range(0, b"l", 0, -1).expect("range").len(), 2);
    }

    /// One huge key is refused by the per-value cap; the store keeps its bytes.
    #[test]
    fn single_huge_key_is_refused_and_nothing_else_is_evicted() {
        let mut s = store(8, 1 << 20, 64);
        s.set(0, b"small", b"v".to_vec()).expect("set");
        let before = s.total_bytes();
        let err = s
            .set(0, b"huge", vec![b'x'; 65])
            .expect_err("over the per-value cap");
        assert_eq!(err, StoreError::ValueTooLarge { size: 65, max: 64 });
        assert_eq!(s.total_bytes(), before, "a refused write evicts nothing");
        assert_eq!(s.live_keys(), 1);
    }

    /// Overwriting the same key a thousand times must not leak charge: the
    /// accounting is a function of the contents, not of the write count.
    #[test]
    fn repeated_overwrites_do_not_leak_charge() {
        let mut s = store(16, 1 << 20, 4_096);
        s.set(0, b"k", vec![b'a'; 100]).expect("set");
        let single = s.total_bytes();
        for round in 0..1_000_u32 {
            let payload = vec![b'a'; 100 + (round as usize % 7)];
            s.set(0, b"k", payload).expect("overwrite");
        }
        s.set(0, b"k", vec![b'a'; 100]).expect("set");
        assert_eq!(s.total_bytes(), single);
        assert_eq!(s.live_keys(), 1);
    }

    /// `store_max_bytes` is the real bound: pushing many lists cannot exceed it,
    /// and the store keeps answering by evicting rather than failing.
    #[test]
    fn total_bytes_never_exceeds_the_budget() {
        let mut s = VirtualStore::new(StoreCaps {
            max_keys: 1_000,
            max_bytes: 16 * 1_024,
            max_value_bytes: 4_096,
            max_collection_len: 128,
            max_ttl: Duration::from_secs(3_600),
        });
        let empties = vec![Vec::new(); 8];
        for index in 0..500_u32 {
            let key = format!("list:{index}").into_bytes();
            let _ = s.list_push(0, &key, &empties, false);
            assert!(
                s.total_bytes() <= 16 * 1_024,
                "charge {} exceeded the budget at key {index}",
                s.total_bytes()
            );
        }
        // Everything still answers.
        assert!(s.live_keys() > 0);
        assert!(s.db_size(0) > 0);
    }

    /// A value larger than the whole budget is refused before anything is
    /// evicted, so an impossible write cannot wipe the keyspace.
    #[test]
    fn impossible_write_does_not_evict_the_store() {
        let mut s = VirtualStore::new(StoreCaps {
            max_keys: 32,
            max_bytes: 1_024,
            max_value_bytes: 1 << 20,
            max_collection_len: 1 << 20,
            max_ttl: Duration::from_secs(3_600),
        });
        s.set(0, b"keep", b"v".to_vec()).expect("set");
        let err = s
            .set(0, b"impossible", vec![b'x'; 2_048])
            .expect_err("cannot ever fit");
        assert!(matches!(err, StoreError::ValueTooLarge { .. }));
        assert_eq!(s.get(0, b"keep").expect("get"), Some(b"v".to_vec()));
    }

    /// `LPUSH` keeps Redis order and stays linear: a thousand elements are
    /// pushed without the quadratic re-shift the old `insert(0, …)` caused.
    #[test]
    fn lpush_keeps_redis_order_and_scales() {
        let mut s = VirtualStore::new(StoreCaps {
            max_keys: 4,
            max_bytes: 1 << 20,
            max_value_bytes: 1 << 20,
            max_collection_len: 2_000,
            max_ttl: Duration::from_secs(3_600),
        });
        let started = Instant::now();
        for index in 0..1_000_u32 {
            let value = index.to_string().into_bytes();
            s.list_push(0, b"q", &[value], true).expect("lpush");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "1000 LPUSHes took {elapsed:?}; the list is still being re-shifted"
        );
        let items = s.list_range(0, b"q", 0, -1).expect("range");
        assert_eq!(items.len(), 1_000);
        assert_eq!(items[0], b"999".to_vec(), "LPUSH puts the newest first");
        assert_eq!(items[999], b"0".to_vec());

        // `LPUSH k a b c` leaves `c b a`.
        let mut s2 = store_with_elements(8);
        s2.list_push(
            0,
            b"multi",
            &[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            true,
        )
        .expect("push");
        let items = s2.list_range(0, b"multi", 0, -1).expect("range");
        assert_eq!(items, vec![b"c".to_vec(), b"b".to_vec(), b"a".to_vec()]);
    }

    /// Sets and hashes charge their members and refuse at the same cap, and a
    /// replaced hash field only moves the payload delta.
    #[test]
    fn set_and_hash_element_accounting() {
        let mut s = store_with_elements(4);
        // A set of four empty strings is one member, exactly like real Redis:
        // deduplication comes before charging, not after.
        let empties = vec![Vec::new(); 4];
        assert_eq!(s.set_add(0, b"s", &empties).expect("sadd"), 1);
        assert_eq!(
            s.total_bytes(),
            b"s".len() + KEY_OVERHEAD + charged_bytes(0, 1)
        );

        let distinct = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        assert_eq!(s.set_add(0, b"s", &distinct).expect("sadd"), 3);
        assert_eq!(
            s.total_bytes(),
            b"s".len() + KEY_OVERHEAD + charged_bytes(3, 4)
        );
        // Duplicates are neither counted nor charged a second time.
        let dup = vec![Vec::new(); 2];
        let added = s.set_add(0, b"s", &dup).expect("dup sadd");
        assert_eq!(added, 0);
        let err = s
            .set_add(0, b"s", &[b"d".to_vec()])
            .expect_err("over the element cap");
        assert_eq!(err, StoreError::TooManyElements { count: 5, max: 4 });

        let mut h = store_with_elements(4);
        h.hash_set(0, b"h", &[(b"f".to_vec(), Vec::new())])
            .expect("hset");
        let after_new = h.total_bytes();
        assert_eq!(after_new, b"h".len() + KEY_OVERHEAD + charged_bytes(1, 1));
        // Replacing an existing field with a same-size value changes nothing.
        h.hash_set(0, b"h", &[(b"f".to_vec(), Vec::new())])
            .expect("hset again");
        assert_eq!(h.total_bytes(), after_new);
        for index in 0..3_u32 {
            h.hash_set(0, b"h", &[(format!("g{index}").into_bytes(), Vec::new())])
                .expect("hset");
        }
        let err = h
            .hash_set(0, b"h", &[(b"full".to_vec(), Vec::new())])
            .expect_err("over the element cap");
        assert_eq!(err, StoreError::TooManyElements { count: 5, max: 4 });
    }

    /// Reads and writes from several threads keep the accounting consistent:
    /// the store is behind a `Mutex`, and a panicking or racing reader must not
    /// be able to leave `total_bytes` describing a different keyspace.
    #[test]
    fn concurrent_readers_and_writers_keep_the_accounting_consistent() {
        use std::sync::Arc;
        use std::sync::Mutex;

        let store = Arc::new(Mutex::new(VirtualStore::new(StoreCaps {
            max_keys: 64,
            max_bytes: 64 * 1_024,
            max_value_bytes: 4_096,
            max_collection_len: 64,
            max_ttl: Duration::from_secs(3_600),
        })));

        let mut threads = Vec::new();
        for worker in 0..4_u8 {
            let store = Arc::clone(&store);
            threads.push(std::thread::spawn(move || {
                for index in 0..250_u32 {
                    let key = format!("w{worker}:{index}").into_bytes();
                    let mut guard = store.lock().expect("lock");
                    match index % 4 {
                        0 => {
                            let _ = guard.set(0, &key, vec![b'v'; 32]);
                        }
                        1 => {
                            let empties = vec![Vec::new(); 2];
                            let _ = guard.list_push(0, &key, &empties, false);
                        }
                        2 => {
                            let _ = guard.set_add(0, &key, &[b"a".to_vec()]);
                        }
                        _ => {
                            let _ = guard.hash_set(0, &key, &[(b"f".to_vec(), b"v".to_vec())]);
                        }
                    }
                    // Reading back must not panic and must never observe a
                    // charge above the configured budget.
                    assert!(guard.total_bytes() <= 64 * 1_024);
                    let _ = guard.get(0, &key);
                    let _ = guard.live_keys();
                }
            }));
        }
        for thread in threads {
            thread.join().expect("worker thread");
        }

        let mut guard = store.lock().expect("lock");
        // Recompute the charge from scratch and compare it with the running
        // total: they may only differ if the accounting drifted.
        let recomputed: usize = guard
            .entries
            .iter()
            .map(|((_, key), entry)| charged_entry_bytes(key.len(), &entry.value))
            .fold(0_usize, usize::saturating_add);
        assert_eq!(guard.total_bytes, recomputed);
        guard.flush_all();
        assert_eq!(guard.total_bytes(), 0);
    }

    /// `set` after a long list keeps the list's charge, not the string's.
    #[test]
    fn replacing_a_collection_with_a_string_releases_its_charge() {
        let mut s = store_with_elements(32);
        let empties = vec![Vec::new(); 32];
        s.list_push(0, b"k", &empties, false).expect("push");
        let big = s.total_bytes();
        s.set(0, b"k", b"v".to_vec()).expect("set");
        assert!(s.total_bytes() < big);
        assert_eq!(
            s.total_bytes(),
            b"k".len() + KEY_OVERHEAD + charged_bytes(1, 1)
        );
        assert_eq!(s.type_of(0, b"k"), "string");
    }
}
