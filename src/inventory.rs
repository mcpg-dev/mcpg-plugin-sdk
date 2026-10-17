//! Object inventories as MCP Events: each object a store lists that was
//! created, modified or deleted since the last listing is one
//! `object.changed` event, the same shape for a local folder, a glob, a
//! bucket or a remote directory.
//!
//! A plugin supplies only a listing; [`spawn_inventory_watch`] polls it,
//! diffs it against the listing the host has confirmed, and emits the
//! changes. The confirmed listing moves only on the host's
//! acknowledgements, so a change the host dropped shows again at the next
//! listing. The last event of each poll carries a snapshot of the confirmed
//! listing when it fits `snapshot_bytes`, so a restart from it is exact,
//! deletions included; past that budget a restart reports a gap and takes
//! the listing it finds as its baseline.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use mcpg_plugin_protocol::backend::{WatchError, WatchEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ffi::WatchHandleBox;

/// The glob pattern of [`WalkOptions::pattern`].
pub use glob::Pattern;

/// The event type every inventory strategy emits.
pub const OBJECT_CHANGED_EVENT_TYPE: &str = "object.changed";
/// Shortest interval between two listings.
pub const MIN_INTERVAL: Duration = Duration::from_millis(250);
/// Largest snapshot an event may carry: the host takes events up to 256 KiB.
pub const MAX_SNAPSHOT_BYTES: usize = 192 * 1024;
const CURSOR_VERSION: u64 = 1;
/// How long a woken watch waits for more notifications before it lists.
const CHANGE_SETTLE: Duration = Duration::from_millis(50);

/// Defaults of the inventory fields a store plugin's watch spec carries, for
/// `#[serde(default = "…")]`.
pub mod defaults {
    /// `snapshot_bytes`: about 2 000 objects.
    pub fn snapshot_bytes() -> usize {
        128 * 1024
    }
    /// `max_in_flight`.
    pub fn max_in_flight() -> usize {
        256
    }
    /// `ack_timeout_ms`.
    pub fn ack_timeout_ms() -> u64 {
        60_000
    }
    /// `max_files`.
    pub fn max_files() -> usize {
        10_000
    }
    /// `max_dirs`: directories one recursive walk lists.
    pub fn max_dirs() -> usize {
        1_000
    }
}

/// One object a store lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectEntry {
    /// The object's name in its store: a path relative to the folder, an
    /// object key.
    pub key: String,
    pub size: Option<u64>,
    /// When it last changed, Unix milliseconds.
    pub modified_at_ms: Option<i64>,
    pub etag: Option<String>,
    pub version: Option<String>,
}

impl ObjectEntry {
    /// A digest of what the store reports about the object: a change of any
    /// of it is a modification.
    fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        let parts = [
            self.size.map(|s| s.to_string()),
            self.modified_at_ms.map(|m| m.to_string()),
            self.etag.clone(),
            self.version.clone(),
        ];
        for part in parts {
            let part = part.unwrap_or_default();
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher.finalize().to_hex()[..12].to_owned()
    }
}

/// What a change did to its object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectOp {
    Created,
    Modified,
    Deleted,
}

/// Which objects the first listing of a fresh start reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStart {
    /// None: the objects there now are the baseline.
    #[default]
    Now,
    /// Every object there now, as created.
    Existing,
}

/// How an inventory watch runs, from its spec.
#[derive(Debug, Clone)]
pub struct InventoryOptions {
    /// The store kind, `data.store`: `file`, `s3`, `gcs`, `sftp`, …
    pub store: String,
    /// What the keys are relative to, `data.location`: a folder, a bucket.
    pub location: String,
    pub interval: Duration,
    pub start: InventoryStart,
    /// Largest snapshot of the confirmed listing an event carries.
    pub snapshot_bytes: usize,
    /// Most changes emitted ahead of the host's acknowledgements.
    pub max_in_flight: usize,
    /// How long a change waits for its acknowledgement before the next
    /// listing may report it again.
    pub ack_timeout: Duration,
}

impl InventoryOptions {
    /// Check the bounds a spec may set.
    pub fn validate(&self) -> Result<(), String> {
        if self.interval < MIN_INTERVAL {
            return Err(format!(
                "interval_ms must be at least {}",
                MIN_INTERVAL.as_millis()
            ));
        }
        if self.snapshot_bytes > MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "snapshot_bytes must be at most {MAX_SNAPSHOT_BYTES}"
            ));
        }
        if !(1..=1000).contains(&self.max_in_flight) {
            return Err("max_in_flight must be 1 to 1000".into());
        }
        if self.ack_timeout.is_zero() {
            return Err("ack_timeout_ms must be greater than 0".into());
        }
        Ok(())
    }
}

/// The position after a change: its sequence number, and on the last
/// change of a poll the confirmed listing it leads to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Cursor {
    v: u64,
    seq: u64,
    /// Key to digest, when it fit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snap: Option<BTreeMap<String, String>>,
}

/// A change emitted and not yet acknowledged.
#[derive(Debug, Clone)]
struct Pending {
    seq: u64,
    key: String,
    /// The digest it leads to; `None` for a deletion.
    digest: Option<String>,
    at: std::time::Instant,
}

/// The diff engine of one inventory watch.
pub struct Inventory {
    options: InventoryOptions,
    /// Key to digest, as the host stored.
    confirmed: BTreeMap<String, String>,
    /// The last details seen of each confirmed key, for deletions.
    seen: BTreeMap<String, ObjectEntry>,
    pending: Vec<Pending>,
    next_seq: u64,
    /// No baseline yet: the next listing sets it.
    baseline: Baseline,
    /// A resume that could not be exact reports a gap first.
    gap: bool,
    /// The snapshot outgrew its budget; said once.
    warned: bool,
    describe: Option<Describe>,
    /// An object that leaves the listing is forgotten without an event.
    quiet_removals: bool,
}

/// Details a plugin adds to the events of a poll, read only for what
/// changed: for each entry created or modified, in order, the fields to put
/// in its event's `data` beside the shared ones, or `None`.
pub type Describe = Box<dyn FnMut(&[ObjectEntry]) -> Vec<Option<Map<String, Value>>> + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Baseline {
    /// The listing is the baseline; nothing is reported.
    Silent,
    /// Every object listed is reported, as created.
    Report,
    /// The confirmed listing came from a snapshot.
    Known,
}

impl Inventory {
    /// The inventory a watch starts with, from the position the host
    /// stored, when there is one.
    pub fn new(options: InventoryOptions, resume: Option<Value>) -> Result<Self, WatchError> {
        let cursor: Option<Cursor> =
            resume
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| WatchError::InvalidSpec {
                    message: format!(
                        "{}: the stored position is not one an inventory wrote: {e}",
                        options.store
                    ),
                })?;
        let (confirmed, baseline, gap) = match cursor {
            None => (
                BTreeMap::new(),
                match options.start {
                    InventoryStart::Now => Baseline::Silent,
                    InventoryStart::Existing => Baseline::Report,
                },
                false,
            ),
            Some(Cursor {
                snap: Some(snap), ..
            }) => (snap, Baseline::Known, false),
            // A position without a snapshot: what changed while stopped is
            // not known exactly.
            Some(Cursor { snap: None, .. }) => (BTreeMap::new(), Baseline::Silent, true),
        };
        Ok(Self {
            options,
            confirmed,
            seen: BTreeMap::new(),
            pending: Vec::new(),
            next_seq: 0,
            baseline,
            gap,
            warned: false,
            describe: None,
            quiet_removals: false,
        })
    }

    /// Have `describe` add details to the events of what changed.
    pub fn with_describe(mut self, describe: Describe) -> Self {
        self.describe = Some(describe);
        self
    }

    /// Forget an object that leaves the listing without reporting it
    /// deleted: a feed that shows only its latest items.
    pub fn with_quiet_removals(mut self) -> Self {
        self.quiet_removals = true;
        self
    }

    /// The events a full `listing` makes, in order.
    pub fn poll(&mut self, listing: Vec<ObjectEntry>) -> Vec<WatchEvent> {
        // A change never acknowledged was lost on the way: report it again.
        let timeout = self.options.ack_timeout;
        self.pending.retain(|p| p.at.elapsed() < timeout);
        let mut events = Vec::new();
        if std::mem::take(&mut self.gap) {
            events.push(WatchEvent {
                gap: true,
                ..WatchEvent::default()
            });
        }
        let current: BTreeMap<String, ObjectEntry> = listing
            .into_iter()
            .map(|entry| (entry.key.clone(), entry))
            .collect();
        if self.baseline == Baseline::Silent {
            self.confirmed = current
                .iter()
                .map(|(key, entry)| (key.clone(), entry.digest()))
                .collect();
            self.seen = current;
            self.baseline = Baseline::Known;
            return events;
        }
        self.baseline = Baseline::Known;
        let mut changes: Vec<(ObjectOp, ObjectEntry, Option<String>)> = Vec::new();
        for (key, entry) in &current {
            let digest = entry.digest();
            if self.pending_digest(key) == Some(Some(&digest)) {
                continue;
            }
            match self.confirmed.get(key) {
                Some(known) if *known == digest => {}
                Some(_) => changes.push((ObjectOp::Modified, entry.clone(), Some(digest))),
                None => changes.push((ObjectOp::Created, entry.clone(), Some(digest))),
            }
        }
        let gone: Vec<String> = self
            .confirmed
            .keys()
            .filter(|key| !current.contains_key(*key) && self.pending_digest(key) != Some(None))
            .cloned()
            .collect();
        for key in gone {
            if self.quiet_removals {
                self.confirmed.remove(&key);
                self.seen.remove(&key);
                continue;
            }
            let last = self.seen.get(&key).cloned().unwrap_or_else(|| ObjectEntry {
                key: key.clone(),
                ..ObjectEntry::default()
            });
            changes.push((ObjectOp::Deleted, last, None));
        }
        for entry in current.values() {
            self.seen.insert(entry.key.clone(), entry.clone());
        }
        let room = self
            .options
            .max_in_flight
            .saturating_sub(self.pending.len());
        let take = changes.len().min(room);
        changes.truncate(take);
        let mut details = self.details(&changes);
        for (index, (op, entry, digest)) in changes.into_iter().enumerate() {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.pending.push(Pending {
                seq,
                key: entry.key.clone(),
                digest: digest.clone(),
                at: std::time::Instant::now(),
            });
            let snap = (index + 1 == take)
                .then(|| self.snapshot(&entry.key, digest.as_deref()))
                .flatten();
            let mut event = self.event(op, &entry, digest.as_deref(), seq, snap);
            if let (Some(extra), Some(Value::Object(data))) =
                (details.remove(&entry.key), event.data.as_mut())
            {
                for (field, value) in extra {
                    data.entry(field).or_insert(value);
                }
            }
            events.push(event);
        }
        events
    }

    /// What the plugin adds to the events of `changes`, by key.
    fn details(
        &mut self,
        changes: &[(ObjectOp, ObjectEntry, Option<String>)],
    ) -> HashMap<String, Map<String, Value>> {
        let Some(describe) = self.describe.as_mut() else {
            return HashMap::new();
        };
        let alive: Vec<ObjectEntry> = changes
            .iter()
            .filter(|(op, _, _)| *op != ObjectOp::Deleted)
            .map(|(_, entry, _)| entry.clone())
            .collect();
        if alive.is_empty() {
            return HashMap::new();
        }
        alive
            .iter()
            .zip(describe(&alive))
            .filter_map(|(entry, extra)| extra.map(|extra| (entry.key.clone(), extra)))
            .collect()
    }

    /// The digest of the pending change of `key`: `Some(None)` for a
    /// pending deletion, `None` when nothing is pending.
    fn pending_digest(&self, key: &str) -> Option<Option<&String>> {
        self.pending
            .iter()
            .rev()
            .find(|p| p.key == key)
            .map(|p| p.digest.as_ref())
    }

    /// The listing a restart from the change of `key` to `digest` may trust,
    /// when it fits the budget: the confirmed one with that change. Other
    /// changes still in flight stay out; a restart reports them again under
    /// the same event ids.
    fn snapshot(&mut self, key: &str, digest: Option<&str>) -> Option<BTreeMap<String, String>> {
        let mut snap = self.confirmed.clone();
        match digest {
            Some(digest) => {
                snap.insert(key.to_owned(), digest.to_owned());
            }
            None => {
                snap.remove(key);
            }
        }
        let size = serde_json::to_vec(&snap).map_or(usize::MAX, |b| b.len());
        if size <= self.options.snapshot_bytes {
            return Some(snap);
        }
        if !std::mem::replace(&mut self.warned, true) {
            tracing::warn!(
                store = %self.options.store,
                location = %self.options.location,
                objects = snap.len(),
                bytes = size,
                budget = self.options.snapshot_bytes,
                "inventory watch: the listing outgrew snapshot_bytes; a restart reports a gap \
                 and misses what changed while stopped"
            );
        }
        None
    }

    fn event(
        &self,
        op: ObjectOp,
        entry: &ObjectEntry,
        digest: Option<&str>,
        seq: u64,
        snap: Option<BTreeMap<String, String>>,
    ) -> WatchEvent {
        let mut hasher = blake3::Hasher::new();
        let op_name = serde_json::to_string(&op).unwrap_or_default();
        for part in [
            self.options.store.as_str(),
            self.options.location.as_str(),
            entry.key.as_str(),
            op_name.as_str(),
            digest.unwrap_or(""),
        ] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        let mut data = serde_json::json!({
            "op": op,
            "store": self.options.store,
            "location": self.options.location,
            "key": entry.key,
        });
        if let Some(size) = entry.size {
            data["size"] = Value::from(size);
        }
        let modified_at = entry
            .modified_at_ms
            .and_then(mcpg_plugin_protocol::occurred_at_from_millis);
        if let Some(at) = &modified_at {
            data["modifiedAt"] = Value::from(at.clone());
        }
        if let Some(etag) = &entry.etag {
            data["etag"] = Value::from(etag.clone());
        }
        if let Some(version) = &entry.version {
            data["version"] = Value::from(version.clone());
        }
        WatchEvent {
            event_id: Some(format!("obj-{}", &hasher.finalize().to_hex()[..32])),
            event_type: Some(OBJECT_CHANGED_EVENT_TYPE.to_owned()),
            occurred_at: if op == ObjectOp::Deleted {
                None
            } else {
                modified_at
            },
            data: Some(data),
            upstream_cursor: serde_json::to_value(Cursor {
                v: CURSOR_VERSION,
                seq,
                snap,
            })
            .ok(),
            ..WatchEvent::default()
        }
    }

    /// The host is done with change `seq`. Changes before it that it never
    /// acknowledged were dropped; they show again at the next listing.
    pub fn acknowledged(&mut self, position: &Value) {
        let Some(seq) = position.get("seq").and_then(Value::as_u64) else {
            return;
        };
        let Some(index) = self.pending.iter().position(|p| p.seq == seq) else {
            return;
        };
        let pending = self.pending.remove(index);
        self.pending.retain(|p| p.seq > seq);
        match pending.digest {
            Some(digest) => {
                self.confirmed.insert(pending.key, digest);
            }
            None => {
                self.confirmed.remove(&pending.key);
                self.seen.remove(&pending.key);
            }
        }
    }

    /// Changes in flight.
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Whether the window has room for another change.
    pub fn has_room(&self) -> bool {
        self.pending.len() < self.options.max_in_flight
    }
}

/// Whether `key`, a path with `/` between parts, matches `pattern`: `*`
/// stays within a part and `**` crosses them.
pub fn matches_key(pattern: &Pattern, key: &str) -> bool {
    let options = glob::MatchOptions {
        require_literal_separator: true,
        ..glob::MatchOptions::default()
    };
    pattern.matches_with(key, options)
}

/// One entry of a remote directory listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirItem {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    /// Unix milliseconds.
    pub modified_at_ms: Option<i64>,
}

/// How [`walk`] goes through a directory tree.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Go into subdirectories.
    pub recursive: bool,
    /// Keep only the files whose path relative to the root matches; `*`
    /// stays within a directory and `**` crosses them.
    pub pattern: Option<glob::Pattern>,
    /// Most files kept: the first in key order; past it the listing is cut,
    /// with a warning.
    pub max_files: usize,
    /// Most directories listed in one walk, in breadth-first name order.
    pub max_dirs: usize,
}

/// The files under a root, keyed by their path relative to it with `/`
/// between parts, in key order: `list_dir` lists one directory, given that
/// relative path (`""` for the root). Directories and files are taken in
/// name order, so a cut listing keeps the same objects from poll to poll.
pub fn walk<F>(options: &WalkOptions, mut list_dir: F) -> Result<Vec<ObjectEntry>, String>
where
    F: FnMut(&str) -> Result<Vec<DirItem>, String>,
{
    let mut entries = Vec::new();
    let mut dirs = std::collections::VecDeque::from([String::new()]);
    let mut listed = 0usize;
    while let Some(dir) = dirs.pop_front() {
        if listed == options.max_dirs {
            tracing::warn!(
                max_dirs = options.max_dirs,
                "inventory walk: more directories than max_dirs; the rest are not listed"
            );
            break;
        }
        listed += 1;
        let mut items = list_dir(&dir)?;
        items.sort_by(|a, b| a.name.cmp(&b.name));
        for item in items {
            if item.name.is_empty() || item.name == "." || item.name == ".." {
                continue;
            }
            let key = if dir.is_empty() {
                item.name.clone()
            } else {
                format!("{dir}/{}", item.name)
            };
            if item.is_dir {
                if options.recursive {
                    dirs.push_back(key);
                }
                continue;
            }
            if options
                .pattern
                .as_ref()
                .is_some_and(|p| !matches_key(p, &key))
            {
                continue;
            }
            entries.push(ObjectEntry {
                key,
                size: item.size,
                modified_at_ms: item.modified_at_ms,
                etag: None,
                version: None,
            });
        }
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries.dedup_by(|a, b| a.key == b.key);
    if entries.len() > options.max_files {
        tracing::warn!(
            listed = entries.len(),
            max_files = options.max_files,
            "inventory walk: more files than max_files; the listing is cut"
        );
        entries.truncate(options.max_files);
    }
    Ok(entries)
}

enum Wake {
    Ack(Value),
    /// List now: something told the plugin the store changed.
    Changed,
    Stop,
}

/// Wakes an inventory watch for an early listing, as a store's change
/// notification would.
#[derive(Clone)]
pub struct InventoryWaker(Sender<Wake>);

impl InventoryWaker {
    /// List now rather than at the next interval.
    pub fn wake(&self) {
        let _ = self.0.send(Wake::Changed);
    }
}

/// Boxed behind the opaque [`WatchHandleBox`].
struct InventoryState {
    wake: Sender<Wake>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

/// Start an inventory watch on its own thread: list with `list` every
/// `options.interval`, and emit the changes through `emit_event`. A resource
/// watch, on a URI that is not an MCP Events source, gets one bare change
/// per poll that changed anything. `list` returns the whole listing, or an
/// error that is logged and retried at the next poll.
pub fn spawn_inventory_watch<F>(
    resource_uri: &str,
    options: InventoryOptions,
    resume: Option<Value>,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    list: F,
) -> Result<WatchHandleBox, WatchError>
where
    F: FnMut() -> Result<Vec<ObjectEntry>, String> + Send + 'static,
{
    spawn_inventory_watch_with_waker(resource_uri, options, resume, emit_event, list)
        .map(|(handle, _)| handle)
}

/// [`spawn_inventory_watch`], with a waker that asks for an early listing.
pub fn spawn_inventory_watch_with_waker<F>(
    resource_uri: &str,
    options: InventoryOptions,
    resume: Option<Value>,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    list: F,
) -> Result<(WatchHandleBox, InventoryWaker), WatchError>
where
    F: FnMut() -> Result<Vec<ObjectEntry>, String> + Send + 'static,
{
    spawn_described_inventory_watch(resource_uri, options, resume, emit_event, list, None)
}

/// [`spawn_inventory_watch_with_waker`], with `describe` adding details to
/// the events of what changed: a listing stays cheap, and only a change is
/// read in full.
pub fn spawn_described_inventory_watch<F>(
    resource_uri: &str,
    options: InventoryOptions,
    resume: Option<Value>,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    list: F,
    describe: Option<Describe>,
) -> Result<(WatchHandleBox, InventoryWaker), WatchError>
where
    F: FnMut() -> Result<Vec<ObjectEntry>, String> + Send + 'static,
{
    let hooks = InventoryHooks {
        describe,
        ..InventoryHooks::default()
    };
    spawn_inventory_watch_hooked(resource_uri, options, resume, emit_event, list, hooks)
}

/// What a plugin changes about an inventory watch beyond its listing.
#[derive(Default)]
pub struct InventoryHooks {
    /// Details for the events of what changed.
    pub describe: Option<Describe>,
    /// Forget an object that leaves the listing without reporting it
    /// deleted.
    pub quiet_removals: bool,
}

/// [`spawn_inventory_watch_with_waker`], with `hooks`.
pub fn spawn_inventory_watch_hooked<F>(
    resource_uri: &str,
    options: InventoryOptions,
    resume: Option<Value>,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    mut list: F,
    hooks: InventoryHooks,
) -> Result<(WatchHandleBox, InventoryWaker), WatchError>
where
    F: FnMut() -> Result<Vec<ObjectEntry>, String> + Send + 'static,
{
    options
        .validate()
        .map_err(|message| WatchError::InvalidSpec {
            message: format!("{}: {message}", options.store),
        })?;
    let interval = options.interval;
    let store = options.store.clone();
    let mut inventory = Inventory::new(options, resume)?;
    if let Some(describe) = hooks.describe {
        inventory = inventory.with_describe(describe);
    }
    if hooks.quiet_removals {
        inventory = inventory.with_quiet_removals();
    }
    let event_source = mcpg_plugin_protocol::is_event_source(resource_uri);
    let uri = resource_uri.to_owned();
    let (wake, wakes): (Sender<Wake>, Receiver<Wake>) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name("mcpg-inventory-watch".to_owned())
        .spawn(move || {
            loop {
                if stop_thread.load(Ordering::Acquire) {
                    return;
                }
                if inventory.has_room() {
                    match list() {
                        Ok(listing) => {
                            let events = inventory.poll(listing);
                            if event_source {
                                for event in events {
                                    if let Ok(json) = serde_json::to_string(&event) {
                                        emit_event(&json);
                                    }
                                }
                            } else if events.iter().any(|e| e.event_type.is_some()) {
                                // A notification is never retried, so it is
                                // done with at once.
                                for event in &events {
                                    if let Some(position) = &event.upstream_cursor {
                                        inventory.acknowledged(position);
                                    }
                                }
                                emit_event(r#"{}"#);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(resource_uri = %uri, store = %store, error = %error, "inventory watch: listing failed; retrying at the next poll");
                        }
                    }
                }
                let deadline = std::time::Instant::now() + interval;
                loop {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    match wakes.recv_timeout(left) {
                        Ok(Wake::Ack(position)) => {
                            inventory.acknowledged(&position);
                            let mut changed = false;
                            loop {
                                match wakes.try_recv() {
                                    Ok(Wake::Ack(position)) => inventory.acknowledged(&position),
                                    Ok(Wake::Changed) => changed = true,
                                    Ok(Wake::Stop) | Err(TryRecvError::Disconnected) => return,
                                    Err(TryRecvError::Empty) => break,
                                }
                            }
                            if changed {
                                break;
                            }
                        }
                        // Let a burst of notifications settle into one
                        // listing.
                        Ok(Wake::Changed) => {
                            std::thread::sleep(CHANGE_SETTLE);
                            loop {
                                match wakes.try_recv() {
                                    Ok(Wake::Ack(position)) => inventory.acknowledged(&position),
                                    Ok(Wake::Changed) => {}
                                    Ok(Wake::Stop) | Err(TryRecvError::Disconnected) => return,
                                    Err(TryRecvError::Empty) => break,
                                }
                            }
                            break;
                        }
                        Ok(Wake::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                        Err(RecvTimeoutError::Timeout) => break,
                    }
                }
            }
        })
        .map_err(|e| WatchError::Subscribe {
            message: format!("inventory watch: cannot start its thread: {e}"),
        })?;
    let waker = InventoryWaker(wake.clone());
    let state = Box::new(InventoryState {
        wake,
        stop,
        join: Some(join),
    });
    Ok((WatchHandleBox(Box::into_raw(state) as *mut ()), waker))
}

/// Pass the host's acknowledgement of `position` to the watch `handle`
/// started by [`spawn_inventory_watch`].
pub fn acknowledge_inventory_watch(handle: &WatchHandleBox, position: &Value) {
    if handle.0.is_null() {
        return;
    }
    // SAFETY: the pointer `spawn_inventory_watch` returned, still owned by
    // the host, which never acknowledges after cancel.
    #[allow(unsafe_code)]
    let state = unsafe { &*(handle.0 as *const InventoryState) };
    let _ = state.wake.send(Wake::Ack(position.clone()));
}

/// Stop and join a watch started by [`spawn_inventory_watch`]. Idempotent
/// on a null handle; the host calls it once per handle.
pub fn cancel_inventory_watch(handle: WatchHandleBox) {
    if handle.0.is_null() {
        return;
    }
    // SAFETY: produced by `Box::into_raw` in `spawn_inventory_watch` and
    // round-tripped by the host exactly once.
    #[allow(unsafe_code)]
    let mut state = unsafe { Box::from_raw(handle.0 as *mut InventoryState) };
    state.stop.store(true, Ordering::Release);
    let _ = state.wake.send(Wake::Stop);
    if let Some(join) = state.join.take() {
        let _ = join.join();
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
