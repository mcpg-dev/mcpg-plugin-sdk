//! Message queues as MCP Events: each message a broker delivers is one
//! event, settled upstream only once the host has stored it.
//!
//! A plugin supplies a [`QueueSource`]: connect, receive, ack and release
//! for its broker. [`spawn_queue_watch`] runs it: it keeps at most
//! `max_in_flight` messages delivered and not yet settled, acks a message
//! when the host acknowledges its event, and releases it for redelivery when
//! the host has not done so in `ack_timeout`, so a message the host dropped
//! comes back. Delivery is at-least-once; a message id kept across
//! redeliveries, as [`WatchEvent::event_id`], lets the host take it once.
//!
//! One thread receives and one settles, so an acknowledgement never waits
//! for a receive to return; the source is shared between them.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mcpg_plugin_protocol::abi::FFI_MAX_PAYLOAD_BYTES;
use mcpg_plugin_protocol::backend::{WatchError, WatchEvent};
use serde_json::Value;

use crate::ffi::WatchHandleBox;

const CURSOR_VERSION: u64 = 1;
/// Longest wait between two connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_millis(500);

/// Defaults of the queue fields a broker plugin's watch spec carries, for
/// `#[serde(default = "…")]`.
pub mod defaults {
    /// `max_in_flight`.
    pub fn max_in_flight() -> usize {
        256
    }
    /// `ack_timeout_ms`.
    pub fn ack_timeout_ms() -> u64 {
        60_000
    }
    /// `max_body_bytes`: a body past it is left out of the event.
    pub fn max_body_bytes() -> usize {
        128 * 1024
    }
}

/// One message as the broker delivered it.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// The event the message makes; the helper sets its `upstream_cursor`.
    pub event: WatchEvent,
    /// What [`QueueSource::ack`] and [`QueueSource::release`] need to settle
    /// this delivery: a delivery tag, a receipt handle, an ack id.
    pub receipt: Value,
}

/// A broker's side of a queue watch. The receiving thread calls
/// [`connect`](Self::connect) and [`receive`](Self::receive); the settling
/// thread calls [`ack`](Self::ack) and [`release`](Self::release), possibly
/// while a receive is in progress.
pub trait QueueSource: Send + Sync + 'static {
    /// Open the connection: before the first receive, and again after a
    /// receive failed. A receipt from an older connection may still reach
    /// `ack` or `release`, and must then be left alone if the broker would
    /// refuse it.
    fn connect(&self) -> Result<(), String>;
    /// Up to `max` deliveries, waiting at most about `wait` for the first.
    /// An error makes the helper connect again.
    fn receive(&self, max: usize, wait: Duration) -> Result<Vec<Delivery>, String>;
    /// The host stored the message: remove it from the queue.
    fn ack(&self, receipt: &Value) -> Result<(), String>;
    /// The host did not take the message in time: make it deliverable
    /// again.
    fn release(&self, receipt: &Value) -> Result<(), String>;
}

/// How a queue watch runs, from its spec.
#[derive(Debug, Clone)]
pub struct QueueOptions {
    /// What the source reads, for logs: `amqp:orders`, an SQS queue URL.
    pub source: String,
    /// Most messages delivered and not yet settled.
    pub max_in_flight: usize,
    /// How long a message waits for the host before it is released.
    pub ack_timeout: Duration,
    /// Longest a receive waits for a message; also bounds how long a
    /// cancel waits for the receiving thread.
    pub receive_wait: Duration,
}

impl QueueOptions {
    /// Check the bounds a spec may set.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=1000).contains(&self.max_in_flight) {
            return Err("max_in_flight must be 1 to 1000".into());
        }
        if self.ack_timeout.is_zero() {
            return Err("ack_timeout_ms must be greater than 0".into());
        }
        if self.receive_wait.is_zero() || self.receive_wait > Duration::from_secs(20) {
            return Err("the receive wait must be 1 ms to 20 s".into());
        }
        Ok(())
    }
}

/// The deliveries emitted and not yet settled, by sequence number.
struct Window {
    pending: BTreeMap<u64, (Value, Instant)>,
    next_seq: u64,
}

struct Shared<S> {
    source: S,
    options: QueueOptions,
    window: Mutex<Window>,
    /// Signalled when the window has room again, and on stop.
    room: Condvar,
    stop: AtomicBool,
}

impl<S: QueueSource> Shared<S> {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Wait until the window has room; the room, or `None` once stopped.
    fn wait_for_room(&self) -> Option<usize> {
        let mut window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if self.stopped() {
                return None;
            }
            let held = window.pending.len();
            if held < self.options.max_in_flight {
                return Some(self.options.max_in_flight - held);
            }
            window = self
                .room
                .wait_timeout(window, Duration::from_secs(1))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Sleep `delay`, or less once stopped.
    fn pause(&self, delay: Duration) {
        let window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self
            .room
            .wait_timeout_while(window, delay, |_| !self.stopped());
    }

    fn take(&self, seq: u64) -> Option<Value> {
        let mut window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let taken = window.pending.remove(&seq).map(|(receipt, _)| receipt);
        if taken.is_some() {
            self.room.notify_all();
        }
        taken
    }

    /// The deliveries that waited past the timeout, out of the window.
    fn expired(&self) -> Vec<Value> {
        let mut window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let timeout = self.options.ack_timeout;
        let late: Vec<u64> = window
            .pending
            .iter()
            .filter(|(_, (_, at))| at.elapsed() >= timeout)
            .map(|(seq, _)| *seq)
            .collect();
        let receipts: Vec<Value> = late
            .iter()
            .filter_map(|seq| window.pending.remove(seq).map(|(receipt, _)| receipt))
            .collect();
        if !receipts.is_empty() {
            self.room.notify_all();
        }
        receipts
    }

    /// When the oldest delivery times out.
    fn next_expiry(&self) -> Option<Instant> {
        let window = self.window.lock().unwrap_or_else(|e| e.into_inner());
        window
            .pending
            .values()
            .map(|(_, at)| *at + self.options.ack_timeout)
            .min()
    }

    fn ack(&self, receipt: &Value) {
        if let Err(error) = self.source.ack(receipt) {
            tracing::warn!(source = %self.options.source, error = %error, "queue watch: ack failed; the broker redelivers the message");
        }
    }

    fn release(&self, receipt: &Value) {
        if let Err(error) = self.source.release(receipt) {
            tracing::warn!(source = %self.options.source, error = %error, "queue watch: release failed; the broker redelivers the message when its lock lapses");
        }
    }
}

enum Settle {
    Ack(Value),
    Stop,
}

/// Boxed behind the opaque [`WatchHandleBox`].
struct QueueState {
    settle: Sender<Settle>,
    stop: Box<dyn Fn() + Send + Sync>,
    receiver: Option<JoinHandle<()>>,
    settler: Option<JoinHandle<()>>,
}

/// Start a queue watch: receive from `source` and emit each delivery
/// through `emit_event`, an acknowledgement settling it upstream. A
/// resource watch, on a URI that is not an MCP Events source, gets one bare
/// change per receive that delivered anything, and each delivery is settled
/// at once.
pub fn spawn_queue_watch<S: QueueSource>(
    resource_uri: &str,
    options: QueueOptions,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    source: S,
) -> Result<WatchHandleBox, WatchError> {
    options
        .validate()
        .map_err(|message| WatchError::InvalidSpec {
            message: format!("{}: {message}", options.source),
        })?;
    let event_source = mcpg_plugin_protocol::is_event_source(resource_uri);
    let shared = Arc::new(Shared {
        source,
        options,
        window: Mutex::new(Window {
            pending: BTreeMap::new(),
            next_seq: 0,
        }),
        room: Condvar::new(),
        stop: AtomicBool::new(false),
    });
    let (settle, settles) = channel();

    let receiving = Arc::clone(&shared);
    let receiver = std::thread::Builder::new()
        .name("mcpg-queue-receive".to_owned())
        .spawn(move || receive_loop(&receiving, event_source, &*emit_event))
        .map_err(|e| WatchError::Subscribe {
            message: format!("queue watch: cannot start its thread: {e}"),
        })?;
    let settling = Arc::clone(&shared);
    let settler = std::thread::Builder::new()
        .name("mcpg-queue-settle".to_owned())
        .spawn(move || settle_loop(&settling, &settles))
        .map_err(|e| WatchError::Subscribe {
            message: format!("queue watch: cannot start its thread: {e}"),
        })?;

    // Weak, so the source, and any runtime it owns, drops on one of the
    // watch's own threads rather than on the host's.
    let stopping = Arc::downgrade(&shared);
    drop(shared);
    let state = Box::new(QueueState {
        settle,
        stop: Box::new(move || {
            if let Some(shared) = stopping.upgrade() {
                shared.stop.store(true, Ordering::Release);
                shared.room.notify_all();
            }
        }),
        receiver: Some(receiver),
        settler: Some(settler),
    });
    Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
}

fn receive_loop<S: QueueSource>(shared: &Shared<S>, event_source: bool, emit: &dyn Fn(&str)) {
    let mut connected = false;
    let mut backoff = FIRST_BACKOFF;
    while !shared.stopped() {
        if !connected {
            match shared.source.connect() {
                Ok(()) => {
                    connected = true;
                    backoff = FIRST_BACKOFF;
                }
                Err(error) => {
                    tracing::warn!(source = %shared.options.source, error = %error, retry_in_ms = backoff.as_millis() as u64, "queue watch: connect failed");
                    shared.pause(backoff);
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            }
        }
        let Some(room) = shared.wait_for_room() else {
            return;
        };
        let deliveries = match shared.source.receive(room, shared.options.receive_wait) {
            Ok(deliveries) => deliveries,
            Err(error) => {
                tracing::warn!(source = %shared.options.source, error = %error, "queue watch: receive failed; connecting again");
                connected = false;
                shared.pause(backoff);
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        if deliveries.is_empty() {
            continue;
        }
        if shared.stopped() {
            for delivery in &deliveries {
                shared.release(&delivery.receipt);
            }
            return;
        }
        if !event_source {
            for delivery in &deliveries {
                shared.ack(&delivery.receipt);
            }
            emit(r#"{}"#);
            continue;
        }
        for delivery in deliveries {
            offer(shared, delivery, emit);
        }
    }
}

/// Emit one delivery, held in the window until the host acknowledges it.
fn offer<S: QueueSource>(shared: &Shared<S>, delivery: Delivery, emit: &dyn Fn(&str)) {
    let Delivery { mut event, receipt } = delivery;
    let seq = {
        let mut window = shared.window.lock().unwrap_or_else(|e| e.into_inner());
        let seq = window.next_seq;
        window.next_seq += 1;
        window
            .pending
            .insert(seq, (receipt.clone(), Instant::now()));
        seq
    };
    event.upstream_cursor = Some(serde_json::json!({ "v": CURSOR_VERSION, "seq": seq }));
    let json = match serde_json::to_string(&event) {
        Ok(json) => json,
        Err(error) => {
            tracing::warn!(source = %shared.options.source, error = %error, "queue watch: event does not serialize; the message is removed");
            shared.take(seq);
            shared.ack(&receipt);
            return;
        }
    };
    // The host drops an event past its payload limit without a word, so
    // the broker would deliver it again and again.
    if json.len() > FFI_MAX_PAYLOAD_BYTES {
        tracing::warn!(
            source = %shared.options.source,
            bytes = json.len(),
            limit = FFI_MAX_PAYLOAD_BYTES,
            event_id = ?event.event_id,
            "queue watch: event too large for the host; the message is removed"
        );
        shared.take(seq);
        shared.ack(&receipt);
        return;
    }
    emit(&json);
}

fn settle_loop<S: QueueSource>(shared: &Shared<S>, settles: &Receiver<Settle>) {
    loop {
        for receipt in shared.expired() {
            shared.release(&receipt);
        }
        let wait = shared
            .next_expiry()
            .map_or(Duration::from_secs(1), |at| {
                at.saturating_duration_since(Instant::now())
            })
            .min(Duration::from_secs(1));
        match settles.recv_timeout(wait) {
            Ok(Settle::Ack(position)) => {
                let receipt = position
                    .get("seq")
                    .and_then(Value::as_u64)
                    .and_then(|seq| shared.take(seq));
                if let Some(receipt) = receipt {
                    shared.ack(&receipt);
                }
            }
            Ok(Settle::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    // A successor gets the messages still held at once, rather than when
    // their locks lapse.
    let held: Vec<Value> = {
        let mut window = shared.window.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut window.pending)
            .into_values()
            .map(|(receipt, _)| receipt)
            .collect()
    };
    for receipt in held {
        shared.release(&receipt);
    }
}

/// Pass the host's acknowledgement of `position` to the watch `handle`
/// started by [`spawn_queue_watch`]. Returns at once.
pub fn acknowledge_queue_watch(handle: &WatchHandleBox, position: &Value) {
    if handle.0.is_null() {
        return;
    }
    // SAFETY: the pointer `spawn_queue_watch` returned, still owned by the
    // host, which never acknowledges after cancel.
    #[allow(unsafe_code)]
    let state = unsafe { &*(handle.0 as *const QueueState) };
    let _ = state.settle.send(Settle::Ack(position.clone()));
}

/// Stop and join a watch started by [`spawn_queue_watch`]; the messages it
/// still holds are released. Idempotent on a null handle; the host calls it
/// once per handle.
pub fn cancel_queue_watch(handle: WatchHandleBox) {
    if handle.0.is_null() {
        return;
    }
    // SAFETY: produced by `Box::into_raw` in `spawn_queue_watch` and
    // round-tripped by the host exactly once.
    #[allow(unsafe_code)]
    let mut state = unsafe { Box::from_raw(handle.0 as *mut QueueState) };
    (state.stop)();
    // The receiver first: once it is gone, nothing joins the window, and
    // the settler releases all that is left.
    if let Some(receiver) = state.receiver.take() {
        let _ = receiver.join();
    }
    let _ = state.settle.send(Settle::Stop);
    if let Some(settler) = state.settler.take() {
        let _ = settler.join();
    }
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
