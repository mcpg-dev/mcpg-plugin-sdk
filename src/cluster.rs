//! Plugin-side `ClusterClient` — the surface identity / policy
//! plugins use to call into the host's registered
//! `cluster_backend` from inside their sync FFI shim.
//!
//! # Why sync (not async) on the SDK side
//!
//! The host-side `ClusterBackend` trait is async — backends do
//! real I/O (Raft RPC, JetStream KV, Consul HTTP). But the SDK
//! `ClusterClient` is invoked from inside a `SyncIdentityResolver`
//! / `SyncPolicyEngine` impl, which runs on a host blocking-thread
//! after the gateway hands the FFI call off via `spawn_blocking`.
//! Each coordinator vtable slot is a sync `extern "C" fn` (the
//! coordinator plugin's own block_on bridges its async backend
//! internally) — so the SDK exposes those slots directly with
//! sync method shapes. Plugin authors call them synchronously
//! from their sync evaluate / resolve_identity slot.
//!
//! # What's exposed in v20 ABI
//!
//! - **Read**: [`ClusterClient::node_info`], [`ClusterClient::list_peers`].
//! - **Publish**: [`ClusterClient::publish`] — fire-and-forget
//!   notification.
//! - **Subscribe / watch_peers**: [`ClusterClient::subscribe`] +
//!   [`ClusterClient::watch_peers`] take a Rust closure and return
//!   a [`Subscription`] handle. Drop on the handle calls the
//!   coordinator's `cancel_stream` slot synchronously, then frees
//!   the closure box. The host promises no more callbacks fire
//!   after `cancel_stream` returns, so the close+free sequence is
//!   race-free.
//! - **Leases**: [`ClusterClient::acquire_leadership`],
//!   [`ClusterClient::acquire_lock`], with the returned
//!   [`ClusterLease`] handle exposing `renew` / `release` /
//!   automatic Drop-time release.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use abi_stable::std_types::RString;
use bytes::Bytes;
use serde_json::json;

use mcpg_cluster_api::{ClusterError, ClusterNodeInfo, ClusterPeer, PeerEvent, PublishedMessage};
use mcpg_plugin_protocol::abi::{ClusterClientRef, ClusterVTable, EventSinkRef, RPluginHandle};

/// Sync handle to the host's registered `cluster` plugin.
///
/// Constructed by the SDK macro from the `ClusterClientRef` the
/// host hands to a plugin's `make` slot. Plugins receive
/// `Option<ClusterClient>` in their factory closure: `None` when
/// the operator has not registered a `cluster` plugin
/// (single-node deploys), `Some(client)` otherwise.
///
/// `Clone` is cheap — both fields are `Copy`. Plugins that hand
/// the client to background tasks (bundle-reload watchers, peer-
/// notification gossip) clone it and stash one copy per task.
#[derive(Clone)]
pub struct ClusterClient {
    handle: RPluginHandle,
    vtable: ClusterVTable,
}

impl std::fmt::Debug for ClusterClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterClient")
            .field("handle", &(self.handle as usize))
            .finish()
    }
}

// SAFETY: the underlying handle + vtable are immutable Copy data
// once `from_ffi` returns. The vtable's function pointers are
// `Send + Sync` by construction (extern "C" fn). The host
// guarantees `handle` stays valid (and the coordinator's cdylib
// stays loaded) for the lifetime of every consumer plugin.
unsafe impl Send for ClusterClient {}
unsafe impl Sync for ClusterClient {}

impl ClusterClient {
    /// Build a client from the FFI ref the host passed to `make`.
    ///
    /// # Safety
    ///
    /// The caller (the SDK's `declare_plugin!` macro expansion for
    /// `identity` / `policy_engine` entities) MUST only call this
    /// with a `ClusterClientRef` that came directly from
    /// the host's vtable invocation. The host enforces validity:
    /// it constructs the ref from a live coordinator handle + the
    /// matching vtable, and it only drops the consumer plugin
    /// before dropping the coordinator.
    pub unsafe fn from_ffi(client_ref: ClusterClientRef) -> Self {
        Self {
            handle: client_ref.handle as RPluginHandle,
            vtable: client_ref.vtable,
        }
    }

    /// Information about the local node. Cheap snapshot — call
    /// once at plugin construction or on a slow cadence.
    pub fn node_info(&self) -> ClusterNodeInfo {
        let json_rstring = (self.vtable.node_info)(self.handle);
        // Coordinator contract guarantees a valid `ClusterNodeInfo`
        // JSON shape; on parse failure we return a minimal
        // placeholder rather than panicking.
        serde_json::from_str(json_rstring.as_str()).unwrap_or(ClusterNodeInfo {
            node_id: String::new(),
            address: String::new(),
            version: String::new(),
            started_at: String::new(),
            roles: Vec::new(),
        })
    }

    /// Peer snapshot. Cheap.
    pub fn list_peers(&self) -> Vec<ClusterPeer> {
        let json_rstring = (self.vtable.list_peers)(self.handle);
        serde_json::from_str(json_rstring.as_str()).unwrap_or_default()
    }

    /// Publish a notification to a topic. Fire-and-forget; the
    /// coordinator's delivery semantics are backend-specific
    /// (NATS JetStream → at-least-once; Consul events → best
    /// effort; etcd watch → at-least-once via key bumps).
    pub fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: Bytes,
    ) -> Result<(), ClusterError> {
        let args = json!({
            "topic": topic,
            "routing_key": routing_key,
            "payload": payload.to_vec(),
        });
        let args_json = abi_stable::std_types::RString::from(
            serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
        );
        let result = (self.vtable.publish)(self.handle, args_json);
        if result.as_str().is_empty() {
            Ok(())
        } else {
            Err(decode_error(result.as_str(), "publish"))
        }
    }

    /// Acquire leadership for `role`. Blocks until acquired (the
    /// coordinator decides what "blocks" means: Raft returns
    /// immediately with the known leader, JetStream waits for the
    /// current holder's lease to lapse). Returns a [`ClusterLease`]
    /// whose Drop releases automatically.
    pub fn acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<ClusterLease, ClusterError> {
        let args = json!({"role": role, "ttl_ms": lease_ttl.as_millis() as u64});
        self.acquire_common(self.vtable.acquire_leadership, args)
    }

    /// Acquire a fenced distributed lock on `key`. Same shape as
    /// `acquire_leadership`. Non-reentrant — caller MUST NOT
    /// double-acquire from the same node.
    pub fn acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<ClusterLease, ClusterError> {
        let args = json!({"key": key, "ttl_ms": lease_ttl.as_millis() as u64});
        self.acquire_common(self.vtable.acquire_lock, args)
    }

    /// v21 — non-blocking variant of [`acquire_leadership`].
    ///
    /// `Ok(Some(lease))` → acquired (lease is yours; Drop releases).
    /// `Ok(None)` → another node holds the role; caller decides
    ///              whether to retry, sleep, or skip the operation.
    /// `Err(...)` → backend failure (unreachable, refused, malformed).
    ///
    /// Use this from hot loops (bundle-reload pre-tick hooks,
    /// per-request lease attempts) where blocking on contention
    /// would defeat the loop's purpose.
    pub fn try_acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<Option<ClusterLease>, ClusterError> {
        let args = json!({"role": role, "ttl_ms": lease_ttl.as_millis() as u64});
        self.try_acquire_common(self.vtable.try_acquire_leadership, args)
    }

    /// v21 — non-blocking variant of [`acquire_lock`]. Same
    /// `Ok(Some)` / `Ok(None)` / `Err` semantics as
    /// [`try_acquire_leadership`].
    ///
    /// Canonical consumer is the bundle-reload `pre_tick` hook —
    /// see `mcpg-bundle-reload::PreTickHook`.
    pub fn try_acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<Option<ClusterLease>, ClusterError> {
        let args = json!({"key": key, "ttl_ms": lease_ttl.as_millis() as u64});
        self.try_acquire_common(self.vtable.try_acquire_lock, args)
    }

    /// Subscribe to a topic. `on_event` is invoked for every
    /// matching `PublishedMessage` until the returned
    /// [`Subscription`] is dropped (or the host shuts the stream
    /// down — currently the coordinator decides when that happens
    /// during cluster-shutdown).
    ///
    /// `group` selects load-balanced delivery (queue semantics
    /// across subscribers in the same group); `None` means every
    /// subscriber sees every message.
    /// `routing_key` is an optional shard hint the coordinator
    /// uses to route messages within a topic (NATS subjects'
    /// suffix, JetStream filter, …).
    ///
    /// The closure runs on whatever thread the coordinator's
    /// vtable trampoline runs on (typically a dedicated event-
    /// dispatch thread inside the coordinator plugin). It MUST
    /// NOT block — long work belongs on a channel hand-off to a
    /// worker pool inside the closure.
    pub fn subscribe<F>(
        &self,
        topic: &str,
        group: Option<&str>,
        routing_key: Option<&str>,
        on_event: F,
    ) -> Result<Subscription<PublishedMessage>, ClusterError>
    where
        F: Fn(PublishedMessage) + Send + Sync + 'static,
    {
        let cb_box = Box::new(CallbackBox::<PublishedMessage> {
            callback: Box::new(on_event),
        });
        let cb_ptr = Box::into_raw(cb_box) as usize;
        let sink = EventSinkRef {
            ctx: cb_ptr,
            callback: trampoline_published,
        };
        let args = json!({
            "topic": topic,
            "group": group,
            "routing_key": routing_key,
        });
        let args_json = RString::from(serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()));
        let result = (self.vtable.subscribe)(self.handle, args_json, sink);
        if result.handle == 0 {
            // SAFETY: subscribe failed before any callback could
            // fire; we own the box again unconditionally.
            unsafe {
                let _ = Box::from_raw(cb_ptr as *mut CallbackBox<PublishedMessage>);
            }
            return Err(decode_error(result.error_json.as_str(), "subscribe"));
        }
        Ok(Subscription {
            coord_handle: self.handle,
            cancel_stream: self.vtable.cancel_stream,
            stream_handle: result.handle,
            callback_ptr: cb_ptr,
            _phantom: PhantomData,
        })
    }

    /// Subscribe to peer-lifecycle events. `on_event` is invoked
    /// for every Joined / Left / HealthChanged event the
    /// coordinator observes. Same lifetime + threading rules as
    /// [`subscribe`](Self::subscribe).
    pub fn watch_peers<F>(&self, on_event: F) -> Result<Subscription<PeerEvent>, ClusterError>
    where
        F: Fn(PeerEvent) + Send + Sync + 'static,
    {
        let cb_box = Box::new(CallbackBox::<PeerEvent> {
            callback: Box::new(on_event),
        });
        let cb_ptr = Box::into_raw(cb_box) as usize;
        let sink = EventSinkRef {
            ctx: cb_ptr,
            callback: trampoline_peer,
        };
        let result = (self.vtable.watch_peers)(self.handle, sink);
        if result.handle == 0 {
            // SAFETY: watch_peers failed before any callback fired.
            unsafe {
                let _ = Box::from_raw(cb_ptr as *mut CallbackBox<PeerEvent>);
            }
            return Err(decode_error(result.error_json.as_str(), "watch_peers"));
        }
        Ok(Subscription {
            coord_handle: self.handle,
            cancel_stream: self.vtable.cancel_stream,
            stream_handle: result.handle,
            callback_ptr: cb_ptr,
            _phantom: PhantomData,
        })
    }

    fn acquire_common(
        &self,
        vt_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> mcpg_plugin_protocol::abi::LeaseHandle,
        args: serde_json::Value,
    ) -> Result<ClusterLease, ClusterError> {
        let args_json = abi_stable::std_types::RString::from(
            serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
        );
        let result = vt_fn(self.handle, args_json);
        if result.handle == 0 {
            return Err(decode_error(result.error_json.as_str(), "acquire"));
        }
        Ok(ClusterLease {
            coord_handle: self.handle,
            vtable: self.vtable,
            lease_handle: result.handle,
            fencing_token: result.fencing_token,
            expires_at: result.expires_at.into(),
            released: AtomicBool::new(false),
        })
    }

    /// v21 — return-shape decoder for try-variants. Same vtable
    /// signature as `acquire_common` (the host packs all three
    /// states into a single `LeaseHandle`):
    ///
    ///   `handle != 0`                            → `Ok(Some)`
    ///   `handle == 0` && `error_json.is_empty()` → `Ok(None)`  (declined)
    ///   `handle == 0` && `!error_json.is_empty()` → `Err`
    fn try_acquire_common(
        &self,
        vt_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> mcpg_plugin_protocol::abi::LeaseHandle,
        args: serde_json::Value,
    ) -> Result<Option<ClusterLease>, ClusterError> {
        let args_json = abi_stable::std_types::RString::from(
            serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
        );
        let result = vt_fn(self.handle, args_json);
        match decode_try_acquire(&result)? {
            TryAcquireOutcome::Acquired {
                lease_handle,
                fencing_token,
                expires_at,
            } => Ok(Some(ClusterLease {
                coord_handle: self.handle,
                vtable: self.vtable,
                lease_handle,
                fencing_token,
                expires_at,
                released: AtomicBool::new(false),
            })),
            TryAcquireOutcome::Declined => Ok(None),
        }
    }
}

fn decode_error(payload: &str, op: &'static str) -> ClusterError {
    serde_json::from_str(payload).unwrap_or(ClusterError::Internal {
        reason: format!("undecodable {op} error from coordinator"),
    })
}

/// v21 — pure decoder for the try-acquire return convention. Split
/// out so unit tests can exercise the three states without a real
/// vtable function.
///
///   `handle != 0`                            → `Ok(Some)`  (acquired)
///   `handle == 0` && `error_json.is_empty()` → `Ok(None)`  (declined)
///   `handle == 0` && `!error_json.is_empty()` → `Err`      (backend error)
fn decode_try_acquire(
    result: &mcpg_plugin_protocol::abi::LeaseHandle,
) -> Result<TryAcquireOutcome, ClusterError> {
    if result.handle != 0 {
        return Ok(TryAcquireOutcome::Acquired {
            lease_handle: result.handle,
            fencing_token: result.fencing_token,
            expires_at: result.expires_at.as_str().to_owned(),
        });
    }
    if result.error_json.as_str().is_empty() {
        return Ok(TryAcquireOutcome::Declined);
    }
    Err(decode_error(result.error_json.as_str(), "try_acquire"))
}

#[derive(Debug)]
enum TryAcquireOutcome {
    Acquired {
        lease_handle: usize,
        fencing_token: u64,
        expires_at: String,
    },
    Declined,
}

// ---------------------------------------------------------------------------
// Subscription callback bridge
// ---------------------------------------------------------------------------
//
// The coordinator vtable's `subscribe` and `watch_peers` slots take an
// [`EventSinkRef`] = `(ctx: usize, callback: extern "C" fn(usize, RString))`.
// To bridge that C-shape to a Rust closure we:
//
//   1. Box the user closure inside a [`CallbackBox`] — a struct with one
//      indirected `Box<dyn Fn>` field. The outer struct owns a thin
//      pointer (`*mut CallbackBox<E>`) which fits in a `usize`. Storing
//      the fat `Box<dyn Fn>` directly would not — its pointer is two
//      words.
//   2. Pass that thin pointer as `ctx` plus a static
//      [`trampoline_published`] / [`trampoline_peer`] as `callback`.
//   3. The trampoline reconstitutes `&CallbackBox<E>` from `ctx`,
//      deserialises the event JSON, and invokes the user closure.
//   4. [`Subscription::drop`] calls the coordinator's `cancel_stream`
//      first (host promises no callbacks fire after that returns),
//      then `Box::from_raw`'s the callback box. Race-free.

struct CallbackBox<E> {
    callback: Box<dyn Fn(E) + Send + Sync + 'static>,
}

extern "C" fn trampoline_published(ctx: usize, json: RString) {
    if ctx == 0 {
        return;
    }
    // SAFETY: `ctx` came from `Box::into_raw(Box<CallbackBox<PublishedMessage>>)`
    // in [`ClusterClient::subscribe`]. The pointee is alive until the
    // matching [`Subscription::drop`] runs, and the host promises no
    // callbacks fire after `cancel_stream` (which Drop runs first).
    let cb_box: &CallbackBox<PublishedMessage> =
        unsafe { &*(ctx as *const CallbackBox<PublishedMessage>) };
    let payload = json.as_str();
    if payload.is_empty() {
        return;
    }
    match serde_json::from_str::<PublishedMessage>(payload) {
        // A panic in the plugin's callback must not unwind across this
        // `extern "C"` boundary (aborts the process on rustc >= 1.81).
        Ok(msg) => {
            let _ =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (cb_box.callback)(msg)));
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                payload_len = payload.len(),
                "ClusterClient::subscribe: undecodable event payload",
            );
        }
    }
}

extern "C" fn trampoline_peer(ctx: usize, json: RString) {
    if ctx == 0 {
        return;
    }
    // SAFETY: see [`trampoline_published`].
    let cb_box: &CallbackBox<PeerEvent> = unsafe { &*(ctx as *const CallbackBox<PeerEvent>) };
    let payload = json.as_str();
    if payload.is_empty() {
        return;
    }
    match serde_json::from_str::<PeerEvent>(payload) {
        // A panic in the plugin's callback must not unwind across this
        // `extern "C"` boundary (aborts the process on rustc >= 1.81).
        Ok(evt) => {
            let _ =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (cb_box.callback)(evt)));
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                payload_len = payload.len(),
                "ClusterClient::watch_peers: undecodable event payload",
            );
        }
    }
}

/// Handle to a running subscription. Drop cancels the stream and
/// frees the boxed callback.
///
/// `E` is the event payload type — `PublishedMessage` for
/// [`ClusterClient::subscribe`], `PeerEvent` for
/// [`ClusterClient::watch_peers`]. Drop is parameterised on `E`
/// so the right-shaped `CallbackBox<E>` is reclaimed.
pub struct Subscription<E: 'static> {
    coord_handle: RPluginHandle,
    cancel_stream: extern "C" fn(RPluginHandle, usize),
    stream_handle: usize,
    callback_ptr: usize,
    _phantom: PhantomData<fn(E)>,
}

// SAFETY: only the coordinator handle + the function pointers are
// shared across threads; both are immutable. The callback box
// itself is `Send + Sync` by trait bound on `subscribe` /
// `watch_peers`.
unsafe impl<E: 'static> Send for Subscription<E> {}
unsafe impl<E: 'static> Sync for Subscription<E> {}

impl<E: 'static> std::fmt::Debug for Subscription<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("event_type", &std::any::type_name::<E>())
            .field("stream_handle", &self.stream_handle)
            .finish()
    }
}

impl<E: 'static> Drop for Subscription<E> {
    fn drop(&mut self) {
        // Cancel synchronously — host promises no further callbacks
        // after this returns.
        (self.cancel_stream)(self.coord_handle, self.stream_handle);
        // Reclaim the callback box. SAFETY: cb_ptr came from
        // `Box::into_raw(Box<CallbackBox<E>>)` and no one else
        // holds a Box reference to it.
        if self.callback_ptr != 0 {
            unsafe {
                let _ = Box::from_raw(self.callback_ptr as *mut CallbackBox<E>);
            }
        }
    }
}

/// Sync handle to a held lease (leadership role or distributed
/// lock). Drop releases automatically (best-effort; the
/// coordinator's `lease_drop` slot is called regardless of
/// whether the consumer remembered to call `release`).
///
/// Mirrors the async [`mcpg_cluster_api::ActiveLease`]
/// trait used host-side, with sync method shapes for the SDK.
pub struct ClusterLease {
    coord_handle: RPluginHandle,
    vtable: ClusterVTable,
    lease_handle: usize,
    fencing_token: u64,
    expires_at: String,
    released: AtomicBool,
}

unsafe impl Send for ClusterLease {}
unsafe impl Sync for ClusterLease {}

impl std::fmt::Debug for ClusterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterLease")
            .field("fencing_token", &self.fencing_token)
            .field("expires_at", &self.expires_at)
            .field("released", &self.released.load(Ordering::SeqCst))
            .finish()
    }
}

impl ClusterLease {
    /// Strictly-monotonic fencing token. Embed in writes to
    /// fencing-aware backends so a stale lease holder can't
    /// resurrect.
    #[must_use]
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Wall-clock expiry of the current grant (RFC3339).
    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    /// Renew the lease for the same TTL it was acquired with.
    /// Returns `ClusterError::LeaseExpired` if the coordinator
    /// has already reassigned this role / key.
    pub fn renew(&mut self) -> Result<(), ClusterError> {
        let result = (self.vtable.lease_renew)(self.coord_handle, self.lease_handle);
        let payload = result.as_str();
        // Renew uses the host's `Result<expires_at, ClusterError>`
        // JSON convention — `{"ok": "<rfc3339>"}` or `{"err": ...}`.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) {
            if let Some(expires) = value.get("ok").and_then(|v| v.as_str()) {
                self.expires_at = expires.to_owned();
                return Ok(());
            }
            if let Some(err_val) = value.get("err")
                && let Ok(err) = serde_json::from_value::<ClusterError>(err_val.clone())
            {
                return Err(err);
            }
        }
        Err(ClusterError::Internal {
            reason: format!("undecodable renew payload: {payload}"),
        })
    }

    /// Release the lease explicitly. Subsequent renew / release
    /// are no-ops. The coordinator's `lease_drop` will still run
    /// when the `ClusterLease` is dropped, but it's safe to
    /// double-release.
    pub fn release(&self) -> Result<(), ClusterError> {
        if self.released.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let result = (self.vtable.lease_release)(self.coord_handle, self.lease_handle);
        let payload = result.as_str();
        if payload.is_empty() {
            Ok(())
        } else {
            Err(decode_error(payload, "release"))
        }
    }
}

impl Drop for ClusterLease {
    fn drop(&mut self) {
        // Best-effort release if the consumer didn't call
        // `release` explicitly. The coordinator's `lease_drop`
        // slot frees plugin-side state regardless.
        if !self.released.swap(true, Ordering::SeqCst) {
            // Ignore the error — Drop can't fail.
            let _ = (self.vtable.lease_release)(self.coord_handle, self.lease_handle);
        }
        (self.vtable.lease_drop)(self.coord_handle, self.lease_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn cluster_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ClusterClient>();
        assert_send_sync::<ClusterLease>();
        assert_send_sync::<Subscription<PublishedMessage>>();
        assert_send_sync::<Subscription<PeerEvent>>();
    }

    // The subscribe / watch_peers callback bridge has no
    // ergonomic in-process test path: there's no way to construct
    // a real `ClusterVTable` from the SDK side
    // (function pointers point at the loaded coordinator's cdylib
    // code). What we CAN test in isolation is the trampoline
    // round-trip: hand the trampoline a synthetic ctx pointing at
    // a `CallbackBox`, fire it with a JSON payload, observe the
    // user closure run. This is a tight unit on the most subtle
    // bit of the bridge — the `Box::into_raw` / `Box::from_raw`
    // type discipline.

    #[test]
    fn published_trampoline_dispatches_to_callback() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cloned = Arc::clone(&counter);
        let cb_box = Box::new(CallbackBox::<PublishedMessage> {
            callback: Box::new(move |msg| {
                assert_eq!(msg.topic, "t1");
                assert_eq!(msg.payload.as_ref(), b"hello");
                counter_cloned.fetch_add(1, AtomicOrdering::SeqCst);
            }),
        });
        let ctx = Box::into_raw(cb_box) as usize;

        let payload = serde_json::json!({
            "topic": "t1",
            "routing_key": null,
            "payload": b"hello",
            "from_node": "node-a",
        });
        let json = RString::from(payload.to_string());
        trampoline_published(ctx, json);
        assert_eq!(counter.load(AtomicOrdering::SeqCst), 1);

        // SAFETY: reclaim the box we Box::into_raw'd above.
        unsafe {
            let _ = Box::from_raw(ctx as *mut CallbackBox<PublishedMessage>);
        }
    }

    #[test]
    fn peer_trampoline_dispatches_to_callback() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_cloned = Arc::clone(&counter);
        let cb_box = Box::new(CallbackBox::<PeerEvent> {
            callback: Box::new(move |evt| {
                if let PeerEvent::Joined { peer } = evt {
                    assert_eq!(peer.node_id, "n2");
                    counter_cloned.fetch_add(1, AtomicOrdering::SeqCst);
                }
            }),
        });
        let ctx = Box::into_raw(cb_box) as usize;

        let payload = serde_json::json!({
            "kind": "joined",
            "peer": {
                "node_id": "n2",
                "address": "10.0.0.2",
                "last_seen": "2026-04-26T20:00:00Z",
                "health": "healthy",
                "roles": []
            }
        });
        let json = RString::from(payload.to_string());
        trampoline_peer(ctx, json);
        assert_eq!(counter.load(AtomicOrdering::SeqCst), 1);

        // SAFETY: reclaim.
        unsafe {
            let _ = Box::from_raw(ctx as *mut CallbackBox<PeerEvent>);
        }
    }

    #[test]
    fn try_acquire_decoder_acquired() {
        let r = mcpg_plugin_protocol::abi::LeaseHandle {
            handle: 0xdeadbeef,
            fencing_token: 42,
            expires_at: RString::from("2026-04-26T20:00:00Z"),
            error_json: RString::new(),
        };
        match decode_try_acquire(&r).unwrap() {
            TryAcquireOutcome::Acquired {
                lease_handle,
                fencing_token,
                expires_at,
            } => {
                assert_eq!(lease_handle, 0xdeadbeef);
                assert_eq!(fencing_token, 42);
                assert_eq!(expires_at, "2026-04-26T20:00:00Z");
            }
            TryAcquireOutcome::Declined => panic!("expected acquired"),
        }
    }

    #[test]
    fn try_acquire_decoder_declined() {
        let r = mcpg_plugin_protocol::abi::LeaseHandle {
            handle: 0,
            fencing_token: 0,
            expires_at: RString::new(),
            error_json: RString::new(), // empty == declined
        };
        assert!(matches!(
            decode_try_acquire(&r).unwrap(),
            TryAcquireOutcome::Declined
        ));
    }

    #[test]
    fn try_acquire_decoder_error_passes_through() {
        let err_payload = serde_json::to_string(&ClusterError::Timeout).unwrap();
        let r = mcpg_plugin_protocol::abi::LeaseHandle {
            handle: 0,
            fencing_token: 0,
            expires_at: RString::new(),
            error_json: RString::from(err_payload),
        };
        match decode_try_acquire(&r) {
            Err(ClusterError::Timeout) => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn try_acquire_decoder_garbled_error_falls_back_to_internal() {
        let r = mcpg_plugin_protocol::abi::LeaseHandle {
            handle: 0,
            fencing_token: 0,
            expires_at: RString::new(),
            error_json: RString::from("not-json{"),
        };
        match decode_try_acquire(&r) {
            Err(ClusterError::Internal { reason }) => {
                assert!(
                    reason.contains("undecodable"),
                    "expected fallback reason, got: {reason}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn trampoline_ignores_zero_ctx_and_empty_payload() {
        // Both should be no-ops — important for robustness if a
        // misbehaving coordinator ever invokes the trampoline
        // post-cancel.
        trampoline_published(0, RString::from(""));
        trampoline_peer(0, RString::from(""));

        let cb_box = Box::new(CallbackBox::<PublishedMessage> {
            callback: Box::new(|_| panic!("must not fire on empty payload")),
        });
        let ctx = Box::into_raw(cb_box) as usize;
        trampoline_published(ctx, RString::from(""));
        unsafe {
            let _ = Box::from_raw(ctx as *mut CallbackBox<PublishedMessage>);
        }
    }
}
