//! FFI helpers for cdylib plugin authors.
//!
//! This module exists so third-party plugin authors don't have to hand-roll
//! the boilerplate around `mcpg_plugin_protocol::abi`. A plugin using the
//! [`declare_plugin!`](crate::declare_plugin) macro pulls in exactly these
//! helpers — nothing else.
//!
//! # Contract
//!
//! Plugin state lives on the heap, addressed by a raw pointer (`RPluginHandle`
//! is a `*mut ()` alias). The host calls the `make` vtable slot to obtain a
//! handle, passes it back on every per-request dispatch, and finally calls
//! `drop_instance` to release the allocation. This module's helpers ensure
//! the cast/free symmetry is correct:
//!
//! - [`boxed_make`] allocates and leaks the box to the host.
//! - [`boxed_drop`] takes the pointer back and drops the box.
//! - [`typed_handle`] is the safe view for per-request slots.
//!
//! All three are `unsafe` on the back end (they dereference raw pointers)
//! but the macro-generated entry points guarantee the type matches, so
//! plugin authors never call these directly.

use mcpg_cluster_api::{ClusterError, ClusterNodeInfo, ClusterPeer, Entry};
use mcpg_plugin_protocol::abi::RPluginHandle;
use mcpg_plugin_protocol::approval_notifier::{
    NotificationError, NotificationRequest, NotificationResult,
};
use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditReceipt};
use mcpg_plugin_protocol::cache::CacheError;
use mcpg_plugin_protocol::catalog::{CatalogEntry, EnrichedToolDescriptor};
use mcpg_plugin_protocol::config::{ConfigError, ConfigSnapshot};
use mcpg_plugin_protocol::content_store::{
    ContentStoreError, ContentStoreStats, ContentToStore, ResourceContent, ResourceHandle,
};
use mcpg_plugin_protocol::credential::{CredentialError, IssuedCredential};
use mcpg_plugin_protocol::http_route::{HttpRouteRequest, HttpRouteResponse, RouteSpec};
use mcpg_plugin_protocol::logs::{LogError, LogRecord};
use mcpg_plugin_protocol::metrics::MetricsError;
use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyVersion};
use mcpg_plugin_protocol::secret::{SecretError, SecretValueWire};
use mcpg_plugin_protocol::store::{
    AppendResult, StoreError, StorePageWire, StoreRole, StoreValueWire,
};
use mcpg_plugin_protocol::telemetry::{MetricPoint, SpanEnd, SpanStart, TelemetryError};
use mcpg_plugin_protocol::transport::{DispatcherError, TransportError};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendRequest, BackendResponse, CapabilitySet, GateDecision, IdentityResolution,
    PluginContext, PluginManifest, ResourcePage, TransformResult, WatchError,
};
use serde_json::Value;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// http_route streaming support
// ---------------------------------------------------------------------------
//
// The `declare_plugin!` macro's `http_route` arm emits calls to
// `spawn_http_stream_drain` + `cancel_http_stream` on the
// streaming branch. Real implementation is gated on the
// `streaming` feature (which pulls in tokio); without the
// feature, the helpers degrade gracefully — streaming responses
// surface as a 500 with an explanatory body. Moving the cfg into
// a helper fn keeps it out of the macro body — `#[cfg]` inside a
// macro expands in the plugin crate's context, not plugin-sdk's.

/// Drain an `HttpBody::Stream` into the FFI sink on a spawned
/// task. Returns an `HttpHandleResult` with a non-zero handle
/// pointing at an internally-boxed task state. The host's
/// `cancel_stream` slot + [`cancel_http_stream`] frees it.
///
/// Requires the `streaming` feature (pulls in tokio). Without
/// it, returns a 500 `HttpHandleResult` explaining the feature
/// gate.
pub fn spawn_http_stream_drain(
    resp: mcpg_plugin_protocol::http_route::HttpRouteResponse,
    sink: mcpg_plugin_protocol::abi::EventSinkRef,
) -> mcpg_plugin_protocol::abi::HttpHandleResult {
    #[cfg(feature = "streaming")]
    {
        __streaming::spawn_http_stream_drain(resp, sink)
    }
    #[cfg(not(feature = "streaming"))]
    {
        let _ = (resp, sink);
        fallback_error("streaming responses require mcpg-plugin-sdk/streaming feature")
    }
}

/// Cancel a task spawned by [`spawn_http_stream_drain`] and
/// free its state. No-op on `stream_handle == 0` or when the
/// `streaming` feature is disabled.
pub fn cancel_http_stream(stream_handle: usize) {
    #[cfg(feature = "streaming")]
    {
        __streaming::cancel_http_stream(stream_handle);
    }
    #[cfg(not(feature = "streaming"))]
    {
        let _ = stream_handle;
    }
}

#[cfg(feature = "streaming")]
#[doc(hidden)]
pub mod __streaming {
    use mcpg_plugin_protocol::abi::{EventSinkRef, HttpHandleResult};
    use mcpg_plugin_protocol::http_route::{
        HttpBody, HttpChunkWire, HttpRouteResponse, HttpStreamHead,
    };

    pub(super) struct StreamingTaskState {
        pub(super) join: tokio::task::JoinHandle<()>,
        /// Signalled (via the drain task's [`DoneGuard`]) the instant the
        /// task body fully unwinds — whether it ended normally or was
        /// aborted. `cancel_http_stream` blocks on this so it can't return
        /// while a `sink.callback` is still in flight.
        pub(super) done_rx: std::sync::mpsc::Receiver<()>,
    }

    /// Sends on its channel when dropped — i.e. when the drain task's
    /// future is dropped (normal completion OR `abort()`). Because abort
    /// only takes effect at an `.await` point, any synchronous
    /// `sink.callback` already running completes before the future is
    /// dropped, so receiving this signal proves no callback is in flight.
    struct DoneGuard(std::sync::mpsc::Sender<()>);
    impl Drop for DoneGuard {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    pub fn spawn_http_stream_drain(
        resp: HttpRouteResponse,
        sink: EventSinkRef,
    ) -> HttpHandleResult {
        let (status, headers, mut stream) = match resp.body {
            HttpBody::Stream(s) => (resp.status, resp.headers, s),
            HttpBody::Bytes(_) => {
                return super::fallback_error(
                    "spawn_http_stream_drain called on Bytes body — caller bug",
                );
            }
        };
        let rt = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                return super::fallback_error(
                    "streaming requires the plugin to run in a tokio runtime",
                );
            }
        };
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let join = rt.spawn(async move {
            // Dropped when this future ends (normal break OR abort), after
            // any in-flight synchronous `sink.callback` has returned.
            let _done = DoneGuard(done_tx);
            use std::future::poll_fn;
            loop {
                let next = poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
                match next {
                    Some(chunk) => {
                        let wire: HttpChunkWire = chunk.into();
                        let json = ::serde_json::to_string(&wire).unwrap_or_default();
                        (sink.callback)(sink.ctx, ::abi_stable::std_types::RString::from(json));
                    }
                    None => {
                        let end = ::serde_json::to_string(&HttpChunkWire::End).unwrap_or_default();
                        (sink.callback)(sink.ctx, ::abi_stable::std_types::RString::from(end));
                        break;
                    }
                }
            }
        });
        let state = Box::new(StreamingTaskState { join, done_rx });
        let ptr = Box::into_raw(state);
        let head = HttpStreamHead { status, headers };
        HttpHandleResult {
            handle: ptr as usize,
            head_json: ::abi_stable::std_types::RString::from(
                ::serde_json::to_string(&head).unwrap_or_default(),
            ),
        }
    }

    pub fn cancel_http_stream(stream_handle: usize) {
        if stream_handle == 0 {
            return;
        }
        // SAFETY: `stream_handle` was Box::into_raw'd in
        // `spawn_http_stream_drain`. Host contract forbids
        // further emit callbacks after cancel_stream returns.
        let state: Box<StreamingTaskState> =
            unsafe { Box::from_raw(stream_handle as *mut StreamingTaskState) };
        state.join.abort();
        // Make cancel SYNCHRONOUS: block until the drain task's future has
        // fully unwound (DoneGuard drop) so a `sink.callback` can't fire
        // into the host's freed StreamBridge after this returns. Bounded so
        // a wedged task can't hang teardown; if the task already finished,
        // the signal is waiting and recv returns immediately.
        let _ = state
            .done_rx
            .recv_timeout(std::time::Duration::from_secs(5));
        drop(state);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use mcpg_plugin_protocol::abi::EventSinkRef;
        use mcpg_plugin_protocol::http_route::HttpChunk;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Poll;

        static CB_COUNT: AtomicUsize = AtomicUsize::new(0);

        extern "C" fn count_cb(_ctx: usize, _payload: ::abi_stable::std_types::RString) {
            CB_COUNT.fetch_add(1, Ordering::SeqCst);
        }

        /// Minimal immediately-ready `Stream` over an iterator (avoids a
        /// `futures-util` dep) — mirrors the cluster_forward test helper.
        struct IterStream<I>(I);
        impl<I: Iterator<Item = HttpChunk> + Unpin> futures_core::Stream for IterStream<I> {
            type Item = HttpChunk;
            fn poll_next(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<Option<HttpChunk>> {
                Poll::Ready(self.0.next())
            }
        }

        #[test]
        fn drain_then_cancel_reclaims_without_hanging() {
            CB_COUNT.store(0, Ordering::SeqCst);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let chunks = vec![
                HttpChunk::Data(bytes::Bytes::from_static(b"a")),
                HttpChunk::Data(bytes::Bytes::from_static(b"b")),
            ];
            let resp = HttpRouteResponse {
                status: 200,
                headers: vec![],
                body: HttpBody::Stream(Box::pin(IterStream(chunks.into_iter()))),
            };
            let sink = EventSinkRef {
                ctx: 0,
                callback: count_cb,
            };
            // Spawn + drive the drain to completion inside the runtime
            // context (spawn_http_stream_drain needs a current handle).
            let handle = rt.block_on(async {
                let result = spawn_http_stream_drain(resp, sink);
                assert_ne!(result.handle, 0);
                // The immediately-ready stream drains in a single poll; one
                // yield hands the executor to the spawned task.
                tokio::task::yield_now().await;
                result.handle
            });
            // 2 Data chunks + the synthetic End = 3 callbacks.
            assert_eq!(CB_COUNT.load(Ordering::SeqCst), 3, "2 data chunks + End");
            // Cancel after natural completion: the DoneGuard already
            // signalled, so the synchronous wait returns immediately and
            // must NOT block on the 5s timeout.
            let started = std::time::Instant::now();
            cancel_http_stream(handle);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "cancel must not block on the timeout when the task already finished"
            );
        }

        #[test]
        fn cancel_null_handle_is_noop() {
            cancel_http_stream(0);
        }
    }
}

fn fallback_error(reason: &str) -> mcpg_plugin_protocol::abi::HttpHandleResult {
    let err = mcpg_plugin_protocol::http_route::HttpRouteResponseWire {
        status: 500,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&serde_json::json!({ "error": reason })).unwrap_or_default(),
    };
    mcpg_plugin_protocol::abi::HttpHandleResult {
        handle: 0,
        head_json: abi_stable::std_types::RString::from(
            serde_json::to_string(&err).unwrap_or_default(),
        ),
    }
}

/// Ergonomic Rust wrapper around the FFI [`BytesSinkRef`] — the
/// binary-streaming sink.
///
/// Plugins that opt into the binary path on
/// `HttpRouteVTable::handle_streaming` receive a `BytesSinkRef`
/// and lift it into a [`BytesSinkHandle`] to call `emit(bytes)`
/// per chunk and `end()` once. Mixing this with the text/SSE
/// `EventSinkRef` on the same response is undefined behaviour.
///
/// The handle is `Copy` because the underlying `BytesSinkRef` is
/// `Copy` and the FFI callback pointer + context never change
/// over the lifetime of the request.
#[derive(Debug, Clone, Copy)]
pub struct BytesSinkHandle {
    inner: mcpg_plugin_protocol::abi::BytesSinkRef,
}

impl BytesSinkHandle {
    /// Wrap an FFI sink ref. Typically called inside a custom
    /// `handle_streaming` slot body where the macro hands the
    /// raw `BytesSinkRef` to plugin code.
    pub fn new(inner: mcpg_plugin_protocol::abi::BytesSinkRef) -> Self {
        Self { inner }
    }

    /// Send one chunk of bytes to the host. No-op on an empty
    /// slice — `end()` is the way to terminate the stream
    /// (sending an empty chunk would also terminate per ABI
    /// convention, but `emit` is intentionally non-terminating
    /// to keep the call-site shape unambiguous).
    pub fn emit(self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let payload = abi_stable::std_types::RVec::from(bytes.to_vec());
        (self.inner.callback)(self.inner.ctx, payload);
    }

    /// Terminate the stream — the host treats the empty
    /// `RVec<u8>` as the end-of-stream sentinel (mirrors
    /// `HttpChunk::End` from the text path).
    pub fn end(self) {
        let payload = abi_stable::std_types::RVec::<u8>::new();
        (self.inner.callback)(self.inner.ctx, payload);
    }
}

impl From<mcpg_plugin_protocol::abi::BytesSinkRef> for BytesSinkHandle {
    fn from(inner: mcpg_plugin_protocol::abi::BytesSinkRef) -> Self {
        Self::new(inner)
    }
}

/// Sync contract a cdylib tool-gate plugin implements.
///
/// The FFI boundary is synchronous. Plugins that need async I/O can spawn
/// their own runtime inside the methods (but ~90% of in-tree plugins do
/// no async work in the request path — they're observability, policy,
/// or stateful-in-memory checks).
///
/// A `SyncToolGate` implementation is lifted to the FFI vtable by the
/// [`declare_plugin!`](crate::declare_plugin) macro's `tool_gate` arm.
pub trait SyncToolGate: Send + Sync + 'static {
    /// Manifest describing this plugin. The macro serialises this to
    /// JSON for the `manifest_json` vtable slot; it must match the
    /// `plugin.yaml` descriptor or `FirstPartyRegistrar` will reject
    /// the plugin at registration time.
    fn manifest(&self) -> &PluginManifest;

    /// Called before the tool is dispatched. Return `Allow`, `Deny`,
    /// or `Challenge`. `meta` is transport-level metadata the gateway
    /// may pass through; `config` is the operator-provided config JSON
    /// scoped to this plugin.
    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision;

    /// Called after the tool has executed. Plugins here may log,
    /// record metrics, or reject after seeing the result. `duration_ms`
    /// is wall-clock time for the tool dispatch itself (not including
    /// other plugins in the chain).
    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        result: &Value,
        duration_ms: u64,
        config: &Value,
    ) -> GateDecision;

    /// Called once at plugin teardown. Default no-op; implement only
    /// if the plugin owns background state that needs explicit cleanup.
    fn shutdown(&self) {}
}

/// Sync contract a cdylib transform plugin implements.
///
/// Transform plugins rewrite tool arguments before dispatch and/or
/// tool results after dispatch — PII masking, schema migration, field
/// mapping, response enrichment. Same FFI shape as
/// [`SyncToolGate`]: per-call methods stay synchronous; the macro
/// builds the async [`TransformPlugin`](::mcpg_plugin_protocol::traits::TransformPlugin)
/// surface the host registry consumes.
pub trait SyncTransform: Send + Sync + 'static {
    /// Manifest describing this plugin. Macro-serialised to JSON for
    /// the `manifest_json` vtable slot; must match the on-disk
    /// `plugin.yaml` descriptor or `FirstPartyRegistrar` rejects it
    /// at registration time.
    fn manifest(&self) -> &PluginManifest;

    /// Rewrite tool arguments before dispatch. Return `Unchanged` to
    /// keep the original arguments, `Modified` to swap them, or
    /// `Error` to short-circuit the chain.
    fn transform_arguments(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        config: &Value,
    ) -> TransformResult;

    /// Rewrite the tool result after dispatch. Same return contract
    /// as [`Self::transform_arguments`].
    fn transform_result(
        &self,
        ctx: &PluginContext,
        result: &Value,
        config: &Value,
    ) -> TransformResult;

    /// Called once at plugin teardown. Default no-op; override if the
    /// plugin owns background state needing explicit cleanup.
    fn shutdown(&self) {}
}

/// Sync contract a cdylib identity-provider plugin implements.
///
/// Identity plugins resolve a caller identity from HTTP request
/// headers (bearer tokens, cookies, API keys, mTLS assertions) so
/// downstream tool-gates see a verified `PluginIdentity` instead of
/// only the raw transport headers.
///
/// The FFI boundary is synchronous, matching `SyncToolGate`. Plugins
/// that do network I/O on every request (e.g. JWKS refresh) can run
/// a private tokio runtime internally; the common case is a
/// pre-fetched JWKS cached in memory and CPU-bound JWT verify per
/// request.
pub trait SyncIdentityResolver: Send + Sync + 'static {
    /// Manifest describing this plugin. Cross-checked against the
    /// sibling `plugin.yaml` descriptor at registration time.
    fn manifest(&self) -> &PluginManifest;

    /// Resolve an identity from the request's headers + per-
    /// request `RequestMetadata` (protocol 1.1).
    ///
    /// Return `IdentityResolution::Resolved { identity }` when a
    /// valid credential is present, `None` when the request is
    /// anonymous, `Invalid { reason }` when a credential is present
    /// but fails verification.
    ///
    /// `metadata` carries remote address, TLS handshake info,
    /// transport label, request path. Header-only plugins ignore
    /// it; native-mTLS / SPIFFE / geo-fence plugins consume the
    /// fields they need. `Default::default()` when the gateway has
    /// no metadata to populate (stdio transport, plain HTTP, no
    /// peer-cert handshake).
    ///
    /// `config` is the operator-provided config JSON scoped to this
    /// plugin (same value every call, sourced from
    /// `plugins[*].config`).
    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        config: &Value,
    ) -> IdentityResolution;

    /// Optional teardown hook invoked once before the plugin handle
    /// is dropped. Default is a no-op; override to flush JWKS caches
    /// or stop background refresh tasks.
    fn shutdown(&self) {}
}

/// Sink the host hands to [`SyncBackendPlugin::execute_streaming`].
/// Call it once per stream item (in order); the SDK serializes each
/// to a `{"ok":<BackendChunk>}` / `{"err":<BackendError>}` envelope and
/// pushes it across the FFI `EventSinkRef`. The stream conventionally
/// ends with a `BackendChunk::Done`. `Send + Sync + 'static` so a
/// streaming backend can move it into a runtime task draining its
/// async chunk stream. v34 (backend-plugin-migration).
pub type BackendChunkEmitter = Box<
    dyn Fn(Result<mcpg_plugin_protocol::backend::BackendChunk, BackendError>)
        + Send
        + Sync
        + 'static,
>;

/// FFI stream-handle sentinel for "stream succeeded, but there is nothing to
/// cancel".
///
/// The host's [`StreamHandle`](mcpg_plugin_protocol::abi::StreamHandle) contract
/// reserves `handle == 0` for "the plugin **failed** to start the stream". But a
/// [`SyncBackendPlugin::execute_streaming`](SyncBackendPlugin::execute_streaming)
/// that emits its chunks synchronously and returns `Ok(0)` ("nothing to cancel")
/// is a **success** — yet a naive mapping of that `0` to `StreamHandle.handle`
/// would be read by the host as failure and the stream rejected (backlog A-2).
///
/// So the `declare_plugin!` backend wrapper maps a successful `Ok(0)` to this
/// sentinel on the way out, and maps the sentinel back to `0` before invoking
/// [`cancel_stream`](SyncBackendPlugin::cancel_stream). Authors keep the
/// ergonomic `Ok(0)` and a no-op `cancel_stream`; the host sees a non-zero
/// (success) handle. (A plugin that genuinely needs cancellation returns its own
/// non-zero token, which passes through untouched.)
pub const STREAM_NO_CANCEL_SENTINEL: usize = usize::MAX;

/// Sync contract a cdylib binding plugin implements.
///
/// Mirrors [`mcpg_plugin_protocol::BackendPlugin`] but with
/// synchronous methods — the FFI boundary is sync, and plugins
/// that need async I/O bundle a private tokio runtime internally
/// (the same pattern the Tier-1 slots use). Lifted into the
/// FFI vtable by the
/// [`declare_plugin!`](crate::declare_plugin) macro's `backend` arm.
pub trait SyncBackendPlugin: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn kind(&self) -> &str;

    /// Validate + register a per-profile config. Plugins MUST
    /// return `InvalidSpec` synchronously so misconfigurations
    /// fail fast at startup.
    fn register_profile(&self, profile_name: &str, spec: &Value) -> Result<(), BackendError>;

    /// Execute a request synchronously. Bind a private runtime
    /// inside if async I/O is required; the FFI boundary is sync.
    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError>;

    /// Execute with an incremental response stream (LLM token
    /// streaming). The default emits the buffered [`execute`](Self::execute)
    /// result as a single `BackendChunk::Done` (parity with
    /// `BackendPlugin::execute_streaming`'s default — fine for backends
    /// that don't stream). Async backends that genuinely stream
    /// override this: drive the inner stream on a private runtime, push
    /// each item via `emit`, and return an opaque non-zero cancel token
    /// the host passes to [`cancel_stream`](Self::cancel_stream) on
    /// teardown. Returning `Ok(0)` means "nothing to cancel" (the
    /// synchronous default does this); the `declare_plugin!` wrapper maps
    /// that `0` to a non-zero FFI handle so the host doesn't read it as a
    /// failed stream, and maps it back to `0` before `cancel_stream` — see
    /// [`STREAM_NO_CANCEL_SENTINEL`]. `Err` always reports the stream as
    /// failed to start.
    fn execute_streaming(
        &self,
        profile_name: &str,
        request: BackendRequest,
        emit: BackendChunkEmitter,
    ) -> Result<usize, BackendError> {
        let resp = self.execute(profile_name, request)?;
        emit(Ok(mcpg_plugin_protocol::backend::BackendChunk::Done(resp)));
        Ok(0)
    }

    /// Cancel a stream started by [`execute_streaming`](Self::execute_streaming).
    /// `token` is the value that call returned. Default no-op (the
    /// synchronous default `execute_streaming` has nothing running).
    fn cancel_stream(&self, _token: usize) {}

    /// Execute a multi-statement transaction group atomically (the
    /// `sql_tx` pipeline step). `tx_group` is an opaque JSON object the
    /// backend interprets; the backend runs the whole transaction
    /// (begin / per-step / commit-or-rollback) and returns the
    /// per-step results. Default: unsupported. Async backends bridge
    /// this via `block_on` of `BackendPlugin::execute_transaction`. v35
    /// (backend-plugin-migration).
    fn execute_transaction(
        &self,
        _backend_name: &str,
        _tx_group: &Value,
    ) -> Result<Value, BackendError> {
        Err(BackendError::Transport {
            message: "execute_transaction is not supported by this backend".to_owned(),
        })
    }

    /// Domain-specific audit fields merged into the backend audit event
    /// (e.g. SQL's `db.driver` / `db.query_ref`). Default: empty map.
    /// v36 (backend-plugin-migration).
    fn audit_metadata(&self, _profile_name: &str) -> serde_json::Map<String, Value> {
        serde_json::Map::new()
    }

    fn input_schema(&self, _profile_name: &str) -> Option<Value> {
        None
    }
    fn output_schema(&self, _profile_name: &str) -> Option<Value> {
        None
    }
    fn list_resources(
        &self,
        _profile_name: &str,
        _cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        Ok(ResourcePage::empty())
    }
    /// Capabilities this backend auto-registers from its own config.
    /// Default empty — backends that don't produce capabilities stay
    /// wired but inert.
    fn expand_capabilities(&self) -> Result<CapabilitySet, BackendError> {
        Ok(CapabilitySet::default())
    }
    /// Return completion candidates for a resource template variable
    /// given the partially-typed prefix. Default returns an empty list
    /// — backends without dynamic completion inherit no-op behavior.
    fn complete_template_variable(
        &self,
        _profile_name: &str,
        _variable_name: &str,
        _prefix: &str,
        _config: &Value,
        _context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        Ok(vec![])
    }
    fn shutdown(&self) {}
}

/// Sync contract a cdylib watch-strategy plugin implements.
/// Watch events are delivered via `emit_event` — the macro
/// wraps the host's sink callback so plugin authors never touch
/// raw FFI pointers directly.
pub trait SyncWatchStrategyPlugin: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn kind(&self) -> &str;

    /// Start a watcher. Plugin runs its own background work and
    /// emits events by calling `emit_event(&event_json)` where
    /// `event_json` is a serialised `WatchEvent`. Returns an
    /// opaque handle the host will pass back to `cancel`.
    ///
    /// `emit_event` is a closure the macro constructs around the
    /// host's `WatchEventSinkRef` — plugin authors call it as a
    /// normal Rust closure; no `unsafe` needed.
    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError>;

    /// Cancel a running watcher by the opaque handle the plugin
    /// returned in `watch()`.
    fn cancel(&self, watch_handle: WatchHandleBox);

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `http_route` plugin implements.
///
/// Mirrors [`mcpg_plugin_protocol::http_route::HttpRoute`] with
/// synchronous methods. The FFI boundary is sync; plugins that need
/// async I/O bundle a private tokio runtime internally. Lifted into
/// the FFI vtable by the
/// [`declare_plugin!`](crate::declare_plugin) macro's `http_route` arm.
///
/// Streaming response bodies are NOT supported across this sync FFI
/// boundary; a plugin that returns
/// `HttpBody::Stream` is rejected at the adapter layer with a 500.
/// Plugins that need streaming must ship as static in-tree crates.
pub trait SyncHttpRoute: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;

    /// Dispatch table this plugin contributes. Called once by the
    /// host at registration time; the macro caches the result in the
    /// `routes_json` vtable slot.
    fn routes(&self) -> Vec<RouteSpec>;

    /// Handle a request that matched one of this plugin's routes.
    fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse;

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `audit_sink` plugin implements.
///
/// Fan-out shape: the host calls `emit` on every registered audit
/// sink for every event. A sink MUST durably persist before
/// returning Ok — the receipt is the gateway's contract that the
/// event is safe (per spec §9.12).
///
/// The FFI boundary is sync; plugins that need async I/O (HTTP POSTs
/// to an audit backend, NATS publish, etc.) bundle a private tokio
/// runtime internally and `block_on` at the entry point.
pub trait SyncAuditSink: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;

    /// Persist + acknowledge an event.
    fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError>;

    /// Force a flush with a millisecond deadline. Default is a
    /// no-op — sinks that don't buffer can ignore the hint.
    fn flush(&self, _timeout_ms: u64) -> Result<(), AuditError> {
        Ok(())
    }

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `log_sink` plugin implements.
///
/// Fan-out shape with a best-effort contract: `emit` is infallible
/// and plugins MAY drop records under overload (distinct from
/// `audit_sink`, which MUST persist every event per spec §9.12).
pub trait SyncLogSink: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;

    /// Emit a log record. Best-effort; a panicking plugin silently
    /// drops the record via the macro's `catch_panic_silent` guard.
    fn emit(&self, record: &LogRecord);

    /// Force a flush with a millisecond deadline. Returns
    /// `LogError::Timeout` if the sink can't drain in time.
    fn flush(&self, _timeout_ms: u64) -> Result<(), LogError> {
        Ok(())
    }

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `store` plugin implements.
/// Role-keyed durable KV. Streaming `watch` now rides the same
/// callback-channel pattern the other streaming Sync* traits use
/// (see [`Self::watch`]).
pub trait SyncStorePlugin: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn supported_roles(&self) -> Vec<StoreRole>;

    fn get(&self, role: &StoreRole, key: &str) -> Result<Option<StoreValueWire>, StoreError>;

    fn put(&self, role: &StoreRole, key: &str, value: StoreValueWire) -> Result<(), StoreError>;

    fn delete(&self, role: &StoreRole, key: &str) -> Result<(), StoreError>;

    fn list(
        &self,
        role: &StoreRole,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<StorePageWire, StoreError>;

    fn compare_and_swap(
        &self,
        role: &StoreRole,
        key: &str,
        expected: Option<StoreValueWire>,
        new: StoreValueWire,
    ) -> Result<bool, StoreError>;

    fn append(
        &self,
        role: &StoreRole,
        key: &str,
        value: StoreValueWire,
    ) -> Result<AppendResult, StoreError> {
        self.put(role, key, value)?;
        Ok(AppendResult { sequence: 0 })
    }

    /// Start a watch on `(role, key)`. Plugin runs its own
    /// background work (polling loop, backend subscription) and
    /// emits events by calling `emit_event(&json)` where `json`
    /// is a serialised
    /// `mcpg_plugin_protocol::store::StoreEventWire`.
    /// Returns an opaque handle the host will pass back to
    /// [`Self::cancel_watch`] at teardown.
    ///
    /// Default returns `Unsupported { op: "watch" }` so plugin
    /// authors who don't need watch can skip the method.
    fn watch(
        &self,
        _role: &StoreRole,
        _key: &str,
        _emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, StoreError> {
        Err(StoreError::Unsupported { op: "watch".into() })
    }

    /// Cancel a running watch. Default is a no-op; plugins that
    /// implemented `watch` must override this to tear down the
    /// corresponding background work. Idempotent.
    fn cancel_watch(&self, _watch_handle: WatchHandleBox) {}

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `cache` plugin implements.
/// Ephemeral TTL'd KV. No streaming ops on the trait, so full
/// scope is FFI-reachable.
pub trait SyncCachePlugin: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn supported_namespaces(&self) -> Vec<String>;
    fn serves_any_namespace(&self) -> bool {
        false
    }

    /// `None` = miss.
    fn get(&self, ns: &str, key: &str) -> Option<Vec<u8>>;

    fn put(&self, ns: &str, key: &str, value: Vec<u8>, ttl_ms: u64) -> Result<(), CacheError>;

    fn delete(&self, ns: &str, key: &str);

    fn clear(&self, ns: &str) -> Result<(), CacheError>;

    fn incr(&self, ns: &str, key: &str, by: i64, ttl_ms: u64) -> Result<i64, CacheError>;

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `secret_provider` plugin implements.
/// Scheme-keyed URI-addressable
/// resource. Plugins that don't need rotation watching can skip
/// the `watch` / `cancel_watch` methods — defaults return
/// `UnsupportedScheme { scheme: "watch" }`.
pub trait SyncSecretProvider: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn supported_schemes(&self) -> Vec<String>;
    fn get(&self, secret_ref: &str) -> Result<SecretValueWire, SecretError>;
    /// Start a rotation-event subscription. Plugin emits
    /// JSON-encoded `SecretRotationWire` payloads via
    /// `emit_event`.
    fn watch(
        &self,
        _secret_ref: &str,
        _emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, SecretError> {
        Err(SecretError::UnsupportedScheme {
            scheme: "watch".into(),
        })
    }
    fn cancel_watch(&self, _watch_handle: WatchHandleBox) {}
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `config_provider` plugin implements.
/// Scheme-keyed URI-addressable
/// document.
pub trait SyncConfigProvider: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn supported_schemes(&self) -> Vec<String>;
    fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError>;
    /// Start a delta-event subscription on a config reference.
    /// Plugin emits JSON-encoded `ConfigDelta` payloads via
    /// `emit_event`.
    fn watch(
        &self,
        _reference: &str,
        _emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, ConfigError> {
        Err(ConfigError::UnsupportedScheme {
            scheme: "watch".into(),
        })
    }
    fn cancel_watch(&self, _watch_handle: WatchHandleBox) {}
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `cluster_backend` plugin implements.
/// Read-only snapshots + publish + pub/sub + peer-event streams +
/// leases (the lease methods ride the deferred
/// trait-object-across-FFI shape, see [`Self::acquire_leadership`]).
pub trait SyncClusterBackend: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn node_info(&self) -> ClusterNodeInfo;
    fn list_peers(&self) -> Vec<ClusterPeer>;
    fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: Vec<u8>,
    ) -> Result<(), ClusterError>;
    /// Start a subscription to `topic`. Plugin emits JSON-encoded
    /// `PublishedMessage` payloads via `emit_event`.
    fn subscribe(
        &self,
        _topic: &str,
        _group: Option<&str>,
        _routing_key: Option<&str>,
        _emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, ClusterError> {
        Err(ClusterError::Internal {
            reason: "subscribe not implemented".into(),
        })
    }
    /// Start a peer-lifecycle watch. Plugin emits JSON-encoded
    /// `PeerEvent` payloads.
    fn watch_peers(
        &self,
        _emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, ClusterError> {
        Err(ClusterError::Internal {
            reason: "watch_peers not implemented".into(),
        })
    }
    /// Cancel a running stream. Default is a no-op; plugins that
    /// implement subscribe/watch_peers override.
    fn cancel_stream(&self, _stream_handle: WatchHandleBox) {}

    /// Acquire leadership for a named role.
    /// Returns `(handle, fencing_token, expires_at_rfc3339)`.
    fn acquire_leadership(
        &self,
        _role: &str,
        _ttl_ms: u64,
    ) -> Result<(WatchHandleBox, u64, String), ClusterError> {
        Err(ClusterError::Internal {
            reason: "acquire_leadership not implemented".into(),
        })
    }
    /// Acquire a distributed lock.
    fn acquire_lock(
        &self,
        _key: &str,
        _ttl_ms: u64,
    ) -> Result<(WatchHandleBox, u64, String), ClusterError> {
        Err(ClusterError::Internal {
            reason: "acquire_lock not implemented".into(),
        })
    }
    /// Non-blocking variant of [`acquire_leadership`].
    /// ABI v21. Return convention:
    ///   `Ok(Some(...))` → acquired
    ///   `Ok(None)`      → declined (peer holds the lease)
    ///   `Err(...)`      → backend failure
    ///
    /// Default impl delegates to `acquire_leadership`. Backends
    /// with native non-blocking acquire override (Consul `?cas=`,
    /// etcd lease+txn, JetStream KV CAS).
    fn try_acquire_leadership(
        &self,
        role: &str,
        ttl_ms: u64,
    ) -> Result<Option<(WatchHandleBox, u64, String)>, ClusterError> {
        self.acquire_leadership(role, ttl_ms).map(Some)
    }
    /// Non-blocking variant of [`acquire_lock`]. Same semantics
    /// as [`try_acquire_leadership`].
    fn try_acquire_lock(
        &self,
        key: &str,
        ttl_ms: u64,
    ) -> Result<Option<(WatchHandleBox, u64, String)>, ClusterError> {
        self.acquire_lock(key, ttl_ms).map(Some)
    }
    /// Renew a lease by its opaque handle. Returns the new
    /// RFC3339 expiry on success.
    fn lease_renew(&self, _lease_handle: WatchHandleBox) -> Result<String, ClusterError> {
        Err(ClusterError::LeaseExpired)
    }
    /// Release a lease. Idempotent.
    fn lease_release(&self, _lease_handle: WatchHandleBox) -> Result<(), ClusterError> {
        Ok(())
    }
    /// Free any plugin-side state associated with the lease.
    /// Called after `lease_release` by the host.
    fn lease_drop(&self, _lease_handle: WatchHandleBox) {}

    // -- KeyValueStore primitive over FFI --
    //
    // Coordinators that back a durable namespaced KV (redis, nats JetStream)
    // implement these by blocking on their own runtime, mirroring the async
    // `KeyValueStore` trait the host consumes via `key_value_store()`. The
    // default impls return a `Precondition` error so coordinators that
    // advertise no `kv` role (consul / etcd) compile unchanged — the host
    // never routes KV to them (it gates `key_value_store()` on the `kv`
    // role). `ttl_ms` is whole milliseconds; `None` == no TTL.

    /// Fetch the value for `key`. `Ok(None)` when the key is absent.
    fn kv_get(&self, _key: &str) -> Result<Option<Entry>, ClusterError> {
        Err(kv_unsupported())
    }
    /// Store `value` under `key` with an optional TTL.
    fn kv_put(
        &self,
        _key: &str,
        _value: Vec<u8>,
        _ttl_ms: Option<u64>,
    ) -> Result<(), ClusterError> {
        Err(kv_unsupported())
    }
    /// Atomically store `value` under `key` iff absent. `Ok(true)` when this
    /// call created the entry (cross-replica single-winner claim).
    fn kv_put_if_absent(
        &self,
        _key: &str,
        _value: Vec<u8>,
        _ttl_ms: Option<u64>,
    ) -> Result<bool, ClusterError> {
        Err(kv_unsupported())
    }
    /// Delete `key`. `Ok(true)` when the key existed (idempotent).
    fn kv_delete(&self, _key: &str) -> Result<bool, ClusterError> {
        Err(kv_unsupported())
    }
    /// List up to `limit` `(key, entry)` pairs under `prefix`.
    fn kv_list_prefix(
        &self,
        _prefix: &str,
        _limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        Err(kv_unsupported())
    }
    /// Update only the TTL of an existing key. `Ok(false)` when absent.
    fn kv_expire(&self, _key: &str, _ttl_ms: Option<u64>) -> Result<bool, ClusterError> {
        Err(kv_unsupported())
    }

    fn shutdown(&self) {}
}

/// The error every default (non-KV) `SyncClusterBackend` KV slot returns —
/// signals the coordinator backs no key/value store.
fn kv_unsupported() -> ClusterError {
    ClusterError::Unsupported {
        reason: "coordinator does not provide a key_value_store".into(),
    }
}

/// Sync contract a cdylib `policy_engine` plugin implements.
/// Side-effect-free per spec §9.14. `evaluate`
/// returns `PolicyDecision` directly (no Result) — plugin encodes
/// failure as `Deny` / `NotApplicable`.
pub trait SyncPolicyEngine: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn name(&self) -> &str;
    fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision;
    fn policy_version(&self) -> PolicyVersion;
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `approval_notifier` plugin implements.
/// Posts human-approval requests to a channel
/// (Slack, email, PagerDuty, Teams). The async trait counterpart
/// is `mcpg_plugin_protocol::approval_notifier::ApprovalNotifier`;
/// the SDK macro bridges the sync↔async gap by block_on'ing a
/// runtime the plugin author bundles.
///
/// Plugins SHOULD validate channel config at boot
/// (`from_config_json` panic) so misconfigured deploys fail fast
/// instead of dropping approval requests at runtime.
pub trait SyncApprovalNotifier: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn notify(
        &self,
        request: &NotificationRequest,
    ) -> Result<NotificationResult, NotificationError>;
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `credential_issuer` plugin implements.
/// Issues per-request backend credentials keyed on
/// caller `PluginIdentity` + an operator-supplied target.
///
/// Plugin authors may panic on unrecoverable bugs; the SDK macro
/// catches panics and surfaces them as
/// `CredentialError::Backend { reason: "panic" }`. Recoverable
/// errors (Vault unreachable, role not found) MUST be returned
/// as typed `CredentialError` variants.
pub trait SyncCredentialIssuer: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError>;
    fn revoke(&self, lease_id: &str) -> Result<(), CredentialError> {
        let _ = lease_id;
        Ok(())
    }
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `catalog_provider` plugin implements.
/// Chain-bound: each provider receives the previous
/// provider's filtered + enriched output as `in_progress`.
///
/// Implementations MUST follow the chain merge rules
/// (`mcpg_plugin_protocol::catalog` module docs):
///
/// - Scalar fields (`owner`, `doc_url`, `sample_arguments`,
///   `trust_required`, `requires_approval`, `maturity`):
///   first-write-wins.
/// - `tags`: union, deduplicated.
/// - `attributes` map: per-key first-write-wins.
/// - `hide`: providers MAY drop tools by omission; downstream
///   providers don't see hidden tools and can't re-add.
///
/// `describe` and `list_catalog` are forward-compat for a future
/// admin API and are NOT consumed by the gateway in v0.1.
/// Plugins should still implement them (returning `None` /
/// empty Vec for "not in scope" is fine).
pub trait SyncCatalogProvider: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn filter_and_enrich(
        &self,
        ctx: &PluginContext,
        in_progress: &[EnrichedToolDescriptor],
    ) -> Vec<EnrichedToolDescriptor>;
    fn describe(&self, tool_id: &str) -> Option<CatalogEntry>;
    fn list_catalog(&self) -> Vec<CatalogEntry>;
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `content_store` plugin implements — the
/// storage-backend side of the `content_store` entity (spec §9.20).
///
/// Shape mirrors [`SyncBackendPlugin`]: one plugin instance is a
/// *manager* that owns multiple named profiles. The host calls
/// [`register_profile`](Self::register_profile) once per
/// `storage.providers:` entry, then routes blob `put` / `get` / `delete`
/// / `signed_url` / `stats` / `sweep_expired` to a profile by name. The
/// FFI vtable ([`mcpg_plugin_protocol::abi::ContentStoreVTable`]) encodes
/// each call as a single JSON `args` envelope carrying `profile_name`;
/// the [`declare_plugin!`](crate::declare_plugin) macro's `content_store`
/// arm marshals those onto this trait.
///
/// Methods are synchronous (the FFI boundary is sync); a backend that
/// needs async I/O (S3, GCS) bundles a private tokio runtime and
/// `block_on`s internally — the same pattern the other factory kinds
/// use. The host lifts this into the async
/// [`ContentStorePlugin`](mcpg_plugin_protocol::content_store::ContentStorePlugin)
/// factory + per-profile
/// [`ContentStore`](mcpg_plugin_protocol::content_store::ContentStore)
/// surface via [`SyncContentStoreAdapter`](crate::adapters::SyncContentStoreAdapter).
pub trait SyncContentStore: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;

    /// Operator-facing kind discriminator (the string operators write
    /// in `storage.providers: [{kind: ...}]`).
    fn kind(&self) -> &str;

    /// Validate + register a per-profile config. Plugins MUST return an
    /// error synchronously so misconfigurations fail fast at boot.
    fn register_profile(&self, profile_name: &str, spec: &Value) -> Result<(), ContentStoreError>;

    /// Store bytes under `profile_name`; return a stable handle.
    fn put(
        &self,
        profile_name: &str,
        content: ContentToStore,
    ) -> Result<ResourceHandle, ContentStoreError>;

    /// Fetch by id. `Ok(None)` = not found / expired / evicted.
    fn get(
        &self,
        profile_name: &str,
        id: &str,
    ) -> Result<Option<ResourceContent>, ContentStoreError>;

    /// Best-effort, idempotent delete.
    fn delete(&self, profile_name: &str, id: &str) -> Result<(), ContentStoreError>;

    /// Pre-signed URL for direct client fetch. `Ok(None)` = the store
    /// has a presigner but no public URL for this id;
    /// `Err(SignedUrlNotSupported)` = no presigner at all (the default).
    fn signed_url(
        &self,
        _profile_name: &str,
        _id: &str,
        _ttl: std::time::Duration,
    ) -> Result<Option<String>, ContentStoreError> {
        Err(ContentStoreError::SignedUrlNotSupported)
    }

    /// Snapshot of storage utilisation (Prometheus gauges).
    fn stats(&self, profile_name: &str) -> ContentStoreStats;

    /// Sweep expired entries for `profile_name`; return the count
    /// removed. Default no-op (lazy-on-read stores).
    fn sweep_expired(&self, _profile_name: &str) -> usize {
        0
    }

    fn shutdown(&self) {}
}

/// Sync contract a cdylib `telemetry_sink` plugin implements.
/// Fan-out shape; emit slots are best-effort
/// (`catch_panic_silent` on the plugin side).
pub trait SyncTelemetrySink: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    fn span_started(&self, span: &SpanStart);
    fn span_ended(&self, span: &SpanEnd);
    fn metric_recorded(&self, metric: &MetricPoint);
    /// Default: ignore. Operators pipe logs through
    /// `log_sink` directly unless a vendor needs one sink for
    /// everything.
    fn log_recorded(&self, _record: &LogRecord) {}
    fn flush(&self, _timeout_ms: u64) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn shutdown(&self) {}
}

/// Sync contract a cdylib `metrics_sink` plugin implements.
/// Pure-metrics analogue of [`SyncLogSink`] — one
/// `emit` slot, infallible + best-effort. A panicking plugin
/// silently drops the metric via the macro's `catch_panic_silent`
/// guard (same contract as `log_sink::emit`).
pub trait SyncMetricsSink: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;

    /// Emit a metric data point. Best-effort delivery; a sink
    /// that aggregates rolls these raw samples up downstream.
    fn emit(&self, metric: &MetricPoint);

    /// Force a flush with a millisecond deadline. Returns
    /// [`MetricsError::Timeout`] if the sink can't drain in time.
    fn flush(&self, _timeout_ms: u64) -> Result<(), MetricsError> {
        Ok(())
    }

    /// Optional textual snapshot — see
    /// [`mcpg_plugin_protocol::metrics::MetricsSink::render_text_exposition`]
    /// for the contract. Pull-style sinks
    /// (Prometheus exposition) override; push-only sinks keep
    /// the `None` default.
    fn render_text_exposition(&self) -> Option<String> {
        None
    }

    fn shutdown(&self) {}
}

/// Opaque watch-handle wrapper. The plugin's `watch()` returns
/// whatever state it needs to cancel the watcher; the macro
/// marshals this across the FFI as a `*mut ()`.
pub struct WatchHandleBox(pub *mut ());

// SAFETY: the plugin owns the watch-handle; the Send+Sync bounds
// on the plugin side ensure the pointer crosses thread boundaries
// safely. Plugins that hold !Send state inside the handle MUST box
// it behind a lock themselves.
unsafe impl Send for WatchHandleBox {}
unsafe impl Sync for WatchHandleBox {}

/// Heap-allocate the plugin instance and leak the pointer as an
/// `RPluginHandle` the host keeps. Paired with [`boxed_drop`] in
/// the `drop_instance` vtable slot.
///
/// `factory` is called once with the config-JSON string the host
/// supplied at `make` time. The factory returns the plugin's own
/// state type; this function boxes it.
pub fn boxed_make<T, F>(config_json: &str, factory: F) -> RPluginHandle
where
    F: FnOnce(&str) -> T,
{
    let instance = factory(config_json);
    Box::into_raw(Box::new(instance)) as RPluginHandle
}

/// Variant of [`boxed_make`] that hands the unified [`HostHandle`]
/// to the factory: every kind's `make` arm
/// constructs a `HostHandle` from the FFI ref the host passed in and
/// forwards it to the user factory closure as the second arg, so
/// plugin authors can call `host.audit_event(...)`,
/// `host.metric_emit(...)`, `host.resolve_secret(...)`,
/// `host.cluster()` etc. inside their request handlers.
///
/// The factory shape is unified across all 20 kinds — cluster access
/// is reachable as `host.cluster()`.
pub fn boxed_make_with_host<T, F>(
    config_json: &str,
    host: crate::HostHandle,
    factory: F,
) -> RPluginHandle
where
    F: FnOnce(&str, crate::HostHandle) -> T,
{
    let instance = factory(config_json, host);
    Box::into_raw(Box::new(instance)) as RPluginHandle
}

/// Reclaim the box that [`boxed_make`] leaked.
///
/// # Safety
///
/// `handle` MUST have been returned by `boxed_make::<T>` with the same
/// `T` type, and MUST NOT have been dropped previously. Calling this
/// on an arbitrary pointer is undefined behaviour.
///
/// The macro-generated `drop_instance` slot upholds this contract by
/// using the same `T` for both `boxed_make` and `boxed_drop`.
pub unsafe fn boxed_drop<T>(handle: RPluginHandle) {
    // SAFETY: contract documented on this function.
    unsafe {
        drop(Box::from_raw(handle as *mut T));
    }
}

/// Borrow the plugin state behind `handle` as `&T` for the lifetime
/// `'a`. The macro-generated per-request slots use this to hand the
/// plugin's own `&self` into `SyncToolGate` methods without taking
/// ownership.
///
/// # Safety
///
/// - `handle` must have been produced by `boxed_make::<T>` with the
///   same `T`.
/// - `handle` must still be live — i.e. `boxed_drop::<T>` must not
///   have run yet.
/// - The caller guarantees the returned reference is not used after
///   the host calls `drop_instance`.
///
/// The macro-generated vtable upholds all three — the host only
/// calls evaluate slots between `make` and `drop_instance`, and the
/// macro fixes `T` at compile time.
pub unsafe fn typed_handle<'a, T>(handle: RPluginHandle) -> &'a T {
    // SAFETY: contract documented on this function.
    unsafe { &*(handle as *const T) }
}

// ---------------------------------------------------------------------------
// Transport SDK support
// ---------------------------------------------------------------------------

/// Sync contract a cdylib `transport` plugin implements. The
/// plugin's accept loop runs on its own
/// thread; per received message it calls
/// `dispatcher.dispatch(session_id, bytes)` to route into the
/// gateway + get reply bytes back.
///
/// Narrowing note: streaming dispatcher replies are not
/// supported — the host surfaces
/// `DispatcherError::Internal { reason: "streaming reply not
/// supported across FFI" }` when the gateway would have returned
/// a `DispatchResponse.stream`. SSE-capable transports stay
/// static until that restriction is lifted.
pub trait SyncTransport: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    /// Self-declared transport name (`"http-v1"`, `"stdio-v1"`,
    /// …). Host refuses duplicate registrations.
    fn name(&self) -> &str;
    /// Start accepting sessions. Returns a
    /// [`SyncTransportHandle`] the plugin uses to track the
    /// running listener; the macro marshals its fields into the
    /// `StreamHandle` FFI wire shape (listen address lives in
    /// `metadata_json`).
    fn start(
        &self,
        listener_config: &Value,
        dispatcher: Arc<dyn SyncMessageDispatcher>,
    ) -> Result<SyncTransportHandle, TransportError>;
    /// Stop accepting new sessions. `transport_handle` is the
    /// opaque cookie the plugin minted in `start()`. Plugin
    /// MUST return promptly; in-flight sessions may still drain
    /// on the plugin's accept loop until `transport_handle_drop`.
    fn transport_handle_close(&self, transport_handle: WatchHandleBox);
    /// Free plugin-side transport state. After this returns,
    /// the plugin MUST NOT call the dispatcher any further.
    /// Host frees its own dispatcher bridge immediately after.
    fn transport_handle_drop(&self, transport_handle: WatchHandleBox);
    /// Return the transport's operator-visible listen address.
    /// `None` for transports without a meaningful address (e.g.
    /// stdio). Default returns `None`; plugins with a network
    /// listener override.
    fn transport_handle_listen_address(&self, _transport_handle: WatchHandleBox) -> Option<String> {
        None
    }
    fn shutdown(&self) {}
}

/// Sync contract the plugin calls per received MCP message to
/// dispatch into the gateway. Implemented by the SDK macro
/// against the incoming `DispatcherCallbackRef` — plugin
/// authors only consume this trait, they never implement it.
pub trait SyncMessageDispatcher: Send + Sync {
    fn dispatch(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>, DispatcherError>;
}

/// Return value from `SyncTransport::start`. `handle` is an
/// opaque plugin-side cookie (cast to `*mut ()`); the host
/// passes it back in the `transport_handle_*` vtable slots.
pub struct SyncTransportHandle {
    pub handle: *mut (),
    pub listen_address: Option<String>,
}

// SAFETY: the opaque handle is owned by the plugin; the plugin
// guarantees thread-safe access through the trait's `&self`
// methods. Plugin authors who hold !Send state inside the
// handle wrap it in their own lock.
unsafe impl Send for SyncTransportHandle {}
unsafe impl Sync for SyncTransportHandle {}

/// Build a `SyncMessageDispatcher` from the raw FFI callback.
/// Called from the `declare_plugin!` macro's `transport` arm —
/// plugin authors never invoke this directly.
#[doc(hidden)]
pub fn dispatcher_from_cb(
    cb: mcpg_plugin_protocol::abi::DispatcherCallbackRef,
) -> Arc<dyn SyncMessageDispatcher> {
    Arc::new(FfiDispatcher { cb })
}

struct FfiDispatcher {
    cb: mcpg_plugin_protocol::abi::DispatcherCallbackRef,
}

impl SyncMessageDispatcher for FfiDispatcher {
    fn dispatch(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>, DispatcherError> {
        // Wire form: host expects `{"bytes": Vec<u8>}` for
        // message; returns `{"ok": {"bytes": Vec<u8>}}` or
        // `{"err": DispatcherError}`.
        let msg_json = serde_json::to_string(&serde_json::json!({
            "bytes": message,
        }))
        .map_err(|e| DispatcherError::Internal {
            reason: format!("dispatcher message encode failed: {e}"),
        })?;
        let result = (self.cb.dispatch)(
            self.cb.ctx,
            abi_stable::std_types::RString::from(session_id),
            abi_stable::std_types::RString::from(msg_json),
        );
        #[derive(serde::Deserialize)]
        struct ReplyWire {
            bytes: Vec<u8>,
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: ReplyWire },
            Err { err: DispatcherError },
        }
        let raw = result.reply_json.as_str();
        match serde_json::from_str::<Wire>(raw) {
            Ok(Wire::Ok { ok }) => Ok(ok.bytes),
            Ok(Wire::Err { err }) => Err(err),
            Err(e) => Err(DispatcherError::Internal {
                // Don't echo the raw reply body — it can carry sampled model
                // content or solicited credential material. The serde error
                // already names the position and expected shape.
                reason: format!("dispatcher reply decode failed: {e}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Cluster pub/sub + peer-watch FFI forwarder
// ---------------------------------------------------------------------------

/// Shared forwarder that bridges a cluster `subscribe` / `watch_peers`
/// async stream into the host's synchronous `emit_event(&str)` FFI
/// callback, returning a [`WatchHandleBox`] the host stores and later
/// passes back to `SyncClusterBackend::cancel_stream`.
///
/// Every cdylib cluster plugin needs this exact lifecycle, so it lives
/// here once rather than being re-implemented (and re-bugged) per plugin.
/// It is the generalised form of the NATS plugin's proven `pubsub`
/// forwarder, including the use-after-free guard: cancelling
/// the handle aborts the forwarder task **and blocks until any in-flight
/// `emit_event` call has returned**, so a callback can never touch the
/// host's freed `StreamBridge` after `cancel_stream` returns.
///
/// Gated behind the `cluster-forward` feature (pulls in `tokio` + the
/// `Stream` trait) so non-cluster plugins don't carry the cost.
#[cfg(feature = "cluster-forward")]
pub mod cluster_forward {
    use super::WatchHandleBox;
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Sends a single signal when the forwarder future is dropped (normal
    /// completion OR abort). Lets [`ForwardState::drop`] wait for the
    /// forwarder — and therefore any in-flight synchronous `emit_event`
    /// inside the current poll — to quiesce before the host frees its
    /// bridge.
    struct ForwarderDone(mpsc::Sender<()>);

    impl Drop for ForwarderDone {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    /// Heap state behind the `WatchHandleBox` returned by
    /// [`forward_cluster_stream`]. Drop aborts the forwarder task and
    /// blocks (bounded) until it has quiesced.
    struct ForwardState {
        abort: tokio::task::AbortHandle,
        done_rx: mpsc::Receiver<()>,
    }

    impl Drop for ForwardState {
        fn drop(&mut self) {
            self.abort.abort();
            // `abort()` only takes effect at the forwarder's next `.await`;
            // an in-flight `emit_event` (a synchronous call into the host's
            // StreamBridge, freed the moment `cancel_stream` returns) must
            // finish first or it's a use-after-free. Block until the
            // forwarder future has dropped its `ForwarderDone`. Bounded so a
            // wedged task can't hang teardown.
            if self.done_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                tracing::warn!(
                    "cluster forwarder did not quiesce within 5s of cancel; \
                     proceeding with teardown"
                );
            }
        }
    }

    /// Spawn a forwarder that pulls items off `stream`, JSON-encodes each,
    /// and hands the string to `emit_event`. The returned handle is opaque
    /// to the host; pass it to [`cancel_cluster_stream`] (the plugin's
    /// `cancel_stream` slot) to stop + reclaim.
    ///
    /// `stream` is the same `Box`ed stream the plugin's async
    /// `ClusterBackend::subscribe` / `watch_peers` already returns, so the
    /// emitted JSON is exactly the `PublishedMessage` / `PeerEvent` shape
    /// the host's adapter decodes.
    pub fn forward_cluster_stream<T>(
        runtime: &tokio::runtime::Handle,
        mut stream: Pin<Box<dyn futures_core::Stream<Item = T> + Send + 'static>>,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> WatchHandleBox
    where
        T: serde::Serialize + Send + 'static,
    {
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let join = runtime.spawn(async move {
            // Fires on drop (completion OR abort) — see `ForwarderDone`.
            let _done = ForwarderDone(done_tx);
            while let Some(item) = poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
                match serde_json::to_string(&item) {
                    Ok(s) => emit_event(&s),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "cluster forwarder: event serialize failed; dropping"
                    ),
                }
            }
        });
        let state = Box::new(ForwardState {
            abort: join.abort_handle(),
            done_rx,
        });
        WatchHandleBox(Box::into_raw(state) as *mut ())
    }

    /// Cancel + reclaim a handle produced by [`forward_cluster_stream`].
    /// Aborts the forwarder, then blocks until it has quiesced so no
    /// in-flight `emit_event` can fire after this returns. Idempotent on a
    /// null pointer.
    ///
    /// # Safety
    /// `handle` MUST have been produced by [`forward_cluster_stream`] and
    /// not previously passed here.
    pub unsafe fn cancel_cluster_stream(handle: WatchHandleBox) {
        if handle.0.is_null() {
            return;
        }
        // Reclaim the leaked Box → its `Drop` aborts + waits for quiescence.
        drop(unsafe { Box::from_raw(handle.0 as *mut ForwardState) });
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{Arc, Mutex};
        use std::task::Poll;

        /// Minimal `Stream` over an iterator (avoids a `futures-util` dep).
        struct IterStream<I>(I);
        impl<T, I: Iterator<Item = T> + Unpin> futures_core::Stream for IterStream<I> {
            type Item = T;
            fn poll_next(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<Option<T>> {
                Poll::Ready(self.0.next())
            }
        }

        #[test]
        fn forwards_each_item_as_json_then_cancels_cleanly() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let collected = Arc::new(Mutex::new(Vec::<String>::new()));
            let sink = Arc::clone(&collected);
            let stream: Pin<Box<dyn futures_core::Stream<Item = i32> + Send + 'static>> =
                Box::pin(IterStream(vec![1, 2, 3].into_iter()));
            let handle = forward_cluster_stream(
                rt.handle(),
                stream,
                Box::new(move |s| sink.lock().unwrap().push(s.to_owned())),
            );
            // Let the current-thread runtime drain the (immediately-ready) stream.
            rt.block_on(async { tokio::task::yield_now().await });
            std::thread::sleep(std::time::Duration::from_millis(20));
            // Cancel after natural completion: must reclaim without UAF/hang.
            unsafe { cancel_cluster_stream(handle) };
            let got = collected.lock().unwrap();
            assert_eq!(*got, vec!["1".to_owned(), "2".to_owned(), "3".to_owned()]);
        }

        #[test]
        fn cancel_on_null_handle_is_a_noop() {
            // Defensive: a null/already-taken handle must not crash.
            unsafe { cancel_cluster_stream(WatchHandleBox(std::ptr::null_mut())) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boxed_make_drop_round_trips() {
        struct Counter {
            value: u64,
        }
        let handle = boxed_make::<Counter, _>("{}", |_| Counter { value: 42 });
        // SAFETY: round-trip under the same T.
        let borrow: &Counter = unsafe { typed_handle::<Counter>(handle) };
        assert_eq!(borrow.value, 42);
        // SAFETY: round-trip drop.
        unsafe { boxed_drop::<Counter>(handle) };
    }

    #[test]
    fn boxed_make_passes_config_json() {
        let handle = boxed_make::<String, _>(r#"{"k":"v"}"#, |cfg| cfg.to_owned());
        let borrow = unsafe { typed_handle::<String>(handle) };
        assert_eq!(borrow.as_str(), r#"{"k":"v"}"#);
        unsafe { boxed_drop::<String>(handle) };
    }

    // `BytesSinkHandle`.

    #[test]
    fn bytes_sink_handle_emit_and_end_invoke_callback() {
        use std::sync::Mutex;
        static EVENTS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

        extern "C" fn capture(_ctx: usize, chunk: abi_stable::std_types::RVec<u8>) {
            EVENTS.lock().unwrap().push(chunk.into());
        }

        EVENTS.lock().unwrap().clear();
        let sink_ref = mcpg_plugin_protocol::abi::BytesSinkRef {
            ctx: 0,
            callback: capture,
        };
        let handle = BytesSinkHandle::from(sink_ref);
        handle.emit(b"hello");
        // Empty emit is a no-op (callers use `end()` to terminate).
        handle.emit(b"");
        handle.end();

        let got = EVENTS.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "emit(&[]) must not call the callback");
        assert_eq!(got[0], b"hello");
        assert!(got[1].is_empty(), "end() sends the EOS sentinel");
    }
}
