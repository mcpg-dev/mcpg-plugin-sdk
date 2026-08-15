//! Plugin-side `HostHandle` — the unified Rust surface plugin
//! authors use to call back into the host.
//!
//! # Why this layer exists
//!
//! The FFI plumbing underneath is already in place: every `*VTable::make` slot
//! receives a [`HostHandleRef`] that points at the host's bridge,
//! and the bridge dispatches plugin-emitted callbacks (resolve_secret,
//! audit_event, metric_emit, span_*, …) through a vtable of 10
//! `extern "C"` slots. That's the right shape for the wire — but
//! the SDK side has, until now, exposed only the raw [`HostHandleRef`]
//! struct. Plugin authors building on top had to:
//!
//! - hand-encode `RString::from(serde_json::to_string(...))` on every
//!   call,
//! - hand-decode `ResultEnvelope<T, E>` from the response string,
//! - convert `SecretValueWire → SecretValue` etc. at every call site,
//! - thread an `&str` alias through every helper (the FFI ref carries
//!   it implicitly via `vtable.alias(ctx)`).
//!
//! That's boilerplate every adapter would re-implement. `HostHandle`
//! consolidates it: one Rust struct, ergonomic methods for every
//! slot, identical surface across cdylib + static-firstparty.
//!
//! # Two backends, one API
//!
//! `HostHandle` wraps **either**:
//!
//! - [`HostHandle::from_ffi`] — a [`HostHandleRef`] handed in by the
//!   gateway's native loader (cdylib path). Method calls are JSON
//!   round-trips through the vtable's `extern "C"` slots.
//! - [`HostHandle::from_services`] — direct [`HostServices`] trait
//!   object + alias + optional cluster ref (static-firstparty path).
//!   Method calls dispatch into the trait without FFI marshalling.
//!
//! Both produce identical Rust-side semantics, so a plugin's
//! `evaluate_*` body looks the same whether it runs as a dynamic
//! `.so` or compiled directly into the gateway binary. This is
//! the parity guarantee the protocol makes for the static
//! fast-path.
//!
//! # Sync, with a runtime caveat
//!
//! Every method on `HostHandle` is **synchronous**. Plugins are
//! invoked from `spawn_blocking`'d worker threads (the host's
//! pattern for every native plugin), and the SDK keeps the same
//! shape on the static path. For static-firstparty mode the
//! handle captures a [`tokio::runtime::Handle`] at construction
//! time (or `Handle::try_current()` if unspecified) and uses
//! `block_on` to bridge the async [`HostServices`] methods. Plugins
//! that need to call `HostHandle` methods from inside a Tokio
//! `current_thread` runtime must construct the handle on a thread
//! that has access to a multi-threaded runtime handle, or arrange
//! to call from a [`tokio::task::spawn_blocking`] task — exactly
//! the same constraint that applies to the host bridge.
//!
//! # SpanGuard
//!
//! [`SpanGuard`] is the RAII wrapper for `span_start` / `span_end`:
//! constructing one opens a span; dropping it closes the span. This
//! mirrors the `tracing::span::Entered` ergonomics most Rust authors
//! expect.

#[cfg(feature = "static-firstparty")]
use std::sync::Arc;

use abi_stable::std_types::{RNone, ROption, RString};

use base64::Engine;
#[cfg(feature = "static-firstparty")]
use mcpg_plugin_protocol::abi::ClusterClientRef;
use mcpg_plugin_protocol::abi::HostHandleRef;
use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditReceipt};
use mcpg_plugin_protocol::backend::{
    BackendHostError, CredentialRevocationCallback, CredentialRevocationSubscription,
    SecretRotationCallback, SecretRotationSubscription,
};
use mcpg_plugin_protocol::config::{ConfigError, ConfigSnapshot};
use mcpg_plugin_protocol::credential::{CredentialError, IssuedCredential};
use mcpg_plugin_protocol::result_envelope::decode_result_envelope;
use mcpg_plugin_protocol::secret::{SecretError, SecretValue, SecretValueWire};
use mcpg_plugin_protocol::types::PluginIdentity;

use crate::ClusterClient;

/// Adapts a [`HostHandle`] to the async [`BackendHost`] trait so a
/// dynamically-loaded (cdylib) backend's existing async `BackendPlugin`
/// impl can reach host services through the v31 FFI slots — without
/// rewriting its logic for the sync FFI surface.
///
/// The plugin stores the `HostHandle` it receives at `make` time, and
/// its `SyncBackendPlugin` bridge constructs
/// `Arc::new(HostHandleBackendHost::new(handle.clone()))` to pass as the
/// `host` argument when `block_on`-ing the async
/// `BackendPlugin::register_profile` / `execute`.
///
/// Services not yet carried by the cdylib host FFI fall back to the
/// `BackendHost` defaults: `invoke_tool` → `NotImplemented` (no tool-
/// chaining slot yet; backends needing it stay static), `store_content`/
/// `fetch_content`/`cache_put`/`cache_invalidate` → their no-op/
/// NotImplemented defaults.
pub struct HostHandleBackendHost {
    handle: HostHandle,
}

impl HostHandleBackendHost {
    /// Wrap a host handle as a `BackendHost`.
    #[must_use]
    pub fn new(handle: HostHandle) -> Self {
        Self { handle }
    }
}

impl std::fmt::Debug for HostHandleBackendHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostHandleBackendHost").finish()
    }
}

#[mcpg_plugin_protocol::async_trait]
impl mcpg_plugin_protocol::backend::BackendHost for HostHandleBackendHost {
    async fn invoke_tool(
        &self,
        ctx: &mcpg_plugin_protocol::backend::BackendInvocationContext,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError> {
        // v33 host-FFI slot: marshal the agentic child-tool call back to
        // the gateway dispatcher (depth/cycle enforced host-side from the
        // ctx the plugin threads through).
        self.handle.invoke_tool(ctx, tool_name, args)
    }

    async fn cache_get(
        &self,
        _ctx: &mcpg_plugin_protocol::backend::BackendInvocationContext,
        key: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        self.handle.cache_get(key)
    }

    async fn fetch_content(
        &self,
        _ctx: &mcpg_plugin_protocol::backend::BackendInvocationContext,
        uri: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        self.handle.fetch_content(uri)
    }

    async fn store_content(
        &self,
        _ctx: &mcpg_plugin_protocol::backend::BackendInvocationContext,
        bytes: bytes::Bytes,
        mime_type: String,
        ttl: Option<std::time::Duration>,
    ) -> Result<mcpg_plugin_protocol::backend::BackendResource, BackendHostError> {
        self.handle.store_content(bytes, &mime_type, ttl)
    }

    async fn resolve_credentials(
        &self,
        ctx: &mcpg_plugin_protocol::backend::BackendInvocationContext,
        value: &mut serde_json::Value,
    ) -> Result<usize, BackendHostError> {
        self.handle
            .resolve_credentials(value, ctx.identity.as_ref())
    }

    fn subscribe_credential_revoked(
        &self,
        cb: CredentialRevocationCallback,
    ) -> CredentialRevocationSubscription {
        self.handle.subscribe_credential_revoked(cb)
    }

    fn subscribe_secret_rotation(&self, cb: SecretRotationCallback) -> SecretRotationSubscription {
        self.handle.subscribe_secret_rotation(cb)
    }
}

/// A single metric point a plugin can emit through
/// [`HostHandle::emit_metric`]. JSON-identical with the host-side
/// `mcpg_plugin_host::host_services::MetricPoint`, so the wire
/// format crosses the FFI seam unchanged.
///
/// Most callers should prefer the typed convenience methods —
/// [`HostHandle::counter`], [`HostHandle::gauge`],
/// [`HostHandle::histogram`] — which build the right variant
/// inline. The enum is exposed for callers that already have a
/// `MetricPoint` in hand (e.g. plugins that pre-compute a batch
/// from their internal recorder).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetricPoint {
    Counter {
        name: String,
        value: u64,
        #[serde(default)]
        labels: Vec<(String, String)>,
    },
    Gauge {
        name: String,
        value: f64,
        #[serde(default)]
        labels: Vec<(String, String)>,
    },
    Histogram {
        name: String,
        value: f64,
        #[serde(default)]
        labels: Vec<(String, String)>,
    },
}

#[cfg(feature = "static-firstparty")]
impl MetricPoint {
    /// Convert to the host-side `MetricPoint` for direct trait
    /// dispatch on the static-firstparty path.
    fn into_host(self) -> mcpg_plugin_host::host_services::MetricPoint {
        use mcpg_plugin_host::host_services::MetricPoint as Host;
        match self {
            Self::Counter {
                name,
                value,
                labels,
            } => Host::Counter {
                name,
                value,
                labels,
            },
            Self::Gauge {
                name,
                value,
                labels,
            } => Host::Gauge {
                name,
                value,
                labels,
            },
            Self::Histogram {
                name,
                value,
                labels,
            } => Host::Histogram {
                name,
                value,
                labels,
            },
        }
    }
}

/// Plugin-side handle to the host's service surface. Constructed by
/// the SDK macro from the [`HostHandleRef`] the host hands in at
/// `make` time, or by [`HostHandle::from_services`] on the
/// static-firstparty path. See [module docs](self) for the
/// design rationale.
///
/// `Clone` is cheap (the FFI backend is `Copy`; the services
/// backend clones an `Arc`). Plugins that hand the handle to
/// background tasks (rotation watchers, bundle reloaders) clone
/// it and stash a copy per task.
#[derive(Clone)]
pub struct HostHandle {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    /// Wraps a host-provided `HostHandleRef` — the canonical path
    /// for cdylib plugins. Method calls dispatch through the
    /// vtable's `extern "C"` slots.
    Ffi { handle_ref: HostHandleRef },
    /// Direct trait dispatch for static-firstparty plugins. Skips
    /// FFI marshalling entirely.
    #[cfg(feature = "static-firstparty")]
    Services {
        alias: Arc<str>,
        services: Arc<dyn mcpg_plugin_host::host_services::HostServices>,
        cluster: Option<ClusterClientRef>,
        runtime: Option<tokio::runtime::Handle>,
    },
}

// SAFETY: the FFI backend's `HostHandleRef` carries only `Copy`
// scalars and `extern "C" fn` pointers (which are `Send + Sync` by
// construction). The host guarantees the underlying bridge stays
// alive for the plugin's lifetime. The services backend holds
// `Send + Sync` types directly.
unsafe impl Send for HostHandle {}
unsafe impl Sync for HostHandle {}

impl std::fmt::Debug for HostHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.backend {
            Backend::Ffi { handle_ref } => f
                .debug_struct("HostHandle")
                .field("backend", &"ffi")
                .field("ctx", &(handle_ref.ctx as *const ()))
                .finish(),
            #[cfg(feature = "static-firstparty")]
            Backend::Services { alias, .. } => f
                .debug_struct("HostHandle")
                .field("backend", &"services")
                .field("alias", &alias.as_ref())
                .finish(),
        }
    }
}

impl HostHandle {
    /// Build a handle from the FFI ref the host passes to a
    /// plugin's `make` slot. The canonical cdylib path.
    ///
    /// # Safety
    ///
    /// The caller — typically the SDK's `declare_plugin!` macro
    /// expansion — MUST only call this with a `HostHandleRef` that
    /// came directly from the host's invocation of the plugin's
    /// `make` slot. The host enforces validity: it constructs the
    /// ref from a live bridge + matching vtable, and the bridge
    /// outlives every method call the plugin makes (only freed
    /// after `drop_instance` returns).
    pub unsafe fn from_ffi(handle_ref: HostHandleRef) -> Self {
        Self {
            backend: Backend::Ffi { handle_ref },
        }
    }

    /// Build a handle backed by an in-process [`HostServices`]
    /// implementation. Used by the static-firstparty registration
    /// path so plugins compiled directly into the gateway binary
    /// get the same Rust surface without paying for FFI
    /// marshalling.
    ///
    /// `cluster` is the optional cluster ref the host has already
    /// constructed for this plugin entry; the handle exposes it
    /// through [`HostHandle::cluster`] identically to the FFI
    /// path. Pass `None` for single-node deploys or for plugins
    /// the operator has not opted in to cluster sharing.
    ///
    /// The captured runtime is `Handle::try_current()` — the
    /// caller MUST be on a Tokio runtime worker thread (which the
    /// gateway always is when constructing static plugins during
    /// boot). Calls from a thread without a runtime fall back to
    /// returning `Backend{reason: "no runtime"}`-style errors
    /// from the fallible async slots, matching the host bridge's
    /// behaviour for `peek/derive` paths.
    #[cfg(feature = "static-firstparty")]
    pub fn from_services(
        services: Arc<dyn mcpg_plugin_host::host_services::HostServices>,
        alias: impl Into<Arc<str>>,
        cluster: Option<ClusterClientRef>,
    ) -> Self {
        Self {
            backend: Backend::Services {
                alias: alias.into(),
                services,
                cluster,
                runtime: tokio::runtime::Handle::try_current().ok(),
            },
        }
    }

    /// The operator alias of the plugin entry this handle is bound
    /// to. Useful for plugin-emitted log lines that want to
    /// identify themselves (`tracing::info!(alias = %h.alias(), ...)`).
    pub fn alias(&self) -> String {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let s = (handle_ref.vtable.alias)(handle_ref.ctx);
                s.as_str().to_owned()
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services { alias, .. } => alias.as_ref().to_owned(),
        }
    }

    /// Optional cluster handle the host has registered for this
    /// plugin entry. `None` in single-node deploys.
    pub fn cluster(&self) -> Option<ClusterClient> {
        let cluster_ref = match &self.backend {
            Backend::Ffi { handle_ref } => (handle_ref.vtable.cluster)(handle_ref.ctx),
            #[cfg(feature = "static-firstparty")]
            Backend::Services { cluster, .. } => match cluster {
                Some(c) => ROption::RSome(*c),
                None => RNone,
            },
        };
        match cluster_ref {
            ROption::RSome(cr) => Some(unsafe { ClusterClient::from_ffi(cr) }),
            RNone => None,
        }
    }

    /// Resolve a secret reference. The host filters against the
    /// plugin's `SecretsRead{schemes}` capability before
    /// dispatching to the registered scheme provider.
    pub fn resolve_secret(&self, uri: &str) -> Result<SecretValue, SecretError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let out: RString =
                    (handle_ref.vtable.resolve_secret)(handle_ref.ctx, RString::from(uri));
                decode_secret_envelope(out.as_str())
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.clone();
                let uri = uri.to_owned();
                block_on_or_err(
                    runtime,
                    async move { services.resolve_secret(&alias, &uri).await },
                    || SecretError::Backend {
                        reason: "host handle: no tokio runtime captured".into(),
                    },
                )
            }
        }
    }

    /// Resolve `cred://…` URIs inside `value` in place against the
    /// gateway's credential cache. Returns the substitution count.
    /// (Backend host service — see [`crate::HostHandle`] FFI v31.)
    pub fn resolve_credentials(
        &self,
        value: &mut serde_json::Value,
        identity: Option<&PluginIdentity>,
    ) -> Result<usize, BackendHostError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let value_json = serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned());
                let id_json =
                    serde_json::to_string(&identity).unwrap_or_else(|_| "null".to_owned());
                let out: RString = (handle_ref.vtable.resolve_credentials)(
                    handle_ref.ctx,
                    RString::from(value_json),
                    RString::from(id_json),
                );
                let wire =
                    decode_result_envelope::<ResolveCredsWire, BackendHostError>(out.as_str())
                        .map_err(envelope_err)??;
                *value = wire.value;
                Ok(wire.count)
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let identity_owned = identity.cloned();
                block_on_or_err(
                    runtime,
                    services.resolve_credentials(alias.as_ref(), value, identity_owned),
                    || BackendHostError::NotImplemented,
                )
            }
        }
    }

    /// Look up a cached response by opaque hash key. `Ok(None)` on miss.
    pub fn cache_get(&self, key: &str) -> Result<Option<bytes::Bytes>, BackendHostError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let out: RString =
                    (handle_ref.vtable.cache_get)(handle_ref.ctx, RString::from(key));
                let b64 = decode_result_envelope::<Option<String>, BackendHostError>(out.as_str())
                    .map_err(envelope_err)??;
                match b64 {
                    Some(s) => {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(s.as_bytes())
                            .map_err(|e| BackendHostError::Backend {
                                tool_name: String::new(),
                                cause: mcpg_plugin_protocol::BackendError::Transport {
                                    message: format!("cache_get: bad base64: {e}"),
                                },
                            })?;
                        Ok(Some(bytes::Bytes::from(bytes)))
                    }
                    None => Ok(None),
                }
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.as_ref().to_owned();
                let key = key.to_owned();
                block_on_or_err(
                    runtime,
                    async move { services.cache_get(&alias, &key).await },
                    || BackendHostError::NotImplemented,
                )
            }
        }
    }

    /// Fetch host-stored content (multimodal inputs) by
    /// `mcpg-resource://` URI. `Ok(None)` = not found. v32
    /// (backend-plugin-migration). Same wire shape as [`cache_get`].
    pub fn fetch_content(&self, uri: &str) -> Result<Option<bytes::Bytes>, BackendHostError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let out: RString =
                    (handle_ref.vtable.fetch_content)(handle_ref.ctx, RString::from(uri));
                let b64 = decode_result_envelope::<Option<String>, BackendHostError>(out.as_str())
                    .map_err(envelope_err)??;
                match b64 {
                    Some(s) => {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(s.as_bytes())
                            .map_err(|e| BackendHostError::Backend {
                                tool_name: String::new(),
                                cause: mcpg_plugin_protocol::BackendError::Transport {
                                    message: format!("fetch_content: bad base64: {e}"),
                                },
                            })?;
                        Ok(Some(bytes::Bytes::from(bytes)))
                    }
                    None => Ok(None),
                }
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.as_ref().to_owned();
                let uri = uri.to_owned();
                block_on_or_err(
                    runtime,
                    async move { services.fetch_content(&alias, &uri).await },
                    || BackendHostError::NotImplemented,
                )
            }
        }
    }

    /// Store content (generated images / audio) in the host's content
    /// store, returning the resulting `BackendResource`. v32
    /// (backend-plugin-migration).
    pub fn store_content(
        &self,
        bytes: bytes::Bytes,
        mime_type: &str,
        ttl: Option<std::time::Duration>,
    ) -> Result<mcpg_plugin_protocol::backend::BackendResource, BackendHostError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let args = serde_json::json!({
                    "bytes": base64::engine::general_purpose::STANDARD.encode(&bytes),
                    "mime_type": mime_type,
                    "ttl_ms": ttl.map(|d| d.as_millis() as u64),
                });
                let out: RString = (handle_ref.vtable.store_content)(
                    handle_ref.ctx,
                    RString::from(serde_json::to_string(&args).unwrap_or_default()),
                );
                decode_result_envelope::<
                    mcpg_plugin_protocol::backend::BackendResource,
                    BackendHostError,
                >(out.as_str())
                .map_err(envelope_err)?
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.as_ref().to_owned();
                let mime_type = mime_type.to_owned();
                block_on_or_err(
                    runtime,
                    async move { services.store_content(&alias, bytes, mime_type, ttl).await },
                    || BackendHostError::NotImplemented,
                )
            }
        }
    }

    /// Invoke another gateway tool (agentic child-tool call). `ctx`
    /// carries the caller's depth / parent_request_id so the host can
    /// enforce its depth cap + cycle detection. v33
    /// (backend-plugin-migration).
    pub fn invoke_tool(
        &self,
        ctx: &mcpg_plugin_protocol::backend::BackendInvocationContext,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let ctx_json = serde_json::to_string(ctx).unwrap_or_default();
                let args_json = serde_json::to_string(args).unwrap_or_default();
                let out: RString = (handle_ref.vtable.invoke_tool)(
                    handle_ref.ctx,
                    RString::from(ctx_json),
                    RString::from(tool_name),
                    RString::from(args_json),
                );
                decode_result_envelope::<serde_json::Value, BackendHostError>(out.as_str())
                    .map_err(envelope_err)?
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                services, runtime, ..
            } => {
                let services = services.clone();
                let ctx = ctx.clone();
                let tool_name = tool_name.to_owned();
                let args = args.clone();
                block_on_or_err(
                    runtime,
                    async move { services.invoke_tool(&ctx, &tool_name, &args).await },
                    || BackendHostError::NotImplemented,
                )
            }
        }
    }

    /// Subscribe to credential-revocation events `(plugin_id, target)`.
    /// The returned guard unsubscribes on drop — retain it for the
    /// subscriber's lifetime.
    pub fn subscribe_credential_revoked(
        &self,
        cb: CredentialRevocationCallback,
    ) -> CredentialRevocationSubscription {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                extern "C" fn tramp(cb_ctx: usize, plugin_id: RString, target: RString) {
                    // SAFETY: cb_ctx is the `Box<CredentialRevocationCallback>`
                    // leaked below; the host stops invoking before the guard's
                    // `free` reclaims it.
                    let cb = unsafe { &*(cb_ctx as *const CredentialRevocationCallback) };
                    // A panic in the plugin's callback must not unwind across
                    // this `extern "C"` boundary (aborts the process on
                    // rustc >= 1.81).
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        cb(plugin_id.as_str(), target.as_str());
                    }));
                }
                unsafe fn free(cb_ctx: usize) {
                    drop(unsafe { Box::from_raw(cb_ctx as *mut CredentialRevocationCallback) });
                }
                let cb_ctx = Box::into_raw(Box::new(cb)) as usize;
                let sub_id = (handle_ref.vtable.subscribe_credential_revoked)(
                    handle_ref.ctx,
                    tramp as *const () as usize,
                    cb_ctx,
                );
                CredentialRevocationSubscription::new(FfiSubGuard {
                    ctx: handle_ref.ctx,
                    unsubscribe: handle_ref.vtable.host_unsubscribe,
                    sub_id,
                    cb_ctx,
                    free,
                })
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias, services, ..
            } => services.subscribe_credential_revoked(alias.as_ref(), cb),
        }
    }

    /// Subscribe to secret-rotation events `(secret_ref, version)`.
    /// The returned guard unsubscribes on drop.
    pub fn subscribe_secret_rotation(
        &self,
        cb: SecretRotationCallback,
    ) -> SecretRotationSubscription {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                extern "C" fn tramp(cb_ctx: usize, secret_ref: RString, version: u64) {
                    // SAFETY: see subscribe_credential_revoked.
                    let cb = unsafe { &*(cb_ctx as *const SecretRotationCallback) };
                    // A panic in the plugin's callback must not unwind across
                    // this `extern "C"` boundary (aborts the process on
                    // rustc >= 1.81).
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        cb(secret_ref.as_str(), version);
                    }));
                }
                unsafe fn free(cb_ctx: usize) {
                    drop(unsafe { Box::from_raw(cb_ctx as *mut SecretRotationCallback) });
                }
                let cb_ctx = Box::into_raw(Box::new(cb)) as usize;
                let sub_id = (handle_ref.vtable.subscribe_secret_rotation)(
                    handle_ref.ctx,
                    tramp as *const () as usize,
                    cb_ctx,
                );
                SecretRotationSubscription::new(FfiSubGuard {
                    ctx: handle_ref.ctx,
                    unsubscribe: handle_ref.vtable.host_unsubscribe,
                    sub_id,
                    cb_ctx,
                    free,
                })
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias, services, ..
            } => services.subscribe_secret_rotation(alias.as_ref(), cb),
        }
    }

    /// Issue a per-caller credential for an outbound call. The
    /// host filters against the plugin's `CredentialIssue{kinds}`
    /// capability before dispatching to the named issuer.
    pub fn issue_credential(
        &self,
        uri: &str,
        identity: &PluginIdentity,
    ) -> Result<IssuedCredential, CredentialError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let id_json = serde_json::to_string(identity).map_err(|e| {
                    CredentialError::Misconfigured {
                        reason: format!("identity serialise: {e}"),
                    }
                })?;
                let out: RString = (handle_ref.vtable.issue_credential)(
                    handle_ref.ctx,
                    RString::from(uri),
                    RString::from(id_json),
                );
                decode_result_envelope::<IssuedCredential, CredentialError>(out.as_str()).map_err(
                    |e| CredentialError::Misconfigured {
                        reason: format!("undecodable credential envelope: {e}"),
                    },
                )?
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.clone();
                let uri = uri.to_owned();
                let identity = identity.clone();
                block_on_or_err(
                    runtime,
                    async move { services.issue_credential(&alias, &uri, identity).await },
                    || CredentialError::Backend {
                        reason: "host handle: no tokio runtime captured".into(),
                    },
                )
            }
        }
    }

    /// Read a configuration snapshot. The host filters against the
    /// plugin's `ConfigRead{schemes}` capability.
    pub fn config_snapshot(&self, uri: &str) -> Result<ConfigSnapshot, ConfigError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let out: RString =
                    (handle_ref.vtable.config_snapshot)(handle_ref.ctx, RString::from(uri));
                decode_result_envelope::<ConfigSnapshot, ConfigError>(out.as_str()).map_err(
                    |e| ConfigError::Backend {
                        reason: format!("undecodable config envelope: {e}"),
                    },
                )?
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.clone();
                let uri = uri.to_owned();
                block_on_or_err(
                    runtime,
                    async move { services.config_snapshot(&alias, &uri).await },
                    || ConfigError::Backend {
                        reason: "host handle: no tokio runtime captured".into(),
                    },
                )
            }
        }
    }

    /// Emit an audit event. The host force-overwrites the event's
    /// `plugin_alias` field (when present) with the handle's alias
    /// before fan-out so plugins cannot spoof another plugin's
    /// audit trail.
    pub fn audit_event(&self, event: AuditEvent) -> Result<AuditReceipt, AuditError> {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let event_json =
                    serde_json::to_string(&event).map_err(|e| AuditError::WriteFailed {
                        reason: format!("event serialise: {e}"),
                    })?;
                let out: RString =
                    (handle_ref.vtable.audit_event)(handle_ref.ctx, RString::from(event_json));
                decode_result_envelope::<AuditReceipt, AuditError>(out.as_str()).map_err(|e| {
                    AuditError::WriteFailed {
                        reason: format!("undecodable audit envelope: {e}"),
                    }
                })?
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias,
                services,
                runtime,
                ..
            } => {
                let services = services.clone();
                let alias = alias.clone();
                block_on_or_err(
                    runtime,
                    async move { services.audit_event(&alias, event).await },
                    || AuditError::WriteFailed {
                        reason: "host handle: no tokio runtime captured".into(),
                    },
                )
            }
        }
    }

    /// Emit a single metric point. The host prepends a
    /// `plugin_alias=<alias>` label before forwarding to the global
    /// `metrics-rs` recorder.
    pub fn emit_metric(&self, point: MetricPoint) {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let payload =
                    serde_json::to_string(&point).expect("MetricPoint serialise is infallible");
                (handle_ref.vtable.metric_emit)(handle_ref.ctx, RString::from(payload));
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias, services, ..
            } => {
                services.metric_emit(alias.as_ref(), point.into_host());
            }
        }
    }

    /// Convenience: increment a counter by `value`.
    pub fn counter(&self, name: impl Into<String>, value: u64, labels: &[(&str, &str)]) {
        self.emit_metric(MetricPoint::Counter {
            name: name.into(),
            value,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        });
    }

    /// Convenience: set a gauge to `value`.
    pub fn gauge(&self, name: impl Into<String>, value: f64, labels: &[(&str, &str)]) {
        self.emit_metric(MetricPoint::Gauge {
            name: name.into(),
            value,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        });
    }

    /// Convenience: record a histogram observation.
    pub fn histogram(&self, name: impl Into<String>, value: f64, labels: &[(&str, &str)]) {
        self.emit_metric(MetricPoint::Histogram {
            name: name.into(),
            value,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        });
    }

    /// Open a tracing span attributed to this plugin. Returns a
    /// [`SpanGuard`] whose Drop calls `span_end`.
    ///
    /// `attrs` is a JSON object the host attaches as span fields.
    /// Pass `serde_json::json!({})` when there are no extra fields.
    pub fn span(&self, name: &str, attrs: serde_json::Value) -> SpanGuard {
        let attrs_json = attrs.to_string();
        let span_id = match &self.backend {
            Backend::Ffi { handle_ref } => (handle_ref.vtable.span_start)(
                handle_ref.ctx,
                RString::from(name),
                RString::from(attrs_json),
            ),
            #[cfg(feature = "static-firstparty")]
            Backend::Services {
                alias, services, ..
            } => services.span_start(alias.as_ref(), name, attrs),
        };
        SpanGuard {
            handle: self.clone(),
            span_id,
        }
    }

    /// Record an event on an active span. `span_id == 0` records on
    /// the current span (the host's tracing subscriber decides what
    /// "current" means).
    pub fn span_event(&self, span_id: u64, name: &str, attrs: serde_json::Value) {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                let attrs_json = attrs.to_string();
                (handle_ref.vtable.span_event)(
                    handle_ref.ctx,
                    span_id,
                    RString::from(name),
                    RString::from(attrs_json),
                );
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services { services, .. } => {
                services.span_event(span_id, name, attrs);
            }
        }
    }

    /// Close a span previously opened with [`HostHandle::span`].
    /// Usually called automatically via [`SpanGuard::drop`].
    fn span_end_raw(&self, span_id: u64) {
        match &self.backend {
            Backend::Ffi { handle_ref } => {
                (handle_ref.vtable.span_end)(handle_ref.ctx, span_id);
            }
            #[cfg(feature = "static-firstparty")]
            Backend::Services { services, .. } => {
                services.span_end(span_id);
            }
        }
    }
}

/// RAII guard for an open span. Drop calls
/// [`HostHandle::span_end_raw`].
pub struct SpanGuard {
    handle: HostHandle,
    span_id: u64,
}

impl SpanGuard {
    /// The opaque span id the host returned. `0` indicates the host
    /// did not allocate an addressable handle (see
    /// `mcpg_plugin_host::host_services::HostServices::span_start`);
    /// `span_event` calls still flow through but lose the
    /// `span_id` selector.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.span_id
    }

    /// Record an event on this span.
    pub fn event(&self, name: &str, attrs: serde_json::Value) {
        self.handle.span_event(self.span_id, name, attrs);
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        self.handle.span_end_raw(self.span_id);
    }
}

impl std::fmt::Debug for SpanGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpanGuard")
            .field("span_id", &self.span_id)
            .finish()
    }
}

fn decode_secret_envelope(s: &str) -> Result<SecretValue, SecretError> {
    decode_result_envelope::<SecretValueWire, SecretError>(s)
        .map_err(|e| SecretError::Backend {
            reason: format!("undecodable secret envelope: {e}"),
        })?
        .map(SecretValue::from)
}

#[cfg(feature = "static-firstparty")]
fn block_on_or_err<T, E, F, FErr>(
    runtime: &Option<tokio::runtime::Handle>,
    fut: F,
    on_no_runtime: FErr,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    FErr: FnOnce() -> E,
{
    match runtime {
        Some(rt) => rt.block_on(fut),
        None => Err(on_no_runtime()),
    }
}

/// Wire shape of the `resolve_credentials` FFI `ok` envelope.
#[derive(serde::Deserialize)]
struct ResolveCredsWire {
    value: serde_json::Value,
    count: usize,
}

/// Map a malformed result-envelope (serde) error from a backend host
/// service slot into a `BackendHostError`.
fn envelope_err(e: serde_json::Error) -> BackendHostError {
    BackendHostError::Backend {
        tool_name: String::new(),
        cause: mcpg_plugin_protocol::BackendError::Transport {
            message: format!("host service: bad result envelope: {e}"),
        },
    }
}

/// RAII guard for an FFI host subscription. On drop it tells the host to
/// stop firing the callback (`host_unsubscribe`), then reclaims the boxed
/// plugin callback. Stored inside the protocol's subscription wrapper so
/// the subscriber holds a single opaque guard regardless of backend.
struct FfiSubGuard {
    ctx: usize,
    unsubscribe: extern "C" fn(usize, u64),
    sub_id: u64,
    cb_ctx: usize,
    free: unsafe fn(usize),
}

// SAFETY: `ctx` points at the host bridge (Send+Sync, outlives the
// plugin); `cb_ctx` is a heap box owned solely by this guard; the fn
// pointers are plain `extern "C"` items. The guard is the unique owner
// of `cb_ctx` so there's no aliasing.
unsafe impl Send for FfiSubGuard {}
unsafe impl Sync for FfiSubGuard {}

impl Drop for FfiSubGuard {
    fn drop(&mut self) {
        if self.sub_id != 0 {
            (self.unsubscribe)(self.ctx, self.sub_id);
        }
        // SAFETY: `cb_ctx` was `Box::into_raw`'d in the subscribe call and
        // is reclaimed exactly once here; the host stopped invoking it via
        // the unsubscribe above.
        unsafe { (self.free)(self.cb_ctx) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::stub_host_ref;

    #[test]
    fn host_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HostHandle>();
        assert_send_sync::<SpanGuard>();
        assert_send_sync::<MetricPoint>();
    }

    #[test]
    fn ffi_alias_returns_empty_from_stub() {
        // The stub vtable returns RString::new() for every slot — exercise
        // the dispatch path without asserting on payload content.
        let handle = unsafe { HostHandle::from_ffi(stub_host_ref()) };
        assert_eq!(handle.alias(), "");
    }

    #[test]
    fn ffi_cluster_is_none_from_stub() {
        let handle = unsafe { HostHandle::from_ffi(stub_host_ref()) };
        assert!(handle.cluster().is_none());
    }

    #[test]
    fn ffi_span_guard_drops_cleanly() {
        let handle = unsafe { HostHandle::from_ffi(stub_host_ref()) };
        let guard = handle.span("test.span", serde_json::json!({"k": "v"}));
        assert_eq!(guard.id(), 0); // stub's s_span_start returns 0
        guard.event("midway", serde_json::json!({}));
        // Drop closes the span — no panic, no UB on the stub vtable.
    }

    #[test]
    fn ffi_emit_metric_doesnt_panic() {
        let handle = unsafe { HostHandle::from_ffi(stub_host_ref()) };
        handle.counter("requests_total", 1, &[("route", "/v1/foo")]);
        handle.gauge("queue_depth", 42.0, &[]);
        handle.histogram("latency_seconds", 0.012, &[]);
        handle.emit_metric(MetricPoint::Counter {
            name: "raw".into(),
            value: 7,
            labels: vec![("dim".into(), "x".into())],
        });
    }

    #[test]
    fn ffi_resolve_secret_returns_decoder_error_on_empty_envelope() {
        // Stub returns RString::new() → undecodable as a result envelope.
        let handle = unsafe { HostHandle::from_ffi(stub_host_ref()) };
        let err = handle.resolve_secret("vault://kv/x").unwrap_err();
        assert!(matches!(err, SecretError::Backend { .. }));
    }

    #[test]
    fn metric_point_serde_round_trip() {
        let p = MetricPoint::Histogram {
            name: "latency".into(),
            value: 0.5,
            labels: vec![("route".into(), "/foo".into())],
        };
        let j = serde_json::to_string(&p).unwrap();
        // Wire shape MUST match the host's `MetricPoint` exactly so the
        // FFI seam is lossless.
        assert!(j.contains(r#""kind":"histogram""#));
        let back: MetricPoint = serde_json::from_str(&j).unwrap();
        match back {
            MetricPoint::Histogram {
                name,
                value,
                labels,
            } => {
                assert_eq!(name, "latency");
                assert!((value - 0.5).abs() < 1e-9);
                assert_eq!(labels, vec![("route".into(), "/foo".into())]);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[cfg(feature = "static-firstparty")]
    mod services_backend {
        use super::*;
        use mcpg_plugin_host::host_services::HostServices;
        use mcpg_plugin_protocol::async_trait;
        use std::sync::Mutex;

        #[derive(Default)]
        struct Recorder {
            calls: Mutex<Vec<String>>,
        }

        #[async_trait]
        impl HostServices for Recorder {
            async fn resolve_secret(
                &self,
                alias: &str,
                uri: &str,
            ) -> Result<SecretValue, SecretError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("resolve_secret(alias={alias}, uri={uri})"));
                Ok(SecretValue::new(b"value-bytes".to_vec()))
            }

            async fn issue_credential(
                &self,
                alias: &str,
                uri: &str,
                _identity: PluginIdentity,
            ) -> Result<IssuedCredential, CredentialError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("issue_credential(alias={alias}, uri={uri})"));
                Ok(IssuedCredential::from_value("tok-abc", 60))
            }

            async fn config_snapshot(
                &self,
                alias: &str,
                uri: &str,
            ) -> Result<ConfigSnapshot, ConfigError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("config_snapshot(alias={alias}, uri={uri})"));
                Ok(ConfigSnapshot {
                    version: "v1".into(),
                    values: serde_json::json!({"x": 1}),
                    fetched_at: "2026-05-11T00:00:00Z".into(),
                    source: uri.to_owned(),
                })
            }

            async fn audit_event(
                &self,
                alias: &str,
                event: AuditEvent,
            ) -> Result<AuditReceipt, AuditError> {
                self.calls.lock().unwrap().push(format!(
                    "audit_event(alias={alias}, action={})",
                    event.action
                ));
                Ok(AuditReceipt {
                    sink_id: "test.sink".into(),
                    persisted_at: event.occurred_at,
                    durable_hash: String::new(),
                })
            }

            fn metric_emit(
                &self,
                alias: &str,
                _point: mcpg_plugin_host::host_services::MetricPoint,
            ) {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("metric_emit(alias={alias})"));
            }

            fn span_start(&self, alias: &str, name: &str, _attrs: serde_json::Value) -> u64 {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("span_start(alias={alias}, name={name})"));
                42
            }

            fn span_end(&self, span_id: u64) {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("span_end(span_id={span_id})"));
            }

            fn span_event(&self, span_id: u64, name: &str, _attrs: serde_json::Value) {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("span_event(span_id={span_id}, name={name})"));
            }
        }

        fn ident() -> PluginIdentity {
            PluginIdentity {
                kind: "test".into(),
                trust_level: "untrusted".into(),
                subject_id: Some("alice".into()),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            }
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn services_path_round_trips_alias_and_calls() {
            // Plugin slots are dispatched from `spawn_blocking` worker
            // threads in production (the host bridges sync FFI calls
            // through that path), so the `block_on` inside
            // HostHandle's services backend resolves to a fresh
            // worker — mirror that here.
            let rec = Arc::new(Recorder::default());
            let handle = HostHandle::from_services(rec.clone(), "test-alias", None);

            assert_eq!(handle.alias(), "test-alias");
            assert!(handle.cluster().is_none());

            let h = handle.clone();
            let recorded = tokio::task::spawn_blocking(move || {
                let v = h.resolve_secret("vault://kv/x").unwrap();
                assert_eq!(v.bytes.as_ref(), b"value-bytes");

                let _ = h
                    .issue_credential("cred://issuer/target", &ident())
                    .unwrap();

                let _ = h.config_snapshot("file:///foo").unwrap();

                let event = AuditEvent {
                    event_id: "evt-1".into(),
                    occurred_at: "2026-05-11T00:00:00Z".into(),
                    actor: ident(),
                    action: "test.action".into(),
                    resource: None,
                    outcome: mcpg_plugin_protocol::audit::AuditOutcome::Success,
                    request_id: None,
                    node_id: None,
                    details: serde_json::json!({}),
                    prev_event_hash: None,
                };
                let _ = h.audit_event(event).unwrap();

                h.counter("c", 1, &[]);
                {
                    let g = h.span("s", serde_json::json!({}));
                    assert_eq!(g.id(), 42);
                    g.event("e", serde_json::json!({}));
                }
            })
            .await;
            recorded.unwrap();

            let calls = rec.calls.lock().unwrap().clone();
            assert!(
                calls
                    .iter()
                    .any(|s| s == "resolve_secret(alias=test-alias, uri=vault://kv/x)")
            );
            assert!(
                calls
                    .iter()
                    .any(|s| s.starts_with("issue_credential(alias=test-alias"))
            );
            assert!(
                calls
                    .iter()
                    .any(|s| s.starts_with("config_snapshot(alias=test-alias"))
            );
            assert!(
                calls
                    .iter()
                    .any(|s| s == "audit_event(alias=test-alias, action=test.action)")
            );
            assert!(calls.iter().any(|s| s == "metric_emit(alias=test-alias)"));
            assert!(
                calls
                    .iter()
                    .any(|s| s == "span_start(alias=test-alias, name=s)")
            );
            assert!(calls.iter().any(|s| s == "span_event(span_id=42, name=e)"));
            assert!(calls.iter().any(|s| s == "span_end(span_id=42)"));
        }
    }
}
