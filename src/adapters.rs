//! Sync-to-async trait adapters used by the unified
//! [`declare_plugin!`](crate::declare_plugin) macro to bridge the
//! cdylib-side `SyncToolGate`-style sync traits into the
//! `ToolGatePlugin`-style async traits the host registry consumes.
//!
//! The macro emits a `register_static(registrar, granted)` function
//! alongside the cdylib `mcpg_plugin_register()` export so a plugin
//! crate can be compiled both ways from one source:
//!
//! - **cdylib build** (`--features cdylib-export`) — the user's
//!   `SyncToolGate` implementation is lifted to the FFI vtable by
//!   the per-entity wrappers (the same path the per-kind macros
//!   already use).
//! - **static-firstparty build** — `register_static()` wraps the same
//!   `SyncToolGate` implementation in [`SyncToolGateAdapter`], boxes
//!   it as `Box<dyn ToolGatePlugin>`, and hands it to
//!   `FirstPartyRegistrar::register`. No FFI, no JSON, no
//!   `spawn_blocking` — direct in-process trait dispatch (~ns
//!   per-call vs ~µs through the FFI).
//!
//! [`SyncToolGateAdapter`] below is the canonical shape; the other 19
//! sync traits (`SyncIdentityResolver`, `SyncBackendPlugin`, ...) each
//! get a matching `Sync*Adapter` further down, one per entity kind the
//! `declare_plugin!` macro accepts.

use async_trait::async_trait;

use mcpg_plugin_protocol::manifest::PluginManifest;
use mcpg_plugin_protocol::traits::ToolGatePlugin;
use mcpg_plugin_protocol::types::{GateDecision, PluginContext};

use crate::ffi::SyncToolGate;

/// Newtype that lifts a [`SyncToolGate`] implementation into the
/// async [`ToolGatePlugin`] trait the host registry consumes.
///
/// The adapter is `#[repr(transparent)]` — it owns the inner sync
/// plugin by value, no boxing, no virtual call beyond the async-trait
/// shim itself. Each delegated method calls into the inner trait
/// directly; the `async fn` wrapper resolves immediately because the
/// sync trait methods are pure compute.
///
/// # Construction
///
/// The unified `declare_plugin!` macro constructs the adapter as
/// `Box::new(SyncToolGateAdapter::new(<UserType>::factory(...)))`
/// inside the `register_static()` it emits. Plugin authors do not
/// construct it directly; it exists as a public type so the macro
/// expansion is visible in rustdoc.
#[repr(transparent)]
pub struct SyncToolGateAdapter<T: SyncToolGate> {
    inner: T,
}

impl<T: SyncToolGate> SyncToolGateAdapter<T> {
    /// Wrap a sync `ToolGate` implementation so it satisfies the
    /// async [`ToolGatePlugin`] trait.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped sync plugin. Tests / introspection only.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Unwrap and recover the inner plugin.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait]
impl<T: SyncToolGate> ToolGatePlugin for SyncToolGateAdapter<T> {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        meta: Option<&serde_json::Value>,
        config: &serde_json::Value,
    ) -> GateDecision {
        self.inner.evaluate_pre(ctx, arguments, meta, config)
    }

    async fn evaluate_post_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        result: &serde_json::Value,
        execution_duration_ms: u64,
        config: &serde_json::Value,
    ) -> GateDecision {
        self.inner
            .evaluate_post(ctx, arguments, result, execution_duration_ms, config)
    }

    async fn shutdown(&self) {
        self.inner.shutdown();
    }
}

// ===========================================================================
// Follow-on adapters
//
// Same shape as `SyncToolGateAdapter` above — one `#[repr(transparent)]`
// newtype + `new` / `inner` / `into_inner` + `#[async_trait]` impl
// delegating each async method to the wrapped sync trait. One section per
// kind. Every entity kind that the unified `declare_plugin!` macro accepts
// has a matching `Sync*Adapter` here, since `declare_plugin!`'s
// `register_static` expansion needs it to bridge the sync user trait into
// the async host trait without going through the FFI vtable.
// ===========================================================================

// ---------------------------------------------------------------------------
// Transform
// ---------------------------------------------------------------------------

/// Lifts a [`SyncTransform`](crate::ffi::SyncTransform) implementation
/// into the async [`TransformPlugin`] trait the host registry consumes.
/// Same shape as [`SyncToolGateAdapter`].
#[repr(transparent)]
pub struct SyncTransformAdapter<T: crate::ffi::SyncTransform> {
    inner: T,
}

impl<T: crate::ffi::SyncTransform> SyncTransformAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
    pub fn inner(&self) -> &T {
        &self.inner
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait]
impl<T: crate::ffi::SyncTransform> mcpg_plugin_protocol::traits::TransformPlugin
    for SyncTransformAdapter<T>
{
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    async fn transform_arguments(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        config: &serde_json::Value,
    ) -> mcpg_plugin_protocol::types::TransformResult {
        self.inner.transform_arguments(ctx, arguments, config)
    }

    async fn transform_result(
        &self,
        ctx: &PluginContext,
        result: &serde_json::Value,
        config: &serde_json::Value,
    ) -> mcpg_plugin_protocol::types::TransformResult {
        self.inner.transform_result(ctx, result, config)
    }

    async fn shutdown(&self) {
        self.inner.shutdown();
    }
}

mod sinks {
    use std::time::Duration;

    use async_trait::async_trait;

    use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditReceipt, AuditSink};
    use mcpg_plugin_protocol::logs::{LogError, LogRecord, LogSink};
    use mcpg_plugin_protocol::manifest::PluginManifest;
    use mcpg_plugin_protocol::metrics::{MetricsError, MetricsSink};
    use mcpg_plugin_protocol::telemetry::{
        MetricPoint, SpanEnd, SpanStart, TelemetryError, TelemetrySink,
    };

    use crate::ffi::{SyncAuditSink, SyncLogSink, SyncMetricsSink, SyncTelemetrySink};

    /// Lifts a [`SyncAuditSink`] implementation into the async
    /// [`AuditSink`] trait the host registry consumes. Same pattern
    /// as [`SyncToolGateAdapter`](super::SyncToolGateAdapter).
    #[repr(transparent)]
    pub struct SyncAuditSinkAdapter<T: SyncAuditSink> {
        inner: T,
    }

    impl<T: SyncAuditSink> SyncAuditSinkAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncAuditSink> AuditSink for SyncAuditSinkAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
            self.inner.emit(event)
        }
        async fn flush(&self, timeout_ms: u64) -> Result<(), AuditError> {
            self.inner.flush(timeout_ms)
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    /// Lifts a [`SyncLogSink`] implementation into the async
    /// [`LogSink`] trait. Same pattern as [`SyncToolGateAdapter`](super::SyncToolGateAdapter).
    /// Note: async `flush` takes `Duration`, sync takes `u64 ms` — bridged via `as_millis() as u64`.
    #[repr(transparent)]
    pub struct SyncLogSinkAdapter<T: SyncLogSink> {
        inner: T,
    }

    impl<T: SyncLogSink> SyncLogSinkAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncLogSink> LogSink for SyncLogSinkAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn emit(&self, record: &LogRecord) {
            self.inner.emit(record);
        }
        async fn flush(&self, timeout: Duration) -> Result<(), LogError> {
            self.inner.flush(timeout.as_millis() as u64)
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    /// Lifts a [`SyncMetricsSink`] implementation into the async
    /// [`MetricsSink`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](super::SyncToolGateAdapter).
    #[repr(transparent)]
    pub struct SyncMetricsSinkAdapter<T: SyncMetricsSink> {
        inner: T,
    }

    impl<T: SyncMetricsSink> SyncMetricsSinkAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncMetricsSink> MetricsSink for SyncMetricsSinkAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn emit(&self, metric: &MetricPoint) {
            self.inner.emit(metric);
        }
        async fn flush(&self, timeout: Duration) -> Result<(), MetricsError> {
            self.inner.flush(timeout.as_millis() as u64)
        }
        async fn render_text_exposition(&self) -> Option<String> {
            self.inner.render_text_exposition()
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    /// Lifts a [`SyncTelemetrySink`] implementation into the async
    /// [`TelemetrySink`] trait. Sync takes `&SpanStart` / `&SpanEnd`
    /// / `&MetricPoint`; async takes them by value — adapter inserts
    /// `&span` / `&metric` borrows.
    #[repr(transparent)]
    pub struct SyncTelemetrySinkAdapter<T: SyncTelemetrySink> {
        inner: T,
    }

    impl<T: SyncTelemetrySink> SyncTelemetrySinkAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncTelemetrySink> TelemetrySink for SyncTelemetrySinkAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn span_started(&self, span: SpanStart) {
            self.inner.span_started(&span);
        }
        async fn span_ended(&self, span: SpanEnd) {
            self.inner.span_ended(&span);
        }
        async fn metric_recorded(&self, metric: MetricPoint) {
            self.inner.metric_recorded(&metric);
        }
        async fn log_recorded(&self, record: &LogRecord) {
            self.inner.log_recorded(record);
        }
        async fn flush(&self, timeout: Duration) -> Result<(), TelemetryError> {
            self.inner.flush(timeout.as_millis() as u64)
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }
}
pub use sinks::{
    SyncAuditSinkAdapter, SyncLogSinkAdapter, SyncMetricsSinkAdapter, SyncTelemetrySinkAdapter,
};

mod simple_kinds {
    use async_trait::async_trait;

    use mcpg_plugin_protocol::approval_notifier::{
        ApprovalNotifier, NotificationError, NotificationRequest, NotificationResult,
    };
    use mcpg_plugin_protocol::catalog::{CatalogEntry, CatalogProvider, EnrichedToolDescriptor};
    use mcpg_plugin_protocol::manifest::PluginManifest;
    use mcpg_plugin_protocol::traits::IdentityProviderPlugin;
    use mcpg_plugin_protocol::types::{IdentityResolution, PluginContext, RequestMetadata};

    use crate::ffi::{SyncApprovalNotifier, SyncCatalogProvider, SyncIdentityResolver};

    /// Lifts a [`SyncIdentityResolver`] implementation into the async
    /// [`IdentityProviderPlugin`] trait. The async trait has no
    /// `shutdown` slot — the host treats `drop_instance` as the only
    /// teardown point for identity plugins.
    #[repr(transparent)]
    pub struct SyncIdentityAdapter<T: SyncIdentityResolver> {
        inner: T,
    }

    impl<T: SyncIdentityResolver> SyncIdentityAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncIdentityResolver> IdentityProviderPlugin for SyncIdentityAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn resolve_identity(
            &self,
            headers: &[(String, String)],
            metadata: &RequestMetadata,
            config: &serde_json::Value,
        ) -> IdentityResolution {
            self.inner.resolve_identity(headers, metadata, config)
        }
    }

    /// Lifts a [`SyncApprovalNotifier`] implementation into the async
    /// [`ApprovalNotifier`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](super::SyncToolGateAdapter).
    #[repr(transparent)]
    pub struct SyncApprovalNotifierAdapter<T: SyncApprovalNotifier> {
        inner: T,
    }

    impl<T: SyncApprovalNotifier> SyncApprovalNotifierAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncApprovalNotifier> ApprovalNotifier for SyncApprovalNotifierAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn notify(
            &self,
            request: &NotificationRequest,
        ) -> Result<NotificationResult, NotificationError> {
            self.inner.notify(request)
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    /// Lifts a [`SyncCatalogProvider`] implementation into the async
    /// [`CatalogProvider`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](super::SyncToolGateAdapter).
    #[repr(transparent)]
    pub struct SyncCatalogProviderAdapter<T: SyncCatalogProvider> {
        inner: T,
    }

    impl<T: SyncCatalogProvider> SyncCatalogProviderAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncCatalogProvider> CatalogProvider for SyncCatalogProviderAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn filter_and_enrich(
            &self,
            ctx: &PluginContext,
            in_progress: &[EnrichedToolDescriptor],
        ) -> Vec<EnrichedToolDescriptor> {
            self.inner.filter_and_enrich(ctx, in_progress)
        }
        async fn describe(&self, tool_id: &str) -> Option<CatalogEntry> {
            self.inner.describe(tool_id)
        }
        async fn list_catalog(&self) -> Vec<CatalogEntry> {
            self.inner.list_catalog()
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }
}
pub use simple_kinds::{
    SyncApprovalNotifierAdapter, SyncCatalogProviderAdapter, SyncIdentityAdapter,
};

mod governance_kinds {
    use async_trait::async_trait;

    use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
    use mcpg_plugin_protocol::manifest::PluginManifest;
    use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyEngine, PolicyVersion};
    use mcpg_plugin_protocol::secret::{SecretError, SecretProvider, SecretValue};
    use mcpg_plugin_protocol::types::{PluginContext, PluginIdentity};

    use crate::ffi::{SyncCredentialIssuer, SyncPolicyEngine, SyncSecretProvider};

    /// Lifts a [`SyncPolicyEngine`] implementation into the async
    /// [`PolicyEngine`] trait. `name()` is sync on both sides; the
    /// other methods are async on the host side and delegate
    /// directly to the inner sync impl.
    #[repr(transparent)]
    pub struct SyncPolicyEngineAdapter<T: SyncPolicyEngine> {
        inner: T,
    }

    impl<T: SyncPolicyEngine> SyncPolicyEngineAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncPolicyEngine> PolicyEngine for SyncPolicyEngineAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        fn name(&self) -> &str {
            self.inner.name()
        }
        async fn evaluate(
            &self,
            decision_point: &str,
            input: &serde_json::Value,
            context: &PluginContext,
        ) -> PolicyDecision {
            self.inner.evaluate(decision_point, input, context)
        }
        async fn policy_version(&self) -> PolicyVersion {
            self.inner.policy_version()
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    /// Lifts a [`SyncCredentialIssuer`] implementation into the async
    /// [`CredentialIssuer`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](super::SyncToolGateAdapter).
    #[repr(transparent)]
    pub struct SyncCredentialIssuerAdapter<T: SyncCredentialIssuer> {
        inner: T,
    }

    impl<T: SyncCredentialIssuer> SyncCredentialIssuerAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncCredentialIssuer> CredentialIssuer for SyncCredentialIssuerAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        async fn issue(
            &self,
            identity: &PluginIdentity,
            target: &str,
            config: &serde_json::Value,
        ) -> Result<IssuedCredential, CredentialError> {
            self.inner.issue(identity, target, config)
        }
        async fn revoke(&self, lease_id: &str) -> Result<(), CredentialError> {
            self.inner.revoke(lease_id)
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    /// Lifts a [`SyncSecretProvider`] implementation into the async
    /// [`SecretProvider`] trait.
    ///
    /// `get` bridges `SecretValueWire` (Vec<u8>, FFI-friendly) → `SecretValue`
    /// (`bytes::Bytes`) via the existing `From` impl (zero-copy).
    ///
    /// **`watch` / `cancel_watch` intentionally NOT bridged.** The
    /// sync side is a push-callback (`Box<dyn Fn(&str)>` +
    /// `WatchHandleBox`); the async side returns a pull-stream
    /// (`BoxSecretRotationStream`). Bridging requires a host-side
    /// channel + the streaming-FFI watch plumbing,
    /// which doesn't fit the trivial 1:1 delegation pattern. The
    /// async trait's default `watch` returns
    /// `SecretError::UnsupportedScheme { scheme: "watch" }` —
    /// matches the cdylib path's behaviour when a plugin doesn't
    /// override `watch`. Operators that need rotation watching for
    /// a first-party `SecretProvider` should impl the async trait
    /// directly (no adapter) rather than relying on the streaming-FFI
    /// bridge.
    #[repr(transparent)]
    pub struct SyncSecretProviderAdapter<T: SyncSecretProvider> {
        inner: T,
    }

    impl<T: SyncSecretProvider> SyncSecretProviderAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncSecretProvider> SecretProvider for SyncSecretProviderAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }
        fn supported_schemes(&self) -> Vec<String> {
            self.inner.supported_schemes()
        }
        async fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
            self.inner.get(secret_ref).map(SecretValue::from)
        }
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }
}
pub use governance_kinds::{
    SyncCredentialIssuerAdapter, SyncPolicyEngineAdapter, SyncSecretProviderAdapter,
};

// ===========================================================================
// Follow-on adapters — backend / store / cache kinds.
// ===========================================================================

mod backend_store_cache_kinds {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;

    use mcpg_plugin_protocol::backend::{
        BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, ResourcePage,
    };
    use mcpg_plugin_protocol::cache::{Cache, CacheError};
    use mcpg_plugin_protocol::manifest::PluginManifest;
    use mcpg_plugin_protocol::store::{
        AppendResult, BoxStoreEventStream, Store, StoreError, StorePage, StoreRole, StoreValue,
    };

    use crate::ffi::{SyncBackendPlugin, SyncCachePlugin, SyncStorePlugin};

    // ---------------------------------------------------------------------------
    // Backend
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncBackendPlugin`] implementation into the async
    /// [`BackendPlugin`] trait the host registry consumes. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    ///
    /// `host` on `register_profile` is dropped — the sync FFI surface has no
    /// re-entrant tool-dispatch slot, and bindings that need it bind the host
    /// through a separate vtable slot. `execute_streaming` and
    /// `audit_metadata` are not overridden so the async trait's defaults
    /// (one-shot `Done` chunk, empty metadata) are inherited. Bindings whose
    /// upstream streams tokens or whose audit needs per-profile metadata
    /// MUST impl the async trait directly.
    #[repr(transparent)]
    pub struct SyncBackendPluginAdapter<T: SyncBackendPlugin> {
        inner: T,
    }

    impl<T: SyncBackendPlugin> SyncBackendPluginAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncBackendPlugin> BackendPlugin for SyncBackendPluginAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn kind(&self) -> &str {
            self.inner.kind()
        }

        async fn register_profile(
            &self,
            profile_name: &str,
            spec: &serde_json::Value,
            _host: Arc<dyn BackendHost>,
        ) -> Result<(), BackendError> {
            self.inner.register_profile(profile_name, spec)
        }

        async fn execute(
            &self,
            profile_name: &str,
            request: BackendRequest,
        ) -> Result<BackendResponse, BackendError> {
            self.inner.execute(profile_name, request)
        }

        fn input_schema(&self, profile_name: &str) -> Option<serde_json::Value> {
            self.inner.input_schema(profile_name)
        }

        fn output_schema(&self, profile_name: &str) -> Option<serde_json::Value> {
            self.inner.output_schema(profile_name)
        }

        async fn list_resources(
            &self,
            profile_name: &str,
            cursor: Option<&str>,
        ) -> Result<ResourcePage, BackendError> {
            self.inner.list_resources(profile_name, cursor)
        }

        async fn complete_template_variable(
            &self,
            profile_name: &str,
            variable_name: &str,
            prefix: &str,
            config: &serde_json::Value,
            context: &std::collections::BTreeMap<String, String>,
        ) -> Result<Vec<String>, BackendError> {
            self.inner.complete_template_variable(
                profile_name,
                variable_name,
                prefix,
                config,
                context,
            )
        }

        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    // ---------------------------------------------------------------------------
    // Store
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncStorePlugin`] implementation into the async [`Store`]
    /// trait. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    ///
    /// `StoreRole` is passed by value async-side, by reference sync-side —
    /// the adapter borrows on delegation. `StoreValue` / `StorePage` bridge
    /// via the existing `From<…Wire>` impls (zero-copy on bytes).
    ///
    /// `watch` is the same push-callback ↔ pull-stream gap as
    /// [`SyncSecretProviderAdapter`](crate::adapters::SyncSecretProviderAdapter)
    /// — but `Store::watch` has no async default, so the adapter must surface
    /// a body. It returns `StoreError::Unsupported { op: "watch" }`, matching
    /// the cdylib path's behaviour when the plugin doesn't implement watch.
    /// First-party stores that need watching must impl `Store` directly until
    /// the streaming-FFI-aware slice lands. `cancel_watch` has no async-side
    /// counterpart and is not delegated.
    #[repr(transparent)]
    pub struct SyncStorePluginAdapter<T: SyncStorePlugin> {
        inner: T,
    }

    impl<T: SyncStorePlugin> SyncStorePluginAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncStorePlugin> Store for SyncStorePluginAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn supported_roles(&self) -> Vec<StoreRole> {
            self.inner.supported_roles()
        }

        async fn get(&self, role: StoreRole, key: &str) -> Result<Option<StoreValue>, StoreError> {
            self.inner
                .get(&role, key)
                .map(|opt| opt.map(StoreValue::from))
        }

        async fn put(
            &self,
            role: StoreRole,
            key: &str,
            value: StoreValue,
        ) -> Result<(), StoreError> {
            self.inner.put(&role, key, value.into())
        }

        async fn delete(&self, role: StoreRole, key: &str) -> Result<(), StoreError> {
            self.inner.delete(&role, key)
        }

        async fn list(
            &self,
            role: StoreRole,
            prefix: &str,
            cursor: Option<String>,
        ) -> Result<StorePage, StoreError> {
            self.inner.list(&role, prefix, cursor).map(StorePage::from)
        }

        async fn compare_and_swap(
            &self,
            role: StoreRole,
            key: &str,
            expected: Option<StoreValue>,
            new: StoreValue,
        ) -> Result<bool, StoreError> {
            self.inner
                .compare_and_swap(&role, key, expected.map(Into::into), new.into())
        }

        async fn append(
            &self,
            role: StoreRole,
            key: &str,
            value: StoreValue,
        ) -> Result<AppendResult, StoreError> {
            self.inner.append(&role, key, value.into())
        }

        async fn watch(
            &self,
            _role: StoreRole,
            _key: &str,
        ) -> Result<BoxStoreEventStream, StoreError> {
            Err(StoreError::Unsupported { op: "watch".into() })
        }

        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    // ---------------------------------------------------------------------------
    // Cache
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncCachePlugin`] implementation into the async [`Cache`]
    /// trait. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    ///
    /// `bytes::Bytes` ↔ `Vec<u8>` bridge: `get` returns `Bytes::from(vec)`
    /// (move, not copy); `put` copies via `.to_vec()` (unavoidable across
    /// the FFI owned-buffer boundary). `Duration` ↔ `u64 ms` via
    /// `.as_millis() as u64`.
    #[repr(transparent)]
    pub struct SyncCachePluginAdapter<T: SyncCachePlugin> {
        inner: T,
    }

    impl<T: SyncCachePlugin> SyncCachePluginAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncCachePlugin> Cache for SyncCachePluginAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn supported_namespaces(&self) -> Vec<String> {
            self.inner.supported_namespaces()
        }

        fn serves_any_namespace(&self) -> bool {
            self.inner.serves_any_namespace()
        }

        async fn get(&self, ns: &str, key: &str) -> Option<bytes::Bytes> {
            self.inner.get(ns, key).map(bytes::Bytes::from)
        }

        async fn put(
            &self,
            ns: &str,
            key: &str,
            value: bytes::Bytes,
            ttl: Duration,
        ) -> Result<(), CacheError> {
            self.inner
                .put(ns, key, value.to_vec(), ttl.as_millis() as u64)
        }

        async fn delete(&self, ns: &str, key: &str) {
            self.inner.delete(ns, key);
        }

        async fn clear(&self, ns: &str) -> Result<(), CacheError> {
            self.inner.clear(ns)
        }

        async fn incr(
            &self,
            ns: &str,
            key: &str,
            by: i64,
            ttl: Duration,
        ) -> Result<i64, CacheError> {
            self.inner.incr(ns, key, by, ttl.as_millis() as u64)
        }

        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }
}
pub use backend_store_cache_kinds::{
    SyncBackendPluginAdapter, SyncCachePluginAdapter, SyncStorePluginAdapter,
};

// ===========================================================================
// content_store kind — factory + per-profile handle.
//
// Unlike the other factory kinds, `content_store`'s protocol surface is
// TWO traits: `ContentStorePlugin` (the factory, keyed by `kind`, builds
// profiles) and `ContentStore` (a single-profile blob handle). The
// cdylib's `SyncContentStore` is a multi-profile manager; this adapter
// lowers it into the factory (which registers a profile and hands back an
// `Arc<dyn ContentStore>`) plus a thin per-profile handle that re-attaches
// the profile name on every call. Only the static-firstparty path uses
// this adapter; the cdylib-load path is bridged host-side by
// `NativeContentStoreAdapter`.
// ===========================================================================

mod content_store_kinds {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;

    use mcpg_plugin_protocol::content_store::{
        ContentStore, ContentStoreError, ContentStorePlugin, ContentStoreStats, ContentToStore,
        ResourceContent, ResourceHandle,
    };
    use mcpg_plugin_protocol::manifest::PluginManifest;

    use crate::ffi::SyncContentStore;

    /// Lifts a [`SyncContentStore`] (multi-profile manager) into the async
    /// [`ContentStorePlugin`] factory the gateway's storage registry
    /// consumes. `build_profile` registers the profile on the inner manager
    /// and returns a per-profile [`ContentStore`] handle bound to that name.
    pub struct SyncContentStoreAdapter<T: SyncContentStore> {
        inner: Arc<T>,
    }

    impl<T: SyncContentStore> SyncContentStoreAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner: Arc::new(inner),
            }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
    }

    // The protocol traits require `Debug`, but `SyncContentStore` does not,
    // so emit a name-only impl that never touches `T`'s fields.
    impl<T: SyncContentStore> std::fmt::Debug for SyncContentStoreAdapter<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SyncContentStoreAdapter")
                .field("kind", &self.inner.kind())
                .finish()
        }
    }

    #[async_trait]
    impl<T: SyncContentStore> ContentStorePlugin for SyncContentStoreAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn kind(&self) -> &str {
            self.inner.kind()
        }

        async fn build_profile(
            &self,
            profile_name: &str,
            spec: &serde_json::Value,
        ) -> Result<Arc<dyn ContentStore>, ContentStoreError> {
            self.inner.register_profile(profile_name, spec)?;
            Ok(Arc::new(SyncContentStoreProfile {
                inner: Arc::clone(&self.inner),
                profile_name: profile_name.to_owned(),
            }))
        }
    }

    /// A single-profile [`ContentStore`] handle that re-attaches its
    /// `profile_name` to every call routed back into the shared
    /// [`SyncContentStore`] manager.
    struct SyncContentStoreProfile<T: SyncContentStore> {
        inner: Arc<T>,
        profile_name: String,
    }

    impl<T: SyncContentStore> std::fmt::Debug for SyncContentStoreProfile<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SyncContentStoreProfile")
                .field("kind", &self.inner.kind())
                .field("profile_name", &self.profile_name)
                .finish()
        }
    }

    #[async_trait]
    impl<T: SyncContentStore> ContentStore for SyncContentStoreProfile<T> {
        async fn put(&self, content: ContentToStore) -> Result<ResourceHandle, ContentStoreError> {
            self.inner.put(&self.profile_name, content)
        }

        async fn get(&self, id: &str) -> Result<Option<ResourceContent>, ContentStoreError> {
            self.inner.get(&self.profile_name, id)
        }

        async fn delete(&self, id: &str) -> Result<(), ContentStoreError> {
            self.inner.delete(&self.profile_name, id)
        }

        async fn signed_url(
            &self,
            id: &str,
            ttl: Duration,
        ) -> Result<Option<String>, ContentStoreError> {
            self.inner.signed_url(&self.profile_name, id, ttl)
        }

        fn stats(&self) -> ContentStoreStats {
            self.inner.stats(&self.profile_name)
        }

        async fn sweep_expired(&self) -> usize {
            self.inner.sweep_expired(&self.profile_name)
        }

        // The factory has no shutdown hook, so the per-profile handle is the
        // only teardown surface. Multiple profiles of one manager each
        // forward here, so `SyncContentStore::shutdown` MUST be idempotent.
        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }
}
pub use content_store_kinds::SyncContentStoreAdapter;

// ===========================================================================
// Follow-on adapters — http_route / message_dispatcher kinds.
//
// SyncTransport is deliberately NOT bridged here: the sync surface
// returns a SyncTransportHandle (raw cookie + vtable methods) and consumes
// Arc<dyn SyncMessageDispatcher> from its accept loop, while the async
// Transport returns Box<dyn TransportHandle> with async listen_address/close
// and consumes Arc<dyn MessageDispatcher>. Bridging requires both a
// trait-object-across-FFI wrapper and a sync→async dispatcher lowering with
// runtime-handle plumbing — the same streaming-FFI gap that
// SyncSecretProviderAdapter defers. Operators that need a first-party
// Transport impl the async trait directly (no adapter) rather than relying
// on an adapter.
// ===========================================================================

mod http_route_kinds {
    use async_trait::async_trait;
    use bytes::Bytes;

    use mcpg_plugin_protocol::http_route::{
        HttpRoute, HttpRouteRequest, HttpRouteResponse, RouteSpec,
    };
    use mcpg_plugin_protocol::manifest::PluginManifest;
    use mcpg_plugin_protocol::transport::{DispatchResponse, DispatcherError, MessageDispatcher};

    use crate::ffi::{SyncHttpRoute, SyncMessageDispatcher};

    // ---------------------------------------------------------------------------
    // HttpRoute
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncHttpRoute`] implementation into the async [`HttpRoute`]
    /// trait the host registry consumes. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    ///
    /// `routes()` is sync on both sides; `handle()` takes
    /// `HttpRouteRequest` by value on both sides — direct delegation.
    /// Streaming response bodies remain gated by `RouteSpec.streaming` on
    /// each emitted route; the adapter adds no extra constraint.
    #[repr(transparent)]
    pub struct SyncHttpRouteAdapter<T: SyncHttpRoute> {
        inner: T,
    }

    impl<T: SyncHttpRoute> SyncHttpRouteAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncHttpRoute> HttpRoute for SyncHttpRouteAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn routes(&self) -> Vec<RouteSpec> {
            self.inner.routes()
        }

        async fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse {
            self.inner.handle(req)
        }

        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    // ---------------------------------------------------------------------------
    // MessageDispatcher
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncMessageDispatcher`] implementation into the async
    /// [`MessageDispatcher`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    /// Neither trait carries a manifest.
    ///
    /// `Bytes` (async) → `&[u8]` (sync) borrows the underlying slice
    /// (zero copy). The sync reply `Vec<u8>` is wrapped as
    /// `DispatchResponse::unary(Vec<u8>)`; `DispatchResponse::stream` is
    /// unreachable from a sync dispatcher because no stream type exists on
    /// the sync side.
    #[repr(transparent)]
    pub struct SyncMessageDispatcherAdapter<T: SyncMessageDispatcher + 'static> {
        inner: T,
    }

    impl<T: SyncMessageDispatcher + 'static> SyncMessageDispatcherAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncMessageDispatcher + 'static> MessageDispatcher for SyncMessageDispatcherAdapter<T> {
        async fn dispatch(
            &self,
            session_id: &str,
            message: Bytes,
        ) -> Result<DispatchResponse, DispatcherError> {
            self.inner
                .dispatch(session_id, message.as_ref())
                .map(DispatchResponse::unary)
        }
    }
}
pub use http_route_kinds::{SyncHttpRouteAdapter, SyncMessageDispatcherAdapter};

// ===========================================================================
// Follow-on adapters — watch_strategy / config_provider kinds.
//
// SyncClusterBackend is deliberately NOT bridged here: its sync
// surface returns (WatchHandleBox, fencing_token, expires_at_rfc3339) tuples
// for leases with separate lease_renew/release/drop methods, while the async
// ClusterBackend returns BoxActiveLease trait objects whose renew/release
// are async fn on &self. Bridging requires constructing a trait-object
// wrapper that re-enters the sync coordinator on every call — the deferred
// trait-object-across-FFI work, not 1:1 delegation.
// Operators that need a first-party cluster coordinator impl the async trait
// directly (no adapter).
// ===========================================================================

mod watch_config_kinds {
    use std::sync::Arc;

    use async_trait::async_trait;

    use mcpg_plugin_protocol::backend::{
        WatchError, WatchEventSink, WatchHandle, WatchStrategyPlugin,
    };
    use mcpg_plugin_protocol::config::{ConfigError, ConfigProvider, ConfigSnapshot};
    use mcpg_plugin_protocol::manifest::PluginManifest;

    use crate::ffi::{SyncConfigProvider, SyncWatchStrategyPlugin};

    // ---------------------------------------------------------------------------
    // WatchStrategy
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncWatchStrategyPlugin`] implementation into the async
    /// [`WatchStrategyPlugin`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    ///
    /// `watch` is the push-callback ↔ typed-sink gap from
    /// [`SyncSecretProviderAdapter`](crate::adapters::SyncSecretProviderAdapter)
    /// — sync side hands a `Box<dyn Fn(&str)>` JSON callback plus a
    /// `WatchHandleBox`; async side hands an `Arc<dyn WatchEventSink>` and
    /// returns a `Box<dyn WatchHandle>`. Bridging needs JSON-decoding each
    /// event back into `WatchEvent` plus a tokio runtime handle to drive
    /// `sink.emit(...)` — streaming-FFI plumbing, not 1:1 delegation. The
    /// async trait has no `watch` default, so the adapter surfaces
    /// `WatchError::Subscribe` matching the sync trait's own "not bridgeable"
    /// signal. First-party watch strategies that need wired events must
    /// impl the async trait directly until that slice lands.
    #[repr(transparent)]
    pub struct SyncWatchStrategyAdapter<T: SyncWatchStrategyPlugin> {
        inner: T,
    }

    impl<T: SyncWatchStrategyPlugin> SyncWatchStrategyAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncWatchStrategyPlugin> WatchStrategyPlugin for SyncWatchStrategyAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn kind(&self) -> &str {
            self.inner.kind()
        }

        async fn watch(
            &self,
            _resource_uri: &str,
            _spec: &serde_json::Value,
            _sink: Arc<dyn WatchEventSink>,
        ) -> Result<Box<dyn WatchHandle>, WatchError> {
            Err(WatchError::Subscribe {
                message: "SyncWatchStrategyAdapter does not bridge `watch` across the \
                          sync push-callback / async typed-sink gap; impl the async \
                          trait directly"
                    .into(),
            })
        }

        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }

    // ---------------------------------------------------------------------------
    // ConfigProvider
    // ---------------------------------------------------------------------------

    /// Lifts a [`SyncConfigProvider`] implementation into the async
    /// [`ConfigProvider`] trait. Same pattern as
    /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
    ///
    /// `watch` is the same push-callback ↔ pull-stream gap as
    /// [`SyncSecretProviderAdapter`](crate::adapters::SyncSecretProviderAdapter)
    /// — the async trait's default returns `ConfigError::UnsupportedScheme`
    /// matching the cdylib path when no override is present, so the
    /// adapter doesn't override.
    #[repr(transparent)]
    pub struct SyncConfigProviderAdapter<T: SyncConfigProvider> {
        inner: T,
    }

    impl<T: SyncConfigProvider> SyncConfigProviderAdapter<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
        pub fn inner(&self) -> &T {
            &self.inner
        }
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    #[async_trait]
    impl<T: SyncConfigProvider> ConfigProvider for SyncConfigProviderAdapter<T> {
        fn manifest(&self) -> &PluginManifest {
            self.inner.manifest()
        }

        fn supported_schemes(&self) -> Vec<String> {
            self.inner.supported_schemes()
        }

        async fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError> {
            self.inner.snapshot(reference)
        }

        async fn shutdown(&self) {
            self.inner.shutdown();
        }
    }
}
pub use watch_config_kinds::{SyncConfigProviderAdapter, SyncWatchStrategyAdapter};

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
    use mcpg_plugin_protocol::types::PluginIdentity;

    struct AlwaysAllow {
        manifest: PluginManifest,
    }

    fn anon_ctx() -> PluginContext {
        PluginContext {
            request_id: "test-req".into(),
            session_id: None,
            tool_name: "test_tool".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "test".into(),
        }
    }

    impl AlwaysAllow {
        fn new() -> Self {
            Self {
                manifest: PluginManifest {
                    id: "dev.mcpg.test.always-allow".into(),
                    version: "0.1.0".into(),
                    name: "AlwaysAllow".into(),
                    plugin_class: PluginClass::ToolGate,
                    protocol_version: mcpg_plugin_protocol::PROTOCOL_VERSION.into(),
                    license: None,
                    required_capabilities: vec![],
                    tags: vec![],
                    provides: vec![],
                    provides_schemes: vec![],
                    module_path_prefix: "adapters_test".into(),
                    backend_profile: None,
                },
            }
        }
    }

    impl SyncToolGate for AlwaysAllow {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn evaluate_pre(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _cfg: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
        fn evaluate_post(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _result: &serde_json::Value,
            _dur: u64,
            _cfg: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
    }

    #[tokio::test]
    async fn adapter_delegates_pre_dispatch_to_sync() {
        let adapter = SyncToolGateAdapter::new(AlwaysAllow::new());
        let ctx = anon_ctx();
        let args = serde_json::json!({});
        let cfg = serde_json::json!({});
        let decision = adapter.evaluate_pre_dispatch(&ctx, &args, None, &cfg).await;
        assert!(decision.is_allow());
    }

    #[tokio::test]
    async fn adapter_delegates_post_dispatch_to_sync() {
        let adapter = SyncToolGateAdapter::new(AlwaysAllow::new());
        let ctx = anon_ctx();
        let args = serde_json::json!({});
        let result = serde_json::json!({});
        let cfg = serde_json::json!({});
        let decision = adapter
            .evaluate_post_dispatch(&ctx, &args, &result, 0, &cfg)
            .await;
        assert!(decision.is_allow());
    }

    #[tokio::test]
    async fn adapter_manifest_matches_inner() {
        let adapter = SyncToolGateAdapter::new(AlwaysAllow::new());
        assert_eq!(
            <SyncToolGateAdapter<AlwaysAllow> as ToolGatePlugin>::manifest(&adapter).id,
            "dev.mcpg.test.always-allow"
        );
    }
}
