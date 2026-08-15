//! Mock gateway test harness for plugin development.
//!
//! Provides a lightweight simulation of the MCPG plugin dispatch chain.
//! Developers test their plugins against this harness without running
//! a real gateway.

use mcpg_cluster_api::ClusterBackend;
use mcpg_plugin_protocol::{
    GateDecision, IdentityProviderPlugin, IdentityResolution, PluginContext, PluginIdentity,
    ToolGatePlugin, TransformPlugin, TransformResult,
    audit::{AuditEvent, AuditReceipt, AuditSink},
    cache::Cache,
    config::ConfigProvider,
    http_route::{HttpRoute, HttpRouteRequest, HttpRouteResponse, RouteSpec},
    logs::{LogRecord, LogSink},
    policy::PolicyEngine,
    secret::SecretProvider,
    store::{Store, StoreRole},
    telemetry::{MetricPoint, SpanEnd, SpanStart, TelemetrySink},
    transport::Transport,
};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Mock gateway
// ---------------------------------------------------------------------------

/// A mock gateway that simulates the plugin dispatch chain.
///
/// Register your plugins, then call `call_tool()` to simulate a tool call
/// flowing through the chain. Useful for integration testing.
pub struct MockGateway {
    tool_gates: Vec<(Box<dyn ToolGatePlugin>, serde_json::Value)>,
    transforms: Vec<(Box<dyn TransformPlugin>, serde_json::Value)>,
    identities: Vec<(Box<dyn IdentityProviderPlugin>, serde_json::Value)>,
    /// Registered `http_route` entities keyed by `(plugin_id,
    /// entity_name)` — mirrors the real registry's multi-entity
    /// layout so plugin authors can exercise collision behaviour
    /// before wiring against the live gateway.
    http_routes: Vec<(String, Arc<dyn HttpRoute>)>,
    /// Registered `audit_sink` entities in registration order.
    /// `emit_audit` fans every event out to every sink sequentially
    /// — matches the production registry's fan-out contract so
    /// plugin authors can test their sink's behaviour under
    /// multi-sink conditions.
    audit_sinks: Vec<Arc<dyn AuditSink>>,
    /// Role → plugin dispatch table for store entities. Mirrors
    /// the production registry's `bind_store_role` model: the
    /// SDK harness lets authors register a plugin under one or
    /// more roles without wiring a full operator-config block.
    stores: std::collections::BTreeMap<StoreRole, Arc<dyn Store>>,
    /// Namespace → plugin dispatch table for cache entities.
    /// Mirrors `bind_cache_namespace` semantics — same register-
    /// then-bind flow as stores, plus a `serves_any` escape hatch.
    caches: std::collections::BTreeMap<String, Arc<dyn Cache>>,
    /// Registered telemetry sinks for fan-out. Each `emit_*`
    /// helper fans the event to every sink in registration order
    /// — mirrors the production registry's contract.
    telemetry_sinks: Vec<Arc<dyn TelemetrySink>>,
    /// Registered log sinks for fan-out.
    log_sinks: Vec<Arc<dyn LogSink>>,
    /// Scheme → plugin dispatch table for secret providers.
    /// Mirrors `bind_secret_scheme` — same register-then-bind
    /// shape as stores / caches.
    secret_providers: std::collections::BTreeMap<String, Arc<dyn SecretProvider>>,
    /// Scheme → plugin dispatch table for config providers.
    /// Mirrors `bind_config_scheme` — same register-then-bind
    /// shape as secret providers.
    config_providers: std::collections::BTreeMap<String, Arc<dyn ConfigProvider>>,
    /// Transport-name → plugin dispatch table. Unlike secret /
    /// config (keyed by scheme), transport is keyed by the
    /// plugin's self-declared `name()`; the mock asserts the
    /// map key matches `plugin.name()` at insert time.
    transports: std::collections::BTreeMap<String, Arc<dyn Transport>>,
    /// Engine-name → plugin dispatch table. Same shape as
    /// transport — keyed by the plugin's self-declared `name()`.
    policy_engines: std::collections::BTreeMap<String, Arc<dyn PolicyEngine>>,
    /// Registered cluster coordinator (singleton — spec §9.13).
    /// `None` in a fresh mock; `Some` after `with_cluster_backend`.
    cluster_backend: Option<Arc<dyn ClusterBackend>>,
    default_identity: PluginIdentity,
}

impl MockGateway {
    /// Create a new empty mock gateway.
    pub fn new() -> Self {
        Self {
            tool_gates: Vec::new(),
            transforms: Vec::new(),
            identities: Vec::new(),
            http_routes: Vec::new(),
            audit_sinks: Vec::new(),
            stores: std::collections::BTreeMap::new(),
            caches: std::collections::BTreeMap::new(),
            telemetry_sinks: Vec::new(),
            log_sinks: Vec::new(),
            secret_providers: std::collections::BTreeMap::new(),
            config_providers: std::collections::BTreeMap::new(),
            transports: std::collections::BTreeMap::new(),
            policy_engines: std::collections::BTreeMap::new(),
            cluster_backend: None,
            default_identity: PluginIdentity {
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
        }
    }

    /// Register a tool-gate plugin with default config.
    pub fn with_tool_gate(mut self, plugin: Box<dyn ToolGatePlugin>) -> Self {
        self.tool_gates.push((plugin, serde_json::json!({})));
        self
    }

    /// Register a tool-gate plugin with specific config.
    pub fn with_tool_gate_config(
        mut self,
        plugin: Box<dyn ToolGatePlugin>,
        config: serde_json::Value,
    ) -> Self {
        self.tool_gates.push((plugin, config));
        self
    }

    /// Register a transform plugin with default config.
    pub fn with_transform(mut self, plugin: Box<dyn TransformPlugin>) -> Self {
        self.transforms.push((plugin, serde_json::json!({})));
        self
    }

    /// Register a transform plugin with specific config.
    pub fn with_transform_config(
        mut self,
        plugin: Box<dyn TransformPlugin>,
        config: serde_json::Value,
    ) -> Self {
        self.transforms.push((plugin, config));
        self
    }

    /// Register an identity plugin with default config.
    pub fn with_identity(mut self, plugin: Box<dyn IdentityProviderPlugin>) -> Self {
        self.identities.push((plugin, serde_json::json!({})));
        self
    }

    /// Set the default identity for simulated requests.
    pub fn with_default_identity(mut self, identity: PluginIdentity) -> Self {
        self.default_identity = identity;
        self
    }

    /// Register an `http_route` entity under `entity_name`. See
    /// [`Self::call_http_route`] for the dispatch helper.
    ///
    /// The mock gateway does NOT enforce the
    /// `(plugin_id, entity_name)` uniqueness that the real registry
    /// requires — duplicate registrations silently stack, and
    /// [`Self::call_http_route`] picks the first entity whose
    /// `entity_name` matches. Tests that want to exercise the
    /// duplicate-rejection path should use the real registry instead.
    pub fn with_http_route(
        mut self,
        entity_name: impl Into<String>,
        plugin: Arc<dyn HttpRoute>,
    ) -> Self {
        self.http_routes.push((entity_name.into(), plugin));
        self
    }

    /// Dispatch `req` to the registered `http_route` entity with
    /// `entity_name`. Runs the minimum viable subset of the real
    /// axum dispatcher (`apps/gateway/src/transports/http_route.rs`):
    ///
    /// - 404 (`HttpRouteResponse::status(404)`) if no entity
    ///   matches `entity_name`.
    /// - 404 if no `RouteSpec` matches the request's method +
    ///   relative path (`:name` placeholders are NOT captured here —
    ///   set them on `req.path_params` yourself if the plugin reads
    ///   them).
    /// - Otherwise, invokes the plugin's `handle` and returns its
    ///   response verbatim.
    ///
    /// This is intentionally simpler than the production dispatcher
    /// — no body-cap enforcement, no `requires_identity` 401, no
    /// streaming-response validation. Plugin authors want fast
    /// feedback on the happy path; edge cases are covered by the
    /// dispatcher's own unit tests.
    pub async fn call_http_route(
        &self,
        entity_name: &str,
        req: HttpRouteRequest,
    ) -> HttpRouteResponse {
        let Some((_, plugin)) = self
            .http_routes
            .iter()
            .find(|(name, _)| name == entity_name)
        else {
            return HttpRouteResponse::status(404);
        };

        let req_path = &req.method;
        let path = &req.full_path;
        let specs = plugin.routes();
        let matched = specs.iter().any(|s| spec_matches(s, req_path, path));
        if !matched {
            return HttpRouteResponse::status(404);
        }
        plugin.handle(req).await
    }

    /// Register an `audit_sink` for fan-out. [`Self::emit_audit`]
    /// fans every event out to every registered sink in registration
    /// order — matches the production registry's contract.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sinks.push(sink);
        self
    }

    /// Emit `event` to every registered audit sink. Returns one
    /// result per sink in registration order; fan-out continues
    /// across individual sink failures so a broken sink cannot
    /// starve the others (same semantics as the real registry).
    ///
    /// Unlike the production `PluginRegistry::emit_audit_event`,
    /// this helper does NOT record metrics — the mock harness is a
    /// unit-test affordance, not an observability surface.
    pub async fn emit_audit(
        &self,
        event: &AuditEvent,
    ) -> Vec<Result<AuditReceipt, mcpg_plugin_protocol::audit::AuditError>> {
        let mut out = Vec::with_capacity(self.audit_sinks.len());
        for sink in &self.audit_sinks {
            out.push(sink.emit(event).await);
        }
        out
    }

    /// Bind `role` to `plugin` in the mock's dispatch table. Per
    /// spec §9.8 the real registry refuses binding a role the
    /// plugin doesn't advertise; the mock re-checks via
    /// `plugin.supported_roles()` + panics on mismatch — unit
    /// tests want to catch the drift immediately, not surface it
    /// as a runtime error.
    pub fn with_store(mut self, role: StoreRole, plugin: Arc<dyn Store>) -> Self {
        let supported = plugin.supported_roles();
        assert!(
            supported.contains(&role),
            "MockGateway::with_store: plugin does not support role {role}; supported: {supported:?}",
        );
        self.stores.insert(role, plugin);
        self
    }

    /// Look up the store plugin bound to `role`. Mirrors
    /// `PluginRegistry::store_for_role` so test authors write the
    /// same code path against the mock and the production registry.
    pub fn store_for_role(&self, role: &StoreRole) -> Option<Arc<dyn Store>> {
        self.stores.get(role).cloned()
    }

    /// Bind `namespace` to `plugin` in the mock's cache dispatch
    /// table. Per spec §9.9 the real registry refuses binding a
    /// namespace the plugin doesn't advertise (unless the plugin's
    /// `serves_any_namespace = true`); the mock re-checks both
    /// paths + panics on mismatch so unit tests catch drift
    /// immediately.
    pub fn with_cache(mut self, namespace: impl Into<String>, plugin: Arc<dyn Cache>) -> Self {
        let namespace = namespace.into();
        let supported = plugin.supported_namespaces();
        let any = plugin.serves_any_namespace();
        assert!(
            any || supported.iter().any(|ns| ns == &namespace),
            "MockGateway::with_cache: plugin does not support namespace \
             '{namespace}'; supported: {supported:?}, serves_any: {any}",
        );
        self.caches.insert(namespace, plugin);
        self
    }

    /// Look up the cache plugin bound to `namespace`. Mirrors
    /// `PluginRegistry::cache_for_namespace`.
    pub fn cache_for_namespace(&self, namespace: &str) -> Option<Arc<dyn Cache>> {
        self.caches.get(namespace).cloned()
    }

    /// Register a telemetry sink for fan-out. Mirrors the
    /// production registry's `register_telemetry_sink` + sequential
    /// fan-out semantics.
    pub fn with_telemetry_sink(mut self, sink: Arc<dyn TelemetrySink>) -> Self {
        self.telemetry_sinks.push(sink);
        self
    }

    /// Fan `span` (Start) out to every registered telemetry sink.
    pub async fn emit_telemetry_span_started(&self, span: &SpanStart) {
        for sink in &self.telemetry_sinks {
            sink.span_started(span.clone()).await;
        }
    }

    /// Fan `span` (End) out to every registered telemetry sink.
    pub async fn emit_telemetry_span_ended(&self, span: &SpanEnd) {
        for sink in &self.telemetry_sinks {
            sink.span_ended(span.clone()).await;
        }
    }

    /// Fan `metric` out to every registered telemetry sink.
    pub async fn emit_telemetry_metric(&self, metric: &MetricPoint) {
        for sink in &self.telemetry_sinks {
            sink.metric_recorded(metric.clone()).await;
        }
    }

    /// Register a log sink for fan-out.
    pub fn with_log_sink(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.log_sinks.push(sink);
        self
    }

    /// Fan `record` out to every registered log sink.
    pub async fn emit_log_record(&self, record: &LogRecord) {
        for sink in &self.log_sinks {
            sink.emit(record).await;
        }
    }

    /// Bind `scheme` to `provider` in the mock's secret-provider
    /// dispatch table. Per spec §9.15 the real registry refuses a
    /// binding that names a scheme the provider doesn't advertise;
    /// the mock asserts + panics on mismatch so unit tests catch
    /// drift immediately — same pattern as `with_store` /
    /// `with_cache`.
    pub fn with_secret_provider(
        mut self,
        scheme: impl Into<String>,
        provider: Arc<dyn SecretProvider>,
    ) -> Self {
        let scheme = scheme.into();
        let supported = provider.supported_schemes();
        assert!(
            supported.iter().any(|s| s == &scheme),
            "MockGateway::with_secret_provider: provider does not support \
             scheme '{scheme}'; supported: {supported:?}",
        );
        self.secret_providers.insert(scheme, provider);
        self
    }

    /// Look up the secret provider bound to `scheme`. Mirrors
    /// `PluginRegistry::secret_provider_for_scheme`.
    pub fn secret_provider_for_scheme(&self, scheme: &str) -> Option<Arc<dyn SecretProvider>> {
        self.secret_providers.get(scheme).cloned()
    }

    /// Bind `scheme` to `provider` in the mock's config-provider
    /// dispatch table. Per spec §9.16 the real registry refuses a
    /// binding that names a scheme the provider doesn't advertise;
    /// the mock panics on mismatch — same pattern as
    /// `with_secret_provider`.
    pub fn with_config_provider(
        mut self,
        scheme: impl Into<String>,
        provider: Arc<dyn ConfigProvider>,
    ) -> Self {
        let scheme = scheme.into();
        let supported = provider.supported_schemes();
        assert!(
            supported.iter().any(|s| s == &scheme),
            "MockGateway::with_config_provider: provider does not support \
             scheme '{scheme}'; supported: {supported:?}",
        );
        self.config_providers.insert(scheme, provider);
        self
    }

    /// Look up the config provider bound to `scheme`. Mirrors
    /// `PluginRegistry::config_provider_for_scheme`.
    pub fn config_provider_for_scheme(&self, scheme: &str) -> Option<Arc<dyn ConfigProvider>> {
        self.config_providers.get(scheme).cloned()
    }

    /// Register a transport plugin in the mock. Per spec §9.6
    /// transports are keyed by `name()`; the mock asserts the
    /// plugin's declared name matches the map key it's being
    /// inserted under — catches drift at test-write time the
    /// same way `with_secret_provider` does.
    pub fn with_transport(mut self, transport: Arc<dyn Transport>) -> Self {
        let name = transport.name().to_owned();
        assert!(
            !name.is_empty(),
            "MockGateway::with_transport: transport declared empty name()",
        );
        assert!(
            !self.transports.contains_key(&name),
            "MockGateway::with_transport: transport name '{name}' already \
             registered",
        );
        self.transports.insert(name, transport);
        self
    }

    /// Look up the transport registered under `name`. Mirrors
    /// `PluginRegistry::transport_by_name`.
    pub fn transport_by_name(&self, name: &str) -> Option<Arc<dyn Transport>> {
        self.transports.get(name).cloned()
    }

    /// Register a policy engine in the mock. Keyed by the
    /// plugin's self-declared `name()`. Panics on duplicate /
    /// empty name — same drift-catching pattern as
    /// `with_transport`.
    pub fn with_policy_engine(mut self, engine: Arc<dyn PolicyEngine>) -> Self {
        let name = engine.name().to_owned();
        assert!(
            !name.is_empty(),
            "MockGateway::with_policy_engine: engine declared empty name()",
        );
        assert!(
            !self.policy_engines.contains_key(&name),
            "MockGateway::with_policy_engine: engine name '{name}' already \
             registered",
        );
        self.policy_engines.insert(name, engine);
        self
    }

    /// Look up the policy engine registered under `name`. Mirrors
    /// `PluginRegistry::policy_engine_by_name`.
    pub fn policy_engine_by_name(&self, name: &str) -> Option<Arc<dyn PolicyEngine>> {
        self.policy_engines.get(name).cloned()
    }

    /// Install the cluster coordinator. Singleton — panics if
    /// one is already installed (mirrors registry behaviour:
    /// runtime replacement is forbidden because fencing token
    /// semantics depend on a single coordinator lifetime).
    pub fn with_cluster_backend(mut self, coordinator: Arc<dyn ClusterBackend>) -> Self {
        assert!(
            self.cluster_backend.is_none(),
            "MockGateway::with_cluster_backend: already installed",
        );
        self.cluster_backend = Some(coordinator);
        self
    }

    /// The currently-installed cluster coordinator, if any.
    pub fn cluster_backend(&self) -> Option<Arc<dyn ClusterBackend>> {
        self.cluster_backend.as_ref().map(Arc::clone)
    }

    /// Simulate a tool call through the full plugin chain.
    ///
    /// Runs:
    /// 1. Pre-dispatch tool gates
    /// 2. Pre-dispatch transforms (argument rewriting)
    /// 3. Simulated execution (returns the arguments as the "result")
    /// 4. Post-dispatch transforms (result rewriting)
    /// 5. Post-dispatch tool gates
    pub async fn call_tool(&self, tool_name: &str, arguments: serde_json::Value) -> ToolCallResult {
        self.call_tool_with_meta(tool_name, arguments, None).await
    }

    /// Simulate a tool call with _meta field.
    pub async fn call_tool_with_meta(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        meta: Option<serde_json::Value>,
    ) -> ToolCallResult {
        let ctx = PluginContext {
            request_id: "mock-request-1".into(),
            session_id: Some("mock-session-1".into()),
            tool_name: tool_name.into(),
            surface: "tool".to_owned(),
            identity: self.default_identity.clone(),
            transport: "mock".into(),
        };

        // Step 1: Pre-dispatch tool gates
        for (gate, config) in &self.tool_gates {
            let decision = gate
                .evaluate_pre_dispatch(&ctx, &arguments, meta.as_ref(), config)
                .await;
            match &decision {
                GateDecision::Deny { .. } => {
                    return ToolCallResult {
                        phase: ToolCallPhase::PreDispatchGate,
                        gate_decision: Some(decision),
                        arguments: arguments.clone(),
                        result: None,
                        metadata: Vec::new(),
                    };
                }
                GateDecision::Challenge { .. } => {
                    return ToolCallResult {
                        phase: ToolCallPhase::PreDispatchGate,
                        gate_decision: Some(decision),
                        arguments: arguments.clone(),
                        result: None,
                        metadata: Vec::new(),
                    };
                }
                GateDecision::Allow { .. } => {
                    // Allow — continue to next plugin in chain
                }
                GateDecision::PendingApproval { .. } => {
                    // The test harness doesn't model
                    // the in-flight pause/resume state machine.
                    // Surfaced as a synthetic phase so callers
                    // can assert on it; real behavior is exercised
                    // by gateway integration tests.
                    return ToolCallResult {
                        phase: ToolCallPhase::PreDispatchGate,
                        gate_decision: Some(decision),
                        arguments: arguments.clone(),
                        result: None,
                        metadata: Vec::new(),
                    };
                }
            }
        }

        // Step 2: Pre-dispatch transforms
        let mut current_args = arguments.clone();
        for (transform, config) in &self.transforms {
            match transform
                .transform_arguments(&ctx, &current_args, config)
                .await
            {
                TransformResult::Unchanged => {}
                TransformResult::Modified { value } => {
                    current_args = value;
                }
                TransformResult::Error { message } => {
                    return ToolCallResult {
                        phase: ToolCallPhase::PreDispatchTransform,
                        gate_decision: None,
                        arguments: current_args,
                        result: Some(serde_json::json!({"error": message})),
                        metadata: Vec::new(),
                    };
                }
            }
        }

        // Step 3: Simulated execution (echo arguments as result)
        let execution_result = serde_json::json!({
            "content": [{"type": "text", "text": current_args.to_string()}],
            "isError": false,
        });

        // Step 4: Post-dispatch transforms
        let mut current_result = execution_result;
        for (transform, config) in &self.transforms {
            match transform
                .transform_result(&ctx, &current_result, config)
                .await
            {
                TransformResult::Unchanged => {}
                TransformResult::Modified { value } => {
                    current_result = value;
                }
                TransformResult::Error { message } => {
                    return ToolCallResult {
                        phase: ToolCallPhase::PostDispatchTransform,
                        gate_decision: None,
                        arguments: current_args,
                        result: Some(serde_json::json!({"error": message})),
                        metadata: Vec::new(),
                    };
                }
            }
        }

        // Step 5: Post-dispatch tool gates
        for (gate, config) in &self.tool_gates {
            let decision = gate
                .evaluate_post_dispatch(
                    &ctx,
                    &current_args,
                    &current_result,
                    1, // simulated 1ms execution
                    config,
                )
                .await;
            match &decision {
                GateDecision::Deny { .. }
                | GateDecision::Challenge { .. }
                | GateDecision::PendingApproval { .. } => {
                    return ToolCallResult {
                        phase: ToolCallPhase::PostDispatchGate,
                        gate_decision: Some(decision),
                        arguments: current_args,
                        result: Some(current_result),
                        metadata: Vec::new(),
                    };
                }
                GateDecision::Allow { .. } => {}
            }
        }

        ToolCallResult {
            phase: ToolCallPhase::Complete,
            gate_decision: None,
            arguments: current_args,
            result: Some(current_result),
            metadata: Vec::new(),
        }
    }

    /// Resolve identity from headers through the identity plugin chain.
    /// Test-helper variant — passes `RequestMetadata::default()`. For
    /// tests that need to assert on TLS / metadata fields, call
    /// [`Self::resolve_identity_with_metadata`] instead.
    pub async fn resolve_identity(&self, headers: &[(String, String)]) -> IdentityResolution {
        self.resolve_identity_with_metadata(
            headers,
            &mcpg_plugin_protocol::types::RequestMetadata::default(),
        )
        .await
    }

    /// Resolve identity threading through a caller-supplied
    /// `RequestMetadata`. Used by tests covering native-mTLS /
    /// SPIFFE / geo-fence paths that consume the protocol-1.1
    /// metadata fields.
    pub async fn resolve_identity_with_metadata(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
    ) -> IdentityResolution {
        for (plugin, config) in &self.identities {
            let result = plugin.resolve_identity(headers, metadata, config).await;
            match &result {
                IdentityResolution::Resolved { .. } => return result,
                IdentityResolution::Invalid { .. } => return result,
                IdentityResolution::None => continue,
            }
        }
        IdentityResolution::None
    }
}

impl Default for MockGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// `http_route` dispatch helper
// ---------------------------------------------------------------------------

/// Minimum-viable path matcher for the mock gateway's http_route
/// dispatch helper. Matches literal segments only — `:name`
/// placeholders are treated as literal strings, so tests that need
/// placeholder capture should set `req.path_params` by hand before
/// calling [`MockGateway::call_http_route`]. Returns `true` if the
/// spec's method + path match the request.
fn spec_matches(spec: &RouteSpec, incoming_method: &str, incoming_path: &str) -> bool {
    let method_ok = spec.method == "*" || spec.method.eq_ignore_ascii_case(incoming_method);
    if !method_ok {
        return false;
    }
    // Suffix check — the production dispatcher strips the
    // `/plugins/{id}/{entity}` mount prefix before matching; since
    // the mock gateway doesn't know the mount prefix, we accept
    // either an exact match or a suffix match on the incoming path.
    let suffix = normalise(&spec.path);
    let incoming = normalise(incoming_path);
    incoming == suffix || incoming.ends_with(&format!("/{}", suffix.trim_start_matches('/')))
}

fn normalise(p: &str) -> String {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Phase at which a tool call stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCallPhase {
    PreDispatchGate,
    PreDispatchTransform,
    PostDispatchGate,
    PostDispatchTransform,
    Complete,
}

/// Result of a simulated tool call through the mock gateway.
#[derive(Debug)]
pub struct ToolCallResult {
    /// The phase at which the call completed or was interrupted.
    pub phase: ToolCallPhase,
    /// The gate decision that interrupted the call (if any).
    pub gate_decision: Option<GateDecision>,
    /// The final arguments (after transforms).
    pub arguments: serde_json::Value,
    /// The execution result (after transforms), if execution occurred.
    pub result: Option<serde_json::Value>,
    /// Metadata collected from allow decisions.
    pub metadata: Vec<serde_json::Value>,
}

impl ToolCallResult {
    /// Did the call complete successfully through the full chain?
    pub fn is_allowed(&self) -> bool {
        self.phase == ToolCallPhase::Complete
    }

    /// Was the call denied by a gate?
    pub fn is_denied(&self) -> bool {
        matches!(&self.gate_decision, Some(GateDecision::Deny { .. }))
    }

    /// Was the call challenged by a gate?
    pub fn is_challenged(&self) -> bool {
        matches!(&self.gate_decision, Some(GateDecision::Challenge { .. }))
    }

    /// Get the denial message if denied.
    pub fn denial_message(&self) -> Option<&str> {
        match &self.gate_decision {
            Some(GateDecision::Deny { message, .. }) => Some(message),
            _ => None,
        }
    }

    /// Get the challenge data if challenged.
    pub fn challenge_data(&self) -> Option<&serde_json::Value> {
        match &self.gate_decision {
            Some(GateDecision::Challenge { challenge_data, .. }) => Some(challenge_data),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// Assertion helper for plugin tests.
pub trait ToolCallResultAssertions {
    fn assert_allowed(&self);
    fn assert_denied(&self);
    fn assert_challenged(&self);
    fn assert_denied_with_message(&self, expected: &str);
}

impl ToolCallResultAssertions for ToolCallResult {
    fn assert_allowed(&self) {
        assert!(
            self.is_allowed(),
            "expected tool call to be allowed, but it was {:?} at phase {:?}",
            self.gate_decision,
            self.phase,
        );
    }

    fn assert_denied(&self) {
        assert!(
            self.is_denied(),
            "expected tool call to be denied, but it was {:?} at phase {:?}",
            self.gate_decision,
            self.phase,
        );
    }

    fn assert_challenged(&self) {
        assert!(
            self.is_challenged(),
            "expected tool call to be challenged, but it was {:?} at phase {:?}",
            self.gate_decision,
            self.phase,
        );
    }

    fn assert_denied_with_message(&self, expected: &str) {
        assert!(
            self.is_denied(),
            "expected denial, got {:?}",
            self.gate_decision
        );
        let msg = self.denial_message().unwrap_or("");
        assert!(
            msg.contains(expected),
            "expected denial message to contain '{}', got '{}'",
            expected,
            msg,
        );
    }
}

// ---------------------------------------------------------------------------
// Test context builders
// ---------------------------------------------------------------------------

/// Builder for PluginContext in tests.
pub struct ContextBuilder {
    request_id: String,
    session_id: Option<String>,
    tool_name: String,
    identity: PluginIdentity,
    transport: String,
}

impl ContextBuilder {
    pub fn new(tool_name: &str) -> Self {
        Self {
            request_id: "test-request-1".into(),
            session_id: Some("test-session-1".into()),
            tool_name: tool_name.into(),
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
            transport: "http".into(),
        }
    }

    pub fn request_id(mut self, id: &str) -> Self {
        self.request_id = id.into();
        self
    }

    pub fn session_id(mut self, id: &str) -> Self {
        self.session_id = Some(id.into());
        self
    }

    pub fn anonymous(mut self) -> Self {
        self.identity = PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        self
    }

    pub fn verified(mut self, subject: &str) -> Self {
        self.identity = PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some(subject.into()),
            auth_provider: Some("test".into()),
            issuer: Some("test-issuer".into()),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        self
    }

    pub fn transport(mut self, transport: &str) -> Self {
        self.transport = transport.into();
        self
    }

    pub fn build(self) -> PluginContext {
        PluginContext {
            request_id: self.request_id,
            session_id: self.session_id,
            tool_name: self.tool_name,
            surface: "tool".to_owned(),
            identity: self.identity,
            transport: self.transport,
        }
    }
}

// ---------------------------------------------------------------------------
// Test helpers for FFI macro round-trip tests
// ---------------------------------------------------------------------------

/// Build a stub [`HostHandleRef`](mcpg_plugin_protocol::abi::HostHandleRef)
/// suitable for tests that drive the macro-generated `__mcpg_<kind>_make`
/// functions directly. The returned ref's `cluster()` slot returns
/// `RNone` and the other slots are no-ops; tests that only need to
/// round-trip a plugin instance through `make` / `manifest_json` /
/// `drop_instance` are unaffected. v26 ABI.
pub fn stub_host_ref() -> mcpg_plugin_protocol::abi::HostHandleRef {
    use abi_stable::std_types::{RNone, ROption, RString};
    use mcpg_plugin_protocol::abi::{ClusterClientRef, HostHandleRef, HostServicesVTable};

    extern "C" fn s_resolve_secret(_ctx: usize, _uri: RString) -> RString {
        RString::new()
    }
    extern "C" fn s_issue_credential(_ctx: usize, _uri: RString, _id: RString) -> RString {
        RString::new()
    }
    extern "C" fn s_config_snapshot(_ctx: usize, _uri: RString) -> RString {
        RString::new()
    }
    extern "C" fn s_audit_event(_ctx: usize, _e: RString) -> RString {
        RString::new()
    }
    extern "C" fn s_metric_emit(_ctx: usize, _p: RString) {}
    extern "C" fn s_cluster(_ctx: usize) -> ROption<ClusterClientRef> {
        RNone
    }
    extern "C" fn s_span_start(_ctx: usize, _n: RString, _a: RString) -> u64 {
        0
    }
    extern "C" fn s_span_end(_ctx: usize, _id: u64) {}
    extern "C" fn s_span_event(_ctx: usize, _id: u64, _n: RString, _a: RString) {}
    extern "C" fn s_alias(_ctx: usize) -> RString {
        RString::new()
    }
    // Backend host services (v31) — empty `{"ok":...}` envelopes / no-op
    // subscriptions for the mock host.
    extern "C" fn s_resolve_credentials(_ctx: usize, _v: RString, _id: RString) -> RString {
        RString::from(r#"{"ok":{"value":null,"count":0}}"#)
    }
    extern "C" fn s_cache_get(_ctx: usize, _key: RString) -> RString {
        RString::from(r#"{"ok":null}"#)
    }
    extern "C" fn s_fetch_content(_ctx: usize, _uri: RString) -> RString {
        RString::from(r#"{"ok":null}"#)
    }
    extern "C" fn s_store_content(_ctx: usize, _args: RString) -> RString {
        RString::from(r#"{"err":{"error":"not_implemented"}}"#)
    }
    extern "C" fn s_invoke_tool(
        _ctx: usize,
        _ctx_json: RString,
        _tool: RString,
        _args: RString,
    ) -> RString {
        RString::from(r#"{"err":{"error":"not_implemented"}}"#)
    }
    extern "C" fn s_subscribe_credential_revoked(_ctx: usize, _cb: usize, _cb_ctx: usize) -> u64 {
        0
    }
    extern "C" fn s_subscribe_secret_rotation(_ctx: usize, _cb: usize, _cb_ctx: usize) -> u64 {
        0
    }
    extern "C" fn s_unsubscribe(_ctx: usize, _sub_id: u64) {}

    HostHandleRef {
        ctx: 0,
        vtable: HostServicesVTable {
            resolve_secret: s_resolve_secret,
            issue_credential: s_issue_credential,
            config_snapshot: s_config_snapshot,
            audit_event: s_audit_event,
            metric_emit: s_metric_emit,
            cluster: s_cluster,
            span_start: s_span_start,
            span_end: s_span_end,
            span_event: s_span_event,
            alias: s_alias,
            resolve_credentials: s_resolve_credentials,
            cache_get: s_cache_get,
            fetch_content: s_fetch_content,
            store_content: s_store_content,
            invoke_tool: s_invoke_tool,
            subscribe_credential_revoked: s_subscribe_credential_revoked,
            subscribe_secret_rotation: s_subscribe_secret_rotation,
            host_unsubscribe: s_unsubscribe,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::{PROTOCOL_VERSION, PluginClass, PluginManifest, async_trait};

    // A simple allow-all gate for testing
    struct AlwaysAllowGate {
        manifest: PluginManifest,
    }
    impl AlwaysAllowGate {
        fn new() -> Self {
            Self {
                manifest: PluginManifest {
                    id: "test.allow".into(),
                    version: "1.0.0".into(),
                    name: "Always Allow".into(),
                    plugin_class: PluginClass::ToolGate,
                    protocol_version: PROTOCOL_VERSION.to_owned(),
                    license: None,
                    required_capabilities: vec![],
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
            }
        }
    }
    #[async_trait]

    impl ToolGatePlugin for AlwaysAllowGate {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
    }

    // A gate that denies everything
    struct AlwaysDenyGate {
        manifest: PluginManifest,
    }
    impl AlwaysDenyGate {
        fn new() -> Self {
            Self {
                manifest: PluginManifest {
                    id: "test.deny".into(),
                    version: "1.0.0".into(),
                    name: "Always Deny".into(),
                    plugin_class: PluginClass::ToolGate,
                    protocol_version: PROTOCOL_VERSION.to_owned(),
                    license: None,
                    required_capabilities: vec![],
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
            }
        }
    }
    #[async_trait]

    impl ToolGatePlugin for AlwaysDenyGate {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::Deny {
                http_status: 403,
                code: -32001,
                message: "denied by test".into(),
                error_data: None,
            }
        }
    }

    // A transform that uppercases a "name" field
    struct UppercaseTransform {
        manifest: PluginManifest,
    }
    impl UppercaseTransform {
        fn new() -> Self {
            Self {
                manifest: PluginManifest {
                    id: "test.uppercase".into(),
                    version: "1.0.0".into(),
                    name: "Uppercase Transform".into(),
                    plugin_class: PluginClass::Transform,
                    protocol_version: PROTOCOL_VERSION.to_owned(),
                    license: None,
                    required_capabilities: vec![],
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
            }
        }
    }
    #[async_trait]

    impl TransformPlugin for UppercaseTransform {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn transform_arguments(
            &self,
            _ctx: &PluginContext,
            args: &serde_json::Value,
            _config: &serde_json::Value,
        ) -> TransformResult {
            if let Some(name) = args.get("name").and_then(|v| v.as_str()) {
                let mut new_args = args.clone();
                new_args["name"] = serde_json::Value::String(name.to_uppercase());
                TransformResult::Modified { value: new_args }
            } else {
                TransformResult::Unchanged
            }
        }
        async fn transform_result(
            &self,
            _ctx: &PluginContext,
            _result: &serde_json::Value,
            _config: &serde_json::Value,
        ) -> TransformResult {
            TransformResult::Unchanged
        }
    }

    #[tokio::test]
    async fn mock_gateway_empty_chain_allows() {
        let gw = MockGateway::new();
        let result = gw.call_tool("test_tool", serde_json::json!({"x": 1})).await;
        result.assert_allowed();
        assert!(result.result.is_some());
    }

    #[tokio::test]
    async fn mock_gateway_allow_gate_passes() {
        let gw = MockGateway::new().with_tool_gate(Box::new(AlwaysAllowGate::new()));
        let result = gw.call_tool("test_tool", serde_json::json!({})).await;
        result.assert_allowed();
    }

    #[tokio::test]
    async fn mock_gateway_deny_gate_blocks() {
        let gw = MockGateway::new().with_tool_gate(Box::new(AlwaysDenyGate::new()));
        let result = gw.call_tool("test_tool", serde_json::json!({})).await;
        result.assert_denied();
        result.assert_denied_with_message("denied by test");
        assert_eq!(result.phase, ToolCallPhase::PreDispatchGate);
    }

    #[tokio::test]
    async fn mock_gateway_transform_modifies_arguments() {
        let gw = MockGateway::new().with_transform(Box::new(UppercaseTransform::new()));
        let result = gw
            .call_tool("test_tool", serde_json::json!({"name": "hello"}))
            .await;
        result.assert_allowed();
        // Transformed arguments should have uppercase name
        assert_eq!(result.arguments["name"], "HELLO");
    }

    #[tokio::test]
    async fn mock_gateway_deny_after_allow_still_denies() {
        let gw = MockGateway::new()
            .with_tool_gate(Box::new(AlwaysAllowGate::new()))
            .with_tool_gate(Box::new(AlwaysDenyGate::new()));
        let result = gw.call_tool("test_tool", serde_json::json!({})).await;
        result.assert_denied();
    }

    #[test]
    fn context_builder_verified() {
        let ctx = ContextBuilder::new("my_tool")
            .verified("user@example.com")
            .transport("https")
            .build();
        assert_eq!(ctx.tool_name, "my_tool");
        assert_eq!(ctx.identity.kind, "verified");
        assert_eq!(ctx.identity.subject_id.as_deref(), Some("user@example.com"));
        assert_eq!(ctx.transport, "https");
    }

    #[test]
    fn context_builder_anonymous() {
        let ctx = ContextBuilder::new("tool").anonymous().build();
        assert_eq!(ctx.identity.kind, "anonymous");
        assert!(ctx.identity.subject_id.is_none());
    }

    // -- http_route helper tests --------------------------------------------

    use mcpg_plugin_protocol::http_route::{
        HttpBody, HttpRoute, HttpRouteRequest, HttpRouteResponse, RouteSpec,
    };

    struct EchoRoute {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl HttpRoute for EchoRoute {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn routes(&self) -> Vec<RouteSpec> {
            vec![RouteSpec {
                method: "GET".into(),
                path: "/ping".into(),
                requires_identity: false,
                streaming: false,
                max_body_bytes: None,
            }]
        }
        async fn handle(&self, _req: HttpRouteRequest) -> HttpRouteResponse {
            HttpRouteResponse::ok_json(&serde_json::json!({ "pong": true }))
        }
    }

    fn echo_plugin() -> std::sync::Arc<dyn HttpRoute> {
        std::sync::Arc::new(EchoRoute {
            manifest: PluginManifest {
                id: "dev.mcpg.test.echo".into(),
                version: "0.1.0".into(),
                name: "Echo".into(),
                plugin_class: PluginClass::HttpRoute,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
        })
    }

    fn http_req(method: &str, path: &str) -> HttpRouteRequest {
        HttpRouteRequest {
            method: method.into(),
            full_path: path.into(),
            path_params: Default::default(),
            query: vec![],
            headers: vec![],
            body: bytes::Bytes::new(),
            identity: None,
            request_id: "r1".into(),
            remote_addr: None,
        }
    }

    #[tokio::test]
    async fn http_route_happy_path() {
        let gw = MockGateway::new().with_http_route("echo", echo_plugin());
        let resp = gw.call_http_route("echo", http_req("GET", "/ping")).await;
        assert_eq!(resp.status, 200);
        if let HttpBody::Bytes(b) = resp.body {
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            assert_eq!(v["pong"], true);
        } else {
            panic!("expected bytes body");
        }
    }

    #[tokio::test]
    async fn http_route_unknown_entity_is_404() {
        let gw = MockGateway::new().with_http_route("echo", echo_plugin());
        let resp = gw
            .call_http_route("missing", http_req("GET", "/ping"))
            .await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn http_route_method_mismatch_is_404() {
        let gw = MockGateway::new().with_http_route("echo", echo_plugin());
        let resp = gw.call_http_route("echo", http_req("POST", "/ping")).await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn http_route_matches_with_mount_prefix() {
        // Prefix inclusion simulates the production dispatcher's
        // behaviour: the axum handler passes the full path from the
        // URL, and the mock matcher's suffix rule should still find
        // the spec.
        let gw = MockGateway::new().with_http_route("echo", echo_plugin());
        let resp = gw
            .call_http_route(
                "echo",
                http_req("GET", "/plugins/dev.mcpg.test.echo/echo/ping"),
            )
            .await;
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn spec_matches_wildcard_method() {
        let spec = RouteSpec {
            method: "*".into(),
            path: "/x".into(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: None,
        };
        assert!(spec_matches(&spec, "GET", "/x"));
        assert!(spec_matches(&spec, "POST", "/x"));
        assert!(spec_matches(&spec, "DELETE", "/x"));
    }

    #[test]
    fn spec_matches_case_insensitive_method() {
        let spec = RouteSpec {
            method: "get".into(),
            path: "/x".into(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: None,
        };
        assert!(spec_matches(&spec, "GET", "/x"));
        assert!(!spec_matches(&spec, "POST", "/x"));
    }

    // -- audit_sink helper tests --------------------------------------------

    use mcpg_plugin_protocol::audit::{
        AuditError, AuditEvent, AuditOutcome, AuditReceipt, AuditSink,
    };

    struct RecordingAuditSink {
        manifest: PluginManifest,
        events: tokio::sync::Mutex<Vec<AuditEvent>>,
        fail_with: Option<AuditError>,
    }

    #[async_trait]
    impl AuditSink for RecordingAuditSink {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
            if let Some(e) = &self.fail_with {
                return Err(e.clone());
            }
            self.events.lock().await.push(event.clone());
            Ok(AuditReceipt {
                sink_id: self.manifest.id.clone(),
                persisted_at: "2026-04-24T12:00:00Z".into(),
                durable_hash: "0".repeat(64),
            })
        }
    }

    fn audit_manifest(id: &str) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "0.1.0".into(),
            name: "Test audit sink".into(),
            plugin_class: PluginClass::AuditSink,
            protocol_version: PROTOCOL_VERSION.into(),
            license: None,
            required_capabilities: vec![],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    fn sample_event() -> AuditEvent {
        AuditEvent {
            event_id: "e1".into(),
            occurred_at: "2026-04-24T12:00:00Z".into(),
            actor: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            action: "tool.call.denied".into(),
            resource: None,
            outcome: AuditOutcome::Denied,
            request_id: None,
            node_id: None,
            details: serde_json::json!({}),
            prev_event_hash: None,
        }
    }

    #[tokio::test]
    async fn audit_fan_out_reaches_every_sink() {
        let a = Arc::new(RecordingAuditSink {
            manifest: audit_manifest("dev.test.a"),
            events: tokio::sync::Mutex::new(Vec::new()),
            fail_with: None,
        });
        let b = Arc::new(RecordingAuditSink {
            manifest: audit_manifest("dev.test.b"),
            events: tokio::sync::Mutex::new(Vec::new()),
            fail_with: None,
        });
        let gw = MockGateway::new()
            .with_audit_sink(a.clone())
            .with_audit_sink(b.clone());
        let results = gw.emit_audit(&sample_event()).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(a.events.lock().await.len(), 1);
        assert_eq!(b.events.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn audit_fan_out_continues_across_failure() {
        let failing = Arc::new(RecordingAuditSink {
            manifest: audit_manifest("dev.test.fail"),
            events: tokio::sync::Mutex::new(Vec::new()),
            fail_with: Some(AuditError::Throttled),
        });
        let working = Arc::new(RecordingAuditSink {
            manifest: audit_manifest("dev.test.ok"),
            events: tokio::sync::Mutex::new(Vec::new()),
            fail_with: None,
        });
        let gw = MockGateway::new()
            .with_audit_sink(failing)
            .with_audit_sink(working.clone());
        let results = gw.emit_audit(&sample_event()).await;
        assert_eq!(results.len(), 2);
        assert!(results[0].is_err());
        assert!(results[1].is_ok());
        assert_eq!(working.events.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn audit_fan_out_empty_when_no_sinks_registered() {
        let gw = MockGateway::new();
        let results = gw.emit_audit(&sample_event()).await;
        assert!(results.is_empty());
    }

    // -- store helper tests --------------------------------------------------

    use mcpg_plugin_protocol::store::{
        AppendResult, BoxStoreEventStream, Store, StoreError, StorePage, StoreRole, StoreValue,
    };

    struct NoopStore {
        manifest: PluginManifest,
        supported: Vec<StoreRole>,
    }

    #[async_trait]
    impl Store for NoopStore {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_roles(&self) -> Vec<StoreRole> {
            self.supported.clone()
        }
        async fn get(
            &self,
            _role: StoreRole,
            _key: &str,
        ) -> Result<Option<StoreValue>, StoreError> {
            Ok(None)
        }
        async fn put(
            &self,
            _role: StoreRole,
            _key: &str,
            _value: StoreValue,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        async fn delete(&self, _role: StoreRole, _key: &str) -> Result<(), StoreError> {
            Ok(())
        }
        async fn list(
            &self,
            _role: StoreRole,
            _prefix: &str,
            _cursor: Option<String>,
        ) -> Result<StorePage, StoreError> {
            Ok(StorePage {
                items: vec![],
                next_cursor: None,
            })
        }
        async fn compare_and_swap(
            &self,
            _role: StoreRole,
            _key: &str,
            _expected: Option<StoreValue>,
            _new: StoreValue,
        ) -> Result<bool, StoreError> {
            Ok(true)
        }
        async fn append(
            &self,
            _role: StoreRole,
            _key: &str,
            _value: StoreValue,
        ) -> Result<AppendResult, StoreError> {
            Ok(AppendResult { sequence: 0 })
        }
        async fn watch(
            &self,
            _role: StoreRole,
            _key: &str,
        ) -> Result<BoxStoreEventStream, StoreError> {
            Err(StoreError::Unsupported { op: "watch".into() })
        }
    }

    fn store_plugin(roles: Vec<StoreRole>) -> Arc<NoopStore> {
        Arc::new(NoopStore {
            manifest: PluginManifest {
                id: "dev.test.store".into(),
                version: "0.1.0".into(),
                name: "Test Store".into(),
                plugin_class: PluginClass::Store,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            supported: roles,
        })
    }

    #[test]
    fn store_role_binding_resolves_lookup() {
        let gw = MockGateway::new()
            .with_store(StoreRole::Session, store_plugin(vec![StoreRole::Session]));
        assert!(gw.store_for_role(&StoreRole::Session).is_some());
        assert!(gw.store_for_role(&StoreRole::Task).is_none());
    }

    #[test]
    #[should_panic(expected = "does not support role task")]
    fn store_role_binding_panics_on_unsupported_role() {
        // Plugin only advertises Session; caller binds Task.
        // Per the helper's contract this panics immediately so
        // the author catches the drift at test time.
        MockGateway::new().with_store(StoreRole::Task, store_plugin(vec![StoreRole::Session]));
    }

    #[test]
    fn store_role_binding_supports_multiple_roles() {
        let plugin = store_plugin(vec![StoreRole::Session, StoreRole::Task]);
        let gw = MockGateway::new()
            .with_store(StoreRole::Session, plugin.clone())
            .with_store(StoreRole::Task, plugin);
        assert!(gw.store_for_role(&StoreRole::Session).is_some());
        assert!(gw.store_for_role(&StoreRole::Task).is_some());
    }

    // -- cache helper tests -------------------------------------------------

    use mcpg_plugin_protocol::cache::{Cache, CacheError};
    use std::time::Duration as StdDuration;

    struct NoopCache {
        manifest: PluginManifest,
        supported: Vec<String>,
        any: bool,
    }

    #[async_trait]
    impl Cache for NoopCache {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_namespaces(&self) -> Vec<String> {
            self.supported.clone()
        }
        fn serves_any_namespace(&self) -> bool {
            self.any
        }
        async fn get(&self, _ns: &str, _key: &str) -> Option<bytes::Bytes> {
            None
        }
        async fn put(
            &self,
            _ns: &str,
            _key: &str,
            _value: bytes::Bytes,
            _ttl: StdDuration,
        ) -> Result<(), CacheError> {
            Ok(())
        }
        async fn delete(&self, _ns: &str, _key: &str) {}
        async fn clear(&self, _ns: &str) -> Result<(), CacheError> {
            Ok(())
        }
        async fn incr(
            &self,
            _ns: &str,
            _key: &str,
            by: i64,
            _ttl: StdDuration,
        ) -> Result<i64, CacheError> {
            Ok(by)
        }
    }

    fn cache_plugin(supported: Vec<String>, any: bool) -> Arc<NoopCache> {
        Arc::new(NoopCache {
            manifest: PluginManifest {
                id: "dev.test.cache".into(),
                version: "0.1.0".into(),
                name: "Test cache".into(),
                plugin_class: PluginClass::Cache,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            supported,
            any,
        })
    }

    #[test]
    fn cache_namespace_binding_resolves_lookup() {
        let gw = MockGateway::new().with_cache("jwks", cache_plugin(vec!["jwks".into()], false));
        assert!(gw.cache_for_namespace("jwks").is_some());
        assert!(gw.cache_for_namespace("response-cache").is_none());
    }

    #[test]
    fn cache_namespace_binding_accepts_serves_any() {
        let gw = MockGateway::new().with_cache("whatever", cache_plugin(vec![], true));
        assert!(gw.cache_for_namespace("whatever").is_some());
    }

    #[test]
    #[should_panic(expected = "does not support namespace 'response-cache'")]
    fn cache_namespace_binding_panics_on_unsupported() {
        MockGateway::new().with_cache("response-cache", cache_plugin(vec!["jwks".into()], false));
    }

    // -- telemetry + log helpers --------------------------------------------

    use mcpg_plugin_protocol::logs::{LogLevel, LogRecord, LogSink};
    use mcpg_plugin_protocol::telemetry::{
        MetricKind, MetricPoint, MetricValue, SpanEnd, SpanKind, SpanStart, SpanStatus,
        TelemetryError, TelemetrySink,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingTelemetry {
        manifest: PluginManifest,
        spans_started: AtomicUsize,
        spans_ended: AtomicUsize,
        metrics: AtomicUsize,
    }
    #[async_trait]
    impl TelemetrySink for CountingTelemetry {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn span_started(&self, _s: SpanStart) {
            self.spans_started.fetch_add(1, Ordering::AcqRel);
        }
        async fn span_ended(&self, _s: SpanEnd) {
            self.spans_ended.fetch_add(1, Ordering::AcqRel);
        }
        async fn metric_recorded(&self, _m: MetricPoint) {
            self.metrics.fetch_add(1, Ordering::AcqRel);
        }
        async fn flush(&self, _t: std::time::Duration) -> Result<(), TelemetryError> {
            Ok(())
        }
    }

    struct CountingLog {
        manifest: PluginManifest,
        emitted: AtomicUsize,
    }
    #[async_trait]
    impl LogSink for CountingLog {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn emit(&self, _r: &LogRecord) {
            self.emitted.fetch_add(1, Ordering::AcqRel);
        }
        async fn flush(
            &self,
            _t: std::time::Duration,
        ) -> Result<(), mcpg_plugin_protocol::logs::LogError> {
            Ok(())
        }
    }

    fn telemetry_sink() -> Arc<CountingTelemetry> {
        Arc::new(CountingTelemetry {
            manifest: PluginManifest {
                id: "dev.test.t".into(),
                version: "0.1.0".into(),
                name: "Test telemetry".into(),
                plugin_class: PluginClass::TelemetrySink,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            spans_started: AtomicUsize::new(0),
            spans_ended: AtomicUsize::new(0),
            metrics: AtomicUsize::new(0),
        })
    }
    fn log_sink(id: &str) -> Arc<CountingLog> {
        Arc::new(CountingLog {
            manifest: PluginManifest {
                id: id.into(),
                version: "0.1.0".into(),
                name: "Test log".into(),
                plugin_class: PluginClass::LogSink,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            emitted: AtomicUsize::new(0),
        })
    }
    fn sample_span_start() -> SpanStart {
        SpanStart {
            trace_id: "t".into(),
            span_id: "s".into(),
            parent_id: None,
            name: "op".into(),
            kind: SpanKind::Internal,
            start_ns: 0,
            attributes: Default::default(),
        }
    }
    fn sample_span_end() -> SpanEnd {
        SpanEnd {
            trace_id: "t".into(),
            span_id: "s".into(),
            end_ns: 1,
            status: SpanStatus::Ok,
            events: vec![],
            additional_attributes: Default::default(),
        }
    }
    fn sample_metric() -> MetricPoint {
        MetricPoint {
            name: "m".into(),
            unit: None,
            kind: MetricKind::Counter,
            value: MetricValue::I64 { value: 1 },
            labels: Default::default(),
            timestamp_ns: 0,
        }
    }
    fn sample_log() -> LogRecord {
        LogRecord {
            timestamp_ns: 0,
            level: LogLevel::Info,
            target: "mcpg".into(),
            message: "hi".into(),
            fields: Default::default(),
            span_id: None,
            trace_id: None,
            request_id: None,
            identity: None,
            node_id: None,
            plugin_id: None,
        }
    }

    #[tokio::test]
    async fn telemetry_fan_out_reaches_every_sink_in_mock() {
        let a = telemetry_sink();
        let b = telemetry_sink();
        let gw = MockGateway::new()
            .with_telemetry_sink(a.clone())
            .with_telemetry_sink(b.clone());
        gw.emit_telemetry_span_started(&sample_span_start()).await;
        gw.emit_telemetry_span_ended(&sample_span_end()).await;
        gw.emit_telemetry_metric(&sample_metric()).await;
        for sink in [&a, &b] {
            assert_eq!(sink.spans_started.load(Ordering::Acquire), 1);
            assert_eq!(sink.spans_ended.load(Ordering::Acquire), 1);
            assert_eq!(sink.metrics.load(Ordering::Acquire), 1);
        }
    }

    #[tokio::test]
    async fn log_fan_out_reaches_every_sink_in_mock() {
        let a = log_sink("dev.test.a");
        let b = log_sink("dev.test.b");
        let gw = MockGateway::new()
            .with_log_sink(a.clone())
            .with_log_sink(b.clone());
        gw.emit_log_record(&sample_log()).await;
        gw.emit_log_record(&sample_log()).await;
        for sink in [&a, &b] {
            assert_eq!(sink.emitted.load(Ordering::Acquire), 2);
        }
    }

    #[tokio::test]
    async fn telemetry_and_log_fan_outs_empty_when_no_sinks_registered() {
        let gw = MockGateway::new();
        // No panic on empty fan-out.
        gw.emit_telemetry_span_started(&sample_span_start()).await;
        gw.emit_log_record(&sample_log()).await;
    }

    // -- secret_provider helper tests ---------------------------------------

    use mcpg_plugin_protocol::secret::{SecretError, SecretProvider, SecretValue};

    struct FixedSecret {
        manifest: PluginManifest,
        schemes: Vec<String>,
    }

    #[async_trait]
    impl SecretProvider for FixedSecret {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_schemes(&self) -> Vec<String> {
            self.schemes.clone()
        }
        async fn get(&self, _r: &str) -> Result<SecretValue, SecretError> {
            Ok(SecretValue::new(b"v".to_vec()))
        }
    }

    fn secret_provider(schemes: Vec<&str>) -> Arc<FixedSecret> {
        Arc::new(FixedSecret {
            manifest: PluginManifest {
                id: "dev.test.secret".into(),
                version: "0.1.0".into(),
                name: "Test secret".into(),
                plugin_class: PluginClass::SecretProvider,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            schemes: schemes.into_iter().map(String::from).collect(),
        })
    }

    #[test]
    fn secret_provider_binding_resolves_lookup() {
        let gw = MockGateway::new().with_secret_provider("env", secret_provider(vec!["env"]));
        assert!(gw.secret_provider_for_scheme("env").is_some());
        assert!(gw.secret_provider_for_scheme("vault").is_none());
    }

    #[test]
    #[should_panic(expected = "does not support scheme 'vault'")]
    fn secret_provider_binding_panics_on_unsupported_scheme() {
        MockGateway::new().with_secret_provider("vault", secret_provider(vec!["env"]));
    }

    #[test]
    fn secret_provider_binding_supports_multiple_schemes_per_plugin() {
        let plugin = secret_provider(vec!["env", "file"]);
        let gw = MockGateway::new()
            .with_secret_provider("env", plugin.clone())
            .with_secret_provider("file", plugin);
        assert!(gw.secret_provider_for_scheme("env").is_some());
        assert!(gw.secret_provider_for_scheme("file").is_some());
    }

    // -- config_provider helper tests ---------------------------------------

    use mcpg_plugin_protocol::config::{ConfigError, ConfigProvider, ConfigSnapshot};

    struct FixedConfig {
        manifest: PluginManifest,
        schemes: Vec<String>,
    }

    #[async_trait]
    impl ConfigProvider for FixedConfig {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_schemes(&self) -> Vec<String> {
            self.schemes.clone()
        }
        async fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError> {
            Ok(ConfigSnapshot {
                version: "v1".into(),
                values: serde_json::json!({"ok": true}),
                fetched_at: "2026-04-23T00:00:00Z".into(),
                source: reference.to_owned(),
            })
        }
    }

    fn config_provider(schemes: Vec<&str>) -> Arc<FixedConfig> {
        Arc::new(FixedConfig {
            manifest: PluginManifest {
                id: "dev.test.config".into(),
                version: "0.1.0".into(),
                name: "Test config".into(),
                plugin_class: PluginClass::ConfigProvider,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            schemes: schemes.into_iter().map(String::from).collect(),
        })
    }

    #[test]
    fn config_provider_binding_resolves_lookup() {
        let gw = MockGateway::new().with_config_provider("file", config_provider(vec!["file"]));
        assert!(gw.config_provider_for_scheme("file").is_some());
        assert!(gw.config_provider_for_scheme("consul").is_none());
    }

    #[test]
    #[should_panic(expected = "does not support scheme 'consul'")]
    fn config_provider_binding_panics_on_unsupported_scheme() {
        MockGateway::new().with_config_provider("consul", config_provider(vec!["file"]));
    }

    #[test]
    fn config_provider_binding_supports_multiple_schemes_per_plugin() {
        let plugin = config_provider(vec!["file", "consul"]);
        let gw = MockGateway::new()
            .with_config_provider("file", plugin.clone())
            .with_config_provider("consul", plugin);
        assert!(gw.config_provider_for_scheme("file").is_some());
        assert!(gw.config_provider_for_scheme("consul").is_some());
    }

    // -- transport helper tests ---------------------------------------------

    use mcpg_plugin_protocol::transport::{
        DispatchResponse, DispatcherError, MessageDispatcher, Transport, TransportError,
        TransportHandle,
    };

    struct FixedTransport {
        manifest: PluginManifest,
        name: String,
    }

    #[async_trait]
    impl Transport for FixedTransport {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn name(&self) -> &str {
            &self.name
        }
        async fn start(
            &self,
            _listener_config: &serde_json::Value,
            _dispatcher: Arc<dyn MessageDispatcher>,
        ) -> Result<Box<dyn TransportHandle>, TransportError> {
            Err(TransportError::Shutdown)
        }
    }

    fn fixed_transport(id: &str, name: &str) -> Arc<FixedTransport> {
        Arc::new(FixedTransport {
            manifest: PluginManifest {
                id: id.into(),
                version: "0.1.0".into(),
                name: "Test transport".into(),
                plugin_class: PluginClass::Transport,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            name: name.to_owned(),
        })
    }

    #[test]
    fn transport_binding_resolves_lookup() {
        let gw = MockGateway::new().with_transport(fixed_transport("dev.test.http", "http-v1"));
        assert!(gw.transport_by_name("http-v1").is_some());
        assert!(gw.transport_by_name("stdio-v1").is_none());
    }

    #[test]
    #[should_panic(expected = "transport name 'http-v1' already registered")]
    fn transport_binding_panics_on_duplicate_name() {
        MockGateway::new()
            .with_transport(fixed_transport("dev.test.a", "http-v1"))
            .with_transport(fixed_transport("dev.test.b", "http-v1"));
    }

    #[test]
    #[should_panic(expected = "declared empty name")]
    fn transport_binding_panics_on_empty_name() {
        MockGateway::new().with_transport(fixed_transport("dev.test.empty", ""));
    }

    // Silence the unused-warning on DispatchResponse/DispatcherError
    // — they're only referenced via the trait above.
    #[allow(dead_code)]
    fn _transport_type_refs(_: DispatchResponse, _: DispatcherError) {}

    // -- policy_engine helper tests -----------------------------------------

    use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyEngine, PolicyVersion};

    struct FixedPolicy {
        manifest: PluginManifest,
        name: String,
    }

    #[async_trait]
    impl PolicyEngine for FixedPolicy {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn name(&self) -> &str {
            &self.name
        }
        async fn evaluate(
            &self,
            _decision_point: &str,
            _input: &serde_json::Value,
            _context: &PluginContext,
        ) -> PolicyDecision {
            PolicyDecision::allow("sha256:test")
        }
        async fn policy_version(&self) -> PolicyVersion {
            PolicyVersion {
                hash: "sha256:test".into(),
                loaded_at: "2026-04-23T00:00:00Z".into(),
                source: "test".into(),
            }
        }
    }

    fn fixed_policy(id: &str, name: &str) -> Arc<FixedPolicy> {
        Arc::new(FixedPolicy {
            manifest: PluginManifest {
                id: id.into(),
                version: "0.1.0".into(),
                name: "Test policy".into(),
                plugin_class: PluginClass::PolicyEngine,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            name: name.to_owned(),
        })
    }

    #[test]
    fn policy_engine_binding_resolves_lookup() {
        let gw = MockGateway::new().with_policy_engine(fixed_policy("dev.test.opa", "opa"));
        assert!(gw.policy_engine_by_name("opa").is_some());
        assert!(gw.policy_engine_by_name("cedar").is_none());
    }

    #[test]
    #[should_panic(expected = "engine name 'opa' already registered")]
    fn policy_engine_binding_panics_on_duplicate_name() {
        MockGateway::new()
            .with_policy_engine(fixed_policy("dev.test.a", "opa"))
            .with_policy_engine(fixed_policy("dev.test.b", "opa"));
    }

    #[test]
    #[should_panic(expected = "declared empty name")]
    fn policy_engine_binding_panics_on_empty_name() {
        MockGateway::new().with_policy_engine(fixed_policy("dev.test.empty", ""));
    }

    // -- cluster_backend helper tests -----------------------------------

    use mcpg_cluster_api::{
        BoxActiveLease, BoxPeerEventStream, BoxPublishedMessageStream, ClusterError,
        ClusterNodeInfo, ClusterPeer,
    };

    struct FixedCluster {
        manifest: PluginManifest,
        node_id: String,
    }

    #[async_trait]
    impl mcpg_cluster_api::ClusterBackend for FixedCluster {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn node_info(&self) -> ClusterNodeInfo {
            ClusterNodeInfo {
                node_id: self.node_id.clone(),
                address: "local".into(),
                version: "0.1.0".into(),
                started_at: "2026-04-23T00:00:00Z".into(),
                roles: vec![],
            }
        }
        async fn list_peers(&self) -> Vec<ClusterPeer> {
            vec![]
        }
        async fn watch_peers(&self) -> BoxPeerEventStream {
            Box::pin(empty_stream())
        }
        async fn acquire_leadership(
            &self,
            _role: &str,
            _lease_ttl: std::time::Duration,
        ) -> Result<BoxActiveLease, ClusterError> {
            Err(ClusterError::Shutdown)
        }
        async fn acquire_lock(
            &self,
            _key: &str,
            _lease_ttl: std::time::Duration,
        ) -> Result<BoxActiveLease, ClusterError> {
            Err(ClusterError::Shutdown)
        }
        async fn publish(
            &self,
            _topic: &str,
            _routing_key: Option<&str>,
            _payload: bytes::Bytes,
        ) -> Result<(), ClusterError> {
            Ok(())
        }
        async fn subscribe(
            &self,
            _topic: &str,
            _group: Option<&str>,
            _routing_key: Option<&str>,
        ) -> Result<BoxPublishedMessageStream, ClusterError> {
            Ok(Box::pin(empty_stream()))
        }
    }

    fn empty_stream<T: Send + 'static>() -> impl futures_core::Stream<Item = T> + Send + 'static {
        struct E<T>(std::marker::PhantomData<T>);
        unsafe impl<T: Send> Send for E<T> {}
        impl<T> futures_core::Stream for E<T> {
            type Item = T;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<T>> {
                std::task::Poll::Ready(None)
            }
        }
        E::<T>(std::marker::PhantomData)
    }

    fn fixed_cluster(id: &str, node_id: &str) -> Arc<FixedCluster> {
        Arc::new(FixedCluster {
            manifest: PluginManifest {
                id: id.into(),
                version: "0.1.0".into(),
                name: "Test cluster".into(),
                plugin_class: PluginClass::Cluster,
                protocol_version: PROTOCOL_VERSION.into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            node_id: node_id.into(),
        })
    }

    #[tokio::test]
    async fn cluster_backend_install_resolves_lookup() {
        let gw = MockGateway::new().with_cluster_backend(fixed_cluster("dev.test.cc", "n1"));
        let cc = gw.cluster_backend().expect("installed");
        let info = cc.node_info().await;
        assert_eq!(info.node_id, "n1");
    }

    #[test]
    #[should_panic(expected = "already installed")]
    fn cluster_backend_install_panics_on_duplicate() {
        MockGateway::new()
            .with_cluster_backend(fixed_cluster("dev.test.a", "n1"))
            .with_cluster_backend(fixed_cluster("dev.test.b", "n2"));
    }

    #[test]
    fn cluster_backend_default_is_none() {
        let gw = MockGateway::new();
        assert!(gw.cluster_backend().is_none());
    }
}
