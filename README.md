# mcpg-plugin-sdk

> The plugin-authoring SDK: the declaration macro, host-service client helpers, and a mock-gateway test harness.

This is the crate you build an MCPG plugin against. It gives you one macro,
`declare_plugin!`, that turns a plain Rust type into a loadable plugin — emitting
the cdylib `mcpg_plugin_register` export, the in-process `register_static()`
registration function, or both, from a single declaration. Around that it
provides the plugin-side clients for everything a plugin calls back into the
gateway for, and a `MockGateway` harness so a plugin can be unit-tested with no
gateway process anywhere in sight. It re-exports `mcpg-plugin-protocol`,
`abi_stable`, and — under `static-firstparty` — `mcpg-plugin-host` and `anyhow`,
so a plugin crate needs one SDK dependency rather than four coordinated ones. The
`mcpg-sdk` façade wraps this crate together with the protocol crate behind a
single `prelude`; use that if you would rather not pick between them.

## What's here

- `declare_plugin!` — the sole authoring entry point. One invocation declares any
  number of entities, of mixed kinds, and produces exactly one
  `mcpg_plugin_register` symbol and one `register_static` function. Each entity
  registers under `{plugin_id}:{inner_name}`, falling back to the bare
  `plugin_id` when `inner_name` is empty, so a multi-entity plugin cannot collide
  with itself on the registry's uniqueness check. The macro also emits
  `DESCRIPTOR_YAML`, the embedded `plugin.yaml`, so packaging tooling can prove
  the binary and the on-disk descriptor have not drifted. `cluster_backend` and
  `transport` entities are accepted for the cdylib path but are a compile error
  under `register_static`, with the diagnostic pointing at the kind keyword.
- `ffi` — the `Sync*` traits a cdylib entity actually implements, one per kind:
  `SyncToolGate`, `SyncTransform`, `SyncIdentityResolver`, `SyncBackendPlugin`,
  `SyncWatchStrategyPlugin`, `SyncHttpRoute`, `SyncAuditSink`, `SyncLogSink`,
  `SyncStorePlugin`, `SyncCachePlugin`, `SyncSecretProvider`,
  `SyncConfigProvider`, `SyncPolicyEngine`, `SyncClusterBackend`,
  `SyncApprovalNotifier`, `SyncCredentialIssuer` and peers. Their methods are
  synchronous; the macro builds the async trait surface the host registry
  consumes.
- `HostHandle`, with `MetricPoint` and `SpanGuard` — the unified surface for
  calling back into the host: secrets, credentials, config, audit, metrics,
  spans, cache, and content.
- `cluster` — `ClusterClient`, `ClusterLease`, and `Subscription`, the
  plugin-side view of the gateway's cluster backbone.
- `adapters` — the sync-to-async bridges (`SyncToolGateAdapter` and peers) the
  macro's static path wraps your type in.
- `config` — `parse_config_or_fail_closed` and the `fail_closed_config!` macro.
  These exist because the obvious idiom, `from_str(cfg).unwrap_or_default()`,
  fails **open**: a typo'd operator config block silently becomes default
  behaviour. These fail closed instead, turning a malformed config into a
  refused load, while an empty or absent block still resolves to `Default`.
- `sql_guard::enforce_read_only` — the conservative, parser-free statement
  classifier the SQL-shaped backends apply when a binding declares
  `read_only: true`.
- `watch` — `spawn_polling_watch` and `cancel_polling_watch`, the shared
  high-water polling loop for backends with no native change-push channel.
- `testing` — `MockGateway` with per-class builders (`with_tool_gate`,
  `with_transform`, `with_identity`, `with_audit_sink`, `with_store`,
  `with_cache`, `with_policy_engine`, and the rest), `ContextBuilder` for
  constructing a `PluginContext` at a chosen trust level, and `ToolCallResult`
  with the `ToolCallResultAssertions` helpers.

Four features, all off by default:

| Feature | What it turns on |
|---|---|
| `cdylib-export` | Makes the macro's `mcpg_plugin_register` symbol exportable. Recognised-but-empty here; the real gate is the same-named feature in your own crate. |
| `static-firstparty` | Emits `register_static()` for in-process registration, and pulls in `mcpg-plugin-host`, `anyhow`, and `tokio`. |
| `streaming` | Streaming-body support in the macro's `http_route` and `transport` arms. |
| `cluster-forward` | The `ffi::cluster_forward` module, whose `forward_cluster_stream` bridges a cluster pub/sub or peer-watch stream into the host's synchronous `emit_event` callback. Cancelling the handle aborts the forwarder and blocks until any in-flight callback has returned, so it can never touch a freed host bridge. |

## Used by

- Every in-tree plugin crate, and every third-party plugin — directly or through
  the `mcpg-sdk` façade.
- The gateway, indirectly: a plugin built with `static-firstparty` registers
  through `mcpg-plugin-host`'s `FirstPartyRegistrar` instead of the FFI vtable.

## Usage

A plugin crate builds both ways from one source, so it declares both artefact
kinds and its own `cdylib-export` feature — that is the flag the macro's
`#[cfg]` reads in *your* crate:

```toml
[package]
name = "my-mcpg-gate"
edition = "2024"

[lib]
crate-type = ["cdylib", "rlib"]

[features]
default = []
cdylib-export = []

[dependencies]
mcpg-plugin-sdk = { version = "<version>", features = ["static-firstparty"] }
mcpg-plugin-protocol = "<version>"
serde_json = "1"
```

Implement the sync trait for your kind, then declare the plugin:

```rust
use mcpg_plugin_protocol::{
    GateDecision, PluginClass, PluginContext, PluginManifest, PROTOCOL_VERSION,
};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde_json::Value;

pub struct BlockDebugTools {
    manifest: PluginManifest,
}

impl BlockDebugTools {
    pub fn from_config_json(config_json: &str) -> Self {
        // Refuses a malformed operator config block instead of
        // silently falling back to defaults.
        let _cfg: serde_json::Map<String, Value> =
            mcpg_plugin_sdk::fail_closed_config!(config_json);

        Self {
            manifest: PluginManifest {
                id: "dev.example.tool-gate.block-debug".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Block Debug Tools".to_owned(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: PROTOCOL_VERSION.to_owned(),
                license: Some("Apache-2.0".to_owned()),
                // Host-derived: the authoring point is the macro's
                // `capabilities:` list, not this field.
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: module_path!()
                    .split("::")
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
            },
        }
    }
}

impl SyncToolGate for BlockDebugTools {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        _arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if ctx.tool_name.starts_with("debug_") {
            GateDecision::Deny {
                http_status: 403,
                code: -32030,
                message: "debug tools are not callable through the gateway".to_owned(),
                error_data: None,
            }
        } else {
            GateDecision::allow()
        }
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        GateDecision::allow()
    }
}

mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.example.tool-gate.block-debug",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: BlockDebugTools,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| {
                BlockDebugTools::from_config_json(cfg)
            },
        },
    ],
}
```

Build the loadable artefact by enabling your crate's `cdylib-export` feature:

```bash
cargo build -p my-mcpg-gate --features cdylib-export --release   # → target/release/libmy_mcpg_gate.so
```

Exercise it without a gateway using the mock harness:

```rust
use mcpg_plugin_sdk::{SyncToolGateAdapter, testing::MockGateway};

// The adapter lifts the sync trait into the async one the registry
// consumes — the same wrap `register_static()` performs.
let plugin = SyncToolGateAdapter::new(BlockDebugTools::from_config_json("{}"));
let gw = MockGateway::new().with_tool_gate(Box::new(plugin));

let result = gw.call_tool("debug_dump", serde_json::json!({})).await;
assert!(result.is_denied());
```

## Build / test

```bash
cargo build -p mcpg-plugin-sdk
cargo test  -p mcpg-plugin-sdk
cargo test  -p mcpg-plugin-sdk --features static-firstparty   # adds the register_static conformance tests
```

Three integration tests — the static fast-path conformance test, the
delegation-arms smoke test, and the mixed-kind multi-entity test — require
`static-firstparty` and are skipped without it.

## Licence

Apache-2.0.

## See also

- [Plugin authoring](https://mcpg.dev/docs/plugins/plugin-authoring) — the end-to-end guide, including `plugin.yaml`.
- [Plugins and the plugin protocol](https://mcpg.dev/docs/plugins/plugins-and-protocol) — the classes, tiers, and ABI.
- [Plugin security](https://mcpg.dev/docs/security/plugin-security) — signing and loading a built artefact in production.
- `libs/sdk` — the `mcpg-sdk` façade that re-exports this crate and the protocol crate behind one prelude.
