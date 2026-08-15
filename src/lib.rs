//! # mcpg-plugin-sdk
//!
//! Developer SDK for building, testing, and packaging MCPG plugins.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use mcpg_plugin_sdk::testing::MockGateway;
//! use mcpg_plugin_protocol::*;
//!
//! // Your plugin
//! struct MyGatePlugin;
//! #[async_trait]
//! impl ToolGatePlugin for MyGatePlugin {
//!     fn manifest(&self) -> &PluginManifest { todo!() }
//!     async fn evaluate_pre_dispatch(&self, ctx: &PluginContext, args: &serde_json::Value, meta: Option<&serde_json::Value>, config: &serde_json::Value) -> GateDecision {
//!         GateDecision::allow()
//!     }
//! }
//!
//! // Test it (async)
//! # async fn example() {
//! let gw = MockGateway::new()
//!     .with_tool_gate(Box::new(MyGatePlugin));
//!
//! let result = gw.call_tool("my_tool", serde_json::json!({"x": 1})).await;
//! assert!(result.is_allowed());
//! # }
//! ```

pub mod adapters;
pub mod cluster;
pub mod config;
#[macro_use]
pub mod declare_plugin;
pub mod ffi;
pub mod host_handle;
#[macro_use]
pub mod macros;
pub mod sql_guard;
pub mod template;
pub mod testing;
pub mod watch;

/// Re-export the sync-to-async trait adapters so plugin authors
/// using `declare_plugin!` see `mcpg_plugin_sdk::SyncToolGateAdapter`
/// in error messages instead of the deeper module path.
pub use adapters::SyncToolGateAdapter;

/// Re-export the SDK-side cluster surface so plugin authors call it as
/// `mcpg_plugin_sdk::ClusterClient` without typing the `cluster::`
/// segment.
pub use cluster::{ClusterClient, ClusterLease, Subscription};

/// Re-export the unified `HostHandle` surface so plugin authors can
/// write `use mcpg_plugin_sdk::{HostHandle, MetricPoint, SpanGuard};`
/// instead of typing the `host_handle::` path.
pub use host_handle::{HostHandle, HostHandleBackendHost, MetricPoint, SpanGuard};

/// Re-export the plugin API for convenience.
pub use mcpg_plugin_protocol;

/// Re-export abi_stable for downstream cdylib crates using the macro.
/// The macro expansion references `::abi_stable::std_types` at
/// user-crate compile time, so downstream must have abi_stable in
/// their dependency graph — exposing it from the SDK lets plugin
/// authors add a single `mcpg-plugin-sdk` dep instead of two.
pub use abi_stable;

/// Re-export `mcpg_plugin_host` so the
/// [`declare_plugin!`](crate::declare_plugin) macro's
/// `register_static()` expansion can reference
/// `::mcpg_plugin_sdk::plugin_host::FirstPartyRegistrar` instead of
/// `::mcpg_plugin_host::FirstPartyRegistrar`. Plugin crates that
/// enable the `static-firstparty` feature get the host symbols for
/// free without needing a direct `mcpg-plugin-host` dep.
#[cfg(feature = "static-firstparty")]
pub use mcpg_plugin_host as plugin_host;

/// Re-export `anyhow` for the same reason as `plugin_host` — the
/// macro's `register_static()` returns `::mcpg_plugin_sdk::anyhow::Result`
/// so plugin crates don't need their own `anyhow` dep just to
/// satisfy the macro's expansion.
#[cfg(feature = "static-firstparty")]
pub use anyhow;
