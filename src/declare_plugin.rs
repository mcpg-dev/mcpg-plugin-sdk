//! Unified [`declare_plugin!`] macro — the sole
//! plugin-author entry point.
//!
//! Generates BOTH a static-firstparty registration function AND a
//! cdylib export from a single source. Supports multi-entity plugins
//! across ALL 20 entity kinds (mixed-kind support) — one
//! plugin exposing multiple entities of any kind, each with a distinct
//! `inner_name`. One `declare_plugin!` invocation produces ONE
//! `mcpg_plugin_register` symbol + ONE `register_static` function, even
//! when the entity list mixes (say) two `tool_gate`s and an
//! `audit_sink`. This macro supersedes the 20 retired per-kind
//! `declare_<kind>_plugin!` macros.
//!
//! # Example — mixed-kind multi-entity
//!
//! ```ignore
//! use mcpg_plugin_sdk::declare_plugin;
//! use mcpg_plugin_protocol::capability::Capability;
//!
//! declare_plugin! {
//!     plugin_id: "dev.mcpg.example.multi",
//!     plugin_version: env!("CARGO_PKG_VERSION"),
//!     descriptor_yaml: include_str!("../plugin.yaml"),
//!     capabilities: &[Capability::AuditWrite],
//!     entities: [
//!         tool_gate as rate_limit_entity {
//!             inner_name: "rate-limit",
//!             plugin_type: RateLimitGate,
//!             factory: |cfg| RateLimitGate::new(cfg),
//!         },
//!         tool_gate as circuit_breaker_entity {
//!             inner_name: "circuit-breaker",
//!             plugin_type: CircuitBreakerGate,
//!             factory: |cfg| CircuitBreakerGate::new(cfg),
//!         },
//!         audit_sink as my_audit_sink {
//!             inner_name: "",
//!             plugin_type: MyAuditSink,
//!             factory: |cfg| MyAuditSink::new(cfg),
//!         },
//!     ],
//! }
//! ```
//!
//! The macro generates:
//!
//! - `pub const DESCRIPTOR_YAML: &str` — the embedded `plugin.yaml`,
//!   cross-checkable against the on-disk descriptor by packaging
//!   tooling.
//! - One hygienic sub-module per entity (e.g. `mod rate_limit_entity`)
//!   containing the entity's `extern "C"` vtable wrappers, emitted via
//!   the matching `__mcpg_decl_<kind>_entity!` helper. Sub-modules
//!   keep the wrapper symbols (`__make`, `__drop`, `__evaluate_pre`,
//!   …) from colliding across entities.
//! - `#[cfg(feature = "cdylib-export")] pub extern "C" fn
//!   mcpg_plugin_register()` returning a [`PluginRegistration`] whose
//!   `entities` vec contains one entry per declared entity (variant
//!   chosen by the entity's kind keyword).
//! - `#[cfg(feature = "static-firstparty")] pub fn
//!   register_static(registrar, granted) -> Result<()>` — the
//!   static-firstparty fast path. Wraps each entity's user type
//!   through the matching `Sync*Adapter`, and registers it with the
//!   host's [`PluginRegistry`] via the alias-aware
//!   `register_<kind>_with_alias` slot. No FFI, no JSON, no
//!   `spawn_blocking` — direct in-process trait dispatch.
//!
//! Each entity is registered statically under
//! `format!("{plugin_id}:{inner_name}")` so multi-entity plugins
//! don't collide on the registry's per-alias uniqueness check.
//! Entities with an empty `inner_name` fall back to the bare
//! `plugin_id` so single-entity plugins keep their familiar alias.
//!
//! # Unsupported kinds for `register_static`
//!
//! `cluster_backend` and `transport` are accepted in the cdylib
//! `entities: [ ... ]` list, but invoking `register_static` for them
//! is a compile error — `FirstPartyRegistrar` has no
//! `register_<kind>_with_alias` slot for those kinds today. The
//! diagnostic points at the kind keyword.

/// Declare a plugin's static-firstparty registration function and
/// cdylib export from one source. See module docs for syntax.
///
/// # Multi-entity model
///
/// The unified arm accepts ANY of the 20 entity kinds — mix freely.
/// Each entity is registered under a unique alias derived from
/// `inner_name`. Empty `inner_name` defaults the alias to the bare
/// `plugin_id` (single-entity case).
#[macro_export]
macro_rules! declare_plugin {
    (
        plugin_id: $id:expr,
        plugin_version: $version:expr,
        descriptor_yaml: $descriptor:expr,
        $( capabilities: $caps:expr, )?
        $( backend_profile: $backend_profile:expr, )?
        entities: [
            $(
                $kind:ident as $mod_name:ident {
                    inner_name: $inner:expr,
                    plugin_type: $ty:ty,
                    factory: $factory:expr $(,)?
                }
            ),+ $(,)?
        ] $(,)?
    ) => {
        /// Embedded YAML descriptor. Packaging tooling cross-checks
        /// it against the sibling on-disk `plugin.yaml` so the binary
        /// and the descriptor can't drift.
        pub const DESCRIPTOR_YAML: &str = $descriptor;

        $(
            #[doc(hidden)]
            pub mod $mod_name {
                use super::*;
                $crate::__mcpg_dispatch_entity_module! {
                    $kind,
                    plugin_type: $ty,
                    factory: $factory,
                }
            }
        )+

        /// Cdylib entry point looked up by the host's dynamic loader.
        /// Returns one [`EntityRegistration`] per declared entity, in
        /// declaration order; variant is selected by each entity's
        /// kind keyword.
        #[cfg(feature = "cdylib-export")]
        #[unsafe(no_mangle)]
        pub extern "C" fn mcpg_plugin_register()
            -> ::mcpg_plugin_protocol::abi::PluginRegistration
        {
            ::mcpg_plugin_protocol::abi::catch_panic_to_panicked_registration(|| {
                use $crate::abi_stable::std_types::{RString, RVec};
                let mut entities: RVec<::mcpg_plugin_protocol::abi::EntityRegistration>
                    = RVec::new();
                $(
                    entities.push(
                        $crate::__mcpg_dispatch_entity_registration!(
                            $kind, $mod_name, $inner
                        )
                    );
                )+
                ::mcpg_plugin_protocol::abi::PluginRegistration {
                    abi_version: ::mcpg_plugin_protocol::abi::MCPG_PLUGIN_ABI_VERSION,
                    plugin_id: RString::from($id),
                    plugin_version: RString::from($version),
                    module_path_prefix: RString::from(::std::module_path!()),
                    entities,
                    capabilities: {
                        #[allow(unused_mut)]
                        let mut __caps = RVec::new();
                        $( for c in $caps.iter() {
                            __caps.push(
                                ::mcpg_plugin_protocol::abi::TypedCapabilityDecl
                                    ::from_capability(c),
                            );
                        } )?
                        __caps
                    },
                    backend_profile_json: {
                        #[allow(unused_mut, unused_assignments)]
                        let mut __bp = $crate::abi_stable::std_types::ROption::RNone;
                        $(
                            let __profile: ::mcpg_plugin_protocol::manifest::BackendProfile
                                = $backend_profile;
                            __bp = $crate::abi_stable::std_types::ROption::RSome(
                                RString::from(
                                    ::mcpg_plugin_protocol::serde_json::to_string(&__profile)
                                        .unwrap_or_default(),
                                ),
                            );
                        )?
                        __bp
                    },
                    descriptor_yaml: RString::from(DESCRIPTOR_YAML),
                }
            })
        }

        /// Type-identity check: exports this cdylib's
        /// `PluginRegistration` `abi_stable` type layout so the host can
        /// structurally verify ABI compatibility *before* reading the
        /// by-value struct `mcpg_plugin_register` returns. See
        /// [`mcpg_plugin_protocol::abi::plugin_registration_layout`].
        #[cfg(feature = "cdylib-export")]
        #[unsafe(no_mangle)]
        pub extern "C" fn mcpg_plugin_abi_layout()
            -> ::mcpg_plugin_protocol::abi::AbiLayoutPtr
        {
            ::mcpg_plugin_protocol::abi::plugin_registration_layout()
        }

        /// Static-firstparty registration entry. The gateway boot
        /// path calls this after building a
        /// [`FirstPartyRegistrar`](::mcpg_plugin_host::FirstPartyRegistrar).
        ///
        /// `granted` is the operator-grantable capability slice from
        /// the matching `plugins[]` entry (or `&[]` for built-ins
        /// that ship outside the operator's plugin config).
        ///
        /// This path bypasses the FFI
        /// entirely — each entity's adapter-wrapped plugin handle is
        /// constructed once at boot and registered into the chain
        /// directly. Per-request dispatch then runs through the
        /// async trait's vtable (~ns/call), not through
        /// `extern "C"` + JSON encode/decode + `spawn_blocking`
        /// (~µs/call).
        #[cfg(feature = "static-firstparty")]
        pub fn register_static(
            registrar: &mut $crate::plugin_host::FirstPartyRegistrar,
            granted: &[::mcpg_plugin_protocol::capability::Capability],
            host: $crate::HostHandle,
        ) -> $crate::anyhow::Result<()> {
            registrar.register(DESCRIPTOR_YAML, granted, host, |registry, host| {
                $(
                    $crate::__mcpg_dispatch_register_static!(
                        $kind, $mod_name, $inner, $id, registry, host
                    );
                )+
                Ok(())
            })
        }
    };
}
