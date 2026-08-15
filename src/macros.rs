//! Per-entity helper macros consumed by the unified
//! [`declare_plugin!`](crate::declare_plugin) macro.
//!
//! Each `__mcpg_decl_<kind>_entity!` in this file emits the per-kind
//! `extern "C"` vtable wrappers + `make_vtable()` (and, where the
//! kind has a `register_static` slot, `build_static()`). These
//! helpers are `#[doc(hidden)] #[macro_export]`: not part of the
//! SDK's public surface, but exported so the user-facing
//! `declare_plugin!` expansion can call them from a downstream
//! crate's scope. Plugin authors should never invoke them directly.
//!
//! Authoring path: see [`declare_plugin!`](crate::declare_plugin)
//! for the macro plugin crates actually use.

/// Internal helper — emit per-entity `tool_gate` vtable wrappers plus
/// `make_vtable()` / `build_static()` accessor fns at the current
/// scope. The unified [`declare_plugin!`] macro composes multiple
/// entities (of any kind) under a single `mcpg_plugin_register`
/// export by invoking this helper once per declared entity.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_tool_gate_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_plugin_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_plugin_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: the host only ever passes back a handle we
                // previously returned from `__mcpg_plugin_make`, which
                // boxed a `$ty`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_plugin_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract, handle is live for the call.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncToolGate>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        // One slot: borrowed `RStr` args/meta/config in, typed decision
        // out. The host calls it ferried-by-default or inline (operator opt-in);
        // either way the SDK parses the borrowed JSON to `&Value` and calls the
        // author's `evaluate_pre`.
        extern "C" fn __mcpg_plugin_evaluate_pre(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            ctx: ::mcpg_plugin_protocol::abi::RPluginContext,
            args: $crate::abi_stable::std_types::RStr<'_>,
            meta: $crate::abi_stable::std_types::ROption<$crate::abi_stable::std_types::RStr<'_>>,
            cfg: $crate::abi_stable::std_types::RStr<'_>,
        ) -> ::mcpg_plugin_protocol::abi::RGateDecision {
            ::mcpg_plugin_protocol::abi::catch_panic_to_deny(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let ctx: ::mcpg_plugin_protocol::PluginContext = ctx.into();
                let args_val: ::serde_json::Value =
                    ::serde_json::from_str(args.as_str()).unwrap_or(::serde_json::Value::Null);
                let meta_val: Option<::serde_json::Value> = meta
                    .into_option()
                    .and_then(|s| ::serde_json::from_str(s.as_str()).ok());
                let cfg_val: ::serde_json::Value =
                    ::serde_json::from_str(cfg.as_str()).unwrap_or(::serde_json::json!({}));
                let decision = <$ty as $crate::ffi::SyncToolGate>::evaluate_pre(
                    plugin,
                    &ctx,
                    &args_val,
                    meta_val.as_ref(),
                    &cfg_val,
                );
                decision.into()
            })
        }

        extern "C" fn __mcpg_plugin_evaluate_post(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            ctx: ::mcpg_plugin_protocol::abi::RPluginContext,
            args: $crate::abi_stable::std_types::RStr<'_>,
            result: $crate::abi_stable::std_types::RStr<'_>,
            duration_ms: u64,
            cfg: $crate::abi_stable::std_types::RStr<'_>,
        ) -> ::mcpg_plugin_protocol::abi::RGateDecision {
            ::mcpg_plugin_protocol::abi::catch_panic_to_deny(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let ctx: ::mcpg_plugin_protocol::PluginContext = ctx.into();
                let args_val: ::serde_json::Value =
                    ::serde_json::from_str(args.as_str()).unwrap_or(::serde_json::Value::Null);
                let result_val: ::serde_json::Value =
                    ::serde_json::from_str(result.as_str()).unwrap_or(::serde_json::Value::Null);
                let cfg_val: ::serde_json::Value =
                    ::serde_json::from_str(cfg.as_str()).unwrap_or(::serde_json::json!({}));
                let decision = <$ty as $crate::ffi::SyncToolGate>::evaluate_post(
                    plugin,
                    &ctx,
                    &args_val,
                    &result_val,
                    duration_ms,
                    &cfg_val,
                );
                decision.into()
            })
        }

        extern "C" fn __mcpg_plugin_shutdown(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncToolGate>::shutdown(plugin);
            })
        }

        /// Build this entity's [`ToolGateVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::ToolGateVTable {
            ::mcpg_plugin_protocol::abi::ToolGateVTable {
                make: __mcpg_plugin_make,
                manifest_json: __mcpg_plugin_manifest_json,
                evaluate_pre_dispatch: __mcpg_plugin_evaluate_pre,
                evaluate_post_dispatch: __mcpg_plugin_evaluate_post,
                shutdown: __mcpg_plugin_shutdown,
                drop_instance: __mcpg_plugin_drop,
            }
        }

        /// Build a `Box<dyn ToolGatePlugin>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncToolGateAdapter`](crate::adapters::SyncToolGateAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins. Note tool_gate uses `Box<dyn>` (not `Arc<dyn>`) —
        /// the host's `register_tool_gate*` slots take `Box`.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::boxed::Box<dyn ::mcpg_plugin_protocol::traits::ToolGatePlugin> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::boxed::Box::new($crate::adapters::SyncToolGateAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `transform` vtable wrappers plus
/// `make_vtable()` / `build_static()` accessor fns at the current
/// scope. The unified [`declare_plugin!`] macro can compose multiple
/// entities (of any kind) under a single `mcpg_plugin_register`
/// export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_transform_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_transform_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_transform_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: round-trip under the same T as `make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_transform_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncTransform>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_transform_arguments(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            ctx: ::mcpg_plugin_protocol::abi::RPluginContext,
            args_json: $crate::abi_stable::std_types::RStr<'_>,
            cfg_json: $crate::abi_stable::std_types::RStr<'_>,
        ) -> ::mcpg_plugin_protocol::abi::RTransformResult {
            ::mcpg_plugin_protocol::abi::catch_panic_to_transform_error(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let ctx: ::mcpg_plugin_protocol::PluginContext = ctx.into();
                let args_val: ::serde_json::Value =
                    ::serde_json::from_str(args_json.as_str()).unwrap_or(::serde_json::Value::Null);
                let cfg_val: ::serde_json::Value =
                    ::serde_json::from_str(cfg_json.as_str()).unwrap_or(::serde_json::json!({}));
                let result = <$ty as $crate::ffi::SyncTransform>::transform_arguments(
                    plugin, &ctx, &args_val, &cfg_val,
                );
                result.into()
            })
        }

        extern "C" fn __mcpg_transform_result(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            ctx: ::mcpg_plugin_protocol::abi::RPluginContext,
            result_json: $crate::abi_stable::std_types::RStr<'_>,
            cfg_json: $crate::abi_stable::std_types::RStr<'_>,
        ) -> ::mcpg_plugin_protocol::abi::RTransformResult {
            ::mcpg_plugin_protocol::abi::catch_panic_to_transform_error(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let ctx: ::mcpg_plugin_protocol::PluginContext = ctx.into();
                let result_val: ::serde_json::Value = ::serde_json::from_str(result_json.as_str())
                    .unwrap_or(::serde_json::Value::Null);
                let cfg_val: ::serde_json::Value =
                    ::serde_json::from_str(cfg_json.as_str()).unwrap_or(::serde_json::json!({}));
                let result = <$ty as $crate::ffi::SyncTransform>::transform_result(
                    plugin,
                    &ctx,
                    &result_val,
                    &cfg_val,
                );
                result.into()
            })
        }

        extern "C" fn __mcpg_transform_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncTransform>::shutdown(plugin);
            })
        }

        /// Build this entity's [`TransformVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::TransformVTable {
            ::mcpg_plugin_protocol::abi::TransformVTable {
                make: __mcpg_transform_make,
                manifest_json: __mcpg_transform_manifest_json,
                transform_arguments: __mcpg_transform_arguments,
                transform_result: __mcpg_transform_result,
                shutdown: __mcpg_transform_shutdown,
                drop_instance: __mcpg_transform_drop,
            }
        }

        /// Build a `Box<dyn TransformPlugin>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncTransformAdapter`](crate::adapters::SyncTransformAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins. The caller (`declare_plugin!` arm) supplies the
        /// `config: serde_json::Value` arg when calling
        /// `register_transform*` on the host registry.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::boxed::Box<dyn ::mcpg_plugin_protocol::traits::TransformPlugin> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::boxed::Box::new($crate::adapters::SyncTransformAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `identity` vtable wrappers
/// plus `make_vtable()` / `build_static()` accessor fns at the
/// current scope. The unified [`declare_plugin!`]
/// macro can compose multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_identity_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        // `make` takes `(host: HostHandleRef, config_json, inner_name)`.
        // The SDK hands a unified `HostHandle` to every kind's factory and
        // the plugin derives cluster on-demand via `host.cluster()`.
        // Identity plugins that need cluster (workload, …) call
        // `host.cluster()` inline; plugins that don't ignore the host
        // argument.
        extern "C" fn __mcpg_identity_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_identity_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: round-trip under the same T as `make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        // `shutdown` slot on `IdentityProviderVTable`. Default impl on
        // `SyncIdentityResolver::shutdown` is a no-op; identity plugins
        // that need to flush JWKS or stop background refresh tasks
        // override the trait method.
        extern "C" fn __mcpg_identity_shutdown(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract, handle is live until
                // drop_instance returns.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncIdentityResolver>::shutdown(plugin);
            })
        }

        extern "C" fn __mcpg_identity_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract, handle is live for the call.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncIdentityResolver>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_identity_resolve(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            headers_json: $crate::abi_stable::std_types::RStr<'_>,
            metadata_json: $crate::abi_stable::std_types::RStr<'_>,
            config_json: $crate::abi_stable::std_types::RStr<'_>,
        ) -> ::mcpg_plugin_protocol::abi::RIdentityResolution {
            ::mcpg_plugin_protocol::abi::catch_panic_to_identity_invalid(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                // Host encodes headers as a JSON array of
                // [name, value] tuples (see
                // `NativeIdentityProviderAdapter::resolve_identity`). Parse
                // back to the native `&[(String, String)]`.
                let headers_val: ::serde_json::Value =
                    ::serde_json::from_str(headers_json.as_str())
                        .unwrap_or(::serde_json::Value::Array(Vec::new()));
                let headers: Vec<(String, String)> = headers_val
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|entry| {
                                let pair = entry.as_array()?;
                                let k = pair.first()?.as_str()?.to_owned();
                                let v = pair.get(1)?.as_str()?.to_owned();
                                Some((k, v))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // RequestMetadata flows through a separate JSON
                // parameter. Empty-string and parse failure both fall
                // back to default(), so hosts that don't populate it
                // stay compatible.
                let metadata: ::mcpg_plugin_protocol::types::RequestMetadata =
                    if metadata_json.as_str().is_empty() {
                        ::mcpg_plugin_protocol::types::RequestMetadata::default()
                    } else {
                        ::serde_json::from_str(metadata_json.as_str()).unwrap_or_default()
                    };
                let cfg: ::serde_json::Value =
                    ::serde_json::from_str(config_json.as_str()).unwrap_or(::serde_json::json!({}));
                let resolution = <$ty as $crate::ffi::SyncIdentityResolver>::resolve_identity(
                    plugin, &headers, &metadata, &cfg,
                );
                resolution.into()
            })
        }

        /// Build this entity's [`IdentityProviderVTable`]. The
        /// caller's `mcpg_plugin_register` invokes this once per
        /// entity to keep the per-entity wrappers private to the
        /// sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::IdentityProviderVTable {
            ::mcpg_plugin_protocol::abi::IdentityProviderVTable {
                make: __mcpg_identity_make,
                manifest_json: __mcpg_identity_manifest_json,
                resolve_identity: __mcpg_identity_resolve,
                shutdown: __mcpg_identity_shutdown,
                drop_instance: __mcpg_identity_drop,
            }
        }

        /// Build a static `Box<dyn IdentityProviderPlugin>` from the
        /// user's sync `$ty` implementation, wrapped through
        /// [`SyncIdentityAdapter`](crate::adapters::SyncIdentityAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins. The caller hands a `HostHandle` and identity plugins
        /// that need cluster derive it via `host.cluster()`.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::boxed::Box<dyn ::mcpg_plugin_protocol::traits::IdentityProviderPlugin> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::boxed::Box::new($crate::adapters::SyncIdentityAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `backend` vtable wrappers plus
/// `make_vtable()` / `build_static()` accessor fns at the current
/// scope. The unified [`declare_plugin!`] macro can compose multiple
/// entities (of any kind) under a single `mcpg_plugin_register`
/// export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_backend_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_binding_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_binding_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: handle round-trips through `__mcpg_binding_make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_binding_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncBackendPlugin>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_binding_kind(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                $crate::abi_stable::std_types::RString::from(
                    <$ty as $crate::ffi::SyncBackendPlugin>::kind(plugin),
                )
            })
        }

        extern "C" fn __mcpg_binding_register_profile(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
            spec_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let spec: ::serde_json::Value =
                    ::serde_json::from_str(spec_json.as_str()).unwrap_or(::serde_json::Value::Null);
                let r = <$ty as $crate::ffi::SyncBackendPlugin>::register_profile(
                    plugin,
                    backend_name.as_str(),
                    &spec,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_binding_execute(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
            request_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let request: ::mcpg_plugin_protocol::BackendRequest =
                    match ::serde_json::from_str(request_json.as_str()) {
                        Ok(r) => r,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_plugin_protocol::BackendError::Transport {
                                    message: format!("invalid request JSON: {e}"),
                                },
                            );
                        }
                    };
                let r = <$ty as $crate::ffi::SyncBackendPlugin>::execute(
                    plugin,
                    backend_name.as_str(),
                    request,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        // Incremental response stream.
        // Wraps the host's `EventSinkRef` into a typed
        // `BackendChunkEmitter` (each chunk serialized to a result
        // envelope + pushed across the seam) and returns the
        // `StreamHandle` whose `handle` is the plugin's cancel token.
        extern "C" fn __mcpg_binding_execute_streaming(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
            request_json: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            ::mcpg_plugin_protocol::abi::catch_panic_to_stream_failure(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let request: ::mcpg_plugin_protocol::BackendRequest =
                    match ::serde_json::from_str(request_json.as_str()) {
                        Ok(r) => r,
                        Err(e) => {
                            let err = ::mcpg_plugin_protocol::BackendError::Transport {
                                message: format!("invalid request JSON: {e}"),
                            };
                            return ::mcpg_plugin_protocol::abi::StreamHandle {
                                handle: 0,
                                error_json: $crate::abi_stable::std_types::RString::from(
                                    ::serde_json::to_string(&err).unwrap_or_default(),
                                ),
                                metadata_json: $crate::abi_stable::std_types::RString::new(),
                            };
                        }
                    };
                let emit: $crate::ffi::BackendChunkEmitter = ::std::boxed::Box::new(
                    move |chunk: ::std::result::Result<
                        ::mcpg_plugin_protocol::backend::BackendChunk,
                        ::mcpg_plugin_protocol::BackendError,
                    >| {
                        let json =
                            ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&chunk);
                        (sink.callback)(sink.ctx, json);
                    },
                );
                match <$ty as $crate::ffi::SyncBackendPlugin>::execute_streaming(
                    plugin,
                    backend_name.as_str(),
                    request,
                    emit,
                ) {
                    Ok(token) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        // A successful stream MUST report a non-zero handle:
                        // the host reads `handle == 0` as "stream failed to
                        // start". A plugin returning `Ok(0)`
                        // ("nothing to cancel" — e.g. the buffered default)
                        // maps to the sentinel here; `cancel_stream` maps it
                        // back to 0.
                        handle: if token == 0 {
                            $crate::ffi::STREAM_NO_CANCEL_SENTINEL
                        } else {
                            token
                        },
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            })
        }

        extern "C" fn __mcpg_binding_cancel_stream(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            stream_token: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                // Undo the execute_streaming sentinel mapping: restore the
                // plugin's own "nothing to cancel" 0.
                let token = if stream_token == $crate::ffi::STREAM_NO_CANCEL_SENTINEL {
                    0
                } else {
                    stream_token
                };
                <$ty as $crate::ffi::SyncBackendPlugin>::cancel_stream(plugin, token);
            })
        }

        // Atomic transaction group.
        // JSON in (`tx_group`), result-envelope JSON out.
        extern "C" fn __mcpg_binding_execute_transaction(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
            tx_group_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let tx_group: ::serde_json::Value = ::serde_json::from_str(tx_group_json.as_str())
                    .unwrap_or(::serde_json::Value::Null);
                let r = <$ty as $crate::ffi::SyncBackendPlugin>::execute_transaction(
                    plugin,
                    backend_name.as_str(),
                    &tx_group,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_binding_input_schema_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::ROption<$crate::abi_stable::std_types::RString> {
            // Schema derivation MUST be infallible — a panic here is
            // a plugin bug (the schema shape is fixed at build time);
            // we `catch_unwind` defensively and return RNone on
            // panic so a buggy plugin doesn't UB across the FFI.
            let result = ::std::panic::catch_unwind(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncBackendPlugin>::input_schema(plugin, backend_name.as_str())
            });
            match result {
                Ok(Some(v)) => $crate::abi_stable::std_types::ROption::RSome(
                    $crate::abi_stable::std_types::RString::from(
                        ::serde_json::to_string(&v).unwrap_or_default(),
                    ),
                ),
                _ => $crate::abi_stable::std_types::ROption::RNone,
            }
        }

        extern "C" fn __mcpg_binding_output_schema_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::ROption<$crate::abi_stable::std_types::RString> {
            let result = ::std::panic::catch_unwind(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncBackendPlugin>::output_schema(
                    plugin,
                    backend_name.as_str(),
                )
            });
            match result {
                Ok(Some(v)) => $crate::abi_stable::std_types::ROption::RSome(
                    $crate::abi_stable::std_types::RString::from(
                        ::serde_json::to_string(&v).unwrap_or_default(),
                    ),
                ),
                _ => $crate::abi_stable::std_types::ROption::RNone,
            }
        }

        extern "C" fn __mcpg_binding_list_resources(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
            cursor: $crate::abi_stable::std_types::ROption<$crate::abi_stable::std_types::RString>,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let cursor_owned = cursor.into_option().map(|r| r.as_str().to_owned());
                let r = <$ty as $crate::ffi::SyncBackendPlugin>::list_resources(
                    plugin,
                    backend_name.as_str(),
                    cursor_owned.as_deref(),
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_binding_shutdown(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncBackendPlugin>::shutdown(plugin);
            })
        }

        // Domain-specific audit fields.
        // Returns a JSON object (empty `{}` on panic / nothing to add).
        extern "C" fn __mcpg_binding_audit_metadata(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            backend_name: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let map = <$ty as $crate::ffi::SyncBackendPlugin>::audit_metadata(
                    plugin,
                    backend_name.as_str(),
                );
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&::serde_json::Value::Object(map))
                        .unwrap_or_else(|_| "{}".to_owned()),
                )
            })
        }

        // Parameterless capability-expansion slot.
        // Output `{"ok": CapabilitySet}` or `{"err": BackendError}`. The
        // default-impl `SyncBackendPlugin::expand_capabilities` returns an
        // empty set, so backends that don't produce capabilities stay wired
        // but inert.
        extern "C" fn __mcpg_binding_expand_capabilities(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let r = <$ty as $crate::ffi::SyncBackendPlugin>::expand_capabilities(plugin);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        // Vtable slot for dynamic
        // resource-template variable completion. JSON envelope:
        // input `{profile_name, variable_name, prefix, config,
        // context}`; output `{"ok": Vec<String>}` or
        // `{"err": BackendError}`. The default-impl
        // `SyncBackendPlugin::complete_template_variable` returns
        // an empty list, so plugins that don't override remain
        // wired but inert.
        extern "C" fn __mcpg_binding_complete_template_variable(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let args: ::serde_json::Value =
                    ::serde_json::from_str(args_json.as_str()).unwrap_or(::serde_json::Value::Null);
                let profile_name = args
                    .get("profile_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let variable_name = args
                    .get("variable_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let prefix = args.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
                let cfg = args
                    .get("config")
                    .cloned()
                    .unwrap_or(::serde_json::Value::Null);
                let context: ::std::collections::BTreeMap<String, String> = args
                    .get("context")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default();
                let r = <$ty as $crate::ffi::SyncBackendPlugin>::complete_template_variable(
                    plugin,
                    profile_name,
                    variable_name,
                    prefix,
                    &cfg,
                    &context,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        /// Build this entity's [`BackendVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::BackendVTable {
            ::mcpg_plugin_protocol::abi::BackendVTable {
                make: __mcpg_binding_make,
                manifest_json: __mcpg_binding_manifest_json,
                kind: __mcpg_binding_kind,
                register_profile: __mcpg_binding_register_profile,
                execute: __mcpg_binding_execute,
                execute_streaming: __mcpg_binding_execute_streaming,
                cancel_stream: __mcpg_binding_cancel_stream,
                execute_transaction: __mcpg_binding_execute_transaction,
                input_schema_json: __mcpg_binding_input_schema_json,
                output_schema_json: __mcpg_binding_output_schema_json,
                complete_template_variable: __mcpg_binding_complete_template_variable,
                list_resources: __mcpg_binding_list_resources,
                audit_metadata: __mcpg_binding_audit_metadata,
                expand_capabilities: __mcpg_binding_expand_capabilities,
                shutdown: __mcpg_binding_shutdown,
                drop_instance: __mcpg_binding_drop,
            }
        }

        /// Build a static `Arc<dyn BackendPlugin>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncBackendPluginAdapter`](crate::adapters::SyncBackendPluginAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::backend::BackendPlugin> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncBackendPluginAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `watch_strategy` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_watch_strategy_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_watch_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_watch_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(handle)
            })
        }

        extern "C" fn __mcpg_watch_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncWatchStrategyPlugin>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_watch_kind(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                $crate::abi_stable::std_types::RString::from(
                    <$ty as $crate::ffi::SyncWatchStrategyPlugin>::kind(plugin),
                )
            })
        }

        extern "C" fn __mcpg_watch_watch(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            uri: $crate::abi_stable::std_types::RString,
            spec_json: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::WatchEventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            // `watch` returns the canonical `StreamHandle`. Structured
            // `WatchError`s flow through `error_json` instead of
            // collapsing to a null pointer.
            ::mcpg_plugin_protocol::abi::catch_panic_to_stream_failure(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let spec: ::serde_json::Value =
                    ::serde_json::from_str(spec_json.as_str()).unwrap_or(::serde_json::Value::Null);

                // Wrap the host's FFI sink into a Rust closure the
                // plugin can call freely. `WatchEventSinkRef` is
                // `Copy`, so capturing by value into the closure is
                // cheap + avoids lifetime issues across threads.
                let emit_event: ::std::boxed::Box<dyn Fn(&str) + Send + Sync + 'static> =
                    ::std::boxed::Box::new(move |event_json: &str| {
                        (sink.callback)(
                            sink.ctx,
                            $crate::abi_stable::std_types::RString::from(event_json),
                        );
                    });

                match <$ty as $crate::ffi::SyncWatchStrategyPlugin>::watch(
                    plugin,
                    uri.as_str(),
                    &spec,
                    emit_event,
                ) {
                    Ok(wh) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: wh.0 as usize,
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            })
        }

        extern "C" fn __mcpg_watch_cancel(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            cancel_token: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncWatchStrategyPlugin>::cancel(
                    plugin,
                    $crate::ffi::WatchHandleBox(cancel_token as *mut ()),
                );
            })
        }

        extern "C" fn __mcpg_watch_shutdown(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncWatchStrategyPlugin>::shutdown(plugin);
            })
        }

        /// Build this entity's [`WatchStrategyVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::WatchStrategyVTable {
            ::mcpg_plugin_protocol::abi::WatchStrategyVTable {
                make: __mcpg_watch_make,
                manifest_json: __mcpg_watch_manifest_json,
                kind: __mcpg_watch_kind,
                watch: __mcpg_watch_watch,
                cancel: __mcpg_watch_cancel,
                shutdown: __mcpg_watch_shutdown,
                drop_instance: __mcpg_watch_drop,
            }
        }

        /// Build a static `Arc<dyn WatchStrategyPlugin>` from the
        /// user's sync `$ty` implementation, wrapped through
        /// [`SyncWatchStrategyAdapter`](crate::adapters::SyncWatchStrategyAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::backend::WatchStrategyPlugin> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncWatchStrategyAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `http_route` vtable wrappers
/// plus `make_vtable()` / `build_static()` accessor fns at the
/// current scope. The unified [`declare_plugin!`]
/// macro can compose multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user crates'
/// `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_http_route_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_http_route_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(
                    config_json.as_str(),
                    host,
                    $factory,
                )
            })
        }

        extern "C" fn __mcpg_http_route_drop(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: handle round-trips through `__mcpg_http_route_make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_http_route_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncHttpRoute>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_http_route_routes_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let routes = <$ty as $crate::ffi::SyncHttpRoute>::routes(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&routes).unwrap_or_else(|_| "[]".into()),
                )
            })
        }

        extern "C" fn __mcpg_http_route_handle(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            request_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let wire: ::mcpg_plugin_protocol::http_route::HttpRouteRequestWire =
                    match ::serde_json::from_str(request_json.as_str()) {
                        Ok(w) => w,
                        Err(e) => {
                            let err = ::mcpg_plugin_protocol::http_route::HttpRouteResponseWire {
                                status: 400,
                                headers: vec![(
                                    "Content-Type".into(),
                                    "application/json".into(),
                                )],
                                body: ::serde_json::to_vec(&::serde_json::json!({
                                    "error": format!("invalid request JSON: {e}"),
                                }))
                                .unwrap_or_default(),
                            };
                            return $crate::abi_stable::std_types::RString::from(
                                ::serde_json::to_string(&err).unwrap_or_default(),
                            );
                        }
                    };
                let req: ::mcpg_plugin_protocol::http_route::HttpRouteRequest = wire.into();
                let resp = <$ty as $crate::ffi::SyncHttpRoute>::handle(plugin, req);
                let wire_resp: ::mcpg_plugin_protocol::http_route::HttpRouteResponseWire =
                    match ::std::convert::TryFrom::try_from(resp) {
                        Ok(w) => w,
                        Err(_) => {
                            // Plugin returned a streaming body; this sync
                            // FFI path doesn't support that. Surface it as a 500.
                            ::mcpg_plugin_protocol::http_route::HttpRouteResponseWire {
                                status: 500,
                                headers: vec![(
                                    "Content-Type".into(),
                                    "application/json".into(),
                                )],
                                body: ::serde_json::to_vec(&::serde_json::json!({
                                    "error": "streaming response bodies are not supported across the FFI boundary",
                                }))
                                .unwrap_or_default(),
                            }
                        }
                    };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&wire_resp).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_http_route_handle_streaming(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            request_json: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
            bytes_sink: ::mcpg_plugin_protocol::abi::BytesSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::HttpHandleResult {
            // The default macro body leaves the bytes
            // sink unused and routes streaming through the text/SSE
            // path (`spawn_http_stream_drain`). Plugins wanting the
            // binary path implement this vtable slot manually and
            // emit via `BytesSinkHandle::from(bytes_sink)`.
            let _ = bytes_sink;
            let result = ::std::panic::catch_unwind(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let wire: ::mcpg_plugin_protocol::http_route::HttpRouteRequestWire =
                    match ::serde_json::from_str(request_json.as_str()) {
                        Ok(w) => w,
                        Err(e) => {
                            let err_resp =
                                ::mcpg_plugin_protocol::http_route::HttpRouteResponseWire {
                                    status: 400,
                                    headers: vec![(
                                        "Content-Type".into(),
                                        "application/json".into(),
                                    )],
                                    body: ::serde_json::to_vec(&::serde_json::json!({
                                        "error": format!("invalid request JSON: {e}"),
                                    }))
                                    .unwrap_or_default(),
                                };
                            return ::mcpg_plugin_protocol::abi::HttpHandleResult {
                                handle: 0,
                                head_json: $crate::abi_stable::std_types::RString::from(
                                    ::serde_json::to_string(&err_resp)
                                        .unwrap_or_default(),
                                ),
                            };
                        }
                    };
                let req: ::mcpg_plugin_protocol::http_route::HttpRouteRequest = wire.into();
                let resp = <$ty as $crate::ffi::SyncHttpRoute>::handle(plugin, req);
                // Bytes path: serialise as HttpRouteResponseWire
                // and return `handle: 0`. Streaming path: delegate
                // to `spawn_http_stream_drain`, which requires
                // the `streaming` feature + a tokio runtime
                // (degrades to a 500 otherwise).
                match resp.body {
                    ::mcpg_plugin_protocol::http_route::HttpBody::Bytes(b) => {
                        let wire = ::mcpg_plugin_protocol::http_route::HttpRouteResponseWire {
                            status: resp.status,
                            headers: resp.headers,
                            body: b.to_vec(),
                        };
                        ::mcpg_plugin_protocol::abi::HttpHandleResult {
                            handle: 0,
                            head_json: $crate::abi_stable::std_types::RString::from(
                                ::serde_json::to_string(&wire).unwrap_or_default(),
                            ),
                        }
                    }
                    ::mcpg_plugin_protocol::http_route::HttpBody::Stream(_) => {
                        $crate::ffi::spawn_http_stream_drain(resp, sink)
                    }
                }
            });
            result.unwrap_or_else(|_| {
                let err_resp = ::mcpg_plugin_protocol::http_route::HttpRouteResponseWire {
                    status: 500,
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: ::serde_json::to_vec(&::serde_json::json!({
                        "error": "plugin panicked during handle_streaming",
                    }))
                    .unwrap_or_default(),
                };
                ::mcpg_plugin_protocol::abi::HttpHandleResult {
                    handle: 0,
                    head_json: $crate::abi_stable::std_types::RString::from(
                        ::serde_json::to_string(&err_resp).unwrap_or_default(),
                    ),
                }
            })
        }

        extern "C" fn __mcpg_http_route_cancel_stream(
            _handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            stream_handle: usize,
        ) {
            // Delegate to the shared helper. When the
            // `streaming` feature is on, aborts the spawned
            // stream-drain task + frees its state. When off,
            // stream_handle is always 0 (bytes-only) and the
            // helper is a no-op.
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                $crate::ffi::cancel_http_stream(stream_handle);
            })
        }

        extern "C" fn __mcpg_http_route_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncHttpRoute>::shutdown(plugin);
            })
        }

        /// Build this entity's [`HttpRouteVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::HttpRouteVTable {
            ::mcpg_plugin_protocol::abi::HttpRouteVTable {
                make: __mcpg_http_route_make,
                manifest_json: __mcpg_http_route_manifest_json,
                routes_json: __mcpg_http_route_routes_json,
                handle: __mcpg_http_route_handle,
                handle_streaming: __mcpg_http_route_handle_streaming,
                cancel_stream: __mcpg_http_route_cancel_stream,
                shutdown: __mcpg_http_route_shutdown,
                drop_instance: __mcpg_http_route_drop,
            }
        }

        /// Build a static `Arc<dyn HttpRoute>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncHttpRouteAdapter`](crate::adapters::SyncHttpRouteAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins. The host's `register_http_route` takes an
        /// `entity_name` string in addition to the plugin — that
        /// argument is owned by the caller (the `declare_plugin!` arm
        /// wires it up from the `plugin_id`).
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::http_route::HttpRoute> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncHttpRouteAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `audit_sink` vtable wrappers
/// plus `make_vtable()` / `build_static()` accessor fns at the
/// current scope. The unified [`declare_plugin!`]
/// macro can compose multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user crates'
/// `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_audit_sink_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_audit_sink_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_audit_sink_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: handle round-trips through `__mcpg_audit_sink_make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_audit_sink_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncAuditSink>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_audit_sink_emit(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            event_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let event: ::mcpg_plugin_protocol::audit::AuditEvent =
                    match ::serde_json::from_str(event_json.as_str()) {
                        Ok(e) => e,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_plugin_protocol::audit::AuditError::WriteFailed {
                                    reason: format!("invalid event JSON: {e}"),
                                },
                            );
                        }
                    };
                let r = <$ty as $crate::ffi::SyncAuditSink>::emit(plugin, &event);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_audit_sink_flush(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            timeout_ms: u64,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let r = <$ty as $crate::ffi::SyncAuditSink>::flush(plugin, timeout_ms);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_audit_sink_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncAuditSink>::shutdown(plugin);
            })
        }

        /// Build this entity's [`AuditSinkVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::AuditSinkVTable {
            ::mcpg_plugin_protocol::abi::AuditSinkVTable {
                make: __mcpg_audit_sink_make,
                manifest_json: __mcpg_audit_sink_manifest_json,
                emit: __mcpg_audit_sink_emit,
                flush: __mcpg_audit_sink_flush,
                shutdown: __mcpg_audit_sink_shutdown,
                drop_instance: __mcpg_audit_sink_drop,
            }
        }

        /// Build a static `Arc<dyn AuditSink>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncAuditSinkAdapter`](crate::adapters::SyncAuditSinkAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::audit::AuditSink> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncAuditSinkAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `log_sink` vtable wrappers
/// plus `make_vtable()` / `build_static()` accessor fns at the
/// current scope. The unified [`declare_plugin!`]
/// macro can compose multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user crates'
/// `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_log_sink_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_log_sink_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_log_sink_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: handle round-trips through `__mcpg_log_sink_make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_log_sink_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncLogSink>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_log_sink_emit(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            record_json: $crate::abi_stable::std_types::RStr<'_>,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let record: ::mcpg_plugin_protocol::logs::LogRecord =
                    match ::serde_json::from_str(record_json.as_str()) {
                        Ok(r) => r,
                        // Best-effort: silently drop malformed records
                        // rather than surface an error. Log sinks are
                        // explicitly infallible on the in-tree trait.
                        Err(_) => return,
                    };
                <$ty as $crate::ffi::SyncLogSink>::emit(plugin, &record);
            })
        }

        extern "C" fn __mcpg_log_sink_flush(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            timeout_ms: u64,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let r = <$ty as $crate::ffi::SyncLogSink>::flush(plugin, timeout_ms);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_log_sink_shutdown(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncLogSink>::shutdown(plugin);
            })
        }

        /// Build this entity's [`LogSinkVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::LogSinkVTable {
            ::mcpg_plugin_protocol::abi::LogSinkVTable {
                make: __mcpg_log_sink_make,
                manifest_json: __mcpg_log_sink_manifest_json,
                emit: __mcpg_log_sink_emit,
                flush: __mcpg_log_sink_flush,
                shutdown: __mcpg_log_sink_shutdown,
                drop_instance: __mcpg_log_sink_drop,
            }
        }

        /// Build a static `Arc<dyn LogSink>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncLogSinkAdapter`](crate::adapters::SyncLogSinkAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::logs::LogSink> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncLogSinkAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `metrics_sink` vtable wrappers
/// plus `make_vtable()` / `build_static()` accessor fns at the
/// current scope. The unified [`declare_plugin!`]
/// macro can compose multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user crates'
/// `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_metrics_sink_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_metrics_sink_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_metrics_sink_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: handle round-trips through `__mcpg_metrics_sink_make`.
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_metrics_sink_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let manifest = <$ty as $crate::ffi::SyncMetricsSink>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(manifest).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_metrics_sink_emit(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            metric_json: $crate::abi_stable::std_types::RString,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let metric: ::mcpg_plugin_protocol::metrics::MetricPoint =
                    match ::serde_json::from_str(metric_json.as_str()) {
                        Ok(m) => m,
                        // Best-effort: silently drop malformed
                        // metrics rather than surface an error.
                        // Metric sinks are explicitly infallible
                        // on the in-tree trait.
                        Err(_) => return,
                    };
                <$ty as $crate::ffi::SyncMetricsSink>::emit(plugin, &metric);
            })
        }

        extern "C" fn __mcpg_metrics_sink_flush(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            timeout_ms: u64,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let r = <$ty as $crate::ffi::SyncMetricsSink>::flush(plugin, timeout_ms);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_metrics_sink_render_text_exposition(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                match <$ty as $crate::ffi::SyncMetricsSink>::render_text_exposition(plugin) {
                    Some(s) => $crate::abi_stable::std_types::RString::from(s),
                    None => $crate::abi_stable::std_types::RString::new(),
                }
            })
        }

        extern "C" fn __mcpg_metrics_sink_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                // SAFETY: per FFI contract.
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncMetricsSink>::shutdown(plugin);
            })
        }

        /// Build this entity's [`MetricsSinkVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::MetricsSinkVTable {
            ::mcpg_plugin_protocol::abi::MetricsSinkVTable {
                make: __mcpg_metrics_sink_make,
                manifest_json: __mcpg_metrics_sink_manifest_json,
                emit: __mcpg_metrics_sink_emit,
                flush: __mcpg_metrics_sink_flush,
                render_text_exposition: __mcpg_metrics_sink_render_text_exposition,
                shutdown: __mcpg_metrics_sink_shutdown,
                drop_instance: __mcpg_metrics_sink_drop,
            }
        }

        /// Build a static `Arc<dyn MetricsSink>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncMetricsSinkAdapter`](crate::adapters::SyncMetricsSinkAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::metrics::MetricsSink> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncMetricsSinkAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `telemetry_sink` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns
/// at the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user crates'
/// `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_telemetry_sink_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_telemetry_sink_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(
                    config_json.as_str(),
                    host,
                    $factory,
                )
            })
        }

        extern "C" fn __mcpg_telemetry_sink_drop(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                unsafe { $crate::ffi::boxed_drop::<$ty>(handle) }
            })
        }

        extern "C" fn __mcpg_telemetry_sink_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let m = <$ty as $crate::ffi::SyncTelemetrySink>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(m).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_telemetry_sink_span_started(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            span_json: $crate::abi_stable::std_types::RString,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                if let Ok(span) = ::serde_json::from_str::<
                    ::mcpg_plugin_protocol::telemetry::SpanStart,
                >(span_json.as_str())
                {
                    <$ty as $crate::ffi::SyncTelemetrySink>::span_started(plugin, &span);
                }
            })
        }

        extern "C" fn __mcpg_telemetry_sink_span_ended(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            span_json: $crate::abi_stable::std_types::RString,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                if let Ok(span) = ::serde_json::from_str::<
                    ::mcpg_plugin_protocol::telemetry::SpanEnd,
                >(span_json.as_str())
                {
                    <$ty as $crate::ffi::SyncTelemetrySink>::span_ended(plugin, &span);
                }
            })
        }

        extern "C" fn __mcpg_telemetry_sink_metric_recorded(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            metric_json: $crate::abi_stable::std_types::RString,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                if let Ok(metric) = ::serde_json::from_str::<
                    ::mcpg_plugin_protocol::telemetry::MetricPoint,
                >(metric_json.as_str())
                {
                    <$ty as $crate::ffi::SyncTelemetrySink>::metric_recorded(plugin, &metric);
                }
            })
        }

        extern "C" fn __mcpg_telemetry_sink_log_recorded(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            record_json: $crate::abi_stable::std_types::RString,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                if let Ok(record) = ::serde_json::from_str::<
                    ::mcpg_plugin_protocol::logs::LogRecord,
                >(record_json.as_str())
                {
                    <$ty as $crate::ffi::SyncTelemetrySink>::log_recorded(plugin, &record);
                }
            })
        }

        extern "C" fn __mcpg_telemetry_sink_flush(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            timeout_ms: u64,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let r = <$ty as $crate::ffi::SyncTelemetrySink>::flush(plugin, timeout_ms);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_telemetry_sink_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncTelemetrySink>::shutdown(plugin);
            })
        }

        /// Build this entity's [`TelemetrySinkVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::TelemetrySinkVTable {
            ::mcpg_plugin_protocol::abi::TelemetrySinkVTable {
                make: __mcpg_telemetry_sink_make,
                manifest_json: __mcpg_telemetry_sink_manifest_json,
                span_started: __mcpg_telemetry_sink_span_started,
                span_ended: __mcpg_telemetry_sink_span_ended,
                metric_recorded: __mcpg_telemetry_sink_metric_recorded,
                log_recorded: __mcpg_telemetry_sink_log_recorded,
                flush: __mcpg_telemetry_sink_flush,
                shutdown: __mcpg_telemetry_sink_shutdown,
                drop_instance: __mcpg_telemetry_sink_drop,
            }
        }

        /// Build a static `Arc<dyn TelemetrySink>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncTelemetrySinkAdapter`](crate::adapters::SyncTelemetrySinkAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::telemetry::TelemetrySink> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncTelemetrySinkAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `store` vtable wrappers plus
/// `make_vtable()` / `build_static()` accessor fns at the current
/// scope. The unified [`declare_plugin!`] macro can compose multiple
/// entities (of any kind) under a single `mcpg_plugin_register`
/// export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_store_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_store_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_store_drop(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(handle)
            })
        }

        extern "C" fn __mcpg_store_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let m = <$ty as $crate::ffi::SyncStorePlugin>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(m).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_store_supported_roles(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let roles = <$ty as $crate::ffi::SyncStorePlugin>::supported_roles(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&roles).unwrap_or_else(|_| "[]".into()),
                )
            })
        }

        fn __mcpg_store_err_to_wire(
            err: ::mcpg_plugin_protocol::store::StoreError,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(&err)
        }

        fn __mcpg_store_ok_to_wire<T: ::serde::Serialize>(
            value: T,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::result_envelope::respond_ok_rstring(&value)
        }

        extern "C" fn __mcpg_store_get(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    key: String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_store_err_to_wire(
                            ::mcpg_plugin_protocol::store::StoreError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncStorePlugin>::get(plugin, &args.role, &args.key) {
                    Ok(opt) => __mcpg_store_ok_to_wire(opt),
                    Err(e) => __mcpg_store_err_to_wire(e),
                }
            })
        }

        extern "C" fn __mcpg_store_put(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    key: String,
                    value: ::mcpg_plugin_protocol::store::StoreValueWire,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                            &::mcpg_plugin_protocol::store::StoreError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                let r = <$ty as $crate::ffi::SyncStorePlugin>::put(
                    plugin, &args.role, &args.key, args.value,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_store_delete(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    key: String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                            &::mcpg_plugin_protocol::store::StoreError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                let r =
                    <$ty as $crate::ffi::SyncStorePlugin>::delete(plugin, &args.role, &args.key);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_store_list(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    prefix: String,
                    #[serde(default)]
                    cursor: Option<String>,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_store_err_to_wire(
                            ::mcpg_plugin_protocol::store::StoreError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncStorePlugin>::list(
                    plugin,
                    &args.role,
                    &args.prefix,
                    args.cursor,
                ) {
                    Ok(page) => __mcpg_store_ok_to_wire(page),
                    Err(e) => __mcpg_store_err_to_wire(e),
                }
            })
        }

        extern "C" fn __mcpg_store_cas(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    key: String,
                    #[serde(default)]
                    expected: Option<::mcpg_plugin_protocol::store::StoreValueWire>,
                    new: ::mcpg_plugin_protocol::store::StoreValueWire,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_store_err_to_wire(
                            ::mcpg_plugin_protocol::store::StoreError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncStorePlugin>::compare_and_swap(
                    plugin,
                    &args.role,
                    &args.key,
                    args.expected,
                    args.new,
                ) {
                    Ok(ok) => __mcpg_store_ok_to_wire(ok),
                    Err(e) => __mcpg_store_err_to_wire(e),
                }
            })
        }

        extern "C" fn __mcpg_store_append(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    key: String,
                    value: ::mcpg_plugin_protocol::store::StoreValueWire,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_store_err_to_wire(
                            ::mcpg_plugin_protocol::store::StoreError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncStorePlugin>::append(
                    plugin, &args.role, &args.key, args.value,
                ) {
                    Ok(r) => __mcpg_store_ok_to_wire(r),
                    Err(e) => __mcpg_store_err_to_wire(e),
                }
            })
        }

        extern "C" fn __mcpg_store_watch(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            let result = ::std::panic::catch_unwind(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: ::mcpg_plugin_protocol::store::StoreRole,
                    key: String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::abi::StreamHandle {
                            handle: 0,
                            error_json: $crate::abi_stable::std_types::RString::from(
                                ::serde_json::to_string(
                                    &::mcpg_plugin_protocol::store::StoreError::Backend {
                                        reason: format!("invalid watch args: {e}"),
                                    },
                                )
                                .unwrap_or_default(),
                            ),
                            metadata_json: $crate::abi_stable::std_types::RString::new(),
                        };
                    }
                };
                // Wrap the FFI sink in a plugin-side closure that
                // takes a JSON &str and forwards to the host.
                let emit: Box<dyn Fn(&str) + Send + Sync + 'static> = Box::new(move |s: &str| {
                    (sink.callback)(sink.ctx, $crate::abi_stable::std_types::RString::from(s));
                });
                match <$ty as $crate::ffi::SyncStorePlugin>::watch(
                    plugin, &args.role, &args.key, emit,
                ) {
                    Ok(watch_box) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: watch_box.0 as usize,
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            });
            result.unwrap_or_else(|_| ::mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&::mcpg_plugin_protocol::store::StoreError::Backend {
                        reason: "plugin panicked during watch".into(),
                    })
                    .unwrap_or_default(),
                ),
                metadata_json: $crate::abi_stable::std_types::RString::new(),
            })
        }

        extern "C" fn __mcpg_store_cancel_watch(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            watch_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncStorePlugin>::cancel_watch(
                    plugin,
                    $crate::ffi::WatchHandleBox(watch_handle as *mut ()),
                );
            })
        }

        extern "C" fn __mcpg_store_shutdown(handle: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncStorePlugin>::shutdown(plugin);
            })
        }

        /// Build this entity's [`StoreVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::StoreVTable {
            ::mcpg_plugin_protocol::abi::StoreVTable {
                make: __mcpg_store_make,
                manifest_json: __mcpg_store_manifest_json,
                supported_roles_json: __mcpg_store_supported_roles,
                get: __mcpg_store_get,
                put: __mcpg_store_put,
                delete: __mcpg_store_delete,
                list: __mcpg_store_list,
                compare_and_swap: __mcpg_store_cas,
                append: __mcpg_store_append,
                watch: __mcpg_store_watch,
                cancel_watch: __mcpg_store_cancel_watch,
                shutdown: __mcpg_store_shutdown,
                drop_instance: __mcpg_store_drop,
            }
        }

        /// Build a static `Arc<dyn Store>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncStorePluginAdapter`](crate::adapters::SyncStorePluginAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::store::Store> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncStorePluginAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `cache` vtable wrappers plus
/// `make_vtable()` / `build_static()` accessor fns at the current
/// scope. The unified [`declare_plugin!`] macro can compose multiple
/// entities (of any kind) under a single `mcpg_plugin_register`
/// export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_cache_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_cache_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // Construct the unified `HostHandle`
            // from the FFI ref the host passed in, and hand it to the
            // user factory as the 2nd arg so plugins can call
            // `host.audit_event(...)` / `metric_emit` / `resolve_secret`
            // / `cluster()` etc. inside their request handlers.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the
            // plugin handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(
                    config_json.as_str(),
                    host,
                    $factory,
                )
            })
        }

        extern "C" fn __mcpg_cache_drop(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(handle)
            })
        }

        extern "C" fn __mcpg_cache_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let m = <$ty as $crate::ffi::SyncCachePlugin>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(m).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_cache_supported_namespaces(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let ns = <$ty as $crate::ffi::SyncCachePlugin>::supported_namespaces(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&ns).unwrap_or_else(|_| "[]".into()),
                )
            })
        }

        extern "C" fn __mcpg_cache_serves_any(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> u8 {
            let result = ::std::panic::catch_unwind(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncCachePlugin>::serves_any_namespace(plugin)
            });
            match result {
                Ok(true) => 1,
                _ => 0,
            }
        }

        extern "C" fn __mcpg_cache_get(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    ns: String,
                    key: String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(_) => {
                        // Malformed → miss.
                        return $crate::abi_stable::std_types::RString::from("null");
                    }
                };
                let opt = <$ty as $crate::ffi::SyncCachePlugin>::get(
                    plugin, &args.ns, &args.key,
                );
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&opt).unwrap_or_else(|_| "null".into()),
                )
            })
        }

        extern "C" fn __mcpg_cache_put(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    ns: String,
                    key: String,
                    value: Vec<u8>,
                    ttl_ms: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                            &::mcpg_plugin_protocol::cache::CacheError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                let r = <$ty as $crate::ffi::SyncCachePlugin>::put(
                    plugin, &args.ns, &args.key, args.value, args.ttl_ms,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cache_delete(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    ns: String,
                    key: String,
                }
                if let Ok(args) = ::serde_json::from_str::<Args>(args_json.as_str()) {
                    <$ty as $crate::ffi::SyncCachePlugin>::delete(
                        plugin, &args.ns, &args.key,
                    );
                }
            })
        }

        extern "C" fn __mcpg_cache_clear(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    ns: String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                            &::mcpg_plugin_protocol::cache::CacheError::Backend {
                                reason: format!("invalid args: {e}"),
                            },
                        );
                    }
                };
                let r = <$ty as $crate::ffi::SyncCachePlugin>::clear(plugin, &args.ns);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cache_incr(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    ns: String,
                    key: String,
                    by: i64,
                    ttl_ms: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&::serde_json::json!({
                                "err": ::mcpg_plugin_protocol::cache::CacheError::Backend {
                                    reason: format!("invalid args: {e}"),
                                }
                            }))
                            .unwrap_or_default(),
                        );
                    }
                };
                let r = <$ty as $crate::ffi::SyncCachePlugin>::incr(
                    plugin, &args.ns, &args.key, args.by, args.ttl_ms,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cache_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncCachePlugin>::shutdown(plugin);
            })
        }

        /// Build this entity's [`CacheVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::CacheVTable {
            ::mcpg_plugin_protocol::abi::CacheVTable {
                make: __mcpg_cache_make,
                manifest_json: __mcpg_cache_manifest_json,
                supported_namespaces_json: __mcpg_cache_supported_namespaces,
                serves_any_namespace: __mcpg_cache_serves_any,
                get: __mcpg_cache_get,
                put: __mcpg_cache_put,
                delete: __mcpg_cache_delete,
                clear: __mcpg_cache_clear,
                incr: __mcpg_cache_incr,
                shutdown: __mcpg_cache_shutdown,
                drop_instance: __mcpg_cache_drop,
            }
        }

        /// Build a static `Arc<dyn Cache>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncCachePluginAdapter`](crate::adapters::SyncCachePluginAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::cache::Cache> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncCachePluginAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `secret_provider` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_secret_provider_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_secret_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_secret_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_secret_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncSecretProvider>::manifest(p))
                        .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_secret_supported(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let s = <$ty as $crate::ffi::SyncSecretProvider>::supported_schemes(p);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&s).unwrap_or_else(|_| "[]".into()),
                )
            })
        }
        extern "C" fn __mcpg_secret_get(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            reference: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let r = <$ty as $crate::ffi::SyncSecretProvider>::get(p, reference.as_str());
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }
        extern "C" fn __mcpg_secret_watch(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            reference: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let emit: Box<dyn Fn(&str) + Send + Sync + 'static> = Box::new(move |s: &str| {
                    (sink.callback)(sink.ctx, $crate::abi_stable::std_types::RString::from(s));
                });
                match <$ty as $crate::ffi::SyncSecretProvider>::watch(p, reference.as_str(), emit) {
                    Ok(h) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: h.0 as usize,
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            });
            result.unwrap_or_else(|_| ::mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(
                        &::mcpg_plugin_protocol::secret::SecretError::Backend {
                            reason: "plugin panicked during watch".into(),
                        },
                    )
                    .unwrap_or_default(),
                ),
                metadata_json: $crate::abi_stable::std_types::RString::new(),
            })
        }
        extern "C" fn __mcpg_secret_cancel_watch(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            watch_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncSecretProvider>::cancel_watch(
                    p,
                    $crate::ffi::WatchHandleBox(watch_handle as *mut ()),
                );
            })
        }
        extern "C" fn __mcpg_secret_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncSecretProvider>::shutdown(p);
            })
        }

        /// Build this entity's [`SecretProviderVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::SecretProviderVTable {
            ::mcpg_plugin_protocol::abi::SecretProviderVTable {
                make: __mcpg_secret_make,
                manifest_json: __mcpg_secret_manifest,
                supported_schemes_json: __mcpg_secret_supported,
                get: __mcpg_secret_get,
                watch: __mcpg_secret_watch,
                cancel_watch: __mcpg_secret_cancel_watch,
                shutdown: __mcpg_secret_shutdown,
                drop_instance: __mcpg_secret_drop,
            }
        }

        /// Build a static `Arc<dyn SecretProvider>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncSecretProviderAdapter`](crate::adapters::SyncSecretProviderAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::secret::SecretProvider> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncSecretProviderAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `config_provider` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_config_provider_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_config_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_config_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_config_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncConfigProvider>::manifest(p))
                        .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_config_supported(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let s = <$ty as $crate::ffi::SyncConfigProvider>::supported_schemes(p);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&s).unwrap_or_else(|_| "[]".into()),
                )
            })
        }
        extern "C" fn __mcpg_config_snapshot(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            reference: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let r = <$ty as $crate::ffi::SyncConfigProvider>::snapshot(p, reference.as_str());
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }
        extern "C" fn __mcpg_config_watch(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            reference: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let emit: Box<dyn Fn(&str) + Send + Sync + 'static> = Box::new(move |s: &str| {
                    (sink.callback)(sink.ctx, $crate::abi_stable::std_types::RString::from(s));
                });
                match <$ty as $crate::ffi::SyncConfigProvider>::watch(p, reference.as_str(), emit) {
                    Ok(h) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: h.0 as usize,
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            });
            result.unwrap_or_else(|_| ::mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(
                        &::mcpg_plugin_protocol::config::ConfigError::Backend {
                            reason: "plugin panicked during watch".into(),
                        },
                    )
                    .unwrap_or_default(),
                ),
                metadata_json: $crate::abi_stable::std_types::RString::new(),
            })
        }
        extern "C" fn __mcpg_config_cancel_watch(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            watch_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncConfigProvider>::cancel_watch(
                    p,
                    $crate::ffi::WatchHandleBox(watch_handle as *mut ()),
                );
            })
        }
        extern "C" fn __mcpg_config_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncConfigProvider>::shutdown(p);
            })
        }

        /// Build this entity's [`ConfigProviderVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::ConfigProviderVTable {
            ::mcpg_plugin_protocol::abi::ConfigProviderVTable {
                make: __mcpg_config_make,
                manifest_json: __mcpg_config_manifest,
                supported_schemes_json: __mcpg_config_supported,
                snapshot: __mcpg_config_snapshot,
                watch: __mcpg_config_watch,
                cancel_watch: __mcpg_config_cancel_watch,
                shutdown: __mcpg_config_shutdown,
                drop_instance: __mcpg_config_drop,
            }
        }

        /// Build a static `Arc<dyn ConfigProvider>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncConfigProviderAdapter`](crate::adapters::SyncConfigProviderAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::config::ConfigProvider> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncConfigProviderAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `policy_engine` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_policy_engine_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        // `make` takes `(host: HostHandleRef, config_json, inner_name)`.
        // The unified `HostHandle` is the 2nd arg and policy engines reach
        // cluster via `host.cluster()`. Engines that don't care about
        // cluster ignore the host arg.
        extern "C" fn __mcpg_policy_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_policy_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_policy_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncPolicyEngine>::manifest(p))
                        .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_policy_name(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    <$ty as $crate::ffi::SyncPolicyEngine>::name(p),
                )
            })
        }
        extern "C" fn __mcpg_policy_evaluate(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    decision_point: String,
                    input: ::serde_json::Value,
                    context: ::mcpg_plugin_protocol::PluginContext,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(_) => {
                        // Malformed input surfaces as Deny.
                        return $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(
                                &::mcpg_plugin_protocol::policy::PolicyDecision::deny(
                                    "malformed policy input",
                                    "",
                                ),
                            )
                            .unwrap_or_default(),
                        );
                    }
                };
                let decision = <$ty as $crate::ffi::SyncPolicyEngine>::evaluate(
                    p,
                    &args.decision_point,
                    &args.input,
                    &args.context,
                );
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&decision).unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_policy_version(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let v = <$ty as $crate::ffi::SyncPolicyEngine>::policy_version(p);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&v).unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_policy_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncPolicyEngine>::shutdown(p);
            })
        }

        /// Build this entity's [`PolicyEngineVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::PolicyEngineVTable {
            ::mcpg_plugin_protocol::abi::PolicyEngineVTable {
                make: __mcpg_policy_make,
                manifest_json: __mcpg_policy_manifest,
                name: __mcpg_policy_name,
                evaluate: __mcpg_policy_evaluate,
                policy_version: __mcpg_policy_version,
                shutdown: __mcpg_policy_shutdown,
                drop_instance: __mcpg_policy_drop,
            }
        }

        /// Build a static `Arc<dyn PolicyEngine>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncPolicyEngineAdapter`](crate::adapters::SyncPolicyEngineAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins. The caller hands a `HostHandle` and policy engines
        /// that need cluster derive it via `host.cluster()`.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::policy::PolicyEngine> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncPolicyEngineAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `approval_notifier` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_approval_notifier_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_appr_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_appr_drop(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_appr_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(
                        <$ty as $crate::ffi::SyncApprovalNotifier>::manifest(p),
                    )
                    .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_appr_notify(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            request_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let req: ::mcpg_plugin_protocol::approval_notifier::NotificationRequest =
                    match ::serde_json::from_str(request_json.as_str()) {
                        Ok(r) => r,
                        Err(_) => {
                            let err: Result<
                                ::mcpg_plugin_protocol::approval_notifier::NotificationResult,
                                ::mcpg_plugin_protocol::approval_notifier::NotificationError,
                            > = Err(
                                ::mcpg_plugin_protocol::approval_notifier::NotificationError::Internal {
                                    reason: "malformed notification request json".into(),
                                },
                            );
                            return $crate::abi_stable::std_types::RString::from(
                                ::serde_json::to_string(&err).unwrap_or_default(),
                            );
                        }
                    };
                let result =
                    <$ty as $crate::ffi::SyncApprovalNotifier>::notify(p, &req);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&result).unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_appr_shutdown(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncApprovalNotifier>::shutdown(p);
            })
        }

        /// Build this entity's [`ApprovalNotifierVTable`]. The
        /// caller's `mcpg_plugin_register` invokes this once per
        /// entity to keep the per-entity wrappers private to the
        /// sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::ApprovalNotifierVTable {
            ::mcpg_plugin_protocol::abi::ApprovalNotifierVTable {
                make: __mcpg_appr_make,
                manifest_json: __mcpg_appr_manifest,
                notify: __mcpg_appr_notify,
                shutdown: __mcpg_appr_shutdown,
                drop_instance: __mcpg_appr_drop,
            }
        }

        /// Build a static `Arc<dyn ApprovalNotifier>` from the
        /// user's sync `$ty` implementation, wrapped through
        /// [`SyncApprovalNotifierAdapter`](crate::adapters::SyncApprovalNotifierAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::approval_notifier::ApprovalNotifier> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncApprovalNotifierAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `credential_issuer` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_credential_issuer_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_credential_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_credential_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_credential_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncCredentialIssuer>::manifest(
                        p,
                    ))
                    .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_credential_issue(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    identity: ::mcpg_plugin_protocol::types::PluginIdentity,
                    target: String,
                    config: ::serde_json::Value,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(_) => {
                        let err: Result<
                            ::mcpg_plugin_protocol::credential::IssuedCredential,
                            ::mcpg_plugin_protocol::credential::CredentialError,
                        > = Err(
                            ::mcpg_plugin_protocol::credential::CredentialError::Backend {
                                reason: "malformed args json".into(),
                            },
                        );
                        return $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&err).unwrap_or_default(),
                        );
                    }
                };
                let result = <$ty as $crate::ffi::SyncCredentialIssuer>::issue(
                    p,
                    &args.identity,
                    &args.target,
                    &args.config,
                );
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&result).unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_credential_revoke(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            lease_id: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let r = <$ty as $crate::ffi::SyncCredentialIssuer>::revoke(p, lease_id.as_str());
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }
        extern "C" fn __mcpg_credential_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncCredentialIssuer>::shutdown(p);
            })
        }

        /// Build this entity's [`CredentialIssuerVTable`]. The
        /// caller's `mcpg_plugin_register` invokes this once per
        /// entity to keep the per-entity wrappers private to the
        /// sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::CredentialIssuerVTable {
            ::mcpg_plugin_protocol::abi::CredentialIssuerVTable {
                make: __mcpg_credential_make,
                manifest_json: __mcpg_credential_manifest,
                issue: __mcpg_credential_issue,
                revoke: __mcpg_credential_revoke,
                shutdown: __mcpg_credential_shutdown,
                drop_instance: __mcpg_credential_drop,
            }
        }

        /// Build a static `Arc<dyn CredentialIssuer>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncCredentialIssuerAdapter`](crate::adapters::SyncCredentialIssuerAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::credential::CredentialIssuer> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncCredentialIssuerAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `catalog_provider` vtable
/// wrappers plus `make_vtable()` / `build_static()` accessor fns at
/// the current scope. The unified [`declare_plugin!`] macro
/// composes multiple entities (of any kind) under a single
/// `mcpg_plugin_register` export.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out
/// of rustdoc and `#[macro_export]` makes it callable from user
/// crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_catalog_provider_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_catalog_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_catalog_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_catalog_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncCatalogProvider>::manifest(p))
                        .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_catalog_filter_and_enrich(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    ctx: ::mcpg_plugin_protocol::PluginContext,
                    in_progress: Vec<::mcpg_plugin_protocol::catalog::EnrichedToolDescriptor>,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(_) => {
                        // Malformed input — return empty (fail-closed).
                        return $crate::abi_stable::std_types::RString::from("[]");
                    }
                };
                let refined = <$ty as $crate::ffi::SyncCatalogProvider>::filter_and_enrich(
                    p,
                    &args.ctx,
                    &args.in_progress,
                );
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&refined).unwrap_or_else(|_| "[]".into()),
                )
            })
        }
        extern "C" fn __mcpg_catalog_describe(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            tool_id: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let entry =
                    <$ty as $crate::ffi::SyncCatalogProvider>::describe(p, tool_id.as_str());
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&entry).unwrap_or_else(|_| "null".into()),
                )
            })
        }
        extern "C" fn __mcpg_catalog_list_catalog(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let entries = <$ty as $crate::ffi::SyncCatalogProvider>::list_catalog(p);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into()),
                )
            })
        }
        extern "C" fn __mcpg_catalog_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncCatalogProvider>::shutdown(p);
            })
        }

        /// Build this entity's [`CatalogProviderVTable`]. The
        /// caller's `mcpg_plugin_register` invokes this once per
        /// entity to keep the per-entity wrappers private to the
        /// sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::CatalogProviderVTable {
            ::mcpg_plugin_protocol::abi::CatalogProviderVTable {
                make: __mcpg_catalog_make,
                manifest_json: __mcpg_catalog_manifest,
                filter_and_enrich: __mcpg_catalog_filter_and_enrich,
                describe: __mcpg_catalog_describe,
                list_catalog: __mcpg_catalog_list_catalog,
                shutdown: __mcpg_catalog_shutdown,
                drop_instance: __mcpg_catalog_drop,
            }
        }

        /// Build a `Box<dyn CatalogProvider>` from the user's sync
        /// `$ty` implementation, wrapped through
        /// [`SyncCatalogProviderAdapter`](crate::adapters::SyncCatalogProviderAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins. The caller (`declare_plugin!` arm) supplies the
        /// `config: serde_json::Value` arg when calling
        /// `register_catalog_provider*` on the host registry.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::boxed::Box<dyn ::mcpg_plugin_protocol::catalog::CatalogProvider> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::boxed::Box::new($crate::adapters::SyncCatalogProviderAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `content_store` vtable wrappers
/// plus `make_vtable()` / `build_static()` accessors at the current
/// scope. The unified [`declare_plugin!`] macro composes multiple
/// entities (of any kind) under a single `mcpg_plugin_register` export.
///
/// `content_store` is a factory-with-profiles kind (like `backend`): one
/// plugin instance manages N named profiles. The FFI calling convention
/// matches the `store` kind — every per-call slot carries a single JSON
/// `args` envelope with `profile_name` inside — so the wrappers
/// deserialize a small `Args` struct per slot and marshal the typed
/// result through the `{"ok"|"err"}` envelope helpers. `stats` and
/// `sweep_expired` return bare JSON (a `ContentStoreStats` object and a
/// number, respectively) per [`ContentStoreVTable`](mcpg_plugin_protocol::abi::ContentStoreVTable).
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it out of
/// rustdoc and `#[macro_export]` makes it callable from user crates'
/// `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_content_store_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_content_store_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            config_json: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for the
            // HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot; the host's bridge outlives the handle.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(config_json.as_str(), host, $factory)
            })
        }

        extern "C" fn __mcpg_content_store_drop(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(handle)
            })
        }

        extern "C" fn __mcpg_content_store_manifest_json(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                let m = <$ty as $crate::ffi::SyncContentStore>::manifest(plugin);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(m).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_content_store_kind(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                $crate::abi_stable::std_types::RString::from(
                    <$ty as $crate::ffi::SyncContentStore>::kind(plugin),
                )
            })
        }

        // Shared: a malformed `args` envelope becomes a typed `Storage`
        // error in the `{"err"}` envelope (the enveloped slots) so the
        // host adapter surfaces a real `ContentStoreError` rather than an
        // empty string.
        fn __mcpg_content_store_bad_args(
            e: ::serde_json::Error,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                &::mcpg_plugin_protocol::content_store::ContentStoreError::Storage {
                    message: ::std::format!("invalid args: {e}"),
                },
            )
        }

        extern "C" fn __mcpg_content_store_register_profile(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                    spec: ::serde_json::Value,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => return __mcpg_content_store_bad_args(e),
                };
                let r = <$ty as $crate::ffi::SyncContentStore>::register_profile(
                    plugin,
                    &args.profile_name,
                    &args.spec,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_content_store_put(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                    content: ::mcpg_plugin_protocol::content_store::ContentToStore,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => return __mcpg_content_store_bad_args(e),
                };
                let r = <$ty as $crate::ffi::SyncContentStore>::put(
                    plugin,
                    &args.profile_name,
                    args.content,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_content_store_get(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                    id: ::std::string::String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => return __mcpg_content_store_bad_args(e),
                };
                let r = <$ty as $crate::ffi::SyncContentStore>::get(
                    plugin,
                    &args.profile_name,
                    &args.id,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_content_store_delete(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                    id: ::std::string::String,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => return __mcpg_content_store_bad_args(e),
                };
                let r = <$ty as $crate::ffi::SyncContentStore>::delete(
                    plugin,
                    &args.profile_name,
                    &args.id,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_content_store_signed_url(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                    id: ::std::string::String,
                    ttl_seconds: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => return __mcpg_content_store_bad_args(e),
                };
                let r = <$ty as $crate::ffi::SyncContentStore>::signed_url(
                    plugin,
                    &args.profile_name,
                    &args.id,
                    ::std::time::Duration::from_secs(args.ttl_seconds),
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_content_store_stats(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                }
                // `stats` returns a bare `ContentStoreStats` (no envelope);
                // a bad-args read degrades to the zeroed default snapshot.
                let stats = match ::serde_json::from_str::<Args>(args_json.as_str()) {
                    Ok(a) => <$ty as $crate::ffi::SyncContentStore>::stats(plugin, &a.profile_name),
                    Err(_) => ::mcpg_plugin_protocol::content_store::ContentStoreStats::default(),
                };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&stats).unwrap_or_default(),
                )
            })
        }

        extern "C" fn __mcpg_content_store_sweep_expired(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    profile_name: ::std::string::String,
                }
                // Bare number output; bad args sweep nothing.
                let removed = match ::serde_json::from_str::<Args>(args_json.as_str()) {
                    Ok(a) => <$ty as $crate::ffi::SyncContentStore>::sweep_expired(
                        plugin,
                        &a.profile_name,
                    ),
                    Err(_) => 0,
                };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&removed).unwrap_or_else(|_| "0".into()),
                )
            })
        }

        extern "C" fn __mcpg_content_store_shutdown(
            handle: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let plugin: &$ty = unsafe { $crate::ffi::typed_handle(handle) };
                <$ty as $crate::ffi::SyncContentStore>::shutdown(plugin);
            })
        }

        /// Build this entity's [`ContentStoreVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to keep
        /// the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::ContentStoreVTable {
            ::mcpg_plugin_protocol::abi::ContentStoreVTable {
                make: __mcpg_content_store_make,
                manifest_json: __mcpg_content_store_manifest_json,
                kind: __mcpg_content_store_kind,
                register_profile: __mcpg_content_store_register_profile,
                put: __mcpg_content_store_put,
                get: __mcpg_content_store_get,
                delete: __mcpg_content_store_delete,
                signed_url: __mcpg_content_store_signed_url,
                stats: __mcpg_content_store_stats,
                sweep_expired: __mcpg_content_store_sweep_expired,
                shutdown: __mcpg_content_store_shutdown,
                drop_instance: __mcpg_content_store_drop,
            }
        }

        /// Build a static `Arc<dyn ContentStorePlugin>` from the user's
        /// sync `$ty` implementation, wrapped through
        /// [`SyncContentStoreAdapter`](crate::adapters::SyncContentStoreAdapter).
        /// The unified `register_static` wrapper calls this once per
        /// entity to avoid going through the FFI vtable for in-process
        /// plugins.
        #[cfg(feature = "static-firstparty")]
        pub fn build_static(
            config_json: &str,
            host: $crate::HostHandle,
        ) -> ::std::sync::Arc<dyn ::mcpg_plugin_protocol::content_store::ContentStorePlugin> {
            let factory = $factory;
            let inner: $ty = factory(config_json, host);
            ::std::sync::Arc::new($crate::adapters::SyncContentStoreAdapter::new(inner))
        }
    };
}

/// Internal helper — emit per-entity `cluster_backend` vtable
/// wrappers plus a `make_vtable()` accessor at the current scope.
/// The unified [`declare_plugin!`] macro composes multiple
/// entities (of any kind) under a single `mcpg_plugin_register`
/// export by invoking this helper once per declared entity.
///
/// Static-firstparty path: **omitted**. `FirstPartyRegistrar` has
/// no `register_cluster_backend` method today, so the helper
/// emits only the cdylib vtable wrappers + `make_vtable()`. The
/// absence of `build_static` cleanly signals to the
/// `register_static` dispatch arm that the static path is
/// cdylib-only for this kind until a follow-up lifts the
/// restriction.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it
/// out of rustdoc and `#[macro_export]` makes it callable from
/// user crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_cluster_backend_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_cluster_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_cluster_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_cluster_manifest(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncClusterBackend>::manifest(p))
                        .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_cluster_node_info(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let info = <$ty as $crate::ffi::SyncClusterBackend>::node_info(p);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&info).unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_cluster_list_peers(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let peers = <$ty as $crate::ffi::SyncClusterBackend>::list_peers(p);
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&peers).unwrap_or_else(|_| "[]".into()),
                )
            })
        }
        extern "C" fn __mcpg_cluster_publish(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    topic: String,
                    #[serde(default)]
                    routing_key: Option<String>,
                    payload: Vec<u8>,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                            &::mcpg_cluster_api::ClusterError::InvalidReference {
                                message: format!("malformed publish args: {e}"),
                            },
                        );
                    }
                };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::publish(
                    p,
                    &args.topic,
                    args.routing_key.as_deref(),
                    args.payload,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }
        extern "C" fn __mcpg_cluster_subscribe(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    topic: String,
                    #[serde(default)]
                    group: Option<String>,
                    #[serde(default)]
                    routing_key: Option<String>,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return ::mcpg_plugin_protocol::abi::StreamHandle {
                            handle: 0,
                            error_json: $crate::abi_stable::std_types::RString::from(
                                ::serde_json::to_string(
                                    &::mcpg_cluster_api::ClusterError::InvalidReference {
                                        message: format!("malformed subscribe args: {e}"),
                                    },
                                )
                                .unwrap_or_default(),
                            ),
                            metadata_json: $crate::abi_stable::std_types::RString::new(),
                        };
                    }
                };
                let emit: Box<dyn Fn(&str) + Send + Sync + 'static> = Box::new(move |s: &str| {
                    (sink.callback)(sink.ctx, $crate::abi_stable::std_types::RString::from(s));
                });
                match <$ty as $crate::ffi::SyncClusterBackend>::subscribe(
                    p,
                    &args.topic,
                    args.group.as_deref(),
                    args.routing_key.as_deref(),
                    emit,
                ) {
                    Ok(hbox) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: hbox.0 as usize,
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            });
            result.unwrap_or_else(|_| ::mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&::mcpg_cluster_api::ClusterError::Internal {
                        reason: "plugin panicked during subscribe".into(),
                    })
                    .unwrap_or_default(),
                ),
                metadata_json: $crate::abi_stable::std_types::RString::new(),
            })
        }

        extern "C" fn __mcpg_cluster_watch_peers(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            sink: ::mcpg_plugin_protocol::abi::EventSinkRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let emit: Box<dyn Fn(&str) + Send + Sync + 'static> = Box::new(move |s: &str| {
                    (sink.callback)(sink.ctx, $crate::abi_stable::std_types::RString::from(s));
                });
                match <$ty as $crate::ffi::SyncClusterBackend>::watch_peers(p, emit) {
                    Ok(hbox) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: hbox.0 as usize,
                        error_json: $crate::abi_stable::std_types::RString::new(),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => ::mcpg_plugin_protocol::abi::StreamHandle {
                        handle: 0,
                        error_json: $crate::abi_stable::std_types::RString::from(
                            ::serde_json::to_string(&e).unwrap_or_default(),
                        ),
                        metadata_json: $crate::abi_stable::std_types::RString::new(),
                    },
                }
            });
            result.unwrap_or_else(|_| ::mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&::mcpg_cluster_api::ClusterError::Internal {
                        reason: "plugin panicked during watch_peers".into(),
                    })
                    .unwrap_or_default(),
                ),
                metadata_json: $crate::abi_stable::std_types::RString::new(),
            })
        }

        extern "C" fn __mcpg_cluster_cancel_stream(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            stream_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncClusterBackend>::cancel_stream(
                    p,
                    $crate::ffi::WatchHandleBox(stream_handle as *mut ()),
                );
            })
        }

        fn __mcpg_cluster_lease_acquire_err(
            err: ::mcpg_cluster_api::ClusterError,
        ) -> ::mcpg_plugin_protocol::abi::LeaseHandle {
            ::mcpg_plugin_protocol::abi::LeaseHandle {
                handle: 0,
                fencing_token: 0,
                expires_at: $crate::abi_stable::std_types::RString::new(),
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&err).unwrap_or_default(),
                ),
            }
        }

        extern "C" fn __mcpg_cluster_acquire_leadership(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::LeaseHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: String,
                    ttl_ms: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_cluster_lease_acquire_err(
                            ::mcpg_cluster_api::ClusterError::InvalidReference {
                                message: format!("malformed acquire args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncClusterBackend>::acquire_leadership(
                    p,
                    &args.role,
                    args.ttl_ms,
                ) {
                    Ok((hbox, token, expires)) => ::mcpg_plugin_protocol::abi::LeaseHandle {
                        handle: hbox.0 as usize,
                        fencing_token: token,
                        expires_at: $crate::abi_stable::std_types::RString::from(expires),
                        error_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => __mcpg_cluster_lease_acquire_err(e),
                }
            });
            result.unwrap_or_else(|_| {
                __mcpg_cluster_lease_acquire_err(::mcpg_cluster_api::ClusterError::Internal {
                    reason: "plugin panicked during acquire_leadership".into(),
                })
            })
        }

        extern "C" fn __mcpg_cluster_acquire_lock(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::LeaseHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    key: String,
                    ttl_ms: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_cluster_lease_acquire_err(
                            ::mcpg_cluster_api::ClusterError::InvalidReference {
                                message: format!("malformed acquire args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncClusterBackend>::acquire_lock(
                    p,
                    &args.key,
                    args.ttl_ms,
                ) {
                    Ok((hbox, token, expires)) => ::mcpg_plugin_protocol::abi::LeaseHandle {
                        handle: hbox.0 as usize,
                        fencing_token: token,
                        expires_at: $crate::abi_stable::std_types::RString::from(expires),
                        error_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => __mcpg_cluster_lease_acquire_err(e),
                }
            });
            result.unwrap_or_else(|_| {
                __mcpg_cluster_lease_acquire_err(::mcpg_cluster_api::ClusterError::Internal {
                    reason: "plugin panicked during acquire_lock".into(),
                })
            })
        }

        // try-variants. Return convention:
        //   handle != 0                              → acquired
        //   handle == 0 && error_json.is_empty()     → declined
        //   handle == 0 && !error_json.is_empty()    → JSON ClusterError
        extern "C" fn __mcpg_cluster_try_acquire_leadership(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::LeaseHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    role: String,
                    ttl_ms: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_cluster_lease_acquire_err(
                            ::mcpg_cluster_api::ClusterError::InvalidReference {
                                message: format!("malformed acquire args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncClusterBackend>::try_acquire_leadership(
                    p,
                    &args.role,
                    args.ttl_ms,
                ) {
                    Ok(Some((hbox, token, expires))) => ::mcpg_plugin_protocol::abi::LeaseHandle {
                        handle: hbox.0 as usize,
                        fencing_token: token,
                        expires_at: $crate::abi_stable::std_types::RString::from(expires),
                        error_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Ok(None) => ::mcpg_plugin_protocol::abi::LeaseHandle {
                        handle: 0,
                        fencing_token: 0,
                        expires_at: $crate::abi_stable::std_types::RString::new(),
                        error_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => __mcpg_cluster_lease_acquire_err(e),
                }
            });
            result.unwrap_or_else(|_| {
                __mcpg_cluster_lease_acquire_err(::mcpg_cluster_api::ClusterError::Internal {
                    reason: "plugin panicked during try_acquire_leadership".into(),
                })
            })
        }

        extern "C" fn __mcpg_cluster_try_acquire_lock(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::LeaseHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                #[derive(::serde::Deserialize)]
                struct Args {
                    key: String,
                    ttl_ms: u64,
                }
                let args: Args = match ::serde_json::from_str(args_json.as_str()) {
                    Ok(a) => a,
                    Err(e) => {
                        return __mcpg_cluster_lease_acquire_err(
                            ::mcpg_cluster_api::ClusterError::InvalidReference {
                                message: format!("malformed acquire args: {e}"),
                            },
                        );
                    }
                };
                match <$ty as $crate::ffi::SyncClusterBackend>::try_acquire_lock(
                    p,
                    &args.key,
                    args.ttl_ms,
                ) {
                    Ok(Some((hbox, token, expires))) => ::mcpg_plugin_protocol::abi::LeaseHandle {
                        handle: hbox.0 as usize,
                        fencing_token: token,
                        expires_at: $crate::abi_stable::std_types::RString::from(expires),
                        error_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Ok(None) => ::mcpg_plugin_protocol::abi::LeaseHandle {
                        handle: 0,
                        fencing_token: 0,
                        expires_at: $crate::abi_stable::std_types::RString::new(),
                        error_json: $crate::abi_stable::std_types::RString::new(),
                    },
                    Err(e) => __mcpg_cluster_lease_acquire_err(e),
                }
            });
            result.unwrap_or_else(|_| {
                __mcpg_cluster_lease_acquire_err(::mcpg_cluster_api::ClusterError::Internal {
                    reason: "plugin panicked during try_acquire_lock".into(),
                })
            })
        }

        extern "C" fn __mcpg_cluster_lease_renew(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            lease_handle: usize,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::lease_renew(
                    p,
                    $crate::ffi::WatchHandleBox(lease_handle as *mut ()),
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_lease_release(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            lease_handle: usize,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::lease_release(
                    p,
                    $crate::ffi::WatchHandleBox(lease_handle as *mut ()),
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_lease_drop(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            lease_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncClusterBackend>::lease_drop(
                    p,
                    $crate::ffi::WatchHandleBox(lease_handle as *mut ()),
                );
            })
        }

        extern "C" fn __mcpg_cluster_kv_get(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let args: ::mcpg_cluster_api::KvKeyArgs =
                    match ::serde_json::from_str(args_json.as_str()) {
                        Ok(a) => a,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_cluster_api::ClusterError::InvalidReference {
                                    message: format!("malformed kv_get args: {e}"),
                                },
                            );
                        }
                    };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::kv_get(p, &args.key).map(|opt| {
                    opt.map(|entry| ::mcpg_cluster_api::KvEntryWire::from_entry(&entry))
                });
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_kv_put(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let args: ::mcpg_cluster_api::KvPutArgs =
                    match ::serde_json::from_str(args_json.as_str()) {
                        Ok(a) => a,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_cluster_api::ClusterError::InvalidReference {
                                    message: format!("malformed kv_put args: {e}"),
                                },
                            );
                        }
                    };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::kv_put(
                    p,
                    &args.key,
                    args.value,
                    args.ttl_ms,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_kv_put_if_absent(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let args: ::mcpg_cluster_api::KvPutArgs =
                    match ::serde_json::from_str(args_json.as_str()) {
                        Ok(a) => a,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_cluster_api::ClusterError::InvalidReference {
                                    message: format!("malformed kv_put_if_absent args: {e}"),
                                },
                            );
                        }
                    };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::kv_put_if_absent(
                    p,
                    &args.key,
                    args.value,
                    args.ttl_ms,
                );
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_kv_delete(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let args: ::mcpg_cluster_api::KvKeyArgs =
                    match ::serde_json::from_str(args_json.as_str()) {
                        Ok(a) => a,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_cluster_api::ClusterError::InvalidReference {
                                    message: format!("malformed kv_delete args: {e}"),
                                },
                            );
                        }
                    };
                let r = <$ty as $crate::ffi::SyncClusterBackend>::kv_delete(p, &args.key);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_kv_list_prefix(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let args: ::mcpg_cluster_api::KvListPrefixArgs =
                    match ::serde_json::from_str(args_json.as_str()) {
                        Ok(a) => a,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_cluster_api::ClusterError::InvalidReference {
                                    message: format!("malformed kv_list_prefix args: {e}"),
                                },
                            );
                        }
                    };
                let limit = usize::try_from(args.limit).unwrap_or(usize::MAX);
                let r = <$ty as $crate::ffi::SyncClusterBackend>::kv_list_prefix(
                    p,
                    &args.prefix,
                    limit,
                )
                .map(|pairs| {
                    pairs
                        .into_iter()
                        .map(|(key, entry)| ::mcpg_cluster_api::KvListEntryWire {
                            key,
                            entry: ::mcpg_cluster_api::KvEntryWire::from_entry(&entry),
                        })
                        .collect::<Vec<_>>()
                });
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_kv_expire(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            args_json: $crate::abi_stable::std_types::RString,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let args: ::mcpg_cluster_api::KvExpireArgs =
                    match ::serde_json::from_str(args_json.as_str()) {
                        Ok(a) => a,
                        Err(e) => {
                            return ::mcpg_plugin_protocol::result_envelope::respond_err_rstring(
                                &::mcpg_cluster_api::ClusterError::InvalidReference {
                                    message: format!("malformed kv_expire args: {e}"),
                                },
                            );
                        }
                    };
                let r =
                    <$ty as $crate::ffi::SyncClusterBackend>::kv_expire(p, &args.key, args.ttl_ms);
                ::mcpg_plugin_protocol::result_envelope::respond_result_rstring(&r)
            })
        }

        extern "C" fn __mcpg_cluster_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncClusterBackend>::shutdown(p);
            })
        }

        /// Build this entity's [`ClusterVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::ClusterVTable {
            ::mcpg_plugin_protocol::abi::ClusterVTable {
                make: __mcpg_cluster_make,
                manifest_json: __mcpg_cluster_manifest,
                node_info: __mcpg_cluster_node_info,
                list_peers: __mcpg_cluster_list_peers,
                publish: __mcpg_cluster_publish,
                subscribe: __mcpg_cluster_subscribe,
                watch_peers: __mcpg_cluster_watch_peers,
                cancel_stream: __mcpg_cluster_cancel_stream,
                acquire_leadership: __mcpg_cluster_acquire_leadership,
                acquire_lock: __mcpg_cluster_acquire_lock,
                try_acquire_leadership: __mcpg_cluster_try_acquire_leadership,
                try_acquire_lock: __mcpg_cluster_try_acquire_lock,
                lease_renew: __mcpg_cluster_lease_renew,
                lease_release: __mcpg_cluster_lease_release,
                lease_drop: __mcpg_cluster_lease_drop,
                kv_get: __mcpg_cluster_kv_get,
                kv_put: __mcpg_cluster_kv_put,
                kv_put_if_absent: __mcpg_cluster_kv_put_if_absent,
                kv_delete: __mcpg_cluster_kv_delete,
                kv_list_prefix: __mcpg_cluster_kv_list_prefix,
                kv_expire: __mcpg_cluster_kv_expire,
                shutdown: __mcpg_cluster_shutdown,
                drop_instance: __mcpg_cluster_drop,
            }
        }

        // NOTE: `build_static` is intentionally omitted for
        // `cluster_backend`. The static-firstparty path is
        // cdylib-only for this kind today — `FirstPartyRegistrar`
        // has no `register_cluster_backend` method, so
        // `declare_plugin!`'s `register_static` dispatch arm
        // refuses to compile for `cluster_backend` entries. A
        // follow-up can add `build_static` here without
        // touching call-sites.
    };
}

/// Internal helper — emit per-entity `transport` vtable wrappers
/// plus a `make_vtable()` accessor at the current scope. The
/// unified [`declare_plugin!`] macro composes multiple entities
/// (of any kind) under a single `mcpg_plugin_register` export by
/// invoking this helper once per declared entity.
///
/// Static-firstparty path: **omitted**. `FirstPartyRegistrar` has
/// no `register_transport` method today, so the helper emits only
/// the cdylib vtable wrappers + `make_vtable()`. The absence of
/// `build_static` cleanly signals to the `register_static`
/// dispatch arm that the static path is cdylib-only for this kind
/// until a follow-up lifts the restriction.
///
/// Not part of the SDK's public API — `#[doc(hidden)]` keeps it
/// out of rustdoc and `#[macro_export]` makes it callable from
/// user crates' `declare_plugin!` expansions.
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_decl_transport_entity {
    (
        plugin_type: $ty:ty,
        factory: $factory:expr $(,)?
    ) => {
        extern "C" fn __mcpg_transport_make(
            host: ::mcpg_plugin_protocol::abi::HostHandleRef,
            cfg: $crate::abi_stable::std_types::RString,
            _inner_name: $crate::abi_stable::std_types::RString,
        ) -> ::mcpg_plugin_protocol::abi::RPluginHandle {
            // See __mcpg_decl_tool_gate_entity for
            // the HostHandle construction rationale.
            //
            // SAFETY: `host` is the live `HostHandleRef` the host passed
            // to this `make` slot.
            let host = unsafe { $crate::HostHandle::from_ffi(host) };
            ::mcpg_plugin_protocol::abi::catch_panic_to_null_handle(|| {
                $crate::ffi::boxed_make_with_host::<$ty, _>(cfg.as_str(), host, $factory)
            })
        }
        extern "C" fn __mcpg_transport_drop(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| unsafe {
                $crate::ffi::boxed_drop::<$ty>(h)
            })
        }
        extern "C" fn __mcpg_transport_manifest_json(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(<$ty as $crate::ffi::SyncTransport>::manifest(p))
                        .unwrap_or_default(),
                )
            })
        }
        extern "C" fn __mcpg_transport_name(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                $crate::abi_stable::std_types::RString::from(
                    <$ty as $crate::ffi::SyncTransport>::name(p),
                )
            })
        }

        fn __mcpg_transport_start_err(
            err: ::mcpg_plugin_protocol::transport::TransportError,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            ::mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: $crate::abi_stable::std_types::RString::from(
                    ::serde_json::to_string(&err).unwrap_or_default(),
                ),
                metadata_json: $crate::abi_stable::std_types::RString::new(),
            }
        }

        extern "C" fn __mcpg_transport_start(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            listener_config_json: $crate::abi_stable::std_types::RString,
            dispatcher_cb: ::mcpg_plugin_protocol::abi::DispatcherCallbackRef,
        ) -> ::mcpg_plugin_protocol::abi::StreamHandle {
            let result = ::std::panic::catch_unwind(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let listener_config: ::serde_json::Value =
                    match ::serde_json::from_str(listener_config_json.as_str()) {
                        Ok(v) => v,
                        Err(e) => {
                            return __mcpg_transport_start_err(
                                ::mcpg_plugin_protocol::transport::TransportError::InvalidConfig {
                                    message: format!("listener_config not JSON: {e}"),
                                },
                            );
                        }
                    };
                let dispatcher = $crate::ffi::dispatcher_from_cb(dispatcher_cb);
                match <$ty as $crate::ffi::SyncTransport>::start(p, &listener_config, dispatcher) {
                    Ok(h) => {
                        // Transports use the canonical `StreamHandle`
                        // shape; the listen address (when present) lives in
                        // `metadata_json` as `{"listen_address":"..."}`.
                        let metadata_json = match h.listen_address {
                            Some(addr) if !addr.is_empty() => {
                                $crate::abi_stable::std_types::RString::from(
                                    ::serde_json::to_string(
                                        &::serde_json::json!({"listen_address": addr}),
                                    )
                                    .unwrap_or_default(),
                                )
                            }
                            _ => $crate::abi_stable::std_types::RString::new(),
                        };
                        ::mcpg_plugin_protocol::abi::StreamHandle {
                            handle: h.handle as usize,
                            error_json: $crate::abi_stable::std_types::RString::new(),
                            metadata_json,
                        }
                    }
                    Err(e) => __mcpg_transport_start_err(e),
                }
            });
            result.unwrap_or_else(|_| {
                __mcpg_transport_start_err(::mcpg_plugin_protocol::transport::TransportError::Io {
                    reason: "plugin panicked during start".into(),
                })
            })
        }

        extern "C" fn __mcpg_transport_handle_close(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            transport_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncTransport>::transport_handle_close(
                    p,
                    $crate::ffi::WatchHandleBox(transport_handle as *mut ()),
                );
            })
        }

        extern "C" fn __mcpg_transport_handle_drop(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            transport_handle: usize,
        ) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncTransport>::transport_handle_drop(
                    p,
                    $crate::ffi::WatchHandleBox(transport_handle as *mut ()),
                );
            })
        }

        extern "C" fn __mcpg_transport_handle_listen_address(
            h: ::mcpg_plugin_protocol::abi::RPluginHandle,
            transport_handle: usize,
        ) -> $crate::abi_stable::std_types::RString {
            ::mcpg_plugin_protocol::abi::catch_panic_to_empty_rstring(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                let addr = <$ty as $crate::ffi::SyncTransport>::transport_handle_listen_address(
                    p,
                    $crate::ffi::WatchHandleBox(transport_handle as *mut ()),
                );
                $crate::abi_stable::std_types::RString::from(addr.unwrap_or_default())
            })
        }

        extern "C" fn __mcpg_transport_shutdown(h: ::mcpg_plugin_protocol::abi::RPluginHandle) {
            ::mcpg_plugin_protocol::abi::catch_panic_silent(|| {
                let p: &$ty = unsafe { $crate::ffi::typed_handle(h) };
                <$ty as $crate::ffi::SyncTransport>::shutdown(p);
            })
        }

        /// Build this entity's [`TransportVTable`]. The caller's
        /// `mcpg_plugin_register` invokes this once per entity to
        /// keep the per-entity wrappers private to the sub-module.
        #[inline]
        pub fn make_vtable() -> ::mcpg_plugin_protocol::abi::TransportVTable {
            ::mcpg_plugin_protocol::abi::TransportVTable {
                make: __mcpg_transport_make,
                manifest_json: __mcpg_transport_manifest_json,
                name: __mcpg_transport_name,
                start: __mcpg_transport_start,
                transport_handle_close: __mcpg_transport_handle_close,
                transport_handle_drop: __mcpg_transport_handle_drop,
                transport_handle_listen_address: __mcpg_transport_handle_listen_address,
                shutdown: __mcpg_transport_shutdown,
                drop_instance: __mcpg_transport_drop,
            }
        }

        // NOTE: `build_static` is intentionally omitted for
        // `transport`. The static-firstparty path is cdylib-only
        // for this kind today — `FirstPartyRegistrar` has no
        // `register_transport` method and `declare_plugin!` has no
        // `transport` arm. A follow-up can add `build_static`
        // here without touching call-sites.
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch helpers used by the unified mixed-kind
// `declare_plugin!` arm.
//
// `macro_rules!` cannot branch on an `:ident` at expansion time, so the
// unified arm dispatches each entity by re-parsing the kind keyword through
// these three helpers. Each helper has one arm per supported kind that
// expands to the kind-specific code; misuse falls through to a `compile_error!`
// guard with a precise message.
//
// All three are `#[macro_export] #[doc(hidden)]` — invokable from user
// crates' `declare_plugin!` expansions but kept out of rustdoc.
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch to the appropriate `__mcpg_decl_<kind>_entity!` helper for a
/// single entity. Emits the per-entity vtable wrappers + `make_vtable()` +
/// `build_static()` at the current scope (typically a `pub mod $mod_name`
/// generated by `declare_plugin!`).
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_dispatch_entity_module {
    (tool_gate, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_tool_gate_entity! { plugin_type: $ty, factory: $factory, }
    };
    (transform, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_transform_entity! { plugin_type: $ty, factory: $factory, }
    };
    (identity, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_identity_entity! { plugin_type: $ty, factory: $factory, }
    };
    (backend, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_backend_entity! { plugin_type: $ty, factory: $factory, }
    };
    (watch_strategy, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_watch_strategy_entity! { plugin_type: $ty, factory: $factory, }
    };
    (http_route, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_http_route_entity! { plugin_type: $ty, factory: $factory, }
    };
    (audit_sink, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_audit_sink_entity! { plugin_type: $ty, factory: $factory, }
    };
    (log_sink, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_log_sink_entity! { plugin_type: $ty, factory: $factory, }
    };
    (metrics_sink, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_metrics_sink_entity! { plugin_type: $ty, factory: $factory, }
    };
    (telemetry_sink, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_telemetry_sink_entity! { plugin_type: $ty, factory: $factory, }
    };
    (store, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_store_entity! { plugin_type: $ty, factory: $factory, }
    };
    (cache, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_cache_entity! { plugin_type: $ty, factory: $factory, }
    };
    (secret_provider, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_secret_provider_entity! { plugin_type: $ty, factory: $factory, }
    };
    (config_provider, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_config_provider_entity! { plugin_type: $ty, factory: $factory, }
    };
    (policy_engine, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_policy_engine_entity! { plugin_type: $ty, factory: $factory, }
    };
    (approval_notifier, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_approval_notifier_entity! { plugin_type: $ty, factory: $factory, }
    };
    (credential_issuer, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_credential_issuer_entity! { plugin_type: $ty, factory: $factory, }
    };
    (catalog_provider, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_catalog_provider_entity! { plugin_type: $ty, factory: $factory, }
    };
    (content_store, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_content_store_entity! { plugin_type: $ty, factory: $factory, }
    };
    (cluster_backend, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_cluster_backend_entity! { plugin_type: $ty, factory: $factory, }
    };
    (transport, plugin_type: $ty:ty, factory: $factory:expr $(,)?) => {
        $crate::__mcpg_decl_transport_entity! { plugin_type: $ty, factory: $factory, }
    };
    ($other:ident, $($rest:tt)*) => {
        ::std::compile_error!(::std::concat!(
            "declare_plugin!: unknown entity kind `",
            ::std::stringify!($other),
            "`. Supported kinds: tool_gate, transform, identity, backend, \
             watch_strategy, http_route, audit_sink, log_sink, metrics_sink, \
             telemetry_sink, store, cache, secret_provider, config_provider, \
             policy_engine, approval_notifier, credential_issuer, \
             catalog_provider, content_store, cluster_backend, transport."
        ));
    };
}

/// Emit one `EntityRegistration::<Variant>` literal for the cdylib path's
/// per-entity push into the `entities: RVec<...>` vec. `$mod` is the
/// per-entity sub-module generated by `declare_plugin!` (which holds the
/// `make_vtable()` accessor emitted by `__mcpg_dispatch_entity_module!`).
#[macro_export]
#[doc(hidden)]
macro_rules! __mcpg_dispatch_entity_registration {
    (tool_gate, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::ToolGate {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (transform, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::Transform {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (identity, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::IdentityProvider {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (backend, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::Backend {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (watch_strategy, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::WatchStrategy {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (http_route, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::HttpRoute {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (audit_sink, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::AuditSink {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (log_sink, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::LogSink {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (metrics_sink, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::MetricsSink {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (telemetry_sink, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::TelemetrySink {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (store, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::Store {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (cache, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::Cache {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (secret_provider, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::SecretProvider {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (config_provider, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::ConfigProvider {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (policy_engine, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::PolicyEngine {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (approval_notifier, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::ApprovalNotifier {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (credential_issuer, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::CredentialIssuer {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (catalog_provider, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::CatalogProvider {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (content_store, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::ContentStore {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (cluster_backend, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::Cluster {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    (transport, $mod:ident, $inner:expr) => {
        ::mcpg_plugin_protocol::abi::EntityRegistration::Transport {
            inner_name: $crate::abi_stable::std_types::RString::from($inner),
            vtable: $mod::make_vtable(),
        }
    };
    ($other:ident, $mod:ident, $inner:expr) => {
        ::std::compile_error!(::std::concat!(
            "declare_plugin!: unknown entity kind `",
            ::std::stringify!($other),
            "` in cdylib registration dispatch."
        ));
    };
}

/// Emit the per-entity body of the unified `register_static()` function.
/// Each arm wraps the user's sync type through the matching
/// `Sync*Adapter` (via the per-entity helper's `build_static`), and calls
/// the alias-aware registrar method directly. Multi-instance plugins pass
/// a non-empty `$inner` to register multiple entities of the same kind
/// from one plugin source under distinct aliases.
///
/// `cluster_backend` and `transport` have no `FirstPartyRegistrar`
/// counterpart today, so misuse of those kinds in a `declare_plugin!`
/// invocation surfaces as a precise `compile_error!` instead of a
/// cryptic missing-method diagnostic at expansion time.
#[macro_export]
#[doc(hidden)]
#[cfg(feature = "static-firstparty")]
macro_rules! __mcpg_dispatch_register_static {
    (tool_gate, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_tool_gate_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
            ::serde_json::json!({}),
            true,
        )?
    }};
    (transform, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_transform_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
            ::serde_json::json!({}),
        )?
    }};
    (identity, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        // Identity factory is 2-arg `(&str, HostHandle) -> T`. Cluster
        // access is via `host.cluster()`.
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_identity_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
            ::serde_json::json!({}),
        )?
    }};
    (backend, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_backend_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (watch_strategy, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_watch_strategy_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (http_route, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        // http_route uniquely needs a non-empty `entity_name` for the
        // axum mount path. Single-entity plugins reuse the plugin_id;
        // multi-entity plugins pass distinct `inner_name`s and the
        // alias defaults to "{plugin_id}:{inner_name}".
        let (alias, entity_name): (
            ::std::option::Option<::std::string::String>,
            ::std::string::String,
        ) = if inner_name_str.is_empty() {
            (None, ::std::string::String::from($id))
        } else {
            (
                Some(::std::format!("{}:{}", $id, inner_name_str)),
                ::std::string::String::from(inner_name_str),
            )
        };
        let plugin = $mod::build_static("", $host.clone());
        // Static-firstparty mounts are always namespaced (default
        // overrides → no path override), so no capability is required.
        $registry.register_http_route_with_alias_and_overrides(
            alias,
            entity_name,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
            $crate::plugin_host::HttpRouteOverrides::default(),
            &[],
        )?
    }};
    (audit_sink, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_audit_sink_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (log_sink, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_log_sink_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (metrics_sink, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_metrics_sink_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (telemetry_sink, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_telemetry_sink_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (store, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_store_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (cache, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_cache_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (secret_provider, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_secret_provider_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (config_provider, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_config_provider_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (policy_engine, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        // Policy_engine factory is 2-arg `(&str, HostHandle) -> T`.
        // Cluster access via `host.cluster()`.
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_policy_engine_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (approval_notifier, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_approval_notifier_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (credential_issuer, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_credential_issuer_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (catalog_provider, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_catalog_provider_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
            ::serde_json::json!({}),
        )?
    }};
    (content_store, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {{
        let inner_name_str: &str = $inner;
        let alias: ::std::option::Option<::std::string::String> = if inner_name_str.is_empty() {
            None
        } else {
            Some(::std::format!("{}:{}", $id, inner_name_str))
        };
        let plugin = $mod::build_static("", $host.clone());
        $registry.register_content_store_with_alias(
            alias,
            plugin,
            ::mcpg_plugin_protocol::PluginTier::Native,
        )?
    }};
    (cluster_backend, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {
        ::std::compile_error!(
            "declare_plugin!: `cluster_backend` static-firstparty registration \
             is not supported. FirstPartyRegistrar has no \
             `register_cluster_backend_with_alias` slot today — use the cdylib \
             path (omit static-firstparty feature) for cluster_backend plugins \
             until a static slot is added."
        )
    };
    (transport, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {
        ::std::compile_error!(
            "declare_plugin!: `transport` static-firstparty registration is not \
             supported. FirstPartyRegistrar has no `register_transport_with_alias` \
             slot today — use the cdylib path (omit static-firstparty feature) for \
             transport plugins until a static slot is added."
        )
    };
    ($other:ident, $mod:ident, $inner:expr, $id:expr, $registry:ident, $host:ident) => {
        ::std::compile_error!(::std::concat!(
            "declare_plugin!: unknown entity kind `",
            ::std::stringify!($other),
            "` in static-firstparty registration dispatch."
        ));
    };
}
