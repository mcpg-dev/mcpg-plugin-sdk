//! Plugin project templates for scaffolding.
//!
//! Library helpers for author-side scaffolding tools. Not invoked by
//! `mcpg-plugin`, which is scoped to artifact file management. The
//! plugin-authoring scaffold flow (plugin-author-owned) may consume
//! these helpers.

/// Template definitions for plugin scaffolding.
#[derive(Debug, Clone)]
pub struct PluginTemplate {
    /// Template name (e.g., "tool-gate", "transform", "identity").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Plugin class.
    pub plugin_class: &'static str,
    /// Generated files: (relative_path, content).
    pub files: Vec<(String, String)>,
}

impl PluginTemplate {
    /// Get the tool-gate plugin template.
    pub fn tool_gate(plugin_name: &str, plugin_id: &str) -> Self {
        let crate_name = plugin_name.replace('-', "_");
        Self {
            name: "tool-gate".into(),
            description: "A tool-gate plugin that can allow, deny, or challenge tool calls".into(),
            plugin_class: "ToolGate",
            files: vec![
                ("Cargo.toml".into(), cargo_toml(plugin_name, "Tool gate")),
                ("src/lib.rs".into(), tool_gate_lib(&crate_name, plugin_id)),
                ("README.md".into(), readme(plugin_name, "tool gate")),
            ],
        }
    }

    /// Get the transform plugin template.
    pub fn transform(plugin_name: &str, plugin_id: &str) -> Self {
        let crate_name = plugin_name.replace('-', "_");
        Self {
            name: "transform".into(),
            description: "A transform plugin that can rewrite tool arguments and results".into(),
            plugin_class: "Transform",
            files: vec![
                ("Cargo.toml".into(), cargo_toml(plugin_name, "Transform")),
                ("src/lib.rs".into(), transform_lib(&crate_name, plugin_id)),
                ("README.md".into(), readme(plugin_name, "transform")),
            ],
        }
    }

    /// Get the identity plugin template.
    pub fn identity(plugin_name: &str, plugin_id: &str) -> Self {
        let crate_name = plugin_name.replace('-', "_");
        Self {
            name: "identity".into(),
            description: "An identity plugin that resolves caller identity from request headers"
                .into(),
            plugin_class: "IdentityProvider",
            files: vec![
                ("Cargo.toml".into(), cargo_toml(plugin_name, "Identity")),
                ("src/lib.rs".into(), identity_lib(&crate_name, plugin_id)),
                ("README.md".into(), readme(plugin_name, "identity")),
            ],
        }
    }

    /// List all available templates.
    pub fn list() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "tool-gate",
                "Pre/post-dispatch gating (payment, rate-limit, approval)",
            ),
            (
                "transform",
                "Argument/result rewriting (PII masking, schema migration)",
            ),
            (
                "identity",
                "Identity resolution from request headers (JWT, API key)",
            ),
        ]
    }
}

fn cargo_toml(name: &str, kind: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
description = "{kind} plugin for MCPG"

[dependencies]
mcpg-plugin-protocol = {{ version = "0.1" }}
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"

[dev-dependencies]
mcpg-plugin-sdk = {{ version = "0.1" }}
"#
    )
}

fn tool_gate_lib(crate_name: &str, plugin_id: &str) -> String {
    format!(
        r#"use mcpg_plugin_protocol::{{
    GateDecision, PluginClass, PluginContext, PluginManifest,
    ToolGatePlugin, PROTOCOL_VERSION,
}};

pub struct {struct_name};

impl ToolGatePlugin for {struct_name} {{
    fn manifest(&self) -> &PluginManifest {{
        &PluginManifest {{
            license: None,
            id: "{plugin_id}".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "{struct_name}".into(),
            plugin_class: PluginClass::ToolGate,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            required_capabilities: vec![],
            tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!().split("::").next().unwrap_or("").to_owned(),
        }}
    }}

    fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        meta: Option<&serde_json::Value>,
        config: &serde_json::Value,
    ) -> GateDecision {{
        // TODO: Implement your pre-dispatch logic here.
        //
        // Return GateDecision::allow() to let the call proceed.
        // Return GateDecision::Deny {{ .. }} to block it.
        // Return GateDecision::Challenge {{ .. }} to require additional input.
        GateDecision::allow()
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use mcpg_plugin_sdk::testing::{{MockGateway, ToolCallResultAssertions}};

    #[test]
    fn allows_by_default() {{
        let gw = MockGateway::new()
            .with_tool_gate(Box::new({struct_name}));
        let result = gw.call_tool("any_tool", serde_json::json!({{}}));
        result.assert_allowed();
    }}
}}
"#,
        struct_name = to_pascal_case(crate_name),
    )
}

fn transform_lib(crate_name: &str, plugin_id: &str) -> String {
    format!(
        r#"use mcpg_plugin_protocol::{{
    PluginClass, PluginContext, PluginManifest,
    TransformPlugin, TransformResult,
}};

pub struct {struct_name};

impl TransformPlugin for {struct_name} {{
    fn manifest(&self) -> &PluginManifest {{
        &PluginManifest {{
            license: None,
            id: "{plugin_id}".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "{struct_name}".into(),
            plugin_class: PluginClass::Transform,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            required_capabilities: vec![],
            tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!().split("::").next().unwrap_or("").to_owned(),
        }}
    }}

    fn transform_arguments(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult {{
        // TODO: Implement argument transformation here.
        TransformResult::Unchanged
    }}

    fn transform_result(
        &self,
        ctx: &PluginContext,
        result: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult {{
        // TODO: Implement result transformation here.
        TransformResult::Unchanged
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use mcpg_plugin_sdk::testing::{{MockGateway, ToolCallResultAssertions}};

    #[test]
    fn passes_through_unchanged() {{
        let gw = MockGateway::new()
            .with_transform(Box::new({struct_name}));
        let result = gw.call_tool("any_tool", serde_json::json!({{"key": "value"}}));
        result.assert_allowed();
        assert_eq!(result.arguments["key"], "value");
    }}
}}
"#,
        struct_name = to_pascal_case(crate_name),
    )
}

fn identity_lib(crate_name: &str, plugin_id: &str) -> String {
    format!(
        r#"use mcpg_plugin_protocol::{{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity,
    PluginManifest,
}};

pub struct {struct_name};

impl IdentityProviderPlugin for {struct_name} {{
    fn manifest(&self) -> &PluginManifest {{
        &PluginManifest {{
            license: None,
            id: "{plugin_id}".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "{struct_name}".into(),
            plugin_class: PluginClass::IdentityProvider,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            required_capabilities: vec![],
            tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!().split("::").next().unwrap_or("").to_owned(),
        }}
    }}

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        config: &serde_json::Value,
    ) -> IdentityResolution {{
        // TODO: Extract and verify identity from headers (and
        // optionally `metadata`, e.g. metadata.tls for native
        // mTLS plugins). Return IdentityResolution::Resolved(..).
        IdentityResolution::None
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn returns_no_token_for_empty_headers() {{
        let plugin = {struct_name};
        let result = plugin.resolve_identity(
            &[],
            &mcpg_plugin_protocol::types::RequestMetadata::default(),
            &serde_json::json!({{}}),
        );
        assert!(matches!(result, IdentityResolution::None));
    }}
}}
"#,
        struct_name = to_pascal_case(crate_name),
    )
}

fn readme(name: &str, kind: &str) -> String {
    format!(
        r#"# {name}

A {kind} plugin for MCPG.

## Development

```bash
# Run tests
cargo test

# Run with mock gateway harness
cargo test -- --nocapture
```

## Configuration

```yaml
plugins:
  - id: com.example.{name_dotted}
    kind: native
    source:
      path: /opt/mcpg/plugins/lib{name_underscored}.so
    config: {{}}
```
"#,
        name_dotted = name.replace('-', "."),
        name_underscored = name.replace('-', "_"),
    )
}

/// Convert snake_case or kebab-case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split(['_', '-'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let upper: String = first.to_uppercase().collect();
                    upper + chars.as_str()
                }
                None => String::new(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_pascal_case_works() {
        assert_eq!(to_pascal_case("my_rate_limiter"), "MyRateLimiter");
        assert_eq!(to_pascal_case("my-rate-limiter"), "MyRateLimiter");
        assert_eq!(to_pascal_case("simple"), "Simple");
        assert_eq!(to_pascal_case(""), "");
    }

    #[test]
    fn tool_gate_template_generates_valid_files() {
        let template = PluginTemplate::tool_gate("my-gate", "com.example.gate");
        assert_eq!(template.files.len(), 3);
        assert_eq!(template.files[0].0, "Cargo.toml");
        assert!(template.files[0].1.contains("my-gate"));
        assert_eq!(template.files[1].0, "src/lib.rs");
        assert!(template.files[1].1.contains("MyGate"));
        assert!(template.files[1].1.contains("com.example.gate"));
    }

    #[test]
    fn transform_template_generates_valid_files() {
        let template = PluginTemplate::transform("pii-masker", "com.example.pii");
        assert_eq!(template.files.len(), 3);
        assert!(template.files[1].1.contains("PiiMasker"));
        assert!(template.files[1].1.contains("TransformPlugin"));
    }

    #[test]
    fn identity_template_generates_valid_files() {
        let template = PluginTemplate::identity("jwt-verifier", "com.example.jwt");
        assert_eq!(template.files.len(), 3);
        assert!(template.files[1].1.contains("JwtVerifier"));
        assert!(template.files[1].1.contains("IdentityProviderPlugin"));
    }

    #[test]
    fn list_templates() {
        let templates = PluginTemplate::list();
        assert_eq!(templates.len(), 3);
    }
}
