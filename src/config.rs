//! Config-parsing conventions for plugin authors (SDK-default
//! conventions).
//!
//! [`fail_closed_config!`](crate::fail_closed_config) /
//! [`parse_config_or_fail_closed`] make the SECURE behaviour the EASY
//! default. The historical idiom
//!
//! ```ignore
//! let config: MyConfig = serde_json::from_str(config_json).unwrap_or_default();
//! ```
//!
//! fails **OPEN**: a typo'd or schema-violating operator `config:` block
//! silently degrades to defaults, so a security plugin can boot wide
//! open. The convention here fails **CLOSED** — a present-but-malformed
//! config refuses the plugin:
//!
//! * cdylib: the factory panics; the `declare_plugin!`-generated `make`
//!   slot's [`catch_panic_to_null_handle`](mcpg_plugin_protocol::abi::catch_panic_to_null_handle)
//!   turns that into a null handle, which the host rejects as a boot
//!   error. The panic message (config type + serde error) reaches the
//!   operator via the default panic hook's stderr.
//! * static-firstparty: the panic propagates and aborts boot directly.
//!
//! An **empty / absent** config block (`""`, `"{}"`, `"null"`) still
//! uses `T::default()` — the operator opted out, which is not a typo.
//! Plugins that *require* config validate the parsed value afterwards
//! (an empty default that's semantically invalid is the plugin's own
//! `validate()` concern, distinct from this parse-level gate).
//!
//! Pair this with `#[serde(deny_unknown_fields)]` on the config struct
//! so a stray / renamed key is itself a parse error (and therefore
//! fail-closed), not a silently-ignored field.

use serde::de::DeserializeOwned;

/// Parse an operator `config:` JSON block into a typed config, failing
/// CLOSED on malformed input (see the [module docs](self)). Prefer the
/// [`fail_closed_config!`](crate::fail_closed_config) macro at call sites
/// — it names the config type in the panic for a clearer operator
/// message — but this function is the same contract for callers that
/// already have an explicit turbofish.
///
/// # Panics
///
/// Panics when `config_json` is non-empty and does not deserialise into
/// `T`. This is intentional and load-bearing: it is the fail-closed
/// signal the FFI `make` slot converts into a boot rejection.
pub fn parse_config_or_fail_closed<T>(config_json: &str) -> T
where
    T: DeserializeOwned + Default,
{
    let trimmed = config_json.trim();
    if trimmed.is_empty() || trimmed == "{}" || trimmed == "null" {
        return T::default();
    }
    match serde_json::from_str::<T>(trimmed) {
        Ok(v) => v,
        Err(e) => panic!(
            "plugin config rejected (failing closed) for `{}`: {e}. A malformed \
             operator `config:` block refuses the plugin rather than silently \
             falling back to defaults — fix the config.",
            std::any::type_name::<T>(),
        ),
    }
}

/// Parse the operator `config:` JSON into a typed config, failing CLOSED
/// on malformed input and using `Default` for an empty / absent block.
/// The SDK-default replacement for the fail-OPEN
/// `serde_json::from_str(cfg).unwrap_or_default()`.
///
/// ```ignore
/// use mcpg_plugin_sdk::fail_closed_config;
/// let config: MyConfig = fail_closed_config!(config_json);   // type inferred
/// let config = fail_closed_config!(config_json, MyConfig);   // explicit
/// ```
#[macro_export]
macro_rules! fail_closed_config {
    ($config_json:expr $(,)?) => {
        $crate::config::parse_config_or_fail_closed($config_json)
    };
    ($config_json:expr, $ty:ty $(,)?) => {
        $crate::config::parse_config_or_fail_closed::<$ty>($config_json)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Default, PartialEq, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cfg {
        #[serde(default)]
        name: String,
        #[serde(default)]
        count: u32,
    }

    #[test]
    fn empty_and_unit_blocks_use_default() {
        assert_eq!(parse_config_or_fail_closed::<Cfg>(""), Cfg::default());
        assert_eq!(parse_config_or_fail_closed::<Cfg>("   "), Cfg::default());
        assert_eq!(parse_config_or_fail_closed::<Cfg>("{}"), Cfg::default());
        assert_eq!(parse_config_or_fail_closed::<Cfg>("null"), Cfg::default());
    }

    #[test]
    fn valid_config_parses() {
        let c: Cfg = parse_config_or_fail_closed(r#"{"name":"x","count":3}"#);
        assert_eq!(
            c,
            Cfg {
                name: "x".into(),
                count: 3
            }
        );
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_json_fails_closed() {
        let _: Cfg = parse_config_or_fail_closed("not json");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_field_fails_closed() {
        // deny_unknown_fields makes a stray key a parse error → fail closed.
        let _: Cfg = parse_config_or_fail_closed(r#"{"naem":"typo"}"#);
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn wrong_type_fails_closed() {
        let _: Cfg = parse_config_or_fail_closed(r#"{"count":"not a number"}"#);
    }

    #[test]
    fn macro_infers_and_accepts_explicit_type() {
        let a: Cfg = fail_closed_config!("{}");
        assert_eq!(a, Cfg::default());
        let b = fail_closed_config!(r#"{"count":7}"#, Cfg);
        assert_eq!(b.count, 7);
    }
}
