//! A native plugin's own `tracing` events, forwarded to the host log.
//!
//! A cdylib links its own copy of `tracing`, whose global dispatcher is
//! never set, so the events a plugin emits reach no subscriber. [`install`]
//! (called by the cdylib's `mcpg_plugin_register`) sets one that sends each
//! event at INFO and above to the host as a [`PLUGIN_LOG_EVENT`] span event.
//!
//! It sends through the host handle of a live instance: every `make` attaches
//! its handle and every `drop_instance` detaches it, and the host frees a
//! handle's bridge only after `drop_instance` returns. A forward holds the
//! registry's read lock for the whole host call, so a detach waits for it.

use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

use abi_stable::std_types::RString;
use mcpg_plugin_protocol::abi::{HostHandleRef, RPluginHandle};
use mcpg_plugin_protocol::logs::{LogLevel, LogRecord, PLUGIN_LOG_EVENT};
use serde_json::Value;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, span};

/// The most verbose level forwarded. The host filters on top of it; DEBUG
/// and TRACE stay in the plugin, as each would cost an FFI call and a JSON
/// round trip.
const MAX_LEVEL: LevelFilter = LevelFilter::INFO;

/// The host handles of the live instances, newest last, each with the
/// plugin handle its `make` returned.
static LIVE: RwLock<Vec<(usize, HostHandleRef)>> = RwLock::new(Vec::new());

/// Set the forwarding subscriber as this cdylib's global default. Later
/// calls, or a default set before the first one, leave the dispatcher as
/// it is.
pub fn install() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(Forwarder);
    });
}

/// Record the host handle of the instance `make` returned as `plugin`.
pub(crate) fn attach(plugin: RPluginHandle, host: HostHandleRef) {
    let mut live = LIVE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    live.push((plugin as usize, host));
}

/// Forget the host handle of `plugin`.
pub(crate) fn detach(plugin: RPluginHandle) {
    let mut live = LIVE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    live.retain(|(p, _)| *p != plugin as usize);
}

/// Whether `plugin` has a host handle attached.
#[cfg(test)]
fn is_attached(plugin: RPluginHandle) -> bool {
    let live = LIVE.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    live.iter().any(|(p, _)| *p == plugin as usize)
}

struct Forwarder;

impl tracing::Subscriber for Forwarder {
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.enabled(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && *metadata.level() <= MAX_LEVEL
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(MAX_LEVEL)
    }

    // Spans are never enabled, so no span id is ever handed out.
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let Ok(attrs) = serde_json::to_string(&record_of(event)) else {
            return;
        };
        let live = LIVE.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, host)) = live.last() {
            deliver(host, attrs);
        }
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// Send one serialised [`LogRecord`] to the host.
fn deliver(host: &HostHandleRef, attrs: String) {
    (host.vtable.span_event)(
        host.ctx,
        0,
        RString::from(PLUGIN_LOG_EVENT),
        RString::from(attrs),
    );
}

/// `event` as the record the host logs.
fn record_of(event: &Event<'_>) -> LogRecord {
    let metadata = event.metadata();
    let mut fields = Fields::default();
    event.record(&mut fields);
    LogRecord {
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        level: match *metadata.level() {
            tracing::Level::ERROR => LogLevel::Error,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::TRACE => LogLevel::Trace,
        },
        target: metadata.target().to_owned(),
        message: fields.message,
        fields: fields.rest,
        span_id: None,
        trace_id: None,
        request_id: None,
        identity: None,
        node_id: None,
        plugin_id: None,
    }
}

/// An event's `message` and its other fields.
#[derive(Default)]
struct Fields {
    message: String,
    rest: BTreeMap<String, Value>,
}

impl Fields {
    fn put(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            self.message = match value {
                Value::String(s) => s,
                other => other.to_string(),
            };
        } else {
            self.rest.insert(field.name().to_owned(), value);
        }
    }
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, Value::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::String(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::Bool(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(
            field,
            serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
        );
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Collects each event as [`record_of`] builds it, the way the
    /// forwarder does.
    struct Collect(Mutex<Vec<LogRecord>>);

    impl tracing::Subscriber for Collect {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            Forwarder.enabled(metadata)
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            self.0.lock().unwrap().push(record_of(event));
        }
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }

    #[test]
    fn an_event_becomes_a_record_with_its_level_target_message_and_fields() {
        let collect = std::sync::Arc::new(Collect(Mutex::new(Vec::new())));
        tracing::subscriber::with_default(std::sync::Arc::clone(&collect), || {
            tracing::warn!(
                target: "mcpg_plugin_example::kv",
                bucket = "leases",
                attempts = 3u64,
                ok = false,
                error = %"deadline has elapsed",
                "sweep failed after {} tries",
                3
            );
            tracing::info!("connected");
            tracing::debug!("a debug line stays in the plugin");
        });
        let records = collect.0.lock().unwrap();
        assert_eq!(records.len(), 2, "INFO and above only: {records:?}");
        let warn = &records[0];
        assert_eq!(warn.level, LogLevel::Warn);
        assert_eq!(warn.target, "mcpg_plugin_example::kv");
        assert_eq!(warn.message, "sweep failed after 3 tries");
        assert_eq!(warn.fields["bucket"], "leases");
        assert_eq!(warn.fields["attempts"], 3);
        assert_eq!(warn.fields["ok"], false);
        assert_eq!(warn.fields["error"], "deadline has elapsed");
        assert!(!warn.fields.contains_key("message"));
        assert_eq!(records[1].level, LogLevel::Info);
        assert_eq!(records[1].message, "connected");
    }

    #[test]
    fn spans_are_not_enabled() {
        let collect = std::sync::Arc::new(Collect(Mutex::new(Vec::new())));
        tracing::subscriber::with_default(std::sync::Arc::clone(&collect), || {
            assert!(tracing::info_span!("work").is_disabled());
        });
    }

    static DELIVERED: Mutex<Vec<(u64, String, String)>> = Mutex::new(Vec::new());

    extern "C" fn capture_span_event(_ctx: usize, span_id: u64, name: RString, attrs: RString) {
        DELIVERED
            .lock()
            .unwrap()
            .push((span_id, name.into_string(), attrs.into_string()));
    }

    #[test]
    fn a_record_reaches_the_host_as_a_log_span_event() {
        let mut host = crate::testing::stub_host_ref();
        host.vtable.span_event = capture_span_event;
        deliver(&host, r#"{"level":"warn"}"#.to_owned());
        let delivered = DELIVERED.lock().unwrap();
        assert_eq!(
            delivered.as_slice(),
            [(
                0,
                PLUGIN_LOG_EVENT.to_owned(),
                r#"{"level":"warn"}"#.to_owned()
            )]
        );
    }

    #[test]
    fn an_instance_is_attached_from_make_until_drop() {
        let host = crate::testing::stub_host_ref();
        let first = 0x10 as RPluginHandle;
        let second = 0x20 as RPluginHandle;
        attach(first, host);
        attach(second, host);
        assert!(is_attached(first) && is_attached(second));
        detach(first);
        assert!(
            !is_attached(first),
            "a dropped instance's handle is never used again"
        );
        assert!(is_attached(second));
        detach(second);
        assert!(!is_attached(second));
    }
}
