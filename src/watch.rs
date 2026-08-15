//! Shared polling watch-strategy helper for cdylib backends.
//!
//! Many backends have no native change-push channel but can be *polled*: run a
//! cheap scalar "high-water" query on a cadence (`SELECT max(updated_at)`, a
//! row count, a monotonic sequence, a directory-listing fingerprint, …) and
//! signal a change whenever that scalar advances. This module factors that loop
//! out so each backend's `watch_strategy` entity is just a closure over its own
//! engine — the thread, the cursor diff, the stop signal, and the opaque
//! [`WatchHandleBox`] round-trip all live here once.
//!
//! The loop runs on a dedicated OS thread (not a tokio runtime): the `poll`
//! closure is synchronous, so an async-engine backend does its own `block_on`
//! inside the closure (sequential ticks, a current-thread runtime is enough).
//! The first successful poll establishes the baseline WITHOUT emitting, so a
//! watcher never fires spuriously at startup.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchEvent;

use crate::ffi::WatchHandleBox;

/// Floor on the poll cadence — a misconfigured tiny interval would hammer the
/// backend. 250 ms is well below any realistic resource-change cadence.
const MIN_INTERVAL: Duration = Duration::from_millis(250);

/// Cancel-state boxed behind the opaque [`WatchHandleBox`]. Owned by this crate
/// on both ends (spawn boxes it, [`cancel_polling_watch`] unboxes it) so the
/// raw pointer always round-trips a type we control.
struct PollingCancelState {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

/// Spawn a polling watch loop on a dedicated thread.
///
/// `poll` returns the current high-water cursor (`Some(scalar)`), `None` when
/// there is no signal yet (e.g. an empty table — treated as "no change"), or
/// `Err` for a transient failure (logged and retried on the next tick). When a
/// non-null cursor differs from the previously-seen non-null cursor, a default
/// [`WatchEvent`] is emitted — the host turns that into
/// `notifications/resources/updated` for `resource_uri`. `interval` is clamped
/// up to [`MIN_INTERVAL`]. The returned handle is cancelled via
/// [`cancel_polling_watch`].
pub fn spawn_polling_watch<F>(
    resource_uri: &str,
    interval: Duration,
    emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    mut poll: F,
) -> WatchHandleBox
where
    F: FnMut() -> Result<Option<String>, String> + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let uri = resource_uri.to_owned();
    let interval = interval.max(MIN_INTERVAL);
    // The change signal carries no per-event payload: the host already knows
    // which resource_uri this watcher is bound to, so a default WatchEvent is
    // "the watched collection changed". Not session/user-scoped (a backend
    // poll is not tied to an MCP session).
    let event_json =
        serde_json::to_string(&WatchEvent::default()).unwrap_or_else(|_| "{}".to_owned());

    let join = std::thread::Builder::new()
        .name("mcpg-poll-watch".to_owned())
        .spawn(move || {
            let mut last: Option<String> = None;
            while !stop_thread.load(Ordering::Relaxed) {
                match poll() {
                    Ok(Some(cur)) => match &last {
                        // Baseline: remember without firing.
                        None => last = Some(cur),
                        // Advance: the tracked scalar moved → signal a change.
                        Some(prev) if *prev != cur => {
                            last = Some(cur);
                            emit_event(&event_json);
                        }
                        _ => {}
                    },
                    // No rows / no signal this tick — not a change.
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(resource_uri = %uri, error = %e, "polling watch: tick failed");
                    }
                }
                sleep_interruptible(&stop_thread, interval);
            }
        })
        .unwrap_or_else(|e| panic!("polling watch: thread spawn failed: {e}"));

    let state = Box::new(PollingCancelState {
        stop,
        join: Some(join),
    });
    WatchHandleBox(Box::into_raw(state) as *mut ())
}

/// Sleep `total`, waking early (within a 200 ms slice) when `stop` is set so a
/// cancel doesn't block on a long poll interval.
fn sleep_interruptible(stop: &AtomicBool, total: Duration) {
    let slice = Duration::from_millis(200);
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let nap = slice.min(total - elapsed);
        std::thread::sleep(nap);
        elapsed += nap;
    }
}

/// Stop and join a watch started by [`spawn_polling_watch`]. Idempotent on a
/// null handle. The host calls this exactly once per handle.
pub fn cancel_polling_watch(handle: WatchHandleBox) {
    if handle.0.is_null() {
        return;
    }
    // SAFETY: the pointer was produced by `Box::into_raw` in
    // `spawn_polling_watch` and is round-tripped by the host exactly once.
    #[allow(unsafe_code)]
    let mut state = unsafe { Box::from_raw(handle.0 as *mut PollingCancelState) };
    state.stop.store(true, Ordering::Relaxed);
    if let Some(join) = state.join.take() {
        let _ = join.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn emits_on_cursor_advance_not_on_baseline_or_repeat() {
        // A scripted cursor sequence (consumed front-to-back), then steady at
        // the last value. Only the two distinct advances after the baseline
        // should emit.
        let script = Arc::new(Mutex::new(std::collections::VecDeque::from(vec![
            "1".to_owned(), // baseline — no emit
            "1".to_owned(), // repeat — no emit
            "2".to_owned(), // advance — EMIT
            "2".to_owned(), // repeat — no emit
            "3".to_owned(), // advance — EMIT
        ])));
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_c = Arc::clone(&count);
        let emit: Box<dyn Fn(&str) + Send + Sync> = Box::new(move |_json| {
            count_c.fetch_add(1, Ordering::Relaxed);
        });
        let script_c = Arc::clone(&script);
        let mut tail = "3".to_owned();
        let handle =
            spawn_polling_watch("res://test", Duration::from_millis(250), emit, move || {
                if let Some(next) = script_c.lock().unwrap().pop_front() {
                    tail = next.clone();
                    Ok(Some(next))
                } else {
                    Ok(Some(tail.clone()))
                }
            });
        std::thread::sleep(Duration::from_millis(1700));
        cancel_polling_watch(handle);
        assert_eq!(
            count.load(Ordering::Relaxed),
            2,
            "exactly two distinct advances emit"
        );
    }

    #[test]
    fn cancel_null_handle_is_noop() {
        cancel_polling_watch(WatchHandleBox(std::ptr::null_mut()));
    }
}
