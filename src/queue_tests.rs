use super::*;
use std::collections::VecDeque;

/// A broker in memory: messages wait in `ready`, a released one goes back
/// to its end, and every call is recorded.
#[derive(Default)]
struct Broker {
    ready: Mutex<VecDeque<String>>,
    acked: Mutex<Vec<String>>,
    released: Mutex<Vec<String>>,
    receives: Mutex<Vec<usize>>,
    /// Connects that fail before one succeeds.
    failing_connects: Mutex<u32>,
    connects: Mutex<u32>,
    /// Receives that fail, once each.
    failing_receives: Mutex<u32>,
}

#[derive(Clone, Default)]
struct Source(Arc<Broker>);

impl Source {
    fn with(messages: &[&str]) -> Self {
        let source = Self::default();
        source
            .0
            .ready
            .lock()
            .unwrap()
            .extend(messages.iter().map(|m| (*m).to_owned()));
        source
    }
    fn push(&self, message: &str) {
        self.0.ready.lock().unwrap().push_back(message.to_owned());
    }
    fn acked(&self) -> Vec<String> {
        self.0.acked.lock().unwrap().clone()
    }
    fn released(&self) -> Vec<String> {
        self.0.released.lock().unwrap().clone()
    }
}

impl QueueSource for Source {
    fn connect(&self) -> Result<(), String> {
        *self.0.connects.lock().unwrap() += 1;
        let mut failing = self.0.failing_connects.lock().unwrap();
        if *failing > 0 {
            *failing -= 1;
            return Err("broker down".into());
        }
        Ok(())
    }

    fn receive(&self, max: usize, wait: Duration) -> Result<Vec<Delivery>, String> {
        self.0.receives.lock().unwrap().push(max);
        {
            let mut failing = self.0.failing_receives.lock().unwrap();
            if *failing > 0 {
                *failing -= 1;
                return Err("connection reset".into());
            }
        }
        let taken: Vec<String> = {
            let mut ready = self.0.ready.lock().unwrap();
            let n = max.min(ready.len());
            ready.drain(..n).collect()
        };
        if taken.is_empty() {
            std::thread::sleep(wait);
        }
        Ok(taken
            .into_iter()
            .map(|body| Delivery {
                event: WatchEvent {
                    event_id: Some(format!("id-{body}")),
                    event_type: Some("test.message".into()),
                    data: Some(serde_json::json!({ "body": body })),
                    ..WatchEvent::default()
                },
                receipt: Value::from(body),
            })
            .collect())
    }

    fn ack(&self, receipt: &Value) -> Result<(), String> {
        self.0
            .acked
            .lock()
            .unwrap()
            .push(receipt.as_str().unwrap().to_owned());
        Ok(())
    }

    fn release(&self, receipt: &Value) -> Result<(), String> {
        let body = receipt.as_str().unwrap().to_owned();
        self.0.released.lock().unwrap().push(body.clone());
        self.0.ready.lock().unwrap().push_back(body);
        Ok(())
    }
}

fn options(max_in_flight: usize, ack_timeout: Duration) -> QueueOptions {
    QueueOptions {
        source: "test".into(),
        max_in_flight,
        ack_timeout,
        receive_wait: Duration::from_millis(20),
    }
}

/// The callback a watch emits its events through.
type Emit = Box<dyn Fn(&str) + Send + Sync>;

/// The events a watch emits.
fn collector() -> (Emit, Receiver<WatchEvent>) {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    let emit = move |json: &str| {
        let event: WatchEvent = serde_json::from_str(json).unwrap();
        let _ = tx.lock().unwrap().send(event);
    };
    (Box::new(emit), rx)
}

fn next(events: &Receiver<WatchEvent>) -> WatchEvent {
    events
        .recv_timeout(Duration::from_secs(5))
        .expect("an event")
}

fn body(event: &WatchEvent) -> String {
    event.data.as_ref().unwrap()["body"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Wait until `done` holds, or fail.
fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn each_message_is_an_event_settled_only_when_the_host_acknowledges_it() {
    let source = Source::with(&["a", "b"]);
    let (emit, events) = collector();
    let handle = spawn_queue_watch(
        "mcpg-event://orders",
        options(10, Duration::from_secs(60)),
        emit,
        source.clone(),
    )
    .unwrap();
    let a = next(&events);
    let b = next(&events);
    assert_eq!((body(&a), body(&b)), ("a".into(), "b".into()));
    assert_eq!(
        a.event_id.as_deref(),
        Some("id-a"),
        "the broker's id is kept"
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(source.acked().is_empty(), "nothing settles before the host");

    acknowledge_queue_watch(&handle, a.upstream_cursor.as_ref().unwrap());
    eventually("the ack of a", || source.acked() == ["a"]);
    // The same position twice settles nothing more.
    acknowledge_queue_watch(&handle, a.upstream_cursor.as_ref().unwrap());
    acknowledge_queue_watch(&handle, b.upstream_cursor.as_ref().unwrap());
    eventually("the ack of b", || source.acked() == ["a", "b"]);
    cancel_queue_watch(handle);
    assert!(source.released().is_empty());
}

#[test]
fn the_window_holds_at_most_max_in_flight_messages() {
    let source = Source::with(&["a", "b", "c"]);
    let (emit, events) = collector();
    let handle = spawn_queue_watch(
        "mcpg-event://orders",
        options(2, Duration::from_secs(60)),
        emit,
        source.clone(),
    )
    .unwrap();
    let a = next(&events);
    let _b = next(&events);
    assert!(
        events.recv_timeout(Duration::from_millis(200)).is_err(),
        "a third waits for room"
    );
    assert!(
        source
            .0
            .receives
            .lock()
            .unwrap()
            .iter()
            .all(|max| *max <= 2)
    );
    acknowledge_queue_watch(&handle, a.upstream_cursor.as_ref().unwrap());
    assert_eq!(body(&next(&events)), "c");
    cancel_queue_watch(handle);
}

#[test]
fn a_message_the_host_does_not_acknowledge_in_time_is_released_and_comes_back() {
    let source = Source::with(&["a"]);
    let (emit, events) = collector();
    let handle = spawn_queue_watch(
        "mcpg-event://orders",
        options(10, Duration::from_millis(300)),
        emit,
        source.clone(),
    )
    .unwrap();
    let first = next(&events);
    let again = next(&events);
    assert_eq!(body(&again), "a");
    assert_eq!(source.released(), ["a"]);
    assert_eq!(
        first.event_id, again.event_id,
        "the same id, so the host takes it once"
    );
    assert_ne!(first.upstream_cursor, again.upstream_cursor);
    // The late acknowledgement of the first delivery settles nothing.
    acknowledge_queue_watch(&handle, first.upstream_cursor.as_ref().unwrap());
    acknowledge_queue_watch(&handle, again.upstream_cursor.as_ref().unwrap());
    eventually("the ack", || source.acked() == ["a"]);
    cancel_queue_watch(handle);
}

#[test]
fn a_broker_that_is_down_or_drops_the_connection_is_connected_again() {
    let source = Source::default();
    *source.0.failing_connects.lock().unwrap() = 1;
    *source.0.failing_receives.lock().unwrap() = 1;
    source.push("a");
    let (emit, events) = collector();
    let handle = spawn_queue_watch(
        "mcpg-event://orders",
        options(10, Duration::from_secs(60)),
        emit,
        source.clone(),
    )
    .unwrap();
    assert_eq!(body(&next(&events)), "a");
    assert_eq!(
        *source.0.connects.lock().unwrap(),
        3,
        "a failed connect, a good one, and one after the failed receive"
    );
    cancel_queue_watch(handle);
}

#[test]
fn a_resource_watch_gets_a_bare_change_and_the_messages_are_settled() {
    let source = Source::with(&["a", "b"]);
    let emitted = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&emitted);
    let handle = spawn_queue_watch(
        "amqp://orders",
        options(10, Duration::from_secs(60)),
        Box::new(move |json| sink.lock().unwrap().push(json.to_owned())),
        source.clone(),
    )
    .unwrap();
    eventually("both acks", || source.acked().len() == 2);
    cancel_queue_watch(handle);
    let emitted = emitted.lock().unwrap();
    assert!(!emitted.is_empty());
    assert!(emitted.iter().all(|json| json == "{}"));
}

#[test]
fn cancel_releases_what_the_host_has_not_acknowledged() {
    let source = Source::with(&["a", "b"]);
    let (emit, events) = collector();
    let handle = spawn_queue_watch(
        "mcpg-event://orders",
        options(10, Duration::from_secs(60)),
        emit,
        source.clone(),
    )
    .unwrap();
    let a = next(&events);
    let _b = next(&events);
    acknowledge_queue_watch(&handle, a.upstream_cursor.as_ref().unwrap());
    eventually("the ack of a", || source.acked() == ["a"]);
    let started = Instant::now();
    cancel_queue_watch(handle);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancel returns promptly"
    );
    assert_eq!(source.released(), ["b"]);
}

#[test]
fn an_event_too_large_for_the_host_is_removed_rather_than_redelivered_forever() {
    let big = "x".repeat(FFI_MAX_PAYLOAD_BYTES);
    let source = Source::with(&[big.as_str(), "small"]);
    let (emit, events) = collector();
    let handle = spawn_queue_watch(
        "mcpg-event://orders",
        options(10, Duration::from_secs(60)),
        emit,
        source.clone(),
    )
    .unwrap();
    assert_eq!(body(&next(&events)), "small");
    eventually("the removal", || source.acked() == [big.clone()]);
    cancel_queue_watch(handle);
}

#[test]
fn options_are_checked() {
    let (emit, _events) = collector();
    let refused = spawn_queue_watch(
        "mcpg-event://orders",
        options(0, Duration::from_secs(60)),
        emit,
        Source::default(),
    );
    match refused {
        Err(WatchError::InvalidSpec { message }) => assert!(message.contains("max_in_flight")),
        _ => panic!("max_in_flight 0 is refused"),
    }
    assert!(options(10, Duration::ZERO).validate().is_err());
    let slow = QueueOptions {
        receive_wait: Duration::from_secs(21),
        ..options(10, Duration::from_secs(1))
    };
    assert!(slow.validate().is_err());
}
