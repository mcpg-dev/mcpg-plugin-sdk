use super::*;

fn options() -> InventoryOptions {
    InventoryOptions {
        store: "file".into(),
        location: "/data/in".into(),
        interval: Duration::from_millis(250),
        start: InventoryStart::Now,
        snapshot_bytes: 64 * 1024,
        max_in_flight: 100,
        ack_timeout: Duration::from_secs(60),
    }
}

fn entry(key: &str, size: u64, modified: i64) -> ObjectEntry {
    ObjectEntry {
        key: key.into(),
        size: Some(size),
        modified_at_ms: Some(modified),
        etag: None,
        version: None,
    }
}

/// Each change as (op, key).
fn changes(events: &[WatchEvent]) -> Vec<(String, String)> {
    events
        .iter()
        .filter(|e| e.event_type.is_some())
        .map(|e| {
            let data = e.data.as_ref().unwrap();
            (
                data["op"].as_str().unwrap().to_owned(),
                data["key"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn ack_all(inventory: &mut Inventory, events: &[WatchEvent]) {
    for event in events {
        if let Some(position) = &event.upstream_cursor {
            inventory.acknowledged(position);
        }
    }
}

fn op(op: &str, key: &str) -> (String, String) {
    (op.to_owned(), key.to_owned())
}

#[test]
fn creates_changes_and_deletes_are_reported_once_each() {
    let mut inv = Inventory::new(options(), None).unwrap();
    assert!(
        inv.poll(vec![entry("a", 1, 10)]).is_empty(),
        "the first listing is the baseline"
    );

    let events = inv.poll(vec![entry("a", 2, 11), entry("b", 1, 12)]);
    assert_eq!(changes(&events), [op("modified", "a"), op("created", "b")]);
    let data = events[1].data.as_ref().unwrap();
    assert_eq!(data["store"], "file");
    assert_eq!(data["location"], "/data/in");
    assert_eq!(data["size"], 1);
    assert_eq!(data["modifiedAt"], "1970-01-01T00:00:00.012Z");
    assert_eq!(
        events[1].event_type.as_deref(),
        Some(OBJECT_CHANGED_EVENT_TYPE)
    );
    assert!(events[1].event_id.as_ref().unwrap().starts_with("obj-"));
    ack_all(&mut inv, &events);

    assert!(
        inv.poll(vec![entry("a", 2, 11), entry("b", 1, 12)])
            .is_empty()
    );
    let events = inv.poll(vec![entry("b", 1, 12)]);
    assert_eq!(changes(&events), [op("deleted", "a")]);
    assert_eq!(
        events[0].data.as_ref().unwrap()["size"],
        2,
        "a deletion names what was there"
    );
    assert!(events[0].occurred_at.is_none());
}

#[test]
fn describe_adds_details_to_what_changed_and_only_to_that() {
    let asked = Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
    let seen = Arc::clone(&asked);
    let describe: Describe = Box::new(move |entries: &[ObjectEntry]| {
        seen.lock()
            .unwrap()
            .push(entries.iter().map(|e| e.key.clone()).collect());
        entries
            .iter()
            .map(|e| {
                let mut extra = Map::new();
                extra.insert("subject".into(), Value::from(format!("about {}", e.key)));
                // A shared field is never replaced.
                extra.insert("op".into(), Value::from("overridden"));
                (e.key != "quiet").then_some(extra)
            })
            .collect()
    });
    let mut inventory = Inventory::new(options(), None)
        .unwrap()
        .with_describe(describe);
    let baseline = inventory.poll(vec![entry("a", 1, 1), entry("gone", 1, 1)]);
    assert!(baseline.is_empty());
    let events = inventory.poll(vec![
        entry("a", 2, 2),
        entry("b", 1, 1),
        entry("quiet", 1, 1),
    ]);
    assert_eq!(
        changes(&events),
        [
            op("modified", "a"),
            op("created", "b"),
            op("created", "quiet"),
            op("deleted", "gone")
        ]
    );
    let data = |i: usize| events[i].data.as_ref().unwrap().clone();
    assert_eq!(data(0)["subject"], Value::from("about a"));
    assert_eq!(data(0)["op"], Value::from("modified"));
    assert_eq!(data(1)["subject"], Value::from("about b"));
    assert!(data(2).get("subject").is_none(), "None adds nothing");
    assert!(
        data(3).get("subject").is_none(),
        "a deletion is not described"
    );
    assert_eq!(
        *asked.lock().unwrap(),
        [vec!["a".to_owned(), "b".to_owned(), "quiet".to_owned()]],
        "asked once, for what changed, and not for the baseline"
    );
    ack_all(&mut inventory, &events);
    assert!(
        inventory
            .poll(vec![
                entry("a", 2, 2),
                entry("b", 1, 1),
                entry("quiet", 1, 1)
            ])
            .is_empty()
    );
    assert_eq!(
        asked.lock().unwrap().len(),
        1,
        "nothing changed, nothing asked"
    );
}

#[test]
fn with_quiet_removals_an_object_that_leaves_is_forgotten_without_an_event() {
    let mut inventory = Inventory::new(
        InventoryOptions {
            start: InventoryStart::Existing,
            ..options()
        },
        None,
    )
    .unwrap()
    .with_quiet_removals();
    let events = inventory.poll(vec![entry("old", 1, 1), entry("new", 1, 1)]);
    assert_eq!(
        changes(&events),
        [op("created", "new"), op("created", "old")]
    );
    ack_all(&mut inventory, &events);
    let events = inventory.poll(vec![entry("new", 1, 1)]);
    assert!(events.is_empty(), "the old item scrolled away: no deletion");
    // It is forgotten, so coming back is a creation.
    let events = inventory.poll(vec![entry("new", 1, 1), entry("old", 1, 1)]);
    assert_eq!(changes(&events), [op("created", "old")]);
}

#[test]
fn a_change_in_flight_is_not_reported_twice() {
    let mut inv = Inventory::new(options(), None).unwrap();
    inv.poll(vec![]);
    let first = inv.poll(vec![entry("a", 1, 10)]);
    assert_eq!(changes(&first), [op("created", "a")]);
    assert!(
        inv.poll(vec![entry("a", 1, 10)]).is_empty(),
        "still in flight"
    );
    ack_all(&mut inv, &first);
    assert!(inv.poll(vec![entry("a", 1, 10)]).is_empty());
}

#[test]
fn a_change_the_host_passed_over_is_reported_again_with_its_id() {
    let mut inv = Inventory::new(options(), None).unwrap();
    inv.poll(vec![]);
    let events = inv.poll(vec![entry("a", 1, 10), entry("b", 1, 10)]);
    // The host stored `b` and dropped `a`.
    inv.acknowledged(events[1].upstream_cursor.as_ref().unwrap());
    let again = inv.poll(vec![entry("a", 1, 10), entry("b", 1, 10)]);
    assert_eq!(changes(&again), [op("created", "a")]);
    assert_eq!(again[0].event_id, events[0].event_id);
}

#[test]
fn an_overdue_change_is_reported_again() {
    let mut inv = Inventory::new(
        InventoryOptions {
            ack_timeout: Duration::from_millis(1),
            ..options()
        },
        None,
    )
    .unwrap();
    inv.poll(vec![]);
    let first = inv.poll(vec![entry("a", 1, 10)]);
    std::thread::sleep(Duration::from_millis(5));
    let again = inv.poll(vec![entry("a", 1, 10)]);
    assert_eq!(changes(&again), changes(&first));
}

#[test]
fn the_window_bounds_the_changes_in_flight() {
    let mut inv = Inventory::new(
        InventoryOptions {
            max_in_flight: 2,
            ..options()
        },
        None,
    )
    .unwrap();
    inv.poll(vec![]);
    let listing: Vec<ObjectEntry> = (0..5).map(|i| entry(&format!("k{i}"), 1, 1)).collect();
    let first = inv.poll(listing.clone());
    assert_eq!(first.len(), 2);
    assert!(!inv.has_room());
    ack_all(&mut inv, &first);
    let next = inv.poll(listing.clone());
    assert_eq!(changes(&next), [op("created", "k2"), op("created", "k3")]);
}

#[test]
fn existing_objects_are_reported_on_a_fresh_start_when_asked() {
    let mut inv = Inventory::new(
        InventoryOptions {
            start: InventoryStart::Existing,
            ..options()
        },
        None,
    )
    .unwrap();
    let events = inv.poll(vec![entry("a", 1, 1), entry("b", 1, 1)]);
    assert_eq!(changes(&events), [op("created", "a"), op("created", "b")]);
}

#[test]
fn a_restart_from_a_snapshot_reports_exactly_what_changed_while_stopped() {
    let mut inv = Inventory::new(options(), None).unwrap();
    inv.poll(vec![entry("a", 1, 1), entry("b", 1, 1)]);
    let events = inv.poll(vec![entry("a", 1, 1), entry("b", 1, 1), entry("c", 1, 1)]);
    ack_all(&mut inv, &events);
    let stored = events.last().unwrap().upstream_cursor.clone().unwrap();
    assert!(
        stored.get("snap").is_some(),
        "the last change of a poll carries the listing"
    );

    // Stopped: a was deleted, b modified, d created.
    let mut again = Inventory::new(options(), Some(stored)).unwrap();
    let events = again.poll(vec![entry("b", 2, 2), entry("c", 1, 1), entry("d", 1, 1)]);
    assert!(events.iter().all(|e| !e.gap));
    assert_eq!(
        changes(&events),
        [op("modified", "b"), op("created", "d"), op("deleted", "a")]
    );
}

#[test]
fn a_change_still_in_flight_is_outside_the_snapshot() {
    let mut inv = Inventory::new(options(), None).unwrap();
    inv.poll(vec![]);
    let events = inv.poll(vec![entry("a", 1, 1), entry("b", 1, 1)]);
    // `a` is still in flight when `b`'s cursor is taken.
    let snap = events[1].upstream_cursor.as_ref().unwrap()["snap"].clone();
    assert!(snap.get("a").is_none());
    assert!(snap.get("b").is_some());
    let mut again = Inventory::new(options(), events[1].upstream_cursor.clone()).unwrap();
    let repeat = again.poll(vec![entry("a", 1, 1), entry("b", 1, 1)]);
    assert_eq!(changes(&repeat), [op("created", "a")]);
    assert_eq!(
        repeat[0].event_id, events[0].event_id,
        "taken once by the host"
    );
}

#[test]
fn a_listing_past_the_budget_restarts_with_a_gap() {
    let mut inv = Inventory::new(
        InventoryOptions {
            snapshot_bytes: 64,
            ..options()
        },
        None,
    )
    .unwrap();
    inv.poll(vec![]);
    let mut listing: Vec<ObjectEntry> = (0..20).map(|i| entry(&format!("key-{i}"), 1, 1)).collect();
    let events = inv.poll(listing.clone());
    ack_all(&mut inv, &events);
    listing.push(entry("one-more", 1, 1));
    let events = inv.poll(listing.clone());
    let stored = events.last().unwrap().upstream_cursor.clone().unwrap();
    assert!(
        stored.get("snap").is_none(),
        "21 objects do not fit 64 bytes"
    );

    let mut again = Inventory::new(options(), Some(stored)).unwrap();
    let events = again.poll(listing);
    assert_eq!(events.len(), 1);
    assert!(
        events[0].gap,
        "readers are told that changes while stopped may be missing"
    );
    assert!(events[0].event_type.is_none());
    assert_eq!(
        again.poll(vec![]).len(),
        21,
        "the listing it found is its baseline"
    );
}

#[test]
fn a_position_from_elsewhere_is_refused_and_options_are_checked() {
    assert!(Inventory::new(options(), Some(serde_json::json!({ "k": [1] }))).is_err());
    for (bad, needle) in [
        (
            InventoryOptions {
                interval: Duration::from_millis(10),
                ..options()
            },
            "interval_ms",
        ),
        (
            InventoryOptions {
                snapshot_bytes: MAX_SNAPSHOT_BYTES + 1,
                ..options()
            },
            "snapshot_bytes",
        ),
        (
            InventoryOptions {
                max_in_flight: 0,
                ..options()
            },
            "max_in_flight",
        ),
        (
            InventoryOptions {
                ack_timeout: Duration::ZERO,
                ..options()
            },
            "ack_timeout_ms",
        ),
    ] {
        assert!(bad.validate().unwrap_err().contains(needle));
    }
}

#[test]
fn the_watch_thread_lists_emits_and_hears_acknowledgements() {
    let listing = Arc::new(std::sync::Mutex::new(vec![entry("a", 1, 1)]));
    let emitted = Arc::new(std::sync::Mutex::new(Vec::<WatchEvent>::new()));
    let sink = Arc::clone(&emitted);
    let source = Arc::clone(&listing);
    let handle = spawn_inventory_watch(
        "mcpg-event://inbox",
        options(),
        None,
        Box::new(move |json| {
            sink.lock()
                .unwrap()
                .push(serde_json::from_str(json).unwrap());
        }),
        move || Ok(source.lock().unwrap().clone()),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    listing.lock().unwrap().push(entry("b", 1, 1));
    let wait = |n: usize| {
        for _ in 0..50 {
            if emitted.lock().unwrap().len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    };
    assert!(wait(1));
    assert_eq!(changes(&emitted.lock().unwrap()), [op("created", "b")]);
    let position = emitted.lock().unwrap()[0].upstream_cursor.clone().unwrap();
    acknowledge_inventory_watch(&handle, &position);
    listing.lock().unwrap().retain(|e| e.key != "a");
    assert!(wait(2));
    assert_eq!(
        changes(&emitted.lock().unwrap()),
        [op("created", "b"), op("deleted", "a")]
    );
    cancel_inventory_watch(handle);
}

#[test]
fn a_resource_watch_gets_one_bare_change_per_poll_that_changed() {
    let listing = Arc::new(std::sync::Mutex::new(vec![entry("a", 1, 1)]));
    let emitted = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&emitted);
    let source = Arc::clone(&listing);
    let handle = spawn_inventory_watch(
        "file:///data/in",
        options(),
        None,
        Box::new(move |json| sink.lock().unwrap().push(json.to_owned())),
        move || Ok(source.lock().unwrap().clone()),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    listing.lock().unwrap().push(entry("b", 1, 1));
    listing.lock().unwrap().push(entry("c", 1, 1));
    std::thread::sleep(Duration::from_millis(400));
    cancel_inventory_watch(handle);
    assert_eq!(*emitted.lock().unwrap(), ["{}"]);
}

/// A tree as a directory lister: each directory, by its path relative to the
/// root, to its entries.
fn tree(dirs: &[(&str, &[(&str, bool)])]) -> BTreeMap<String, Vec<DirItem>> {
    dirs.iter()
        .map(|(dir, items)| {
            let items = items
                .iter()
                .map(|(name, is_dir)| DirItem {
                    name: (*name).to_owned(),
                    is_dir: *is_dir,
                    size: Some(1),
                    modified_at_ms: Some(1_000),
                })
                .collect();
            ((*dir).to_owned(), items)
        })
        .collect()
}

fn walk_options(recursive: bool, pattern: Option<&str>) -> WalkOptions {
    WalkOptions {
        recursive,
        pattern: pattern.map(|p| Pattern::new(p).unwrap()),
        max_files: 100,
        max_dirs: 100,
    }
}

fn keys(entries: &[ObjectEntry]) -> Vec<&str> {
    entries.iter().map(|e| e.key.as_str()).collect()
}

#[test]
fn a_walk_keys_files_by_their_path_and_goes_down_only_when_recursive() {
    let dirs = tree(&[
        (
            "",
            &[
                ("b.csv", false),
                ("sub", true),
                ("a.txt", false),
                (".", true),
            ],
        ),
        ("sub", &[("c.csv", false), ("deep", true)]),
        ("sub/deep", &[("d.csv", false)]),
    ]);
    let lister = |dir: &str| Ok(dirs.get(dir).cloned().unwrap_or_default());
    let flat = walk(&walk_options(false, None), lister).unwrap();
    assert_eq!(keys(&flat), ["a.txt", "b.csv"]);
    let all = walk(&walk_options(true, None), lister).unwrap();
    assert_eq!(
        keys(&all),
        ["a.txt", "b.csv", "sub/c.csv", "sub/deep/d.csv"]
    );
    assert_eq!(all[0].size, Some(1));
    assert_eq!(all[0].modified_at_ms, Some(1_000));
}

#[test]
fn a_walk_pattern_star_stays_in_a_directory_and_double_star_crosses() {
    let dirs = tree(&[
        ("", &[("a.csv", false), ("sub", true), ("a.txt", false)]),
        ("sub", &[("b.csv", false)]),
    ]);
    let lister = |dir: &str| Ok(dirs.get(dir).cloned().unwrap_or_default());
    let top = walk(&walk_options(true, Some("*.csv")), lister).unwrap();
    assert_eq!(keys(&top), ["a.csv"]);
    let every = walk(&walk_options(true, Some("**/*.csv")), lister).unwrap();
    assert_eq!(keys(&every), ["a.csv", "sub/b.csv"]);
}

#[test]
fn a_cut_walk_keeps_the_same_objects_whatever_the_listing_order() {
    let forward = tree(&[
        (
            "",
            &[("a", true), ("b", true), ("z.txt", false), ("y.txt", false)],
        ),
        ("a", &[("1.txt", false)]),
        ("b", &[("2.txt", false)]),
    ]);
    let backward = tree(&[
        (
            "",
            &[("y.txt", false), ("z.txt", false), ("b", true), ("a", true)],
        ),
        ("a", &[("1.txt", false)]),
        ("b", &[("2.txt", false)]),
    ]);
    let cut = WalkOptions {
        max_files: 2,
        max_dirs: 2,
        ..walk_options(true, None)
    };
    let one = walk(&cut, |dir| {
        Ok(forward.get(dir).cloned().unwrap_or_default())
    })
    .unwrap();
    let two = walk(&cut, |dir| {
        Ok(backward.get(dir).cloned().unwrap_or_default())
    })
    .unwrap();
    assert_eq!(one, two);
    assert_eq!(
        keys(&one),
        ["a/1.txt", "y.txt"],
        "the root and `a` are listed; the first two keys are kept"
    );
}

#[test]
fn a_walk_that_cannot_list_a_directory_fails_rather_than_report_deletions() {
    let dirs = tree(&[("", &[("a.txt", false), ("locked", true)])]);
    let error = walk(&walk_options(true, None), |dir| {
        if dir == "locked" {
            Err("permission denied".to_owned())
        } else {
            Ok(dirs.get(dir).cloned().unwrap_or_default())
        }
    })
    .unwrap_err();
    assert_eq!(error, "permission denied");
}
