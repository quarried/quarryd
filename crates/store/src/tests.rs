use std::sync::Arc;

use super::*;

fn usage_row(instance_id: &str, bucket_start_unix: i64) -> UsageRow
{
    UsageRow {
        id: format!("{instance_id}:{bucket_start_unix}"),
        instance_id: instance_id.to_string(),
        bucket_start_unix,
        bucket_seconds: 60,
        cpu_usec: 1_500_000,
        memory_mib_max: 2048,
        memory_mib_avg: 1900,
        disk_read_bytes: 4096,
        disk_write_bytes: 8192,
        net_rx_bytes: 1000,
        net_tx_bytes: 2000,
    }
}

fn artifact(digest: &str, size_bytes: u64, last_used_unix: i64) -> ArtifactRow
{
    ArtifactRow {
        digest: digest.to_string(),
        path: format!("/var/lib/quarryd/artifacts/{digest}"),
        size_bytes,
        kind: "rootfs".to_string(),
        last_used_unix,
        verified: true,
    }
}

fn sample_actual() -> ActualState
{
    ActualState {
        observed_generation: 3,
        phase: "Running".to_string(),
        reason: "server ready".to_string(),
        unit_name: Some("quarry-vm@srv-1.service".to_string()),
        api_socket: Some("/srv/jailer/firecracker/srv-1/root/api.sock".to_string()),
        pid: Some(4242),
        sandbox_record: Some(r#"{"kind":"firecracker"}"#.to_string()),
        network_attachment: Some(r#"{"tap":"qtap0"}"#.to_string()),
        guest_ip: Some("10.20.0.5".to_string()),
        uid: Some(100_001),
        restart_count: 2,
        last_exit_unix: Some(1_700_000_000),
        lease_epoch: 7,
        lease_expires_unix_ms: Some(1_700_000_060_000),
    }
}

#[test]
fn store_is_send_and_sync()
{
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();
    assert_send_sync::<Arc<Store>>();
}

#[test]
fn migrations_run_from_empty_database()
{
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    let connection = store.connection();
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for table in [
        "artifact_refs",
        "artifacts",
        "instances",
        "kv",
        "operations",
        "uid_allocations",
        "usage_outbox",
    ]
    {
        assert!(
            tables.iter().any(|name| name == table),
            "missing table {table}"
        );
    }
}

#[test]
fn file_store_uses_wal_full_sync_and_busy_timeout()
{
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("state.db")).unwrap();
    let connection = store.connection();
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    assert_eq!(synchronous, 2);
    let timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(timeout, 5000);
}

#[test]
fn reopen_persists_data_and_does_not_rerun_migrations()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.db");
    {
        let store = Store::open(&path).unwrap();
        store.put_desired("srv-1", 1, b"spec-1").unwrap();
        store.update_actual("srv-1", &sample_actual()).unwrap();
        store.insert_usage(&usage_row("srv-1", 120)).unwrap();
        store.kv_set_u64("seq/out", 41).unwrap();
        store
            .begin_operation("op-1", "SnapshotNow", "srv-1")
            .unwrap();
        store
            .upsert_artifact(&artifact("sha256:aa", 10, 5))
            .unwrap();
        store.add_artifact_ref("sha256:aa", "srv-1").unwrap();
        store.allocate_uid("srv-1", 100_000, 10).unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    let instance = store.get_instance("srv-1").unwrap().unwrap();
    assert_eq!(instance.spec, b"spec-1");
    assert_eq!(instance.actual(), sample_actual());
    assert_eq!(
        store.pending_usage(10).unwrap(),
        vec![usage_row("srv-1", 120)]
    );
    assert_eq!(store.kv_get_u64("seq/out").unwrap(), Some(41));
    assert!(matches!(
        store.get_operation("op-1").unwrap().unwrap().status,
        OperationStatus::InProgress
    ));
    assert_eq!(store.artifact_ref_count("sha256:aa").unwrap(), 1);
    assert_eq!(store.allocate_uid("srv-1", 100_000, 10).unwrap(), 100_000);
}

#[test]
fn open_refuses_newer_schema()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.db");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "user_version", i64::from(SCHEMA_VERSION) + 1)
            .unwrap();
    }
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::SchemaTooNew { .. })
    ));
    assert!(matches!(
        Store::open_read_only(&path),
        Err(StoreError::SchemaTooNew { .. })
    ));
}

#[test]
fn read_only_open_reads_but_refuses_writes()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.db");
    let writer = Store::open(&path).unwrap();
    writer.put_desired("srv-1", 1, b"spec").unwrap();
    writer.kv_set("node/id", b"node-a").unwrap();

    let reader = Store::open_read_only(&path).unwrap();
    assert_eq!(reader.list_instances().unwrap().len(), 1);
    assert_eq!(reader.kv_get("node/id").unwrap(), Some(b"node-a".to_vec()));
    assert!(reader.kv_set("node/id", b"other").is_err());
    assert!(reader.put_desired("srv-2", 1, b"spec").is_err());
    assert!(reader.insert_usage(&usage_row("srv-1", 60)).is_err());
    assert_eq!(writer.kv_get("node/id").unwrap(), Some(b"node-a".to_vec()));
}

#[test]
fn read_only_open_refuses_unmigrated_database()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.db");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE unrelated (x INTEGER)")
        .unwrap();
    assert!(matches!(
        Store::open_read_only(&path),
        Err(StoreError::SchemaTooOld { found: 0, .. })
    ));
}

#[test]
fn read_only_open_of_missing_file_fails()
{
    let directory = tempfile::tempdir().unwrap();
    assert!(Store::open_read_only(&directory.path().join("absent.db")).is_err());
}

#[test]
fn read_only_open_works_after_writer_closed()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.db");
    {
        let writer = Store::open(&path).unwrap();
        writer.put_desired("srv-1", 1, b"spec").unwrap();
    }
    let reader = Store::open_read_only(&path).unwrap();
    assert_eq!(reader.get_instance("srv-1").unwrap().unwrap().spec, b"spec");
    assert!(reader.remove_instance("srv-1").is_err());
}

#[test]
fn put_desired_outcomes()
{
    let store = Store::open_in_memory().unwrap();
    assert_eq!(
        store.put_desired("srv-1", 2, b"a").unwrap(),
        PutOutcome::Inserted
    );
    assert_eq!(
        store.put_desired("srv-1", 2, b"a").unwrap(),
        PutOutcome::Unchanged
    );
    assert_eq!(
        store.put_desired("srv-1", 1, b"old").unwrap(),
        PutOutcome::Stale
    );
    assert_eq!(store.get_instance("srv-1").unwrap().unwrap().spec, b"a");
    assert_eq!(
        store.put_desired("srv-1", 2, b"b").unwrap(),
        PutOutcome::Updated
    );
    assert_eq!(
        store.put_desired("srv-1", 3, b"c").unwrap(),
        PutOutcome::Updated
    );
    let row = store.get_instance("srv-1").unwrap().unwrap();
    assert_eq!(row.generation, 3);
    assert_eq!(row.spec, b"c");
    assert_eq!(row.phase, "Pending");
    assert_eq!(row.observed_generation, 0);
}

#[test]
fn put_desired_keeps_actual_state()
{
    let store = Store::open_in_memory().unwrap();
    store.put_desired("srv-1", 1, b"a").unwrap();
    store.update_actual("srv-1", &sample_actual()).unwrap();
    store.put_desired("srv-1", 2, b"b").unwrap();
    assert_eq!(
        store.get_instance("srv-1").unwrap().unwrap().actual(),
        sample_actual()
    );
}

#[test]
fn put_desired_rejects_generation_beyond_i64()
{
    let store = Store::open_in_memory().unwrap();
    assert!(matches!(
        store.put_desired("srv-1", u64::MAX, b"a"),
        Err(StoreError::ValueOutOfRange(u64::MAX))
    ));
}

#[test]
fn mark_deleted_desired_is_idempotent_and_blocks_replayed_puts()
{
    let store = Store::open_in_memory().unwrap();
    assert!(!store.mark_deleted_desired("missing").unwrap());
    store.put_desired("srv-1", 4, b"a").unwrap();
    assert!(store.mark_deleted_desired("srv-1").unwrap());
    assert!(store.mark_deleted_desired("srv-1").unwrap());
    assert!(
        store
            .get_instance("srv-1")
            .unwrap()
            .unwrap()
            .desired_deleted
    );
    assert_eq!(
        store.put_desired("srv-1", 4, b"a").unwrap(),
        PutOutcome::Stale
    );
    assert_eq!(
        store.put_desired("srv-1", 3, b"a").unwrap(),
        PutOutcome::Stale
    );
    assert!(
        store
            .get_instance("srv-1")
            .unwrap()
            .unwrap()
            .desired_deleted
    );
    assert_eq!(
        store.put_desired("srv-1", 5, b"new").unwrap(),
        PutOutcome::Updated
    );
    let row = store.get_instance("srv-1").unwrap().unwrap();
    assert!(!row.desired_deleted);
    assert_eq!(row.generation, 5);
}

#[test]
fn update_actual_requires_existing_instance()
{
    let store = Store::open_in_memory().unwrap();
    assert!(matches!(
        store.update_actual("missing", &ActualState::default()),
        Err(StoreError::InstanceNotFound(id)) if id == "missing"
    ));
    store.put_desired("srv-1", 1, b"a").unwrap();
    store.update_actual("srv-1", &sample_actual()).unwrap();
    store.update_actual("srv-1", &sample_actual()).unwrap();
    let mut cleared = sample_actual();
    cleared.pid = None;
    cleared.api_socket = None;
    store.update_actual("srv-1", &cleared).unwrap();
    assert_eq!(
        store.get_instance("srv-1").unwrap().unwrap().actual(),
        cleared
    );
}

#[test]
fn list_and_remove_instances()
{
    let store = Store::open_in_memory().unwrap();
    store.put_desired("srv-b", 1, b"b").unwrap();
    store.put_desired("srv-a", 1, b"a").unwrap();
    let ids: Vec<String> = store
        .list_instances()
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(ids, ["srv-a", "srv-b"]);
    store.remove_instance("srv-a").unwrap();
    store.remove_instance("srv-a").unwrap();
    assert!(store.get_instance("srv-a").unwrap().is_none());
    assert_eq!(store.list_instances().unwrap().len(), 1);
}

#[test]
fn remove_instance_releases_uid_and_artifact_refs()
{
    let store = Store::open_in_memory().unwrap();
    store.put_desired("srv-1", 1, b"a").unwrap();
    store.allocate_uid("srv-1", 1000, 5).unwrap();
    store.add_artifact_ref("sha256:aa", "srv-1").unwrap();
    store.remove_instance("srv-1").unwrap();
    assert_eq!(store.artifact_ref_count("sha256:aa").unwrap(), 0);
    assert_eq!(store.allocate_uid("srv-2", 1000, 5).unwrap(), 1000);
}

#[test]
fn allocate_uid_is_unique_idempotent_and_reuses_freed_ids()
{
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.allocate_uid("a", 1000, 3).unwrap(), 1000);
    assert_eq!(store.allocate_uid("b", 1000, 3).unwrap(), 1001);
    assert_eq!(store.allocate_uid("a", 1000, 3).unwrap(), 1000);
    assert_eq!(store.allocate_uid("c", 1000, 3).unwrap(), 1002);
    assert!(matches!(
        store.allocate_uid("d", 1000, 3),
        Err(StoreError::UidRangeExhausted {
            base: 1000,
            count: 3
        })
    ));
    store.remove_instance("b").unwrap();
    assert_eq!(store.allocate_uid("d", 1000, 3).unwrap(), 1001);
}

#[test]
fn allocate_uid_rejects_invalid_ranges()
{
    let store = Store::open_in_memory().unwrap();
    assert!(matches!(
        store.allocate_uid("a", 1000, 0),
        Err(StoreError::InvalidUidRange { .. })
    ));
    assert!(matches!(
        store.allocate_uid("a", u32::MAX, 2),
        Err(StoreError::InvalidUidRange { .. })
    ));
    assert_eq!(store.allocate_uid("a", u32::MAX, 1).unwrap(), u32::MAX);
}

#[test]
fn begin_operation_replays_stored_state()
{
    let store = Store::open_in_memory().unwrap();
    assert_eq!(
        store
            .begin_operation("op-1", "SnapshotNow", "srv-1")
            .unwrap(),
        BeginOperation::Started
    );
    let BeginOperation::InProgress(row) = store
        .begin_operation("op-1", "SnapshotNow", "srv-1")
        .unwrap()
    else
    {
        panic!("expected in progress");
    };
    assert_eq!(row.kind, "SnapshotNow");
    assert_eq!(row.instance_id, "srv-1");
    assert_eq!(row.status, OperationStatus::InProgress);
    assert!(row.finished_at_unix.is_none());

    store
        .finish_operation("op-1", true, "snapshot uploaded", b"manifest")
        .unwrap();
    let BeginOperation::Finished(row) = store
        .begin_operation("op-1", "SnapshotNow", "srv-1")
        .unwrap()
    else
    {
        panic!("expected finished");
    };
    assert_eq!(row.status, OperationStatus::Succeeded);
    assert_eq!(row.message, "snapshot uploaded");
    assert_eq!(row.payload, b"manifest");
    assert!(row.finished_at_unix.is_some());
}

#[test]
fn finish_operation_keeps_first_result()
{
    let store = Store::open_in_memory().unwrap();
    store.begin_operation("op-1", "Drain", "srv-1").unwrap();
    store
        .finish_operation("op-1", false, "guest timeout", b"")
        .unwrap();
    store
        .finish_operation("op-1", true, "late success", b"x")
        .unwrap();
    let row = store.get_operation("op-1").unwrap().unwrap();
    assert_eq!(row.status, OperationStatus::Failed);
    assert_eq!(row.message, "guest timeout");
    assert!(row.payload.is_empty());
    assert!(matches!(
        store.finish_operation("missing", true, "", b""),
        Err(StoreError::OperationNotFound(_))
    ));
    assert!(store.get_operation("missing").unwrap().is_none());
}

#[test]
fn list_operations_filters_by_status()
{
    let store = Store::open_in_memory().unwrap();
    store.begin_operation("op-1", "Drain", "srv-1").unwrap();
    store
        .begin_operation("op-2", "SnapshotNow", "srv-1")
        .unwrap();
    store
        .begin_operation("op-3", "CollectDiagnostics", "srv-2")
        .unwrap();
    store.finish_operation("op-2", true, "", b"").unwrap();
    store.finish_operation("op-3", false, "", b"").unwrap();
    let ids = |status| -> Vec<String> {
        store
            .list_operations(status)
            .unwrap()
            .into_iter()
            .map(|row| row.op_id)
            .collect()
    };
    assert_eq!(ids(None), ["op-1", "op-2", "op-3"]);
    assert_eq!(ids(Some(OperationStatus::InProgress)), ["op-1"]);
    assert_eq!(ids(Some(OperationStatus::Succeeded)), ["op-2"]);
    assert_eq!(ids(Some(OperationStatus::Failed)), ["op-3"]);
}

#[test]
fn insert_usage_is_idempotent_and_never_overwrites()
{
    let store = Store::open_in_memory().unwrap();
    let record = usage_row("srv-1", 60);
    assert!(store.insert_usage(&record).unwrap());
    assert!(!store.insert_usage(&record).unwrap());
    let mut changed = record.clone();
    changed.cpu_usec = 1;
    assert!(!store.insert_usage(&changed).unwrap());
    assert_eq!(store.pending_usage(10).unwrap(), vec![record]);
    assert_eq!(store.usage_depth().unwrap(), 1);
}

#[test]
fn pending_usage_is_ordered_and_limited()
{
    let store = Store::open_in_memory().unwrap();
    for (instance, start) in [
        ("srv-b", 120),
        ("srv-a", 120),
        ("srv-c", 60),
        ("srv-a", 180),
    ]
    {
        store.insert_usage(&usage_row(instance, start)).unwrap();
    }
    let ids: Vec<String> = store
        .pending_usage(10)
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(ids, ["srv-c:60", "srv-a:120", "srv-b:120", "srv-a:180"]);
    assert_eq!(store.pending_usage(2).unwrap().len(), 2);
    assert_eq!(store.pending_usage(0).unwrap().len(), 0);
}

#[test]
fn delete_usage_counts_only_existing_rows()
{
    let store = Store::open_in_memory().unwrap();
    store.insert_usage(&usage_row("srv-1", 60)).unwrap();
    store.insert_usage(&usage_row("srv-1", 120)).unwrap();
    let ids = vec!["srv-1:60".to_string(), "srv-1:999".to_string()];
    assert_eq!(store.delete_usage(&ids).unwrap(), 1);
    assert_eq!(store.delete_usage(&ids).unwrap(), 0);
    assert_eq!(store.usage_depth().unwrap(), 1);
    assert_eq!(store.delete_usage(&[]).unwrap(), 0);
}

#[test]
fn artifact_index_and_refcounts()
{
    let store = Store::open_in_memory().unwrap();
    assert!(store.get_artifact("sha256:aa").unwrap().is_none());
    store
        .upsert_artifact(&artifact("sha256:aa", 100, 10))
        .unwrap();
    store
        .upsert_artifact(&artifact("sha256:bb", 200, 5))
        .unwrap();
    store
        .upsert_artifact(&artifact("sha256:cc", 300, 20))
        .unwrap();
    let mut updated = artifact("sha256:aa", 150, 10);
    updated.verified = false;
    store.upsert_artifact(&updated).unwrap();
    assert_eq!(store.get_artifact("sha256:aa").unwrap(), Some(updated));
    assert_eq!(store.total_artifact_bytes().unwrap(), 650);

    store.add_artifact_ref("sha256:bb", "srv-1").unwrap();
    store.add_artifact_ref("sha256:bb", "srv-1").unwrap();
    store.add_artifact_ref("sha256:bb", "srv-2").unwrap();
    assert_eq!(store.artifact_ref_count("sha256:bb").unwrap(), 2);
    store.remove_artifact_ref("sha256:bb", "srv-1").unwrap();
    store.remove_artifact_ref("sha256:bb", "srv-1").unwrap();
    assert_eq!(store.artifact_ref_count("sha256:bb").unwrap(), 1);

    let lru: Vec<String> = store
        .unreferenced_artifacts_lru()
        .unwrap()
        .into_iter()
        .map(|row| row.digest)
        .collect();
    assert_eq!(lru, ["sha256:aa", "sha256:cc"]);

    store.touch_artifact("sha256:aa", 30).unwrap();
    let lru: Vec<String> = store
        .unreferenced_artifacts_lru()
        .unwrap()
        .into_iter()
        .map(|row| row.digest)
        .collect();
    assert_eq!(lru, ["sha256:cc", "sha256:aa"]);
    assert!(matches!(
        store.touch_artifact("sha256:zz", 1),
        Err(StoreError::ArtifactNotFound(_))
    ));

    assert!(matches!(
        store.delete_artifact("sha256:bb"),
        Err(StoreError::ArtifactReferenced(_))
    ));
    store.remove_instance_artifact_refs("srv-2").unwrap();
    store.remove_instance_artifact_refs("srv-2").unwrap();
    assert_eq!(store.artifact_ref_count("sha256:bb").unwrap(), 0);
    store.delete_artifact("sha256:bb").unwrap();
    store.delete_artifact("sha256:bb").unwrap();
    assert!(store.get_artifact("sha256:bb").unwrap().is_none());
    assert_eq!(store.total_artifact_bytes().unwrap(), 450);
}

#[test]
fn empty_artifact_index_totals_zero()
{
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.total_artifact_bytes().unwrap(), 0);
    assert!(store.unreferenced_artifacts_lru().unwrap().is_empty());
    assert_eq!(store.artifact_ref_count("sha256:aa").unwrap(), 0);
}

#[test]
fn kv_round_trips()
{
    let store = Store::open_in_memory().unwrap();
    assert!(store.kv_get("node/id").unwrap().is_none());
    store.kv_set("node/id", b"node-a").unwrap();
    store.kv_set("node/id", b"node-b").unwrap();
    assert_eq!(store.kv_get("node/id").unwrap(), Some(b"node-b".to_vec()));
    store.kv_delete("node/id").unwrap();
    store.kv_delete("node/id").unwrap();
    assert!(store.kv_get("node/id").unwrap().is_none());

    assert!(store.kv_get_u64("seq").unwrap().is_none());
    store.kv_set_u64("seq", u64::MAX).unwrap();
    assert_eq!(store.kv_get_u64("seq").unwrap(), Some(u64::MAX));
    store.kv_set("seq", b"not a number").unwrap();
    assert!(matches!(
        store.kv_get_u64("seq"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn kv_list_prefix_returns_only_matching_keys_in_order()
{
    let store = Store::open_in_memory().unwrap();
    for key in [
        "lease/b",
        "lease/a",
        "leasex",
        "lease",
        "node/id",
        "lease/c/d",
    ]
    {
        store.kv_set(key, key.as_bytes()).unwrap();
    }
    let keys: Vec<String> = store
        .kv_list_prefix("lease/")
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    assert_eq!(keys, ["lease/a", "lease/b", "lease/c/d"]);
    assert_eq!(store.kv_list_prefix("").unwrap().len(), 6);
    assert!(store.kv_list_prefix("zzz").unwrap().is_empty());
}

#[test]
fn store_is_usable_across_threads()
{
    let store = Arc::new(Store::open_in_memory().unwrap());
    let threads: Vec<_> = (0..4)
        .map(|thread| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for minute in 0..25
                {
                    store
                        .insert_usage(&usage_row(&format!("srv-{thread}"), minute * 60))
                        .unwrap();
                }
            })
        })
        .collect();
    for thread in threads
    {
        thread.join().unwrap();
    }
    assert_eq!(store.usage_depth().unwrap(), 100);
}
