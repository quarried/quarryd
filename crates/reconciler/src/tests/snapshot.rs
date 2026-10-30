use std::io::{Read, Seek, SeekFrom, Write};

use proto::v1::{Lease, Phase, SnapshotRef};
use volume::SnapshotManifest;

use super::*;
use crate::ReconcilerError;

const MARKERS: [(u64, &[u8]); 2] = [
    (4096, b"level.dat contents"),
    (300 << 20, b"region r.0.0.mca"),
];

fn volume_path(fixture: &Fixture, id: &str) -> PathBuf
{
    fixture
        .path("volumes")
        .join(format!("{}.img", volume_name(id, "data")))
}

fn write_markers(path: &std::path::Path)
{
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    for (offset, content) in MARKERS
    {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(content).unwrap();
    }
    file.sync_all().unwrap();
}

fn read_markers(path: &std::path::Path) -> Vec<Vec<u8>>
{
    let mut file = std::fs::File::open(path).unwrap();
    MARKERS
        .iter()
        .map(|(offset, content)| {
            let mut buffer = vec![0u8; content.len()];
            file.seek(SeekFrom::Start(*offset)).unwrap();
            file.read_exact(&mut buffer).unwrap();
            buffer
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshots_are_world_consistent_and_restorable()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let source = "snap-src";
    let mut spec = fixture.spec(source, "normal");
    spec.lease = Some(Lease {
        epoch: 7,
        ttl_ms: 60_000,
    });
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(source, 1).await;
    let pid = fixture.last_pid(source).unwrap();
    write_markers(&volume_path(&fixture, source));

    let prefix = "snapshots/world-1/0001";
    let key = node.handle.snapshot_now(source, prefix).await.unwrap();
    assert_eq!(key, "snapshots/world-1/0001/manifest.json");

    let stored = fixture
        .snapshot_objects
        .get(&ObjectPath::from(key.as_str()))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let manifest: SnapshotManifest = serde_json::from_slice(&stored).unwrap();
    assert_eq!(manifest.lease_epoch, 7);
    assert_eq!(manifest.source, volume_name(source, "data"));
    assert_eq!(manifest.total_size, GIB);
    assert_eq!(
        manifest.chunks.iter().filter(|c| c.key.is_some()).count(),
        2
    );

    let trace = fixture.trace(source);
    let prepared = trace.iter().position(|l| l == "prepare-snapshot").unwrap();
    let resumed = trace.iter().position(|l| l == "resume-writes").unwrap();
    assert!(prepared < resumed, "{trace:?}");
    assert_eq!(
        fixture.volume_files(),
        vec![format!("{}.img", volume_name(source, "data"))]
    );
    assert_eq!(
        node.status(source).map(|s| phase_of(&s)),
        Some(Phase::Running)
    );
    assert_eq!(fixture.last_pid(source), Some(pid));
    assert!(process_alive(pid));

    let restored = "snap-dst";
    let mut spec = fixture.spec(restored, "normal");
    spec.disks[0].restore_from = Some(SnapshotRef {
        manifest_key: key.clone(),
    });
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(restored, 1).await;
    let expected: Vec<Vec<u8>> = MARKERS.iter().map(|(_, c)| c.to_vec()).collect();
    assert_eq!(read_markers(&volume_path(&fixture, restored)), expected);
    let restore_marker = fixture
        .store
        .kv_get(&format!(
            "reconciler/restore/{}",
            volume_name(restored, "data")
        ))
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&restore_marker).starts_with("done:"));

    match node.handle.snapshot_now("snap-none", prefix).await
    {
        Err(ReconcilerError::InstanceNotFound(id)) => assert_eq!(id, "snap-none"),
        other => panic!("unexpected result {other:?}"),
    }

    for id in [source, restored]
    {
        node.handle.delete_instance(id).await.unwrap();
    }
    for id in [source, restored]
    {
        node.wait_gone(id, &fixture.store).await;
    }
    assert!(fixture.volume_files().is_empty());
    assert!(
        fixture
            .store
            .kv_get(&format!(
                "reconciler/restore/{}",
                volume_name(restored, "data")
            ))
            .unwrap()
            .is_none()
    );
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshots_require_a_running_instance_with_a_connected_guest()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "snap-stop";
    let mut spec = fixture.spec(id, "normal");
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    spec.generation = 2;
    spec.run_state = RunState::Stopped as i32;
    node.handle.put_instance(spec).await.unwrap();
    node.wait_phase(id, Phase::Stopped).await;
    match node.handle.snapshot_now(id, "snapshots/x").await
    {
        Err(ReconcilerError::NotRunning { phase, .. }) => assert_eq!(phase, Phase::Stopped),
        other => panic!("unexpected result {other:?}"),
    }
    assert!(
        fixture
            .snapshot_objects
            .get(&ObjectPath::from("snapshots/x/manifest.json"))
            .await
            .is_err()
    );
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_work_cannot_outlive_the_guest_freeze_deadline()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "snap-freeze-deadline";
    node.handle
        .put_instance(fixture.spec(id, "normal"))
        .await
        .unwrap();
    node.wait_running(id, 1).await;
    crash::arm(id, "after-snapshot-prepared");
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        node.handle.snapshot_now(id, "deadline-expired"),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "snapshot must fail within the freeze budget: {result:?}"
    );
    assert!(crash::was_hit(id, "after-snapshot-prepared"));
    fixture.wait_trace(id, "resume-writes").await;
    assert!(
        fixture
            .snapshot_objects
            .get(&ObjectPath::from("deadline-expired/manifest.json"))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.volume_files(),
        vec![format!("{}.img", volume_name(id, "data"))]
    );
    assert!(process_alive(fixture.last_pid(id).unwrap()));
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_acknowledgement_from_a_previous_request_cannot_authorize_a_snapshot()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "snap-stale-ack";
    node.handle
        .put_instance(fixture.spec(id, "stale-snapshot"))
        .await
        .unwrap();
    node.wait_running(id, 1).await;
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        node.handle.snapshot_now(id, "stale-ack"),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "an unrelated preparation ack was accepted: {result:?}"
    );
    fixture.wait_trace(id, "resume-writes").await;
    assert!(
        fixture
            .snapshot_objects
            .get(&ObjectPath::from("stale-ack/manifest.json"))
            .await
            .is_err()
    );
    assert_eq!(
        fixture.volume_files(),
        vec![format!("{}.img", volume_name(id, "data"))]
    );
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}
