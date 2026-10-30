use std::io::{Read, Seek, SeekFrom, Write};

use prost::Message;
use volume::Volume;

use super::*;
use crate::admission::legacy_volume_name;

fn write_marker(path: &std::path::Path, marker: &[u8])
{
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(4096)).unwrap();
    file.write_all(marker).unwrap();
    file.sync_all().unwrap();
}

fn assert_marker(path: &std::path::Path, marker: &[u8])
{
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::Start(4096)).unwrap();
    let mut actual = vec![0; marker.len()];
    file.read_exact(&mut actual).unwrap();
    assert_eq!(actual, marker);
}

fn persist_legacy_spec(fixture: &Fixture, spec: &InstanceSpec)
{
    fixture
        .store
        .put_desired_with_lease(
            &spec.id,
            spec.generation,
            &spec.encode_to_vec(),
            Some((1, crate::leases::unix_ms_now() + 60_000)),
        )
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn colliding_legacy_names_have_separate_disks_and_deletion_preserves_the_other_world()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let mut first = fixture.spec("disk-a-b", "normal");
    first.disks[0].name = "c".to_owned();
    let mut second = fixture.spec("disk-a", "normal");
    second.disks[0].name = "b-c".to_owned();
    assert_eq!(
        legacy_volume_name(&first.id, "c"),
        legacy_volume_name(&second.id, "b-c")
    );
    node.handle.put_instance(first.clone()).await.unwrap();
    node.handle.put_instance(second.clone()).await.unwrap();
    node.wait_running(&first.id, 1).await;
    node.wait_running(&second.id, 1).await;
    let first_name = fixture.store.disk_binding(&first.id, "c").unwrap().unwrap();
    let second_name = fixture
        .store
        .disk_binding(&second.id, "b-c")
        .unwrap()
        .unwrap();
    assert_ne!(first_name, second_name);
    let second_path = fixture.path("volumes").join(format!("{second_name}.img"));
    write_marker(&second_path, b"second tenant world");
    node.handle.delete_instance(&first.id).await.unwrap();
    node.wait_gone(&first.id, &fixture.store).await;
    assert_marker(&second_path, b"second tenant world");
    node.stop().await;
    let node = fixture.start().await;
    node.wait_running(&second.id, 1).await;
    assert_eq!(
        fixture.store.disk_binding(&second.id, "b-c").unwrap(),
        Some(second_name)
    );
    assert_marker(&second_path, b"second tenant world");
    node.handle.delete_instance(&second.id).await.unwrap();
    node.wait_gone(&second.id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_world_is_bound_in_place_across_restart_and_deleted_by_its_real_name()
{
    let fixture = Fixture::new().await;
    let spec = fixture.spec("legacy-world", "normal");
    let legacy = legacy_volume_name(&spec.id, "data");
    let volume = FileVolume::new(fixture.path("volumes"), fixture.volume_capacity)
        .create(&legacy, GIB)
        .await
        .unwrap();
    write_marker(&volume.path, b"existing world must survive upgrade");
    persist_legacy_spec(&fixture, &spec);
    fixture.store.remember_disk(&spec.id, &legacy).unwrap();
    let node = fixture.start().await;
    node.configure().await;
    node.wait_running(&spec.id, 1).await;
    assert_eq!(
        fixture.store.disk_binding(&spec.id, "data").unwrap(),
        Some(legacy.clone())
    );
    assert_eq!(fixture.volume_files(), [format!("{legacy}.img")]);
    assert_marker(&volume.path, b"existing world must survive upgrade");
    node.stop().await;
    let node = fixture.start().await;
    node.wait_running(&spec.id, 1).await;
    assert_marker(&volume.path, b"existing world must survive upgrade");
    node.handle.delete_instance(&spec.id).await.unwrap();
    node.wait_gone(&spec.id, &fixture.store).await;
    assert!(!volume.path.exists());
    assert_eq!(fixture.store.disk_binding(&spec.id, "data").unwrap(), None);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ambiguous_legacy_world_is_quarantined_before_any_boot_or_delete()
{
    let fixture = Fixture::new().await;
    let mut first = fixture.spec("ambiguous-a-b", "normal");
    first.disks[0].name = "c".to_owned();
    let mut second = fixture.spec("ambiguous-a", "normal");
    second.disks[0].name = "b-c".to_owned();
    let legacy = legacy_volume_name(&first.id, "c");
    let volume = FileVolume::new(fixture.path("volumes"), fixture.volume_capacity)
        .create(&legacy, GIB)
        .await
        .unwrap();
    write_marker(&volume.path, b"ambiguous world retained");
    persist_legacy_spec(&fixture, &first);
    persist_legacy_spec(&fixture, &second);
    // Old crashes could leave only one inventory row even though both specs
    // refer to this name. Removing the other desired row must not erase proof.
    fixture.store.remember_disk(&first.id, &legacy).unwrap();
    let node = fixture.start().await;
    node.configure().await;
    node.wait_phase(&first.id, Phase::Rejected).await;
    node.wait_phase(&second.id, Phase::Rejected).await;
    assert_eq!(fixture.starts(&first.id), 0);
    assert_eq!(fixture.starts(&second.id), 0);
    assert!(
        fixture
            .store
            .disk_binding(&first.id, "c")
            .unwrap()
            .is_none()
    );
    node.handle.delete_instance(&second.id).await.unwrap();
    node.wait_gone(&second.id, &fixture.store).await;
    node.handle.delete_instance(&first.id).await.unwrap();
    sleep_ms(300).await;
    assert!(fixture.store.assert_disk_owner(&first.id, &legacy).is_err());
    assert_marker(&volume.path, b"ambiguous world retained");
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unowned_legacy_volume_cannot_be_claimed_by_a_new_spec()
{
    let fixture = Fixture::new().await;
    let spec = fixture.spec("unowned-world", "normal");
    let legacy = legacy_volume_name(&spec.id, "data");
    let volume = FileVolume::new(fixture.path("volumes"), fixture.volume_capacity)
        .create(&legacy, GIB)
        .await
        .unwrap();
    write_marker(
        &volume.path,
        b"unowned data must not be attached or removed",
    );
    let node = fixture.start().await;
    node.configure().await;
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_phase(&spec.id, Phase::Failed).await;
    assert_eq!(fixture.starts(&spec.id), 0);
    assert_eq!(fixture.store.disk_binding(&spec.id, "data").unwrap(), None);
    node.handle.delete_instance(&spec.id).await.unwrap();
    node.wait_gone(&spec.id, &fixture.store).await;
    assert_marker(
        &volume.path,
        b"unowned data must not be attached or removed",
    );
    assert!(fixture.store.claim_disk(&spec.id, "data", &legacy).is_err());
    node.stop().await;
}
