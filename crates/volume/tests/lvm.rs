use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use object_store::local::LocalFileSystem;
use volume::{LvmThin, SnapshotStore, Volume, VolumeKind};

const MIB: u64 = 1024 * 1024;
const EXT4_MAGIC_OFFSET: u64 = 1024 + 0x38;

fn backend() -> LvmThin
{
    let volume_group =
        std::env::var("QUARRY_TEST_VG").expect("QUARRY_TEST_VG names the test volume group");
    let thin_pool =
        std::env::var("QUARRY_TEST_THIN_POOL").expect("QUARRY_TEST_THIN_POOL names the thin pool");
    LvmThin::new(volume_group, thin_pool)
}

fn unique(name: &str) -> String
{
    format!("quarry-test-{}-{name}", std::process::id())
}

fn read_at(path: &Path, offset: u64, length: usize) -> Vec<u8>
{
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer).unwrap();
    buffer
}

fn write_at(path: &Path, offset: u64, data: &[u8])
{
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(data).unwrap();
    file.sync_all().unwrap();
}

fn has_ext4_magic(path: &Path) -> bool
{
    read_at(path, EXT4_MAGIC_OFFSET, 2) == [0x53, 0xef]
}

#[tokio::test]
#[ignore = "needs root and an LVM thin pool named by QUARRY_TEST_VG / QUARRY_TEST_THIN_POOL"]
async fn lvm_thin_create_snapshot_delete_and_pool_usage()
{
    let lvm = backend();
    assert_eq!(lvm.kind(), VolumeKind::LvmThin);
    let name = unique("vol");
    let snapshot_name = unique("snap");
    let blank_name = unique("blank");

    let created = lvm.create(&name, 64 * MIB).await.unwrap();
    assert_eq!(created.name, name);
    assert!(created.size_bytes >= 64 * MIB);
    assert_eq!(
        created.path,
        Path::new("/dev").join(lvm.volume_group()).join(&name)
    );
    assert!(has_ext4_magic(&created.path));
    assert_eq!(lvm.create(&name, 64 * MIB).await.unwrap(), created);
    assert_eq!(lvm.get(&name).await.unwrap(), Some(created.clone()));
    assert!(lvm.list().await.unwrap().contains(&created));

    let blank = lvm.create_blank(&blank_name, 16 * MIB).await.unwrap();
    assert!(!has_ext4_magic(&blank.path));
    assert_eq!(
        lvm.create_blank(&blank_name, 16 * MIB).await.unwrap(),
        blank
    );

    let marker = b"quarry snapshot marker";
    write_at(&created.path, 32 * MIB, marker);
    let snapshot = lvm.snapshot(&name, &snapshot_name).await.unwrap();
    assert_eq!(snapshot.size_bytes, created.size_bytes);
    assert_eq!(read_at(&snapshot.path, 32 * MIB, marker.len()), marker);
    assert!(has_ext4_magic(&snapshot.path));
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&snapshot.path)
            .is_err()
    );
    assert_eq!(lvm.snapshot(&name, &snapshot_name).await.unwrap(), snapshot);

    write_at(&created.path, 32 * MIB, b"changed after the snapshot");
    assert_eq!(read_at(&snapshot.path, 32 * MIB, marker.len()), marker);

    let usage = lvm.pool_usage().await.unwrap();
    assert!(usage.size_bytes > 0);
    assert!((0.0..=100.0).contains(&usage.used_percent));

    for volume in [&snapshot_name, &name, &blank_name]
    {
        lvm.delete(volume).await.unwrap();
        lvm.delete(volume).await.unwrap();
        assert_eq!(lvm.get(volume).await.unwrap(), None);
    }
}

#[tokio::test]
#[ignore = "needs root and an LVM thin pool named by QUARRY_TEST_VG / QUARRY_TEST_THIN_POOL"]
async fn lvm_snapshot_upload_restore_end_to_end()
{
    let lvm = backend();
    let origin_name = unique("e2e-origin");
    let snapshot_name = unique("e2e-snap");
    let restored_name = unique("e2e-restored");
    let bucket = tempfile::tempdir().unwrap();

    let origin = lvm.create(&origin_name, 64 * MIB).await.unwrap();
    write_at(
        &origin.path,
        8 * MIB + 17,
        b"world data that must survive the round trip",
    );
    write_at(&origin.path, 63 * MIB, &vec![0xa5u8; 4096]);
    let snapshot = lvm.snapshot(&origin_name, &snapshot_name).await.unwrap();

    let store = Arc::new(LocalFileSystem::new_with_prefix(bucket.path()).unwrap());
    let snapshots = SnapshotStore::new(store, 4 * MIB, 4);
    let manifest = snapshots
        .upload(&snapshot.path, "worlds/e2e", &origin_name, 1)
        .await
        .unwrap();
    assert_eq!(manifest.total_size, snapshot.size_bytes);
    assert!(manifest.chunks.iter().any(|chunk| chunk.key.is_none()));

    let restored = lvm
        .create_blank(&restored_name, snapshot.size_bytes)
        .await
        .unwrap();
    snapshots
        .restore(&SnapshotStore::manifest_key("worlds/e2e"), &restored.path)
        .await
        .unwrap();
    let length = usize::try_from(snapshot.size_bytes).unwrap();
    assert_eq!(
        read_at(&restored.path, 0, length),
        read_at(&snapshot.path, 0, length)
    );
    assert!(has_ext4_magic(&restored.path));

    for volume in [&restored_name, &snapshot_name, &origin_name]
    {
        lvm.delete(volume).await.unwrap();
    }
}
