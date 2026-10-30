use std::io::{Seek, SeekFrom, Write};

use volume::{FileVolume, Volume, VolumeError, VolumeKind};

const MIB: u64 = 1024 * 1024;

fn fixture() -> (tempfile::TempDir, FileVolume)
{
    let dir = tempfile::tempdir().unwrap();
    let volumes = FileVolume::new(dir.path().join("volumes"), 100 * MIB);
    (dir, volumes)
}

#[tokio::test]
async fn create_is_idempotent_and_sparse()
{
    let (_dir, volumes) = fixture();
    assert_eq!(volumes.kind(), VolumeKind::File);
    let created = volumes.create("world-1", 8 * MIB).await.unwrap();
    assert_eq!(created.name, "world-1");
    assert_eq!(created.size_bytes, 8 * MIB);
    assert_eq!(std::fs::metadata(&created.path).unwrap().len(), 8 * MIB);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&created.path)
        .unwrap();
    file.seek(SeekFrom::Start(4096)).unwrap();
    file.write_all(b"level.dat").unwrap();
    drop(file);

    let again = volumes.create("world-1", 16 * MIB).await.unwrap();
    assert_eq!(again, created);
    let contents = std::fs::read(&created.path).unwrap();
    assert_eq!(&contents[4096..4105], b"level.dat");

    let blank = volumes.create_blank("restore-1", 2 * MIB).await.unwrap();
    assert_eq!(
        volumes.create_blank("restore-1", 2 * MIB).await.unwrap(),
        blank
    );
}

#[tokio::test]
async fn get_and_list_report_volumes()
{
    let (_dir, volumes) = fixture();
    assert_eq!(volumes.get("missing").await.unwrap(), None);
    assert!(volumes.list().await.unwrap().is_empty());

    let b = volumes.create("b", MIB).await.unwrap();
    let a = volumes.create("a", 2 * MIB).await.unwrap();
    assert_eq!(volumes.get("a").await.unwrap(), Some(a.clone()));
    assert_eq!(volumes.list().await.unwrap(), vec![a, b]);
}

#[tokio::test]
async fn delete_is_idempotent()
{
    let (_dir, volumes) = fixture();
    let created = volumes.create("world-1", MIB).await.unwrap();
    volumes.delete("world-1").await.unwrap();
    assert!(!created.path.exists());
    assert_eq!(volumes.get("world-1").await.unwrap(), None);
    volumes.delete("world-1").await.unwrap();
    volumes.delete("never-existed").await.unwrap();
}

#[tokio::test]
async fn snapshot_copies_read_only_and_is_idempotent()
{
    let (_dir, volumes) = fixture();
    let origin = volumes.create("world-1", MIB).await.unwrap();
    std::fs::write(&origin.path, vec![7u8; MIB as usize]).unwrap();

    let snapshot = volumes.snapshot("world-1", "world-1-snap").await.unwrap();
    assert_eq!(snapshot.size_bytes, MIB);
    assert!(
        std::fs::metadata(&snapshot.path)
            .unwrap()
            .permissions()
            .readonly()
    );
    assert_eq!(
        std::fs::read(&snapshot.path).unwrap(),
        vec![7u8; MIB as usize]
    );

    std::fs::write(&origin.path, vec![9u8; MIB as usize]).unwrap();
    let again = volumes.snapshot("world-1", "world-1-snap").await.unwrap();
    assert_eq!(again, snapshot);
    assert_eq!(
        std::fs::read(&snapshot.path).unwrap(),
        vec![7u8; MIB as usize]
    );

    let names: Vec<String> = volumes
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, vec!["world-1".to_owned(), "world-1-snap".to_owned()]);

    volumes.delete("world-1-snap").await.unwrap();
    volumes.delete("world-1-snap").await.unwrap();
    assert_eq!(volumes.get("world-1-snap").await.unwrap(), None);
}

#[tokio::test]
async fn snapshot_of_missing_volume_fails()
{
    let (_dir, volumes) = fixture();
    let error = volumes
        .snapshot("missing", "missing-snap")
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::NotFound { name } if name == "missing"));
}

#[tokio::test]
async fn rejects_unsafe_names()
{
    let (_dir, volumes) = fixture();
    for name in ["", "../escape", "a/b", "-flag", ".hidden"]
    {
        assert!(matches!(
            volumes.create(name, MIB).await,
            Err(VolumeError::InvalidName { .. })
        ));
    }
}

#[tokio::test]
async fn pool_usage_is_nominal_size_over_capacity()
{
    let (_dir, volumes) = fixture();
    let empty = volumes.pool_usage().await.unwrap();
    assert_eq!(empty.size_bytes, 100 * MIB);
    assert_eq!(empty.used_percent, 0.0);

    volumes.create("a", 25 * MIB).await.unwrap();
    volumes.create("b", 10 * MIB).await.unwrap();
    let usage = volumes.pool_usage().await.unwrap();
    assert!((usage.used_percent - 35.0).abs() < 1e-9);
}
