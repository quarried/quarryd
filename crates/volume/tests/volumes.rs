use std::sync::Arc;

use volume::{FileVolume, PoolAlert, Volume, VolumeError, Volumes};

const MIB: u64 = 1024 * 1024;

fn fixture() -> (tempfile::TempDir, Arc<FileVolume>, Volumes)
{
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FileVolume::new(dir.path().to_path_buf(), 100 * MIB));
    let volumes = Volumes::new(backend.clone());
    (dir, backend, volumes)
}

#[test]
fn alert_thresholds()
{
    assert_eq!(PoolAlert::from_used_percent(0.0), PoolAlert::Normal);
    assert_eq!(PoolAlert::from_used_percent(79.99), PoolAlert::Normal);
    assert_eq!(PoolAlert::from_used_percent(80.0), PoolAlert::Warning);
    assert_eq!(PoolAlert::from_used_percent(89.99), PoolAlert::Warning);
    assert_eq!(PoolAlert::from_used_percent(90.0), PoolAlert::Critical);
    assert_eq!(PoolAlert::from_used_percent(100.0), PoolAlert::Critical);
}

#[tokio::test]
async fn ensure_is_idempotent_and_exposes_backend()
{
    let (_dir, backend, volumes) = fixture();
    let created = volumes.ensure("world-1", 10 * MIB).await.unwrap();
    assert_eq!(volumes.ensure("world-1", 10 * MIB).await.unwrap(), created);
    assert_eq!(
        volumes.backend().get("world-1").await.unwrap(),
        Some(created.clone())
    );
    assert_eq!(backend.list().await.unwrap(), vec![created]);

    let blank = volumes.ensure_blank("restore-1", MIB).await.unwrap();
    assert_eq!(volumes.ensure_blank("restore-1", MIB).await.unwrap(), blank);

    volumes.remove("world-1").await.unwrap();
    volumes.remove("world-1").await.unwrap();
    assert_eq!(backend.get("world-1").await.unwrap(), None);
}

#[tokio::test]
async fn refuses_new_volumes_at_ninety_percent_but_returns_existing()
{
    let (_dir, _backend, volumes) = fixture();
    let existing = volumes.ensure("existing", 85 * MIB).await.unwrap();
    volumes.ensure("small", 4 * MIB).await.unwrap();
    assert_eq!(
        volumes.pool_status().await.unwrap().alert,
        PoolAlert::Warning
    );
    volumes.ensure("tipping", MIB).await.unwrap();

    let status = volumes.pool_status().await.unwrap();
    assert_eq!(status.alert, PoolAlert::Critical);
    assert!((status.usage.used_percent - 90.0).abs() < 1e-9);

    match volumes.ensure("new", MIB).await
    {
        Err(VolumeError::PoolFull { used_percent }) => assert!((used_percent - 90.0).abs() < 1e-9),
        other => panic!("expected PoolFull, got {other:?}"),
    }
    assert!(matches!(
        volumes.ensure_blank("new-blank", MIB).await,
        Err(VolumeError::PoolFull { .. })
    ));
    assert_eq!(
        volumes.ensure("existing", 85 * MIB).await.unwrap(),
        existing
    );

    volumes.remove("small").await.unwrap();
    volumes.ensure("new", MIB).await.unwrap();
}
