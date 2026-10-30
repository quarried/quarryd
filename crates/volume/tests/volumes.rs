use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use volume::{FileVolume, PoolAlert, PoolUsage, Volume, VolumeError, VolumeInfo, VolumeKind, Volumes};

const MIB: u64 = 1024 * 1024;

struct RecoveringVolume
{
    ready: AtomicBool,
}

impl RecoveringVolume
{
    fn info(name: &str, size_bytes: u64) -> VolumeInfo
    {
        VolumeInfo { name: name.to_owned(), path: format!("/dev/test/{name}").into(), size_bytes }
    }

    fn recover(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        if !self.ready.load(Ordering::SeqCst)
        {
            return Err(VolumeError::Integrity { detail: "unfinished formatting".to_owned() });
        }
        Ok(Self::info(name, size_bytes))
    }
}

#[async_trait]
impl Volume for RecoveringVolume
{
    fn kind(&self) -> VolumeKind { VolumeKind::LvmThin }
    async fn create(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        self.recover(name, size_bytes)
    }
    async fn create_blank(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        self.recover(name, size_bytes)
    }
    async fn get(&self, name: &str) -> Result<Option<VolumeInfo>, VolumeError>
    {
        Ok(Some(Self::info(name, MIB)))
    }
    async fn list(&self) -> Result<Vec<VolumeInfo>, VolumeError> { unreachable!() }
    async fn delete(&self, _name: &str) -> Result<(), VolumeError> { unreachable!() }
    async fn snapshot(&self, _name: &str, _snapshot_name: &str) -> Result<VolumeInfo, VolumeError> { unreachable!() }
    async fn pool_usage(&self) -> Result<PoolUsage, VolumeError>
    {
        panic!("recovering an existing volume must not require pool admission")
    }
}

#[tokio::test]
async fn existing_volumes_must_complete_backend_recovery_before_being_returned()
{
    let backend = Arc::new(RecoveringVolume { ready: AtomicBool::new(false) });
    let volumes = Volumes::new(backend.clone());
    assert!(matches!(volumes.ensure("world", MIB).await, Err(VolumeError::Integrity { .. })));
    assert!(matches!(volumes.ensure_blank("restore", MIB).await, Err(VolumeError::Integrity { .. })));
    backend.ready.store(true, Ordering::SeqCst);
    assert_eq!(volumes.ensure("world", MIB).await.unwrap(), RecoveringVolume::info("world", MIB));
    assert_eq!(volumes.ensure_blank("restore", MIB).await.unwrap(), RecoveringVolume::info("restore", MIB));
}

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
