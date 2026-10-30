use std::fmt;
use std::path::Path as FsPath;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use volume::{SnapshotManifest, SnapshotStore, VolumeError};

const CHUNK: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModeKind
{
    Overwrite,
    Create,
    Update,
}

#[derive(Debug, Default)]
struct TestStore
{
    inner: InMemory,
    puts: AtomicUsize,
    fail_after_puts: Mutex<Option<usize>>,
    manifest_modes: Mutex<Vec<ModeKind>>,
    interfere_with_manifest: Mutex<Option<Bytes>>,
}

impl TestStore
{
    fn puts(&self) -> usize
    {
        self.puts.load(Ordering::SeqCst)
    }

    fn reset_puts(&self)
    {
        self.puts.store(0, Ordering::SeqCst);
    }

    fn manifest_modes(&self) -> Vec<ModeKind>
    {
        self.manifest_modes.lock().unwrap().clone()
    }
}

impl fmt::Display for TestStore
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "TestStore")
    }
}

#[async_trait]
impl ObjectStore for TestStore
{
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult>
    {
        let limit = *self.fail_after_puts.lock().unwrap();
        if let Some(limit) = limit
            && self.puts() >= limit
        {
            return Err(object_store::Error::Generic {
                store: "TestStore",
                source: "injected upload failure".into(),
            });
        }
        self.puts.fetch_add(1, Ordering::SeqCst);
        if location.as_ref().ends_with("manifest.json")
        {
            let kind = match opts.mode
            {
                PutMode::Overwrite => ModeKind::Overwrite,
                PutMode::Create => ModeKind::Create,
                PutMode::Update(_) => ModeKind::Update,
            };
            self.manifest_modes.lock().unwrap().push(kind);
            let competing = self.interfere_with_manifest.lock().unwrap().take();
            if let Some(competing) = competing
            {
                self.inner
                    .put(location, PutPayload::from(competing))
                    .await?;
            }
        }
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>>
    {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult>
    {
        self.inner.get_opts(location, options).await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>>
    {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>>
    {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult>
    {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: CopyOptions,
    ) -> object_store::Result<()>
    {
        self.inner.copy_opts(from, to, options).await
    }
}

fn pattern(seed: u8, length: usize) -> Vec<u8>
{
    let mut state = u32::from(seed) | 0x9e37_0000;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn sample_image() -> Vec<u8>
{
    let chunk = CHUNK as usize;
    let mut image = Vec::new();
    image.extend(pattern(1, chunk));
    image.extend(vec![0u8; chunk]);
    image.extend(pattern(2, chunk));
    image.extend(pattern(1, chunk));
    image.extend(vec![0u8; chunk]);
    image.extend(pattern(3, chunk / 3));
    image
}

fn write_image(dir: &FsPath, name: &str, image: &[u8]) -> std::path::PathBuf
{
    let path = dir.join(name);
    std::fs::write(&path, image).unwrap();
    path
}

async fn stored_manifest(store: &dyn ObjectStore, key: &str) -> SnapshotManifest
{
    let body = store
        .get(&Path::from(key))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn round_trip_is_byte_identical_with_zero_and_partial_chunks()
{
    let dir = tempfile::tempdir().unwrap();
    let image = sample_image();
    let source = write_image(dir.path(), "source.img", &image);
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 3);

    let manifest = snapshots
        .upload(&source, "worlds/w1/snap-1", "world-1", 7)
        .await
        .unwrap();
    assert_eq!(manifest.format_version, volume::MANIFEST_FORMAT_VERSION);
    assert_eq!(manifest.lease_epoch, 7);
    assert_eq!(manifest.source, "world-1");
    assert_eq!(manifest.chunk_size, CHUNK);
    assert_eq!(manifest.total_size, image.len() as u64);
    assert_eq!(manifest.chunks.len(), 6);
    assert_eq!(manifest.chunks[5].length, CHUNK / 3);
    assert_eq!(manifest.chunks[5].offset, 5 * CHUNK);
    assert_eq!(manifest.chunks[1].key, None);
    assert_eq!(manifest.chunks[4].key, None);
    assert_eq!(manifest.chunks[0].key, manifest.chunks[3].key);
    assert_eq!(
        manifest.chunks[0].key.as_deref(),
        Some(SnapshotStore::chunk_key("worlds/w1/snap-1", &manifest.chunks[0].sha256).as_str())
    );
    assert!(manifest.created_at_unix > 0);
    assert_eq!(store.puts(), 4);

    let manifest_key = SnapshotStore::manifest_key("worlds/w1/snap-1");
    assert_eq!(manifest_key, "worlds/w1/snap-1/manifest.json");
    assert_eq!(
        stored_manifest(store.as_ref(), &manifest_key).await,
        manifest
    );

    let target = dir.path().join("restored.img");
    let restored = snapshots.restore(&manifest_key, &target).await.unwrap();
    assert_eq!(restored, manifest);
    assert_eq!(std::fs::read(&target).unwrap(), image);

    std::fs::write(&target, vec![0xffu8; image.len() * 2]).unwrap();
    snapshots.restore(&manifest_key, &target).await.unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), image);
}

#[tokio::test]
async fn round_trip_through_local_filesystem_store()
{
    let dir = tempfile::tempdir().unwrap();
    let bucket = dir.path().join("bucket");
    std::fs::create_dir_all(&bucket).unwrap();
    let image = sample_image();
    let source = write_image(dir.path(), "source.img", &image);
    let store = Arc::new(LocalFileSystem::new_with_prefix(&bucket).unwrap());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);

    snapshots.upload(&source, "w1", "world-1", 1).await.unwrap();
    let second = snapshots.upload(&source, "w1", "world-1", 2).await.unwrap();
    assert_eq!(
        stored_manifest(store.as_ref(), "w1/manifest.json").await,
        second
    );
    assert!(matches!(
        snapshots.upload(&source, "w1", "world-1", 1).await,
        Err(VolumeError::StaleEpoch {
            ours: 1,
            current: 2
        })
    ));

    let target = dir.path().join("restored.img");
    snapshots
        .restore("w1/manifest.json", &target)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), image);
}

#[tokio::test]
async fn empty_image_round_trips()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "empty.img", &[]);
    let snapshots = SnapshotStore::new(Arc::new(InMemory::new()), CHUNK, 2);
    let manifest = snapshots
        .upload(&source, "empty", "empty", 1)
        .await
        .unwrap();
    assert!(manifest.chunks.is_empty());
    let target = dir.path().join("restored.img");
    snapshots
        .restore("empty/manifest.json", &target)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), Vec::<u8>::new());
}

#[tokio::test]
async fn interrupted_upload_resumes_without_reuploading_chunks()
{
    let dir = tempfile::tempdir().unwrap();
    let chunk = CHUNK as usize;
    let mut image = Vec::new();
    for seed in 10..16
    {
        image.extend(pattern(seed, chunk));
    }
    let source = write_image(dir.path(), "source.img", &image);
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 1);

    *store.fail_after_puts.lock().unwrap() = Some(4);
    assert!(matches!(
        snapshots.upload(&source, "w1", "world-1", 3).await,
        Err(VolumeError::ObjectStore(_))
    ));
    assert_eq!(store.puts(), 4);
    assert!(
        store
            .inner
            .head(&Path::from("w1/manifest.json"))
            .await
            .is_err()
    );

    *store.fail_after_puts.lock().unwrap() = None;
    store.reset_puts();
    let manifest = snapshots.upload(&source, "w1", "world-1", 3).await.unwrap();
    assert_eq!(store.puts(), 2 + 1);
    assert_eq!(manifest.chunks.len(), 6);

    store.reset_puts();
    snapshots.upload(&source, "w1", "world-1", 3).await.unwrap();
    assert_eq!(store.puts(), 1);

    let target = dir.path().join("restored.img");
    snapshots
        .restore("w1/manifest.json", &target)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), image);
}

#[tokio::test]
async fn refuses_stale_epoch()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);

    let current = snapshots.upload(&source, "w1", "world-1", 5).await.unwrap();
    store.reset_puts();
    let error = snapshots
        .upload(&source, "w1", "world-1", 4)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        VolumeError::StaleEpoch {
            ours: 4,
            current: 5
        }
    ));
    assert_eq!(store.puts(), 0);
    assert_eq!(
        stored_manifest(store.as_ref(), "w1/manifest.json").await,
        current
    );
}

#[tokio::test]
async fn manifest_uses_create_then_update()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);

    snapshots.upload(&source, "w1", "world-1", 5).await.unwrap();
    snapshots.upload(&source, "w1", "world-1", 5).await.unwrap();
    let newer = snapshots.upload(&source, "w1", "world-1", 6).await.unwrap();
    assert_eq!(
        store.manifest_modes(),
        vec![ModeKind::Create, ModeKind::Update, ModeKind::Update]
    );
    assert_eq!(
        stored_manifest(store.as_ref(), "w1/manifest.json").await,
        newer
    );
}

fn competing_manifest(lease_epoch: u64) -> Bytes
{
    let manifest = SnapshotManifest {
        format_version: volume::MANIFEST_FORMAT_VERSION,
        lease_epoch,
        source: "elsewhere".to_owned(),
        created_at_unix: 1,
        chunk_size: CHUNK,
        total_size: 0,
        image_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        chunks: Vec::new(),
    };
    Bytes::from(serde_json::to_vec(&manifest).unwrap())
}

#[tokio::test]
async fn concurrent_create_with_newer_epoch_is_detected()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);

    *store.interfere_with_manifest.lock().unwrap() = Some(competing_manifest(9));
    let error = snapshots
        .upload(&source, "w1", "world-1", 8)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        VolumeError::StaleEpoch {
            ours: 8,
            current: 9
        }
    ));
    assert_eq!(store.manifest_modes(), vec![ModeKind::Create]);
    assert_eq!(
        stored_manifest(store.as_ref(), "w1/manifest.json")
            .await
            .source,
        "elsewhere"
    );
}

#[tokio::test]
async fn concurrent_update_with_newer_epoch_is_detected()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);

    snapshots.upload(&source, "w1", "world-1", 8).await.unwrap();
    *store.interfere_with_manifest.lock().unwrap() = Some(competing_manifest(9));
    let error = snapshots
        .upload(&source, "w1", "world-1", 8)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        VolumeError::StaleEpoch {
            ours: 8,
            current: 9
        }
    ));
    assert_eq!(
        store.manifest_modes(),
        vec![ModeKind::Create, ModeKind::Update]
    );
}

#[tokio::test]
async fn concurrent_update_with_older_epoch_is_retried()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(TestStore::default());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);

    snapshots.upload(&source, "w1", "world-1", 8).await.unwrap();
    *store.interfere_with_manifest.lock().unwrap() = Some(competing_manifest(8));
    let ours = snapshots.upload(&source, "w1", "world-1", 9).await.unwrap();
    assert_eq!(
        store.manifest_modes(),
        vec![ModeKind::Create, ModeKind::Update, ModeKind::Update]
    );
    assert_eq!(
        stored_manifest(store.as_ref(), "w1/manifest.json").await,
        ours
    );
}

#[tokio::test]
async fn corrupted_chunk_is_detected_on_restore()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(InMemory::new());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);
    let manifest = snapshots.upload(&source, "w1", "world-1", 1).await.unwrap();

    let victim = manifest.chunks[2].key.clone().unwrap();
    let forged = zstd::bulk::compress(&pattern(99, CHUNK as usize), 3).unwrap();
    store
        .put(&Path::from(victim.as_str()), PutPayload::from(forged))
        .await
        .unwrap();

    let target = dir.path().join("restored.img");
    let error = snapshots
        .restore("w1/manifest.json", &target)
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::Integrity { .. }), "{error:?}");

    store
        .put(
            &Path::from(victim.as_str()),
            PutPayload::from_static(b"not zstd"),
        )
        .await
        .unwrap();
    let error = snapshots
        .restore("w1/manifest.json", &target)
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::Integrity { .. }), "{error:?}");
}

#[tokio::test]
async fn image_hash_mismatch_is_detected_on_restore()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let store = Arc::new(InMemory::new());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);
    let mut manifest = snapshots.upload(&source, "w1", "world-1", 1).await.unwrap();

    manifest.image_sha256 = "0".repeat(64);
    store
        .put(
            &Path::from("w1/manifest.json"),
            PutPayload::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await
        .unwrap();
    let error = snapshots
        .restore("w1/manifest.json", &dir.path().join("restored.img"))
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::Integrity { .. }), "{error:?}");
}

#[tokio::test]
async fn restore_rejects_missing_and_malformed_manifests()
{
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(InMemory::new());
    let snapshots = SnapshotStore::new(store.clone(), CHUNK, 2);
    let target = dir.path().join("restored.img");

    assert!(matches!(
        snapshots.restore("nope/manifest.json", &target).await,
        Err(VolumeError::ManifestMissing { .. })
    ));

    let source = write_image(dir.path(), "source.img", &sample_image());
    let mut manifest = snapshots.upload(&source, "w1", "world-1", 1).await.unwrap();
    manifest.chunks[1].offset += 1;
    store
        .put(
            &Path::from("w1/manifest.json"),
            PutPayload::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await
        .unwrap();
    assert!(matches!(
        snapshots.restore("w1/manifest.json", &target).await,
        Err(VolumeError::Integrity { .. })
    ));

    manifest.chunks[1].offset -= 1;
    manifest.format_version = 2;
    store
        .put(
            &Path::from("w1/manifest.json"),
            PutPayload::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await
        .unwrap();
    assert!(matches!(
        snapshots.restore("w1/manifest.json", &target).await,
        Err(VolumeError::UnsupportedFormat { version: 2 })
    ));
}

#[tokio::test]
async fn zero_chunk_size_is_rejected()
{
    let dir = tempfile::tempdir().unwrap();
    let source = write_image(dir.path(), "source.img", &sample_image());
    let snapshots = SnapshotStore::new(Arc::new(InMemory::new()), 0, 2);
    assert!(matches!(
        snapshots.upload(&source, "w1", "world-1", 1).await,
        Err(VolumeError::InvalidChunkSize { chunk_size: 0 })
    ));
}
