use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::BoxStream;
use minisign::KeyPair;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    ObjectStoreExt, PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use sha2::{Digest, Sha256};
use store::Store;
use volume::{ArtifactDescriptor, ArtifactKind, ImageCache, VolumeError};

#[derive(Debug, Default)]
struct CountingStore
{
    inner: InMemory,
    gets: AtomicUsize,
}

impl fmt::Display for CountingStore
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "CountingStore")
    }
}

#[async_trait]
impl ObjectStore for CountingStore
{
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult>
    {
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
        self.gets.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
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

struct Fixture
{
    dir: tempfile::TempDir,
    objects: Arc<CountingStore>,
    store: Arc<Store>,
    keypair: KeyPair,
}

impl Fixture
{
    fn new() -> Fixture
    {
        Fixture {
            dir: tempfile::tempdir().unwrap(),
            objects: Arc::new(CountingStore::default()),
            store: Arc::new(Store::open_in_memory().unwrap()),
            keypair: KeyPair::generate_unencrypted_keypair().unwrap(),
        }
    }

    fn cache(&self, capacity_bytes: u64) -> ImageCache
    {
        ImageCache::new(
            self.dir.path().join("images"),
            self.objects.clone(),
            &self.keypair.pk.to_base64(),
            self.store.clone(),
            capacity_bytes,
        )
        .unwrap()
    }

    fn sign(&self, content: &[u8]) -> Vec<u8>
    {
        minisign::sign(
            Some(&self.keypair.pk),
            &self.keypair.sk,
            content,
            None,
            None,
        )
        .unwrap()
        .to_string()
        .into_bytes()
    }

    async fn publish_with_signature(
        &self,
        name: &str,
        content: &[u8],
        signature: Vec<u8>,
    ) -> ArtifactDescriptor
    {
        let digest = sha256_hex(content);
        let key = format!("artifacts/{name}");
        let signature_key = format!("artifacts/{name}.minisig");
        self.objects
            .inner
            .put(
                &Path::from(key.as_str()),
                PutPayload::from(content.to_vec()),
            )
            .await
            .unwrap();
        self.objects
            .inner
            .put(
                &Path::from(signature_key.as_str()),
                PutPayload::from(signature),
            )
            .await
            .unwrap();
        ArtifactDescriptor {
            digest,
            key,
            signature_key,
            size_bytes: content.len() as u64,
        }
    }

    async fn publish(&self, name: &str, content: &[u8]) -> ArtifactDescriptor
    {
        self.publish_with_signature(name, content, self.sign(content))
            .await
    }

    fn cache_entries(&self) -> Vec<String>
    {
        let mut names: Vec<String> = match std::fs::read_dir(self.dir.path().join("images"))
        {
            Ok(entries) => entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }
}

fn sha256_hex(content: &[u8]) -> String
{
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn content(seed: u8, length: usize) -> Vec<u8>
{
    (0..length)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn rejects_invalid_public_key()
{
    let fixture = Fixture::new();
    let result = ImageCache::new(
        fixture.dir.path().to_path_buf(),
        fixture.objects.clone(),
        "not a key",
        fixture.store.clone(),
        1024,
    );
    assert!(matches!(result, Err(VolumeError::InvalidPublicKey(_))));
}

#[test]
fn kinds_map_to_row_strings()
{
    assert_eq!(ArtifactKind::Kernel.as_str(), "kernel");
    assert_eq!(ArtifactKind::Rootfs.as_str(), "rootfs");
    assert_eq!(ArtifactKind::Agent.as_str(), "agent");
}

#[tokio::test]
async fn miss_then_hit_with_verified_read_only_file()
{
    let fixture = Fixture::new();
    let cache = fixture.cache(1 << 20);
    let kernel = content(1, 5000);
    let descriptor = fixture.publish("vmlinux", &kernel).await;

    let first = cache
        .ensure(&descriptor, ArtifactKind::Kernel)
        .await
        .unwrap();
    assert!(!first.hit);
    assert_eq!(first.digest, descriptor.digest);
    assert_eq!(first.path, cache.artifact_path(&descriptor.digest));
    assert_eq!(std::fs::read(&first.path).unwrap(), kernel);
    let mode = std::fs::metadata(&first.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o444);
    assert_eq!((cache.hits(), cache.misses()), (0, 1));

    let row = fixture
        .store
        .get_artifact(&descriptor.digest)
        .unwrap()
        .unwrap();
    assert!(row.verified);
    assert_eq!(row.kind, "kernel");
    assert_eq!(row.size_bytes, 5000);
    assert_eq!(row.path, first.path.to_string_lossy());

    let gets_before = fixture.objects.gets.load(Ordering::SeqCst);
    let second = cache
        .ensure(&descriptor, ArtifactKind::Kernel)
        .await
        .unwrap();
    assert!(second.hit);
    assert_eq!(second.path, first.path);
    assert_eq!((cache.hits(), cache.misses()), (1, 1));
    assert_eq!(fixture.objects.gets.load(Ordering::SeqCst), gets_before);
    assert_eq!(fixture.cache_entries(), vec![descriptor.digest.clone()]);
}

#[tokio::test]
async fn refuses_bad_signature()
{
    let fixture = Fixture::new();
    let cache = fixture.cache(1 << 20);
    let rootfs = content(2, 3000);
    let other_key = KeyPair::generate_unencrypted_keypair().unwrap();
    let foreign = minisign::sign(
        Some(&other_key.pk),
        &other_key.sk,
        rootfs.as_slice(),
        None,
        None,
    )
    .unwrap()
    .to_string()
    .into_bytes();
    let descriptor = fixture
        .publish_with_signature("rootfs-foreign", &rootfs, foreign)
        .await;
    let error = cache
        .ensure(&descriptor, ArtifactKind::Rootfs)
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::Signature { .. }), "{error:?}");

    let wrong_content_signature = fixture.sign(&content(3, 3000));
    let descriptor = fixture
        .publish_with_signature("rootfs-wrong", &rootfs, wrong_content_signature)
        .await;
    let error = cache
        .ensure(&descriptor, ArtifactKind::Rootfs)
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::Signature { .. }), "{error:?}");

    let descriptor = fixture
        .publish_with_signature("rootfs-garbage", &rootfs, b"not a signature".to_vec())
        .await;
    let error = cache
        .ensure(&descriptor, ArtifactKind::Rootfs)
        .await
        .unwrap_err();
    assert!(matches!(error, VolumeError::Signature { .. }), "{error:?}");

    assert!(fixture.cache_entries().is_empty());
    assert_eq!(
        fixture.store.get_artifact(&descriptor.digest).unwrap(),
        None
    );
    assert_eq!(fixture.store.total_artifact_bytes().unwrap(), 0);
}

#[tokio::test]
async fn refuses_digest_mismatch_and_leaves_nothing_behind()
{
    let fixture = Fixture::new();
    let cache = fixture.cache(1 << 20);
    let agent = content(4, 2048);
    let mut descriptor = fixture.publish("agent", &agent).await;
    let claimed = sha256_hex(b"something else entirely");
    descriptor.digest = claimed.clone();

    match cache.ensure(&descriptor, ArtifactKind::Agent).await
    {
        Err(VolumeError::DigestMismatch { expected, actual }) =>
        {
            assert_eq!(expected, claimed);
            assert_eq!(actual, sha256_hex(&agent));
        }
        other => panic!("expected DigestMismatch, got {other:?}"),
    }
    assert!(fixture.cache_entries().is_empty());
    assert_eq!(fixture.store.get_artifact(&claimed).unwrap(), None);

    let mut truncated = fixture.publish("agent-2", &agent).await;
    truncated.size_bytes = 100;
    assert!(matches!(
        cache.ensure(&truncated, ArtifactKind::Agent).await,
        Err(VolumeError::SizeMismatch { expected: 100, .. })
    ));
    assert!(fixture.cache_entries().is_empty());

    let mut traversal = fixture.publish("agent-3", &agent).await;
    traversal.digest = "../../etc/passwd".to_owned();
    assert!(matches!(
        cache.ensure(&traversal, ArtifactKind::Agent).await,
        Err(VolumeError::InvalidDigest { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_ensure_downloads_once()
{
    let fixture = Fixture::new();
    let cache = Arc::new(fixture.cache(1 << 20));
    let rootfs = content(5, 64 * 1024);
    let descriptor = fixture.publish("rootfs", &rootfs).await;

    let mut tasks = Vec::new();
    for _ in 0..8
    {
        let cache = cache.clone();
        let descriptor = descriptor.clone();
        tasks.push(tokio::spawn(async move {
            cache.ensure(&descriptor, ArtifactKind::Rootfs).await
        }));
    }
    let mut downloaded = 0;
    for task in tasks
    {
        let cached = task.await.unwrap().unwrap();
        assert_eq!(std::fs::read(&cached.path).unwrap(), rootfs);
        if !cached.hit
        {
            downloaded += 1;
        }
    }
    assert_eq!(downloaded, 1);
    assert_eq!((cache.hits(), cache.misses()), (7, 1));
    assert_eq!(fixture.objects.gets.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn eviction_is_lru_and_never_touches_referenced_artifacts()
{
    let fixture = Fixture::new();
    let cache = fixture.cache(300);
    let a = fixture.publish("a", &content(10, 100)).await;
    let b = fixture.publish("b", &content(11, 100)).await;
    let c = fixture.publish("c", &content(12, 100)).await;
    let d = fixture.publish("d", &content(13, 100)).await;

    cache.acquire(&a.digest, "instance-1").unwrap();
    cache.ensure(&a, ArtifactKind::Kernel).await.unwrap();
    cache.ensure(&b, ArtifactKind::Rootfs).await.unwrap();
    cache.ensure(&c, ArtifactKind::Rootfs).await.unwrap();
    assert!(cache.evict().await.unwrap().is_empty());
    fixture.store.touch_artifact(&a.digest, 1).unwrap();
    fixture.store.touch_artifact(&b.digest, 2).unwrap();
    fixture.store.touch_artifact(&c.digest, 3).unwrap();

    cache.ensure(&d, ArtifactKind::Agent).await.unwrap();
    assert_eq!(fixture.store.get_artifact(&b.digest).unwrap(), None);
    assert!(!cache.artifact_path(&b.digest).exists());
    for kept in [&a, &c, &d]
    {
        assert!(cache.artifact_path(&kept.digest).exists());
    }
    assert_eq!(fixture.store.total_artifact_bytes().unwrap(), 300);
    assert!(cache.evict().await.unwrap().is_empty());

    let tiny = fixture.cache(0);
    tiny.acquire(&d.digest, "instance-2").unwrap();
    assert_eq!(tiny.evict().await.unwrap(), vec![c.digest.clone()]);
    assert!(!cache.artifact_path(&c.digest).exists());
    assert!(cache.artifact_path(&a.digest).exists());
    assert!(cache.artifact_path(&d.digest).exists());

    tiny.release_instance("instance-2").unwrap();
    assert_eq!(tiny.evict().await.unwrap(), vec![d.digest.clone()]);
    assert!(cache.artifact_path(&a.digest).exists());
    assert_eq!(
        fixture
            .store
            .get_artifact(&a.digest)
            .unwrap()
            .map(|row| row.size_bytes),
        Some(100)
    );
    assert_eq!(fixture.store.artifact_ref_count(&a.digest).unwrap(), 1);
}

#[tokio::test]
async fn corrupted_cached_file_is_downloaded_again()
{
    let fixture = Fixture::new();
    let cache = fixture.cache(1 << 20);
    let kernel = content(20, 4096);
    let descriptor = fixture.publish("vmlinux", &kernel).await;
    let cached = cache
        .ensure(&descriptor, ArtifactKind::Kernel)
        .await
        .unwrap();

    std::fs::set_permissions(&cached.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&cached.path, b"truncated").unwrap();
    let repaired = cache
        .ensure(&descriptor, ArtifactKind::Kernel)
        .await
        .unwrap();
    assert!(!repaired.hit);
    assert_eq!(std::fs::read(&repaired.path).unwrap(), kernel);

    std::fs::remove_file(&repaired.path).unwrap();
    let restored = cache
        .ensure(&descriptor, ArtifactKind::Kernel)
        .await
        .unwrap();
    assert!(!restored.hit);
    assert_eq!(std::fs::read(&restored.path).unwrap(), kernel);
    assert_eq!((cache.hits(), cache.misses()), (0, 3));
    assert_eq!(fixture.cache_entries(), vec![descriptor.digest.clone()]);
}

#[tokio::test]
async fn acquire_and_release_are_idempotent()
{
    let fixture = Fixture::new();
    let cache = fixture.cache(1 << 20);
    let descriptor = fixture.publish("agent", &content(30, 512)).await;
    let digest = descriptor.digest.clone();

    cache.acquire(&digest, "instance-1").unwrap();
    cache.acquire(&digest, "instance-1").unwrap();
    assert_eq!(fixture.store.artifact_ref_count(&digest).unwrap(), 1);
    cache.acquire(&digest, "instance-2").unwrap();
    assert_eq!(fixture.store.artifact_ref_count(&digest).unwrap(), 2);

    cache.release(&digest, "instance-1").unwrap();
    cache.release(&digest, "instance-1").unwrap();
    assert_eq!(fixture.store.artifact_ref_count(&digest).unwrap(), 1);

    cache.release_instance("instance-2").unwrap();
    cache.release_instance("instance-2").unwrap();
    cache.release(&digest, "never-acquired").unwrap();
    assert_eq!(fixture.store.artifact_ref_count(&digest).unwrap(), 0);

    assert!(matches!(
        cache.acquire("not-a-digest", "instance-1"),
        Err(VolumeError::InvalidDigest { .. })
    ));
}
