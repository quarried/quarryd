use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use futures::StreamExt;
use minisign_verify::{PublicKey, Signature};
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use store::{ArtifactRow, Store, StoreError};
use tokio::io::AsyncWriteExt;

use crate::VolumeError;
use crate::file::remove_if_present;
use crate::snapshot::{to_hex, unix_now};

const READ_ONLY_MODE: u32 = 0o444;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDescriptor
{
    pub digest: String,
    pub key: String,
    pub signature_key: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind
{
    Kernel,
    Rootfs,
    Agent,
}

impl ArtifactKind
{
    pub fn as_str(self) -> &'static str
    {
        match self
        {
            ArtifactKind::Kernel => "kernel",
            ArtifactKind::Rootfs => "rootfs",
            ArtifactKind::Agent => "agent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedArtifact
{
    pub digest: String,
    pub path: PathBuf,
    pub hit: bool,
}

pub struct ImageCache
{
    dir: PathBuf,
    objects: Arc<dyn ObjectStore>,
    public_key: PublicKey,
    store: Arc<Store>,
    capacity_bytes: u64,
    digest_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    eviction: tokio::sync::Mutex<()>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ImageCache
{
    pub fn new(
        dir: PathBuf,
        objects: Arc<dyn ObjectStore>,
        public_key: &str,
        store: Arc<Store>,
        capacity_bytes: u64,
    ) -> Result<ImageCache, VolumeError>
    {
        let public_key =
            PublicKey::from_base64(public_key.trim()).map_err(VolumeError::InvalidPublicKey)?;
        Ok(ImageCache {
            dir,
            objects,
            public_key,
            store,
            capacity_bytes,
            digest_locks: Mutex::new(HashMap::new()),
            eviction: tokio::sync::Mutex::new(()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }

    pub fn dir(&self) -> &Path
    {
        &self.dir
    }

    pub fn artifact_path(&self, digest: &str) -> PathBuf
    {
        self.dir.join(digest)
    }

    pub async fn ensure(
        &self,
        artifact: &ArtifactDescriptor,
        kind: ArtifactKind,
    ) -> Result<CachedArtifact, VolumeError>
    {
        validate_digest(&artifact.digest)?;
        let lock = self.digest_lock(&artifact.digest);
        let result = {
            let _guard = lock.lock().await;
            self.ensure_locked(artifact, kind).await
        };
        self.forget_lock(&artifact.digest, lock);
        result
    }

    pub fn acquire(&self, digest: &str, instance_id: &str) -> Result<(), VolumeError>
    {
        validate_digest(digest)?;
        Ok(self.store.add_artifact_ref(digest, instance_id)?)
    }

    pub fn release(&self, digest: &str, instance_id: &str) -> Result<(), VolumeError>
    {
        validate_digest(digest)?;
        Ok(self.store.remove_artifact_ref(digest, instance_id)?)
    }

    pub fn release_instance(&self, instance_id: &str) -> Result<(), VolumeError>
    {
        Ok(self.store.remove_instance_artifact_refs(instance_id)?)
    }

    pub async fn evict(&self) -> Result<Vec<String>, VolumeError>
    {
        let _serialized = self.eviction.lock().await;
        let mut total = self.store.total_artifact_bytes()?;
        let mut evicted = Vec::new();
        if total <= self.capacity_bytes
        {
            return Ok(evicted);
        }
        for row in self.store.unreferenced_artifacts_lru()?
        {
            if total <= self.capacity_bytes
            {
                break;
            }
            let lock = self.digest_lock(&row.digest);
            let removed = match lock.try_lock()
            {
                Ok(_guard) => self.evict_row(&row).await,
                Err(_) => Ok(false),
            };
            self.forget_lock(&row.digest, lock);
            if removed?
            {
                total = total.saturating_sub(row.size_bytes);
                evicted.push(row.digest);
            }
        }
        if !evicted.is_empty()
        {
            tracing::info!(
                count = evicted.len(),
                total_bytes = total,
                "evicted unreferenced artifacts"
            );
        }
        Ok(evicted)
    }

    pub fn hits(&self) -> u64
    {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64
    {
        self.misses.load(Ordering::Relaxed)
    }

    fn digest_lock(&self, digest: &str) -> Arc<tokio::sync::Mutex<()>>
    {
        let mut locks = self
            .digest_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(locks.entry(digest.to_owned()).or_default())
    }

    fn forget_lock(&self, digest: &str, lock: Arc<tokio::sync::Mutex<()>>)
    {
        let mut locks = self
            .digest_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        drop(lock);
        if locks
            .get(digest)
            .is_some_and(|remaining| Arc::strong_count(remaining) == 1)
        {
            locks.remove(digest);
        }
    }

    async fn ensure_locked(
        &self,
        artifact: &ArtifactDescriptor,
        kind: ArtifactKind,
    ) -> Result<CachedArtifact, VolumeError>
    {
        let path = self.artifact_path(&artifact.digest);
        if let Some(row) = self.store.get_artifact(&artifact.digest)?
            && row.verified
            && file_len(&path).await? == Some(row.size_bytes)
        {
            self.store.touch_artifact(&artifact.digest, unix_now())?;
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(CachedArtifact {
                digest: artifact.digest.clone(),
                path,
                hit: true,
            });
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        remove_if_present(&path).await?;
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(VolumeError::io(format!("creating {}", self.dir.display())))?;
        let partial = self.dir.join(format!(".{}.partial", artifact.digest));
        remove_if_present(&partial).await?;
        if let Err(error) = self.download(artifact, &partial).await
        {
            remove_if_present(&partial).await?;
            return Err(error);
        }
        tokio::fs::rename(&partial, &path)
            .await
            .map_err(VolumeError::io(format!(
                "renaming {} into place",
                partial.display()
            )))?;
        self.store.upsert_artifact(&ArtifactRow {
            digest: artifact.digest.clone(),
            path: path.to_string_lossy().into_owned(),
            size_bytes: artifact.size_bytes,
            kind: kind.as_str().to_owned(),
            last_used_unix: unix_now(),
            verified: true,
        })?;
        tracing::info!(digest = %artifact.digest, kind = kind.as_str(), size_bytes = artifact.size_bytes, "cached verified artifact");

        if self.store.total_artifact_bytes()? > self.capacity_bytes
        {
            self.evict().await?;
        }
        Ok(CachedArtifact {
            digest: artifact.digest.clone(),
            path,
            hit: false,
        })
    }

    async fn download(
        &self,
        artifact: &ArtifactDescriptor,
        partial: &Path,
    ) -> Result<(), VolumeError>
    {
        let signature_bytes = self
            .objects
            .get(&ObjectPath::from(artifact.signature_key.as_str()))
            .await?
            .bytes()
            .await?;
        let signature_error = |source| VolumeError::Signature {
            key: artifact.signature_key.clone(),
            source,
        };
        let signature_text = String::from_utf8_lossy(&signature_bytes);
        let signature = Signature::decode(&signature_text).map_err(signature_error)?;
        let mut verifier = self
            .public_key
            .verify_stream(&signature)
            .map_err(signature_error)?;

        let mut file = tokio::fs::File::create(partial)
            .await
            .map_err(VolumeError::io(format!("creating {}", partial.display())))?;
        let mut hasher = Sha256::new();
        let mut received = 0u64;
        let mut body = self
            .objects
            .get(&ObjectPath::from(artifact.key.as_str()))
            .await?
            .into_stream();
        while let Some(piece) = body.next().await
        {
            let piece = piece?;
            received = received.saturating_add(piece.len() as u64);
            if received > artifact.size_bytes
            {
                return Err(VolumeError::SizeMismatch {
                    expected: artifact.size_bytes,
                    actual: received,
                });
            }
            hasher.update(&piece);
            verifier.update(&piece);
            file.write_all(&piece)
                .await
                .map_err(VolumeError::io(format!("writing {}", partial.display())))?;
        }
        if received != artifact.size_bytes
        {
            return Err(VolumeError::SizeMismatch {
                expected: artifact.size_bytes,
                actual: received,
            });
        }
        let actual = to_hex(&hasher.finalize());
        if actual != artifact.digest
        {
            return Err(VolumeError::DigestMismatch {
                expected: artifact.digest.clone(),
                actual,
            });
        }
        verifier.finalize().map_err(signature_error)?;

        file.sync_all()
            .await
            .map_err(VolumeError::io(format!("syncing {}", partial.display())))?;
        drop(file);
        tokio::fs::set_permissions(partial, std::fs::Permissions::from_mode(READ_ONLY_MODE))
            .await
            .map_err(VolumeError::io(format!(
                "making {} read-only",
                partial.display()
            )))?;
        Ok(())
    }

    async fn evict_row(&self, row: &ArtifactRow) -> Result<bool, VolumeError>
    {
        match self.store.delete_artifact(&row.digest)
        {
            Ok(()) =>
            {}
            Err(StoreError::ArtifactReferenced(_)) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        if validate_digest(&row.digest).is_ok()
        {
            remove_if_present(&self.artifact_path(&row.digest)).await?;
        }
        Ok(true)
    }
}

fn validate_digest(digest: &str) -> Result<(), VolumeError>
{
    let valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid
    {
        Ok(())
    }
    else
    {
        Err(VolumeError::InvalidDigest {
            digest: digest.to_owned(),
        })
    }
}

async fn file_len(path: &Path) -> Result<Option<u64>, VolumeError>
{
    match tokio::fs::metadata(path).await
    {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata.len())),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(VolumeError::io(format!(
            "reading metadata of {}",
            path.display()
        ))(error)),
    }
}
