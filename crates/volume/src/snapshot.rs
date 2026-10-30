use std::collections::HashSet;
use std::io::{ErrorKind, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::VolumeError;

pub const MANIFEST_FORMAT_VERSION: u32 = 1;
const ZSTD_LEVEL: i32 = 3;
const VERIFY_BUFFER_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotManifest
{
    pub format_version: u32,
    pub lease_epoch: u64,
    pub source: String,
    pub created_at_unix: i64,
    pub chunk_size: u64,
    pub total_size: u64,
    pub image_sha256: String,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChunkRef
{
    pub index: u64,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    pub key: Option<String>,
}

pub struct SnapshotStore
{
    store: Arc<dyn ObjectStore>,
    chunk_size: u64,
    parallelism: usize,
}

struct ScannedChunk
{
    data: Vec<u8>,
    image_hasher: Sha256,
    sha256: String,
    all_zero: bool,
}

impl SnapshotStore
{
    pub fn new(store: Arc<dyn ObjectStore>, chunk_size: u64, parallelism: usize) -> SnapshotStore
    {
        SnapshotStore {
            store,
            chunk_size,
            parallelism: parallelism.max(1),
        }
    }

    pub fn manifest_key(prefix: &str) -> String
    {
        format!("{}/manifest.json", prefix.trim_end_matches('/'))
    }

    pub fn chunk_key(prefix: &str, sha256: &str) -> String
    {
        format!("{}/chunks/{sha256}.zst", prefix.trim_end_matches('/'))
    }

    pub async fn upload(
        &self,
        source: &Path,
        prefix: &str,
        source_name: &str,
        lease_epoch: u64,
    ) -> Result<SnapshotManifest, VolumeError>
    {
        let chunk_length = usize::try_from(self.chunk_size)
            .ok()
            .filter(|length| *length > 0)
            .ok_or(VolumeError::InvalidChunkSize {
                chunk_size: self.chunk_size,
            })?;
        let manifest_key = Self::manifest_key(prefix);
        if let Some((current, _)) = self.read_manifest(&manifest_key).await?
        {
            check_epoch(lease_epoch, current.lease_epoch)?;
        }

        let mut file = tokio::fs::File::open(source)
            .await
            .map_err(VolumeError::io(format!("opening {}", source.display())))?;
        let total_size = file
            .seek(SeekFrom::End(0))
            .await
            .map_err(VolumeError::io(format!("measuring {}", source.display())))?;
        file.seek(SeekFrom::Start(0))
            .await
            .map_err(VolumeError::io(format!("rewinding {}", source.display())))?;

        let mut image_hasher = Sha256::new();
        let mut chunks = Vec::new();
        let mut scheduled = HashSet::new();
        let mut uploads = JoinSet::new();
        let mut offset = 0u64;
        while offset < total_size
        {
            let length =
                chunk_length.min(usize::try_from(total_size - offset).unwrap_or(usize::MAX));
            let mut data = vec![0u8; length];
            file.read_exact(&mut data)
                .await
                .map_err(VolumeError::io(format!(
                    "reading {} at offset {offset}",
                    source.display()
                )))?;
            let scanned =
                tokio::task::spawn_blocking(move || scan_chunk(data, image_hasher)).await?;
            image_hasher = scanned.image_hasher;
            let key = if scanned.all_zero
            {
                None
            }
            else
            {
                let key = Self::chunk_key(prefix, &scanned.sha256);
                if scheduled.insert(key.clone())
                {
                    while uploads.len() >= self.parallelism
                    {
                        if let Some(finished) = uploads.join_next().await
                        {
                            finished??;
                        }
                    }
                    uploads.spawn(upload_chunk(
                        Arc::clone(&self.store),
                        key.clone(),
                        scanned.data,
                    ));
                }
                Some(key)
            };
            chunks.push(ChunkRef {
                index: chunks.len() as u64,
                offset,
                length: length as u64,
                sha256: scanned.sha256,
                key,
            });
            offset += length as u64;
        }
        while let Some(finished) = uploads.join_next().await
        {
            finished??;
        }

        let manifest = SnapshotManifest {
            format_version: MANIFEST_FORMAT_VERSION,
            lease_epoch,
            source: source_name.to_owned(),
            created_at_unix: unix_now(),
            chunk_size: self.chunk_size,
            total_size,
            image_sha256: to_hex(&image_hasher.finalize()),
            chunks,
        };
        self.write_manifest(&manifest_key, &manifest).await?;
        Ok(manifest)
    }

    pub async fn restore(
        &self,
        manifest_key: &str,
        target: &Path,
    ) -> Result<SnapshotManifest, VolumeError>
    {
        let (manifest, _) = self.read_manifest(manifest_key).await?.ok_or_else(|| {
            VolumeError::ManifestMissing {
                key: manifest_key.to_owned(),
            }
        })?;
        if manifest.format_version != MANIFEST_FORMAT_VERSION
        {
            return Err(VolumeError::UnsupportedFormat {
                version: manifest.format_version,
            });
        }
        validate_layout(&manifest)?;

        let mut file = open_target(target, manifest.total_size).await?;
        let stored_chunks: Vec<(String, ChunkRef)> = manifest
            .chunks
            .iter()
            .filter_map(|chunk| chunk.key.clone().map(|key| (key, chunk.clone())))
            .collect();
        let mut downloads = futures::stream::iter(stored_chunks)
            .map(|(key, chunk)| download_chunk(Arc::clone(&self.store), key, chunk))
            .buffer_unordered(self.parallelism);
        while let Some((offset, data)) = downloads.try_next().await?
        {
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(VolumeError::io(format!(
                    "seeking {} to {offset}",
                    target.display()
                )))?;
            file.write_all(&data)
                .await
                .map_err(VolumeError::io(format!(
                    "writing {} at {offset}",
                    target.display()
                )))?;
        }
        file.flush()
            .await
            .map_err(VolumeError::io(format!("flushing {}", target.display())))?;
        file.sync_all()
            .await
            .map_err(VolumeError::io(format!("syncing {}", target.display())))?;
        drop(file);

        let restored_sha256 = hash_prefix(target, manifest.total_size).await?;
        if restored_sha256 != manifest.image_sha256
        {
            return Err(VolumeError::Integrity {
                detail: format!(
                    "restored image {} hashes to {restored_sha256}, manifest says {}",
                    target.display(),
                    manifest.image_sha256
                ),
            });
        }
        Ok(manifest)
    }

    async fn read_manifest(
        &self,
        key: &str,
    ) -> Result<Option<(SnapshotManifest, UpdateVersion)>, VolumeError>
    {
        let result = match self.store.get(&ObjectPath::from(key)).await
        {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let version = UpdateVersion {
            e_tag: result.meta.e_tag.clone(),
            version: result.meta.version.clone(),
        };
        let body = result.bytes().await?;
        let manifest = serde_json::from_slice(&body).map_err(|source| VolumeError::Manifest {
            key: key.to_owned(),
            source,
        })?;
        Ok(Some((manifest, version)))
    }

    async fn write_manifest(
        &self,
        key: &str,
        manifest: &SnapshotManifest,
    ) -> Result<(), VolumeError>
    {
        let body = Bytes::from(serde_json::to_vec_pretty(manifest).map_err(|source| {
            VolumeError::Manifest {
                key: key.to_owned(),
                source,
            }
        })?);
        let path = ObjectPath::from(key);
        for _ in 0..2
        {
            let mode = match self.read_manifest(key).await?
            {
                None => PutMode::Create,
                Some((current, version)) =>
                {
                    check_epoch(manifest.lease_epoch, current.lease_epoch)?;
                    PutMode::Update(version)
                }
            };
            match self
                .store
                .put_opts(
                    &path,
                    PutPayload::from(body.clone()),
                    PutOptions::from(mode),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(
                    object_store::Error::Precondition { .. }
                    | object_store::Error::AlreadyExists { .. },
                ) =>
                {
                    tracing::debug!(
                        key,
                        "snapshot manifest changed during conditional write; re-reading"
                    );
                }
                Err(object_store::Error::NotImplemented { .. }) =>
                {
                    tracing::debug!(
                        key,
                        "object store lacks conditional writes; overwriting manifest"
                    );
                    self.store.put(&path, PutPayload::from(body)).await?;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(VolumeError::ManifestConflict {
            key: key.to_owned(),
        })
    }
}

fn check_epoch(ours: u64, current: u64) -> Result<(), VolumeError>
{
    if current > ours
    {
        return Err(VolumeError::StaleEpoch { ours, current });
    }
    Ok(())
}

fn scan_chunk(data: Vec<u8>, mut image_hasher: Sha256) -> ScannedChunk
{
    image_hasher.update(&data);
    let sha256 = to_hex(&Sha256::digest(&data));
    let all_zero = data.iter().all(|byte| *byte == 0);
    ScannedChunk {
        data,
        image_hasher,
        sha256,
        all_zero,
    }
}

async fn upload_chunk(
    store: Arc<dyn ObjectStore>,
    key: String,
    data: Vec<u8>,
) -> Result<(), VolumeError>
{
    let path = ObjectPath::from(key.as_str());
    match store.head(&path).await
    {
        Ok(_) => return Ok(()),
        Err(object_store::Error::NotFound { .. }) =>
        {}
        Err(error) => return Err(error.into()),
    }
    let compressed = tokio::task::spawn_blocking(move || zstd::bulk::compress(&data, ZSTD_LEVEL))
        .await?
        .map_err(VolumeError::io(format!("compressing chunk {key}")))?;
    store.put(&path, PutPayload::from(compressed)).await?;
    Ok(())
}

async fn download_chunk(
    store: Arc<dyn ObjectStore>,
    key: String,
    chunk: ChunkRef,
) -> Result<(u64, Vec<u8>), VolumeError>
{
    let compressed = store
        .get(&ObjectPath::from(key.as_str()))
        .await?
        .bytes()
        .await?;
    tokio::task::spawn_blocking(move || {
        let capacity = usize::try_from(chunk.length).map_err(|_| VolumeError::Integrity {
            detail: format!(
                "chunk {} length {} does not fit in memory",
                chunk.index, chunk.length
            ),
        })?;
        let data = zstd::bulk::decompress(&compressed, capacity).map_err(|error| {
            VolumeError::Integrity {
                detail: format!("chunk {} ({key}) does not decompress: {error}", chunk.index),
            }
        })?;
        if data.len() as u64 != chunk.length
        {
            return Err(VolumeError::Integrity {
                detail: format!(
                    "chunk {} ({key}) is {} bytes, manifest says {}",
                    chunk.index,
                    data.len(),
                    chunk.length
                ),
            });
        }
        let sha256 = to_hex(&Sha256::digest(&data));
        if sha256 != chunk.sha256
        {
            return Err(VolumeError::Integrity {
                detail: format!(
                    "chunk {} ({key}) hashes to {sha256}, manifest says {}",
                    chunk.index, chunk.sha256
                ),
            });
        }
        Ok((chunk.offset, data))
    })
    .await?
}

fn validate_layout(manifest: &SnapshotManifest) -> Result<(), VolumeError>
{
    let mut expected_offset = 0u64;
    for (position, chunk) in manifest.chunks.iter().enumerate()
    {
        let consistent = chunk.index == position as u64
            && chunk.offset == expected_offset
            && chunk.length > 0
            && chunk.length <= manifest.chunk_size;
        if !consistent
        {
            return Err(VolumeError::Integrity {
                detail: format!("manifest chunk {position} does not continue the image layout"),
            });
        }
        expected_offset = expected_offset.saturating_add(chunk.length);
    }
    if expected_offset != manifest.total_size
    {
        return Err(VolumeError::Integrity {
            detail: format!(
                "manifest chunks cover {expected_offset} bytes, total size is {}",
                manifest.total_size
            ),
        });
    }
    Ok(())
}

async fn open_target(target: &Path, total_size: u64) -> Result<tokio::fs::File, VolumeError>
{
    let is_regular_file = match tokio::fs::metadata(target).await
    {
        Ok(metadata) => metadata.is_file(),
        Err(error) if error.kind() == ErrorKind::NotFound => true,
        Err(error) =>
        {
            return Err(VolumeError::io(format!(
                "reading metadata of {}",
                target.display()
            ))(error));
        }
    };
    if is_regular_file
    {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)
            .await
            .map_err(VolumeError::io(format!("opening {}", target.display())))?;
        file.set_len(total_size)
            .await
            .map_err(VolumeError::io(format!("sizing {}", target.display())))?;
        return Ok(file);
    }
    let mut device = tokio::fs::OpenOptions::new()
        .write(true)
        .open(target)
        .await
        .map_err(VolumeError::io(format!("opening {}", target.display())))?;
    let available = device
        .seek(SeekFrom::End(0))
        .await
        .map_err(VolumeError::io(format!("measuring {}", target.display())))?;
    if available < total_size
    {
        return Err(VolumeError::TargetTooSmall {
            path: target.to_path_buf(),
            needed: total_size,
            available,
        });
    }
    Ok(device)
}

async fn hash_prefix(path: &Path, length: u64) -> Result<String, VolumeError>
{
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(VolumeError::io(format!("opening {}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; VERIFY_BUFFER_BYTES];
    let mut remaining = length;
    while remaining > 0
    {
        let wanted = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(buffer.len()));
        let read = file
            .read(&mut buffer[..wanted])
            .await
            .map_err(VolumeError::io(format!("reading {}", path.display())))?;
        if read == 0
        {
            return Err(VolumeError::Integrity {
                detail: format!("{} ended {remaining} bytes early", path.display()),
            });
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(to_hex(&hasher.finalize()))
}

fn unix_now() -> i64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String
{
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes
    {
        hex.push(DIGITS[usize::from(byte >> 4)] as char);
        hex.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    hex
}
