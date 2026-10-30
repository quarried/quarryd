mod error;
mod file;
mod images;
mod lvm;
mod snapshot;
mod volumes;

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use error::VolumeError;
pub use file::FileVolume;
pub use images::{ArtifactDescriptor, ArtifactKind, CachedArtifact, ImageCache};
pub use lvm::LvmThin;
pub use snapshot::{ChunkRef, MANIFEST_FORMAT_VERSION, SnapshotManifest, SnapshotStore};
pub use volumes::{CRITICAL_PERCENT, PoolAlert, PoolStatus, Volumes, WARNING_PERCENT};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeKind
{
    LvmThin,
    File,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo
{
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoolUsage
{
    pub size_bytes: u64,
    pub used_percent: f64,
}

#[async_trait]
pub trait Volume: Send + Sync
{
    fn kind(&self) -> VolumeKind;
    async fn create(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>;
    async fn create_blank(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>;
    async fn get(&self, name: &str) -> Result<Option<VolumeInfo>, VolumeError>;
    async fn list(&self) -> Result<Vec<VolumeInfo>, VolumeError>;
    async fn delete(&self, name: &str) -> Result<(), VolumeError>;
    async fn snapshot(&self, name: &str, snapshot_name: &str) -> Result<VolumeInfo, VolumeError>;
    async fn pool_usage(&self) -> Result<PoolUsage, VolumeError>;
}

const MAX_NAME_LEN: usize = 127;

/// A bounded, backend-safe identity for a logical disk. Length prefixes keep
/// component boundaries unambiguous; the digest also preserves arbitrary names.
pub fn disk_volume_name(instance_id: &str, disk_name: &str) -> String
{
    let mut hash = Sha256::new();
    hash.update(b"quarryd/disk/v1\0");
    for component in [instance_id, disk_name]
    {
        hash.update((component.len() as u64).to_be_bytes());
        hash.update(component.as_bytes());
    }
    let digest: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("qd-{digest}")
}

#[cfg(test)]
mod name_tests
{
    use super::*;

    #[test]
    fn disk_identity_preserves_boundaries_and_unsanitized_names()
    {
        assert_ne!(disk_volume_name("a-b", "c"), disk_volume_name("a", "b-c"));
        assert_ne!(disk_volume_name("a", "b/c"), disk_volume_name("a", "b-c"));
        let prefix = "x".repeat(100);
        assert_ne!(
            disk_volume_name("a", &format!("{prefix}b")),
            disk_volume_name("a", &format!("{prefix}c"))
        );
        let name = disk_volume_name("snapshot-test", "world_tmeta");
        assert_eq!(name.len(), 67);
        validate_name(&name).unwrap();
        assert_eq!(name, disk_volume_name("snapshot-test", "world_tmeta"));
    }
}

pub(crate) fn validate_name(name: &str) -> Result<(), VolumeError>
{
    let valid_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '_' | '.' | '-'));
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && valid_chars
        && !name.starts_with('-')
        && !name.starts_with('.');
    if valid
    {
        Ok(())
    }
    else
    {
        Err(VolumeError::InvalidName {
            name: name.to_owned(),
        })
    }
}
