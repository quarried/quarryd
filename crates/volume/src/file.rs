use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::{PoolUsage, Volume, VolumeError, VolumeInfo, VolumeKind, validate_name};

const IMAGE_EXTENSION: &str = ".img";

pub struct FileVolume
{
    dir: PathBuf,
    capacity_bytes: u64,
}

impl FileVolume
{
    pub fn new(dir: PathBuf, capacity_bytes: u64) -> FileVolume
    {
        FileVolume {
            dir,
            capacity_bytes,
        }
    }

    pub fn dir(&self) -> &Path
    {
        &self.dir
    }

    fn image_path(&self, name: &str) -> PathBuf
    {
        self.dir.join(format!("{name}{IMAGE_EXTENSION}"))
    }

    fn partial_path(&self, name: &str) -> PathBuf
    {
        self.dir.join(format!(".{name}{IMAGE_EXTENSION}.partial"))
    }

    async fn info(&self, name: &str) -> Result<Option<VolumeInfo>, VolumeError>
    {
        let path = self.image_path(name);
        match tokio::fs::metadata(&path).await
        {
            Ok(metadata) => Ok(Some(VolumeInfo {
                name: name.to_owned(),
                path,
                size_bytes: metadata.len(),
            })),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(VolumeError::io(format!(
                "reading metadata of {}",
                path.display()
            ))(error)),
        }
    }

    async fn existing(&self, name: &str) -> Result<VolumeInfo, VolumeError>
    {
        self.info(name).await?.ok_or_else(|| VolumeError::NotFound {
            name: name.to_owned(),
        })
    }

    async fn create_sparse(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        validate_name(name)?;
        if let Some(info) = self.info(name).await?
        {
            return Ok(info);
        }
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(VolumeError::io(format!("creating {}", self.dir.display())))?;
        let partial = self.partial_path(name);
        let file = tokio::fs::File::create(&partial)
            .await
            .map_err(VolumeError::io(format!("creating {}", partial.display())))?;
        file.set_len(size_bytes)
            .await
            .map_err(VolumeError::io(format!("sizing {}", partial.display())))?;
        drop(file);
        let path = self.image_path(name);
        tokio::fs::rename(&partial, &path)
            .await
            .map_err(VolumeError::io(format!(
                "renaming {} into place",
                partial.display()
            )))?;
        self.existing(name).await
    }
}

#[async_trait]
impl Volume for FileVolume
{
    fn kind(&self) -> VolumeKind
    {
        VolumeKind::File
    }

    async fn create(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        self.create_sparse(name, size_bytes).await
    }

    async fn create_blank(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        self.create_sparse(name, size_bytes).await
    }

    async fn get(&self, name: &str) -> Result<Option<VolumeInfo>, VolumeError>
    {
        validate_name(name)?;
        self.info(name).await
    }

    async fn list(&self) -> Result<Vec<VolumeInfo>, VolumeError>
    {
        let mut entries = match tokio::fs::read_dir(&self.dir).await
        {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) =>
            {
                return Err(VolumeError::io(format!("listing {}", self.dir.display()))(
                    error,
                ));
            }
        };
        let mut volumes = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(VolumeError::io(format!("listing {}", self.dir.display())))?
        {
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|file_name| file_name.strip_suffix(IMAGE_EXTENSION))
            else
            {
                continue;
            };
            if validate_name(name).is_err()
            {
                continue;
            }
            if let Some(info) = self.info(name).await?
            {
                volumes.push(info);
            }
        }
        volumes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(volumes)
    }

    async fn delete(&self, name: &str) -> Result<(), VolumeError>
    {
        validate_name(name)?;
        remove_if_present(&self.image_path(name)).await
    }

    async fn snapshot(&self, name: &str, snapshot_name: &str) -> Result<VolumeInfo, VolumeError>
    {
        validate_name(name)?;
        validate_name(snapshot_name)?;
        if let Some(info) = self.info(snapshot_name).await?
        {
            return Ok(info);
        }
        let source = self.existing(name).await?;
        let partial = self.partial_path(snapshot_name);
        remove_if_present(&partial).await?;
        tokio::fs::copy(&source.path, &partial)
            .await
            .map_err(VolumeError::io(format!(
                "copying {} to {}",
                source.path.display(),
                partial.display()
            )))?;
        let mut permissions = tokio::fs::metadata(&partial)
            .await
            .map_err(VolumeError::io(format!(
                "reading metadata of {}",
                partial.display()
            )))?
            .permissions();
        permissions.set_readonly(true);
        tokio::fs::set_permissions(&partial, permissions)
            .await
            .map_err(VolumeError::io(format!(
                "making {} read-only",
                partial.display()
            )))?;
        let path = self.image_path(snapshot_name);
        tokio::fs::rename(&partial, &path)
            .await
            .map_err(VolumeError::io(format!(
                "renaming {} into place",
                partial.display()
            )))?;
        self.existing(snapshot_name).await
    }

    async fn pool_usage(&self) -> Result<PoolUsage, VolumeError>
    {
        let used: u64 = self
            .list()
            .await?
            .iter()
            .map(|volume| volume.size_bytes)
            .sum();
        let used_percent = if self.capacity_bytes == 0
        {
            100.0
        }
        else
        {
            used as f64 * 100.0 / self.capacity_bytes as f64
        };
        Ok(PoolUsage {
            size_bytes: self.capacity_bytes,
            used_percent,
        })
    }
}

async fn remove_if_present(path: &Path) -> Result<(), VolumeError>
{
    match tokio::fs::remove_file(path).await
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VolumeError::io(format!("removing {}", path.display()))(
            error,
        )),
    }
}
