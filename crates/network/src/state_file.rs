use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::NetworkError;

pub(crate) fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, NetworkError>
{
    let bytes = match fs::read(path)
    {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) =>
        {
            return Err(NetworkError::io(
                format!("reading {}", path.display()),
                error,
            ));
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| NetworkError::StateFile {
            path: path.to_path_buf(),
            source,
        })
}

pub(crate) fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), NetworkError>
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| NetworkError::StateFile {
        path: path.to_path_buf(),
        source,
    })?;
    write_atomically(path, &bytes, 0o644)
}

pub(crate) fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> Result<(), NetworkError>
{
    let context = |action: &str| format!("{action} {}", path.display());
    if let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent)
            .map_err(|e| NetworkError::io(context("creating the directory of"), e))?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = std::path::PathBuf::from(temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|e| NetworkError::io(context("creating a temporary file for"), e))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .map_err(|e| NetworkError::io(context("writing"), e))?;
    fs::rename(&temporary, path).map_err(|e| NetworkError::io(context("replacing"), e))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn round_trips_and_reports_missing_files_as_none()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");
        assert_eq!(load::<Vec<u32>>(&path).unwrap(), None);
        save(&path, &vec![1u32, 2, 3]).unwrap();
        assert_eq!(load::<Vec<u32>>(&path).unwrap(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn corrupt_files_are_errors()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            load::<Vec<u32>>(&path),
            Err(NetworkError::StateFile { .. })
        ));
    }
}
