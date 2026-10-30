use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use proto::v1::AgentUpdate;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use tracing::{error, info, warn};
use volume::{ArtifactDescriptor, ArtifactKind, ImageCache};

use sandbox::unit_bus::{TransientServiceProperties, UnitBus};

pub const ROLLBACK_UNIT: &str = "quarryd-rollback.service";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PendingUpdate
{
    pub version: String,
    pub digest: String,
    pub previous_version: String,
}

pub struct UpdatePaths
{
    pub binary: PathBuf,
    pub previous: PathBuf,
    pub marker: PathBuf,
}

impl UpdatePaths
{
    pub fn new(binary: PathBuf, state_dir: &Path) -> UpdatePaths
    {
        let mut previous = binary.clone().into_os_string();
        previous.push(".prev");
        UpdatePaths {
            binary,
            previous: PathBuf::from(previous),
            marker: state_dir.join("update-pending.json"),
        }
    }
}

pub struct Updater
{
    paths: UpdatePaths,
    current_version: String,
    images: Option<Arc<ImageCache>>,
    systemd: Option<UnitBus>,
    service_name: String,
    rollback_after: Duration,
    restart: Arc<watch::Sender<bool>>,
    in_progress: Mutex<bool>,
}

pub fn read_marker(path: &Path) -> Result<Option<PendingUpdate>>
{
    match std::fs::read(path)
    {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("parsing update marker")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_marker(path: &Path, marker: &PendingUpdate) -> Result<()>
{
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec(marker)?)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()>
{
    match std::fs::remove_file(path)
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn install_executable(source: &Path, destination: &Path) -> Result<()>
{
    use std::os::unix::fs::PermissionsExt;

    let mut staging = destination.as_os_str().to_owned();
    staging.push(".new");
    let staging = PathBuf::from(staging);
    std::fs::copy(source, &staging).with_context(|| format!("staging {}", staging.display()))?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
    std::fs::File::open(&staging)?.sync_all()?;
    std::fs::rename(&staging, destination)
        .with_context(|| format!("replacing {}", destination.display()))?;
    if let Some(parent) = destination.parent()
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub fn swap_in(paths: &UpdatePaths, new_binary: &Path) -> Result<()>
{
    install_executable(&paths.binary, &paths.previous)?;
    install_executable(new_binary, &paths.binary)
}

pub fn roll_back(paths: &UpdatePaths) -> Result<bool>
{
    if read_marker(&paths.marker)?.is_none()
    {
        return Ok(false);
    }
    if !paths.previous.exists()
    {
        bail!("no previous binary at {}", paths.previous.display());
    }
    install_executable(&paths.previous, &paths.binary)?;
    remove_if_present(&paths.marker)?;
    Ok(true)
}

impl Updater
{
    pub fn new(
        paths: UpdatePaths,
        current_version: String,
        images: Option<Arc<ImageCache>>,
        systemd: Option<UnitBus>,
        service_name: String,
        rollback_after: Duration,
        restart: Arc<watch::Sender<bool>>,
    ) -> Updater
    {
        Updater {
            paths,
            current_version,
            images,
            systemd,
            service_name,
            rollback_after,
            restart,
            in_progress: Mutex::new(false),
        }
    }

    pub fn begin(self: &Arc<Self>, update: AgentUpdate)
    {
        let updater = self.clone();
        tokio::spawn(async move {
            match updater.apply(update).await
            {
                Ok(true) => updater.restart.send_replace(true),
                Ok(false) => false,
                Err(error) =>
                {
                    error!(error = %format!("{error:#}"), "agent update failed");
                    false
                }
            };
        });
    }

    pub async fn apply(&self, update: AgentUpdate) -> Result<bool>
    {
        if update.version == self.current_version
        {
            info!(version = %update.version, "agent update already applied");
            return Ok(false);
        }
        let mut in_progress = self.in_progress.lock().await;
        if *in_progress
        {
            info!(version = %update.version, "agent update already in progress");
            return Ok(false);
        }
        *in_progress = true;
        let images = self
            .images
            .as_ref()
            .context("no artifact store configured for agent updates")?;
        let systemd = self
            .systemd
            .as_ref()
            .context("self-update requires systemd for the rollback watchdog")?;
        let artifact = images
            .ensure(
                &ArtifactDescriptor {
                    digest: update.digest.clone(),
                    key: update.key.clone(),
                    signature_key: update.signature_key.clone(),
                    size_bytes: update.size_bytes,
                },
                ArtifactKind::Agent,
            )
            .await
            .context("downloading and verifying the agent binary")?;
        write_marker(
            &self.paths.marker,
            &PendingUpdate {
                version: update.version.clone(),
                digest: update.digest.clone(),
                previous_version: self.current_version.clone(),
            },
        )?;
        if let Err(error) = swap_in(&self.paths, &artifact.path)
        {
            remove_if_present(&self.paths.marker)?;
            return Err(error);
        }
        let rollback_command = vec![
            self.paths.previous.display().to_string(),
            "rollback".to_string(),
            "--binary".to_string(),
            self.paths.binary.display().to_string(),
            "--marker".to_string(),
            self.paths.marker.display().to_string(),
            "--delay-secs".to_string(),
            self.rollback_after.as_secs().to_string(),
            "--service".to_string(),
            self.service_name.clone(),
        ];
        let _ = systemd.stop_unit(ROLLBACK_UNIT).await;
        let _ = systemd.reset_failed_unit(ROLLBACK_UNIT).await;
        let properties = TransientServiceProperties {
            description: "quarryd update rollback watchdog".to_string(),
            ..TransientServiceProperties::default()
        };
        systemd
            .start_transient_service(ROLLBACK_UNIT, &rollback_command, &properties)
            .await
            .context("arming the rollback watchdog")?;
        info!(version = %update.version, previous = %self.current_version, "agent binary swapped; exiting for restart");
        Ok(true)
    }

    pub async fn confirm_connected(&self)
    {
        match read_marker(&self.paths.marker)
        {
            Ok(Some(marker)) =>
            {
                if marker.version == self.current_version
                {
                    info!(version = %marker.version, "agent update confirmed by a control plane connection");
                }
                else
                {
                    warn!(expected = %marker.version, running = %self.current_version, "update marker does not match the running version");
                }
                if let Err(error) = remove_if_present(&self.paths.marker)
                {
                    warn!(error = %error, "failed to remove the update marker");
                }
                if let Some(systemd) = &self.systemd
                    && let Err(error) = systemd.stop_unit(ROLLBACK_UNIT).await
                {
                    warn!(error = %error, "failed to stop the rollback watchdog");
                }
            }
            Ok(None) =>
            {}
            Err(error) => warn!(error = %format!("{error:#}"), "unreadable update marker"),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn swap_and_rollback_restore_the_previous_binary()
    {
        let dir = tempfile::tempdir().unwrap();
        let paths = UpdatePaths::new(dir.path().join("quarryd"), dir.path());
        std::fs::write(&paths.binary, b"old").unwrap();
        let new_binary = dir.path().join("download");
        std::fs::write(&new_binary, b"new").unwrap();
        write_marker(
            &paths.marker,
            &PendingUpdate {
                version: "2".to_string(),
                digest: "d".to_string(),
                previous_version: "1".to_string(),
            },
        )
        .unwrap();
        swap_in(&paths, &new_binary).unwrap();
        assert_eq!(std::fs::read(&paths.binary).unwrap(), b"new");
        assert_eq!(std::fs::read(&paths.previous).unwrap(), b"old");
        assert!(roll_back(&paths).unwrap());
        assert_eq!(std::fs::read(&paths.binary).unwrap(), b"old");
        assert!(read_marker(&paths.marker).unwrap().is_none());
        assert!(!roll_back(&paths).unwrap());
    }

    #[test]
    fn rollback_without_marker_does_nothing()
    {
        let dir = tempfile::tempdir().unwrap();
        let paths = UpdatePaths::new(dir.path().join("quarryd"), dir.path());
        std::fs::write(&paths.binary, b"current").unwrap();
        assert!(!roll_back(&paths).unwrap());
        assert_eq!(std::fs::read(&paths.binary).unwrap(), b"current");
    }
}
