use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum FreezeOutcome
{
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Frozen,
    Skipped(String),
}

pub fn sync_and_freeze(dir: &Path) -> Result<FreezeOutcome, String>
{
    nix::unistd::sync();
    freeze(dir)
}

#[cfg(target_os = "linux")]
mod ioctls
{
    nix::ioctl_readwrite!(fifreeze, b'X', 119, nix::libc::c_int);
    nix::ioctl_readwrite!(fithaw, b'X', 120, nix::libc::c_int);
}

#[cfg(target_os = "linux")]
pub fn is_mount_point(path: &Path) -> std::io::Result<bool>
{
    use std::os::unix::fs::MetadataExt;
    let own = std::fs::metadata(path)?;
    let parent = std::fs::metadata(path.join(".."))?;
    Ok(own.dev() != parent.dev())
}

#[cfg(target_os = "linux")]
pub fn freeze(dir: &Path) -> Result<FreezeOutcome, String>
{
    use nix::errno::Errno;
    use std::os::fd::AsRawFd;

    match std::fs::metadata(dir)
    {
        Ok(_) =>
        {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(FreezeOutcome::Skipped(format!(
                "{} does not exist",
                dir.display()
            )));
        }
        Err(error) => return Err(format!("stat {}: {error}", dir.display())),
    }
    let separate =
        is_mount_point(dir).map_err(|error| format!("stat {}: {error}", dir.display()))?;
    if !separate
    {
        return Ok(FreezeOutcome::Skipped(format!(
            "{} is not a separate filesystem",
            dir.display()
        )));
    }
    let file =
        std::fs::File::open(dir).map_err(|error| format!("open {}: {error}", dir.display()))?;
    let mut argument: nix::libc::c_int = 0;
    match unsafe { ioctls::fifreeze(file.as_raw_fd(), &mut argument) }
    {
        Ok(_) | Err(Errno::EBUSY) => Ok(FreezeOutcome::Frozen),
        Err(errno @ (Errno::EOPNOTSUPP | Errno::ENOTTY | Errno::EINVAL | Errno::ENOSYS)) =>
        {
            Ok(FreezeOutcome::Skipped(format!(
                "FIFREEZE is not supported on {} ({errno})",
                dir.display()
            )))
        }
        Err(errno) => Err(format!("FIFREEZE {}: {errno}", dir.display())),
    }
}

#[cfg(target_os = "linux")]
pub fn thaw(dir: &Path) -> Result<(), String>
{
    use nix::errno::Errno;
    use std::os::fd::AsRawFd;

    if !is_mount_point(dir).unwrap_or(false)
    {
        return Ok(());
    }
    let file =
        std::fs::File::open(dir).map_err(|error| format!("open {}: {error}", dir.display()))?;
    let mut argument: nix::libc::c_int = 0;
    match unsafe { ioctls::fithaw(file.as_raw_fd(), &mut argument) }
    {
        Ok(_) | Err(Errno::EINVAL) => Ok(()),
        Err(errno) => Err(format!("FITHAW {}: {errno}", dir.display())),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn freeze(_dir: &Path) -> Result<FreezeOutcome, String>
{
    Ok(FreezeOutcome::Skipped(
        "filesystem freeze is only available on Linux".to_owned(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn thaw(_dir: &Path) -> Result<(), String>
{
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_missing_directory_is_skipped()
    {
        let scratch = tempfile::tempdir().unwrap();
        let outcome = sync_and_freeze(&scratch.path().join("absent")).unwrap();
        assert!(matches!(outcome, FreezeOutcome::Skipped(_)));
    }

    #[test]
    fn a_directory_on_the_parent_filesystem_is_never_frozen()
    {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("data");
        std::fs::create_dir(&dir).unwrap();
        assert!(matches!(
            sync_and_freeze(&dir).unwrap(),
            FreezeOutcome::Skipped(_)
        ));
        assert_eq!(thaw(&dir), Ok(()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root on Linux with mkfs.ext4, losetup and loop devices"]
    fn an_ext4_mount_is_frozen_and_thawed()
    {
        use std::process::Command;
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("data.img");
        let dir = scratch.path().join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        assert!(
            Command::new("mkfs.ext4")
                .args(["-q", "-F"])
                .arg(&image)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("mount")
                .args(["-o", "loop"])
                .arg(&image)
                .arg(&dir)
                .status()
                .unwrap()
                .success()
        );
        assert!(is_mount_point(&dir).unwrap());
        let frozen = sync_and_freeze(&dir);
        let thawed = thaw(&dir);
        let unmounted = Command::new("umount").arg(&dir).status().unwrap();
        assert_eq!(frozen, Ok(FreezeOutcome::Frozen));
        assert_eq!(thawed, Ok(()));
        assert_eq!(thaw(&dir), Ok(()));
        assert!(unmounted.success());
    }
}
