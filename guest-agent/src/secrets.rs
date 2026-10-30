use std::collections::HashMap;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const SECRETS_DIR_ENV: &str = "QUARRY_SECRETS_DIR";
const RUN_SECRETS_DIR: &str = "/run/quarry/secrets";

#[derive(Debug, PartialEq, Eq)]
pub struct SecretsDir
{
    pub path: PathBuf,
    pub reason: &'static str,
}

pub fn prepare_dir(override_dir: Option<&Path>, vm_init: bool) -> io::Result<SecretsDir>
{
    if let Some(dir) = override_dir
    {
        create_private_dir(dir)?;
        return Ok(SecretsDir {
            path: dir.to_path_buf(),
            reason: "set by QUARRY_SECRETS_DIR",
        });
    }
    #[cfg(target_os = "linux")]
    if vm_init
    {
        let dir = Path::new(RUN_SECRETS_DIR);
        fs::create_dir_all(dir)?;
        mount_tmpfs(dir)?;
        return Ok(SecretsDir {
            path: dir.to_path_buf(),
            reason: "dedicated tmpfs",
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = vm_init;
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute());
    choose_dir(
        Path::new(RUN_SECRETS_DIR),
        runtime_dir.as_deref(),
        &std::env::temp_dir(),
    )
}

fn choose_dir(run_dir: &Path, runtime_dir: Option<&Path>, temp_dir: &Path)
-> io::Result<SecretsDir>
{
    if create_private_dir(run_dir).is_ok()
    {
        return Ok(SecretsDir {
            path: run_dir.to_path_buf(),
            reason: "under /run",
        });
    }
    if let Some(runtime_dir) = runtime_dir
    {
        let dir = runtime_dir.join("quarry").join("secrets");
        if create_private_dir(&dir).is_ok()
        {
            return Ok(SecretsDir {
                path: dir,
                reason: "under $XDG_RUNTIME_DIR because /run is not writable",
            });
        }
    }
    let dir = temp_dir.join(format!("quarry-secrets-{}", std::process::id()));
    create_private_dir(&dir)?;
    Ok(SecretsDir {
        path: dir,
        reason: "temporary directory because /run and $XDG_RUNTIME_DIR are not writable; it may not be a tmpfs",
    })
}

fn create_private_dir(dir: &Path) -> io::Result<()>
{
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, Permissions::from_mode(0o700))
}

#[cfg(target_os = "linux")]
fn mount_tmpfs(dir: &Path) -> io::Result<()>
{
    use nix::mount::{MsFlags, mount};
    mount(
        Some("tmpfs"),
        dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=0700,size=4m"),
    )
    .map_err(io::Error::from)
}

pub fn write(dir: &Path, secrets: &HashMap<String, Vec<u8>>) -> io::Result<()>
{
    for (name, value) in secrets
    {
        write_one(&dir.join(name), value)
            .map_err(|error| io::Error::new(error.kind(), format!("secret {name}: {error}")))?;
    }
    Ok(())
}

fn write_one(path: &Path, value: &[u8]) -> io::Result<()>
{
    match fs::remove_file(path)
    {
        Ok(()) =>
        {}
        Err(error) if error.kind() == io::ErrorKind::NotFound =>
        {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(value)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn mode(path: &Path) -> u32
    {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn falls_back_to_the_runtime_dir_when_run_is_not_writable()
    {
        let scratch = tempfile::tempdir().unwrap();
        let blocker = scratch.path().join("not-a-dir");
        fs::write(&blocker, b"").unwrap();
        let runtime = scratch.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        let chosen = choose_dir(&blocker.join("secrets"), Some(&runtime), scratch.path()).unwrap();
        assert_eq!(chosen.path, runtime.join("quarry").join("secrets"));
        assert!(chosen.reason.contains("XDG_RUNTIME_DIR"));
        assert_eq!(mode(&chosen.path), 0o700);
    }

    #[test]
    fn falls_back_to_a_temp_dir_last()
    {
        let scratch = tempfile::tempdir().unwrap();
        let blocker = scratch.path().join("not-a-dir");
        fs::write(&blocker, b"").unwrap();
        let chosen = choose_dir(&blocker.join("run"), Some(&blocker), scratch.path()).unwrap();
        assert!(chosen.path.starts_with(scratch.path()));
        assert!(chosen.reason.contains("temporary"));
        assert_eq!(mode(&chosen.path), 0o700);
    }

    #[test]
    fn prefers_run_when_writable()
    {
        let scratch = tempfile::tempdir().unwrap();
        let run = scratch.path().join("run").join("quarry").join("secrets");
        let chosen = choose_dir(&run, None, scratch.path()).unwrap();
        assert_eq!(chosen.path, run);
        assert_eq!(mode(&run), 0o700);
    }

    #[test]
    fn override_is_used_as_is()
    {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("secrets");
        let chosen = prepare_dir(Some(&dir), false).unwrap();
        assert_eq!(chosen.path, dir);
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn secrets_are_written_read_only_and_replaced()
    {
        let scratch = tempfile::tempdir().unwrap();
        let secrets = HashMap::from([
            ("rcon.password".to_owned(), b"first".to_vec()),
            ("token".to_owned(), vec![0, 1, 2, 255]),
        ]);
        write(scratch.path(), &secrets).unwrap();
        let path = scratch.path().join("rcon.password");
        assert_eq!(fs::read(&path).unwrap(), b"first");
        assert_eq!(mode(&path), 0o400);
        assert_eq!(
            fs::read(scratch.path().join("token")).unwrap(),
            vec![0, 1, 2, 255]
        );
        let replaced = HashMap::from([("rcon.password".to_owned(), b"second".to_vec())]);
        write(scratch.path(), &replaced).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(mode(&path), 0o400);
    }

    #[test]
    fn errors_name_the_secret_but_not_its_value()
    {
        let scratch = tempfile::tempdir().unwrap();
        let missing = scratch.path().join("missing");
        let secrets = HashMap::from([("api".to_owned(), b"value-must-not-leak".to_vec())]);
        let error = write(&missing, &secrets).unwrap_err().to_string();
        assert!(error.contains("api"));
        assert!(!error.contains("value-must-not-leak"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root on Linux (mounts a tmpfs)"]
    fn the_secrets_tmpfs_is_private()
    {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("secrets");
        fs::create_dir(&dir).unwrap();
        let mounted = mount_tmpfs(&dir);
        let is_tmpfs = nix::sys::statfs::statfs(&dir)
            .map(|stats| stats.filesystem_type() == nix::sys::statfs::TMPFS_MAGIC)
            .unwrap_or(false);
        let dir_mode = mode(&dir);
        let secrets = HashMap::from([("key".to_owned(), b"v".to_vec())]);
        let written = write(&dir, &secrets);
        let file_mode = mode(&dir.join("key"));
        let _ = nix::mount::umount(&dir);
        mounted.unwrap();
        written.unwrap();
        assert!(is_tmpfs);
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o400);
    }
}
