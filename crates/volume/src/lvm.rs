use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::{PoolUsage, Volume, VolumeError, VolumeInfo, VolumeKind, validate_name};

const LEGACY_MKFS_PENDING_TAG: &str = "quarry_mkfs_pending";
const MKFS_PENDING_TAG: &str = "quarry_mkfs_pending_v2";
const LOCK_DIRECTORY: &str = "/run/quarryd/volume-locks";
const LV_FIELDS: &str = "lv_name,lv_size,lv_attr,lv_tags,pool_lv";
const POOL_FIELDS: &str = "lv_size,data_percent,metadata_percent";

pub struct LvmThin
{
    volume_group: String,
    thin_pool: String,
    #[cfg(test)]
    test_root: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogicalVolume
{
    name: String,
    size_bytes: u64,
    attr: String,
    tags: Vec<String>,
    pool: String,
}

impl LogicalVolume
{
    fn is_active(&self) -> bool
    {
        self.attr.chars().nth(4) == Some('a')
    }

    fn is_writable(&self) -> bool
    {
        self.attr.chars().nth(1) == Some('w')
    }

    fn has_tag(&self, tag: &str) -> bool
    {
        self.tags.iter().any(|candidate| candidate == tag)
    }
}

impl LvmThin
{
    pub fn new(volume_group: String, thin_pool: String) -> LvmThin
    {
        LvmThin {
            volume_group,
            thin_pool,
            #[cfg(test)]
            test_root: None,
        }
    }

    pub fn volume_group(&self) -> &str
    {
        &self.volume_group
    }

    pub fn thin_pool(&self) -> &str
    {
        &self.thin_pool
    }

    fn device_path(&self, name: &str) -> PathBuf
    {
        #[cfg(test)]
        if let Some(root) = &self.test_root
        {
            return root.join("dev").join(name);
        }
        PathBuf::from("/dev").join(&self.volume_group).join(name)
    }

    fn program<'a>(&self, name: &'a str) -> Cow<'a, str>
    {
        #[cfg(test)]
        if let Some(root) = &self.test_root
        {
            return Cow::Owned(root.join("bin").join(name).to_string_lossy().into_owned());
        }
        Cow::Borrowed(name)
    }

    async fn run(&self, program: &str, args: &[&str]) -> Result<String, VolumeError>
    {
        run_with_lock(&self.program(program), args, None).await
    }

    async fn run_locked(&self, program: &str, args: &[&str], lock: &File) -> Result<String, VolumeError>
    {
        run_with_lock(&self.program(program), args, Some(lock)).await
    }

    fn qualified(&self, name: &str) -> String
    {
        format!("{}/{}", self.volume_group, name)
    }

    fn info(&self, volume: &LogicalVolume) -> VolumeInfo
    {
        VolumeInfo {
            name: volume.name.clone(),
            path: self.device_path(&volume.name),
            size_bytes: volume.size_bytes,
        }
    }

    async fn logical_volumes(&self) -> Result<Vec<LogicalVolume>, VolumeError>
    {
        let output = self.run(
            "lvs",
            &[
                "--noheadings",
                "--units",
                "b",
                "--nosuffix",
                "--separator",
                "|",
                "-o",
                LV_FIELDS,
                &self.volume_group,
            ],
        )
        .await?;
        let volumes = parse_logical_volumes(&output)?;
        Ok(volumes
            .into_iter()
            .filter(|volume| volume.pool == self.thin_pool)
            .collect())
    }

    async fn find(&self, name: &str) -> Result<Option<LogicalVolume>, VolumeError>
    {
        Ok(self
            .logical_volumes()
            .await?
            .into_iter()
            .find(|volume| volume.name == name))
    }

    async fn require(&self, name: &str) -> Result<LogicalVolume, VolumeError>
    {
        self.find(name).await?.ok_or_else(|| VolumeError::NotFound {
            name: name.to_owned(),
        })
    }

    async fn activate(&self, volume: &LogicalVolume, lock: &File) -> Result<(), VolumeError>
    {
        if volume.is_active()
        {
            return Ok(());
        }
        self.run_locked(
            "lvchange",
            &[
                "--activate",
                "y",
                "--ignoreactivationskip",
                &self.qualified(&volume.name),
            ],
            lock,
        )
        .await
        .map(drop)
    }

    async fn create_thin(
        &self,
        name: &str,
        size_bytes: u64,
        tags: &[&str],
        lock: &File,
    ) -> Result<(), VolumeError>
    {
        let size = format!("{size_bytes}b");
        let pool = self.qualified(&self.thin_pool);
        let mut args = vec![
            "--yes",
            "--virtualsize",
            &size,
            "--thinpool",
            &pool,
            "--name",
            name,
            "--activate",
            "y",
        ];
        for tag in tags
        {
            args.push("--addtag");
            args.push(tag);
        }
        self.run_locked("lvcreate", &args, lock).await.map(drop)
    }

    async fn format(&self, name: &str, lock: &File) -> Result<(), VolumeError>
    {
        let path = self.device_path(name);
        self.run_locked("mkfs.ext4", &["-q", "-F", &path.to_string_lossy()], lock).await?;
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .map_err(VolumeError::io(format!("opening {} after formatting", path.display())))?
            .sync_all()
            .await
            .map_err(VolumeError::io(format!("syncing {} after formatting", path.display())))?;
        self.run_locked(
            "lvchange",
            &["--deltag", MKFS_PENDING_TAG, &self.qualified(name)],
            lock,
        )
        .await
        .map(drop)
    }

    async fn recover_legacy(&self, volume: &LogicalVolume, lock: &File) -> Result<(), VolumeError>
    {
        let path = self.device_path(&volume.name);
        let args = ["-p", "-o", "value", "-s", "TYPE", "--", &path.to_string_lossy()];
        let output = command_output(&self.program("blkid"), &args, Some(lock)).await?;
        match legacy_filesystem(&output)?
        {
            LegacyFilesystem::Ext4 =>
            {
                // The legacy shortcut could expose a filesystem before clearing its tag.
                // It may contain a world already, so never run mkfs on it again.
                let mut args = vec!["--deltag", LEGACY_MKFS_PENDING_TAG];
                if volume.has_tag(MKFS_PENDING_TAG)
                {
                    args.extend(["--deltag", MKFS_PENDING_TAG]);
                }
                let qualified = self.qualified(&volume.name);
                args.push(&qualified);
                self.run_locked("lvchange", &args, lock).await?;
            }
            LegacyFilesystem::NoSignature =>
            {
                if !is_zeroed(&path, volume.size_bytes).await?
                {
                    return Err(VolumeError::Integrity {
                        detail: format!("refusing to format legacy pending volume {}: unrecognized nonblank data", volume.name),
                    });
                }
                self.run_locked(
                    "lvchange",
                    &["--addtag", MKFS_PENDING_TAG, "--deltag", LEGACY_MKFS_PENDING_TAG, &self.qualified(&volume.name)],
                    lock,
                ).await?;
                self.format(&volume.name, lock).await?;
            }
        }
        Ok(())
    }

    async fn lock_volume(&self, name: &str) -> Result<File, VolumeError>
    {
        let digest = Sha256::digest(self.qualified(name).as_bytes());
        let key: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        #[cfg(test)]
        if let Some(root) = &self.test_root
        {
            return acquire_lock(root.join("locks").join(format!("{key}.lock"))).await;
        }
        acquire_lock(Path::new(LOCK_DIRECTORY).join(format!("{key}.lock"))).await
    }

    async fn ensure_thin(
        &self,
        name: &str,
        size_bytes: u64,
        with_filesystem: bool,
    ) -> Result<VolumeInfo, VolumeError>
    {
        validate_name(name)?;
        let lock = self.lock_volume(name).await?;
        let existing = match self.find(name).await?
        {
            Some(volume) => volume,
            None =>
            {
                let tags: &[&str] = if with_filesystem
                {
                    &[MKFS_PENDING_TAG]
                }
                else
                {
                    &[]
                };
                self.create_thin(name, size_bytes, tags, &lock).await?;
                self.require(name).await?
            }
        };
        self.activate(&existing, &lock).await?;
        if existing.has_tag(LEGACY_MKFS_PENDING_TAG)
        {
            self.recover_legacy(&existing, &lock).await?;
        }
        else if existing.has_tag(MKFS_PENDING_TAG)
        {
            self.format(name, &lock).await?;
        }
        Ok(self.info(&existing))
    }
}

#[async_trait]
impl Volume for LvmThin
{
    fn kind(&self) -> VolumeKind
    {
        VolumeKind::LvmThin
    }

    async fn create(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        self.ensure_thin(name, size_bytes, true).await
    }

    async fn create_blank(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        self.ensure_thin(name, size_bytes, false).await
    }

    async fn get(&self, name: &str) -> Result<Option<VolumeInfo>, VolumeError>
    {
        validate_name(name)?;
        Ok(self.find(name).await?.map(|volume| self.info(&volume)))
    }

    async fn list(&self) -> Result<Vec<VolumeInfo>, VolumeError>
    {
        let mut volumes: Vec<VolumeInfo> = self
            .logical_volumes()
            .await?
            .iter()
            .map(|volume| self.info(volume))
            .collect();
        volumes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(volumes)
    }

    async fn delete(&self, name: &str) -> Result<(), VolumeError>
    {
        validate_name(name)?;
        let lock = self.lock_volume(name).await?;
        if self.find(name).await?.is_none()
        {
            return Ok(());
        }
        match self.run_locked("lvremove", &["--yes", &self.qualified(name)], &lock).await
        {
            Ok(_) => Ok(()),
            Err(error) => match self.find(name).await?
            {
                None => Ok(()),
                Some(_) => Err(error),
            },
        }
    }

    async fn snapshot(&self, name: &str, snapshot_name: &str) -> Result<VolumeInfo, VolumeError>
    {
        validate_name(name)?;
        validate_name(snapshot_name)?;
        let lock = self.lock_volume(snapshot_name).await?;
        let snapshot = match self.find(snapshot_name).await?
        {
            Some(snapshot) => snapshot,
            None =>
            {
                self.require(name).await?;
                self.run_locked(
                    "lvcreate",
                    &[
                        "--yes",
                        "--snapshot",
                        "--setactivationskip",
                        "n",
                        "--activate",
                        "y",
                        "--permission",
                        "r",
                        "--name",
                        snapshot_name,
                        &self.qualified(name),
                    ],
                    &lock,
                )
                .await?;
                self.require(snapshot_name).await?
            }
        };
        self.activate(&snapshot, &lock).await?;
        if snapshot.is_writable()
        {
            self.run_locked(
                "lvchange",
                &["--permission", "r", &self.qualified(snapshot_name)],
                &lock,
            )
            .await?;
        }
        Ok(self.info(&snapshot))
    }

    async fn pool_usage(&self) -> Result<PoolUsage, VolumeError>
    {
        let output = self.run(
            "lvs",
            &[
                "--noheadings",
                "--units",
                "b",
                "--nosuffix",
                "--separator",
                "|",
                "-o",
                POOL_FIELDS,
                &self.qualified(&self.thin_pool),
            ],
        )
        .await?;
        parse_pool_usage(&output)
    }
}

async fn run_with_lock(program: &str, args: &[&str], lock: Option<&File>) -> Result<String, VolumeError>
{
    let command_line = format!("{program} {}", args.join(" "));
    let output = command_output(program, args, lock).await?;
    if !output.status.success()
    {
        return Err(VolumeError::Command {
            command: command_line,
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    String::from_utf8(output.stdout).map_err(|error| VolumeError::Parse {
        command: command_line,
        detail: error.to_string(),
    })
}

async fn command_output(program: &str, args: &[&str], lock: Option<&File>) -> Result<Output, VolumeError>
{
    // A clone of the locked open-file description survives in the child even if
    // quarryd is killed. Recovery cannot race an orphan lvcreate/mkfs/lvchange.
    let stdin = match lock
    {
        Some(lock) => Stdio::from(lock.try_clone().map_err(VolumeError::io("inheriting volume lock"))?),
        None => Stdio::null(),
    };
    Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(stdin)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(VolumeError::io(format!("running `{program} {}`", args.join(" "))))
}

async fn acquire_lock(path: PathBuf) -> Result<File, VolumeError>
{
    tokio::task::spawn_blocking(move || {
        let directory = path.parent().expect("volume lock has a parent directory");
        std::fs::create_dir_all(directory)
            .map_err(VolumeError::io(format!("creating {}", directory.display())))?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(VolumeError::io(format!("opening {}", path.display())))?;
        file.lock().map_err(VolumeError::io(format!("locking {}", path.display())))?;
        Ok(file)
    }).await?
}

#[derive(Debug, PartialEq, Eq)]
enum LegacyFilesystem
{
    Ext4,
    NoSignature,
}

fn legacy_filesystem(output: &Output) -> Result<LegacyFilesystem, VolumeError>
{
    let kind = String::from_utf8_lossy(&output.stdout);
    if output.status.success() && kind.trim() == "ext4"
    {
        return Ok(LegacyFilesystem::Ext4);
    }
    if output.status.code() == Some(2) && kind.trim().is_empty() && output.stderr.is_empty()
    {
        return Ok(LegacyFilesystem::NoSignature);
    }
    Err(VolumeError::Integrity {
        detail: format!(
            "refusing to format legacy pending volume: blkid returned {} with type {:?}: {}",
            output.status,
            kind.trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        ),
    })
}

async fn is_zeroed(path: &Path, size_bytes: u64) -> Result<bool, VolumeError>
{
    let mut file = tokio::fs::File::open(path).await
        .map_err(VolumeError::io(format!("opening {} to inspect legacy volume", path.display())))?;
    let mut remaining = size_bytes;
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining != 0
    {
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count]).await
            .map_err(VolumeError::io(format!("checking {} for existing data", path.display())))?;
        if buffer[..count].iter().any(|byte| *byte != 0)
        {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    Ok(true)
}

fn parse_error(fields: &str, detail: impl Into<String>) -> VolumeError
{
    VolumeError::Parse {
        command: format!("lvs -o {fields}"),
        detail: detail.into(),
    }
}

fn parse_bytes(fields: &str, value: &str) -> Result<u64, VolumeError>
{
    let value = value.trim();
    let digits = value.split('.').next().unwrap_or(value);
    digits
        .parse()
        .map_err(|_| parse_error(fields, format!("invalid size {value:?}")))
}

fn parse_logical_volumes(output: &str) -> Result<Vec<LogicalVolume>, VolumeError>
{
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('|').map(str::trim).collect();
            let [name, size, attr, tags, pool] = fields[..]
            else
            {
                return Err(parse_error(LV_FIELDS, format!("unexpected line {line:?}")));
            };
            Ok(LogicalVolume {
                name: name.to_owned(),
                size_bytes: parse_bytes(LV_FIELDS, size)?,
                attr: attr.to_owned(),
                tags: tags
                    .split(',')
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned)
                    .collect(),
                pool: pool.to_owned(),
            })
        })
        .collect()
}

fn parse_percent(value: &str) -> Result<f64, VolumeError>
{
    value
        .trim()
        .parse()
        .map_err(|_| parse_error(POOL_FIELDS, format!("invalid percentage {value:?}")))
}

fn parse_pool_usage(output: &str) -> Result<PoolUsage, VolumeError>
{
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| parse_error(POOL_FIELDS, "no output"))?;
    let fields: Vec<&str> = line.split('|').map(str::trim).collect();
    let [size, data, metadata] = fields[..]
    else
    {
        return Err(parse_error(
            POOL_FIELDS,
            format!("unexpected line {line:?}"),
        ));
    };
    let used_percent = parse_percent(data)?.max(parse_percent(metadata)?);
    Ok(PoolUsage {
        size_bytes: parse_bytes(POOL_FIELDS, size)?,
        used_percent,
    })
}

#[cfg(test)]
mod tests
{
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::Arc;

    use super::*;

    const MOCK_LVM: &str = r#"#!/bin/sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
tool=${0##*/}
case "$tool" in
    lvs)
        [ -e "$root/exists" ] || exit 0
        printf 'world|4096|Vwi-%s-tz--|%s|pool\n' "$(cat "$root/active")" "$(cat "$root/tags")"
        ;;
    blkid)
        cat "$root/probe"
        exit "$(cat "$root/probe-status")"
        ;;
    mkfs.ext4)
        printf 'mkfs\n' >> "$root/log"
        printf 'formatted filesystem\n' > "$root/dev/world"
        printf 'ext4\n' > "$root/probe"
        printf '0\n' > "$root/probe-status"
        ;;
    lvcreate)
        printf 'lvcreate %s\n' "$*" >> "$root/log"
        touch "$root/exists"
        printf 'a\n' > "$root/active"
        : > "$root/tags"
        while [ "$#" -gt 0 ]; do
            if [ "$1" = --addtag ]; then
                printf '%s\n' "$2" > "$root/tags"
                shift
            fi
            shift
        done
        dd if=/dev/zero of="$root/dev/world" bs=4096 count=1 2>/dev/null
        ;;
    lvchange)
        printf 'lvchange %s\n' "$*" >> "$root/log"
        tags=$(cat "$root/tags")
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --activate)
                    if [ "$2" = y ]; then printf 'a\n'; else printf -- '-\n'; fi > "$root/active"
                    shift
                    ;;
                --addtag)
                    tags="${tags:+$tags,}$2"
                    shift
                    ;;
                --deltag)
                    [ ! -e "$root/fail-clear" ] || exit 5
                    tags=$(printf '%s\n' "$tags" | tr ',' '\n' | sed "/^$2$/d" | paste -sd, -)
                    shift
                    ;;
            esac
            shift
        done
        printf '%s\n' "$tags" > "$root/tags"
        ;;
    *) exit 99 ;;
esac
"#;

    fn mock_backend(tags: &str, data: &[u8]) -> (tempfile::TempDir, Arc<LvmThin>)
    {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir(root.join("bin")).unwrap();
        std::fs::create_dir(root.join("dev")).unwrap();
        for program in ["lvs", "lvchange", "lvcreate", "blkid", "mkfs.ext4"]
        {
            let path = root.join("bin").join(program);
            std::fs::write(&path, MOCK_LVM).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, contents) in [
            ("exists", ""), ("active", "-"), ("tags", tags), ("probe", ""),
            ("probe-status", "2"), ("log", ""),
        ]
        {
            std::fs::write(root.join(name), contents).unwrap();
        }
        std::fs::write(root.join("dev/world"), data).unwrap();
        let mut lvm = LvmThin::new("vg".to_owned(), "pool".to_owned());
        lvm.test_root = Some(root.to_path_buf());
        (directory, Arc::new(lvm))
    }

    fn mock_log(directory: &tempfile::TempDir) -> String
    {
        std::fs::read_to_string(directory.path().join("log")).unwrap()
    }

    #[tokio::test]
    async fn pending_v2_is_retried_until_tag_clear_then_never_reformatted()
    {
        let (directory, lvm) = mock_backend(MKFS_PENDING_TAG, &[0; 4096]);
        let volumes = crate::Volumes::new(lvm.clone());
        let failure = directory.path().join("fail-clear");
        std::fs::write(&failure, "").unwrap();
        assert!(volumes.ensure("world", 4096).await.is_err());
        assert_eq!(mock_log(&directory).lines().filter(|line| *line == "mkfs").count(), 1);
        assert!(std::fs::read_to_string(directory.path().join("tags")).unwrap().contains(MKFS_PENDING_TAG));
        std::fs::remove_file(failure).unwrap();
        let info = volumes.ensure("world", 4096).await.unwrap();
        assert_eq!(mock_log(&directory).lines().filter(|line| *line == "mkfs").count(), 2);
        std::fs::write(&info.path, b"new world data").unwrap();
        volumes.ensure("world", 4096).await.unwrap();
        assert_eq!(std::fs::read(&info.path).unwrap(), b"new world data");
        assert_eq!(mock_log(&directory).lines().filter(|line| *line == "mkfs").count(), 2);
        assert!(mock_log(&directory).contains("--activate y"));
    }

    #[tokio::test]
    async fn legacy_ext4_world_is_preserved_even_if_both_pending_tags_exist()
    {
        let tags = format!("{LEGACY_MKFS_PENDING_TAG},{MKFS_PENDING_TAG}");
        let (directory, lvm) = mock_backend(&tags, b"existing world data");
        std::fs::write(directory.path().join("probe"), "ext4\n").unwrap();
        std::fs::write(directory.path().join("probe-status"), "0").unwrap();
        let volumes = crate::Volumes::new(lvm);
        let info = volumes.ensure("world", 4096).await.unwrap();
        assert_eq!(std::fs::read(&info.path).unwrap(), b"existing world data");
        assert!(!mock_log(&directory).lines().any(|line| line == "mkfs"));
        assert!(std::fs::read_to_string(directory.path().join("tags")).unwrap().trim().is_empty());
        volumes.ensure("world", 4096).await.unwrap();
        assert_eq!(std::fs::read(&info.path).unwrap(), b"existing world data");
    }

    #[tokio::test]
    async fn legacy_unknown_data_is_never_formatted_but_a_blank_volume_recovers()
    {
        let mut bytes = vec![0; 4096];
        bytes[4095] = 1;
        let (directory, lvm) = mock_backend(LEGACY_MKFS_PENDING_TAG, &bytes);
        let volumes = crate::Volumes::new(lvm);
        assert!(matches!(volumes.ensure("world", 4096).await, Err(VolumeError::Integrity { .. })));
        assert_eq!(std::fs::read(directory.path().join("dev/world")).unwrap(), bytes);
        assert!(!mock_log(&directory).lines().any(|line| line == "mkfs"));
        std::fs::write(directory.path().join("dev/world"), [0; 4096]).unwrap();
        let info = volumes.ensure("world", 4096).await.unwrap();
        assert_eq!(std::fs::read(info.path).unwrap(), b"formatted filesystem\n");
        assert!(mock_log(&directory).contains("--addtag quarry_mkfs_pending_v2 --deltag quarry_mkfs_pending"));
    }

    #[tokio::test]
    async fn new_volumes_use_the_v2_marker_and_blank_existing_volumes_are_activated()
    {
        let (directory, lvm) = mock_backend("", &[0; 4096]);
        let volumes = crate::Volumes::new(lvm.clone());
        let blank = volumes.ensure_blank("world", 4096).await.unwrap();
        assert_eq!(std::fs::read(blank.path).unwrap(), [0; 4096]);
        assert!(mock_log(&directory).contains("--activate y"));
        assert!(!mock_log(&directory).lines().any(|line| line == "mkfs"));
        std::fs::remove_file(directory.path().join("exists")).unwrap();
        lvm.create("world", 4096).await.unwrap();
        let log = mock_log(&directory);
        assert!(log.lines().any(|line| line.starts_with("lvcreate ") && line.ends_with("--addtag quarry_mkfs_pending_v2")));
        assert_eq!(log.lines().filter(|line| *line == "mkfs").count(), 1);
    }

    fn probe_output(code: i32, kind: &str, stderr: &str) -> Output
    {
        Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: kind.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn legacy_recovery_preserves_ext4_and_rejects_ambiguous_probes()
    {
        assert_eq!(
            legacy_filesystem(&probe_output(0, "ext4\n", "")).unwrap(),
            LegacyFilesystem::Ext4
        );
        assert_eq!(
            legacy_filesystem(&probe_output(2, "", "")).unwrap(),
            LegacyFilesystem::NoSignature
        );
        for output in [
            probe_output(0, "xfs\n", ""),
            probe_output(0, "", ""),
            probe_output(8, "ext4\n", "ambivalent result"),
            probe_output(2, "", "read failed"),
        ]
        {
            assert!(matches!(legacy_filesystem(&output), Err(VolumeError::Integrity { .. })));
        }
    }

    #[tokio::test]
    async fn legacy_blank_check_inspects_the_entire_volume_and_rejects_short_reads()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.img");
        let size = 2 * 1024 * 1024 + 1;
        let mut file = File::create(&path).unwrap();
        file.set_len(size).unwrap();
        assert!(is_zeroed(&path, size).await.unwrap());
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[1]).unwrap();
        file.sync_all().unwrap();
        assert!(!is_zeroed(&path, size).await.unwrap());
        file.set_len(1024).unwrap();
        assert!(is_zeroed(&path, size).await.is_err());
    }

    #[tokio::test]
    async fn child_retains_volume_lock_after_parent_handle_is_dropped()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("volume.lock");
        let lock = acquire_lock(path.clone()).await.unwrap();
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::from(lock.try_clone().unwrap()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        drop(lock);
        let next = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        assert!(matches!(next.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        next.try_lock().unwrap();
    }

    #[test]
    fn parses_logical_volumes()
    {
        let output = "  pool|107374182400|twi-aotz--||\n  \
                      world-1|10737418240|Vwi-aotz--|quarry_mkfs_pending|pool\n  \
                      world-1-snap|10737418240|Vri---tz-k|a,b|pool\n\n";
        let volumes = parse_logical_volumes(output).unwrap();
        assert_eq!(volumes.len(), 3);
        assert_eq!(volumes[0].pool, "");
        assert_eq!(volumes[1].name, "world-1");
        assert_eq!(volumes[1].size_bytes, 10_737_418_240);
        assert!(volumes[1].is_active());
        assert!(volumes[1].is_writable());
        assert!(volumes[1].has_tag(LEGACY_MKFS_PENDING_TAG));
        assert_eq!(volumes[2].pool, "pool");
        assert_eq!(volumes[2].tags, vec!["a".to_owned(), "b".to_owned()]);
        assert!(!volumes[2].is_active());
        assert!(!volumes[2].is_writable());
    }

    #[test]
    fn rejects_malformed_logical_volume_line()
    {
        assert!(matches!(
            parse_logical_volumes("world-1|10|Vwi-aotz--"),
            Err(VolumeError::Parse { .. })
        ));
        assert!(matches!(
            parse_logical_volumes("world-1|ten|Vwi-aotz--||"),
            Err(VolumeError::Parse { .. })
        ));
    }

    #[test]
    fn pool_usage_takes_the_fuller_of_data_and_metadata()
    {
        let usage = parse_pool_usage("  107374182400|42.50|91.20\n").unwrap();
        assert_eq!(usage.size_bytes, 107_374_182_400);
        assert!((usage.used_percent - 91.2).abs() < 1e-9);
        let usage = parse_pool_usage("  1024|80.00|1.00\n").unwrap();
        assert!((usage.used_percent - 80.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_malformed_pool_usage()
    {
        assert!(parse_pool_usage("").is_err());
        assert!(parse_pool_usage("1024||1.00").is_err());
    }

    #[test]
    fn device_paths_live_under_the_volume_group()
    {
        let lvm = LvmThin::new("vg0".to_owned(), "pool".to_owned());
        assert_eq!(lvm.device_path("world"), PathBuf::from("/dev/vg0/world"));
        assert_eq!(lvm.qualified("world"), "vg0/world");
        assert_eq!(lvm.kind(), VolumeKind::LvmThin);
    }
}
