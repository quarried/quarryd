use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use crate::{PoolUsage, Volume, VolumeError, VolumeInfo, VolumeKind, validate_name};

const MKFS_PENDING_TAG: &str = "quarry_mkfs_pending";
const LV_FIELDS: &str = "lv_name,lv_size,lv_attr,lv_tags,pool_lv";
const POOL_FIELDS: &str = "lv_size,data_percent,metadata_percent";

pub struct LvmThin
{
    volume_group: String,
    thin_pool: String,
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
        PathBuf::from("/dev").join(&self.volume_group).join(name)
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
        let output = run(
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

    async fn activate(&self, volume: &LogicalVolume) -> Result<(), VolumeError>
    {
        if volume.is_active()
        {
            return Ok(());
        }
        run(
            "lvchange",
            &[
                "--activate",
                "y",
                "--ignoreactivationskip",
                &self.qualified(&volume.name),
            ],
        )
        .await
        .map(drop)
    }

    async fn create_thin(
        &self,
        name: &str,
        size_bytes: u64,
        tags: &[&str],
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
        run("lvcreate", &args).await.map(drop)
    }

    async fn format(&self, name: &str) -> Result<(), VolumeError>
    {
        let path = self.device_path(name);
        let path = path.to_string_lossy();
        run("mkfs.ext4", &["-q", "-F", &path]).await?;
        run(
            "lvchange",
            &["--deltag", MKFS_PENDING_TAG, &self.qualified(name)],
        )
        .await
        .map(drop)
    }

    async fn ensure_thin(
        &self,
        name: &str,
        size_bytes: u64,
        with_filesystem: bool,
    ) -> Result<VolumeInfo, VolumeError>
    {
        validate_name(name)?;
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
                self.create_thin(name, size_bytes, tags).await?;
                self.require(name).await?
            }
        };
        self.activate(&existing).await?;
        if existing.has_tag(MKFS_PENDING_TAG)
        {
            self.format(name).await?;
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
        if self.find(name).await?.is_none()
        {
            return Ok(());
        }
        match run("lvremove", &["--yes", &self.qualified(name)]).await
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
        let snapshot = match self.find(snapshot_name).await?
        {
            Some(snapshot) => snapshot,
            None =>
            {
                self.require(name).await?;
                run(
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
                )
                .await?;
                self.require(snapshot_name).await?
            }
        };
        self.activate(&snapshot).await?;
        if snapshot.is_writable()
        {
            run(
                "lvchange",
                &["--permission", "r", &self.qualified(snapshot_name)],
            )
            .await?;
        }
        Ok(self.info(&snapshot))
    }

    async fn pool_usage(&self) -> Result<PoolUsage, VolumeError>
    {
        let output = run(
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

async fn run(program: &str, args: &[&str]) -> Result<String, VolumeError>
{
    let command_line = format!("{program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(VolumeError::io(format!("running `{command_line}`")))?;
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
    use super::*;

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
        assert!(volumes[1].has_tag(MKFS_PENDING_TAG));
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
