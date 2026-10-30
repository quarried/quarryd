use std::path::Path;

use crate::UsageError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupStats
{
    pub cpu_usage_usec: u64,
    pub memory_current_bytes: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}

pub fn parse_cpu_stat(text: &str) -> Result<u64, UsageError>
{
    for line in text.lines()
    {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("usage_usec")
        {
            let value = fields.next().unwrap_or_default();
            return value.parse().map_err(|_| UsageError::Parse {
                what: "cpu.stat",
                detail: format!("invalid usage_usec value {value:?}"),
            });
        }
    }
    Err(UsageError::Parse {
        what: "cpu.stat",
        detail: "missing usage_usec".to_string(),
    })
}

pub fn parse_io_stat(text: &str) -> (u64, u64)
{
    let mut read_bytes = 0_u64;
    let mut write_bytes = 0_u64;
    for line in text.lines()
    {
        for field in line.split_whitespace().skip(1)
        {
            let Some((key, value)) = field.split_once('=')
            else
            {
                continue;
            };
            let Ok(value) = value.parse::<u64>()
            else
            {
                continue;
            };
            match key
            {
                "rbytes" => read_bytes = read_bytes.saturating_add(value),
                "wbytes" => write_bytes = write_bytes.saturating_add(value),
                _ =>
                {}
            }
        }
    }
    (read_bytes, write_bytes)
}

pub fn parse_memory_current(text: &str) -> Result<u64, UsageError>
{
    let value = text.trim();
    value.parse().map_err(|_| UsageError::Parse {
        what: "memory.current",
        detail: format!("invalid value {value:?}"),
    })
}

pub async fn read_cgroup(path: &Path) -> Result<CgroupStats, UsageError>
{
    let cpu_stat = read_file(&path.join("cpu.stat")).await?;
    let memory_current = read_file(&path.join("memory.current")).await?;
    let io_stat = read_file(&path.join("io.stat")).await?;
    let (io_read_bytes, io_write_bytes) = parse_io_stat(&io_stat);
    Ok(CgroupStats {
        cpu_usage_usec: parse_cpu_stat(&cpu_stat)?,
        memory_current_bytes: parse_memory_current(&memory_current)?,
        io_read_bytes,
        io_write_bytes,
    })
}

async fn read_file(path: &Path) -> Result<String, UsageError>
{
    tokio::fs::read_to_string(path)
        .await
        .map_err(|source| UsageError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests
{
    use super::*;

    const CPU_STAT: &str = "usage_usec 81234567\n\
        user_usec 60123456\n\
        system_usec 21111111\n\
        core_sched.force_idle_usec 0\n\
        nr_periods 3021\n\
        nr_throttled 12\n\
        throttled_usec 450000\n\
        nr_bursts 0\n\
        burst_usec 0\n";

    const IO_STAT: &str = "259:0 rbytes=1048576 wbytes=4194304 rios=256 wios=1024 dbytes=0 dios=0\n\
        253:3 rbytes=524288 wbytes=8192 rios=128 wios=2 dbytes=4096 dios=1\n";

    #[test]
    fn parses_cpu_stat_usage()
    {
        assert_eq!(parse_cpu_stat(CPU_STAT).unwrap(), 81_234_567);
    }

    #[test]
    fn cpu_stat_without_usage_is_an_error()
    {
        assert!(parse_cpu_stat("user_usec 5\nsystem_usec 6\n").is_err());
        assert!(parse_cpu_stat("usage_usec abc\n").is_err());
        assert!(parse_cpu_stat("usage_usec\n").is_err());
        assert!(parse_cpu_stat("").is_err());
    }

    #[test]
    fn parses_io_stat_summed_over_devices()
    {
        assert_eq!(parse_io_stat(IO_STAT), (1_572_864, 4_202_496));
    }

    #[test]
    fn io_stat_tolerates_empty_and_malformed_input()
    {
        assert_eq!(parse_io_stat(""), (0, 0));
        assert_eq!(
            parse_io_stat("259:0 rbytes=x wbytes=10 garbage\n8:0\n"),
            (0, 10)
        );
    }

    #[test]
    fn parses_memory_current()
    {
        assert_eq!(parse_memory_current("2147483648\n").unwrap(), 2_147_483_648);
        assert!(parse_memory_current("max\n").is_err());
    }

    #[tokio::test]
    async fn reads_cgroup_directory()
    {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cpu.stat"), CPU_STAT).unwrap();
        std::fs::write(directory.path().join("memory.current"), "1073741824\n").unwrap();
        std::fs::write(directory.path().join("io.stat"), IO_STAT).unwrap();
        let stats = read_cgroup(directory.path()).await.unwrap();
        assert_eq!(
            stats,
            CgroupStats {
                cpu_usage_usec: 81_234_567,
                memory_current_bytes: 1_073_741_824,
                io_read_bytes: 1_572_864,
                io_write_bytes: 4_202_496,
            }
        );
    }

    #[tokio::test]
    async fn missing_io_stat_is_an_error()
    {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cpu.stat"), CPU_STAT).unwrap();
        std::fs::write(directory.path().join("memory.current"), "4096\n").unwrap();
        assert!(matches!(
            read_cgroup(directory.path()).await,
            Err(UsageError::Io { path, source })
                if path == directory.path().join("io.stat")
                    && source.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[tokio::test]
    async fn empty_io_stat_reads_as_zero()
    {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("cpu.stat"), CPU_STAT).unwrap();
        std::fs::write(directory.path().join("memory.current"), "4096\n").unwrap();
        std::fs::write(directory.path().join("io.stat"), "").unwrap();
        let stats = read_cgroup(directory.path()).await.unwrap();
        assert_eq!(stats.io_read_bytes, 0);
        assert_eq!(stats.io_write_bytes, 0);
        assert_eq!(stats.memory_current_bytes, 4096);
    }

    #[tokio::test]
    async fn missing_cpu_stat_is_an_error()
    {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("memory.current"), "4096\n").unwrap();
        assert!(matches!(
            read_cgroup(directory.path()).await,
            Err(UsageError::Io { .. })
        ));
    }

    #[tokio::test]
    #[ignore = "needs Linux cgroup v2 mounted at /sys/fs/cgroup with memory.current and io.stat (container or delegated cgroup)"]
    async fn reads_real_cgroup_v2()
    {
        let stats = read_cgroup(Path::new("/sys/fs/cgroup")).await.unwrap();
        assert!(stats.cpu_usage_usec > 0);
        assert!(stats.memory_current_bytes > 0);
    }
}
