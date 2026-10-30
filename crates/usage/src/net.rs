use std::path::{Path, PathBuf};

use crate::UsageError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestNetCounters
{
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn interface_statistics_dir(interface: &str) -> PathBuf
{
    Path::new("/sys/class/net")
        .join(interface)
        .join("statistics")
}

pub async fn read_tap_counters(statistics_dir: &Path) -> Result<GuestNetCounters, UsageError>
{
    let host_rx_bytes = read_counter(&statistics_dir.join("rx_bytes")).await?;
    let host_tx_bytes = read_counter(&statistics_dir.join("tx_bytes")).await?;
    Ok(GuestNetCounters {
        rx_bytes: host_tx_bytes,
        tx_bytes: host_rx_bytes,
    })
}

async fn read_counter(path: &Path) -> Result<u64, UsageError>
{
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|source| UsageError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let value = text.trim();
    value.parse().map_err(|_| UsageError::Parse {
        what: "interface statistics counter",
        detail: format!("{}: invalid value {value:?}", path.display()),
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn statistics_dir_is_under_sysfs()
    {
        assert_eq!(
            interface_statistics_dir("qtap7"),
            Path::new("/sys/class/net/qtap7/statistics")
        );
    }

    #[tokio::test]
    async fn tap_counters_are_reported_from_the_guest_side()
    {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("rx_bytes"), "1500\n").unwrap();
        std::fs::write(directory.path().join("tx_bytes"), "90000\n").unwrap();
        let counters = read_tap_counters(directory.path()).await.unwrap();
        assert_eq!(
            counters,
            GuestNetCounters {
                rx_bytes: 90_000,
                tx_bytes: 1500,
            }
        );
    }

    #[tokio::test]
    async fn invalid_or_missing_counters_are_errors()
    {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_tap_counters(directory.path()).await,
            Err(UsageError::Io { .. })
        ));
        std::fs::write(directory.path().join("rx_bytes"), "x\n").unwrap();
        std::fs::write(directory.path().join("tx_bytes"), "1\n").unwrap();
        assert!(matches!(
            read_tap_counters(directory.path()).await,
            Err(UsageError::Parse { .. })
        ));
    }
}
