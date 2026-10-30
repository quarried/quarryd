use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::UsageError;

const MAX_PENDING_BYTES: usize = 1 << 20;
const READ_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FirecrackerMetrics
{
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub block_read_bytes: u64,
    pub block_write_bytes: u64,
    pub vcpu_exits: u64,
}

impl FirecrackerMetrics
{
    fn accumulate(&mut self, delta: &FirecrackerMetrics)
    {
        self.net_rx_bytes = self.net_rx_bytes.saturating_add(delta.net_rx_bytes);
        self.net_tx_bytes = self.net_tx_bytes.saturating_add(delta.net_tx_bytes);
        self.block_read_bytes = self.block_read_bytes.saturating_add(delta.block_read_bytes);
        self.block_write_bytes = self
            .block_write_bytes
            .saturating_add(delta.block_write_bytes);
        self.vcpu_exits = self.vcpu_exits.saturating_add(delta.vcpu_exits);
    }
}

pub fn parse_firecracker_metrics(line: &str) -> Result<FirecrackerMetrics, UsageError>
{
    let value: Value = serde_json::from_str(line).map_err(UsageError::FirecrackerMetrics)?;
    if !value.is_object()
    {
        return Err(UsageError::Parse {
            what: "firecracker metrics",
            detail: "line is not a JSON object".to_string(),
        });
    }
    let counter = |section: &str, field: &str| {
        value
            .get(section)
            .and_then(|section| section.get(field))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let vcpu_exits = value
        .get("vcpu")
        .and_then(Value::as_object)
        .map(|vcpu| {
            vcpu.iter()
                .filter(|(name, _)| name.starts_with("exit_"))
                .filter_map(|(_, count)| count.as_u64())
                .fold(0_u64, u64::saturating_add)
        })
        .unwrap_or(0);
    Ok(FirecrackerMetrics {
        net_rx_bytes: counter("net", "rx_bytes_count"),
        net_tx_bytes: counter("net", "tx_bytes_count"),
        block_read_bytes: counter("block", "read_bytes"),
        block_write_bytes: counter("block", "write_bytes"),
        vcpu_exits,
    })
}

pub struct FirecrackerMetricsReader
{
    path: PathBuf,
    file: File,
    pending: Vec<u8>,
    totals: FirecrackerMetrics,
}

impl FirecrackerMetricsReader
{
    pub fn open(path: &Path) -> Result<FirecrackerMetricsReader, UsageError>
    {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(|source| UsageError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(FirecrackerMetricsReader {
            path: path.to_path_buf(),
            file,
            pending: Vec::new(),
            totals: FirecrackerMetrics::default(),
        })
    }

    pub fn totals(&self) -> FirecrackerMetrics
    {
        self.totals
    }

    pub fn read_available(&mut self) -> Result<FirecrackerMetrics, UsageError>
    {
        let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
        loop
        {
            match self.file.read(&mut chunk)
            {
                Ok(0) => break,
                Ok(read) =>
                {
                    self.pending.extend_from_slice(&chunk[..read]);
                    self.consume_complete_lines();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) =>
                {
                    return Err(UsageError::Io {
                        path: self.path.clone(),
                        source,
                    });
                }
            }
        }
        Ok(self.totals)
    }

    fn consume_complete_lines(&mut self)
    {
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n')
        {
            let line: Vec<u8> = self.pending.drain(..=newline).collect();
            let text = String::from_utf8_lossy(&line);
            let text = text.trim();
            if text.is_empty()
            {
                continue;
            }
            match parse_firecracker_metrics(text)
            {
                Ok(delta) => self.totals.accumulate(&delta),
                Err(error) =>
                {
                    tracing::warn!(path = %self.path.display(), %error, "skipping firecracker metrics line");
                }
            }
        }
        if self.pending.len() > MAX_PENDING_BYTES
        {
            tracing::warn!(
                path = %self.path.display(),
                bytes = self.pending.len(),
                "discarding oversized partial firecracker metrics line"
            );
            self.pending.clear();
        }
    }
}

#[cfg(test)]
mod tests
{
    use std::io::Write;
    use std::process::Command;

    use super::*;

    fn metrics_line(rx: u64, tx: u64, read: u64, write: u64) -> String
    {
        format!(
            concat!(
                r#"{{"utc_timestamp_ms":1700000000123,"#,
                r#""api_server":{{"process_startup_time_us":0,"process_startup_time_cpu_us":0}},"#,
                r#""balloon":{{"activate_fails":0,"inflate_count":0,"stats_updates_count":0}},"#,
                r#""block":{{"activate_fails":0,"cfg_fails":0,"no_avail_buffer":0,"event_fails":0,"#,
                r#""execute_fails":0,"invalid_reqs":0,"flush_count":2,"queue_event_count":120,"#,
                r#""rate_limiter_event_count":0,"update_count":0,"update_fails":0,"read_bytes":{read},"#,
                r#""write_bytes":{write},"read_count":64,"write_count":32,"rate_limiter_throttled_events":0}},"#,
                r#""block_rootfs":{{"read_bytes":{read},"write_bytes":0}},"#,
                r#""net":{{"activate_fails":0,"cfg_fails":0,"mac_address_updates":0,"no_rx_avail_buffer":0,"#,
                r#""no_tx_avail_buffer":0,"event_fails":0,"rx_queue_event_count":10,"rx_tap_event_count":40,"#,
                r#""rx_bytes_count":{rx},"rx_packets_count":40,"rx_fails":0,"rx_count":40,"tap_read_fails":0,"#,
                r#""tap_write_fails":0,"tx_bytes_count":{tx},"tx_malformed_frames":0,"tx_fails":0,"#,
                r#""tx_count":20,"tx_packets_count":20,"tx_spoofed_mac_count":0}},"#,
                r#""net_eth0":{{"rx_bytes_count":{rx},"tx_bytes_count":{tx}}},"#,
                r#""vcpu":{{"exit_io_in":10,"exit_io_out":20,"exit_mmio_read":30,"exit_mmio_write":40,"#,
                r#""failures":0,"exit_io_in_agg":{{"min_us":1,"max_us":9,"sum_us":30}}}},"#,
                r#""vmm":{{"device_events":5,"panic_count":0}}}}"#
            ),
            rx = rx,
            tx = tx,
            read = read,
            write = write
        )
    }

    #[test]
    fn parses_device_counters()
    {
        let metrics =
            parse_firecracker_metrics(&metrics_line(20_480, 10_240, 1_048_576, 524_288)).unwrap();
        assert_eq!(
            metrics,
            FirecrackerMetrics {
                net_rx_bytes: 20_480,
                net_tx_bytes: 10_240,
                block_read_bytes: 1_048_576,
                block_write_bytes: 524_288,
                vcpu_exits: 100,
            }
        );
    }

    #[test]
    fn missing_sections_read_as_zero()
    {
        let metrics = parse_firecracker_metrics(r#"{"utc_timestamp_ms":1}"#).unwrap();
        assert_eq!(metrics, FirecrackerMetrics::default());
    }

    #[test]
    fn rejects_invalid_lines()
    {
        assert!(matches!(
            parse_firecracker_metrics("{not json"),
            Err(UsageError::FirecrackerMetrics(_))
        ));
        assert!(matches!(
            parse_firecracker_metrics("[1,2]"),
            Err(UsageError::Parse { .. })
        ));
    }

    #[test]
    fn reader_accumulates_deltas_from_a_fifo()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics.fifo");
        let status = Command::new("mkfifo").arg(&path).status().unwrap();
        assert!(status.success());

        let mut reader = FirecrackerMetricsReader::open(&path).unwrap();
        assert_eq!(
            reader.read_available().unwrap(),
            FirecrackerMetrics::default()
        );

        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            reader.read_available().unwrap(),
            FirecrackerMetrics::default()
        );

        let first = metrics_line(100, 50, 4096, 8192);
        let second = metrics_line(10, 5, 0, 512);
        let (second_head, second_tail) = second.split_at(40);
        write!(writer, "{first}\nnot json\n{second_head}").unwrap();
        writer.flush().unwrap();
        let totals = reader.read_available().unwrap();
        assert_eq!(totals.net_rx_bytes, 100);
        assert_eq!(totals.block_write_bytes, 8192);

        writeln!(writer, "{second_tail}").unwrap();
        writer.flush().unwrap();
        let totals = reader.read_available().unwrap();
        assert_eq!(
            totals,
            FirecrackerMetrics {
                net_rx_bytes: 110,
                net_tx_bytes: 55,
                block_read_bytes: 4096,
                block_write_bytes: 8704,
                vcpu_exits: 200,
            }
        );
        assert_eq!(reader.totals(), totals);

        drop(writer);
        assert_eq!(reader.read_available().unwrap(), totals);
    }

    #[test]
    fn reader_open_fails_for_missing_path()
    {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            FirecrackerMetricsReader::open(&directory.path().join("absent")),
            Err(UsageError::Io { .. })
        ));
    }
}
