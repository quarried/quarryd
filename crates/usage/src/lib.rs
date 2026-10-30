use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use store::StoreError;

mod aggregator;
mod cgroup;
mod firecracker;
mod metrics;
mod net;
mod outbox;
mod server;

pub use aggregator::{BUCKET_SECONDS, UsageAggregator, UsageSample, usage_record_id};
pub use cgroup::{CgroupStats, parse_cpu_stat, parse_io_stat, parse_memory_current, read_cgroup};
pub use firecracker::{FirecrackerMetrics, FirecrackerMetricsReader, parse_firecracker_metrics};
pub use metrics::Metrics;
pub use net::{GuestNetCounters, interface_statistics_dir, read_tap_counters};
pub use outbox::Outbox;
pub use server::serve_metrics;
pub use store::UsageRow;

#[derive(Debug, thiserror::Error)]
pub enum UsageError
{
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("failed to read {path}: {source}")]
    Io
    {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse {what}: {detail}")]
    Parse
    {
        what: &'static str, detail: String
    },
    #[error("invalid firecracker metrics line: {0}")]
    FirecrackerMetrics(#[source] serde_json::Error),
    #[error("corrupt aggregator state for instance {instance_id}: {source}")]
    CorruptState
    {
        instance_id: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to encode aggregator state: {0}")]
    EncodeState(#[source] serde_json::Error),
    #[error("metrics address {0} is not a loopback address")]
    NotLoopback(SocketAddr),
    #[error("failed to bind metrics listener on {addr}: {source}")]
    Bind
    {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
}
