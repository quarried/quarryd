//! Core engine of quarryd: the level-triggered [`Reconciler`], one
//! supervisor task per instance, the section 6 [`Lifecycle`], admission,
//! leases, the host side of the guest channel, adoption after restarts, and
//! usage sampling.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod admission;
mod error;
mod guest_channel;
mod leases;
mod lifecycle;
mod provision;
mod reconciler;
mod sampler;
mod supervisor;

#[cfg(test)]
mod tests;

pub use error::ReconcilerError;
pub use lifecycle::Lifecycle;
pub use reconciler::{Reconciler, ReconcilerHandle};

pub struct ReconcilerConfig
{
    pub node_id: String,
    pub capacity: proto::v1::Resources,
    pub reservation: proto::v1::Resources,
    pub default_lease_ttl: Duration,
    pub state_dir: PathBuf,
    pub uid_base: u32,
    pub uid_count: u32,
    pub console_max_bytes: u64,
    pub stop_deadline: Duration,
    pub kill_deadline: Duration,
    pub reconcile_interval: Duration,
    pub sample_interval: Duration,
    pub restart_backoff_base: Duration,
    pub restart_backoff_max: Duration,
    pub guest_rate_capacity: u32,
    pub guest_rate_per_sec: f64,
    pub guest_connect_timeout: Duration,
    pub ready_timeout: Duration,
}

pub struct ReconcilerParts
{
    pub store: Arc<store::Store>,
    pub sandbox: Arc<dyn sandbox::Sandbox>,
    pub volumes: Arc<volume::Volumes>,
    pub network: Arc<dyn network::Network>,
    pub images: Arc<volume::ImageCache>,
    pub snapshots: Option<Arc<volume::SnapshotStore>>,
    pub metrics: Arc<usage::Metrics>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReconcilerEvent
{
    Status(proto::v1::InstanceStatus),
}
