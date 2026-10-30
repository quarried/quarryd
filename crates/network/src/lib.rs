mod error;
mod fake;
mod instance;
mod ipam;
mod names;
pub mod nft;
mod node;
mod state_file;
mod subnet;
pub mod tc;
pub mod wireguard;

#[cfg(target_os = "linux")]
mod networking;

use std::path::PathBuf;

use async_trait::async_trait;

pub use error::NetworkError;
pub use fake::{FakeCall, FakeNetwork, FakeOperation};
pub use instance::{
    AttachMode, InstanceNetworkSpec, InterfaceCounters, NetworkAttachment, host_veth_mac,
    namespace_veth_mac,
};
pub use ipam::{Ipam, guest_mac};
pub use names::{IFNAMSIZ_MAX_LEN, InterfaceNames, NETNS_DIR};
#[cfg(target_os = "linux")]
pub use networking::Networking;
pub use node::{NodeNetwork, WireGuardPeerConfig};
pub use subnet::Subnet;

#[async_trait]
pub trait Network: Send + Sync
{
    async fn configure_node(&self, node: &NodeNetwork) -> Result<(), NetworkError>;
    async fn attach(&self, spec: &InstanceNetworkSpec) -> Result<NetworkAttachment, NetworkError>;
    async fn detach(&self, instance_id: &str) -> Result<(), NetworkError>;
    async fn counters(
        &self,
        attachment: &NetworkAttachment,
    ) -> Result<InterfaceCounters, NetworkError>;
    async fn wireguard_public_key(&self) -> Result<Option<String>, NetworkError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkingConfig
{
    pub state_dir: PathBuf,
    pub uplink_ifname: Option<String>,
    pub nft_bin: PathBuf,
    pub tc_bin: PathBuf,
    pub wg_bin: PathBuf,
}

impl NetworkingConfig
{
    pub fn new(state_dir: PathBuf) -> NetworkingConfig
    {
        NetworkingConfig {
            state_dir,
            uplink_ifname: None,
            nft_bin: PathBuf::from("nft"),
            tc_bin: PathBuf::from("tc"),
            wg_bin: PathBuf::from("wg"),
        }
    }
}

pub(crate) fn ensure_subnet_change_allowed(
    current: Option<&NodeNetwork>,
    has_attachments: bool,
    requested: &NodeNetwork,
) -> Result<(), NetworkError>
{
    match current
    {
        Some(current) if has_attachments && current.subnet != requested.subnet =>
        {
            Err(NetworkError::InvalidNodeNetwork(format!(
                "cannot move from subnet {} to {} while instances are attached",
                current.subnet, requested.subnet
            )))
        }
        _ => Ok(()),
    }
}
