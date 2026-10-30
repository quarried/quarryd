use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::subnet::Subnet;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError
{
    #[error("invalid subnet {input:?}: {reason}")]
    InvalidSubnet
    {
        input: String, reason: &'static str
    },
    #[error("no free addresses left in {0}")]
    Exhausted(Subnet),
    #[error("invalid allocation of {ip} to instance {instance_id}: {reason}")]
    InvalidAllocation
    {
        instance_id: String,
        ip: Ipv4Addr,
        reason: String,
    },
    #[error("invalid network spec for instance {instance_id}: {reason}")]
    InvalidSpec
    {
        instance_id: String, reason: String
    },
    #[error("invalid node network configuration: {0}")]
    InvalidNodeNetwork(String),
    #[error("node network has not been configured")]
    NodeNotConfigured,
    #[error("instance {0} has no network attachment")]
    NotAttached(String),
    #[error("{context}: {source}")]
    Io
    {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{command} exited with {status}: {stderr}")]
    Command
    {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("unexpected output from {command}: {reason}")]
    UnexpectedOutput
    {
        command: String, reason: String
    },
    #[error("netlink {context}: {message}")]
    Netlink
    {
        context: String, message: String
    },
    #[error("state file {path}: {source}")]
    StateFile
    {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("injected failure: {0}")]
    Injected(String),
}

impl NetworkError
{
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> NetworkError
    {
        NetworkError::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn invalid_spec(instance_id: &str, reason: impl Into<String>) -> NetworkError
    {
        NetworkError::InvalidSpec {
            instance_id: instance_id.to_string(),
            reason: reason.into(),
        }
    }
}
