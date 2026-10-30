use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::subnet::Subnet;
use crate::wireguard::{IpPrefix, is_valid_key};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardPeerConfig
{
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNetwork
{
    pub subnet: Subnet,
    pub region: String,
    pub wireguard_listen_port: u16,
    pub wireguard_address: Option<String>,
    pub peers: Vec<WireGuardPeerConfig>,
}

impl NodeNetwork
{
    pub fn wireguard_requested(&self) -> bool
    {
        self.wireguard_listen_port != 0
            || self.wireguard_address.is_some()
            || !self.peers.is_empty()
    }

    pub fn wireguard_prefix(&self) -> Result<Option<IpPrefix>, NetworkError>
    {
        self.wireguard_address
            .as_deref()
            .map(IpPrefix::parse)
            .transpose()
    }

    pub fn validate(&self) -> Result<(), NetworkError>
    {
        self.wireguard_prefix()?;
        let mut seen = std::collections::BTreeSet::new();
        for peer in &self.peers
        {
            if !is_valid_key(&peer.public_key)
            {
                return Err(NetworkError::InvalidNodeNetwork(format!(
                    "peer public key {:?} is not a base64 WireGuard key",
                    peer.public_key
                )));
            }
            if !seen.insert(peer.public_key.as_str())
            {
                return Err(NetworkError::InvalidNodeNetwork(format!(
                    "peer {} is listed more than once",
                    peer.public_key
                )));
            }
            if peer.endpoint.chars().any(char::is_whitespace)
            {
                return Err(NetworkError::InvalidNodeNetwork(format!(
                    "peer {} has a malformed endpoint {:?}",
                    peer.public_key, peer.endpoint
                )));
            }
            for allowed in &peer.allowed_ips
            {
                let prefix = IpPrefix::parse(allowed)?;
                if prefix.len == 0
                {
                    return Err(NetworkError::InvalidNodeNetwork(format!(
                        "peer {} allowed ip {allowed} would replace the default route",
                        peer.public_key
                    )));
                }
                if prefix.overlaps_subnet(self.subnet)
                {
                    return Err(NetworkError::InvalidNodeNetwork(format!(
                        "peer {} allowed ip {allowed} overlaps this node's instance subnet {}",
                        peer.public_key, self.subnet
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const KEY_A: &str = "YJ0yE1WkYc1y3ZtTV8mXH1v7Nf1F4q1Yq0fGkqJmSWc=";

    fn node() -> NodeNetwork
    {
        NodeNetwork {
            subnet: Subnet::parse("10.0.0.0/24").unwrap(),
            region: "eu-1".to_string(),
            wireguard_listen_port: 51820,
            wireguard_address: Some("10.250.0.1/24".to_string()),
            peers: vec![WireGuardPeerConfig {
                public_key: KEY_A.to_string(),
                endpoint: "203.0.113.7:51820".to_string(),
                allowed_ips: vec!["10.250.0.2/32".to_string(), "10.0.1.0/24".to_string()],
            }],
        }
    }

    #[test]
    fn accepts_a_valid_node()
    {
        node().validate().unwrap();
        assert!(node().wireguard_requested());
    }

    #[test]
    fn wireguard_is_not_requested_without_port_address_or_peers()
    {
        let node = NodeNetwork {
            wireguard_listen_port: 0,
            wireguard_address: None,
            peers: Vec::new(),
            ..node()
        };
        assert!(!node.wireguard_requested());
        node.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_peers()
    {
        let mut bad_key = node();
        bad_key.peers[0].public_key = "remove".to_string();
        let mut duplicate = node();
        duplicate.peers.push(duplicate.peers[0].clone());
        let mut default_route = node();
        default_route.peers[0].allowed_ips = vec!["0.0.0.0/0".to_string()];
        let mut overlapping = node();
        overlapping.peers[0].allowed_ips = vec!["10.0.0.128/25".to_string()];
        let mut endpoint = node();
        endpoint.peers[0].endpoint = "a b".to_string();
        let mut address = node();
        address.wireguard_address = Some("10.250.0.1/40".to_string());
        for case in [
            bad_key,
            duplicate,
            default_route,
            overlapping,
            endpoint,
            address,
        ]
        {
            assert!(case.validate().is_err(), "{case:?}");
        }
    }
}
