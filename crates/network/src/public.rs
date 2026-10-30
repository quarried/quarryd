use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{NetworkError, PublicIpMode, PublicIpv4Arp, PublicIpv4Config};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicState
{
    pub config: PublicIpv4Config,
    pub bindings: BTreeMap<String, PublicBinding>,
    #[serde(default)]
    pub retired_proxies: BTreeSet<ProxyNeighbour>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicBinding
{
    pub address: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub mode: PublicIpMode,
    pub responder_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct ProxyNeighbour
{
    pub interface: String,
    pub address: Ipv4Addr,
}

impl PublicState
{
    pub fn configure(&mut self, config: &PublicIpv4Config) -> Result<(), NetworkError>
    {
        validate_config(config)?;
        let mut updated = self.clone();
        updated.config = config.clone();
        for (instance_id, binding) in &self.bindings
        {
            updated.validate(instance_id, &binding.address.to_string())?;
        }
        if self.config != *config
        {
            self.retired_proxies.extend(self.proxies());
            self.config = config.clone();
        }
        Ok(())
    }

    pub fn validate(&self, instance_id: &str, address: &str) -> Result<(), NetworkError>
    {
        if address.is_empty()
        {
            return Ok(());
        }
        let address: Ipv4Addr = address.parse().map_err(|_| {
            NetworkError::invalid_spec(instance_id, "public_ipv4 must be an IPv4 address")
        })?;
        let mut in_pool = false;
        for entry in &self.config.pool
        {
            let (network, prefix) = pool_entry(entry)?;
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            in_pool |= u32::from(address) & mask == u32::from(network);
        }
        if !in_pool
        {
            return Err(NetworkError::invalid_spec(
                instance_id,
                format!("public IPv4 address {address} is outside this node's configured pool"),
            ));
        }
        if let Some((owner, _)) = self
            .bindings
            .iter()
            .find(|(owner, binding)| owner.as_str() != instance_id && binding.address == address)
        {
            return Err(NetworkError::invalid_spec(
                instance_id,
                format!("public IPv4 address {address} is already bound to instance {owner}"),
            ));
        }
        Ok(())
    }

    pub fn proxies(&self) -> BTreeSet<ProxyNeighbour>
    {
        if self.config.arp != PublicIpv4Arp::Proxy
        {
            return BTreeSet::new();
        }
        self.bindings
            .values()
            .map(|binding| ProxyNeighbour {
                interface: self.config.uplink_interface.clone(),
                address: binding.address,
            })
            .collect()
    }

    pub fn remove(&mut self, instance_id: &str)
    {
        if let Some(binding) = self.bindings.remove(instance_id)
            && self.config.arp == PublicIpv4Arp::Proxy
        {
            self.retired_proxies.insert(ProxyNeighbour {
                interface: self.config.uplink_interface.clone(),
                address: binding.address,
            });
        }
    }

    pub fn attach(
        &mut self,
        instance_id: &str,
        address: Ipv4Addr,
        guest_ip: Ipv4Addr,
    ) -> Result<(), NetworkError>
    {
        self.validate(instance_id, &address.to_string())?;
        if let Some(binding) = self.bindings.get_mut(instance_id)
            && binding.address == address
        {
            binding.guest_ip = guest_ip;
            return Ok(());
        }
        self.remove(instance_id);
        self.bindings.insert(
            instance_id.to_string(),
            PublicBinding {
                address,
                guest_ip,
                mode: PublicIpMode::Starting,
                responder_port: 0,
            },
        );
        Ok(())
    }
}

fn validate_config(config: &PublicIpv4Config) -> Result<(), NetworkError>
{
    if !config.pool.is_empty()
        && (config.uplink_interface.is_empty()
            || config.uplink_interface.len() > crate::IFNAMSIZ_MAX_LEN
            || !config
                .uplink_interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)))
    {
        return Err(NetworkError::InvalidNodeNetwork(
            "a public IPv4 pool requires a valid uplink_interface".to_string(),
        ));
    }
    for entry in &config.pool
    {
        pool_entry(entry)?;
    }
    Ok(())
}

fn pool_entry(entry: &str) -> Result<(Ipv4Addr, u8), NetworkError>
{
    let invalid =
        || NetworkError::InvalidNodeNetwork(format!("invalid public IPv4 pool entry {entry:?}"));
    let (address, prefix) = match entry.split_once('/')
    {
        Some((address, prefix)) => (address, prefix.parse::<u8>().map_err(|_| invalid())?),
        None => (entry, 32),
    };
    let address: Ipv4Addr = address.parse().map_err(|_| invalid())?;
    if prefix > 32
    {
        return Err(invalid());
    }
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    if u32::from(address) & !mask != 0
    {
        return Err(invalid());
    }
    Ok((address, prefix))
}
