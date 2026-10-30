use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::ipam::{format_mac, mac_with_prefix, parse_mac};
use crate::names::InterfaceNames;
use crate::subnet::Subnet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachMode
{
    Tap,
    Veth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNetworkSpec
{
    pub instance_id: String,
    pub world_id: String,
    pub guest_ip: Ipv4Addr,
    pub guest_mac: String,
    pub egress_mbit: u32,
    pub ports: Vec<u16>,
    pub mode: AttachMode,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAttachment
{
    pub instance_id: String,
    pub netns_path: Option<PathBuf>,
    pub host_ifname: String,
    pub tap_name: Option<String>,
    pub guest_ip: Ipv4Addr,
    pub guest_mac: String,
    pub gateway: Ipv4Addr,
    pub prefix_len: u8,
    pub world_id: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterfaceCounters
{
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl InstanceNetworkSpec
{
    pub fn validate(&self, subnet: Subnet) -> Result<(), NetworkError>
    {
        let invalid = |reason: String| NetworkError::invalid_spec(&self.instance_id, reason);
        if self.instance_id.is_empty()
        {
            return Err(invalid("instance id is empty".to_string()));
        }
        if !subnet.is_instance_address(self.guest_ip)
        {
            return Err(invalid(format!(
                "guest ip {} is not an instance address of {subnet}",
                self.guest_ip
            )));
        }
        let mac = parse_mac(&self.guest_mac)
            .ok_or_else(|| invalid(format!("guest mac {:?} is malformed", self.guest_mac)))?;
        if mac[0] & 0b01 != 0
        {
            return Err(invalid(format!(
                "guest mac {} is not a unicast address",
                self.guest_mac
            )));
        }
        if self.ports.contains(&0)
        {
            return Err(invalid("port 0 cannot be exposed".to_string()));
        }
        Ok(())
    }

    pub(crate) fn ensure_address_is_free<'a>(
        &self,
        attached: impl IntoIterator<Item = (&'a str, Ipv4Addr)>,
    ) -> Result<(), NetworkError>
    {
        match attached
            .into_iter()
            .find(|(instance_id, ip)| *ip == self.guest_ip && *instance_id != self.instance_id)
        {
            Some((owner, _)) => Err(NetworkError::invalid_spec(
                &self.instance_id,
                format!(
                    "guest ip {} is already attached to instance {owner}",
                    self.guest_ip
                ),
            )),
            None => Ok(()),
        }
    }

    pub fn normalized_guest_mac(&self) -> String
    {
        self.guest_mac.to_ascii_lowercase()
    }

    pub fn exposed_ports(&self) -> Vec<u16>
    {
        let mut ports = self.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn attachment(&self, subnet: Subnet) -> NetworkAttachment
    {
        let names = InterfaceNames::for_instance(&self.instance_id);
        NetworkAttachment {
            instance_id: self.instance_id.clone(),
            netns_path: Some(names.netns_path()),
            host_ifname: names.host_veth.clone(),
            tap_name: match self.mode
            {
                AttachMode::Tap => Some(names.tap.clone()),
                AttachMode::Veth => None,
            },
            guest_ip: self.guest_ip,
            guest_mac: self.normalized_guest_mac(),
            gateway: subnet.gateway(),
            prefix_len: subnet.prefix_len(),
            world_id: self.world_id.clone(),
        }
    }
}

pub fn host_veth_mac(guest_ip: Ipv4Addr) -> String
{
    format_mac(mac_with_prefix(0x01, guest_ip))
}

pub fn namespace_veth_mac(guest_ip: Ipv4Addr) -> String
{
    format_mac(mac_with_prefix(0x02, guest_ip))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::ipam::guest_mac;

    fn spec() -> InstanceNetworkSpec
    {
        InstanceNetworkSpec {
            instance_id: "srv-1".to_string(),
            world_id: "world-a".to_string(),
            guest_ip: Ipv4Addr::new(10, 0, 0, 5),
            guest_mac: guest_mac(Ipv4Addr::new(10, 0, 0, 5)),
            egress_mbit: 100,
            ports: vec![25565, 25565, 19132],
            mode: AttachMode::Tap,
            uid: 10_005,
            gid: 10_005,
        }
    }

    #[test]
    fn valid_spec_produces_attachment()
    {
        let subnet = Subnet::parse("10.0.0.0/24").unwrap();
        let spec = spec();
        spec.validate(subnet).unwrap();
        let attachment = spec.attachment(subnet);
        let names = InterfaceNames::for_instance("srv-1");
        assert_eq!(attachment.gateway, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(attachment.prefix_len, 24);
        assert_eq!(attachment.host_ifname, names.host_veth);
        assert_eq!(attachment.tap_name, Some(names.tap.clone()));
        assert_eq!(attachment.netns_path, Some(names.netns_path()));
        assert_eq!(spec.exposed_ports(), vec![19132, 25565]);
        let veth = InstanceNetworkSpec {
            mode: AttachMode::Veth,
            ..spec
        };
        assert_eq!(veth.attachment(subnet).tap_name, None);
    }

    #[test]
    fn rejects_invalid_specs()
    {
        let subnet = Subnet::parse("10.0.0.0/24").unwrap();
        let cases = [
            InstanceNetworkSpec {
                instance_id: String::new(),
                ..spec()
            },
            InstanceNetworkSpec {
                guest_ip: Ipv4Addr::new(10, 0, 0, 1),
                ..spec()
            },
            InstanceNetworkSpec {
                guest_ip: Ipv4Addr::new(10, 0, 1, 5),
                ..spec()
            },
            InstanceNetworkSpec {
                guest_mac: "nonsense".to_string(),
                ..spec()
            },
            InstanceNetworkSpec {
                guest_mac: "01:00:5e:00:00:01".to_string(),
                ..spec()
            },
            InstanceNetworkSpec {
                ports: vec![0],
                ..spec()
            },
        ];
        for case in cases
        {
            assert!(
                matches!(case.validate(subnet), Err(NetworkError::InvalidSpec { .. })),
                "{case:?}"
            );
        }
    }

    #[test]
    fn link_macs_are_distinct_from_the_guest_mac()
    {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        assert_eq!(host_veth_mac(ip), "06:01:0a:00:00:05");
        assert_eq!(namespace_veth_mac(ip), "06:02:0a:00:00:05");
        assert_ne!(host_veth_mac(ip), guest_mac(ip));
    }
}
