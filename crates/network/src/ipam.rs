use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::error::NetworkError;
use crate::subnet::Subnet;

#[derive(Clone, Debug)]
pub struct Ipam
{
    subnet: Subnet,
    by_instance: BTreeMap<String, Ipv4Addr>,
    in_use: BTreeSet<Ipv4Addr>,
}

impl Ipam
{
    pub fn new(
        subnet: Subnet,
        existing: impl IntoIterator<Item = (String, Ipv4Addr)>,
    ) -> Result<Ipam, NetworkError>
    {
        let mut ipam = Ipam {
            subnet,
            by_instance: BTreeMap::new(),
            in_use: BTreeSet::new(),
        };
        for (instance_id, ip) in existing
        {
            let invalid = |reason: &str| NetworkError::InvalidAllocation {
                instance_id: instance_id.clone(),
                ip,
                reason: reason.to_string(),
            };
            if !subnet.is_instance_address(ip)
            {
                return Err(invalid(
                    "address is outside the subnet or is its network, gateway, or broadcast address",
                ));
            }
            match ipam.by_instance.get(&instance_id)
            {
                Some(previous) if *previous == ip => continue,
                Some(_) => return Err(invalid("instance already has a different address")),
                None =>
                {}
            }
            if ipam.in_use.contains(&ip)
            {
                return Err(invalid("address is already allocated to another instance"));
            }
            ipam.in_use.insert(ip);
            ipam.by_instance.insert(instance_id, ip);
        }
        Ok(ipam)
    }

    pub fn allocate(&mut self, instance_id: &str) -> Result<Ipv4Addr, NetworkError>
    {
        if let Some(ip) = self.by_instance.get(instance_id)
        {
            return Ok(*ip);
        }
        let ip = self
            .subnet
            .instance_addresses()
            .find(|candidate| !self.in_use.contains(candidate))
            .ok_or(NetworkError::Exhausted(self.subnet))?;
        self.in_use.insert(ip);
        self.by_instance.insert(instance_id.to_string(), ip);
        Ok(ip)
    }

    pub fn release(&mut self, instance_id: &str)
    {
        if let Some(ip) = self.by_instance.remove(instance_id)
        {
            self.in_use.remove(&ip);
        }
    }

    pub fn get(&self, instance_id: &str) -> Option<Ipv4Addr>
    {
        self.by_instance.get(instance_id).copied()
    }

    pub fn subnet(&self) -> Subnet
    {
        self.subnet
    }

    pub fn allocations(&self) -> impl Iterator<Item = (&str, Ipv4Addr)>
    {
        self.by_instance.iter().map(|(id, ip)| (id.as_str(), *ip))
    }
}

pub fn guest_mac(ip: Ipv4Addr) -> String
{
    format_mac(mac_with_prefix(0x00, ip))
}

pub(crate) fn mac_with_prefix(second_octet: u8, ip: Ipv4Addr) -> [u8; 6]
{
    let [a, b, c, d] = ip.octets();
    [0x06, second_octet, a, b, c, d]
}

pub(crate) fn format_mac(mac: [u8; 6]) -> String
{
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(crate) fn parse_mac(text: &str) -> Option<[u8; 6]>
{
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for octet in &mut mac
    {
        let part = parts.next()?;
        if part.len() != 2
        {
            return None;
        }
        *octet = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some()
    {
        return None;
    }
    Some(mac)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn subnet() -> Subnet
    {
        Subnet::parse("10.0.0.0/29").unwrap()
    }

    #[test]
    fn allocation_is_idempotent_per_instance()
    {
        let mut ipam = Ipam::new(subnet(), []).unwrap();
        let first = ipam.allocate("a").unwrap();
        assert_eq!(ipam.allocate("a").unwrap(), first);
        assert_eq!(first, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ipam.get("a"), Some(first));
        assert_ne!(ipam.allocate("b").unwrap(), first);
    }

    #[test]
    fn never_hands_out_network_gateway_or_broadcast()
    {
        let mut ipam = Ipam::new(subnet(), []).unwrap();
        let mut handed_out = Vec::new();
        for n in 0..5
        {
            handed_out.push(ipam.allocate(&format!("i{n}")).unwrap());
        }
        assert_eq!(
            handed_out,
            (2..=6)
                .map(|last| Ipv4Addr::new(10, 0, 0, last))
                .collect::<Vec<_>>()
        );
        assert!(
            matches!(ipam.allocate("overflow"), Err(NetworkError::Exhausted(s)) if s == subnet())
        );
    }

    #[test]
    fn release_makes_the_address_reusable()
    {
        let mut ipam = Ipam::new(subnet(), []).unwrap();
        for n in 0..5
        {
            ipam.allocate(&format!("i{n}")).unwrap();
        }
        let freed = ipam.get("i2").unwrap();
        ipam.release("i2");
        ipam.release("i2");
        ipam.release("never-allocated");
        assert_eq!(ipam.get("i2"), None);
        assert_eq!(ipam.allocate("new").unwrap(), freed);
    }

    #[test]
    fn restores_existing_allocations()
    {
        let existing = vec![
            ("a".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
            ("b".to_string(), Ipv4Addr::new(10, 0, 0, 4)),
            ("b".to_string(), Ipv4Addr::new(10, 0, 0, 4)),
        ];
        let mut ipam = Ipam::new(subnet(), existing).unwrap();
        assert_eq!(ipam.get("a"), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(ipam.allocate("b").unwrap(), Ipv4Addr::new(10, 0, 0, 4));
        assert_eq!(ipam.allocate("c").unwrap(), Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(ipam.allocate("d").unwrap(), Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(ipam.allocations().count(), 4);
        assert_eq!(ipam.subnet(), subnet());
    }

    #[test]
    fn rejects_invalid_restored_allocations()
    {
        let cases = [
            vec![("a".to_string(), Ipv4Addr::new(10, 0, 0, 1))],
            vec![("a".to_string(), Ipv4Addr::new(10, 0, 0, 0))],
            vec![("a".to_string(), Ipv4Addr::new(10, 0, 0, 7))],
            vec![("a".to_string(), Ipv4Addr::new(10, 0, 1, 2))],
            vec![
                ("a".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
                ("b".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
            ],
            vec![
                ("a".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
                ("a".to_string(), Ipv4Addr::new(10, 0, 0, 3)),
            ],
        ];
        for existing in cases
        {
            assert!(matches!(
                Ipam::new(subnet(), existing.clone()),
                Err(NetworkError::InvalidAllocation { .. })
            ));
        }
    }

    #[test]
    fn guest_mac_is_deterministic_and_locally_administered()
    {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        assert_eq!(guest_mac(ip), "06:00:0a:00:00:05");
        assert_eq!(guest_mac(ip), guest_mac(ip));
        assert_ne!(guest_mac(ip), guest_mac(Ipv4Addr::new(10, 0, 0, 6)));
        let mac = parse_mac(&guest_mac(ip)).unwrap();
        assert_eq!(mac[0] & 0b10, 0b10, "locally administered bit");
        assert_eq!(mac[0] & 0b01, 0, "unicast");
    }

    #[test]
    fn parses_macs_strictly()
    {
        assert_eq!(parse_mac("06:00:0A:00:00:ff"), Some([6, 0, 10, 0, 0, 255]));
        for bad in [
            "",
            "06:00:0a:00:00",
            "06:00:0a:00:00:05:07",
            "6:00:0a:00:00:05",
            "zz:00:0a:00:00:05",
        ]
        {
            assert_eq!(parse_mac(bad), None, "{bad:?}");
        }
    }
}
