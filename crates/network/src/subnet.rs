use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Subnet
{
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Subnet
{
    pub const MIN_PREFIX_LEN: u8 = 1;
    pub const MAX_PREFIX_LEN: u8 = 30;

    pub fn parse(s: &str) -> Result<Subnet, NetworkError>
    {
        let invalid = |reason: &'static str| NetworkError::InvalidSubnet {
            input: s.to_string(),
            reason,
        };
        let (address, prefix) = s
            .trim()
            .split_once('/')
            .ok_or_else(|| invalid("expected <address>/<prefix length>"))?;
        let network: Ipv4Addr = address
            .parse()
            .map_err(|_| invalid("address is not a valid IPv4 address"))?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid("prefix length is not a number"));
        }
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| invalid("prefix length is not a number"))?;
        if !(Self::MIN_PREFIX_LEN..=Self::MAX_PREFIX_LEN).contains(&prefix_len)
        {
            return Err(invalid(
                "prefix length must be between 1 and 30 so the subnet holds a gateway and at least one instance",
            ));
        }
        let subnet = Subnet {
            network,
            prefix_len,
        };
        if u32::from(network) & !subnet.mask_bits() != 0
        {
            return Err(invalid("address has host bits set"));
        }
        Ok(subnet)
    }

    pub fn network(&self) -> Ipv4Addr
    {
        self.network
    }

    pub fn prefix_len(&self) -> u8
    {
        self.prefix_len
    }

    pub fn netmask(&self) -> Ipv4Addr
    {
        Ipv4Addr::from(self.mask_bits())
    }

    pub fn gateway(&self) -> Ipv4Addr
    {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }

    pub fn broadcast(&self) -> Ipv4Addr
    {
        Ipv4Addr::from(u32::from(self.network) | !self.mask_bits())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool
    {
        u32::from(ip) & self.mask_bits() == u32::from(self.network)
    }

    pub fn is_instance_address(&self, ip: Ipv4Addr) -> bool
    {
        self.contains(ip) && ip != self.network && ip != self.gateway() && ip != self.broadcast()
    }

    pub fn instance_addresses(&self) -> impl Iterator<Item = Ipv4Addr> + use<>
    {
        let first = u32::from(self.gateway()) + 1;
        let last = u32::from(self.broadcast()) - 1;
        (first..=last).map(Ipv4Addr::from)
    }

    fn mask_bits(&self) -> u32
    {
        u32::MAX << (32 - u32::from(self.prefix_len))
    }
}

impl fmt::Display for Subnet
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Subnet
{
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Subnet, NetworkError>
    {
        Subnet::parse(s)
    }
}

impl TryFrom<String> for Subnet
{
    type Error = NetworkError;

    fn try_from(value: String) -> Result<Subnet, NetworkError>
    {
        Subnet::parse(&value)
    }
}

impl From<Subnet> for String
{
    fn from(subnet: Subnet) -> String
    {
        subnet.to_string()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn parses_a_slash_24()
    {
        let subnet = Subnet::parse("10.0.0.0/24").unwrap();
        assert_eq!(subnet.network(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(subnet.prefix_len(), 24);
        assert_eq!(subnet.gateway(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(subnet.broadcast(), Ipv4Addr::new(10, 0, 0, 255));
        assert_eq!(subnet.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(subnet.to_string(), "10.0.0.0/24");
    }

    #[test]
    fn from_str_and_display_round_trip()
    {
        let subnet: Subnet = "172.16.8.0/21".parse().unwrap();
        assert_eq!(subnet.to_string().parse::<Subnet>().unwrap(), subnet);
        assert_eq!(subnet.broadcast(), Ipv4Addr::new(172, 16, 15, 255));
    }

    #[test]
    fn rejects_malformed_input()
    {
        for input in [
            "",
            "10.0.0.0",
            "10.0.0.0/",
            "10.0.0/24",
            "10.0.0.0/abc",
            "10.0.0.0/+24",
            "10.0.0.0/33",
            "10.0.0.0/0",
            "10.0.0.0/31",
            "10.0.0.0/32",
            "fd00::/64",
            "10.0.0.1/24",
        ]
        {
            assert!(
                matches!(
                    Subnet::parse(input),
                    Err(NetworkError::InvalidSubnet { .. })
                ),
                "{input:?} should be rejected"
            );
        }
    }

    #[test]
    fn smallest_subnet_has_one_instance_address()
    {
        let subnet = Subnet::parse("192.168.1.4/30").unwrap();
        assert_eq!(subnet.gateway(), Ipv4Addr::new(192, 168, 1, 5));
        let addresses: Vec<_> = subnet.instance_addresses().collect();
        assert_eq!(addresses, vec![Ipv4Addr::new(192, 168, 1, 6)]);
    }

    #[test]
    fn contains_respects_boundaries()
    {
        let subnet = Subnet::parse("10.1.2.0/24").unwrap();
        assert!(subnet.contains(Ipv4Addr::new(10, 1, 2, 0)));
        assert!(subnet.contains(Ipv4Addr::new(10, 1, 2, 255)));
        assert!(!subnet.contains(Ipv4Addr::new(10, 1, 3, 0)));
        assert!(!subnet.contains(Ipv4Addr::new(10, 1, 1, 255)));
        assert!(!subnet.is_instance_address(Ipv4Addr::new(10, 1, 2, 0)));
        assert!(!subnet.is_instance_address(Ipv4Addr::new(10, 1, 2, 1)));
        assert!(!subnet.is_instance_address(Ipv4Addr::new(10, 1, 2, 255)));
        assert!(subnet.is_instance_address(Ipv4Addr::new(10, 1, 2, 2)));
        assert!(subnet.is_instance_address(Ipv4Addr::new(10, 1, 2, 254)));
    }

    #[test]
    fn large_subnet_edges()
    {
        let subnet = Subnet::parse("128.0.0.0/1").unwrap();
        assert_eq!(subnet.broadcast(), Ipv4Addr::new(255, 255, 255, 255));
        assert!(subnet.contains(Ipv4Addr::new(200, 1, 1, 1)));
        assert!(!subnet.contains(Ipv4Addr::new(10, 1, 1, 1)));
    }

    #[test]
    fn serializes_as_a_string()
    {
        let subnet = Subnet::parse("10.0.0.0/24").unwrap();
        let json = serde_json::to_string(&subnet).unwrap();
        assert_eq!(json, "\"10.0.0.0/24\"");
        assert_eq!(serde_json::from_str::<Subnet>(&json).unwrap(), subnet);
        assert!(serde_json::from_str::<Subnet>("\"10.0.0.0/33\"").is_err());
    }
}
