use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::error::NetworkError;
use crate::node::WireGuardPeerConfig;
use crate::subnet::Subnet;

pub const INTERFACE: &str = "wg-quarry";
pub const PERSISTENT_KEEPALIVE_SECS: u16 = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpPrefix
{
    pub addr: IpAddr,
    pub len: u8,
}

impl IpPrefix
{
    pub fn parse(text: &str) -> Result<IpPrefix, NetworkError>
    {
        let invalid =
            || NetworkError::InvalidNodeNetwork(format!("{text:?} is not an IP address or prefix"));
        let (address, len) = match text.split_once('/')
        {
            Some((address, len)) => (address, Some(len)),
            None => (text, None),
        };
        let addr: IpAddr = address.parse().map_err(|_| invalid())?;
        let max_len = match addr
        {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let len = match len
        {
            None => max_len,
            Some(len) if !len.is_empty() && len.bytes().all(|b| b.is_ascii_digit()) =>
            {
                len.parse::<u8>().map_err(|_| invalid())?
            }
            Some(_) => return Err(invalid()),
        };
        if len > max_len
        {
            return Err(invalid());
        }
        Ok(IpPrefix { addr, len })
    }

    pub fn network(&self) -> IpPrefix
    {
        let addr = match self.addr
        {
            IpAddr::V4(v4) =>
            {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) =>
            {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        IpPrefix {
            addr,
            len: self.len,
        }
    }

    pub fn overlaps_subnet(&self, subnet: Subnet) -> bool
    {
        let IpAddr::V4(v4) = self.network().addr
        else
        {
            return false;
        };
        let shorter = self.len.min(subnet.prefix_len());
        let mask = u32::MAX.checked_shl(32 - u32::from(shorter)).unwrap_or(0);
        u32::from(v4) & mask == u32::from(subnet.network()) & mask
    }
}

impl fmt::Display for IpPrefix
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

pub fn is_valid_key(key: &str) -> bool
{
    let bytes = key.as_bytes();
    bytes.len() == 44
        && bytes[43] == b'='
        && bytes[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

pub fn set_args(
    interface: &str,
    listen_port: u16,
    private_key_path: &Path,
    peers: &[WireGuardPeerConfig],
    current_peers: &[String],
) -> Vec<String>
{
    let mut args = vec![
        "set".to_string(),
        interface.to_string(),
        "listen-port".to_string(),
        listen_port.to_string(),
        "private-key".to_string(),
        private_key_path.display().to_string(),
    ];
    for peer in peers
    {
        args.push("peer".to_string());
        args.push(peer.public_key.clone());
        if !peer.endpoint.is_empty()
        {
            args.push("endpoint".to_string());
            args.push(peer.endpoint.clone());
        }
        args.push("persistent-keepalive".to_string());
        args.push(PERSISTENT_KEEPALIVE_SECS.to_string());
        args.push("allowed-ips".to_string());
        args.push(peer.allowed_ips.join(","));
    }
    for stale in current_peers
        .iter()
        .filter(|key| !peers.iter().any(|peer| &peer.public_key == *key))
    {
        args.push("peer".to_string());
        args.push(stale.clone());
        args.push("remove".to_string());
    }
    args
}

pub fn parse_peers(output: &str) -> Vec<String>
{
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn desired_routes(peers: &[WireGuardPeerConfig]) -> Result<Vec<IpPrefix>, NetworkError>
{
    let mut routes = Vec::new();
    for peer in peers
    {
        for allowed in &peer.allowed_ips
        {
            routes.push(IpPrefix::parse(allowed)?.network());
        }
    }
    routes.sort();
    routes.dedup();
    Ok(routes)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const KEY_A: &str = "YJ0yE1WkYc1y3ZtTV8mXH1v7Nf1F4q1Yq0fGkqJmSWc=";
    const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const KEY_C: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    fn peer(key: &str, endpoint: &str, allowed: &[&str]) -> WireGuardPeerConfig
    {
        WireGuardPeerConfig {
            public_key: key.to_string(),
            endpoint: endpoint.to_string(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn set_args_add_desired_and_remove_stale_peers()
    {
        let peers = vec![
            peer(
                KEY_A,
                "203.0.113.7:51820",
                &["10.250.0.2/32", "10.0.1.0/24"],
            ),
            peer(KEY_B, "", &[]),
        ];
        let current = vec![KEY_A.to_string(), KEY_C.to_string()];
        let args = set_args(
            INTERFACE,
            51820,
            Path::new("/state/wireguard.key"),
            &peers,
            &current,
        );
        assert_eq!(
            args,
            [
                "set",
                "wg-quarry",
                "listen-port",
                "51820",
                "private-key",
                "/state/wireguard.key",
                "peer",
                KEY_A,
                "endpoint",
                "203.0.113.7:51820",
                "persistent-keepalive",
                "25",
                "allowed-ips",
                "10.250.0.2/32,10.0.1.0/24",
                "peer",
                KEY_B,
                "persistent-keepalive",
                "25",
                "allowed-ips",
                "",
                "peer",
                KEY_C,
                "remove",
            ]
        );
    }

    #[test]
    fn parses_peer_listing()
    {
        let output = format!("{KEY_A}\n{KEY_B}\n\n");
        assert_eq!(
            parse_peers(&output),
            vec![KEY_A.to_string(), KEY_B.to_string()]
        );
        assert!(parse_peers("").is_empty());
    }

    #[test]
    fn validates_keys()
    {
        assert!(is_valid_key(KEY_A));
        assert!(!is_valid_key("remove"));
        assert!(!is_valid_key(&KEY_A.replace('=', "A")));
        assert!(!is_valid_key(&format!("-{}", &KEY_A[1..])));
    }

    #[test]
    fn parses_prefixes()
    {
        let prefix = IpPrefix::parse("10.0.1.7/24").unwrap();
        assert_eq!(prefix.network().to_string(), "10.0.1.0/24");
        assert_eq!(IpPrefix::parse("10.0.1.7").unwrap().len, 32);
        assert_eq!(
            IpPrefix::parse("fd00::1/64").unwrap().network().to_string(),
            "fd00::/64"
        );
        assert_eq!(
            IpPrefix::parse("0.0.0.0/0").unwrap().network().to_string(),
            "0.0.0.0/0"
        );
        for bad in [
            "",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/",
            "host/24",
            "10.0.0.0/-1",
        ]
        {
            assert!(IpPrefix::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn detects_overlap_with_the_instance_subnet()
    {
        let subnet = Subnet::parse("10.0.0.0/24").unwrap();
        assert!(
            IpPrefix::parse("10.0.0.0/16")
                .unwrap()
                .overlaps_subnet(subnet)
        );
        assert!(
            IpPrefix::parse("10.0.0.9/32")
                .unwrap()
                .overlaps_subnet(subnet)
        );
        assert!(
            !IpPrefix::parse("10.0.1.0/24")
                .unwrap()
                .overlaps_subnet(subnet)
        );
        assert!(!IpPrefix::parse("fd00::/8").unwrap().overlaps_subnet(subnet));
    }

    #[test]
    fn desired_routes_are_normalized_and_deduplicated()
    {
        let peers = vec![
            peer(KEY_A, "", &["10.0.1.5/24", "10.250.0.2"]),
            peer(KEY_B, "", &["10.0.1.0/24", "fd00::7/64"]),
        ];
        let routes: Vec<String> = desired_routes(&peers)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(routes, vec!["10.0.1.0/24", "10.250.0.2/32", "fd00::/64"]);
    }
}
