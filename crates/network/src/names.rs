use std::path::PathBuf;

pub const IFNAMSIZ_MAX_LEN: usize = 15;
pub const NETNS_DIR: &str = "/var/run/netns";
pub const SHORT_ID_LEN: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceNames
{
    pub short_id: String,
    pub netns: String,
    pub host_veth: String,
    pub guest_veth: String,
    pub tap: String,
}

impl InterfaceNames
{
    pub fn for_instance(instance_id: &str) -> InterfaceNames
    {
        let short_id = short_id(instance_id);
        InterfaceNames {
            netns: format!("quarry-{short_id}"),
            host_veth: format!("qh-{short_id}"),
            guest_veth: format!("qg-{short_id}"),
            tap: format!("qt-{short_id}"),
            short_id,
        }
    }

    pub fn netns_path(&self) -> PathBuf
    {
        PathBuf::from(NETNS_DIR).join(&self.netns)
    }
}

pub fn short_id(text: &str) -> String
{
    let mut hex = stable_hash_hex(text);
    hex.truncate(SHORT_ID_LEN);
    hex
}

pub fn stable_hash_hex(text: &str) -> String
{
    format!("{:016x}", fnv1a_64(text.as_bytes()))
}

fn fnv1a_64(bytes: &[u8]) -> u64
{
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn names_fit_ifnamsiz()
    {
        for id in [
            "",
            "a",
            "srv-0123456789abcdef0123456789abcdef",
            &"x".repeat(500),
        ]
        {
            let names = InterfaceNames::for_instance(id);
            for ifname in [&names.host_veth, &names.guest_veth, &names.tap]
            {
                assert!(ifname.len() <= IFNAMSIZ_MAX_LEN, "{ifname} is too long");
                assert!(
                    ifname
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                );
            }
        }
    }

    #[test]
    fn names_are_stable_and_distinct()
    {
        let first = InterfaceNames::for_instance("instance-1");
        assert_eq!(first, InterfaceNames::for_instance("instance-1"));
        assert_eq!(first.short_id, "3ca7aed14d");
        assert_eq!(first.host_veth, "qh-3ca7aed14d");
        assert_eq!(first.guest_veth, "qg-3ca7aed14d");
        assert_eq!(first.tap, "qt-3ca7aed14d");
        assert_eq!(first.netns, "quarry-3ca7aed14d");
        assert_eq!(
            first.netns_path(),
            PathBuf::from("/var/run/netns/quarry-3ca7aed14d")
        );
        let second = InterfaceNames::for_instance("instance-2");
        assert_ne!(first.short_id, second.short_id);
    }

    #[test]
    fn fnv_matches_reference_vectors()
    {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
