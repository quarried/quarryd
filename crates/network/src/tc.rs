pub const INGRESS_HANDLE: &str = "ffff:";
pub const POLICER_PREF: &str = "1";
pub const POLICER_HANDLE: &str = "800::800";
pub const POLICER_MTU_BYTES: u64 = 65_535;
pub const BURST_WINDOW_MILLIS: u64 = 20;
pub const MIN_BURST_BYTES: u64 = 64 * 1024;

const _: () = assert!(MIN_BURST_BYTES >= POLICER_MTU_BYTES);

pub fn police_burst_bytes(egress_mbit: u32) -> u64
{
    let bytes_per_second = u64::from(egress_mbit) * 1_000_000 / 8;
    (bytes_per_second * BURST_WINDOW_MILLIS / 1000).max(MIN_BURST_BYTES)
}

pub fn ingress_qdisc_args(host_ifname: &str) -> Vec<String>
{
    strings(&[
        "qdisc",
        "replace",
        "dev",
        host_ifname,
        "handle",
        INGRESS_HANDLE,
        "ingress",
    ])
}

pub fn egress_police_filter_args(host_ifname: &str, egress_mbit: u32) -> Vec<String>
{
    let rate = format!("{egress_mbit}mbit");
    let burst = police_burst_bytes(egress_mbit).to_string();
    let mtu = POLICER_MTU_BYTES.to_string();
    strings(&[
        "filter",
        "replace",
        "dev",
        host_ifname,
        "parent",
        INGRESS_HANDLE,
        "pref",
        POLICER_PREF,
        "handle",
        POLICER_HANDLE,
        "protocol",
        "all",
        "u32",
        "match",
        "u32",
        "0",
        "0",
        "action",
        "police",
        "rate",
        &rate,
        "burst",
        &burst,
        "mtu",
        &mtu,
        "conform-exceed",
        "drop",
    ])
}

pub fn remove_ingress_qdisc_args(host_ifname: &str) -> Vec<String>
{
    strings(&[
        "qdisc",
        "del",
        "dev",
        host_ifname,
        "handle",
        INGRESS_HANDLE,
        "ingress",
    ])
}

pub fn egress_limit_commands(host_ifname: &str, egress_mbit: u32) -> Vec<Vec<String>>
{
    if egress_mbit == 0
    {
        return Vec::new();
    }
    vec![
        ingress_qdisc_args(host_ifname),
        egress_police_filter_args(host_ifname, egress_mbit),
    ]
}

pub fn is_missing_qdisc_error(stderr: &str) -> bool
{
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("cannot find specified qdisc")
        || stderr.contains("invalid handle")
        || stderr.contains("no such file or directory")
        || stderr.contains("cannot find device")
}

fn strings(parts: &[&str]) -> Vec<String>
{
    parts.iter().map(|part| part.to_string()).collect()
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn limit_polices_traffic_entering_the_host_from_the_instance()
    {
        let commands = egress_limit_commands("qh-0123456789", 100);
        assert_eq!(
            commands,
            vec![
                strings(&[
                    "qdisc",
                    "replace",
                    "dev",
                    "qh-0123456789",
                    "handle",
                    "ffff:",
                    "ingress"
                ]),
                strings(&[
                    "filter",
                    "replace",
                    "dev",
                    "qh-0123456789",
                    "parent",
                    "ffff:",
                    "pref",
                    "1",
                    "handle",
                    "800::800",
                    "protocol",
                    "all",
                    "u32",
                    "match",
                    "u32",
                    "0",
                    "0",
                    "action",
                    "police",
                    "rate",
                    "100mbit",
                    "burst",
                    "250000",
                    "mtu",
                    "65535",
                    "conform-exceed",
                    "drop",
                ]),
            ]
        );
    }

    #[test]
    fn zero_means_unlimited()
    {
        assert!(egress_limit_commands("qh-0123456789", 0).is_empty());
        assert_eq!(
            remove_ingress_qdisc_args("qh-0123456789"),
            strings(&[
                "qdisc",
                "del",
                "dev",
                "qh-0123456789",
                "handle",
                "ffff:",
                "ingress"
            ])
        );
    }

    #[test]
    fn burst_has_a_floor_that_admits_full_size_offloaded_packets()
    {
        assert_eq!(police_burst_bytes(1), MIN_BURST_BYTES);
        assert_eq!(police_burst_bytes(1000), 2_500_000);
    }

    #[test]
    fn recognizes_missing_qdisc_errors()
    {
        assert!(is_missing_qdisc_error(
            "Error: Cannot find specified qdisc on specified device."
        ));
        assert!(!is_missing_qdisc_error(
            "RTNETLINK answers: Operation not permitted"
        ));
    }
}
