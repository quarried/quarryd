#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

use network::{
    AttachMode, InstanceNetworkSpec, Network, Networking, NetworkingConfig, NodeNetwork, Subnet,
    guest_mac, nft,
};
use serde_json::Value;

fn spec(id: &str, last_octet: u8) -> InstanceNetworkSpec
{
    let guest_ip = Ipv4Addr::new(10, 233, 91, last_octet);
    InstanceNetworkSpec {
        instance_id: id.to_string(),
        world_id: "retirement-old".to_string(),
        guest_ip,
        guest_mac: guest_mac(guest_ip),
        egress_mbit: 50,
        ports: vec![25565],
        mode: AttachMode::Veth,
        uid: 20_000 + u32::from(last_octet),
        gid: 20_000 + u32::from(last_octet),
    }
}

fn members(world: &str) -> Vec<String>
{
    let set_name = nft::world_set_name(world, "");
    let output = Command::new("nft")
        .args(["-j", "list", "set", "inet", "quarry", &set_name])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let listing: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut members: Vec<_> = listing["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry.get("set"))
        .flat_map(|set| set["elem"].as_array().cloned().unwrap_or_default())
        .map(|entry| entry.as_str().unwrap().to_string())
        .collect();
    members.sort();
    members
}

fn pending_retirements(state_dir: &Path, instance_id: &str) -> usize
{
    let state: Value = serde_json::from_slice(
        &std::fs::read(state_dir.join("network-state.json")).unwrap(),
    )
    .unwrap();
    state["instances"][instance_id]["retired_worlds"]
        .as_array()
        .unwrap()
        .len()
}

#[tokio::test]
#[ignore = "needs isolated root Linux network namespace, nftables and iproute2"]
async fn world_retirement_recovers_before_and_after_firewall_application()
{
    let directory = tempfile::tempdir().unwrap();
    let config = NetworkingConfig::new(directory.path().to_path_buf());
    let network = Networking::new(config.clone()).unwrap();
    network
        .configure_node(&NodeNetwork {
            subnet: Subnet::parse("10.233.91.0/24").unwrap(),
            region: "test".to_string(),
            wireguard_listen_port: 0,
            wireguard_address: None,
            peers: Vec::new(),
        })
        .await
        .unwrap();
    let mut moving = spec("retirement-moving", 2);
    let peer = spec("retirement-peer", 3);
    network.attach(&moving).await.unwrap();
    network.attach(&peer).await.unwrap();
    drop(network);

    // Persist the new desired world, then fail before the kernel sees its rules.
    moving.world_id = "retirement-new".to_string();
    let mut failed_config = config.clone();
    failed_config.nft_bin = "/bin/false".into();
    let failed = Networking::new(failed_config).unwrap();
    assert!(failed.attach(&moving).await.is_err());
    assert_eq!(pending_retirements(directory.path(), &moving.instance_id), 1);
    assert_eq!(members("retirement-old"), vec!["10.233.91.2", "10.233.91.3"]);
    drop(failed);

    // Recover and apply the atomic firewall change, but fail before completing attach.
    let mut failed_config = config.clone();
    failed_config.tc_bin = "/bin/false".into();
    let failed = Networking::new(failed_config).unwrap();
    assert!(failed.attach(&moving).await.is_err());
    assert_eq!(pending_retirements(directory.path(), &moving.instance_id), 1);
    assert_eq!(members("retirement-old"), vec!["10.233.91.3"]);
    assert_eq!(members("retirement-new"), vec!["10.233.91.2"]);
    drop(failed);

    let recovered = Networking::new(config).unwrap();
    recovered.attach(&moving).await.unwrap();
    assert_eq!(pending_retirements(directory.path(), &moving.instance_id), 0);
    assert_eq!(members("retirement-old"), vec!["10.233.91.3"]);
    assert_eq!(members("retirement-new"), vec!["10.233.91.2"]);
    recovered.detach(&moving.instance_id).await.unwrap();
    recovered.detach(&peer.instance_id).await.unwrap();
}
