#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use network::{
    AttachMode, InstanceNetworkSpec, Network, Networking, NetworkingConfig, NodeNetwork,
    PublicIpMode, PublicIpv4Arp, PublicIpv4Config, Subnet, guest_mac,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};

fn ip(args: &[&str])
{
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn instance(id: &str, address: &str) -> InstanceNetworkSpec
{
    let guest_ip: Ipv4Addr = address.parse().unwrap();
    InstanceNetworkSpec {
        instance_id: id.to_owned(),
        world_id: id.to_owned(),
        guest_ip,
        guest_mac: guest_mac(guest_ip),
        egress_mbit: 0,
        ports: vec![],
        mode: AttachMode::Veth,
        uid: 10000,
        gid: 10000,
    }
}

async fn udp_server(
    namespace: &str,
    address: &str,
    port: u16,
    response: &str,
) -> tokio::process::Child
{
    let script = format!(
        r#"
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(('{address}', {port}))
    print('ready', flush=True)
    while True:
        data, peer = server.recvfrom(1024)
        response = peer[0] if '{response}' == 'source' else '{response}'
        server.sendto(response.encode(), peer)
"#
    );
    let mut child = tokio::process::Command::new("ip")
        .args(["netns", "exec", namespace, "python3", "-u", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.trim(), "ready");
    child
}

async fn udp_probe(
    namespace: &str,
    source: &str,
    source_port: u16,
    destination: &str,
    destination_port: u16,
    expected: &str,
)
{
    let script = format!(
        r#"
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.bind(('{source}', {source_port}))
    client.settimeout(.5)
    client.sendto(b'probe', ('{destination}', {destination_port}))
    try:
        data, peer = client.recvfrom(1024)
    except socket.timeout:
        assert '{expected}' == 'timeout', 'unexpected timeout'
    else:
        assert data.decode() == '{expected}', repr(data)
"#
    );
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("ip")
            .args(["netns", "exec", namespace, "python3", "-c", &script])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "needs root, isolated Linux networking, nftables, conntrack-tools, iproute2 and Python 3"]
async fn reassignment_retires_dnat_and_snat_and_recovers_interrupted_cleanup()
{
    let directory = tempfile::tempdir().unwrap();
    let client = "quarry-ct-client";
    let uplink = "qct-test0";
    let peer = "qct-peer";
    ip(&["netns", "add", client]);
    ip(&["link", "add", uplink, "type", "veth", "peer", "name", peer]);
    ip(&["link", "set", peer, "netns", client]);
    ip(&["addr", "add", "192.0.2.21/24", "dev", uplink]);
    ip(&["link", "set", uplink, "up"]);
    ip(&["-n", client, "addr", "add", "192.0.2.22/24", "dev", peer]);
    ip(&["-n", client, "link", "set", peer, "up"]);
    ip(&["-n", client, "link", "set", "lo", "up"]);
    ip(&[
        "-n",
        client,
        "route",
        "add",
        "203.0.113.19/32",
        "via",
        "192.0.2.21",
    ]);
    let mut config = NetworkingConfig::new(directory.path().to_path_buf());
    config.uplink_ifname = Some(uplink.to_owned());
    let public = PublicIpv4Config {
        pool: vec!["203.0.113.19".to_owned()],
        uplink_interface: uplink.to_owned(),
        arp: PublicIpv4Arp::Routed,
    };
    let address: Ipv4Addr = "203.0.113.19".parse().unwrap();
    let network = Networking::new(config.clone()).unwrap();
    network.configure_public(&public).await.unwrap();
    network
        .configure_node(&NodeNetwork {
            subnet: Subnet::parse("10.232.0.0/24").unwrap(),
            region: "test".to_owned(),
            wireguard_listen_port: 0,
            wireguard_address: None,
            peers: vec![],
        })
        .await
        .unwrap();
    let a = instance("ct-old-owner", "10.232.0.2");
    let b = instance("ct-new-owner", "10.232.0.3");
    let attachment_a = network.attach(&a).await.unwrap();
    let attachment_b = network.attach(&b).await.unwrap();
    let ns_a = network::InterfaceNames::for_instance(&a.instance_id).netns;
    let ns_b = network::InterfaceNames::for_instance(&b.instance_id).netns;
    network
        .attach_public(&a.instance_id, address)
        .await
        .unwrap();
    network
        .set_public_mode(&a.instance_id, PublicIpMode::Running)
        .await
        .unwrap();
    let mut server_a = udp_server(&ns_a, "10.232.0.2", 24445, "a").await;
    let mut server_b = udp_server(&ns_b, "10.232.0.3", 24445, "b").await;
    let mut outside = udp_server(client, "192.0.2.22", 24447, "source").await;
    udp_probe(client, "192.0.2.22", 44448, "203.0.113.19", 24445, "a").await;
    udp_probe(
        &ns_a,
        "10.232.0.2",
        44446,
        "192.0.2.22",
        24447,
        "203.0.113.19",
    )
    .await;
    drop(network);
    tokio::task::yield_now().await;

    let mut failing_config = config.clone();
    failing_config.conntrack_bin = "/bin/false".into();
    let failed = Networking::new(failing_config).unwrap();
    assert!(failed.detach_public(&a.instance_id).await.is_err());
    assert!(
        failed
            .validate_public_ipv4(&b.instance_id, "203.0.113.19")
            .is_err()
    );
    let state_path = directory.path().join("network-state.json");
    let saved: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(
        saved["public"]["retired_bindings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    udp_probe(
        client,
        "192.0.2.22",
        44448,
        "203.0.113.19",
        24445,
        "timeout",
    )
    .await;
    udp_probe(&ns_a, "10.232.0.2", 44446, "192.0.2.22", 24447, "timeout").await;
    drop(failed);

    let recovered = Networking::new(config).unwrap();
    recovered.configure_public(&public).await.unwrap();
    let saved: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert!(
        saved["public"]["retired_bindings"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    recovered
        .attach_public(&b.instance_id, address)
        .await
        .unwrap();
    recovered
        .set_public_mode(&b.instance_id, PublicIpMode::Running)
        .await
        .unwrap();
    // These reuse precisely the tuples established by the former owner.
    udp_probe(client, "192.0.2.22", 44448, "203.0.113.19", 24445, "b").await;
    udp_probe(
        &ns_a,
        "10.232.0.2",
        44446,
        "192.0.2.22",
        24447,
        "192.0.2.21",
    )
    .await;
    udp_probe(
        &ns_b,
        "10.232.0.3",
        44446,
        "192.0.2.22",
        24447,
        "203.0.113.19",
    )
    .await;
    assert_eq!(recovered.attach(&a).await.unwrap(), attachment_a);
    assert_eq!(recovered.attach(&b).await.unwrap(), attachment_b);

    server_a.kill().await.unwrap();
    server_b.kill().await.unwrap();
    outside.kill().await.unwrap();
    recovered.detach(&a.instance_id).await.unwrap();
    recovered.detach(&b.instance_id).await.unwrap();
    ip(&["link", "del", uplink]);
    ip(&["netns", "del", client]);
}
