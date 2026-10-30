#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use network::{
    AttachMode, InstanceNetworkSpec, InterfaceNames, Network, NetworkAttachment, Networking,
    NetworkingConfig, NodeNetwork, Subnet, WireGuardPeerConfig, guest_mac, nft,
};
use serde_json::Value;
use tokio::sync::Mutex;

static HOST: Mutex<()> = Mutex::const_new(());

const SUBNET: &str = "10.231.0.0/24";

fn networking(state_dir: &Path) -> Networking
{
    Networking::new(NetworkingConfig::new(state_dir.to_path_buf())).unwrap()
}

fn node() -> NodeNetwork
{
    NodeNetwork {
        subnet: Subnet::parse(SUBNET).unwrap(),
        region: "test".to_string(),
        wireguard_listen_port: 0,
        wireguard_address: None,
        peers: Vec::new(),
    }
}

fn spec(id: &str, world: &str, last_octet: u8, mode: AttachMode) -> InstanceNetworkSpec
{
    let ip = Ipv4Addr::new(10, 231, 0, last_octet);
    InstanceNetworkSpec {
        instance_id: id.to_string(),
        world_id: world.to_string(),
        guest_ip: ip,
        guest_mac: guest_mac(ip),
        egress_mbit: 50,
        ports: vec![25565],
        mode,
        uid: 10_000 + u32::from(last_octet),
        gid: 10_000 + u32::from(last_octet),
    }
}

fn run(program: &str, args: &[&str]) -> (bool, String)
{
    let output = Command::new(program).args(args).output().unwrap();
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn run_ok(program: &str, args: &[&str]) -> String
{
    let (success, output) = run(program, args);
    assert!(success, "{program} {args:?} failed: {output}");
    output
}

fn piped(program: &str, args: &[&str], input: &str) -> String
{
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn link_exists(name: &str, netns: Option<&str>) -> bool
{
    match netns
    {
        Some(netns) => run("ip", &["-n", netns, "link", "show", name]).0,
        None => run("ip", &["link", "show", name]).0,
    }
}

fn nft_objects(family: &str, netns: Option<&str>) -> Vec<Value>
{
    let mut args = Vec::new();
    if let Some(netns) = netns
    {
        args.extend(["netns", "exec", netns, "nft"]);
    }
    args.extend(["-j", "list", "table", family, "quarry"]);
    let (program, args) = match netns
    {
        Some(_) => ("ip", args),
        None => ("nft", args),
    };
    let (success, output) = run(program, &args);
    if !success
    {
        return Vec::new();
    }
    let listing: Value = serde_json::from_str(&output).unwrap();
    listing["nftables"].as_array().unwrap().clone()
}

fn chain_names(family: &str, netns: Option<&str>) -> Vec<String>
{
    nft_objects(family, netns)
        .iter()
        .filter_map(|object| object.get("chain"))
        .map(|chain| chain["name"].as_str().unwrap().to_string())
        .collect()
}

fn rule_count(family: &str, chain: &str) -> usize
{
    nft_objects(family, None)
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| rule["chain"] == chain)
        .count()
}

fn set_elements(set_name: &str) -> Vec<String>
{
    nft_objects("inet", None)
        .iter()
        .filter_map(|object| object.get("set"))
        .filter(|set| set["name"] == set_name)
        .flat_map(|set| set["elem"].as_array().cloned().unwrap_or_default())
        .map(|element| element.as_str().unwrap().to_string())
        .collect()
}

fn host_links_with_prefix(prefix: &str) -> usize
{
    run_ok("ip", &["-o", "link", "show"])
        .lines()
        .filter(|line| {
            line.split(": ")
                .nth(1)
                .is_some_and(|name| name.starts_with(prefix))
        })
        .count()
}

fn assert_attachment(attachment: &NetworkAttachment, spec: &InstanceNetworkSpec)
{
    let names = InterfaceNames::for_instance(&spec.instance_id);
    assert_eq!(attachment.instance_id, spec.instance_id);
    assert_eq!(attachment.host_ifname, names.host_veth);
    assert_eq!(
        attachment.netns_path.as_deref(),
        Some(names.netns_path().as_path())
    );
    assert_eq!(attachment.guest_ip, spec.guest_ip);
    assert_eq!(attachment.guest_mac, spec.guest_mac);
    assert_eq!(attachment.gateway, Ipv4Addr::new(10, 231, 0, 1));
    assert_eq!(attachment.prefix_len, 24);
    assert_eq!(attachment.world_id, spec.world_id);
}

fn assert_detached(names: &InterfaceNames, family_chains_gone: &[String])
{
    assert!(!link_exists(&names.host_veth, None));
    assert!(!names.netns_path().exists());
    let chains = chain_names("inet", None);
    for chain in family_chains_gone
    {
        assert!(!chains.contains(chain), "{chain} still present");
    }
}

#[tokio::test]
#[ignore = "needs root, nft, iproute2 and /dev/net/tun on Linux"]
async fn attach_and_detach_in_tap_mode()
{
    let _host = HOST.lock().await;
    let state = tempfile::tempdir().unwrap();
    let networking = networking(state.path());
    networking.configure_node(&node()).await.unwrap();
    let spec = spec("it-tap", "world-tap", 21, AttachMode::Tap);
    let names = InterfaceNames::for_instance(&spec.instance_id);

    let attachment = networking.attach(&spec).await.unwrap();
    assert_attachment(&attachment, &spec);
    assert_eq!(attachment.tap_name.as_deref(), Some(names.tap.as_str()));
    assert!(names.netns_path().exists());
    assert!(link_exists(&names.host_veth, None));
    assert!(link_exists(&names.guest_veth, Some(&names.netns)));
    let tap_details = run_ok(
        "ip",
        &["-n", &names.netns, "-d", "link", "show", &names.tap],
    );
    assert!(tap_details.contains("tap"), "{tap_details}");
    assert!(tap_details.contains("persist on"), "{tap_details}");
    assert!(tap_details.contains("user 10021"), "{tap_details}");
    assert!(tap_details.contains("group 10021"), "{tap_details}");
    let tap_route = run_ok("ip", &["-n", &names.netns, "route", "show", "10.231.0.21"]);
    assert!(tap_route.contains(&names.tap), "{tap_route}");
    let default_route = run_ok("ip", &["-n", &names.netns, "route", "show", "default"]);
    assert!(default_route.contains("via 10.231.0.1"), "{default_route}");
    let host_route = run_ok("ip", &["route", "show", "10.231.0.21"]);
    assert!(host_route.contains(&names.host_veth), "{host_route}");
    assert!(host_route.contains("src 10.231.0.1"), "{host_route}");
    let forwarding = run_ok(
        "ip",
        &[
            "netns",
            "exec",
            &names.netns,
            "cat",
            "/proc/sys/net/ipv4/ip_forward",
        ],
    );
    assert_eq!(forwarding.trim(), "1");
    assert_eq!(
        chain_names("netdev", Some(&names.netns)),
        vec![nft::NAMESPACE_GUARD_CHAIN]
    );
    let chains = chain_names("inet", None);
    let instance_chains = vec![
        nft::guard_chain(&names),
        nft::forward_chain(&names),
        nft::host_chain(&names),
    ];
    for chain in &instance_chains
    {
        assert!(chains.contains(chain), "{chain} missing");
    }
    let police = run_ok(
        "tc",
        &["filter", "show", "dev", &names.host_veth, "ingress"],
    );
    assert!(police.contains("police"), "{police}");

    let rules_before: Vec<usize> = instance_chains
        .iter()
        .map(|chain| rule_count("inet", chain))
        .collect();
    let links_before = host_links_with_prefix("qh-");
    let again = networking.attach(&spec).await.unwrap();
    assert_eq!(again, attachment);
    assert_eq!(host_links_with_prefix("qh-"), links_before);
    let rules_after: Vec<usize> = instance_chains
        .iter()
        .map(|chain| rule_count("inet", chain))
        .collect();
    assert_eq!(rules_after, rules_before);
    assert_eq!(
        set_elements(&nft::world_set_name("world-tap", "it-tap")),
        vec!["10.231.0.21"]
    );

    networking.counters(&attachment).await.unwrap();

    let restarted = networking_after_restart(state.path());
    assert_eq!(restarted.attach(&spec).await.unwrap(), attachment);

    restarted.detach(&spec.instance_id).await.unwrap();
    assert_detached(&names, &instance_chains);
    assert!(set_elements(&nft::world_set_name("world-tap", "it-tap")).is_empty());
    restarted.detach(&spec.instance_id).await.unwrap();
    assert!(matches!(
        restarted.counters(&attachment).await,
        Err(network::NetworkError::NotAttached(_))
    ));
}

fn networking_after_restart(state_dir: &Path) -> Networking
{
    networking(state_dir)
}

#[tokio::test]
#[ignore = "needs root, nft and iproute2 on Linux"]
async fn attach_and_detach_in_veth_mode()
{
    let _host = HOST.lock().await;
    let state = tempfile::tempdir().unwrap();
    let networking = networking(state.path());
    networking.configure_node(&node()).await.unwrap();
    let spec = spec("it-veth", "world-veth", 22, AttachMode::Veth);
    let names = InterfaceNames::for_instance(&spec.instance_id);

    let attachment = networking.attach(&spec).await.unwrap();
    assert_attachment(&attachment, &spec);
    assert_eq!(attachment.tap_name, None);
    assert!(!link_exists(&names.tap, Some(&names.netns)));
    let guest_link = run_ok(
        "ip",
        &["-n", &names.netns, "link", "show", &names.guest_veth],
    );
    assert!(guest_link.contains(&spec.guest_mac), "{guest_link}");
    let guest_address = run_ok(
        "ip",
        &["-n", &names.netns, "-4", "addr", "show", &names.guest_veth],
    );
    assert!(guest_address.contains("10.231.0.22/24"), "{guest_address}");
    let default_route = run_ok("ip", &["-n", &names.netns, "route", "show", "default"]);
    assert!(default_route.contains("via 10.231.0.1"), "{default_route}");
    let host_chains = chain_names("netdev", None);
    assert!(host_chains.contains(&nft::mac_chain(&names)));

    let links_before = host_links_with_prefix("qh-");
    assert_eq!(networking.attach(&spec).await.unwrap(), attachment);
    assert_eq!(host_links_with_prefix("qh-"), links_before);
    assert_eq!(rule_count("netdev", &nft::mac_chain(&names)), 2);

    let unlimited = InstanceNetworkSpec {
        egress_mbit: 0,
        world_id: "world-veth-moved".to_string(),
        ..spec.clone()
    };
    networking.attach(&unlimited).await.unwrap();
    let filters = run_ok(
        "tc",
        &["filter", "show", "dev", &names.host_veth, "ingress"],
    );
    assert!(!filters.contains("police"), "{filters}");
    assert!(set_elements(&nft::world_set_name("world-veth", "it-veth")).is_empty());
    assert_eq!(
        set_elements(&nft::world_set_name("world-veth-moved", "it-veth")),
        vec!["10.231.0.22"]
    );

    networking.detach(&spec.instance_id).await.unwrap();
    assert_detached(
        &names,
        &[
            nft::guard_chain(&names),
            nft::forward_chain(&names),
            nft::host_chain(&names),
        ],
    );
    assert!(!chain_names("netdev", None).contains(&nft::mac_chain(&names)));
    networking.detach(&spec.instance_id).await.unwrap();
}

#[tokio::test]
#[ignore = "needs root, nft, iproute2, the wireguard kernel module and wireguard-tools on Linux"]
async fn configure_node_with_wireguard_mesh()
{
    let _host = HOST.lock().await;
    let state = tempfile::tempdir().unwrap();
    let networking = networking(state.path());
    let key_a = piped("wg", &["pubkey"], &run_ok("wg", &["genkey"]));
    let key_b = piped("wg", &["pubkey"], &run_ok("wg", &["genkey"]));
    let peer_a = WireGuardPeerConfig {
        public_key: key_a.clone(),
        endpoint: "192.0.2.10:51820".to_string(),
        allowed_ips: vec!["10.250.0.2/32".to_string(), "10.232.0.0/24".to_string()],
    };
    let peer_b = WireGuardPeerConfig {
        public_key: key_b.clone(),
        endpoint: String::new(),
        allowed_ips: vec!["10.250.0.3/32".to_string()],
    };
    let mesh = NodeNetwork {
        wireguard_listen_port: 51820,
        wireguard_address: Some("10.250.0.1/24".to_string()),
        peers: vec![peer_a.clone(), peer_b],
        ..node()
    };

    networking.configure_node(&mesh).await.unwrap();
    networking.configure_node(&mesh).await.unwrap();
    let peers = run_ok("wg", &["show", "wg-quarry", "peers"]);
    assert!(peers.contains(&key_a) && peers.contains(&key_b), "{peers}");
    assert_eq!(
        run_ok("wg", &["show", "wg-quarry", "listen-port"]).trim(),
        "51820"
    );
    let public_key = networking.wireguard_public_key().await.unwrap().unwrap();
    assert_eq!(
        run_ok("wg", &["show", "wg-quarry", "public-key"]).trim(),
        public_key
    );
    let routes = run_ok("ip", &["route", "show", "dev", "wg-quarry"]);
    assert!(
        routes.contains("10.232.0.0/24") && routes.contains("10.250.0.3"),
        "{routes}"
    );
    let addresses = run_ok("ip", &["-4", "addr", "show", "dev", "wg-quarry"]);
    assert!(addresses.contains("10.250.0.1/24"), "{addresses}");
    let gateway = run_ok("ip", &["-4", "addr", "show", "dev", "quarry0"]);
    assert!(gateway.contains("10.231.0.1/32"), "{gateway}");

    let shrunk = NodeNetwork {
        peers: vec![peer_a],
        ..mesh.clone()
    };
    networking.configure_node(&shrunk).await.unwrap();
    let peers = run_ok("wg", &["show", "wg-quarry", "peers"]);
    assert!(peers.contains(&key_a) && !peers.contains(&key_b), "{peers}");
    let routes = run_ok("ip", &["route", "show", "dev", "wg-quarry"]);
    assert!(!routes.contains("10.250.0.3"), "{routes}");

    let restarted = networking_after_restart(state.path());
    assert_eq!(
        restarted.wireguard_public_key().await.unwrap(),
        Some(public_key)
    );

    restarted.configure_node(&node()).await.unwrap();
    assert!(!link_exists("wg-quarry", None));
}

fn accept_once_inside(netns_path: &Path, address: SocketAddr) -> JoinHandle<bool>
{
    let netns_path = netns_path.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let listener = thread::spawn(move || {
        let netns = File::open(netns_path).unwrap();
        assert_eq!(
            unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) },
            0
        );
        let listener = TcpListener::bind(address).unwrap();
        listener.set_nonblocking(true).unwrap();
        ready_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop
        {
            match listener.accept()
            {
                Ok(_) => return true,
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(_) => return false,
            }
        }
    });
    ready_rx.recv().unwrap();
    listener
}

fn host_connects(netns_path: &Path, address: SocketAddr) -> bool
{
    let listener = accept_once_inside(netns_path, address);
    let connected = TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok();
    let accepted = listener.join().unwrap();
    connected && accepted
}

fn ping(netns: &str, target: &str) -> bool
{
    run(
        "ip",
        &["netns", "exec", netns, "ping", "-c", "1", "-W", "2", target],
    )
    .0
}

#[tokio::test]
#[ignore = "needs root, nft, iproute2 and ping on Linux"]
async fn same_world_instances_can_talk_and_other_worlds_cannot()
{
    let _host = HOST.lock().await;
    let state = tempfile::tempdir().unwrap();
    let networking = networking(state.path());
    networking.configure_node(&node()).await.unwrap();
    let a = spec("it-iso-a", "world-one", 31, AttachMode::Veth);
    let b = spec("it-iso-b", "world-one", 32, AttachMode::Veth);
    let c = InstanceNetworkSpec {
        egress_mbit: 0,
        ..spec("it-iso-c", "world-two", 33, AttachMode::Veth)
    };
    for instance in [&a, &b, &c]
    {
        networking.attach(instance).await.unwrap();
    }
    let netns = |spec: &InstanceNetworkSpec| InterfaceNames::for_instance(&spec.instance_id).netns;

    assert!(
        ping(&netns(&a), "10.231.0.32"),
        "same world must be reachable"
    );
    assert!(
        ping(&netns(&b), "10.231.0.31"),
        "same world must be reachable both ways"
    );
    assert!(
        !ping(&netns(&a), "10.231.0.33"),
        "other worlds must be unreachable"
    );
    assert!(
        !ping(&netns(&c), "10.231.0.31"),
        "other worlds must be unreachable both ways"
    );
    assert!(
        !ping(&netns(&a), "10.231.0.1"),
        "instances must not reach the host"
    );

    let guest_veth_a = InterfaceNames::for_instance(&a.instance_id).guest_veth;
    run_ok(
        "ip",
        &[
            "-n",
            &netns(&a),
            "addr",
            "add",
            "10.231.0.35/32",
            "dev",
            &guest_veth_a,
        ],
    );
    let spoofing = run(
        "ip",
        &[
            "netns",
            "exec",
            &netns(&a),
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "-I",
            "10.231.0.35",
            "10.231.0.32",
        ],
    );
    assert!(
        !spoofing.0,
        "spoofed sources must be dropped even towards the same world"
    );
    run_ok(
        "ip",
        &[
            "-n",
            &netns(&a),
            "addr",
            "del",
            "10.231.0.35/32",
            "dev",
            &guest_veth_a,
        ],
    );
    assert!(ping(&netns(&a), "10.231.0.32"));

    let netns_b = InterfaceNames::for_instance(&b.instance_id).netns_path();
    assert!(
        host_connects(&netns_b, "10.231.0.32:25565".parse().unwrap()),
        "the host must reach declared ports"
    );
    assert!(
        !host_connects(&netns_b, "10.231.0.32:25566".parse().unwrap()),
        "the host must not reach undeclared ports"
    );

    for instance in [&a, &b, &c]
    {
        networking.detach(&instance.instance_id).await.unwrap();
    }
    assert!(set_elements(&nft::world_set_name("world-one", "it-iso-a")).is_empty());
}
