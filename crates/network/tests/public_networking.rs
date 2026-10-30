use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use network::{
    AttachMode, FakeCall, FakeNetwork, FakeOperation, InstanceNetworkSpec, Network, NetworkError,
    NodeNetwork, PublicIpMode, PublicIpv4Arp, PublicIpv4Config, Subnet, guest_mac, nft,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn config(arp: PublicIpv4Arp) -> PublicIpv4Config
{
    PublicIpv4Config {
        pool: vec!["203.0.113.8/30".to_string(), "198.51.100.2".to_string()],
        uplink_interface: "eth0".to_string(),
        arp,
    }
}

fn spec(instance_id: &str, last: u8) -> InstanceNetworkSpec
{
    let guest_ip = Ipv4Addr::new(10, 0, 0, last);
    InstanceNetworkSpec {
        instance_id: instance_id.to_string(),
        world_id: "world".to_string(),
        guest_ip,
        guest_mac: guest_mac(guest_ip),
        egress_mbit: 10,
        ports: vec![],
        mode: AttachMode::Veth,
        uid: 1000,
        gid: 1000,
    }
}

async fn configured(path: Option<std::path::PathBuf>, arp: PublicIpv4Arp) -> FakeNetwork
{
    let fake = FakeNetwork::new(path).unwrap();
    fake.configure_public(&config(arp)).await.unwrap();
    fake.configure_node(&NodeNetwork {
        subnet: Subnet::parse("10.0.0.0/24").unwrap(),
        region: "test".to_string(),
        wireguard_listen_port: 0,
        wireguard_address: None,
        peers: vec![],
    })
    .await
    .unwrap();
    fake
}

fn public_ip() -> Ipv4Addr
{
    Ipv4Addr::new(203, 0, 113, 9)
}

fn rules(value: &Value, chain: &str) -> Vec<Value>
{
    value["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|command| command.get("add")?.get("rule"))
        .filter(|rule| rule["chain"] == chain)
        .map(|rule| rule["expr"].clone())
        .collect()
}

fn last_public(fake: &FakeNetwork) -> Value
{
    fake.nft_transactions()
        .into_iter()
        .rev()
        .find(|transaction| {
            transaction["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .any(|command| command["flush"]["chain"]["name"] == nft::PUBLIC_DNAT_CHAIN)
        })
        .unwrap()
}

#[tokio::test]
async fn admission_and_attachment_enforce_pool_and_unique_claims()
{
    let fake = configured(None, PublicIpv4Arp::Routed).await;
    assert!(fake.validate_public_ipv4("a", "").is_ok());
    for address in ["bad", "::1", "203.0.113.7", "203.0.113.12", "198.51.100.3"]
    {
        assert!(matches!(
            fake.validate_public_ipv4("a", address),
            Err(NetworkError::InvalidSpec { .. })
        ));
    }
    assert!(matches!(
        fake.attach_public("a", public_ip()).await,
        Err(NetworkError::NotAttached(_))
    ));
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach(&spec("b", 3)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    assert!(
        fake.validate_public_ipv4("a", &public_ip().to_string())
            .is_ok()
    );
    assert!(matches!(
        fake.validate_public_ipv4("b", &public_ip().to_string()),
        Err(NetworkError::InvalidSpec { .. })
    ));
    assert!(matches!(
        fake.attach_public("b", public_ip()).await,
        Err(NetworkError::InvalidSpec { .. })
    ));
    assert!(matches!(
        fake.attach_public("b", Ipv4Addr::new(192, 0, 2, 1)).await,
        Err(NetworkError::InvalidSpec { .. })
    ));
    let mut removed_pool = config(PublicIpv4Arp::Routed);
    removed_pool.pool.clear();
    assert!(fake.configure_public(&removed_pool).await.is_err());
    assert!(
        fake.validate_public_ipv4("a", &public_ip().to_string())
            .is_ok()
    );
}

#[tokio::test]
async fn public_rules_swap_atomically_preserve_sources_and_allow_every_port()
{
    let fake = configured(None, PublicIpv4Arp::Proxy).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    assert_eq!(fake.public_mode("a"), Some(PublicIpMode::Starting));
    let port = fake.responder_address("a").unwrap().port();
    let starting = last_public(&fake);
    assert_eq!(
        rules(&starting, nft::PUBLIC_DNAT_CHAIN),
        vec![json!([
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"203.0.113.9"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":25565}},
            {"redirect":{"port":port}}
        ])]
    );
    let ingress = rules(&starting, nft::PUBLIC_INGRESS_CHAIN);
    assert_eq!(ingress.len(), 2);
    assert_eq!(ingress[1][1], json!({"drop":null}));
    assert!(rules(&starting, nft::PUBLIC_FORWARD_CHAIN).is_empty());
    assert_eq!(
        fake.proxy_neighbours(),
        vec![("eth0".to_string(), public_ip())]
    );
    let before = fake.nft_transactions().len();
    fake.attach_public("a", public_ip()).await.unwrap();
    assert_eq!(fake.nft_transactions().len(), before);
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    assert_eq!(fake.nft_transactions().len(), before + 2);
    let running = last_public(&fake);
    let dnat = rules(&running, nft::PUBLIC_DNAT_CHAIN);
    assert_eq!(dnat.len(), 1);
    assert_eq!(dnat[0].as_array().unwrap().len(), 2);
    assert_eq!(
        dnat[0][1],
        json!({"dnat":{"family":"ip","addr":"10.0.0.2"}})
    );
    assert!(!dnat[0].to_string().contains("dport"));
    let snat = rules(&running, nft::PUBLIC_SNAT_CHAIN);
    assert_eq!(snat.len(), 1);
    assert_eq!(snat[0][0]["match"]["right"], "10.0.0.2");
    assert_eq!(
        snat[0][2],
        json!({"snat":{"family":"ip","addr":"203.0.113.9"}})
    );
    let forward = rules(&running, nft::PUBLIC_FORWARD_CHAIN);
    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0][0]["match"]["left"]["ct"]["dir"], "original");
    assert_eq!(forward[0][1]["match"]["right"], "10.0.0.2");
    assert_eq!(
        forward[0][2]["match"]["right"],
        network::InterfaceNames::for_instance("a").host_veth
    );
    assert!(!forward[0].to_string().contains("dport"));
    fake.attach_public("a", public_ip()).await.unwrap();
    assert_eq!(fake.public_mode("a"), Some(PublicIpMode::Running));
    fake.detach("a").await.unwrap();
    assert!(fake.public_bindings().is_empty());
    assert!(fake.proxy_neighbours().is_empty());
    assert!(rules(&last_public(&fake), nft::PUBLIC_DNAT_CHAIN).is_empty());
    assert!(fake.responder_address("a").is_none());
    let before = fake.nft_transactions().len();
    fake.detach_public("a").await.unwrap();
    fake.detach("a").await.unwrap();
    assert_eq!(before, fake.nft_transactions().len());
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    assert_eq!(fake.public_metrics().bound, 1);
}

#[tokio::test]
async fn persisted_intent_recovers_failed_attach_mode_swap_and_detach()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("network-state.json");
    let fake = configured(Some(path.clone()), PublicIpv4Arp::Proxy).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.fail_next(FakeOperation::ApplyPublic, "crash before nft apply");
    assert!(fake.attach_public("a", public_ip()).await.is_err());
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["public"]["bindings"]["a"]["mode"], "Starting");
    assert!(
        persisted["public"]["bindings"]["a"]["responder_port"]
            .as_u64()
            .unwrap()
            > 0
    );
    drop(fake);
    tokio::task::yield_now().await;
    let fake = FakeNetwork::new(Some(path.clone())).unwrap();
    assert_eq!(fake.public_mode("a"), Some(PublicIpMode::Starting));
    assert_eq!(fake.proxy_neighbours().len(), 1);
    assert_eq!(rules(&last_public(&fake), nft::PUBLIC_DNAT_CHAIN).len(), 1);
    fake.fail_next(FakeOperation::ApplyPublic, "crash before swap");
    assert!(
        fake.set_public_mode("a", PublicIpMode::Hibernated)
            .await
            .is_err()
    );
    drop(fake);
    tokio::task::yield_now().await;
    let fake = FakeNetwork::new(Some(path.clone())).unwrap();
    assert_eq!(fake.public_mode("a"), Some(PublicIpMode::Hibernated));
    fake.fail_next(FakeOperation::ApplyPublic, "crash before removal");
    assert!(fake.detach_public("a").await.is_err());
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        persisted["public"]["bindings"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        persisted["public"]["retired_proxies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    drop(fake);
    tokio::task::yield_now().await;
    let fake = FakeNetwork::new(Some(path)).unwrap();
    assert!(fake.public_bindings().is_empty());
    assert!(fake.proxy_neighbours().is_empty());
    assert!(rules(&last_public(&fake), nft::PUBLIC_DNAT_CHAIN).is_empty());
}

#[tokio::test]
async fn address_replacement_and_proxy_configuration_converge()
{
    let fake = configured(None, PublicIpv4Arp::Proxy).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    let replacement: Ipv4Addr = "198.51.100.2".parse().unwrap();
    fake.attach_public("a", replacement).await.unwrap();
    assert_eq!(fake.public_mode("a"), Some(PublicIpMode::Starting));
    assert_eq!(
        fake.proxy_neighbours(),
        vec![("eth0".to_string(), replacement)]
    );
    assert!(!last_public(&fake).to_string().contains("203.0.113.9"));
    fake.configure_public(&config(PublicIpv4Arp::Routed))
        .await
        .unwrap();
    assert!(fake.proxy_neighbours().is_empty());
    fake.attach(&spec("a", 4)).await.unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    assert_eq!(
        rules(&last_public(&fake), nft::PUBLIC_DNAT_CHAIN)[0][1]["dnat"]["addr"],
        "10.0.0.4"
    );
}

#[tokio::test]
async fn failed_routed_detach_recovers_an_empty_ruleset_without_proxy_tombstones()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("network-state.json");
    let fake = configured(Some(path.clone()), PublicIpv4Arp::Routed).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    fake.fail_next(FakeOperation::ApplyPublic, "crash before routed removal");
    assert!(fake.detach_public("a").await.is_err());
    drop(fake);
    tokio::task::yield_now().await;
    let recovered = FakeNetwork::new(Some(path)).unwrap();
    assert!(recovered.public_bindings().is_empty());
    assert!(rules(&last_public(&recovered), nft::PUBLIC_DNAT_CHAIN).is_empty());
    assert!(rules(&last_public(&recovered), nft::PUBLIC_SNAT_CHAIN).is_empty());
    assert!(rules(&last_public(&recovered), nft::PUBLIC_FORWARD_CHAIN).is_empty());
}

#[tokio::test]
async fn failed_conntrack_cleanup_keeps_the_address_reserved_until_restart_retries_it()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("network-state.json");
    let fake = configured(Some(path.clone()), PublicIpv4Arp::Routed).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach(&spec("b", 3)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    fake.fail_next(
        FakeOperation::CleanupPublic,
        "conntrack deletion interrupted",
    );
    assert!(fake.detach_public("a").await.is_err());
    let guard = fake.nft_transactions().last().unwrap().clone();
    assert_eq!(rules(&guard, nft::PUBLIC_RETIREMENT_CHAIN).len(), 2);
    assert!(rules(&guard, nft::PUBLIC_DNAT_CHAIN).is_empty());
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        persisted["public"]["retired_bindings"],
        json!([
            {"address": "203.0.113.9", "guest_ip": "10.0.0.2"}
        ])
    );
    assert!(
        fake.validate_public_ipv4("b", &public_ip().to_string())
            .is_err()
    );
    assert!(fake.attach_public("b", public_ip()).await.is_err());
    drop(fake);
    tokio::task::yield_now().await;

    let recovered = FakeNetwork::new(Some(path.clone())).unwrap();
    assert!(
        recovered
            .calls()
            .contains(&FakeCall::CleanupPublic(public_ip()))
    );
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["public"]["retired_bindings"], json!([]));
    recovered.attach_public("b", public_ip()).await.unwrap();
    assert_eq!(recovered.public_bindings().get("b"), Some(&public_ip()));
}

#[tokio::test]
async fn address_guest_and_running_mode_changes_retire_connections_but_replays_do_not()
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("network-state.json");
    let fake = configured(Some(path.clone()), PublicIpv4Arp::Routed).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    let calls = fake.calls();
    let cleanups = calls
        .iter()
        .filter(|call| matches!(call, FakeCall::CleanupPublic(_)))
        .count();
    assert_eq!(cleanups, 1);
    fake.attach_public("a", public_ip()).await.unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::CleanupPublic(_)))
            .count(),
        cleanups,
    );

    fake.fail_next(
        FakeOperation::CleanupPublic,
        "guest address cleanup interrupted",
    );
    assert!(fake.attach(&spec("a", 4)).await.is_err());
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["public"]["bindings"]["a"]["guest_ip"], "10.0.0.4");
    assert_eq!(
        persisted["public"]["retired_bindings"][0]["guest_ip"],
        "10.0.0.2"
    );
    fake.attach(&spec("a", 4)).await.unwrap();
    assert_eq!(fake.public_mode("a"), Some(PublicIpMode::Starting));

    fake.fail_next(
        FakeOperation::CleanupPublic,
        "public address cleanup interrupted",
    );
    assert!(
        fake.attach_public("a", "198.51.100.2".parse().unwrap())
            .await
            .is_err()
    );
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        persisted["public"]["retired_bindings"],
        json!([
            {"address": "203.0.113.9", "guest_ip": "10.0.0.4"}
        ])
    );
    fake.attach_public("a", "198.51.100.2".parse().unwrap())
        .await
        .unwrap();
    fake.set_public_mode("a", PublicIpMode::Running)
        .await
        .unwrap();
    fake.fail_next(
        FakeOperation::CleanupPublic,
        "sleep transition cleanup interrupted",
    );
    assert!(
        fake.set_public_mode("a", PublicIpMode::Hibernated)
            .await
            .is_err()
    );
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        persisted["public"]["retired_bindings"][0]["address"],
        "198.51.100.2"
    );
    fake.set_public_mode("a", PublicIpMode::Hibernated)
        .await
        .unwrap();
}

fn varint(mut value: u32, output: &mut Vec<u8>)
{
    loop
    {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(if value == 0 { byte } else { byte | 128 });
        if value == 0
        {
            return;
        }
    }
}

fn frame(bytes: &[u8]) -> Vec<u8>
{
    let mut output = Vec::new();
    varint(bytes.len() as u32, &mut output);
    output.extend_from_slice(bytes);
    output
}

fn handshake(state: u8) -> Vec<u8>
{
    let mut bytes = vec![0];
    varint(769, &mut bytes);
    varint(9, &mut bytes);
    bytes.extend_from_slice(b"localhost");
    bytes.extend_from_slice(&25565u16.to_be_bytes());
    bytes.push(state);
    frame(&bytes)
}

async fn read_varint(stream: &mut TcpStream) -> u32
{
    let mut value = 0;
    for shift in (0..35).step_by(7)
    {
        let byte = stream.read_u8().await.unwrap();
        value |= u32::from(byte & 127) << shift;
        if byte & 128 == 0
        {
            return value;
        }
    }
    panic!("invalid varint");
}

async fn packet(stream: &mut TcpStream) -> Vec<u8>
{
    let length = read_varint(stream).await as usize;
    assert!(length <= 1024);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}

fn json_packet(packet: &[u8]) -> Value
{
    assert_eq!(packet[0], 0);
    let mut length = 0;
    let mut cursor = 1;
    loop
    {
        let byte = packet[cursor];
        length |= usize::from(byte & 127) << ((cursor - 1) * 7);
        cursor += 1;
        if byte & 128 == 0
        {
            break;
        }
    }
    assert_eq!(packet.len() - cursor, length);
    serde_json::from_slice(&packet[cursor..]).unwrap()
}

async fn login(address: SocketAddr) -> Value
{
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&handshake(2)).await.unwrap();
    json_packet(&packet(&mut stream).await)
}

#[tokio::test]
async fn status_ping_and_login_cover_all_sleep_modes_and_wake_only_hibernated()
{
    let fake = configured(None, PublicIpv4Arp::Routed).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    let address = fake.responder_address("a").unwrap();
    let mut wakes = fake.subscribe_wakes();
    for mode in [
        PublicIpMode::Stopped,
        PublicIpMode::Hibernated,
        PublicIpMode::Starting,
    ]
    {
        fake.set_public_mode("a", mode).await.unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&handshake(1)).await.unwrap();
        stream.write_all(&frame(&[0])).await.unwrap();
        let status = json_packet(&packet(&mut stream).await);
        assert_eq!(status["version"]["protocol"], 769);
        let expected = if mode == PublicIpMode::Starting
        {
            "starting"
        }
        else
        {
            "sleeping"
        };
        assert!(
            status["description"]["text"]
                .as_str()
                .unwrap()
                .contains(expected)
        );
        let mut ping = vec![1];
        ping.extend_from_slice(&123456789i64.to_be_bytes());
        stream.write_all(&frame(&ping)).await.unwrap();
        assert_eq!(packet(&mut stream).await, ping);
        assert!(wakes.try_recv().is_err());
        let disconnect = login(address).await;
        assert!(disconnect["text"].as_str().unwrap().contains("30 seconds"));
        if mode == PublicIpMode::Hibernated
        {
            let wake = wakes.try_recv().unwrap();
            assert_eq!(wake.instance_id, "a");
            assert!(wake.requested_at_unix_ms > 0);
            login(address).await;
        }
        assert!(wakes.try_recv().is_err());
    }
    for _ in 0..10
    {
        tokio::task::yield_now().await;
    }
    let metrics = fake.public_metrics();
    assert_eq!(metrics.wake_requests, 1);
    assert_eq!(metrics.connections.get("status"), Some(&3));
    assert_eq!(metrics.connections.get("login"), Some(&4));
}

async fn closed(mut stream: TcpStream)
{
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(read.is_err() || read.unwrap() == 0);
}

#[tokio::test]
async fn legacy_oversized_malformed_and_invalid_state_connections_close()
{
    let fake = configured(None, PublicIpv4Arp::Routed).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    let address = fake.responder_address("a").unwrap();
    let mut too_large = Vec::new();
    varint(1024, &mut too_large);
    for bytes in [
        vec![0xfe],
        too_large,
        vec![0xff, 0xff, 0xff, 0xff, 0x7f],
        handshake(3),
        frame(&[1]),
    ]
    {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        closed(stream).await;
    }
    for _ in 0..10
    {
        tokio::task::yield_now().await;
    }
    let metrics = fake.public_metrics();
    assert_eq!(metrics.connections.get("legacy"), Some(&1));
    assert_eq!(metrics.connections.get("invalid"), Some(&4));
}

#[tokio::test]
async fn handshake_deadline_closes_partial_connections()
{
    let fake = configured(None, PublicIpv4Arp::Routed).await;
    fake.attach(&spec("a", 2)).await.unwrap();
    fake.attach_public("a", public_ip()).await.unwrap();
    let mut stream = TcpStream::connect(fake.responder_address("a").unwrap())
        .await
        .unwrap();
    stream.write_all(&[0x80]).await.unwrap();
    let start = tokio::time::Instant::now();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(6), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    assert!(start.elapsed() >= Duration::from_secs(4));
    assert_eq!(fake.public_metrics().connections.get("timeout"), Some(&1));
}

#[tokio::test]
async fn per_source_rate_limit_is_shared_across_instance_listeners()
{
    let fake = configured(None, PublicIpv4Arp::Routed).await;
    for (id, last, public) in [
        ("a", 2, public_ip()),
        ("b", 3, Ipv4Addr::new(203, 0, 113, 10)),
    ]
    {
        fake.attach(&spec(id, last)).await.unwrap();
        fake.attach_public(id, public).await.unwrap();
    }
    let start = tokio::time::Instant::now();
    let mut connections = tokio::task::JoinSet::new();
    for index in 0..64
    {
        let address = fake
            .responder_address(if index % 2 == 0 { "a" } else { "b" })
            .unwrap();
        connections.spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let _ = stream.write_all(&[0xfe]).await;
            closed(stream).await;
        });
    }
    while let Some(result) = connections.join_next().await
    {
        result.unwrap();
    }
    let metrics = fake.public_metrics();
    assert!(
        metrics
            .connections
            .get("rate_limited")
            .copied()
            .unwrap_or_default()
            > 0
    );
    let allowed = (20.0 + start.elapsed().as_secs_f64() * 10.0).floor() as u64;
    assert!(
        metrics
            .connections
            .get("legacy")
            .copied()
            .unwrap_or_default()
            <= allowed
    );
    tokio::time::sleep(Duration::from_millis(110)).await;
    assert!(login(fake.responder_address("a").unwrap()).await["text"].is_string());
}

#[tokio::test]
async fn fake_network_accepts_a_public_pool_without_an_uplink()
{
    let fake = FakeNetwork::new(None).unwrap();
    fake.configure_public(&PublicIpv4Config {
        uplink_interface: String::new(),
        ..config(PublicIpv4Arp::default())
    })
    .await
    .unwrap();
}
