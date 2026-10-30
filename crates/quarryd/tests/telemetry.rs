mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::Harness;
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::{InstanceHealth, LiveMetrics, Phase, RunState};
use quarryd::agent::Agent;

#[test]
fn guest_entry()
{
    common::run_guest_if_requested();
}

fn now_ms() -> u64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn health_after(harness: &Harness, after: u64) -> InstanceHealth
{
    let message = harness.control.wait_for(Duration::from_secs(15), |message| {
        matches!(&message.body, Some(AgentBody::Health(health)) if health.instance_id == "health-1" && health.sampled_at_unix_ms > after && health.tps == 20.0)
    }).await.expect("missing upstream health");
    assert_eq!(message.seq, 0);
    match message.body
    {
        Some(AgentBody::Health(health)) => health,
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_health_uses_five_seconds_and_live_updates_use_one_second()
{
    let harness = Harness::new().await;
    let agent = harness.start_agent().await;
    harness
        .control
        .put_instance(harness.spec("health-1", 1))
        .await;
    harness.wait_status("health-1", Phase::Running, 1).await;
    use std::io::Write;
    let mut disk = std::fs::OpenOptions::new()
        .write(true)
        .open(harness.path("state/volumes/health-1-data.img"))
        .unwrap();
    disk.write_all(b"world state").unwrap();
    disk.sync_all().unwrap();
    let first = health_after(&harness, 0).await;
    let normal = health_after(&harness, first.sampled_at_unix_ms).await;
    assert!((4500..=6500).contains(&(normal.sampled_at_unix_ms - first.sampled_at_unix_ms)));
    assert!(normal.disk_used_bytes > 0);

    harness
        .control
        .live_metrics(LiveMetrics {
            instance_id: "health-1".to_owned(),
            until_unix_ms: now_ms() + 3500,
        })
        .await;
    let live = health_after(&harness, normal.sampled_at_unix_ms).await;
    let next = health_after(&harness, live.sampled_at_unix_ms).await;
    assert!((750..=1750).contains(&(next.sampled_at_unix_ms - live.sampled_at_unix_ms)));
    harness
        .control
        .live_metrics(LiveMetrics {
            instance_id: "health-1".to_owned(),
            until_unix_ms: 0,
        })
        .await;
    let cancelled = health_after(&harness, next.sampled_at_unix_ms).await;
    assert!(cancelled.sampled_at_unix_ms - next.sampled_at_unix_ms >= 4500);

    let until = now_ms() + 1800;
    harness
        .control
        .live_metrics(LiveMetrics {
            instance_id: "health-1".to_owned(),
            until_unix_ms: until,
        })
        .await;
    let last_live = health_after(&harness, cancelled.sampled_at_unix_ms).await;
    let expired = health_after(&harness, last_live.sampled_at_unix_ms).await;
    assert!(expired.sampled_at_unix_ms >= until);
    assert!(expired.sampled_at_unix_ms - last_live.sampled_at_unix_ms >= 4500);
    harness.control.delete_instance("health-1").await;
    harness.wait_status("health-1", Phase::Deleted, 1).await;
    agent.stop().await.unwrap();
}

fn binding(harness: &Harness, id: &str) -> serde_json::Value
{
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(harness.path("state/fake-network.json")).unwrap())
            .unwrap();
    state["public"]["bindings"][id].clone()
}

async fn wait_mode(harness: &Harness, mode: &str)
{
    tokio::time::timeout(Duration::from_secs(15), async {
        while binding(harness, "public-1")["mode"] != mode
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_pool_admission_modes_and_wake_are_wired_through_the_agent()
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::new().await;
    let mut config = harness.config();
    config.public_ipv4_pool = vec!["203.0.113.80/32".to_owned()];
    config.uplink_interface = "eth0".to_owned();
    let agent = Agent::start(config.clone()).await.unwrap();
    let hello = harness
        .control
        .wait_for(Duration::from_secs(15), |message| {
            matches!(message.body, Some(AgentBody::Hello(_)))
        })
        .await
        .unwrap();
    let Some(AgentBody::Hello(hello)) = hello.body
    else
    {
        unreachable!()
    };
    let capabilities = hello.capabilities.unwrap();
    assert_eq!(capabilities.public_ipv4_pool, config.public_ipv4_pool);
    assert_eq!(capabilities.uplink_interface, "eth0");

    let mut spec = harness.spec("public-1", 1);
    spec.network.as_mut().unwrap().public_ipv4 = "203.0.113.80".to_owned();
    spec.run_state = RunState::Stopped as i32;
    harness.control.put_instance(spec.clone()).await;
    harness.wait_status("public-1", Phase::Stopped, 1).await;
    wait_mode(&harness, "Stopped").await;
    for (id, ip) in [("outside", "203.0.113.81"), ("duplicate", "203.0.113.80")]
    {
        let mut rejected = harness.spec(id, 1);
        rejected.network.as_mut().unwrap().public_ipv4 = ip.to_owned();
        harness.control.put_instance(rejected).await;
        harness.wait_status(id, Phase::Rejected, 1).await;
        assert!(harness.fake_sandbox_pid(id).is_none());
    }
    spec.generation = 2;
    spec.env
        .insert("QUARRY_HIBERNATED".to_owned(), "true".to_owned());
    harness.control.put_instance(spec.clone()).await;
    harness.wait_status("public-1", Phase::Stopped, 2).await;
    wait_mode(&harness, "Hibernated").await;
    let port = binding(&harness, "public-1")["responder_port"]
        .as_u64()
        .unwrap() as u16;
    for _ in 0..2
    {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client
            .write_all(&[7, 0, 47, 1, b'a', 0x63, 0xdd, 2])
            .await
            .unwrap();
        let mut reply = [0u8; 1024];
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply))
                .await
                .unwrap()
                .unwrap()
                > 0
        );
    }
    let wake = harness.control.wait_for(Duration::from_secs(5), |message| matches!(&message.body, Some(AgentBody::Wake(wake)) if wake.instance_id == "public-1")).await.unwrap();
    assert_eq!(wake.seq, 0);
    assert_eq!(harness.control.received().await.iter().filter(|message| matches!(&message.body, Some(AgentBody::Wake(wake)) if wake.instance_id == "public-1")).count(), 1);
    spec.generation = 3;
    spec.run_state = RunState::Running as i32;
    spec.env.remove("QUARRY_HIBERNATED");
    harness.control.put_instance(spec.clone()).await;
    harness.wait_status("public-1", Phase::Running, 3).await;
    wait_mode(&harness, "Running").await;
    agent.stop().await.unwrap();
    let agent = Agent::start(config).await.unwrap();
    wait_mode(&harness, "Running").await;
    harness.control.delete_instance("public-1").await;
    harness.wait_status("public-1", Phase::Deleted, 3).await;
    assert!(binding(&harness, "public-1").is_null());
    agent.stop().await.unwrap();
}
