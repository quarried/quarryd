mod common;

use std::time::Duration;

use common::{Harness, phases_for};
use proto::v1::Phase;
use proto::v1::agent_message::Body as AgentBody;

#[test]
fn guest_entry()
{
    common::run_guest_if_requested();
}

#[tokio::test(flavor = "multi_thread")]
async fn put_instance_reaches_running_through_the_provisioning_sequence()
{
    let harness = Harness::new().await;
    let agent = harness.start_agent().await;

    let hello = harness
        .control
        .wait_for(Duration::from_secs(30), |message| {
            matches!(message.body, Some(AgentBody::Hello(_)))
        })
        .await
        .expect("agent never said hello");
    let Some(AgentBody::Hello(hello)) = hello.body
    else
    {
        unreachable!()
    };
    assert_eq!(hello.node_id, "node-test");
    assert!(hello.capabilities.unwrap().isolations.len() >= 1);
    assert_eq!(harness.control.enrollments().await.len(), 1);

    harness.control.put_instance(harness.spec("mc-1", 1)).await;
    harness.wait_status("mc-1", Phase::Running, 1).await;

    let phases = phases_for(&harness.control.received().await, "mc-1");
    let expected = [
        Phase::Preparing,
        Phase::Booting,
        Phase::Starting,
        Phase::Running,
    ];
    let mut position = 0;
    for phase in phases
    {
        if position < expected.len() && phase == expected[position] as i32
        {
            position += 1;
        }
    }
    assert_eq!(position, expected.len(), "provisioning phases out of order");

    harness
        .control
        .wait_for(Duration::from_secs(30), |message| {
            matches!(message.body, Some(AgentBody::Heartbeat(_)))
        })
        .await
        .expect("no heartbeat");
    harness
        .control
        .wait_for(Duration::from_secs(30), |message| match &message.body
        {
            Some(AgentBody::Lease(renewal)) => renewal
                .leases
                .iter()
                .any(|lease| lease.instance_id == "mc-1"),
            _ => false,
        })
        .await
        .expect("no lease renewal");

    let metrics = reqwest_free_get(agent.metrics_addr()).await;
    assert!(metrics.contains("quarryd_reconcile_duration_seconds"));
    assert!(metrics.contains("node_id=\"node-test\""));

    harness.control.delete_instance("mc-1").await;
    harness.wait_status("mc-1", Phase::Deleted, 1).await;
    agent.stop().await.unwrap();
}

async fn reqwest_free_get(addr: std::net::SocketAddr) -> String
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    body
}
