mod common;

use std::time::Duration;

use common::{Harness, phases_for};
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::run_operation::Kind;
use proto::v1::{OperationStatus, Phase, RunOperation, SendConsoleCommand};

#[test]
fn guest_entry()
{
    common::run_guest_if_requested();
}

async fn wait_connections(harness: &Harness, count: u64)
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while harness.control.connection_count().await < count
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent did not reconnect"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_replays_unacked_control_messages()
{
    let harness = Harness::new().await;
    let agent = harness.start_agent().await;
    harness.control.put_instance(harness.spec("mc-r", 1)).await;
    harness.wait_status("mc-r", Phase::Running, 1).await;
    wait_connections(&harness, 1).await;

    harness.control.set_available(false).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut updated = harness.spec("mc-r", 2);
    updated.memory_mib = 2048;
    harness.control.put_instance(updated).await;
    harness.control.set_available(true).await;

    wait_connections(&harness, 2).await;
    harness.wait_status("mc-r", Phase::Running, 2).await;
    assert!(harness.control.last_agent_ack().await > 0);
    agent.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_put_instance_has_no_side_effects()
{
    let harness = Harness::new().await;
    let agent = harness.start_agent().await;
    let seq = harness.control.put_instance(harness.spec("mc-p", 1)).await;
    harness.wait_status("mc-p", Phase::Running, 1).await;
    let pid = harness.fake_sandbox_pid("mc-p").expect("no pid recorded");
    let statuses_before = phases_for(&harness.control.received().await, "mc-p").len();

    assert!(harness.control.resend(seq).await);
    harness.control.put_instance(harness.spec("mc-p", 1)).await;
    harness.control.disconnect().await;
    wait_connections(&harness, 2).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert_eq!(harness.fake_sandbox_pid("mc-p"), Some(pid));
    assert!(common::process_alive(pid));
    let phases = phases_for(&harness.control.received().await, "mc-p");
    assert!(
        phases[statuses_before..]
            .iter()
            .all(|phase| *phase == Phase::Running as i32),
        "replay changed the lifecycle: {phases:?}"
    );
    agent.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_run_operation_returns_stored_result_without_rerunning()
{
    let harness = Harness::new().await;
    let agent = harness.start_agent().await;
    harness.control.put_instance(harness.spec("mc-o", 1)).await;
    harness.wait_status("mc-o", Phase::Running, 1).await;

    let operation = RunOperation {
        op_id: "op-console-1".to_string(),
        instance_id: "mc-o".to_string(),
        kind: Some(Kind::Console(SendConsoleCommand {
            command: "say replay-marker".to_string(),
        })),
    };
    let seq = harness.control.run_operation(operation.clone()).await;
    let result = harness
        .control
        .wait_for(Duration::from_secs(30), |message| {
            matches!(&message.body, Some(AgentBody::OpResult(result)) if result.op_id == "op-console-1")
        })
        .await
        .expect("no operation result");
    let Some(AgentBody::OpResult(first)) = result.body
    else
    {
        unreachable!()
    };
    assert_eq!(first.status, OperationStatus::Succeeded as i32);

    assert!(harness.control.resend(seq).await);
    harness.control.run_operation(operation).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop
    {
        let results: Vec<_> = harness
            .control
            .received()
            .await
            .into_iter()
            .filter_map(|message| match message.body
            {
                Some(AgentBody::OpResult(result)) if result.op_id == "op-console-1" => Some(result),
                _ => None,
            })
            .collect();
        if results.len() >= 2
        {
            assert!(results.iter().all(|result| result == &first));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "replayed op_id was not answered"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let commands = std::fs::read_to_string(harness.command_log("mc-o")).unwrap();
    assert_eq!(
        commands.matches("say replay-marker").count(),
        1,
        "{commands}"
    );
    agent.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn outage_shorter_than_lease_ttl_changes_nothing()
{
    let harness = Harness::with_lease_ttl(15, 15_000).await;
    let agent = harness.start_agent().await;
    harness.control.put_instance(harness.spec("mc-l", 1)).await;
    harness.wait_status("mc-l", Phase::Running, 1).await;
    let pid = harness.fake_sandbox_pid("mc-l").unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = phases_for(&harness.control.received().await, "mc-l").len();

    harness.control.set_available(false).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    harness.control.set_available(true).await;
    wait_connections(&harness, 2).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let phases = phases_for(&harness.control.received().await, "mc-l");
    assert_eq!(harness.fake_sandbox_pid("mc-l"), Some(pid));
    assert!(common::process_alive(pid));
    assert!(
        phases[before..]
            .iter()
            .all(|phase| *phase == Phase::Running as i32),
        "{phases:?}"
    );
    agent.stop().await.unwrap();
}
