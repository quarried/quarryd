mod common;

use std::time::Duration;

use common::{Harness, phases_for};
use proto::v1::Phase;

#[test]
fn guest_entry()
{
    common::run_guest_if_requested();
}

#[tokio::test(flavor = "multi_thread")]
async fn restarted_agent_adopts_running_instances_without_restarting_them()
{
    let harness = Harness::new().await;
    let agent = harness.start_agent().await;
    harness.control.put_instance(harness.spec("mc-a", 1)).await;
    harness.wait_status("mc-a", Phase::Running, 1).await;
    let pid = harness.fake_sandbox_pid("mc-a").expect("no pid");

    agent.stop().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        common::process_alive(pid),
        "stopping quarryd must not stop instances"
    );
    let seen_before_restart = phases_for(&harness.control.received().await, "mc-a").len();
    let connections_before = harness.control.connection_count().await;

    let agent = harness.start_agent().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while harness.control.connection_count().await <= connections_before
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    harness.wait_status("mc-a", Phase::Running, 1).await;

    assert_eq!(harness.fake_sandbox_pid("mc-a"), Some(pid));
    assert!(common::process_alive(pid));
    let phases = phases_for(&harness.control.received().await, "mc-a");
    assert!(
        !phases[seen_before_restart..]
            .iter()
            .any(|phase| *phase == Phase::Booting as i32 || *phase == Phase::Stopping as i32),
        "instance was restarted during adoption: {phases:?}"
    );

    harness.control.delete_instance("mc-a").await;
    harness.wait_status("mc-a", Phase::Deleted, 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!common::process_alive(pid));
    agent.stop().await.unwrap();
}
