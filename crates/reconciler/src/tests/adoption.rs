use proto::v1::{LeaseGrant, Phase, RestartPolicy};

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_reconciler_adopts_running_instances_without_restarting_them()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "adopt-live";
    node.handle
        .put_instance(fixture.spec(id, "normal"))
        .await
        .unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();
    node.stop().await;
    sleep_ms(300).await;
    assert!(process_alive(pid));

    let node = fixture.start().await;
    assert_eq!(node.status(id).map(|s| phase_of(&s)), Some(Phase::Running));
    fixture.wait_trace(id, "ready again").await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while !(node.guest_ready(id) && node.health_reports(id) > 2)
    {
        assert!(tokio::time::Instant::now() < deadline);
        sleep_ms(20).await;
    }
    assert_eq!(fixture.starts(id), 1);
    assert_eq!(fixture.last_pid(id), Some(pid));
    assert!(process_alive(pid));
    assert!(
        node.history(id)
            .iter()
            .all(|(phase, _, _)| *phase == Phase::Running),
        "{:?}",
        node.history(id)
    );
    let connections = fixture
        .trace(id)
        .iter()
        .filter(|line| *line == "connected")
        .count();
    assert_eq!(connections, 2);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    assert!(!process_alive(pid));
    node.stop().await;
}

async fn kill_while_down(policy: RestartPolicy, id: &str, expire_lease: bool) -> (Fixture, Node)
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let mut spec = fixture.spec(id, "normal");
    spec.restart_policy = policy as i32;
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();
    node.stop().await;
    kill_process(pid);
    let deadline = tokio::time::Instant::now() + WAIT;
    while process_alive(pid)
    {
        assert!(tokio::time::Instant::now() < deadline);
        sleep_ms(20).await;
    }
    sleep_ms(200).await;
    if expire_lease
    {
        let row = fixture.store.get_instance(id).unwrap().unwrap();
        let mut actual = row.actual();
        actual.lease_expires_unix_ms = Some(crate::leases::unix_ms_now() - 1000);
        fixture.store.update_actual(id, &actual).unwrap();
    }
    let node = fixture.start().await;
    (fixture, node)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_instance_that_died_while_down_fails_and_restarts_by_policy()
{
    let id = "adopt-dead";
    let (fixture, node) = kill_while_down(RestartPolicy::OnFailure, id, false).await;
    let failed = node.wait_event(id, Phase::Failed).await;
    assert_eq!(failed.reason, "not adoptable after restart");
    node.wait_running(id, 1).await;
    assert_eq!(fixture.starts(id), 2);
    assert_eq!(
        node.phases(id),
        vec![
            Phase::Failed,
            Phase::Booting,
            Phase::Starting,
            Phase::Running
        ]
    );
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_instance_that_died_while_down_stays_failed_with_policy_never()
{
    let id = "adopt-never";
    let (fixture, node) = kill_while_down(RestartPolicy::Never, id, false).await;
    let failed = node.wait_phase(id, Phase::Failed).await;
    assert_eq!(failed.reason, "not adoptable after restart");
    sleep_ms(1000).await;
    assert_eq!(fixture.starts(id), 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_reboot_instances_with_expired_leases_wait_for_the_control_plane()
{
    let id = "adopt-reboot";
    let (fixture, node) = kill_while_down(RestartPolicy::OnFailure, id, true).await;
    let waiting = node
        .wait_for(id, "waiting for lease", |status| {
            phase_of(status) == Phase::Failed && status.reason.ends_with("waiting for lease")
        })
        .await;
    assert!(waiting.reason.starts_with("not adoptable after restart"));
    sleep_ms(800).await;
    assert_eq!(fixture.starts(id), 1);
    node.handle
        .grant_lease(LeaseGrant {
            instance_id: id.to_owned(),
            epoch: 1,
            ttl_ms: 60_000,
        })
        .await
        .unwrap();
    node.wait_running(id, 1).await;
    assert_eq!(fixture.starts(id), 2);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}
