use proto::v1::{Phase, RestartPolicy, RunState};

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_update_stop_start_and_delete()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-a";
    let mut spec = fixture.spec(id, "normal");
    spec.secrets
        .insert("rcon.password".to_owned(), b"hunter2".to_vec());
    node.handle.put_instance(spec.clone()).await.unwrap();

    let running = node.wait_running(id, 1).await;
    assert_eq!(running.lease_epoch, 1);
    assert!(running.guest_ip.starts_with("10.77.0."));
    assert_eq!(
        node.phases(id),
        vec![
            Phase::Preparing,
            Phase::Booting,
            Phase::Starting,
            Phase::Running
        ]
    );
    let first_pid = fixture.last_pid(id).unwrap();
    let trace = fixture.trace(id);
    assert!(trace.contains(&"configure 1 memory=512 secrets=[rcon.password=hunter2]".to_owned()));
    let row = fixture.store.get_instance(id).unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&row.spec).contains("hunter2"));
    let diagnostics = node.handle.diagnostics().await.unwrap().to_string();
    assert!(diagnostics.contains(id));
    assert!(!diagnostics.contains("hunter2"));
    assert_eq!(fixture.volume_files(), vec!["flow-a-data.img".to_owned()]);
    assert_eq!(node.network.attachments().len(), 1);
    assert_eq!(
        fixture
            .store
            .artifact_ref_count(&fixture.rootfs.digest)
            .unwrap(),
        1
    );
    assert!(node.handle.console_path(id).is_some());
    let inventory = node.handle.inventory();
    assert_eq!(inventory.instances.len(), 1);
    assert_eq!(inventory.allocatable.unwrap().memory_mib, 30720);
    let heartbeat = node.handle.heartbeat();
    let load = heartbeat.load.unwrap();
    assert_eq!(load.running_instances, 1);
    assert_eq!(load.committed.unwrap().memory_mib, 512);

    spec.generation = 2;
    spec.env.insert("SERVER_VERSION".to_owned(), "2".to_owned());
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 2).await;
    let after_update: Vec<Phase> = node.phases(id)[4..].to_vec();
    assert_eq!(
        after_update,
        vec![
            Phase::Stopping,
            Phase::Stopped,
            Phase::Booting,
            Phase::Starting,
            Phase::Running
        ]
    );
    let trace = fixture.trace(id);
    assert!(trace.iter().any(|line| line.starts_with("shutdown ")));
    assert!(trace.contains(&"exit 0".to_owned()));
    assert!(trace.iter().any(|line| line.starts_with("configure 2 ")));
    assert_ne!(fixture.last_pid(id).unwrap(), first_pid);
    assert!(!process_alive(first_pid));

    node.handle
        .send_console_command(id, "say hello")
        .await
        .unwrap();
    fixture.wait_trace(id, "console say hello").await;
    assert!(
        node.handle
            .send_console_command(id, "say\nhello")
            .await
            .is_err()
    );

    spec.generation = 3;
    spec.run_state = RunState::Stopped as i32;
    node.handle.put_instance(spec.clone()).await.unwrap();
    let stopped = node
        .wait_for(id, "STOPPED at generation 3", |status| {
            phase_of(status) == Phase::Stopped && status.observed_generation == 3
        })
        .await;
    assert_eq!(stopped.reason, "stopped");
    assert_eq!(fixture.volume_files().len(), 1);
    assert_eq!(node.network.attachments().len(), 1);

    spec.generation = 4;
    spec.run_state = RunState::Running as i32;
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 4).await;
    assert_eq!(fixture.starts(id), 3);

    let pid = fixture.last_pid(id).unwrap();
    node.handle.delete_instance(id).await.unwrap();
    node.wait_event(id, Phase::Deleted).await;
    node.wait_gone(id, &fixture.store).await;
    let tail: Vec<Phase> = node.phases(id).into_iter().rev().take(4).collect();
    assert_eq!(
        tail,
        vec![
            Phase::Deleted,
            Phase::Deleting,
            Phase::Stopped,
            Phase::Stopping
        ]
    );
    assert!(!process_alive(pid));
    assert!(fixture.volume_files().is_empty());
    assert!(node.network.attachments().is_empty());
    assert_eq!(
        fixture
            .store
            .artifact_ref_count(&fixture.rootfs.digest)
            .unwrap(),
        0
    );
    assert!(node.handle.console_path(id).is_none());
    assert!(node.handle.lease_renewal().leases.is_empty());
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn booting_fails_when_the_guest_never_connects_and_failed_instances_delete()
{
    let mut fixture = Fixture::new().await;
    fixture.guest_connect_timeout = Duration::from_millis(1500);
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-never-connect";
    node.handle
        .put_instance(fixture.spec(id, "never-connect"))
        .await
        .unwrap();
    let failed = node.wait_phase(id, Phase::Failed).await;
    assert!(failed.reason.contains("did not connect"), "{failed:?}");
    assert_eq!(
        node.phases(id),
        vec![Phase::Preparing, Phase::Booting, Phase::Failed]
    );
    sleep_ms(800).await;
    assert_eq!(node.status(id).map(|s| phase_of(&s)), Some(Phase::Failed));
    assert_eq!(fixture.starts(id), 1);
    let pid = fixture.last_pid(id).unwrap();
    assert!(!process_alive(pid));

    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    let tail: Vec<Phase> = node.phases(id).into_iter().rev().take(3).collect();
    assert_eq!(tail, vec![Phase::Deleted, Phase::Deleting, Phase::Failed]);
    assert!(fixture.volume_files().is_empty());
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn starting_fails_when_the_server_never_reports_ready()
{
    let mut fixture = Fixture::new().await;
    fixture.ready_timeout = Duration::from_millis(1500);
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-never-ready";
    node.handle
        .put_instance(fixture.spec(id, "never-ready"))
        .await
        .unwrap();
    let failed = node.wait_phase(id, Phase::Failed).await;
    assert!(failed.reason.contains("did not report Ready"), "{failed:?}");
    assert_eq!(
        node.phases(id),
        vec![
            Phase::Preparing,
            Phase::Booting,
            Phase::Starting,
            Phase::Failed
        ]
    );
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

async fn crash_and_restart(policy: RestartPolicy, id: &str)
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let mut spec = fixture.spec(id, "normal");
    spec.restart_policy = policy as i32;
    spec.env
        .insert(guest::CRASH_MS_ENV.to_owned(), "600".to_owned());
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    let failed = node.wait_event(id, Phase::Failed).await;
    assert_eq!(failed.reason, "sandbox exited with code 3");
    let deadline = tokio::time::Instant::now() + WAIT;
    while fixture.starts(id) < 2
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            node.history(id)
        );
        sleep_ms(20).await;
    }
    let phases = node.phases(id);
    let failed_at = phases
        .iter()
        .position(|phase| *phase == Phase::Failed)
        .unwrap();
    assert_eq!(phases[failed_at - 1], Phase::Running);
    let deadline = tokio::time::Instant::now() + WAIT;
    while node.phases(id).len() <= failed_at + 1
    {
        assert!(tokio::time::Instant::now() < deadline);
        sleep_ms(20).await;
    }
    assert_eq!(node.phases(id)[failed_at + 1], Phase::Booting);
    let row = fixture.store.get_instance(id).unwrap().unwrap();
    assert!(row.restart_count >= 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_crash_restarts_with_policy_on_failure()
{
    crash_and_restart(RestartPolicy::OnFailure, "flow-crash-on-failure").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_crash_restarts_with_policy_always()
{
    crash_and_restart(RestartPolicy::Always, "flow-crash-always").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_crash_with_policy_never_stays_failed()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-crash-never";
    let mut spec = fixture.spec(id, "normal");
    spec.env
        .insert(guest::CRASH_MS_ENV.to_owned(), "300".to_owned());
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    node.wait_phase(id, Phase::Failed).await;
    sleep_ms(1500).await;
    assert_eq!(node.status(id).map(|s| phase_of(&s)), Some(Phase::Failed));
    assert_eq!(fixture.starts(id), 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preparation_failure_fails_and_on_failure_retries()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    node.network
        .fail_next(network::FakeOperation::Attach, "attach exploded");
    let id = "flow-prepare-fail";
    let mut spec = fixture.spec(id, "normal");
    spec.restart_policy = RestartPolicy::OnFailure as i32;
    node.handle.put_instance(spec).await.unwrap();
    let failed = node.wait_event(id, Phase::Failed).await;
    assert!(failed.reason.contains("attach exploded"), "{failed:?}");
    node.wait_running(id, 1).await;
    assert_eq!(
        node.phases(id),
        vec![
            Phase::Preparing,
            Phase::Failed,
            Phase::Booting,
            Phase::Starting,
            Phase::Running
        ]
    );
    assert_eq!(node.network.attachments().len(), 1);
    assert_eq!(fixture.volume_files().len(), 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopped_instances_delete_and_ignore_shutdown_escalates_to_force()
{
    let mut fixture = Fixture::new().await;
    fixture.stop_deadline = Duration::from_millis(800);
    fixture.kill_deadline = Duration::from_millis(800);
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-stubborn";
    let mut spec = fixture.spec(id, "ignore-shutdown");
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();

    spec.generation = 2;
    spec.run_state = RunState::Stopped as i32;
    node.handle.put_instance(spec).await.unwrap();
    let stopped = node.wait_phase(id, Phase::Stopped).await;
    assert!(
        stopped
            .reason
            .starts_with("stopped; guest did not stop within 800 ms"),
        "{stopped:?}"
    );
    assert!(stopped.reason.contains("killed"), "{stopped:?}");
    let trace = fixture.trace(id);
    assert!(trace.contains(&"shutdown 800".to_owned()), "{trace:?}");
    assert!(trace.contains(&"sigterm".to_owned()), "{trace:?}");
    assert!(!process_alive(pid));

    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    let tail: Vec<Phase> = node.phases(id).into_iter().rev().take(3).collect();
    assert_eq!(tail, vec![Phase::Deleted, Phase::Deleting, Phase::Stopped]);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_instances_have_memory_reclaimed_by_the_balloon()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-balloon";
    let mut spec = fixture.spec(id, "normal");
    spec.balloon_idle_reclaim = true;
    spec.idle_reclaim_minutes = 0;
    spec.memory_mib = 2048;
    spec.cpu_pinning = true;
    spec.env
        .insert(guest::PLAYERS_ENV.to_owned(), "0".to_owned());
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while node.sandbox.memory_target(id) != Some(1024)
    {
        assert!(tokio::time::Instant::now() < deadline);
        sleep_ms(20).await;
    }
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sampler_reports_interface_counters_and_unknown_deletes_are_reported()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "flow-sampler";
    node.handle
        .put_instance(fixture.spec(id, "normal"))
        .await
        .unwrap();
    node.wait_running(id, 1).await;
    node.network.set_counters(
        id,
        network::InterfaceCounters {
            rx_bytes: 123_456,
            tx_bytes: 654_321,
        },
    );
    let deadline = tokio::time::Instant::now() + WAIT;
    loop
    {
        let rendered = node.metrics.render();
        if rendered.contains("123456") && rendered.contains("654321")
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{rendered}");
        sleep_ms(50).await;
    }
    node.handle.delete_instance("never-existed").await.unwrap();
    node.wait_event("never-existed", Phase::Deleted).await;
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}
