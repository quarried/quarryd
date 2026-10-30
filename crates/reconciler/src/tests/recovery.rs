use proto::v1::Phase;

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage
{
    Create,
    Update,
    Delete,
}

async fn wait_for_crash(id: &str, label: &str)
{
    let deadline = tokio::time::Instant::now() + WAIT;
    while !crash::was_hit(id, label)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{id} never reached crash point {label}"
        );
        sleep_ms(10).await;
    }
}

async fn crash_and_converge(stage: Stage, label: &str, id: &str)
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let mut spec = fixture.spec(id, "normal");
    match stage
    {
        Stage::Create =>
        {
            crash::arm(id, label);
            node.handle.put_instance(spec.clone()).await.unwrap();
        }
        Stage::Update =>
        {
            node.handle.put_instance(spec.clone()).await.unwrap();
            node.wait_running(id, 1).await;
            crash::arm(id, label);
            spec.generation = 2;
            spec.env.insert("SERVER_VERSION".to_owned(), "2".to_owned());
            node.handle.put_instance(spec.clone()).await.unwrap();
        }
        Stage::Delete =>
        {
            node.handle.put_instance(spec.clone()).await.unwrap();
            node.wait_running(id, 1).await;
            crash::arm(id, label);
            node.handle.delete_instance(id).await.unwrap();
        }
    }
    wait_for_crash(id, label).await;
    node.stop().await;

    let node = fixture.start().await;
    match stage
    {
        Stage::Create =>
        {
            node.wait_running(id, 1).await;
            assert_eq!(fixture.starts(id), 1, "{:?}", fixture.trace(id));
            assert!(process_alive(fixture.last_pid(id).unwrap()));
        }
        Stage::Update =>
        {
            node.wait_running(id, 2).await;
            assert_eq!(fixture.starts(id), 2, "{:?}", fixture.trace(id));
            let trace = fixture.trace(id);
            assert!(trace.iter().any(|line| line.starts_with("configure 2 ")));
        }
        Stage::Delete =>
        {
            node.wait_gone(id, &fixture.store).await;
            assert!(!process_alive(fixture.last_pid(id).unwrap()));
            assert!(fixture.volume_files().is_empty());
            assert!(node.network.attachments().is_empty());
            assert_eq!(
                fixture
                    .store
                    .artifact_ref_count(&fixture.rootfs.digest)
                    .unwrap(),
                0
            );
            assert_eq!(fixture.starts(id), 1);
            node.stop().await;
            return;
        }
    }
    assert_eq!(fixture.volume_files().len(), 1);
    assert_eq!(node.network.attachments().len(), 1);
    let pid = fixture.last_pid(id).unwrap();
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    assert!(!process_alive(pid));
    assert!(fixture.volume_files().is_empty());
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_preparing()
{
    crash_and_converge(Stage::Create, "PHASE_PREPARING", "rc-c-prep").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_fetching_artifacts()
{
    crash_and_converge(Stage::Create, "after-artifacts", "rc-c-art").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_creating_the_volume()
{
    crash_and_converge(Stage::Create, "after-volume", "rc-c-vol").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_attaching_the_network()
{
    crash_and_converge(Stage::Create, "after-attach", "rc-c-att").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_booting_before_launch()
{
    crash_and_converge(Stage::Create, "PHASE_BOOTING", "rc-c-boot").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_launch()
{
    crash_and_converge(Stage::Create, "after-launch", "rc-c-launch").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_sending_configure()
{
    crash_and_converge(Stage::Create, "after-configure", "rc-c-conf").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_starting()
{
    crash_and_converge(Stage::Create, "PHASE_STARTING", "rc-c-start").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_running()
{
    crash_and_converge(Stage::Create, "PHASE_RUNNING", "rc-c-run").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_stopping_for_a_new_generation()
{
    crash_and_converge(Stage::Update, "PHASE_STOPPING", "rc-u-stopping").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_destroying_the_old_sandbox()
{
    crash_and_converge(Stage::Update, "after-destroy", "rc-u-destroy").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_stopped_for_a_new_generation()
{
    crash_and_converge(Stage::Update, "PHASE_STOPPED", "rc-u-stopped").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_rebooting_into_a_new_generation()
{
    crash_and_converge(Stage::Update, "after-launch", "rc-u-launch").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_stopping_for_delete()
{
    crash_and_converge(Stage::Delete, "PHASE_STOPPING", "rc-d-stopping").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_entering_deleting()
{
    crash_and_converge(Stage::Delete, "PHASE_DELETING", "rc-d-deleting").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_detaching_the_network()
{
    crash_and_converge(Stage::Delete, "after-detach", "rc-d-detach").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_releasing_everything_before_removing_the_row()
{
    crash_and_converge(Stage::Delete, "after-release", "rc-d-release").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_mid_failure_resumes_the_restart_policy()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "rec-failed";
    let mut spec = fixture.spec(id, "normal");
    spec.restart_policy = proto::v1::RestartPolicy::OnFailure as i32;
    spec.env
        .insert(guest::CRASH_MS_ENV.to_owned(), "400".to_owned());
    crash::arm(id, "PHASE_FAILED");
    node.handle.put_instance(spec).await.unwrap();
    wait_for_crash(id, "PHASE_FAILED").await;
    node.stop().await;
    let node = fixture.start().await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while fixture.starts(id) < 2
    {
        assert!(tokio::time::Instant::now() < deadline);
        sleep_ms(20).await;
    }
    node.wait_event(id, Phase::Booting).await;
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_puts_and_repeated_passes_have_no_side_effects()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "idem-a";
    let spec = fixture.spec(id, "normal");
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();
    let attaches = node.attach_calls(id);
    let events = node.event_count(id);
    let renewal = node.handle.lease_renewal();
    for _ in 0..3
    {
        node.handle.put_instance(spec.clone()).await.unwrap();
        node.handle
            .apply_desired_state(proto::v1::DesiredState {
                instances: vec![spec.clone()],
                network: Some(network_config()),
            })
            .await
            .unwrap();
    }
    sleep_ms(2000).await;
    assert_eq!(fixture.last_pid(id), Some(pid));
    assert_eq!(fixture.starts(id), 1);
    assert!(process_alive(pid));
    assert_eq!(node.attach_calls(id), attaches);
    assert_eq!(node.event_count(id), events, "{:?}", node.history(id));
    assert_eq!(fixture.volume_files().len(), 1);
    assert_eq!(node.network.attachments().len(), 1);
    assert_eq!(node.status(id).map(|s| phase_of(&s)), Some(Phase::Running));
    assert!(node.handle.lease_renewal().leases[0].remaining_ms <= renewal.leases[0].remaining_ms);

    let mut stale = spec.clone();
    stale.generation = 0;
    stale.memory_mib = 4096;
    node.handle.put_instance(stale).await.unwrap();
    sleep_ms(700).await;
    assert_eq!(fixture.starts(id), 1);
    assert_eq!(node.status(id).unwrap().observed_generation, 1);

    node.handle
        .apply_desired_state(proto::v1::DesiredState {
            instances: Vec::new(),
            network: None,
        })
        .await
        .unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacement_cleanup_survives_a_crash_after_the_new_disk_is_running()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let snapshot_path = fixture.path("replacement-snapshot.img");
    std::fs::write(&snapshot_path, b"snapshot world contents").unwrap();
    let snapshots = SnapshotStore::new(fixture.snapshot_objects.clone(), 1024, 2);
    snapshots
        .upload(&snapshot_path, "replacement", "old-world", 1)
        .await
        .unwrap();
    let id = "disk-replace-crash";
    let mut spec = fixture.spec(id, "normal");
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    crash::arm(id, "PHASE_RUNNING");
    spec.generation = 2;
    spec.disks[0].name = "restored".to_owned();
    spec.disks[0].restore_from = Some(proto::v1::SnapshotRef {
        manifest_key: SnapshotStore::manifest_key("replacement"),
    });
    node.handle.put_instance(spec.clone()).await.unwrap();
    wait_for_crash(id, "PHASE_RUNNING").await;
    assert_eq!(
        fixture.store.instance_disks(id).unwrap(),
        vec![format!("{id}-data"), format!("{id}-restored")]
    );
    assert_eq!(fixture.volume_files().len(), 2);
    node.stop().await;
    let node = fixture.start().await;
    node.wait_running(id, 2).await;
    let until = tokio::time::Instant::now() + WAIT;
    while fixture.volume_files().len() != 1
    {
        assert!(tokio::time::Instant::now() < until);
        sleep_ms(10).await;
    }
    assert_eq!(fixture.volume_files(), vec![format!("{id}-restored.img")]);
    let restored = fixture.path(&format!("volumes/{id}-restored.img"));
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        b"snapshot world contents"
    );
    std::fs::write(&restored, b"new live world changes").unwrap();
    spec.generation = 3;
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 3).await;
    assert_eq!(std::fs::read(&restored).unwrap(), b"new live world changes");
    assert_eq!(fixture.volume_files(), vec![format!("{id}-restored.img")]);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    assert!(fixture.store.instance_disks(id).unwrap().is_empty());
    node.stop().await;
}
