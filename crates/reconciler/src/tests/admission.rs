use proto::v1::Phase;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_specs_are_rejected_and_a_later_generation_is_reevaluated()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "adm-big";
    let mut spec = fixture.spec(id, "normal");
    spec.memory_mib = 40_000;
    node.handle.put_instance(spec.clone()).await.unwrap();
    let rejected = node.wait_phase(id, Phase::Rejected).await;
    assert_eq!(
        rejected.reason,
        "insufficient memory: requested 40000 MiB, available 30720 MiB"
    );
    assert_eq!(rejected.observed_generation, 1);
    let row = fixture.store.get_instance(id).unwrap().unwrap();
    assert_eq!(row.phase, "PHASE_REJECTED");
    assert_eq!(fixture.starts(id), 0);
    assert!(fixture.volume_files().is_empty());

    spec.generation = 2;
    spec.memory_mib = 512;
    spec.vcpus = 20;
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_for(id, "vcpu rejection", |status| {
        status.observed_generation == 2
            && status.reason == "insufficient vcpus: requested 20, available 14"
    })
    .await;

    spec.generation = 3;
    spec.vcpus = 1;
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 3).await;
    let phases = node.phases(id);
    assert_eq!(
        phases,
        vec![
            Phase::Rejected,
            Phase::Pending,
            Phase::Preparing,
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
async fn malformed_specs_and_invalid_ids_are_rejected()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;

    let mut no_disk = fixture.spec("adm-nodisk", "normal");
    no_disk.disks.clear();
    node.handle.put_instance(no_disk).await.unwrap();
    let rejected = node.wait_phase("adm-nodisk", Phase::Rejected).await;
    assert!(
        rejected.reason.contains("exactly one data disk"),
        "{rejected:?}"
    );

    let mut unknown_isolation = fixture.spec("adm-iso", "normal");
    unknown_isolation.isolation = 9;
    node.handle.put_instance(unknown_isolation).await.unwrap();
    let rejected = node.wait_phase("adm-iso", Phase::Rejected).await;
    assert!(
        rejected.reason.contains("unknown isolation"),
        "{rejected:?}"
    );

    node.handle
        .put_instance(fixture.spec("bad/id", "normal"))
        .await
        .unwrap();
    let rejected = node.wait_event("bad/id", Phase::Rejected).await;
    assert!(rejected.reason.contains("malformed spec"));
    assert!(fixture.store.get_instance("bad/id").unwrap().is_none());

    node.handle.delete_instance("adm-nodisk").await.unwrap();
    node.handle.delete_instance("adm-iso").await.unwrap();
    node.wait_gone("adm-nodisk", &fixture.store).await;
    node.wait_gone("adm-iso", &fixture.store).await;
    assert_eq!(
        node.phases("adm-iso"),
        vec![Phase::Rejected, Phase::Deleting, Phase::Deleted]
    );
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn draining_rejects_new_instances_and_keeps_existing_ones()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let mut existing = fixture.spec("adm-keep", "normal");
    node.handle.put_instance(existing.clone()).await.unwrap();
    node.wait_running("adm-keep", 1).await;
    let pid = fixture.last_pid("adm-keep").unwrap();

    node.handle.set_draining(true);
    assert!(node.handle.heartbeat().load.unwrap().draining);
    let mut fresh = fixture.spec("adm-new", "normal");
    node.handle.put_instance(fresh.clone()).await.unwrap();
    let rejected = node.wait_phase("adm-new", Phase::Rejected).await;
    assert!(rejected.reason.contains("draining"), "{rejected:?}");
    sleep_ms(600).await;
    assert_eq!(fixture.last_pid("adm-keep"), Some(pid));
    assert_eq!(
        node.status("adm-keep").map(|s| phase_of(&s)),
        Some(Phase::Running)
    );

    existing.generation = 2;
    node.handle.put_instance(existing).await.unwrap();
    node.wait_running("adm-keep", 2).await;

    node.handle.set_draining(false);
    fresh.generation = 2;
    node.handle.put_instance(fresh).await.unwrap();
    node.wait_running("adm-new", 2).await;
    assert_eq!(
        node.handle
            .heartbeat()
            .load
            .unwrap()
            .committed
            .unwrap()
            .memory_mib,
        1024
    );

    for id in ["adm-keep", "adm-new"]
    {
        node.handle.delete_instance(id).await.unwrap();
    }
    for id in ["adm-keep", "adm-new"]
    {
        node.wait_gone(id, &fixture.store).await;
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_thin_pool_rejects_new_volumes()
{
    let mut fixture = Fixture::new().await;
    fixture.volume_capacity = 10 * GIB;
    let node = fixture.start().await;
    node.configure().await;
    let mut big = fixture.spec("adm-pool", "normal");
    big.disks[0].size_gib = 9;
    node.handle.put_instance(big).await.unwrap();
    node.wait_running("adm-pool", 1).await;

    node.handle
        .put_instance(fixture.spec("adm-pool2", "normal"))
        .await
        .unwrap();
    let rejected = node.wait_phase("adm-pool2", Phase::Rejected).await;
    assert!(
        rejected.reason.starts_with("thin pool is 90.0% full"),
        "{rejected:?}"
    );
    let deadline = tokio::time::Instant::now() + WAIT;
    while node.handle.heartbeat().load.unwrap().thin_pool_used_percent < 89.9
    {
        assert!(tokio::time::Instant::now() < deadline);
        sleep_ms(50).await;
    }
    let pool = node.volumes.pool_status().await.unwrap();
    assert_eq!(pool.alert, volume::PoolAlert::Critical);
    assert!(fixture.volume_files() == vec![format!("{}.img", volume_name("adm-pool", "data"))]);
    for id in ["adm-pool", "adm-pool2"]
    {
        node.handle.delete_instance(id).await.unwrap();
        node.wait_gone(id, &fixture.store).await;
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_new_generation_stops_the_old_one()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "adm-regen";
    let mut spec = fixture.spec(id, "normal");
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();

    spec.generation = 2;
    spec.memory_mib = 64_000;
    node.handle.put_instance(spec.clone()).await.unwrap();
    let rejected = node.wait_phase(id, Phase::Rejected).await;
    assert_eq!(rejected.observed_generation, 2);
    assert!(rejected.reason.starts_with("insufficient memory"));
    assert!(!process_alive(pid));
    let phases = node.phases(id);
    assert_eq!(
        phases[phases.len() - 4..],
        [
            Phase::Running,
            Phase::Stopping,
            Phase::Stopped,
            Phase::Rejected
        ]
    );
    assert_eq!(fixture.volume_files().len(), 1);

    spec.generation = 3;
    spec.memory_mib = 1024;
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 3).await;
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_generation_resource_edits_are_readmitted_and_repaired()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "adm-same-generation";
    let mut spec = fixture.spec(id, "normal");
    node.handle.put_instance(spec.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();

    spec.memory_mib = 64_000;
    node.handle.put_instance(spec.clone()).await.unwrap();
    let rejected = node.wait_phase(id, Phase::Rejected).await;
    assert_eq!(rejected.observed_generation, 1);
    assert!(
        rejected.reason.contains("insufficient memory"),
        "{rejected:?}"
    );
    assert!(!process_alive(pid));

    spec.memory_mib = 1024;
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    assert_eq!(fixture.starts(id), 2);
    assert_eq!(
        node.handle
            .heartbeat()
            .load
            .unwrap()
            .committed
            .unwrap()
            .memory_mib,
        1024
    );
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

async fn public_rejection_keeps_generation_fence(id: &str, occupied: bool)
{
    use network::Network;
    use prost::Message;

    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    node.network
        .configure_public(&network::PublicIpv4Config {
            pool: vec!["192.0.2.51".to_owned(), "192.0.2.52".to_owned()],
            uplink_interface: "eth0".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    if occupied
    {
        let mut owner = fixture.spec("public-owner", "normal");
        owner.network.as_mut().unwrap().public_ipv4 = "192.0.2.52".to_owned();
        node.handle.put_instance(owner).await.unwrap();
        node.wait_running("public-owner", 1).await;
    }
    let mut original = fixture.spec(id, "normal");
    original.network.as_mut().unwrap().public_ipv4 = "192.0.2.51".to_owned();
    node.handle.put_instance(original.clone()).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();
    let mut updated = original.clone();
    updated.generation = 2;
    updated.network.as_mut().unwrap().public_ipv4 = if occupied
    {
        "192.0.2.52".to_owned()
    }
    else
    {
        "198.51.100.99".to_owned()
    };
    node.handle.put_instance(updated.clone()).await.unwrap();
    let rejected = node.wait_phase(id, Phase::Rejected).await;
    assert_eq!(rejected.observed_generation, 2);
    assert!(!process_alive(pid));
    let row = fixture.store.get_instance(id).unwrap().unwrap();
    assert_eq!(row.generation, 2);
    assert_eq!(InstanceSpec::decode(row.spec.as_slice()).unwrap(), updated);
    node.handle.put_instance(original.clone()).await.unwrap();
    assert_eq!(
        fixture.store.get_instance(id).unwrap().unwrap().generation,
        2
    );
    node.stop().await;

    let node = fixture.start().await;
    node.wait_phase(id, Phase::Rejected).await;
    node.handle.put_instance(original).await.unwrap();
    sleep_ms(600).await;
    assert_eq!(node.status(id).unwrap().observed_generation, 2);
    assert_eq!(phase_of(&node.status(id).unwrap()), Phase::Rejected);
    assert_eq!(fixture.starts(id), 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    if occupied
    {
        node.handle.delete_instance("public-owner").await.unwrap();
        node.wait_gone("public-owner", &fixture.store).await;
    }
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_public_address_update_persists_and_stops_the_previous_generation()
{
    public_rejection_keeps_generation_fence("adm-public-invalid", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn occupied_public_address_update_persists_and_stops_the_previous_generation()
{
    public_rejection_keeps_generation_fence("adm-public-occupied", true).await;
}
