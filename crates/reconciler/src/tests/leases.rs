use proto::v1::{Lease, LeaseGrant, Phase};

use super::*;

use prost::Message;

fn grant(id: &str, epoch: u64, ttl_ms: u64) -> LeaseGrant
{
    LeaseGrant {
        instance_id: id.to_owned(),
        epoch,
        ttl_ms,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_stops_gracefully_and_a_later_grant_restarts()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "lease-expire";
    let mut spec = fixture.spec(id, "normal");
    spec.lease = Some(Lease {
        epoch: 3,
        ttl_ms: 3000,
    });
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();

    let stopped = node.wait_phase(id, Phase::Stopped).await;
    assert_eq!(stopped.reason, "lease expired");
    assert_eq!(stopped.lease_epoch, 3);
    let phases = node.phases(id);
    assert_eq!(
        phases[phases.len() - 3..],
        [Phase::Running, Phase::Stopping, Phase::Stopped]
    );
    let trace = fixture.trace(id);
    assert!(trace.iter().any(|line| line.starts_with("shutdown ")));
    assert!(trace.contains(&"exit 0".to_owned()));
    assert!(!process_alive(pid));
    assert!(node.handle.lease_renewal().leases.is_empty());
    sleep_ms(700).await;
    assert_eq!(node.status(id).unwrap().reason, "lease expired");
    assert_eq!(fixture.starts(id), 1);

    node.handle.grant_lease(grant(id, 2, 60_000)).await.unwrap();
    sleep_ms(500).await;
    assert_eq!(fixture.starts(id), 1);

    node.handle.grant_lease(grant(id, 3, 60_000)).await.unwrap();
    node.wait_running(id, 1).await;
    assert_eq!(fixture.starts(id), 2);
    let phases = node.phases(id);
    assert_eq!(
        phases[phases.len() - 4..],
        [
            Phase::Stopped,
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
async fn renewal_keeps_the_instance_running_across_several_ttls()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "lease-renew";
    let mut spec = fixture.spec(id, "normal");
    spec.lease = Some(Lease {
        epoch: 1,
        ttl_ms: 1500,
    });
    node.handle.put_instance(spec).await.unwrap();
    let started = tokio::time::Instant::now();
    let mut pid = None;
    while started.elapsed() < Duration::from_secs(6)
    {
        node.handle.grant_lease(grant(id, 1, 1500)).await.unwrap();
        if pid.is_none()
            && node
                .status(id)
                .is_some_and(|status| phase_of(&status) == Phase::Running)
        {
            pid = fixture.last_pid(id);
        }
        sleep_ms(300).await;
    }
    let pid = pid.expect("instance never reached RUNNING");
    assert_eq!(node.status(id).map(|s| phase_of(&s)), Some(Phase::Running));
    assert_eq!(fixture.last_pid(id), Some(pid));
    assert_eq!(fixture.starts(id), 1);
    assert!(!node.phases(id).contains(&Phase::Stopping));
    let renewal = node.handle.lease_renewal();
    assert_eq!(renewal.leases.len(), 1);
    assert_eq!(renewal.leases[0].epoch, 1);
    assert!(renewal.leases[0].remaining_ms <= 1500);
    let row = fixture.store.get_instance(id).unwrap().unwrap();
    assert_eq!(row.lease_epoch, 1);
    assert!(row.lease_expires_unix_ms.unwrap() > crate::leases::unix_ms_now());
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outage_shorter_than_the_ttl_changes_nothing()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "lease-outage";
    let mut spec = fixture.spec(id, "normal");
    spec.lease = Some(Lease {
        epoch: 1,
        ttl_ms: 6000,
    });
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();
    let events = node.event_count(id);
    sleep_ms(2500).await;
    assert_eq!(node.event_count(id), events, "{:?}", node.history(id));
    assert_eq!(fixture.last_pid(id), Some(pid));
    assert_eq!(node.status(id).map(|s| phase_of(&s)), Some(Phase::Running));
    node.handle.grant_lease(grant(id, 1, 60_000)).await.unwrap();
    sleep_ms(300).await;
    assert_eq!(node.event_count(id), events);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instances_without_a_lease_wait_and_lower_epochs_are_ignored()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "lease-wait";
    let mut spec = fixture.spec(id, "normal");
    spec.lease = None;
    node.handle.put_instance(spec).await.unwrap();
    let pending = node
        .wait_for(id, "waiting for lease", |status| {
            phase_of(status) == Phase::Pending && status.reason == "waiting for lease"
        })
        .await;
    assert_eq!(pending.lease_epoch, 0);
    sleep_ms(600).await;
    assert_eq!(fixture.starts(id), 0);

    node.handle.grant_lease(grant(id, 5, 0)).await.unwrap();
    let running = node.wait_running(id, 1).await;
    assert_eq!(running.lease_epoch, 5);
    let renewal = node.handle.lease_renewal();
    assert!(renewal.leases[0].remaining_ms > 50_000);

    node.handle.grant_lease(grant(id, 4, 60_000)).await.unwrap();
    assert_eq!(node.handle.lease_renewal().leases[0].epoch, 5);
    node.handle.grant_lease(grant(id, 6, 60_000)).await.unwrap();
    node.wait_for(id, "epoch 6", |status| status.lease_epoch == 6)
        .await;
    assert_eq!(fixture.starts(id), 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn semantic_replay_of_legacy_map_encoding_does_not_renew_an_expired_lease()
{
    let fixture = Fixture::new().await;
    let id = "lease-map-replay";
    let mut spec = fixture.spec(id, "normal");
    for index in 0..8
    {
        spec.env
            .insert(format!("SETTING_{index}"), format!("value-{index}"));
    }
    spec.secrets.insert("alpha".to_owned(), b"first".to_vec());
    spec.secrets.insert("beta".to_owned(), b"second".to_vec());

    // Old databases contain protobuf map entries in arbitrary wire order.
    // Construct one without depending on HashMap's randomized iteration order.
    let mut stored = spec.clone();
    let env = std::mem::take(&mut stored.env);
    let secrets = std::mem::take(&mut stored.secrets);
    let mut legacy = stored.encode_to_vec();
    for (name, value) in env
        .into_iter()
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .rev()
    {
        legacy.extend(
            InstanceSpec {
                env: HashMap::from([(name, value)]),
                ..Default::default()
            }
            .encode_to_vec(),
        );
    }
    for name in secrets
        .into_keys()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .rev()
    {
        legacy.extend(
            InstanceSpec {
                secrets: HashMap::from([(name, Vec::new())]),
                ..Default::default()
            }
            .encode_to_vec(),
        );
    }
    fixture.store.put_desired(id, 1, &legacy).unwrap();
    let mut actual = fixture.store.get_instance(id).unwrap().unwrap().actual();
    let expired_at = crate::leases::unix_ms_now() - 1000;
    actual.lease_epoch = 1;
    actual.lease_expires_unix_ms = Some(expired_at);
    fixture.store.update_actual(id, &actual).unwrap();

    let node = fixture.start().await;
    node.configure().await;
    for _ in 0..8
    {
        let replay = InstanceSpec::decode(spec.encode_to_vec().as_slice()).unwrap();
        node.handle.put_instance(replay).await.unwrap();
        let row = fixture.store.get_instance(id).unwrap().unwrap();
        assert_eq!(row.lease_expires_unix_ms, Some(expired_at));
        assert!(node.handle.lease_renewal().leases.is_empty());
    }
    sleep_ms(700).await;
    assert_eq!(fixture.starts(id), 0);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_mode_failures_do_not_block_expired_lease_shutdown()
{
    use network::Network;

    let mut fixture = Fixture::new().await;
    fixture.stop_deadline = Duration::from_millis(500);
    fixture.kill_deadline = Duration::from_millis(500);
    let node = fixture.start().await;
    node.configure().await;
    node.network
        .configure_public(&network::PublicIpv4Config {
            pool: vec!["192.0.2.50".to_owned()],
            uplink_interface: "eth0".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let id = "lease-network-error";
    let mut spec = fixture.spec(id, "ignore-shutdown");
    spec.network.as_mut().unwrap().public_ipv4 = "192.0.2.50".to_owned();
    node.handle.put_instance(spec).await.unwrap();
    node.wait_running(id, 1).await;
    let pid = fixture.last_pid(id).unwrap();
    for _ in 0..100
    {
        node.network.fail_next(
            network::FakeOperation::SetPublicMode,
            "nftables unavailable",
        );
    }
    node.handle.grant_lease(grant(id, 1, 400)).await.unwrap();
    node.wait_phase(id, Phase::Stopped).await;
    assert!(
        !process_alive(pid),
        "expired lease retained a live sandbox after network failure"
    );
    assert!(
        fixture
            .trace(id)
            .iter()
            .any(|line| line.starts_with("shutdown "))
    );
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_expiring_during_slow_preparation_is_checked_before_launch()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    let id = "lease-slow-prepare";
    let spec = fixture.spec(id, "normal");
    crash::delay(id, "after-attach", Duration::from_millis(1200));
    node.handle.put_instance(spec).await.unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    while !crash::was_hit(id, "after-attach")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            node.history(id)
        );
        sleep_ms(20).await;
    }
    node.handle.grant_lease(grant(id, 1, 100)).await.unwrap();
    sleep_ms(1700).await;
    assert_eq!(
        fixture.starts(id),
        0,
        "the expired preparation must not start a guest"
    );
    assert!(node.handle.lease_renewal().leases.is_empty());
    node.handle.grant_lease(grant(id, 1, 60_000)).await.unwrap();
    node.wait_running(id, 1).await;
    assert_eq!(fixture.starts(id), 1);
    node.handle.delete_instance(id).await.unwrap();
    node.wait_gone(id, &fixture.store).await;
    node.stop().await;
}
