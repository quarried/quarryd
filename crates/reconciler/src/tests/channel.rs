use proto::v1::Phase;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn misbehaving_guests_are_dropped_without_affecting_other_instances()
{
    let fixture = Fixture::new().await;
    let node = fixture.start().await;
    node.configure().await;
    node.handle
        .put_instance(fixture.spec("ch-good", "normal"))
        .await
        .unwrap();
    node.wait_running("ch-good", 1).await;
    let good_pid = fixture.last_pid("ch-good").unwrap();

    let abusers = ["ch-oversized", "ch-malformed", "ch-flood"];
    for (id, mode) in abusers.iter().zip(["oversized", "malformed", "flood"])
    {
        node.handle
            .put_instance(fixture.spec(id, mode))
            .await
            .unwrap();
    }
    let deadline = tokio::time::Instant::now() + WAIT;
    while abusers.iter().any(|id| node.dropped_connections(id) < 1)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "drops: {:?}",
            abusers
                .iter()
                .map(|id| node.dropped_connections(id))
                .collect::<Vec<_>>()
        );
        sleep_ms(20).await;
    }

    let before = node.health_reports("ch-good");
    sleep_ms(1500).await;
    let after = node.health_reports("ch-good");
    assert!(after >= before + 4, "health went from {before} to {after}");
    assert_eq!(
        node.status("ch-good").map(|s| phase_of(&s)),
        Some(Phase::Running)
    );
    assert_eq!(fixture.last_pid("ch-good"), Some(good_pid));
    assert!(node.guest_ready("ch-good"));
    assert_eq!(node.dropped_connections("ch-good"), 0);
    assert!(
        node.history("ch-good")
            .iter()
            .all(|(phase, _, _)| *phase != Phase::Failed)
    );
    assert_ne!(
        node.status("ch-oversized").map(|s| phase_of(&s)),
        Some(Phase::Running)
    );
    assert_ne!(
        node.status("ch-malformed").map(|s| phase_of(&s)),
        Some(Phase::Running)
    );
    let diagnostics = node.handle.diagnostics().await.unwrap();
    let flood = diagnostics["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|instance| instance["id"] == "ch-flood")
        .unwrap()
        .clone();
    assert!(flood["guest"]["dropped_connections"].as_u64().unwrap() >= 1);

    for id in ["ch-good", "ch-oversized", "ch-malformed", "ch-flood"]
    {
        node.handle.delete_instance(id).await.unwrap();
    }
    for id in ["ch-good", "ch-oversized", "ch-malformed", "ch-flood"]
    {
        node.wait_gone(id, &fixture.store).await;
    }
    node.stop().await;
}
