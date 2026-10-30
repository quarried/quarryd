mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::Harness;
use proto::v1::Phase;
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::run_operation::Kind;
use proto::v1::{OperationStatus, RunOperation, SendConsoleCommand, SnapshotNow};

#[test]
fn guest_entry()
{
    common::run_guest_if_requested();
}

async fn metrics(addr: std::net::SocketAddr) -> String
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

fn gauge(text: &str, name: &str, instance_id: &str) -> Option<f64>
{
    let prefix = format!("{name}{{node_id=\"node-test\",instance_id=\"{instance_id}\"}} ");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.trim().parse().ok())
}

async fn run_operation(harness: &Harness, op_id: &str, kind: Kind) -> proto::v1::OperationResult
{
    harness
        .control
        .run_operation(RunOperation {
            op_id: op_id.to_string(),
            instance_id: "mc-q".to_string(),
            kind: Some(kind),
        })
        .await;
    let id = op_id.to_string();
    let message = harness
        .control
        .wait_for(Duration::from_secs(90), move |message| {
            matches!(&message.body, Some(AgentBody::OpResult(result)) if result.op_id == id)
        })
        .await
        .unwrap_or_else(|| panic!("operation {op_id} never finished"));
    let Some(AgentBody::OpResult(result)) = message.body
    else
    {
        unreachable!()
    };
    result
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Quarry server binary at /usr/local/bin/quarry-server and an empty writable /data"]
async fn the_quarry_server_binary_runs_under_the_default_guest_command()
{
    let data = Path::new("/data");
    assert!(
        Path::new(guest_proto::SERVER_BINARY_PATH).is_file(),
        "install the Quarry server binary at {}",
        guest_proto::SERVER_BINARY_PATH
    );
    assert!(
        !data.join("quarry.toml").exists() && !data.join("world").exists(),
        "/data must start empty"
    );

    let harness = Harness::new().await;
    let agent = harness.start_agent().await;
    let mut spec = harness.spec("mc-q", 1);
    spec.env.remove("QUARRY_SERVER_COMMAND");
    spec.env
        .insert("QUARRY_WORLD_SEED".to_string(), "42".to_string());
    harness.control.put_instance(spec).await;
    harness.wait_status("mc-q", Phase::Running, 1).await;

    let config = std::fs::read_to_string(data.join("quarry.toml")).unwrap();
    assert!(config.contains("world_path"), "{config}");
    assert!(data.join("world/level.dat").is_file());

    let deadline = Instant::now() + Duration::from_secs(60);
    loop
    {
        let text = metrics(agent.metrics_addr()).await;
        let tps = gauge(&text, "quarryd_guest_tps", "mc-q");
        if tps.is_some_and(|tps| tps > 1.0)
        {
            assert_eq!(gauge(&text, "quarryd_guest_players", "mc-q"), Some(0.0));
            assert!(gauge(&text, "quarryd_guest_mspt", "mc-q").is_some_and(|mspt| mspt > 0.0));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no guest health from the Quarry server: {tps:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let console = run_operation(
        &harness,
        "op-console",
        Kind::Console(SendConsoleCommand {
            command: "save-all".to_string(),
        }),
    )
    .await;
    assert_eq!(
        console.status,
        OperationStatus::Succeeded as i32,
        "{console:?}"
    );

    let snapshot = run_operation(
        &harness,
        "op-snapshot",
        Kind::Snapshot(SnapshotNow {
            destination_prefix: "worlds/mc-q".to_string(),
        }),
    )
    .await;
    assert_eq!(
        snapshot.status,
        OperationStatus::Succeeded as i32,
        "{snapshot:?}"
    );

    harness.control.delete_instance("mc-q").await;
    harness.wait_status("mc-q", Phase::Deleted, 1).await;
    let summaries = std::fs::read_dir(data.join("target/quarry-metrics"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert!(
        summaries > 0,
        "the Quarry server did not shut down cleanly (no metrics summary)"
    );
    agent.stop().await.unwrap();
}
