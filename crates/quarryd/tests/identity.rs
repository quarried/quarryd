use std::time::Duration;

use proto::v1::agent_gateway_client::AgentGatewayClient;
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::control_message::Body as ControlBody;
use proto::v1::{AgentMessage, Hello};
use quarryd::identity::Transport;
use stub_control_plane::{StubConfig, StubControlPlane, TestPki};
use tokio_stream::wrappers::ReceiverStream;

async fn stub(join_token: &str) -> StubControlPlane
{
    let pki = TestPki::generate(&["localhost", "127.0.0.1"]).unwrap();
    StubControlPlane::start(StubConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        pki,
        join_token: join_token.to_string(),
        lease_ttl_ms: 60_000,
        auto_grant_leases: true,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn enrolls_with_join_token_then_connects_over_mtls()
{
    let control = stub("join-secret").await;
    let dir = tempfile::tempdir().unwrap();
    let transport = Transport::new(
        control.ca_cert_pem(),
        dir.path().join("identity"),
        "node-a".to_string(),
    );
    let identity = transport
        .ensure_identity(&control.endpoint(), Some("join-secret"))
        .await
        .unwrap();
    assert!(identity.expires_at_unix > quarryd::identity::now_unix());
    assert!(dir.path().join("identity/node.crt").exists());
    assert_eq!(control.enrollments().await.len(), 1);

    let reloaded = transport
        .ensure_identity(&control.endpoint(), None)
        .await
        .unwrap();
    assert_eq!(reloaded.certificate_pem, identity.certificate_pem);
    assert_eq!(control.enrollments().await.len(), 1);

    let channel = transport
        .connect(&control.endpoint(), Some(&identity))
        .await
        .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    sender
        .send(AgentMessage {
            seq: 0,
            ack: 0,
            body: Some(AgentBody::Hello(Hello {
                node_id: "node-a".to_string(),
                ..Default::default()
            })),
        })
        .await
        .unwrap();
    let mut client = AgentGatewayClient::new(channel);
    let mut inbound = client
        .connect(ReceiverStream::new(receiver))
        .await
        .unwrap()
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(5), inbound.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(first.body, Some(ControlBody::Desired(_))));
}

#[tokio::test]
async fn rotation_reenrolls_with_current_certificate()
{
    let control = stub("join-secret").await;
    let dir = tempfile::tempdir().unwrap();
    let transport = Transport::new(
        control.ca_cert_pem(),
        dir.path().join("identity"),
        "node-b".to_string(),
    );
    let first = transport
        .enroll(&control.endpoint(), None, "join-secret")
        .await
        .unwrap();
    let rotated = transport
        .enroll(&control.endpoint(), Some(&first), "")
        .await
        .unwrap();
    assert_ne!(rotated.certificate_pem, first.certificate_pem);
    assert_ne!(rotated.key_pem, first.key_pem);
}

#[tokio::test]
async fn refuses_wrong_join_token()
{
    let control = stub("join-secret").await;
    let dir = tempfile::tempdir().unwrap();
    let transport = Transport::new(
        control.ca_cert_pem(),
        dir.path().join("identity"),
        "node-c".to_string(),
    );
    assert!(
        transport
            .ensure_identity(&control.endpoint(), Some("wrong"))
            .await
            .is_err()
    );
    assert!(transport.identity().unwrap().is_none());
}
