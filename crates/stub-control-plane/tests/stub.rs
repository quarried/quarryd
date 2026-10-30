use proto::v1::agent_gateway_client::AgentGatewayClient;
use proto::v1::{
    AgentMessage, ControlMessage, EnrollRequest, Heartbeat, Hello, InstanceSpec, InstanceStatus,
    LeaseHeld, LeaseRenewal, LogChunk, NetworkConfig, Phase, RunOperation, agent_message,
    control_message, run_operation,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use std::time::Duration;
use stub_control_plane::{StubConfig, StubControlPlane, TestPki};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::{Code, Streaming};

const TOKEN: &str = "join-secret";
const TTL_MS: u64 = 45_000;
const STEP: Duration = Duration::from_secs(5);

async fn start_stub(auto_grant_leases: bool) -> StubControlPlane
{
    let pki = TestPki::generate(&["localhost", "127.0.0.1"]).unwrap();
    StubControlPlane::start(StubConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        pki,
        join_token: TOKEN.to_owned(),
        lease_ttl_ms: TTL_MS,
        auto_grant_leases,
    })
    .await
    .unwrap()
}

async fn client_with(
    stub: &StubControlPlane,
    identity: Option<(String, String)>,
) -> AgentGatewayClient<Channel>
{
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(stub.ca_cert_pem()))
        .domain_name("localhost");
    if let Some((cert, key)) = identity
    {
        tls = tls.identity(Identity::from_pem(cert, key));
    }
    let channel = Channel::from_shared(stub.endpoint())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    AgentGatewayClient::new(channel)
}

async fn client(stub: &StubControlPlane, node_id: &str) -> AgentGatewayClient<Channel>
{
    client_with(stub, Some(stub.pki().issue_client(node_id).unwrap())).await
}

fn hello(ack: u64) -> AgentMessage
{
    AgentMessage {
        seq: 0,
        ack,
        body: Some(agent_message::Body::Hello(Hello {
            node_id: "node-1".to_owned(),
            agent_version: "test".to_owned(),
            capabilities: None,
            inventory: None,
        })),
    }
}

fn heartbeat(seq: u64) -> AgentMessage
{
    AgentMessage {
        seq,
        ack: 0,
        body: Some(agent_message::Body::Heartbeat(Heartbeat::default())),
    }
}

fn spec(id: &str) -> InstanceSpec
{
    InstanceSpec {
        id: id.to_owned(),
        generation: 1,
        memory_mib: 2048,
        vcpus: 2,
        ..Default::default()
    }
}

fn console_op(op_id: &str) -> RunOperation
{
    RunOperation {
        op_id: op_id.to_owned(),
        instance_id: "a".to_owned(),
        kind: Some(run_operation::Kind::Console(
            proto::v1::SendConsoleCommand {
                command: "list".to_owned(),
            },
        )),
    }
}

struct AgentStream
{
    outbound: mpsc::Sender<AgentMessage>,
    inbound: Streaming<ControlMessage>,
}

impl AgentStream
{
    async fn open(client: &mut AgentGatewayClient<Channel>, hello_ack: u64) -> AgentStream
    {
        let (outbound, receiver) = mpsc::channel(64);
        outbound.send(hello(hello_ack)).await.unwrap();
        let inbound = client
            .connect(ReceiverStream::new(receiver))
            .await
            .unwrap()
            .into_inner();
        AgentStream { outbound, inbound }
    }

    async fn send(&self, message: AgentMessage)
    {
        self.outbound.send(message).await.unwrap();
    }

    async fn next(&mut self) -> ControlMessage
    {
        tokio::time::timeout(STEP, self.inbound.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    async fn next_numbered(&mut self) -> ControlMessage
    {
        loop
        {
            let message = self.next().await;
            if message.seq != 0
            {
                return message;
            }
        }
    }

    async fn expect_end(&mut self, code: Code)
    {
        let status = tokio::time::timeout(STEP, self.inbound.message())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(status.code(), code);
    }

    async fn expect_silence(&mut self)
    {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), self.inbound.message())
                .await
                .is_err()
        );
    }
}

fn desired(message: &ControlMessage) -> &proto::v1::DesiredState
{
    match &message.body
    {
        Some(control_message::Body::Desired(desired)) => desired,
        other => panic!("expected DesiredState, got {other:?}"),
    }
}

#[tokio::test]
async fn connect_requires_client_certificate()
{
    let stub = start_stub(false).await;
    let mut anonymous = client_with(&stub, None).await;
    let (_outbound, receiver) = mpsc::channel(1);
    let status = anonymous
        .connect(ReceiverStream::new(receiver))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(stub.connection_count().await, 0);
}

#[tokio::test]
async fn connect_sends_full_desired_state_first()
{
    let stub = start_stub(false).await;
    let network = NetworkConfig {
        subnet: "10.20.0.0/24".to_owned(),
        ..Default::default()
    };
    stub.set_desired(vec![spec("a"), spec("b")], Some(network.clone()))
        .await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;

    let first = stream.next().await;
    assert_eq!(first.seq, 1);
    let state = desired(&first);
    assert_eq!(
        state
            .instances
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert_eq!(state.network, Some(network));
    assert_eq!(stub.connection_count().await, 1);
    let recorded = stub
        .wait_for(STEP, |m| {
            matches!(m.body, Some(agent_message::Body::Hello(_)))
        })
        .await;
    assert!(recorded.is_some());
}

#[tokio::test]
async fn reconnect_replays_unacked_with_original_seqs_then_desired_state()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    assert_eq!(stream.next().await.seq, 1);

    assert_eq!(stub.put_instance(spec("a")).await, 2);
    assert_eq!(stub.run_operation(console_op("op-1")).await, 3);
    assert_eq!(stub.delete_instance("missing").await, 4);
    assert_eq!(stream.next().await.seq, 2);
    assert_eq!(stream.next().await.seq, 3);
    assert_eq!(stream.next().await.seq, 4);

    stub.disconnect().await;
    stream.expect_end(Code::Unavailable).await;

    let mut stream = AgentStream::open(&mut client, 2).await;
    let replayed_op = stream.next().await;
    assert_eq!(replayed_op.seq, 3);
    assert!(matches!(&replayed_op.body, Some(control_message::Body::Op(op)) if op.op_id == "op-1"));
    let replayed_delete = stream.next().await;
    assert_eq!(replayed_delete.seq, 4);
    assert!(
        matches!(&replayed_delete.body, Some(control_message::Body::Delete(d)) if d.id == "missing")
    );
    let resync = stream.next().await;
    assert_eq!(resync.seq, 5);
    assert_eq!(
        desired(&resync)
            .instances
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        ["a"]
    );
    assert_eq!(stub.connection_count().await, 2);
    assert_eq!(stub.last_agent_ack().await, 2);
}

#[tokio::test]
async fn messages_queued_while_disconnected_are_delivered_on_connect()
{
    let stub = start_stub(false).await;
    assert_eq!(stub.put_instance(spec("a")).await, 1);
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    let put = stream.next().await;
    assert_eq!(put.seq, 1);
    assert!(
        matches!(&put.body, Some(control_message::Body::Put(p)) if p.spec.as_ref().is_some_and(|s| s.id == "a"))
    );
    assert_eq!(stream.next().await.seq, 2);
}

#[tokio::test]
async fn agent_ack_ahead_of_stub_gets_only_desired_state_with_a_higher_seq()
{
    let stub = start_stub(false).await;
    stub.put_instance(spec("a")).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 40).await;
    let resync = stream.next().await;
    assert_eq!(resync.seq, 41);
    assert_eq!(desired(&resync).instances.len(), 1);
    stream.expect_silence().await;
    assert_eq!(stub.put_instance(spec("b")).await, 42);
    assert_eq!(stub.last_agent_ack().await, 40);
}

#[tokio::test]
async fn numbered_agent_messages_are_acked_and_deduplicated()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    assert_eq!(stream.next().await.seq, 1);

    stream.send(heartbeat(1)).await;
    assert_eq!(
        stream.next().await,
        ControlMessage {
            seq: 0,
            ack: 1,
            body: None
        }
    );

    stream.send(heartbeat(1)).await;
    assert_eq!(
        stream.next().await,
        ControlMessage {
            seq: 0,
            ack: 1,
            body: None
        }
    );

    let status = AgentMessage {
        seq: 2,
        ack: 1,
        body: Some(agent_message::Body::Status(InstanceStatus {
            id: "a".to_owned(),
            phase: Phase::Running as i32,
            ..Default::default()
        })),
    };
    stream.send(status.clone()).await;
    assert_eq!(
        stream.next().await,
        ControlMessage {
            seq: 0,
            ack: 2,
            body: None
        }
    );

    stream
        .send(AgentMessage {
            seq: 0,
            ack: 1,
            body: None,
        })
        .await;
    stub.wait_for(STEP, |m| m.seq == 0 && m.body.is_none())
        .await
        .unwrap();
    stream.expect_silence().await;

    let put_seq = stub.put_instance(spec("a")).await;
    let put = stream.next().await;
    assert_eq!((put.seq, put.ack), (put_seq, 2));

    let received = stub.received().await;
    assert_eq!(received.len(), 5);
    assert_eq!(received.iter().filter(|m| m.seq == 1).count(), 2);
    let processed = stub.processed().await;
    assert_eq!(processed.iter().map(|m| m.seq).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(processed[1], status);
    assert_eq!(stub.last_agent_ack().await, 1);
}

#[tokio::test]
async fn processed_watermark_survives_reconnect()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    stream.next().await;
    stream.send(heartbeat(1)).await;
    stream.send(heartbeat(2)).await;
    stub.wait_for(STEP, |m| m.seq == 2).await.unwrap();
    stub.disconnect().await;

    let mut stream = AgentStream::open(&mut client, 1).await;
    let resync = stream.next().await;
    assert!(matches!(
        resync.body,
        Some(control_message::Body::Desired(_))
    ));
    assert_eq!(resync.ack, 2);
    stream.send(heartbeat(2)).await;
    stream.send(heartbeat(3)).await;
    stub.wait_for(STEP, |m| m.seq == 3).await.unwrap();
    assert_eq!(
        stub.processed()
            .await
            .iter()
            .map(|m| m.seq)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[tokio::test]
async fn lease_renewals_are_granted_automatically()
{
    let stub = start_stub(true).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    stream.next().await;

    let renewal = |seq| AgentMessage {
        seq,
        ack: 1,
        body: Some(agent_message::Body::Lease(LeaseRenewal {
            leases: vec![
                LeaseHeld {
                    instance_id: "a".to_owned(),
                    epoch: 3,
                    remaining_ms: 1000,
                },
                LeaseHeld {
                    instance_id: "b".to_owned(),
                    epoch: 9,
                    remaining_ms: 2000,
                },
            ],
        })),
    };
    stream.send(renewal(1)).await;
    let mut grants = Vec::new();
    while grants.len() < 2
    {
        if let Some(control_message::Body::Lease(grant)) = stream.next_numbered().await.body
        {
            grants.push(grant);
        }
    }
    assert_eq!(
        (
            grants[0].instance_id.as_str(),
            grants[0].epoch,
            grants[0].ttl_ms
        ),
        ("a", 3, TTL_MS)
    );
    assert_eq!(
        (
            grants[1].instance_id.as_str(),
            grants[1].epoch,
            grants[1].ttl_ms
        ),
        ("b", 9, TTL_MS)
    );

    stream.send(renewal(1)).await;
    let marker = stub.put_instance(spec("marker")).await;
    assert_eq!(stream.next_numbered().await.seq, marker);

    stub.set_auto_grant_leases(false).await;
    stream.send(renewal(2)).await;
    let marker = stub.put_instance(spec("marker-2")).await;
    assert_eq!(stream.next_numbered().await.seq, marker);
}

#[tokio::test]
async fn explicit_sends_carry_their_bodies()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    stream.next().await;

    stub.grant_lease(proto::v1::LeaseGrant {
        instance_id: "a".to_owned(),
        epoch: 2,
        ttl_ms: 10,
    })
    .await;
    assert!(
        matches!(stream.next().await.body, Some(control_message::Body::Lease(g)) if g.epoch == 2)
    );
    let network = NetworkConfig {
        region: "eu".to_owned(),
        ..Default::default()
    };
    stub.send_network_config(network.clone()).await;
    assert!(
        matches!(stream.next().await.body, Some(control_message::Body::Network(n)) if n == network)
    );
    stub.send_agent_update(proto::v1::AgentUpdate {
        version: "2.0.0".to_owned(),
        ..Default::default()
    })
    .await;
    assert!(
        matches!(stream.next().await.body, Some(control_message::Body::Update(u)) if u.version == "2.0.0")
    );
    let seq = stub.send_desired().await;
    let resync = stream.next().await;
    assert_eq!(resync.seq, seq);
    assert_eq!(desired(&resync).network, Some(network));
}

#[tokio::test]
async fn resend_repeats_a_message_with_its_original_seq()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    stream.next().await;
    let seq = stub.run_operation(console_op("op-7")).await;
    let original = stream.next().await;
    stream.send(heartbeat(1)).await;
    assert_eq!(stream.next().await.seq, 0);

    assert!(stub.resend(seq).await);
    let repeated = stream.next().await;
    assert_eq!(repeated.seq, original.seq);
    assert_eq!(repeated.body, original.body);
    assert_eq!(repeated.ack, 1);

    assert!(!stub.resend(999).await);
    stub.disconnect().await;
    assert!(!stub.resend(seq).await);
}

#[tokio::test]
async fn outage_ends_streams_and_rejects_new_calls()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    stream.next().await;

    stub.set_available(false).await;
    stream.expect_end(Code::Unavailable).await;
    let (_outbound, receiver) = mpsc::channel(1);
    let status = client
        .connect(ReceiverStream::new(receiver))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
    let queued = stub.put_instance(spec("during-outage")).await;

    stub.set_available(true).await;
    let mut stream = AgentStream::open(&mut client, 1).await;
    assert_eq!(stream.next().await.seq, queued);
    assert!(matches!(
        stream.next().await.body,
        Some(control_message::Body::Desired(_))
    ));
    assert_eq!(stub.connection_count().await, 2);
}

#[tokio::test]
async fn newer_connection_supersedes_older()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut first = AgentStream::open(&mut client, 0).await;
    first.next().await;
    let mut second = AgentStream::open(&mut client, 1).await;
    assert!(matches!(
        second.next().await.body,
        Some(control_message::Body::Desired(_))
    ));
    first.expect_end(Code::Unavailable).await;
    let seq = stub.put_instance(spec("a")).await;
    assert_eq!(second.next().await.seq, seq);
}

#[tokio::test]
async fn first_message_must_be_hello()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let (outbound, receiver) = mpsc::channel(1);
    outbound.send(heartbeat(1)).await.unwrap();
    let mut inbound = client
        .connect(ReceiverStream::new(receiver))
        .await
        .unwrap()
        .into_inner();
    let status = tokio::time::timeout(STEP, inbound.message())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(stub.connection_count().await, 0);
}

#[tokio::test]
async fn wait_for_sees_past_and_future_messages_and_times_out()
{
    let stub = start_stub(false).await;
    let mut client = client(&stub, "node-1").await;
    let mut stream = AgentStream::open(&mut client, 0).await;
    stream.next().await;
    stream.send(heartbeat(1)).await;
    assert_eq!(
        stub.wait_for(STEP, |m| m.seq == 1).await.map(|m| m.seq),
        Some(1)
    );
    assert_eq!(
        stub.wait_for(STEP, |m| m.seq == 1).await.map(|m| m.seq),
        Some(1)
    );

    let waiter = {
        let stub = stub.clone();
        tokio::spawn(async move { stub.wait_for(STEP, |m| m.seq == 2).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    stream.send(heartbeat(2)).await;
    assert_eq!(waiter.await.unwrap().map(|m| m.seq), Some(2));

    assert!(
        stub.wait_for(Duration::from_millis(100), |m| m.seq == 99)
            .await
            .is_none()
    );
}

fn csr_for(common_name: &str) -> (String, KeyPair)
{
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    let csr = params.serialize_request(&key).unwrap();
    (csr.pem().unwrap(), key)
}

fn enroll_request(node_id: &str, join_token: &str, csr_pem: String) -> EnrollRequest
{
    EnrollRequest {
        node_id: node_id.to_owned(),
        join_token: join_token.to_owned(),
        csr_pem,
    }
}

#[tokio::test]
async fn enroll_with_join_token_issues_a_usable_24h_certificate()
{
    let stub = start_stub(false).await;
    let mut anonymous = client_with(&stub, None).await;
    let (csr, key) = csr_for("node-7");
    let response = anonymous
        .enroll(enroll_request("node-7", TOKEN, csr))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.ca_pem, stub.ca_cert_pem());

    let (_, pem) = x509_parser::pem::parse_x509_pem(response.certificate_pem.as_bytes()).unwrap();
    let certificate = pem.parse_x509().unwrap();
    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(common_name, "node-7");
    let validity = certificate.validity();
    assert_eq!(
        validity.not_after.timestamp() - validity.not_before.timestamp(),
        24 * 60 * 60
    );
    assert_eq!(
        validity.not_after.timestamp() as u64,
        response.expires_at_unix
    );

    let mut enrolled =
        client_with(&stub, Some((response.certificate_pem, key.serialize_pem()))).await;
    let mut stream = AgentStream::open(&mut enrolled, 0).await;
    assert!(matches!(
        stream.next().await.body,
        Some(control_message::Body::Desired(_))
    ));

    let (csr, _) = csr_for("node-7");
    assert!(
        anonymous
            .enroll(enroll_request("node-7", TOKEN, csr))
            .await
            .is_ok()
    );
    assert_eq!(stub.enrollments().await.len(), 2);
}

#[tokio::test]
async fn enroll_rejects_bad_requests()
{
    let stub = start_stub(false).await;
    let mut anonymous = client_with(&stub, None).await;

    let (csr, _) = csr_for("node-1");
    let status = anonymous
        .enroll(enroll_request("node-1", "wrong", csr))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);

    let (csr, _) = csr_for("node-1");
    let status = anonymous
        .enroll(enroll_request("node-1", "", csr))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);

    let status = anonymous
        .enroll(enroll_request("node-1", TOKEN, "not a csr".to_owned()))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);

    let (csr, _) = csr_for("someone-else");
    let status = anonymous
        .enroll(enroll_request("node-1", TOKEN, csr))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);

    let (csr, _) = csr_for("node-1");
    anonymous
        .enroll(enroll_request("node-1", TOKEN, csr))
        .await
        .unwrap();
    let (csr, _) = csr_for("node-2");
    let status = anonymous
        .enroll(enroll_request("node-2", TOKEN, csr))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);

    assert_eq!(stub.enrollments().await.len(), 6);
}

#[tokio::test]
async fn enroll_without_token_rotates_with_a_valid_client_certificate()
{
    let stub = start_stub(false).await;
    let mut node = client(&stub, "node-1").await;
    let (csr, _) = csr_for("node-1");
    let response = node
        .enroll(enroll_request("node-1", "", csr))
        .await
        .unwrap()
        .into_inner();
    assert!(
        response
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );

    let (csr, _) = csr_for("node-2");
    let status = node
        .enroll(enroll_request("node-2", "", csr))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn enroll_rejected_during_outage()
{
    let stub = start_stub(false).await;
    stub.set_available(false).await;
    let mut anonymous = client_with(&stub, None).await;
    let (csr, _) = csr_for("node-1");
    let status = anonymous
        .enroll(enroll_request("node-1", TOKEN, csr))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
}

#[tokio::test]
async fn stream_logs_records_chunks_and_counts_bytes()
{
    let stub = start_stub(false).await;
    let mut node = client(&stub, "node-1").await;
    let chunks = vec![
        LogChunk {
            op_id: "op-1".to_owned(),
            instance_id: "a".to_owned(),
            data: b"hello ".to_vec(),
            eof: false,
        },
        LogChunk {
            op_id: "op-1".to_owned(),
            instance_id: "a".to_owned(),
            data: b"world\n".to_vec(),
            eof: true,
        },
    ];
    let summary = node
        .stream_logs(tokio_stream::iter(chunks.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(summary.bytes_received, 12);
    assert_eq!(stub.log_chunks().await, chunks);

    let mut anonymous = client_with(&stub, None).await;
    let status = anonymous
        .stream_logs(tokio_stream::iter(chunks))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);
}

#[test]
fn issued_client_certificates_carry_the_node_id()
{
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let (cert, key) = pki.issue_client("node-42").unwrap();
    assert!(key.contains("PRIVATE KEY"));
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert.as_bytes()).unwrap();
    let certificate = pem.parse_x509().unwrap();
    assert_eq!(
        certificate
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        "node-42"
    );
    assert_eq!(
        certificate
            .issuer()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        "quarry stub CA"
    );
}

#[test]
fn pki_round_trips_through_a_directory()
{
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    assert!(!TestPki::exists_in(dir.path()));
    pki.write_to(dir.path()).unwrap();
    assert!(TestPki::exists_in(dir.path()));
    let loaded = TestPki::read_from(dir.path()).unwrap();
    assert_eq!(loaded.ca_cert_pem, pki.ca_cert_pem);
    assert_eq!(loaded.ca_key_pem, pki.ca_key_pem);
    assert_eq!(loaded.server_cert_pem, pki.server_cert_pem);
    assert_eq!(loaded.server_key_pem, pki.server_key_pem);
}
