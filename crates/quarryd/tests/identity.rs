use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use proto::v1::agent_gateway_client::AgentGatewayClient;
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::control_message::Body as ControlBody;
use proto::v1::{AgentMessage, Hello};
use quarryd::identity::{NodeIdentity, Transport, now_unix};
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
    assert!(dir.path().join("identity/identity.json").exists());
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
    assert_identity(&transport.identity().unwrap().unwrap(), &rotated);
    assert_identity(
        &read_bundle(&dir.path().join("identity/identity.previous.json")),
        &first,
    );
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

fn issued_identity(pki: &TestPki, node_id: &str, expires_at_unix: u64) -> NodeIdentity
{
    let (certificate_pem, key_pem) = pki.issue_client(node_id).unwrap();
    NodeIdentity {
        certificate_pem,
        key_pem,
        expires_at_unix,
    }
}

fn assert_identity(actual: &NodeIdentity, expected: &NodeIdentity)
{
    assert_eq!(actual.certificate_pem, expected.certificate_pem);
    // Do not print private keys if an assertion fails.
    assert!(actual.key_pem == expected.key_pem);
    assert_eq!(actual.expires_at_unix, expected.expires_at_unix);
}

fn read_bundle(path: &Path) -> NodeIdentity
{
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn generations_round_trip_with_private_permissions()
{
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("new/state/identity");
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 3600);
    let second = issued_identity(&pki, "node-a", now_unix() + 86_400);
    first.save(&identity_dir).unwrap();
    second.save(&identity_dir).unwrap();

    assert_identity(
        &NodeIdentity::load(&identity_dir).unwrap().unwrap(),
        &second,
    );
    assert_identity(
        &read_bundle(&identity_dir.join("identity.previous.json")),
        &first,
    );
    for name in ["identity.json", "identity.previous.json"]
    {
        let mode = fs::metadata(identity_dir.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(fs::read_dir(identity_dir).unwrap().count(), 2);
}

#[test]
fn incomplete_staging_files_are_never_activated()
{
    let dir = tempfile::tempdir().unwrap();
    let staged = dir.path().join(".identity-interrupted.tmp");
    fs::write(&staged, b"{\"key_pem\":").unwrap();
    assert!(NodeIdentity::load(dir.path()).unwrap().is_none());

    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 86_400);
    first.save(dir.path()).unwrap();
    fs::write(&staged, b"unfinished replacement").unwrap();
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);
}

#[test]
fn corrupt_or_missing_current_generation_recovers_previous_pair()
{
    let dir = tempfile::tempdir().unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 3600);
    let second = issued_identity(&pki, "node-a", now_unix() + 86_400);
    first.save(dir.path()).unwrap();
    second.save(dir.path()).unwrap();

    let current = dir.path().join("identity.json");
    fs::write(&current, b"{\"certificate_pem\":").unwrap();
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);

    let mut mismatched = second.clone();
    mismatched.key_pem = first.key_pem.clone();
    fs::write(&current, serde_json::to_vec(&mismatched).unwrap()).unwrap();
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);

    fs::remove_file(&current).unwrap();
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);
    second.save(dir.path()).unwrap();
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &second);
    assert_identity(
        &read_bundle(&dir.path().join("identity.previous.json")),
        &first,
    );
}

#[test]
fn invalid_replacement_cannot_change_existing_credentials()
{
    let dir = tempfile::tempdir().unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 86_400);
    let mut invalid = issued_identity(&pki, "node-a", now_unix() + 86_400);
    first.save(dir.path()).unwrap();
    invalid.key_pem = first.key_pem.clone();

    let error = invalid.save(dir.path()).unwrap_err();
    assert!(!format!("{error:#}").contains(&first.key_pem));
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);
    assert!(!dir.path().join("identity.previous.json").exists());
}

#[test]
fn failed_previous_generation_write_keeps_current_credentials()
{
    let dir = tempfile::tempdir().unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 3600);
    let second = issued_identity(&pki, "node-a", now_unix() + 86_400);
    first.save(dir.path()).unwrap();
    fs::create_dir(dir.path().join("identity.previous.json")).unwrap();

    assert!(second.save(dir.path()).is_err());
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn failed_activation_keeps_recoverable_previous_generation()
{
    let dir = tempfile::tempdir().unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 3600);
    let second = issued_identity(&pki, "node-a", now_unix() + 86_400);
    first.save(dir.path()).unwrap();
    let current = dir.path().join("identity.json");
    let previous = dir.path().join("identity.previous.json");
    fs::rename(&current, &previous).unwrap();
    fs::create_dir(&current).unwrap();

    assert!(second.save(dir.path()).is_err());
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &first);
    assert_identity(&read_bundle(&previous), &first);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn legacy_identity_migrates_without_replacing_legacy_files()
{
    let dir = tempfile::tempdir().unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let legacy = issued_identity(&pki, "node-a", now_unix() + 3600);
    let replacement = issued_identity(&pki, "node-a", now_unix() + 86_400);
    fs::write(dir.path().join("node.crt"), &legacy.certificate_pem).unwrap();
    fs::write(dir.path().join("node.key"), &legacy.key_pem).unwrap();
    fs::write(
        dir.path().join("node.expires"),
        legacy.expires_at_unix.to_string(),
    )
    .unwrap();

    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &legacy);
    replacement.save(dir.path()).unwrap();
    assert_identity(
        &NodeIdentity::load(dir.path()).unwrap().unwrap(),
        &replacement,
    );
    assert_identity(
        &read_bundle(&dir.path().join("identity.previous.json")),
        &legacy,
    );
    assert!(fs::read_to_string(dir.path().join("node.key")).unwrap() == legacy.key_pem);
    assert_eq!(
        fs::read_to_string(dir.path().join("node.crt")).unwrap(),
        legacy.certificate_pem
    );

    fs::write(dir.path().join("identity.json"), b"interrupted generation").unwrap();
    assert_identity(&NodeIdentity::load(dir.path()).unwrap().unwrap(), &legacy);
}

#[test]
fn legacy_identity_requires_a_matching_key_and_missing_expiry_triggers_rotation()
{
    let dir = tempfile::tempdir().unwrap();
    let pki = TestPki::generate(&["localhost"]).unwrap();
    let first = issued_identity(&pki, "node-a", now_unix() + 86_400);
    let other = issued_identity(&pki, "node-a", now_unix() + 86_400);
    fs::write(dir.path().join("node.crt"), &first.certificate_pem).unwrap();
    fs::write(dir.path().join("node.key"), &other.key_pem).unwrap();
    assert!(NodeIdentity::load(dir.path()).is_err());

    fs::write(dir.path().join("node.key"), &first.key_pem).unwrap();
    let loaded = NodeIdentity::load(dir.path()).unwrap().unwrap();
    assert!(loaded.needs_rotation(now_unix()));
    assert!(loaded.key_pem == first.key_pem);
}

#[test]
fn malformed_bundle_errors_do_not_include_private_contents()
{
    let dir = tempfile::tempdir().unwrap();
    let secret = "private-key-material-must-not-be-logged";
    let malformed = serde_json::json!({
        "certificate_pem": "",
        "key_pem": "",
        "expires_at_unix": secret,
    });
    fs::write(
        dir.path().join("identity.json"),
        serde_json::to_vec(&malformed).unwrap(),
    )
    .unwrap();
    let error = NodeIdentity::load(dir.path()).err().unwrap();
    assert!(!format!("{error:#}").contains(secret));
}

#[tokio::test]
async fn failed_rotation_commit_retains_a_working_current_identity()
{
    let control = stub("join-secret").await;
    let dir = tempfile::tempdir().unwrap();
    let transport = Transport::new(
        control.ca_cert_pem(),
        dir.path().to_path_buf(),
        "node-a".into(),
    );
    let mut current = transport
        .enroll(&control.endpoint(), None, "join-secret")
        .await
        .unwrap();
    current.expires_at_unix = now_unix() + 3600;
    current.save(dir.path()).unwrap();
    fs::remove_file(dir.path().join("identity.previous.json")).unwrap();
    fs::create_dir(dir.path().join("identity.previous.json")).unwrap();

    let retained = transport
        .ensure_identity(&control.endpoint(), None)
        .await
        .unwrap();
    assert_identity(&retained, &current);
    assert_identity(&transport.identity().unwrap().unwrap(), &current);
    assert_eq!(control.enrollments().await.len(), 2);
    transport
        .connect(&control.endpoint(), Some(&retained))
        .await
        .unwrap();
}
