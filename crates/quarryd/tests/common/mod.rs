#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use minisign::KeyPair;
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::{
    AgentMessage, ArtifactRef, DiskSpec, InstanceNetwork, InstanceSpec, Lease, NetworkConfig,
    Phase, RestartPolicy, RunState,
};
use quarryd::agent::Agent;
use quarryd::config::Config;
use sha2::{Digest, Sha256};
use stub_control_plane::{StubConfig, StubControlPlane, TestPki};
use tempfile::TempDir;

pub const GUEST_ENTRY: &str = "guest_entry";

pub const FAKE_SERVER: &str = r#"echo "Starting minecraft server version 1.21.1"; echo "Done (0.1s)! For help, type \"help\""; while read line; do echo "$line" >> "$QUARRY_TEST_COMMAND_LOG"; case "$line" in stop) echo "Saving worlds"; exit 0;; list) echo "There are 0 of a max of 20 players online: ";; tps) echo "TPS from last 1m, 5m, 15m: 20.0, 20.0, 20.0";; *) echo "$line";; esac; done"#;

pub fn run_guest_if_requested()
{
    if std::env::var(guest_proto::TRANSPORT_ENV).is_err()
    {
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let code = runtime.block_on(guest_agent::run());
    std::process::exit(code);
}

pub struct Harness
{
    pub dir: TempDir,
    pub control: StubControlPlane,
    keypair: KeyPair,
    pub rootfs: ArtifactRef,
    lease_ttl_secs: u64,
}

fn hex(bytes: &[u8]) -> String
{
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Harness
{
    pub async fn new() -> Harness
    {
        Harness::with_lease_ttl(60, 60_000).await
    }

    pub async fn with_lease_ttl(agent_ttl_secs: u64, grant_ttl_ms: u64) -> Harness
    {
        let dir = tempfile::tempdir().unwrap();
        let pki = TestPki::generate(&["localhost", "127.0.0.1"]).unwrap();
        let control = StubControlPlane::start(StubConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            pki,
            join_token: "join-token".to_string(),
            lease_ttl_ms: grant_ttl_ms,
            auto_grant_leases: true,
        })
        .await
        .unwrap();
        control
            .set_desired(
                Vec::new(),
                Some(NetworkConfig {
                    subnet: "10.77.0.0/24".to_string(),
                    region: "test".to_string(),
                    ..Default::default()
                }),
            )
            .await;
        let keypair = KeyPair::generate_unencrypted_keypair().unwrap();
        let mut harness = Harness {
            dir,
            control,
            keypair,
            rootfs: ArtifactRef::default(),
            lease_ttl_secs: agent_ttl_secs,
        };
        harness.rootfs = harness.publish("images/rootfs.squashfs", &vec![7u8; 64 * 1024]);
        std::fs::write(harness.path("ca.pem"), harness.control.ca_cert_pem()).unwrap();
        std::fs::write(harness.path("join-token"), "join-token").unwrap();
        harness
    }

    pub fn path(&self, name: &str) -> PathBuf
    {
        self.dir.path().join(name)
    }

    pub fn publish(&self, key: &str, content: &[u8]) -> ArtifactRef
    {
        let artifacts = self.path("artifacts");
        let object = artifacts.join(key);
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        std::fs::write(&object, content).unwrap();
        let signature = minisign::sign(
            Some(&self.keypair.pk),
            &self.keypair.sk,
            content,
            None,
            None,
        )
        .unwrap()
        .to_string();
        let signature_key = format!("{key}.minisig");
        std::fs::write(artifacts.join(&signature_key), signature).unwrap();
        ArtifactRef {
            digest: hex(&Sha256::digest(content)),
            key: key.to_string(),
            signature_key,
            size_bytes: content.len() as u64,
        }
    }

    pub fn config(&self) -> Config
    {
        let guest_program = std::env::current_exe().unwrap();
        let text = format!(
            r#"
node_id = "node-test"
state_dir = "{state}"
endpoints = ["{endpoint}"]
ca_cert = "{ca}"
join_token_file = "{token}"
metrics_addr = "127.0.0.1:0"
lease_ttl_secs = {ttl}

[capacity]
vcpus = 8
memory_mib = 16384
disk_gib = 100

[reservation]
vcpus = 1
memory_mib = 1024
disk_gib = 0

[sandbox]
backend = "fake"
fake_program = "{guest}"
fake_args = ["--exact", "{entry}", "--nocapture", "--test-threads=1"]

[volume]
backend = "file"
file_capacity_gib = 100

[network]
backend = "fake"

[artifacts]
bucket = "artifacts"
local_dir = "{artifacts}"
public_key = "{public_key}"

[snapshots]
bucket = "snapshots"
local_dir = "{snapshots}"

[update]
binary_path = "{binary}"

[instances]
stop_deadline_secs = 5
kill_deadline_secs = 2
restart_backoff_base_ms = 200
restart_backoff_max_secs = 2
guest_connect_timeout_secs = 20
ready_timeout_secs = 20
"#,
            state = self.path("state").display(),
            endpoint = self.control.endpoint(),
            ca = self.path("ca.pem").display(),
            token = self.path("join-token").display(),
            ttl = self.lease_ttl_secs,
            guest = guest_program.display(),
            entry = GUEST_ENTRY,
            artifacts = self.path("artifacts").display(),
            public_key = self.keypair.pk.to_base64(),
            snapshots = self.path("snapshots").display(),
            binary = self.path("bin/quarryd").display(),
        );
        Config::parse(&text).unwrap()
    }

    pub async fn start_agent(&self) -> Agent
    {
        Agent::start(self.config()).await.unwrap()
    }

    pub fn spec(&self, id: &str, generation: u64) -> InstanceSpec
    {
        let mut env = std::collections::HashMap::new();
        env.insert("QUARRY_SERVER_COMMAND".to_string(), FAKE_SERVER.to_string());
        env.insert(
            "QUARRY_TEST_COMMAND_LOG".to_string(),
            self.command_log(id).display().to_string(),
        );
        InstanceSpec {
            id: id.to_string(),
            generation,
            image: Some(self.rootfs.clone()),
            vcpus: 1,
            memory_mib: 1024,
            disks: vec![DiskSpec {
                name: "data".to_string(),
                size_gib: 1,
                restore_from: None,
            }],
            network: Some(InstanceNetwork {
                world_id: "world-1".to_string(),
                egress_mbit: 100,
                ports: vec![25565],
            }),
            env,
            restart_policy: RestartPolicy::Always as i32,
            lease: Some(Lease {
                epoch: 1,
                ttl_ms: 0,
            }),
            run_state: RunState::Running as i32,
            stop_deadline_seconds: 5,
            ..Default::default()
        }
    }

    pub async fn wait_status(&self, id: &str, phase: Phase, generation: u64) -> AgentMessage
    {
        let id = id.to_string();
        self.control
            .wait_for(Duration::from_secs(60), move |message| {
                match &message.body
                {
                    Some(AgentBody::Status(status)) =>
                    {
                        status.id == id
                            && status.phase == phase as i32
                            && status.observed_generation == generation
                    }
                    _ => false,
                }
            })
            .await
            .unwrap_or_else(|| {
                panic!("instance never reached {phase:?} at generation {generation}")
            })
    }

    pub fn command_log(&self, id: &str) -> PathBuf
    {
        self.path(&format!("commands-{id}.log"))
    }

    pub fn fake_sandbox_pid(&self, id: &str) -> Option<u32>
    {
        let store = store::Store::open_read_only(&self.path("state/quarryd.db")).ok()?;
        store.get_instance(id).ok()??.pid
    }
}

pub fn phases_for(messages: &[AgentMessage], id: &str) -> Vec<i32>
{
    messages
        .iter()
        .filter_map(|message| match &message.body
        {
            Some(AgentBody::Status(status)) if status.id == id => Some(status.phase),
            _ => None,
        })
        .collect()
}

pub fn process_alive(pid: u32) -> bool
{
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/stat"))
        {
            Ok(stat) => stat
                .rsplit_once(')')
                .map(|(_, rest)| !rest.trim_start().starts_with('Z'))
                .unwrap_or(false),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}
