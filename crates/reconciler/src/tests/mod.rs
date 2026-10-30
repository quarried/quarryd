pub(crate) mod crash;
mod guest;

mod admission;
mod adoption;
mod backends;
mod channel;
mod flow;
mod leases;
mod recovery;
mod snapshot;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use minisign::KeyPair;
use network::FakeNetwork;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStoreExt, PutPayload};
use proto::v1::{
    ArtifactRef, DiskSpec, InstanceNetwork, InstanceSpec, InstanceStatus, Lease, NetworkConfig,
    Phase, Resources, RestartPolicy, RunState,
};
use sandbox::fake::{FakeConfig, FakeSandbox};
use sha2::{Digest, Sha256};
use store::Store;
use usage::Metrics;
use volume::{FileVolume, ImageCache, SnapshotStore, Volumes};

use crate::{Reconciler, ReconcilerConfig, ReconcilerEvent, ReconcilerHandle, ReconcilerParts};

pub const GIB: u64 = 1024 * 1024 * 1024;
pub const WAIT: Duration = Duration::from_secs(30);

pub struct Fixture
{
    pub dir: tempfile::TempDir,
    pub store: Arc<Store>,
    pub objects: Arc<InMemory>,
    pub snapshot_objects: Arc<InMemory>,
    pub keypair: KeyPair,
    pub rootfs: ArtifactRef,
    pub kernel: ArtifactRef,
    pub volume_capacity: u64,
    pub guest_connect_timeout: Duration,
    pub ready_timeout: Duration,
    pub stop_deadline: Duration,
    pub kill_deadline: Duration,
}

pub struct Node
{
    pub handle: ReconcilerHandle,
    pub events: Arc<Mutex<Vec<InstanceStatus>>>,
    pub network: Arc<FakeNetwork>,
    pub sandbox: Arc<FakeSandbox>,
    pub volumes: Arc<Volumes>,
    pub metrics: Arc<Metrics>,
    collector: tokio::task::JoinHandle<()>,
}

pub fn sign(keypair: &KeyPair, content: &[u8]) -> Vec<u8>
{
    minisign::sign(Some(&keypair.pk), &keypair.sk, content, None, None)
        .unwrap()
        .to_string()
        .into_bytes()
}

pub fn sha256_hex(content: &[u8]) -> String
{
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub async fn publish(
    objects: &InMemory,
    keypair: &KeyPair,
    name: &str,
    content: &[u8],
) -> ArtifactRef
{
    let key = format!("artifacts/{name}");
    let signature_key = format!("artifacts/{name}.minisig");
    objects
        .put(
            &ObjectPath::from(key.as_str()),
            PutPayload::from(content.to_vec()),
        )
        .await
        .unwrap();
    objects
        .put(
            &ObjectPath::from(signature_key.as_str()),
            PutPayload::from(sign(keypair, content)),
        )
        .await
        .unwrap();
    ArtifactRef {
        digest: sha256_hex(content),
        key,
        signature_key,
        size_bytes: content.len() as u64,
    }
}

impl Fixture
{
    pub async fn new() -> Fixture
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("state.db")).unwrap());
        let objects = Arc::new(InMemory::new());
        let keypair = KeyPair::generate_unencrypted_keypair().unwrap();
        let rootfs = publish(&objects, &keypair, "rootfs.squashfs", b"test rootfs image").await;
        let kernel = publish(&objects, &keypair, "vmlinux", b"test kernel image").await;
        std::fs::create_dir_all(dir.path().join("trace")).unwrap();
        Fixture {
            dir,
            store,
            objects,
            snapshot_objects: Arc::new(InMemory::new()),
            keypair,
            rootfs,
            kernel,
            volume_capacity: 1000 * GIB,
            guest_connect_timeout: Duration::from_secs(15),
            ready_timeout: Duration::from_secs(15),
            stop_deadline: Duration::from_secs(3),
            kill_deadline: Duration::from_secs(1),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf
    {
        self.dir.path().join(name)
    }

    pub fn config(&self) -> ReconcilerConfig
    {
        ReconcilerConfig {
            node_id: "node-test".to_owned(),
            capacity: Resources {
                vcpus: 16,
                memory_mib: 32768,
                disk_gib: 1000,
            },
            reservation: Resources {
                vcpus: 2,
                memory_mib: 2048,
                disk_gib: 0,
            },
            default_lease_ttl: Duration::from_secs(60),
            state_dir: self.path("instances"),
            uid_base: 200_000,
            uid_count: 1000,
            console_max_bytes: 1 << 20,
            stop_deadline: self.stop_deadline,
            kill_deadline: self.kill_deadline,
            reconcile_interval: Duration::from_millis(500),
            sample_interval: Duration::from_millis(200),
            restart_backoff_base: Duration::from_millis(100),
            restart_backoff_max: Duration::from_secs(1),
            guest_rate_capacity: 50,
            guest_rate_per_sec: 25.0,
            guest_connect_timeout: self.guest_connect_timeout,
            ready_timeout: self.ready_timeout,
        }
    }

    pub fn sandbox(&self) -> FakeSandbox
    {
        FakeSandbox::new(FakeConfig {
            state_dir: self.path("s"),
            program: std::env::current_exe().unwrap(),
            args: vec![
                "--exact".to_owned(),
                guest::TEST_NAME.to_owned(),
                "--nocapture".to_owned(),
                "--test-threads".to_owned(),
                "1".to_owned(),
            ],
            env: BTreeMap::new(),
            console_writer: None,
        })
    }

    pub async fn start(&self) -> Node
    {
        let sandbox = Arc::new(self.sandbox());
        let network = Arc::new(FakeNetwork::new(Some(self.path("network.json"))).unwrap());
        let volumes = Arc::new(Volumes::new(Arc::new(FileVolume::new(
            self.path("volumes"),
            self.volume_capacity,
        ))));
        let images = Arc::new(
            ImageCache::new(
                self.path("images"),
                self.objects.clone(),
                &self.keypair.pk.to_base64(),
                self.store.clone(),
                10 * GIB,
            )
            .unwrap(),
        );
        let snapshots = Arc::new(SnapshotStore::new(
            self.snapshot_objects.clone(),
            1 << 20,
            4,
        ));
        let metrics = Arc::new(Metrics::new("node-test"));
        let parts = ReconcilerParts {
            store: self.store.clone(),
            sandbox: sandbox.clone(),
            volumes: volumes.clone(),
            network: network.clone(),
            images,
            snapshots: Some(snapshots),
            metrics: metrics.clone(),
        };
        let (handle, mut receiver) = Reconciler::start(self.config(), parts).await.unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let collector = tokio::spawn(async move {
            while let Some(ReconcilerEvent::Status(status)) = receiver.recv().await
            {
                sink.lock().unwrap().push(status);
            }
        });
        Node {
            handle,
            events,
            network,
            sandbox,
            volumes,
            metrics,
            collector,
        }
    }

    pub fn trace_path(&self, id: &str) -> PathBuf
    {
        self.path("trace").join(format!("{id}.log"))
    }

    pub fn trace(&self, id: &str) -> Vec<String>
    {
        std::fs::read_to_string(self.trace_path(id))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    pub fn starts(&self, id: &str) -> usize
    {
        self.trace(id)
            .iter()
            .filter(|line| line.starts_with("start "))
            .count()
    }

    pub fn last_pid(&self, id: &str) -> Option<u32>
    {
        self.trace(id)
            .iter()
            .rev()
            .find_map(|line| line.strip_prefix("start ").and_then(|pid| pid.parse().ok()))
    }

    pub async fn wait_trace(&self, id: &str, needle: &str) -> Vec<String>
    {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop
        {
            let trace = self.trace(id);
            if trace.iter().any(|line| line.starts_with(needle))
            {
                return trace;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "trace of {id} never contained {needle:?}: {trace:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn spec(&self, id: &str, mode: &str) -> InstanceSpec
    {
        let env: HashMap<String, String> = HashMap::from([
            (guest::MODE_ENV.to_owned(), mode.to_owned()),
            (
                guest::TRACE_ENV.to_owned(),
                self.trace_path(id).display().to_string(),
            ),
            (guest::HEALTH_MS_ENV.to_owned(), "200".to_owned()),
        ]);
        InstanceSpec {
            id: id.to_owned(),
            generation: 1,
            isolation: 0,
            image: Some(self.rootfs.clone()),
            kernel: Some(self.kernel.clone()),
            vcpus: 1,
            memory_mib: 512,
            disks: vec![DiskSpec {
                name: "data".to_owned(),
                size_gib: 1,
                restore_from: None,
            }],
            network: Some(InstanceNetwork {
                world_id: "world-1".to_owned(),
                egress_mbit: 100,
                ports: vec![25565],
                ..Default::default()
            }),
            env,
            restart_policy: RestartPolicy::Never as i32,
            lease: Some(Lease {
                epoch: 1,
                ttl_ms: 60_000,
            }),
            run_state: RunState::Running as i32,
            secrets: HashMap::new(),
            stop_deadline_seconds: 0,
            cpu_pinning: false,
            balloon_idle_reclaim: false,
            idle_reclaim_minutes: 0,
        }
    }

    pub fn volume_files(&self) -> Vec<String>
    {
        let mut names: Vec<String> = std::fs::read_dir(self.path("volumes"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.ends_with(".img") && !name.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

pub fn network_config() -> NetworkConfig
{
    NetworkConfig {
        subnet: "10.77.0.0/24".to_owned(),
        region: "test".to_owned(),
        wireguard_listen_port: 0,
        wireguard_address: String::new(),
        peers: Vec::new(),
    }
}

pub fn phase_of(status: &InstanceStatus) -> Phase
{
    Phase::try_from(status.phase).unwrap_or(Phase::Unspecified)
}

impl Node
{
    pub async fn configure(&self)
    {
        self.handle
            .configure_network(network_config())
            .await
            .unwrap();
    }

    pub fn status(&self, id: &str) -> Option<InstanceStatus>
    {
        self.handle
            .statuses()
            .into_iter()
            .find(|status| status.id == id)
    }

    pub async fn wait_for(
        &self,
        id: &str,
        what: &str,
        predicate: impl Fn(&InstanceStatus) -> bool,
    ) -> InstanceStatus
    {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop
        {
            if let Some(status) = self.status(id)
                && predicate(&status)
            {
                return status;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} never reached {what}; status {:?}; history {:?}",
                self.status(id),
                self.history(id)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn wait_phase(&self, id: &str, phase: Phase) -> InstanceStatus
    {
        self.wait_for(id, phase.as_str_name(), |status| phase_of(status) == phase)
            .await
    }

    pub async fn wait_running(&self, id: &str, generation: u64) -> InstanceStatus
    {
        self.wait_for(id, "RUNNING", |status| {
            phase_of(status) == Phase::Running && status.observed_generation == generation
        })
        .await
    }

    pub async fn wait_event(&self, id: &str, phase: Phase) -> InstanceStatus
    {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop
        {
            if let Some(status) = self
                .events
                .lock()
                .unwrap()
                .iter()
                .find(|status| status.id == id && phase_of(status) == phase)
            {
                return status.clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} never emitted {phase:?}; history {:?}",
                self.history(id)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn history(&self, id: &str) -> Vec<(Phase, u64, String)>
    {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|status| status.id == id)
            .map(|status| {
                (
                    phase_of(status),
                    status.observed_generation,
                    status.reason.clone(),
                )
            })
            .collect()
    }

    pub fn phases(&self, id: &str) -> Vec<Phase>
    {
        let mut phases: Vec<Phase> = Vec::new();
        for (phase, _, _) in self.history(id)
        {
            if phases.last() != Some(&phase)
            {
                phases.push(phase);
            }
        }
        phases
    }

    pub fn event_count(&self, id: &str) -> usize
    {
        self.history(id).len()
    }

    pub fn health_reports(&self, id: &str) -> u64
    {
        crate::reconciler::lock(&self.handle.inner().observed)
            .instances
            .get(id)
            .map(|view| view.guest.health_reports)
            .unwrap_or(0)
    }

    pub fn guest_ready(&self, id: &str) -> bool
    {
        crate::reconciler::lock(&self.handle.inner().observed)
            .instances
            .get(id)
            .is_some_and(|view| view.guest.ready)
    }

    pub fn dropped_connections(&self, id: &str) -> u64
    {
        crate::reconciler::lock(&self.handle.inner().observed)
            .instances
            .get(id)
            .map(|view| view.abuse.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn attach_calls(&self, id: &str) -> usize
    {
        self.network
            .calls()
            .iter()
            .filter(
                |call| matches!(call, network::FakeCall::Attach(spec) if spec.instance_id == id),
            )
            .count()
    }

    pub async fn wait_gone(&self, id: &str, store: &Store)
    {
        let deadline = tokio::time::Instant::now() + WAIT;
        while self.status(id).is_some() || store.get_instance(id).unwrap().is_some()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} was never removed; history {:?}",
                self.history(id)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn stop(self)
    {
        self.handle.shutdown().await;
        let _ = self.collector.await;
    }
}

pub async fn sleep_ms(ms: u64)
{
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[cfg(target_os = "linux")]
pub fn process_alive(pid: u32) -> bool
{
    // Killed guests may linger as zombies until their new parent reaps them.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .map(|(_, rest)| !rest.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
pub fn process_alive(pid: u32) -> bool
{
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn kill_process(pid: u32)
{
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();
}
