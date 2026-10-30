use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use network::Network;
use object_store::ObjectStore;
use proto::v1::{Capabilities, Isolation, Resources};
use reconciler::{Reconciler, ReconcilerConfig, ReconcilerHandle, ReconcilerParts};
use sandbox::{Sandbox, SandboxKind};
use store::Store;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use usage::Metrics;
use volume::{FileVolume, ImageCache, LvmThin, SnapshotStore, Volume, Volumes};

use crate::channel::{ChannelSettings, ControlChannel};
use crate::config::{BucketConfig, Config, NetworkBackend, SandboxBackend, VolumeBackend};
use crate::identity::Transport;
use crate::ops::Operations;
use crate::update::{UpdatePaths, Updater};

const GIB: u64 = 1024 * 1024 * 1024;
const SNAPSHOT_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
const SNAPSHOT_PARALLELISM: usize = 4;

pub struct Agent
{
    stop: Arc<watch::Sender<bool>>,
    channel_task: JoinHandle<Result<()>>,
    reconciler: ReconcilerHandle,
    metrics_addr: std::net::SocketAddr,
    connected: watch::Receiver<bool>,
}

fn object_store(bucket: &BucketConfig) -> Result<Arc<dyn ObjectStore>>
{
    if let Some(dir) = &bucket.local_dir
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let local = object_store::local::LocalFileSystem::new_with_prefix(dir)
            .with_context(|| format!("opening local object store {}", dir.display()))?;
        return Ok(Arc::new(local));
    }
    let mut builder =
        object_store::aws::AmazonS3Builder::from_env().with_bucket_name(&bucket.bucket);
    if let Some(region) = &bucket.region
    {
        builder = builder.with_region(region);
    }
    if let Some(endpoint) = &bucket.endpoint
    {
        builder = builder.with_endpoint(endpoint);
    }
    Ok(Arc::new(
        builder.build().context("configuring the S3 client")?,
    ))
}

fn kvm_available() -> bool
{
    Path::new("/dev/kvm").exists()
}

fn console_writer() -> Result<Vec<String>>
{
    let exe = std::env::current_exe().context("locating the quarryd binary")?;
    Ok(vec![exe.display().to_string(), "console-ring".to_string()])
}

async fn build_sandbox(config: &Config) -> Result<Arc<dyn Sandbox>>
{
    let backend = match config.sandbox.backend
    {
        SandboxBackend::Auto if kvm_available() => SandboxBackend::Firecracker,
        SandboxBackend::Auto => SandboxBackend::Gvisor,
        other => other,
    };
    let sandbox: Arc<dyn Sandbox> = match backend
    {
        SandboxBackend::Firecracker =>
        {
            let systemd = sandbox::unit_bus::UnitBus::connect()
                .await
                .context("connecting to systemd")?;
            Arc::new(sandbox::firecracker::Firecracker::new(
                sandbox::firecracker::FirecrackerConfig {
                    firecracker_bin: config.sandbox.firecracker_bin.clone(),
                    jailer_bin: config.sandbox.jailer_bin.clone(),
                    chroot_base_dir: config.sandbox.chroot_base.clone(),
                    console_writer: console_writer()?,
                    cgroup_version: 2,
                    slice: None,
                },
                systemd,
            )?)
        }
        SandboxBackend::Gvisor =>
        {
            let systemd = sandbox::unit_bus::UnitBus::connect()
                .await
                .context("connecting to systemd")?;
            Arc::new(sandbox::gvisor::Gvisor::new(
                sandbox::gvisor::GvisorConfig {
                    runsc_bin: config.sandbox.runsc_bin.clone(),
                    runsc_root: config.sandbox.runsc_root.clone(),
                    bundle_base_dir: config.sandbox.bundle_base.clone(),
                    console_writer: console_writer()?,
                    slice: None,
                },
                systemd,
            )?)
        }
        SandboxBackend::Fake =>
        {
            let program = config
                .sandbox
                .fake_program
                .clone()
                .context("sandbox.fake_program is required for the fake backend")?;
            sandbox::fake::check_socket_paths()?;
            Arc::new(sandbox::fake::FakeSandbox::new(sandbox::fake::FakeConfig {
                state_dir: config.state_dir.join("fake-sandbox"),
                program,
                args: config.sandbox.fake_args.clone(),
                env: Default::default(),
                console_writer: None,
            }))
        }
        SandboxBackend::Auto => bail!("sandbox backend could not be resolved"),
    };
    Ok(sandbox)
}

fn build_volume(config: &Config) -> Arc<dyn Volume>
{
    match config.volume.backend
    {
        VolumeBackend::LvmThin => Arc::new(LvmThin::new(
            config.volume.volume_group.clone(),
            config.volume.thin_pool.clone(),
        )),
        VolumeBackend::File => Arc::new(FileVolume::new(
            config.file_volume_dir(),
            config.volume.file_capacity_gib.saturating_mul(GIB),
        )),
    }
}

fn build_network(config: &Config) -> Result<Arc<dyn Network>>
{
    match config.network.backend
    {
        NetworkBackend::Fake => Ok(Arc::new(network::FakeNetwork::new(Some(
            config.state_dir.join("fake-network.json"),
        ))?)),
        NetworkBackend::Host => host_network(config),
    }
}

#[cfg(target_os = "linux")]
fn host_network(config: &Config) -> Result<Arc<dyn Network>>
{
    let mut networking = network::NetworkingConfig::new(config.state_dir.join("network"));
    networking.uplink_ifname = (!config.uplink_interface.is_empty())
        .then(|| config.uplink_interface.clone())
        .or_else(|| config.network.uplink.clone());
    Ok(Arc::new(network::Networking::new(networking)?))
}

#[cfg(not(target_os = "linux"))]
fn host_network(_config: &Config) -> Result<Arc<dyn Network>>
{
    bail!("host networking requires Linux; use network.backend = \"fake\" on this platform")
}

fn memory_total_mib() -> Option<u64>
{
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| {
            rest.trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
        .map(|kib| kib / 1024)
}

async fn capacity(config: &Config, volumes: &Volumes) -> Result<Resources>
{
    if let Some(capacity) = &config.capacity
    {
        return Ok(Resources {
            vcpus: capacity.vcpus,
            memory_mib: capacity.memory_mib,
            disk_gib: capacity.disk_gib,
        });
    }
    let vcpus = std::thread::available_parallelism()
        .map(|count| count.get() as u32)
        .context("detecting CPU count")?;
    let memory_mib =
        memory_total_mib().context("detecting memory; set [capacity] in the configuration")?;
    let disk_gib = volumes.pool_status().await?.usage.size_bytes / GIB;
    Ok(Resources {
        vcpus,
        memory_mib,
        disk_gib,
    })
}

fn isolations(kind: SandboxKind) -> Vec<i32>
{
    match kind
    {
        SandboxKind::Firecracker => vec![Isolation::Firecracker as i32],
        SandboxKind::Gvisor => vec![Isolation::Gvisor as i32],
        SandboxKind::Fake => vec![Isolation::Firecracker as i32, Isolation::Gvisor as i32],
    }
}

pub fn heartbeat_interval(lease_ttl: Duration) -> Duration
{
    (lease_ttl / 3)
        .min(Duration::from_secs(10))
        .max(Duration::from_millis(100))
}

impl Agent
{
    pub async fn start(config: Config) -> Result<Agent>
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for dir in [
            config.state_dir.clone(),
            config.instances_dir(),
            config.identity_dir(),
        ]
        {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let store = Arc::new(Store::open(&config.database_path())?);
        let metrics = Arc::new(Metrics::new(&config.node_id));
        let (stop, stop_receiver) = watch::channel(false);
        let stop = Arc::new(stop);
        let metrics_shutdown = {
            let mut receiver = stop_receiver.clone();
            async move {
                let _ = receiver.wait_for(|stopped| *stopped).await;
            }
        };
        let metrics_addr =
            usage::serve_metrics(metrics.clone(), config.metrics_addr, metrics_shutdown).await?;
        info!(addr = %metrics_addr, "metrics endpoint listening");

        let artifacts = object_store(&config.artifacts.bucket)?;
        let images = Arc::new(ImageCache::new(
            config.artifact_cache_dir(),
            artifacts,
            &config.artifacts.public_key,
            store.clone(),
            config.artifacts.cache_capacity_gib.saturating_mul(GIB),
        )?);
        let snapshots = match &config.snapshots
        {
            Some(bucket) => Some(Arc::new(SnapshotStore::new(
                object_store(bucket)?,
                SNAPSHOT_CHUNK_BYTES,
                SNAPSHOT_PARALLELISM,
            ))),
            None => None,
        };
        let sandbox = build_sandbox(&config).await?;
        let kind = sandbox.kind();
        let volumes = Arc::new(Volumes::new(build_volume(&config)));
        let network = build_network(&config)?;
        network
            .configure_public(&network::PublicIpv4Config {
                pool: config.public_ipv4_pool.clone(),
                uplink_interface: config.uplink_interface.clone(),
                arp: config.public_ipv4_arp,
            })
            .await?;
        let wireguard_public_key = match network.wireguard_public_key().await
        {
            Ok(key) => key.unwrap_or_default(),
            Err(error) =>
            {
                warn!(error = %error, "WireGuard key unavailable");
                String::new()
            }
        };
        let capacity = capacity(&config, &volumes).await?;
        let reservation = Resources {
            vcpus: config.reservation.vcpus,
            memory_mib: config.reservation.memory_mib,
            disk_gib: config.reservation.disk_gib,
        };
        let instances = &config.instances;
        let (reconciler, events) = Reconciler::start(
            ReconcilerConfig {
                node_id: config.node_id.clone(),
                capacity,
                reservation,
                default_lease_ttl: config.lease_ttl(),
                state_dir: config.instances_dir(),
                uid_base: instances.uid_base,
                uid_count: instances.uid_count,
                console_max_bytes: instances.console_max_bytes,
                stop_deadline: Duration::from_secs(instances.stop_deadline_secs),
                kill_deadline: Duration::from_secs(instances.kill_deadline_secs),
                reconcile_interval: Duration::from_secs(30),
                sample_interval: Duration::from_secs(10),
                restart_backoff_base: Duration::from_millis(instances.restart_backoff_base_ms),
                restart_backoff_max: Duration::from_secs(instances.restart_backoff_max_secs),
                guest_rate_capacity: instances.guest_rate_capacity,
                guest_rate_per_sec: instances.guest_rate_per_sec,
                guest_connect_timeout: Duration::from_secs(instances.guest_connect_timeout_secs),
                ready_timeout: Duration::from_secs(instances.ready_timeout_secs),
            },
            ReconcilerParts {
                store: store.clone(),
                sandbox,
                volumes,
                network,
                images: images.clone(),
                snapshots,
                metrics: metrics.clone(),
            },
        )
        .await?;

        let ca_pem = std::fs::read_to_string(&config.ca_cert)
            .with_context(|| format!("reading pinned CA {}", config.ca_cert.display()))?;
        let join_token = match &config.join_token_file
        {
            Some(path) if path.exists() => Some(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?
                    .trim()
                    .to_string(),
            ),
            _ => None,
        };
        let transport = Transport::new(ca_pem, config.identity_dir(), config.node_id.clone());
        let current_channel = Arc::new(Mutex::new(None));
        let operations =
            Operations::new(store.clone(), reconciler.clone(), current_channel.clone())?;
        let systemd = if kind == SandboxKind::Fake
        {
            None
        }
        else
        {
            sandbox::unit_bus::UnitBus::connect().await.ok()
        };
        let updater = Arc::new(Updater::new(
            UpdatePaths::new(config.update.binary_path.clone(), &config.state_dir),
            env!("CARGO_PKG_VERSION").to_string(),
            Some(images),
            systemd,
            config.update.service_name.clone(),
            Duration::from_secs(config.update.rollback_after_secs),
            stop.clone(),
        ));
        let (connected_sender, connected) = watch::channel(false);
        let channel = ControlChannel::new(
            ChannelSettings {
                node_id: config.node_id.clone(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                endpoints: config.endpoints.clone(),
                join_token,
                capabilities: Capabilities {
                    kvm: kvm_available(),
                    isolations: isolations(kind),
                    arch: std::env::consts::ARCH.to_string(),
                    wireguard_public_key,
                    public_ipv4_pool: config.public_ipv4_pool.clone(),
                    uplink_interface: config.uplink_interface.clone(),
                },
                heartbeat_interval: heartbeat_interval(config.lease_ttl()),
            },
            transport,
            store,
            reconciler.clone(),
            events,
            metrics,
            operations,
            updater,
            current_channel,
            connected_sender,
        )?;
        let channel_task = tokio::spawn(channel.run(stop_receiver));
        info!(node_id = %config.node_id, sandbox = ?kind, "quarryd started");
        Ok(Agent {
            stop,
            channel_task,
            reconciler,
            metrics_addr,
            connected,
        })
    }

    pub fn stop_handle(&self) -> Arc<watch::Sender<bool>>
    {
        self.stop.clone()
    }

    pub fn reconciler(&self) -> &ReconcilerHandle
    {
        &self.reconciler
    }

    pub fn metrics_addr(&self) -> std::net::SocketAddr
    {
        self.metrics_addr
    }

    pub fn connected(&self) -> watch::Receiver<bool>
    {
        self.connected.clone()
    }

    pub async fn wait(self) -> Result<()>
    {
        let outcome = match self.channel_task.await
        {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!("control channel task failed: {error}")),
        };
        self.reconciler.shutdown().await;
        info!("quarryd stopped; instances keep running");
        outcome
    }

    pub async fn stop(self) -> Result<()>
    {
        self.stop.send_replace(true);
        self.wait().await
    }
}
