use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config
{
    pub node_id: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    pub endpoints: Vec<String>,
    pub ca_cert: PathBuf,
    #[serde(default)]
    pub join_token_file: Option<PathBuf>,
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,
    #[serde(default = "default_lease_ttl_secs")]
    pub lease_ttl_secs: u64,
    #[serde(default)]
    pub reservation: Reservation,
    #[serde(default)]
    pub capacity: Option<Capacity>,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub volume: VolumeConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    pub artifacts: ArtifactsConfig,
    #[serde(default)]
    pub snapshots: Option<BucketConfig>,
    #[serde(default)]
    pub update: UpdateConfig,
    #[serde(default)]
    pub instances: InstancesConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation
{
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub memory_mib: u64,
    #[serde(default)]
    pub disk_gib: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity
{
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxBackend
{
    #[default]
    Auto,
    Firecracker,
    Gvisor,
    Fake,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig
{
    #[serde(default)]
    pub backend: SandboxBackend,
    #[serde(default = "default_firecracker_bin")]
    pub firecracker_bin: PathBuf,
    #[serde(default = "default_jailer_bin")]
    pub jailer_bin: PathBuf,
    #[serde(default = "default_chroot_base")]
    pub chroot_base: PathBuf,
    #[serde(default = "default_runsc_bin")]
    pub runsc_bin: PathBuf,
    #[serde(default = "default_runsc_root")]
    pub runsc_root: PathBuf,
    #[serde(default = "default_bundle_base")]
    pub bundle_base: PathBuf,
    #[serde(default)]
    pub fake_program: Option<PathBuf>,
    #[serde(default)]
    pub fake_args: Vec<String>,
}

impl Default for SandboxConfig
{
    fn default() -> Self
    {
        SandboxConfig {
            backend: SandboxBackend::Auto,
            firecracker_bin: default_firecracker_bin(),
            jailer_bin: default_jailer_bin(),
            chroot_base: default_chroot_base(),
            runsc_bin: default_runsc_bin(),
            runsc_root: default_runsc_root(),
            bundle_base: default_bundle_base(),
            fake_program: None,
            fake_args: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeBackend
{
    #[default]
    LvmThin,
    File,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeConfig
{
    #[serde(default)]
    pub backend: VolumeBackend,
    #[serde(default = "default_volume_group")]
    pub volume_group: String,
    #[serde(default = "default_thin_pool")]
    pub thin_pool: String,
    #[serde(default)]
    pub file_dir: Option<PathBuf>,
    #[serde(default = "default_file_capacity_gib")]
    pub file_capacity_gib: u64,
}

impl Default for VolumeConfig
{
    fn default() -> Self
    {
        VolumeConfig {
            backend: VolumeBackend::LvmThin,
            volume_group: default_volume_group(),
            thin_pool: default_thin_pool(),
            file_dir: None,
            file_capacity_gib: default_file_capacity_gib(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkBackend
{
    #[default]
    Host,
    Fake,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig
{
    #[serde(default)]
    pub backend: NetworkBackend,
    #[serde(default)]
    pub uplink: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketConfig
{
    pub bucket: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub local_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactsConfig
{
    #[serde(flatten)]
    pub bucket: BucketConfig,
    pub public_key: String,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default = "default_cache_capacity_gib")]
    pub cache_capacity_gib: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig
{
    #[serde(default = "default_binary_path")]
    pub binary_path: PathBuf,
    #[serde(default = "default_rollback_after_secs")]
    pub rollback_after_secs: u64,
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

impl Default for UpdateConfig
{
    fn default() -> Self
    {
        UpdateConfig {
            binary_path: default_binary_path(),
            rollback_after_secs: default_rollback_after_secs(),
            service_name: default_service_name(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstancesConfig
{
    #[serde(default = "default_uid_base")]
    pub uid_base: u32,
    #[serde(default = "default_uid_count")]
    pub uid_count: u32,
    #[serde(default = "default_console_max_bytes")]
    pub console_max_bytes: u64,
    #[serde(default = "default_stop_deadline_secs")]
    pub stop_deadline_secs: u64,
    #[serde(default = "default_kill_deadline_secs")]
    pub kill_deadline_secs: u64,
    #[serde(default = "default_restart_backoff_base_ms")]
    pub restart_backoff_base_ms: u64,
    #[serde(default = "default_restart_backoff_max_secs")]
    pub restart_backoff_max_secs: u64,
    #[serde(default = "default_guest_rate_capacity")]
    pub guest_rate_capacity: u32,
    #[serde(default = "default_guest_rate_per_sec")]
    pub guest_rate_per_sec: f64,
    #[serde(default = "default_guest_connect_timeout_secs")]
    pub guest_connect_timeout_secs: u64,
    #[serde(default = "default_ready_timeout_secs")]
    pub ready_timeout_secs: u64,
}

impl Default for InstancesConfig
{
    fn default() -> Self
    {
        InstancesConfig {
            uid_base: default_uid_base(),
            uid_count: default_uid_count(),
            console_max_bytes: default_console_max_bytes(),
            stop_deadline_secs: default_stop_deadline_secs(),
            kill_deadline_secs: default_kill_deadline_secs(),
            restart_backoff_base_ms: default_restart_backoff_base_ms(),
            restart_backoff_max_secs: default_restart_backoff_max_secs(),
            guest_rate_capacity: default_guest_rate_capacity(),
            guest_rate_per_sec: default_guest_rate_per_sec(),
            guest_connect_timeout_secs: default_guest_connect_timeout_secs(),
            ready_timeout_secs: default_ready_timeout_secs(),
        }
    }
}

impl Config
{
    pub fn load(path: &Path) -> Result<Config>
    {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config>
    {
        let config: Config = toml::from_str(text).context("parsing configuration")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()>
    {
        if self.node_id.is_empty()
        {
            bail!("node_id must not be empty");
        }
        if self.endpoints.is_empty()
        {
            bail!("at least one control plane endpoint is required");
        }
        if let Some(endpoint) = self
            .endpoints
            .iter()
            .find(|endpoint| !endpoint.starts_with("https://"))
        {
            bail!("endpoint {endpoint} must use https");
        }
        if !self.metrics_addr.ip().is_loopback()
        {
            bail!("metrics_addr must be a loopback address");
        }
        if self.lease_ttl_secs == 0
        {
            bail!("lease_ttl_secs must be positive");
        }
        if self.instances.uid_count == 0
        {
            bail!("instances.uid_count must be positive");
        }
        Ok(())
    }

    pub fn lease_ttl(&self) -> Duration
    {
        Duration::from_secs(self.lease_ttl_secs)
    }

    pub fn database_path(&self) -> PathBuf
    {
        self.state_dir.join("quarryd.db")
    }

    pub fn identity_dir(&self) -> PathBuf
    {
        self.state_dir.join("identity")
    }

    pub fn instances_dir(&self) -> PathBuf
    {
        self.state_dir.join("instances")
    }

    pub fn artifact_cache_dir(&self) -> PathBuf
    {
        self.artifacts
            .cache_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("artifacts"))
    }

    pub fn file_volume_dir(&self) -> PathBuf
    {
        self.volume
            .file_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("volumes"))
    }
}

fn default_state_dir() -> PathBuf
{
    PathBuf::from("/var/lib/quarryd")
}

fn default_metrics_addr() -> SocketAddr
{
    SocketAddr::from(([127, 0, 0, 1], 9478))
}

fn default_lease_ttl_secs() -> u64
{
    60
}

fn default_firecracker_bin() -> PathBuf
{
    PathBuf::from("/usr/local/bin/firecracker")
}

fn default_jailer_bin() -> PathBuf
{
    PathBuf::from("/usr/local/bin/jailer")
}

fn default_chroot_base() -> PathBuf
{
    PathBuf::from("/srv/jailer")
}

fn default_runsc_bin() -> PathBuf
{
    PathBuf::from("/usr/local/bin/runsc")
}

fn default_runsc_root() -> PathBuf
{
    PathBuf::from("/run/quarryd/runsc")
}

fn default_bundle_base() -> PathBuf
{
    PathBuf::from("/var/lib/quarryd/bundles")
}

fn default_volume_group() -> String
{
    "quarry".to_string()
}

fn default_thin_pool() -> String
{
    "instances".to_string()
}

fn default_file_capacity_gib() -> u64
{
    100
}

fn default_cache_capacity_gib() -> u64
{
    50
}

fn default_binary_path() -> PathBuf
{
    PathBuf::from("/usr/local/bin/quarryd")
}

fn default_rollback_after_secs() -> u64
{
    600
}

fn default_service_name() -> String
{
    "quarryd.service".to_string()
}

fn default_uid_base() -> u32
{
    200_000
}

fn default_uid_count() -> u32
{
    65_536
}

fn default_console_max_bytes() -> u64
{
    4 * 1024 * 1024
}

fn default_stop_deadline_secs() -> u64
{
    30
}

fn default_kill_deadline_secs() -> u64
{
    10
}

fn default_restart_backoff_base_ms() -> u64
{
    1000
}

fn default_restart_backoff_max_secs() -> u64
{
    300
}

fn default_guest_rate_capacity() -> u32
{
    200
}

fn default_guest_rate_per_sec() -> f64
{
    50.0
}

fn default_guest_connect_timeout_secs() -> u64
{
    120
}

fn default_ready_timeout_secs() -> u64
{
    600
}

#[cfg(test)]
mod tests
{
    use super::*;

    const MINIMAL: &str = r#"
node_id = "node-1"
endpoints = ["https://cp.example:443"]
ca_cert = "/etc/quarryd/ca.pem"

[artifacts]
bucket = "artifacts"
public_key = "RWQ"
"#;

    #[test]
    fn minimal_config_gets_defaults()
    {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!(config.lease_ttl(), Duration::from_secs(60));
        assert_eq!(config.metrics_addr, default_metrics_addr());
        assert_eq!(config.sandbox.backend, SandboxBackend::Auto);
        assert_eq!(
            config.database_path(),
            PathBuf::from("/var/lib/quarryd/quarryd.db")
        );
    }

    #[test]
    fn rejects_plaintext_endpoint()
    {
        let text = MINIMAL.replace("https://cp.example:443", "http://cp.example:80");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_public_metrics_address()
    {
        let text = format!("metrics_addr = \"0.0.0.0:9478\"\n{MINIMAL}");
        assert!(Config::parse(&text).is_err());
    }
}
