use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod console;
mod error;
pub mod fake;
pub mod firecracker;
pub mod gvisor;
mod shell;
mod unit;
pub mod unit_bus;

pub use error::SandboxError;

pub const GUEST_VSOCK_PORT: u32 = 5252;
pub const GUEST_AGENT_PATH: &str = "/usr/local/bin/quarry-guest-agent";
pub const AGENT_TRANSPORT_ENV: &str = "QUARRY_AGENT_TRANSPORT";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxKind
{
    Firecracker,
    Gvisor,
    Fake,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxNetwork
{
    pub netns_path: Option<PathBuf>,
    pub tap_name: Option<String>,
    pub guest_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix_len: u8,
    pub guest_mac: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSpec
{
    pub instance_id: String,
    pub generation: u64,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub kernel: Option<PathBuf>,
    pub rootfs: PathBuf,
    pub data_volume: PathBuf,
    pub network: SandboxNetwork,
    pub env: BTreeMap<String, String>,
    pub uid: u32,
    pub gid: u32,
    pub cpu_pinning: Option<Vec<u32>>,
    pub console_max_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SandboxRecord
{
    pub instance_id: String,
    pub generation: u64,
    pub kind: SandboxKind,
    pub unit_name: String,
    pub api_socket: Option<PathBuf>,
    pub guest_socket: PathBuf,
    pub console_path: PathBuf,
    pub cgroup_path: Option<PathBuf>,
    pub metrics_path: Option<PathBuf>,
    pub pid: Option<u32>,
    pub runtime_dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SandboxHandle
{
    record: SandboxRecord,
}

impl SandboxHandle
{
    pub(crate) fn new(record: SandboxRecord) -> Self
    {
        Self { record }
    }

    pub fn record(&self) -> &SandboxRecord
    {
        &self.record
    }

    pub fn into_record(self) -> SandboxRecord
    {
        self.record
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownMode
{
    Graceful,
    Force,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxState
{
    Running,
    Exited
    {
        code: Option<i32>,
    },
    Missing,
}

#[async_trait]
pub trait Sandbox: Send + Sync
{
    fn kind(&self) -> SandboxKind;
    fn guest_socket_path(&self, instance_id: &str) -> PathBuf;
    async fn launch(&self, spec: &SandboxSpec) -> Result<SandboxHandle, SandboxError>;
    async fn adopt(&self, record: &SandboxRecord) -> Result<Option<SandboxHandle>, SandboxError>;
    async fn shutdown(
        &self,
        handle: &SandboxHandle,
        mode: ShutdownMode,
    ) -> Result<(), SandboxError>;
    async fn set_memory_target(
        &self,
        handle: &SandboxHandle,
        target_mib: u64,
    ) -> Result<(), SandboxError>;
    async fn status(&self, handle: &SandboxHandle) -> Result<SandboxState, SandboxError>;
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SandboxError>;
}

pub fn unit_name(instance_id: &str) -> String
{
    format!("quarry-vm@{instance_id}.service")
}

pub fn validate_instance_id(instance_id: &str) -> Result<(), SandboxError>
{
    let valid = !instance_id.is_empty()
        && instance_id.len() <= 64
        && instance_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if valid
    {
        Ok(())
    }
    else
    {
        Err(SandboxError::InvalidSpec(format!(
            "instance id {instance_id:?} must be 1-64 ASCII letters, digits, or '-'"
        )))
    }
}

fn is_env_name(name: &str) -> bool
{
    let mut bytes = name.bytes();
    match bytes.next()
    {
        Some(first) if first.is_ascii_alphabetic() || first == b'_' =>
        {
            bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
        _ => false,
    }
}

pub(crate) fn validate_spec(spec: &SandboxSpec) -> Result<(), SandboxError>
{
    validate_instance_id(&spec.instance_id)?;
    if spec.vcpus == 0
    {
        return Err(SandboxError::InvalidSpec("vcpus must be at least 1".into()));
    }
    if spec.memory_mib == 0
    {
        return Err(SandboxError::InvalidSpec(
            "memory_mib must be at least 1".into(),
        ));
    }
    if spec.console_max_bytes == 0
    {
        return Err(SandboxError::InvalidSpec(
            "console_max_bytes must be at least 1".into(),
        ));
    }
    if spec.network.prefix_len > 32
    {
        return Err(SandboxError::InvalidSpec(format!(
            "prefix_len {} is larger than 32",
            spec.network.prefix_len
        )));
    }
    if let Some(name) = spec.env.keys().find(|name| !is_env_name(name))
    {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid environment variable name {name:?}"
        )));
    }
    if spec.env.values().any(|value| value.contains('\0'))
    {
        return Err(SandboxError::InvalidSpec(
            "environment values must not contain NUL".into(),
        ));
    }
    if let Some(cpus) = &spec.cpu_pinning
        && cpus.is_empty()
    {
        return Err(SandboxError::InvalidSpec(
            "cpu_pinning must not be empty when set".into(),
        ));
    }
    Ok(())
}

pub(crate) fn guest_environment(spec: &SandboxSpec, transport: String) -> BTreeMap<String, String>
{
    let mut env = spec.env.clone();
    env.insert(AGENT_TRANSPORT_ENV.to_string(), transport);
    env
}

pub(crate) fn read_persisted_record(runtime_dir: &Path, instance_id: &str)
-> Option<SandboxRecord>
{
    let bytes = std::fs::read(runtime_dir.join(RECORD_FILE)).ok()?;
    let record: SandboxRecord = serde_json::from_slice(&bytes).ok()?;
    (record.instance_id == instance_id).then_some(record)
}

pub(crate) fn persist_record(record: &SandboxRecord) -> Result<(), SandboxError>
{
    let path = record.runtime_dir.join(RECORD_FILE);
    let temporary = record.runtime_dir.join(format!("{RECORD_FILE}.tmp"));
    let bytes = serde_json::to_vec_pretty(record)?;
    std::fs::write(&temporary, bytes)
        .map_err(error::io(format!("write {}", temporary.display())))?;
    std::fs::rename(&temporary, &path).map_err(error::io(format!("rename to {}", path.display())))
}

pub(crate) const RECORD_FILE: &str = "record.json";

#[cfg(test)]
pub(crate) mod tests
{
    use super::*;

    pub fn sample_spec(instance_id: &str) -> SandboxSpec
    {
        SandboxSpec {
            instance_id: instance_id.to_string(),
            generation: 3,
            vcpus: 2,
            memory_mib: 2048,
            kernel: Some(PathBuf::from("/var/lib/quarry/images/kernel")),
            rootfs: PathBuf::from("/var/lib/quarry/images/rootfs.squashfs"),
            data_volume: PathBuf::from("/dev/quarry/data-abc"),
            network: SandboxNetwork {
                netns_path: Some(PathBuf::from("/var/run/netns/q-abc")),
                tap_name: Some("qtap0".into()),
                guest_ip: Ipv4Addr::new(10, 20, 0, 5),
                gateway: Ipv4Addr::new(10, 20, 0, 1),
                prefix_len: 24,
                guest_mac: "06:00:0a:14:00:05".into(),
            },
            env: BTreeMap::from([("SERVER_JAR".to_string(), "paper.jar".to_string())]),
            uid: 100_005,
            gid: 100_005,
            cpu_pinning: None,
            console_max_bytes: 1 << 20,
        }
    }

    #[test]
    fn instance_ids_are_validated()
    {
        assert!(validate_instance_id("abc-123").is_ok());
        assert!(validate_instance_id("").is_err());
        assert!(validate_instance_id("a/b").is_err());
        assert!(validate_instance_id("a_b").is_err());
        assert!(validate_instance_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn spec_validation_rejects_bad_values()
    {
        assert!(validate_spec(&sample_spec("ok")).is_ok());
        let mut spec = sample_spec("ok");
        spec.vcpus = 0;
        assert!(validate_spec(&spec).is_err());
        let mut spec = sample_spec("ok");
        spec.env.insert("1BAD".into(), "x".into());
        assert!(validate_spec(&spec).is_err());
        let mut spec = sample_spec("ok");
        spec.cpu_pinning = Some(Vec::new());
        assert!(validate_spec(&spec).is_err());
        let mut spec = sample_spec("ok");
        spec.network.prefix_len = 33;
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn transport_variable_overrides_spec_env()
    {
        let mut spec = sample_spec("ok");
        spec.env
            .insert(AGENT_TRANSPORT_ENV.into(), "spoofed".into());
        let env = guest_environment(&spec, "vsock:5252".into());
        assert_eq!(
            env.get(AGENT_TRANSPORT_ENV).map(String::as_str),
            Some("vsock:5252")
        );
        assert_eq!(env.get("SERVER_JAR").map(String::as_str), Some("paper.jar"));
    }

    #[test]
    fn unit_names_follow_the_template()
    {
        assert_eq!(unit_name("abc"), "quarry-vm@abc.service");
    }
}
