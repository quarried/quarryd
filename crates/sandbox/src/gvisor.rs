use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use oci_spec::runtime::{
    LinuxBuilder, LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxMemoryBuilder,
    LinuxNamespaceBuilder, LinuxNamespaceType, LinuxResourcesBuilder, Mount, MountBuilder,
    PosixRlimitBuilder, PosixRlimitType, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
    UserBuilder, get_default_maskedpaths, get_default_mounts, get_default_readonly_paths,
};
use serde::Deserialize;
use tokio::time::{Instant, sleep};

use crate::error::io;
use crate::shell::{console_script, join, path_text, quote, writer_argv};
use crate::unit::{self, EXIT_STATUS_FILE, blocking};
use crate::unit_bus::{TransientServiceProperties, UnitBus};
use crate::{
    GUEST_AGENT_PATH, Sandbox, SandboxError, SandboxHandle, SandboxKind, SandboxRecord,
    SandboxSpec, SandboxState, ShutdownMode, guest_environment, persist_record,
    read_persisted_record, unit_name, validate_spec,
};

pub const SANDBOX_AGENT_SOCKET: &str = "/run/quarry/agent.sock";
const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const CPU_PERIOD_USEC: u64 = 100_000;
const OPEN_FILES_LIMIT: u64 = 65_536;
const CONTAINER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const STOP_TIMEOUT_USEC: u64 = 30_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GvisorConfig
{
    pub runsc_bin: PathBuf,
    pub runsc_root: PathBuf,
    pub bundle_base_dir: PathBuf,
    pub console_writer: Vec<String>,
    pub slice: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundlePaths
{
    pub bundle: PathBuf,
    pub rootfs: PathBuf,
    pub data: PathBuf,
    pub config: PathBuf,
    pub guest_socket: PathBuf,
    pub console: PathBuf,
    pub console_fifo: PathBuf,
    pub exit_file: PathBuf,
}

impl BundlePaths
{
    pub fn new(bundle_base_dir: &Path, instance_id: &str) -> Self
    {
        let bundle = bundle_base_dir.join(instance_id);
        Self {
            rootfs: bundle.join("rootfs"),
            data: bundle.join("data"),
            config: bundle.join("config.json"),
            guest_socket: bundle.join("agent.sock"),
            console: bundle.join("console.ring"),
            console_fifo: bundle.join("console.fifo"),
            exit_file: bundle.join(EXIT_STATUS_FILE),
            bundle,
        }
    }
}

fn mount(
    destination: &str,
    kind: &str,
    source: &Path,
    options: &[&str],
) -> Result<Mount, SandboxError>
{
    Ok(MountBuilder::default()
        .destination(destination)
        .typ(kind)
        .source(source)
        .options(
            options
                .iter()
                .map(|option| option.to_string())
                .collect::<Vec<_>>(),
        )
        .build()?)
}

fn memory_limit_bytes(memory_mib: u64) -> Result<i64, SandboxError>
{
    memory_mib
        .checked_mul(1024 * 1024)
        .and_then(|bytes| i64::try_from(bytes).ok())
        .ok_or_else(|| SandboxError::InvalidSpec(format!("memory_mib {memory_mib} is too large")))
}

pub fn oci_spec(spec: &SandboxSpec, paths: &BundlePaths) -> Result<Spec, SandboxError>
{
    let mut mounts = get_default_mounts();
    mounts.push(mount(
        "/run",
        "tmpfs",
        Path::new("tmpfs"),
        &["nosuid", "nodev", "mode=755"],
    )?);
    mounts.push(mount(
        "/tmp",
        "tmpfs",
        Path::new("tmpfs"),
        &["nosuid", "nodev", "mode=1777"],
    )?);
    mounts.push(mount(
        "/data",
        "bind",
        &paths.data,
        &["rbind", "rw", "nosuid", "nodev"],
    )?);
    mounts.push(mount(
        SANDBOX_AGENT_SOCKET,
        "bind",
        &paths.guest_socket,
        &["bind", "rw"],
    )?);

    let mut env = vec![DEFAULT_PATH.to_string()];
    env.extend(
        guest_environment(spec, format!("unix:{SANDBOX_AGENT_SOCKET}"))
            .into_iter()
            .map(|(name, value)| format!("{name}={value}")),
    );
    let no_capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(HashSet::new())
        .effective(HashSet::new())
        .inheritable(HashSet::new())
        .permitted(HashSet::new())
        .ambient(HashSet::new())
        .build()?;
    let process = ProcessBuilder::default()
        .terminal(false)
        .user(UserBuilder::default().uid(spec.uid).gid(spec.gid).build()?)
        .args(vec![GUEST_AGENT_PATH.to_string()])
        .env(env)
        .cwd("/")
        .capabilities(no_capabilities)
        .rlimits(vec![
            PosixRlimitBuilder::default()
                .typ(PosixRlimitType::RlimitNofile)
                .hard(OPEN_FILES_LIMIT)
                .soft(OPEN_FILES_LIMIT)
                .build()?,
        ])
        .no_new_privileges(true)
        .build()?;

    let mut namespaces = Vec::new();
    for kind in [
        LinuxNamespaceType::Pid,
        LinuxNamespaceType::Ipc,
        LinuxNamespaceType::Uts,
        LinuxNamespaceType::Mount,
    ]
    {
        namespaces.push(LinuxNamespaceBuilder::default().typ(kind).build()?);
    }
    let mut network = LinuxNamespaceBuilder::default().typ(LinuxNamespaceType::Network);
    if let Some(path) = &spec.network.netns_path
    {
        network = network.path(path.clone());
    }
    namespaces.push(network.build()?);

    let mut cpu = LinuxCpuBuilder::default()
        .quota(i64::from(spec.vcpus) * CPU_PERIOD_USEC as i64)
        .period(CPU_PERIOD_USEC);
    if let Some(cpus) = &spec.cpu_pinning
    {
        cpu = cpu.cpus(
            cpus.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    let resources = LinuxResourcesBuilder::default()
        .memory(
            LinuxMemoryBuilder::default()
                .limit(memory_limit_bytes(spec.memory_mib)?)
                .build()?,
        )
        .cpu(cpu.build()?)
        .build()?;
    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .resources(resources)
        .masked_paths(get_default_maskedpaths())
        .readonly_paths(get_default_readonly_paths())
        .build()?;

    Ok(SpecBuilder::default()
        .version("1.0.2")
        .root(
            RootBuilder::default()
                .path("rootfs")
                .readonly(true)
                .build()?,
        )
        .mounts(mounts)
        .process(process)
        .hostname(spec.instance_id.clone())
        .linux(linux)
        .build()?)
}

pub fn runsc_run_argv(
    config: &GvisorConfig,
    spec: &SandboxSpec,
    paths: &BundlePaths,
) -> Result<Vec<String>, SandboxError>
{
    Ok(vec![
        path_text(&config.runsc_bin)?,
        "--root".to_string(),
        path_text(&config.runsc_root)?,
        "--platform=systrap".to_string(),
        "--network=sandbox".to_string(),
        "--host-uds=open".to_string(),
        "run".to_string(),
        "--bundle".to_string(),
        path_text(&paths.bundle)?,
        spec.instance_id.clone(),
    ])
}

fn runsc_delete_statement(config: &GvisorConfig, instance_id: &str)
-> Result<String, SandboxError>
{
    Ok(format!(
        "{} >/dev/null 2>&1 || true",
        join(&[
            path_text(&config.runsc_bin)?,
            "--root".to_string(),
            path_text(&config.runsc_root)?,
            "delete".to_string(),
            "--force".to_string(),
            instance_id.to_string(),
        ])
    ))
}

pub fn start_script(
    config: &GvisorConfig,
    spec: &SandboxSpec,
    paths: &BundlePaths,
) -> Result<String, SandboxError>
{
    let rootfs_image = quote(&path_text(&spec.rootfs)?);
    let data_volume = quote(&path_text(&spec.data_volume)?);
    let rootfs = quote(&path_text(&paths.rootfs)?);
    let data = quote(&path_text(&paths.data)?);
    let setup = vec![
        format!("mkdir -p {rootfs} {data}"),
        format!("mountpoint -q {rootfs} || mount -o loop,ro {rootfs_image} {rootfs}"),
        format!("mountpoint -q {data} || mount -t ext4 -o nosuid,nodev {data_volume} {data}"),
        runsc_delete_statement(config, &spec.instance_id)?,
    ];
    let writer = writer_argv(
        &config.console_writer,
        &paths.console,
        spec.console_max_bytes,
    )?;
    console_script(
        &setup,
        &runsc_run_argv(config, spec, paths)?,
        &writer,
        &paths.console_fifo,
    )
}

pub fn cleanup_script(
    config: &GvisorConfig,
    instance_id: &str,
    paths: &BundlePaths,
) -> Result<String, SandboxError>
{
    let rootfs = quote(&path_text(&paths.rootfs)?);
    let data = quote(&path_text(&paths.data)?);
    let fifo = quote(&path_text(&paths.console_fifo)?);
    Ok([
        runsc_delete_statement(config, instance_id)?,
        format!("! mountpoint -q {data} || umount {data}"),
        format!("! mountpoint -q {rootfs} || umount {rootfs}"),
        format!("rm -f {fifo}"),
    ]
    .join("\n"))
}

pub fn unit_properties(
    config: &GvisorConfig,
    spec: &SandboxSpec,
    paths: &BundlePaths,
) -> Result<TransientServiceProperties, SandboxError>
{
    Ok(TransientServiceProperties {
        description: format!(
            "quarry gVisor instance {} generation {}",
            spec.instance_id, spec.generation
        ),
        slice: config.slice.clone(),
        kill_mode: Some("control-group".to_string()),
        cpu_quota_per_sec_usec: Some(u64::from(spec.vcpus) * 1_000_000),
        memory_max: Some(spec.memory_mib.saturating_mul(1024 * 1024)),
        allowed_cpus: spec.cpu_pinning.clone(),
        exec_stop_post: vec![
            unit::exit_status_command(&paths.exit_file)?,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                cleanup_script(config, &spec.instance_id, paths)?,
            ],
        ],
        timeout_stop_usec: Some(STOP_TIMEOUT_USEC),
        ..Default::default()
    })
}

fn prepare_bundle(paths: &BundlePaths, spec: &SandboxSpec) -> Result<(), SandboxError>
{
    for directory in [&paths.bundle, &paths.rootfs, &paths.data]
    {
        fs::create_dir_all(directory).map_err(io(format!("create {}", directory.display())))?;
    }
    for stale in [
        &paths.exit_file,
        &paths.console_fifo,
        &paths.bundle.join(crate::RECORD_FILE),
    ]
    {
        unit::remove_file_if_exists(stale)?;
    }
    let document = serde_json::to_vec_pretty(&oci_spec(spec, paths)?)?;
    let temporary = paths.bundle.join("config.json.tmp");
    fs::write(&temporary, document).map_err(io(format!("write {}", temporary.display())))?;
    fs::rename(&temporary, &paths.config)
        .map_err(io(format!("rename to {}", paths.config.display())))?;
    unit::chown_if_exists(&paths.guest_socket, spec.uid, spec.gid)
}

fn mount_points() -> Vec<PathBuf>
{
    let Ok(table) = fs::read_to_string("/proc/self/mountinfo")
    else
    {
        return Vec::new();
    };
    table
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .map(|field| PathBuf::from(unescape_mount_field(field)))
        .collect()
}

fn unescape_mount_field(field: &str) -> String
{
    let bytes = field.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len()
    {
        let octal = bytes.get(index + 1..index + 4).filter(|digits| {
            bytes[index] == b'\\' && digits.iter().all(|digit| (b'0'..=b'7').contains(digit))
        });
        match octal
        {
            Some(digits) =>
            {
                output.push(
                    digits
                        .iter()
                        .fold(0u8, |value, digit| value.wrapping_mul(8) + (digit - b'0')),
                );
                index += 4;
            }
            None =>
            {
                output.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[derive(Debug, Deserialize)]
struct ContainerState
{
    status: String,
}

pub struct Gvisor
{
    config: GvisorConfig,
    systemd: UnitBus,
}

impl Gvisor
{
    pub fn new(config: GvisorConfig, systemd: UnitBus) -> Result<Self, SandboxError>
    {
        if config.console_writer.is_empty()
        {
            return Err(SandboxError::InvalidSpec(
                "console writer command is empty".into(),
            ));
        }
        Ok(Self { config, systemd })
    }

    pub fn config(&self) -> &GvisorConfig
    {
        &self.config
    }

    fn paths(&self, instance_id: &str) -> BundlePaths
    {
        BundlePaths::new(&self.config.bundle_base_dir, instance_id)
    }

    fn runsc_args(&self, command: &[&str]) -> Result<Vec<String>, SandboxError>
    {
        let mut args = vec!["--root".to_string(), path_text(&self.config.runsc_root)?];
        args.extend(command.iter().map(|word| word.to_string()));
        Ok(args)
    }

    async fn container_status(&self, instance_id: &str) -> Result<Option<String>, SandboxError>
    {
        let args = self.runsc_args(&["state", instance_id])?;
        match unit::run_command(&self.config.runsc_bin, &args).await
        {
            Ok(stdout) => Ok(Some(
                serde_json::from_slice::<ContainerState>(&stdout)?.status,
            )),
            Err(SandboxError::Command { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn delete_container(&self, instance_id: &str) -> Result<(), SandboxError>
    {
        if self.container_status(instance_id).await?.is_some()
        {
            let args = self.runsc_args(&["delete", "--force", instance_id])?;
            unit::run_command(&self.config.runsc_bin, &args).await?;
        }
        Ok(())
    }

    async fn wait_for_container(
        &self,
        spec: &SandboxSpec,
        paths: &BundlePaths,
    ) -> Result<(), SandboxError>
    {
        let unit = unit_name(&spec.instance_id);
        let deadline = Instant::now() + CONTAINER_READY_TIMEOUT;
        loop
        {
            if self.container_status(&spec.instance_id).await?.as_deref() == Some("running")
            {
                return Ok(());
            }
            unit::ensure_running(&self.systemd, &unit, &paths.console).await?;
            if Instant::now() >= deadline
            {
                return Err(SandboxError::Timeout(format!(
                    "waiting for gVisor container {} to run",
                    spec.instance_id
                )));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    fn base_record(&self, spec: &SandboxSpec, paths: &BundlePaths) -> SandboxRecord
    {
        SandboxRecord {
            instance_id: spec.instance_id.clone(),
            generation: spec.generation,
            kind: SandboxKind::Gvisor,
            unit_name: unit_name(&spec.instance_id),
            api_socket: None,
            guest_socket: paths.guest_socket.clone(),
            console_path: paths.console.clone(),
            cgroup_path: None,
            metrics_path: None,
            pid: None,
            runtime_dir: paths.bundle.clone(),
        }
    }

    async fn refresh(&self, mut record: SandboxRecord) -> Result<SandboxRecord, SandboxError>
    {
        record.pid = self.systemd.unit_main_pid(&record.unit_name).await?;
        record.cgroup_path = unit::cgroup_path(&self.systemd, &record.unit_name).await?;
        Ok(record)
    }

    async fn finish(
        &self,
        spec: &SandboxSpec,
        paths: &BundlePaths,
    ) -> Result<SandboxHandle, SandboxError>
    {
        let record = read_persisted_record(&paths.bundle, &spec.instance_id)
            .unwrap_or_else(|| self.base_record(spec, paths));
        let record = self.refresh(record).await?;
        let to_persist = record.clone();
        blocking(move || persist_record(&to_persist)).await?;
        Ok(SandboxHandle::new(record))
    }

    async fn force_stop(&self, record: &SandboxRecord) -> Result<(), SandboxError>
    {
        unit::kill_and_wait(&self.systemd, &record.unit_name).await?;
        self.delete_container(&record.instance_id).await
    }

    fn check_kind(record: &SandboxRecord) -> Result<(), SandboxError>
    {
        if record.kind == SandboxKind::Gvisor
        {
            Ok(())
        }
        else
        {
            Err(SandboxError::InvalidSpec(format!(
                "record for {} belongs to the {:?} backend",
                record.instance_id, record.kind
            )))
        }
    }
}

#[async_trait]
impl Sandbox for Gvisor
{
    fn kind(&self) -> SandboxKind
    {
        SandboxKind::Gvisor
    }

    fn guest_socket_path(&self, instance_id: &str) -> PathBuf
    {
        self.paths(instance_id).guest_socket
    }

    async fn launch(&self, spec: &SandboxSpec) -> Result<SandboxHandle, SandboxError>
    {
        validate_spec(spec)?;
        let paths = self.paths(&spec.instance_id);
        let unit = unit_name(&spec.instance_id);
        match self.systemd.unit_active_state(&unit).await?
        {
            Some(state) if unit::is_running_state(&state) =>
            {
                return self.finish(spec, &paths).await;
            }
            Some(_) => unit::clear_stale_unit(&self.systemd, &unit).await?,
            None =>
            {}
        }
        let prepared_paths = paths.clone();
        let prepared_spec = spec.clone();
        blocking(move || prepare_bundle(&prepared_paths, &prepared_spec)).await?;
        let script = start_script(&self.config, spec, &paths)?;
        let exec = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let properties = unit_properties(&self.config, spec, &paths)?;
        self.systemd
            .start_transient_service(&unit, &exec, &properties)
            .await?;
        let started =
            match unit::wait_until_active(&self.systemd, &unit, &paths.exit_file, &paths.console)
                .await
            {
                Ok(()) => self.wait_for_container(spec, &paths).await,
                Err(error) => Err(error),
            };
        if let Err(error) = started
        {
            if let Err(kill_error) = unit::kill_and_wait(&self.systemd, &unit).await
            {
                tracing::warn!(unit, %kill_error, "could not stop a partially launched instance");
            }
            return Err(error);
        }
        self.finish(spec, &paths).await
    }

    async fn adopt(&self, record: &SandboxRecord) -> Result<Option<SandboxHandle>, SandboxError>
    {
        Self::check_kind(record)?;
        if !unit::is_running(&self.systemd, &record.unit_name).await?
        {
            return Ok(None);
        }
        if self.container_status(&record.instance_id).await?.as_deref() != Some("running")
        {
            return Ok(None);
        }
        Ok(Some(SandboxHandle::new(
            self.refresh(record.clone()).await?,
        )))
    }

    async fn shutdown(&self, handle: &SandboxHandle, mode: ShutdownMode)
    -> Result<(), SandboxError>
    {
        let record = handle.record();
        match mode
        {
            ShutdownMode::Graceful =>
            {
                if !unit::is_running(&self.systemd, &record.unit_name).await?
                {
                    return Ok(());
                }
                let args = self.runsc_args(&["kill", &record.instance_id, "SIGTERM"])?;
                match unit::run_command(&self.config.runsc_bin, &args).await
                {
                    Ok(_) => Ok(()),
                    Err(_) if !unit::is_running(&self.systemd, &record.unit_name).await? => Ok(()),
                    Err(error) => Err(error),
                }
            }
            ShutdownMode::Force => self.force_stop(record).await,
        }
    }

    async fn set_memory_target(
        &self,
        _handle: &SandboxHandle,
        _target_mib: u64,
    ) -> Result<(), SandboxError>
    {
        Err(SandboxError::Unsupported)
    }

    async fn status(&self, handle: &SandboxHandle) -> Result<SandboxState, SandboxError>
    {
        let record = handle.record();
        unit::status(
            &self.systemd,
            &record.unit_name,
            &record.runtime_dir.join(EXIT_STATUS_FILE),
        )
        .await
    }

    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SandboxError>
    {
        let record = handle.record();
        self.force_stop(record).await?;
        self.systemd.reset_failed_unit(&record.unit_name).await?;
        let mounted = mount_points();
        for mount_point in [
            record.runtime_dir.join("data"),
            record.runtime_dir.join("rootfs"),
        ]
        {
            if mounted.contains(&mount_point)
            {
                unit::run_command(Path::new("umount"), &[path_text(&mount_point)?]).await?;
            }
        }
        let bundle = record.runtime_dir.clone();
        blocking(move || unit::remove_dir_if_exists(&bundle)).await
    }
}

#[cfg(test)]
mod tests
{
    use serde_json::{Value, json};

    use super::*;
    use crate::tests::sample_spec;

    fn config() -> GvisorConfig
    {
        GvisorConfig {
            runsc_bin: PathBuf::from("/usr/local/bin/runsc"),
            runsc_root: PathBuf::from("/run/quarry/runsc"),
            bundle_base_dir: PathBuf::from("/var/lib/quarry/bundles"),
            console_writer: vec!["/usr/local/bin/quarryd".into(), "console-ring".into()],
            slice: None,
        }
    }

    fn spec_json(spec: &SandboxSpec) -> Value
    {
        let paths = BundlePaths::new(Path::new("/var/lib/quarry/bundles"), &spec.instance_id);
        serde_json::to_value(oci_spec(spec, &paths).unwrap()).unwrap()
    }

    #[test]
    fn oci_spec_runs_the_guest_agent_unprivileged_on_a_read_only_root()
    {
        let document = spec_json(&sample_spec("abc"));
        assert_eq!(
            document["root"],
            json!({"path": "rootfs", "readonly": true})
        );
        let process = &document["process"];
        assert_eq!(
            process["args"],
            json!(["/usr/local/bin/quarry-guest-agent"])
        );
        assert_eq!(process["user"]["uid"], json!(100_005));
        assert_eq!(process["user"]["gid"], json!(100_005));
        assert_eq!(process["noNewPrivileges"], json!(true));
        assert_eq!(process["terminal"], json!(false));
        assert_eq!(
            process["env"],
            json!([
                DEFAULT_PATH,
                "QUARRY_AGENT_TRANSPORT=unix:/run/quarry/agent.sock",
                "SERVER_JAR=paper.jar"
            ])
        );
        assert_eq!(
            process["rlimits"],
            json!([{"type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536}])
        );
        assert_eq!(process["capabilities"]["bounding"], json!([]));
        assert_eq!(document["hostname"], json!("abc"));
    }

    #[test]
    fn oci_spec_mounts_data_and_the_agent_socket()
    {
        let document = spec_json(&sample_spec("abc"));
        let mounts = document["mounts"].as_array().unwrap();
        let find = |destination: &str| {
            mounts
                .iter()
                .find(|mount| mount["destination"] == json!(destination))
                .unwrap_or_else(|| panic!("no mount at {destination}"))
                .clone()
        };
        assert_eq!(
            find("/data"),
            json!({
                "destination": "/data",
                "type": "bind",
                "source": "/var/lib/quarry/bundles/abc/data",
                "options": ["rbind", "rw", "nosuid", "nodev"]
            })
        );
        assert_eq!(
            find("/run/quarry/agent.sock"),
            json!({
                "destination": "/run/quarry/agent.sock",
                "type": "bind",
                "source": "/var/lib/quarry/bundles/abc/agent.sock",
                "options": ["bind", "rw"]
            })
        );
        let run_index = mounts
            .iter()
            .position(|mount| mount["destination"] == json!("/run"))
            .unwrap();
        let socket_index = mounts
            .iter()
            .position(|mount| mount["destination"] == json!("/run/quarry/agent.sock"))
            .unwrap();
        assert!(run_index < socket_index);
        assert!(
            mounts
                .iter()
                .any(|mount| mount["destination"] == json!("/proc"))
        );
    }

    #[test]
    fn oci_spec_joins_the_network_namespace_and_limits_resources()
    {
        let mut spec = sample_spec("abc");
        spec.cpu_pinning = Some(vec![2, 3]);
        let document = spec_json(&spec);
        let linux = &document["linux"];
        let namespaces = linux["namespaces"].as_array().unwrap();
        assert!(namespaces.contains(&json!({"type": "network", "path": "/var/run/netns/q-abc"})));
        assert!(namespaces.contains(&json!({"type": "pid"})));
        assert!(namespaces.contains(&json!({"type": "mount"})));
        assert_eq!(
            linux["resources"]["memory"]["limit"],
            json!(2048_i64 * 1024 * 1024)
        );
        assert_eq!(linux["resources"]["cpu"]["quota"], json!(200_000));
        assert_eq!(linux["resources"]["cpu"]["period"], json!(100_000));
        assert_eq!(linux["resources"]["cpu"]["cpus"], json!("2,3"));
        assert!(linux.get("cgroupsPath").is_none());

        let mut spec = sample_spec("abc");
        spec.network.netns_path = None;
        let document = spec_json(&spec);
        assert!(
            document["linux"]["namespaces"]
                .as_array()
                .unwrap()
                .contains(&json!({"type": "network"}))
        );
        assert!(document["linux"]["resources"]["cpu"].get("cpus").is_none());
    }

    #[test]
    fn runsc_uses_systrap_and_the_bundle()
    {
        let spec = sample_spec("abc");
        let paths = BundlePaths::new(&config().bundle_base_dir, "abc");
        assert_eq!(
            runsc_run_argv(&config(), &spec, &paths).unwrap(),
            vec![
                "/usr/local/bin/runsc",
                "--root",
                "/run/quarry/runsc",
                "--platform=systrap",
                "--network=sandbox",
                "--host-uds=open",
                "run",
                "--bundle",
                "/var/lib/quarry/bundles/abc",
                "abc",
            ]
        );
    }

    #[test]
    fn start_script_mounts_before_running_and_cleanup_unmounts()
    {
        let spec = sample_spec("abc");
        let paths = BundlePaths::new(&config().bundle_base_dir, "abc");
        let script = start_script(&config(), &spec, &paths).unwrap();
        let mount_rootfs = script
            .find("mount -o loop,ro /var/lib/quarry/images/rootfs.squashfs /var/lib/quarry/bundles/abc/rootfs")
            .unwrap();
        let mount_data = script
            .find("mount -t ext4 -o nosuid,nodev /dev/quarry/data-abc /var/lib/quarry/bundles/abc/data")
            .unwrap();
        let run = script.find("exec /usr/local/bin/runsc").unwrap();
        assert!(mount_rootfs < run && mount_data < run);
        assert!(
            script.contains("--path /var/lib/quarry/bundles/abc/console.ring --max-bytes 1048576")
        );
        let cleanup = cleanup_script(&config(), "abc", &paths).unwrap();
        assert!(cleanup.contains("delete --force abc"));
        assert!(cleanup.contains("umount /var/lib/quarry/bundles/abc/data"));
        assert!(cleanup.contains("umount /var/lib/quarry/bundles/abc/rootfs"));
    }

    #[test]
    fn unit_properties_cap_memory_and_cpu()
    {
        let spec = sample_spec("abc");
        let paths = BundlePaths::new(&config().bundle_base_dir, "abc");
        let properties = unit_properties(&config(), &spec, &paths).unwrap();
        assert_eq!(properties.memory_max, Some(2048 * 1024 * 1024));
        assert_eq!(properties.cpu_quota_per_sec_usec, Some(2_000_000));
        assert_eq!(properties.exec_stop_post.len(), 2);
    }

    #[test]
    fn bundle_preparation_writes_config_and_keeps_the_guest_socket()
    {
        let directory = tempfile::tempdir().unwrap();
        let paths = BundlePaths::new(directory.path(), "abc");
        fs::create_dir_all(&paths.bundle).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&paths.guest_socket).unwrap();
        fs::write(&paths.exit_file, b"exited 1").unwrap();
        let mut spec = sample_spec("abc");
        spec.uid = nix::unistd::getuid().as_raw();
        spec.gid = nix::unistd::getgid().as_raw();
        prepare_bundle(&paths, &spec).unwrap();
        assert!(paths.rootfs.is_dir());
        assert!(paths.data.is_dir());
        assert!(paths.guest_socket.exists());
        assert!(!paths.exit_file.exists());
        let written: Spec = serde_json::from_slice(&fs::read(&paths.config).unwrap()).unwrap();
        assert_eq!(written, oci_spec(&spec, &paths).unwrap());
        drop(listener);
    }

    #[test]
    fn mountinfo_fields_are_unescaped()
    {
        assert_eq!(
            unescape_mount_field("/var/lib/with\\040space"),
            "/var/lib/with space"
        );
        assert_eq!(unescape_mount_field("/plain"), "/plain");
        assert_eq!(unescape_mount_field("/odd\\x"), "/odd\\x");
    }

    #[test]
    fn huge_memory_is_rejected()
    {
        assert!(memory_limit_bytes(u64::MAX).is_err());
    }

    fn integration_config(bundle_base_dir: PathBuf) -> GvisorConfig
    {
        let variable =
            |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
        GvisorConfig {
            runsc_bin: PathBuf::from(variable("QUARRY_TEST_RUNSC")),
            runsc_root: bundle_base_dir.join("runsc-root"),
            bundle_base_dir,
            console_writer: variable("QUARRY_TEST_CONSOLE_WRITER")
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            slice: None,
        }
    }

    #[tokio::test]
    #[ignore = "needs root, systemd, runsc, util-linux mount and QUARRY_TEST_{RUNSC,ROOTFS,DATA,CONSOLE_WRITER}"]
    async fn gvisor_launch_adopt_and_shutdown()
    {
        let variable =
            |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
        let base = tempfile::Builder::new()
            .prefix("quarry-gvisor-test")
            .tempdir_in("/var/tmp")
            .unwrap();
        let backend = Gvisor::new(
            integration_config(base.path().to_path_buf()),
            UnitBus::connect().await.unwrap(),
        )
        .unwrap();
        let instance_id = format!("gv-test-{}", std::process::id());
        let mut spec = sample_spec(&instance_id);
        spec.kernel = None;
        spec.rootfs = PathBuf::from(variable("QUARRY_TEST_ROOTFS"));
        spec.data_volume = PathBuf::from(variable("QUARRY_TEST_DATA"));
        spec.network.netns_path = None;
        spec.network.tap_name = None;
        spec.uid = 0;
        spec.gid = 0;
        spec.vcpus = 1;
        spec.memory_mib = 512;
        let guest_socket = backend.guest_socket_path(&instance_id);
        fs::create_dir_all(guest_socket.parent().unwrap()).unwrap();
        let _listener = tokio::net::UnixListener::bind(&guest_socket).unwrap();

        let handle = backend.launch(&spec).await.unwrap();
        let record = handle.record().clone();
        assert_eq!(record.kind, SandboxKind::Gvisor);
        assert!(record.pid.is_some());
        let cgroup = record.cgroup_path.clone().unwrap();
        assert_eq!(
            fs::read_to_string(cgroup.join("memory.max"))
                .unwrap()
                .trim(),
            (512_u64 * 1024 * 1024).to_string()
        );
        assert_eq!(
            fs::read_to_string(cgroup.join("cpu.max")).unwrap().trim(),
            "100000 100000"
        );
        assert_eq!(
            backend.status(&handle).await.unwrap(),
            SandboxState::Running
        );
        assert_eq!(
            backend.launch(&spec).await.unwrap().record().pid,
            record.pid
        );

        let restarted = Gvisor::new(
            integration_config(base.path().to_path_buf()),
            UnitBus::connect().await.unwrap(),
        )
        .unwrap();
        let adopted = restarted.adopt(&record).await.unwrap().unwrap();
        assert_eq!(adopted.record().pid, record.pid);
        assert!(matches!(
            restarted.set_memory_target(&adopted, 256).await,
            Err(SandboxError::Unsupported)
        ));

        restarted
            .shutdown(&adopted, ShutdownMode::Graceful)
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while restarted.status(&adopted).await.unwrap() == SandboxState::Running
            && Instant::now() < deadline
        {
            sleep(POLL_INTERVAL).await;
        }
        restarted
            .shutdown(&adopted, ShutdownMode::Force)
            .await
            .unwrap();
        assert_ne!(
            restarted.status(&adopted).await.unwrap(),
            SandboxState::Running
        );
        assert!(restarted.adopt(&record).await.unwrap().is_none());
        restarted.destroy(&adopted).await.unwrap();
        restarted.destroy(&adopted).await.unwrap();
        assert!(!record.runtime_dir.exists());
        assert!(!mount_points().contains(&record.runtime_dir.join("rootfs")));
    }
}
