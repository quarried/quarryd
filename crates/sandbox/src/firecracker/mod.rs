use std::ffi::OsStr;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use nix::sys::stat::{Mode, SFlag, mknod};
use nix::unistd::mkfifo;
use tokio::time::{Instant, sleep};

use crate::error::io;
use crate::shell::{console_script, path_text, writer_argv};
use crate::unit::{self, EXIT_STATUS_FILE, blocking};
use crate::unit_bus::{TransientServiceProperties, UnitBus};
use crate::{
    GUEST_AGENT_PATH, GUEST_VSOCK_PORT, Sandbox, SandboxError, SandboxHandle, SandboxKind,
    SandboxRecord, SandboxSpec, SandboxState, ShutdownMode, guest_environment, persist_record,
    read_persisted_record, unit_name, validate_spec,
};

mod api;

pub use api::{
    ActionType, Balloon, BalloonStats, BalloonUpdate, BootSource, Drive, FirecrackerApi,
    InstanceAction, InstanceInfo, Logger, MachineConfig, Metrics, NetworkInterface, Vsock,
};

const JAIL_API_SOCKET: &str = "/run/firecracker.socket";
const JAIL_VSOCK: &str = "/run/v.sock";
const JAIL_KERNEL: &str = "/vmlinux";
const JAIL_ROOTFS: &str = "/rootfs";
const JAIL_DATA: &str = "/data";
const JAIL_METRICS: &str = "/metrics.fifo";
const JAIL_LOG: &str = "/firecracker.log";
const GUEST_CID: u32 = 3;
const BALLOON_STATS_INTERVAL_S: u32 = 5;
const API_READY_TIMEOUT: Duration = Duration::from_secs(10);
const VCPU_THREAD_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const STOP_TIMEOUT_USEC: u64 = 30_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirecrackerConfig
{
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    pub chroot_base_dir: PathBuf,
    pub console_writer: Vec<String>,
    pub cgroup_version: u8,
    pub slice: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JailPaths
{
    jail_dir: PathBuf,
    root: PathBuf,
    api_socket: PathBuf,
    guest_socket: PathBuf,
    console: PathBuf,
    console_fifo: PathBuf,
    metrics: PathBuf,
    log: PathBuf,
    exit_file: PathBuf,
}

fn inside(root: &Path, jail_path: &str) -> PathBuf
{
    root.join(jail_path.trim_start_matches('/'))
}

impl JailPaths
{
    fn new(config: &FirecrackerConfig, instance_id: &str) -> Self
    {
        let exec_name = config
            .firecracker_bin
            .file_name()
            .unwrap_or_else(|| OsStr::new("firecracker"));
        let jail_dir = config.chroot_base_dir.join(exec_name).join(instance_id);
        let root = jail_dir.join("root");
        Self {
            api_socket: inside(&root, JAIL_API_SOCKET),
            guest_socket: inside(&root, &format!("{JAIL_VSOCK}_{GUEST_VSOCK_PORT}")),
            console: jail_dir.join("console.ring"),
            console_fifo: jail_dir.join("console.fifo"),
            metrics: inside(&root, JAIL_METRICS),
            log: inside(&root, JAIL_LOG),
            exit_file: jail_dir.join(EXIT_STATUS_FILE),
            root,
            jail_dir,
        }
    }
}

pub fn netmask(prefix_len: u8) -> Ipv4Addr
{
    Ipv4Addr::from(
        u32::MAX
            .checked_shl(32 - u32::from(prefix_len.min(32)))
            .unwrap_or(0),
    )
}

fn kernel_param(name: &str, value: &str) -> Result<String, SandboxError>
{
    if value
        .chars()
        .any(|character| character == '"' || character.is_control())
    {
        return Err(SandboxError::InvalidSpec(format!(
            "environment value for {name} cannot be passed on the kernel command line"
        )));
    }
    if value.is_empty() || value.contains(' ')
    {
        Ok(format!("{name}=\"{value}\""))
    }
    else
    {
        Ok(format!("{name}={value}"))
    }
}

pub fn boot_args(spec: &SandboxSpec) -> Result<String, SandboxError>
{
    let mut args = vec![
        "console=ttyS0".to_string(),
        "reboot=k".to_string(),
        "panic=1".to_string(),
        "pci=off".to_string(),
    ];
    if spec.network.tap_name.is_some()
    {
        let network = &spec.network;
        args.push(format!(
            "ip={}::{}:{}::eth0:off",
            network.guest_ip,
            network.gateway,
            netmask(network.prefix_len)
        ));
    }
    args.push(format!("init={GUEST_AGENT_PATH}"));
    for (name, value) in guest_environment(spec, format!("vsock:{GUEST_VSOCK_PORT}"))
    {
        args.push(kernel_param(&name, &value)?);
    }
    Ok(args.join(" "))
}

pub fn jailer_argv(
    config: &FirecrackerConfig,
    spec: &SandboxSpec,
) -> Result<Vec<String>, SandboxError>
{
    let mut argv = vec![
        path_text(&config.jailer_bin)?,
        "--id".to_string(),
        spec.instance_id.clone(),
        "--exec-file".to_string(),
        path_text(&config.firecracker_bin)?,
        "--uid".to_string(),
        spec.uid.to_string(),
        "--gid".to_string(),
        spec.gid.to_string(),
        "--chroot-base-dir".to_string(),
        path_text(&config.chroot_base_dir)?,
        "--cgroup-version".to_string(),
        config.cgroup_version.to_string(),
    ];
    if let Some(netns) = &spec.network.netns_path
    {
        argv.push("--netns".to_string());
        argv.push(path_text(netns)?);
    }
    argv.extend([
        "--".to_string(),
        "--api-sock".to_string(),
        JAIL_API_SOCKET.to_string(),
    ]);
    Ok(argv)
}

pub fn unit_properties(
    config: &FirecrackerConfig,
    spec: &SandboxSpec,
    exit_file: &Path,
) -> Result<TransientServiceProperties, SandboxError>
{
    Ok(TransientServiceProperties {
        description: format!(
            "quarry Firecracker instance {} generation {}",
            spec.instance_id, spec.generation
        ),
        slice: config.slice.clone(),
        kill_mode: Some("control-group".to_string()),
        cpu_quota_per_sec_usec: Some(u64::from(spec.vcpus) * 1_000_000),
        allowed_cpus: spec.cpu_pinning.clone(),
        exec_stop_post: vec![unit::exit_status_command(exit_file)?],
        timeout_stop_usec: Some(STOP_TIMEOUT_USEC),
        ..Default::default()
    })
}

pub fn drives() -> [Drive; 2]
{
    [
        Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: JAIL_ROOTFS.to_string(),
            is_root_device: true,
            is_read_only: true,
        },
        Drive {
            drive_id: "data".to_string(),
            path_on_host: JAIL_DATA.to_string(),
            is_root_device: false,
            is_read_only: false,
        },
    ]
}

fn clean_directory(directory: &Path, keep: &[&OsStr]) -> Result<(), SandboxError>
{
    let entries = fs::read_dir(directory).map_err(io(format!("list {}", directory.display())))?;
    for entry in entries
    {
        let entry = entry.map_err(io(format!("list {}", directory.display())))?;
        if keep.contains(&entry.file_name().as_os_str())
        {
            continue;
        }
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(io(format!("stat {}", path.display())))?;
        if file_type.is_dir()
        {
            unit::remove_dir_if_exists(&path)?;
        }
        else
        {
            unit::remove_file_if_exists(&path)?;
        }
    }
    Ok(())
}

fn copy_owned(source: &Path, target: &Path, uid: u32, gid: u32) -> Result<(), SandboxError>
{
    fs::copy(source, target).map_err(io(format!(
        "copy {} to {}",
        source.display(),
        target.display()
    )))?;
    std::os::unix::fs::chown(target, Some(uid), Some(gid))
        .map_err(io(format!("chown {}", target.display())))?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o400))
        .map_err(io(format!("chmod {}", target.display())))
}

fn place_artifact(source: &Path, target: &Path, uid: u32, gid: u32) -> Result<(), SandboxError>
{
    if fs::hard_link(source, target).is_err()
    {
        return copy_owned(source, target, uid, gid);
    }
    let mode = fs::metadata(target)
        .map_err(io(format!("stat {}", target.display())))?
        .mode();
    if mode & 0o004 == 0
    {
        unit::remove_file_if_exists(target)?;
        return copy_owned(source, target, uid, gid);
    }
    Ok(())
}

fn place_data_volume(source: &Path, target: &Path, uid: u32, gid: u32) -> Result<(), SandboxError>
{
    let metadata =
        fs::metadata(source).map_err(io(format!("stat data volume {}", source.display())))?;
    if metadata.file_type().is_block_device()
    {
        mknod(
            target,
            SFlag::S_IFBLK,
            Mode::from_bits_truncate(0o600),
            metadata.rdev() as libc::dev_t,
        )?;
    }
    else if metadata.is_file()
    {
        fs::hard_link(source, target).map_err(io(format!(
            "link data volume {} into {}",
            source.display(),
            target.display()
        )))?;
    }
    else
    {
        return Err(SandboxError::InvalidSpec(format!(
            "data volume {} is neither a block device nor a regular file",
            source.display()
        )));
    }
    std::os::unix::fs::chown(target, Some(uid), Some(gid))
        .map_err(io(format!("chown {}", target.display())))
}

fn prepare_jail(paths: &JailPaths, spec: &SandboxSpec, kernel: &Path) -> Result<(), SandboxError>
{
    let run_dir = inside(&paths.root, "/run");
    fs::create_dir_all(&run_dir).map_err(io(format!("create {}", run_dir.display())))?;
    clean_directory(&paths.root, &[OsStr::new("run")])?;
    let guest_socket_name = paths
        .guest_socket
        .file_name()
        .unwrap_or_else(|| OsStr::new(""));
    clean_directory(&run_dir, &[guest_socket_name])?;
    for stale in [
        &paths.exit_file,
        &paths.console_fifo,
        &paths.jail_dir.join(crate::RECORD_FILE),
    ]
    {
        unit::remove_file_if_exists(stale)?;
    }
    place_artifact(
        kernel,
        &inside(&paths.root, JAIL_KERNEL),
        spec.uid,
        spec.gid,
    )?;
    place_artifact(
        &spec.rootfs,
        &inside(&paths.root, JAIL_ROOTFS),
        spec.uid,
        spec.gid,
    )?;
    place_data_volume(
        &spec.data_volume,
        &inside(&paths.root, JAIL_DATA),
        spec.uid,
        spec.gid,
    )?;
    std::os::unix::fs::chown(&run_dir, Some(spec.uid), Some(spec.gid))
        .map_err(io(format!("chown {}", run_dir.display())))?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))
        .map_err(io(format!("chmod {}", run_dir.display())))?;
    unit::chown_if_exists(&paths.guest_socket, spec.uid, spec.gid)?;
    mkfifo(&paths.metrics, Mode::from_bits_truncate(0o600))?;
    std::os::unix::fs::chown(&paths.metrics, Some(spec.uid), Some(spec.gid))
        .map_err(io(format!("chown {}", paths.metrics.display())))?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&paths.log)
        .map_err(io(format!("create {}", paths.log.display())))?;
    std::os::unix::fs::chown(&paths.log, Some(spec.uid), Some(spec.gid))
        .map_err(io(format!("chown {}", paths.log.display())))
}

#[cfg(target_os = "linux")]
fn pin_vcpu_threads(pid: u32, cpus: &[u32]) -> Result<usize, SandboxError>
{
    use nix::sched::{CpuSet, sched_setaffinity};
    use nix::unistd::Pid;

    let task_dir = PathBuf::from(format!("/proc/{pid}/task"));
    let entries = fs::read_dir(&task_dir).map_err(io(format!("list {}", task_dir.display())))?;
    let mut pinned = 0;
    for entry in entries
    {
        let entry = entry.map_err(io(format!("list {}", task_dir.display())))?;
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else
        {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm"))
        else
        {
            continue;
        };
        let Some(index) = comm
            .trim()
            .strip_prefix("fc_vcpu ")
            .and_then(|index| index.parse::<usize>().ok())
        else
        {
            continue;
        };
        let mut set = CpuSet::new();
        set.set(cpus[index % cpus.len()] as usize)?;
        sched_setaffinity(Pid::from_raw(tid), &set)?;
        pinned += 1;
    }
    Ok(pinned)
}

#[cfg(not(target_os = "linux"))]
fn pin_vcpu_threads(_pid: u32, _cpus: &[u32]) -> Result<usize, SandboxError>
{
    Err(SandboxError::Unsupported)
}

pub struct Firecracker
{
    config: FirecrackerConfig,
    systemd: UnitBus,
}

impl Firecracker
{
    pub fn new(config: FirecrackerConfig, systemd: UnitBus) -> Result<Self, SandboxError>
    {
        let exec_name = config
            .firecracker_bin
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if !exec_name.contains("firecracker")
        {
            return Err(SandboxError::InvalidSpec(format!(
                "the jailer requires the firecracker binary name to contain \"firecracker\", got {exec_name:?}"
            )));
        }
        if config.console_writer.is_empty()
        {
            return Err(SandboxError::InvalidSpec(
                "console writer command is empty".into(),
            ));
        }
        Ok(Self { config, systemd })
    }

    pub fn config(&self) -> &FirecrackerConfig
    {
        &self.config
    }

    fn paths(&self, instance_id: &str) -> JailPaths
    {
        JailPaths::new(&self.config, instance_id)
    }

    fn base_record(&self, spec: &SandboxSpec, paths: &JailPaths) -> SandboxRecord
    {
        SandboxRecord {
            instance_id: spec.instance_id.clone(),
            generation: spec.generation,
            kind: SandboxKind::Firecracker,
            unit_name: unit_name(&spec.instance_id),
            api_socket: Some(paths.api_socket.clone()),
            guest_socket: paths.guest_socket.clone(),
            console_path: paths.console.clone(),
            cgroup_path: None,
            metrics_path: Some(paths.metrics.clone()),
            pid: None,
            runtime_dir: paths.jail_dir.clone(),
        }
    }

    async fn refresh(&self, mut record: SandboxRecord) -> Result<SandboxRecord, SandboxError>
    {
        record.pid = self.systemd.unit_main_pid(&record.unit_name).await?;
        record.cgroup_path = unit::cgroup_path(&self.systemd, &record.unit_name).await?;
        Ok(record)
    }

    async fn wait_for_api(
        &self,
        api: &FirecrackerApi,
        unit: &str,
        console: &Path,
    ) -> Result<InstanceInfo, SandboxError>
    {
        let deadline = Instant::now() + API_READY_TIMEOUT;
        loop
        {
            match api.instance_info().await
            {
                Ok(info) => return Ok(info),
                Err(error) if Instant::now() >= deadline =>
                {
                    return Err(SandboxError::Timeout(format!(
                        "waiting for firecracker API {}: {error}",
                        api.socket().display()
                    )));
                }
                Err(_) =>
                {
                    unit::ensure_running(&self.systemd, unit, console).await?;
                    sleep(POLL_INTERVAL).await;
                }
            }
        }
    }

    async fn configure_and_start(
        &self,
        api: &FirecrackerApi,
        spec: &SandboxSpec,
    ) -> Result<(), SandboxError>
    {
        api.put_logger(&Logger {
            log_path: JAIL_LOG.to_string(),
            level: "Warning".to_string(),
            show_level: true,
            show_log_origin: false,
        })
        .await?;
        api.put_metrics(&Metrics {
            metrics_path: JAIL_METRICS.to_string(),
        })
        .await?;
        api.put_machine_config(&MachineConfig {
            vcpu_count: spec.vcpus,
            mem_size_mib: spec.memory_mib,
            smt: false,
        })
        .await?;
        api.put_boot_source(&BootSource {
            kernel_image_path: JAIL_KERNEL.to_string(),
            boot_args: boot_args(spec)?,
        })
        .await?;
        for drive in drives()
        {
            api.put_drive(&drive).await?;
        }
        if let Some(tap) = &spec.network.tap_name
        {
            api.put_network_interface(&NetworkInterface {
                iface_id: "eth0".to_string(),
                host_dev_name: tap.clone(),
                guest_mac: Some(spec.network.guest_mac.clone()),
            })
            .await?;
        }
        api.put_vsock(&Vsock {
            guest_cid: GUEST_CID,
            uds_path: JAIL_VSOCK.to_string(),
        })
        .await?;
        api.put_balloon(&Balloon {
            amount_mib: 0,
            deflate_on_oom: true,
            stats_polling_interval_s: BALLOON_STATS_INTERVAL_S,
        })
        .await?;
        api.instance_start().await?;
        if let Some(cpus) = &spec.cpu_pinning
        {
            self.pin_vcpus(&unit_name(&spec.instance_id), spec.vcpus, cpus)
                .await?;
        }
        Ok(())
    }

    async fn pin_vcpus(&self, unit: &str, vcpus: u32, cpus: &[u32]) -> Result<(), SandboxError>
    {
        let pid =
            self.systemd
                .unit_main_pid(unit)
                .await?
                .ok_or_else(|| SandboxError::UnitFailed {
                    unit: unit.to_string(),
                    detail: "no main process to pin".to_string(),
                })?;
        let deadline = Instant::now() + VCPU_THREAD_TIMEOUT;
        loop
        {
            let cpus = cpus.to_vec();
            let pinned = blocking(move || pin_vcpu_threads(pid, &cpus)).await?;
            if pinned >= vcpus as usize
            {
                return Ok(());
            }
            if Instant::now() >= deadline
            {
                return Err(SandboxError::Timeout(format!(
                    "found {pinned} of {vcpus} vCPU threads of pid {pid} to pin"
                )));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn boot(&self, spec: &SandboxSpec, paths: &JailPaths) -> Result<(), SandboxError>
    {
        let unit = unit_name(&spec.instance_id);
        let api = FirecrackerApi::new(&paths.api_socket);
        let info = self.wait_for_api(&api, &unit, &paths.console).await?;
        if !info.is_started()
        {
            self.configure_and_start(&api, spec).await?;
        }
        Ok(())
    }

    async fn finish(
        &self,
        spec: &SandboxSpec,
        paths: &JailPaths,
    ) -> Result<SandboxHandle, SandboxError>
    {
        let record = read_persisted_record(&paths.jail_dir, &spec.instance_id)
            .unwrap_or_else(|| self.base_record(spec, paths));
        let record = self.refresh(record).await?;
        let to_persist = record.clone();
        blocking(move || persist_record(&to_persist)).await?;
        Ok(SandboxHandle::new(record))
    }

    async fn start_unit(&self, spec: &SandboxSpec, paths: &JailPaths) -> Result<(), SandboxError>
    {
        let unit = unit_name(&spec.instance_id);
        let writer = writer_argv(
            &self.config.console_writer,
            &paths.console,
            spec.console_max_bytes,
        )?;
        let script = console_script(
            &[],
            &jailer_argv(&self.config, spec)?,
            &writer,
            &paths.console_fifo,
        )?;
        let exec = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let properties = unit_properties(&self.config, spec, &paths.exit_file)?;
        self.systemd
            .start_transient_service(&unit, &exec, &properties)
            .await?;
        unit::wait_until_active(&self.systemd, &unit, &paths.exit_file, &paths.console).await
    }

    async fn abort(&self, unit: &str, error: SandboxError) -> SandboxError
    {
        if let Err(kill_error) = unit::kill_and_wait(&self.systemd, unit).await
        {
            tracing::warn!(unit, %kill_error, "could not stop a partially launched instance");
        }
        error
    }

    fn api(&self, record: &SandboxRecord) -> FirecrackerApi
    {
        let socket = record
            .api_socket
            .clone()
            .unwrap_or_else(|| self.paths(&record.instance_id).api_socket);
        FirecrackerApi::new(socket)
    }

    fn check_kind(record: &SandboxRecord) -> Result<(), SandboxError>
    {
        if record.kind == SandboxKind::Firecracker
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
impl Sandbox for Firecracker
{
    fn kind(&self) -> SandboxKind
    {
        SandboxKind::Firecracker
    }

    fn guest_socket_path(&self, instance_id: &str) -> PathBuf
    {
        self.paths(instance_id).guest_socket
    }

    async fn launch(&self, spec: &SandboxSpec) -> Result<SandboxHandle, SandboxError>
    {
        validate_spec(spec)?;
        let kernel = spec.kernel.clone().ok_or_else(|| {
            SandboxError::InvalidSpec("the Firecracker backend needs a kernel".into())
        })?;
        boot_args(spec)?;
        let paths = self.paths(&spec.instance_id);
        let unit = unit_name(&spec.instance_id);
        match self.systemd.unit_active_state(&unit).await?
        {
            Some(state) if unit::is_running_state(&state) =>
            {
                self.boot(spec, &paths).await?;
                return self.finish(spec, &paths).await;
            }
            Some(_) => unit::clear_stale_unit(&self.systemd, &unit).await?,
            None =>
            {}
        }
        let prepared_paths = paths.clone();
        let prepared_spec = spec.clone();
        blocking(move || {
            fs::create_dir_all(&prepared_paths.root)
                .map_err(io(format!("create {}", prepared_paths.root.display())))?;
            prepare_jail(&prepared_paths, &prepared_spec, &kernel)
        })
        .await?;
        let started = match self.start_unit(spec, &paths).await
        {
            Ok(()) => self.boot(spec, &paths).await,
            Err(error) => Err(error),
        };
        if let Err(error) = started
        {
            return Err(self.abort(&unit, error).await);
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
        let info = self.api(record).instance_info().await?;
        if !info.is_started()
        {
            return Ok(None);
        }
        let record = self.refresh(record.clone()).await?;
        Ok(Some(SandboxHandle::new(record)))
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
                match self.api(record).send_ctrl_alt_del().await
                {
                    Ok(()) => Ok(()),
                    Err(_) if !unit::is_running(&self.systemd, &record.unit_name).await? => Ok(()),
                    Err(error) => Err(error),
                }
            }
            ShutdownMode::Force => unit::kill_and_wait(&self.systemd, &record.unit_name).await,
        }
    }

    async fn set_memory_target(
        &self,
        handle: &SandboxHandle,
        target_mib: u64,
    ) -> Result<(), SandboxError>
    {
        let api = self.api(handle.record());
        let configured = api.machine_config().await?.mem_size_mib;
        if target_mib == 0 || target_mib > configured
        {
            return Err(SandboxError::InvalidSpec(format!(
                "memory target {target_mib} MiB must be between 1 and the configured {configured} MiB"
            )));
        }
        api.patch_balloon(configured - target_mib).await
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
        unit::kill_and_wait(&self.systemd, &record.unit_name).await?;
        self.systemd.reset_failed_unit(&record.unit_name).await?;
        let jail_dir = record.runtime_dir.clone();
        blocking(move || unit::remove_dir_if_exists(&jail_dir)).await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::tests::sample_spec;

    fn config() -> FirecrackerConfig
    {
        FirecrackerConfig {
            firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
            jailer_bin: PathBuf::from("/usr/local/bin/jailer"),
            chroot_base_dir: PathBuf::from("/srv/jailer"),
            console_writer: vec!["/usr/local/bin/quarryd".into(), "console-ring".into()],
            cgroup_version: 2,
            slice: Some("quarry.slice".into()),
        }
    }

    #[test]
    fn netmasks_follow_the_prefix()
    {
        assert_eq!(netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(netmask(17), Ipv4Addr::new(255, 255, 128, 0));
    }

    #[test]
    fn boot_args_configure_console_network_init_and_transport()
    {
        let mut spec = sample_spec("abc");
        spec.env.insert("MOTD".into(), "hello world".into());
        assert_eq!(
            boot_args(&spec).unwrap(),
            "console=ttyS0 reboot=k panic=1 pci=off ip=10.20.0.5::10.20.0.1:255.255.255.0::eth0:off \
             init=/usr/local/bin/quarry-guest-agent MOTD=\"hello world\" QUARRY_AGENT_TRANSPORT=vsock:5252 \
             SERVER_JAR=paper.jar"
        );
        spec.network.tap_name = None;
        assert!(!boot_args(&spec).unwrap().contains("ip="));
        spec.env.insert("BAD".into(), "quote\"inside".into());
        assert!(matches!(
            boot_args(&spec),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn jailer_argv_isolates_the_instance()
    {
        let spec = sample_spec("abc");
        assert_eq!(
            jailer_argv(&config(), &spec).unwrap(),
            vec![
                "/usr/local/bin/jailer",
                "--id",
                "abc",
                "--exec-file",
                "/usr/local/bin/firecracker",
                "--uid",
                "100005",
                "--gid",
                "100005",
                "--chroot-base-dir",
                "/srv/jailer",
                "--cgroup-version",
                "2",
                "--netns",
                "/var/run/netns/q-abc",
                "--",
                "--api-sock",
                "/run/firecracker.socket",
            ]
        );
        let mut spec = sample_spec("abc");
        spec.network.netns_path = None;
        assert!(
            !jailer_argv(&config(), &spec)
                .unwrap()
                .contains(&"--netns".to_string())
        );
    }

    #[test]
    fn jail_paths_place_the_vsock_listener_where_firecracker_forwards()
    {
        let paths = JailPaths::new(&config(), "abc");
        assert_eq!(paths.jail_dir, PathBuf::from("/srv/jailer/firecracker/abc"));
        assert_eq!(
            paths.api_socket,
            PathBuf::from("/srv/jailer/firecracker/abc/root/run/firecracker.socket")
        );
        assert_eq!(
            paths.guest_socket,
            PathBuf::from("/srv/jailer/firecracker/abc/root/run/v.sock_5252")
        );
        assert_eq!(
            paths.metrics,
            PathBuf::from("/srv/jailer/firecracker/abc/root/metrics.fifo")
        );
        assert_eq!(
            paths.console,
            PathBuf::from("/srv/jailer/firecracker/abc/console.ring")
        );
        assert_eq!(
            paths.guest_socket,
            inside(&paths.root, &format!("{JAIL_VSOCK}_{GUEST_VSOCK_PORT}"))
        );
    }

    #[test]
    fn unit_properties_limit_cpu_and_pin_cpus()
    {
        let mut spec = sample_spec("abc");
        spec.cpu_pinning = Some(vec![4, 5]);
        let properties =
            unit_properties(&config(), &spec, Path::new("/srv/x/exit_status")).unwrap();
        assert_eq!(properties.cpu_quota_per_sec_usec, Some(2_000_000));
        assert_eq!(properties.allowed_cpus, Some(vec![4, 5]));
        assert_eq!(properties.memory_max, None);
        assert_eq!(properties.kill_mode.as_deref(), Some("control-group"));
        assert_eq!(properties.slice.as_deref(), Some("quarry.slice"));
        assert_eq!(properties.exec_stop_post.len(), 1);
    }

    #[test]
    fn drives_attach_rootfs_read_only_and_data_read_write()
    {
        let [rootfs, data] = drives();
        assert!(rootfs.is_root_device && rootfs.is_read_only);
        assert!(!data.is_root_device && !data.is_read_only);
    }

    #[test]
    fn jail_preparation_links_artifacts_and_keeps_the_guest_socket()
    {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        config.chroot_base_dir = directory.path().join("jail");
        let paths = JailPaths::new(&config, "abc");
        let kernel = directory.path().join("kernel");
        fs::write(&kernel, b"kernel").unwrap();
        fs::set_permissions(&kernel, fs::Permissions::from_mode(0o644)).unwrap();
        let mut spec = sample_spec("abc");
        spec.rootfs = directory.path().join("rootfs");
        fs::write(&spec.rootfs, b"rootfs").unwrap();
        fs::set_permissions(&spec.rootfs, fs::Permissions::from_mode(0o600)).unwrap();
        spec.data_volume = directory.path().join("data.img");
        fs::write(&spec.data_volume, b"data").unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        spec.uid = uid;
        spec.gid = gid;
        fs::create_dir_all(paths.guest_socket.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&paths.guest_socket).unwrap();
        fs::create_dir_all(paths.root.join("dev/net")).unwrap();
        fs::write(paths.root.join("dev/net/tun"), b"stale").unwrap();
        fs::write(&paths.api_socket, b"stale").unwrap();
        fs::write(&paths.exit_file, b"exited 0").unwrap();

        prepare_jail(&paths, &spec, &kernel).unwrap();

        assert!(!paths.root.join("dev").exists());
        assert!(!paths.api_socket.exists());
        assert!(!paths.exit_file.exists());
        assert!(paths.guest_socket.exists());
        assert_eq!(fs::read(paths.root.join("vmlinux")).unwrap(), b"kernel");
        assert_eq!(
            fs::metadata(paths.root.join("vmlinux")).unwrap().ino(),
            fs::metadata(&kernel).unwrap().ino()
        );
        assert_eq!(fs::read(paths.root.join("rootfs")).unwrap(), b"rootfs");
        assert_ne!(
            fs::metadata(paths.root.join("rootfs")).unwrap().ino(),
            fs::metadata(&spec.rootfs).unwrap().ino()
        );
        assert_eq!(fs::read(paths.root.join("data")).unwrap(), b"data");
        assert!(fs::metadata(&paths.metrics).unwrap().file_type().is_fifo());
        assert!(paths.log.exists());
        assert_eq!(
            fs::metadata(paths.root.join("run")).unwrap().mode() & 0o777,
            0o700
        );

        prepare_jail(&paths, &spec, &kernel).unwrap();
        assert!(paths.guest_socket.exists());
        drop(listener);
    }

    fn integration_config() -> FirecrackerConfig
    {
        let variable =
            |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
        FirecrackerConfig {
            firecracker_bin: PathBuf::from(variable("QUARRY_TEST_FIRECRACKER")),
            jailer_bin: PathBuf::from(variable("QUARRY_TEST_JAILER")),
            chroot_base_dir: PathBuf::from(
                std::env::var("QUARRY_TEST_CHROOT_BASE")
                    .unwrap_or_else(|_| "/srv/quarry-test-jailer".into()),
            ),
            console_writer: variable("QUARRY_TEST_CONSOLE_WRITER")
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            cgroup_version: 2,
            slice: None,
        }
    }

    #[tokio::test]
    #[ignore = "needs root, /dev/kvm, systemd, firecracker+jailer and QUARRY_TEST_{FIRECRACKER,JAILER,KERNEL,ROOTFS,DATA,CONSOLE_WRITER}"]
    async fn firecracker_launch_adopt_and_shutdown()
    {
        let variable =
            |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
        let systemd = UnitBus::connect().await.unwrap();
        let backend = Firecracker::new(integration_config(), systemd.clone()).unwrap();
        let instance_id = format!("fc-test-{}", std::process::id());
        let mut spec = sample_spec(&instance_id);
        spec.kernel = Some(PathBuf::from(variable("QUARRY_TEST_KERNEL")));
        spec.rootfs = PathBuf::from(variable("QUARRY_TEST_ROOTFS"));
        spec.data_volume = PathBuf::from(variable("QUARRY_TEST_DATA"));
        spec.network.netns_path = None;
        spec.network.tap_name = None;
        spec.vcpus = 1;
        spec.memory_mib = 256;
        spec.cpu_pinning = Some(vec![0]);
        let guest_socket = backend.guest_socket_path(&instance_id);
        fs::create_dir_all(guest_socket.parent().unwrap()).unwrap();
        let _listener = tokio::net::UnixListener::bind(&guest_socket).unwrap();

        let handle = backend.launch(&spec).await.unwrap();
        let record = handle.record().clone();
        assert_eq!(record.kind, SandboxKind::Firecracker);
        assert_eq!(record.unit_name, format!("quarry-vm@{instance_id}.service"));
        assert_eq!(record.guest_socket, guest_socket);
        assert!(record.pid.is_some());
        assert!(
            record
                .cgroup_path
                .as_ref()
                .unwrap()
                .join("cpu.max")
                .exists()
        );
        assert_eq!(
            backend.status(&handle).await.unwrap(),
            SandboxState::Running
        );
        let api = FirecrackerApi::new(record.api_socket.clone().unwrap());
        assert_eq!(api.instance_info().await.unwrap().state, "Running");

        let again = backend.launch(&spec).await.unwrap();
        assert_eq!(again.record().pid, record.pid);

        let restarted =
            Firecracker::new(integration_config(), UnitBus::connect().await.unwrap()).unwrap();
        let adopted = restarted.adopt(&record).await.unwrap().unwrap();
        assert_eq!(adopted.record().pid, record.pid);

        restarted.set_memory_target(&adopted, 128).await.unwrap();
        assert!(restarted.set_memory_target(&adopted, 0).await.is_err());

        restarted
            .shutdown(&adopted, ShutdownMode::Graceful)
            .await
            .ok();
        restarted
            .shutdown(&adopted, ShutdownMode::Force)
            .await
            .unwrap();
        assert!(matches!(
            restarted.status(&adopted).await.unwrap(),
            SandboxState::Exited { .. } | SandboxState::Missing
        ));
        assert!(restarted.adopt(&record).await.unwrap().is_none());
        restarted.destroy(&adopted).await.unwrap();
        restarted.destroy(&adopted).await.unwrap();
        assert!(!record.runtime_dir.exists());
    }
}
