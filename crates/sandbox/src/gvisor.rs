use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    GUEST_AGENT_PATH, LaunchControl, Sandbox, SandboxError, SandboxHandle, SandboxKind,
    SandboxRecord, SandboxSpec, SandboxState, ShutdownMode, guest_environment, persist_record,
    read_persisted_record, unit_name, validate_spec,
};

pub const SANDBOX_AGENT_SOCKET: &str = "/run/quarry/agent.sock";
const SANDBOX_AGENT_DIR: &str = "/run/quarry";
const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const CPU_PERIOD_USEC: u64 = 100_000;
const OPEN_FILES_LIMIT: u64 = 65_536;
const BUNDLE_PREPARE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONTAINER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const RUNSC_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
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
    pub guest_dir: PathBuf,
    pub guest_socket: PathBuf,
    pub console: PathBuf,
    pub console_fifo: PathBuf,
    pub exit_file: PathBuf,
    pub prepared_file: PathBuf,
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
            guest_dir: bundle.join("guest"),
            guest_socket: bundle.join("guest/agent.sock"),
            console: bundle.join("console.ring"),
            console_fifo: bundle.join("console.fifo"),
            exit_file: bundle.join(EXIT_STATUS_FILE),
            prepared_file: bundle.join("launch-prepared"),
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
        SANDBOX_AGENT_DIR,
        "bind",
        &paths.guest_dir,
        &["bind", "ro", "nosuid", "nodev", "noexec"],
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
        // The transient service owns resource limits and usage accounting.
        // Otherwise runsc moves its sandbox/gofer into a separate /<id> cgroup.
        "--ignore-cgroups".to_string(),
        "run".to_string(),
        "--bundle".to_string(),
        path_text(&paths.bundle)?,
        spec.instance_id.clone(),
    ])
}

fn runsc_delete_statement(config: &GvisorConfig, instance_id: &str)
-> Result<String, SandboxError>
{
    // runsc delete --force succeeds when the container does not exist. Other
    // failures must prevent both data ownership changes and mount cleanup.
    Ok(join(&[
        path_text(&config.runsc_bin)?,
        "--root".to_string(),
        path_text(&config.runsc_root)?,
        "delete".to_string(),
        "--force".to_string(),
        instance_id.to_string(),
    ]))
}

fn unmount_statement(path: &Path) -> Result<String, SandboxError>
{
    let path = quote(&path_text(path)?);
    // util-linux mountpoint uses 32 for "not a mountpoint"; an inspection error
    // is not evidence that it is safe to mount over or remove this directory.
    Ok(format!(
        "if mountpoint -q {path}; then umount {path}; else mount_status=$?; [ \"$mount_status\" -eq 32 ] || exit \"$mount_status\"; fi"
    ))
}

fn data_ownership_script(data: &Path, uid: u32, gid: u32) -> Result<String, SandboxError>
{
    let data = quote(&path_text(data)?);
    // A restored disk can contain files owned by root (Firecracker) or by a
    // different node's allocated UID. Normalize the whole single-user disk,
    // including after an interrupted previous pass. The old container must be
    // stopped first: physical traversal and chown -h never follow guest links.
    Ok(format!(
        "find -P {data} -xdev -mindepth 1 \\( ! -uid {uid} -o ! -gid {gid} \\) -exec chown -h -- {uid}:{gid} {{}} +\nchown -h -- {uid}:{gid} {data}"
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
        runsc_delete_statement(config, &spec.instance_id)?,
        format!("mkdir -p {rootfs} {data}"),
        unmount_statement(&paths.data)?,
        unmount_statement(&paths.rootfs)?,
        format!("mount -o loop,ro {rootfs_image} {rootfs}"),
        format!("mount -t ext4 -o nosuid,nodev {data_volume} {data}"),
        data_ownership_script(&paths.data, spec.uid, spec.gid)?,
        format!(": > {}", quote(&path_text(&paths.prepared_file)?)),
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
    let fifo = quote(&path_text(&paths.console_fifo)?);
    Ok([
        "set -e".to_string(),
        runsc_delete_statement(config, instance_id)?,
        unmount_statement(&paths.data)?,
        unmount_statement(&paths.rootfs)?,
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
        io_accounting: true,
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
    for directory in [&paths.bundle, &paths.rootfs, &paths.data, &paths.guest_dir]
    {
        fs::create_dir_all(directory).map_err(io(format!("create {}", directory.display())))?;
    }
    let guest_dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&paths.guest_dir)
        .map_err(io("open guest socket directory"))?;
    nix::unistd::fchown(
        &guest_dir,
        Some(nix::unistd::geteuid()),
        Some(nix::unistd::getegid()),
    )?;
    guest_dir
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(io("protect guest socket directory"))?;
    for stale in [
        &paths.exit_file,
        &paths.console_fifo,
        &paths.prepared_file,
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

fn bundle_has_socket_directory(paths: &BundlePaths) -> Result<bool, SandboxError>
{
    let bytes = fs::read(&paths.config).map_err(io("read gVisor bundle socket layout"))?;
    let document: Spec = serde_json::from_slice(&bytes)?;
    Ok(document
        .mounts()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|mount| {
            mount.destination().as_path() == Path::new(SANDBOX_AGENT_DIR)
                && mount.source().as_deref() == Some(paths.guest_dir.as_path())
                && mount.typ().as_deref() == Some("bind")
        }))
}

fn path_exists(path: &Path) -> Result<bool, SandboxError>
{
    match fs::symlink_metadata(path)
    {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(format!("inspect {}", path.display()))(error)),
    }
}

fn mount_points() -> Result<Vec<PathBuf>, SandboxError>
{
    let table = fs::read_to_string("/proc/self/mountinfo").map_err(io("read mount table"))?;
    Ok(table
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .map(|field| PathBuf::from(unescape_mount_field(field)))
        .collect())
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

async fn command_with_timeout(
    program: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<Vec<u8>, SandboxError>
{
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| {
            SandboxError::Timeout(format!("run {} {}", program.display(), args.join(" ")))
        })?
        .map_err(io(format!("run {}", program.display())))?;
    if output.status.success()
    {
        Ok(output.stdout)
    }
    else
    {
        Err(SandboxError::Command {
            program: format!("{} {}", program.display(), args.join(" ")),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

async fn launch_cancelled(control: &LaunchControl) -> SandboxError
{
    loop
    {
        if let Err(error) = control.check()
        {
            return error;
        }
        sleep(POLL_INTERVAL).await;
    }
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

    async fn runsc_command(&self, args: &[String]) -> Result<Vec<u8>, SandboxError>
    {
        command_with_timeout(&self.config.runsc_bin, args, RUNSC_COMMAND_TIMEOUT).await
    }

    async fn container_status(&self, instance_id: &str) -> Result<Option<String>, SandboxError>
    {
        let args = self.runsc_args(&["state", instance_id])?;
        match self.runsc_command(&args).await
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
        // Do not mistake a failed state query for a missing container.
        let args = self.runsc_args(&["delete", "--force", instance_id])?;
        self.runsc_command(&args).await?;
        Ok(())
    }

    async fn wait_for_container(
        &self,
        spec: &SandboxSpec,
        paths: &BundlePaths,
        control: &LaunchControl,
    ) -> Result<(), SandboxError>
    {
        let unit = unit_name(&spec.instance_id);
        let prepare_deadline = Instant::now() + BUNDLE_PREPARE_TIMEOUT;
        let mut container_deadline = None;
        loop
        {
            control.check()?;
            tokio::select! {
                result = unit::ensure_running(&self.systemd, &unit, &paths.console) => result?,
                error = launch_cancelled(control) => return Err(error),
            }
            if path_exists(&paths.prepared_file)?
            {
                let deadline = *container_deadline
                    .get_or_insert_with(|| Instant::now() + CONTAINER_READY_TIMEOUT);
                if Instant::now() >= deadline
                {
                    return Err(SandboxError::Timeout(format!(
                        "waiting for gVisor container {} to run",
                        spec.instance_id
                    )));
                }
                let state = tokio::select! {
                    result = tokio::time::timeout_at(deadline, self.container_status(&spec.instance_id)) => {
                        result.map_err(|_| SandboxError::Timeout(format!("waiting for gVisor container {} to run", spec.instance_id)))??
                    }
                    error = launch_cancelled(control) => return Err(error),
                };
                control.check()?;
                if state.as_deref() == Some("running")
                {
                    return Ok(());
                }
            }
            else if Instant::now() >= prepare_deadline
            {
                return Err(SandboxError::Timeout(format!(
                    "preparing gVisor mounts and data ownership for {}",
                    spec.instance_id
                )));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    fn base_record(&self, spec: &SandboxSpec, paths: &BundlePaths) -> SandboxRecord
    {
        self.record_for(&spec.instance_id, spec.generation, paths)
    }

    fn record_for(&self, instance_id: &str, generation: u64, paths: &BundlePaths) -> SandboxRecord
    {
        SandboxRecord {
            instance_id: instance_id.to_owned(),
            generation,
            kind: SandboxKind::Gvisor,
            unit_name: unit_name(instance_id),
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

    async fn complete_launch(
        &self,
        spec: &SandboxSpec,
        paths: &BundlePaths,
        control: &LaunchControl,
    ) -> Result<SandboxHandle, SandboxError>
    {
        if let Err(error) = self.wait_for_container(spec, paths, control).await
        {
            return Err(self.failed_launch(spec, paths, error).await);
        }
        let handle = self.finish(spec, paths).await?;
        if let Err(error) = control.check()
        {
            return Err(self.failed_launch(spec, paths, error).await);
        }
        Ok(handle)
    }

    async fn failed_launch(
        &self,
        spec: &SandboxSpec,
        paths: &BundlePaths,
        error: SandboxError,
    ) -> SandboxError
    {
        match self.force_stop(&self.base_record(spec, paths)).await
        {
            Ok(()) => error,
            Err(cleanup) => SandboxError::LaunchCleanup {
                launch: Box::new(error),
                cleanup: Box::new(cleanup),
            },
        }
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

    async fn launch_controlled(
        &self,
        spec: &SandboxSpec,
        control: LaunchControl,
    ) -> Result<SandboxHandle, SandboxError>
    {
        validate_spec(spec)?;
        control.check()?;
        let paths = self.paths(&spec.instance_id);
        let unit = unit_name(&spec.instance_id);
        match self.systemd.unit_active_state(&unit).await?
        {
            Some(state) if unit::is_running_state(&state) =>
            {
                if !bundle_has_socket_directory(&paths)?
                {
                    return Err(SandboxError::UnitFailed {
                        unit,
                        detail: "legacy gVisor socket mount requires container replacement".into(),
                    });
                }
                return self.complete_launch(spec, &paths, &control).await;
            }
            Some(_) => unit::clear_stale_unit(&self.systemd, &unit).await?,
            None =>
            {}
        }
        let prepared_paths = paths.clone();
        let prepared_spec = spec.clone();
        blocking(move || prepare_bundle(&prepared_paths, &prepared_spec)).await?;
        control.check()?;
        let script = start_script(&self.config, spec, &paths)?;
        let exec = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let properties = unit_properties(&self.config, spec, &paths)?;
        control.check()?;
        // Await this side effect even if authority is revoked while D-Bus is
        // replying. Cleanup must run after the start request has settled.
        if let Err(error) = self
            .systemd
            .start_transient_service(&unit, &exec, &properties)
            .await
        {
            return Err(self.failed_launch(spec, &paths, error).await);
        }
        if let Err(error) = control.check()
        {
            return Err(self.failed_launch(spec, &paths, error).await);
        }
        let started = tokio::select! {
            result = unit::wait_until_active(&self.systemd, &unit, &paths.exit_file, &paths.console) => result,
            error = launch_cancelled(&control) => Err(error),
        };
        if let Err(error) = started
        {
            return Err(self.failed_launch(spec, &paths, error).await);
        }
        self.complete_launch(spec, &paths, &control).await
    }

    fn requires_restart(&self, record: &SandboxRecord) -> bool
    {
        let paths = self.paths(&record.instance_id);
        record.guest_socket != paths.guest_socket
            || bundle_has_socket_directory(&paths).is_ok_and(|compatible| !compatible)
    }

    async fn adopt(&self, record: &SandboxRecord) -> Result<Option<SandboxHandle>, SandboxError>
    {
        Self::check_kind(record)?;
        if !unit::is_running(&self.systemd, &record.unit_name).await?
        {
            return Ok(None);
        }
        let paths = self.paths(&record.instance_id);
        // Old containers pinned a socket inode. They must be recovered and
        // replaced once; rebinding a listener cannot repair that live mount.
        if self.requires_restart(record) || !bundle_has_socket_directory(&paths)?
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

    async fn recover(
        &self,
        instance_id: &str,
        record: Option<&SandboxRecord>,
    ) -> Result<Option<SandboxHandle>, SandboxError>
    {
        crate::validate_instance_id(instance_id)?;
        let paths = self.paths(instance_id);
        let record = record
            .cloned()
            .or_else(|| read_persisted_record(&paths.bundle, instance_id))
            .unwrap_or_else(|| self.record_for(instance_id, 0, &paths));
        Self::check_kind(&record)?;
        if record.instance_id != instance_id || record.unit_name != unit_name(instance_id)
        {
            return Err(SandboxError::InvalidSpec(
                "gVisor recovery identity mismatch".into(),
            ));
        }
        let has_unit = self
            .systemd
            .unit_active_state(&record.unit_name)
            .await?
            .is_some();
        let has_bundle = path_exists(&record.runtime_dir)? || path_exists(&paths.bundle)?;
        if !has_unit && !has_bundle
        {
            if !path_exists(&self.config.runsc_root)?
            {
                return Ok(None);
            }
            // A failed state query cannot distinguish absent from unreadable
            // metadata. --quiet lists IDs without loading their state, whereas
            // the JSON inventory silently skips containers it cannot load.
            let args = self.runsc_args(&["list", "--quiet"])?;
            let bytes = self.runsc_command(&args).await?;
            let containers = std::str::from_utf8(&bytes).map_err(|error| {
                io("decode runsc inventory")(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    error,
                ))
            })?;
            if !containers.lines().any(|id| id == instance_id)
            {
                return Ok(None);
            }
        }
        // Cleanup does not need a healthy runsc API or a live MainPID. Retain
        // this handle until shutdown/destroy has confirmed removal.
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
                let args = self.runsc_args(&["kill", &record.instance_id, "SIGTERM"])?;
                match self.runsc_command(&args).await
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
        let mounted = mount_points()?;
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
    use std::os::unix::fs::{MetadataExt, symlink};

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
    fn oci_spec_mounts_data_and_only_the_guest_socket_directory()
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
            find("/run/quarry"),
            json!({
                "destination": "/run/quarry",
                "type": "bind",
                "source": "/var/lib/quarry/bundles/abc/guest",
                "options": ["bind", "ro", "nosuid", "nodev", "noexec"]
            })
        );
        let run_index = mounts
            .iter()
            .position(|mount| mount["destination"] == json!("/run"))
            .unwrap();
        let socket_index = mounts
            .iter()
            .position(|mount| mount["destination"] == json!("/run/quarry"))
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
                "--ignore-cgroups",
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
        let delete = script.find("delete --force abc").unwrap();
        let ownership = script
            .find("find -P /var/lib/quarry/bundles/abc/data")
            .unwrap();
        assert!(mount_rootfs < run && mount_data < run);
        assert!(delete < mount_rootfs && mount_data < ownership && ownership < run);
        assert!(
            script.contains("--path /var/lib/quarry/bundles/abc/console.ring --max-bytes 1048576")
        );
        let cleanup = cleanup_script(&config(), "abc", &paths).unwrap();
        assert!(cleanup.contains("delete --force abc"));
        assert!(cleanup.contains("umount /var/lib/quarry/bundles/abc/data"));
        assert!(cleanup.contains("umount /var/lib/quarry/bundles/abc/rootfs"));
        assert!(cleanup.starts_with("set -e\n"));
        assert!(!cleanup.contains("|| true"));
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
        assert!(properties.io_accounting);
    }

    #[test]
    fn bundle_preparation_writes_config_and_keeps_the_guest_socket()
    {
        let directory = tempfile::tempdir().unwrap();
        let paths = BundlePaths::new(directory.path(), "abc");
        fs::create_dir_all(&paths.guest_dir).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&paths.guest_socket).unwrap();
        fs::write(&paths.exit_file, b"exited 1").unwrap();
        fs::write(&paths.prepared_file, b"").unwrap();
        let mut spec = sample_spec("abc");
        spec.uid = nix::unistd::getuid().as_raw();
        spec.gid = nix::unistd::getgid().as_raw();
        prepare_bundle(&paths, &spec).unwrap();
        assert!(paths.rootfs.is_dir());
        assert!(paths.data.is_dir());
        assert!(paths.guest_socket.exists());
        assert_eq!(
            fs::metadata(&paths.guest_dir).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&paths.guest_dir).unwrap().uid(),
            nix::unistd::geteuid().as_raw()
        );
        assert!(!paths.exit_file.exists());
        assert!(!paths.prepared_file.exists());
        let written: Spec = serde_json::from_slice(&fs::read(&paths.config).unwrap()).unwrap();
        assert_eq!(written, oci_spec(&spec, &paths).unwrap());
        assert!(bundle_has_socket_directory(&paths).unwrap());
        drop(listener);
    }

    #[test]
    fn legacy_socket_inode_mount_is_not_adoptable()
    {
        let directory = tempfile::tempdir().unwrap();
        let paths = BundlePaths::new(directory.path(), "abc");
        fs::create_dir_all(&paths.bundle).unwrap();
        let mut document =
            serde_json::to_value(oci_spec(&sample_spec("abc"), &paths).unwrap()).unwrap();
        let mounts = document["mounts"].as_array_mut().unwrap();
        let socket = mounts
            .iter_mut()
            .find(|mount| mount["destination"] == SANDBOX_AGENT_DIR)
            .unwrap();
        socket["destination"] = json!(SANDBOX_AGENT_SOCKET);
        socket["source"] = json!(paths.bundle.join("agent.sock"));
        fs::write(&paths.config, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(!bundle_has_socket_directory(&paths).unwrap());
    }

    #[test]
    fn guest_directory_symlink_is_rejected_without_changing_its_target()
    {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        let paths = BundlePaths::new(directory.path(), "abc");
        fs::create_dir(&paths.bundle).unwrap();
        symlink(&outside, &paths.guest_dir).unwrap();
        assert!(prepare_bundle(&paths, &sample_spec("abc")).is_err());
        assert_eq!(fs::metadata(&outside).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn failed_container_deletion_prevents_mount_and_ownership_changes()
    {
        let directory = tempfile::tempdir().unwrap();
        let runsc = directory.path().join("runsc");
        fs::write(&runsc, "#!/bin/sh\nexit 19\n").unwrap();
        fs::set_permissions(&runsc, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = config();
        config.runsc_bin = runsc;
        let paths = BundlePaths::new(&directory.path().join("not-created"), "abc");
        let script = start_script(&config, &sample_spec("abc"), &paths).unwrap();
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(19));
        assert!(!paths.bundle.exists());
    }

    #[test]
    fn ownership_walk_is_physical_and_chown_does_not_dereference_links()
    {
        let script =
            data_ownership_script(Path::new("/data/with ' quote"), 200_000, 200_000).unwrap();
        assert!(script.starts_with("find -P '/data/with '\\'' quote' -xdev"));
        assert!(script.contains("! -uid 200000 -o ! -gid 200000"));
        assert!(script.contains("-exec chown -h -- 200000:200000 {} +"));
    }

    #[tokio::test]
    async fn timed_out_runsc_control_process_is_killed()
    {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("pid");
        let script = format!(
            "printf '%s' \"$$\" > {}\nexec sleep 30",
            quote(&path_text(&pid_file).unwrap())
        );
        let result = command_with_timeout(
            Path::new("/bin/sh"),
            &["-c".into(), script],
            Duration::from_millis(500),
        )
        .await;
        assert!(matches!(result, Err(SandboxError::Timeout(_))));
        let pid =
            nix::unistd::Pid::from_raw(fs::read_to_string(pid_file).unwrap().parse().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while nix::sys::signal::kill(pid, None).is_ok() && Instant::now() < deadline
        {
            sleep(Duration::from_millis(10)).await;
        }
        let gone = nix::sys::signal::kill(pid, None) == Err(nix::errno::Errno::ESRCH);
        if !gone
        {
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        }
        assert!(gone, "timed-out control subprocess survived cancellation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root on Linux to exercise restored UID ownership changes"]
    fn restored_ownership_is_repaired_without_following_guest_symlinks()
    {
        assert!(nix::unistd::geteuid().is_root());
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        fs::create_dir_all(data.join("nested")).unwrap();
        fs::write(data.join("nested/world"), b"world").unwrap();
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("host-file"), b"keep host ownership").unwrap();
        symlink(&outside, data.join("escape")).unwrap();
        // A matching root owner does not mean restored children are ready.
        std::os::unix::fs::lchown(&data, Some(200_005), Some(200_005)).unwrap();
        let script = format!(
            "set -e\n{}",
            data_ownership_script(&data, 200_005, 200_005).unwrap()
        );
        for _ in 0..2
        {
            assert!(
                std::process::Command::new("/bin/sh")
                    .args(["-c", &script])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        for entry in [
            &data,
            &data.join("nested"),
            &data.join("nested/world"),
            &data.join("escape"),
        ]
        {
            let metadata = fs::symlink_metadata(entry).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), (200_005, 200_005));
        }
        assert_eq!(fs::metadata(&outside).unwrap().uid(), 0);
        assert_eq!(fs::metadata(outside.join("host-file")).unwrap().uid(), 0);
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
        spec.uid = 200_005;
        spec.gid = 200_005;
        spec.vcpus = 1;
        spec.memory_mib = 512;
        let guest_socket = backend.guest_socket_path(&instance_id);
        fs::create_dir_all(guest_socket.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(&guest_socket).unwrap();

        let handle = backend.launch(&spec).await.unwrap();
        let record = handle.record().clone();
        assert_eq!(record.kind, SandboxKind::Gvisor);
        assert!(record.pid.is_some());
        let cgroup = record.cgroup_path.clone().unwrap();
        let state = backend.runsc_args(&["state", &instance_id]).unwrap();
        let state: Value = serde_json::from_slice(
            &unit::run_command(&backend.config.runsc_bin, &state)
                .await
                .unwrap(),
        )
        .unwrap();
        let sandbox_pid = state["pid"].as_u64().unwrap().to_string();
        assert!(
            fs::read_to_string(cgroup.join("cgroup.procs"))
                .unwrap()
                .lines()
                .any(|pid| pid == sandbox_pid)
        );
        let data = fs::metadata(record.runtime_dir.join("data")).unwrap();
        assert_eq!((data.uid(), data.gid()), (spec.uid, spec.gid));
        let (connection, _) = tokio::time::timeout(CONTAINER_READY_TIMEOUT, listener.accept())
            .await
            .unwrap()
            .unwrap();
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
        drop(connection);
        drop(listener);
        fs::remove_file(&guest_socket).unwrap();
        let rebound = tokio::net::UnixListener::bind(&guest_socket).unwrap();
        std::os::unix::fs::lchown(&guest_socket, Some(spec.uid), Some(spec.gid)).unwrap();
        fs::set_permissions(&guest_socket, fs::Permissions::from_mode(0o600)).unwrap();
        let (_reconnected, _) = tokio::time::timeout(CONTAINER_READY_TIMEOUT, rebound.accept())
            .await
            .unwrap()
            .unwrap();
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
        assert!(
            !mount_points()
                .unwrap()
                .contains(&record.runtime_dir.join("rootfs"))
        );
    }
}
