use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep};

use crate::error::io;
use crate::shell::{join, path_text, quote, writer_argv};
use crate::unit::{self, blocking};
use crate::{
    AGENT_TRANSPORT_ENV, LaunchControl, Sandbox, SandboxError, SandboxHandle, SandboxKind, SandboxRecord,
    SandboxSpec, SandboxState, ShutdownMode, persist_record, read_persisted_record,
    validate_instance_id, validate_spec,
};

const PROCESS_FILE: &str = "process.json";
const PID_FILE: &str = "pid";
const EXIT_CODE_FILE: &str = "exit_code";
const MEMORY_TARGET_FILE: &str = "memory_target";
const KILL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/// Longest Unix socket path the platform accepts, excluding the terminating NUL.
const MAX_SOCKET_PATH_BYTES: usize = if cfg!(target_os = "linux") { 107 } else { 103 };
const SHORT_SOCKET_PREFIX: &str = "quarryd-";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeConfig
{
    pub state_dir: PathBuf,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub console_writer: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessIdentity
{
    pid: u32,
    pgid: i32,
    marker: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FakePaths
{
    dir: PathBuf,
    process: PathBuf,
    pid: PathBuf,
    exit_code: PathBuf,
    guest_socket: PathBuf,
    console: PathBuf,
    console_fifo: PathBuf,
    memory_target: PathBuf,
}

impl FakePaths
{
    fn new(dir: PathBuf, ring: bool) -> Self
    {
        Self {
            process: dir.join(PROCESS_FILE),
            pid: dir.join(PID_FILE),
            exit_code: dir.join(EXIT_CODE_FILE),
            guest_socket: guest_socket_path(&dir),
            console: dir.join(if ring { "console.ring" } else { "console.log" }),
            console_fifo: dir.join("console.fifo"),
            memory_target: dir.join(MEMORY_TARGET_FILE),
            dir,
        }
    }
}

/// The guest socket lives in the instance directory when the path fits in a Unix
/// socket address. A state directory under a macOS home folder plus an instance ID
/// does not fit in 104 bytes, so the socket then moves to a short name in the
/// temporary directory, derived from the preferred path so that recovery after a
/// restart finds the same socket.
fn guest_socket_path(dir: &Path) -> PathBuf
{
    let preferred = dir.join("agent.sock");
    if preferred.as_os_str().len() <= MAX_SOCKET_PATH_BYTES
    {
        return preferred;
    }
    short_socket_path(&preferred)
}

fn short_socket_path(preferred: &Path) -> PathBuf
{
    use std::os::unix::ffi::OsStrExt;

    std::env::temp_dir().join(format!(
        "{SHORT_SOCKET_PREFIX}{:016x}.sock",
        fnv1a(preferred.as_os_str().as_bytes())
    ))
}

/// FNV-1a: stable across Rust releases, unlike `DefaultHasher`, so socket names
/// survive a quarryd upgrade.
fn fnv1a(bytes: &[u8]) -> u64
{
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Fails when even the short fallback socket path is too long, so a misconfigured
/// host stops at startup instead of failing every instance launch.
pub fn check_socket_paths() -> Result<(), SandboxError>
{
    let fallback = short_socket_path(Path::new(""));
    if fallback.as_os_str().len() > MAX_SOCKET_PATH_BYTES
    {
        return Err(SandboxError::InvalidSpec(format!(
            "guest sockets need a path of at most {MAX_SOCKET_PATH_BYTES} bytes, but the \
             temporary directory {} is too long; set TMPDIR to a shorter directory",
            std::env::temp_dir().display()
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessInfo
{
    zombie: bool,
    start: String,
}

#[cfg(target_os = "linux")]
async fn process_info(pid: u32) -> Option<ProcessInfo>
{
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(')')?;
    let fields: Vec<&str> = fields.split_whitespace().collect();
    let state = fields.first()?;
    let start = fields.get(19)?;
    Some(ProcessInfo {
        zombie: *state == "Z" || *state == "X",
        start: (*start).to_string(),
    })
}

#[cfg(not(target_os = "linux"))]
async fn process_info(pid: u32) -> Option<ProcessInfo>
{
    let output = tokio::process::Command::new("ps")
        .args(["-o", "stat=,lstart=", "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success()
    {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    let (state, start) = text.split_once(char::is_whitespace)?;
    Some(ProcessInfo {
        zombie: state.contains('Z'),
        start: start.trim().to_string(),
    })
}

async fn is_alive(identity: &ProcessIdentity) -> bool
{
    let Some(marker) = &identity.marker
    else
    {
        return false;
    };
    match process_info(identity.pid).await
    {
        Some(info) =>
        {
            !info.zombie && *marker == info.start
        }
        None => false,
    }
}

fn pid_exists(pid: u32) -> Result<bool, SandboxError>
{
    let pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| SandboxError::InvalidSpec("invalid fake sandbox pid".into()))?;
    match nix::sys::signal::kill(Pid::from_raw(pid), None)
    {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_identity(paths: &FakePaths) -> Option<ProcessIdentity>
{
    let bytes = fs::read(&paths.process).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn read_exit_code(paths: &FakePaths) -> Option<Option<i32>>
{
    fs::read_to_string(&paths.exit_code)
        .ok()
        .map(|text| text.trim().parse().ok())
}

fn cap_plain_log(path: &Path, max_bytes: u64) -> Result<(), SandboxError>
{
    let mut file = match fs::OpenOptions::new().read(true).write(true).open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) =>
        {
            return Err(SandboxError::Io {
                context: format!("open {}", path.display()),
                source: error,
            });
        }
    };
    let length = file
        .metadata()
        .map_err(io(format!("stat {}", path.display())))?
        .len();
    if length <= max_bytes
    {
        return Ok(());
    }
    let mut newest = Vec::new();
    file.seek(SeekFrom::Start(length - max_bytes))
        .and_then(|_| file.read_to_end(&mut newest))
        .map_err(io(format!("read {}", path.display())))?;
    fs::write(path, newest).map_err(io(format!("rewrite {}", path.display())))
}

fn wrapper_script(paths: &FakePaths, writer: Option<&[String]>) -> Result<String, SandboxError>
{
    let console = quote(&path_text(&paths.console)?);
    let fifo = quote(&path_text(&paths.console_fifo)?);
    let exit_code = quote(&path_text(&paths.exit_code)?);
    let exit_code_tmp = quote(&format!("{}.tmp", path_text(&paths.exit_code)?));
    let pid = quote(&path_text(&paths.pid)?);
    let (setup, output) = match writer
    {
        Some(writer) => (
            format!(
                "rm -f {fifo}\nmkfifo -m 600 {fifo}\n( trap '' TERM INT HUP; exec {} < {fifo} ) &\n",
                join(writer)
            ),
            format!("> {fifo} 2>&1"),
        ),
        None => (String::new(), format!(">> {console} 2>&1")),
    };
    Ok(format!(
        "(\n\
         trap ':' TERM INT HUP\n\
         {setup}\"$@\" {output} &\n\
         child=$!\n\
         while :; do\n\
         wait \"$child\"\n\
         code=$?\n\
         kill -0 \"$child\" 2>/dev/null || break\n\
         done\n\
         printf '%s\\n' \"$code\" > {exit_code_tmp}\n\
         mv {exit_code_tmp} {exit_code}\n\
         ) </dev/null >/dev/null 2>&1 &\n\
         printf '%s\\n' \"$!\" > {pid}\n"
    ))
}

pub struct FakeSandbox
{
    config: FakeConfig,
    fail_adopt: AtomicBool,
    fail_recover: AtomicBool,
    launch_delay: std::sync::Mutex<Option<Duration>>,
    #[cfg(test)]
    launch_barriers: std::sync::Mutex<Option<(std::sync::Arc<tokio::sync::Barrier>, std::sync::Arc<tokio::sync::Barrier>)>>,
}

impl FakeSandbox
{
    pub fn new(config: FakeConfig) -> Self
    {
        Self {
            config,
            fail_adopt: AtomicBool::new(false),
            fail_recover: AtomicBool::new(false),
            launch_delay: std::sync::Mutex::new(None),
            #[cfg(test)]
            launch_barriers: std::sync::Mutex::new(None),
        }
    }

    pub fn config(&self) -> &FakeConfig
    {
        &self.config
    }

    /// Inject an uncertain adoption result without stopping the fake process.
    pub fn fail_next_adopt(&self)
    {
        self.fail_adopt.store(true, Ordering::SeqCst);
    }

    /// Inject an uncertain recovery result without changing process ownership.
    pub fn fail_next_recover(&self)
    {
        self.fail_recover.store(true, Ordering::SeqCst);
    }

    /// Delay the next new-process launch to exercise cancellation during setup.
    pub fn delay_next_launch(&self, delay: Duration)
    {
        *self.launch_delay.lock().unwrap() = Some(delay);
    }

    fn paths(&self, instance_id: &str) -> FakePaths
    {
        FakePaths::new(
            self.config.state_dir.join(instance_id),
            self.config.console_writer.is_some(),
        )
    }

    fn record_paths(record: &SandboxRecord) -> FakePaths
    {
        let ring = record
            .console_path
            .file_name()
            .is_some_and(|name| name == "console.ring");
        FakePaths::new(record.runtime_dir.clone(), ring)
    }

    pub fn memory_target(&self, instance_id: &str) -> Option<u64>
    {
        fs::read_to_string(self.paths(instance_id).memory_target)
            .ok()
            .and_then(|text| text.trim().parse().ok())
    }

    fn base_record(
        &self,
        instance_id: &str,
        generation: u64,
        paths: &FakePaths,
        pid: Option<u32>,
    ) -> SandboxRecord
    {
        SandboxRecord {
            instance_id: instance_id.to_owned(),
            generation,
            kind: SandboxKind::Fake,
            unit_name: format!("fake:{instance_id}"),
            api_socket: None,
            guest_socket: paths.guest_socket.clone(),
            console_path: paths.console.clone(),
            cgroup_path: None,
            metrics_path: None,
            pid,
            runtime_dir: paths.dir.clone(),
        }
    }

    async fn spawn(
        &self,
        spec: &SandboxSpec,
        paths: &FakePaths,
    ) -> Result<ProcessIdentity, SandboxError>
    {
        let writer = match &self.config.console_writer
        {
            Some(writer) => Some(writer_argv(writer, &paths.console, spec.console_max_bytes)?),
            None => None,
        };
        let script = wrapper_script(paths, writer.as_deref())?;
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            // Each instance runs in its own directory, as a guest has its own filesystem,
            // so programs that write relative to their working directory stay apart.
            .current_dir(&paths.dir)
            .arg("-c")
            .arg(script)
            .arg("quarry-fake-sandbox")
            .arg(&self.config.program)
            .args(&self.config.args)
            .envs(&self.config.env)
            .envs(&spec.env)
            .env(
                AGENT_TRANSPORT_ENV,
                format!("unix:{}", path_text(&paths.guest_socket)?),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command.spawn().map_err(io("spawn fake sandbox wrapper"))?;
        let pgid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .ok_or_else(|| SandboxError::Io {
                context: "fake sandbox wrapper".into(),
                source: std::io::Error::other("wrapper exited before reporting its pid"),
            })?;
        let output = child
            .wait_with_output()
            .await
            .map_err(io("wait for fake sandbox wrapper"))?;
        if !output.status.success()
        {
            return Err(SandboxError::Command {
                program: "/bin/sh (fake sandbox wrapper)".into(),
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        let pid_text =
            fs::read_to_string(&paths.pid).map_err(io(format!("read {}", paths.pid.display())))?;
        let pid = pid_text
            .trim()
            .parse::<u32>()
            .map_err(|_| SandboxError::Io {
                context: format!("parse {}", paths.pid.display()),
                source: std::io::Error::other(format!("invalid pid {pid_text:?}")),
            })?;
        let marker = process_info(pid).await.map(|info| info.start);
        Ok(ProcessIdentity { pid, pgid, marker })
    }

    async fn signal_group(
        &self,
        identity: &ProcessIdentity,
        signal: Signal,
    ) -> Result<(), SandboxError>
    {
        match killpg(Pid::from_raw(identity.pgid), signal)
        {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn force_stop(&self, identity: &ProcessIdentity) -> Result<(), SandboxError>
    {
        if !is_alive(identity).await
        {
            return Ok(());
        }
        self.signal_group(identity, Signal::SIGKILL).await?;
        let deadline = Instant::now() + KILL_TIMEOUT;
        while is_alive(identity).await
        {
            if Instant::now() >= deadline
            {
                return Err(SandboxError::Timeout(format!(
                    "waiting for fake sandbox pid {} to exit after SIGKILL",
                    identity.pid
                )));
            }
            sleep(POLL_INTERVAL).await;
        }
        Ok(())
    }

    async fn abort(&self, identity: &ProcessIdentity, error: SandboxError) -> SandboxError
    {
        match self.force_stop(identity).await
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
        if record.kind == SandboxKind::Fake
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
impl Sandbox for FakeSandbox
{
    fn kind(&self) -> SandboxKind
    {
        SandboxKind::Fake
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
        control.check()?;
        validate_spec(spec)?;
        let paths = self.paths(&spec.instance_id);
        if let Some(identity) = read_identity(&paths)
            && is_alive(&identity).await
        {
            if let Err(error) = control.check()
            {
                return Err(self.abort(&identity, error).await);
            }
            let mut record = read_persisted_record(&paths.dir, &spec.instance_id)
                .unwrap_or_else(|| {
                    self.base_record(
                        &spec.instance_id,
                        spec.generation,
                        &paths,
                        Some(identity.pid),
                    )
                });
            record.pid = Some(identity.pid);
            return Ok(SandboxHandle::new(record));
        }
        let prepared = paths.clone();
        let ring = self.config.console_writer.is_some();
        let max_bytes = spec.console_max_bytes;
        let prepare_control = control.clone();
        blocking(move || {
            prepare_control.check()?;
            fs::create_dir_all(&prepared.dir)
                .map_err(io(format!("create {}", prepared.dir.display())))?;
            for stale in [
                &prepared.process,
                &prepared.pid,
                &prepared.exit_code,
                &prepared.dir.join(format!("{EXIT_CODE_FILE}.tmp")),
                &prepared.dir.join(crate::RECORD_FILE),
            ]
            {
                unit::remove_file_if_exists(stale)?;
            }
            if ring
            {
                Ok(())
            }
            else
            {
                cap_plain_log(&prepared.console, max_bytes)
            }
        })
        .await?;
        let delay = self.launch_delay.lock().unwrap().take();
        if let Some(delay) = delay
        {
            let started = Instant::now();
            loop
            {
                control.check()?;
                let remaining = delay.saturating_sub(started.elapsed());
                if remaining.is_zero()
                {
                    break;
                }
                sleep(remaining.min(Duration::from_millis(10))).await;
            }
        }
        control.check()?;
        let identity = self.spawn(spec, &paths).await?;
        #[cfg(test)]
        {
            let barriers = self.launch_barriers.lock().unwrap().take();
            if let Some((started, release)) = barriers
            {
                started.wait().await;
                release.wait().await;
            }
        }
        let authority = control.check();
        let record = self.base_record(
            &spec.instance_id,
            spec.generation,
            &paths,
            Some(identity.pid),
        );
        let process_file = paths.process.clone();
        let to_persist = record.clone();
        let to_persist_identity = identity.clone();
        let persisted = blocking(move || {
            let bytes = serde_json::to_vec(&to_persist_identity)?;
            fs::write(&process_file, bytes)
                .map_err(io(format!("write {}", process_file.display())))?;
            persist_record(&to_persist)
        })
        .await;
        if let Err(error) = persisted.and(authority).and_then(|()| control.check())
        {
            return Err(self.abort(&identity, error).await);
        }
        Ok(SandboxHandle::new(record))
    }

    async fn adopt(&self, record: &SandboxRecord) -> Result<Option<SandboxHandle>, SandboxError>
    {
        Self::check_kind(record)?;
        if self.fail_adopt.swap(false, Ordering::SeqCst)
        {
            return Err(SandboxError::Io {
                context: "fake sandbox adoption".into(),
                source: std::io::Error::other("injected adoption failure"),
            });
        }
        let paths = Self::record_paths(record);
        let Some(identity) = read_identity(&paths)
        else
        {
            return Ok(None);
        };
        if !is_alive(&identity).await
        {
            return Ok(None);
        }
        let mut record = record.clone();
        record.pid = Some(identity.pid);
        Ok(Some(SandboxHandle::new(record)))
    }

    async fn recover(
        &self,
        instance_id: &str,
        record: Option<&SandboxRecord>,
    ) -> Result<Option<SandboxHandle>, SandboxError>
    {
        validate_instance_id(instance_id)?;
        if self.fail_recover.swap(false, Ordering::SeqCst)
        {
            return Err(SandboxError::Io {
                context: "fake sandbox recovery".into(),
                source: std::io::Error::other("injected recovery failure"),
            });
        }
        if let Some(record) = record
        {
            Self::check_kind(record)?;
            if record.instance_id != instance_id
            {
                return Err(SandboxError::InvalidSpec(format!(
                    "sandbox recovery record does not belong to instance {instance_id}"
                )));
            }
        }
        let paths = record
            .map(Self::record_paths)
            .unwrap_or_else(|| self.paths(instance_id));
        if !paths
            .dir
            .try_exists()
            .map_err(io(format!("stat {}", paths.dir.display())))?
        {
            return if record
                .and_then(|record| record.pid)
                .map(pid_exists)
                .transpose()?
                .unwrap_or(false)
            {
                Err(SandboxError::Io {
                    context: format!("recover fake sandbox {instance_id}"),
                    source: std::io::Error::other("process identity directory is missing"),
                })
            }
            else
            {
                Ok(None)
            };
        }
        let identity: Option<ProcessIdentity> = match fs::read(&paths.process)
        {
            Ok(bytes) => Some(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io(format!("read {}", paths.process.display()))(error)),
        };
        let missing_identity_pid = if let Some(identity) = &identity
        {
            identity.marker.is_none().then_some(identity.pid)
        }
        else if let Some(pid) = record.and_then(|record| record.pid)
        {
            Some(pid)
        }
        else
        {
            match fs::read_to_string(&paths.pid)
            {
                Ok(pid) => Some(pid.trim().parse().map_err(|_| {
                    SandboxError::InvalidSpec("invalid fake sandbox pid file".into())
                })?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(io(format!("read {}", paths.pid.display()))(error)),
            }
        };
        if read_exit_code(&paths).is_none()
            && missing_identity_pid
                .map(pid_exists)
                .transpose()?
                .unwrap_or(false)
        {
            return Err(SandboxError::Io {
                context: format!("recover fake sandbox {instance_id}"),
                source: std::io::Error::other("durable process start identity is missing"),
            });
        }
        let mut recovered = record
            .cloned()
            .or_else(|| read_persisted_record(&paths.dir, instance_id))
            .unwrap_or_else(|| self.base_record(instance_id, 0, &paths, None));
        Self::check_kind(&recovered)?;
        recovered.pid = identity.map(|identity| identity.pid);
        Ok(Some(SandboxHandle::new(recovered)))
    }

    async fn shutdown(&self, handle: &SandboxHandle, mode: ShutdownMode)
    -> Result<(), SandboxError>
    {
        let paths = Self::record_paths(handle.record());
        let Some(identity) = read_identity(&paths)
        else
        {
            return Ok(());
        };
        match mode
        {
            ShutdownMode::Graceful =>
            {
                if is_alive(&identity).await
                {
                    self.signal_group(&identity, Signal::SIGTERM).await?;
                }
                Ok(())
            }
            ShutdownMode::Force => self.force_stop(&identity).await,
        }
    }

    async fn set_memory_target(
        &self,
        handle: &SandboxHandle,
        target_mib: u64,
    ) -> Result<(), SandboxError>
    {
        if target_mib == 0
        {
            return Err(SandboxError::InvalidSpec(
                "memory target must be at least 1 MiB".into(),
            ));
        }
        let path = Self::record_paths(handle.record()).memory_target;
        fs::write(&path, target_mib.to_string()).map_err(io(format!("write {}", path.display())))
    }

    async fn status(&self, handle: &SandboxHandle) -> Result<SandboxState, SandboxError>
    {
        let paths = Self::record_paths(handle.record());
        let Some(identity) = read_identity(&paths)
        else
        {
            return Ok(match read_exit_code(&paths)
            {
                Some(code) => SandboxState::Exited { code },
                None => SandboxState::Missing,
            });
        };
        if is_alive(&identity).await
        {
            return Ok(SandboxState::Running);
        }
        Ok(SandboxState::Exited {
            code: read_exit_code(&paths).flatten(),
        })
    }

    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SandboxError>
    {
        let paths = Self::record_paths(handle.record());
        if let Some(identity) = read_identity(&paths)
        {
            self.force_stop(&identity).await?;
        }
        blocking(move || {
            if !paths.guest_socket.starts_with(&paths.dir)
            {
                unit::remove_file_if_exists(&paths.guest_socket)?;
            }
            unit::remove_dir_if_exists(&paths.dir)
        })
        .await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::console::read_console;
    use crate::tests::sample_spec;

    fn sandbox(state_dir: &Path, script: &str) -> FakeSandbox
    {
        FakeSandbox::new(FakeConfig {
            state_dir: state_dir.to_path_buf(),
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), script.to_string()],
            env: BTreeMap::from([("FAKE_EXTRA".to_string(), "extra".to_string())]),
            console_writer: None,
        })
    }

    async fn wait_until_not_running(sandbox: &FakeSandbox, handle: &SandboxHandle) -> SandboxState
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop
        {
            let state = sandbox.status(handle).await.unwrap();
            if state != SandboxState::Running || Instant::now() >= deadline
            {
                return state;
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn wait_for_console(path: &Path, needle: &str) -> String
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop
        {
            let text = String::from_utf8_lossy(&read_console(path).unwrap()).into_owned();
            if text.contains(needle) || Instant::now() >= deadline
            {
                return text;
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    const TERM_EXITS_7: &str = "trap 'exit 7' TERM; echo \"started $QUARRY_AGENT_TRANSPORT $SERVER_JAR $FAKE_EXTRA\"; \
                                while :; do sleep 0.05; done";

    #[tokio::test]
    async fn graceful_shutdown_reports_the_exit_code()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), TERM_EXITS_7);
        let handle = sandbox.launch(&sample_spec("graceful")).await.unwrap();
        assert_eq!(handle.record().kind, SandboxKind::Fake);
        assert_eq!(
            sandbox.status(&handle).await.unwrap(),
            SandboxState::Running
        );
        let expected = format!(
            "started unix:{} paper.jar extra",
            sandbox.guest_socket_path("graceful").display()
        );
        let console = wait_for_console(&handle.record().console_path, &expected).await;
        assert!(console.contains(&expected), "console was {console:?}");

        sandbox
            .shutdown(&handle, ShutdownMode::Graceful)
            .await
            .unwrap();
        assert_eq!(
            wait_until_not_running(&sandbox, &handle).await,
            SandboxState::Exited { code: Some(7) }
        );
        sandbox
            .shutdown(&handle, ShutdownMode::Graceful)
            .await
            .unwrap();
        sandbox.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn force_kills_a_process_that_ignores_sigterm()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(
            directory.path(),
            "trap '' TERM; while :; do sleep 0.05; done",
        );
        let handle = sandbox.launch(&sample_spec("stubborn")).await.unwrap();
        sandbox
            .shutdown(&handle, ShutdownMode::Graceful)
            .await
            .unwrap();
        sleep(Duration::from_millis(300)).await;
        assert_eq!(
            sandbox.status(&handle).await.unwrap(),
            SandboxState::Running
        );
        sandbox
            .shutdown(&handle, ShutdownMode::Force)
            .await
            .unwrap();
        assert_eq!(
            sandbox.status(&handle).await.unwrap(),
            SandboxState::Exited { code: None }
        );
        let pid = handle.record().pid.unwrap();
        assert!(process_info(pid).await.is_none_or(|info| info.zombie));
        sandbox
            .shutdown(&handle, ShutdownMode::Force)
            .await
            .unwrap();
        sandbox.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn adopt_after_restart_keeps_the_same_process()
    {
        let directory = tempfile::tempdir().unwrap();
        let record = {
            let sandbox = sandbox(directory.path(), TERM_EXITS_7);
            let handle = sandbox.launch(&sample_spec("adopted")).await.unwrap();
            wait_for_console(&handle.record().console_path, "started").await;
            handle.into_record()
        };
        let serialized = serde_json::to_string(&record).unwrap();
        let record: SandboxRecord = serde_json::from_str(&serialized).unwrap();

        let restarted = sandbox(directory.path(), TERM_EXITS_7);
        let handle = restarted.adopt(&record).await.unwrap().unwrap();
        assert_eq!(handle.record().pid, record.pid);
        assert_eq!(
            restarted.status(&handle).await.unwrap(),
            SandboxState::Running
        );
        sleep(Duration::from_millis(100)).await;
        let console =
            String::from_utf8_lossy(&read_console(&record.console_path).unwrap()).into_owned();
        assert_eq!(console.matches("started").count(), 1);

        restarted
            .shutdown(&handle, ShutdownMode::Graceful)
            .await
            .unwrap();
        assert_eq!(
            wait_until_not_running(&restarted, &handle).await,
            SandboxState::Exited { code: Some(7) }
        );
        restarted.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn recover_without_a_committed_record_keeps_process_identity()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), TERM_EXITS_7);
        let handle = sandbox.launch(&sample_spec("recovering")).await.unwrap();
        let paths = FakeSandbox::record_paths(handle.record());
        fs::remove_file(paths.dir.join(crate::RECORD_FILE)).unwrap();

        let restarted = self::sandbox(directory.path(), TERM_EXITS_7);
        let recovered = restarted.recover("recovering", None).await.unwrap().unwrap();
        assert_eq!(recovered.record().pid, handle.record().pid);
        assert_eq!(recovered.record().runtime_dir, handle.record().runtime_dir);
        assert_eq!(
            restarted.status(&recovered).await.unwrap(),
            SandboxState::Running
        );
        restarted.destroy(&recovered).await.unwrap();
        assert!(restarted.recover("recovering", None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn recover_rejects_missing_or_corrupt_process_identity()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), TERM_EXITS_7);
        let handle = sandbox.launch(&sample_spec("uncertain")).await.unwrap();
        let paths = FakeSandbox::record_paths(handle.record());
        let identity = fs::read(&paths.process).unwrap();
        fs::remove_file(&paths.process).unwrap();
        assert!(sandbox.recover("uncertain", None).await.is_err());
        fs::write(&paths.process, b"broken").unwrap();
        assert!(
            sandbox.recover("uncertain", Some(handle.record())).await.is_err()
        );
        fs::write(&paths.process, identity).unwrap();
        assert_eq!(
            sandbox.status(&handle).await.unwrap(),
            SandboxState::Running
        );
        sandbox.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn failed_record_finalization_stops_the_launched_process()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), TERM_EXITS_7);
        let paths = sandbox.paths("finalization");
        fs::create_dir_all(paths.dir.join(format!("{}.tmp", crate::RECORD_FILE))).unwrap();

        assert!(sandbox.launch(&sample_spec("finalization")).await.is_err());
        let identity = read_identity(&paths).unwrap();
        assert!(!is_alive(&identity).await);
        let recovered = sandbox
            .recover("finalization", None)
            .await
            .unwrap()
            .unwrap();
        sandbox.destroy(&recovered).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_launch_does_not_spawn_a_process()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), TERM_EXITS_7);
        let control = LaunchControl::default();
        control.cancel();
        assert!(matches!(
            sandbox.launch_controlled(&sample_spec("cancelled"), control).await,
            Err(SandboxError::LaunchCancelled)
        ));
        assert!(!sandbox.paths("cancelled").dir.exists());
    }

    #[tokio::test]
    async fn cancellation_after_spawn_waits_for_cleanup_before_returning()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = std::sync::Arc::new(sandbox(directory.path(), TERM_EXITS_7));
        let started = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let release = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        *sandbox.launch_barriers.lock().unwrap() = Some((started.clone(), release.clone()));
        let control = LaunchControl::default();
        let worker_control = control.clone();
        let worker_sandbox = sandbox.clone();
        let worker = tokio::spawn(async move {
            worker_sandbox
                .launch_controlled(&sample_spec("revoked"), worker_control)
                .await
        });
        started.wait().await;
        control.cancel();
        release.wait().await;
        assert!(matches!(worker.await.unwrap(), Err(SandboxError::LaunchCancelled)));
        let identity = read_identity(&sandbox.paths("revoked")).unwrap();
        assert!(!is_alive(&identity).await);
        let recovered = sandbox.recover("revoked", None).await.unwrap().unwrap();
        sandbox.destroy(&recovered).await.unwrap();
    }

    #[test]
    fn fake_guest_socket_uses_the_process_credentials()
    {
        let sandbox = sandbox(Path::new("/unused"), "exit 0");
        assert_eq!(
            sandbox.guest_socket_owner(200_000, 200_000),
            (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw())
        );
    }

    #[tokio::test]
    async fn adopt_returns_none_for_a_dead_or_replaced_process()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), "exit 3");
        let handle = sandbox.launch(&sample_spec("dead")).await.unwrap();
        assert_eq!(
            wait_until_not_running(&sandbox, &handle).await,
            SandboxState::Exited { code: Some(3) }
        );
        assert!(sandbox.adopt(handle.record()).await.unwrap().is_none());

        let sleeper = self::sandbox(directory.path(), "while :; do sleep 0.05; done");
        let running = sleeper.launch(&sample_spec("replaced")).await.unwrap();
        let paths = FakeSandbox::record_paths(running.record());
        let mut identity = read_identity(&paths).unwrap();
        let original = identity.clone();
        identity.marker = Some("a different start time".into());
        fs::write(&paths.process, serde_json::to_vec(&identity).unwrap()).unwrap();
        assert!(sleeper.adopt(running.record()).await.unwrap().is_none());
        let recovered = sleeper.recover("replaced", None).await.unwrap().unwrap();
        sleeper
            .shutdown(&recovered, ShutdownMode::Force)
            .await
            .unwrap();
        assert!(is_alive(&original).await);
        fs::write(&paths.process, serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(sleeper.adopt(running.record()).await.unwrap().is_some());
        sleeper.destroy(&running).await.unwrap();
        sandbox.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn launch_is_idempotent()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), TERM_EXITS_7);
        let spec = sample_spec("twice");
        let first = sandbox.launch(&spec).await.unwrap();
        wait_for_console(&first.record().console_path, "started").await;
        let second = sandbox.launch(&spec).await.unwrap();
        assert_eq!(first.record(), second.record());
        sleep(Duration::from_millis(100)).await;
        let console = String::from_utf8_lossy(&read_console(&first.record().console_path).unwrap())
            .into_owned();
        assert_eq!(console.matches("started").count(), 1);
        sandbox.destroy(&first).await.unwrap();
    }

    #[tokio::test]
    async fn destroy_is_idempotent_and_removes_state()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(
            directory.path(),
            "trap '' TERM; while :; do sleep 0.05; done",
        );
        let handle = sandbox.launch(&sample_spec("doomed")).await.unwrap();
        let pid = handle.record().pid.unwrap();
        sandbox.destroy(&handle).await.unwrap();
        assert!(process_info(pid).await.is_none_or(|info| info.zombie));
        assert!(!handle.record().runtime_dir.exists());
        assert_eq!(
            sandbox.status(&handle).await.unwrap(),
            SandboxState::Missing
        );
        sandbox.destroy(&handle).await.unwrap();
        assert!(sandbox.adopt(handle.record()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn relaunch_after_exit_starts_a_new_process()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), "echo run; exit 0");
        let spec = sample_spec("again");
        let first = sandbox.launch(&spec).await.unwrap();
        assert_eq!(
            wait_until_not_running(&sandbox, &first).await,
            SandboxState::Exited { code: Some(0) }
        );
        let second = sandbox.launch(&spec).await.unwrap();
        assert_eq!(
            wait_until_not_running(&sandbox, &second).await,
            SandboxState::Exited { code: Some(0) }
        );
        let console =
            String::from_utf8_lossy(&read_console(&second.record().console_path).unwrap())
                .into_owned();
        assert_eq!(console.matches("run").count(), 2);
        sandbox.destroy(&second).await.unwrap();
    }

    #[tokio::test]
    async fn memory_targets_are_recorded()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), "while :; do sleep 0.05; done");
        let handle = sandbox.launch(&sample_spec("balloon")).await.unwrap();
        assert_eq!(sandbox.memory_target("balloon"), None);
        sandbox.set_memory_target(&handle, 1024).await.unwrap();
        assert_eq!(sandbox.memory_target("balloon"), Some(1024));
        assert!(sandbox.set_memory_target(&handle, 0).await.is_err());
        sandbox.destroy(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn console_writer_receives_output_and_survives_sigterm()
    {
        let directory = tempfile::tempdir().unwrap();
        let writer = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "while [ $# -gt 0 ]; do if [ \"$1\" = --path ]; then target=$2; fi; shift; done; cat > \"$target\""
                .to_string(),
            "test-console-writer".to_string(),
        ];
        let sandbox = FakeSandbox::new(FakeConfig {
            state_dir: directory.path().to_path_buf(),
            program: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".to_string(),
                "trap 'echo bye; exit 5' TERM; echo hi; while :; do sleep 0.05; done".to_string(),
            ],
            env: BTreeMap::new(),
            console_writer: Some(writer),
        });
        let handle = sandbox.launch(&sample_spec("piped")).await.unwrap();
        assert!(handle.record().console_path.ends_with("console.ring"));
        wait_for_console(&handle.record().console_path, "hi").await;
        sandbox
            .shutdown(&handle, ShutdownMode::Graceful)
            .await
            .unwrap();
        assert_eq!(
            wait_until_not_running(&sandbox, &handle).await,
            SandboxState::Exited { code: Some(5) }
        );
        let console = wait_for_console(&handle.record().console_path, "bye").await;
        assert!(
            console.starts_with("hi\n") && console.ends_with("bye\n"),
            "console was {console:?}"
        );
        sandbox.destroy(&handle).await.unwrap();
    }

    #[test]
    fn plain_logs_are_capped_to_the_newest_bytes()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("console.log");
        fs::write(&path, b"0123456789").unwrap();
        cap_plain_log(&path, 4).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"6789");
        cap_plain_log(&directory.path().join("absent"), 4).unwrap();
    }

    fn long_state_dir(root: &Path) -> PathBuf
    {
        let dir = root.join("a".repeat(60)).join("b".repeat(60));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn guest_socket_stays_in_a_short_instance_directory()
    {
        let dir = Path::new("/var/lib/quarryd/fake-sandbox/mc-1");
        assert_eq!(guest_socket_path(dir), dir.join("agent.sock"));
    }

    #[test]
    fn guest_socket_moves_to_a_short_stable_path_when_too_long()
    {
        let dir = PathBuf::from("/").join("d".repeat(120)).join("mc-1");
        let socket = guest_socket_path(&dir);
        assert!(
            socket.starts_with(std::env::temp_dir()),
            "{}",
            socket.display()
        );
        assert!(socket.as_os_str().len() <= MAX_SOCKET_PATH_BYTES);
        assert_eq!(guest_socket_path(&dir), socket);
        assert_ne!(guest_socket_path(&dir.with_file_name("mc-2")), socket);
    }

    #[test]
    fn guest_socket_paths_fit_on_this_host()
    {
        check_socket_paths().unwrap();
    }

    #[tokio::test]
    async fn destroy_removes_a_relocated_guest_socket()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(&long_state_dir(directory.path()), "sleep 30");
        let handle = sandbox.launch(&sample_spec("relocated")).await.unwrap();
        let socket = handle.record().guest_socket.clone();
        assert!(!socket.starts_with(&handle.record().runtime_dir));
        assert_eq!(sandbox.guest_socket_path("relocated"), socket);
        fs::write(&socket, b"").unwrap();
        sandbox.destroy(&handle).await.unwrap();
        assert!(!socket.exists());
        assert!(!handle.record().runtime_dir.exists());
    }

    #[tokio::test]
    async fn the_program_runs_in_the_instance_directory()
    {
        let directory = tempfile::tempdir().unwrap();
        let sandbox = sandbox(directory.path(), "pwd -P; exit 0");
        let handle = sandbox.launch(&sample_spec("cwd")).await.unwrap();
        wait_until_not_running(&sandbox, &handle).await;
        let console =
            String::from_utf8_lossy(&read_console(&handle.record().console_path).unwrap())
                .into_owned();
        let expected = handle.record().runtime_dir.canonicalize().unwrap();
        assert_eq!(console.trim(), expected.display().to_string());
        sandbox.destroy(&handle).await.unwrap();
    }
}
