use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::sys::signal::Signal;
use tokio::time::{Instant, sleep};

use crate::console::tail_console;
use crate::shell::{path_text, quote};
use crate::unit_bus::UnitBus;
use crate::{SandboxError, SandboxState};

pub(crate) const EXIT_STATUS_FILE: &str = "exit_status";
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
const UNLOAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONSOLE_TAIL_BYTES: usize = 2048;

pub(crate) fn is_running_state(state: &str) -> bool
{
    matches!(
        state,
        "active" | "activating" | "deactivating" | "reloading" | "refreshing"
    )
}

pub(crate) fn exit_status_command(exit_file: &Path) -> Result<Vec<String>, SandboxError>
{
    Ok(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!(
            "printf '%s %s\\n' \"$EXIT_CODE\" \"$EXIT_STATUS\" > {}",
            quote(&path_text(exit_file)?)
        ),
    ])
}

pub(crate) fn parse_exit_status(text: &str) -> Option<i32>
{
    let mut parts = text.split_whitespace();
    match (parts.next(), parts.next())
    {
        (Some("exited"), Some(status)) => status.parse().ok(),
        _ => None,
    }
}

fn read_exit_status(exit_file: &Path) -> Option<Option<i32>>
{
    std::fs::read_to_string(exit_file)
        .ok()
        .map(|text| parse_exit_status(&text))
}

pub(crate) async fn status(
    systemd: &UnitBus,
    unit: &str,
    exit_file: &Path,
) -> Result<SandboxState, SandboxError>
{
    let state = systemd.unit_active_state(unit).await?;
    Ok(match state
    {
        Some(state) if is_running_state(&state) => SandboxState::Running,
        Some(_) => SandboxState::Exited {
            code: read_exit_status(exit_file).flatten(),
        },
        None => match read_exit_status(exit_file)
        {
            Some(code) => SandboxState::Exited { code },
            None => SandboxState::Missing,
        },
    })
}

pub(crate) async fn is_running(systemd: &UnitBus, unit: &str) -> Result<bool, SandboxError>
{
    Ok(systemd
        .unit_active_state(unit)
        .await?
        .is_some_and(|state| is_running_state(&state)))
}

pub(crate) async fn clear_stale_unit(systemd: &UnitBus, unit: &str) -> Result<(), SandboxError>
{
    systemd.reset_failed_unit(unit).await?;
    let deadline = Instant::now() + UNLOAD_TIMEOUT;
    loop
    {
        match systemd.unit_active_state(unit).await?
        {
            None => return Ok(()),
            Some(state) if is_running_state(&state) =>
            {
                return Err(SandboxError::UnitFailed {
                    unit: unit.to_string(),
                    detail: format!("unit became {state} while clearing a stale instance"),
                });
            }
            Some(_) if Instant::now() >= deadline =>
            {
                return Err(SandboxError::Timeout(format!(
                    "waiting for stale unit {unit} to unload"
                )));
            }
            Some(_) =>
            {
                systemd.reset_failed_unit(unit).await?;
                sleep(POLL_INTERVAL).await;
            }
        }
    }
}

pub(crate) fn failure_detail(state: &str, console: &Path) -> String
{
    let tail = tail_console(console, CONSOLE_TAIL_BYTES).unwrap_or_default();
    format!(
        "state {state}; console tail: {}",
        String::from_utf8_lossy(&tail)
    )
}

pub(crate) async fn wait_until_active(
    systemd: &UnitBus,
    unit: &str,
    exit_file: &Path,
    console: &Path,
) -> Result<(), SandboxError>
{
    let deadline = Instant::now() + START_TIMEOUT;
    loop
    {
        let state = systemd.unit_active_state(unit).await?;
        match state.as_deref()
        {
            Some("active") => return Ok(()),
            Some("failed") | None =>
            {
                return Err(SandboxError::UnitFailed {
                    unit: unit.to_string(),
                    detail: failure_detail(state.as_deref().unwrap_or("unloaded"), console),
                });
            }
            Some(other) if exit_file.exists() =>
            {
                return Err(SandboxError::UnitFailed {
                    unit: unit.to_string(),
                    detail: failure_detail(other, console),
                });
            }
            Some(_) if Instant::now() >= deadline =>
            {
                return Err(SandboxError::Timeout(format!(
                    "waiting for unit {unit} to become active"
                )));
            }
            Some(_) => sleep(POLL_INTERVAL).await,
        }
    }
}

pub(crate) async fn ensure_running(
    systemd: &UnitBus,
    unit: &str,
    console: &Path,
) -> Result<(), SandboxError>
{
    match systemd.unit_active_state(unit).await?
    {
        Some(state) if is_running_state(&state) => Ok(()),
        state => Err(SandboxError::UnitFailed {
            unit: unit.to_string(),
            detail: failure_detail(state.as_deref().unwrap_or("unloaded"), console),
        }),
    }
}

pub(crate) async fn kill_and_wait(systemd: &UnitBus, unit: &str) -> Result<(), SandboxError>
{
    if !is_running(systemd, unit).await?
    {
        return Ok(());
    }
    if let Err(error) = systemd.kill_unit(unit, Signal::SIGKILL).await
        && is_running(systemd, unit).await?
    {
        return Err(error);
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while is_running(systemd, unit).await?
    {
        if Instant::now() >= deadline
        {
            return Err(SandboxError::Timeout(format!(
                "waiting for unit {unit} to stop after SIGKILL"
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
    Ok(())
}

pub(crate) async fn cgroup_path(
    systemd: &UnitBus,
    unit: &str,
) -> Result<Option<PathBuf>, SandboxError>
{
    Ok(systemd
        .unit_control_group(unit)
        .await?
        .map(|group| PathBuf::from(format!("/sys/fs/cgroup{group}"))))
}

pub(crate) async fn blocking<T, F>(work: F) -> Result<T, SandboxError>
where
    F: FnOnce() -> Result<T, SandboxError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| SandboxError::Io {
            context: "blocking sandbox task".into(),
            source: std::io::Error::other(error),
        })?
}

pub(crate) fn remove_file_if_exists(path: &Path) -> Result<(), SandboxError>
{
    match std::fs::remove_file(path)
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SandboxError::Io {
            context: format!("remove {}", path.display()),
            source: error,
        }),
    }
}

pub(crate) fn remove_dir_if_exists(path: &Path) -> Result<(), SandboxError>
{
    match std::fs::remove_dir_all(path)
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SandboxError::Io {
            context: format!("remove {}", path.display()),
            source: error,
        }),
    }
}

pub(crate) fn chown_if_exists(path: &Path, uid: u32, gid: u32) -> Result<(), SandboxError>
{
    match std::os::unix::fs::lchown(path, Some(uid), Some(gid))
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SandboxError::Io {
            context: format!("chown {}", path.display()),
            source: error,
        }),
    }
}

pub(crate) async fn run_command(program: &Path, args: &[String]) -> Result<Vec<u8>, SandboxError>
{
    let output = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(crate::error::io(format!("run {}", program.display())))?;
    if output.status.success()
    {
        Ok(output.stdout)
    }
    else
    {
        Err(SandboxError::Command {
            program: format!("{} {}", program.display(), args.join(" ")),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn exit_status_lines_are_parsed()
    {
        assert_eq!(parse_exit_status("exited 0\n"), Some(0));
        assert_eq!(parse_exit_status("exited 3"), Some(3));
        assert_eq!(parse_exit_status("killed KILL\n"), None);
        assert_eq!(parse_exit_status(" \n"), None);
    }

    #[test]
    fn running_states_include_transitions()
    {
        assert!(is_running_state("active"));
        assert!(is_running_state("deactivating"));
        assert!(!is_running_state("failed"));
        assert!(!is_running_state("inactive"));
    }

    #[tokio::test]
    async fn exit_status_command_records_both_fields()
    {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("exit status");
        let argv = exit_status_command(&file).unwrap();
        let status = tokio::process::Command::new(&argv[0])
            .args(&argv[1..])
            .env("EXIT_CODE", "exited")
            .env("EXIT_STATUS", "42")
            .status()
            .await
            .unwrap();
        assert!(status.success());
        assert_eq!(read_exit_status(&file), Some(Some(42)));
    }

    #[tokio::test]
    async fn failing_commands_report_stderr()
    {
        let error = run_command(
            Path::new("/bin/sh"),
            &["-c".into(), "echo nope >&2; exit 4".into()],
        )
        .await
        .unwrap_err();
        match error
        {
            SandboxError::Command { status, stderr, .. } =>
            {
                assert_eq!(status, Some(4));
                assert_eq!(stderr, "nope");
            }
            other => panic!("unexpected error {other:?}"),
        }
    }
}
