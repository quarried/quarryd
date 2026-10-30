use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::error::NetworkError;

pub(crate) async fn run(
    program: &Path,
    args: &[String],
    stdin: Option<&[u8]>,
    netns: Option<&File>,
) -> Result<String, NetworkError>
{
    let display = format!("{} {}", program.display(), args.join(" "));
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(
            if stdin.is_some()
            {
                Stdio::piped()
            }
            else
            {
                Stdio::null()
            },
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(netns) = netns
    {
        let netns_fd = netns.as_raw_fd();
        // SAFETY: setns is async-signal-safe and only touches the forked child before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setns(netns_fd, libc::CLONE_NEWNET) == 0
                {
                    Ok(())
                }
                else
                {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| NetworkError::io(format!("starting {display}"), e))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take())
    {
        pipe.write_all(input)
            .await
            .map_err(|e| NetworkError::io(format!("writing to {display}"), e))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| NetworkError::io(format!("waiting for {display}"), e))?;
    if !output.status.success()
    {
        return Err(NetworkError::Command {
            command: display,
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(crate) fn failed_with(error: &NetworkError, matches: impl Fn(&str) -> bool) -> bool
{
    matches!(error, NetworkError::Command { stderr, .. } if matches(stderr))
}
