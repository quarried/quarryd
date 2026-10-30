use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

use crate::NetworkError;

const DELETE_TIMEOUT: Duration = Duration::from_secs(30);

/// The caller must first block the retiring public address and guest in nftables.
/// Original-destination matches incoming DNAT/REDIRECT connections; reply-destination
/// matches outgoing SNAT connections. Both are needed before reusing an address.
pub(crate) async fn remove_public_address(
    program: &Path,
    address: Ipv4Addr,
) -> Result<(), NetworkError>
{
    for direction in ["--orig-dst", "--reply-dst"]
    {
        let address = address.to_string();
        let args = ["--delete", "--family", "ipv4", direction, &address];
        let display = format!("{} {}", program.display(), args.join(" "));
        let output = timeout(
            DELETE_TIMEOUT,
            Command::new(program)
                .args(args)
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                // Deleted entries contain peer details and can be numerous.
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| {
            NetworkError::io(
                format!("waiting for {display}"),
                std::io::Error::new(std::io::ErrorKind::TimedOut, "conntrack deletion timed out"),
            )
        })?
        .map_err(|error| {
            let context = if error.kind() == std::io::ErrorKind::NotFound
            {
                format!("running {display}; dedicated public IPv4 networking requires conntrack-tools (Debian/Ubuntu: apt install conntrack)")
            }
            else
            {
                format!("running {display}")
            };
            NetworkError::io(context, error)
        })?;
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !output.status.success()
            && !(output.status.code() == Some(1) && no_entries_deleted(&stderr))
        {
            return Err(NetworkError::Command {
                command: display,
                status: output.status.to_string(),
                stderr,
            });
        }
    }
    Ok(())
}

fn no_entries_deleted(stderr: &str) -> bool
{
    !stderr.contains('\n')
        && stderr.starts_with("conntrack v")
        && stderr.ends_with(" (conntrack-tools): 0 flow entries have been deleted.")
}

#[cfg(test)]
mod tests
{
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    // A concurrently forked test helper can briefly inherit another test's open
    // executable writer before exec closes it, making Linux return ETXTBSY.
    static COMMAND_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn executable(directory: &Path, body: &str) -> std::path::PathBuf
    {
        let path = directory.join("conntrack");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[tokio::test]
    async fn deletes_both_nat_directions_and_all_transport_protocols()
    {
        let _serial = COMMAND_TESTS.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let program = executable(
            directory.path(),
            "printf '%s\\n' \"$*\" >> \"$0.args\"\nexit 0",
        );
        remove_public_address(&program, Ipv4Addr::new(203, 0, 113, 9))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(directory.path().join("conntrack.args")).unwrap(),
            "--delete --family ipv4 --orig-dst 203.0.113.9\n\
             --delete --family ipv4 --reply-dst 203.0.113.9\n"
        );
    }

    #[tokio::test]
    async fn repeated_cleanup_accepts_only_the_zero_deletions_exit_one()
    {
        let _serial = COMMAND_TESTS.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let program = executable(
            directory.path(),
            "echo 'conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.' >&2\nexit 1",
        );
        remove_public_address(&program, Ipv4Addr::new(203, 0, 113, 9))
            .await
            .unwrap();
        for error in [
            "conntrack v1.4.8 (conntrack-tools): Operation failed: you must be root or get CAP_NET_ADMIN capability to do this",
            "conntrack v1.4.8 (conntrack-tools): 1 flow entries have been deleted.",
            "netlink failure\nconntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.",
        ]
        {
            let directory = tempfile::tempdir().unwrap();
            let program = executable(directory.path(), &format!("echo '{error}' >&2\nexit 1"));
            assert!(matches!(
                remove_public_address(&program, Ipv4Addr::new(203, 0, 113, 9)).await,
                Err(NetworkError::Command { .. })
            ));
        }
    }

    #[tokio::test]
    async fn a_reply_direction_failure_is_reported_and_can_be_retried()
    {
        let _serial = COMMAND_TESTS.lock().await;
        let directory = tempfile::tempdir().unwrap();
        let program = executable(
            directory.path(),
            "if [ \"$4\" = '--reply-dst' ]; then echo 'netlink failure' >&2; exit 1; fi\nexit 0",
        );
        assert!(matches!(
            remove_public_address(&program, Ipv4Addr::new(203, 0, 113, 9)).await,
            Err(NetworkError::Command { command, .. }) if command.contains("--reply-dst")
        ));
        executable(
            directory.path(),
            "echo 'conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.' >&2\nexit 1",
        );
        remove_public_address(&program, Ipv4Addr::new(203, 0, 113, 9))
            .await
            .unwrap();
    }
}
