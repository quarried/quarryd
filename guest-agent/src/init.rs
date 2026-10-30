use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::mount::{MsFlags, mount, umount};
use nix::sys::reboot::{RebootMode, reboot};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
use nix::unistd::{Pid, sync};
use tokio::signal::unix::{SignalKind, signal};

use crate::server::DATA_DIR;
use crate::snapshot;

pub const DATA_DEVICE: &str = "/dev/vdb";
const REAP_SWEEP: Duration = Duration::from_secs(5);
const FINAL_REAP_LIMIT: Duration = Duration::from_secs(2);
const STOP_MODES: [RebootMode; 2] = [RebootMode::RB_AUTOBOOT, RebootMode::RB_POWER_OFF];

#[derive(Debug, PartialEq, Eq)]
pub struct MountPoint
{
    pub source: PathBuf,
    pub target: PathBuf,
    pub fstype: &'static str,
    pub flags: MsFlags,
    pub data: Option<&'static str>,
    pub required: bool,
}

pub fn vm_mounts(root: &Path, data_device: &Path) -> Vec<MountPoint>
{
    let common = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    let entry = |source: &Path,
                 target: &str,
                 fstype: &'static str,
                 flags: MsFlags,
                 data: Option<&'static str>,
                 required: bool| MountPoint {
        source: source.to_path_buf(),
        target: root.join(target),
        fstype,
        flags,
        data,
        required,
    };
    vec![
        entry(
            Path::new("proc"),
            "proc",
            "proc",
            common | MsFlags::MS_NOEXEC,
            None,
            false,
        ),
        entry(
            Path::new("sysfs"),
            "sys",
            "sysfs",
            common | MsFlags::MS_NOEXEC,
            None,
            false,
        ),
        entry(
            Path::new("devtmpfs"),
            "dev",
            "devtmpfs",
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
            false,
        ),
        entry(
            Path::new("tmpfs"),
            "run",
            "tmpfs",
            common,
            Some("mode=0755"),
            false,
        ),
        entry(
            Path::new("tmpfs"),
            "tmp",
            "tmpfs",
            common,
            Some("mode=1777"),
            false,
        ),
        entry(data_device, "data", "ext4", common, None, true),
    ]
}

pub fn mount_vm_filesystems(root: &Path, data_device: &Path) -> Result<(), String>
{
    for point in vm_mounts(root, data_device)
    {
        if let Err(error) = std::fs::create_dir_all(&point.target)
            && !point.target.is_dir()
        {
            log!("cannot create {}: {error}", point.target.display());
        }
        if snapshot::is_mount_point(&point.target).unwrap_or(false)
        {
            log!("{} is already mounted", point.target.display());
            continue;
        }
        let result = mount(
            Some(point.source.as_path()),
            point.target.as_path(),
            Some(point.fstype),
            point.flags,
            point.data,
        );
        match result
        {
            Ok(()) =>
            {}
            Err(errno) if point.required =>
            {
                return Err(format!(
                    "cannot mount {} on {}: {errno}",
                    point.source.display(),
                    point.target.display()
                ));
            }
            Err(errno) => log!(
                "cannot mount {} on {}: {errno}",
                point.fstype,
                point.target.display()
            ),
        }
    }
    Ok(())
}

pub fn spawn_reaper(server_pid: Arc<AtomicU32>) -> std::io::Result<()>
{
    let mut child_exits = signal(SignalKind::child())?;
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(REAP_SWEEP);
        loop
        {
            tokio::select! {
                _ = child_exits.recv() => {}
                _ = sweep.tick() => {}
            }
            reap_orphans(server_pid.load(Ordering::Relaxed));
        }
    });
    Ok(())
}

fn reap_orphans(server_pid: u32)
{
    loop
    {
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
        let Ok(status) = waitid(Id::All, flags)
        else
        {
            return;
        };
        let Some(pid) = status.pid()
        else
        {
            return;
        };
        if u32::try_from(pid.as_raw()).ok() == Some(server_pid)
        {
            return;
        }
        let _ = waitpid(pid, Some(WaitPidFlag::WNOHANG));
    }
}

pub fn stop_vm_on_panic()
{
    std::panic::set_hook(Box::new(|info| {
        log!("panic: {info}");
        stop_vm();
    }));
}

pub fn stop_vm() -> !
{
    log!("stopping the VM");
    sync();
    let _ = kill(Pid::from_raw(-1), Signal::SIGKILL);
    let limit = Instant::now() + FINAL_REAP_LIMIT;
    while Instant::now() < limit
    {
        match waitpid(None::<Pid>, Some(WaitPidFlag::WNOHANG))
        {
            Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(20)),
            Ok(_) =>
            {}
            Err(_) => break,
        }
    }
    let data = Path::new(DATA_DIR);
    if let Err(error) = snapshot::thaw(data)
    {
        log!("{error}");
    }
    match umount(data)
    {
        Ok(()) | Err(Errno::EINVAL) | Err(Errno::ENOENT) =>
        {}
        Err(errno) => log!("cannot unmount {DATA_DIR}: {errno}"),
    }
    sync();
    for mode in STOP_MODES
    {
        let Err(errno) = reboot(mode);
        log!("reboot({mode:?}) failed: {errno}");
    }
    loop
    {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::process::Command;

    #[test]
    fn the_vm_mount_table_covers_the_pid1_filesystems()
    {
        let mounts = vm_mounts(Path::new("/"), Path::new(DATA_DEVICE));
        let summary: Vec<(&str, &str, bool)> = mounts
            .iter()
            .map(|point| (point.target.to_str().unwrap(), point.fstype, point.required))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("/proc", "proc", false),
                ("/sys", "sysfs", false),
                ("/dev", "devtmpfs", false),
                ("/run", "tmpfs", false),
                ("/tmp", "tmpfs", false),
                ("/data", "ext4", true),
            ]
        );
        assert_eq!(mounts[5].source, PathBuf::from("/dev/vdb"));
        assert!(
            mounts
                .iter()
                .all(|point| point.flags.contains(MsFlags::MS_NOSUID))
        );
    }

    #[test]
    fn the_vm_is_stopped_by_rebooting_before_powering_off()
    {
        assert_eq!(
            STOP_MODES,
            [RebootMode::RB_AUTOBOOT, RebootMode::RB_POWER_OFF]
        );
    }

    fn run(program: &str, arguments: &[&str]) -> String
    {
        let output = Command::new(program).args(arguments).output().unwrap();
        assert!(output.status.success(), "{program} {arguments:?} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    #[ignore = "needs root on Linux with mkfs.ext4, losetup and loop devices (mounts proc, sysfs, devtmpfs, tmpfs, ext4)"]
    fn pid1_filesystems_are_mounted_under_a_root()
    {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let image = scratch.path().join("data.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        run("mkfs.ext4", &["-q", "-F", image.to_str().unwrap()]);
        let device = run("losetup", &["--find", "--show", image.to_str().unwrap()]);
        let result = mount_vm_filesystems(&root, Path::new(&device));
        let mounted: Vec<bool> = ["proc", "sys", "dev", "run", "tmp", "data"]
            .iter()
            .map(|name| snapshot::is_mount_point(&root.join(name)).unwrap_or(false))
            .collect();
        let has_proc_self = root.join("proc/self/status").exists();
        let has_dev_null = root.join("dev/null").exists();
        let has_lost_found = root.join("data/lost+found").is_dir();
        let second = mount_vm_filesystems(&root, Path::new(&device));
        for name in ["data", "tmp", "run", "dev", "sys", "proc"]
        {
            let target = root.join(name);
            while snapshot::is_mount_point(&target).unwrap_or(false)
            {
                if umount(&target).is_err()
                {
                    break;
                }
            }
        }
        run("losetup", &["-d", &device]);
        assert_eq!(result, Ok(()));
        assert_eq!(mounted, vec![true; 6]);
        assert!(has_proc_self && has_dev_null && has_lost_found);
        assert_eq!(second, Ok(()));
    }
}
