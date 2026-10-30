use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, setns, unshare};
use nix::sys::statfs::{NSFS_MAGIC, statfs};

use crate::error::NetworkError;

const THREAD_NETNS: &str = "/proc/thread-self/ns/net";

fn errno_error(context: String, errno: Errno) -> NetworkError
{
    NetworkError::io(context, std::io::Error::from(errno))
}

pub(crate) async fn run_inside<T, F>(netns_path: &Path, work: F) -> Result<T, NetworkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, NetworkError> + Send + 'static,
{
    let netns_path = netns_path.to_path_buf();
    let context = format!("running inside network namespace {}", netns_path.display());
    on_dedicated_thread(context, move || {
        let netns = open(&netns_path)?;
        setns(&netns, CloneFlags::CLONE_NEWNET).map_err(|e| {
            errno_error(
                format!("entering network namespace {}", netns_path.display()),
                e,
            )
        })?;
        work()
    })
    .await
}

pub(crate) fn open(netns_path: &Path) -> Result<File, NetworkError>
{
    File::open(netns_path).map_err(|e| {
        NetworkError::io(
            format!("opening network namespace {}", netns_path.display()),
            e,
        )
    })
}

pub(crate) fn exists(netns_path: &Path) -> Result<bool, NetworkError>
{
    match statfs(netns_path)
    {
        Ok(stat) => Ok(stat.filesystem_type() == NSFS_MAGIC),
        Err(Errno::ENOENT) => Ok(false),
        Err(e) => Err(errno_error(
            format!("inspecting {}", netns_path.display()),
            e,
        )),
    }
}

pub(crate) async fn create(netns_path: &Path) -> Result<(), NetworkError>
{
    if exists(netns_path)?
    {
        return Ok(());
    }
    let directory = netns_path
        .parent()
        .ok_or_else(|| {
            NetworkError::io(
                format!("{} has no parent directory", netns_path.display()),
                std::io::Error::from(ErrorKind::InvalidInput),
            )
        })?
        .to_path_buf();
    make_shared_directory(&directory)?;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o444)
        .open(netns_path)
        .map_err(|e| {
            NetworkError::io(format!("creating mount point {}", netns_path.display()), e)
        })?;
    let target = netns_path.to_path_buf();
    let context = format!("creating network namespace {}", target.display());
    let created = on_dedicated_thread(context, move || {
        unshare(CloneFlags::CLONE_NEWNET)
            .map_err(|e| errno_error("unsharing the network namespace".to_string(), e))?;
        mount(
            Some(THREAD_NETNS),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            errno_error(
                format!("bind-mounting the namespace onto {}", target.display()),
                e,
            )
        })
    })
    .await;
    if created.is_err()
    {
        remove_mount_point(netns_path)?;
    }
    created
}

pub(crate) fn remove(netns_path: &Path) -> Result<(), NetworkError>
{
    match umount2(netns_path, MntFlags::MNT_DETACH)
    {
        Ok(()) | Err(Errno::EINVAL) | Err(Errno::ENOENT) =>
        {}
        Err(e) =>
        {
            return Err(errno_error(
                format!("unmounting {}", netns_path.display()),
                e,
            ));
        }
    }
    remove_mount_point(netns_path)
}

fn remove_mount_point(netns_path: &Path) -> Result<(), NetworkError>
{
    match fs::remove_file(netns_path)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NetworkError::io(
            format!("removing {}", netns_path.display()),
            e,
        )),
    }
}

fn make_shared_directory(directory: &Path) -> Result<(), NetworkError>
{
    fs::create_dir_all(directory)
        .map_err(|e| NetworkError::io(format!("creating {}", directory.display()), e))?;
    let make_shared = || {
        mount(
            None::<&str>,
            directory,
            None::<&str>,
            MsFlags::MS_SHARED | MsFlags::MS_REC,
            None::<&str>,
        )
    };
    match make_shared()
    {
        Ok(()) => Ok(()),
        Err(Errno::EINVAL) =>
        {
            mount(
                Some(directory),
                directory,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
            .map_err(|e| {
                errno_error(
                    format!("bind-mounting {} onto itself", directory.display()),
                    e,
                )
            })?;
            make_shared().map_err(|e| {
                errno_error(format!("making {} a shared mount", directory.display()), e)
            })
        }
        Err(e) => Err(errno_error(
            format!("making {} a shared mount", directory.display()),
            e,
        )),
    }
}

async fn on_dedicated_thread<T, F>(context: String, work: F) -> Result<T, NetworkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, NetworkError> + Send + 'static,
{
    let panicked = |context: &str| {
        NetworkError::io(
            context.to_string(),
            std::io::Error::other("worker thread panicked"),
        )
    };
    let blocking_context = context.clone();
    tokio::task::spawn_blocking(move || {
        std::thread::Builder::new()
            .name("quarry-netns".to_string())
            .spawn(work)
            .map_err(|e| NetworkError::io(blocking_context.clone(), e))?
            .join()
            .map_err(|_| panicked(&blocking_context))?
    })
    .await
    .map_err(|_| panicked(&context))?
}
