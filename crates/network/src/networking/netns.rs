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
const HOST_MOUNTNS: &str = "/proc/1/ns/mnt";

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
    let netns = open(&netns_path)?;
    let context = format!("running inside network namespace {}", netns_path.display());
    on_dedicated_thread(context, move || {
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
    let netns_path = netns_path.to_path_buf();
    let context = format!("opening network namespace {}", netns_path.display());
    on_host_mount_thread(context.clone(), move || {
        File::open(&netns_path).map_err(|e| NetworkError::io(context, e))
    })
}

pub(crate) fn exists(netns_path: &Path) -> Result<bool, NetworkError>
{
    let netns_path = netns_path.to_path_buf();
    let context = format!("inspecting network namespace {}", netns_path.display());
    on_host_mount_thread(context, move || exists_here(&netns_path))
}

fn exists_here(netns_path: &Path) -> Result<bool, NetworkError>
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
    let netns_path = netns_path.to_path_buf();
    let context = format!("creating network namespace {}", netns_path.display());
    on_dedicated_thread(context, move || {
        enter_host_mount_namespace()?;
        create_here(&netns_path)
    })
    .await
}

fn create_here(netns_path: &Path) -> Result<(), NetworkError>
{
    if exists_here(netns_path)?
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
    let created = (|| {
        unshare(CloneFlags::CLONE_NEWNET)
            .map_err(|e| errno_error("unsharing the network namespace".to_string(), e))?;
        mount(
            Some(THREAD_NETNS),
            netns_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            errno_error(
                format!("bind-mounting the namespace onto {}", netns_path.display()),
                e,
            )
        })
    })();
    if created.is_err()
    {
        remove_mount_point(netns_path)?;
    }
    created
}

pub(crate) fn remove(netns_path: &Path) -> Result<(), NetworkError>
{
    let netns_path = netns_path.to_path_buf();
    let context = format!("removing network namespace {}", netns_path.display());
    on_host_mount_thread(context, move || remove_here(&netns_path))
}

fn remove_here(netns_path: &Path) -> Result<(), NetworkError>
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
    let blocking_context = context.clone();
    tokio::task::spawn_blocking(move || dedicated_thread(blocking_context, work))
        .await
        .map_err(|_| worker_panicked(context))?
}

fn dedicated_thread<T, F>(context: String, work: F) -> Result<T, NetworkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, NetworkError> + Send + 'static,
{
    // Never run setns on a Tokio worker, including its reusable blocking pool.
    // A fresh OS thread exits after the operation, also on errors or panics.
    std::thread::Builder::new()
        .name("quarry-netns".to_string())
        .spawn(work)
        .map_err(|e| NetworkError::io(context.clone(), e))?
        .join()
        .map_err(|_| worker_panicked(context))?
}

fn worker_panicked(context: String) -> NetworkError
{
    NetworkError::io(context, std::io::Error::other("worker thread panicked"))
}

fn on_host_mount_thread<T, F>(context: String, work: F) -> Result<T, NetworkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, NetworkError> + Send + 'static,
{
    dedicated_thread(context, move || {
        enter_host_mount_namespace()?;
        work()
    })
}

fn enter_host_mount_namespace() -> Result<(), NetworkError>
{
    // systemd's filesystem protections prevent mounts made by quarryd from
    // propagating to the independently launched VM units. Persist and look up
    // namespace mounts in PID 1's mount namespace instead. CLONE_FS must be
    // unshared first: Rust threads otherwise share the root/cwd with callers,
    // and Linux refuses mount setns while those attributes are shared.
    let host = File::open(HOST_MOUNTNS)
        .map_err(|e| NetworkError::io("opening the host mount namespace".to_string(), e))?;
    unshare(CloneFlags::CLONE_FS)
        .map_err(|e| errno_error("unsharing filesystem attributes".to_string(), e))?;
    setns(&host, CloneFlags::CLONE_NEWNS)
        .map_err(|e| errno_error("entering the host mount namespace".to_string(), e))
}

#[cfg(test)]
mod tests
{
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use super::*;

    const THREAD_MOUNTNS: &str = "/proc/thread-self/ns/mnt";

    struct NamespaceCleanup(PathBuf);

    impl Drop for NamespaceCleanup
    {
        fn drop(&mut self)
        {
            let _ = remove(&self.0);
        }
    }

    fn isolate_mounts() -> Result<PathBuf, NetworkError>
    {
        unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_FS)
            .map_err(|e| errno_error("isolating test mounts".to_string(), e))?;
        // Stronger than systemd's slave propagation: host-side changes cannot
        // reach this worker, so open/exists must also use the host's view.
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| errno_error("isolating test mount propagation".to_string(), e))?;
        Ok(fs::read_link(THREAD_MOUNTNS).unwrap())
    }

    #[tokio::test]
    #[ignore = "needs root with CAP_SYS_ADMIN and CAP_SYS_CHROOT in PID 1's mount namespace on Linux"]
    async fn namespace_mounts_survive_private_service_mount_namespaces()
    {
        let original_mount = fs::read_link(THREAD_MOUNTNS).unwrap();
        let original_network = fs::read_link(THREAD_NETNS).unwrap();
        assert_eq!(original_mount, fs::read_link(HOST_MOUNTNS).unwrap());
        let path = PathBuf::from(format!(
            "/run/netns/quarry-mount-test-{}",
            std::process::id()
        ));
        assert!(!path.exists(), "test namespace already exists");
        let _cleanup = NamespaceCleanup(path.clone());

        let target = path.clone();
        let inode =
            on_dedicated_thread("test isolated namespace creation".to_string(), move || {
                let private_mount = isolate_mounts()?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(create(&target))?;
                assert_eq!(fs::read_link(THREAD_MOUNTNS).unwrap(), private_mount);
                assert!(!exists_here(&target)?);
                assert!(exists(&target)?);
                let inode = open(&target)?.metadata().unwrap().ino();
                runtime.block_on(create(&target))?;
                assert_eq!(open(&target)?.metadata().unwrap().ino(), inode);
                assert!(
                    runtime
                        .block_on(create(&target.join("invalid-child")))
                        .is_err()
                );
                assert_eq!(fs::read_link(THREAD_MOUNTNS).unwrap(), private_mount);
                Ok(inode)
            })
            .await
            .unwrap();

        // The creating service and its private mount namespace are now gone.
        assert!(exists_here(&path).unwrap());
        assert_eq!(File::open(&path).unwrap().metadata().unwrap().ino(), inode);
        assert_eq!(fs::read_link(THREAD_MOUNTNS).unwrap(), original_mount);
        assert_eq!(fs::read_link(THREAD_NETNS).unwrap(), original_network);

        let target = path.clone();
        on_dedicated_thread("test isolated namespace removal".to_string(), move || {
            let private_mount = isolate_mounts()?;
            remove(&target)?;
            remove(&target)?;
            assert!(!exists(&target)?);
            assert_eq!(fs::read_link(THREAD_MOUNTNS).unwrap(), private_mount);
            Ok(())
        })
        .await
        .unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read_link(THREAD_MOUNTNS).unwrap(), original_mount);
        assert_eq!(fs::read_link(THREAD_NETNS).unwrap(), original_network);
    }
}
