#![cfg(target_os = "linux")]

use std::path::Path;

use network::{Networking, NetworkingConfig};
use proto::v1::{Isolation, Phase};
use sandbox::Sandbox;
use sandbox::firecracker::{Firecracker, FirecrackerConfig};
use sandbox::gvisor::{Gvisor, GvisorConfig};
use sandbox::unit_bus::UnitBus;
use volume::LvmThin;

use super::*;

const BOOT_WAIT: Duration = Duration::from_secs(300);

fn env(name: &str) -> String
{
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to run this test"))
}

fn env_or(name: &str, default: &str) -> String
{
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn console_writer() -> Vec<String>
{
    env("QUARRY_TEST_CONSOLE_WRITER")
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

async fn publish_file(fixture: &Fixture, variable: &str, name: &str) -> ArtifactRef
{
    let content = std::fs::read(env(variable)).unwrap();
    publish(&fixture.objects, &fixture.keypair, name, &content).await
}

async fn start_real(
    fixture: &Fixture,
    sandbox: Arc<dyn Sandbox>,
) -> (ReconcilerHandle, Arc<Volumes>)
{
    let volumes = Arc::new(Volumes::new(Arc::new(LvmThin::new(
        env("QUARRY_TEST_LVM_VG"),
        env("QUARRY_TEST_LVM_POOL"),
    ))));
    let network =
        Arc::new(Networking::new(NetworkingConfig::new(fixture.path("network"))).unwrap());
    let images = Arc::new(
        ImageCache::new(
            fixture.path("images"),
            fixture.objects.clone(),
            &fixture.keypair.pk.to_base64(),
            fixture.store.clone(),
            20 * GIB,
        )
        .unwrap(),
    );
    let parts = ReconcilerParts {
        store: fixture.store.clone(),
        sandbox,
        volumes: volumes.clone(),
        network,
        images,
        snapshots: None,
        metrics: Arc::new(Metrics::new("node-test")),
    };
    let (handle, mut receiver) = Reconciler::start(fixture.config(), parts).await.unwrap();
    tokio::spawn(async move {
        while receiver.recv().await.is_some()
        {}
    });
    (handle, volumes)
}

async fn wait_until(
    handle: &ReconcilerHandle,
    id: &str,
    what: &str,
    done: impl Fn(Option<&InstanceStatus>) -> bool,
)
{
    let deadline = tokio::time::Instant::now() + BOOT_WAIT;
    loop
    {
        let status = handle.statuses().into_iter().find(|status| status.id == id);
        if done(status.as_ref())
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{id} never reached {what}: {status:?}"
        );
        sleep_ms(250).await;
    }
}

async fn run_end_to_end(
    mut fixture: Fixture,
    isolation: Isolation,
    make_sandbox: impl Fn(&Path) -> Arc<dyn Sandbox>,
)
{
    fixture.guest_connect_timeout = Duration::from_secs(120);
    fixture.ready_timeout = BOOT_WAIT;
    fixture.stop_deadline = Duration::from_secs(60);
    fixture.kill_deadline = Duration::from_secs(10);
    let id = "e2e-1";
    let mut spec = fixture.spec(id, "normal");
    spec.isolation = isolation as i32;
    spec.env.clear();
    spec.memory_mib = env_or("QUARRY_TEST_MEMORY_MIB", "2048").parse().unwrap();
    spec.vcpus = 2;
    spec.disks[0].size_gib = 2;

    let (handle, volumes) = start_real(&fixture, make_sandbox(fixture.dir.path())).await;
    handle.configure_network(network_config()).await.unwrap();
    handle.put_instance(spec.clone()).await.unwrap();
    wait_until(&handle, id, "RUNNING", |status| {
        status.is_some_and(|s| phase_of(s) == Phase::Running)
    })
    .await;
    let record = fixture
        .store
        .get_instance(id)
        .unwrap()
        .unwrap()
        .sandbox_record;
    assert!(record.is_some());
    handle.send_console_command(id, "list").await.unwrap();
    handle.shutdown().await;

    let (handle, _) = start_real(&fixture, make_sandbox(fixture.dir.path())).await;
    let adopted = handle
        .statuses()
        .into_iter()
        .find(|status| status.id == id)
        .unwrap();
    assert_eq!(phase_of(&adopted), Phase::Running);
    assert_eq!(
        fixture
            .store
            .get_instance(id)
            .unwrap()
            .unwrap()
            .sandbox_record,
        record
    );
    handle.put_instance(spec).await.unwrap();
    sleep_ms(2000).await;
    assert_eq!(
        fixture
            .store
            .get_instance(id)
            .unwrap()
            .unwrap()
            .sandbox_record,
        record
    );

    handle.delete_instance(id).await.unwrap();
    wait_until(&handle, id, "deletion", |status| status.is_none()).await;
    assert!(fixture.store.get_instance(id).unwrap().is_none());
    assert!(volumes.backend().get("e2e-1-data").await.unwrap().is_none());
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs root, KVM, systemd, Firecracker, jailer, LVM thin pool and a guest kernel/rootfs (QUARRY_TEST_* env vars)"]
async fn firecracker_instance_runs_end_to_end()
{
    let mut fixture = Fixture::new().await;
    fixture.kernel = publish_file(&fixture, "QUARRY_TEST_KERNEL", "vmlinux-e2e").await;
    fixture.rootfs = publish_file(&fixture, "QUARRY_TEST_ROOTFS", "rootfs-e2e").await;
    let systemd = UnitBus::connect().await.unwrap();
    run_end_to_end(fixture, Isolation::Firecracker, |_| {
        let config = FirecrackerConfig {
            firecracker_bin: PathBuf::from(env("QUARRY_TEST_FIRECRACKER")),
            jailer_bin: PathBuf::from(env("QUARRY_TEST_JAILER")),
            chroot_base_dir: PathBuf::from(env_or("QUARRY_TEST_CHROOT_BASE", "/srv/jailer")),
            console_writer: console_writer(),
            cgroup_version: env_or("QUARRY_TEST_CGROUP_VERSION", "2").parse().unwrap(),
            slice: None,
        };
        Arc::new(Firecracker::new(config, systemd.clone()).unwrap())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs root, systemd, runsc, LVM thin pool and a guest rootfs (QUARRY_TEST_* env vars)"]
async fn gvisor_instance_runs_end_to_end()
{
    let mut fixture = Fixture::new().await;
    fixture.rootfs = publish_file(&fixture, "QUARRY_TEST_ROOTFS", "rootfs-e2e").await;
    let systemd = UnitBus::connect().await.unwrap();
    run_end_to_end(fixture, Isolation::Gvisor, |dir| {
        let config = GvisorConfig {
            runsc_bin: PathBuf::from(env("QUARRY_TEST_RUNSC")),
            runsc_root: PathBuf::from(env_or("QUARRY_TEST_RUNSC_ROOT", "/run/quarry-test-runsc")),
            bundle_base_dir: dir.join("bundles"),
            console_writer: console_writer(),
            slice: None,
        };
        Arc::new(Gvisor::new(config, systemd.clone()).unwrap())
    })
    .await;
}
