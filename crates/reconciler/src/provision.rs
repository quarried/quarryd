use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use network::{AttachMode, InstanceNetworkSpec, NetworkAttachment, guest_mac};
use proto::v1::{ArtifactRef, InstanceSpec};
use sandbox::{SandboxKind, SandboxNetwork, SandboxSpec};
use volume::{ArtifactDescriptor, ArtifactKind, VolumeInfo};

use crate::ReconcilerError;
use crate::admission::volume_name;
use crate::reconciler::lock;
use crate::supervisor::Supervisor;

const GIB: u64 = 1024 * 1024 * 1024;
const RESTORE_PENDING: &str = "pending:";
const RESTORE_DONE: &str = "done:";

/// Everything a boot needs, produced by preparation (section 7).
#[derive(Clone, Debug)]
pub(crate) struct Prepared
{
    pub generation: u64,
    pub kernel: Option<PathBuf>,
    pub rootfs: PathBuf,
    pub volume: VolumeInfo,
    pub uid: u32,
    pub attachment: NetworkAttachment,
}

pub(crate) fn restore_key(volume: &str) -> String
{
    format!("reconciler/restore/{volume}")
}

fn descriptor(artifact: &ArtifactRef) -> ArtifactDescriptor
{
    ArtifactDescriptor {
        digest: artifact.digest.clone(),
        key: artifact.key.clone(),
        signature_key: artifact.signature_key.clone(),
        size_bytes: artifact.size_bytes,
    }
}

pub(crate) fn pinned_cpus(total: u32, reserved: u32, slot: u32, vcpus: u32) -> Vec<u32>
{
    let total = total.max(1);
    let pool: Vec<u32> = if reserved < total
    {
        (reserved..total).collect()
    }
    else
    {
        (0..total).collect()
    };
    let count = (vcpus.max(1) as usize).min(pool.len());
    let start = (slot as usize).wrapping_mul(count) % pool.len();
    (0..count)
        .map(|offset| pool[(start + offset) % pool.len()])
        .collect()
}

impl Supervisor
{
    pub(crate) async fn prepare(&mut self, spec: &InstanceSpec)
    -> Result<Prepared, ReconcilerError>
    {
        let started = Instant::now();
        let parts = &self.inner.parts;
        let kind = parts.sandbox.kind();
        parts.images.release_instance(&self.id)?;
        let kernel = if kind == SandboxKind::Firecracker
        {
            let kernel = spec
                .kernel
                .as_ref()
                .ok_or(ReconcilerError::MissingField("kernel"))?;
            Some(self.fetch(kernel, ArtifactKind::Kernel).await?)
        }
        else
        {
            None
        };
        let image = spec
            .image
            .as_ref()
            .ok_or(ReconcilerError::MissingField("image"))?;
        let rootfs = self.fetch(image, ArtifactKind::Rootfs).await?;
        self.checkpoint("after-artifacts").await;

        let volume = self.ensure_volume(spec).await?;
        self.checkpoint("after-volume").await;

        let uid = self.inner.parts.store.allocate_uid(
            &self.id,
            self.inner.config.uid_base,
            self.inner.config.uid_count,
        )?;
        self.uid = Some(uid);
        let guest_ip = {
            let mut ipam = lock(&self.inner.ipam);
            ipam.as_mut()
                .ok_or(ReconcilerError::NetworkNotConfigured)?
                .allocate(&self.id)?
        };
        self.guest_ip = Some(guest_ip);
        self.commit()?;

        let network = spec.network.clone().unwrap_or_default();
        let ports = network
            .ports
            .iter()
            .filter_map(|port| u16::try_from(*port).ok())
            .collect();
        let attach = InstanceNetworkSpec {
            instance_id: self.id.clone(),
            world_id: network.world_id.clone(),
            guest_ip,
            guest_mac: guest_mac(guest_ip),
            egress_mbit: network.egress_mbit,
            ports,
            mode: match kind
            {
                SandboxKind::Firecracker => AttachMode::Tap,
                SandboxKind::Gvisor | SandboxKind::Fake => AttachMode::Veth,
            },
            uid,
            gid: uid,
        };
        let attachment = self.inner.parts.network.attach(&attach).await?;
        self.attachment = Some(attachment.clone());
        self.commit()?;
        self.checkpoint("after-attach").await;
        tracing::info!(
            generation = spec.generation,
            guest_ip = %guest_ip,
            volume = %volume.name,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "instance prepared"
        );
        Ok(Prepared {
            generation: spec.generation,
            kernel,
            rootfs,
            volume,
            uid,
            attachment,
        })
    }

    async fn fetch(
        &self,
        artifact: &ArtifactRef,
        kind: ArtifactKind,
    ) -> Result<PathBuf, ReconcilerError>
    {
        let images = &self.inner.parts.images;
        images.acquire(&artifact.digest, &self.id)?;
        let cached = images.ensure(&descriptor(artifact), kind).await?;
        self.inner.parts.metrics.record_artifact_cache(cached.hit);
        tracing::info!(
            kind = kind.as_str(),
            digest = %artifact.digest,
            hit = cached.hit,
            "artifact ready"
        );
        Ok(cached.path)
    }

    async fn ensure_volume(&self, spec: &InstanceSpec) -> Result<VolumeInfo, ReconcilerError>
    {
        let disk = spec
            .disks
            .first()
            .ok_or(ReconcilerError::MissingField("disk"))?;
        let name = volume_name(&self.id, &disk.name);
        let size = disk.size_gib.saturating_mul(GIB);
        let volumes = &self.inner.parts.volumes;
        let manifest = disk
            .restore_from
            .as_ref()
            .map(|snapshot| snapshot.manifest_key.clone())
            .filter(|key| !key.is_empty());
        let Some(manifest) = manifest
        else
        {
            return Ok(volumes.ensure(&name, size).await?);
        };
        let store = &self.inner.parts.store;
        let key = restore_key(&name);
        let marker = store
            .kv_get(&key)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        match marker
        {
            Some(marker) if marker.starts_with(RESTORE_DONE) =>
            {
                return Ok(volumes.ensure(&name, size).await?);
            }
            Some(_) =>
            {
                tracing::warn!(volume = %name, "an interrupted restore is being redone");
                volumes.remove(&name).await?;
            }
            None =>
            {
                if let Some(existing) = volumes.backend().get(&name).await?
                {
                    return Ok(existing);
                }
            }
        }
        let snapshots = self
            .inner
            .parts
            .snapshots
            .as_ref()
            .ok_or(ReconcilerError::SnapshotsUnavailable)?;
        store.kv_set(&key, format!("{RESTORE_PENDING}{manifest}").as_bytes())?;
        let info = volumes.ensure_blank(&name, size).await?;
        self.checkpoint("after-blank-volume").await;
        tracing::info!(volume = %name, manifest_key = %manifest, "restoring world snapshot");
        snapshots.restore(&manifest, &info.path).await?;
        store.kv_set(&key, format!("{RESTORE_DONE}{manifest}").as_bytes())?;
        Ok(info)
    }

    fn sandbox_spec(&self, prepared: &Prepared, spec: &InstanceSpec) -> SandboxSpec
    {
        let config = &self.inner.config;
        let attachment = &prepared.attachment;
        let cpu_pinning = spec.cpu_pinning.then(|| {
            pinned_cpus(
                config.capacity.vcpus,
                config.reservation.vcpus,
                prepared.uid.saturating_sub(config.uid_base),
                spec.vcpus,
            )
        });
        SandboxSpec {
            instance_id: self.id.clone(),
            generation: spec.generation,
            vcpus: spec.vcpus,
            memory_mib: spec.memory_mib,
            kernel: prepared.kernel.clone(),
            rootfs: prepared.rootfs.clone(),
            data_volume: prepared.volume.path.clone(),
            network: SandboxNetwork {
                netns_path: attachment.netns_path.clone(),
                tap_name: attachment.tap_name.clone(),
                guest_ip: attachment.guest_ip,
                gateway: attachment.gateway,
                prefix_len: attachment.prefix_len,
                guest_mac: attachment.guest_mac.clone(),
            },
            env: spec
                .env
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
            uid: prepared.uid,
            gid: prepared.uid,
            cpu_pinning,
            console_max_bytes: config.console_max_bytes,
        }
    }

    pub(crate) async fn launch(&mut self) -> Result<(), ReconcilerError>
    {
        let prepared = self
            .prepared
            .clone()
            .ok_or(ReconcilerError::MissingField("prepared resources"))?;
        let spec = self
            .running_spec
            .clone()
            .ok_or(ReconcilerError::MissingField("spec"))?;
        self.bind_guest()?;
        let sandbox_spec = self.sandbox_spec(&prepared, &spec);
        let sandbox = Arc::clone(&self.inner.parts.sandbox);
        let handle = tokio::spawn(async move { sandbox.launch(&sandbox_spec).await }).await??;
        tracing::info!(
            unit = %handle.record().unit_name,
            pid = ?handle.record().pid,
            "sandbox launched"
        );
        self.handle = Some(handle);
        self.commit()?;
        self.checkpoint("after-launch").await;
        Ok(())
    }

    pub(crate) async fn release_resources(
        &mut self,
        spec: &InstanceSpec,
    ) -> Result<(), ReconcilerError>
    {
        let parts = &self.inner.parts;
        parts.network.detach(&self.id).await?;
        if let Some(ipam) = lock(&self.inner.ipam).as_mut()
        {
            ipam.release(&self.id);
        }
        self.checkpoint("after-detach").await;
        for disk in &spec.disks
        {
            let name = volume_name(&self.id, &disk.name);
            parts.volumes.remove(&name).await?;
            parts.store.kv_delete(&restore_key(&name))?;
        }
        parts.images.release_instance(&self.id)?;
        let dir = self.inner.config.state_dir.join(&self.id);
        match tokio::fs::remove_dir_all(&dir).await
        {
            Ok(()) =>
            {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound =>
            {}
            Err(error) =>
            {
                return Err(ReconcilerError::io(format!("remove {}", dir.display()))(
                    error,
                ));
            }
        }
        parts.metrics.remove_instance(&self.id);
        tracing::info!("instance resources released");
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn pinning_is_deterministic_and_skips_reserved_cpus()
    {
        assert_eq!(pinned_cpus(8, 2, 0, 2), vec![2, 3]);
        assert_eq!(pinned_cpus(8, 2, 1, 2), vec![4, 5]);
        assert_eq!(pinned_cpus(8, 2, 2, 2), vec![6, 7]);
        assert_eq!(pinned_cpus(8, 2, 3, 2), vec![2, 3]);
        assert_eq!(pinned_cpus(8, 2, 0, 16), vec![2, 3, 4, 5, 6, 7]);
        assert_eq!(pinned_cpus(4, 4, 0, 1), vec![0]);
        assert_eq!(pinned_cpus(8, 2, 5, 3), pinned_cpus(8, 2, 5, 3));
    }
}
