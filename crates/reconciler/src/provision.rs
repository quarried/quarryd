use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use network::{AttachMode, InstanceNetworkSpec, NetworkAttachment, guest_mac};
use proto::v1::{ArtifactRef, InstanceSpec};
use sandbox::{LaunchControl, SandboxKind, SandboxNetwork, SandboxSpec};
use volume::{ArtifactDescriptor, ArtifactKind, VolumeInfo};

use crate::ReconcilerError;
use crate::admission::{legacy_volume_name, volume_name};
use crate::reconciler::{Inner, decode_spec, lock};
use crate::supervisor::Supervisor;

const GIB: u64 = 1024 * 1024 * 1024;
const RESTORE_PENDING: &str = "pending:";
const RESTORE_DONE: &str = "done:";

/// A dropped supervisor future must also withdraw a detached launch worker's
/// permission to start. Backends retain ownership until cancellation settles.
struct CancelLaunchOnDrop(LaunchControl);

impl Drop for CancelLaunchOnDrop
{
    fn drop(&mut self)
    {
        self.0.cancel();
    }
}

/// Everything a boot needs, produced by preparation (section 7).
#[derive(Clone, Debug)]
pub(crate) struct Prepared
{
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

/// Resolve an old disk in place or claim a new collision-resistant name. The
/// binding is durable before any volume mutation, including creation.
pub(crate) async fn resolve_disk_name(
    inner: &Inner,
    instance_id: &str,
    disk_name: &str,
) -> Result<String, ReconcilerError>
{
    let _guard = inner.disk_lock.lock().await;
    resolve_disk_name_locked(inner, instance_id, disk_name).await
}

async fn resolve_disk_name_locked(
    inner: &Inner,
    instance_id: &str,
    disk_name: &str,
) -> Result<String, ReconcilerError>
{
    let store = &inner.parts.store;
    if let Some(name) = store.disk_binding(instance_id, disk_name)?
    {
        store.assert_disk_owner(instance_id, &name)?;
        return Ok(name);
    }
    let backend = inner.parts.volumes.backend();
    let fresh = volume_name(instance_id, disk_name);
    let legacy = legacy_volume_name(instance_id, disk_name);
    let legacy_exists = backend.get(&legacy).await?.is_some();
    let legacy_tracked = store.instance_disks(instance_id)?.contains(&legacy);
    if legacy_tracked
    {
        store.assert_disk_owner(instance_id, &legacy)?;
    }
    let unbound_legacy = (legacy_exists || legacy_tracked) && store.bound_disk(&legacy)?.is_none();
    let name = if unbound_legacy
    {
        if !legacy_tracked
        {
            let detail = "pre-existing legacy volume has no durable owner; manual ownership recovery is required";
            store.quarantine_disk(&legacy, detail)?;
            return Err(store::StoreError::DiskOwnership {
                name: legacy,
                detail: detail.to_owned(),
            }
            .into());
        }
        // Prior releases recorded only sanitized names. Check every desired and
        // applied spec before giving the old name to the first startup caller.
        for row in store.list_instances()?
        {
            for bytes in std::iter::once(row.spec.as_slice()).chain(row.applied_spec.as_deref())
            {
                let spec = decode_spec(bytes)?;
                for disk in &spec.disks
                {
                    if (row.id != instance_id || disk.name != disk_name)
                        && legacy_volume_name(&row.id, &disk.name) == legacy
                    {
                        let detail =
                            format!("legacy name also matches {:?}/{:?}", row.id, disk.name);
                        store.quarantine_disk(&legacy, &detail)?;
                        return Err(store::StoreError::DiskOwnership {
                            name: legacy,
                            detail,
                        }
                        .into());
                    }
                }
            }
        }
        if fresh != legacy && backend.get(&fresh).await?.is_some()
        {
            let detail = format!("both legacy and new volume {fresh:?} exist without a binding");
            store.quarantine_disk(&legacy, &detail)?;
            store.quarantine_disk(&fresh, &detail)?;
            return Err(store::StoreError::DiskOwnership {
                name: legacy,
                detail,
            }
            .into());
        }
        legacy
    }
    else
    {
        if backend.get(&fresh).await?.is_some()
        {
            // Never adopt an unrelated pre-existing LV merely because its name
            // happens to match the generated identity.
            store.assert_disk_owner(instance_id, &fresh)?;
        }
        fresh
    };
    store.claim_disk(instance_id, disk_name, &name)?;
    Ok(name)
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
        if network.public_ipv4.is_empty()
        {
            self.inner.parts.network.detach_public(&self.id).await?;
        }
        else
        {
            self.inner
                .parts
                .network
                .validate_public_ipv4(&self.id, &network.public_ipv4)?;
            let address = network.public_ipv4.parse().map_err(|_| {
                network::NetworkError::InvalidNodeNetwork(format!(
                    "invalid public IPv4 {}",
                    network.public_ipv4
                ))
            })?;
            self.inner
                .parts
                .network
                .attach_public(&self.id, address)
                .await?;
            self.inner
                .parts
                .network
                .set_public_mode(&self.id, network::PublicIpMode::Starting)
                .await?;
        }
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
        let name = resolve_disk_name(&self.inner, &self.id, &disk.name).await?;
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
                if volumes.backend().get(&name).await?.is_some()
                {
                    return Ok(volumes.ensure(&name, size).await?);
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

    pub(crate) async fn cleanup_replaced_disks(&self) -> Result<(), ReconcilerError>
    {
        let _disk_guard = self.inner.disk_lock.lock().await;
        let Some(row) = self.inner.parts.store.get_instance(&self.id)?
        else
        {
            return Ok(());
        };
        if row.generation != self.observed_generation || row.desired_deleted
        {
            return Ok(());
        }
        let desired = crate::reconciler::decode_spec(&row.spec)?;
        let Some(applied) = self.running_spec.as_deref()
        else
        {
            return Ok(());
        };
        if !crate::supervisor::same_runtime_spec(applied, &desired)
        {
            return Ok(());
        }
        let mut keep = Vec::new();
        for disk in &applied.disks
        {
            keep.push(resolve_disk_name_locked(&self.inner, &self.id, &disk.name).await?);
        }
        for name in self.inner.parts.store.instance_disks(&self.id)?
        {
            if !keep.contains(&name)
            {
                self.inner.parts.store.assert_disk_owner(&self.id, &name)?;
                self.inner.parts.volumes.remove(&name).await?;
                self.inner.parts.store.kv_delete(&restore_key(&name))?;
                self.inner.parts.store.forget_disk(&self.id, &name)?;
            }
        }
        Ok(())
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
            .prepared_spec
            .clone()
            .ok_or(ReconcilerError::MissingField("spec"))?;
        self.bind_guest()?;
        let mut authority_lost = self.launch_authority_lost(Arc::clone(&spec));
        // Poll the authority guard before giving the backend any permission.
        tokio::select! {
            biased;
            error = &mut authority_lost => return Err(error),
            _ = std::future::ready(()) => {}
        }
        let sandbox_spec = self.sandbox_spec(&prepared, &spec);
        let sandbox = Arc::clone(&self.inner.parts.sandbox);
        let control = LaunchControl::default();
        let _cancel_on_drop = CancelLaunchOnDrop(control.clone());
        let worker_control = control.clone();
        let mut worker = tokio::spawn(async move {
            sandbox
                .launch_controlled(&sandbox_spec, worker_control)
                .await
        });
        let handle = tokio::select! {
            biased;
            error = &mut authority_lost => {
                control.cancel();
                // Never release/reuse the disk, UID or network while a launch
                // worker can still complete. The backend observes cancellation
                // during preparation/readiness and settles its unit ownership.
                match worker.await {
                    Ok(Ok(handle)) => {
                        // Cancellation can race the final successful return.
                        // Persist the handle so fail()/recovery must stop it.
                        self.handle = Some(handle);
                        self.running_spec = Some(spec);
                        self.commit()?;
                    }
                    Ok(Err(cleanup)) => tracing::warn!(error = %cleanup, "cancelled launch completed with an error; sandbox recovery will verify cleanup"),
                    Err(cleanup) => tracing::warn!(error = %cleanup, "cancelled launch task failed; sandbox recovery will verify cleanup"),
                }
                return Err(error);
            }
            result = &mut worker => result??,
        };
        tracing::info!(
            unit = %handle.record().unit_name,
            pid = ?handle.record().pid,
            "sandbox launched"
        );
        self.handle = Some(handle);
        self.running_spec = Some(spec);
        self.commit()?;
        self.checkpoint("after-launch").await;
        Ok(())
    }

    pub(crate) async fn release_resources(
        &mut self,
        _spec: &InstanceSpec,
    ) -> Result<(), ReconcilerError>
    {
        let parts = &self.inner.parts;
        parts.network.detach_public(&self.id).await?;
        parts.network.detach(&self.id).await?;
        if let Some(ipam) = lock(&self.inner.ipam).as_mut()
        {
            ipam.release(&self.id);
        }
        self.checkpoint("after-detach").await;
        let _disk_guard = self.inner.disk_lock.lock().await;
        for name in parts.store.instance_disks(&self.id)?
        {
            parts.store.assert_disk_owner(&self.id, &name)?;
            parts.volumes.remove(&name).await?;
            parts.store.kv_delete(&restore_key(&name))?;
            parts.store.forget_disk(&self.id, &name)?;
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
