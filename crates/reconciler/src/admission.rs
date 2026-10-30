use std::collections::BTreeMap;

use proto::v1::{ArtifactRef, InstanceSpec, Isolation, Resources};
use sandbox::SandboxKind;
use usage::Metrics;
use volume::{PoolAlert, Volumes};

const MAX_VOLUME_NAME_LEN: usize = 100;
const MAX_DISK_NAME_LEN: usize = 64;
const MAX_SECRET_NAME_LEN: usize = 255;
const MAX_STOP_DEADLINE_SECONDS: u32 = 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict
{
    Admitted(Resources),
    Rejected(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision
{
    pub generation: u64,
    pub verdict: Verdict,
}

/// Admission check of section 11: allocatable = capacity − reservation, no overcommit.
pub struct Admission
{
    allocatable: Resources,
    kind: SandboxKind,
    snapshots_configured: bool,
    decisions: BTreeMap<String, Decision>,
}

pub fn allocatable(capacity: &Resources, reservation: &Resources) -> Resources
{
    Resources {
        vcpus: capacity.vcpus.saturating_sub(reservation.vcpus),
        memory_mib: capacity.memory_mib.saturating_sub(reservation.memory_mib),
        disk_gib: capacity.disk_gib.saturating_sub(reservation.disk_gib),
    }
}

pub fn spec_resources(spec: &InstanceSpec) -> Resources
{
    Resources {
        vcpus: spec.vcpus,
        memory_mib: spec.memory_mib,
        disk_gib: spec
            .disks
            .iter()
            .fold(0u64, |total, disk| total.saturating_add(disk.size_gib)),
    }
}

pub fn volume_name(instance_id: &str, disk_name: &str) -> String
{
    let raw = format!("{instance_id}-{disk_name}");
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '_' | '.' | '-')
            {
                c
            }
            else
            {
                '-'
            }
        })
        .take(MAX_VOLUME_NAME_LEN)
        .collect()
}

pub fn is_digest(digest: &str) -> bool
{
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_env_name(name: &str) -> bool
{
    let mut bytes = name.bytes();
    match bytes.next()
    {
        Some(first) if first.is_ascii_alphabetic() || first == b'_' =>
        {
            bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }
        _ => false,
    }
}

fn check_artifact(field: &str, artifact: Option<&ArtifactRef>) -> Result<(), String>
{
    let artifact = artifact.ok_or_else(|| format!("malformed spec: {field} is missing"))?;
    if !is_digest(&artifact.digest)
    {
        return Err(format!(
            "malformed spec: {field} digest must be 64 lowercase hex characters"
        ));
    }
    if artifact.key.is_empty() || artifact.signature_key.is_empty()
    {
        return Err(format!(
            "malformed spec: {field} needs an object key and a signature key"
        ));
    }
    if artifact.size_bytes == 0
    {
        return Err(format!(
            "malformed spec: {field} size_bytes must be positive"
        ));
    }
    Ok(())
}

pub fn supports(kind: SandboxKind, isolation: Isolation) -> bool
{
    match kind
    {
        SandboxKind::Firecracker =>
        {
            matches!(isolation, Isolation::Firecracker | Isolation::Unspecified)
        }
        SandboxKind::Gvisor => matches!(isolation, Isolation::Gvisor | Isolation::Unspecified),
        SandboxKind::Fake => true,
    }
}

impl Admission
{
    pub fn new(allocatable: Resources, kind: SandboxKind, snapshots_configured: bool) -> Admission
    {
        Admission {
            allocatable,
            kind,
            snapshots_configured,
            decisions: BTreeMap::new(),
        }
    }

    pub fn seed(&mut self, instance_id: &str, decision: Decision)
    {
        self.decisions.insert(instance_id.to_owned(), decision);
    }

    pub fn forget(&mut self, instance_id: &str)
    {
        self.decisions.remove(instance_id);
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool)
    {
        self.decisions.retain(|id, _| keep(id));
    }

    pub fn committed(&self, excluding: Option<&str>) -> Resources
    {
        self.decisions
            .iter()
            .filter(|(id, _)| Some(id.as_str()) != excluding)
            .filter_map(|(_, decision)| match &decision.verdict
            {
                Verdict::Admitted(resources) => Some(resources),
                Verdict::Rejected(_) => None,
            })
            .fold(Resources::default(), |total, resources| Resources {
                vcpus: total.vcpus.saturating_add(resources.vcpus),
                memory_mib: total.memory_mib.saturating_add(resources.memory_mib),
                disk_gib: total.disk_gib.saturating_add(resources.disk_gib),
            })
    }

    pub fn validate(&self, spec: &InstanceSpec) -> Result<(), String>
    {
        if let Err(error) = sandbox::validate_instance_id(&spec.id)
        {
            return Err(format!("malformed spec: {error}"));
        }
        if spec.vcpus == 0
        {
            return Err("malformed spec: vcpus must be at least 1".to_owned());
        }
        if spec.memory_mib == 0
        {
            return Err("malformed spec: memory_mib must be at least 1".to_owned());
        }
        let isolation = Isolation::try_from(spec.isolation)
            .map_err(|_| format!("malformed spec: unknown isolation {}", spec.isolation))?;
        check_artifact("image", spec.image.as_ref())?;
        if self.kind == SandboxKind::Firecracker
        {
            check_artifact("kernel", spec.kernel.as_ref())?;
        }
        match spec.disks.as_slice()
        {
            [] =>
            {
                return Err(
                    "malformed spec: exactly one data disk is required, the spec has none"
                        .to_owned(),
                );
            }
            [disk] =>
            {
                if disk.name.is_empty() || disk.name.len() > MAX_DISK_NAME_LEN
                {
                    return Err(format!(
                        "malformed spec: disk name must be 1-{MAX_DISK_NAME_LEN} bytes"
                    ));
                }
                if disk.size_gib == 0
                {
                    return Err(format!(
                        "malformed spec: disk {:?} size_gib must be at least 1",
                        disk.name
                    ));
                }
                if !spec.id.starts_with(|c: char| c.is_ascii_alphanumeric())
                {
                    return Err(
                        "malformed spec: instance id must start with a letter or digit to name its volume"
                            .to_owned(),
                    );
                }
                let restores = disk
                    .restore_from
                    .as_ref()
                    .is_some_and(|snapshot| !snapshot.manifest_key.is_empty());
                if restores && !self.snapshots_configured
                {
                    return Err(format!(
                        "disk {:?} restores from a snapshot but no snapshot store is configured",
                        disk.name
                    ));
                }
            }
            disks =>
            {
                return Err(format!(
                    "malformed spec: exactly one data disk is supported, the spec has {}",
                    disks.len()
                ));
            }
        }
        if let Some(network) = &spec.network
            && let Some(port) = network
                .ports
                .iter()
                .find(|port| **port == 0 || **port > 65535)
        {
            return Err(format!("malformed spec: invalid port {port}"));
        }
        if let Some(name) = spec.env.keys().find(|name| !is_env_name(name))
        {
            return Err(format!(
                "malformed spec: invalid environment variable name {name:?}"
            ));
        }
        if spec.env.values().any(|value| value.contains('\0'))
        {
            return Err("malformed spec: environment values must not contain NUL".to_owned());
        }
        if let Some(name) = spec.secrets.keys().find(|name| {
            name.is_empty()
                || name.len() > MAX_SECRET_NAME_LEN
                || name.as_str() == "."
                || name.as_str() == ".."
                || name.contains('/')
                || name.chars().any(char::is_control)
        })
        {
            return Err(format!("malformed spec: invalid secret name {name:?}"));
        }
        if spec.stop_deadline_seconds > MAX_STOP_DEADLINE_SECONDS
        {
            return Err(format!(
                "malformed spec: stop_deadline_seconds must be at most {MAX_STOP_DEADLINE_SECONDS}"
            ));
        }
        if !supports(self.kind, isolation)
        {
            return Err(format!(
                "unsupported isolation {}: this node runs the {:?} sandbox",
                isolation.as_str_name(),
                self.kind
            ));
        }
        Ok(())
    }

    pub fn check_resources(&self, spec: &InstanceSpec) -> Result<Resources, String>
    {
        let requested = spec_resources(spec);
        let committed = self.committed(Some(&spec.id));
        let available = Resources {
            vcpus: self.allocatable.vcpus.saturating_sub(committed.vcpus),
            memory_mib: self
                .allocatable
                .memory_mib
                .saturating_sub(committed.memory_mib),
            disk_gib: self.allocatable.disk_gib.saturating_sub(committed.disk_gib),
        };
        if requested.vcpus > available.vcpus
        {
            return Err(format!(
                "insufficient vcpus: requested {}, available {}",
                requested.vcpus, available.vcpus
            ));
        }
        if requested.memory_mib > available.memory_mib
        {
            return Err(format!(
                "insufficient memory: requested {} MiB, available {} MiB",
                requested.memory_mib, available.memory_mib
            ));
        }
        if requested.disk_gib > available.disk_gib
        {
            return Err(format!(
                "insufficient disk: requested {} GiB, available {} GiB",
                requested.disk_gib, available.disk_gib
            ));
        }
        Ok(requested)
    }

    pub async fn decide(
        &mut self,
        spec: &InstanceSpec,
        is_new: bool,
        draining: bool,
        volumes: &Volumes,
        metrics: &Metrics,
    ) -> Decision
    {
        if let Some(existing) = self.decisions.get(&spec.id)
            && existing.generation == spec.generation
        {
            return existing.clone();
        }
        let verdict = match self
            .evaluate(spec, is_new, draining, volumes, metrics)
            .await
        {
            Ok(resources) => Verdict::Admitted(resources),
            Err(reason) => Verdict::Rejected(reason),
        };
        let decision = Decision {
            generation: spec.generation,
            verdict,
        };
        self.decisions.insert(spec.id.clone(), decision.clone());
        decision
    }

    async fn evaluate(
        &self,
        spec: &InstanceSpec,
        is_new: bool,
        draining: bool,
        volumes: &Volumes,
        metrics: &Metrics,
    ) -> Result<Resources, String>
    {
        self.validate(spec)?;
        if draining && is_new
        {
            return Err("node is draining and admits no new instances".to_owned());
        }
        let resources = self.check_resources(spec)?;
        for disk in &spec.disks
        {
            let name = volume_name(&spec.id, &disk.name);
            let exists = volumes
                .backend()
                .get(&name)
                .await
                .map_err(|error| format!("cannot inspect volume {name}: {error}"))?
                .is_some();
            if exists
            {
                continue;
            }
            let status = volumes
                .pool_status()
                .await
                .map_err(|error| format!("cannot read thin pool usage: {error}"))?;
            metrics.set_pool_used_percent(status.usage.used_percent);
            if status.alert == PoolAlert::Critical
            {
                return Err(format!(
                    "thin pool is {:.1}% full; refusing new volume {name}",
                    status.usage.used_percent
                ));
            }
        }
        Ok(resources)
    }
}

#[cfg(test)]
mod tests
{
    use proto::v1::{DiskSpec, InstanceNetwork, SnapshotRef};

    use super::*;

    fn digest() -> String
    {
        "a".repeat(64)
    }

    fn artifact() -> ArtifactRef
    {
        ArtifactRef {
            digest: digest(),
            key: "artifacts/rootfs".to_owned(),
            signature_key: "artifacts/rootfs.minisig".to_owned(),
            size_bytes: 10,
        }
    }

    fn spec(id: &str, vcpus: u32, memory_mib: u64, disk_gib: u64) -> InstanceSpec
    {
        InstanceSpec {
            id: id.to_owned(),
            generation: 1,
            image: Some(artifact()),
            kernel: Some(artifact()),
            vcpus,
            memory_mib,
            disks: vec![DiskSpec {
                name: "data".to_owned(),
                size_gib: disk_gib,
                restore_from: None,
            }],
            ..InstanceSpec::default()
        }
    }

    fn admission(kind: SandboxKind) -> Admission
    {
        Admission::new(
            Resources {
                vcpus: 8,
                memory_mib: 8192,
                disk_gib: 100,
            },
            kind,
            false,
        )
    }

    #[test]
    fn allocatable_subtracts_the_reservation()
    {
        let capacity = Resources {
            vcpus: 16,
            memory_mib: 65536,
            disk_gib: 1000,
        };
        let reservation = Resources {
            vcpus: 2,
            memory_mib: 4096,
            disk_gib: 2000,
        };
        assert_eq!(
            allocatable(&capacity, &reservation),
            Resources {
                vcpus: 14,
                memory_mib: 61440,
                disk_gib: 0
            }
        );
    }

    #[test]
    fn resources_exclude_the_instance_itself_and_rejections()
    {
        let mut admission = admission(SandboxKind::Fake);
        admission.seed(
            "a",
            Decision {
                generation: 1,
                verdict: Verdict::Admitted(Resources {
                    vcpus: 4,
                    memory_mib: 4096,
                    disk_gib: 10,
                }),
            },
        );
        admission.seed(
            "r",
            Decision {
                generation: 1,
                verdict: Verdict::Rejected("no".to_owned()),
            },
        );
        assert_eq!(
            admission
                .check_resources(&spec("b", 2, 8192, 1))
                .unwrap_err(),
            "insufficient memory: requested 8192 MiB, available 4096 MiB"
        );
        assert_eq!(
            admission
                .check_resources(&spec("b", 5, 1024, 1))
                .unwrap_err(),
            "insufficient vcpus: requested 5, available 4"
        );
        assert_eq!(
            admission
                .check_resources(&spec("b", 1, 1024, 91))
                .unwrap_err(),
            "insufficient disk: requested 91 GiB, available 90 GiB"
        );
        assert!(admission.check_resources(&spec("b", 4, 4096, 90)).is_ok());
        assert!(admission.check_resources(&spec("a", 8, 8192, 100)).is_ok());
    }

    #[test]
    fn malformed_specs_are_rejected_with_reasons()
    {
        let admission = admission(SandboxKind::Firecracker);
        let cases: Vec<(InstanceSpec, &str)> = vec![
            (
                InstanceSpec {
                    vcpus: 0,
                    ..spec("a", 1, 1, 1)
                },
                "vcpus",
            ),
            (
                InstanceSpec {
                    memory_mib: 0,
                    ..spec("a", 1, 1, 1)
                },
                "memory_mib",
            ),
            (
                InstanceSpec {
                    image: None,
                    ..spec("a", 1, 1, 1)
                },
                "image is missing",
            ),
            (
                InstanceSpec {
                    kernel: None,
                    ..spec("a", 1, 1, 1)
                },
                "kernel is missing",
            ),
            (
                InstanceSpec {
                    disks: Vec::new(),
                    ..spec("a", 1, 1, 1)
                },
                "has none",
            ),
            (
                InstanceSpec {
                    disks: vec![DiskSpec::default(), DiskSpec::default()],
                    ..spec("a", 1, 1, 1)
                },
                "has 2",
            ),
            (spec("bad/id", 1, 1, 1), "instance id"),
            (spec("a", 1, 1, 0), "size_gib"),
            (
                InstanceSpec {
                    network: Some(InstanceNetwork {
                        world_id: String::new(),
                        egress_mbit: 0,
                        ports: vec![70000],
                    }),
                    ..spec("a", 1, 1, 1)
                },
                "invalid port",
            ),
            (
                InstanceSpec {
                    isolation: Isolation::Gvisor as i32,
                    ..spec("a", 1, 1, 1)
                },
                "unsupported isolation ISOLATION_GVISOR",
            ),
        ];
        for (spec, needle) in cases
        {
            let reason = admission.validate(&spec).unwrap_err();
            assert!(
                reason.contains(needle),
                "{reason:?} should mention {needle:?}"
            );
        }
        assert!(admission.validate(&spec("a", 1, 1, 1)).is_ok());
    }

    #[test]
    fn restore_requires_a_snapshot_store()
    {
        let admission = admission(SandboxKind::Fake);
        let mut restoring = spec("a", 1, 1, 1);
        restoring.disks[0].restore_from = Some(SnapshotRef {
            manifest_key: "worlds/a/manifest.json".to_owned(),
        });
        assert!(
            admission
                .validate(&restoring)
                .unwrap_err()
                .contains("no snapshot store")
        );
    }

    #[test]
    fn isolation_support_matches_the_backend()
    {
        assert!(supports(SandboxKind::Firecracker, Isolation::Unspecified));
        assert!(supports(SandboxKind::Firecracker, Isolation::Firecracker));
        assert!(!supports(SandboxKind::Firecracker, Isolation::Gvisor));
        assert!(supports(SandboxKind::Gvisor, Isolation::Gvisor));
        assert!(!supports(SandboxKind::Gvisor, Isolation::Firecracker));
        assert!(supports(SandboxKind::Fake, Isolation::Gvisor));
        assert!(supports(SandboxKind::Fake, Isolation::Firecracker));
    }

    #[test]
    fn volume_names_are_sanitized()
    {
        assert_eq!(volume_name("srv-1", "data"), "srv-1-data");
        assert_eq!(volume_name("srv-1", "my disk/x"), "srv-1-my-disk-x");
        assert_eq!(volume_name("a", &"x".repeat(200)).len(), 100);
    }
}
