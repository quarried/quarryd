use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use network::{Ipam, NetworkAttachment, NetworkError, NodeNetwork, Subnet, WireGuardPeerConfig};
use prost::Message;
use proto::v1::{
    DesiredState, Heartbeat, InstanceSpec, InstanceStatus, Inventory, InventoryEntry, LeaseGrant,
    LeaseRenewal, Load, NetworkConfig, Phase, Resources,
};
use sandbox::SandboxRecord;
use serde_json::{Value, json};
use store::{InstanceRow, PutOutcome};
use tokio::sync::{Notify, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::admission::{Admission, Decision, Verdict, allocatable, spec_resources};
use crate::leases::{Leases, unix_ms_now};
use crate::lifecycle::Lifecycle;
use crate::sampler::Sampler;
use crate::supervisor::{Command, Desired, Supervisor};
use crate::{ReconcilerConfig, ReconcilerError, ReconcilerEvent, ReconcilerParts};

pub(crate) const KV_NETWORK: &str = "reconciler/network";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T>
{
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GuestView
{
    pub connected: bool,
    pub ready: bool,
    pub health: Option<guest_proto::Health>,
    pub health_reports: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct InstanceView
{
    pub status: InstanceStatus,
    pub record: Option<SandboxRecord>,
    pub console_path: Option<PathBuf>,
    pub attachment: Option<NetworkAttachment>,
    pub sandbox_state: String,
    pub guest: GuestView,
    pub abuse: Arc<AtomicU64>,
    pub vmm_metrics: Option<usage::FirecrackerMetrics>,
}

#[derive(Default)]
pub(crate) struct Observed
{
    pub instances: BTreeMap<String, InstanceView>,
    pub committed: Resources,
    pub pool_used_percent: f64,
    pub load_1m: f64,
    pub forgotten: Vec<String>,
}

pub(crate) struct SupervisorLink
{
    pub desired: watch::Sender<Desired>,
    pub poke: Arc<Notify>,
    pub commands: mpsc::Sender<Command>,
    pub task: JoinHandle<()>,
}

/// Secret values by name, held in memory only (decision 10).
pub(crate) type SecretValues = HashMap<String, Vec<u8>>;

pub(crate) struct Inner
{
    pub config: ReconcilerConfig,
    pub parts: ReconcilerParts,
    pub observed: Mutex<Observed>,
    pub leases: Mutex<Leases>,
    pub ipam: Mutex<Option<Ipam>>,
    pub secrets: Mutex<HashMap<String, (u64, SecretValues)>>,
    pub write_lock: Mutex<()>,
    pub disk_lock: tokio::sync::Mutex<()>,
    pub wake: Notify,
    pub live_metrics: Mutex<HashMap<String, u64>>,
    pub health: broadcast::Sender<proto::v1::InstanceHealth>,
    events: Mutex<Option<mpsc::UnboundedSender<ReconcilerEvent>>>,
    pub supervisors: Mutex<BTreeMap<String, SupervisorLink>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    pending_network: Mutex<Option<NetworkConfig>>,
    draining: AtomicBool,
    shut_down: AtomicBool,
    pub node_span: tracing::Span,
}

impl Inner
{
    pub fn emit(&self, status: InstanceStatus)
    {
        if let Some(sender) = lock(&self.events).as_ref()
        {
            let _ = sender.send(ReconcilerEvent::Status(status));
        }
    }

    pub fn allocatable(&self) -> Resources
    {
        allocatable(&self.config.capacity, &self.config.reservation)
    }

    pub fn is_shut_down(&self) -> bool
    {
        self.shut_down.load(Ordering::SeqCst)
    }

    pub fn poke(&self, instance_id: &str)
    {
        if let Some(link) = lock(&self.supervisors).get(instance_id)
        {
            link.poke.notify_one();
        }
    }
}

pub(crate) fn decode_spec(bytes: &[u8]) -> Result<InstanceSpec, ReconcilerError>
{
    Ok(InstanceSpec::decode(bytes)?)
}

/// Compare desired state by its contents, independent of protobuf map ordering.
/// Secret values remain memory-only and are refilled even when a put is a replay.
pub(crate) fn normalized_spec(spec: &InstanceSpec) -> InstanceSpec
{
    let mut normalized = spec.clone();
    for value in normalized.secrets.values_mut()
    {
        value.clear();
    }
    normalized
}

fn node_network(config: &NetworkConfig) -> Result<NodeNetwork, ReconcilerError>
{
    let subnet = Subnet::parse(&config.subnet)?;
    let wireguard_listen_port = u16::try_from(config.wireguard_listen_port).map_err(|_| {
        NetworkError::InvalidNodeNetwork(format!(
            "WireGuard listen port {} is out of range",
            config.wireguard_listen_port
        ))
    })?;
    Ok(NodeNetwork {
        subnet,
        region: config.region.clone(),
        wireguard_listen_port,
        wireguard_address: (!config.wireguard_address.is_empty())
            .then(|| config.wireguard_address.clone()),
        peers: config
            .peers
            .iter()
            .map(|peer| WireGuardPeerConfig {
                public_key: peer.public_key.clone(),
                endpoint: peer.endpoint.clone(),
                allowed_ips: peer.allowed_ips.clone(),
            })
            .collect(),
    })
}

async fn apply_network(inner: &Inner, config: &NetworkConfig) -> Result<(), ReconcilerError>
{
    let node = node_network(config)?;
    inner.parts.network.configure_node(&node).await?;
    let rows = inner.parts.store.list_instances()?;
    let mut ipam = lock(&inner.ipam);
    if ipam.as_ref().map(Ipam::subnet) != Some(node.subnet)
    {
        let mut by_ip: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
        for row in &rows
        {
            if let Some(ip) = row
                .guest_ip
                .as_deref()
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                .filter(|ip| node.subnet.is_instance_address(*ip))
            {
                by_ip.entry(ip).or_insert_with(|| row.id.clone());
            }
        }
        let existing = by_ip.into_iter().map(|(ip, id)| (id, ip));
        *ipam = Some(Ipam::new(node.subnet, existing)?);
    }
    Ok(())
}

fn seed_decision(row: &InstanceRow, spec: &InstanceSpec) -> Option<Decision>
{
    if row.desired_deleted
    {
        return None;
    }
    match Lifecycle::parse_phase(&row.phase)
    {
        Phase::Rejected if row.observed_generation == row.generation => Some(Decision::unverified(
            row.generation,
            Verdict::Rejected(row.reason.clone()),
        )),
        Phase::Pending | Phase::Rejected | Phase::Deleting | Phase::Deleted => None,
        _ => Some(
            match row
                .applied_spec
                .as_deref()
                .and_then(|bytes| decode_spec(bytes).ok())
            {
                Some(applied) =>
                {
                    Decision::new(&applied, Verdict::Admitted(spec_resources(&applied)))
                }
                None if row.sandbox_record.is_some()
                    || Lifecycle::holds_sandbox(Lifecycle::parse_phase(&row.phase)) =>
                {
                    // Preserve an existing legacy placement until its desired contents
                    // change. This is only an admission baseline, never an applied spec:
                    // actual_resources still reserves the full node for unknown usage.
                    Decision::new(spec, Verdict::Admitted(spec_resources(spec)))
                }
                None => Decision::unverified(
                    row.observed_generation,
                    Verdict::Admitted(spec_resources(spec)),
                ),
            },
        ),
    }
}

fn actual_resources(rows: &[InstanceRow], allocatable: Resources) -> BTreeMap<String, Resources>
{
    rows.iter()
        .filter(|row| {
            row.sandbox_record.is_some()
                || Lifecycle::holds_sandbox(Lifecycle::parse_phase(&row.phase))
        })
        .map(|row| {
            let resources = row
                .applied_spec
                .as_deref()
                .and_then(|bytes| decode_spec(bytes).ok())
                .map(|spec| spec_resources(&spec))
                // An older row may have lost the original running spec when a
                // desired update was stored. Do not assume it uses the new limits.
                .unwrap_or(allocatable);
            (row.id.clone(), resources)
        })
        .collect()
}

fn strip_secrets(spec: &mut InstanceSpec) -> SecretValues
{
    let secrets = std::mem::take(&mut spec.secrets);
    spec.secrets = secrets
        .keys()
        .map(|name| (name.clone(), Vec::new()))
        .collect();
    secrets
}

/// The level-triggered reconciler of section 4.2.
pub struct Reconciler
{
    inner: Arc<Inner>,
    admission: Admission,
}

impl Reconciler
{
    pub async fn start(
        config: ReconcilerConfig,
        parts: ReconcilerParts,
    ) -> Result<(ReconcilerHandle, mpsc::UnboundedReceiver<ReconcilerEvent>), ReconcilerError>
    {
        let (events, receiver) = mpsc::unbounded_channel();
        let node_span = tracing::info_span!("reconciler", node_id = %config.node_id);
        let kind = parts.sandbox.kind();
        let snapshots_configured = parts.snapshots.is_some();
        let inner = Arc::new(Inner {
            config,
            parts,
            observed: Mutex::new(Observed::default()),
            leases: Mutex::new(Leases::default()),
            ipam: Mutex::new(None),
            secrets: Mutex::new(HashMap::new()),
            write_lock: Mutex::new(()),
            disk_lock: tokio::sync::Mutex::new(()),
            wake: Notify::new(),
            live_metrics: Mutex::new(HashMap::new()),
            health: broadcast::channel(512).0,
            events: Mutex::new(Some(events)),
            supervisors: Mutex::new(BTreeMap::new()),
            tasks: Mutex::new(Vec::new()),
            pending_network: Mutex::new(None),
            draining: AtomicBool::new(false),
            shut_down: AtomicBool::new(false),
            node_span: node_span.clone(),
        });
        let mut admission = Admission::new(inner.allocatable(), kind, snapshots_configured);
        async {
            if let Some(bytes) = inner.parts.store.kv_get(KV_NETWORK)?
            {
                let network = NetworkConfig::decode(bytes.as_slice())?;
                if let Err(error) = apply_network(&inner, &network).await
                {
                    tracing::error!(error = %error, "stored node network configuration could not be applied");
                    *lock(&inner.pending_network) = Some(network);
                }
            }
            let rows = inner.parts.store.list_instances()?;
            admission.set_actual_resources(actual_resources(&rows, inner.allocatable()));
            {
                let now = Instant::now();
                let now_ms = unix_ms_now();
                let mut leases = lock(&inner.leases);
                for row in &rows
                {
                    if let Some(expires) = row.lease_expires_unix_ms
                    {
                        leases.restore(&row.id, row.lease_epoch, expires, now, now_ms);
                    }
                }
            }
            for row in rows
            {
                let spec = match decode_spec(&row.spec)
                {
                    Ok(spec) => spec,
                    Err(error) =>
                    {
                        tracing::error!(instance_id = %row.id, error = %error, "skipping instance with an undecodable spec");
                        continue;
                    }
                };
                let mut disk_names: BTreeSet<String> = spec
                    .disks
                    .iter()
                    .map(|disk| disk.name.clone())
                    .collect();
                if let Some(bytes) = row.applied_spec.as_deref()
                {
                    disk_names.extend(decode_spec(bytes)?.disks.into_iter().map(|disk| disk.name));
                }
                let mut ownership_rejection = None;
                for disk in disk_names
                {
                    match crate::provision::resolve_disk_name(&inner, &row.id, &disk).await
                    {
                        Ok(_) => {}
                        Err(error @ ReconcilerError::Store(store::StoreError::DiskOwnership { .. })) =>
                        {
                            tracing::error!(instance_id = %row.id, error = %error, "refusing an instance with ambiguous disk ownership");
                            ownership_rejection = Some(error.to_string());
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                }
                let decision = ownership_rejection
                    .map(|reason| Decision::new(&spec, Verdict::Rejected(reason)))
                    .or_else(|| seed_decision(&row, &spec));
                if let Some(decision) = &decision
                {
                    admission.seed(&row.id, decision.clone());
                }
                let id = row.id.clone();
                let link = Supervisor::spawn(Arc::clone(&inner), row, spec, decision).await?;
                lock(&inner.supervisors).insert(id, link);
            }
            Ok::<(), ReconcilerError>(())
        }
        .instrument(node_span.clone())
        .await?;
        lock(&inner.observed).committed = admission.committed(None);

        let reconciler = Reconciler {
            inner: Arc::clone(&inner),
            admission,
        };
        let loop_task = tokio::spawn(reconciler.run().instrument(node_span.clone()));
        let sampler_task = tokio::spawn(
            Sampler::new(Arc::clone(&inner))
                .run()
                .instrument(node_span.clone()),
        );
        lock(&inner.tasks).extend([loop_task, sampler_task]);
        node_span.in_scope(|| tracing::info!("reconciler started"));
        Ok((ReconcilerHandle { inner }, receiver))
    }

    async fn run(mut self)
    {
        let mut interval = tokio::time::interval(self.inner.config.reconcile_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop
        {
            let started = Instant::now();
            let result = self.pass().await;
            self.inner
                .parts
                .metrics
                .observe_reconcile(started.elapsed(), result.is_ok());
            if let Err(error) = result
            {
                tracing::warn!(error = %error, "reconcile pass failed");
            }
            tokio::select! {
                _ = self.inner.wake.notified() => {}
                _ = interval.tick() => {}
            }
        }
    }

    async fn pass(&mut self) -> Result<(), ReconcilerError>
    {
        let pending_network = lock(&self.inner.pending_network).clone();
        if let Some(network) = pending_network
        {
            match apply_network(&self.inner, &network).await
            {
                Ok(()) =>
                {
                    tracing::info!("node network configuration applied");
                    *lock(&self.inner.pending_network) = None;
                }
                Err(error) =>
                {
                    tracing::warn!(error = %error, "node network configuration still failing")
                }
            }
        }
        let rows = self.inner.parts.store.list_instances()?;
        self.admission
            .set_actual_resources(actual_resources(&rows, self.inner.allocatable()));
        let ids: BTreeSet<String> = rows.iter().map(|row| row.id.clone()).collect();
        lock(&self.inner.supervisors).retain(|_, link| !link.task.is_finished());
        self.admission.retain(|id| ids.contains(id));
        let draining = self.inner.draining.load(Ordering::SeqCst);
        let mut public_claims = BTreeMap::<String, String>::new();
        for row in rows
        {
            let spec = match decode_spec(&row.spec)
            {
                Ok(spec) => spec,
                Err(error) =>
                {
                    tracing::error!(instance_id = %row.id, error = %error, "undecodable stored spec");
                    continue;
                }
            };
            let decision = if row.desired_deleted
            {
                self.admission.forget(&row.id);
                None
            }
            else
            {
                let is_new = matches!(
                    Lifecycle::parse_phase(&row.phase),
                    Phase::Pending | Phase::Rejected
                );
                let mut decision = self
                    .admission
                    .decide(
                        &spec,
                        is_new,
                        draining,
                        &self.inner.parts.volumes,
                        &self.inner.parts.store,
                        &self.inner.parts.metrics,
                    )
                    .await;
                if let Some(network) = &spec.network
                    && !network.public_ipv4.is_empty()
                {
                    let rejection = self
                        .inner
                        .parts
                        .network
                        .validate_public_ipv4(&spec.id, &network.public_ipv4)
                        .err()
                        .map(|error| error.to_string())
                        .or_else(|| {
                            public_claims.get(&network.public_ipv4).map(|owner| {
                                format!(
                                    "public IPv4 {} is already reserved by instance {owner}",
                                    network.public_ipv4
                                )
                            })
                        });
                    if let Some(reason) = rejection
                    {
                        decision.verdict = Verdict::Rejected(reason);
                        self.admission.seed(&spec.id, decision.clone());
                    }
                    else if matches!(decision.verdict, Verdict::Admitted(_))
                    {
                        public_claims.insert(network.public_ipv4.clone(), spec.id.clone());
                    }
                }
                if let Verdict::Rejected(reason) = &decision.verdict
                {
                    tracing::debug!(instance_id = %row.id, generation = decision.generation, reason = %reason, "admission rejected");
                }
                Some(decision)
            };
            let desired = Desired {
                spec: Arc::new(spec.clone()),
                deleted: row.desired_deleted,
                decision: decision.clone(),
            };
            let exists = lock(&self.inner.supervisors).contains_key(&row.id);
            if !exists
            {
                let id = row.id.clone();
                let link = Supervisor::spawn(Arc::clone(&self.inner), row, spec, decision).await?;
                lock(&self.inner.supervisors).insert(id.clone(), link);
            }
            let supervisors = lock(&self.inner.supervisors);
            if let Some(link) = supervisors.get(desired.spec.id.as_str())
            {
                link.desired.send_if_modified(|current| {
                    if current.same_as(&desired)
                    {
                        false
                    }
                    else
                    {
                        *current = desired;
                        true
                    }
                });
                link.poke.notify_one();
            }
        }
        lock(&self.inner.observed).committed = self.admission.committed(None);
        Ok(())
    }
}

/// Cloneable handle to a running [`Reconciler`].
#[derive(Clone)]
pub struct ReconcilerHandle
{
    inner: Arc<Inner>,
}

impl ReconcilerHandle
{
    pub async fn put_instance(&self, mut spec: InstanceSpec) -> Result<(), ReconcilerError>
    {
        let _span = self.inner.node_span.enter();
        tracing::info!(instance_id = %spec.id, generation = spec.generation, "put instance");
        if let Err(error) = sandbox::validate_instance_id(&spec.id)
        {
            tracing::warn!(instance_id = %spec.id, generation = spec.generation, "rejecting a spec with an invalid instance id");
            self.inner.emit(InstanceStatus {
                id: spec.id.clone(),
                observed_generation: spec.generation,
                phase: Phase::Rejected as i32,
                reason: format!("malformed spec: {error}"),
                lease_epoch: 0,
                guest_ip: String::new(),
            });
            return Ok(());
        }
        let secrets = strip_secrets(&mut spec);
        let bytes = spec.encode_to_vec();
        let outcome = {
            let _disk_guard = self.inner.disk_lock.lock().await;
            let _guard = lock(&self.inner.write_lock);
            let previous = self.inner.parts.store.get_instance(&spec.id)?;
            if previous.as_ref().is_some_and(|current| {
                current.generation > spec.generation
                    || (current.desired_deleted && current.generation == spec.generation)
            })
            {
                return Ok(());
            }
            // Protobuf maps have no wire-order guarantee. Compare decoded contents
            // against legacy rows too, rather than treating a new encoding as a put.
            let unchanged = match &previous
            {
                Some(current) if current.generation == spec.generation =>
                {
                    normalized_spec(&decode_spec(&current.spec)?) == spec
                }
                _ => false,
            };
            let outcome = if unchanged
            {
                PutOutcome::Unchanged
            }
            else
            {
                let mut leases = lock(&self.inner.leases);
                let held = leases.get(&spec.id);
                let epoch_floor = previous
                    .as_ref()
                    .map(|row| row.lease_epoch)
                    .unwrap_or(0)
                    .max(held.map(|lease| lease.epoch).unwrap_or(0));
                let now = Instant::now();
                let now_ms = unix_ms_now();
                let embedded = spec
                    .lease
                    .as_ref()
                    .filter(|lease| lease.epoch >= epoch_floor)
                    .map(|lease| (lease.epoch, self.lease_ttl(lease.ttl_ms)));
                let durable_lease = embedded
                    .map(|(epoch, ttl)| {
                        let ttl_ms = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
                        (epoch, now_ms.saturating_add(ttl_ms))
                    })
                    .or_else(|| held.map(|lease| (lease.epoch, lease.expires_unix_ms)));
                // A crash must not leave a stored spec whose initial embedded grant
                // was never applied: an identical replay deliberately does not renew.
                let outcome = self.inner.parts.store.put_desired_with_lease(
                    &spec.id,
                    spec.generation,
                    &bytes,
                    durable_lease,
                )?;
                if matches!(outcome, PutOutcome::Inserted | PutOutcome::Updated)
                    && let Some((epoch, ttl)) = embedded
                {
                    leases.grant(&spec.id, epoch, ttl, now, now_ms);
                }
                outcome
            };
            if outcome != PutOutcome::Stale
            {
                lock(&self.inner.secrets).insert(spec.id.clone(), (spec.generation, secrets));
            }
            outcome
        };
        tracing::info!(instance_id = %spec.id, generation = spec.generation, outcome = ?outcome, "put instance stored");
        if outcome == PutOutcome::Stale
        {
            return Ok(());
        }
        self.inner.poke(&spec.id);
        self.inner.wake.notify_one();
        Ok(())
    }

    pub async fn delete_instance(&self, id: &str) -> Result<(), ReconcilerError>
    {
        let _span = self.inner.node_span.enter();
        tracing::info!(instance_id = %id, "delete instance");
        let changed = {
            let _guard = lock(&self.inner.write_lock);
            self.inner.parts.store.mark_deleted_desired(id)?
        };
        if !changed
        {
            tracing::info!(instance_id = %id, "delete of an unknown instance; reporting it deleted");
            self.inner.emit(InstanceStatus {
                id: id.to_owned(),
                observed_generation: 0,
                phase: Phase::Deleted as i32,
                reason: "unknown instance".to_owned(),
                lease_epoch: 0,
                guest_ip: String::new(),
            });
            return Ok(());
        }
        self.inner.poke(id);
        self.inner.wake.notify_one();
        Ok(())
    }

    pub async fn apply_desired_state(&self, desired: DesiredState) -> Result<(), ReconcilerError>
    {
        {
            let _span = self.inner.node_span.enter();
            tracing::info!(
                instances = desired.instances.len(),
                network = desired.network.is_some(),
                "apply full desired state"
            );
        }
        if let Some(network) = desired.network
        {
            self.configure_network(network).await?;
        }
        let listed: BTreeSet<String> = desired
            .instances
            .iter()
            .map(|spec| spec.id.clone())
            .collect();
        for spec in desired.instances
        {
            self.put_instance(spec).await?;
        }
        for row in self.inner.parts.store.list_instances()?
        {
            if !row.desired_deleted && !listed.contains(&row.id)
            {
                self.delete_instance(&row.id).await?;
            }
        }
        Ok(())
    }

    pub async fn configure_network(&self, config: NetworkConfig) -> Result<(), ReconcilerError>
    {
        let span = self.inner.node_span.clone();
        async {
            tracing::info!(
                subnet = %config.subnet,
                region = %config.region,
                peers = config.peers.len(),
                "configure node network"
            );
            self.inner
                .parts
                .store
                .kv_set(KV_NETWORK, &config.encode_to_vec())?;
            match apply_network(&self.inner, &config).await
            {
                Ok(()) => *lock(&self.inner.pending_network) = None,
                Err(error) =>
                {
                    tracing::error!(error = %error, "node network configuration failed; retrying on later passes");
                    *lock(&self.inner.pending_network) = Some(config);
                }
            }
            self.inner.wake.notify_one();
            Ok(())
        }
        .instrument(span)
        .await
    }

    pub async fn grant_lease(&self, grant: LeaseGrant) -> Result<(), ReconcilerError>
    {
        let _span = self.inner.node_span.enter();
        tracing::info!(instance_id = %grant.instance_id, epoch = grant.epoch, ttl_ms = grant.ttl_ms, "lease grant");
        self.apply_grant(&grant.instance_id, grant.epoch, grant.ttl_ms)?;
        self.inner.poke(&grant.instance_id);
        Ok(())
    }

    fn apply_grant(&self, instance_id: &str, epoch: u64, ttl_ms: u64)
    -> Result<(), ReconcilerError>
    {
        let _guard = lock(&self.inner.write_lock);
        let mut leases = lock(&self.inner.leases);
        let row = self.inner.parts.store.get_instance(instance_id)?;
        let epoch_floor = row
            .as_ref()
            .map(|row| row.lease_epoch)
            .unwrap_or(0)
            .max(leases.epoch(instance_id));
        if epoch < epoch_floor
        {
            tracing::info!(instance_id, epoch, "lease grant with a lower epoch ignored");
            return Ok(());
        }
        let ttl = self.lease_ttl(ttl_ms);
        let now = Instant::now();
        let now_ms = unix_ms_now();
        if let Some(row) = row
        {
            let mut actual = row.actual();
            actual.lease_epoch = epoch;
            actual.lease_expires_unix_ms =
                Some(now_ms.saturating_add(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX)));
            self.inner.parts.store.update_actual(instance_id, &actual)?;
        }
        // Publish authority only after its durable state is committed. Keeping the
        // same locks as put_instance also prevents an older put racing a renewal.
        leases.grant(instance_id, epoch, ttl, now, now_ms);
        Ok(())
    }

    fn lease_ttl(&self, ttl_ms: u64) -> Duration
    {
        if ttl_ms == 0
        {
            self.inner.config.default_lease_ttl
        }
        else
        {
            Duration::from_millis(ttl_ms)
        }
    }

    pub fn lease_renewal(&self) -> LeaseRenewal
    {
        lock(&self.inner.leases).renewal(Instant::now())
    }

    pub fn inventory(&self) -> Inventory
    {
        let observed = lock(&self.inner.observed);
        Inventory {
            total: Some(self.inner.config.capacity),
            allocatable: Some(self.inner.allocatable()),
            instances: observed
                .instances
                .values()
                .map(|view| InventoryEntry {
                    instance_id: view.status.id.clone(),
                    observed_generation: view.status.observed_generation,
                    phase: view.status.phase,
                })
                .collect(),
        }
    }

    pub fn heartbeat(&self) -> Heartbeat
    {
        let observed = lock(&self.inner.observed);
        let running = observed
            .instances
            .values()
            .filter(|view| view.status.phase == Phase::Running as i32)
            .count();
        Heartbeat {
            allocatable: Some(self.inner.allocatable()),
            load: Some(Load {
                running_instances: u32::try_from(running).unwrap_or(u32::MAX),
                committed: Some(observed.committed),
                cpu_load_1m: observed.load_1m,
                thin_pool_used_percent: observed.pool_used_percent,
                draining: self.inner.draining.load(Ordering::SeqCst),
            }),
            sent_at_unix_ms: u64::try_from(unix_ms_now()).unwrap_or(0),
        }
    }

    pub fn statuses(&self) -> Vec<InstanceStatus>
    {
        lock(&self.inner.observed)
            .instances
            .values()
            .map(|view| view.status.clone())
            .collect()
    }

    async fn command(&self, instance_id: &str, command: Command) -> Result<(), ReconcilerError>
    {
        if self.inner.is_shut_down()
        {
            return Err(ReconcilerError::ShutDown);
        }
        let sender = lock(&self.inner.supervisors)
            .get(instance_id)
            .map(|link| link.commands.clone())
            .ok_or_else(|| ReconcilerError::InstanceNotFound(instance_id.to_owned()))?;
        sender.try_send(command).map_err(|error| match error
        {
            mpsc::error::TrySendError::Full(_) => ReconcilerError::Busy(instance_id.to_owned()),
            mpsc::error::TrySendError::Closed(_) =>
            {
                ReconcilerError::InstanceNotFound(instance_id.to_owned())
            }
        })
    }

    async fn reply<T>(
        &self,
        what: &str,
        receiver: oneshot::Receiver<Result<T, ReconcilerError>>,
    ) -> Result<T, ReconcilerError>
    {
        match tokio::time::timeout(COMMAND_TIMEOUT, receiver).await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ReconcilerError::ShutDown),
            Err(_) => Err(ReconcilerError::Timeout(what.to_owned())),
        }
    }

    pub async fn snapshot_now(
        &self,
        instance_id: &str,
        destination_prefix: &str,
    ) -> Result<String, ReconcilerError>
    {
        Ok(self
            .snapshot_details(instance_id, destination_prefix)
            .await?
            .0)
    }

    pub async fn snapshot_details(
        &self,
        instance_id: &str,
        destination_prefix: &str,
    ) -> Result<(String, u64, String), ReconcilerError>
    {
        let span = self.inner.node_span.clone();
        async {
            tracing::info!(instance_id = %instance_id, prefix = %destination_prefix, "snapshot requested");
            let snapshots = self
                .inner
                .parts
                .snapshots
                .clone()
                .ok_or(ReconcilerError::SnapshotsUnavailable)?;
            let (reply, receiver) = oneshot::channel();
            self.command(instance_id, Command::Snapshot { reply }).await?;
            let taken = self.reply("world-consistent snapshot", receiver).await?;
            let uploaded = snapshots
                .upload(
                    &taken.snapshot.path,
                    destination_prefix,
                    &taken.volume,
                    taken.lease_epoch,
                )
                .await;
            let removed = self
                .inner
                .parts
                .volumes
                .backend()
                .delete(&taken.snapshot.name)
                .await;
            let manifest = uploaded?;
            removed?;
            let key = volume::SnapshotStore::manifest_key(destination_prefix);
            tracing::info!(
                instance_id = %instance_id,
                manifest_key = %key,
                lease_epoch = manifest.lease_epoch,
                bytes = manifest.total_size,
                "snapshot uploaded"
            );
            Ok((key, manifest.total_size, taken.disk))
        }
        .instrument(span)
        .await
    }

    pub async fn send_console_command(
        &self,
        instance_id: &str,
        command: &str,
    ) -> Result<Vec<String>, ReconcilerError>
    {
        static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);
        let request_id = format!(
            "{}-{}",
            unix_ms_now(),
            NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
        );
        self.console_output(instance_id, &request_id, command).await
    }

    pub async fn console_output(
        &self,
        instance_id: &str,
        request_id: &str,
        command: &str,
    ) -> Result<Vec<String>, ReconcilerError>
    {
        let message = guest_proto::HostMessage {
            body: Some(guest_proto::HostBody::ConsoleCommand(
                guest_proto::ConsoleCommand {
                    command: command.to_owned(),
                    request_id: request_id.to_owned(),
                },
            )),
        };
        guest_proto::decode_host_message(&message.encode_to_vec())
            .map_err(|error| ReconcilerError::InvalidCommand(error.to_string()))?;
        let (reply, receiver) = oneshot::channel();
        self.command(instance_id, Command::Console { message, reply })
            .await?;
        self.reply("console output", receiver).await
    }

    pub fn set_live_metrics(&self, live: proto::v1::LiveMetrics)
    {
        let mut subscriptions = lock(&self.inner.live_metrics);
        if live.until_unix_ms <= u64::try_from(unix_ms_now()).unwrap_or(0)
        {
            subscriptions.remove(&live.instance_id);
        }
        else
        {
            subscriptions.insert(live.instance_id, live.until_unix_ms);
        }
    }

    pub fn subscribe_health(&self) -> broadcast::Receiver<proto::v1::InstanceHealth>
    {
        self.inner.health.subscribe()
    }

    pub fn subscribe_wakes(&self) -> broadcast::Receiver<network::PublicWake>
    {
        self.inner.parts.network.subscribe_wakes()
    }

    pub fn set_draining(&self, draining: bool)
    {
        let _span = self.inner.node_span.enter();
        tracing::info!(draining, "drain setting changed");
        self.inner.draining.store(draining, Ordering::SeqCst);
        self.inner.wake.notify_one();
    }

    pub async fn diagnostics(&self) -> Result<Value, ReconcilerError>
    {
        let rows = self.inner.parts.store.list_instances()?;
        let views = lock(&self.inner.observed).instances.clone();
        let now = Instant::now();
        let leases: Vec<Value> = lock(&self.inner.leases)
            .all()
            .map(|(id, lease)| {
                json!({
                    "instance_id": id,
                    "epoch": lease.epoch,
                    "valid": lease.is_valid(now),
                    "remaining_ms": u64::try_from(lease.remaining(now).as_millis()).unwrap_or(u64::MAX),
                    "expires_unix_ms": lease.expires_unix_ms,
                })
            })
            .collect();
        let mut instances = Vec::new();
        for row in &rows
        {
            let spec = decode_spec(&row.spec).ok();
            let view = views.get(&row.id);
            let mut env_names: Vec<&String> = spec
                .as_ref()
                .map(|spec| spec.env.keys().collect())
                .unwrap_or_default();
            env_names.sort();
            instances.push(json!({
                "id": row.id,
                "generation": row.generation,
                "observed_generation": row.observed_generation,
                "desired_deleted": row.desired_deleted,
                "phase": Lifecycle::parse_phase(&row.phase).as_str_name(),
                "reason": row.reason,
                "restart_count": row.restart_count,
                "uid": row.uid,
                "guest_ip": row.guest_ip,
                "spec": spec.as_ref().map(|spec| json!({
                    "isolation": spec.isolation,
                    "vcpus": spec.vcpus,
                    "memory_mib": spec.memory_mib,
                    "disks": spec.disks.iter().map(|disk| json!({
                        "name": disk.name,
                        "size_gib": disk.size_gib,
                        "restore_from": disk.restore_from.as_ref().map(|r| r.manifest_key.clone()),
                    })).collect::<Vec<_>>(),
                    "run_state": spec.run_state,
                    "restart_policy": spec.restart_policy,
                    "env_names": env_names,
                    "secret_count": spec.secrets.len(),
                    "cpu_pinning": spec.cpu_pinning,
                    "balloon_idle_reclaim": spec.balloon_idle_reclaim,
                })),
                "sandbox": view.map(|view| json!({
                    "state": view.sandbox_state,
                    "record": view.record,
                    "vmm_metrics": view.vmm_metrics.map(|m| json!({
                        "net_rx_bytes": m.net_rx_bytes,
                        "net_tx_bytes": m.net_tx_bytes,
                        "block_read_bytes": m.block_read_bytes,
                        "block_write_bytes": m.block_write_bytes,
                        "vcpu_exits": m.vcpu_exits,
                    })),
                })),
                "network": view.and_then(|view| view.attachment.clone()),
                "guest": view.map(|view| json!({
                    "connected": view.guest.connected,
                    "ready": view.guest.ready,
                    "health_reports": view.guest.health_reports,
                    "health": view.guest.health.as_ref().map(|h| json!({
                        "tps": h.tps,
                        "mspt": h.mspt,
                        "players": h.players,
                        "heap_used_bytes": h.heap_used_bytes,
                    })),
                    "dropped_connections": view.abuse.load(Ordering::Relaxed),
                })),
            }));
        }
        let pool = match self.inner.parts.volumes.pool_status().await
        {
            Ok(status) => json!({
                "size_bytes": status.usage.size_bytes,
                "used_percent": status.usage.used_percent,
                "alert": format!("{:?}", status.alert),
            }),
            Err(error) => json!({ "error": error.to_string() }),
        };
        let observed = lock(&self.inner.observed);
        let resources = |r: &Resources| json!({ "vcpus": r.vcpus, "memory_mib": r.memory_mib, "disk_gib": r.disk_gib });
        Ok(json!({
            "node_id": self.inner.config.node_id,
            "sandbox_kind": format!("{:?}", self.inner.parts.sandbox.kind()),
            "draining": self.inner.draining.load(Ordering::SeqCst),
            "capacity": resources(&self.inner.config.capacity),
            "reservation": resources(&self.inner.config.reservation),
            "allocatable": resources(&self.inner.allocatable()),
            "committed": resources(&observed.committed),
            "network_pending": lock(&self.inner.pending_network).is_some(),
            "pool": pool,
            "image_cache": {
                "hits": self.inner.parts.images.hits(),
                "misses": self.inner.parts.images.misses(),
            },
            "leases": leases,
            "instances": instances,
        }))
    }

    pub fn console_path(&self, instance_id: &str) -> Option<PathBuf>
    {
        lock(&self.inner.observed)
            .instances
            .get(instance_id)
            .and_then(|view| view.console_path.clone())
    }

    pub async fn shutdown(&self)
    {
        if self.inner.shut_down.swap(true, Ordering::SeqCst)
        {
            return;
        }
        self.inner
            .node_span
            .in_scope(|| tracing::info!("reconciler shutting down; instances keep running"));
        let tasks: Vec<JoinHandle<()>> = lock(&self.inner.tasks).drain(..).collect();
        for task in &tasks
        {
            task.abort();
        }
        for task in tasks
        {
            let _ = task.await;
        }
        let links: Vec<SupervisorLink> = std::mem::take(&mut *lock(&self.inner.supervisors))
            .into_values()
            .collect();
        for link in &links
        {
            link.task.abort();
        }
        for link in links
        {
            let _ = link.task.await;
        }
        lock(&self.inner.events).take();
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &Arc<Inner>
    {
        &self.inner
    }
}
