use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use guest_proto::{
    Configure, GuestBody, HostBody, HostMessage, PrepareSnapshot, ResumeWrites, Shutdown,
    SnapshotPrepared,
};
use network::NetworkAttachment;
use proto::v1::{InstanceSpec, InstanceStatus, Phase, RestartPolicy, RunState};
use sandbox::{SandboxHandle, SandboxRecord, SandboxState, ShutdownMode};
use store::{ActualState, InstanceRow};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tracing::Instrument;
use volume::VolumeInfo;

use crate::ReconcilerError;
use crate::admission::{Decision, Verdict, volume_name};
use crate::guest_channel::{GuestChannel, GuestEvent, GuestLimits};
use crate::leases::unix_ms_now;
use crate::lifecycle::Lifecycle;
use crate::provision::Prepared;
use crate::reconciler::{GuestView, Inner, InstanceView, SupervisorLink, lock};

pub(crate) const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(500);
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
const HEALTH_TIMEOUT: Duration = HEALTH_INTERVAL.saturating_mul(3);
const RETRY_DELAY: Duration = Duration::from_secs(1);
const SNAPSHOT_PREPARE_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_WAKE: Duration = Duration::from_secs(3600);
const COMMAND_BUFFER: usize = 8;

pub(crate) const LEASE_EXPIRED: &str = "lease expired";
pub(crate) const WAITING_FOR_LEASE: &str = "waiting for lease";
const WAITING_FOR_SECRETS: &str = "waiting for secrets from the control plane";
const WAITING_FOR_NETWORK: &str = "waiting for node network configuration";
const RUN_STATE_STOPPED: &str = "desired run state is STOPPED";
pub(crate) const NOT_ADOPTABLE: &str = "not adoptable after restart";

/// Desired state of one instance as handed from the reconciler to its supervisor.
#[derive(Clone)]
pub(crate) struct Desired
{
    pub spec: Arc<InstanceSpec>,
    pub deleted: bool,
    pub decision: Option<Decision>,
}

impl Desired
{
    pub fn same_as(&self, other: &Desired) -> bool
    {
        self.deleted == other.deleted
            && self.decision == other.decision
            && *self.spec == *other.spec
    }

    fn admitted(&self) -> bool
    {
        matches!(
            &self.decision,
            Some(Decision { generation, verdict: Verdict::Admitted(_) }) if *generation == self.spec.generation
        )
    }

    fn rejection(&self) -> Option<&str>
    {
        match &self.decision
        {
            Some(Decision {
                generation,
                verdict: Verdict::Rejected(reason),
            }) if *generation == self.spec.generation => Some(reason),
            _ => None,
        }
    }

    fn run_requested(&self) -> bool
    {
        RunState::try_from(self.spec.run_state) != Ok(RunState::Stopped)
    }
}

pub(crate) struct TakenSnapshot
{
    pub snapshot: VolumeInfo,
    pub volume: String,
    pub lease_epoch: u64,
}

pub(crate) enum Command
{
    Snapshot
    {
        reply: oneshot::Sender<Result<TakenSnapshot, ReconcilerError>>,
    },
    Console
    {
        message: HostMessage,
        reply: oneshot::Sender<Result<(), ReconcilerError>>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopOutcome
{
    Exited,
    Completed,
    TimedOut,
}

async fn next_guest_event(guest: &mut Option<GuestChannel>) -> GuestEvent
{
    match guest
    {
        Some(channel) => match channel.next_event().await
        {
            Some(event) => event,
            None => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}

fn sleep_until(at: Instant) -> tokio::time::Sleep
{
    tokio::time::sleep_until(tokio::time::Instant::from_std(at))
}

fn unix_now() -> i64
{
    unix_ms_now() / 1000
}

fn describe_exit(code: Option<i32>) -> String
{
    match code
    {
        Some(code) => format!("sandbox exited with code {code}"),
        None => "sandbox exited".to_owned(),
    }
}

/// One task per instance (section 4.4): owns the sandbox handle, the guest
/// channel, the restart policy, crash detection, and graceful stop.
pub(crate) struct Supervisor
{
    pub(crate) inner: Arc<Inner>,
    pub(crate) id: String,
    desired: watch::Receiver<Desired>,
    poke: Arc<Notify>,
    commands: mpsc::Receiver<Command>,

    pub(crate) phase: Phase,
    pub(crate) reason: String,
    pub(crate) observed_generation: u64,
    restart_count: u32,
    last_exit_unix: Option<i64>,
    pub(crate) uid: Option<u32>,
    pub(crate) guest_ip: Option<Ipv4Addr>,
    pub(crate) attachment: Option<NetworkAttachment>,
    pub(crate) handle: Option<SandboxHandle>,
    last_record: Option<SandboxRecord>,
    guest: Option<GuestChannel>,
    abuse: Arc<AtomicU64>,
    pub(crate) running_spec: Option<Arc<InstanceSpec>>,
    pub(crate) prepared: Option<Prepared>,

    connection: Option<u64>,
    guest_ready: bool,
    health: Option<guest_proto::Health>,
    health_reports: u64,
    shutdown_complete: bool,
    snapshot_prepared: Option<SnapshotPrepared>,
    phase_started: Instant,
    connect_deadline: Option<Instant>,
    ready_deadline: Option<Instant>,
    next_status_poll: Instant,
    sandbox_state: String,
    failed_at: Instant,
    restart_at: Option<Instant>,
    retry_at: Option<Instant>,
    running_since: Option<Instant>,
    last_health: Option<Instant>,
    health_warned: bool,
    exit_was_clean: bool,
    idle_since: Option<Instant>,
    reclaimed: bool,
    balloon_unsupported: bool,
    last_emitted: Option<InstanceStatus>,
    finished: bool,
}

impl Supervisor
{
    pub async fn spawn(
        inner: Arc<Inner>,
        row: InstanceRow,
        spec: InstanceSpec,
        decision: Option<Decision>,
    ) -> Result<SupervisorLink, ReconcilerError>
    {
        let spec = Arc::new(spec);
        let (desired_sender, desired) = watch::channel(Desired {
            spec: Arc::clone(&spec),
            deleted: row.desired_deleted,
            decision,
        });
        let (command_sender, commands) = mpsc::channel(COMMAND_BUFFER);
        let poke = Arc::new(Notify::new());
        let span = tracing::info_span!(parent: &inner.node_span, "instance", instance_id = %row.id);
        let now = Instant::now();
        let record: Option<SandboxRecord> = row
            .sandbox_record
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok());
        let attachment: Option<NetworkAttachment> = row
            .network_attachment
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok());
        let mut supervisor = Supervisor {
            id: row.id.clone(),
            desired,
            poke: Arc::clone(&poke),
            commands,
            phase: Lifecycle::parse_phase(&row.phase),
            reason: row.reason.clone(),
            observed_generation: row.observed_generation,
            restart_count: row.restart_count,
            last_exit_unix: row.last_exit_unix,
            uid: row.uid,
            guest_ip: row.guest_ip.as_deref().and_then(|ip| ip.parse().ok()),
            attachment,
            handle: None,
            last_record: record.clone(),
            guest: None,
            abuse: Arc::new(AtomicU64::new(0)),
            running_spec: Some(Arc::clone(&spec)),
            prepared: None,
            connection: None,
            guest_ready: false,
            health: None,
            health_reports: 0,
            shutdown_complete: false,
            snapshot_prepared: None,
            phase_started: now,
            connect_deadline: None,
            ready_deadline: None,
            next_status_poll: now,
            sandbox_state: "none".to_owned(),
            failed_at: now,
            restart_at: None,
            retry_at: None,
            running_since: None,
            last_health: None,
            health_warned: false,
            exit_was_clean: false,
            idle_since: None,
            reclaimed: false,
            balloon_unsupported: false,
            last_emitted: None,
            finished: false,
            inner,
        };
        supervisor.last_emitted = Some(supervisor.status());
        supervisor.publish_view();
        if let Some(record) = record
        {
            supervisor.adopt(record).instrument(span.clone()).await;
        }
        let task = tokio::spawn(supervisor.run().instrument(span));
        Ok(SupervisorLink {
            desired: desired_sender,
            poke,
            commands: command_sender,
            task,
        })
    }

    async fn adopt(&mut self, record: SandboxRecord)
    {
        let adopted = match self.inner.parts.sandbox.adopt(&record).await
        {
            Ok(adopted) => adopted,
            Err(error) =>
            {
                tracing::warn!(error = %error, "adoption failed");
                None
            }
        };
        let now = Instant::now();
        match adopted
        {
            Some(handle)
                if Lifecycle::holds_sandbox(self.phase) || self.phase == Phase::Deleting =>
            {
                tracing::info!(
                    phase = %self.phase,
                    pid = ?handle.record().pid,
                    "adopted running sandbox"
                );
                self.handle = Some(handle);
                self.sandbox_state = "running".to_owned();
                if let Err(error) = self.bind_guest()
                {
                    tracing::warn!(error = %error, "could not re-bind the guest channel");
                }
                match self.phase
                {
                    Phase::Booting =>
                    {
                        self.connect_deadline = Some(now + self.inner.config.guest_connect_timeout)
                    }
                    Phase::Starting =>
                    {
                        self.ready_deadline = Some(now + self.inner.config.ready_timeout)
                    }
                    Phase::Running =>
                    {
                        self.running_since = Some(now);
                        self.last_health = Some(now);
                    }
                    _ =>
                    {}
                }
                self.publish_view();
            }
            Some(handle) =>
            {
                tracing::warn!(phase = %self.phase, "destroying a stray sandbox left behind by a crash");
                self.handle = Some(handle);
                self.stop_sandbox_now().await;
                if let Err(error) = self.commit()
                {
                    tracing::warn!(error = %error, "persisting after stray cleanup failed");
                }
            }
            None =>
            {
                self.sandbox_state = "missing".to_owned();
                let result = match self.phase
                {
                    Phase::Booting | Phase::Starting | Phase::Running =>
                    {
                        tracing::warn!(phase = %self.phase, "sandbox is gone; not adoptable");
                        self.fail(NOT_ADOPTABLE.to_owned()).await
                    }
                    Phase::Stopping =>
                    {
                        let reason = self.reason.clone();
                        self.transition(Phase::Stopped, reason).await
                    }
                    _ => self.commit(),
                };
                if let Err(error) = result
                {
                    tracing::warn!(error = %error, "recording a non-adoptable sandbox failed");
                }
            }
        }
    }

    pub(crate) fn bind_guest(&mut self) -> Result<(), ReconcilerError>
    {
        self.guest = None;
        self.connection = None;
        self.guest_ready = false;
        let path = self.inner.parts.sandbox.guest_socket_path(&self.id);
        let limits = GuestLimits {
            rate_capacity: self.inner.config.guest_rate_capacity,
            rate_per_sec: self.inner.config.guest_rate_per_sec,
        };
        self.guest = Some(GuestChannel::bind(
            &self.id,
            &path,
            limits,
            Arc::clone(&self.abuse),
        )?);
        Ok(())
    }

    async fn run(mut self)
    {
        loop
        {
            if let Err(error) = self.advance().await
            {
                tracing::warn!(phase = %self.phase, error = %error, "supervisor step failed; retrying");
                self.retry_at = Some(Instant::now() + RETRY_DELAY);
            }
            if self.finished
            {
                break;
            }
            let wake_at = self.next_wake();
            tokio::select! {
                changed = self.desired.changed() =>
                {
                    if changed.is_err()
                    {
                        break;
                    }
                }
                _ = self.poke.notified() => {}
                command = self.commands.recv() =>
                {
                    match command
                    {
                        Some(command) => self.on_command(command).await,
                        None => break,
                    }
                }
                event = next_guest_event(&mut self.guest) =>
                {
                    if let Err(error) = self.on_guest_event(event).await
                    {
                        tracing::warn!(error = %error, "handling a guest event failed");
                    }
                }
                _ = sleep_until(wake_at) => {}
            }
        }
    }

    fn next_wake(&self) -> Instant
    {
        let now = Instant::now();
        let mut wake = now + IDLE_WAKE;
        let mut consider = |at: Option<Instant>| {
            if let Some(at) = at
            {
                wake = wake.min(at);
            }
        };
        consider(self.retry_at);
        match self.phase
        {
            Phase::Booting => consider(self.connect_deadline),
            Phase::Starting => consider(self.ready_deadline),
            Phase::Running =>
            {
                consider(
                    lock(&self.inner.leases)
                        .get(&self.id)
                        .map(|lease| lease.expires_at),
                );
                if !self.health_warned
                {
                    consider(self.last_health.map(|at| at + HEALTH_TIMEOUT));
                }
                consider(self.idle_reclaim_at());
            }
            Phase::Failed => consider(self.restart_at),
            _ =>
            {}
        }
        if self.handle.is_some() && Lifecycle::holds_sandbox(self.phase)
        {
            consider(Some(self.next_status_poll));
        }
        wake.max(now)
    }

    async fn advance(&mut self) -> Result<(), ReconcilerError>
    {
        if let Some(at) = self.retry_at
        {
            if Instant::now() < at
            {
                return Ok(());
            }
            self.retry_at = None;
        }
        loop
        {
            if self.finished
            {
                return Ok(());
            }
            let desired = self.desired.borrow_and_update().clone();
            let progressed = match self.phase
            {
                Phase::Pending | Phase::Unspecified => self.step_pending(&desired).await?,
                Phase::Preparing => self.step_preparing(&desired).await?,
                Phase::Booting | Phase::Starting => self.step_booting(&desired).await?,
                Phase::Running => self.step_running(&desired).await?,
                Phase::Stopping => self.step_stopping(&desired).await?,
                Phase::Stopped => self.step_stopped(&desired).await?,
                Phase::Failed => self.step_failed(&desired).await?,
                Phase::Rejected => self.step_rejected(&desired).await?,
                Phase::Deleting => self.step_deleting(&desired).await?,
                Phase::Deleted => false,
            };
            if !progressed
            {
                self.refresh_status();
                return Ok(());
            }
        }
    }

    fn refresh_status(&mut self)
    {
        if self.finished || self.phase == Phase::Deleted
        {
            return;
        }
        let status = self.status();
        if self.last_emitted.as_ref() != Some(&status)
        {
            self.inner.emit(status.clone());
            self.last_emitted = Some(status);
            self.publish_view();
        }
    }

    fn lease_valid(&self) -> bool
    {
        lock(&self.inner.leases).is_valid(&self.id, Instant::now())
    }

    fn secrets_ready(&self, spec: &InstanceSpec) -> bool
    {
        spec.secrets.is_empty()
            || lock(&self.inner.secrets)
                .get(&self.id)
                .is_some_and(|(generation, _)| *generation == spec.generation)
    }

    fn blocker(&self, desired: &Desired) -> Option<&'static str>
    {
        if !desired.run_requested()
        {
            Some(RUN_STATE_STOPPED)
        }
        else if !self.lease_valid()
        {
            Some(WAITING_FOR_LEASE)
        }
        else if !self.secrets_ready(&desired.spec)
        {
            Some(WAITING_FOR_SECRETS)
        }
        else if lock(&self.inner.ipam).is_none()
        {
            Some(WAITING_FOR_NETWORK)
        }
        else
        {
            None
        }
    }

    fn wants_running(&self, desired: &Desired) -> bool
    {
        !desired.deleted && desired.admitted() && self.blocker(desired).is_none()
    }

    async fn step_pending(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if desired.deleted
        {
            self.transition(Phase::Deleting, "deleted".to_owned())
                .await?;
            return Ok(true);
        }
        if let Some(reason) = desired.rejection()
        {
            self.observed_generation = desired.spec.generation;
            tracing::warn!(generation = desired.spec.generation, reason = %reason, "spec rejected by admission");
            self.transition(Phase::Rejected, reason.to_owned()).await?;
            return Ok(true);
        }
        if !desired.admitted()
        {
            return Ok(false);
        }
        if let Some(blocker) = self.blocker(desired)
        {
            self.set_reason(blocker)?;
            return Ok(false);
        }
        self.observed_generation = desired.spec.generation;
        self.running_spec = Some(Arc::clone(&desired.spec));
        self.transition(Phase::Preparing, String::new()).await?;
        Ok(true)
    }

    async fn step_preparing(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if desired.deleted
        {
            self.fail("deleted during preparation".to_owned()).await?;
            return Ok(true);
        }
        if let Some(reason) = desired.rejection()
        {
            self.fail(format!(
                "generation {} rejected: {reason}",
                desired.spec.generation
            ))
            .await?;
            return Ok(true);
        }
        if !desired.admitted()
        {
            return Ok(false);
        }
        let spec = Arc::clone(&desired.spec);
        if self.observed_generation != spec.generation
        {
            self.observed_generation = spec.generation;
            self.commit()?;
        }
        self.running_spec = Some(Arc::clone(&spec));
        match self.prepare(&spec).await
        {
            Ok(prepared) => self.prepared = Some(prepared),
            Err(error) =>
            {
                tracing::warn!(error = %error, "preparation failed");
                self.fail(format!("preparation failed: {error}")).await?;
                return Ok(true);
            }
        }
        if self.desired.has_changed().unwrap_or(false)
        {
            let latest = self.desired.borrow().spec.generation;
            if latest != spec.generation
            {
                return Ok(true);
            }
        }
        self.inner
            .parts
            .metrics
            .observe_boot_phase("preparing", self.phase_started.elapsed());
        self.boot(spec).await?;
        Ok(true)
    }

    async fn boot(&mut self, spec: Arc<InstanceSpec>) -> Result<(), ReconcilerError>
    {
        self.observed_generation = spec.generation;
        self.running_spec = Some(Arc::clone(&spec));
        self.shutdown_complete = false;
        self.ready_deadline = None;
        self.transition(Phase::Booting, String::new()).await?;
        self.connect_deadline = Some(Instant::now() + self.inner.config.guest_connect_timeout);
        if let Err(error) = self.launch().await
        {
            tracing::warn!(error = %error, "launch failed");
            self.fail(format!("launch failed: {error}")).await?;
        }
        Ok(())
    }

    async fn step_booting(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if self.handle.is_none()
        {
            if self.phase == Phase::Starting
            {
                self.fail("sandbox is missing".to_owned()).await?;
                return Ok(true);
            }
            if desired.deleted
            {
                self.fail("deleted during boot".to_owned()).await?;
                return Ok(true);
            }
            let spec = self
                .running_spec
                .clone()
                .unwrap_or_else(|| Arc::clone(&desired.spec));
            if self
                .prepared
                .as_ref()
                .is_none_or(|prepared| prepared.generation != spec.generation)
            {
                match self.prepare(&spec).await
                {
                    Ok(prepared) => self.prepared = Some(prepared),
                    Err(error) =>
                    {
                        self.fail(format!("preparation failed: {error}")).await?;
                        return Ok(true);
                    }
                }
            }
            self.connect_deadline = Some(Instant::now() + self.inner.config.guest_connect_timeout);
            if let Err(error) = self.launch().await
            {
                self.fail(format!("launch failed: {error}")).await?;
            }
            return Ok(true);
        }
        if desired.deleted
        {
            self.fail(format!("deleted during {}", self.phase)).await?;
            return Ok(true);
        }
        let now = Instant::now();
        if self.phase == Phase::Booting && self.connect_deadline.is_some_and(|at| now >= at)
        {
            let waited = self.inner.config.guest_connect_timeout;
            self.fail(format!(
                "guest agent did not connect within {} ms",
                waited.as_millis()
            ))
            .await?;
            return Ok(true);
        }
        if self.phase == Phase::Starting && self.ready_deadline.is_some_and(|at| now >= at)
        {
            let waited = self.inner.config.ready_timeout;
            self.fail(format!(
                "server did not report Ready within {} ms",
                waited.as_millis()
            ))
            .await?;
            return Ok(true);
        }
        if let Some(code) = self.poll_exit(false).await
        {
            self.fail(format!("{} during {}", describe_exit(code), self.phase))
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn step_running(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if self.handle.is_none()
        {
            self.fail("sandbox is missing".to_owned()).await?;
            return Ok(true);
        }
        if let Some(code) = self.poll_exit(false).await
        {
            self.crash(code).await?;
            return Ok(true);
        }
        let stop_reason = if desired.deleted
        {
            Some("deleting".to_owned())
        }
        else if let Some(reason) = desired.rejection()
        {
            Some(format!(
                "generation {} rejected: {reason}",
                desired.spec.generation
            ))
        }
        else if !desired.run_requested()
        {
            Some("stopped".to_owned())
        }
        else if desired.admitted() && desired.spec.generation != self.observed_generation
        {
            Some(format!(
                "restarting for generation {}",
                desired.spec.generation
            ))
        }
        else if !self.lease_valid()
        {
            tracing::warn!("lease expired without renewal; stopping gracefully");
            Some(LEASE_EXPIRED.to_owned())
        }
        else
        {
            None
        };
        if let Some(reason) = stop_reason
        {
            self.graceful_stop(reason).await?;
            return Ok(true);
        }
        self.check_health()?;
        self.reclaim_idle_memory().await;
        Ok(false)
    }

    async fn step_stopping(&mut self, _desired: &Desired) -> Result<bool, ReconcilerError>
    {
        let reason = self.reason.clone();
        self.graceful_stop(reason).await?;
        Ok(true)
    }

    async fn step_stopped(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if desired.deleted
        {
            self.transition(Phase::Deleting, "deleted".to_owned())
                .await?;
            return Ok(true);
        }
        if let Some(reason) = desired.rejection()
        {
            self.observed_generation = desired.spec.generation;
            self.transition(Phase::Rejected, reason.to_owned()).await?;
            return Ok(true);
        }
        if self.wants_running(desired)
        {
            return self.start_from_idle(Arc::clone(&desired.spec)).await;
        }
        if desired.admitted()
            && !desired.run_requested()
            && self.observed_generation != desired.spec.generation
        {
            self.observed_generation = desired.spec.generation;
            self.commit()?;
        }
        if desired.admitted()
            && let Some(blocker) = self.blocker(desired)
            && blocker != RUN_STATE_STOPPED
            && !(blocker == WAITING_FOR_LEASE && self.reason.starts_with(LEASE_EXPIRED))
        {
            self.set_reason(blocker)?;
        }
        Ok(false)
    }

    async fn step_failed(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if desired.deleted
        {
            self.transition(Phase::Deleting, "deleted".to_owned())
                .await?;
            return Ok(true);
        }
        if let Some(reason) = desired.rejection()
        {
            self.observed_generation = desired.spec.generation;
            self.transition(Phase::Rejected, reason.to_owned()).await?;
            return Ok(true);
        }
        if !desired.admitted()
        {
            return Ok(false);
        }
        let new_generation = desired.spec.generation != self.observed_generation;
        let policy = RestartPolicy::try_from(desired.spec.restart_policy)
            .unwrap_or(RestartPolicy::Unspecified);
        let allowed = new_generation
            || match policy
            {
                RestartPolicy::Always => true,
                RestartPolicy::Never => false,
                RestartPolicy::OnFailure | RestartPolicy::Unspecified => !self.exit_was_clean,
            };
        if !allowed
        {
            return Ok(false);
        }
        if let Some(blocker) = self.blocker(desired)
        {
            if blocker != RUN_STATE_STOPPED && !self.reason.ends_with(blocker)
            {
                let reason = format!("{}; {blocker}", self.reason);
                self.set_reason(&reason)?;
            }
            return Ok(false);
        }
        if new_generation
        {
            self.restart_count = 0;
        }
        else
        {
            let delay = self.restart_delay(policy);
            let due = *self.restart_at.get_or_insert(self.failed_at + delay);
            if Instant::now() < due
            {
                return Ok(false);
            }
            self.restart_count = self.restart_count.saturating_add(1);
            tracing::info!(
                restart_count = self.restart_count,
                policy = policy.as_str_name(),
                "restarting after failure"
            );
        }
        self.restart_at = None;
        self.start_from_idle(Arc::clone(&desired.spec)).await
    }

    fn restart_delay(&self, policy: RestartPolicy) -> Duration
    {
        match policy
        {
            RestartPolicy::Always => Duration::ZERO,
            _ =>
            {
                let base = self.inner.config.restart_backoff_base;
                let max = self.inner.config.restart_backoff_max;
                let factor = 2u32.saturating_pow(self.restart_count.min(30));
                base.saturating_mul(factor).min(max)
            }
        }
    }

    async fn start_from_idle(&mut self, spec: Arc<InstanceSpec>) -> Result<bool, ReconcilerError>
    {
        match self.prepare(&spec).await
        {
            Ok(prepared) => self.prepared = Some(prepared),
            Err(error) =>
            {
                tracing::warn!(error = %error, "preparation before boot failed");
                self.set_reason(&format!("preparation failed: {error}"))?;
                self.retry_at =
                    Some(Instant::now() + self.inner.config.restart_backoff_base.max(RETRY_DELAY));
                return Ok(false);
            }
        }
        self.boot(spec).await?;
        Ok(true)
    }

    async fn step_rejected(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        if desired.deleted
        {
            self.transition(Phase::Deleting, "deleted".to_owned())
                .await?;
            return Ok(true);
        }
        if desired.spec.generation == self.observed_generation
        {
            return Ok(false);
        }
        if let Some(reason) = desired.rejection()
        {
            self.observed_generation = desired.spec.generation;
            self.reason = reason.to_owned();
            self.commit()?;
            return Ok(false);
        }
        self.transition(Phase::Pending, String::new()).await?;
        Ok(true)
    }

    async fn step_deleting(&mut self, desired: &Desired) -> Result<bool, ReconcilerError>
    {
        self.stop_sandbox_now().await;
        self.release_resources(&desired.spec).await?;
        self.checkpoint("after-release").await;
        let deleted = InstanceStatus {
            phase: Phase::Deleted as i32,
            reason: String::new(),
            ..self.status()
        };
        Lifecycle::transition(self.phase, Phase::Deleted)?;
        self.phase = Phase::Deleted;
        tracing::info!("instance deleted");
        self.inner.emit(deleted.clone());
        self.last_emitted = Some(deleted);
        let resurrected = {
            let _guard = lock(&self.inner.write_lock);
            match self.inner.parts.store.get_instance(&self.id)?
            {
                Some(row) if !row.desired_deleted =>
                {
                    self.inner
                        .parts
                        .store
                        .update_actual(&self.id, &ActualState::default())?;
                    true
                }
                _ =>
                {
                    self.inner.parts.store.remove_instance(&self.id)?;
                    false
                }
            }
        };
        lock(&self.inner.observed).forgotten.push(self.id.clone());
        if resurrected
        {
            tracing::info!("instance was put again during deletion; starting over");
            self.reset_after_delete();
            self.transition(Phase::Pending, String::new()).await?;
            return Ok(true);
        }
        lock(&self.inner.leases).remove(&self.id);
        lock(&self.inner.secrets).remove(&self.id);
        lock(&self.inner.observed).instances.remove(&self.id);
        self.inner.wake.notify_one();
        self.finished = true;
        Ok(false)
    }

    fn reset_after_delete(&mut self)
    {
        self.observed_generation = 0;
        self.restart_count = 0;
        self.last_exit_unix = None;
        self.uid = None;
        self.guest_ip = None;
        self.attachment = None;
        self.handle = None;
        self.last_record = None;
        self.prepared = None;
        self.reason.clear();
    }

    async fn crash(&mut self, code: Option<i32>) -> Result<(), ReconcilerError>
    {
        tracing::warn!(exit_code = ?code, "sandbox crashed");
        if self
            .running_since
            .is_some_and(|since| since.elapsed() >= self.inner.config.restart_backoff_max)
        {
            self.restart_count = 0;
        }
        self.stop_sandbox_now().await;
        self.exit_was_clean = code == Some(0);
        self.enter_failed(describe_exit(code)).await
    }

    pub(crate) async fn fail(&mut self, reason: String) -> Result<(), ReconcilerError>
    {
        self.stop_sandbox_now().await;
        self.exit_was_clean = false;
        self.enter_failed(reason).await
    }

    async fn enter_failed(&mut self, reason: String) -> Result<(), ReconcilerError>
    {
        self.last_exit_unix = Some(unix_now());
        self.failed_at = Instant::now();
        self.restart_at = None;
        self.running_since = None;
        tracing::warn!(reason = %reason, "instance failed");
        self.transition(Phase::Failed, reason).await
    }

    async fn stop_sandbox_now(&mut self)
    {
        self.guest = None;
        self.connection = None;
        self.guest_ready = false;
        if let Some(handle) = self.handle.clone()
        {
            if let Err(error) = self
                .inner
                .parts
                .sandbox
                .shutdown(&handle, ShutdownMode::Force)
                .await
            {
                tracing::warn!(error = %error, "force shutdown failed");
            }
            if let Err(error) = self.inner.parts.sandbox.destroy(&handle).await
            {
                tracing::warn!(error = %error, "destroying the sandbox failed");
            }
            self.handle = None;
            self.sandbox_state = "destroyed".to_owned();
        }
    }

    async fn poll_exit(&mut self, force: bool) -> Option<Option<i32>>
    {
        let now = Instant::now();
        if !force && now < self.next_status_poll
        {
            return None;
        }
        self.next_status_poll = now + STATUS_POLL_INTERVAL;
        let handle = self.handle.clone()?;
        match self.inner.parts.sandbox.status(&handle).await
        {
            Ok(SandboxState::Running) =>
            {
                self.note_sandbox_state("running");
                None
            }
            Ok(SandboxState::Exited { code }) =>
            {
                self.note_sandbox_state(&match code
                {
                    Some(code) => format!("exited with code {code}"),
                    None => "exited".to_owned(),
                });
                Some(code)
            }
            Ok(SandboxState::Missing) =>
            {
                self.note_sandbox_state("missing");
                Some(None)
            }
            Err(error) =>
            {
                tracing::warn!(error = %error, "sandbox status check failed");
                None
            }
        }
    }

    fn note_sandbox_state(&mut self, state: &str)
    {
        if self.sandbox_state != state
        {
            self.sandbox_state = state.to_owned();
            self.publish_view();
        }
    }

    fn check_health(&mut self) -> Result<(), ReconcilerError>
    {
        let Some(last) = self.last_health
        else
        {
            return Ok(());
        };
        if !self.health_warned && last.elapsed() >= HEALTH_TIMEOUT
        {
            tracing::warn!(
                silent_ms = last.elapsed().as_millis() as u64,
                "guest stopped sending health reports"
            );
            self.health_warned = true;
            self.set_reason(&format!(
                "no guest health report for {} s",
                HEALTH_TIMEOUT.as_secs()
            ))?;
        }
        Ok(())
    }

    fn idle_reclaim_at(&self) -> Option<Instant>
    {
        let spec = self.running_spec.as_ref()?;
        if !spec.balloon_idle_reclaim || self.balloon_unsupported || self.reclaimed
        {
            return None;
        }
        self.idle_since
            .map(|since| since + Duration::from_secs(u64::from(spec.idle_reclaim_minutes) * 60))
    }

    async fn reclaim_idle_memory(&mut self)
    {
        let Some(spec) = self.running_spec.clone()
        else
        {
            return;
        };
        if !spec.balloon_idle_reclaim || self.balloon_unsupported
        {
            return;
        }
        let Some(handle) = self.handle.clone()
        else
        {
            return;
        };
        let players = self.health.as_ref().map(|health| health.players);
        let target = match players
        {
            Some(0) =>
            {
                let due = self.idle_reclaim_at();
                if self.reclaimed || due.is_none_or(|due| Instant::now() < due)
                {
                    return;
                }
                (spec.memory_mib / 2).max(1)
            }
            Some(_) if self.reclaimed => spec.memory_mib,
            _ => return,
        };
        match self
            .inner
            .parts
            .sandbox
            .set_memory_target(&handle, target)
            .await
        {
            Ok(()) =>
            {
                self.reclaimed = target < spec.memory_mib;
                tracing::info!(target_mib = target, "balloon memory target changed");
            }
            Err(sandbox::SandboxError::Unsupported) =>
            {
                tracing::info!("idle memory reclaim is not supported by this sandbox backend");
                self.balloon_unsupported = true;
            }
            Err(error) => tracing::warn!(error = %error, "setting the memory target failed"),
        }
    }

    pub(crate) async fn graceful_stop(&mut self, reason: String) -> Result<(), ReconcilerError>
    {
        if self.phase != Phase::Stopping
        {
            self.transition(Phase::Stopping, reason.clone()).await?;
        }
        let Some(handle) = self.handle.clone()
        else
        {
            self.guest = None;
            self.transition(Phase::Stopped, reason).await?;
            return Ok(());
        };
        let deadline = match self
            .running_spec
            .as_ref()
            .map(|spec| spec.stop_deadline_seconds)
        {
            Some(seconds) if seconds > 0 => Duration::from_secs(u64::from(seconds)),
            _ => self.inner.config.stop_deadline,
        };
        let kill_deadline = self.inner.config.kill_deadline;
        self.shutdown_complete = false;
        self.send_shutdown(deadline).await;
        let mut escalation = String::new();
        match self.wait_for_stop(Instant::now() + deadline, true).await
        {
            StopOutcome::Exited =>
            {}
            StopOutcome::Completed =>
            {
                if self
                    .wait_for_stop(Instant::now() + kill_deadline, false)
                    .await
                    != StopOutcome::Exited
                {
                    self.inner
                        .parts
                        .sandbox
                        .shutdown(&handle, ShutdownMode::Force)
                        .await?;
                }
            }
            StopOutcome::TimedOut =>
            {
                tracing::warn!(
                    deadline_ms = deadline.as_millis() as u64,
                    "guest did not stop before the deadline; shutting the sandbox down"
                );
                if let Err(error) = self
                    .inner
                    .parts
                    .sandbox
                    .shutdown(&handle, ShutdownMode::Graceful)
                    .await
                {
                    tracing::warn!(error = %error, "graceful sandbox shutdown failed");
                }
                escalation = format!(
                    "; guest did not stop within {} ms, sandbox shut down gracefully",
                    deadline.as_millis()
                );
                if self
                    .wait_for_stop(Instant::now() + kill_deadline, false)
                    .await
                    != StopOutcome::Exited
                {
                    tracing::warn!(
                        kill_deadline_ms = kill_deadline.as_millis() as u64,
                        "sandbox still running after the kill deadline; killing it"
                    );
                    self.inner
                        .parts
                        .sandbox
                        .shutdown(&handle, ShutdownMode::Force)
                        .await?;
                    escalation = format!(
                        "; guest did not stop within {} ms, sandbox killed after a further {} ms",
                        deadline.as_millis(),
                        kill_deadline.as_millis()
                    );
                }
            }
        }
        self.guest = None;
        self.connection = None;
        self.inner.parts.sandbox.destroy(&handle).await?;
        self.handle = None;
        self.sandbox_state = "destroyed".to_owned();
        self.checkpoint("after-destroy").await;
        self.transition(Phase::Stopped, format!("{reason}{escalation}"))
            .await
    }

    async fn send_shutdown(&mut self, deadline: Duration)
    {
        let Some(guest) = self.guest.as_ref()
        else
        {
            return;
        };
        if guest.connection().is_none()
        {
            return;
        }
        let message = HostMessage {
            body: Some(HostBody::Shutdown(Shutdown {
                deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            })),
        };
        match guest.send(&message).await
        {
            Ok(()) => tracing::info!(deadline_ms = deadline.as_millis() as u64, "sent Shutdown"),
            Err(error) => tracing::warn!(error = %error, "sending Shutdown failed"),
        }
    }

    async fn wait_for_stop(&mut self, until: Instant, accept_complete: bool) -> StopOutcome
    {
        loop
        {
            if accept_complete && self.shutdown_complete
            {
                return StopOutcome::Completed;
            }
            if let Some(code) = self.poll_exit(true).await
            {
                tracing::info!(exit_code = ?code, "sandbox exited");
                return StopOutcome::Exited;
            }
            if Instant::now() >= until
            {
                return StopOutcome::TimedOut;
            }
            let poll = (Instant::now() + STATUS_POLL_INTERVAL).min(until);
            tokio::select! {
                event = next_guest_event(&mut self.guest) =>
                {
                    let reconnected = matches!(event, GuestEvent::Connected { .. });
                    if let Err(error) = self.on_guest_event(event).await
                    {
                        tracing::warn!(error = %error, "handling a guest event failed");
                    }
                    if reconnected && accept_complete && !self.shutdown_complete
                    {
                        let remaining = until.saturating_duration_since(Instant::now());
                        self.send_shutdown(remaining).await;
                    }
                }
                _ = sleep_until(poll) => {}
            }
        }
    }

    async fn on_guest_event(&mut self, event: GuestEvent) -> Result<(), ReconcilerError>
    {
        match event
        {
            GuestEvent::Connected { connection } =>
            {
                self.connection = Some(connection);
                self.guest_ready = false;
                self.publish_view();
                if self.phase == Phase::Booting
                {
                    self.configure_guest().await?;
                }
            }
            GuestEvent::Message { connection, body } if Some(connection) == self.connection =>
            {
                self.on_guest_message(body).await?;
            }
            GuestEvent::Message { .. } =>
            {}
            GuestEvent::Disconnected {
                connection,
                reason,
                abusive,
            } =>
            {
                if Some(connection) == self.connection
                {
                    self.connection = None;
                    self.guest_ready = false;
                    self.next_status_poll = Instant::now();
                    self.publish_view();
                }
                if abusive
                {
                    tracing::warn!(reason = %reason, "guest connection rejected");
                }
            }
        }
        Ok(())
    }

    async fn configure_guest(&mut self) -> Result<(), ReconcilerError>
    {
        let Some(spec) = self.running_spec.clone()
        else
        {
            return Ok(());
        };
        let secrets = lock(&self.inner.secrets)
            .get(&self.id)
            .filter(|(generation, _)| *generation == spec.generation)
            .map(|(_, secrets)| secrets.clone())
            .unwrap_or_default();
        let message = HostMessage {
            body: Some(HostBody::Configure(Configure {
                instance_id: self.id.clone(),
                generation: spec.generation,
                env: spec.env.clone(),
                secrets,
                memory_mib: spec.memory_mib,
                server_command: Vec::new(),
            })),
        };
        let Some(guest) = self.guest.as_ref()
        else
        {
            return Ok(());
        };
        if let Err(error) = guest.send(&message).await
        {
            tracing::warn!(error = %error, "sending Configure failed; waiting for the guest to reconnect");
            return Ok(());
        }
        tracing::info!(generation = spec.generation, "sent Configure");
        self.checkpoint("after-configure").await;
        self.inner
            .parts
            .metrics
            .observe_boot_phase("booting", self.phase_started.elapsed());
        self.transition(Phase::Starting, String::new()).await?;
        self.ready_deadline = Some(Instant::now() + self.inner.config.ready_timeout);
        Ok(())
    }

    async fn on_guest_message(&mut self, body: GuestBody) -> Result<(), ReconcilerError>
    {
        match body
        {
            GuestBody::Ready(ready) =>
            {
                tracing::info!(server_version = %ready.server_version, "guest reports Ready");
                self.guest_ready = true;
                self.last_health = Some(Instant::now());
                self.publish_view();
                if self.phase == Phase::Starting
                {
                    self.inner
                        .parts
                        .metrics
                        .observe_boot_phase("starting", self.phase_started.elapsed());
                    self.running_since = Some(Instant::now());
                    self.transition(Phase::Running, String::new()).await?;
                }
            }
            GuestBody::Health(health) =>
            {
                self.inner.parts.metrics.set_guest_health(
                    &self.id,
                    health.tps,
                    health.mspt,
                    health.players,
                );
                self.last_health = Some(Instant::now());
                self.health_reports += 1;
                if health.players == 0
                {
                    self.idle_since.get_or_insert_with(Instant::now);
                }
                else
                {
                    self.idle_since = None;
                }
                self.health = Some(health);
                self.publish_view();
                if self.health_warned
                {
                    self.health_warned = false;
                    tracing::info!("guest health reports resumed");
                    if self.phase == Phase::Running
                    {
                        self.set_reason("")?;
                    }
                }
                if self.phase == Phase::Running
                {
                    self.reclaim_idle_memory().await;
                }
            }
            GuestBody::ShutdownComplete(complete) =>
            {
                tracing::info!(
                    exit_code = complete.exit_code,
                    "guest reports ShutdownComplete"
                );
                self.shutdown_complete = true;
            }
            GuestBody::SnapshotPrepared(prepared) =>
            {
                self.snapshot_prepared = Some(prepared);
            }
            GuestBody::Log(_) =>
            {}
        }
        Ok(())
    }

    async fn on_command(&mut self, command: Command)
    {
        match command
        {
            Command::Snapshot { reply } =>
            {
                let result = self.take_snapshot().await;
                let _ = reply.send(result);
            }
            Command::Console { message, reply } =>
            {
                let result = match (self.phase, self.guest.as_ref())
                {
                    (Phase::Running, Some(guest)) => guest.send(&message).await,
                    (Phase::Running, None) =>
                    {
                        Err(ReconcilerError::GuestNotConnected(self.id.clone()))
                    }
                    (phase, _) => Err(ReconcilerError::NotRunning {
                        id: self.id.clone(),
                        phase,
                    }),
                };
                if result.is_ok()
                {
                    tracing::info!("console command sent");
                }
                let _ = reply.send(result);
            }
        }
    }

    async fn take_snapshot(&mut self) -> Result<TakenSnapshot, ReconcilerError>
    {
        if self.phase != Phase::Running
        {
            return Err(ReconcilerError::NotRunning {
                id: self.id.clone(),
                phase: self.phase,
            });
        }
        let spec = self
            .running_spec
            .clone()
            .ok_or(ReconcilerError::MissingField("spec"))?;
        let disk = spec
            .disks
            .first()
            .ok_or(ReconcilerError::MissingField("disk"))?;
        let volume = volume_name(&self.id, &disk.name);
        let guest = self
            .guest
            .as_ref()
            .filter(|guest| guest.connection().is_some())
            .ok_or_else(|| ReconcilerError::GuestNotConnected(self.id.clone()))?;
        self.snapshot_prepared = None;
        let prepare = HostMessage {
            body: Some(HostBody::PrepareSnapshot(PrepareSnapshot {})),
        };
        let sent = guest.send(&prepare).await;
        let result = match sent
        {
            Ok(()) =>
            {
                tracing::info!("sent PrepareSnapshot");
                self.snapshot_volume(&volume).await
            }
            Err(error) => Err(error),
        };
        let resume = HostMessage {
            body: Some(HostBody::ResumeWrites(ResumeWrites {})),
        };
        match self.guest.as_ref()
        {
            Some(guest) => match guest.send(&resume).await
            {
                Ok(()) => tracing::info!("sent ResumeWrites"),
                Err(error) => tracing::warn!(error = %error, "sending ResumeWrites failed"),
            },
            None => tracing::warn!("guest channel closed before ResumeWrites"),
        }
        let snapshot = result?;
        Ok(TakenSnapshot {
            snapshot,
            volume,
            lease_epoch: lock(&self.inner.leases).epoch(&self.id),
        })
    }

    async fn snapshot_volume(&mut self, volume: &str) -> Result<VolumeInfo, ReconcilerError>
    {
        let until = Instant::now() + SNAPSHOT_PREPARE_TIMEOUT;
        while self.snapshot_prepared.is_none() && Instant::now() < until
        {
            tokio::select! {
                event = next_guest_event(&mut self.guest) =>
                {
                    self.on_guest_event(event).await?;
                }
                _ = sleep_until(until) => {}
            }
        }
        match self.snapshot_prepared.take()
        {
            Some(prepared) if prepared.ok =>
            {
                let name = format!("{volume}-snap-{}", unix_now());
                tracing::info!(snapshot = %name, "taking volume snapshot");
                Ok(self
                    .inner
                    .parts
                    .volumes
                    .backend()
                    .snapshot(volume, &name)
                    .await?)
            }
            Some(prepared) => Err(ReconcilerError::SnapshotRefused(prepared.error)),
            None => Err(ReconcilerError::Timeout(
                "waiting for the guest to prepare the snapshot".to_owned(),
            )),
        }
    }

    pub(crate) async fn transition(
        &mut self,
        to: Phase,
        reason: String,
    ) -> Result<(), ReconcilerError>
    {
        let from = self.phase;
        Lifecycle::transition(from, to).inspect_err(|error| {
            tracing::error!(error = %error, "refusing an invalid lifecycle transition");
        })?;
        self.phase = to;
        self.reason = reason;
        self.phase_started = Instant::now();
        tracing::info!(from = %from, to = %to, reason = %self.reason, generation = self.observed_generation, "phase transition");
        self.commit()?;
        self.inner.wake.notify_one();
        self.checkpoint(Lifecycle::phase_name(to)).await;
        Ok(())
    }

    pub(crate) fn set_reason(&mut self, reason: &str) -> Result<(), ReconcilerError>
    {
        if self.reason == reason
        {
            return Ok(());
        }
        self.reason = reason.to_owned();
        self.commit()
    }

    pub(crate) fn status(&self) -> InstanceStatus
    {
        InstanceStatus {
            id: self.id.clone(),
            observed_generation: self.observed_generation,
            phase: self.phase as i32,
            reason: self.reason.clone(),
            lease_epoch: lock(&self.inner.leases).epoch(&self.id),
            guest_ip: self.guest_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        }
    }

    pub(crate) fn commit(&mut self) -> Result<(), ReconcilerError>
    {
        self.persist()?;
        let status = self.status();
        if self.last_emitted.as_ref() != Some(&status)
        {
            self.inner.emit(status.clone());
            self.last_emitted = Some(status);
        }
        self.publish_view();
        Ok(())
    }

    fn persist(&mut self) -> Result<(), ReconcilerError>
    {
        if let Some(handle) = &self.handle
        {
            self.last_record = Some(handle.record().clone());
        }
        let record = self.handle.as_ref().map(SandboxHandle::record);
        let _guard = lock(&self.inner.write_lock);
        let lease = lock(&self.inner.leases).get(&self.id);
        let actual = ActualState {
            observed_generation: self.observed_generation,
            phase: Lifecycle::phase_name(self.phase).to_owned(),
            reason: self.reason.clone(),
            unit_name: record.map(|record| record.unit_name.clone()),
            api_socket: record
                .and_then(|record| record.api_socket.as_ref())
                .map(|path| path.display().to_string()),
            pid: record.and_then(|record| record.pid),
            sandbox_record: record.map(serde_json::to_string).transpose()?,
            network_attachment: self
                .attachment
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            guest_ip: self.guest_ip.map(|ip| ip.to_string()),
            uid: self.uid,
            restart_count: self.restart_count,
            last_exit_unix: self.last_exit_unix,
            lease_epoch: lease.map(|lease| lease.epoch).unwrap_or(0),
            lease_expires_unix_ms: lease.map(|lease| lease.expires_unix_ms),
        };
        self.inner.parts.store.update_actual(&self.id, &actual)?;
        Ok(())
    }

    pub(crate) fn publish_view(&self)
    {
        if self.finished || self.phase == Phase::Deleted
        {
            return;
        }
        let view = InstanceView {
            status: self.last_emitted.clone().unwrap_or_else(|| self.status()),
            record: self.handle.as_ref().map(|handle| handle.record().clone()),
            console_path: self
                .handle
                .as_ref()
                .map(|handle| handle.record().console_path.clone())
                .or_else(|| {
                    self.last_record
                        .as_ref()
                        .map(|record| record.console_path.clone())
                }),
            attachment: self.attachment.clone(),
            sandbox_state: self.sandbox_state.clone(),
            guest: GuestView {
                connected: self.connection.is_some(),
                ready: self.guest_ready,
                health: self.health.clone(),
                health_reports: self.health_reports,
            },
            abuse: Arc::clone(&self.abuse),
            vmm_metrics: None,
        };
        let mut observed = lock(&self.inner.observed);
        let vmm_metrics = observed
            .instances
            .get(&self.id)
            .and_then(|existing| existing.vmm_metrics);
        observed.instances.insert(
            self.id.clone(),
            InstanceView {
                vmm_metrics,
                ..view
            },
        );
    }

    pub(crate) async fn checkpoint(&self, label: &str)
    {
        #[cfg(test)]
        if crate::tests::crash::hit(&self.id, label)
        {
            tracing::warn!(label, "simulated crash: supervisor frozen");
            std::future::pending::<()>().await;
        }
        #[cfg(not(test))]
        let _ = label;
    }
}
