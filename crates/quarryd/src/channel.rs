use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use proto::v1::agent_gateway_client::AgentGatewayClient;
use proto::v1::agent_message::Body as AgentBody;
use proto::v1::control_message::Body as ControlBody;
use proto::v1::{
    AgentMessage, Capabilities, ControlMessage, Hello, InstanceStatus, UsageBatch, UsageRecord,
};
use reconciler::{ReconcilerEvent, ReconcilerHandle};
use store::{Store, UsageRow};
use tokio::sync::{Mutex, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{debug, info, warn};
use usage::{Metrics, Outbox};

use crate::identity::Transport;
use crate::ops::Operations;
use crate::update::Updater;

const KV_NEXT_SEQ: &str = "channel.agent_next_seq";
const KV_CONTROL_WATERMARK: &str = "channel.control_watermark";
const USAGE_BATCH_LIMIT: usize = 500;
const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_CAP: Duration = Duration::from_secs(30);
const STABLE_CONNECTION: Duration = Duration::from_secs(30);

pub struct ChannelSettings
{
    pub node_id: String,
    pub agent_version: String,
    pub endpoints: Vec<String>,
    pub join_token: Option<String>,
    pub capabilities: Capabilities,
    pub heartbeat_interval: Duration,
}

pub struct ControlChannel
{
    settings: ChannelSettings,
    transport: Transport,
    store: Arc<Store>,
    reconciler: ReconcilerHandle,
    events: mpsc::UnboundedReceiver<ReconcilerEvent>,
    outbox: Outbox,
    metrics: Arc<Metrics>,
    operations: Operations,
    updater: Arc<Updater>,
    pending: BTreeMap<u64, AgentMessage>,
    usage_in_flight: BTreeMap<u64, Vec<String>>,
    next_seq: u64,
    watermark: u64,
    lease_renewal_sent: Option<Instant>,
    current_channel: Arc<Mutex<Option<Channel>>>,
    connected: watch::Sender<bool>,
}

enum Disconnect
{
    Stream(anyhow::Error),
    Shutdown,
}

pub fn jitter_fraction() -> f64
{
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(Instant::now().elapsed().as_nanos());
    (hasher.finish() % 10_000) as f64 / 10_000.0
}

pub fn backoff_delay(attempt: u32, jitter: f64) -> Duration
{
    let exponent = attempt.min(16);
    let raw = BACKOFF_BASE
        .saturating_mul(1u32 << exponent)
        .min(BACKOFF_CAP);
    let jittered = raw.as_secs_f64() * (0.5 + jitter * 0.5);
    Duration::from_secs_f64(jittered.min(BACKOFF_CAP.as_secs_f64()))
}

pub fn usage_record(row: &UsageRow) -> UsageRecord
{
    UsageRecord {
        id: row.id.clone(),
        instance_id: row.instance_id.clone(),
        bucket_start_unix: row.bucket_start_unix,
        bucket_seconds: row.bucket_seconds,
        cpu_usec: row.cpu_usec,
        memory_mib_max: row.memory_mib_max,
        memory_mib_avg: row.memory_mib_avg,
        disk_read_bytes: row.disk_read_bytes,
        disk_write_bytes: row.disk_write_bytes,
        net_rx_bytes: row.net_rx_bytes,
        net_tx_bytes: row.net_tx_bytes,
    }
}

fn control_kind(body: &ControlBody) -> &'static str
{
    match body
    {
        ControlBody::Put(_) => "put_instance",
        ControlBody::Delete(_) => "delete_instance",
        ControlBody::Op(_) => "run_operation",
        ControlBody::Network(_) => "network_config",
        ControlBody::Lease(_) => "lease_grant",
        ControlBody::Update(_) => "agent_update",
        ControlBody::Desired(_) => "desired_state",
    }
}

impl ControlChannel
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings: ChannelSettings,
        transport: Transport,
        store: Arc<Store>,
        reconciler: ReconcilerHandle,
        events: mpsc::UnboundedReceiver<ReconcilerEvent>,
        metrics: Arc<Metrics>,
        operations: Operations,
        updater: Arc<Updater>,
        current_channel: Arc<Mutex<Option<Channel>>>,
        connected: watch::Sender<bool>,
    ) -> Result<ControlChannel>
    {
        let next_seq = store.kv_get_u64(KV_NEXT_SEQ)?.unwrap_or(1).max(1);
        let watermark = store.kv_get_u64(KV_CONTROL_WATERMARK)?.unwrap_or(0);
        let outbox = Outbox::new(store.clone());
        Ok(ControlChannel {
            settings,
            transport,
            store,
            reconciler,
            events,
            outbox,
            metrics,
            operations,
            updater,
            pending: BTreeMap::new(),
            usage_in_flight: BTreeMap::new(),
            next_seq,
            watermark,
            lease_renewal_sent: None,
            current_channel,
            connected,
        })
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()>
    {
        let mut attempt: u32 = 0;
        let mut endpoint_index = 0usize;
        loop
        {
            if *shutdown.borrow()
            {
                return Ok(());
            }
            let endpoint =
                self.settings.endpoints[endpoint_index % self.settings.endpoints.len()].clone();
            endpoint_index = endpoint_index.wrapping_add(1);
            let started = Instant::now();
            match self.session(&endpoint, &mut shutdown).await
            {
                Disconnect::Shutdown => return Ok(()),
                Disconnect::Stream(error) =>
                {
                    warn!(endpoint = %endpoint, error = %format!("{error:#}"), "control channel disconnected");
                }
            }
            self.connected.send_replace(false);
            *self.current_channel.lock().await = None;
            if started.elapsed() >= STABLE_CONNECTION
            {
                attempt = 0;
            }
            let delay = backoff_delay(attempt, jitter_fraction());
            attempt = attempt.saturating_add(1);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => {}
            }
        }
    }

    async fn session(&mut self, endpoint: &str, shutdown: &mut watch::Receiver<bool>)
    -> Disconnect
    {
        let identity = match self
            .transport
            .ensure_identity(endpoint, self.settings.join_token.as_deref())
            .await
        {
            Ok(identity) => identity,
            Err(error) => return Disconnect::Stream(error),
        };
        let channel = match self.transport.connect(endpoint, Some(&identity)).await
        {
            Ok(channel) => channel,
            Err(error) => return Disconnect::Stream(error),
        };
        let (sender, receiver) = mpsc::channel::<AgentMessage>(256);
        let mut client = AgentGatewayClient::new(channel.clone());
        let hello = self.hello_message();
        if sender.send(hello).await.is_err()
        {
            return Disconnect::Stream(anyhow!("request stream closed before hello"));
        }
        let mut inbound = match client.connect(ReceiverStream::new(receiver)).await
        {
            Ok(response) => response.into_inner(),
            Err(status) => return Disconnect::Stream(anyhow!("connect rejected: {status}")),
        };
        info!(endpoint = %endpoint, watermark = self.watermark, "control channel connected");
        *self.current_channel.lock().await = Some(channel);
        self.connected.send_replace(true);
        if let Err(error) = self.after_connect(&sender).await
        {
            return Disconnect::Stream(error);
        }
        let mut heartbeat = tokio::time::interval(self.settings.heartbeat_interval);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut rotation_check = tokio::time::interval(Duration::from_secs(600));
        rotation_check.tick().await;
        loop
        {
            tokio::select! {
                message = inbound.message() => {
                    match message
                    {
                        Ok(Some(message)) =>
                        {
                            if let Err(error) = self.receive(message, &sender).await
                            {
                                return Disconnect::Stream(error);
                            }
                        }
                        Ok(None) => return Disconnect::Stream(anyhow!("control plane closed the stream")),
                        Err(status) => return Disconnect::Stream(anyhow!("stream error: {status}")),
                    }
                }
                event = self.events.recv() => {
                    match event
                    {
                        Some(ReconcilerEvent::Status(status)) =>
                        {
                            if let Err(error) = self.send_status(status, &sender).await
                            {
                                return Disconnect::Stream(error);
                            }
                        }
                        None => return Disconnect::Shutdown,
                    }
                }
                result = self.operations.next_result() => {
                    if let Some(result) = result
                    {
                        if let Err(error) = self.send_numbered(AgentBody::OpResult(result), &sender).await
                        {
                            return Disconnect::Stream(error);
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    if let Err(error) = self.periodic(&sender).await
                    {
                        return Disconnect::Stream(error);
                    }
                }
                _ = rotation_check.tick() => {
                    if let Ok(Some(current)) = self.transport.identity()
                    {
                        if current.needs_rotation(crate::identity::now_unix())
                        {
                            match self.transport.enroll(endpoint, Some(&current), "").await
                            {
                                Ok(_) => return Disconnect::Stream(anyhow!("certificate rotated; reconnecting with the new identity")),
                                Err(error) => warn!(error = %format!("{error:#}"), "certificate rotation failed"),
                            }
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow()
                    {
                        return Disconnect::Shutdown;
                    }
                }
            }
        }
    }

    fn hello_message(&self) -> AgentMessage
    {
        AgentMessage {
            seq: 0,
            ack: self.watermark,
            body: Some(AgentBody::Hello(Hello {
                node_id: self.settings.node_id.clone(),
                agent_version: self.settings.agent_version.clone(),
                capabilities: Some(self.settings.capabilities.clone()),
                inventory: Some(self.reconciler.inventory()),
            })),
        }
    }

    async fn after_connect(&mut self, sender: &mpsc::Sender<AgentMessage>) -> Result<()>
    {
        while self.events.try_recv().is_ok()
        {}
        let replay: Vec<AgentMessage> = self.pending.values().cloned().collect();
        for mut message in replay
        {
            message.ack = self.watermark;
            sender
                .send(message)
                .await
                .context("replaying unacked messages")?;
        }
        for status in self.reconciler.statuses()
        {
            self.send_status(status, sender).await?;
        }
        self.updater.confirm_connected().await;
        self.periodic(sender).await
    }

    async fn periodic(&mut self, sender: &mpsc::Sender<AgentMessage>) -> Result<()>
    {
        self.send_unnumbered(AgentBody::Heartbeat(self.reconciler.heartbeat()), sender)
            .await?;
        let renewal = self.reconciler.lease_renewal();
        if !renewal.leases.is_empty()
        {
            self.lease_renewal_sent = Some(Instant::now());
            self.send_unnumbered(AgentBody::Lease(renewal), sender)
                .await?;
        }
        self.send_usage(sender).await?;
        self.metrics.set_outbox_depth(self.outbox.depth()?);
        Ok(())
    }

    async fn send_usage(&mut self, sender: &mpsc::Sender<AgentMessage>) -> Result<()>
    {
        loop
        {
            let rows = self.outbox.next_batch(USAGE_BATCH_LIMIT)?;
            if rows.is_empty()
            {
                return Ok(());
            }
            let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
            let records = rows.iter().map(usage_record).collect();
            let seq = self
                .send_numbered(AgentBody::Usage(UsageBatch { records }), sender)
                .await?;
            self.outbox.mark_sent(seq, ids.clone());
            self.usage_in_flight.insert(seq, ids);
            if rows.len() < USAGE_BATCH_LIMIT
            {
                return Ok(());
            }
        }
    }

    async fn send_status(
        &mut self,
        status: InstanceStatus,
        sender: &mpsc::Sender<AgentMessage>,
    ) -> Result<()>
    {
        let superseded: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, message)| matches!(&message.body, Some(AgentBody::Status(existing)) if existing.id == status.id))
            .map(|(seq, _)| *seq)
            .collect();
        for seq in superseded
        {
            self.pending.remove(&seq);
        }
        self.send_numbered(AgentBody::Status(status), sender)
            .await?;
        Ok(())
    }

    async fn send_numbered(
        &mut self,
        body: AgentBody,
        sender: &mpsc::Sender<AgentMessage>,
    ) -> Result<u64>
    {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.store.kv_set_u64(KV_NEXT_SEQ, self.next_seq)?;
        let message = AgentMessage {
            seq,
            ack: self.watermark,
            body: Some(body),
        };
        self.pending.insert(seq, message.clone());
        sender
            .send(message)
            .await
            .context("request stream closed")?;
        Ok(seq)
    }

    async fn send_unnumbered(
        &mut self,
        body: AgentBody,
        sender: &mpsc::Sender<AgentMessage>,
    ) -> Result<()>
    {
        let message = AgentMessage {
            seq: 0,
            ack: self.watermark,
            body: Some(body),
        };
        sender.send(message).await.context("request stream closed")
    }

    async fn send_ack(&mut self, sender: &mpsc::Sender<AgentMessage>) -> Result<()>
    {
        let message = AgentMessage {
            seq: 0,
            ack: self.watermark,
            body: None,
        };
        sender.send(message).await.context("request stream closed")
    }

    fn apply_ack(&mut self, ack: u64) -> Result<()>
    {
        if ack == 0
        {
            return Ok(());
        }
        let remaining = self.pending.split_off(&(ack + 1));
        self.pending = remaining;
        let still_in_flight = self.usage_in_flight.split_off(&(ack + 1));
        let acked = std::mem::replace(&mut self.usage_in_flight, still_in_flight);
        if !acked.is_empty()
        {
            let deleted = self.outbox.ack(ack)?;
            debug!(ack, deleted, "usage records acknowledged");
            self.metrics.set_outbox_depth(self.outbox.depth()?);
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        message: ControlMessage,
        sender: &mpsc::Sender<AgentMessage>,
    ) -> Result<()>
    {
        self.apply_ack(message.ack)?;
        let Some(body) = message.body
        else
        {
            return Ok(());
        };
        let seq = message.seq;
        let kind = control_kind(&body);
        let is_desired = matches!(body, ControlBody::Desired(_));
        if seq == 0 && !is_desired
        {
            warn!(kind, "ignoring unnumbered control message");
            return Ok(());
        }
        if !is_desired && seq <= self.watermark
        {
            info!(seq, kind, "duplicate control message ignored");
            return self.send_ack(sender).await;
        }
        let op_id = match &body
        {
            ControlBody::Op(op) => op.op_id.clone(),
            _ => String::new(),
        };
        info!(seq, kind, op_id = %op_id, "control message");
        match body
        {
            ControlBody::Put(put) =>
            {
                let spec = put
                    .spec
                    .ok_or_else(|| anyhow!("PutInstance without spec"))?;
                self.reconciler.put_instance(spec).await?;
            }
            ControlBody::Delete(delete) => self.reconciler.delete_instance(&delete.id).await?,
            ControlBody::Op(op) => self.operations.start(op).await?,
            ControlBody::Network(config) => self.reconciler.configure_network(config).await?,
            ControlBody::Lease(grant) =>
            {
                if let Some(sent) = self.lease_renewal_sent.take()
                {
                    self.metrics.observe_lease_renew_latency(sent.elapsed());
                }
                self.reconciler.grant_lease(grant).await?;
            }
            ControlBody::Update(update) => self.updater.begin(update),
            ControlBody::Desired(desired) => self.reconciler.apply_desired_state(desired).await?,
        }
        if seq != 0
        {
            self.watermark = seq;
            self.store.kv_set_u64(KV_CONTROL_WATERMARK, seq)?;
        }
        self.send_ack(sender).await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn backoff_is_capped_at_thirty_seconds()
    {
        for attempt in 0..40
        {
            assert!(backoff_delay(attempt, 1.0) <= BACKOFF_CAP);
        }
        assert_eq!(backoff_delay(30, 1.0), BACKOFF_CAP);
    }

    #[test]
    fn backoff_grows_exponentially()
    {
        assert!(backoff_delay(1, 0.0) < backoff_delay(3, 0.0));
        assert_eq!(backoff_delay(0, 1.0), BACKOFF_BASE);
    }

    #[test]
    fn jitter_stays_in_unit_interval()
    {
        for _ in 0..100
        {
            let jitter = jitter_fraction();
            assert!((0.0..1.0).contains(&jitter));
        }
    }
}
