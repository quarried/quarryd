use proto::v1::{
    AgentMessage, ControlMessage, DesiredState, EnrollRequest, InstanceSpec, LeaseGrant, LogChunk,
    NetworkConfig, agent_message, control_message,
};
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;

pub(crate) type ControlSender = mpsc::UnboundedSender<Result<ControlMessage, Status>>;

/// The attached `Connect` stream. Dropping it ends the response stream and
/// cancels the task reading the agent's messages.
pub(crate) struct Connection
{
    pub(crate) id: u64,
    sender: ControlSender,
    _cancel: oneshot::Sender<()>,
}

impl Connection
{
    pub(crate) fn new(id: u64, sender: ControlSender, cancel: oneshot::Sender<()>) -> Connection
    {
        Connection {
            id,
            sender,
            _cancel: cancel,
        }
    }
}

pub(crate) struct State
{
    pub(crate) available: bool,
    pub(crate) auto_grant_leases: bool,
    pub(crate) lease_ttl_ms: u64,
    pub(crate) desired: Vec<InstanceSpec>,
    pub(crate) network: Option<NetworkConfig>,
    last_control_seq: u64,
    history: BTreeMap<u64, ControlMessage>,
    agent_ack: u64,
    pub(crate) highest_agent_ack: u64,
    agent_watermark: u64,
    connection: Option<Connection>,
    next_connection_id: u64,
    pub(crate) connection_count: u64,
    pub(crate) received: Vec<AgentMessage>,
    pub(crate) processed: Vec<AgentMessage>,
    pub(crate) enrollments: Vec<EnrollRequest>,
    pub(crate) join_token_owner: Option<String>,
    pub(crate) log_chunks: Vec<LogChunk>,
}

impl State
{
    pub(crate) fn new(lease_ttl_ms: u64, auto_grant_leases: bool) -> State
    {
        State {
            available: true,
            auto_grant_leases,
            lease_ttl_ms,
            desired: Vec::new(),
            network: None,
            last_control_seq: 0,
            history: BTreeMap::new(),
            agent_ack: 0,
            highest_agent_ack: 0,
            agent_watermark: 0,
            connection: None,
            next_connection_id: 0,
            connection_count: 0,
            received: Vec::new(),
            processed: Vec::new(),
            enrollments: Vec::new(),
            join_token_owner: None,
            log_chunks: Vec::new(),
        }
    }

    pub(crate) fn next_connection_id(&mut self) -> u64
    {
        self.next_connection_id += 1;
        self.next_connection_id
    }

    pub(crate) fn is_current(&self, connection_id: u64) -> bool
    {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.id == connection_id)
    }

    /// Numbers `body` with the next control seq, keeps it for replay, and
    /// sends it if an agent is attached.
    pub(crate) fn push(&mut self, body: control_message::Body) -> u64
    {
        self.last_control_seq += 1;
        let seq = self.last_control_seq;
        let message = ControlMessage {
            seq,
            ack: self.agent_watermark,
            body: Some(body),
        };
        tracing::info!(
            seq,
            kind = control_kind(&message.body),
            "control message queued"
        );
        self.history.insert(seq, message.clone());
        self.send(message);
        seq
    }

    /// Re-sends a previously numbered message with its original seq.
    pub(crate) fn resend(&mut self, seq: u64) -> bool
    {
        let Some(message) = self.history.get(&seq).cloned()
        else
        {
            return false;
        };
        self.send(message)
    }

    /// Attaches a stream after its `Hello`: replays unacknowledged messages,
    /// then sends a fresh `DesiredState`.
    pub(crate) fn attach(&mut self, connection: Connection, hello_ack: u64)
    {
        self.close(Status::unavailable("superseded by a newer connection"));
        self.connection_count += 1;
        self.connection = Some(connection);
        self.highest_agent_ack = self.highest_agent_ack.max(hello_ack);
        if hello_ack > self.last_control_seq
        {
            tracing::warn!(
                hello_ack,
                last_control_seq = self.last_control_seq,
                "agent ack ahead of control seq; full resync"
            );
            self.last_control_seq = hello_ack;
            self.agent_ack = hello_ack;
        }
        else
        {
            self.agent_ack = hello_ack;
            let unacked: Vec<ControlMessage> = self
                .history
                .range(hello_ack.saturating_add(1)..)
                .map(|(_, message)| message.clone())
                .collect();
            for message in unacked
            {
                self.send(message);
            }
        }
        let desired = DesiredState {
            instances: self.desired.clone(),
            network: self.network.clone(),
        };
        self.push(control_message::Body::Desired(desired));
    }

    /// Ends the attached stream, if any, with `status`.
    pub(crate) fn close(&mut self, status: Status)
    {
        if let Some(connection) = self.connection.take()
        {
            let _ = connection.sender.send(Err(status));
        }
    }

    /// Ends the attached stream cleanly if it is `connection_id`.
    pub(crate) fn detach(&mut self, connection_id: u64)
    {
        if self.is_current(connection_id)
        {
            self.connection = None;
        }
    }

    /// Records an agent message, acknowledges it, and answers lease renewals.
    pub(crate) fn record(&mut self, message: AgentMessage)
    {
        tracing::info!(
            seq = message.seq,
            ack = message.ack,
            kind = agent_kind(&message.body),
            "agent message"
        );
        self.agent_ack = self.agent_ack.max(message.ack);
        self.highest_agent_ack = self.highest_agent_ack.max(message.ack);
        let fresh = message.seq > self.agent_watermark;
        if fresh
        {
            self.agent_watermark = message.seq;
            self.processed.push(message.clone());
        }
        if message.seq > 0
        {
            self.send(ControlMessage {
                seq: 0,
                ack: self.agent_watermark,
                body: None,
            });
        }
        if self.auto_grant_leases
            && (fresh || message.seq == 0)
            && let Some(agent_message::Body::Lease(renewal)) = &message.body
        {
            for held in &renewal.leases
            {
                self.push(control_message::Body::Lease(LeaseGrant {
                    instance_id: held.instance_id.clone(),
                    epoch: held.epoch,
                    ttl_ms: self.lease_ttl_ms,
                }));
            }
        }
        self.received.push(message);
    }

    pub(crate) fn upsert_desired(&mut self, spec: InstanceSpec)
    {
        match self
            .desired
            .iter_mut()
            .find(|existing| existing.id == spec.id)
        {
            Some(existing) => *existing = spec,
            None => self.desired.push(spec),
        }
    }

    fn send(&self, mut message: ControlMessage) -> bool
    {
        message.ack = self.agent_watermark;
        match &self.connection
        {
            Some(connection) => connection.sender.send(Ok(message)).is_ok(),
            None => false,
        }
    }
}

fn agent_kind(body: &Option<agent_message::Body>) -> &'static str
{
    match body
    {
        None => "ack",
        Some(agent_message::Body::Hello(_)) => "hello",
        Some(agent_message::Body::Heartbeat(_)) => "heartbeat",
        Some(agent_message::Body::Status(_)) => "status",
        Some(agent_message::Body::Usage(_)) => "usage",
        Some(agent_message::Body::OpResult(_)) => "op_result",
        Some(agent_message::Body::Lease(_)) => "lease",
        Some(agent_message::Body::Health(_)) => "health",
        Some(agent_message::Body::Wake(_)) => "wake",
    }
}

fn control_kind(body: &Option<control_message::Body>) -> &'static str
{
    match body
    {
        None => "ack",
        Some(control_message::Body::Put(_)) => "put",
        Some(control_message::Body::Delete(_)) => "delete",
        Some(control_message::Body::Op(_)) => "op",
        Some(control_message::Body::Network(_)) => "network",
        Some(control_message::Body::Lease(_)) => "lease",
        Some(control_message::Body::Update(_)) => "update",
        Some(control_message::Body::Desired(_)) => "desired",
        Some(control_message::Body::Live(_)) => "live",
    }
}
