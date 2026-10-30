//! In-process stub of the control plane's `AgentGateway` for integration tests.
//!
//! It numbers its own messages, replays unacknowledged ones on reconnect,
//! always sends a full `DesiredState` after `Hello`, acknowledges every
//! numbered agent message, optionally grants leases, and records everything
//! the agent sends.

mod gateway;
mod pki;
mod state;

pub use pki::{CLIENT_CERT_VALIDITY, TestPki};

use gateway::Gateway;
use proto::v1::agent_gateway_server::AgentGatewayServer;
use proto::v1::{
    AgentMessage, AgentUpdate, DeleteInstance, EnrollRequest, InstanceSpec, LeaseGrant, LogChunk,
    NetworkConfig, PutInstance, RunOperation, control_message,
};
use state::State;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, watch};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

/// Error starting the stub or handling its PKI.
#[derive(Debug, thiserror::Error)]
pub enum StubError
{
    #[error("certificate error: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("system clock is outside the representable certificate validity range")]
    Clock,
}

/// Configuration for [`StubControlPlane::start`].
#[derive(Debug, Clone)]
pub struct StubConfig
{
    /// Address to listen on; port 0 picks a free port.
    pub listen: SocketAddr,
    pub pki: TestPki,
    /// Join token accepted by `Enroll`; empty disables token enrollment.
    pub join_token: String,
    /// TTL put in automatic lease grants.
    pub lease_ttl_ms: u64,
    /// Answer every `LeaseRenewal` with a `LeaseGrant` per listed lease.
    pub auto_grant_leases: bool,
}

pub(crate) struct Shared
{
    pub(crate) pki: TestPki,
    pub(crate) join_token: String,
    local_addr: SocketAddr,
    pub(crate) state: Mutex<State>,
    pub(crate) arrivals: watch::Sender<u64>,
}

/// Handle to a running stub control plane. Clones share the same instance.
#[derive(Clone)]
pub struct StubControlPlane
{
    shared: Arc<Shared>,
}

impl StubControlPlane
{
    /// Binds `config.listen` and serves `AgentGateway` over mTLS in a spawned task.
    pub async fn start(config: StubConfig) -> Result<StubControlPlane, StubError>
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                &config.pki.server_cert_pem,
                &config.pki.server_key_pem,
            ))
            .client_ca_root(Certificate::from_pem(&config.pki.ca_cert_pem))
            .client_auth_optional(true);
        let (arrivals, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            pki: config.pki,
            join_token: config.join_token,
            local_addr,
            state: Mutex::new(State::new(config.lease_ttl_ms, config.auto_grant_leases)),
            arrivals,
        });
        let router = Server::builder()
            .tls_config(tls)?
            .add_service(AgentGatewayServer::new(Gateway {
                shared: Arc::clone(&shared),
            }));
        tokio::spawn(async move {
            if let Err(error) = router
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
            {
                tracing::error!(%error, "stub control plane stopped");
            }
        });
        tracing::info!(%local_addr, "stub control plane listening");
        Ok(StubControlPlane { shared })
    }

    pub fn local_addr(&self) -> SocketAddr
    {
        self.shared.local_addr
    }

    /// `https://localhost:<port>`.
    pub fn endpoint(&self) -> String
    {
        format!("https://localhost:{}", self.shared.local_addr.port())
    }

    pub fn ca_cert_pem(&self) -> String
    {
        self.shared.pki.ca_cert_pem.clone()
    }

    pub fn pki(&self) -> &TestPki
    {
        &self.shared.pki
    }

    /// Replaces the state sent in `DesiredState` on every connect. Sends nothing by itself.
    pub async fn set_desired(&self, specs: Vec<InstanceSpec>, network: Option<NetworkConfig>)
    {
        let mut state = self.shared.state.lock().await;
        state.desired = specs;
        state.network = network;
    }

    pub async fn live_metrics(&self, live: proto::v1::LiveMetrics) -> u64
    {
        self.shared
            .state
            .lock()
            .await
            .push(control_message::Body::Live(live))
    }

    /// Sends a `DesiredState` with the current desired state now.
    pub async fn send_desired(&self) -> u64
    {
        let mut state = self.shared.state.lock().await;
        let desired = proto::v1::DesiredState {
            instances: state.desired.clone(),
            network: state.network.clone(),
        };
        state.push(control_message::Body::Desired(desired))
    }

    /// Adds or replaces the spec in the desired state and sends `PutInstance`.
    pub async fn put_instance(&self, spec: InstanceSpec) -> u64
    {
        let mut state = self.shared.state.lock().await;
        state.upsert_desired(spec.clone());
        state.push(control_message::Body::Put(PutInstance { spec: Some(spec) }))
    }

    /// Removes the spec from the desired state and sends `DeleteInstance`.
    pub async fn delete_instance(&self, id: &str) -> u64
    {
        let mut state = self.shared.state.lock().await;
        state.desired.retain(|spec| spec.id != id);
        state.push(control_message::Body::Delete(DeleteInstance {
            id: id.to_owned(),
        }))
    }

    pub async fn run_operation(&self, op: RunOperation) -> u64
    {
        self.shared
            .state
            .lock()
            .await
            .push(control_message::Body::Op(op))
    }

    pub async fn grant_lease(&self, grant: LeaseGrant) -> u64
    {
        self.shared
            .state
            .lock()
            .await
            .push(control_message::Body::Lease(grant))
    }

    /// Sets the desired network configuration and sends it.
    pub async fn send_network_config(&self, cfg: NetworkConfig) -> u64
    {
        let mut state = self.shared.state.lock().await;
        state.network = Some(cfg.clone());
        state.push(control_message::Body::Network(cfg))
    }

    pub async fn send_agent_update(&self, update: AgentUpdate) -> u64
    {
        self.shared
            .state
            .lock()
            .await
            .push(control_message::Body::Update(update))
    }

    /// Re-sends an already sent message with its original seq. False if the
    /// seq is unknown or no agent is connected.
    pub async fn resend(&self, seq: u64) -> bool
    {
        self.shared.state.lock().await.resend(seq)
    }

    /// Ends the current `Connect` stream with `UNAVAILABLE` so the agent reconnects.
    pub async fn disconnect(&self)
    {
        self.shared
            .state
            .lock()
            .await
            .close(Status::unavailable("stream closed by control plane"));
    }

    /// `false` simulates an outage: the current stream ends and every RPC
    /// fails with `UNAVAILABLE` until set back to `true`.
    pub async fn set_available(&self, available: bool)
    {
        let mut state = self.shared.state.lock().await;
        state.available = available;
        if !available
        {
            state.close(Status::unavailable("control plane unavailable"));
        }
    }

    pub async fn set_auto_grant_leases(&self, on: bool)
    {
        self.shared.state.lock().await.auto_grant_leases = on;
    }

    /// Every agent message in arrival order, duplicates included.
    pub async fn received(&self) -> Vec<AgentMessage>
    {
        self.shared.state.lock().await.received.clone()
    }

    /// Agent messages whose seq was above the highest seen at arrival.
    pub async fn processed(&self) -> Vec<AgentMessage>
    {
        self.shared.state.lock().await.processed.clone()
    }

    /// First received message (earlier or future) matching `pred`, or `None` after `timeout`.
    pub async fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&AgentMessage) -> bool,
    ) -> Option<AgentMessage>
    {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut arrivals = self.shared.arrivals.subscribe();
        let mut scanned = 0;
        loop
        {
            {
                let state = self.shared.state.lock().await;
                if let Some(found) = state.received[scanned..]
                    .iter()
                    .find(|message| pred(message))
                {
                    return Some(found.clone());
                }
                scanned = state.received.len();
            }
            match tokio::time::timeout_at(deadline, arrivals.changed()).await
            {
                Ok(Ok(())) =>
                {}
                Ok(Err(_)) | Err(_) => return None,
            }
        }
    }

    /// Number of `Connect` streams that completed `Hello`.
    pub async fn connection_count(&self) -> u64
    {
        self.shared.state.lock().await.connection_count
    }

    /// Every `Enroll` request received, including rejected ones.
    pub async fn enrollments(&self) -> Vec<EnrollRequest>
    {
        self.shared.state.lock().await.enrollments.clone()
    }

    pub async fn log_chunks(&self) -> Vec<LogChunk>
    {
        self.shared.state.lock().await.log_chunks.clone()
    }

    /// Highest `ack` the agent has sent.
    pub async fn last_agent_ack(&self) -> u64
    {
        self.shared.state.lock().await.highest_agent_ack
    }
}
