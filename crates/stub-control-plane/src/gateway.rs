use crate::Shared;
use crate::pki::{certificate_common_name, csr_common_name};
use crate::state::{Connection, ControlSender};
use proto::v1::agent_gateway_server::AgentGateway;
use proto::v1::{
    AgentMessage, EnrollRequest, EnrollResponse, LogChunk, LogStreamSummary, agent_message,
};
use rcgen::CertificateSigningRequestParams;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status, Streaming};

pub(crate) struct Gateway
{
    pub(crate) shared: Arc<Shared>,
}

fn outage() -> Status
{
    Status::unavailable("control plane unavailable")
}

fn client_common_name<T>(request: &Request<T>) -> Option<String>
{
    let certificates = request.peer_certs()?;
    certificate_common_name(certificates.first()?)
}

fn require_client_certificate<T>(request: &Request<T>) -> Result<String, Status>
{
    client_common_name(request)
        .ok_or_else(|| Status::unauthenticated("client certificate required"))
}

impl Gateway
{
    async fn ensure_available(&self) -> Result<(), Status>
    {
        if self.shared.state.lock().await.available
        {
            Ok(())
        }
        else
        {
            Err(outage())
        }
    }
}

#[tonic::async_trait]
impl AgentGateway for Gateway
{
    type ConnectStream = UnboundedReceiverStream<Result<proto::v1::ControlMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status>
    {
        let node = require_client_certificate(&request)?;
        self.ensure_available().await?;
        let (sender, receiver) = mpsc::unbounded_channel();
        tokio::spawn(run_session(
            Arc::clone(&self.shared),
            request.into_inner(),
            sender,
            node,
        ));
        Ok(Response::new(UnboundedReceiverStream::new(receiver)))
    }

    async fn stream_logs(
        &self,
        request: Request<Streaming<LogChunk>>,
    ) -> Result<Response<LogStreamSummary>, Status>
    {
        require_client_certificate(&request)?;
        self.ensure_available().await?;
        let mut inbound = request.into_inner();
        let mut bytes_received = 0u64;
        while let Some(chunk) = inbound.message().await?
        {
            let mut state = self.shared.state.lock().await;
            if !state.available
            {
                return Err(outage());
            }
            bytes_received += chunk.data.len() as u64;
            state.log_chunks.push(chunk);
        }
        Ok(Response::new(LogStreamSummary { bytes_received }))
    }

    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status>
    {
        let presented_identity = client_common_name(&request);
        let enroll = request.into_inner();
        let mut state = self.shared.state.lock().await;
        if !state.available
        {
            return Err(outage());
        }
        tracing::info!(node_id = %enroll.node_id, with_token = !enroll.join_token.is_empty(), "enroll request");
        state.enrollments.push(enroll.clone());
        if enroll.node_id.is_empty()
        {
            return Err(Status::invalid_argument("node_id is required"));
        }
        if enroll.join_token.is_empty()
        {
            match presented_identity
            {
                None =>
                {
                    return Err(Status::unauthenticated(
                        "join token or client certificate required",
                    ));
                }
                Some(identity) if identity != enroll.node_id =>
                {
                    return Err(Status::permission_denied(
                        "client certificate belongs to another node",
                    ));
                }
                Some(_) =>
                {}
            }
        }
        else
        {
            if self.shared.join_token.is_empty() || enroll.join_token != self.shared.join_token
            {
                return Err(Status::unauthenticated("invalid join token"));
            }
            if state
                .join_token_owner
                .as_ref()
                .is_some_and(|owner| *owner != enroll.node_id)
            {
                return Err(Status::unauthenticated("join token already used"));
            }
        }
        let csr = CertificateSigningRequestParams::from_pem(&enroll.csr_pem)
            .map_err(|error| Status::invalid_argument(format!("invalid CSR: {error}")))?;
        if csr_common_name(&csr).as_deref() != Some(enroll.node_id.as_str())
        {
            return Err(Status::invalid_argument(
                "CSR common name must equal node_id",
            ));
        }
        let issued = self
            .shared
            .pki
            .sign_csr(&csr)
            .map_err(|error| Status::internal(format!("signing failed: {error}")))?;
        if !enroll.join_token.is_empty()
        {
            state.join_token_owner = Some(enroll.node_id.clone());
        }
        Ok(Response::new(EnrollResponse {
            certificate_pem: issued.certificate_pem,
            ca_pem: self.shared.pki.ca_cert_pem.clone(),
            expires_at_unix: issued.expires_at_unix,
        }))
    }
}

async fn run_session(
    shared: Arc<Shared>,
    mut inbound: Streaming<AgentMessage>,
    sender: ControlSender,
    node: String,
)
{
    let hello = match inbound.message().await
    {
        Ok(Some(message)) => message,
        Ok(None) | Err(_) => return,
    };
    let (cancel, mut cancelled) = oneshot::channel();
    let connection_id = {
        let mut state = shared.state.lock().await;
        let hello_ack = hello.ack;
        let is_hello = matches!(hello.body, Some(agent_message::Body::Hello(_)));
        state.record(hello);
        shared.arrivals.send_modify(|count| *count += 1);
        if !is_hello
        {
            let _ = sender.send(Err(Status::invalid_argument("first message must be Hello")));
            return;
        }
        if !state.available
        {
            let _ = sender.send(Err(outage()));
            return;
        }
        let connection_id = state.next_connection_id();
        tracing::info!(%node, connection_id, hello_ack, "agent connected");
        state.attach(Connection::new(connection_id, sender, cancel), hello_ack);
        connection_id
    };
    loop
    {
        tokio::select! {
            _ = &mut cancelled => return,
            next = inbound.message() => match next
            {
                Ok(Some(message)) =>
                {
                    let mut state = shared.state.lock().await;
                    if !state.is_current(connection_id)
                    {
                        return;
                    }
                    state.record(message);
                    shared.arrivals.send_modify(|count| *count += 1);
                }
                Ok(None) | Err(_) => break,
            },
        }
    }
    tracing::info!(%node, connection_id, "agent stream ended");
    shared.state.lock().await.detach(connection_id);
}
