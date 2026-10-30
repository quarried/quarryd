use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use proto::v1::agent_gateway_client::AgentGatewayClient;
use proto::v1::run_operation::Kind;
use proto::v1::{LogChunk, OperationResult, OperationStatus, RunOperation};
use reconciler::ReconcilerHandle;
use store::{BeginOperation, OperationRow, OperationStatus as StoredStatus, Store};
use tokio::sync::{Mutex, mpsc};
use tonic::transport::Channel;
use tracing::{info, warn};

const LOG_CHUNK_BYTES: usize = 32 * 1024;
const LOG_FOLLOW_POLL: Duration = Duration::from_millis(500);

pub struct Operations
{
    store: Arc<Store>,
    reconciler: ReconcilerHandle,
    channel: Arc<Mutex<Option<Channel>>>,
    results_sender: mpsc::UnboundedSender<OperationResult>,
    results: mpsc::UnboundedReceiver<OperationResult>,
}

fn kind_name(kind: &Option<Kind>) -> &'static str
{
    match kind
    {
        Some(Kind::Snapshot(_)) => "snapshot_now",
        Some(Kind::Logs(_)) => "stream_logs",
        Some(Kind::Console(_)) => "send_console_command",
        Some(Kind::Drain(_)) => "drain",
        Some(Kind::Diagnostics(_)) => "collect_diagnostics",
        None => "unknown",
    }
}

fn stored_result(row: &OperationRow) -> OperationResult
{
    let status = match row.status
    {
        StoredStatus::Succeeded => OperationStatus::Succeeded,
        StoredStatus::Failed => OperationStatus::Failed,
        StoredStatus::InProgress => OperationStatus::Unspecified,
    };
    OperationResult {
        op_id: row.op_id.clone(),
        status: status as i32,
        message: row.message.clone(),
        payload: row.payload.clone(),
    }
}

impl Operations
{
    pub fn new(
        store: Arc<Store>,
        reconciler: ReconcilerHandle,
        channel: Arc<Mutex<Option<Channel>>>,
    ) -> Result<Operations>
    {
        let interrupted = store.list_operations(Some(StoredStatus::InProgress))?;
        for row in interrupted
        {
            warn!(op_id = %row.op_id, kind = %row.kind, "operation interrupted by an agent restart");
            store.finish_operation(&row.op_id, false, "interrupted by an agent restart", &[])?;
        }
        let (results_sender, results) = mpsc::unbounded_channel();
        Ok(Operations {
            store,
            reconciler,
            channel,
            results_sender,
            results,
        })
    }

    pub async fn next_result(&mut self) -> Option<OperationResult>
    {
        self.results.recv().await
    }

    pub async fn start(&mut self, op: RunOperation) -> Result<()>
    {
        let kind = kind_name(&op.kind);
        match self
            .store
            .begin_operation(&op.op_id, kind, &op.instance_id)?
        {
            BeginOperation::Finished(row) =>
            {
                info!(op_id = %op.op_id, "replayed operation answered from the stored result");
                let _ = self.results_sender.send(stored_result(&row));
                return Ok(());
            }
            BeginOperation::InProgress(_) =>
            {
                info!(op_id = %op.op_id, "replayed operation is still running");
                return Ok(());
            }
            BeginOperation::Started =>
            {}
        }
        let store = self.store.clone();
        let reconciler = self.reconciler.clone();
        let channel = self.channel.clone();
        let results = self.results_sender.clone();
        tokio::spawn(async move {
            let op_id = op.op_id.clone();
            let instance_id = op.instance_id.clone();
            let outcome = execute(&reconciler, &channel, op).await;
            let (succeeded, message, payload) = match outcome
            {
                Ok((message, payload)) => (true, message, payload),
                Err(error) => (false, format!("{error:#}"), Vec::new()),
            };
            info!(op_id = %op_id, instance_id = %instance_id, succeeded, "operation finished");
            if let Err(error) = store.finish_operation(&op_id, succeeded, &message, &payload)
            {
                warn!(op_id = %op_id, error = %error, "failed to record operation result");
            }
            let status = if succeeded
            {
                OperationStatus::Succeeded
            }
            else
            {
                OperationStatus::Failed
            };
            let _ = results.send(OperationResult {
                op_id,
                status: status as i32,
                message,
                payload,
            });
        });
        Ok(())
    }
}

async fn execute(
    reconciler: &ReconcilerHandle,
    channel: &Arc<Mutex<Option<Channel>>>,
    op: RunOperation,
) -> Result<(String, Vec<u8>)>
{
    match op.kind
    {
        Some(Kind::Snapshot(snapshot)) =>
        {
            let (manifest_key, size_bytes, disk) = reconciler
                .snapshot_details(&op.instance_id, &snapshot.destination_prefix)
                .await?;
            let payload = serde_json::to_vec(
                &serde_json::json!({"manifests": {disk: &manifest_key}, "size_bytes": size_bytes}),
            )?;
            Ok((manifest_key, payload))
        }
        Some(Kind::Console(console)) =>
        {
            let lines = reconciler
                .console_output(&op.instance_id, &op.op_id, &console.command)
                .await?;
            Ok(("completed".to_string(), lines.join("\n").into_bytes()))
        }
        Some(Kind::Drain(drain)) =>
        {
            reconciler.set_draining(drain.enabled);
            Ok((format!("draining={}", drain.enabled), Vec::new()))
        }
        Some(Kind::Diagnostics(_)) =>
        {
            let diagnostics = reconciler.diagnostics().await?;
            let payload = serde_json::to_vec(&diagnostics)?;
            Ok(("collected".to_string(), payload))
        }
        Some(Kind::Logs(logs)) =>
        {
            let sent = stream_logs(
                reconciler,
                channel,
                &op.op_id,
                &op.instance_id,
                logs.tail_bytes,
                logs.follow,
            )
            .await?;
            Ok((format!("streamed {sent} bytes"), Vec::new()))
        }
        None => anyhow::bail!("operation has no kind"),
    }
}

async fn stream_logs(
    reconciler: &ReconcilerHandle,
    channel: &Arc<Mutex<Option<Channel>>>,
    op_id: &str,
    instance_id: &str,
    tail_bytes: u64,
    follow: bool,
) -> Result<u64>
{
    let path = reconciler
        .console_path(instance_id)
        .ok_or_else(|| anyhow::anyhow!("instance {instance_id} has no console"))?;
    let connection = channel
        .lock()
        .await
        .clone()
        .ok_or_else(|| anyhow::anyhow!("control channel is not connected"))?;
    let (sender, receiver) = mpsc::channel::<LogChunk>(16);
    let mut client = AgentGatewayClient::new(connection);
    let upload = tokio::spawn(async move {
        client
            .stream_logs(tokio_stream::wrappers::ReceiverStream::new(receiver))
            .await
    });
    let mut sent: u64 = 0;
    let initial = sandbox::console::read_console(&path)?;
    let start = initial
        .len()
        .saturating_sub(usize::try_from(tail_bytes).unwrap_or(usize::MAX));
    let mut seen = initial.len();
    let mut last_snapshot = initial.clone();
    let chunk = |data: &[u8], eof: bool| LogChunk {
        op_id: op_id.to_string(),
        instance_id: instance_id.to_string(),
        data: data.to_vec(),
        eof,
    };
    let mut closed = sender.send(chunk(&[], false)).await.is_err();
    for piece in initial[start..].chunks(LOG_CHUNK_BYTES)
    {
        if sender.send(chunk(piece, false)).await.is_err()
        {
            closed = true;
            break;
        }
        sent += piece.len() as u64;
    }
    while follow && !closed
    {
        tokio::time::sleep(LOG_FOLLOW_POLL).await;
        if upload.is_finished()
        {
            break;
        }
        let current = sandbox::console::read_console(&path)?;
        let fresh = new_console_bytes(&last_snapshot, &current, seen);
        seen = current.len();
        last_snapshot = current;
        for piece in fresh.chunks(LOG_CHUNK_BYTES)
        {
            if sender.send(chunk(piece, false)).await.is_err()
            {
                closed = true;
                break;
            }
            sent += piece.len() as u64;
        }
        if reconciler.console_path(instance_id).is_none()
        {
            break;
        }
    }
    let _ = sender.send(chunk(&[], true)).await;
    drop(sender);
    match upload.await
    {
        Ok(Ok(_)) => Ok(sent),
        Ok(Err(status)) if closed => Err(anyhow::anyhow!(
            "log stream closed by the control plane: {status}"
        )),
        Ok(Err(status)) => Err(anyhow::anyhow!("log upload failed: {status}")),
        Err(error) => Err(anyhow::anyhow!("log upload task failed: {error}")),
    }
}

pub fn new_console_bytes(previous: &[u8], current: &[u8], previous_len: usize) -> Vec<u8>
{
    if current.len() > previous_len && current.starts_with(previous)
    {
        return current[previous_len..].to_vec();
    }
    let overlap = (1..=previous.len().min(current.len()))
        .rev()
        .find(|length| current.starts_with(&previous[previous.len() - length..]));
    match overlap
    {
        Some(length) => current[length..].to_vec(),
        None => current.to_vec(),
    }
}

#[cfg(test)]
mod tests
{
    use super::new_console_bytes;

    #[test]
    fn appended_bytes_are_detected()
    {
        assert_eq!(new_console_bytes(b"abc", b"abcdef", 3), b"def");
    }

    #[test]
    fn wrapped_ring_keeps_only_new_bytes()
    {
        assert_eq!(new_console_bytes(b"abcdef", b"defghi", 6), b"ghi");
    }

    #[test]
    fn unchanged_console_yields_nothing()
    {
        assert!(new_console_bytes(b"abc", b"abc", 3).is_empty());
    }
}
