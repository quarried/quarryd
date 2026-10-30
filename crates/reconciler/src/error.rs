use proto::v1::Phase;

#[derive(Debug, thiserror::Error)]
pub enum ReconcilerError
{
    #[error(transparent)]
    Store(#[from] store::StoreError),
    #[error(transparent)]
    Sandbox(#[from] sandbox::SandboxError),
    #[error(transparent)]
    Volume(#[from] volume::VolumeError),
    #[error(transparent)]
    Network(#[from] network::NetworkError),
    #[error(transparent)]
    Usage(#[from] usage::UsageError),
    #[error("guest channel: {0}")]
    Frame(#[from] guest_proto::FrameError),
    #[error("invalid guest message: {0}")]
    GuestProto(#[from] guest_proto::GuestProtoError),
    #[error("stored spec cannot be decoded: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{context}: {source}")]
    Io
    {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid lifecycle transition from {from} to {to}")]
    InvalidTransition
    {
        from: Phase, to: Phase
    },
    #[error("instance {0} not found")]
    InstanceNotFound(String),
    #[error("instance {id} is {phase}, not RUNNING")]
    NotRunning
    {
        id: String, phase: Phase
    },
    #[error("no snapshot store is configured")]
    SnapshotsUnavailable,
    #[error("guest agent of instance {0} is not connected")]
    GuestNotConnected(String),
    #[error("guest could not prepare the snapshot: {0}")]
    SnapshotRefused(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("invalid console command: {0}")]
    InvalidCommand(String),
    #[error("supervisor of instance {0} is busy")]
    Busy(String),
    #[error("node network is not configured")]
    NetworkNotConfigured,
    #[error("instance spec has no {0}")]
    MissingField(&'static str),
    #[error("the reconciler is shut down")]
    ShutDown,
    #[error("background task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl ReconcilerError
{
    pub(crate) fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> ReconcilerError
    {
        let context = context.into();
        move |source| ReconcilerError::Io { context, source }
    }
}
