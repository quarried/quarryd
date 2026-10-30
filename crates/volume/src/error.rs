use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum VolumeError
{
    #[error("invalid volume name {name:?}")]
    InvalidName
    {
        name: String
    },
    #[error("volume {name:?} not found")]
    NotFound
    {
        name: String
    },
    #[error("thin pool is {used_percent:.1}% full; refusing new volumes")]
    PoolFull
    {
        used_percent: f64
    },
    #[error("{context}: {source}")]
    Io
    {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{command}` failed ({status}): {stderr}")]
    Command
    {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("unexpected output from `{command}`: {detail}")]
    Parse
    {
        command: String, detail: String
    },
    #[error(transparent)]
    ObjectStore(#[from] object_store::Error),
    #[error("snapshot manifest {key} not found")]
    ManifestMissing
    {
        key: String
    },
    #[error("invalid snapshot manifest {key}: {source}")]
    Manifest
    {
        key: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("unsupported snapshot manifest format version {version}")]
    UnsupportedFormat
    {
        version: u32
    },
    #[error("lease epoch {ours} is stale; the stored manifest is at epoch {current}")]
    StaleEpoch
    {
        ours: u64, current: u64
    },
    #[error("snapshot manifest {key} kept changing during a conditional write")]
    ManifestConflict
    {
        key: String
    },
    #[error("integrity check failed: {detail}")]
    Integrity
    {
        detail: String
    },
    #[error("restore target {path:?} holds {available} bytes but the image needs {needed}")]
    TargetTooSmall
    {
        path: PathBuf,
        needed: u64,
        available: u64,
    },
    #[error("invalid snapshot chunk size {chunk_size}")]
    InvalidChunkSize
    {
        chunk_size: u64
    },
    #[error("background task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl VolumeError
{
    pub(crate) fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> VolumeError
    {
        let context = context.into();
        move |source| VolumeError::Io { context, source }
    }
}
