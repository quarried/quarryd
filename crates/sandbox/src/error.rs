use std::io;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError
{
    #[error("operation not supported by this sandbox backend")]
    Unsupported,
    #[error("{context}: {source}")]
    Io
    {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("systemd D-Bus call failed: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("firecracker API returned {status}: {body}")]
    Api
    {
        status: u16, body: String
    },
    #[error("HTTP transport error: {0}")]
    Http(#[from] hyper::Error),
    #[error("invalid HTTP request: {0}")]
    HttpRequest(#[from] http::Error),
    #[error("{program} exited with {status:?}: {stderr}")]
    Command
    {
        program: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("invalid sandbox spec: {0}")]
    InvalidSpec(String),
    #[error("OCI spec error: {0}")]
    Oci(#[from] oci_spec::OciSpecError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system call failed: {0}")]
    Os(#[from] nix::errno::Errno),
    #[error("unit {unit} failed: {detail}")]
    UnitFailed
    {
        unit: String, detail: String
    },
    #[error("timed out: {0}")]
    Timeout(String),
}

pub(crate) fn io(context: impl Into<String>) -> impl FnOnce(io::Error) -> SandboxError
{
    let context = context.into();
    move |source| SandboxError::Io { context, source }
}
