use crate::GuestProtoError;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Local transport between the guest agent and quarryd, passed in [`crate::TRANSPORT_ENV`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport
{
    /// Firecracker: vsock to the host on `port`; written `vsock:<port>`.
    Vsock
    {
        /// Host vsock port.
        port: u32,
    },
    /// gVisor: Unix socket at an absolute path inside the sandbox; written `unix:<path>`.
    Unix(PathBuf),
}

impl FromStr for Transport
{
    type Err = GuestProtoError;

    fn from_str(value: &str) -> Result<Self, Self::Err>
    {
        let invalid = || GuestProtoError::InvalidTransport(value.to_owned());
        if let Some(port) = value.strip_prefix("vsock:")
        {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid());
            }
            let port = port.parse().map_err(|_| invalid())?;
            return Ok(Transport::Vsock { port });
        }
        if let Some(path) = value.strip_prefix("unix:")
        {
            if !Path::new(path).is_absolute() || path.contains('\0')
            {
                return Err(invalid());
            }
            return Ok(Transport::Unix(PathBuf::from(path)));
        }
        Err(invalid())
    }
}

impl fmt::Display for Transport
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Transport::Vsock { port } => write!(f, "vsock:{port}"),
            Transport::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::{GUEST_SOCKET_PATH, GUEST_VSOCK_PORT};

    #[test]
    fn parses_and_formats_vsock()
    {
        let transport: Transport = "vsock:5252".parse().unwrap();
        assert_eq!(
            transport,
            Transport::Vsock {
                port: GUEST_VSOCK_PORT
            }
        );
        assert_eq!(transport.to_string(), "vsock:5252");
    }

    #[test]
    fn parses_and_formats_unix()
    {
        let transport: Transport = "unix:/run/quarry/agent.sock".parse().unwrap();
        assert_eq!(transport, Transport::Unix(PathBuf::from(GUEST_SOCKET_PATH)));
        assert_eq!(transport.to_string(), "unix:/run/quarry/agent.sock");
    }

    #[test]
    fn round_trips_through_display()
    {
        for transport in [
            Transport::Vsock { port: 0 },
            Transport::Vsock { port: u32::MAX },
            Transport::Unix(PathBuf::from("/a b/c")),
        ]
        {
            assert_eq!(
                transport.to_string().parse::<Transport>().unwrap(),
                transport
            );
        }
    }

    #[test]
    fn rejects_invalid_values()
    {
        for value in [
            "",
            "vsock:",
            "vsock:-1",
            "vsock:+5",
            "vsock:4294967296",
            "vsock:12a",
            "unix:",
            "unix:relative/path",
            "tcp:1.2.3.4:5",
            "VSOCK:5252",
        ]
        {
            assert_eq!(
                value.parse::<Transport>(),
                Err(GuestProtoError::InvalidTransport(value.to_owned())),
                "{value:?}"
            );
        }
    }
}
