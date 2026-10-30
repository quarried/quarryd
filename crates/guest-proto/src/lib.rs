//! Message types, framing, and validation for the channel between quarryd and
//! the guest agent (vsock under Firecracker, a Unix socket under gVisor).
//!
//! Frames are a 4-byte big-endian length followed by a protobuf message. The
//! guest is untrusted: the host reads frames with [`MAX_FRAME_BYTES`], decodes
//! them with [`decode_guest_message`], and rate-limits them with [`RateLimiter`].

mod frame;
mod messages;
mod rate;
mod transport;
mod validate;

pub use frame::{FrameError, MAX_FRAME_BYTES, MAX_HOST_FRAME_BYTES, read_frame, write_message};
pub use messages::{
    Configure, ConsoleCommand, ConsoleOutput, GuestBody, GuestMessage, Health, HostBody,
    HostMessage, Log, PlayerInfo, PrepareSnapshot, Ready, ResumeWrites, Shutdown, ShutdownComplete,
    SnapshotPrepared,
};
pub use rate::RateLimiter;
pub use transport::Transport;
pub use validate::*;

/// vsock port quarryd listens on for Firecracker guests.
pub const GUEST_VSOCK_PORT: u32 = 5252;

/// Path of the guest channel socket inside a gVisor sandbox.
pub const GUEST_SOCKET_PATH: &str = "/run/quarry/agent.sock";

/// Environment variable holding the [`Transport`] the guest agent must use.
pub const TRANSPORT_ENV: &str = "QUARRY_AGENT_TRANSPORT";

/// Path of the guest agent binary inside guest images.
pub const GUEST_AGENT_PATH: &str = "/usr/local/bin/quarry-guest-agent";

/// Path of the server binary the guest agent starts when no server command is configured.
pub const SERVER_BINARY_PATH: &str = "/usr/local/bin/quarry-server";
