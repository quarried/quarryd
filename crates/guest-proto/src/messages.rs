use std::collections::HashMap;
use std::fmt;

/// Message sent by the guest agent to quarryd.
#[derive(Clone, PartialEq, prost::Message)]
pub struct GuestMessage
{
    /// Payload; a message without one is rejected.
    #[prost(oneof = "GuestBody", tags = "1, 2, 3, 4, 5, 6")]
    pub body: Option<GuestBody>,
}

/// Payload of a [`GuestMessage`].
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum GuestBody
{
    /// The server has started and accepts players.
    #[prost(message, tag = "1")]
    Ready(Ready),
    /// Periodic server health sample.
    #[prost(message, tag = "2")]
    Health(Health),
    /// One line of server output.
    #[prost(message, tag = "3")]
    Log(Log),
    /// The server process exited after a shutdown request.
    #[prost(message, tag = "4")]
    ShutdownComplete(ShutdownComplete),
    /// Answer to [`PrepareSnapshot`]: the world is flushed and writes are frozen.
    #[prost(message, tag = "5")]
    SnapshotPrepared(SnapshotPrepared),
    /// Bounded output captured for a host console request.
    #[prost(message, tag = "6")]
    ConsoleOutput(ConsoleOutput),
}

/// The server has started and accepts players.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Ready
{
    /// Server software version, at most 128 bytes on one line.
    #[prost(string, tag = "1")]
    pub server_version: String,
}

/// Periodic server health sample. Used for display and health checks only.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Health
{
    /// Ticks per second, in `0..=1000`.
    #[prost(double, tag = "1")]
    pub tps: f64,
    /// Milliseconds per tick, in `0..=60000`.
    #[prost(double, tag = "2")]
    pub mspt: f64,
    /// Online players, at most 100 000.
    #[prost(uint32, tag = "3")]
    pub players: u32,
    /// JVM heap in use, at most 1 TiB.
    #[prost(uint64, tag = "4")]
    pub heap_used_bytes: u64,
    /// Online players, at most 500 and bounded by the guest frame limit.
    #[prost(message, repeated, tag = "5")]
    pub player_list: Vec<PlayerInfo>,
    /// Median tick duration in milliseconds.
    #[prost(double, tag = "6")]
    pub mspt_p50_ms: f64,
    /// 99th percentile tick duration in milliseconds.
    #[prost(double, tag = "7")]
    pub mspt_p99_ms: f64,
}

/// One line of server output.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Log
{
    /// The line, at most 4096 bytes, without a line terminator.
    #[prost(string, tag = "1")]
    pub line: String,
}

/// The server process exited after a shutdown request.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ShutdownComplete
{
    /// Exit code of the server process.
    #[prost(int32, tag = "1")]
    pub exit_code: i32,
}

/// Answer to [`PrepareSnapshot`].
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct SnapshotPrepared
{
    /// Whether the world was flushed and writes are frozen.
    #[prost(bool, tag = "1")]
    pub ok: bool,
    /// Failure detail when `ok` is false, at most 1024 bytes on one line.
    #[prost(string, tag = "2")]
    pub error: String,
}

/// Message sent by quarryd to the guest agent.
#[derive(Clone, PartialEq, prost::Message)]
pub struct HostMessage
{
    /// Payload; a message without one is rejected.
    #[prost(oneof = "HostBody", tags = "1, 2, 3, 4, 5")]
    pub body: Option<HostBody>,
}

/// Payload of a [`HostMessage`].
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum HostBody
{
    /// Instance configuration; sent once after the guest agent connects.
    #[prost(message, tag = "1")]
    Configure(Configure),
    /// Command to run on the server console.
    #[prost(message, tag = "2")]
    ConsoleCommand(ConsoleCommand),
    /// Flush the world (`save-all flush`) and freeze writes before a volume snapshot.
    #[prost(message, tag = "3")]
    PrepareSnapshot(PrepareSnapshot),
    /// Resume world writes after a volume snapshot.
    #[prost(message, tag = "4")]
    ResumeWrites(ResumeWrites),
    /// Stop the server gracefully before the deadline.
    #[prost(message, tag = "5")]
    Shutdown(Shutdown),
}

/// Instance configuration. Secrets are written by the guest agent to a tmpfs.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Configure
{
    /// Instance identifier.
    #[prost(string, tag = "1")]
    pub instance_id: String,
    /// Spec generation this configuration belongs to.
    #[prost(uint64, tag = "2")]
    pub generation: u64,
    /// Environment for the server process.
    #[prost(map = "string, string", tag = "3")]
    pub env: HashMap<String, String>,
    /// Secret files by file name; never logged.
    #[prost(map = "string, bytes", tag = "4")]
    pub secrets: HashMap<String, Vec<u8>>,
    /// Memory available to the sandbox, in MiB.
    #[prost(uint64, tag = "5")]
    pub memory_mib: u64,
    /// Server command line: program followed by arguments.
    #[prost(string, repeated, tag = "6")]
    pub server_command: Vec<String>,
}

impl fmt::Debug for Configure
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let mut secret_names: Vec<&String> = self.secrets.keys().collect();
        secret_names.sort();
        f.debug_struct("Configure")
            .field("instance_id", &self.instance_id)
            .field("generation", &self.generation)
            .field("env", &self.env)
            .field("secrets", &secret_names)
            .field("memory_mib", &self.memory_mib)
            .field("server_command", &self.server_command)
            .finish()
    }
}

/// Command to run on the server console.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ConsoleCommand
{
    /// The command, at most 1024 bytes, without line terminators.
    #[prost(string, tag = "1")]
    pub command: String,
    /// Correlates the output response; empty for internal probes.
    #[prost(string, tag = "2")]
    pub request_id: String,
}

/// Flush the world and freeze writes; answered with [`SnapshotPrepared`].
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PrepareSnapshot {}

/// Resume world writes after a volume snapshot.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ResumeWrites {}

/// Stop the server gracefully; answered with [`ShutdownComplete`].
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Shutdown
{
    /// Time the server has to exit, in milliseconds.
    #[prost(uint64, tag = "1")]
    pub deadline_ms: u64,
}

/// Player identity reported by the server.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PlayerInfo
{
    /// Canonical UUID text.
    #[prost(string, tag = "1")]
    pub uuid: String,
    /// Minecraft name, at most 16 ASCII letters, digits or underscores.
    #[prost(string, tag = "2")]
    pub name: String,
    /// Login timestamp in Unix milliseconds.
    #[prost(uint64, tag = "3")]
    pub online_since_unix_ms: u64,
    /// Whether the player is an operator.
    #[prost(bool, tag = "4")]
    pub operator: bool,
}

/// Console output collected for at most 500 milliseconds, within one guest frame.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct ConsoleOutput
{
    /// Host request identity, at most 128 bytes.
    #[prost(string, tag = "1")]
    pub request_id: String,
    /// At most 64 lines of at most 4096 bytes each, also limited by frame size.
    #[prost(string, repeated, tag = "2")]
    pub lines: Vec<String>,
}
