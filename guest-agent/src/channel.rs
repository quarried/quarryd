use std::io;
use std::time::Duration;

use guest_proto::{
    GuestMessage, GuestProtoError, HostBody, HostMessage, MAX_FRAME_BYTES, MAX_HOST_FRAME_BYTES,
    Transport, decode_host_message, read_frame, write_message,
};
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::agent::Event;
use crate::server;

const OUTBOUND_QUEUE: usize = 256;
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(2);
const FAILURES_PER_LOG: u64 = 30;

type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;

pub struct Halves
{
    reader: Reader,
    writer: Writer,
}

pub fn spawn_connector(transport: Transport, events: mpsc::Sender<Event>)
{
    tokio::spawn(async move {
        let halves = connect_with_backoff(&transport).await;
        let _ = events.send(Event::Connected(halves)).await;
    });
}

async fn connect_with_backoff(transport: &Transport) -> Halves
{
    let mut delay = INITIAL_BACKOFF;
    let mut failures: u64 = 0;
    loop
    {
        match connect(transport).await
        {
            Ok(halves) => return halves,
            Err(error) =>
            {
                if failures.is_multiple_of(FAILURES_PER_LOG)
                {
                    log!("cannot connect to the host at {transport}: {error}; retrying");
                }
                failures += 1;
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn connect(transport: &Transport) -> io::Result<Halves>
{
    match transport
    {
        Transport::Unix(path) =>
        {
            let (reader, writer) = tokio::net::UnixStream::connect(path).await?.into_split();
            Ok(Halves {
                reader: Box::new(reader),
                writer: Box::new(writer),
            })
        }
        #[cfg(target_os = "linux")]
        Transport::Vsock { port } =>
        {
            let address = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, *port);
            let (reader, writer) =
                tokio::io::split(tokio_vsock::VsockStream::connect(address).await?);
            Ok(Halves {
                reader: Box::new(reader),
                writer: Box::new(writer),
            })
        }
        #[cfg(not(target_os = "linux"))]
        Transport::Vsock { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vsock is only available on Linux",
        )),
    }
}

pub fn decode_host(bytes: &[u8]) -> Result<HostMessage, GuestProtoError>
{
    let mut message = HostMessage::decode(bytes)?;
    if let Some(HostBody::Configure(configure)) = &mut message.body
        && configure.server_command.is_empty()
    {
        configure.server_command = server::resolve_command(configure.memory_mib, &configure.env);
        return decode_host_message(&message.encode_to_vec());
    }
    decode_host_message(bytes)
}

pub struct Connection
{
    id: u64,
    outbound: Option<mpsc::Sender<GuestMessage>>,
    reader: JoinHandle<()>,
    writer: Option<JoinHandle<()>>,
}

impl Connection
{
    pub fn start(id: u64, halves: Halves, events: mpsc::Sender<Event>) -> Connection
    {
        let (outbound, pending) = mpsc::channel(OUTBOUND_QUEUE);
        let reader = tokio::spawn(read_loop(id, halves.reader, events.clone()));
        let writer = tokio::spawn(write_loop(id, halves.writer, pending, events));
        Connection {
            id,
            outbound: Some(outbound),
            reader,
            writer: Some(writer),
        }
    }

    pub fn id(&self) -> u64
    {
        self.id
    }

    pub fn send(&self, message: GuestMessage) -> bool
    {
        self.outbound
            .as_ref()
            .is_some_and(|outbound| outbound.try_send(message).is_ok())
    }

    pub async fn finish(mut self, limit: Duration)
    {
        drop(self.outbound.take());
        if let Some(mut writer) = self.writer.take()
        {
            if tokio::time::timeout(limit, &mut writer).await.is_err()
            {
                log!("could not flush messages to the host within {limit:?}");
            }
            writer.abort();
        }
    }
}

impl Drop for Connection
{
    fn drop(&mut self)
    {
        self.reader.abort();
        if let Some(writer) = self.writer.take()
        {
            writer.abort();
        }
    }
}

async fn read_loop(id: u64, mut reader: Reader, events: mpsc::Sender<Event>)
{
    loop
    {
        match read_frame(&mut reader, MAX_HOST_FRAME_BYTES).await
        {
            Ok(Some(frame)) => match decode_host(&frame)
            {
                Ok(message) =>
                {
                    if events.send(Event::Host(id, message)).await.is_err()
                    {
                        return;
                    }
                }
                Err(error) => log!("ignoring an invalid host message: {error}"),
            },
            Ok(None) =>
            {
                log!("the host closed the connection");
                break;
            }
            Err(error) =>
            {
                log!("the host connection failed: {error}");
                break;
            }
        }
    }
    let _ = events.send(Event::Disconnected(id)).await;
}

async fn write_loop(
    id: u64,
    mut writer: Writer,
    mut pending: mpsc::Receiver<GuestMessage>,
    events: mpsc::Sender<Event>,
)
{
    while let Some(message) = pending.recv().await
    {
        let length = message.encoded_len();
        if length > MAX_FRAME_BYTES
        {
            log!("dropping a {length} byte message above the {MAX_FRAME_BYTES} byte frame limit");
            continue;
        }
        if let Err(error) = write_message(&mut writer, &message).await
        {
            log!("writing to the host failed: {error}");
            let _ = events.try_send(Event::Disconnected(id));
            return;
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests
{
    use super::*;
    use guest_proto::{Configure, ConsoleCommand};
    use std::collections::HashMap;

    fn configure(server_command: Vec<String>, env: HashMap<String, String>) -> Vec<u8>
    {
        HostMessage {
            body: Some(HostBody::Configure(Configure {
                instance_id: "inst-1".to_owned(),
                generation: 1,
                env,
                secrets: HashMap::new(),
                memory_mib: 2048,
                server_command,
            })),
        }
        .encode_to_vec()
    }

    fn command_of(message: HostMessage) -> Vec<String>
    {
        match message.body
        {
            Some(HostBody::Configure(configure)) => configure.server_command,
            other => panic!("unexpected body {other:?}"),
        }
    }

    #[test]
    fn an_explicit_server_command_is_kept()
    {
        let decoded = decode_host(&configure(vec!["/bin/server".into()], HashMap::new())).unwrap();
        assert_eq!(command_of(decoded), vec!["/bin/server"]);
    }

    #[test]
    fn an_empty_server_command_falls_back_to_java()
    {
        let decoded = decode_host(&configure(Vec::new(), HashMap::new())).unwrap();
        assert_eq!(
            command_of(decoded),
            vec![
                "java",
                "-Xms1536M",
                "-Xmx1536M",
                "-jar",
                "server.jar",
                "nogui"
            ]
        );
    }

    #[test]
    fn an_empty_server_command_uses_the_env_command()
    {
        let env = HashMap::from([(
            server::SERVER_COMMAND_ENV.to_owned(),
            "./start.sh".to_owned(),
        )]);
        let decoded = decode_host(&configure(Vec::new(), env)).unwrap();
        assert_eq!(command_of(decoded), vec!["/bin/sh", "-c", "./start.sh"]);
    }

    #[test]
    fn invalid_host_messages_are_rejected()
    {
        let bad = HostMessage {
            body: Some(HostBody::ConsoleCommand(ConsoleCommand {
                command: "stop\nop me".to_owned(),
            })),
        };
        assert!(decode_host(&bad.encode_to_vec()).is_err());
        assert!(decode_host(&[]).is_err());
    }

    #[tokio::test]
    async fn connecting_to_a_unix_socket_carries_frames()
    {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let mut halves = connect(&Transport::Unix(path)).await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        let message = GuestMessage {
            body: Some(guest_proto::GuestBody::Log(guest_proto::Log {
                line: "hello".to_owned(),
            })),
        };
        write_message(&mut halves.writer, &message).await.unwrap();
        let frame = read_frame(&mut accepted, MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(guest_proto::decode_guest_message(&frame).unwrap(), message);
    }
}
