use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use guest_proto::{
    GuestBody, GuestMessage, Health, HostBody, Log, MAX_FRAME_BYTES, MAX_HOST_FRAME_BYTES, Ready,
    ShutdownComplete, SnapshotPrepared, decode_host_message, read_frame, write_message,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::time::Instant;

pub const MODE_ENV: &str = "QUARRY_TEST_GUEST_MODE";
pub const TRACE_ENV: &str = "QUARRY_TEST_GUEST_TRACE";
pub const CRASH_MS_ENV: &str = "QUARRY_TEST_GUEST_CRASH_MS";
pub const HEALTH_MS_ENV: &str = "QUARRY_TEST_GUEST_HEALTH_MS";
pub const PLAYERS_ENV: &str = "QUARRY_TEST_GUEST_PLAYERS";
pub const TEST_NAME: &str = "tests::guest::guest_main";

const MAX_LIFETIME: Duration = Duration::from_secs(180);
const RECONNECT_DELAY: Duration = Duration::from_millis(50);

enum SessionEnd
{
    Exit(i32),
    Disconnected,
}

fn trace(line: &str)
{
    let Ok(path) = std::env::var(TRACE_ENV)
    else
    {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

fn env_u64(name: &str) -> Option<u64>
{
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

async fn send(writer: &mut OwnedWriteHalf, body: GuestBody) -> bool
{
    write_message(writer, &GuestMessage { body: Some(body) })
        .await
        .is_ok()
}

fn ready() -> GuestBody
{
    GuestBody::Ready(Ready {
        server_version: "test-1.0".to_owned(),
    })
}

/// Entry point of the scripted test guest. Without the mode variable it is a
/// no-op test; the fixture re-executes the test binary with `--exact` to run it.
#[test]
fn guest_main()
{
    let Ok(mode) = std::env::var(MODE_ENV)
    else
    {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let code = runtime.block_on(run_guest(mode));
    std::process::exit(code);
}

async fn run_guest(mode: String) -> i32
{
    trace(&format!("start {}", std::process::id()));
    let transport = std::env::var(guest_proto::TRANSPORT_ENV).unwrap_or_default();
    let Some(path) = transport.strip_prefix("unix:").map(PathBuf::from)
    else
    {
        trace("no transport");
        return 2;
    };
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let ignore_term = mode == "ignore-shutdown";
    let deadline = Instant::now() + MAX_LIFETIME;
    let mut configured = false;
    loop
    {
        let parent_gone = path.parent().is_some_and(|parent| !parent.exists());
        if Instant::now() >= deadline || parent_gone
        {
            return 0;
        }
        if mode == "never-connect"
        {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
                _ = sigterm.recv() => return 143,
            }
        }
        let stream = tokio::select! {
            stream = UnixStream::connect(&path) => stream,
            _ = sigterm.recv() =>
            {
                trace("sigterm");
                if ignore_term
                {
                    continue;
                }
                return 143;
            }
        };
        let Ok(stream) = stream
        else
        {
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        };
        trace("connected");
        let end = tokio::select! {
            end = session(stream, &mode, &mut configured, &path) => end,
            _ = wait_for_term(&mut sigterm, ignore_term) => SessionEnd::Exit(143),
        };
        match end
        {
            SessionEnd::Exit(code) =>
            {
                trace(&format!("exit {code}"));
                return code;
            }
            SessionEnd::Disconnected =>
            {
                trace("disconnected");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

async fn wait_for_term(sigterm: &mut tokio::signal::unix::Signal, ignore: bool)
{
    loop
    {
        sigterm.recv().await;
        trace("sigterm");
        if !ignore
        {
            return;
        }
    }
}

fn decode_with_default_command(
    bytes: &[u8],
) -> Result<guest_proto::HostMessage, guest_proto::GuestProtoError>
{
    let mut message = <guest_proto::HostMessage as prost::Message>::decode(bytes)?;
    if let Some(HostBody::Configure(configure)) = message.body.as_mut()
        && configure.server_command.is_empty()
    {
        configure.server_command = vec![
            "java".to_owned(),
            "-jar".to_owned(),
            "server.jar".to_owned(),
        ];
        return decode_host_message(&prost::Message::encode_to_vec(&message));
    }
    decode_host_message(bytes)
}

async fn wait_for_eof(stream: &mut UnixStream)
{
    let mut buffer = [0u8; 64];
    loop
    {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await
        {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(_)) =>
            {}
        }
    }
}

async fn session(
    mut stream: UnixStream,
    mode: &str,
    configured: &mut bool,
    path: &Path,
) -> SessionEnd
{
    match mode
    {
        "oversized" =>
        {
            let mut frame = ((MAX_FRAME_BYTES as u32) + 1).to_be_bytes().to_vec();
            frame.extend_from_slice(&[0u8; 64]);
            let _ = stream.write_all(&frame).await;
            wait_for_eof(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            return SessionEnd::Disconnected;
        }
        "malformed" =>
        {
            let _ = stream.write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff]).await;
            wait_for_eof(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            return SessionEnd::Disconnected;
        }
        _ =>
        {}
    }
    let (mut read, mut write) = stream.into_split();
    if *configured && mode != "never-ready"
    {
        trace("ready again");
        if !send(&mut write, ready()).await
        {
            return SessionEnd::Disconnected;
        }
    }
    let health_every = Duration::from_millis(env_u64(HEALTH_MS_ENV).unwrap_or(200));
    let players = env_u64(PLAYERS_ENV).unwrap_or(1) as u32;
    let crash_after = env_u64(CRASH_MS_ENV).map(Duration::from_millis);
    let mut crash_at: Option<Instant> = None;
    let mut health = tokio::time::interval(health_every);
    loop
    {
        let crash_sleep =
            tokio::time::sleep_until(crash_at.unwrap_or_else(|| Instant::now() + MAX_LIFETIME));
        tokio::select! {
            frame = read_frame(&mut read, MAX_HOST_FRAME_BYTES) =>
            {
                let bytes = match frame
                {
                    Ok(Some(bytes)) => bytes,
                    _ => return SessionEnd::Disconnected,
                };
                let message = match decode_with_default_command(&bytes)
                {
                    Ok(message) => message,
                    Err(error) =>
                    {
                        trace(&format!("invalid host message {error}"));
                        continue;
                    }
                };
                match message.body
                {
                    Some(HostBody::Configure(configure)) =>
                    {
                        let mut secrets: Vec<String> = configure
                            .secrets
                            .iter()
                            .map(|(name, value)| format!("{name}={}", String::from_utf8_lossy(value)))
                            .collect();
                        secrets.sort();
                        trace(&format!(
                            "configure {} memory={} secrets=[{}]",
                            configure.generation,
                            configure.memory_mib,
                            secrets.join(",")
                        ));
                        *configured = true;
                        if mode == "never-ready"
                        {
                            continue;
                        }
                        if !send(&mut write, ready()).await
                        {
                            return SessionEnd::Disconnected;
                        }
                        trace("ready");
                        if let Some(after) = crash_after
                        {
                            crash_at = Some(Instant::now() + after);
                        }
                        if mode == "flood"
                        {
                            let spam = GuestBody::Log(Log { line: "spam".to_owned() });
                            while send(&mut write, spam.clone()).await
                            {}
                            return SessionEnd::Disconnected;
                        }
                    }
                    Some(HostBody::Shutdown(shutdown)) =>
                    {
                        trace(&format!("shutdown {}", shutdown.deadline_ms));
                        if mode == "ignore-shutdown"
                        {
                            continue;
                        }
                        let _ = send(
                            &mut write,
                            GuestBody::ShutdownComplete(ShutdownComplete { exit_code: 0 }),
                        )
                        .await;
                        return SessionEnd::Exit(0);
                    }
                    Some(HostBody::PrepareSnapshot(_)) =>
                    {
                        trace("prepare-snapshot");
                        let prepared = GuestBody::SnapshotPrepared(SnapshotPrepared {
                            ok: true,
                            error: String::new(),
                        });
                        if !send(&mut write, prepared).await
                        {
                            return SessionEnd::Disconnected;
                        }
                    }
                    Some(HostBody::ResumeWrites(_)) => trace("resume-writes"),
                    Some(HostBody::ConsoleCommand(command)) =>
                    {
                        trace(&format!("console {}", command.command));
                    }
                    None =>
                    {}
                }
            }
            _ = health.tick(), if *configured && mode != "never-ready" =>
            {
                let report = GuestBody::Health(Health {
                    tps: 20.0,
                    mspt: 5.0,
                    players,
                    heap_used_bytes: 1 << 20,
                });
                if !send(&mut write, report).await
                {
                    return SessionEnd::Disconnected;
                }
                if path.parent().is_some_and(|parent| !parent.exists())
                {
                    return SessionEnd::Exit(0);
                }
            }
            _ = crash_sleep, if crash_at.is_some() =>
            {
                return SessionEnd::Exit(3);
            }
        }
    }
}
