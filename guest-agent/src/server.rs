use std::collections::HashMap;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use guest_proto::MAX_LOG_LINE_BYTES;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::agent::Event;
use crate::output;
use crate::secrets::SECRETS_DIR_ENV;

pub const DATA_DIR: &str = "/data";
pub const SERVER_COMMAND_ENV: &str = "QUARRY_SERVER_COMMAND";
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const COMMAND_QUEUE: usize = 64;
const OUTPUT_DRAIN: Duration = Duration::from_secs(1);
const MAX_RAW_LINE_BYTES: usize = MAX_LOG_LINE_BYTES * 4;

pub struct Server
{
    pid: u32,
    commands: mpsc::Sender<String>,
    kill: Option<oneshot::Sender<()>>,
}

impl Server
{
    pub fn pid(&self) -> u32
    {
        self.pid
    }

    pub fn command(&self, line: &str)
    {
        if self.commands.try_send(format!("{line}\n")).is_err()
        {
            log!("server console input is full or closed; dropping a command");
        }
    }

    pub fn kill(&mut self)
    {
        if let Some(kill) = self.kill.take()
        {
            let _ = kill.send(());
        }
    }
}

pub fn resolve_command(memory_mib: u64, env: &HashMap<String, String>) -> Vec<String>
{
    if let Some(script) = env.get(SERVER_COMMAND_ENV)
    {
        return vec!["/bin/sh".to_owned(), "-c".to_owned(), script.clone()];
    }
    let heap = (memory_mib.saturating_mul(3) / 4).max(1);
    vec![
        "java".to_owned(),
        format!("-Xms{heap}M"),
        format!("-Xmx{heap}M"),
        "-jar".to_owned(),
        "server.jar".to_owned(),
        "nogui".to_owned(),
    ]
}

fn working_dir() -> PathBuf
{
    let data = Path::new(DATA_DIR);
    if data.is_dir()
    {
        return data.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn spawn(
    argv: &[String],
    env: &HashMap<String, String>,
    secrets_dir: &Path,
    events: mpsc::Sender<Event>,
) -> io::Result<Server>
{
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty server command"))?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .envs(env)
        .env(SECRETS_DIR_ENV, secrets_dir)
        .current_dir(working_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if std::env::var_os("PATH").is_none() && !env.contains_key("PATH")
    {
        command.env("PATH", DEFAULT_PATH);
    }
    let mut child = command.spawn()?;
    let missing = |what: &str| io::Error::other(format!("server {what} is not available"));
    let pid = child.id().ok_or_else(|| missing("pid"))?;
    let stdin = child.stdin.take().ok_or_else(|| missing("stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| missing("stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| missing("stderr"))?;
    let (commands, pending_commands) = mpsc::channel(COMMAND_QUEUE);
    tokio::spawn(feed_console(stdin, pending_commands));
    let readers = [
        tokio::spawn(read_lines(stdout, events.clone())),
        tokio::spawn(read_lines(stderr, events.clone())),
    ];
    let (kill, kill_requested) = oneshot::channel();
    tokio::spawn(supervise(child, readers, kill_requested, events));
    Ok(Server {
        pid,
        commands,
        kill: Some(kill),
    })
}

async fn feed_console(mut stdin: ChildStdin, mut commands: mpsc::Receiver<String>)
{
    while let Some(line) = commands.recv().await
    {
        let written = match stdin.write_all(line.as_bytes()).await
        {
            Ok(()) => stdin.flush().await,
            Err(error) => Err(error),
        };
        if let Err(error) = written
        {
            log!("cannot write to the server console: {error}");
            return;
        }
    }
}

async fn supervise(
    mut child: Child,
    readers: [JoinHandle<()>; 2],
    kill_requested: oneshot::Receiver<()>,
    events: mpsc::Sender<Event>,
)
{
    let status = tokio::select! {
        status = child.wait() => status,
        _ = kill_requested =>
        {
            if let Err(error) = child.start_kill()
            {
                log!("cannot kill the server: {error}");
            }
            child.wait().await
        }
    };
    let code = match status
    {
        Ok(status) => exit_code(status),
        Err(error) =>
        {
            log!("cannot wait for the server: {error}");
            -1
        }
    };
    let drain_until = tokio::time::Instant::now() + OUTPUT_DRAIN;
    for reader in readers
    {
        let _ = tokio::time::timeout_at(drain_until, reader).await;
    }
    let _ = events.send(Event::ServerExited(code)).await;
}

pub fn exit_code(status: ExitStatus) -> i32
{
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(-1)
}

async fn read_lines<R: AsyncRead + Unpin>(stream: R, events: mpsc::Sender<Event>)
{
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop
    {
        match read_capped_line(&mut reader, &mut line, MAX_RAW_LINE_BYTES).await
        {
            Ok(false) => return,
            Ok(true) =>
            {
                let text = output::sanitize(&line);
                if text.is_empty()
                {
                    continue;
                }
                if events.send(Event::ServerLine(text)).await.is_err()
                {
                    return;
                }
            }
            Err(error) =>
            {
                log!("cannot read server output: {error}");
                return;
            }
        }
    }
}

async fn read_capped_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    cap: usize,
) -> io::Result<bool>
{
    line.clear();
    loop
    {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty()
        {
            return Ok(!line.is_empty());
        }
        let (chunk, consumed, complete) = match buffer.iter().position(|&byte| byte == b'\n')
        {
            Some(end) => (&buffer[..end], end + 1, true),
            None => (buffer, buffer.len(), false),
        };
        let room = cap.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        reader.consume(consumed);
        if complete
        {
            return Ok(true);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn resident_bytes(pid: u32) -> u64
{
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| output::vm_rss_bytes(&status))
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn resident_bytes(_pid: u32) -> u64
{
    0
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn default_command_uses_three_quarters_of_memory()
    {
        assert_eq!(
            resolve_command(4096, &HashMap::new()),
            vec![
                "java",
                "-Xms3072M",
                "-Xmx3072M",
                "-jar",
                "server.jar",
                "nogui"
            ]
        );
        assert_eq!(resolve_command(1, &HashMap::new())[1], "-Xms1M");
    }

    #[test]
    fn server_command_env_runs_through_the_shell()
    {
        let env = HashMap::from([(
            SERVER_COMMAND_ENV.to_owned(),
            "exec java -jar paper.jar".to_owned(),
        )]);
        assert_eq!(
            resolve_command(4096, &env),
            vec!["/bin/sh", "-c", "exec java -jar paper.jar"]
        );
    }

    #[test]
    fn exit_codes_include_signals()
    {
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }

    #[tokio::test]
    async fn lines_are_split_and_capped()
    {
        let input: &[u8] = b"first\nsecond line that is long\nlast";
        let mut reader = BufReader::with_capacity(4, input);
        let mut line = Vec::new();
        assert!(read_capped_line(&mut reader, &mut line, 100).await.unwrap());
        assert_eq!(line, b"first");
        assert!(read_capped_line(&mut reader, &mut line, 6).await.unwrap());
        assert_eq!(line, b"second");
        assert!(read_capped_line(&mut reader, &mut line, 100).await.unwrap());
        assert_eq!(line, b"last");
        assert!(!read_capped_line(&mut reader, &mut line, 100).await.unwrap());
    }

    #[test]
    fn resident_memory_of_this_process_is_known_on_linux()
    {
        let bytes = resident_bytes(std::process::id());
        if cfg!(target_os = "linux")
        {
            assert!(bytes > 0);
        }
        else
        {
            assert_eq!(bytes, 0);
        }
    }
}
