use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use guest_proto::{
    Configure, ConsoleCommand, GuestBody, HostBody, HostMessage, MAX_FRAME_BYTES, PrepareSnapshot,
    ResumeWrites, Shutdown, decode_guest_message, read_frame, write_message,
};
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(15);

const FAKE_SERVER: &str = r#"#!/bin/sh
echo "Starting minecraft server version 1.21.4"
echo "pid $$"
echo "secrets ${QUARRY_SECRETS_DIR:-none}"
printf 'color \033[31mred\033[0m end\n'
echo "Done (0.1s)! For help, type \"help\""
while IFS= read -r line; do
  case "$line" in
    list) echo "There are 3 of a max of 20 players online: a, b, c" ;;
    tps) echo "TPS from last 1m, 5m, 15m: *19.5, 20.0, 20.0" ;;
    mspt) echo "Unknown or incomplete command, see below for error"; echo "mspt<--[HERE]" ;;
    "save-all flush") echo "> save-all flush"; echo "Saving the game (this may take a moment!)"; echo "Saved the game" ;;
    whoami) echo "pid $$" ;;
    crash) echo "crashing"; exit 3 ;;
    stop)
      echo "> stop"
      if [ -n "$FAKE_IGNORE_STOP" ]; then continue; fi
      echo "Stopping the server"
      exit "${FAKE_STOP_CODE:-0}" ;;
    *) echo "> $line" ;;
  esac
done
"#;

struct Harness
{
    dir: tempfile::TempDir,
    socket: PathBuf,
    listener: Option<UnixListener>,
    agent: Child,
    stderr: Arc<Mutex<String>>,
}

impl Harness
{
    fn start() -> Harness
    {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::write(dir.path().join("server.sh"), FAKE_SERVER).unwrap();
        let mut agent = Command::new(env!("CARGO_BIN_EXE_quarry-guest-agent"))
            .env(
                "QUARRY_AGENT_TRANSPORT",
                format!("unix:{}", socket.display()),
            )
            .env("QUARRY_SECRETS_DIR", dir.path().join("secrets"))
            .env_remove("QUARRY_READY_PATTERN")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stderr = Arc::new(Mutex::new(String::new()));
        let mut pipe = agent.stderr.take().unwrap();
        let sink = stderr.clone();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = pipe.read(&mut buffer).await
            {
                if read == 0
                {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buffer[..read]));
            }
        });
        Harness {
            dir,
            socket,
            listener: Some(listener),
            agent,
            stderr,
        }
    }

    fn script(&self) -> String
    {
        self.dir.path().join("server.sh").display().to_string()
    }

    async fn accept(&self) -> Host
    {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = timeout(WAIT, listener.accept())
            .await
            .expect("the agent did not connect")
            .unwrap();
        Host {
            stream,
            received: Vec::new(),
        }
    }

    fn configure(&self, env: &[(&str, &str)], secrets: &[(&str, &[u8])]) -> HostBody
    {
        HostBody::Configure(Configure {
            instance_id: "inst-1".to_owned(),
            generation: 7,
            env: env
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            secrets: secrets
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_vec()))
                .collect(),
            memory_mib: 1024,
            server_command: vec!["/bin/sh".to_owned(), self.script()],
        })
    }

    async fn configured(&self) -> Host
    {
        let mut host = self.accept().await;
        host.send(self.configure(&[], &[])).await;
        host.ready().await;
        host
    }

    async fn exit_code(&mut self) -> Option<i32>
    {
        timeout(WAIT, self.agent.wait())
            .await
            .expect("the agent did not exit")
            .unwrap()
            .code()
    }

    fn stderr(&self) -> String
    {
        self.stderr.lock().unwrap().clone()
    }
}

struct Host
{
    stream: UnixStream,
    received: Vec<GuestBody>,
}

impl Host
{
    async fn send(&mut self, body: HostBody)
    {
        write_message(&mut self.stream, &HostMessage { body: Some(body) })
            .await
            .unwrap();
    }

    async fn next(&mut self) -> Option<GuestBody>
    {
        let frame = timeout(WAIT, read_frame(&mut self.stream, MAX_FRAME_BYTES))
            .await
            .expect("no message from the agent")
            .unwrap()?;
        let body = decode_guest_message(&frame).unwrap().body.unwrap();
        self.received.push(body.clone());
        Some(body)
    }

    async fn wait_for<T>(&mut self, mut matches: impl FnMut(&GuestBody) -> Option<T>) -> T
    {
        loop
        {
            let body = self.next().await.expect("the agent closed the connection");
            if let Some(value) = matches(&body)
            {
                return value;
            }
        }
    }

    async fn ready(&mut self) -> String
    {
        self.wait_for(|body| match body
        {
            GuestBody::Ready(ready) => Some(ready.server_version.clone()),
            _ => None,
        })
        .await
    }

    async fn log_containing(&mut self, text: &str) -> String
    {
        self.wait_for(|body| match body
        {
            GuestBody::Log(log) if log.line.contains(text) => Some(log.line.clone()),
            _ => None,
        })
        .await
    }

    async fn earlier_log_containing(&mut self, text: &str) -> String
    {
        match self.logs().into_iter().find(|line| line.contains(text))
        {
            Some(line) => line,
            None => self.log_containing(text).await,
        }
    }

    async fn command(&mut self, command: &str)
    {
        self.send(HostBody::ConsoleCommand(ConsoleCommand {
            command: command.to_owned(),
        }))
        .await;
    }

    async fn shutdown_complete(&mut self) -> i32
    {
        self.wait_for(|body| match body
        {
            GuestBody::ShutdownComplete(complete) => Some(complete.exit_code),
            _ => None,
        })
        .await
    }

    fn logs(&self) -> Vec<String>
    {
        self.received
            .iter()
            .filter_map(|body| match body
            {
                GuestBody::Log(log) => Some(log.line.clone()),
                _ => None,
            })
            .collect()
    }
}

fn position(logs: &[String], line: &str) -> usize
{
    logs.iter()
        .position(|logged| logged == line)
        .unwrap_or_else(|| panic!("{line:?} not in {logs:?}"))
}

#[tokio::test]
async fn configure_starts_the_server_and_reports_ready_logs_and_health()
{
    let harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[], &[])).await;
    assert_eq!(host.ready().await, "1.21.4");
    let health = host
        .wait_for(|body| match body
        {
            GuestBody::Health(health) => Some(health.clone()),
            _ => None,
        })
        .await;
    assert_eq!(health.players, 3);
    assert_eq!(health.tps, 19.5);
    assert_eq!(health.mspt, 0.0);
    if cfg!(target_os = "linux")
    {
        assert!(health.heap_used_bytes > 0);
    }
    host.command("say flush").await;
    host.log_containing("> say flush").await;
    let logs = host.logs();
    assert!(logs.contains(&"Starting minecraft server version 1.21.4".to_owned()));
    assert!(logs.contains(&"color red end".to_owned()));
    assert!(logs.contains(&"Done (0.1s)! For help, type \"help\"".to_owned()));
    for probe_reply in [
        "There are 3",
        "TPS from",
        "Unknown or incomplete",
        "<--[HERE]",
    ]
    {
        assert!(
            logs.iter().all(|line| !line.contains(probe_reply)),
            "{probe_reply:?} was forwarded: {logs:?}"
        );
    }
    assert!(harness.stderr().contains("does not support `mspt`"));
}

#[tokio::test]
async fn console_commands_reach_the_server()
{
    let harness = Harness::start();
    let mut host = harness.configured().await;
    host.command("say hello world").await;
    assert_eq!(host.log_containing("say hello").await, "> say hello world");
}

#[tokio::test]
async fn shutdown_reports_the_server_exit_code()
{
    let mut harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_STOP_CODE", "5")], &[]))
        .await;
    host.ready().await;
    host.send(HostBody::Shutdown(Shutdown {
        deadline_ms: 10_000,
    }))
    .await;
    assert_eq!(host.shutdown_complete().await, 5);
    assert!(host.logs().contains(&"> stop".to_owned()));
    assert_eq!(harness.exit_code().await, Some(0));
}

#[tokio::test]
async fn shutdown_kills_a_server_that_ignores_stop()
{
    let mut harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_IGNORE_STOP", "1")], &[]))
        .await;
    host.ready().await;
    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 300 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 128 + 9);
    assert_eq!(harness.exit_code().await, Some(0));
}

#[tokio::test]
async fn sigterm_stops_the_server_like_shutdown()
{
    let mut harness = Harness::start();
    let mut host = harness.configured().await;
    let pid = nix::unistd::Pid::from_raw(harness.agent.id().unwrap() as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).unwrap();
    assert_eq!(host.shutdown_complete().await, 0);
    assert_eq!(harness.exit_code().await, Some(0));
}

#[tokio::test]
async fn reconnects_after_the_host_restarts_without_restarting_the_server()
{
    let mut harness = Harness::start();
    let mut host = harness.configured().await;
    let first_pid = host.earlier_log_containing("pid ").await;
    drop(host);
    drop(harness.listener.take());
    std::fs::remove_file(&harness.socket).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    harness.listener = Some(UnixListener::bind(&harness.socket).unwrap());
    let mut host = harness.accept().await;
    assert_eq!(host.ready().await, "1.21.4");
    host.send(harness.configure(&[], &[])).await;
    assert_eq!(host.ready().await, "1.21.4");
    host.command("whoami").await;
    assert_eq!(host.log_containing("pid ").await, first_pid);
    assert!(
        host.logs()
            .iter()
            .all(|line| !line.starts_with("Starting minecraft"))
    );
    assert!(harness.stderr().contains("Configure repeated"));
}

#[tokio::test]
async fn prepare_snapshot_and_resume_writes_run_in_order()
{
    let harness = Harness::start();
    let mut host = harness.configured().await;
    host.send(HostBody::PrepareSnapshot(PrepareSnapshot {}))
        .await;
    let prepared = host
        .wait_for(|body| match body
        {
            GuestBody::SnapshotPrepared(prepared) => Some(prepared.clone()),
            _ => None,
        })
        .await;
    assert!(prepared.ok, "{}", prepared.error);
    host.send(HostBody::ResumeWrites(ResumeWrites {})).await;
    host.command("marker").await;
    host.log_containing("> marker").await;
    let logs = host.logs();
    let save_off = position(&logs, "> save-off");
    let save_all = position(&logs, "> save-all flush");
    let saved = position(&logs, "Saved the game");
    let save_on = position(&logs, "> save-on");
    let marker = position(&logs, "> marker");
    assert!(save_off < save_all && save_all < saved && saved < save_on && save_on < marker);
}

#[tokio::test]
async fn a_server_crash_exits_the_agent_with_a_non_zero_code()
{
    let mut harness = Harness::start();
    let mut host = harness.configured().await;
    host.command("crash").await;
    host.log_containing("crashing").await;
    assert_eq!(harness.exit_code().await, Some(3));
    while host.next().await.is_some()
    {}
    assert!(
        host.received
            .iter()
            .all(|body| !matches!(body, GuestBody::ShutdownComplete(_)))
    );
    assert!(harness.stderr().contains("exited unexpectedly with code 3"));
}

#[tokio::test]
async fn secrets_are_private_files_and_never_logged()
{
    let harness = Harness::start();
    let secret_value = b"s3cr3t-value-that-must-not-leak";
    let mut host = harness.accept().await;
    host.send(harness.configure(&[], &[("rcon.password", secret_value)]))
        .await;
    host.ready().await;
    let secrets_dir = harness.dir.path().join("secrets");
    let announced = host.earlier_log_containing("secrets ").await;
    assert_eq!(announced, format!("secrets {}", secrets_dir.display()));
    let file = secrets_dir.join("rcon.password");
    assert_eq!(std::fs::read(&file).unwrap(), secret_value);
    assert_eq!(mode(&file), 0o400);
    assert_eq!(mode(&secrets_dir), 0o700);
    host.command("say done").await;
    host.log_containing("> say done").await;
    let secret_text = std::str::from_utf8(secret_value).unwrap();
    assert!(host.logs().iter().all(|line| !line.contains(secret_text)));
    let stderr = harness.stderr();
    assert!(stderr.contains("secrets directory is"));
    assert!(!stderr.contains(secret_text));
}

#[tokio::test]
async fn an_empty_server_command_runs_the_env_command()
{
    let harness = Harness::start();
    let mut host = harness.accept().await;
    let script = harness.script();
    let mut configure = harness.configure(
        &[("QUARRY_SERVER_COMMAND", &format!("exec /bin/sh {script}"))],
        &[],
    );
    if let HostBody::Configure(configure) = &mut configure
    {
        configure.server_command.clear();
    }
    host.send(configure).await;
    assert_eq!(host.ready().await, "1.21.4");
}

fn mode(path: &Path) -> u32
{
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}
