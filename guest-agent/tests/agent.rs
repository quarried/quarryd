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
if [ -n "$FAKE_IGNORE_INT" ]; then trap '' INT; fi
echo "Starting minecraft server version 1.21.4"
echo "pid $$"
echo "secrets ${QUARRY_SECRETS_DIR:-none}"
echo "memory ${QUARRY_MEMORY_MIB:-none}"
printf 'color \033[31mred\033[0m end\n'
if [ -n "$FAKE_QUARRY" ]; then
  echo "2026-10-30T01:35:10.217244Z  INFO Quarry running in embedded mode address=127.0.0.1:25599 world=/data/world"
else
  echo "Done (0.1s)! For help, type \"help\""
fi
while IFS= read -r line; do
  if [ -n "$FAKE_COMMANDS_FILE" ]; then printf '%s\n' "$line" >> "$FAKE_COMMANDS_FILE"; fi
  case "$line" in
    list|"list uuids") echo "There are 3 of a max of 20 players online: a, b, c" ;;
    tps)
      if [ -n "$FAKE_QUARRY" ]; then
        echo "2026-10-30T01:35:11.000000Z  INFO TPS (5s, 1m): 18.0, 19.5 | MSPT: 0.11 ms (last 0.08 ms)"
      else
        echo "TPS from last 1m, 5m, 15m: *19.5, 20.0, 20.0"
      fi ;;
    mspt) echo "Unknown or incomplete command, see below for error"; echo "mspt<--[HERE]" ;;
    "save-all flush") echo "> save-all flush"; echo "Saving the game (this may take a moment!)"; if [ -n "$FAKE_SAVE_DELAY" ]; then sleep "$FAKE_SAVE_DELAY"; fi; echo "Saved the game" ;;
    whoami) echo "pid $$" ;;
    capture) echo "first output"; echo "stderr excluded" >&2; sleep 0.1; echo "second output"; sleep 0.6; echo "late output" ;;
    flood) i=0; while [ "$i" -lt 100 ]; do printf 'line %s ' "$i"; head -c 4096 /dev/zero | tr '\000' x; printf '\n'; i=$((i+1)); done ;;
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
    stderr_reader: Option<tokio::task::JoinHandle<()>>,
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
        let stderr_reader = tokio::spawn(async move {
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
            stderr_reader: Some(stderr_reader),
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
        let status = timeout(WAIT, self.agent.wait())
            .await
            .expect("the agent did not exit")
            .unwrap();
        if let Some(reader) = self.stderr_reader.take()
        {
            timeout(WAIT, reader)
                .await
                .expect("agent stderr stayed open")
                .unwrap();
        }
        status.code()
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
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        self.send(HostBody::ConsoleCommand(ConsoleCommand {
            command: command.to_owned(),
            request_id: format!(
                "command-{}",
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
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

    async fn prepare_snapshot(&mut self, request_id: &str) -> guest_proto::SnapshotPrepared
    {
        self.send(HostBody::PrepareSnapshot(PrepareSnapshot {
            request_id: request_id.to_owned(),
        }))
        .await;
        self.wait_for(|body| match body
        {
            GuestBody::SnapshotPrepared(prepared) if prepared.request_id == request_id =>
            {
                Some(prepared.clone())
            }
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
    assert!(logs.contains(&"memory 1024".to_owned()));
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
    host.send(harness.configure(&[("FAKE_IGNORE_STOP", "1"), ("FAKE_IGNORE_INT", "1")], &[]))
        .await;
    host.ready().await;
    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 300 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 128 + 9);
    assert_eq!(harness.exit_code().await, Some(0));
    let stderr = harness.stderr();
    assert!(stderr.contains("sending SIGINT"), "{stderr}");
    assert!(stderr.contains("killing it"), "{stderr}");
}

#[tokio::test]
async fn shutdown_interrupts_a_server_that_ignores_stop_before_killing_it()
{
    let mut harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_IGNORE_STOP", "1")], &[]))
        .await;
    host.ready().await;
    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 2_000 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 128 + 2);
    assert_eq!(harness.exit_code().await, Some(0));
    assert!(!harness.stderr().contains("killing it"));
}

#[tokio::test]
async fn quarry_readiness_and_tps_output_are_recognized()
{
    let harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_QUARRY", "1")], &[]))
        .await;
    host.ready().await;
    let health = host
        .wait_for(|body| match body
        {
            GuestBody::Health(health) => Some(health.clone()),
            _ => None,
        })
        .await;
    assert_eq!(health.players, 3);
    assert_eq!(health.tps, 19.5);
    assert_eq!(health.mspt, 0.11);
    host.command("say flush").await;
    host.log_containing("> say flush").await;
    assert!(host.logs().iter().all(|line| !line.contains("TPS (")));
    assert!(!harness.stderr().contains("does not support `mspt`"));
}

#[tokio::test]
async fn a_configured_ready_pattern_overrides_the_defaults()
{
    let harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("QUARRY_READY_PATTERN", "pid ")], &[]))
        .await;
    host.ready().await;
    host.log_containing("Done (").await;
    let ready = host
        .received
        .iter()
        .position(|body| matches!(body, GuestBody::Ready(_)))
        .unwrap();
    let done = host
        .received
        .iter()
        .position(|body| matches!(body, GuestBody::Log(log) if log.line.starts_with("Done (")))
        .unwrap();
    assert!(ready < done);
    assert_eq!(
        host.received
            .iter()
            .filter(|body| matches!(body, GuestBody::Ready(_)))
            .count(),
        1
    );
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
    host.send(HostBody::PrepareSnapshot(PrepareSnapshot {
        request_id: "snapshot-1".to_owned(),
    }))
    .await;
    let prepared = host
        .wait_for(|body| match body
        {
            GuestBody::SnapshotPrepared(prepared) => Some(prepared.clone()),
            _ => None,
        })
        .await;
    assert!(prepared.ok, "{}", prepared.error);
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "snapshot-1".to_owned(),
    }))
    .await;
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
async fn a_prepared_snapshot_can_resume_after_the_host_rebinds_its_listener()
{
    let mut harness = Harness::start();
    let commands = harness.dir.path().join("commands");
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_COMMANDS_FILE", commands.to_str().unwrap())], &[]))
        .await;
    host.ready().await;
    let first_pid = host.earlier_log_containing("pid ").await;
    host.send(HostBody::PrepareSnapshot(PrepareSnapshot {
        request_id: "snapshot-1".to_owned(),
    }))
    .await;
    let prepared = host
        .wait_for(|body| match body
        {
            GuestBody::SnapshotPrepared(prepared) => Some(prepared.clone()),
            _ => None,
        })
        .await;
    assert!(prepared.ok, "{}", prepared.error);

    drop(host);
    drop(harness.listener.take());
    std::fs::remove_file(&harness.socket).unwrap();
    harness.listener = Some(UnixListener::bind(&harness.socket).unwrap());
    let mut host = harness.accept().await;
    assert_eq!(host.ready().await, "1.21.4");
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "snapshot-1".to_owned(),
    }))
    .await;
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "snapshot-1".to_owned(),
    }))
    .await;
    host.command("whoami").await;
    assert_eq!(host.log_containing("pid ").await, first_pid);
    let commands = std::fs::read_to_string(commands).unwrap();
    assert_eq!(
        commands.lines().filter(|line| *line == "save-off").count(),
        1
    );
    assert_eq!(
        commands
            .lines()
            .filter(|line| *line == "save-all flush")
            .count(),
        1
    );
    assert_eq!(
        commands.lines().filter(|line| *line == "save-on").count(),
        1
    );
    assert!(commands.find("save-all flush").unwrap() < commands.find("save-on").unwrap());

    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 1000 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 0);
    assert_eq!(harness.exit_code().await, Some(0));
}

#[tokio::test]
async fn snapshot_ids_cannot_reuse_or_release_another_attempts_freeze()
{
    let mut harness = Harness::start();
    let mut host = harness.configured().await;
    assert!(host.prepare_snapshot("first").await.ok);
    assert!(!host.prepare_snapshot("first").await.ok);
    assert!(!host.prepare_snapshot("second").await.ok);
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "second".to_owned(),
    }))
    .await;
    assert!(!host.prepare_snapshot("third").await.ok);

    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "first".to_owned(),
    }))
    .await;
    host.command("first-resumed").await;
    host.log_containing("> first-resumed").await;
    assert!(host.prepare_snapshot("fourth").await.ok);
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "first".to_owned(),
    }))
    .await;
    assert!(!host.prepare_snapshot("fifth").await.ok);
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "fourth".to_owned(),
    }))
    .await;
    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 1000 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 0);
    assert_eq!(harness.exit_code().await, Some(0));
}

#[tokio::test]
async fn a_cancelled_save_completion_cannot_prepare_a_later_snapshot()
{
    let mut harness = Harness::start();
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_SAVE_DELAY", "0.3")], &[]))
        .await;
    host.ready().await;
    host.send(HostBody::PrepareSnapshot(PrepareSnapshot {
        request_id: "cancelled".to_owned(),
    }))
    .await;
    host.log_containing("Saving the game").await;
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "cancelled".to_owned(),
    }))
    .await;
    assert!(!host.prepare_snapshot("too-early").await.ok);
    host.command("cancelled-save-drained").await;
    host.log_containing("> cancelled-save-drained").await;
    assert!(host.prepare_snapshot("fresh").await.ok);
    assert!(host.received.iter().all(|body| !matches!(
        body,
        GuestBody::SnapshotPrepared(prepared) if prepared.request_id == "cancelled" && prepared.ok
    )));
    host.send(HostBody::ResumeWrites(ResumeWrites {
        request_id: "fresh".to_owned(),
    }))
    .await;
    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 1000 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 0);
    assert_eq!(harness.exit_code().await, Some(0));
}

#[tokio::test]
#[ignore = "waits for the guest's real 60-second snapshot auto-resume deadline"]
async fn a_prepared_snapshot_resumes_without_a_resume_command()
{
    let mut harness = Harness::start();
    let commands = harness.dir.path().join("commands");
    let mut host = harness.accept().await;
    host.send(harness.configure(&[("FAKE_COMMANDS_FILE", commands.to_str().unwrap())], &[]))
        .await;
    host.ready().await;
    host.send(HostBody::PrepareSnapshot(PrepareSnapshot {
        request_id: "snapshot-1".to_owned(),
    }))
    .await;
    let prepared = host
        .wait_for(|body| match body
        {
            GuestBody::SnapshotPrepared(prepared) => Some(prepared.clone()),
            _ => None,
        })
        .await;
    assert!(prepared.ok, "{}", prepared.error);
    timeout(Duration::from_secs(65), async {
        loop
        {
            let trace = std::fs::read_to_string(&commands).unwrap();
            if trace.lines().any(|line| line == "save-on")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("world writes stayed disabled without a resume command");
    assert!(harness.stderr().contains("no ResumeWrites"));

    host.send(HostBody::Shutdown(Shutdown { deadline_ms: 1000 }))
        .await;
    assert_eq!(host.shutdown_complete().await, 0);
    assert_eq!(harness.exit_code().await, Some(0));
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

#[tokio::test]
async fn a_missing_default_server_binary_fails_cleanly()
{
    assert!(
        !Path::new(guest_proto::SERVER_BINARY_PATH).exists(),
        "this test expects no server binary at {} on the test host",
        guest_proto::SERVER_BINARY_PATH
    );
    let mut harness = Harness::start();
    let mut host = harness.accept().await;
    let mut configure = harness.configure(&[], &[]);
    if let HostBody::Configure(configure) = &mut configure
    {
        configure.server_command.clear();
    }
    host.send(configure).await;
    let line = host.log_containing("cannot start the server").await;
    assert!(line.contains(guest_proto::SERVER_BINARY_PATH), "{line}");
    assert_eq!(harness.exit_code().await, Some(1));
    assert!(harness.stderr().contains(guest_proto::SERVER_BINARY_PATH));
    assert!(!harness.dir.path().join("quarry.toml").exists());
}

fn mode(path: &Path) -> u32
{
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn console_output_is_correlated_bounded_and_replayed_without_execution()
{
    let harness = Harness::start();
    let mut host = harness.configured().await;
    let command = HostBody::ConsoleCommand(ConsoleCommand {
        command: "capture".to_owned(),
        request_id: "capture-1".to_owned(),
    });
    host.send(command.clone()).await;
    let output = host
        .wait_for(|body| match body
        {
            GuestBody::ConsoleOutput(output) if output.request_id == "capture-1" =>
            {
                Some(output.clone())
            }
            _ => None,
        })
        .await;
    assert!(output.lines.iter().any(|line| line == "first output"));
    assert!(output.lines.iter().any(|line| line == "second output"));
    assert!(
        !output
            .lines
            .iter()
            .any(|line| line.contains("late output") || line.contains("stderr excluded"))
    );
    host.log_containing("late output").await;
    host.send(command).await;
    let replay = host
        .wait_for(|body| match body
        {
            GuestBody::ConsoleOutput(output) if output.request_id == "capture-1" =>
            {
                Some(output.clone())
            }
            _ => None,
        })
        .await;
    assert_eq!(output, replay);
    assert_eq!(
        host.logs()
            .iter()
            .filter(|line| line.as_str() == "first output")
            .count(),
        1
    );
    host.send(HostBody::ConsoleCommand(ConsoleCommand {
        command: "flood".to_owned(),
        request_id: "capture-2".to_owned(),
    }))
    .await;
    let output = host
        .wait_for(|body| match body
        {
            GuestBody::ConsoleOutput(output) if output.request_id == "capture-2" =>
            {
                Some(output.clone())
            }
            _ => None,
        })
        .await;
    assert!(!output.lines.is_empty());
    assert!(output.lines.len() <= 64);
    assert!(
        output
            .lines
            .iter()
            .all(|line| line.len() <= guest_proto::MAX_LOG_LINE_BYTES)
    );
    use prost::Message;
    assert!(
        guest_proto::GuestMessage {
            body: Some(GuestBody::ConsoleOutput(output))
        }
        .encoded_len()
            <= MAX_FRAME_BYTES
    );
}

#[tokio::test]
async fn console_output_is_returned_when_the_command_exits_the_server()
{
    let harness = Harness::start();
    let mut host = harness.configured().await;
    host.send(HostBody::ConsoleCommand(ConsoleCommand {
        command: "crash".to_owned(),
        request_id: "crash-request".to_owned(),
    }))
    .await;
    let output = host
        .wait_for(|body| match body
        {
            GuestBody::ConsoleOutput(output) if output.request_id == "crash-request" =>
            {
                Some(output.clone())
            }
            _ => None,
        })
        .await;
    assert!(output.lines.iter().any(|line| line == "crashing"));
}
