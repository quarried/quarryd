use prost::Message;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use guest_proto::{
    Configure, ConsoleOutput, GuestBody, GuestMessage, Health, HostBody, HostMessage, Log,
    MAX_ERROR_BYTES, MAX_HEAP_BYTES, MAX_LOG_LINE_BYTES, RateLimiter, Ready, SERVER_BINARY_PATH,
    ShutdownComplete, SnapshotPrepared,
};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::channel::{self, Connection, Halves};
use crate::probe::{Prober, Step};
use crate::server::{self, DATA_DIR, Server};
use crate::snapshot::{self, FreezeOutcome};
use crate::{EXIT_FAILURE, EXIT_OK, READY_PATTERN_ENV, Settings, output, secrets, world};

const HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const CONSOLE_WINDOW: Duration = Duration::from_millis(500);
const SAVE_TIMEOUT: Duration = Duration::from_secs(30);
const FREEZE_LIMIT: Duration = Duration::from_secs(60);
const TERMINATE_DEADLINE: Duration = Duration::from_secs(30);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const LOG_BURST: u32 = 100;
const LOG_LINES_PER_SECOND: f64 = 50.0;
const EVENT_QUEUE: usize = 1024;
const INTERRUPT_FRACTION: f64 = 0.8;

pub enum Event
{
    Connected(Halves),
    Host(u64, HostMessage),
    Disconnected(u64),
    ServerLine(String),
    ServerStderr(String),
    ServerExited(i32),
    Frozen(Result<FreezeOutcome, String>),
    Thawed(Result<(), String>),
    Terminate,
}

enum SnapshotState
{
    Idle,
    Saving
    {
        deadline: Instant,
    },
    Freezing,
    Prepared
    {
        frozen: bool,
        release_at: Instant,
    },
    Thawing,
}

impl SnapshotState
{
    fn deadline(&self) -> Option<Instant>
    {
        match self
        {
            SnapshotState::Saving { deadline } => Some(*deadline),
            SnapshotState::Prepared { release_at, .. } => Some(*release_at),
            _ => None,
        }
    }
}

struct Stopping
{
    interrupt_at: Instant,
    deadline: Instant,
    stop_sent: bool,
    interrupt_sent: bool,
    kill_sent: bool,
}

impl Stopping
{
    fn next_deadline(&self) -> Option<Instant>
    {
        if !self.interrupt_sent
        {
            Some(self.interrupt_at)
        }
        else if !self.kill_sent
        {
            Some(self.deadline)
        }
        else
        {
            None
        }
    }
}

struct Agent
{
    settings: Settings,
    events: mpsc::Sender<Event>,
    connection: Option<Connection>,
    connections_opened: u64,
    server: Option<Server>,
    server_pid: Arc<AtomicU32>,
    configured: Option<(String, u64)>,
    server_version: String,
    ready: bool,
    next_health: Option<Instant>,
    prober: Prober,
    log_limiter: RateLimiter,
    dropped_lines: u64,
    snapshot: SnapshotState,
    resume_after_freeze: bool,
    frozen: bool,
    stopping: Option<Stopping>,
    ready_patterns: Vec<String>,
    console_capture: HashMap<String, (Instant, ConsoleOutput)>,
    console_seen: HashSet<String>,
    console_results: VecDeque<ConsoleOutput>,
}

pub async fn run(settings: Settings) -> i32
{
    let (events, mut incoming) = mpsc::channel(EVENT_QUEUE);
    let mut terminate = match signal(SignalKind::terminate())
    {
        Ok(terminate) => terminate,
        Err(error) =>
        {
            log!("cannot listen for SIGTERM: {error}");
            return EXIT_FAILURE;
        }
    };
    let terminate_events = events.clone();
    tokio::spawn(async move {
        while terminate.recv().await.is_some()
        {
            if terminate_events.send(Event::Terminate).await.is_err()
            {
                return;
            }
        }
    });
    let server_pid = Arc::new(AtomicU32::new(0));
    #[cfg(target_os = "linux")]
    if std::process::id() == 1
        && let Err(error) = crate::init::spawn_reaper(server_pid.clone())
    {
        log!("cannot reap orphaned processes: {error}");
    }
    channel::spawn_connector(settings.transport.clone(), events.clone());
    let ready_patterns = output::ready_patterns(None, settings.ready_pattern.as_deref());
    let mut agent = Agent {
        settings,
        events,
        connection: None,
        connections_opened: 0,
        server: None,
        server_pid,
        configured: None,
        server_version: String::new(),
        ready: false,
        next_health: None,
        prober: Prober::new(),
        log_limiter: RateLimiter::new(LOG_BURST, LOG_LINES_PER_SECOND),
        dropped_lines: 0,
        snapshot: SnapshotState::Idle,
        resume_after_freeze: false,
        frozen: false,
        stopping: None,
        ready_patterns,
        console_capture: HashMap::new(),
        console_seen: HashSet::new(),
        console_results: VecDeque::new(),
    };
    loop
    {
        let deadline = agent.next_deadline();
        let outcome = tokio::select! {
            event = incoming.recv() => match event
            {
                Some(event) => agent.handle(event).await,
                None => Some(EXIT_FAILURE),
            },
            () = sleep_until(deadline) =>
            {
                agent.on_timers();
                None
            }
        };
        if let Some(code) = outcome
        {
            agent.flush().await;
            return code;
        }
    }
}

async fn sleep_until(deadline: Option<Instant>)
{
    match deadline
    {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

impl Agent
{
    fn next_deadline(&self) -> Option<Instant>
    {
        let stop = self.stopping.as_ref().and_then(Stopping::next_deadline);
        let probe = self.prober.deadline().map(Instant::from_std);
        let console = self
            .console_capture
            .values()
            .map(|(deadline, _)| *deadline)
            .min();
        [
            stop,
            probe,
            self.snapshot.deadline(),
            self.next_health,
            console,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    async fn handle(&mut self, event: Event) -> Option<i32>
    {
        match event
        {
            Event::Connected(halves) =>
            {
                self.on_connected(halves);
                None
            }
            Event::Host(id, message) =>
            {
                if self.is_current(id)
                {
                    self.on_host_message(message).await
                }
                else
                {
                    None
                }
            }
            Event::Disconnected(id) =>
            {
                if self.is_current(id)
                {
                    self.connection = None;
                    log!("lost the host connection; reconnecting");
                    channel::spawn_connector(self.settings.transport.clone(), self.events.clone());
                }
                None
            }
            Event::ServerLine(line) =>
            {
                self.capture_line(&line);
                self.on_server_line(line);
                None
            }
            Event::ServerStderr(line) =>
            {
                self.on_server_line(line);
                None
            }
            Event::ServerExited(code) => Some(self.on_server_exited(code).await),
            Event::Frozen(result) =>
            {
                self.on_frozen(result);
                None
            }
            Event::Thawed(result) =>
            {
                self.on_thawed(result);
                None
            }
            Event::Terminate =>
            {
                log!("received SIGTERM");
                self.begin_shutdown(TERMINATE_DEADLINE)
            }
        }
    }

    fn is_current(&self, id: u64) -> bool
    {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.id() == id)
    }

    fn send(&self, body: GuestBody) -> bool
    {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.send(GuestMessage { body: Some(body) }))
    }

    fn command(&self, line: &str)
    {
        if let Some(server) = &self.server
        {
            server.command(line);
        }
    }

    fn on_connected(&mut self, halves: Halves)
    {
        self.connections_opened += 1;
        log!("connected to the host at {}", self.settings.transport);
        self.connection = Some(Connection::start(
            self.connections_opened,
            halves,
            self.events.clone(),
        ));
        if self.ready
        {
            self.send_ready();
        }
    }

    fn send_ready(&self)
    {
        self.send(GuestBody::Ready(Ready {
            server_version: self.server_version.clone(),
        }));
    }

    async fn on_host_message(&mut self, message: HostMessage) -> Option<i32>
    {
        match message.body?
        {
            HostBody::Configure(configure) => self.on_configure(configure).await,
            HostBody::ConsoleCommand(console) =>
            {
                if console.request_id.is_empty()
                {
                    self.command(&console.command);
                    return None;
                }
                if let Some(result) = self
                    .console_results
                    .iter()
                    .find(|result| result.request_id == console.request_id)
                {
                    self.send(GuestBody::ConsoleOutput(result.clone()));
                    return None;
                }
                if self.console_capture.contains_key(&console.request_id)
                {
                    return None;
                }
                let mut result = ConsoleOutput {
                    request_id: console.request_id.clone(),
                    lines: Vec::new(),
                };
                if !self.console_seen.insert(console.request_id.clone())
                {
                    self.send(GuestBody::ConsoleOutput(result));
                    return None;
                }
                let written = match &self.server
                {
                    Some(server) => server.console_command(&console.command).await,
                    None => Err(std::io::Error::other("server is not running")),
                };
                match written
                {
                    Ok(()) =>
                    {
                        self.console_capture.insert(
                            console.request_id,
                            (Instant::now() + CONSOLE_WINDOW, result),
                        );
                    }
                    Err(error) =>
                    {
                        result
                            .lines
                            .push(output::single_line(&error.to_string(), MAX_LOG_LINE_BYTES));
                        self.send_console_result(result);
                    }
                }
                None
            }
            HostBody::PrepareSnapshot(_) =>
            {
                self.on_prepare_snapshot();
                None
            }
            HostBody::ResumeWrites(_) =>
            {
                self.on_resume_writes();
                None
            }
            HostBody::Shutdown(shutdown) =>
            {
                log!(
                    "shutdown requested with a {} ms deadline",
                    shutdown.deadline_ms
                );
                self.begin_shutdown(Duration::from_millis(shutdown.deadline_ms))
            }
        }
    }

    async fn on_configure(&mut self, configure: Configure) -> Option<i32>
    {
        if let Some((instance_id, generation)) = &self.configured
        {
            if *instance_id == configure.instance_id && *generation == configure.generation
            {
                log!(
                    "Configure repeated for {instance_id} generation {generation}; the server keeps running"
                );
                if self.ready
                {
                    self.send_ready();
                }
            }
            else
            {
                log!(
                    "ignoring Configure for {} generation {}: already running {instance_id} generation {generation}",
                    configure.instance_id,
                    configure.generation
                );
            }
            return None;
        }
        if self.stopping.is_some()
        {
            log!("ignoring Configure during shutdown");
            return None;
        }
        let dir = match secrets::prepare_dir(
            self.settings.secrets_override.as_deref(),
            self.settings.vm_init,
        )
        {
            Ok(dir) => dir,
            Err(error) =>
            {
                log!("cannot prepare the secrets directory: {error}");
                return Some(EXIT_FAILURE);
            }
        };
        log!(
            "secrets directory is {} ({})",
            dir.path.display(),
            dir.reason
        );
        if let Err(error) = secrets::write(&dir.path, &configure.secrets)
        {
            log!("cannot write secrets: {error}");
            return Some(EXIT_FAILURE);
        }
        self.ready_patterns = output::ready_patterns(
            configure.env.get(READY_PATTERN_ENV).map(String::as_str),
            self.settings.ready_pattern.as_deref(),
        );
        let argv = if !configure.server_command.is_empty()
        {
            configure.server_command.clone()
        }
        else if let Some(shell) = server::shell_command(&configure.env)
        {
            shell
        }
        else
        {
            let data_dir = server::data_dir();
            if let Err(error) = world::prepare(
                SERVER_BINARY_PATH,
                &data_dir,
                &configure.instance_id,
                &configure.env,
                configure.memory_mib,
                &dir.path,
            )
            .await
            {
                return Some(self.fail_start(&error));
            }
            world::default_command(SERVER_BINARY_PATH, &data_dir)
        };
        match server::spawn(
            &argv,
            &configure.env,
            configure.memory_mib,
            &dir.path,
            self.events.clone(),
        )
        {
            Ok(server) =>
            {
                log!(
                    "started the server (pid {}) for {} generation {}",
                    server.pid(),
                    configure.instance_id,
                    configure.generation
                );
                self.server_pid.store(server.pid(), Ordering::Relaxed);
                self.server = Some(server);
                self.configured = Some((configure.instance_id, configure.generation));
                None
            }
            Err(error) => Some(self.fail_start(&error.to_string())),
        }
    }

    fn fail_start(&self, error: &str) -> i32
    {
        log!("cannot start the server: {error}");
        self.send(GuestBody::Log(Log {
            line: output::single_line(
                &format!("quarry-guest-agent: cannot start the server: {error}"),
                MAX_LOG_LINE_BYTES,
            ),
        }));
        EXIT_FAILURE
    }

    fn on_server_line(&mut self, line: String)
    {
        let now = Instant::now();
        let (consumed, step) = self.prober.observe(&line, now.into_std());
        self.apply_probe_step(step);
        if consumed
        {
            return;
        }
        if !self.ready
        {
            if let Some(version) = output::server_version(&line)
            {
                self.server_version = version;
            }
            if self
                .ready_patterns
                .iter()
                .any(|pattern| line.contains(pattern.as_str()))
            {
                self.ready = true;
                log!("the server is ready (version {:?})", self.server_version);
                self.send_ready();
                self.next_health = Some(now);
            }
        }
        if matches!(self.snapshot, SnapshotState::Saving { .. }) && output::is_save_complete(&line)
        {
            self.start_freeze();
        }
        self.forward_log(line, now);
    }

    fn capture_line(&mut self, line: &str)
    {
        let now = Instant::now();
        for (deadline, capture) in self.console_capture.values_mut()
        {
            if now <= *deadline && capture.lines.len() < 64
            {
                capture
                    .lines
                    .push(output::single_line(line, MAX_LOG_LINE_BYTES));
                if (GuestMessage {
                    body: Some(GuestBody::ConsoleOutput(capture.clone())),
                })
                .encoded_len()
                    > guest_proto::MAX_FRAME_BYTES
                {
                    capture.lines.pop();
                }
            }
        }
    }

    fn send_console_result(&mut self, result: ConsoleOutput)
    {
        self.send(GuestBody::ConsoleOutput(result.clone()));
        self.console_results.push_back(result);
        if self.console_results.len() > 256
        {
            self.console_results.pop_front();
        }
    }

    fn forward_log(&mut self, line: String, now: Instant)
    {
        self.flush_drop_notice(now);
        if self.dropped_lines == 0 && self.log_limiter.allow(now.into_std())
        {
            self.send(GuestBody::Log(Log {
                line: output::single_line(&line, MAX_LOG_LINE_BYTES),
            }));
        }
        else
        {
            self.dropped_lines += 1;
        }
    }

    fn flush_drop_notice(&mut self, now: Instant)
    {
        if self.dropped_lines > 0 && self.log_limiter.allow(now.into_std())
        {
            self.send(GuestBody::Log(Log {
                line: format!(
                    "quarry-guest-agent: dropped {} lines of server output (rate limit)",
                    self.dropped_lines
                ),
            }));
            self.dropped_lines = 0;
        }
    }

    fn apply_probe_step(&mut self, step: Step)
    {
        match step
        {
            Step::Wait =>
            {}
            Step::Send(command) => self.command(command),
            Step::Complete => self.send_health(),
        }
    }

    fn send_health(&self)
    {
        let sample = self.prober.sample();
        let heap_used_bytes = self
            .server
            .as_ref()
            .map_or(0, |server| server::resident_bytes(server.pid()))
            .min(MAX_HEAP_BYTES);
        let mut health = Health {
            tps: sample.tps,
            mspt: sample.mspt,
            players: sample.players,
            heap_used_bytes,
            player_list: self.prober.player_list(),
            mspt_p50_ms: self.prober.percentile(50),
            mspt_p99_ms: self.prober.percentile(99),
        };
        while (GuestMessage {
            body: Some(GuestBody::Health(health.clone())),
        })
        .encoded_len()
            > guest_proto::MAX_FRAME_BYTES
        {
            if health.player_list.pop().is_none()
            {
                break;
            }
        }
        self.send(GuestBody::Health(health));
    }

    fn on_timers(&mut self)
    {
        let now = Instant::now();
        let complete: Vec<String> = self
            .console_capture
            .iter()
            .filter(|(_, (deadline, _))| now >= *deadline)
            .map(|(id, _)| id.clone())
            .collect();
        for id in complete
        {
            if let Some((_, result)) = self.console_capture.remove(&id)
            {
                self.send_console_result(result);
            }
        }
        if let Some(stopping) = &mut self.stopping
            && !stopping.interrupt_sent
            && now >= stopping.interrupt_at
        {
            stopping.interrupt_sent = true;
            if let Some(server) = &self.server
            {
                log!("the server is still running after `stop`; sending SIGINT");
                server.interrupt();
            }
        }
        if let Some(stopping) = &mut self.stopping
            && !stopping.kill_sent
            && now >= stopping.deadline
        {
            stopping.kill_sent = true;
            if let Some(server) = &self.server
            {
                log!("the server did not exit before the deadline; killing it");
                server.kill();
            }
        }
        let step = self.prober.expire(now.into_std());
        self.apply_probe_step(step);
        match self.snapshot
        {
            SnapshotState::Saving { deadline } if now >= deadline =>
            {
                log!("the world save did not finish within {SAVE_TIMEOUT:?}");
                self.command("save-on");
                self.snapshot = SnapshotState::Idle;
                self.reply_prepared(
                    false,
                    "timed out after 30 s waiting for the world save to finish",
                );
                self.send_stop_when_idle();
            }
            SnapshotState::Prepared { release_at, .. } if now >= release_at =>
            {
                log!("no ResumeWrites within {FREEZE_LIMIT:?}; resuming writes");
                self.release_writes();
            }
            _ =>
            {}
        }
        if let Some(next_health) = self.next_health
            && now >= next_health
        {
            self.next_health = Some(now + HEALTH_INTERVAL);
            self.flush_drop_notice(now);
            if self.server.is_some() && self.stopping.is_none()
            {
                self.prober.refresh_profiles(&server::data_dir());
                let step = self.prober.begin(now.into_std());
                self.apply_probe_step(step);
            }
        }
    }

    fn reply_prepared(&self, ok: bool, error: &str)
    {
        self.send(GuestBody::SnapshotPrepared(SnapshotPrepared {
            ok,
            error: output::single_line(error, MAX_ERROR_BYTES),
        }));
    }

    fn on_prepare_snapshot(&mut self)
    {
        let refusal = if self.stopping.is_some()
        {
            Some("the server is shutting down")
        }
        else if self.server.is_none()
        {
            Some("the server is not running")
        }
        else if !self.ready
        {
            Some("the server is not ready")
        }
        else
        {
            None
        };
        if let Some(refusal) = refusal
        {
            self.reply_prepared(false, refusal);
            return;
        }
        match self.snapshot
        {
            SnapshotState::Idle =>
            {
                log!("preparing a snapshot: flushing the world");
                self.command("save-off");
                self.command("save-all flush");
                self.snapshot = SnapshotState::Saving {
                    deadline: Instant::now() + SAVE_TIMEOUT,
                };
            }
            SnapshotState::Saving { .. } | SnapshotState::Freezing =>
            {
                log!("snapshot preparation is already in progress");
            }
            SnapshotState::Prepared { .. } => self.reply_prepared(true, ""),
            SnapshotState::Thawing => self.reply_prepared(false, "writes are being resumed"),
        }
    }

    fn start_freeze(&mut self)
    {
        self.snapshot = SnapshotState::Freezing;
        self.resume_after_freeze = false;
        let events = self.events.clone();
        tokio::spawn(async move {
            let result =
                tokio::task::spawn_blocking(|| snapshot::sync_and_freeze(Path::new(DATA_DIR)))
                    .await
                    .unwrap_or_else(|error| Err(error.to_string()));
            let _ = events.send(Event::Frozen(result)).await;
        });
    }

    fn on_frozen(&mut self, result: Result<FreezeOutcome, String>)
    {
        let release_at = Instant::now() + FREEZE_LIMIT;
        let prepared = match result
        {
            Ok(FreezeOutcome::Frozen) =>
            {
                log!("froze {DATA_DIR}");
                self.frozen = true;
                self.snapshot = SnapshotState::Prepared {
                    frozen: true,
                    release_at,
                };
                Ok(())
            }
            Ok(FreezeOutcome::Skipped(reason)) =>
            {
                log!("not freezing {DATA_DIR}: {reason}; save-off keeps the world unchanged");
                self.snapshot = SnapshotState::Prepared {
                    frozen: false,
                    release_at,
                };
                Ok(())
            }
            Err(error) =>
            {
                log!("snapshot preparation failed: {error}");
                self.command("save-on");
                self.snapshot = SnapshotState::Idle;
                Err(error)
            }
        };
        match prepared
        {
            Ok(()) if self.stopping.is_some() =>
            {
                self.reply_prepared(false, "the server is shutting down")
            }
            Ok(()) => self.reply_prepared(true, ""),
            Err(error) => self.reply_prepared(false, &error),
        }
        if self.stopping.is_some() || self.resume_after_freeze
        {
            self.release_writes();
        }
        self.send_stop_when_idle();
    }

    fn on_resume_writes(&mut self)
    {
        match self.snapshot
        {
            SnapshotState::Prepared { .. } => self.release_writes(),
            SnapshotState::Saving { .. } =>
            {
                log!("ResumeWrites arrived before the snapshot was prepared; resuming");
                self.command("save-on");
                self.snapshot = SnapshotState::Idle;
            }
            SnapshotState::Freezing => self.resume_after_freeze = true,
            SnapshotState::Idle | SnapshotState::Thawing =>
            {}
        }
    }

    fn release_writes(&mut self)
    {
        match self.snapshot
        {
            SnapshotState::Prepared { frozen: true, .. } =>
            {
                self.snapshot = SnapshotState::Thawing;
                let events = self.events.clone();
                tokio::spawn(async move {
                    let result =
                        tokio::task::spawn_blocking(|| snapshot::thaw(Path::new(DATA_DIR)))
                            .await
                            .unwrap_or_else(|error| Err(error.to_string()));
                    let _ = events.send(Event::Thawed(result)).await;
                });
            }
            SnapshotState::Prepared { frozen: false, .. } =>
            {
                self.command("save-on");
                self.snapshot = SnapshotState::Idle;
                self.send_stop_when_idle();
            }
            _ =>
            {}
        }
    }

    fn on_thawed(&mut self, result: Result<(), String>)
    {
        match result
        {
            Ok(()) =>
            {
                log!("thawed {DATA_DIR}");
                self.frozen = false;
            }
            Err(error) => log!("{error}"),
        }
        self.command("save-on");
        self.snapshot = SnapshotState::Idle;
        self.send_stop_when_idle();
    }

    fn begin_shutdown(&mut self, limit: Duration) -> Option<i32>
    {
        if self.server.is_none()
        {
            self.send(GuestBody::ShutdownComplete(ShutdownComplete {
                exit_code: 0,
            }));
            return Some(EXIT_OK);
        }
        let now = Instant::now();
        let deadline = now + limit;
        let interrupt_at = now + limit.mul_f64(INTERRUPT_FRACTION);
        match &mut self.stopping
        {
            Some(stopping) =>
            {
                stopping.deadline = stopping.deadline.min(deadline);
                stopping.interrupt_at = stopping.interrupt_at.min(interrupt_at);
            }
            None =>
            {
                self.stopping = Some(Stopping {
                    interrupt_at,
                    deadline,
                    stop_sent: false,
                    interrupt_sent: false,
                    kill_sent: false,
                });
                self.next_health = None;
            }
        }
        match self.snapshot
        {
            SnapshotState::Saving { .. } =>
            {
                self.command("save-on");
                self.snapshot = SnapshotState::Idle;
                self.reply_prepared(false, "the server is shutting down");
            }
            SnapshotState::Prepared { .. } => self.release_writes(),
            SnapshotState::Idle | SnapshotState::Freezing | SnapshotState::Thawing =>
            {}
        }
        self.send_stop_when_idle();
        None
    }

    fn send_stop_when_idle(&mut self)
    {
        if !matches!(self.snapshot, SnapshotState::Idle)
        {
            return;
        }
        if let Some(stopping) = &mut self.stopping
            && !stopping.stop_sent
        {
            stopping.stop_sent = true;
            if let Some(server) = &self.server
            {
                server.command("stop");
            }
        }
    }

    async fn on_server_exited(&mut self, code: i32) -> i32
    {
        for (_, (_, result)) in std::mem::take(&mut self.console_capture)
        {
            self.send_console_result(result);
        }
        self.server = None;
        self.server_pid.store(0, Ordering::Relaxed);
        if self.frozen
        {
            match tokio::task::spawn_blocking(|| snapshot::thaw(Path::new(DATA_DIR))).await
            {
                Ok(Ok(())) => self.frozen = false,
                Ok(Err(error)) => log!("{error}"),
                Err(error) => log!("thaw task failed: {error}"),
            }
        }
        if self.stopping.is_some()
        {
            log!("the server exited with code {code}");
            self.send(GuestBody::ShutdownComplete(ShutdownComplete {
                exit_code: code,
            }));
            return EXIT_OK;
        }
        log!("the server exited unexpectedly with code {code}");
        self.send(GuestBody::Log(Log {
            line: format!("quarry-guest-agent: the server exited unexpectedly with code {code}"),
        }));
        match code
        {
            1..=255 => code,
            _ => EXIT_FAILURE,
        }
    }

    async fn flush(&mut self)
    {
        if let Some(connection) = self.connection.take()
        {
            connection.finish(FLUSH_TIMEOUT).await;
        }
    }
}
