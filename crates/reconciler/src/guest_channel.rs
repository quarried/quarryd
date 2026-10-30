use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use guest_proto::{
    FrameError, GuestBody, HostMessage, MAX_FRAME_BYTES, RateLimiter, decode_guest_message,
    read_frame, write_message,
};
use tokio::net::UnixListener;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tracing::Instrument;

use crate::ReconcilerError;

const EVENT_BUFFER: usize = 64;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
const CONNECTION_BURST: u32 = 8;
const CONNECTIONS_PER_SEC: f64 = 2.0;
const CONTROL_BURST: u32 = 32;
const CONTROL_PER_SEC: f64 = 10.0;

#[derive(Clone, Copy, Debug)]
pub struct GuestLimits
{
    /// Shared message allowance. Control replies have additional bounded headroom
    /// so a guest using its permitted log rate can still report health and stop.
    pub rate_capacity: u32,
    pub rate_per_sec: f64,
}

struct GuestRateLimiter
{
    messages: RateLimiter,
    control: RateLimiter,
}

impl GuestRateLimiter
{
    fn new(limits: GuestLimits) -> Self
    {
        Self {
            messages: RateLimiter::new(limits.rate_capacity, limits.rate_per_sec),
            control: RateLimiter::new(CONTROL_BURST, CONTROL_PER_SEC),
        }
    }

    fn allow(&mut self, now: Instant, control: bool) -> bool
    {
        // Spend the reserve first: ordinary health traffic must not steal a log
        // token and cause the next permitted log line to disconnect the guest.
        (control && self.control.allow(now)) || self.messages.allow(now)
    }
}

type SharedRateLimiter = Arc<Mutex<GuestRateLimiter>>;

#[derive(Clone, Debug)]
pub enum GuestEvent
{
    Connected
    {
        connection: u64
    },
    Message
    {
        connection: u64, body: GuestBody
    },
    Disconnected
    {
        connection: u64,
        reason: String,
        abusive: bool,
    },
}

struct Slot
{
    id: u64,
    reader: AbortHandle,
    writer: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
}

type SharedSlot = Arc<Mutex<Option<Slot>>>;

fn lock(slot: &SharedSlot) -> MutexGuard<'_, Option<Slot>>
{
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Host side of the guest channel (sections 4.8 and 10): one listener per
/// instance, one active connection, size-limited, validated, rate-limited.
pub struct GuestChannel
{
    instance_id: String,
    events: mpsc::Receiver<GuestEvent>,
    events_sender: mpsc::Sender<GuestEvent>,
    slot: SharedSlot,
    accept: JoinHandle<()>,
}

fn remove_stale_socket(path: &Path) -> Result<(), ReconcilerError>
{
    match std::fs::remove_file(path)
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ReconcilerError::io(format!(
            "remove stale guest socket {}",
            path.display()
        ))(error)),
    }
}

impl GuestChannel
{
    pub fn bind(
        instance_id: &str,
        path: &Path,
        uid: u32,
        gid: u32,
        limits: GuestLimits,
        abuse: Arc<AtomicU64>,
    ) -> Result<GuestChannel, ReconcilerError>
    {
        if let Some(parent) = path.parent()
        {
            let existed = parent.exists();
            std::fs::create_dir_all(parent)
                .map_err(ReconcilerError::io(format!("create {}", parent.display())))?;
            if !existed
            {
                // A newly created gVisor socket directory must be traversable by
                // its guest. Preserve existing directories, notably Firecracker's
                // tenant-owned run directory and its stricter permissions.
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                    .map_err(ReconcilerError::io(format!("chmod {}", parent.display())))?;
            }
        }
        remove_stale_socket(path)?;
        let listener = UnixListener::bind(path).map_err(ReconcilerError::io(format!(
            "bind guest socket {}",
            path.display()
        )))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            ReconcilerError::io(format!("chmod guest socket {}", path.display())),
        )?;
        std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(ReconcilerError::io(
            format!("chown guest socket {}", path.display()),
        ))?;
        let (events_sender, events) = mpsc::channel(EVENT_BUFFER);
        let slot: SharedSlot = Arc::new(Mutex::new(None));
        let limiter = Arc::new(Mutex::new(GuestRateLimiter::new(limits)));
        let accept = tokio::spawn(
            accept_loop(
                listener,
                events_sender.clone(),
                Arc::clone(&slot),
                limiter,
                abuse,
            )
            .in_current_span(),
        );
        Ok(GuestChannel {
            instance_id: instance_id.to_owned(),
            events,
            events_sender,
            slot,
            accept,
        })
    }

    pub async fn next_event(&mut self) -> Option<GuestEvent>
    {
        self.events.recv().await
    }

    pub fn connection(&self) -> Option<u64>
    {
        lock(&self.slot).as_ref().map(|slot| slot.id)
    }

    pub fn disconnect(&self, reason: &str)
    {
        if let Some(id) = self.connection()
        {
            self.drop_connection(id, reason.to_owned());
        }
    }

    pub async fn send(&self, message: &HostMessage) -> Result<(), ReconcilerError>
    {
        let (id, writer) = lock(&self.slot)
            .as_ref()
            .map(|slot| (slot.id, Arc::clone(&slot.writer)))
            .ok_or_else(|| ReconcilerError::GuestNotConnected(self.instance_id.clone()))?;
        let written = tokio::time::timeout(WRITE_TIMEOUT, async {
            let mut writer = writer.lock().await;
            write_message(&mut *writer, message).await
        })
        .await;
        match written
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) =>
            {
                self.drop_connection(id, format!("write failed: {error}"));
                Err(error.into())
            }
            Err(_) =>
            {
                self.drop_connection(id, "write timed out".to_owned());
                Err(ReconcilerError::Timeout(format!(
                    "writing to the guest agent of {}",
                    self.instance_id
                )))
            }
        }
    }

    fn drop_connection(&self, id: u64, reason: String)
    {
        let removed = {
            let mut slot = lock(&self.slot);
            if slot.as_ref().is_some_and(|current| current.id == id)
            {
                slot.take()
            }
            else
            {
                None
            }
        };
        if let Some(removed) = removed
        {
            removed.reader.abort();
            tracing::warn!(connection = id, reason = %reason, "dropped guest connection");
            let _ = self.events_sender.try_send(GuestEvent::Disconnected {
                connection: id,
                reason,
                abusive: false,
            });
        }
    }
}

impl Drop for GuestChannel
{
    fn drop(&mut self)
    {
        self.accept.abort();
        if let Some(slot) = lock(&self.slot).take()
        {
            slot.reader.abort();
        }
    }
}

async fn accept_loop(
    listener: UnixListener,
    events: mpsc::Sender<GuestEvent>,
    slot: SharedSlot,
    limiter: SharedRateLimiter,
    abuse: Arc<AtomicU64>,
)
{
    let mut next_id: u64 = 1;
    let mut connections = RateLimiter::new(CONNECTION_BURST, CONNECTIONS_PER_SEC);
    loop
    {
        let stream = match listener.accept().await
        {
            Ok((stream, _)) => stream,
            Err(error) =>
            {
                tracing::warn!(error = %error, "accepting a guest connection failed");
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
        };
        // Pace connection setup before replacing the reader or producing any
        // events/logs. At most this one accepted descriptor waits for a token;
        // other peers wait in the bounded listen queue. The active reader keeps
        // running throughout, and idle time does not reserve an extra token.
        while !connections.allow(Instant::now())
        {
            tokio::time::sleep(ACCEPT_RETRY).await;
        }
        let id = next_id;
        next_id += 1;
        let (read, write) = stream.into_split();
        let (go, registered) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(
            read_loop(
                id,
                registered,
                read,
                events.clone(),
                Arc::clone(&slot),
                Arc::clone(&limiter),
                Arc::clone(&abuse),
            )
            .in_current_span(),
        );
        let previous = lock(&slot).replace(Slot {
            id,
            reader: reader.abort_handle(),
            writer: Arc::new(tokio::sync::Mutex::new(write)),
        });
        let _ = go.send(());
        if let Some(previous) = previous
        {
            previous.reader.abort();
            tracing::info!(
                connection = id,
                replaced = previous.id,
                "new guest connection replaces the previous one"
            );
        }
    }
}

enum Ended
{
    Closed(String),
    Abusive(String),
}

async fn read_loop(
    id: u64,
    registered: tokio::sync::oneshot::Receiver<()>,
    mut read: OwnedReadHalf,
    events: mpsc::Sender<GuestEvent>,
    slot: SharedSlot,
    limiter: SharedRateLimiter,
    abuse: Arc<AtomicU64>,
)
{
    if registered.await.is_err()
    {
        return;
    }
    if events
        .send(GuestEvent::Connected { connection: id })
        .await
        .is_err()
    {
        return;
    }
    tracing::info!(connection = id, "guest agent connected");
    let ended = loop
    {
        let frame = match read_frame(&mut read, MAX_FRAME_BYTES).await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => break Ended::Closed("guest closed the connection".to_owned()),
            Err(FrameError::TooLarge { len, max }) =>
            {
                break Ended::Abusive(format!("oversized frame of {len} bytes (limit {max})"));
            }
            Err(error) => break Ended::Closed(error.to_string()),
        };
        let message = match decode_guest_message(&frame)
        {
            Ok(message) => message,
            Err(error) => break Ended::Abusive(format!("invalid message: {error}")),
        };
        let control = !matches!(message.body, Some(GuestBody::Log(_)));
        if !limiter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allow(Instant::now(), control)
        {
            break Ended::Abusive("message rate limit exceeded".to_owned());
        }
        match message.body
        {
            Some(GuestBody::Log(log)) =>
            {
                tracing::debug!(connection = id, line = %log.line, "guest log");
            }
            Some(body) =>
            {
                if events
                    .send(GuestEvent::Message {
                        connection: id,
                        body,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            None => break Ended::Abusive("message without a body".to_owned()),
        }
    };
    let (reason, abusive) = match ended
    {
        Ended::Closed(reason) =>
        {
            tracing::info!(connection = id, reason = %reason, "guest agent disconnected");
            (reason, false)
        }
        Ended::Abusive(reason) =>
        {
            abuse.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(connection = id, reason = %reason, "dropping misbehaving guest connection");
            (reason, true)
        }
    };
    {
        let mut current = lock(&slot);
        if current.as_ref().is_some_and(|current| current.id == id)
        {
            current.take();
        }
    }
    drop(read);
    let _ = events
        .send(GuestEvent::Disconnected {
            connection: id,
            reason,
            abusive,
        })
        .await;
}

#[cfg(test)]
mod tests
{
    use std::os::unix::fs::MetadataExt;

    use guest_proto::{GuestMessage, Health, HostBody, Log, Ready, Shutdown};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    use super::*;

    const LIMITS: GuestLimits = GuestLimits {
        rate_capacity: 20,
        rate_per_sec: 10.0,
    };

    fn bind(
        instance_id: &str,
        path: &Path,
        limits: GuestLimits,
        abuse: Arc<AtomicU64>,
    ) -> Result<GuestChannel, ReconcilerError>
    {
        let owner = path
            .ancestors()
            .skip(1)
            .find_map(|parent| std::fs::metadata(parent).ok())
            .unwrap();
        GuestChannel::bind(instance_id, path, owner.uid(), owner.gid(), limits, abuse)
    }

    async fn next(channel: &mut GuestChannel) -> GuestEvent
    {
        tokio::time::timeout(Duration::from_secs(5), channel.next_event())
            .await
            .unwrap()
            .unwrap()
    }

    fn ready() -> GuestMessage
    {
        GuestMessage {
            body: Some(GuestBody::Ready(Ready {
                server_version: "1.21".to_owned(),
            })),
        }
    }

    #[tokio::test]
    async fn forwards_valid_messages_and_writes_host_messages()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/agent.sock");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"stale").unwrap();
        let abuse = Arc::new(AtomicU64::new(0));
        let mut channel = bind("i-1", &path, LIMITS, abuse.clone()).unwrap();
        let mut guest = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { connection: 1 }
        ));
        write_message(
            &mut guest,
            &GuestMessage {
                body: Some(GuestBody::Log(Log {
                    line: "hello".to_owned(),
                })),
            },
        )
        .await
        .unwrap();
        write_message(&mut guest, &ready()).await.unwrap();
        match next(&mut channel).await
        {
            GuestEvent::Message {
                connection: 1,
                body: GuestBody::Ready(ready),
            } => assert_eq!(ready.server_version, "1.21"),
            other => panic!("unexpected {other:?}"),
        }
        channel
            .send(&HostMessage {
                body: Some(HostBody::Shutdown(Shutdown { deadline_ms: 10 })),
            })
            .await
            .unwrap();
        let frame = read_frame(&mut guest, guest_proto::MAX_HOST_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        let message = guest_proto::decode_host_message(&frame).unwrap();
        assert!(matches!(
            message.body,
            Some(HostBody::Shutdown(Shutdown { deadline_ms: 10 }))
        ));
        assert_eq!(abuse.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn oversized_malformed_and_flooding_guests_are_dropped()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let abuse = Arc::new(AtomicU64::new(0));
        let mut channel = bind("i-2", &path, LIMITS, abuse.clone()).unwrap();

        let mut oversized = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { .. }
        ));
        oversized
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        match next(&mut channel).await
        {
            GuestEvent::Disconnected {
                abusive: true,
                reason,
                ..
            } => assert!(reason.contains("oversized")),
            other => panic!("unexpected {other:?}"),
        }

        let mut malformed = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { .. }
        ));
        malformed
            .write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff])
            .await
            .unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Disconnected { abusive: true, .. }
        ));

        let mut invalid = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { .. }
        ));
        write_message(
            &mut invalid,
            &GuestMessage {
                body: Some(GuestBody::Health(Health {
                    tps: -1.0,
                    mspt: 0.0,
                    players: 0,
                    heap_used_bytes: 0,
                    ..Default::default()
                })),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Disconnected { abusive: true, .. }
        ));

        let mut flood = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { .. }
        ));
        let log = GuestMessage {
            body: Some(GuestBody::Log(Log {
                line: "spam".to_owned(),
            })),
        };
        for _ in 0..100
        {
            if write_message(&mut flood, &log).await.is_err()
            {
                break;
            }
        }
        match next(&mut channel).await
        {
            GuestEvent::Disconnected {
                abusive: true,
                reason,
                ..
            } => assert!(reason.contains("rate limit")),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(abuse.load(Ordering::Relaxed), 4);
        assert_eq!(channel.connection(), None);
    }

    #[tokio::test]
    async fn a_new_connection_replaces_the_old_one()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let mut channel = bind("i-3", &path, LIMITS, Arc::new(AtomicU64::new(0))).unwrap();
        let _first = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { connection: 1 }
        ));
        let mut second = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { connection: 2 }
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(channel.connection(), Some(2));
        write_message(&mut second, &ready()).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Message { connection: 2, .. }
        ));
    }

    #[tokio::test]
    async fn rebinding_restores_socket_permissions_and_preserves_existing_directory()
    {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("guest");
        let path = parent.join("agent.sock");
        let owner = std::fs::metadata(dir.path()).unwrap();
        let first = bind("permissions", &path, LIMITS, Arc::new(AtomicU64::new(0))).unwrap();
        let socket = std::fs::metadata(&path).unwrap();
        assert_eq!(socket.uid(), owner.uid());
        assert_eq!(socket.gid(), owner.gid());
        assert_eq!(socket.mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&parent).unwrap().mode() & 0o777, 0o755);

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        drop(first);
        let mut second = bind("permissions", &path, LIMITS, Arc::new(AtomicU64::new(0))).unwrap();
        let socket = std::fs::metadata(&path).unwrap();
        assert_eq!(socket.uid(), owner.uid());
        assert_eq!(socket.gid(), owner.gid());
        assert_eq!(socket.mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&parent).unwrap().mode() & 0o777, 0o700);
        let mut guest = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut second).await,
            GuestEvent::Connected { .. }
        ));
        write_message(&mut guest, &ready()).await.unwrap();
        assert!(matches!(
            next(&mut second).await,
            GuestEvent::Message { .. }
        ));
    }

    #[tokio::test]
    async fn a_listener_is_not_started_when_its_required_owner_cannot_be_set()
    {
        let dir = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(dir.path()).unwrap();
        if owner.uid() == 0
        {
            // Root can assign arbitrary owners; this exercises the failure path
            // on ordinary developer/CI accounts without requiring privilege.
            return;
        }
        let result = GuestChannel::bind(
            "wrong-owner",
            &dir.path().join("agent.sock"),
            0,
            owner.gid(),
            LIMITS,
            Arc::new(AtomicU64::new(0)),
        );
        assert!(result.is_err(), "binding must fail when chown is denied");
    }

    #[test]
    fn sustained_permitted_logs_leave_capacity_for_health_and_replies()
    {
        let mut limiter = GuestRateLimiter::new(GuestLimits {
            rate_capacity: 1,
            rate_per_sec: 50.0,
        });
        let start = Instant::now();
        for tick in 0..30_000
        {
            let now = start + Duration::from_millis(tick * 20);
            if tick % 50 == 0
            {
                assert!(limiter.allow(now, true), "health at tick {tick}");
            }
            if tick % 500 == 0
            {
                for _ in 0..4
                {
                    assert!(limiter.allow(now, true), "control reply at tick {tick}");
                }
            }
            assert!(limiter.allow(now, false), "log at tick {tick}");
        }
    }

    #[test]
    fn control_reserve_is_bounded_and_refills_without_resetting_the_main_bucket()
    {
        let mut limiter = GuestRateLimiter::new(GuestLimits {
            rate_capacity: 2,
            rate_per_sec: 0.0,
        });
        let now = Instant::now();
        for _ in 0..CONTROL_BURST + 2
        {
            assert!(limiter.allow(now, true));
        }
        assert!(!limiter.allow(now, true));
        assert!(!limiter.allow(now, false));
        let later = now + Duration::from_millis(100);
        assert!(limiter.allow(later, true));
        assert!(!limiter.allow(later, true));
        assert!(!limiter.allow(later, false));
    }

    #[tokio::test]
    async fn reconnecting_does_not_reset_the_message_budget()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let abuse = Arc::new(AtomicU64::new(0));
        let mut channel = bind(
            "persistent-budget",
            &path,
            GuestLimits {
                rate_capacity: 2,
                rate_per_sec: 0.0,
            },
            abuse.clone(),
        )
        .unwrap();
        let log = GuestMessage {
            body: Some(GuestBody::Log(Log { line: "log".into() })),
        };
        let mut first = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { connection: 1 }
        ));
        write_message(&mut first, &log).await.unwrap();
        write_message(&mut first, &log).await.unwrap();
        write_message(&mut first, &ready()).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Message { connection: 1, .. }
        ));
        drop(first);
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Disconnected { abusive: false, .. }
        ));

        let mut second = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { connection: 2 }
        ));
        write_message(&mut second, &ready()).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Message { connection: 2, .. }
        ));
        write_message(&mut second, &log).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Disconnected {
                connection: 2,
                abusive: true,
                ..
            }
        ));
        assert_eq!(abuse.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn control_message_flood_is_still_disconnected()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let mut channel = bind(
            "control-flood",
            &path,
            GuestLimits {
                rate_capacity: 0,
                rate_per_sec: 0.0,
            },
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        let mut guest = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            next(&mut channel).await,
            GuestEvent::Connected { .. }
        ));
        for _ in 0..100
        {
            if write_message(&mut guest, &ready()).await.is_err()
            {
                break;
            }
        }
        loop
        {
            match next(&mut channel).await
            {
                GuestEvent::Message { .. } =>
                {}
                GuestEvent::Disconnected { abusive: true, .. } => break,
                event => panic!("unexpected {event:?}"),
            }
        }
    }

    #[tokio::test]
    async fn connection_churn_waits_without_blocking_the_active_reader()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let mut channel = bind("churn", &path, LIMITS, Arc::new(AtomicU64::new(0))).unwrap();
        let mut peers = Vec::new();
        let started = Instant::now();
        for id in 1..=CONNECTION_BURST
        {
            peers.push(UnixStream::connect(&path).await.unwrap());
            assert!(
                matches!(next(&mut channel).await, GuestEvent::Connected { connection } if connection == u64::from(id))
            );
        }
        let pending = UnixStream::connect(&path).await.unwrap();
        // The ninth accept needs a replenished token. The eighth connection
        // remains usable during that wait, including its reserved control path.
        write_message(peers.last_mut().unwrap(), &ready())
            .await
            .unwrap();
        assert!(
            matches!(next(&mut channel).await, GuestEvent::Message { connection, .. } if connection == u64::from(CONNECTION_BURST))
        );
        assert!(
            matches!(next(&mut channel).await, GuestEvent::Connected { connection } if connection == u64::from(CONNECTION_BURST + 1))
        );
        assert!(started.elapsed() >= Duration::from_millis(500));
        drop(pending);
    }
}
