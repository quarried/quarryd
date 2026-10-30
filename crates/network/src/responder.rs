use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout};

use crate::public::PublicState;
use crate::{NetworkError, PublicIpMetrics, PublicIpMode, PublicWake};

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_PACKET: usize = 1024;
const CONNECTIONS_PER_SECOND: f64 = 10.0;
const BURST: f64 = 20.0;
const MAX_SOURCES: usize = 65_536;
const MAX_CONNECTIONS: usize = 256;
const WAKE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Listener
{
    address: SocketAddr,
    task: JoinHandle<()>,
}

#[derive(Debug)]
struct Bucket
{
    tokens: f64,
    updated: Instant,
}

#[derive(Debug, Default)]
struct ResponderState
{
    modes: BTreeMap<String, PublicIpMode>,
    sources: BTreeMap<IpAddr, Bucket>,
    last_wakes: BTreeMap<String, Instant>,
    metrics: PublicIpMetrics,
}

#[derive(Debug)]
pub(crate) struct SleepResponder
{
    bind_ip: Ipv4Addr,
    listeners: Mutex<BTreeMap<String, Listener>>,
    state: Arc<Mutex<ResponderState>>,
    capacity: Arc<Semaphore>,
    wakes: broadcast::Sender<PublicWake>,
}

impl SleepResponder
{
    pub fn new(bind_ip: Ipv4Addr) -> Self
    {
        let (wakes, _) = broadcast::channel(1024);
        Self {
            bind_ip,
            listeners: Mutex::new(BTreeMap::new()),
            state: Arc::new(Mutex::new(ResponderState::default())),
            capacity: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            wakes,
        }
    }

    pub fn prepare(&self, public: &mut PublicState) -> Result<(), NetworkError>
    {
        let mut listeners = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (instance_id, binding) in &mut public.bindings
        {
            if let Some(listener) = listeners.get(instance_id)
            {
                binding.responder_port = listener.address.port();
                continue;
            }
            let runtime = tokio::runtime::Handle::try_current().map_err(|e| {
                NetworkError::io("starting public IP responder", io::Error::other(e))
            })?;
            let requested = (self.bind_ip, binding.responder_port);
            let listener = match std::net::TcpListener::bind(requested)
            {
                Ok(listener) => listener,
                Err(error)
                    if binding.responder_port != 0 && error.kind() == io::ErrorKind::AddrInUse =>
                {
                    std::net::TcpListener::bind((self.bind_ip, 0))
                        .map_err(|e| NetworkError::io("binding public IP responder", e))?
                }
                Err(error) => return Err(NetworkError::io("binding public IP responder", error)),
            };
            listener
                .set_nonblocking(true)
                .map_err(|e| NetworkError::io("setting public IP responder nonblocking", e))?;
            let address = listener
                .local_addr()
                .map_err(|e| NetworkError::io("reading public IP responder address", e))?;
            let listener = TcpListener::from_std(listener)
                .map_err(|e| NetworkError::io("starting public IP responder listener", e))?;
            let task = runtime.spawn(serve(
                listener,
                instance_id.clone(),
                self.state.clone(),
                self.capacity.clone(),
                self.wakes.clone(),
            ));
            binding.responder_port = address.port();
            listeners.insert(instance_id.clone(), Listener { address, task });
        }
        Ok(())
    }

    pub fn publish(&self, public: &PublicState)
    {
        let mut state = lock(&self.state);
        state.modes = public
            .bindings
            .iter()
            .map(|(id, binding)| (id.clone(), binding.mode))
            .collect();
        state.metrics.bound = public.bindings.len() as u64;
        state
            .last_wakes
            .retain(|id, _| public.bindings.contains_key(id));
        drop(state);
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, listener| {
                if public.bindings.contains_key(id)
                {
                    true
                }
                else
                {
                    listener.task.abort();
                    false
                }
            });
    }

    pub fn address(&self, instance_id: &str) -> Option<SocketAddr>
    {
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(instance_id)
            .map(|listener| listener.address)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PublicWake>
    {
        self.wakes.subscribe()
    }

    pub fn metrics(&self) -> PublicIpMetrics
    {
        lock(&self.state).metrics.clone()
    }
}

impl Drop for SleepResponder
{
    fn drop(&mut self)
    {
        for listener in self
            .listeners
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            listener.task.abort();
        }
    }
}

fn lock(state: &Mutex<ResponderState>) -> MutexGuard<'_, ResponderState>
{
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn outcome(state: &Mutex<ResponderState>, name: &str)
{
    *lock(state)
        .metrics
        .connections
        .entry(name.to_string())
        .or_default() += 1;
}

impl ResponderState
{
    fn admit(&mut self, source: IpAddr, now: Instant) -> bool
    {
        if self.sources.len() >= MAX_SOURCES
        {
            self.sources
                .retain(|_, bucket| now.duration_since(bucket.updated) < Duration::from_secs(120));
            if self.sources.len() >= MAX_SOURCES && !self.sources.contains_key(&source)
            {
                return false;
            }
        }
        let bucket = self.sources.entry(source).or_insert(Bucket {
            tokens: BURST,
            updated: now,
        });
        bucket.tokens = (bucket.tokens
            + now.duration_since(bucket.updated).as_secs_f64() * CONNECTIONS_PER_SECOND)
            .min(BURST);
        bucket.updated = now;
        if bucket.tokens < 1.0
        {
            false
        }
        else
        {
            bucket.tokens -= 1.0;
            true
        }
    }

    fn wake(&mut self, instance_id: &str, wakes: &broadcast::Sender<PublicWake>)
    {
        let now = Instant::now();
        if self
            .last_wakes
            .get(instance_id)
            .is_some_and(|last| now.duration_since(*last) < WAKE_INTERVAL)
        {
            return;
        }
        let requested_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        if wakes
            .send(PublicWake {
                instance_id: instance_id.to_string(),
                requested_at_unix_ms,
            })
            .is_ok()
        {
            self.last_wakes.insert(instance_id.to_string(), now);
            self.metrics.wake_requests += 1;
        }
    }
}

async fn serve(
    listener: TcpListener,
    instance_id: String,
    state: Arc<Mutex<ResponderState>>,
    capacity: Arc<Semaphore>,
    wakes: broadcast::Sender<PublicWake>,
)
{
    let mut connections = JoinSet::new();
    loop
    {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, source) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        outcome(&state, "accept_error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                if !lock(&state).admit(source.ip(), Instant::now()) {
                    outcome(&state, "rate_limited");
                    continue;
                }
                let Ok(permit) = capacity.clone().try_acquire_owned() else {
                    outcome(&state, "capacity_limited");
                    continue;
                };
                let state = state.clone();
                let instance_id = instance_id.clone();
                let wakes = wakes.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let result = timeout(DEADLINE, exchange(stream, &instance_id, &state, &wakes)).await;
                    outcome(&state, match result {
                        Ok(Ok(outcome)) => outcome,
                        Ok(Err(_)) => "invalid",
                        Err(_) => "timeout",
                    });
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn exchange(
    mut stream: TcpStream,
    instance_id: &str,
    state: &Mutex<ResponderState>,
    wakes: &broadcast::Sender<PublicWake>,
) -> io::Result<&'static str>
{
    let first = stream.read_u8().await?;
    if first == 0xfe
    {
        return Ok("legacy");
    }
    let handshake = read_packet(&mut stream, Some(first)).await?;
    let (protocol, next_state) = handshake_fields(&handshake)?;
    let mode = lock(state).modes.get(instance_id).copied();
    let Some(mode) = mode.filter(|mode| *mode != PublicIpMode::Running)
    else
    {
        return Ok("unavailable");
    };
    if next_state == 2
    {
        if mode == PublicIpMode::Hibernated
        {
            let mut state = lock(state);
            if state.modes.get(instance_id) == Some(&PublicIpMode::Hibernated)
            {
                state.wake(instance_id, wakes);
            }
        }
        let message = serde_json::json!({"text": "The server is starting. Please rejoin in about 30 seconds."});
        write_json_packet(&mut stream, &message).await?;
        return Ok("login");
    }
    let request = read_packet(&mut stream, None).await?;
    if request != [0]
    {
        return Err(invalid_packet());
    }
    let description = if mode == PublicIpMode::Starting
    {
        "The server is starting. Please rejoin in about 30 seconds."
    }
    else
    {
        "The server is sleeping. Join to wake it up."
    };
    let status = serde_json::json!({
        "version": {"name": "Quarry", "protocol": protocol},
        "players": {"max": 0, "online": 0},
        "description": {"text": description}
    });
    write_json_packet(&mut stream, &status).await?;
    let ping = match read_packet(&mut stream, None).await
    {
        Ok(ping) => ping,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ) =>
        {
            return Ok("status");
        }
        Err(error) => return Err(error),
    };
    if ping.len() != 9 || ping[0] != 1
    {
        return Err(invalid_packet());
    }
    write_packet(&mut stream, &ping).await?;
    Ok("status")
}

fn invalid_packet() -> io::Error
{
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Minecraft sleep responder packet",
    )
}

async fn read_packet(stream: &mut TcpStream, first: Option<u8>) -> io::Result<Vec<u8>>
{
    let mut length = 0u32;
    let mut prefix_len = 0;
    for index in 0..5
    {
        let byte = if index == 0
        {
            match first
            {
                Some(first) => first,
                None => stream.read_u8().await?,
            }
        }
        else
        {
            stream.read_u8().await?
        };
        if index == 4 && byte > 0x0f
        {
            return Err(invalid_packet());
        }
        length |= u32::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0
        {
            prefix_len = index + 1;
            break;
        }
    }
    if prefix_len == 0 || length == 0 || length as usize + prefix_len > MAX_PACKET
    {
        return Err(invalid_packet());
    }
    let mut packet = vec![0; length as usize];
    stream.read_exact(&mut packet).await?;
    Ok(packet)
}

fn take_varint(bytes: &mut &[u8]) -> io::Result<u32>
{
    let mut value = 0;
    for index in 0..5
    {
        let (&byte, rest) = bytes.split_first().ok_or_else(invalid_packet)?;
        *bytes = rest;
        if index == 4 && byte > 0x0f
        {
            return Err(invalid_packet());
        }
        value |= u32::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0
        {
            return Ok(value);
        }
    }
    Err(invalid_packet())
}

fn handshake_fields(mut packet: &[u8]) -> io::Result<(i32, u32)>
{
    if take_varint(&mut packet)? != 0
    {
        return Err(invalid_packet());
    }
    let protocol = take_varint(&mut packet)? as i32;
    let address_len = take_varint(&mut packet)? as usize;
    if address_len > packet.len()
    {
        return Err(invalid_packet());
    }
    let (address, rest) = packet.split_at(address_len);
    let address = std::str::from_utf8(address).map_err(|_| invalid_packet())?;
    if address.chars().count() > 255 || rest.len() < 2
    {
        return Err(invalid_packet());
    }
    packet = &rest[2..];
    let next_state = take_varint(&mut packet)?;
    if !packet.is_empty() || !matches!(next_state, 1 | 2)
    {
        return Err(invalid_packet());
    }
    Ok((protocol, next_state))
}

fn put_varint(mut value: u32, output: &mut Vec<u8>)
{
    loop
    {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0
        {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0
        {
            break;
        }
    }
}

async fn write_packet(stream: &mut TcpStream, packet: &[u8]) -> io::Result<()>
{
    let mut framed = Vec::with_capacity(packet.len() + 5);
    put_varint(packet.len() as u32, &mut framed);
    framed.extend_from_slice(packet);
    stream.write_all(&framed).await
}

async fn write_json_packet(stream: &mut TcpStream, value: &serde_json::Value) -> io::Result<()>
{
    let text = value.to_string();
    let mut packet = vec![0];
    put_varint(text.len() as u32, &mut packet);
    packet.extend_from_slice(text.as_bytes());
    write_packet(stream, &packet).await
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::public::PublicBinding;

    #[tokio::test(start_paused = true)]
    async fn token_bucket_refills_without_exceeding_burst_and_sources_are_independent()
    {
        let mut state = ResponderState::default();
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..20
        {
            assert!(state.admit(source, Instant::now()));
        }
        assert!(!state.admit(source, Instant::now()));
        assert!(state.admit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), Instant::now()));
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!state.admit(source, Instant::now()));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(state.admit(source, Instant::now()));
        assert!(!state.admit(source, Instant::now()));
        tokio::time::advance(Duration::from_secs(60)).await;
        for _ in 0..20
        {
            assert!(state.admit(source, Instant::now()));
        }
        assert!(!state.admit(source, Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn wake_cadence_is_per_instance_and_exactly_ten_seconds()
    {
        let mut state = ResponderState::default();
        let (sender, mut receiver) = broadcast::channel(10);
        state.wake("a", &sender);
        state.wake("a", &sender);
        assert_eq!(receiver.try_recv().unwrap().instance_id, "a");
        assert!(receiver.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(9999)).await;
        state.wake("a", &sender);
        assert!(receiver.try_recv().is_err());
        state.wake("b", &sender);
        assert_eq!(receiver.try_recv().unwrap().instance_id, "b");
        tokio::time::advance(Duration::from_millis(1)).await;
        state.wake("a", &sender);
        assert_eq!(receiver.try_recv().unwrap().instance_id, "a");
        assert_eq!(state.metrics.wake_requests, 3);
    }

    #[tokio::test]
    async fn concurrent_connection_limit_is_shared_by_every_listener()
    {
        let responder = SleepResponder::new(Ipv4Addr::LOCALHOST);
        let mut public = PublicState::default();
        for (id, address) in [
            ("a", Ipv4Addr::new(203, 0, 113, 1)),
            ("b", Ipv4Addr::new(203, 0, 113, 2)),
        ]
        {
            public.bindings.insert(
                id.to_string(),
                PublicBinding {
                    address,
                    guest_ip: Ipv4Addr::new(10, 0, 0, 2),
                    mode: PublicIpMode::Hibernated,
                    responder_port: 0,
                },
            );
        }
        responder.prepare(&mut public).unwrap();
        responder.publish(&public);
        let mut streams = Vec::new();
        for index in 0..MAX_CONNECTIONS
        {
            lock(&responder.state).sources.clear();
            let address = responder
                .address(if index % 2 == 0 { "a" } else { "b" })
                .unwrap();
            streams.push(TcpStream::connect(address).await.unwrap());
            tokio::time::timeout(Duration::from_secs(1), async {
                while responder.capacity.available_permits() != MAX_CONNECTIONS - index - 1
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(responder.capacity.available_permits(), 0);
        let mut rejected = TcpStream::connect(responder.address("b").unwrap())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rejected.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            responder.metrics().connections.get("capacity_limited"),
            Some(&1)
        );
        drop(streams);
        tokio::time::timeout(Duration::from_secs(1), async {
            while responder.capacity.available_permits() != MAX_CONNECTIONS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
