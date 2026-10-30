use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use proto::v1::{InstanceHealth, Phase, PlayerInfo};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::time::Instant;

use sandbox::firecracker::FirecrackerApi;
use usage::{CgroupStats, FirecrackerMetricsReader, UsageAggregator, UsageSample, read_cgroup};

use crate::leases::unix_ms_now;
use crate::reconciler::{Inner, lock};

/// Usage sampling loop (section 4.9). Billing figures come from cgroup and
/// interface counters only, never from guest reports.
pub(crate) struct Sampler
{
    inner: Arc<Inner>,
    aggregator: UsageAggregator,
    vmm_readers: HashMap<String, FirecrackerMetricsReader>,
    health_sent: HashMap<String, Instant>,
}

async fn load_average() -> f64
{
    match tokio::fs::read_to_string("/proc/loadavg").await
    {
        Ok(text) => text
            .split_whitespace()
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.0),
        Err(_) => 0.0,
    }
}

impl Sampler
{
    pub fn new(inner: Arc<Inner>) -> Sampler
    {
        let aggregator = UsageAggregator::new(Arc::clone(&inner.parts.store));
        Sampler {
            inner,
            aggregator,
            vmm_readers: HashMap::new(),
            health_sent: HashMap::new(),
        }
    }

    pub async fn run(mut self)
    {
        let mut interval = tokio::time::interval(
            self.inner
                .config
                .sample_interval
                .min(Duration::from_secs(1)),
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop
        {
            let at = interval.tick().await;
            self.sample(at).await;
        }
    }

    async fn sample(&mut self, at: Instant)
    {
        let now_ms = u64::try_from(unix_ms_now()).unwrap_or(0);
        let now_unix = (now_ms / 1000) as i64;
        let public = self.inner.parts.network.public_metrics();
        self.inner.parts.metrics.set_public_network(
            public.bound,
            public.connections,
            public.wake_requests,
        );
        lock(&self.inner.live_metrics).retain(|_, until| *until > now_ms);
        let forgotten: Vec<String> = std::mem::take(&mut lock(&self.inner.observed).forgotten);
        for instance_id in forgotten
        {
            self.vmm_readers.remove(&instance_id);
            self.health_sent.remove(&instance_id);
            if let Err(error) = self.aggregator.forget(&instance_id, now_unix)
            {
                tracing::warn!(instance_id = %instance_id, error = %error, "closing usage of a deleted instance failed");
            }
        }
        let targets: Vec<_> = lock(&self.inner.observed)
            .instances
            .iter()
            .filter_map(|(id, view)| {
                view.record
                    .clone()
                    .map(|record| (id.clone(), record, view.clone()))
            })
            .collect();
        self.vmm_readers
            .retain(|id, _| targets.iter().any(|(target, _, _)| target == id));
        for (instance_id, record, view) in targets
        {
            self.sample_vmm(&instance_id, &record).await;
            let stats = match &record.cgroup_path
            {
                Some(path) => match read_cgroup(path).await
                {
                    Ok(stats) => stats,
                    Err(error) =>
                    {
                        tracing::debug!(instance_id = %instance_id, error = %error, "cgroup unavailable; skipping sample");
                        continue;
                    }
                },
                None => CgroupStats::default(),
            };
            let counters = match &view.attachment
            {
                Some(attachment) => match self.inner.parts.network.counters(attachment).await
                {
                    Ok(counters) => counters,
                    Err(error) =>
                    {
                        tracing::debug!(instance_id = %instance_id, error = %error, "interface counters unavailable; skipping sample");
                        continue;
                    }
                },
                None => network::InterfaceCounters::default(),
            };
            if view.status.phase == Phase::Running as i32
            {
                let live = lock(&self.inner.live_metrics).contains_key(&instance_id);
                let cadence = Duration::from_secs(if live { 1 } else { 5 });
                let now = at;
                if self
                    .health_sent
                    .get(&instance_id)
                    .is_none_or(|sent| now.duration_since(*sent) >= cadence)
                {
                    let guest = view.guest.health.unwrap_or_default();
                    let disk_used_bytes = self.disk_usage(&instance_id).await;
                    let _ = self.inner.health.send(InstanceHealth {
                        instance_id: instance_id.clone(),
                        sampled_at_unix_ms: now_ms,
                        tps: guest.tps,
                        mspt_p50_ms: guest.mspt_p50_ms,
                        mspt_p99_ms: guest.mspt_p99_ms,
                        players: guest.players,
                        player_list: guest
                            .player_list
                            .into_iter()
                            .map(|player| PlayerInfo {
                                uuid: player.uuid,
                                name: player.name,
                                online_since_unix_ms: player.online_since_unix_ms,
                                operator: player.operator,
                            })
                            .collect(),
                        cpu_usec_total: stats.cpu_usage_usec,
                        memory_bytes: stats.memory_current_bytes,
                        net_tx_bytes_total: counters.tx_bytes,
                        net_rx_bytes_total: counters.rx_bytes,
                        disk_used_bytes,
                    });
                    self.health_sent.insert(instance_id.clone(), now);
                }
            }
            let sample = UsageSample {
                at_unix: now_unix,
                cpu_usec_total: stats.cpu_usage_usec,
                memory_bytes: stats.memory_current_bytes,
                disk_read_total: stats.io_read_bytes,
                disk_write_total: stats.io_write_bytes,
                net_rx_total: counters.rx_bytes,
                net_tx_total: counters.tx_bytes,
            };
            if let Err(error) = self.aggregator.observe(&instance_id, &sample)
            {
                tracing::warn!(instance_id = %instance_id, error = %error, "recording usage failed");
            }
            self.inner.parts.metrics.set_instance_usage(
                &instance_id,
                &stats,
                (counters.rx_bytes, counters.tx_bytes),
            );
        }
        if let Err(error) = self.aggregator.close_due(now_unix)
        {
            tracing::warn!(error = %error, "closing usage buckets failed");
        }
        match self.inner.parts.volumes.pool_status().await
        {
            Ok(status) =>
            {
                self.inner
                    .parts
                    .metrics
                    .set_pool_used_percent(status.usage.used_percent);
                lock(&self.inner.observed).pool_used_percent = status.usage.used_percent;
            }
            Err(error) => tracing::warn!(error = %error, "reading thin pool usage failed"),
        }
        let load = load_average().await;
        lock(&self.inner.observed).load_1m = load;
    }

    async fn disk_usage(&self, instance_id: &str) -> u64
    {
        let names = match self.inner.parts.store.instance_disks(instance_id)
        {
            Ok(names) => names,
            Err(error) =>
            {
                tracing::debug!(instance_id, error = %error, "disk inventory unavailable");
                return 0;
            }
        };
        let mut used = 0u64;
        for name in names
        {
            if let Ok(Some(volume)) = self.inner.parts.volumes.backend().get(&name).await
                && let Ok(bytes) = disk_used_bytes(&volume.path).await
            {
                used = used.saturating_add(bytes);
            }
        }
        used
    }

    async fn sample_vmm(&mut self, instance_id: &str, record: &sandbox::SandboxRecord)
    {
        let Some(metrics_path) = &record.metrics_path
        else
        {
            return;
        };
        if let Some(api_socket) = &record.api_socket
            && let Err(error) = FirecrackerApi::new(api_socket.clone())
                .flush_metrics()
                .await
        {
            tracing::debug!(instance_id = %instance_id, error = %error, "flushing VMM metrics failed");
        }
        if !self.vmm_readers.contains_key(instance_id)
        {
            match FirecrackerMetricsReader::open(metrics_path)
            {
                Ok(reader) =>
                {
                    self.vmm_readers.insert(instance_id.to_owned(), reader);
                }
                Err(error) =>
                {
                    tracing::debug!(instance_id = %instance_id, error = %error, "VMM metrics unavailable");
                    return;
                }
            }
        }
        let Some(reader) = self.vmm_readers.get_mut(instance_id)
        else
        {
            return;
        };
        match reader.read_available()
        {
            Ok(totals) =>
            {
                if let Some(view) = lock(&self.inner.observed).instances.get_mut(instance_id)
                {
                    view.vmm_metrics = Some(totals);
                }
            }
            Err(error) =>
            {
                tracing::debug!(instance_id = %instance_id, error = %error, "reading VMM metrics failed");
                self.vmm_readers.remove(instance_id);
            }
        }
    }
}

async fn disk_used_bytes(path: &std::path::Path) -> Result<u64, std::io::Error>
{
    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    file.seek(std::io::SeekFrom::Start(1024)).await?;
    let mut superblock = [0u8; 1024];
    if file.read_exact(&mut superblock).await.is_ok() && superblock[56..58] == [0x53, 0xef]
    {
        let word = |offset: usize| {
            u32::from_le_bytes([
                superblock[offset],
                superblock[offset + 1],
                superblock[offset + 2],
                superblock[offset + 3],
            ]) as u64
        };
        let shift = word(24);
        if shift <= 6
        {
            let wide = word(96) & 0x80 != 0;
            let total = word(4) | if wide { word(336) << 32 } else { 0 };
            let free = word(12) | if wide { word(344) << 32 } else { 0 };
            return Ok(total.saturating_sub(free).saturating_mul(1024 << shift));
        }
    }
    Ok(metadata.blocks().saturating_mul(512))
}
