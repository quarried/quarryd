use std::collections::HashMap;
use std::sync::Arc;

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
        }
    }

    pub async fn run(mut self)
    {
        let mut interval = tokio::time::interval(self.inner.config.sample_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop
        {
            interval.tick().await;
            self.sample().await;
        }
    }

    async fn sample(&mut self)
    {
        let now_unix = unix_ms_now() / 1000;
        let forgotten: Vec<String> = std::mem::take(&mut lock(&self.inner.observed).forgotten);
        for instance_id in forgotten
        {
            self.vmm_readers.remove(&instance_id);
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
                    .map(|record| (id.clone(), record, view.attachment.clone()))
            })
            .collect();
        self.vmm_readers
            .retain(|id, _| targets.iter().any(|(target, _, _)| target == id));
        for (instance_id, record, attachment) in targets
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
            let counters = match &attachment
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
