use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use store::{Store, UsageRow};

use crate::UsageError;

pub const BUCKET_SECONDS: u32 = 60;

const STATE_KEY_PREFIX: &str = "usage/aggregator/";
const MIB: u64 = 1024 * 1024;
const TOMBSTONE_RETENTION_SECONDS: i64 = 600;

pub fn usage_record_id(instance_id: &str, bucket_start_unix: i64) -> String
{
    format!("{instance_id}:{bucket_start_unix}")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageSample
{
    pub at_unix: i64,
    pub cpu_usec_total: u64,
    pub memory_bytes: u64,
    pub disk_read_total: u64,
    pub disk_write_total: u64,
    pub net_rx_total: u64,
    pub net_tx_total: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Counters
{
    cpu_usec: u64,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
}

impl Counters
{
    fn from_sample(sample: &UsageSample) -> Counters
    {
        Counters {
            cpu_usec: sample.cpu_usec_total,
            disk_read_bytes: sample.disk_read_total,
            disk_write_bytes: sample.disk_write_total,
            net_rx_bytes: sample.net_rx_total,
            net_tx_bytes: sample.net_tx_total,
        }
    }

    fn since(&self, baseline: &Counters) -> Counters
    {
        Counters {
            cpu_usec: counter_delta(self.cpu_usec, baseline.cpu_usec),
            disk_read_bytes: counter_delta(self.disk_read_bytes, baseline.disk_read_bytes),
            disk_write_bytes: counter_delta(self.disk_write_bytes, baseline.disk_write_bytes),
            net_rx_bytes: counter_delta(self.net_rx_bytes, baseline.net_rx_bytes),
            net_tx_bytes: counter_delta(self.net_tx_bytes, baseline.net_tx_bytes),
        }
    }

    fn add(&mut self, delta: &Counters)
    {
        self.cpu_usec = self.cpu_usec.saturating_add(delta.cpu_usec);
        self.disk_read_bytes = self.disk_read_bytes.saturating_add(delta.disk_read_bytes);
        self.disk_write_bytes = self.disk_write_bytes.saturating_add(delta.disk_write_bytes);
        self.net_rx_bytes = self.net_rx_bytes.saturating_add(delta.net_rx_bytes);
        self.net_tx_bytes = self.net_tx_bytes.saturating_add(delta.net_tx_bytes);
    }
}

fn counter_delta(current: u64, baseline: u64) -> u64
{
    if current >= baseline
    {
        current - baseline
    }
    else
    {
        current
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OpenBucket
{
    start_unix: i64,
    usage: Counters,
    memory_max_bytes: u64,
    memory_sum_bytes: u64,
    memory_samples: u64,
}

impl OpenBucket
{
    fn new(start_unix: i64) -> OpenBucket
    {
        OpenBucket {
            start_unix,
            usage: Counters::default(),
            memory_max_bytes: 0,
            memory_sum_bytes: 0,
            memory_samples: 0,
        }
    }

    fn add(&mut self, delta: &Counters, memory_bytes: u64)
    {
        self.usage.add(delta);
        self.memory_max_bytes = self.memory_max_bytes.max(memory_bytes);
        self.memory_sum_bytes = self.memory_sum_bytes.saturating_add(memory_bytes);
        self.memory_samples += 1;
    }

    fn ends_by(&self, now_unix: i64) -> bool
    {
        self.start_unix.saturating_add(i64::from(BUCKET_SECONDS)) <= now_unix
    }

    fn to_row(&self, instance_id: &str) -> UsageRow
    {
        let memory_avg_bytes = self.memory_sum_bytes / self.memory_samples.max(1);
        UsageRow {
            id: usage_record_id(instance_id, self.start_unix),
            instance_id: instance_id.to_string(),
            bucket_start_unix: self.start_unix,
            bucket_seconds: BUCKET_SECONDS,
            cpu_usec: self.usage.cpu_usec,
            memory_mib_max: self.memory_max_bytes.div_ceil(MIB),
            memory_mib_avg: memory_avg_bytes.div_ceil(MIB),
            disk_read_bytes: self.usage.disk_read_bytes,
            disk_write_bytes: self.usage.disk_write_bytes,
            net_rx_bytes: self.usage.net_rx_bytes,
            net_tx_bytes: self.usage.net_tx_bytes,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct InstanceState
{
    baseline: Option<Counters>,
    bucket: Option<OpenBucket>,
    forgotten_at_unix: Option<i64>,
}

pub struct UsageAggregator
{
    store: Arc<Store>,
    loaded: bool,
    instances: BTreeMap<String, InstanceState>,
}

impl UsageAggregator
{
    pub fn new(store: Arc<Store>) -> UsageAggregator
    {
        UsageAggregator {
            store,
            loaded: false,
            instances: BTreeMap::new(),
        }
    }

    pub fn observe(
        &mut self,
        instance_id: &str,
        sample: &UsageSample,
    ) -> Result<Vec<UsageRow>, UsageError>
    {
        self.load()?;
        let mut state = self.instances.get(instance_id).cloned().unwrap_or_default();
        if let Some(forgotten_at_unix) = state.forgotten_at_unix
        {
            if sample.at_unix <= forgotten_at_unix
            {
                return Ok(Vec::new());
            }
            state = InstanceState::default();
        }

        let current = Counters::from_sample(sample);
        let delta = current.since(&state.baseline.unwrap_or_default());
        let sample_bucket_start =
            sample.at_unix - sample.at_unix.rem_euclid(i64::from(BUCKET_SECONDS));

        let mut closed = Vec::new();
        let mut bucket = match state.bucket.take()
        {
            Some(open) if open.start_unix < sample_bucket_start =>
            {
                closed.push(open.to_row(instance_id));
                OpenBucket::new(sample_bucket_start)
            }
            Some(open) => open,
            None => OpenBucket::new(sample_bucket_start),
        };
        bucket.add(&delta, sample.memory_bytes);
        state.baseline = Some(current);
        state.bucket = Some(bucket);

        self.commit(instance_id, state, &closed)?;
        Ok(closed)
    }

    pub fn close_due(&mut self, now_unix: i64) -> Result<Vec<UsageRow>, UsageError>
    {
        self.load()?;
        let mut closed = Vec::new();
        let instance_ids: Vec<String> = self.instances.keys().cloned().collect();
        for instance_id in instance_ids
        {
            let Some(state) = self.instances.get(&instance_id)
            else
            {
                continue;
            };
            if state.forgotten_at_unix.is_some_and(|forgotten| {
                now_unix.saturating_sub(forgotten) >= TOMBSTONE_RETENTION_SECONDS
            })
            {
                self.store.kv_delete(&state_key(&instance_id))?;
                self.instances.remove(&instance_id);
                continue;
            }
            let Some(bucket) = state
                .bucket
                .as_ref()
                .filter(|bucket| bucket.ends_by(now_unix))
            else
            {
                continue;
            };
            let rows = vec![bucket.to_row(&instance_id)];
            let mut next = state.clone();
            next.bucket = None;
            self.commit(&instance_id, next, &rows)?;
            closed.extend(rows);
        }
        Ok(closed)
    }

    pub fn forget(&mut self, instance_id: &str, now_unix: i64)
    -> Result<Vec<UsageRow>, UsageError>
    {
        self.load()?;
        let rows: Vec<UsageRow> = self
            .instances
            .get(instance_id)
            .and_then(|state| state.bucket.as_ref())
            .map(|bucket| bucket.to_row(instance_id))
            .into_iter()
            .collect();
        let tombstone = InstanceState {
            baseline: None,
            bucket: None,
            forgotten_at_unix: Some(now_unix),
        };
        self.commit(instance_id, tombstone, &rows)?;
        Ok(rows)
    }

    fn commit(
        &mut self,
        instance_id: &str,
        state: InstanceState,
        closed: &[UsageRow],
    ) -> Result<(), UsageError>
    {
        for row in closed
        {
            self.store.insert_usage(row)?;
        }
        let encoded = serde_json::to_vec(&state).map_err(UsageError::EncodeState)?;
        self.store.kv_set(&state_key(instance_id), &encoded)?;
        self.instances.insert(instance_id.to_string(), state);
        Ok(())
    }

    fn load(&mut self) -> Result<(), UsageError>
    {
        if self.loaded
        {
            return Ok(());
        }
        let mut instances = BTreeMap::new();
        for (key, value) in self.store.kv_list_prefix(STATE_KEY_PREFIX)?
        {
            let instance_id = key[STATE_KEY_PREFIX.len()..].to_string();
            let state: InstanceState =
                serde_json::from_slice(&value).map_err(|source| UsageError::CorruptState {
                    instance_id: instance_id.clone(),
                    source,
                })?;
            instances.insert(instance_id, state);
        }
        self.instances = instances;
        self.loaded = true;
        Ok(())
    }
}

fn state_key(instance_id: &str) -> String
{
    format!("{STATE_KEY_PREFIX}{instance_id}")
}

#[cfg(test)]
mod tests
{
    use super::*;

    const GIB: u64 = 1024 * MIB;

    fn sample(at_unix: i64, cpu_usec_total: u64, memory_bytes: u64) -> UsageSample
    {
        UsageSample {
            at_unix,
            cpu_usec_total,
            memory_bytes,
            disk_read_total: cpu_usec_total * 2,
            disk_write_total: cpu_usec_total * 3,
            net_rx_total: cpu_usec_total * 4,
            net_tx_total: cpu_usec_total * 5,
        }
    }

    fn aggregator() -> (Arc<Store>, UsageAggregator)
    {
        let store = Arc::new(Store::open_in_memory().unwrap());
        (Arc::clone(&store), UsageAggregator::new(store))
    }

    #[test]
    fn record_id_is_instance_and_bucket_start()
    {
        assert_eq!(usage_record_id("srv-1", 1_700_000_040), "srv-1:1700000040");
    }

    #[test]
    fn closes_bucket_when_a_sample_crosses_the_minute()
    {
        let (store, mut aggregator) = aggregator();
        assert!(
            aggregator
                .observe("srv-1", &sample(1_000_020, 1000, GIB))
                .unwrap()
                .is_empty()
        );
        assert!(
            aggregator
                .observe("srv-1", &sample(1_000_030, 1500, 3 * GIB))
                .unwrap()
                .is_empty()
        );
        assert!(
            aggregator
                .observe("srv-1", &sample(1_000_079, 1600, 2 * GIB))
                .unwrap()
                .is_empty()
        );
        let closed = aggregator
            .observe("srv-1", &sample(1_000_085, 2000, GIB))
            .unwrap();
        assert_eq!(
            closed,
            vec![UsageRow {
                id: "srv-1:1000020".to_string(),
                instance_id: "srv-1".to_string(),
                bucket_start_unix: 1_000_020,
                bucket_seconds: 60,
                cpu_usec: 1600,
                memory_mib_max: 3072,
                memory_mib_avg: 2048,
                disk_read_bytes: 3200,
                disk_write_bytes: 4800,
                net_rx_bytes: 6400,
                net_tx_bytes: 8000,
            }]
        );
        assert_eq!(store.pending_usage(10).unwrap(), closed);

        let closed = aggregator.close_due(1_000_140).unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, "srv-1:1000080");
        assert_eq!(closed[0].cpu_usec, 400);
        assert_eq!(closed[0].memory_mib_max, 1024);
        assert_eq!(store.usage_depth().unwrap(), 2);
    }

    #[test]
    fn buckets_align_to_the_unix_minute()
    {
        let (_, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(119, 10, 0)).unwrap();
        let closed = aggregator.observe("srv-1", &sample(120, 20, 0)).unwrap();
        assert_eq!(closed[0].bucket_start_unix, 60);
        let closed = aggregator.close_due(180).unwrap();
        assert_eq!(closed[0].bucket_start_unix, 120);
        assert_eq!(closed[0].cpu_usec, 10);
    }

    #[test]
    fn counter_reset_counts_from_zero()
    {
        let (_, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(60, 5000, GIB)).unwrap();
        aggregator.observe("srv-1", &sample(70, 300, GIB)).unwrap();
        aggregator.observe("srv-1", &sample(80, 450, GIB)).unwrap();
        let closed = aggregator.close_due(120).unwrap();
        assert_eq!(closed[0].cpu_usec, 5000 + 300 + 150);
        assert_eq!(closed[0].net_tx_bytes, (5000 + 300 + 150) * 5);
    }

    #[test]
    fn close_due_waits_for_the_minute_to_end()
    {
        let (store, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(65, 100, GIB)).unwrap();
        aggregator.observe("srv-2", &sample(70, 200, GIB)).unwrap();
        assert!(aggregator.close_due(119).unwrap().is_empty());
        let closed = aggregator.close_due(120).unwrap();
        let ids: Vec<&str> = closed.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids, ["srv-1:60", "srv-2:60"]);
        assert!(aggregator.close_due(500).unwrap().is_empty());
        assert_eq!(store.usage_depth().unwrap(), 2);

        aggregator.observe("srv-1", &sample(190, 160, GIB)).unwrap();
        let closed = aggregator.close_due(240).unwrap();
        assert_eq!(closed[0].id, "srv-1:180");
        assert_eq!(closed[0].cpu_usec, 60);
    }

    #[test]
    fn late_sample_goes_into_the_open_bucket()
    {
        let (_, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(130, 100, GIB)).unwrap();
        assert!(
            aggregator
                .observe("srv-1", &sample(110, 150, GIB))
                .unwrap()
                .is_empty()
        );
        let closed = aggregator.close_due(180).unwrap();
        assert_eq!(closed[0].bucket_start_unix, 120);
        assert_eq!(closed[0].cpu_usec, 150);
    }

    #[test]
    fn forget_closes_the_open_bucket_and_ignores_stragglers()
    {
        let (store, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(60, 100, GIB)).unwrap();
        aggregator.observe("srv-1", &sample(70, 180, GIB)).unwrap();
        let closed = aggregator.forget("srv-1", 75).unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, "srv-1:60");
        assert_eq!(closed[0].cpu_usec, 180);
        assert_eq!(store.usage_depth().unwrap(), 1);

        assert!(
            aggregator
                .observe("srv-1", &sample(74, 190, GIB))
                .unwrap()
                .is_empty()
        );
        assert!(aggregator.forget("srv-1", 76).unwrap().is_empty());
        assert!(aggregator.close_due(200).unwrap().is_empty());
        assert_eq!(store.usage_depth().unwrap(), 1);

        assert!(aggregator.forget("never-seen", 80).unwrap().is_empty());
    }

    #[test]
    fn tombstones_are_pruned_after_retention()
    {
        let (store, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(60, 100, GIB)).unwrap();
        aggregator.forget("srv-1", 100).unwrap();
        assert_eq!(store.kv_list_prefix(STATE_KEY_PREFIX).unwrap().len(), 1);
        aggregator
            .close_due(100 + TOMBSTONE_RETENTION_SECONDS - 1)
            .unwrap();
        assert_eq!(store.kv_list_prefix(STATE_KEY_PREFIX).unwrap().len(), 1);
        aggregator
            .close_due(100 + TOMBSTONE_RETENTION_SECONDS)
            .unwrap();
        assert!(store.kv_list_prefix(STATE_KEY_PREFIX).unwrap().is_empty());
    }

    #[test]
    fn sample_after_forget_starts_from_zero()
    {
        let (_, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(60, 100, GIB)).unwrap();
        aggregator.forget("srv-1", 100).unwrap();
        aggregator.observe("srv-1", &sample(185, 40, GIB)).unwrap();
        let closed = aggregator.close_due(240).unwrap();
        assert_eq!(closed[0].id, "srv-1:180");
        assert_eq!(closed[0].cpu_usec, 40);
    }

    #[test]
    fn restart_mid_bucket_neither_loses_nor_double_counts()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        let samples = [
            sample(1_000_020, 1000, GIB),
            sample(1_000_030, 1700, 2 * GIB),
            sample(1_000_050, 2100, 3 * GIB),
            sample(1_000_090, 2500, GIB),
        ];

        let reference = {
            let (_, mut aggregator) = aggregator();
            let mut closed = Vec::new();
            for sample in &samples
            {
                closed.extend(aggregator.observe("srv-1", sample).unwrap());
            }
            closed.extend(aggregator.close_due(1_000_140).unwrap());
            closed
        };

        {
            let store = Arc::new(Store::open(&path).unwrap());
            let mut aggregator = UsageAggregator::new(store);
            aggregator.observe("srv-1", &samples[0]).unwrap();
            aggregator.observe("srv-1", &samples[1]).unwrap();
        }
        let store = Arc::new(Store::open(&path).unwrap());
        let mut aggregator = UsageAggregator::new(Arc::clone(&store));
        aggregator.observe("srv-1", &samples[2]).unwrap();
        aggregator.observe("srv-1", &samples[3]).unwrap();
        aggregator.close_due(1_000_140).unwrap();

        assert_eq!(reference.len(), 2);
        assert_eq!(store.pending_usage(10).unwrap(), reference);
    }

    #[test]
    fn restart_closes_buckets_that_ended_while_down()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        {
            let mut aggregator = UsageAggregator::new(Arc::new(Store::open(&path).unwrap()));
            aggregator.observe("srv-1", &sample(65, 100, GIB)).unwrap();
        }
        let store = Arc::new(Store::open(&path).unwrap());
        let mut aggregator = UsageAggregator::new(Arc::clone(&store));
        let closed = aggregator.close_due(300).unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, "srv-1:60");
        assert_eq!(closed[0].cpu_usec, 100);
    }

    #[test]
    fn replayed_close_after_crash_does_not_duplicate()
    {
        let (store, mut aggregator) = aggregator();
        aggregator.observe("srv-1", &sample(65, 100, GIB)).unwrap();
        let saved_state = store.kv_get(&state_key("srv-1")).unwrap().unwrap();
        aggregator.close_due(120).unwrap();
        store.kv_set(&state_key("srv-1"), &saved_state).unwrap();

        let mut restarted = UsageAggregator::new(Arc::clone(&store));
        let closed = restarted.close_due(120).unwrap();
        assert_eq!(closed[0].id, "srv-1:60");
        assert_eq!(store.usage_depth().unwrap(), 1);
        assert_eq!(store.pending_usage(10).unwrap(), closed);
    }

    #[test]
    fn corrupt_state_is_reported()
    {
        let (store, mut aggregator) = aggregator();
        store.kv_set(&state_key("srv-1"), b"{broken").unwrap();
        assert!(matches!(
            aggregator.close_due(0),
            Err(UsageError::CorruptState { instance_id, .. }) if instance_id == "srv-1"
        ));
    }
}
