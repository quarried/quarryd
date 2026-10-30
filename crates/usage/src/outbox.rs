use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use store::{Store, UsageRow};

use crate::UsageError;

pub struct Outbox
{
    store: Arc<Store>,
    in_flight_by_seq: BTreeMap<u64, Vec<String>>,
    in_flight_ids: HashSet<String>,
}

impl Outbox
{
    pub fn new(store: Arc<Store>) -> Outbox
    {
        Outbox {
            store,
            in_flight_by_seq: BTreeMap::new(),
            in_flight_ids: HashSet::new(),
        }
    }

    pub fn next_batch(&mut self, limit: usize) -> Result<Vec<UsageRow>, UsageError>
    {
        let fetch = limit.saturating_add(self.in_flight_ids.len());
        Ok(self
            .store
            .pending_usage(fetch)?
            .into_iter()
            .filter(|row| !self.in_flight_ids.contains(&row.id))
            .take(limit)
            .collect())
    }

    pub fn mark_sent(&mut self, seq: u64, ids: Vec<String>)
    {
        self.in_flight_ids.extend(ids.iter().cloned());
        self.in_flight_by_seq.entry(seq).or_default().extend(ids);
    }

    pub fn ack(&mut self, ack_seq: u64) -> Result<usize, UsageError>
    {
        let acked_seqs: Vec<u64> = self
            .in_flight_by_seq
            .range(..=ack_seq)
            .map(|(seq, _)| *seq)
            .collect();
        if acked_seqs.is_empty()
        {
            return Ok(0);
        }
        let ids: Vec<String> = acked_seqs
            .iter()
            .filter_map(|seq| self.in_flight_by_seq.get(seq))
            .flatten()
            .cloned()
            .collect();
        let deleted = self.store.delete_usage(&ids)?;
        for seq in acked_seqs
        {
            self.in_flight_by_seq.remove(&seq);
        }
        for id in &ids
        {
            self.in_flight_ids.remove(id);
        }
        Ok(deleted)
    }

    pub fn reset_in_flight(&mut self)
    {
        self.in_flight_by_seq.clear();
        self.in_flight_ids.clear();
    }

    pub fn depth(&self) -> Result<u64, UsageError>
    {
        Ok(self.store.usage_depth()?)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::{UsageAggregator, UsageSample, usage_record_id};

    fn sample(at_unix: i64, cpu_usec_total: u64) -> UsageSample
    {
        UsageSample {
            at_unix,
            cpu_usec_total,
            memory_bytes: 512 * 1024 * 1024,
            ..UsageSample::default()
        }
    }

    fn ids(rows: &[UsageRow]) -> Vec<String>
    {
        rows.iter().map(|row| row.id.clone()).collect()
    }

    fn fill(store: &Arc<Store>, minutes: i64)
    {
        let mut aggregator = UsageAggregator::new(Arc::clone(store));
        for minute in 1..=minutes
        {
            aggregator
                .observe("srv-1", &sample(minute * 60 + 5, minute as u64 * 1000))
                .unwrap();
        }
        aggregator.close_due(minutes * 60 + 60).unwrap();
    }

    #[test]
    fn records_survive_restart_with_the_same_ids()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        let before = {
            let store = Arc::new(Store::open(&path).unwrap());
            let mut aggregator = UsageAggregator::new(Arc::clone(&store));
            aggregator.observe("srv-1", &sample(65, 1000)).unwrap();
            aggregator.observe("srv-1", &sample(125, 2000)).unwrap();
            aggregator.observe("srv-2", &sample(70, 500)).unwrap();
            aggregator.close_due(180).unwrap();
            let mut outbox = Outbox::new(Arc::clone(&store));
            let batch = outbox.next_batch(10).unwrap();
            outbox.mark_sent(7, ids(&batch));
            batch
        };
        assert_eq!(ids(&before), ["srv-1:60", "srv-2:60", "srv-1:120"]);

        let store = Arc::new(Store::open(&path).unwrap());
        let mut aggregator = UsageAggregator::new(Arc::clone(&store));
        assert!(aggregator.close_due(180).unwrap().is_empty());
        let mut outbox = Outbox::new(Arc::clone(&store));
        assert_eq!(outbox.depth().unwrap(), 3);
        let after = outbox.next_batch(10).unwrap();
        assert_eq!(after, before);
        assert_eq!(after[0].id, usage_record_id("srv-1", 60));
    }

    #[test]
    fn rows_are_deleted_only_after_ack()
    {
        let store = Arc::new(Store::open_in_memory().unwrap());
        fill(&store, 4);
        let mut outbox = Outbox::new(Arc::clone(&store));

        let first = outbox.next_batch(2).unwrap();
        assert_eq!(ids(&first), ["srv-1:60", "srv-1:120"]);
        outbox.mark_sent(10, ids(&first));
        assert_eq!(outbox.depth().unwrap(), 4);

        let second = outbox.next_batch(2).unwrap();
        assert_eq!(ids(&second), ["srv-1:180", "srv-1:240"]);
        outbox.mark_sent(11, ids(&second));
        assert!(outbox.next_batch(10).unwrap().is_empty());
        assert_eq!(outbox.depth().unwrap(), 4);

        assert_eq!(outbox.ack(9).unwrap(), 0);
        assert_eq!(outbox.depth().unwrap(), 4);

        assert_eq!(outbox.ack(10).unwrap(), 2);
        assert_eq!(outbox.depth().unwrap(), 2);
        assert_eq!(
            ids(&store.pending_usage(10).unwrap()),
            ["srv-1:180", "srv-1:240"]
        );

        assert_eq!(outbox.ack(10).unwrap(), 0);
        assert_eq!(outbox.ack(11).unwrap(), 2);
        assert_eq!(outbox.depth().unwrap(), 0);
    }

    #[test]
    fn cumulative_ack_covers_all_lower_seqs()
    {
        let store = Arc::new(Store::open_in_memory().unwrap());
        fill(&store, 3);
        let mut outbox = Outbox::new(Arc::clone(&store));
        for seq in [3, 4, 5]
        {
            let batch = outbox.next_batch(1).unwrap();
            outbox.mark_sent(seq, ids(&batch));
        }
        assert_eq!(outbox.ack(4).unwrap(), 2);
        assert_eq!(ids(&store.pending_usage(10).unwrap()), ["srv-1:180"]);
    }

    #[test]
    fn reset_in_flight_makes_rows_resendable_with_unchanged_ids()
    {
        let store = Arc::new(Store::open_in_memory().unwrap());
        fill(&store, 2);
        let mut outbox = Outbox::new(Arc::clone(&store));
        let sent = outbox.next_batch(10).unwrap();
        outbox.mark_sent(20, ids(&sent));
        assert!(outbox.next_batch(10).unwrap().is_empty());

        outbox.reset_in_flight();
        assert_eq!(outbox.ack(20).unwrap(), 0);
        assert_eq!(outbox.depth().unwrap(), 2);

        let resent = outbox.next_batch(10).unwrap();
        assert_eq!(resent, sent);
        outbox.mark_sent(3, ids(&resent));
        assert_eq!(outbox.ack(3).unwrap(), 2);
        assert_eq!(outbox.depth().unwrap(), 0);
    }

    #[test]
    fn rows_written_while_in_flight_are_sent_next()
    {
        let store = Arc::new(Store::open_in_memory().unwrap());
        fill(&store, 1);
        let mut outbox = Outbox::new(Arc::clone(&store));
        let first = outbox.next_batch(10).unwrap();
        outbox.mark_sent(1, ids(&first));

        let mut aggregator = UsageAggregator::new(Arc::clone(&store));
        aggregator.observe("srv-2", &sample(65, 10)).unwrap();
        aggregator.close_due(120).unwrap();
        assert_eq!(ids(&outbox.next_batch(10).unwrap()), ["srv-2:60"]);
    }
}
