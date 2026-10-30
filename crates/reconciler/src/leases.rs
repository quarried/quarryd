use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proto::v1::{LeaseHeld, LeaseRenewal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldLease
{
    pub epoch: u64,
    pub ttl: Duration,
    pub expires_at: Instant,
    pub expires_unix_ms: i64,
}

impl HeldLease
{
    pub fn is_valid(&self, now: Instant) -> bool
    {
        now < self.expires_at
    }

    pub fn remaining(&self, now: Instant) -> Duration
    {
        self.expires_at.saturating_duration_since(now)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantOutcome
{
    Ignored,
    Extended,
    NewEpoch,
}

/// Per-instance leases (section 8). Expiry uses monotonic time; the wall-clock
/// expiry is kept alongside for persistence across restarts and reboots.
#[derive(Debug, Default)]
pub struct Leases
{
    held: BTreeMap<String, HeldLease>,
}

pub fn unix_ms_now() -> i64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl Leases
{
    pub fn grant(
        &mut self,
        instance_id: &str,
        epoch: u64,
        ttl: Duration,
        now: Instant,
        now_unix_ms: i64,
    ) -> GrantOutcome
    {
        let outcome = match self.held.get(instance_id)
        {
            Some(current) if epoch < current.epoch => return GrantOutcome::Ignored,
            Some(current) if epoch == current.epoch => GrantOutcome::Extended,
            _ => GrantOutcome::NewEpoch,
        };
        let ttl_ms = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
        self.held.insert(
            instance_id.to_owned(),
            HeldLease {
                epoch,
                ttl,
                expires_at: now + ttl,
                expires_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            },
        );
        outcome
    }

    pub fn restore(
        &mut self,
        instance_id: &str,
        epoch: u64,
        expires_unix_ms: i64,
        now: Instant,
        now_unix_ms: i64,
    )
    {
        let remaining_ms = u64::try_from(expires_unix_ms.saturating_sub(now_unix_ms)).unwrap_or(0);
        let remaining = Duration::from_millis(remaining_ms);
        self.held.insert(
            instance_id.to_owned(),
            HeldLease {
                epoch,
                ttl: remaining,
                expires_at: now + remaining,
                expires_unix_ms,
            },
        );
    }

    pub fn get(&self, instance_id: &str) -> Option<HeldLease>
    {
        self.held.get(instance_id).copied()
    }

    pub fn is_valid(&self, instance_id: &str, now: Instant) -> bool
    {
        self.held
            .get(instance_id)
            .is_some_and(|lease| lease.is_valid(now))
    }

    pub fn epoch(&self, instance_id: &str) -> u64
    {
        self.held
            .get(instance_id)
            .map(|lease| lease.epoch)
            .unwrap_or(0)
    }

    pub fn remove(&mut self, instance_id: &str)
    {
        self.held.remove(instance_id);
    }

    pub fn renewal(&self, now: Instant) -> LeaseRenewal
    {
        LeaseRenewal {
            leases: self
                .held
                .iter()
                .filter(|(_, lease)| lease.is_valid(now))
                .map(|(instance_id, lease)| LeaseHeld {
                    instance_id: instance_id.clone(),
                    epoch: lease.epoch,
                    remaining_ms: u64::try_from(lease.remaining(now).as_millis())
                        .unwrap_or(u64::MAX),
                })
                .collect(),
        }
    }

    pub fn all(&self) -> impl Iterator<Item = (&String, &HeldLease)>
    {
        self.held.iter()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn grants_extend_and_lower_epochs_are_ignored()
    {
        let start = Instant::now();
        let mut leases = Leases::default();
        assert!(!leases.is_valid("a", start));
        assert_eq!(
            leases.grant("a", 3, TTL, start, 1_000),
            GrantOutcome::NewEpoch
        );
        assert!(leases.is_valid("a", start + Duration::from_secs(59)));
        assert!(!leases.is_valid("a", start + TTL));
        let later = start + Duration::from_secs(30);
        assert_eq!(
            leases.grant("a", 3, TTL, later, 31_000),
            GrantOutcome::Extended
        );
        assert!(leases.is_valid("a", start + Duration::from_secs(89)));
        assert_eq!(leases.get("a").unwrap().expires_unix_ms, 91_000);
        assert_eq!(
            leases.grant("a", 2, TTL, later, 31_000),
            GrantOutcome::Ignored
        );
        assert_eq!(leases.epoch("a"), 3);
        assert_eq!(
            leases.grant("a", 4, Duration::from_secs(5), later, 31_000),
            GrantOutcome::NewEpoch
        );
        assert!(!leases.is_valid("a", later + Duration::from_secs(5)));
    }

    #[test]
    fn a_grant_after_expiry_with_the_same_epoch_revalidates()
    {
        let start = Instant::now();
        let mut leases = Leases::default();
        leases.grant("a", 1, TTL, start, 0);
        let expired = start + TTL + Duration::from_secs(1);
        assert!(!leases.is_valid("a", expired));
        assert_eq!(
            leases.grant("a", 1, TTL, expired, 61_000),
            GrantOutcome::Extended
        );
        assert!(leases.is_valid("a", expired));
    }

    #[test]
    fn restore_uses_the_remaining_wall_clock_time()
    {
        let start = Instant::now();
        let mut leases = Leases::default();
        leases.restore("a", 7, 10_000, start, 4_000);
        assert!(leases.is_valid("a", start + Duration::from_millis(5_999)));
        assert!(!leases.is_valid("a", start + Duration::from_millis(6_000)));
        leases.restore("b", 7, 1_000, start, 4_000);
        assert!(!leases.is_valid("b", start));
        assert_eq!(leases.epoch("b"), 7);
    }

    #[test]
    fn renewal_lists_only_valid_leases()
    {
        let start = Instant::now();
        let mut leases = Leases::default();
        leases.grant("a", 1, TTL, start, 0);
        leases.grant("b", 2, Duration::from_secs(1), start, 0);
        let renewal = leases.renewal(start + Duration::from_secs(2));
        assert_eq!(renewal.leases.len(), 1);
        assert_eq!(renewal.leases[0].instance_id, "a");
        assert_eq!(renewal.leases[0].epoch, 1);
        assert_eq!(renewal.leases[0].remaining_ms, 58_000);
        leases.remove("a");
        assert!(leases.renewal(start).leases.len() == 1);
    }
}
