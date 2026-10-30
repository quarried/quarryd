use std::time::Instant;

/// Token bucket for limiting guest messages. Time is supplied by the caller,
/// so behavior is deterministic.
#[derive(Debug, Clone)]
pub struct RateLimiter
{
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Option<Instant>,
}

impl RateLimiter
{
    /// Creates a full bucket holding `capacity` tokens that refills at
    /// `refill_per_sec` tokens per second. A negative or non-finite rate never refills.
    pub fn new(capacity: u32, refill_per_sec: f64) -> RateLimiter
    {
        let refill_per_sec = if refill_per_sec.is_finite() && refill_per_sec > 0.0
        {
            refill_per_sec
        }
        else
        {
            0.0
        };
        RateLimiter {
            capacity: f64::from(capacity),
            tokens: f64::from(capacity),
            refill_per_sec,
            last_refill: None,
        }
    }

    /// Takes one token if available. Times earlier than a previous call add no tokens.
    pub fn allow(&mut self, now: Instant) -> bool
    {
        match self.last_refill
        {
            Some(last) if now > last =>
            {
                let elapsed = now.duration_since(last).as_secs_f64();
                self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
                self.last_refill = Some(now);
            }
            Some(_) =>
            {}
            None => self.last_refill = Some(now),
        }
        if self.tokens >= 1.0
        {
            self.tokens -= 1.0;
            true
        }
        else
        {
            false
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_full_and_drains()
    {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(3, 1.0);
        assert!(limiter.allow(start));
        assert!(limiter.allow(start));
        assert!(limiter.allow(start));
        assert!(!limiter.allow(start));
    }

    #[test]
    fn refills_at_the_configured_rate()
    {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(2, 2.0);
        assert!(limiter.allow(start));
        assert!(limiter.allow(start));
        assert!(!limiter.allow(start));
        assert!(!limiter.allow(start + Duration::from_millis(250)));
        assert!(limiter.allow(start + Duration::from_millis(500)));
        assert!(!limiter.allow(start + Duration::from_millis(500)));
        assert!(limiter.allow(start + Duration::from_millis(1000)));
    }

    #[test]
    fn partial_refills_accumulate()
    {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(1, 4.0);
        assert!(limiter.allow(start));
        assert!(!limiter.allow(start + Duration::from_millis(125)));
        assert!(limiter.allow(start + Duration::from_millis(250)));
    }

    #[test]
    fn refill_is_capped_at_capacity()
    {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(2, 100.0);
        assert!(limiter.allow(start));
        let later = start + Duration::from_secs(3600);
        assert!(limiter.allow(later));
        assert!(limiter.allow(later));
        assert!(!limiter.allow(later));
    }

    #[test]
    fn time_going_backwards_adds_nothing()
    {
        let start = Instant::now() + Duration::from_secs(10);
        let mut limiter = RateLimiter::new(1, 1.0);
        assert!(limiter.allow(start));
        assert!(!limiter.allow(start - Duration::from_secs(5)));
        assert!(!limiter.allow(start + Duration::from_millis(500)));
        assert!(limiter.allow(start + Duration::from_secs(1)));
    }

    #[test]
    fn invalid_rates_never_refill()
    {
        let start = Instant::now();
        for rate in [0.0, -1.0, f64::NAN, f64::INFINITY]
        {
            let mut limiter = RateLimiter::new(1, rate);
            assert!(limiter.allow(start));
            assert!(!limiter.allow(start + Duration::from_secs(1000)));
        }
    }

    #[test]
    fn zero_capacity_never_allows()
    {
        let mut limiter = RateLimiter::new(0, 10.0);
        let start = Instant::now();
        assert!(!limiter.allow(start));
        assert!(!limiter.allow(start + Duration::from_secs(10)));
    }
}
