use std::time::{Duration, Instant};

use guest_proto::{MAX_MSPT, MAX_PLAYERS, MAX_TPS};

use crate::output;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe
{
    List,
    Tps,
    Mspt,
}

const ORDER: [Probe; 3] = [Probe::List, Probe::Tps, Probe::Mspt];

impl Probe
{
    fn command(self) -> &'static str
    {
        match self
        {
            Probe::List => "list",
            Probe::Tps => "tps",
            Probe::Mspt => "mspt",
        }
    }

    fn index(self) -> usize
    {
        match self
        {
            Probe::List => 0,
            Probe::Tps => 1,
            Probe::Mspt => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample
{
    pub players: u32,
    pub tps: f64,
    pub mspt: f64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Step
{
    Wait,
    Send(&'static str),
    Complete,
}

struct Pending
{
    probe: Probe,
    sent_at: Instant,
    header_seen: bool,
}

pub struct Prober
{
    sample: Sample,
    unsupported: [bool; 3],
    pending: Option<Pending>,
    swallow_marker: bool,
    mspt_from_tps: bool,
}

impl Prober
{
    pub fn new() -> Prober
    {
        Prober {
            sample: Sample::default(),
            unsupported: [false; 3],
            pending: None,
            swallow_marker: false,
            mspt_from_tps: false,
        }
    }

    pub fn sample(&self) -> Sample
    {
        self.sample
    }

    pub fn deadline(&self) -> Option<Instant>
    {
        self.pending
            .as_ref()
            .map(|pending| pending.sent_at + PROBE_TIMEOUT)
    }

    pub fn begin(&mut self, now: Instant) -> Step
    {
        if self.pending.is_some()
        {
            return Step::Wait;
        }
        self.mspt_from_tps = false;
        self.advance_from(0, now)
    }

    pub fn expire(&mut self, now: Instant) -> Step
    {
        match self.deadline()
        {
            Some(deadline) if now >= deadline => self.advance(now),
            _ => Step::Wait,
        }
    }

    pub fn observe(&mut self, line: &str, now: Instant) -> (bool, Step)
    {
        let swallow_marker = std::mem::take(&mut self.swallow_marker);
        if swallow_marker && output::is_error_marker(line)
        {
            return (true, Step::Wait);
        }
        let Some(pending) = &self.pending
        else
        {
            return (false, Step::Wait);
        };
        let probe = pending.probe;
        if output::is_unknown_command(line)
        {
            self.unsupported[probe.index()] = true;
            self.swallow_marker = true;
            log!(
                "the server does not support `{}`; health keeps reporting the last known value",
                probe.command()
            );
            return (true, self.advance(now));
        }
        match probe
        {
            Probe::List =>
            {
                if let Some(players) = output::players(line)
                {
                    self.sample.players = players.min(MAX_PLAYERS);
                    return (true, self.advance(now));
                }
            }
            Probe::Tps =>
            {
                if let Some(reading) = output::tps(line)
                {
                    self.sample.tps = reading.tps.clamp(0.0, MAX_TPS);
                    if let Some(mspt) = reading.mspt
                    {
                        self.sample.mspt = mspt.clamp(0.0, MAX_MSPT);
                        self.mspt_from_tps = true;
                    }
                    return (true, self.advance(now));
                }
            }
            Probe::Mspt =>
            {
                if pending.header_seen
                {
                    if let Some(mspt) = output::mspt(line)
                    {
                        self.sample.mspt = mspt.clamp(0.0, MAX_MSPT);
                    }
                    return (true, self.advance(now));
                }
                if output::is_mspt_header(line)
                {
                    if let Some(pending) = &mut self.pending
                    {
                        pending.header_seen = true;
                    }
                    return (true, Step::Wait);
                }
            }
        }
        (false, Step::Wait)
    }

    fn advance(&mut self, now: Instant) -> Step
    {
        let next = self
            .pending
            .as_ref()
            .map_or(ORDER.len(), |pending| pending.probe.index() + 1);
        self.advance_from(next, now)
    }

    fn advance_from(&mut self, start: usize, now: Instant) -> Step
    {
        match ORDER[start.min(ORDER.len())..].iter().find(|probe| {
            !self.unsupported[probe.index()] && !(self.mspt_from_tps && **probe == Probe::Mspt)
        })
        {
            Some(&probe) =>
            {
                self.pending = Some(Pending {
                    probe,
                    sent_at: now,
                    header_seen: false,
                });
                Step::Send(probe.command())
            }
            None =>
            {
                self.pending = None;
                Step::Complete
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn observe(prober: &mut Prober, line: &str, now: Instant) -> (bool, Step)
    {
        prober.observe(line, now)
    }

    #[test]
    fn a_round_probes_list_tps_and_mspt_in_order()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        assert_eq!(prober.begin(now), Step::Send("list"));
        assert_eq!(prober.begin(now), Step::Wait);
        assert_eq!(
            observe(&mut prober, "unrelated chatter", now),
            (false, Step::Wait)
        );
        assert_eq!(
            observe(
                &mut prober,
                "There are 4 of a max of 20 players online: a, b, c, d",
                now
            ),
            (true, Step::Send("tps"))
        );
        assert_eq!(
            observe(
                &mut prober,
                "TPS from last 1m, 5m, 15m: 19.9, 20.0, 20.0",
                now
            ),
            (true, Step::Send("mspt"))
        );
        assert_eq!(
            observe(
                &mut prober,
                "Server tick times (avg/min/max) from last 5s, 10s, 1m:",
                now
            ),
            (true, Step::Wait)
        );
        assert_eq!(
            observe(&mut prober, "◴ 3.5/1.0/9.0, 3.0/1.0/9.0, 2.0/1.0/9.0", now),
            (true, Step::Complete)
        );
        assert_eq!(
            prober.sample(),
            Sample {
                players: 4,
                tps: 19.9,
                mspt: 3.5
            }
        );
        assert_eq!(prober.deadline(), None);
        assert_eq!(
            observe(
                &mut prober,
                "There are 9 of a max of 20 players online:",
                now
            ),
            (false, Step::Wait)
        );
        assert_eq!(prober.sample().players, 4);
    }

    #[test]
    fn unsupported_probes_keep_the_last_value_and_are_skipped_afterwards()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        assert_eq!(prober.begin(now), Step::Send("list"));
        observe(
            &mut prober,
            "There are 1 of a max of 20 players online:",
            now,
        );
        assert_eq!(
            observe(
                &mut prober,
                "Unknown or incomplete command, see below for error",
                now
            ),
            (true, Step::Send("mspt"))
        );
        assert_eq!(
            observe(&mut prober, "tps<--[HERE]", now),
            (true, Step::Wait)
        );
        assert_eq!(
            observe(
                &mut prober,
                "Unknown or incomplete command, see below for error",
                now
            ),
            (true, Step::Complete)
        );
        assert_eq!(
            observe(&mut prober, "mspt<--[HERE]", now),
            (true, Step::Wait)
        );
        assert_eq!(
            observe(&mut prober, "later<--[HERE]", now),
            (false, Step::Wait)
        );
        assert_eq!(
            prober.sample(),
            Sample {
                players: 1,
                tps: 0.0,
                mspt: 0.0
            }
        );
        assert_eq!(prober.begin(now), Step::Send("list"));
        assert_eq!(
            observe(
                &mut prober,
                "There are 2 of a max of 20 players online:",
                now
            ),
            (true, Step::Complete)
        );
    }

    #[test]
    fn a_silent_probe_times_out_and_is_retried_next_round()
    {
        let start = Instant::now();
        let mut prober = Prober::new();
        assert_eq!(prober.begin(start), Step::Send("list"));
        assert_eq!(prober.expire(start + Duration::from_secs(1)), Step::Wait);
        let later = start + PROBE_TIMEOUT;
        assert_eq!(prober.expire(later), Step::Send("tps"));
        assert_eq!(prober.expire(later + PROBE_TIMEOUT), Step::Send("mspt"));
        assert_eq!(prober.expire(later + PROBE_TIMEOUT * 2), Step::Complete);
        assert_eq!(prober.sample(), Sample::default());
        assert_eq!(prober.begin(later + PROBE_TIMEOUT * 3), Step::Send("list"));
    }

    #[test]
    fn a_quarry_tps_reply_carries_mspt_and_skips_the_mspt_probe()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        assert_eq!(prober.begin(now), Step::Send("list"));
        observe(
            &mut prober,
            "INFO There are 2 of a max of 20 players online: ",
            now,
        );
        assert_eq!(
            observe(
                &mut prober,
                "INFO TPS (5s, 1m): 18.0, 19.5 | MSPT: 0.11 ms (last 0.08 ms)",
                now
            ),
            (true, Step::Complete)
        );
        assert_eq!(
            prober.sample(),
            Sample {
                players: 2,
                tps: 19.5,
                mspt: 0.11
            }
        );
        assert_eq!(prober.begin(now), Step::Send("list"));
        observe(
            &mut prober,
            "There are 2 of a max of 20 players online:",
            now,
        );
        assert_eq!(
            observe(
                &mut prober,
                "TPS from last 1m, 5m, 15m: 20.0, 20.0, 20.0",
                now
            ),
            (true, Step::Send("mspt"))
        );
    }

    #[test]
    fn a_quarry_mspt_value_is_clamped()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        prober.begin(now);
        observe(
            &mut prober,
            "There are 0 of a max of 20 players online:",
            now,
        );
        observe(&mut prober, "TPS (5s, 1m): 1, 2 | MSPT: 99999 ms", now);
        assert_eq!(prober.sample().mspt, MAX_MSPT);
    }

    #[test]
    fn values_are_clamped_to_protocol_limits()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        prober.begin(now);
        observe(
            &mut prober,
            "There are 999999 of a max of 20 players online:",
            now,
        );
        observe(&mut prober, "TPS from last 1m, 5m, 15m: 5000.0, 1, 1", now);
        observe(&mut prober, "Server tick times (avg/min/max)", now);
        observe(&mut prober, "99999.0/1/1", now);
        assert_eq!(
            prober.sample(),
            Sample {
                players: MAX_PLAYERS,
                tps: MAX_TPS,
                mspt: MAX_MSPT
            }
        );
    }
}
