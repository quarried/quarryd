use guest_proto::PlayerInfo;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
            Probe::List => "list uuids",
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
    profiles: BTreeMap<String, String>,
    operators: BTreeSet<String>,
    online: BTreeMap<String, (String, u64)>,
    tick_samples: VecDeque<f64>,
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
            profiles: BTreeMap::new(),
            operators: BTreeSet::new(),
            online: BTreeMap::new(),
            tick_samples: VecDeque::new(),
        }
    }

    pub fn sample(&self) -> Sample
    {
        self.sample
    }

    pub fn refresh_profiles(&mut self, directory: &std::path::Path)
    {
        for (name, operators) in [("usercache.json", false), ("ops.json", true)]
        {
            let path = directory.join(name);
            let Ok(metadata) = std::fs::metadata(&path)
            else
            {
                continue;
            };
            if metadata.len() > 1024 * 1024
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(path)
            else
            {
                continue;
            };
            let Ok(serde_json::Value::Array(entries)) = serde_json::from_slice(&bytes)
            else
            {
                continue;
            };
            if operators
            {
                self.operators.clear();
            }
            for entry in entries
            {
                let (Some(name), Some(uuid)) = (
                    entry.get("name").and_then(|v| v.as_str()),
                    entry.get("uuid").and_then(|v| v.as_str()),
                )
                else
                {
                    continue;
                };
                if valid_name(name) && valid_uuid(uuid)
                {
                    self.profiles
                        .insert(name.to_owned(), uuid.to_ascii_lowercase());
                    if operators
                        && entry
                            .get("level")
                            .and_then(|value| value.as_u64())
                            .is_none_or(|level| level > 0)
                    {
                        self.operators.insert(uuid.to_ascii_lowercase());
                    }
                }
            }
        }
    }

    pub fn player_list(&self) -> Vec<PlayerInfo>
    {
        self.online
            .iter()
            .filter_map(|(name, (uuid, since))| {
                let uuid = if uuid.is_empty()
                {
                    self.profiles.get(name)?
                }
                else
                {
                    uuid
                };
                Some(PlayerInfo {
                    uuid: uuid.clone(),
                    name: name.clone(),
                    online_since_unix_ms: *since,
                    operator: self.operators.contains(uuid),
                })
            })
            .take(500)
            .collect()
    }

    pub fn percentile(&self, percent: usize) -> f64
    {
        let mut samples: Vec<f64> = self.tick_samples.iter().copied().collect();
        samples.sort_by(f64::total_cmp);
        if samples.is_empty()
        {
            return 0.0;
        }
        samples[(samples.len() * percent)
            .div_ceil(100)
            .saturating_sub(1)
            .min(samples.len() - 1)]
    }

    fn tick_sample(&mut self, value: f64)
    {
        if value.is_finite() && (0.0..=MAX_MSPT).contains(&value)
        {
            self.tick_samples.push_back(value);
            if self.tick_samples.len() > 60
            {
                self.tick_samples.pop_front();
            }
        }
    }

    fn observe_players(&mut self, line: &str)
    {
        let plain = output::without_color_codes(line);
        let line = plain.as_str();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        if let Some((_, tail)) = line.split_once("UUID of player ")
            && let Some((name, uuid)) = tail.split_once(" is ")
            && valid_name(name)
            && valid_uuid(uuid.trim())
        {
            self.profiles
                .insert(name.to_owned(), uuid.trim().to_ascii_lowercase());
        }
        if let Some((_, names)) = line.split_once("players online:")
        {
            let mut listed = BTreeSet::new();
            for entry in names.split(',').take(500)
            {
                let entry = entry.trim();
                let (name, uuid) = entry
                    .split_once(" (")
                    .map(|(name, uuid)| (name, uuid.trim_end_matches(')')))
                    .unwrap_or((entry, ""));
                if !valid_name(name)
                {
                    continue;
                }
                let uuid = if valid_uuid(uuid)
                {
                    uuid.to_ascii_lowercase()
                }
                else
                {
                    self.profiles.get(name).cloned().unwrap_or_default()
                };
                if !uuid.is_empty()
                {
                    self.profiles.insert(name.to_owned(), uuid.clone());
                }
                self.online
                    .entry(name.to_owned())
                    .and_modify(|(known, _)| {
                        if !uuid.is_empty()
                        {
                            *known = uuid.clone();
                        }
                    })
                    .or_insert((uuid, now));
                listed.insert(name.to_owned());
            }
            self.online.retain(|name, _| listed.contains(name));
        }
        else if output::players(line) == Some(0)
        {
            self.online.clear();
        }
        for (suffix, joined) in [(" joined the game", true), (" left the game", false)]
        {
            if let Some((before, _)) = line.split_once(suffix)
                && let Some(name) = before.split_whitespace().last()
                && valid_name(name)
            {
                if joined
                {
                    self.online
                        .entry(name.to_owned())
                        .or_insert((self.profiles.get(name).cloned().unwrap_or_default(), now));
                }
                else
                {
                    self.online.remove(name);
                }
            }
        }
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
        self.observe_players(line);
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
                        self.tick_sample(output::last_tick(line).unwrap_or(self.sample.mspt));
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
                        self.tick_sample(self.sample.mspt);
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

fn valid_name(name: &str) -> bool
{
    !name.is_empty()
        && name.len() <= 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_uuid(uuid: &str) -> bool
{
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index)
            {
                byte == b'-'
            }
            else
            {
                byte.is_ascii_hexdigit()
            }
        })
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
    fn identities_operator_status_and_online_times_come_from_server_evidence()
    {
        let mut prober = Prober::new();
        let dir = tempfile::tempdir().unwrap();
        let uuid = "069a79f4-44e9-4726-a5be-fca90e38aaf5";
        std::fs::write(
            dir.path().join("ops.json"),
            format!(r#"[{{"name":"Notch","uuid":"{uuid}","level":4}}]"#),
        )
        .unwrap();
        prober.refresh_profiles(dir.path());
        prober.observe_players(&format!(
            "There are 2 of a max of 20 players online: Notch ({uuid}), Unknown"
        ));
        let first = prober.player_list();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].uuid, uuid);
        assert!(first[0].operator);
        assert!(first[0].online_since_unix_ms > 0);
        prober.observe_players(&format!(
            "There are 1 of a max of 20 players online: Notch ({uuid})"
        ));
        assert_eq!(
            prober.player_list()[0].online_since_unix_ms,
            first[0].online_since_unix_ms
        );
        prober.observe_players("[INFO]: Notch left the game");
        assert!(prober.player_list().is_empty());
    }

    #[test]
    fn tick_percentiles_use_bounded_recent_observations()
    {
        let mut prober = Prober::new();
        for value in 1..=100
        {
            prober.tick_sample(value as f64);
        }
        assert_eq!(prober.tick_samples.len(), 60);
        assert_eq!(prober.percentile(50), 70.0);
        assert_eq!(prober.percentile(99), 100.0);
        prober.tick_sample(f64::NAN);
        assert_eq!(prober.percentile(99), 100.0);
    }

    #[test]
    fn a_round_probes_list_tps_and_mspt_in_order()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        assert_eq!(prober.begin(now), Step::Send("list uuids"));
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
        assert_eq!(prober.begin(now), Step::Send("list uuids"));
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
        assert_eq!(prober.begin(now), Step::Send("list uuids"));
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
        assert_eq!(prober.begin(start), Step::Send("list uuids"));
        assert_eq!(prober.expire(start + Duration::from_secs(1)), Step::Wait);
        let later = start + PROBE_TIMEOUT;
        assert_eq!(prober.expire(later), Step::Send("tps"));
        assert_eq!(prober.expire(later + PROBE_TIMEOUT), Step::Send("mspt"));
        assert_eq!(prober.expire(later + PROBE_TIMEOUT * 2), Step::Complete);
        assert_eq!(prober.sample(), Sample::default());
        assert_eq!(
            prober.begin(later + PROBE_TIMEOUT * 3),
            Step::Send("list uuids")
        );
    }

    #[test]
    fn a_quarry_tps_reply_carries_mspt_and_skips_the_mspt_probe()
    {
        let now = Instant::now();
        let mut prober = Prober::new();
        assert_eq!(prober.begin(now), Step::Send("list uuids"));
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
        assert_eq!(prober.begin(now), Step::Send("list uuids"));
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
