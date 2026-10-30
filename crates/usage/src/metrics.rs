use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::CgroupStats;

const DURATION_BUCKETS_SECONDS: [f64; 13] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

#[derive(Debug, Clone, Default)]
struct Histogram
{
    bucket_counts: [u64; DURATION_BUCKETS_SECONDS.len()],
    count: u64,
    sum_seconds: f64,
}

impl Histogram
{
    fn observe(&mut self, duration: Duration)
    {
        let seconds = duration.as_secs_f64();
        for (bound, count) in DURATION_BUCKETS_SECONDS
            .iter()
            .zip(self.bucket_counts.iter_mut())
        {
            if seconds <= *bound
            {
                *count += 1;
            }
        }
        self.count += 1;
        self.sum_seconds += seconds;
    }
}

#[derive(Debug, Clone, Copy)]
struct InstanceUsage
{
    stats: CgroupStats,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestHealth
{
    tps: f64,
    mspt: f64,
    players: u32,
}

type InstanceValue = fn(&InstanceUsage) -> String;
type GuestValue = fn(&GuestHealth) -> String;

#[derive(Debug, Default)]
struct MetricsState
{
    reconcile_duration: Histogram,
    reconcile_errors: u64,
    boot_phase_duration: BTreeMap<String, Histogram>,
    outbox_depth: u64,
    lease_renew_latency: Histogram,
    artifact_cache_hits: u64,
    artifact_cache_misses: u64,
    instance_usage: BTreeMap<String, InstanceUsage>,
    guest_health: BTreeMap<String, GuestHealth>,
    pool_used_percent: Option<f64>,
    public_bound: u64,
    responder_connections: BTreeMap<String, u64>,
    wake_requests: u64,
}

pub struct Metrics
{
    node_id: String,
    state: Mutex<MetricsState>,
}

impl Metrics
{
    pub fn new(node_id: &str) -> Metrics
    {
        Metrics {
            node_id: node_id.to_string(),
            state: Mutex::new(MetricsState::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, MetricsState>
    {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn observe_reconcile(&self, duration: Duration, ok: bool)
    {
        let mut state = self.state();
        state.reconcile_duration.observe(duration);
        if !ok
        {
            state.reconcile_errors += 1;
        }
    }

    pub fn observe_boot_phase(&self, phase: &str, duration: Duration)
    {
        self.state()
            .boot_phase_duration
            .entry(phase.to_string())
            .or_default()
            .observe(duration);
    }

    pub fn set_outbox_depth(&self, depth: u64)
    {
        self.state().outbox_depth = depth;
    }

    pub fn observe_lease_renew_latency(&self, duration: Duration)
    {
        self.state().lease_renew_latency.observe(duration);
    }

    pub fn record_artifact_cache(&self, hit: bool)
    {
        let mut state = self.state();
        if hit
        {
            state.artifact_cache_hits += 1;
        }
        else
        {
            state.artifact_cache_misses += 1;
        }
    }

    pub fn set_instance_usage(&self, instance_id: &str, stats: &CgroupStats, net: (u64, u64))
    {
        self.state().instance_usage.insert(
            instance_id.to_string(),
            InstanceUsage {
                stats: *stats,
                net_rx_bytes: net.0,
                net_tx_bytes: net.1,
            },
        );
    }

    pub fn set_guest_health(&self, instance_id: &str, tps: f64, mspt: f64, players: u32)
    {
        self.state()
            .guest_health
            .insert(instance_id.to_string(), GuestHealth { tps, mspt, players });
    }

    pub fn set_public_network(
        &self,
        bound: u64,
        connections: BTreeMap<String, u64>,
        wake_requests: u64,
    )
    {
        let mut state = self.state();
        state.public_bound = bound;
        state.responder_connections = connections;
        state.wake_requests = wake_requests;
    }

    pub fn set_pool_used_percent(&self, percent: f64)
    {
        self.state().pool_used_percent = Some(percent);
    }

    pub fn remove_instance(&self, instance_id: &str)
    {
        let mut state = self.state();
        state.instance_usage.remove(instance_id);
        state.guest_health.remove(instance_id);
    }

    pub fn render(&self) -> String
    {
        let state = self.state();
        let node = escape_label_value(&self.node_id);
        let mut out = String::new();

        render_histogram(
            &mut out,
            "quarryd_reconcile_duration_seconds",
            "Duration of reconcile passes.",
            &[("node_id", &node)],
            &state.reconcile_duration,
        );
        header(
            &mut out,
            "quarryd_reconcile_errors_total",
            "Reconcile passes that failed.",
            "counter",
        );
        sample(
            &mut out,
            "quarryd_reconcile_errors_total",
            &[("node_id", &node)],
            &state.reconcile_errors.to_string(),
        );

        header(
            &mut out,
            "quarryd_boot_phase_duration_seconds",
            "Instance boot time per phase.",
            "histogram",
        );
        for (phase, histogram) in &state.boot_phase_duration
        {
            let phase = escape_label_value(phase);
            histogram_samples(
                &mut out,
                "quarryd_boot_phase_duration_seconds",
                &[("node_id", &node), ("phase", &phase)],
                histogram,
            );
        }

        header(
            &mut out,
            "quarryd_outbox_depth",
            "Usage records waiting for an ack.",
            "gauge",
        );
        sample(
            &mut out,
            "quarryd_outbox_depth",
            &[("node_id", &node)],
            &state.outbox_depth.to_string(),
        );

        render_histogram(
            &mut out,
            "quarryd_lease_renew_latency_seconds",
            "Latency of lease renewals.",
            &[("node_id", &node)],
            &state.lease_renew_latency,
        );

        let hits = state.artifact_cache_hits;
        let misses = state.artifact_cache_misses;
        header(
            &mut out,
            "quarryd_artifact_cache_hits_total",
            "Artifact cache hits.",
            "counter",
        );
        sample(
            &mut out,
            "quarryd_artifact_cache_hits_total",
            &[("node_id", &node)],
            &hits.to_string(),
        );
        header(
            &mut out,
            "quarryd_artifact_cache_misses_total",
            "Artifact cache misses.",
            "counter",
        );
        sample(
            &mut out,
            "quarryd_artifact_cache_misses_total",
            &[("node_id", &node)],
            &misses.to_string(),
        );
        let lookups = hits.saturating_add(misses);
        let hit_ratio = if lookups == 0
        {
            0.0
        }
        else
        {
            hits as f64 / lookups as f64
        };
        header(
            &mut out,
            "quarryd_artifact_cache_hit_ratio",
            "Fraction of artifact lookups served from the cache.",
            "gauge",
        );
        sample(
            &mut out,
            "quarryd_artifact_cache_hit_ratio",
            &[("node_id", &node)],
            &format_float(hit_ratio),
        );

        for (name, help, kind, value) in [
            (
                "quarryd_public_ipv4_bound",
                "Public IPv4 addresses bound to instances.",
                "gauge",
                state.public_bound,
            ),
            (
                "quarryd_wake_requests_total",
                "Wake requests emitted by the sleep responder.",
                "counter",
                state.wake_requests,
            ),
        ]
        {
            header(&mut out, name, help, kind);
            sample(&mut out, name, &[("node_id", &node)], &value.to_string());
        }
        header(
            &mut out,
            "quarryd_responder_connections_total",
            "Sleep responder connections by outcome.",
            "counter",
        );
        for (outcome, count) in &state.responder_connections
        {
            sample(
                &mut out,
                "quarryd_responder_connections_total",
                &[
                    ("node_id", &node),
                    ("outcome", &escape_label_value(outcome)),
                ],
                &count.to_string(),
            );
        }

        render_instance_usage(&mut out, &node, &state.instance_usage);
        render_guest_health(&mut out, &node, &state.guest_health);

        if let Some(percent) = state.pool_used_percent
        {
            header(
                &mut out,
                "quarryd_pool_used_percent",
                "Thin pool data usage in percent.",
                "gauge",
            );
            sample(
                &mut out,
                "quarryd_pool_used_percent",
                &[("node_id", &node)],
                &format_float(percent),
            );
        }
        out
    }
}

fn render_instance_usage(out: &mut String, node: &str, usage: &BTreeMap<String, InstanceUsage>)
{
    let families: [(&str, &str, &str, InstanceValue); 6] = [
        (
            "quarryd_instance_cpu_usage_seconds_total",
            "CPU time used by the instance cgroup.",
            "counter",
            |usage| format_float(usage.stats.cpu_usage_usec as f64 / 1_000_000.0),
        ),
        (
            "quarryd_instance_memory_bytes",
            "Current memory of the instance cgroup.",
            "gauge",
            |usage| usage.stats.memory_current_bytes.to_string(),
        ),
        (
            "quarryd_instance_disk_read_bytes_total",
            "Bytes read by the instance cgroup.",
            "counter",
            |usage| usage.stats.io_read_bytes.to_string(),
        ),
        (
            "quarryd_instance_disk_write_bytes_total",
            "Bytes written by the instance cgroup.",
            "counter",
            |usage| usage.stats.io_write_bytes.to_string(),
        ),
        (
            "quarryd_instance_network_receive_bytes_total",
            "Bytes received by the instance.",
            "counter",
            |usage| usage.net_rx_bytes.to_string(),
        ),
        (
            "quarryd_instance_network_transmit_bytes_total",
            "Bytes transmitted by the instance.",
            "counter",
            |usage| usage.net_tx_bytes.to_string(),
        ),
    ];
    for (name, help, kind, value) in families
    {
        header(out, name, help, kind);
        for (instance_id, instance) in usage
        {
            let instance_id = escape_label_value(instance_id);
            sample(
                out,
                name,
                &[("node_id", node), ("instance_id", &instance_id)],
                &value(instance),
            );
        }
    }
}

fn render_guest_health(out: &mut String, node: &str, health: &BTreeMap<String, GuestHealth>)
{
    let families: [(&str, &str, GuestValue); 3] = [
        (
            "quarryd_guest_tps",
            "Server ticks per second reported by the guest.",
            |health| format_float(health.tps),
        ),
        (
            "quarryd_guest_mspt",
            "Milliseconds per tick reported by the guest.",
            |health| format_float(health.mspt),
        ),
        (
            "quarryd_guest_players",
            "Players online reported by the guest.",
            |health| health.players.to_string(),
        ),
    ];
    for (name, help, value) in families
    {
        header(out, name, help, "gauge");
        for (instance_id, instance) in health
        {
            let instance_id = escape_label_value(instance_id);
            sample(
                out,
                name,
                &[("node_id", node), ("instance_id", &instance_id)],
                &value(instance),
            );
        }
    }
}

fn render_histogram(
    out: &mut String,
    name: &str,
    help: &str,
    labels: &[(&str, &str)],
    histogram: &Histogram,
)
{
    header(out, name, help, "histogram");
    histogram_samples(out, name, labels, histogram);
}

fn histogram_samples(out: &mut String, name: &str, labels: &[(&str, &str)], histogram: &Histogram)
{
    let bucket_name = format!("{name}_bucket");
    for (bound, count) in DURATION_BUCKETS_SECONDS
        .iter()
        .zip(histogram.bucket_counts.iter())
    {
        let bound = format_float(*bound);
        let mut bucket_labels = labels.to_vec();
        bucket_labels.push(("le", &bound));
        sample(out, &bucket_name, &bucket_labels, &count.to_string());
    }
    let mut infinite_labels = labels.to_vec();
    infinite_labels.push(("le", "+Inf"));
    sample(
        out,
        &bucket_name,
        &infinite_labels,
        &histogram.count.to_string(),
    );
    sample(
        out,
        &format!("{name}_sum"),
        labels,
        &format_float(histogram.sum_seconds),
    );
    sample(
        out,
        &format!("{name}_count"),
        labels,
        &histogram.count.to_string(),
    );
}

fn header(out: &mut String, name: &str, help: &str, kind: &str)
{
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: &str)
{
    out.push_str(name);
    if !labels.is_empty()
    {
        out.push('{');
        for (index, (label, label_value)) in labels.iter().enumerate()
        {
            if index > 0
            {
                out.push(',');
            }
            let _ = write!(out, "{label}=\"{label_value}\"");
        }
        out.push('}');
    }
    let _ = writeln!(out, " {value}");
}

fn escape_label_value(value: &str) -> String
{
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars()
    {
        match character
        {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn format_float(value: f64) -> String
{
    if value.is_nan()
    {
        "NaN".to_string()
    }
    else if value == f64::INFINITY
    {
        "+Inf".to_string()
    }
    else if value == f64::NEG_INFINITY
    {
        "-Inf".to_string()
    }
    else
    {
        value.to_string()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn lines(text: &str) -> Vec<&str>
    {
        text.lines().collect()
    }

    #[test]
    fn renders_public_network_counters()
    {
        let metrics = Metrics::new("node-a");
        metrics.set_public_network(
            2,
            BTreeMap::from([("status".to_owned(), 7), ("login".to_owned(), 3)]),
            1,
        );
        let text = metrics.render();
        assert!(text.contains(r#"quarryd_public_ipv4_bound{node_id="node-a"} 2"#));
        assert!(text.contains(
            r#"quarryd_responder_connections_total{node_id="node-a",outcome="status"} 7"#
        ));
        assert!(text.contains(r#"quarryd_wake_requests_total{node_id="node-a"} 1"#));
    }

    #[test]
    fn renders_histograms_with_cumulative_buckets()
    {
        let metrics = Metrics::new("node-a");
        metrics.observe_reconcile(Duration::from_millis(3), true);
        metrics.observe_reconcile(Duration::from_millis(40), false);
        metrics.observe_reconcile(Duration::from_secs(120), true);
        let text = metrics.render();
        let lines = lines(&text);
        for expected in [
            "# HELP quarryd_reconcile_duration_seconds Duration of reconcile passes.",
            "# TYPE quarryd_reconcile_duration_seconds histogram",
            r#"quarryd_reconcile_duration_seconds_bucket{node_id="node-a",le="0.005"} 1"#,
            r#"quarryd_reconcile_duration_seconds_bucket{node_id="node-a",le="0.025"} 1"#,
            r#"quarryd_reconcile_duration_seconds_bucket{node_id="node-a",le="0.05"} 2"#,
            r#"quarryd_reconcile_duration_seconds_bucket{node_id="node-a",le="60"} 2"#,
            r#"quarryd_reconcile_duration_seconds_bucket{node_id="node-a",le="+Inf"} 3"#,
            r#"quarryd_reconcile_duration_seconds_sum{node_id="node-a"} 120.043"#,
            r#"quarryd_reconcile_duration_seconds_count{node_id="node-a"} 3"#,
            "# TYPE quarryd_reconcile_errors_total counter",
            r#"quarryd_reconcile_errors_total{node_id="node-a"} 1"#,
        ]
        {
            assert!(lines.contains(&expected), "missing {expected:?} in\n{text}");
        }
    }

    #[test]
    fn renders_node_gauges_and_cache_ratio()
    {
        let metrics = Metrics::new("node-a");
        metrics.set_outbox_depth(17);
        metrics.observe_lease_renew_latency(Duration::from_millis(80));
        metrics.observe_boot_phase("network", Duration::from_millis(20));
        metrics.observe_boot_phase("image", Duration::from_secs(3));
        metrics.record_artifact_cache(true);
        metrics.record_artifact_cache(true);
        metrics.record_artifact_cache(true);
        metrics.record_artifact_cache(false);
        metrics.set_pool_used_percent(81.5);
        let text = metrics.render();
        let lines = lines(&text);
        for expected in [
            r#"quarryd_outbox_depth{node_id="node-a"} 17"#,
            r#"quarryd_lease_renew_latency_seconds_bucket{node_id="node-a",le="0.1"} 1"#,
            r#"quarryd_lease_renew_latency_seconds_count{node_id="node-a"} 1"#,
            r#"quarryd_boot_phase_duration_seconds_bucket{node_id="node-a",phase="image",le="5"} 1"#,
            r#"quarryd_boot_phase_duration_seconds_bucket{node_id="node-a",phase="image",le="2.5"} 0"#,
            r#"quarryd_boot_phase_duration_seconds_count{node_id="node-a",phase="network"} 1"#,
            r#"quarryd_artifact_cache_hits_total{node_id="node-a"} 3"#,
            r#"quarryd_artifact_cache_misses_total{node_id="node-a"} 1"#,
            r#"quarryd_artifact_cache_hit_ratio{node_id="node-a"} 0.75"#,
            r#"quarryd_pool_used_percent{node_id="node-a"} 81.5"#,
        ]
        {
            assert!(lines.contains(&expected), "missing {expected:?} in\n{text}");
        }
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("# TYPE quarryd_boot_phase_duration_seconds "))
                .count(),
            1
        );
    }

    #[test]
    fn renders_instance_series_and_removes_them()
    {
        let metrics = Metrics::new("node-a");
        let stats = CgroupStats {
            cpu_usage_usec: 2_500_000,
            memory_current_bytes: 1_073_741_824,
            io_read_bytes: 4096,
            io_write_bytes: 8192,
        };
        metrics.set_instance_usage("srv-1", &stats, (1000, 2000));
        metrics.set_guest_health("srv-1", 19.95, 12.5, 7);
        let text = metrics.render();
        let lines = lines(&text);
        for expected in [
            r#"quarryd_instance_cpu_usage_seconds_total{node_id="node-a",instance_id="srv-1"} 2.5"#,
            r#"quarryd_instance_memory_bytes{node_id="node-a",instance_id="srv-1"} 1073741824"#,
            r#"quarryd_instance_disk_read_bytes_total{node_id="node-a",instance_id="srv-1"} 4096"#,
            r#"quarryd_instance_disk_write_bytes_total{node_id="node-a",instance_id="srv-1"} 8192"#,
            r#"quarryd_instance_network_receive_bytes_total{node_id="node-a",instance_id="srv-1"} 1000"#,
            r#"quarryd_instance_network_transmit_bytes_total{node_id="node-a",instance_id="srv-1"} 2000"#,
            r#"quarryd_guest_tps{node_id="node-a",instance_id="srv-1"} 19.95"#,
            r#"quarryd_guest_mspt{node_id="node-a",instance_id="srv-1"} 12.5"#,
            r#"quarryd_guest_players{node_id="node-a",instance_id="srv-1"} 7"#,
        ]
        {
            assert!(lines.contains(&expected), "missing {expected:?} in\n{text}");
        }

        metrics.remove_instance("srv-1");
        assert!(!metrics.render().contains("srv-1"));
    }

    #[test]
    fn every_sample_carries_node_id_and_is_well_formed()
    {
        let metrics = Metrics::new("node-a");
        metrics.set_instance_usage("srv-1", &CgroupStats::default(), (0, 0));
        metrics.set_guest_health("srv-1", f64::NAN, f64::INFINITY, 0);
        metrics.observe_boot_phase("guest", Duration::from_millis(1));
        metrics.set_pool_used_percent(10.0);
        let text = metrics.render();
        assert!(text.ends_with('\n'));
        let mut declared = Vec::new();
        for line in text.lines()
        {
            if let Some(rest) = line.strip_prefix("# TYPE ")
            {
                let mut parts = rest.split(' ');
                let name = parts.next().unwrap();
                let kind = parts.next().unwrap();
                assert!(["counter", "gauge", "histogram"].contains(&kind));
                declared.push(name.to_string());
                continue;
            }
            if line.starts_with('#')
            {
                continue;
            }
            let (series, value) = line.rsplit_once(' ').unwrap();
            assert!(
                value.parse::<f64>().is_ok() || ["NaN", "+Inf", "-Inf"].contains(&value),
                "bad value in {line:?}"
            );
            assert!(
                series.contains(r#"{node_id="node-a""#),
                "missing node_id in {line:?}"
            );
            let name = &series[..series.find('{').unwrap()];
            assert!(
                declared.iter().any(|family| name == family
                    || name
                        .strip_prefix(family.as_str())
                        .is_some_and(|suffix| ["_bucket", "_sum", "_count"].contains(&suffix))),
                "sample {name} has no TYPE line before it"
            );
        }
        assert!(text.contains(r#"quarryd_guest_tps{node_id="node-a",instance_id="srv-1"} NaN"#));
        assert!(text.contains(r#"quarryd_guest_mspt{node_id="node-a",instance_id="srv-1"} +Inf"#));
    }

    #[test]
    fn label_values_are_escaped()
    {
        let metrics = Metrics::new("node \"a\"\\\n");
        let text = metrics.render();
        assert!(text.contains(r#"quarryd_outbox_depth{node_id="node \"a\"\\\n"} 0"#));
    }

    #[test]
    fn pool_gauge_is_absent_until_set()
    {
        let metrics = Metrics::new("node-a");
        assert!(!metrics.render().contains("quarryd_pool_used_percent"));
    }

    #[test]
    fn metrics_are_shareable_across_threads()
    {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Metrics>();
    }
}
