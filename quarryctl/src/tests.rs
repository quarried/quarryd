use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use proto::v1::{
    ArtifactRef, DiskSpec, InstanceNetwork, InstanceSpec, Isolation, Lease, RestartPolicy,
    RunState, SnapshotRef,
};
use sandbox::{SandboxKind, SandboxRecord};
use serde_json::Value;
use store::{ActualState, Store, UsageRow};

use crate::metrics::Scrape;
use crate::{Command, Invocation, console, execute, open_store, parse_arguments, report};

const SECRET_VALUE: &[u8] = b"hunter2-must-never-appear";
const CONSOLE_RING_BYTES: u64 = 64;

struct Fixture
{
    _dir: tempfile::TempDir,
    db: PathBuf,
    console: PathBuf,
}

fn now_ms() -> i64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn spec() -> InstanceSpec
{
    InstanceSpec {
        id: "mc-1".to_owned(),
        generation: 3,
        isolation: Isolation::Firecracker as i32,
        image: Some(ArtifactRef {
            digest: "sha256:rootfs".to_owned(),
            key: "images/paper.squashfs".to_owned(),
            signature_key: "images/paper.squashfs.minisig".to_owned(),
            size_bytes: 1024,
        }),
        kernel: Some(ArtifactRef {
            digest: "sha256:kernel".to_owned(),
            key: "kernels/vmlinux".to_owned(),
            signature_key: "kernels/vmlinux.minisig".to_owned(),
            size_bytes: 2048,
        }),
        vcpus: 2,
        memory_mib: 4096,
        disks: vec![DiskSpec {
            name: "world".to_owned(),
            size_gib: 20,
            restore_from: Some(SnapshotRef {
                manifest_key: "snapshots/world-9/manifest.json".to_owned(),
            }),
        }],
        network: Some(InstanceNetwork {
            world_id: "world-9".to_owned(),
            egress_mbit: 100,
            ports: vec![25565],
        }),
        env: HashMap::from([
            ("EULA".to_owned(), "true".to_owned()),
            ("MOTD".to_owned(), "hello".to_owned()),
        ]),
        restart_policy: RestartPolicy::OnFailure as i32,
        lease: Some(Lease {
            epoch: 4,
            ttl_ms: 60_000,
        }),
        run_state: RunState::Running as i32,
        secrets: HashMap::from([("rcon.password".to_owned(), SECRET_VALUE.to_vec())]),
        stop_deadline_seconds: 30,
        ..InstanceSpec::default()
    }
}

fn fixture() -> Fixture
{
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("quarryd.db");
    let console = dir.path().join("console.ring");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let output: Vec<u8> = (0..10)
        .flat_map(|line| format!("boot line {line}\n").into_bytes())
        .collect();
    runtime
        .block_on(sandbox::console::run_console_writer(
            &console,
            CONSOLE_RING_BYTES,
            output.as_slice(),
        ))
        .unwrap();
    let store = Store::open(&db).unwrap();
    store
        .put_desired("mc-1", 3, &spec().encode_to_vec())
        .unwrap();
    let mut second = spec();
    second.id = "mc-2".to_owned();
    second.generation = 1;
    store
        .put_desired("mc-2", 1, &second.encode_to_vec())
        .unwrap();
    store.mark_deleted_desired("mc-2").unwrap();
    let record = SandboxRecord {
        instance_id: "mc-1".to_owned(),
        generation: 3,
        kind: SandboxKind::Fake,
        unit_name: "quarry-vm@mc-1.service".to_owned(),
        api_socket: None,
        guest_socket: dir.path().join("agent.sock"),
        console_path: console.clone(),
        cgroup_path: None,
        metrics_path: None,
        pid: Some(4242),
        runtime_dir: dir.path().to_path_buf(),
    };
    store
        .update_actual(
            "mc-1",
            &ActualState {
                observed_generation: 2,
                phase: "Running".to_owned(),
                reason: "server ready".to_owned(),
                unit_name: Some("quarry-vm@mc-1.service".to_owned()),
                pid: Some(4242),
                sandbox_record: Some(serde_json::to_string(&record).unwrap()),
                network_attachment: Some(r#"{"tap":"qtap0","guest_ip":"10.20.0.5"}"#.to_owned()),
                guest_ip: Some("10.20.0.5".to_owned()),
                uid: Some(100_000),
                restart_count: 1,
                lease_epoch: 4,
                lease_expires_unix_ms: Some(now_ms() + 60_000),
                ..ActualState::default()
            },
        )
        .unwrap();
    store.begin_operation("op-1", "snapshot", "mc-1").unwrap();
    store
        .finish_operation("op-1", true, "uploaded", b"\x01\x02\x03")
        .unwrap();
    store.kv_set("channel.agent_next_seq", b"17").unwrap();
    store.kv_set("lease.mc-1", b"4").unwrap();
    store.kv_set("usage/aggregator/mc-1", b"{}").unwrap();
    store
        .insert_usage(&UsageRow {
            id: "mc-1:1700000000".to_owned(),
            instance_id: "mc-1".to_owned(),
            bucket_start_unix: 1_700_000_000,
            bucket_seconds: 60,
            cpu_usec: 1,
            memory_mib_max: 1,
            memory_mib_avg: 1,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
        })
        .unwrap();
    Fixture {
        _dir: dir,
        db,
        console,
    }
}

fn run(fixture: &Fixture, command: Command) -> String
{
    let mut out = Vec::new();
    execute(
        &Invocation {
            db: fixture.db.clone(),
            command,
        },
        &mut out,
    )
    .unwrap();
    String::from_utf8(out).unwrap()
}

fn assert_no_secret(text: &str)
{
    assert!(!text.contains(std::str::from_utf8(SECRET_VALUE).unwrap()));
}

fn arguments(words: &[&str]) -> Result<Invocation, String>
{
    let words: Vec<String> = words.iter().map(|word| word.to_string()).collect();
    parse_arguments(&words)
}

#[test]
fn arguments_are_parsed_by_hand()
{
    assert_eq!(
        arguments(&["list"]).unwrap(),
        Invocation {
            db: PathBuf::from("/var/lib/quarryd/quarryd.db"),
            command: Command::List { json: false },
        }
    );
    assert_eq!(
        arguments(&["show", "mc-1", "--json", "--db", "/tmp/x.db"]).unwrap(),
        Invocation {
            db: PathBuf::from("/tmp/x.db"),
            command: Command::Show {
                id: "mc-1".to_owned(),
                json: true
            },
        }
    );
    assert_eq!(
        arguments(&["console", "mc-1", "--tail", "100", "--follow"])
            .unwrap()
            .command,
        Command::Console {
            id: "mc-1".to_owned(),
            tail: Some(100),
            follow: true
        }
    );
    assert_eq!(
        arguments(&["diagnostics"]).unwrap().command,
        Command::Diagnostics {
            metrics: "127.0.0.1:9478".to_owned()
        }
    );
    assert_eq!(
        arguments(&["diagnostics", "--metrics", "127.0.0.1:1"])
            .unwrap()
            .command,
        Command::Diagnostics {
            metrics: "127.0.0.1:1".to_owned()
        }
    );
    assert_eq!(arguments(&["help"]).unwrap().command, Command::Help);
    assert_eq!(arguments(&["--help"]).unwrap().command, Command::Help);
}

#[test]
fn usage_errors_are_reported()
{
    for words in [
        &[][..],
        &["frobnicate"],
        &["show"],
        &["console"],
        &["list", "extra"],
        &["list", "--bogus"],
        &["console", "mc-1", "--tail", "lots"],
        &["console", "mc-1", "--tail"],
        &["--db"],
        &["list", "--follow"],
        &["diagnostics", "--json"],
        &["console", "mc-1", "--json"],
    ]
    {
        assert!(arguments(words).is_err(), "{words:?}");
    }
}

#[test]
fn help_prints_usage()
{
    let fixture = fixture();
    assert!(run(&fixture, Command::Help).starts_with("usage: quarryctl"));
}

#[test]
fn list_prints_a_table()
{
    let fixture = fixture();
    let output = run(&fixture, Command::List { json: false });
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("ID"));
    assert!(lines[0].contains("LEASE EXPIRES"));
    let first: Vec<&str> = lines[1].split_whitespace().collect();
    assert_eq!(
        &first[..6],
        &["mc-1", "Running", "2/3", "10.20.0.5", "1", "4"]
    );
    assert!(lines[1].contains("(in "));
    assert!(lines[2].starts_with("mc-2"));
    assert!(lines[2].contains("Pending (delete requested)"));
    assert!(lines[2].contains("0/1"));
}

#[test]
fn list_json_is_machine_readable()
{
    let fixture = fixture();
    let output = run(&fixture, Command::List { json: true });
    assert_no_secret(&output);
    let value: Value = serde_json::from_str(&output).unwrap();
    let instances = value.as_array().unwrap();
    assert_eq!(instances.len(), 2);
    assert_eq!(instances[0]["id"], "mc-1");
    assert_eq!(instances[0]["observed_generation"], 2);
    assert_eq!(instances[0]["spec"]["vcpus"], 2);
    assert_eq!(instances[1]["desired_deleted"], true);
}

#[test]
fn show_prints_the_row_and_decoded_spec_without_secret_values()
{
    let fixture = fixture();
    let output = run(
        &fixture,
        Command::Show {
            id: "mc-1".to_owned(),
            json: false,
        },
    );
    assert_no_secret(&output);
    for expected in [
        "observed generation: 2",
        "desired generation:  3",
        "phase:               Running",
        "reason:              server ready",
        "pid:                 4242",
        "uid:                 100000",
        "isolation:         FIRECRACKER",
        "vcpus:             2",
        "memory:            4096 MiB",
        "image:             sha256:rootfs (images/paper.squashfs, 1024 bytes)",
        "kernel:            sha256:kernel",
        "world: 20 GiB, restore from snapshots/world-9/manifest.json",
        "world id:          world-9",
        "ports:             25565",
        "restart policy:    ON_FAILURE",
        "run state:         RUNNING",
        "lease:             epoch 4, ttl 60000 ms",
        "env keys:          EULA, MOTD",
        "secret names:      rcon.password",
        "sandbox record:",
        "\"unit_name\": \"quarry-vm@mc-1.service\"",
        "network attachment:",
        "  {\n    \"guest_ip\": \"10.20.0.5\",",
    ]
    {
        assert!(
            output.contains(expected),
            "{expected:?} missing from\n{output}"
        );
    }
    assert!(!output.contains("hello"), "env values must not be printed");
}

#[test]
fn show_json_has_every_field_and_no_secret_values()
{
    let fixture = fixture();
    let output = run(
        &fixture,
        Command::Show {
            id: "mc-1".to_owned(),
            json: true,
        },
    );
    assert_no_secret(&output);
    let value: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["guest_ip"], "10.20.0.5");
    assert_eq!(value["lease_epoch"], 4);
    assert_eq!(value["restart_count"], 1);
    assert_eq!(value["spec"]["isolation"], "FIRECRACKER");
    assert_eq!(value["spec"]["disks"][0]["size_gib"], 20);
    assert_eq!(
        value["spec"]["env_keys"],
        serde_json::json!(["EULA", "MOTD"])
    );
    assert_eq!(
        value["spec"]["secret_names"],
        serde_json::json!(["rcon.password"])
    );
    assert_eq!(value["sandbox_record"]["pid"], 4242);
    assert_eq!(value["network_attachment"]["tap"], "qtap0");
    assert!(value["spec"].get("env").is_none());
    assert!(value["spec"].get("secrets").is_none());
}

#[test]
fn show_of_an_unknown_instance_fails()
{
    let fixture = fixture();
    let mut out = Vec::new();
    let error = execute(
        &Invocation {
            db: fixture.db.clone(),
            command: Command::Show {
                id: "nope".to_owned(),
                json: false,
            },
        },
        &mut out,
    )
    .unwrap_err();
    assert!(error.to_string().contains("instance nope not found"));
}

#[test]
fn console_prints_the_ring_and_its_tail()
{
    let fixture = fixture();
    let all = run(
        &fixture,
        Command::Console {
            id: "mc-1".to_owned(),
            tail: None,
            follow: false,
        },
    );
    assert_eq!(all.len(), CONSOLE_RING_BYTES as usize);
    assert!(all.ends_with("boot line 9\n"));
    let tail = run(
        &fixture,
        Command::Console {
            id: "mc-1".to_owned(),
            tail: Some(12),
            follow: false,
        },
    );
    assert_eq!(tail, "boot line 9\n");
}

#[test]
fn console_follow_prints_only_new_bytes_across_a_wrap()
{
    let fixture = fixture();
    let store = open_store(&fixture.db).unwrap();
    let path = console::console_path(&store, "mc-1").unwrap();
    assert_eq!(path, fixture.console);
    let mut out = Vec::new();
    let previous = console::print(&path, None, &mut out).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime
        .block_on(sandbox::console::run_console_writer(
            &path,
            CONSOLE_RING_BYTES,
            &b"line ten\nline eleven\n"[..],
        ))
        .unwrap();
    let mut new = Vec::new();
    let current = console::print_new(&path, &previous, &mut new).unwrap();
    assert_eq!(new, b"line ten\nline eleven\n");
    let mut idle = Vec::new();
    console::print_new(&path, &current, &mut idle).unwrap();
    assert!(idle.is_empty());
}

#[test]
fn console_of_an_instance_without_a_sandbox_fails()
{
    let fixture = fixture();
    let store = open_store(&fixture.db).unwrap();
    let error = console::console_path(&store, "mc-2").unwrap_err();
    assert!(error.to_string().contains("no sandbox record"));
}

#[test]
fn diagnostics_dump_state_and_the_metrics_error()
{
    let fixture = fixture();
    let output = run(
        &fixture,
        Command::Diagnostics {
            metrics: "127.0.0.1:1".to_owned(),
        },
    );
    assert_no_secret(&output);
    let value: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["instances"].as_array().unwrap().len(), 2);
    assert_eq!(value["instances"][0]["spec"]["memory_mib"], 4096);
    assert_eq!(value["operations"][0]["op_id"], "op-1");
    assert_eq!(value["operations"][0]["status"], "succeeded");
    assert_eq!(value["operations"][0]["payload_bytes"], 3);
    assert_eq!(value["usage_outbox_depth"], 1);
    assert_eq!(value["kv"]["channel.agent_next_seq"], "17");
    assert_eq!(value["kv"]["lease.mc-1"], "4");
    assert!(value["kv"].get("usage/aggregator/mc-1").is_none());
    assert_eq!(value["metrics"]["address"], "127.0.0.1:1");
    assert!(value["metrics"]["error"].is_string());
}

#[test]
fn diagnostics_include_a_successful_scrape()
{
    let fixture = fixture();
    let store = open_store(&fixture.db).unwrap();
    let scrape = Scrape {
        address: "127.0.0.1:9478".to_owned(),
        result: Ok("quarryd_up 1\n".to_owned()),
    };
    let mut out = Vec::new();
    report::diagnostics(&store, &fixture.db, &scrape, &mut out).unwrap();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["metrics"]["body"], "quarryd_up 1\n");
}

#[test]
fn the_store_is_opened_read_only()
{
    let fixture = fixture();
    let before = std::fs::read(&fixture.db).unwrap();
    for command in [
        Command::List { json: false },
        Command::List { json: true },
        Command::Show {
            id: "mc-1".to_owned(),
            json: false,
        },
        Command::Diagnostics {
            metrics: "127.0.0.1:1".to_owned(),
        },
    ]
    {
        run(&fixture, command);
    }
    let store = open_store(&fixture.db).unwrap();
    assert!(store.kv_set("channel.agent_next_seq", b"99").is_err());
    assert!(store.put_desired("mc-3", 1, b"").is_err());
    assert_eq!(std::fs::read(&fixture.db).unwrap(), before);
}

#[test]
fn non_test_code_only_opens_the_store_read_only()
{
    let sources = [
        include_str!("main.rs"),
        include_str!("report.rs"),
        include_str!("console.rs"),
        include_str!("metrics.rs"),
    ];
    let joined = sources.concat();
    assert_eq!(joined.matches("Store::open_read_only(").count(), 1);
    assert_eq!(joined.matches("Store::open").count(), 1);
    assert!(!joined.contains("open_in_memory"));
    for writer in [
        "kv_set",
        "put_desired",
        "update_actual",
        "begin_operation",
        "insert_usage",
    ]
    {
        assert!(!joined.contains(writer), "{writer} in non-test code");
    }
}

#[test]
fn times_are_rendered_in_utc()
{
    assert_eq!(report::utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(report::utc(1_700_000_000), "2023-11-14T22:13:20Z");
    assert_eq!(report::utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(
        report::lease_expiry(Some(61_000), 1_000),
        "1970-01-01T00:01:01Z (in 60s)"
    );
    assert_eq!(
        report::lease_expiry(Some(1_000), 11_000),
        "1970-01-01T00:00:01Z (expired 10s ago)"
    );
    assert_eq!(report::lease_expiry(None, 0), "-");
}
