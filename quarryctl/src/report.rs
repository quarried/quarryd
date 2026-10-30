use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use prost::Message;
use proto::v1::{ArtifactRef, InstanceSpec, Isolation, RestartPolicy, RunState};
use serde_json::{Map, Value, json};
use store::{InstanceRow, OperationRow, Store};

use crate::metrics::Scrape;

const KV_PREFIXES: [&str; 2] = ["channel.", "lease"];

pub fn list(store: &Store, json: bool, out: &mut impl Write) -> anyhow::Result<()>
{
    let rows = store.list_instances()?;
    if json
    {
        let instances: Vec<Value> = rows.iter().map(instance_json).collect();
        return write_json(&Value::Array(instances), out);
    }
    let now = now_unix_ms();
    let header = [
        "ID",
        "PHASE",
        "GEN (OBSERVED/DESIRED)",
        "GUEST IP",
        "RESTARTS",
        "LEASE EPOCH",
        "LEASE EXPIRES",
    ]
    .map(str::to_owned);
    let mut table = vec![header];
    for row in &rows
    {
        let phase = if row.desired_deleted
        {
            format!("{} (delete requested)", row.phase)
        }
        else
        {
            row.phase.clone()
        };
        table.push([
            row.id.clone(),
            phase,
            format!("{}/{}", row.observed_generation, row.generation),
            row.guest_ip.clone().unwrap_or_else(|| "-".to_owned()),
            row.restart_count.to_string(),
            row.lease_epoch.to_string(),
            lease_expiry(row.lease_expires_unix_ms, now),
        ]);
    }
    let widths: Vec<usize> = (0..table[0].len())
        .map(|column| {
            table
                .iter()
                .map(|line| line[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for line in &table
    {
        let cells: Vec<String> = line
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        writeln!(out, "{}", cells.join("  ").trim_end())?;
    }
    Ok(())
}

pub fn show(store: &Store, id: &str, json: bool, out: &mut impl Write) -> anyhow::Result<()>
{
    let row = store
        .get_instance(id)?
        .ok_or_else(|| anyhow!("instance {id} not found"))?;
    if json
    {
        return write_json(&instance_json(&row), out);
    }
    let now = now_unix_ms();
    let optional = |value: Option<String>| value.unwrap_or_else(|| "-".to_owned());
    writeln!(out, "id:                  {}", row.id)?;
    writeln!(out, "desired generation:  {}", row.generation)?;
    writeln!(out, "observed generation: {}", row.observed_generation)?;
    writeln!(out, "phase:               {}", row.phase)?;
    writeln!(out, "reason:              {}", row.reason)?;
    writeln!(out, "delete requested:    {}", yes_no(row.desired_deleted))?;
    writeln!(
        out,
        "unit:                {}",
        optional(row.unit_name.clone())
    )?;
    writeln!(
        out,
        "api socket:          {}",
        optional(row.api_socket.clone())
    )?;
    writeln!(
        out,
        "pid:                 {}",
        optional(row.pid.map(|pid| pid.to_string()))
    )?;
    writeln!(
        out,
        "guest ip:            {}",
        optional(row.guest_ip.clone())
    )?;
    writeln!(
        out,
        "uid:                 {}",
        optional(row.uid.map(|uid| uid.to_string()))
    )?;
    writeln!(out, "restart count:       {}", row.restart_count)?;
    writeln!(
        out,
        "last exit:           {}",
        optional(row.last_exit_unix.map(utc))
    )?;
    writeln!(out, "lease epoch:         {}", row.lease_epoch)?;
    writeln!(
        out,
        "lease expires:       {}",
        lease_expiry(row.lease_expires_unix_ms, now)
    )?;
    writeln!(out, "updated:             {}", utc(row.updated_at_unix))?;
    writeln!(out, "spec:")?;
    match InstanceSpec::decode(row.spec.as_slice())
    {
        Ok(spec) => write_spec(&spec, out)?,
        Err(error) => writeln!(out, "  cannot decode the stored spec: {error}")?,
    }
    write_embedded("sandbox record", row.sandbox_record.as_deref(), out)?;
    write_embedded("network attachment", row.network_attachment.as_deref(), out)?;
    Ok(())
}

pub fn diagnostics(
    store: &Store,
    db: &Path,
    scrape: &Scrape,
    out: &mut impl Write,
) -> anyhow::Result<()>
{
    let instances: Vec<Value> = store.list_instances()?.iter().map(instance_json).collect();
    let operations: Vec<Value> = store
        .list_operations(None)?
        .iter()
        .map(operation_json)
        .collect();
    let mut kv = Map::new();
    for prefix in KV_PREFIXES
    {
        for (key, value) in store.kv_list_prefix(prefix)?
        {
            kv.insert(key, kv_value(&value));
        }
    }
    let metrics = match &scrape.result
    {
        Ok(body) => json!({ "address": scrape.address, "body": body }),
        Err(error) => json!({ "address": scrape.address, "error": error }),
    };
    let report = json!({
        "generated_at_unix_ms": now_unix_ms(),
        "database": db.display().to_string(),
        "instances": instances,
        "operations": operations,
        "usage_outbox_depth": store.usage_depth()?,
        "kv": kv,
        "metrics": metrics,
    });
    write_json(&report, out)
}

fn write_json(value: &Value, out: &mut impl Write) -> anyhow::Result<()>
{
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

fn write_spec(spec: &InstanceSpec, out: &mut impl Write) -> anyhow::Result<()>
{
    let network = spec.network.clone().unwrap_or_default();
    let lease = spec.lease.unwrap_or_default();
    writeln!(
        out,
        "  isolation:         {}",
        isolation_name(spec.isolation)
    )?;
    writeln!(out, "  vcpus:             {}", spec.vcpus)?;
    writeln!(out, "  memory:            {} MiB", spec.memory_mib)?;
    writeln!(
        out,
        "  image:             {}",
        artifact_text(spec.image.as_ref())
    )?;
    writeln!(
        out,
        "  kernel:            {}",
        artifact_text(spec.kernel.as_ref())
    )?;
    if spec.disks.is_empty()
    {
        writeln!(out, "  disks:             -")?;
    }
    else
    {
        writeln!(out, "  disks:")?;
        for disk in &spec.disks
        {
            let restore = disk
                .restore_from
                .as_ref()
                .map(|snapshot| format!(", restore from {}", snapshot.manifest_key))
                .unwrap_or_default();
            writeln!(out, "    {}: {} GiB{restore}", disk.name, disk.size_gib)?;
        }
    }
    writeln!(out, "  world id:          {}", network.world_id)?;
    writeln!(out, "  egress limit:      {} Mbit/s", network.egress_mbit)?;
    writeln!(out, "  ports:             {}", join(&network.ports))?;
    writeln!(
        out,
        "  restart policy:    {}",
        restart_policy_name(spec.restart_policy)
    )?;
    writeln!(
        out,
        "  run state:         {}",
        run_state_name(spec.run_state)
    )?;
    writeln!(out, "  stop deadline:     {} s", spec.stop_deadline_seconds)?;
    writeln!(
        out,
        "  lease:             epoch {}, ttl {} ms",
        lease.epoch, lease.ttl_ms
    )?;
    writeln!(out, "  cpu pinning:       {}", yes_no(spec.cpu_pinning))?;
    writeln!(
        out,
        "  idle reclaim:      {} after {} min",
        yes_no(spec.balloon_idle_reclaim),
        spec.idle_reclaim_minutes
    )?;
    writeln!(
        out,
        "  env keys:          {}",
        join(&sorted_keys(spec.env.keys()))
    )?;
    writeln!(
        out,
        "  secret names:      {}",
        join(&sorted_keys(spec.secrets.keys()))
    )?;
    Ok(())
}

fn write_embedded(label: &str, text: Option<&str>, out: &mut impl Write) -> anyhow::Result<()>
{
    match text
    {
        None => writeln!(out, "{label}: -")?,
        Some(text) =>
        {
            writeln!(out, "{label}:")?;
            let rendered = match serde_json::from_str::<Value>(text)
            {
                Ok(value) => serde_json::to_string_pretty(&value)?,
                Err(_) => text.to_owned(),
            };
            for line in rendered.lines()
            {
                writeln!(out, "  {line}")?;
            }
        }
    }
    Ok(())
}

pub fn instance_json(row: &InstanceRow) -> Value
{
    json!({
        "id": row.id,
        "generation": row.generation,
        "observed_generation": row.observed_generation,
        "phase": row.phase,
        "reason": row.reason,
        "desired_deleted": row.desired_deleted,
        "unit_name": row.unit_name,
        "api_socket": row.api_socket,
        "pid": row.pid,
        "guest_ip": row.guest_ip,
        "uid": row.uid,
        "restart_count": row.restart_count,
        "last_exit_unix": row.last_exit_unix,
        "lease_epoch": row.lease_epoch,
        "lease_expires_unix_ms": row.lease_expires_unix_ms,
        "updated_at_unix": row.updated_at_unix,
        "spec": spec_json(&row.spec),
        "sandbox_record": embedded_json(row.sandbox_record.as_deref()),
        "network_attachment": embedded_json(row.network_attachment.as_deref()),
    })
}

fn spec_json(bytes: &[u8]) -> Value
{
    let spec = match InstanceSpec::decode(bytes)
    {
        Ok(spec) => spec,
        Err(error) => return json!({ "decode_error": error.to_string() }),
    };
    let network = spec.network.clone().unwrap_or_default();
    let lease = spec.lease.unwrap_or_default();
    let disks: Vec<Value> = spec
        .disks
        .iter()
        .map(|disk| {
            json!({
                "name": disk.name,
                "size_gib": disk.size_gib,
                "restore_from": disk.restore_from.as_ref().map(|snapshot| &snapshot.manifest_key),
            })
        })
        .collect();
    json!({
        "id": spec.id,
        "generation": spec.generation,
        "isolation": isolation_name(spec.isolation),
        "image": artifact_json(spec.image.as_ref()),
        "kernel": artifact_json(spec.kernel.as_ref()),
        "vcpus": spec.vcpus,
        "memory_mib": spec.memory_mib,
        "disks": disks,
        "network": {
            "world_id": network.world_id,
            "egress_mbit": network.egress_mbit,
            "ports": network.ports,
        },
        "env_keys": sorted_keys(spec.env.keys()),
        "secret_names": sorted_keys(spec.secrets.keys()),
        "restart_policy": restart_policy_name(spec.restart_policy),
        "run_state": run_state_name(spec.run_state),
        "lease": { "epoch": lease.epoch, "ttl_ms": lease.ttl_ms },
        "stop_deadline_seconds": spec.stop_deadline_seconds,
        "cpu_pinning": spec.cpu_pinning,
        "balloon_idle_reclaim": spec.balloon_idle_reclaim,
        "idle_reclaim_minutes": spec.idle_reclaim_minutes,
    })
}

fn artifact_json(artifact: Option<&ArtifactRef>) -> Value
{
    match artifact
    {
        Some(artifact) => json!({
            "digest": artifact.digest,
            "key": artifact.key,
            "signature_key": artifact.signature_key,
            "size_bytes": artifact.size_bytes,
        }),
        None => Value::Null,
    }
}

fn artifact_text(artifact: Option<&ArtifactRef>) -> String
{
    match artifact
    {
        Some(artifact) => format!(
            "{} ({}, {} bytes)",
            artifact.digest, artifact.key, artifact.size_bytes
        ),
        None => "-".to_owned(),
    }
}

fn embedded_json(text: Option<&str>) -> Value
{
    match text
    {
        None => Value::Null,
        Some(text) => serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned())),
    }
}

fn operation_json(operation: &OperationRow) -> Value
{
    json!({
        "op_id": operation.op_id,
        "kind": operation.kind,
        "instance_id": operation.instance_id,
        "status": operation.status.as_str(),
        "message": operation.message,
        "payload_bytes": operation.payload.len(),
        "started_at_unix": operation.started_at_unix,
        "finished_at_unix": operation.finished_at_unix,
    })
}

fn kv_value(value: &[u8]) -> Value
{
    match std::str::from_utf8(value)
    {
        Ok(text) => Value::String(text.to_owned()),
        Err(_) =>
        {
            let hex: String = value.iter().map(|byte| format!("{byte:02x}")).collect();
            json!({ "hex": hex })
        }
    }
}

fn enum_name(name: Option<&'static str>, prefix: &str, raw: i32) -> String
{
    match name
    {
        Some(name) => name.strip_prefix(prefix).unwrap_or(name).to_owned(),
        None => format!("UNKNOWN({raw})"),
    }
}

fn isolation_name(raw: i32) -> String
{
    enum_name(
        Isolation::try_from(raw)
            .ok()
            .map(|value| value.as_str_name()),
        "ISOLATION_",
        raw,
    )
}

fn restart_policy_name(raw: i32) -> String
{
    enum_name(
        RestartPolicy::try_from(raw)
            .ok()
            .map(|value| value.as_str_name()),
        "RESTART_POLICY_",
        raw,
    )
}

fn run_state_name(raw: i32) -> String
{
    enum_name(
        RunState::try_from(raw)
            .ok()
            .map(|value| value.as_str_name()),
        "RUN_STATE_",
        raw,
    )
}

fn sorted_keys<'a>(keys: impl Iterator<Item = &'a String>) -> Vec<String>
{
    let mut keys: Vec<String> = keys.cloned().collect();
    keys.sort();
    keys
}

fn join<T: ToString>(values: &[T]) -> String
{
    if values.is_empty()
    {
        return "-".to_owned();
    }
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn yes_no(value: bool) -> &'static str
{
    if value { "yes" } else { "no" }
}

fn now_unix_ms() -> i64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub fn lease_expiry(expires_unix_ms: Option<i64>, now_unix_ms: i64) -> String
{
    let Some(expires) = expires_unix_ms
    else
    {
        return "-".to_owned();
    };
    let remaining = expires.saturating_sub(now_unix_ms) / 1000;
    let relative = if remaining >= 0
    {
        format!("in {remaining}s")
    }
    else
    {
        format!("expired {}s ago", -remaining)
    };
    format!("{} ({relative})", utc(expires.div_euclid(1000)))
}

pub fn utc(unix: i64) -> String
{
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64)
{
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10
    {
        month_index + 3
    }
    else
    {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
