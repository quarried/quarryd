use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, Transaction, params};

#[cfg(test)]
mod tests;

const MIGRATIONS: &[&str] = &[
    "
    CREATE TABLE instances (
        id TEXT PRIMARY KEY NOT NULL,
        generation INTEGER NOT NULL,
        spec BLOB NOT NULL,
        desired_deleted INTEGER NOT NULL DEFAULT 0,
        observed_generation INTEGER NOT NULL DEFAULT 0,
        phase TEXT NOT NULL DEFAULT 'Pending',
        reason TEXT NOT NULL DEFAULT '',
        unit_name TEXT,
        api_socket TEXT,
        pid INTEGER,
        sandbox_record TEXT,
        network_attachment TEXT,
        guest_ip TEXT,
        uid INTEGER,
        restart_count INTEGER NOT NULL DEFAULT 0,
        last_exit_unix INTEGER,
        lease_epoch INTEGER NOT NULL DEFAULT 0,
        lease_expires_unix_ms INTEGER,
        updated_at_unix INTEGER NOT NULL
    );

    CREATE TABLE operations (
        op_id TEXT PRIMARY KEY NOT NULL,
        kind TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL DEFAULT '',
        payload BLOB NOT NULL DEFAULT x'',
        started_at_unix INTEGER NOT NULL,
        finished_at_unix INTEGER
    );
    CREATE INDEX operations_by_status ON operations (status, started_at_unix);
    CREATE INDEX operations_by_instance ON operations (instance_id);

    CREATE TABLE usage_outbox (
        id TEXT PRIMARY KEY NOT NULL,
        instance_id TEXT NOT NULL,
        bucket_start_unix INTEGER NOT NULL,
        bucket_seconds INTEGER NOT NULL,
        cpu_usec INTEGER NOT NULL,
        memory_mib_max INTEGER NOT NULL,
        memory_mib_avg INTEGER NOT NULL,
        disk_read_bytes INTEGER NOT NULL,
        disk_write_bytes INTEGER NOT NULL,
        net_rx_bytes INTEGER NOT NULL,
        net_tx_bytes INTEGER NOT NULL
    );
    CREATE INDEX usage_outbox_by_bucket ON usage_outbox (bucket_start_unix, id);

    CREATE TABLE artifacts (
        digest TEXT PRIMARY KEY NOT NULL,
        path TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        kind TEXT NOT NULL,
        last_used_unix INTEGER NOT NULL,
        verified INTEGER NOT NULL
    );
    CREATE INDEX artifacts_by_last_used ON artifacts (last_used_unix, digest);

    CREATE TABLE artifact_refs (
        digest TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        PRIMARY KEY (digest, instance_id)
    ) WITHOUT ROWID;
    CREATE INDEX artifact_refs_by_instance ON artifact_refs (instance_id);

    CREATE TABLE uid_allocations (
        instance_id TEXT PRIMARY KEY NOT NULL,
        uid INTEGER NOT NULL UNIQUE
    );

    CREATE TABLE kv (
        key TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    ) WITHOUT ROWID;
    ",
    "
    CREATE TABLE instance_disks (
        instance_id TEXT NOT NULL,
        name TEXT NOT NULL,
        PRIMARY KEY (instance_id, name)
    ) WITHOUT ROWID;
    ",
    "
    ALTER TABLE instances ADD COLUMN applied_spec BLOB;
    CREATE TABLE disk_bindings (
        instance_id TEXT NOT NULL,
        disk_name TEXT NOT NULL,
        volume_name TEXT NOT NULL UNIQUE,
        PRIMARY KEY (instance_id, disk_name)
    ) WITHOUT ROWID;
    CREATE TABLE disk_ownership_conflicts (
        name TEXT PRIMARY KEY NOT NULL,
        detail TEXT NOT NULL
    ) WITHOUT ROWID;
    ",
];

pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const INSTANCE_COLUMNS: &str = "id, generation, spec, desired_deleted, observed_generation, phase, reason, \
     unit_name, api_socket, pid, sandbox_record, network_attachment, guest_ip, uid, restart_count, \
     last_exit_unix, lease_epoch, lease_expires_unix_ms, updated_at_unix, applied_spec";

const OPERATION_COLUMNS: &str =
    "op_id, kind, instance_id, status, message, payload, started_at_unix, finished_at_unix";

const USAGE_COLUMNS: &str = "id, instance_id, bucket_start_unix, bucket_seconds, cpu_usec, memory_mib_max, \
     memory_mib_avg, disk_read_bytes, disk_write_bytes, net_rx_bytes, net_tx_bytes";

const ARTIFACT_COLUMNS: &str = "digest, path, size_bytes, kind, last_used_unix, verified";

#[derive(Debug, thiserror::Error)]
pub enum StoreError
{
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew
    {
        found: u32, supported: u32
    },
    #[error("database schema version {found} is older than the required version {required}")]
    SchemaTooOld
    {
        found: u32, required: u32
    },
    #[error("journal mode is {0}, expected wal")]
    WalUnavailable(String),
    #[error("instance {0} not found")]
    InstanceNotFound(String),
    #[error("volume {name:?} has conflicting or unverified ownership: {detail}")]
    DiskOwnership
    {
        name: String, detail: String
    },
    #[error("operation {0} not found")]
    OperationNotFound(String),
    #[error("artifact {0} not found")]
    ArtifactNotFound(String),
    #[error("artifact {0} is still referenced by an instance")]
    ArtifactReferenced(String),
    #[error("invalid uid range: base {base}, count {count}")]
    InvalidUidRange
    {
        base: u32, count: u32
    },
    #[error("no free uid in range starting at {base} with {count} ids")]
    UidRangeExhausted
    {
        base: u32, count: u32
    },
    #[error("value {0} does not fit in a signed 64-bit column")]
    ValueOutOfRange(u64),
    #[error("corrupt value for {key}: {detail}")]
    Corrupt
    {
        key: String, detail: String
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome
{
    Inserted,
    Updated,
    Unchanged,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRow
{
    pub id: String,
    pub generation: u64,
    pub spec: Vec<u8>,
    pub desired_deleted: bool,
    pub observed_generation: u64,
    pub phase: String,
    pub reason: String,
    pub unit_name: Option<String>,
    pub api_socket: Option<String>,
    pub pid: Option<u32>,
    pub sandbox_record: Option<String>,
    pub network_attachment: Option<String>,
    pub guest_ip: Option<String>,
    pub uid: Option<u32>,
    pub restart_count: u32,
    pub last_exit_unix: Option<i64>,
    pub lease_epoch: u64,
    pub lease_expires_unix_ms: Option<i64>,
    pub updated_at_unix: i64,
    pub applied_spec: Option<Vec<u8>>,
}

impl InstanceRow
{
    pub fn actual(&self) -> ActualState
    {
        ActualState {
            observed_generation: self.observed_generation,
            phase: self.phase.clone(),
            reason: self.reason.clone(),
            unit_name: self.unit_name.clone(),
            api_socket: self.api_socket.clone(),
            pid: self.pid,
            sandbox_record: self.sandbox_record.clone(),
            network_attachment: self.network_attachment.clone(),
            guest_ip: self.guest_ip.clone(),
            uid: self.uid,
            restart_count: self.restart_count,
            last_exit_unix: self.last_exit_unix,
            lease_epoch: self.lease_epoch,
            lease_expires_unix_ms: self.lease_expires_unix_ms,
            applied_spec: self.applied_spec.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActualState
{
    pub observed_generation: u64,
    pub phase: String,
    pub reason: String,
    pub unit_name: Option<String>,
    pub api_socket: Option<String>,
    pub pid: Option<u32>,
    pub sandbox_record: Option<String>,
    pub network_attachment: Option<String>,
    pub guest_ip: Option<String>,
    pub uid: Option<u32>,
    pub restart_count: u32,
    pub last_exit_unix: Option<i64>,
    pub lease_epoch: u64,
    pub lease_expires_unix_ms: Option<i64>,
    pub applied_spec: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationStatus
{
    InProgress,
    Succeeded,
    Failed,
}

impl OperationStatus
{
    pub fn as_str(self) -> &'static str
    {
        match self
        {
            OperationStatus::InProgress => "in_progress",
            OperationStatus::Succeeded => "succeeded",
            OperationStatus::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<OperationStatus>
    {
        match text
        {
            "in_progress" => Some(OperationStatus::InProgress),
            "succeeded" => Some(OperationStatus::Succeeded),
            "failed" => Some(OperationStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRow
{
    pub op_id: String,
    pub kind: String,
    pub instance_id: String,
    pub status: OperationStatus,
    pub message: String,
    pub payload: Vec<u8>,
    pub started_at_unix: i64,
    pub finished_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginOperation
{
    Started,
    InProgress(OperationRow),
    Finished(OperationRow),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRow
{
    pub id: String,
    pub instance_id: String,
    pub bucket_start_unix: i64,
    pub bucket_seconds: u32,
    pub cpu_usec: u64,
    pub memory_mib_max: u64,
    pub memory_mib_avg: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRow
{
    pub digest: String,
    pub path: String,
    pub size_bytes: u64,
    pub kind: String,
    pub last_used_unix: i64,
    pub verified: bool,
}

pub struct Store
{
    connection: Mutex<Connection>,
}

impl Store
{
    pub fn open(path: &Path) -> Result<Store, StoreError>
    {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal")
        {
            return Err(StoreError::WalUnavailable(journal_mode));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        migrate(&mut connection)?;
        Ok(Store::from_connection(connection))
    }

    pub fn open_read_only(path: &Path) -> Result<Store, StoreError>
    {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "query_only", "ON")?;
        let found = schema_version(&connection)?;
        if found > SCHEMA_VERSION
        {
            return Err(StoreError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found < SCHEMA_VERSION
        {
            return Err(StoreError::SchemaTooOld {
                found,
                required: SCHEMA_VERSION,
            });
        }
        Ok(Store::from_connection(connection))
    }

    pub fn open_in_memory() -> Result<Store, StoreError>
    {
        let mut connection = Connection::open_in_memory()?;
        migrate(&mut connection)?;
        Ok(Store::from_connection(connection))
    }

    pub fn schema_version(&self) -> Result<u32, StoreError>
    {
        schema_version(&self.connection())
    }

    fn from_connection(connection: Connection) -> Store
    {
        Store {
            connection: Mutex::new(connection),
        }
    }

    fn connection(&self) -> MutexGuard<'_, Connection>
    {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn put_desired(
        &self,
        id: &str,
        generation: u64,
        spec: &[u8],
    ) -> Result<PutOutcome, StoreError>
    {
        self.put_desired_with_lease(id, generation, spec, None)
    }

    pub fn put_desired_with_lease(
        &self,
        id: &str,
        generation: u64,
        spec: &[u8],
        lease: Option<(u64, i64)>,
    ) -> Result<PutOutcome, StoreError>
    {
        let generation = to_i64(generation)?;
        let lease = lease
            .map(|(epoch, expires)| Ok::<_, StoreError>((to_i64(epoch)?, expires)))
            .transpose()?;
        let now = now_unix();
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        let existing: Option<(i64, Vec<u8>, bool)> = transaction
            .query_row(
                "SELECT generation, spec, desired_deleted FROM instances WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let outcome = match existing
        {
            None =>
            {
                transaction.execute(
                    "INSERT INTO instances (id, generation, spec, updated_at_unix) VALUES (?1, ?2, ?3, ?4)",
                    params![id, generation, spec, now],
                )?;
                PutOutcome::Inserted
            }
            Some((stored_generation, _, true)) if generation <= stored_generation =>
            {
                PutOutcome::Stale
            }
            Some((stored_generation, _, _)) if generation < stored_generation => PutOutcome::Stale,
            Some((stored_generation, stored_spec, false))
                if generation == stored_generation && stored_spec == spec =>
            {
                PutOutcome::Unchanged
            }
            Some(_) =>
            {
                transaction.execute(
                    "UPDATE instances SET generation = ?2, spec = ?3, desired_deleted = 0, updated_at_unix = ?4 \
                     WHERE id = ?1",
                    params![id, generation, spec, now],
                )?;
                PutOutcome::Updated
            }
        };
        if matches!(outcome, PutOutcome::Inserted | PutOutcome::Updated)
            && let Some((epoch, expires)) = lease
        {
            transaction.execute(
                "UPDATE instances SET lease_epoch = ?2, lease_expires_unix_ms = ?3 \
                 WHERE id = ?1 AND lease_epoch <= ?2",
                params![id, epoch, expires],
            )?;
        }
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn remember_disk(&self, instance_id: &str, name: &str) -> Result<(), StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        check_disk_owner(&transaction, instance_id, name)?;
        transaction.execute(
            "INSERT OR IGNORE INTO instance_disks (instance_id, name) VALUES (?1, ?2)",
            params![instance_id, name],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Persist a logical disk's physical name before creating or using its volume.
    pub fn claim_disk(
        &self,
        instance_id: &str,
        disk_name: &str,
        name: &str,
    ) -> Result<(), StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        check_disk_owner(&transaction, instance_id, name)?;
        let conflict: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT instance_id, disk_name, volume_name FROM disk_bindings \
             WHERE (volume_name = ?3 OR (instance_id = ?1 AND disk_name = ?2)) \
             AND NOT (instance_id = ?1 AND disk_name = ?2 AND volume_name = ?3)",
                params![instance_id, disk_name, name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((owner, disk, volume)) = conflict
        {
            return Err(StoreError::DiskOwnership {
                name: name.to_owned(),
                detail: format!("already bound to {owner:?}/{disk:?} at {volume:?}"),
            });
        }
        transaction.execute(
            "INSERT OR IGNORE INTO disk_bindings (instance_id, disk_name, volume_name) VALUES (?1, ?2, ?3)",
            params![instance_id, disk_name, name],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO instance_disks (instance_id, name) VALUES (?1, ?2)",
            params![instance_id, name],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn disk_binding(
        &self,
        instance_id: &str,
        disk_name: &str,
    ) -> Result<Option<String>, StoreError>
    {
        let connection = self.connection();
        let name: Option<String> = connection
            .query_row(
                "SELECT volume_name FROM disk_bindings WHERE instance_id = ?1 AND disk_name = ?2",
                params![instance_id, disk_name],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(name) = &name
        {
            check_disk_owner(&connection, instance_id, name)?;
        }
        Ok(name)
    }

    pub fn assert_disk_owner(&self, instance_id: &str, name: &str) -> Result<(), StoreError>
    {
        let connection = self.connection();
        check_disk_owner(&connection, instance_id, name)?;
        let owned: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM instance_disks WHERE instance_id = ?1 AND name = ?2)",
            params![instance_id, name],
            |row| row.get(0),
        )?;
        if !owned
        {
            return Err(StoreError::DiskOwnership {
                name: name.to_owned(),
                detail: "no durable owner".to_owned(),
            });
        }
        Ok(())
    }

    pub fn bound_disk(&self, name: &str) -> Result<Option<(String, String)>, StoreError>
    {
        Ok(self
            .connection()
            .query_row(
                "SELECT instance_id, disk_name FROM disk_bindings WHERE volume_name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Preserve ambiguity even if a later desired update removes the evidence.
    /// These records require an operator to identify the correct world owner.
    pub fn quarantine_disk(&self, name: &str, detail: &str) -> Result<(), StoreError>
    {
        self.connection().execute(
            "INSERT OR IGNORE INTO disk_ownership_conflicts (name, detail) VALUES (?1, ?2)",
            params![name, detail],
        )?;
        Ok(())
    }

    pub fn instance_disks(&self, instance_id: &str) -> Result<Vec<String>, StoreError>
    {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT name FROM instance_disks WHERE instance_id = ?1 ORDER BY name")?;
        Ok(statement
            .query_map([instance_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn forget_disk(&self, instance_id: &str, name: &str) -> Result<(), StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        check_disk_owner(&transaction, instance_id, name)?;
        transaction.execute(
            "DELETE FROM instance_disks WHERE instance_id = ?1 AND name = ?2",
            params![instance_id, name],
        )?;
        transaction.execute(
            "DELETE FROM disk_bindings WHERE instance_id = ?1 AND volume_name = ?2",
            params![instance_id, name],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_deleted_desired(&self, id: &str) -> Result<bool, StoreError>
    {
        let changed = self.connection().execute(
            "UPDATE instances SET desired_deleted = 1, updated_at_unix = ?2 WHERE id = ?1",
            params![id, now_unix()],
        )?;
        Ok(changed > 0)
    }

    pub fn get_instance(&self, id: &str) -> Result<Option<InstanceRow>, StoreError>
    {
        let sql = format!("SELECT {INSTANCE_COLUMNS} FROM instances WHERE id = ?1");
        Ok(self
            .connection()
            .query_row(&sql, [id], instance_from_row)
            .optional()?)
    }

    pub fn list_instances(&self) -> Result<Vec<InstanceRow>, StoreError>
    {
        let sql = format!("SELECT {INSTANCE_COLUMNS} FROM instances ORDER BY id");
        let connection = self.connection();
        let mut statement = connection.prepare(&sql)?;
        let rows = statement
            .query_map([], instance_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn update_actual(&self, id: &str, actual: &ActualState) -> Result<(), StoreError>
    {
        let changed = self.connection().execute(
            "UPDATE instances SET observed_generation = ?2, phase = ?3, reason = ?4, unit_name = ?5, \
             api_socket = ?6, pid = ?7, sandbox_record = ?8, network_attachment = ?9, guest_ip = ?10, \
             uid = ?11, restart_count = ?12, last_exit_unix = ?13, lease_epoch = ?14, \
             lease_expires_unix_ms = ?15, updated_at_unix = ?16, applied_spec = ?17 WHERE id = ?1",
            params![
                id,
                to_i64(actual.observed_generation)?,
                actual.phase,
                actual.reason,
                actual.unit_name,
                actual.api_socket,
                actual.pid,
                actual.sandbox_record,
                actual.network_attachment,
                actual.guest_ip,
                actual.uid,
                actual.restart_count,
                actual.last_exit_unix,
                to_i64(actual.lease_epoch)?,
                actual.lease_expires_unix_ms,
                now_unix(),
                actual.applied_spec,
            ],
        )?;
        if changed == 0
        {
            return Err(StoreError::InstanceNotFound(id.to_string()));
        }
        Ok(())
    }

    pub fn remove_instance(&self, id: &str) -> Result<(), StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM instances WHERE id = ?1", [id])?;
        transaction.execute("DELETE FROM uid_allocations WHERE instance_id = ?1", [id])?;
        transaction.execute("DELETE FROM artifact_refs WHERE instance_id = ?1", [id])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn allocate_uid(&self, instance_id: &str, base: u32, count: u32)
    -> Result<u32, StoreError>
    {
        if count == 0 || base.checked_add(count - 1).is_none()
        {
            return Err(StoreError::InvalidUidRange { base, count });
        }
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        if let Some(uid) = allocated_uid(&transaction, instance_id)?
        {
            return Ok(uid);
        }
        let end = i64::from(base) + i64::from(count);
        let taken = {
            let mut statement = transaction.prepare(
                "SELECT uid FROM uid_allocations WHERE uid >= ?1 AND uid < ?2 ORDER BY uid",
            )?;
            statement
                .query_map(params![base, end], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut candidate = i64::from(base);
        for uid in taken
        {
            if uid != candidate
            {
                break;
            }
            candidate += 1;
        }
        if candidate >= end
        {
            return Err(StoreError::UidRangeExhausted { base, count });
        }
        transaction.execute(
            "INSERT INTO uid_allocations (instance_id, uid) VALUES (?1, ?2)",
            params![instance_id, candidate],
        )?;
        transaction.commit()?;
        u32::try_from(candidate).map_err(|_| StoreError::Corrupt {
            key: format!("uid_allocations/{instance_id}"),
            detail: format!("uid {candidate} out of range"),
        })
    }

    pub fn begin_operation(
        &self,
        op_id: &str,
        kind: &str,
        instance_id: &str,
    ) -> Result<BeginOperation, StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO operations (op_id, kind, instance_id, status, started_at_unix) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                op_id,
                kind,
                instance_id,
                OperationStatus::InProgress.as_str(),
                now_unix()
            ],
        )?;
        let outcome = if inserted > 0
        {
            BeginOperation::Started
        }
        else
        {
            let row = query_operation(&transaction, op_id)?
                .ok_or_else(|| StoreError::OperationNotFound(op_id.to_string()))?;
            match row.status
            {
                OperationStatus::InProgress => BeginOperation::InProgress(row),
                OperationStatus::Succeeded | OperationStatus::Failed =>
                {
                    BeginOperation::Finished(row)
                }
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn finish_operation(
        &self,
        op_id: &str,
        succeeded: bool,
        message: &str,
        payload: &[u8],
    ) -> Result<(), StoreError>
    {
        let status = if succeeded
        {
            OperationStatus::Succeeded
        }
        else
        {
            OperationStatus::Failed
        };
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE operations SET status = ?2, message = ?3, payload = ?4, finished_at_unix = ?5 \
             WHERE op_id = ?1 AND status = ?6",
            params![
                op_id,
                status.as_str(),
                message,
                payload,
                now_unix(),
                OperationStatus::InProgress.as_str()
            ],
        )?;
        if changed == 0 && query_operation(&transaction, op_id)?.is_none()
        {
            return Err(StoreError::OperationNotFound(op_id.to_string()));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn get_operation(&self, op_id: &str) -> Result<Option<OperationRow>, StoreError>
    {
        query_operation(&self.connection(), op_id)
    }

    pub fn list_operations(
        &self,
        status: Option<OperationStatus>,
    ) -> Result<Vec<OperationRow>, StoreError>
    {
        let connection = self.connection();
        let rows = match status
        {
            Some(status) =>
            {
                let sql = format!(
                    "SELECT {OPERATION_COLUMNS} FROM operations WHERE status = ?1 ORDER BY started_at_unix, op_id"
                );
                let mut statement = connection.prepare(&sql)?;
                statement
                    .query_map([status.as_str()], operation_from_row)?
                    .collect::<Result<Vec<_>, _>>()?
            }
            None =>
            {
                let sql = format!(
                    "SELECT {OPERATION_COLUMNS} FROM operations ORDER BY started_at_unix, op_id"
                );
                let mut statement = connection.prepare(&sql)?;
                statement
                    .query_map([], operation_from_row)?
                    .collect::<Result<Vec<_>, _>>()?
            }
        };
        Ok(rows)
    }

    pub fn insert_usage(&self, record: &UsageRow) -> Result<bool, StoreError>
    {
        let inserted = self.connection().execute(
            &format!(
                "INSERT OR IGNORE INTO usage_outbox ({USAGE_COLUMNS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
            ),
            params![
                record.id,
                record.instance_id,
                record.bucket_start_unix,
                record.bucket_seconds,
                to_i64(record.cpu_usec)?,
                to_i64(record.memory_mib_max)?,
                to_i64(record.memory_mib_avg)?,
                to_i64(record.disk_read_bytes)?,
                to_i64(record.disk_write_bytes)?,
                to_i64(record.net_rx_bytes)?,
                to_i64(record.net_tx_bytes)?,
            ],
        )?;
        Ok(inserted > 0)
    }

    pub fn pending_usage(&self, limit: usize) -> Result<Vec<UsageRow>, StoreError>
    {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT {USAGE_COLUMNS} FROM usage_outbox ORDER BY bucket_start_unix, id LIMIT ?1"
        );
        let connection = self.connection();
        let mut statement = connection.prepare(&sql)?;
        let rows = statement
            .query_map([limit], usage_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_usage(&self, ids: &[String]) -> Result<usize, StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        let mut deleted = 0;
        {
            let mut statement = transaction.prepare("DELETE FROM usage_outbox WHERE id = ?1")?;
            for id in ids
            {
                deleted += statement.execute([id])?;
            }
        }
        transaction.commit()?;
        Ok(deleted)
    }

    pub fn usage_depth(&self) -> Result<u64, StoreError>
    {
        let count: i64 =
            self.connection()
                .query_row("SELECT COUNT(*) FROM usage_outbox", [], |row| row.get(0))?;
        from_i64(count, "usage_outbox count")
    }

    pub fn upsert_artifact(&self, artifact: &ArtifactRow) -> Result<(), StoreError>
    {
        self.connection().execute(
            &format!(
                "INSERT INTO artifacts ({ARTIFACT_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT (digest) DO UPDATE SET path = excluded.path, size_bytes = excluded.size_bytes, \
                 kind = excluded.kind, last_used_unix = excluded.last_used_unix, verified = excluded.verified"
            ),
            params![
                artifact.digest,
                artifact.path,
                to_i64(artifact.size_bytes)?,
                artifact.kind,
                artifact.last_used_unix,
                artifact.verified,
            ],
        )?;
        Ok(())
    }

    pub fn get_artifact(&self, digest: &str) -> Result<Option<ArtifactRow>, StoreError>
    {
        let sql = format!("SELECT {ARTIFACT_COLUMNS} FROM artifacts WHERE digest = ?1");
        Ok(self
            .connection()
            .query_row(&sql, [digest], artifact_from_row)
            .optional()?)
    }

    pub fn touch_artifact(&self, digest: &str, now_unix: i64) -> Result<(), StoreError>
    {
        let changed = self.connection().execute(
            "UPDATE artifacts SET last_used_unix = ?2 WHERE digest = ?1",
            params![digest, now_unix],
        )?;
        if changed == 0
        {
            return Err(StoreError::ArtifactNotFound(digest.to_string()));
        }
        Ok(())
    }

    pub fn add_artifact_ref(&self, digest: &str, instance_id: &str) -> Result<(), StoreError>
    {
        self.connection().execute(
            "INSERT OR IGNORE INTO artifact_refs (digest, instance_id) VALUES (?1, ?2)",
            [digest, instance_id],
        )?;
        Ok(())
    }

    pub fn remove_artifact_ref(&self, digest: &str, instance_id: &str) -> Result<(), StoreError>
    {
        self.connection().execute(
            "DELETE FROM artifact_refs WHERE digest = ?1 AND instance_id = ?2",
            [digest, instance_id],
        )?;
        Ok(())
    }

    pub fn remove_instance_artifact_refs(&self, instance_id: &str) -> Result<(), StoreError>
    {
        self.connection().execute(
            "DELETE FROM artifact_refs WHERE instance_id = ?1",
            [instance_id],
        )?;
        Ok(())
    }

    pub fn artifact_ref_count(&self, digest: &str) -> Result<u64, StoreError>
    {
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM artifact_refs WHERE digest = ?1",
            [digest],
            |row| row.get(0),
        )?;
        from_i64(count, "artifact_refs count")
    }

    pub fn unreferenced_artifacts_lru(&self) -> Result<Vec<ArtifactRow>, StoreError>
    {
        let sql = format!(
            "SELECT {ARTIFACT_COLUMNS} FROM artifacts AS a \
             WHERE NOT EXISTS (SELECT 1 FROM artifact_refs AS r WHERE r.digest = a.digest) \
             ORDER BY last_used_unix, digest"
        );
        let connection = self.connection();
        let mut statement = connection.prepare(&sql)?;
        let rows = statement
            .query_map([], artifact_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn total_artifact_bytes(&self) -> Result<u64, StoreError>
    {
        let total: i64 = self.connection().query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts",
            [],
            |row| row.get(0),
        )?;
        from_i64(total, "artifacts total size")
    }

    pub fn delete_artifact(&self, digest: &str) -> Result<(), StoreError>
    {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        let references: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM artifact_refs WHERE digest = ?1",
            [digest],
            |row| row.get(0),
        )?;
        if references > 0
        {
            return Err(StoreError::ArtifactReferenced(digest.to_string()));
        }
        transaction.execute("DELETE FROM artifacts WHERE digest = ?1", [digest])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>
    {
        Ok(self
            .connection()
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn kv_set(&self, key: &str, value: &[u8]) -> Result<(), StoreError>
    {
        self.connection().execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn kv_delete(&self, key: &str) -> Result<(), StoreError>
    {
        self.connection()
            .execute("DELETE FROM kv WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn kv_get_u64(&self, key: &str) -> Result<Option<u64>, StoreError>
    {
        let Some(value) = self.kv_get(key)?
        else
        {
            return Ok(None);
        };
        std::str::from_utf8(&value)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .map(Some)
            .ok_or_else(|| StoreError::Corrupt {
                key: key.to_string(),
                detail: "not a decimal u64".to_string(),
            })
    }

    pub fn kv_set_u64(&self, key: &str, value: u64) -> Result<(), StoreError>
    {
        self.kv_set(key, value.to_string().as_bytes())
    }

    pub fn kv_list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError>
    {
        let connection = self.connection();
        let mut statement =
            connection.prepare("SELECT key, value FROM kv WHERE key >= ?1 ORDER BY key")?;
        let mut rows = statement.query([prefix])?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next()?
        {
            let key: String = row.get(0)?;
            if !key.starts_with(prefix)
            {
                break;
            }
            entries.push((key, row.get(1)?));
        }
        Ok(entries)
    }
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError>
{
    let found = schema_version(connection)?;
    if found > SCHEMA_VERSION
    {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction()?;
    for (version, migration) in (1_i64..).zip(MIGRATIONS).skip(found as usize)
    {
        transaction.execute_batch(migration)?;
        transaction.pragma_update(None, "user_version", version)?;
    }
    transaction.commit()?;
    Ok(())
}

fn schema_version(connection: &Connection) -> Result<u32, StoreError>
{
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    u32::try_from(version).map_err(|_| StoreError::Corrupt {
        key: "user_version".to_string(),
        detail: format!("{version} is not a valid schema version"),
    })
}

fn allocated_uid(
    transaction: &Transaction<'_>,
    instance_id: &str,
) -> Result<Option<u32>, StoreError>
{
    Ok(transaction
        .query_row(
            "SELECT uid FROM uid_allocations WHERE instance_id = ?1",
            [instance_id],
            |row| column_u32(row, 0),
        )
        .optional()?)
}

fn query_operation(connection: &Connection, op_id: &str)
-> Result<Option<OperationRow>, StoreError>
{
    let sql = format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE op_id = ?1");
    Ok(connection
        .query_row(&sql, [op_id], operation_from_row)
        .optional()?)
}

fn check_disk_owner(
    connection: &Connection,
    instance_id: &str,
    name: &str,
) -> Result<(), StoreError>
{
    let conflict: Option<String> = connection
        .query_row(
            "SELECT detail FROM disk_ownership_conflicts WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(detail) = conflict
    {
        return Err(StoreError::DiskOwnership {
            name: name.to_owned(),
            detail,
        });
    }
    let other: Option<String> = connection.query_row(
        "SELECT instance_id FROM instance_disks WHERE name = ?1 AND instance_id != ?2 \
         UNION SELECT instance_id FROM disk_bindings WHERE volume_name = ?1 AND instance_id != ?2 LIMIT 1",
        params![name, instance_id], |row| row.get(0),
    ).optional()?;
    if let Some(owner) = other
    {
        return Err(StoreError::DiskOwnership {
            name: name.to_owned(),
            detail: format!("also recorded for instance {owner:?}"),
        });
    }
    Ok(())
}

fn instance_from_row(row: &Row<'_>) -> rusqlite::Result<InstanceRow>
{
    Ok(InstanceRow {
        id: row.get(0)?,
        generation: column_u64(row, 1)?,
        spec: row.get(2)?,
        desired_deleted: row.get(3)?,
        observed_generation: column_u64(row, 4)?,
        phase: row.get(5)?,
        reason: row.get(6)?,
        unit_name: row.get(7)?,
        api_socket: row.get(8)?,
        pid: column_optional_u32(row, 9)?,
        sandbox_record: row.get(10)?,
        network_attachment: row.get(11)?,
        guest_ip: row.get(12)?,
        uid: column_optional_u32(row, 13)?,
        restart_count: column_u32(row, 14)?,
        last_exit_unix: row.get(15)?,
        lease_epoch: column_u64(row, 16)?,
        lease_expires_unix_ms: row.get(17)?,
        updated_at_unix: row.get(18)?,
        applied_spec: row.get(19)?,
    })
}

fn operation_from_row(row: &Row<'_>) -> rusqlite::Result<OperationRow>
{
    let status_text: String = row.get(3)?;
    let status = OperationStatus::parse(&status_text).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            format!("unknown operation status {status_text:?}").into(),
        )
    })?;
    Ok(OperationRow {
        op_id: row.get(0)?,
        kind: row.get(1)?,
        instance_id: row.get(2)?,
        status,
        message: row.get(4)?,
        payload: row.get(5)?,
        started_at_unix: row.get(6)?,
        finished_at_unix: row.get(7)?,
    })
}

fn usage_from_row(row: &Row<'_>) -> rusqlite::Result<UsageRow>
{
    Ok(UsageRow {
        id: row.get(0)?,
        instance_id: row.get(1)?,
        bucket_start_unix: row.get(2)?,
        bucket_seconds: column_u32(row, 3)?,
        cpu_usec: column_u64(row, 4)?,
        memory_mib_max: column_u64(row, 5)?,
        memory_mib_avg: column_u64(row, 6)?,
        disk_read_bytes: column_u64(row, 7)?,
        disk_write_bytes: column_u64(row, 8)?,
        net_rx_bytes: column_u64(row, 9)?,
        net_tx_bytes: column_u64(row, 10)?,
    })
}

fn artifact_from_row(row: &Row<'_>) -> rusqlite::Result<ArtifactRow>
{
    Ok(ArtifactRow {
        digest: row.get(0)?,
        path: row.get(1)?,
        size_bytes: column_u64(row, 2)?,
        kind: row.get(3)?,
        last_used_unix: row.get(4)?,
        verified: row.get(5)?,
    })
}

fn column_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64>
{
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn column_u32(row: &Row<'_>, index: usize) -> rusqlite::Result<u32>
{
    let value: i64 = row.get(index)?;
    u32::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn column_optional_u32(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u32>>
{
    let value: Option<i64> = row.get(index)?;
    value
        .map(|value| {
            u32::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
        })
        .transpose()
}

fn to_i64(value: u64) -> Result<i64, StoreError>
{
    i64::try_from(value).map_err(|_| StoreError::ValueOutOfRange(value))
}

fn from_i64(value: i64, key: &str) -> Result<u64, StoreError>
{
    u64::try_from(value).map_err(|_| StoreError::Corrupt {
        key: key.to_string(),
        detail: format!("negative value {value}"),
    })
}

fn now_unix() -> i64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
