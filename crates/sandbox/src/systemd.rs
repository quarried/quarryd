use std::path::PathBuf;

use nix::sys::signal::Signal;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Variant};

use crate::SandboxError;

const DESTINATION: &str = "org.freedesktop.systemd1";
const OBJECT_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransientServiceProperties
{
    pub description: String,
    pub slice: Option<String>,
    pub kill_mode: Option<String>,
    pub cpu_quota_per_sec_usec: Option<u64>,
    pub memory_max: Option<u64>,
    pub allowed_cpus: Option<Vec<u32>>,
    pub delegate: bool,
    pub exec_stop_post: Vec<Vec<String>>,
    pub environment: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub timeout_stop_usec: Option<u64>,
}

type Property = (String, Variant<'static>);

fn command_line(argv: &[String]) -> Result<Vec<(String, Vec<String>, bool)>, SandboxError>
{
    let program = argv
        .first()
        .ok_or_else(|| SandboxError::InvalidSpec("unit command line is empty".into()))?;
    Ok(vec![(program.clone(), argv.to_vec(), false)])
}

pub fn cpu_mask(cpus: &[u32]) -> Vec<u8>
{
    let bytes = cpus
        .iter()
        .map(|cpu| *cpu as usize / 8 + 1)
        .max()
        .unwrap_or(0);
    let mut mask = vec![0u8; bytes];
    for cpu in cpus
    {
        mask[*cpu as usize / 8] |= 1 << (cpu % 8);
    }
    mask
}

impl TransientServiceProperties
{
    fn to_dbus(&self, exec: &[String]) -> Result<Vec<Property>, SandboxError>
    {
        let mut properties: Vec<Property> = vec![
            (
                "Description".into(),
                Variant::from(self.description.clone()),
            ),
            ("ExecStart".into(), Variant::from(command_line(exec)?)),
            ("Restart".into(), Variant::from("no".to_string())),
        ];
        if let Some(slice) = &self.slice
        {
            properties.push(("Slice".into(), Variant::from(slice.clone())));
        }
        if let Some(kill_mode) = &self.kill_mode
        {
            properties.push(("KillMode".into(), Variant::from(kill_mode.clone())));
        }
        if let Some(quota) = self.cpu_quota_per_sec_usec
        {
            properties.push(("CPUQuotaPerSecUSec".into(), Variant::from(quota)));
        }
        if let Some(memory_max) = self.memory_max
        {
            properties.push(("MemoryMax".into(), Variant::from(memory_max)));
        }
        if let Some(cpus) = &self.allowed_cpus
        {
            properties.push(("AllowedCPUs".into(), Variant::from(cpu_mask(cpus))));
        }
        if self.delegate
        {
            properties.push(("Delegate".into(), Variant::from(true)));
        }
        for argv in &self.exec_stop_post
        {
            properties.push(("ExecStopPost".into(), Variant::from(command_line(argv)?)));
        }
        if !self.environment.is_empty()
        {
            properties.push((
                "Environment".into(),
                Variant::from(self.environment.clone()),
            ));
        }
        if let Some(directory) = &self.working_directory
        {
            let directory = crate::shell::path_text(directory)?;
            properties.push(("WorkingDirectory".into(), Variant::from(directory)));
        }
        if let Some(timeout) = self.timeout_stop_usec
        {
            properties.push(("TimeoutStopUSec".into(), Variant::from(timeout)));
        }
        Ok(properties)
    }
}

fn is_missing_unit(error: &zbus::Error) -> bool
{
    match error
    {
        zbus::Error::MethodError(name, _, _) =>
        {
            name.as_str() == NO_SUCH_UNIT || name.as_str() == UNKNOWN_OBJECT
        }
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub struct Systemd
{
    connection: Connection,
}

impl Systemd
{
    pub async fn connect() -> Result<Self, SandboxError>
    {
        Ok(Self {
            connection: Connection::system().await?,
        })
    }

    pub fn from_connection(connection: Connection) -> Self
    {
        Self { connection }
    }

    async fn call_systemd<B>(&self, method: &str, body: &B) -> Result<zbus::Message, zbus::Error>
    where
        B: serde::Serialize + zbus::DynamicType,
    {
        self.connection
            .call_method(
                Some(DESTINATION),
                OBJECT_PATH,
                Some(SYSTEMD_INTERFACE),
                method,
                body,
            )
            .await
    }

    pub async fn start_transient_service(
        &self,
        name: &str,
        exec: &[String],
        properties: &TransientServiceProperties,
    ) -> Result<(), SandboxError>
    {
        let properties = properties.to_dbus(exec)?;
        let auxiliary: Vec<(String, Vec<Property>)> = Vec::new();
        self.call_systemd("StartTransientUnit", &(name, "fail", properties, auxiliary))
            .await?;
        Ok(())
    }

    pub async fn stop_unit(&self, name: &str) -> Result<(), SandboxError>
    {
        match self.call_systemd("StopUnit", &(name, "replace")).await
        {
            Ok(_) => Ok(()),
            Err(error) if is_missing_unit(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn restart_unit(&self, name: &str) -> Result<(), SandboxError>
    {
        self.call_systemd("RestartUnit", &(name, "replace")).await?;
        Ok(())
    }

    pub async fn kill_unit(&self, name: &str, signal: Signal) -> Result<(), SandboxError>
    {
        self.call_systemd("KillUnit", &(name, "all", signal as i32))
            .await?;
        Ok(())
    }

    pub async fn reset_failed_unit(&self, name: &str) -> Result<(), SandboxError>
    {
        match self.call_systemd("ResetFailedUnit", &(name,)).await
        {
            Ok(_) => Ok(()),
            Err(error) if is_missing_unit(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn unit_path(&self, name: &str) -> Result<Option<OwnedObjectPath>, SandboxError>
    {
        match self.call_systemd("GetUnit", &(name,)).await
        {
            Ok(reply) => Ok(Some(reply.body().deserialize::<OwnedObjectPath>()?)),
            Err(error) if is_missing_unit(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn unit_property(
        &self,
        name: &str,
        interface: &str,
        property: &str,
    ) -> Result<Option<OwnedVariant>, SandboxError>
    {
        let Some(path) = self.unit_path(name).await?
        else
        {
            return Ok(None);
        };
        let reply = self
            .connection
            .call_method(
                Some(DESTINATION),
                path.as_str(),
                Some(PROPERTIES_INTERFACE),
                "Get",
                &(interface, property),
            )
            .await;
        match reply
        {
            Ok(reply) => Ok(Some(reply.body().deserialize::<OwnedVariant>()?)),
            Err(error) if is_missing_unit(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn unit_active_state(&self, name: &str) -> Result<Option<String>, SandboxError>
    {
        match self
            .unit_property(name, UNIT_INTERFACE, "ActiveState")
            .await?
        {
            Some(value) => Ok(Some(String::try_from(&*value)?)),
            None => Ok(None),
        }
    }

    pub async fn unit_main_pid(&self, name: &str) -> Result<Option<u32>, SandboxError>
    {
        match self
            .unit_property(name, SERVICE_INTERFACE, "MainPID")
            .await?
        {
            Some(value) => Ok(Some(u32::try_from(&*value)?).filter(|pid| *pid != 0)),
            None => Ok(None),
        }
    }

    pub async fn unit_control_group(&self, name: &str) -> Result<Option<String>, SandboxError>
    {
        match self
            .unit_property(name, SERVICE_INTERFACE, "ControlGroup")
            .await?
        {
            Some(value) => Ok(Some(String::try_from(&*value)?).filter(|group| !group.is_empty())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn cpu_masks_set_one_bit_per_cpu()
    {
        assert_eq!(cpu_mask(&[0, 1, 9]), vec![0b0000_0011, 0b0000_0010]);
        assert_eq!(cpu_mask(&[15]), vec![0, 0b1000_0000]);
        assert!(cpu_mask(&[]).is_empty());
    }

    #[test]
    fn transient_properties_carry_the_requested_settings()
    {
        let properties = TransientServiceProperties {
            description: "quarry instance abc".into(),
            slice: Some("quarry.slice".into()),
            kill_mode: Some("control-group".into()),
            cpu_quota_per_sec_usec: Some(2_000_000),
            memory_max: Some(1 << 30),
            allowed_cpus: Some(vec![2, 3]),
            exec_stop_post: vec![vec!["/bin/true".into()]],
            ..Default::default()
        };
        let encoded = properties
            .to_dbus(&["/bin/sleep".to_string(), "10".to_string()])
            .unwrap();
        let names: Vec<&str> = encoded.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Description",
                "ExecStart",
                "Restart",
                "Slice",
                "KillMode",
                "CPUQuotaPerSecUSec",
                "MemoryMax",
                "AllowedCPUs",
                "ExecStopPost"
            ]
        );
        let restart = &encoded[2].1;
        assert_eq!(String::try_from(restart).unwrap(), "no");
        assert_eq!(encoded[1].1.value_signature().to_string(), "a(sasb)");
        assert_eq!(encoded[7].1.value_signature().to_string(), "ay");
        assert_eq!(u64::try_from(&encoded[5].1).unwrap(), 2_000_000);
    }

    #[test]
    fn empty_command_line_is_rejected()
    {
        assert!(TransientServiceProperties::default().to_dbus(&[]).is_err());
    }

    #[tokio::test]
    #[ignore = "needs root and a systemd system bus"]
    async fn transient_unit_starts_and_stops()
    {
        let systemd = Systemd::connect().await.unwrap();
        let name = format!("quarry-sandbox-test-{}.service", std::process::id());
        let properties = TransientServiceProperties {
            description: "quarry sandbox systemd test".into(),
            kill_mode: Some("control-group".into()),
            cpu_quota_per_sec_usec: Some(500_000),
            ..Default::default()
        };
        systemd
            .start_transient_service(
                &name,
                &["/bin/sleep".to_string(), "300".to_string()],
                &properties,
            )
            .await
            .unwrap();
        let mut state = None;
        for _ in 0..100
        {
            state = systemd.unit_active_state(&name).await.unwrap();
            if state.as_deref() == Some("active")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(state.as_deref(), Some("active"));
        let pid = systemd.unit_main_pid(&name).await.unwrap().unwrap();
        assert!(pid > 1);
        let group = systemd.unit_control_group(&name).await.unwrap().unwrap();
        assert!(group.ends_with(&name));
        let quota = std::fs::read_to_string(format!("/sys/fs/cgroup{group}/cpu.max")).unwrap();
        assert_eq!(quota.trim(), "50000 100000");
        systemd.kill_unit(&name, Signal::SIGKILL).await.unwrap();
        for _ in 0..100
        {
            state = systemd.unit_active_state(&name).await.unwrap();
            if !matches!(state.as_deref(), Some("active") | Some("deactivating"))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        systemd.stop_unit(&name).await.unwrap();
        systemd.reset_failed_unit(&name).await.unwrap();
        for _ in 0..100
        {
            state = systemd.unit_active_state(&name).await.unwrap();
            if state.is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(state, None);
        assert_eq!(systemd.unit_main_pid(&name).await.unwrap(), None);
        systemd.reset_failed_unit(&name).await.unwrap();
        systemd.stop_unit(&name).await.unwrap();
    }
}
