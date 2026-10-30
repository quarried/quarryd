macro_rules! log {
    ($($argument:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "quarry-guest-agent: {}", format_args!($($argument)*));
    }};
}

mod agent;
mod channel;
#[cfg(target_os = "linux")]
mod init;
mod output;
mod probe;
mod secrets;
mod server;
mod snapshot;

use std::ffi::OsString;
use std::path::PathBuf;

use guest_proto::{TRANSPORT_ENV, Transport};

const EXIT_OK: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;

const READY_PATTERN_ENV: &str = "QUARRY_READY_PATTERN";
const DEFAULT_READY_PATTERN: &str = "Done (";

struct Settings
{
    transport: Transport,
    ready_pattern: String,
    secrets_override: Option<PathBuf>,
    vm_init: bool,
}

pub async fn run() -> i32
{
    let is_init = cfg!(target_os = "linux") && std::process::id() == 1;
    let transport = match parse_transport(std::env::var_os(TRANSPORT_ENV))
    {
        Ok(transport) => transport,
        Err(message) =>
        {
            log!("{message}");
            return finish(EXIT_USAGE, is_init);
        }
    };
    let vm_init = is_init && matches!(transport, Transport::Vsock { .. });
    #[cfg(target_os = "linux")]
    if vm_init
    {
        init::stop_vm_on_panic();
        if let Err(message) = init::mount_vm_filesystems(
            std::path::Path::new("/"),
            std::path::Path::new(init::DATA_DEVICE),
        )
        {
            log!("{message}");
            return finish(EXIT_FAILURE, true);
        }
    }
    let settings = Settings {
        transport,
        ready_pattern: ready_pattern(std::env::var(READY_PATTERN_ENV).ok()),
        secrets_override: std::env::var_os(secrets::SECRETS_DIR_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        vm_init,
    };
    let code = agent::run(settings).await;
    finish(code, vm_init)
}

fn finish(code: i32, stop_vm: bool) -> i32
{
    #[cfg(target_os = "linux")]
    if stop_vm
    {
        init::stop_vm();
    }
    #[cfg(not(target_os = "linux"))]
    let _ = stop_vm;
    code
}

fn parse_transport(value: Option<OsString>) -> Result<Transport, String>
{
    let value = value.ok_or_else(|| format!("{TRANSPORT_ENV} is not set"))?;
    let text = value
        .to_str()
        .ok_or_else(|| format!("{TRANSPORT_ENV} is not valid UTF-8"))?;
    let transport: Transport = text
        .parse()
        .map_err(|error| format!("{TRANSPORT_ENV}: {error}"))?;
    if matches!(transport, Transport::Vsock { .. }) && !cfg!(target_os = "linux")
    {
        return Err(format!("{TRANSPORT_ENV}: vsock is only available on Linux"));
    }
    Ok(transport)
}

fn ready_pattern(value: Option<String>) -> String
{
    value
        .filter(|pattern| !pattern.is_empty())
        .unwrap_or_else(|| DEFAULT_READY_PATTERN.to_owned())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn unix_transport_is_parsed()
    {
        assert_eq!(
            parse_transport(Some("unix:/run/quarry/agent.sock".into())),
            Ok(Transport::Unix(PathBuf::from("/run/quarry/agent.sock")))
        );
    }

    #[test]
    fn vsock_transport_is_linux_only()
    {
        let parsed = parse_transport(Some("vsock:5252".into()));
        if cfg!(target_os = "linux")
        {
            assert_eq!(parsed, Ok(Transport::Vsock { port: 5252 }));
        }
        else
        {
            assert!(parsed.unwrap_err().contains("only available on Linux"));
        }
    }

    #[test]
    fn missing_or_invalid_transport_is_rejected()
    {
        assert!(parse_transport(None).unwrap_err().contains("is not set"));
        for value in ["", "tcp:1.2.3.4:5", "unix:relative", "vsock:x"]
        {
            assert!(parse_transport(Some(value.into())).is_err(), "{value:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_transport_is_rejected()
    {
        use std::os::unix::ffi::OsStringExt;
        let value = OsString::from_vec(vec![b'u', b'n', 0xff]);
        assert!(parse_transport(Some(value)).unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn ready_pattern_defaults_and_overrides()
    {
        assert_eq!(ready_pattern(None), "Done (");
        assert_eq!(ready_pattern(Some(String::new())), "Done (");
        assert_eq!(
            ready_pattern(Some("Server started".into())),
            "Server started"
        );
    }
}
