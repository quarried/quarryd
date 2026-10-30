use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use quarryd::agent::Agent;
use quarryd::config::Config;
use quarryd::update::{UpdatePaths, roll_back};

const USAGE: &str = "usage:
  quarryd run --config <path>
  quarryd console-ring --path <path> --max-bytes <n>
  quarryd rollback --binary <path> --marker <path> --delay-secs <n> --service <unit>";

fn flag(arguments: &[String], name: &str) -> Option<String>
{
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}

fn required(arguments: &[String], name: &str) -> Result<String>
{
    flag(arguments, name).with_context(|| format!("missing {name}\n{USAGE}"))
}

fn main() -> Result<()>
{
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("run");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    match command
    {
        "run" =>
        {
            let path = flag(&arguments, "--config")
                .unwrap_or_else(|| "/etc/quarryd/quarryd.toml".to_string());
            let config = Config::load(&PathBuf::from(path))?;
            quarryd::logging::init(&config.node_id);
            runtime.block_on(run(config))
        }
        "console-ring" =>
        {
            let path = PathBuf::from(required(&arguments, "--path")?);
            let max_bytes: u64 = required(&arguments, "--max-bytes")?
                .parse()
                .context("--max-bytes must be a number")?;
            runtime.block_on(async {
                sandbox::console::run_console_writer(&path, max_bytes, tokio::io::stdin())
                    .await
                    .context("console writer failed")
            })
        }
        "rollback" =>
        {
            let binary = PathBuf::from(required(&arguments, "--binary")?);
            let marker = PathBuf::from(required(&arguments, "--marker")?);
            let delay: u64 = required(&arguments, "--delay-secs")?
                .parse()
                .context("--delay-secs must be a number")?;
            let service = required(&arguments, "--service")?;
            runtime.block_on(rollback(
                binary,
                marker,
                Duration::from_secs(delay),
                service,
            ))
        }
        "help" | "--help" | "-h" =>
        {
            println!("{USAGE}");
            Ok(())
        }
        other => bail!("unknown command {other}\n{USAGE}"),
    }
}

async fn run(config: Config) -> Result<()>
{
    let agent = Agent::start(config).await?;
    let stop = agent.stop_handle();
    tokio::spawn(async move {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                Ok(signal) => signal,
                Err(error) =>
                {
                    tracing::error!(error = %error, "cannot install SIGTERM handler");
                    return;
                }
            };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        tracing::info!("termination signal received; instances keep running");
        stop.send_replace(true);
    });
    agent.wait().await
}

async fn rollback(binary: PathBuf, marker: PathBuf, delay: Duration, service: String)
-> Result<()>
{
    tokio::time::sleep(delay).await;
    let state_dir = marker.parent().map(PathBuf::from).unwrap_or_default();
    let mut paths = UpdatePaths::new(binary, &state_dir);
    paths.marker = marker;
    if !roll_back(&paths)?
    {
        println!("update confirmed; nothing to roll back");
        return Ok(());
    }
    println!("new agent version did not connect in time; restored the previous binary");
    let systemd = sandbox::unit_bus::UnitBus::connect()
        .await
        .context("connecting to systemd")?;
    systemd
        .restart_unit(&service)
        .await
        .with_context(|| format!("restarting {service}"))?;
    Ok(())
}
