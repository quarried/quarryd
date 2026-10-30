use anyhow::{Context, bail};
use std::net::SocketAddr;
use std::path::PathBuf;
use stub_control_plane::{StubConfig, StubControlPlane, TestPki};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: stub-control-plane [--listen ADDR] [--pki-dir DIR] [--join-token TOKEN] [--lease-ttl-ms MS]";

struct Args
{
    listen: SocketAddr,
    pki_dir: PathBuf,
    join_token: String,
    lease_ttl_ms: u64,
}

fn parse_args() -> anyhow::Result<Args>
{
    let mut args = Args {
        listen: SocketAddr::from(([127, 0, 0, 1], 8443)),
        pki_dir: PathBuf::from("stub-pki"),
        join_token: String::new(),
        lease_ttl_ms: 60_000,
    };
    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next()
    {
        if flag == "--help" || flag == "-h"
        {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let value = raw
            .next()
            .with_context(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str()
        {
            "--listen" =>
            {
                args.listen = value
                    .parse()
                    .with_context(|| format!("invalid --listen {value}"))?
            }
            "--pki-dir" => args.pki_dir = PathBuf::from(value),
            "--join-token" => args.join_token = value,
            "--lease-ttl-ms" =>
            {
                args.lease_ttl_ms = value
                    .parse()
                    .with_context(|| format!("invalid --lease-ttl-ms {value}"))?
            }
            _ => bail!("unknown flag {flag}\n{USAGE}"),
        }
    }
    Ok(args)
}

fn load_or_generate_pki(args: &Args) -> anyhow::Result<TestPki>
{
    if TestPki::exists_in(&args.pki_dir)
    {
        return TestPki::read_from(&args.pki_dir)
            .with_context(|| format!("reading PKI from {}", args.pki_dir.display()));
    }
    let listen_ip = args.listen.ip().to_string();
    let mut names = vec!["localhost", "127.0.0.1", "::1"];
    if !args.listen.ip().is_unspecified() && !names.contains(&listen_ip.as_str())
    {
        names.push(&listen_ip);
    }
    let pki = TestPki::generate(&names)?;
    pki.write_to(&args.pki_dir)
        .with_context(|| format!("writing PKI to {}", args.pki_dir.display()))?;
    tracing::info!(dir = %args.pki_dir.display(), "generated PKI");
    Ok(pki)
}

#[tokio::main]
async fn main() -> anyhow::Result<()>
{
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = parse_args()?;
    let pki = load_or_generate_pki(&args)?;
    let stub = StubControlPlane::start(StubConfig {
        listen: args.listen,
        pki,
        join_token: args.join_token,
        lease_ttl_ms: args.lease_ttl_ms,
        auto_grant_leases: true,
    })
    .await?;
    tracing::info!(endpoint = %stub.endpoint(), ca = %args.pki_dir.join("ca.pem").display(), "serving");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
