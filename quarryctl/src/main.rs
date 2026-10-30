mod console;
mod metrics;
mod report;
#[cfg(test)]
mod tests;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use store::Store;

const DEFAULT_DB: &str = "/var/lib/quarryd/quarryd.db";
const DEFAULT_METRICS: &str = "127.0.0.1:9478";
const FOLLOW_INTERVAL: Duration = Duration::from_millis(500);

const USAGE: &str = "\
usage: quarryctl [--db <path>] <command>

Read-only view of the local quarryd state.

commands:
  list [--json]                                 list instances
  show <id> [--json]                            show one instance and its decoded spec
  console <id> [--tail <bytes>] [--follow]      print the console ring
  diagnostics [--metrics <addr>]                dump state and metrics as JSON
  help                                          print this help

options:
  --db <path>        SQLite database (default /var/lib/quarryd/quarryd.db)
  --metrics <addr>   Prometheus endpoint to scrape (default 127.0.0.1:9478)
";

#[derive(Debug, PartialEq, Eq)]
enum Command
{
    List
    {
        json: bool,
    },
    Show
    {
        id: String,
        json: bool,
    },
    Console
    {
        id: String,
        tail: Option<usize>,
        follow: bool,
    },
    Diagnostics
    {
        metrics: String,
    },
    Help,
}

#[derive(Debug, PartialEq, Eq)]
struct Invocation
{
    db: PathBuf,
    command: Command,
}

fn main() -> ExitCode
{
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let invocation = match parse_arguments(&arguments)
    {
        Ok(invocation) => invocation,
        Err(message) =>
        {
            eprintln!("quarryctl: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match execute(&invocation, &mut out)
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) =>
        {
            let _ = out.flush();
            eprintln!("quarryctl: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn parse_arguments(arguments: &[String]) -> Result<Invocation, String>
{
    let mut db = PathBuf::from(DEFAULT_DB);
    let mut json = false;
    let mut follow = false;
    let mut tail = None;
    let mut metrics = None;
    let mut positional = Vec::new();
    let mut remaining = arguments.iter();
    while let Some(argument) = remaining.next()
    {
        let mut value = |flag: &str| {
            remaining
                .next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match argument.as_str()
        {
            "--db" => db = PathBuf::from(value("--db")?),
            "--json" => json = true,
            "--follow" | "-f" => follow = true,
            "--tail" =>
            {
                let bytes = value("--tail")?;
                tail = Some(
                    bytes
                        .parse::<usize>()
                        .map_err(|_| format!("--tail needs a byte count, got {bytes:?}"))?,
                );
            }
            "--metrics" => metrics = Some(value("--metrics")?),
            "--help" | "-h" =>
            {
                return Ok(Invocation {
                    db,
                    command: Command::Help,
                });
            }
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            word => positional.push(word.to_owned()),
        }
    }
    let mut words = positional.into_iter();
    let name = words.next().ok_or("missing command")?;
    let mut id = |command: &str| {
        words
            .next()
            .ok_or_else(|| format!("{command} needs an instance id"))
    };
    let command = match name.as_str()
    {
        "list" => Command::List { json },
        "show" => Command::Show {
            id: id("show")?,
            json,
        },
        "console" => Command::Console {
            id: id("console")?,
            tail,
            follow,
        },
        "diagnostics" => Command::Diagnostics {
            metrics: metrics
                .clone()
                .unwrap_or_else(|| DEFAULT_METRICS.to_owned()),
        },
        "help" => Command::Help,
        other => return Err(format!("unknown command {other:?}")),
    };
    if let Some(extra) = words.next()
    {
        return Err(format!("unexpected argument {extra:?}"));
    }
    let misplaced = match &command
    {
        Command::List { .. } | Command::Show { .. } => flag_misuse(&[
            ("--tail", tail.is_some()),
            ("--follow", follow),
            ("--metrics", metrics.is_some()),
        ]),
        Command::Console { .. } =>
        {
            flag_misuse(&[("--json", json), ("--metrics", metrics.is_some())])
        }
        Command::Diagnostics { .. } => flag_misuse(&[
            ("--json", json),
            ("--tail", tail.is_some()),
            ("--follow", follow),
        ]),
        Command::Help => None,
    };
    if let Some(flag) = misplaced
    {
        return Err(format!("{flag} does not apply to {name}"));
    }
    Ok(Invocation { db, command })
}

fn flag_misuse(flags: &[(&'static str, bool)]) -> Option<&'static str>
{
    flags.iter().find(|(_, used)| *used).map(|(flag, _)| *flag)
}

fn open_store(path: &Path) -> anyhow::Result<Store>
{
    Store::open_read_only(path).with_context(|| format!("cannot open {}", path.display()))
}

fn execute(invocation: &Invocation, out: &mut impl Write) -> anyhow::Result<()>
{
    match &invocation.command
    {
        Command::Help =>
        {
            out.write_all(USAGE.as_bytes())?;
        }
        Command::List { json } =>
        {
            report::list(&open_store(&invocation.db)?, *json, out)?;
        }
        Command::Show { id, json } =>
        {
            report::show(&open_store(&invocation.db)?, id, *json, out)?;
        }
        Command::Console { id, tail, follow } =>
        {
            let path = console::console_path(&open_store(&invocation.db)?, id)?;
            let mut previous = console::print(&path, *tail, out)?;
            if *follow
            {
                loop
                {
                    std::thread::sleep(FOLLOW_INTERVAL);
                    previous = console::print_new(&path, &previous, out)?;
                }
            }
        }
        Command::Diagnostics { metrics } =>
        {
            let store = open_store(&invocation.db)?;
            report::diagnostics(&store, &invocation.db, &metrics::scrape(metrics), out)?;
        }
    }
    out.flush()?;
    Ok(())
}
