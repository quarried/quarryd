use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use crate::{output, server};

pub const PORT_ENV: &str = "QUARRY_PORT";
pub const WORLD_SEED_ENV: &str = "QUARRY_WORLD_SEED";
const CONFIG_FILE: &str = "quarry.toml";
const WORLD_DIR: &str = "world";
const LEVEL_FILE: &str = "level.dat";
const METRICS_DIR: &str = "quarry-metrics";
const DEFAULT_PORT: u16 = 25565;
const PREGENERATE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_DETAIL_BYTES: usize = 512;

pub fn default_command(binary: &str, data_dir: &Path) -> Vec<String>
{
    vec![
        binary.to_owned(),
        "run".to_owned(),
        "--config".to_owned(),
        data_dir.join(CONFIG_FILE).display().to_string(),
    ]
}

pub async fn prepare(
    binary: &str,
    data_dir: &Path,
    instance_id: &str,
    env: &HashMap<String, String>,
    memory_mib: u64,
    secrets_dir: &Path,
) -> Result<(), String>
{
    server::check_executable(binary).map_err(|error| error.to_string())?;
    let written = write_config_if_missing(data_dir, env).map_err(|error| {
        format!(
            "cannot write {}: {error}",
            data_dir.join(CONFIG_FILE).display()
        )
    })?;
    let world = data_dir.join(WORLD_DIR);
    if !written && !manages_world(data_dir, &world)
    {
        return Ok(());
    }
    if world.join(LEVEL_FILE).exists()
    {
        return Ok(());
    }
    let seed = setting(env, WORLD_SEED_ENV)
        .filter(|seed| !seed.is_empty())
        .unwrap_or_else(|| instance_id.to_owned());
    let mut command = server::base_command(binary, env, memory_mib, secrets_dir);
    command
        .arg("pregenerate")
        .arg("--world")
        .arg(&world)
        .arg("--seed")
        .arg(&seed)
        .args(["--side", "1"])
        .arg("--metrics")
        .arg(data_dir.join(METRICS_DIR))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    log!("pregenerating a world at {}", world.display());
    let child = command
        .spawn()
        .map_err(|error| format!("cannot start world pregeneration with {binary}: {error}"))?;
    let output = match tokio::time::timeout(PREGENERATE_TIMEOUT, child.wait_with_output()).await
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(format!("world pregeneration failed: {error}")),
        Err(_) =>
        {
            return Err(format!(
                "world pregeneration did not finish within {} s",
                PREGENERATE_TIMEOUT.as_secs()
            ));
        }
    };
    if !output.status.success()
    {
        let detail = last_line(&output.stderr)
            .or_else(|| last_line(&output.stdout))
            .unwrap_or_default();
        return Err(format!(
            "world pregeneration exited with code {}: {detail}",
            server::exit_code(output.status)
        ));
    }
    if !world.join(LEVEL_FILE).exists()
    {
        return Err(format!(
            "world pregeneration did not create {}",
            world.join(LEVEL_FILE).display()
        ));
    }
    log!("pregenerated a world at {}", world.display());
    Ok(())
}

fn setting(env: &HashMap<String, String>, name: &str) -> Option<String>
{
    env.get(name).cloned().or_else(|| std::env::var(name).ok())
}

fn port(env: &HashMap<String, String>) -> u16
{
    let Some(value) = setting(env, PORT_ENV)
    else
    {
        return DEFAULT_PORT;
    };
    match value.trim().parse::<u16>()
    {
        Ok(port) if port != 0 => port,
        _ =>
        {
            log!("ignoring invalid {PORT_ENV} {value:?}; using {DEFAULT_PORT}");
            DEFAULT_PORT
        }
    }
}

fn write_config_if_missing(data_dir: &Path, env: &HashMap<String, String>) -> io::Result<bool>
{
    let path = data_dir.join(CONFIG_FILE);
    if fs::symlink_metadata(&path).is_ok()
    {
        return Ok(false);
    }
    let text = format!(
        "listen = \"0.0.0.0\"\nport = {}\n{}",
        port(env),
        world_path_line(&data_dir.join(WORLD_DIR))
    );
    write_atomically(&path, text.as_bytes())?;
    log!("wrote {}", path.display());
    Ok(true)
}

fn world_path_line(world: &Path) -> String
{
    format!(
        "world_path = {}\n",
        toml_string(&world.display().to_string())
    )
}

fn manages_world(data_dir: &Path, world: &Path) -> bool
{
    fs::read_to_string(data_dir.join(CONFIG_FILE))
        .map(|text| text.contains(&world_path_line(world)))
        .unwrap_or(false)
}

fn toml_string(value: &str) -> String
{
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars()
    {
        match c
        {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() => quoted.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()>
{
    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut file = File::create(&temporary)?;
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    if let Err(error) = written.and_then(|()| fs::rename(&temporary, path))
    {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    File::open(parent)?.sync_all()
}

fn last_line(bytes: &[u8]) -> Option<String>
{
    String::from_utf8_lossy(bytes)
        .lines()
        .rev()
        .map(|line| output::single_line(line.trim(), MAX_DETAIL_BYTES))
        .find(|line| !line.is_empty())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const FAKE_PREGENERATE: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$FAKE_ARGS_FILE"
echo "memory=$QUARRY_MEMORY_MIB" >> "$FAKE_ARGS_FILE"
if [ -n "$FAKE_FAIL" ]; then echo "progress" ; echo "error: bad seed $FAKE_FAIL" >&2; exit 4; fi
mkdir -p "$3" && : > "$3/level.dat"
"#;

    struct Scratch
    {
        dir: tempfile::TempDir,
        binary: String,
        args_file: std::path::PathBuf,
    }

    fn scratch() -> Scratch
    {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("quarry-server");
        fs::write(&binary, FAKE_PREGENERATE).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let args_file = dir.path().join("args");
        Scratch {
            binary: binary.display().to_string(),
            args_file,
            dir,
        }
    }

    impl Scratch
    {
        fn data(&self) -> std::path::PathBuf
        {
            let data = self.dir.path().join("data");
            fs::create_dir_all(&data).unwrap();
            data
        }

        fn env(&self, extra: &[(&str, &str)]) -> HashMap<String, String>
        {
            let mut env = HashMap::from([(
                "FAKE_ARGS_FILE".to_owned(),
                self.args_file.display().to_string(),
            )]);
            for (name, value) in extra
            {
                env.insert(name.to_string(), value.to_string());
            }
            env
        }

        async fn prepare(&self, env: &HashMap<String, String>) -> Result<(), String>
        {
            prepare(
                &self.binary,
                &self.data(),
                "inst-7",
                env,
                2048,
                self.dir.path(),
            )
            .await
        }

        fn arguments(&self) -> Vec<String>
        {
            fs::read_to_string(&self.args_file)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    #[test]
    fn the_default_command_runs_the_binary_with_the_data_config()
    {
        assert_eq!(
            default_command(guest_proto::SERVER_BINARY_PATH, Path::new("/data")),
            vec![
                "/usr/local/bin/quarry-server",
                "run",
                "--config",
                "/data/quarry.toml"
            ]
        );
    }

    #[test]
    fn a_fresh_config_uses_the_default_port_and_world_path()
    {
        let scratch = scratch();
        let data = scratch.data();
        assert!(write_config_if_missing(&data, &HashMap::new()).unwrap());
        let text = fs::read_to_string(data.join("quarry.toml")).unwrap();
        assert_eq!(
            text,
            format!(
                "listen = \"0.0.0.0\"\nport = 25565\nworld_path = \"{}\"\n",
                data.join("world").display()
            )
        );
        let leftovers: Vec<_> = fs::read_dir(&data)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("quarry.toml")]);
    }

    #[test]
    fn the_config_port_comes_from_quarry_port_when_valid()
    {
        let scratch = scratch();
        let data = scratch.data();
        let env = HashMap::from([(PORT_ENV.to_owned(), "25600".to_owned())]);
        write_config_if_missing(&data, &env).unwrap();
        assert!(
            fs::read_to_string(data.join("quarry.toml"))
                .unwrap()
                .contains("port = 25600\n")
        );
        for invalid in ["0", "70000", "http", ""]
        {
            let env = HashMap::from([(PORT_ENV.to_owned(), invalid.to_owned())]);
            assert_eq!(port(&env), DEFAULT_PORT, "{invalid:?}");
        }
    }

    #[test]
    fn an_existing_config_is_left_alone()
    {
        let scratch = scratch();
        let data = scratch.data();
        fs::write(data.join("quarry.toml"), "port = 1\n").unwrap();
        assert!(!write_config_if_missing(&data, &HashMap::new()).unwrap());
        assert_eq!(
            fs::read_to_string(data.join("quarry.toml")).unwrap(),
            "port = 1\n"
        );
    }

    #[test]
    fn toml_strings_are_escaped()
    {
        assert_eq!(toml_string("/data/world"), "\"/data/world\"");
        assert_eq!(toml_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(toml_string("\u{1}"), "\"\\u0001\"");
    }

    #[tokio::test]
    async fn a_missing_world_is_pregenerated_with_the_instance_seed()
    {
        let scratch = scratch();
        let env = scratch.env(&[]);
        scratch.prepare(&env).await.unwrap();
        let data = scratch.data();
        assert!(data.join("quarry.toml").is_file());
        assert!(data.join("world/level.dat").is_file());
        assert_eq!(
            scratch.arguments(),
            vec![
                "pregenerate".to_owned(),
                "--world".to_owned(),
                data.join("world").display().to_string(),
                "--seed".to_owned(),
                "inst-7".to_owned(),
                "--side".to_owned(),
                "1".to_owned(),
                "--metrics".to_owned(),
                data.join("quarry-metrics").display().to_string(),
                "memory=2048".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn the_world_seed_comes_from_quarry_world_seed()
    {
        let scratch = scratch();
        let env = scratch.env(&[(WORLD_SEED_ENV, "12345")]);
        scratch.prepare(&env).await.unwrap();
        assert_eq!(scratch.arguments()[4], "12345");
    }

    #[tokio::test]
    async fn an_existing_world_is_not_pregenerated_again()
    {
        let scratch = scratch();
        let data = scratch.data();
        fs::create_dir_all(data.join("world")).unwrap();
        fs::write(data.join("world/level.dat"), b"").unwrap();
        let env = scratch.env(&[("FAKE_FAIL", "would fail")]);
        scratch.prepare(&env).await.unwrap();
        assert!(data.join("quarry.toml").is_file());
        assert!(!scratch.args_file.exists());
    }

    #[tokio::test]
    async fn an_existing_config_skips_world_preparation()
    {
        let scratch = scratch();
        let data = scratch.data();
        fs::write(data.join("quarry.toml"), "world_path = \"/elsewhere\"\n").unwrap();
        let env = scratch.env(&[("FAKE_FAIL", "would fail")]);
        scratch.prepare(&env).await.unwrap();
        assert!(!scratch.args_file.exists());
        assert!(!data.join("world").exists());
    }

    #[tokio::test]
    async fn a_failed_pregeneration_is_retried_on_the_next_start()
    {
        let scratch = scratch();
        let failing = scratch.env(&[("FAKE_FAIL", "x")]);
        assert!(scratch.prepare(&failing).await.is_err());
        let data = scratch.data();
        assert!(data.join("quarry.toml").is_file());
        assert!(!data.join("world/level.dat").exists());
        scratch.prepare(&scratch.env(&[])).await.unwrap();
        assert!(data.join("world/level.dat").is_file());
    }

    #[tokio::test]
    async fn a_failed_pregeneration_reports_the_exit_code_and_last_error_line()
    {
        let scratch = scratch();
        let env = scratch.env(&[("FAKE_FAIL", "x")]);
        let error = scratch.prepare(&env).await.unwrap_err();
        assert!(error.contains("exited with code 4"), "{error}");
        assert!(error.contains("error: bad seed x"), "{error}");
    }

    #[tokio::test]
    async fn a_missing_binary_is_reported_before_anything_is_written()
    {
        let scratch = scratch();
        let data = scratch.data();
        let missing = scratch.dir.path().join("absent").display().to_string();
        let error = prepare(&missing, &data, "inst-7", &HashMap::new(), 1, &data)
            .await
            .unwrap_err();
        assert!(error.contains("is not available"), "{error}");
        assert!(!data.join("quarry.toml").exists());
    }
}
