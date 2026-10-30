use std::path::Path;

use crate::SandboxError;

pub(crate) fn quote(word: &str) -> String
{
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./=:@%+,".contains(&byte));
    if plain
    {
        word.to_string()
    }
    else
    {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

pub(crate) fn join(words: &[String]) -> String
{
    words
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn path_text(path: &Path) -> Result<String, SandboxError>
{
    path.to_str().map(str::to_string).ok_or_else(|| {
        SandboxError::InvalidSpec(format!("path {} is not valid UTF-8", path.display()))
    })
}

pub(crate) fn writer_argv(
    writer: &[String],
    console: &Path,
    max_bytes: u64,
) -> Result<Vec<String>, SandboxError>
{
    if writer.is_empty()
    {
        return Err(SandboxError::InvalidSpec(
            "console writer command is empty".into(),
        ));
    }
    let mut argv = writer.to_vec();
    argv.extend([
        "--path".to_string(),
        path_text(console)?,
        "--max-bytes".to_string(),
        max_bytes.to_string(),
    ]);
    Ok(argv)
}

pub(crate) fn console_script(
    setup: &[String],
    command: &[String],
    writer: &[String],
    fifo: &Path,
) -> Result<String, SandboxError>
{
    let fifo = quote(&path_text(fifo)?);
    let mut statements = vec!["set -e".to_string()];
    statements.extend(setup.iter().cloned());
    statements.push(format!("rm -f {fifo}"));
    statements.push(format!("mkfifo -m 600 {fifo}"));
    statements.push(format!(
        "( trap '' TERM INT HUP; exec {} < {fifo} ) &",
        join(writer)
    ));
    statements.push(format!("exec {} > {fifo} 2>&1", join(command)));
    Ok(statements.join("\n"))
}

#[cfg(test)]
mod tests
{
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn quoting_leaves_plain_words_and_escapes_the_rest()
    {
        assert_eq!(quote("/usr/bin/firecracker"), "/usr/bin/firecracker");
        assert_eq!(quote("--max-bytes=10"), "--max-bytes=10");
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("$(reboot)"), "'$(reboot)'");
    }

    #[tokio::test]
    async fn quoted_words_survive_the_shell()
    {
        let words = vec![
            "a b".to_string(),
            "it's".to_string(),
            "$HOME".to_string(),
            "`x`".to_string(),
        ];
        let script = format!("printf '%s\\n' {}", join(&words));
        let output = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "a b\nit's\n$HOME\n`x`\n"
        );
    }

    #[test]
    fn console_script_pipes_command_into_writer()
    {
        let writer = writer_argv(
            &["/usr/bin/quarryd".to_string(), "console-ring".to_string()],
            &PathBuf::from("/run/q/console ring"),
            4096,
        )
        .unwrap();
        let script = console_script(
            &["mkdir -p /x".to_string()],
            &[
                "/usr/bin/jailer".to_string(),
                "--id".to_string(),
                "abc".to_string(),
            ],
            &writer,
            &PathBuf::from("/run/q/console.fifo"),
        )
        .unwrap();
        assert_eq!(
            script,
            "set -e\nmkdir -p /x\nrm -f /run/q/console.fifo\nmkfifo -m 600 /run/q/console.fifo\n\
             ( trap '' TERM INT HUP; exec /usr/bin/quarryd console-ring --path '/run/q/console ring' \
             --max-bytes 4096 < /run/q/console.fifo ) &\nexec /usr/bin/jailer --id abc > /run/q/console.fifo 2>&1"
        );
    }

    #[test]
    fn empty_writer_is_rejected()
    {
        assert!(writer_argv(&[], Path::new("/x"), 1).is_err());
    }
}
