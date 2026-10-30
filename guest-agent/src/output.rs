use guest_proto::{MAX_LOG_LINE_BYTES, MAX_SERVER_VERSION_BYTES};

const VERSION_MARKER: &str = "Starting minecraft server version ";
const PLAYERS_MARKER: &str = "There are ";
const TPS_MARKER: &str = "TPS from last 1m, 5m, 15m:";
const MSPT_HEADER: &str = "Server tick times";

pub fn sanitize(raw: &[u8]) -> String
{
    single_line(&String::from_utf8_lossy(raw), MAX_LOG_LINE_BYTES)
}

pub fn single_line(text: &str, max_bytes: usize) -> String
{
    let mut clean = String::with_capacity(text.len().min(max_bytes));
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next()
    {
        if c == '\u{1b}'
        {
            skip_escape(&mut chars);
            continue;
        }
        if c.is_control() && c != '\t'
        {
            continue;
        }
        if clean.len() + c.len_utf8() > max_bytes
        {
            break;
        }
        clean.push(c);
    }
    clean
}

fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>)
{
    match chars.peek()
    {
        Some('[') =>
        {
            chars.next();
            for c in chars.by_ref()
            {
                if ('\u{40}'..='\u{7e}').contains(&c)
                {
                    break;
                }
            }
        }
        Some(']') =>
        {
            chars.next();
            while let Some(c) = chars.next()
            {
                if c == '\u{7}'
                {
                    break;
                }
                if c == '\u{1b}'
                {
                    chars.next();
                    break;
                }
            }
        }
        Some(_) =>
        {
            chars.next();
        }
        None =>
        {}
    }
}

fn without_color_codes(line: &str) -> String
{
    let mut plain = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next()
    {
        if c == '§'
        {
            chars.next();
            continue;
        }
        plain.push(c);
    }
    plain
}

fn leading_number(text: &str) -> Option<f64>
{
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let digits: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits.parse().ok().filter(|value: &f64| value.is_finite())
}

pub fn server_version(line: &str) -> Option<String>
{
    let start = line.find(VERSION_MARKER)? + VERSION_MARKER.len();
    let version = line[start..].split_whitespace().next()?;
    let version = single_line(version, MAX_SERVER_VERSION_BYTES);
    (!version.is_empty()).then_some(version)
}

pub fn players(line: &str) -> Option<u32>
{
    let plain = without_color_codes(line);
    if !plain.contains("players online")
    {
        return None;
    }
    let start = plain.find(PLAYERS_MARKER)? + PLAYERS_MARKER.len();
    let digits: String = plain[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

pub fn tps(line: &str) -> Option<f64>
{
    let plain = without_color_codes(line);
    let start = plain.find(TPS_MARKER)? + TPS_MARKER.len();
    let first = plain[start..].split(',').next()?;
    leading_number(first)
}

pub fn is_mspt_header(line: &str) -> bool
{
    line.contains(MSPT_HEADER)
}

pub fn mspt(line: &str) -> Option<f64>
{
    let plain = without_color_codes(line);
    if !plain.contains('/')
    {
        return None;
    }
    let average = plain.split('/').next()?.split_whitespace().last()?;
    leading_number(average)
}

pub fn is_unknown_command(line: &str) -> bool
{
    line.contains("Unknown or incomplete command") || line.contains("Unknown command")
}

pub fn is_error_marker(line: &str) -> bool
{
    line.contains("<--[HERE]")
}

pub fn is_save_complete(line: &str) -> bool
{
    line.contains("Saved the game")
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn vm_rss_bytes(status: &str) -> Option<u64>
{
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: u64 = line
        .trim_start_matches("VmRSS:")
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn sanitize_strips_escapes_and_control_characters()
    {
        assert_eq!(
            sanitize(b"\x1b[31mred\x1b[0m and \x1b]0;title\x07plain\r"),
            "red and plain"
        );
        assert_eq!(sanitize(b"tab\tkept\x00\x08\x7f"), "tab\tkept");
        assert_eq!(sanitize(b"bad \xff utf8"), "bad \u{fffd} utf8");
        assert_eq!(sanitize(b"c1 \xc2\x85 gone"), "c1  gone");
    }

    #[test]
    fn sanitize_truncates_on_a_character_boundary()
    {
        let long = "é".repeat(MAX_LOG_LINE_BYTES);
        let clean = sanitize(long.as_bytes());
        assert!(clean.len() <= MAX_LOG_LINE_BYTES);
        assert_eq!(clean.len(), MAX_LOG_LINE_BYTES);
        let odd = format!("a{}", "é".repeat(MAX_LOG_LINE_BYTES));
        let clean = sanitize(odd.as_bytes());
        assert_eq!(clean.len(), MAX_LOG_LINE_BYTES - 1);
    }

    #[test]
    fn single_line_respects_the_limit()
    {
        assert_eq!(single_line("abc\ndef", 4), "abcd");
        assert_eq!(single_line("", 4), "");
    }

    #[test]
    fn version_is_parsed_from_the_startup_line()
    {
        assert_eq!(
            server_version("[12:00:00 INFO]: Starting minecraft server version 1.21.4").as_deref(),
            Some("1.21.4")
        );
        assert_eq!(
            server_version("Starting minecraft server version 1.20.1 (Paper)").as_deref(),
            Some("1.20.1")
        );
        assert_eq!(server_version("Starting minecraft server version "), None);
        assert_eq!(server_version("Loading libraries"), None);
        let long = format!("Starting minecraft server version {}", "9".repeat(300));
        assert_eq!(
            server_version(&long).unwrap().len(),
            MAX_SERVER_VERSION_BYTES
        );
    }

    #[test]
    fn players_are_parsed_from_vanilla_and_paper_list_output()
    {
        assert_eq!(
            players(
                "[12:00:00] [Server thread/INFO]: There are 3 of a max of 20 players online: a, b, c"
            ),
            Some(3)
        );
        assert_eq!(
            players("[12:00:00 INFO]: There are 0 out of maximum 20 players online."),
            Some(0)
        );
        assert_eq!(
            players("§6There are §c12§6 out of maximum §c50§6 players online."),
            Some(12)
        );
        assert_eq!(players("There are many reasons"), None);
        assert_eq!(players("players online"), None);
    }

    #[test]
    fn tps_is_parsed_from_paper_output()
    {
        assert_eq!(
            tps("[12:00:00 INFO]: TPS from last 1m, 5m, 15m: 20.0, 20.0, 19.98"),
            Some(20.0)
        );
        assert_eq!(
            tps("TPS from last 1m, 5m, 15m: *19.5, 20.0, 20.0"),
            Some(19.5)
        );
        assert_eq!(
            tps("§6TPS from last 1m, 5m, 15m: §a*20.0§r, §a20.0"),
            Some(20.0)
        );
        assert_eq!(tps("TPS from last 1m, 5m, 15m: n/a"), None);
        assert_eq!(tps("Unknown command"), None);
    }

    #[test]
    fn mspt_is_parsed_from_paper_output()
    {
        assert!(is_mspt_header(
            "[12:00:00 INFO]: Server tick times (avg/min/max) from last 5s, 10s, 1m:"
        ));
        assert_eq!(
            mspt("[12:00:00 INFO]: ◴ 1.2/0.8/3.4, 1.1/0.7/3.9, 1.0/0.6/5.2"),
            Some(1.2)
        );
        assert_eq!(mspt("§a12.5§7/§a3.0§7/§a40.1"), Some(12.5));
        assert_eq!(mspt("no numbers here"), None);
    }

    #[test]
    fn unknown_commands_and_markers_are_recognized()
    {
        assert!(is_unknown_command(
            "[Server thread/INFO]: Unknown or incomplete command, see below for error"
        ));
        assert!(is_unknown_command(
            "Unknown command. Type \"/help\" for help."
        ));
        assert!(is_error_marker("tps<--[HERE]"));
        assert!(!is_unknown_command(
            "There are 0 of a max of 20 players online:"
        ));
    }

    #[test]
    fn save_completion_is_recognized()
    {
        assert!(is_save_complete("[Server thread/INFO]: Saved the game"));
        assert!(!is_save_complete(
            "Saving the game (this may take a moment!)"
        ));
    }

    #[test]
    fn resident_memory_is_read_from_proc_status()
    {
        let status = "Name:\tquarry-server\nVmPeak:\t 9000 kB\nVmRSS:\t  204800 kB\nThreads:\t40\n";
        assert_eq!(vm_rss_bytes(status), Some(204_800 * 1024));
        assert_eq!(vm_rss_bytes("Name:\tkthreadd\n"), None);
        assert_eq!(vm_rss_bytes("VmRSS:\tlots kB\n"), None);
    }
}
