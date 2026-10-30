use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use sandbox::SandboxRecord;
use store::Store;

pub fn console_path(store: &Store, id: &str) -> anyhow::Result<PathBuf>
{
    let row = store
        .get_instance(id)?
        .ok_or_else(|| anyhow!("instance {id} not found"))?;
    let record = row
        .sandbox_record
        .ok_or_else(|| anyhow!("instance {id} has no sandbox record yet"))?;
    let record: SandboxRecord = serde_json::from_str(&record)
        .with_context(|| format!("instance {id} has an unreadable sandbox record"))?;
    Ok(record.console_path)
}

pub fn print(path: &Path, tail: Option<usize>, out: &mut impl Write) -> anyhow::Result<Vec<u8>>
{
    let contents = sandbox::console::read_console(path)?;
    let start = tail.map_or(0, |bytes| contents.len().saturating_sub(bytes));
    out.write_all(&contents[start..])?;
    out.flush()?;
    Ok(contents)
}

pub fn print_new(path: &Path, previous: &[u8], out: &mut impl Write) -> anyhow::Result<Vec<u8>>
{
    let contents = sandbox::console::read_console(path)?;
    out.write_all(appended(previous, &contents))?;
    out.flush()?;
    Ok(contents)
}

pub fn appended<'a>(previous: &[u8], current: &'a [u8]) -> &'a [u8]
{
    if current.starts_with(previous)
    {
        return &current[previous.len()..];
    }
    for dropped in 1..previous.len()
    {
        let kept = &previous[dropped..];
        if current.starts_with(kept)
        {
            return &current[kept.len()..];
        }
    }
    current
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn growth_without_wrapping_prints_the_suffix()
    {
        assert_eq!(appended(b"abc", b"abcdef"), b"def");
        assert_eq!(appended(b"", b"abc"), b"abc");
        assert_eq!(appended(b"abc", b"abc"), b"");
    }

    #[test]
    fn a_wrapped_ring_prints_only_new_bytes()
    {
        assert_eq!(appended(b"abcdef", b"cdefgh"), b"gh");
        assert_eq!(appended(b"abcdef", b"fghijk"), b"ghijk");
    }

    #[test]
    fn a_replaced_ring_prints_everything()
    {
        assert_eq!(appended(b"abcdef", b"uvwxyz"), b"uvwxyz");
        assert_eq!(appended(b"abcdef", b""), b"");
    }
}
