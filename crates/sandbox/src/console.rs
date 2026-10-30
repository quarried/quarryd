use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::SandboxError;
use crate::error::io;
use crate::unit::blocking;

const MAGIC: &[u8; 8] = b"QRING\0\0\x01";
const HEADER_LEN: u64 = 32;
const READ_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RingHeader
{
    capacity: u64,
    head: u64,
    len: u64,
}

impl RingHeader
{
    fn parse(bytes: &[u8]) -> Option<Self>
    {
        if bytes.len() < HEADER_LEN as usize || &bytes[..8] != MAGIC
        {
            return None;
        }
        let field = |index: usize| {
            let start = 8 + index * 8;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[start..start + 8]);
            u64::from_le_bytes(raw)
        };
        let header = Self {
            capacity: field(0),
            head: field(1),
            len: field(2),
        };
        let data_len = (bytes.len() as u64) - HEADER_LEN;
        let consistent = header.capacity > 0
            && header.head < header.capacity
            && header.len <= header.capacity
            && (header.len == header.capacity || header.head == header.len)
            && data_len >= header.len;
        consistent.then_some(header)
    }

    fn encode(&self) -> [u8; HEADER_LEN as usize]
    {
        let mut bytes = [0u8; HEADER_LEN as usize];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..16].copy_from_slice(&self.capacity.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.head.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.len.to_le_bytes());
        bytes
    }
}

fn ordered_contents(bytes: &[u8]) -> Vec<u8>
{
    match RingHeader::parse(bytes)
    {
        Some(header) =>
        {
            let data = &bytes[HEADER_LEN as usize..];
            let len = header.len as usize;
            let head = header.head as usize;
            if header.len < header.capacity
            {
                data[..len].to_vec()
            }
            else
            {
                [&data[head..len], &data[..head]].concat()
            }
        }
        None if bytes.starts_with(MAGIC) => Vec::new(),
        None => bytes.to_vec(),
    }
}

pub struct ConsoleRing
{
    file: File,
    header: RingHeader,
}

impl ConsoleRing
{
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self, SandboxError>
    {
        if max_bytes == 0
        {
            return Err(SandboxError::InvalidSpec(
                "console ring size must be at least 1 byte".into(),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o640)
            .open(path)
            .map_err(io(format!("open console ring {}", path.display())))?;
        let existing =
            std::fs::read(path).map_err(io(format!("read console ring {}", path.display())))?;
        if let Some(header) = RingHeader::parse(&existing)
            && header.capacity == max_bytes
        {
            return Ok(Self { file, header });
        }
        let contents = ordered_contents(&existing);
        let keep = &contents[contents.len().saturating_sub(max_bytes as usize)..];
        let mut ring = Self {
            file,
            header: RingHeader {
                capacity: max_bytes,
                head: 0,
                len: 0,
            },
        };
        ring.file
            .set_len(0)
            .map_err(io(format!("truncate console ring {}", path.display())))?;
        ring.write_header()?;
        ring.append(keep)?;
        Ok(ring)
    }

    pub fn append(&mut self, data: &[u8]) -> Result<(), SandboxError>
    {
        let capacity = self.header.capacity as usize;
        let data = &data[data.len().saturating_sub(capacity)..];
        if data.is_empty()
        {
            return Ok(());
        }
        let head = self.header.head as usize;
        let first = data.len().min(capacity - head);
        self.write_at(&data[..first], HEADER_LEN + head as u64)?;
        if first < data.len()
        {
            self.write_at(&data[first..], HEADER_LEN)?;
        }
        self.header.head = ((head + data.len()) % capacity) as u64;
        self.header.len = (self.header.len + data.len() as u64).min(self.header.capacity);
        self.write_header()
    }

    fn write_header(&self) -> Result<(), SandboxError>
    {
        self.write_at(&self.header.encode(), 0)
    }

    fn write_at(&self, data: &[u8], offset: u64) -> Result<(), SandboxError>
    {
        self.file
            .write_all_at(data, offset)
            .map_err(io("write console ring"))
    }
}

pub async fn run_console_writer<R: AsyncRead + Unpin>(
    path: &Path,
    max_bytes: u64,
    mut input: R,
) -> Result<(), SandboxError>
{
    let ring_path = path.to_path_buf();
    let mut ring = blocking(move || ConsoleRing::open(&ring_path, max_bytes)).await?;
    let mut buffer = vec![0u8; READ_CHUNK];
    loop
    {
        let read = input
            .read(&mut buffer)
            .await
            .map_err(io("read console input"))?;
        if read == 0
        {
            return Ok(());
        }
        let chunk = buffer[..read].to_vec();
        ring = blocking(move || {
            ring.append(&chunk)?;
            Ok(ring)
        })
        .await?;
    }
}

pub fn read_console(path: &Path) -> Result<Vec<u8>, SandboxError>
{
    match std::fs::read(path)
    {
        Ok(bytes) => Ok(ordered_contents(&bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(SandboxError::Io {
            context: format!("read console {}", path.display()),
            source: error,
        }),
    }
}

pub fn tail_console(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SandboxError>
{
    let mut contents = read_console(path)?;
    let excess = contents.len().saturating_sub(max_bytes);
    contents.drain(..excess);
    Ok(contents)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn numbered(range: std::ops::Range<u32>) -> Vec<u8>
    {
        range.map(|value| (value % 251) as u8).collect()
    }

    #[test]
    fn wraps_at_the_cap_and_keeps_the_newest_bytes_in_order()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("console.ring");
        let mut ring = ConsoleRing::open(&path, 100).unwrap();
        let all = numbered(0..250);
        for chunk in all.chunks(7)
        {
            ring.append(chunk).unwrap();
        }
        assert_eq!(read_console(&path).unwrap(), all[150..].to_vec());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER_LEN + 100);
    }

    #[test]
    fn chunk_larger_than_the_cap_keeps_its_tail()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("console.ring");
        let mut ring = ConsoleRing::open(&path, 10).unwrap();
        ring.append(b"abc").unwrap();
        ring.append(b"0123456789ABCDEF").unwrap();
        assert_eq!(read_console(&path).unwrap(), b"6789ABCDEF".to_vec());
        ring.append(b"xy").unwrap();
        assert_eq!(read_console(&path).unwrap(), b"89ABCDEFxy".to_vec());
    }

    #[test]
    fn reopening_after_a_writer_restart_continues_the_ring()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("console.ring");
        {
            let mut ring = ConsoleRing::open(&path, 16).unwrap();
            ring.append(b"hello ").unwrap();
        }
        {
            let mut ring = ConsoleRing::open(&path, 16).unwrap();
            ring.append(b"world").unwrap();
        }
        assert_eq!(read_console(&path).unwrap(), b"hello world".to_vec());
        {
            let mut ring = ConsoleRing::open(&path, 16).unwrap();
            ring.append(b", again and again").unwrap();
        }
        assert_eq!(read_console(&path).unwrap(), b" again and again".to_vec());
    }

    #[test]
    fn reopening_with_a_smaller_cap_keeps_the_newest_bytes()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("console.ring");
        {
            let mut ring = ConsoleRing::open(&path, 32).unwrap();
            ring.append(b"0123456789abcdefghij").unwrap();
        }
        let mut ring = ConsoleRing::open(&path, 8).unwrap();
        assert_eq!(read_console(&path).unwrap(), b"cdefghij".to_vec());
        ring.append(b"XY").unwrap();
        assert_eq!(read_console(&path).unwrap(), b"efghijXY".to_vec());
    }

    #[tokio::test]
    async fn writer_consumes_its_input_until_eof()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("console.ring");
        let input = numbered(0..100_000);
        run_console_writer(&path, 4096, &input[..]).await.unwrap();
        assert_eq!(
            read_console(&path).unwrap(),
            input[input.len() - 4096..].to_vec()
        );
        run_console_writer(&path, 4096, &b"tail"[..]).await.unwrap();
        let contents = read_console(&path).unwrap();
        assert_eq!(contents.len(), 4096);
        assert!(contents.ends_with(b"tail"));
        assert_eq!(&contents[..4092], &input[input.len() - 4092..]);
    }

    #[test]
    fn missing_console_reads_empty_and_plain_files_read_verbatim()
    {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            read_console(&directory.path().join("absent"))
                .unwrap()
                .is_empty()
        );
        let plain = directory.path().join("plain.log");
        std::fs::write(&plain, b"line one\nline two\n").unwrap();
        assert_eq!(
            read_console(&plain).unwrap(),
            b"line one\nline two\n".to_vec()
        );
        assert_eq!(tail_console(&plain, 9).unwrap(), b"line two\n".to_vec());
    }

    #[test]
    fn zero_capacity_is_rejected()
    {
        let directory = tempfile::tempdir().unwrap();
        assert!(ConsoleRing::open(&directory.path().join("ring"), 0).is_err());
    }
}
