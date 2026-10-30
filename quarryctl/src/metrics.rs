use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, bail};

const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Scrape
{
    pub address: String,
    pub result: Result<String, String>,
}

pub fn scrape(address: &str) -> Scrape
{
    Scrape {
        address: address.to_owned(),
        result: fetch(address).map_err(|error| format!("{error:#}")),
    }
}

fn fetch(address: &str) -> anyhow::Result<String>
{
    let target = address
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {address}"))?
        .next()
        .with_context(|| format!("{address} resolves to no address"))?;
    let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)
        .with_context(|| format!("cannot connect to {address}"))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(format!("GET /metrics HTTP/1.0\r\nHost: {address}\r\n\r\n").as_bytes())?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut response)
        .context("cannot read the metrics response")?;
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> anyhow::Result<String>
{
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head.lines().next().unwrap_or_default();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code != "200"
    {
        bail!("unexpected HTTP status line {status:?}");
    }
    Ok(String::from_utf8_lossy(&response[split + 4..]).into_owned())
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_metrics_endpoint_is_scraped_over_http_1_0()
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]).into_owned();
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nquarryd_up 1\n")
                .unwrap();
            request
        });
        let scraped = scrape(&address);
        assert_eq!(scraped.result, Ok("quarryd_up 1\n".to_owned()));
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("GET /metrics HTTP/1.0\r\n")
        );
    }

    #[test]
    fn an_unreachable_endpoint_reports_the_error()
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let scraped = scrape(&address);
        assert!(scraped.result.unwrap_err().contains("cannot connect"));
    }

    #[test]
    fn non_200_responses_are_errors()
    {
        assert!(
            parse_response(b"HTTP/1.1 404 Not Found\r\n\r\nnope")
                .unwrap_err()
                .to_string()
                .contains("404")
        );
        assert!(parse_response(b"garbage").is_err());
    }
}
