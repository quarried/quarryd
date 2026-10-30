use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::header::{ALLOW, CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::{Metrics, UsageError};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub async fn serve_metrics(
    metrics: Arc<Metrics>,
    addr: SocketAddr,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<SocketAddr, UsageError>
{
    if !addr.ip().is_loopback()
    {
        return Err(UsageError::NotLoopback(addr));
    }
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| UsageError::Bind { addr, source })?;
    let bound = listener
        .local_addr()
        .map_err(|source| UsageError::Bind { addr, source })?;
    tokio::spawn(accept_connections(listener, metrics, shutdown));
    Ok(bound)
}

async fn accept_connections(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    shutdown: impl Future<Output = ()> + Send + 'static,
)
{
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();
    loop
    {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted
            {
                Ok((stream, _)) =>
                {
                    connections.spawn(serve_connection(stream, Arc::clone(&metrics)));
                }
                Err(error) =>
                {
                    tracing::warn!(%error, "metrics listener accept failed");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve_connection(stream: TcpStream, metrics: Arc<Metrics>)
{
    let service = service_fn(move |request: Request<Incoming>| {
        let response = respond(&metrics, &request);
        async move { Ok::<_, Infallible>(response) }
    });
    if let Err(error) = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(%error, "metrics connection ended with an error");
    }
}

fn respond(metrics: &Metrics, request: &Request<Incoming>) -> Response<Full<Bytes>>
{
    if request.uri().path() != "/metrics"
    {
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    }
    if request.method() != Method::GET && request.method() != Method::HEAD
    {
        let mut response = plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let mut response = Response::new(Full::new(Bytes::from(metrics.render())));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
    );
    response
}

fn plain_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>>
{
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests
{
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    use super::*;

    async fn http_get(addr: SocketAddr, request: &str) -> String
    {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_metrics_on_loopback_until_shutdown()
    {
        let metrics = Arc::new(Metrics::new("node-a"));
        metrics.set_outbox_depth(3);
        let (stop, stopped) = oneshot::channel::<()>();
        let addr = serve_metrics(
            Arc::clone(&metrics),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            async move {
                let _ = stopped.await;
            },
        )
        .await
        .unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);

        let response = http_get(
            addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("content-type: text/plain; version=0.0.4; charset=utf-8\r\n"));
        assert!(response.contains(r#"quarryd_outbox_depth{node_id="node-a"} 3"#));

        let response = http_get(
            addr,
            "GET /other HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );

        let response = http_get(
            addr,
            "POST /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{response}"
        );

        stop.send(()).unwrap();
        let mut refused = false;
        for _ in 0..50
        {
            if TcpStream::connect(addr).await.is_err()
            {
                refused = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(refused, "listener still accepting after shutdown");
    }

    #[tokio::test]
    async fn refuses_non_loopback_addresses()
    {
        let metrics = Arc::new(Metrics::new("node-a"));
        for addr in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 9100)),
        ]
        {
            let result = serve_metrics(Arc::clone(&metrics), addr, std::future::pending()).await;
            assert!(
                matches!(result, Err(UsageError::NotLoopback(refused)) if refused == addr),
                "{addr} was not refused"
            );
        }
    }

    #[tokio::test]
    async fn bind_failure_is_reported()
    {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let result = serve_metrics(
            Arc::new(Metrics::new("node-a")),
            addr,
            std::future::pending(),
        )
        .await;
        assert!(matches!(result, Err(UsageError::Bind { .. })));
    }
}
