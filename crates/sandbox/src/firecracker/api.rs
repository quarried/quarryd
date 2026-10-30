use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, HOST};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

use crate::SandboxError;
use crate::error::io;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig
{
    pub vcpu_count: u32,
    pub mem_size_mib: u64,
    #[serde(default)]
    pub smt: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootSource
{
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drive
{
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface
{
    pub iface_id: String,
    pub host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_mac: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vsock
{
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balloon
{
    pub amount_mib: u64,
    pub deflate_on_oom: bool,
    pub stats_polling_interval_s: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonUpdate
{
    pub amount_mib: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonStats
{
    pub target_pages: u64,
    pub actual_pages: u64,
    pub target_mib: u64,
    pub actual_mib: u64,
    pub swap_in: Option<u64>,
    pub swap_out: Option<u64>,
    pub major_faults: Option<u64>,
    pub minor_faults: Option<u64>,
    pub free_memory: Option<u64>,
    pub total_memory: Option<u64>,
    pub available_memory: Option<u64>,
    pub disk_caches: Option<u64>,
    pub hugetlb_allocations: Option<u64>,
    pub hugetlb_failures: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metrics
{
    pub metrics_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logger
{
    pub log_path: String,
    pub level: String,
    pub show_level: bool,
    pub show_log_origin: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType
{
    InstanceStart,
    SendCtrlAltDel,
    FlushMetrics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceAction
{
    pub action_type: ActionType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfo
{
    pub id: String,
    pub state: String,
    #[serde(default)]
    pub vmm_version: String,
    #[serde(default)]
    pub app_name: String,
}

impl InstanceInfo
{
    pub fn is_started(&self) -> bool
    {
        self.state != "Not started"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirecrackerApi
{
    socket: PathBuf,
}

impl FirecrackerApi
{
    pub fn new(socket: impl Into<PathBuf>) -> Self
    {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path
    {
        &self.socket
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes, SandboxError>
    {
        let stream = UnixStream::connect(&self.socket).await.map_err(io(format!(
            "connect to firecracker API {}",
            self.socket.display()
        )))?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await
            {
                tracing::debug!(%error, "firecracker API connection closed with an error");
            }
        });
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, "localhost")
            .header(ACCEPT, "application/json");
        if body.is_some()
        {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        let request = request.body(Full::new(Bytes::from(body.unwrap_or_default())))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        if status.is_success()
        {
            Ok(bytes)
        }
        else
        {
            Err(SandboxError::Api {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            })
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes, SandboxError>
    {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(method.clone(), path, body))
            .await
            .map_err(|_| SandboxError::Timeout(format!("firecracker API {method} {path}")))?
    }

    async fn put<T: Serialize>(&self, path: &str, value: &T) -> Result<(), SandboxError>
    {
        self.send(Method::PUT, path, Some(serde_json::to_vec(value)?))
            .await
            .map(drop)
    }

    async fn patch<T: Serialize>(&self, path: &str, value: &T) -> Result<(), SandboxError>
    {
        self.send(Method::PATCH, path, Some(serde_json::to_vec(value)?))
            .await
            .map(drop)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, SandboxError>
    {
        let bytes = self.send(Method::GET, path, None).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn instance_info(&self) -> Result<InstanceInfo, SandboxError>
    {
        self.get("/").await
    }

    pub async fn put_machine_config(&self, config: &MachineConfig) -> Result<(), SandboxError>
    {
        self.put("/machine-config", config).await
    }

    pub async fn machine_config(&self) -> Result<MachineConfig, SandboxError>
    {
        self.get("/machine-config").await
    }

    pub async fn put_boot_source(&self, boot_source: &BootSource) -> Result<(), SandboxError>
    {
        self.put("/boot-source", boot_source).await
    }

    pub async fn put_drive(&self, drive: &Drive) -> Result<(), SandboxError>
    {
        self.put(&format!("/drives/{}", drive.drive_id), drive)
            .await
    }

    pub async fn put_network_interface(
        &self,
        interface: &NetworkInterface,
    ) -> Result<(), SandboxError>
    {
        self.put(
            &format!("/network-interfaces/{}", interface.iface_id),
            interface,
        )
        .await
    }

    pub async fn put_vsock(&self, vsock: &Vsock) -> Result<(), SandboxError>
    {
        self.put("/vsock", vsock).await
    }

    pub async fn put_balloon(&self, balloon: &Balloon) -> Result<(), SandboxError>
    {
        self.put("/balloon", balloon).await
    }

    pub async fn patch_balloon(&self, amount_mib: u64) -> Result<(), SandboxError>
    {
        self.patch("/balloon", &BalloonUpdate { amount_mib }).await
    }

    pub async fn balloon_stats(&self) -> Result<BalloonStats, SandboxError>
    {
        self.get("/balloon/statistics").await
    }

    pub async fn put_metrics(&self, metrics: &Metrics) -> Result<(), SandboxError>
    {
        self.put("/metrics", metrics).await
    }

    pub async fn put_logger(&self, logger: &Logger) -> Result<(), SandboxError>
    {
        self.put("/logger", logger).await
    }

    pub async fn action(&self, action_type: ActionType) -> Result<(), SandboxError>
    {
        self.put("/actions", &InstanceAction { action_type }).await
    }

    pub async fn instance_start(&self) -> Result<(), SandboxError>
    {
        self.action(ActionType::InstanceStart).await
    }

    pub async fn send_ctrl_alt_del(&self) -> Result<(), SandboxError>
    {
        self.action(ActionType::SendCtrlAltDel).await
    }

    pub async fn flush_metrics(&self) -> Result<(), SandboxError>
    {
        self.action(ActionType::FlushMetrics).await
    }
}

#[cfg(test)]
mod tests
{
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use http::{Response, StatusCode};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use serde_json::json;
    use tokio::net::UnixListener;

    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Seen
    {
        method: String,
        path: String,
        content_type: Option<String>,
        body: Option<serde_json::Value>,
    }

    async fn fake_firecracker(socket: PathBuf, seen: Arc<Mutex<Vec<Seen>>>)
    {
        let listener = UnixListener::bind(&socket).unwrap();
        loop
        {
            let (stream, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen = seen.clone();
                    async move {
                        let method = request.method().to_string();
                        let path = request.uri().path().to_string();
                        let content_type = request
                            .headers()
                            .get(CONTENT_TYPE)
                            .map(|value| value.to_str().unwrap().to_string());
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let body =
                            (!bytes.is_empty()).then(|| serde_json::from_slice(&bytes).unwrap());
                        seen.lock().unwrap().push(Seen {
                            method: method.clone(),
                            path: path.clone(),
                            content_type,
                            body,
                        });
                        let response = match (method.as_str(), path.as_str())
                        {
                            ("GET", "/") => Response::new(Full::new(Bytes::from(
                                r#"{"id":"abc","state":"Running","vmm_version":"1.10.1","app_name":"Firecracker"}"#,
                            ))),
                            ("GET", "/machine-config") => Response::new(Full::new(Bytes::from(
                                r#"{"vcpu_count":2,"mem_size_mib":2048,"smt":false,"track_dirty_pages":false}"#,
                            ))),
                            ("GET", "/balloon/statistics") =>
                            {
                                Response::new(Full::new(Bytes::from(
                                    r#"{"target_pages":0,"actual_pages":0,"target_mib":0,"actual_mib":0,"free_memory":10}"#,
                                )))
                            }
                            ("PUT", "/drives/bad") =>
                            {
                                let mut response = Response::new(Full::new(Bytes::from(
                                    r#"{"fault_message":"bad drive"}"#,
                                )));
                                *response.status_mut() = StatusCode::BAD_REQUEST;
                                response
                            }
                            _ =>
                            {
                                let mut response = Response::new(Full::new(Bytes::new()));
                                *response.status_mut() = StatusCode::NO_CONTENT;
                                response
                            }
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .unwrap();
            });
        }
    }

    #[tokio::test]
    async fn client_speaks_http_over_the_unix_socket()
    {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("firecracker.socket");
        let seen = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(fake_firecracker(socket.clone(), seen.clone()));
        for _ in 0..100
        {
            if socket.exists()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let api = FirecrackerApi::new(&socket);
        let info = api.instance_info().await.unwrap();
        assert_eq!(info.state, "Running");
        assert!(info.is_started());
        assert_eq!(api.machine_config().await.unwrap().mem_size_mib, 2048);
        api.put_drive(&Drive {
            drive_id: "rootfs".into(),
            path_on_host: "/rootfs".into(),
            is_root_device: true,
            is_read_only: true,
        })
        .await
        .unwrap();
        api.patch_balloon(512).await.unwrap();
        api.send_ctrl_alt_del().await.unwrap();
        assert_eq!(api.balloon_stats().await.unwrap().free_memory, Some(10));
        let error = api
            .put_drive(&Drive {
                drive_id: "bad".into(),
                path_on_host: "/bad".into(),
                is_root_device: false,
                is_read_only: false,
            })
            .await
            .unwrap_err();
        match error
        {
            SandboxError::Api { status, body } =>
            {
                assert_eq!(status, 400);
                assert!(body.contains("bad drive"));
            }
            other => panic!("unexpected error {other:?}"),
        }
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].path, "/");
        assert_eq!(seen[0].content_type, None);
        assert_eq!(seen[2].method, "PUT");
        assert_eq!(seen[2].path, "/drives/rootfs");
        assert_eq!(seen[2].content_type.as_deref(), Some("application/json"));
        assert_eq!(
            seen[2].body,
            Some(
                json!({"drive_id":"rootfs","path_on_host":"/rootfs","is_root_device":true,"is_read_only":true})
            )
        );
        assert_eq!(seen[3].method, "PATCH");
        assert_eq!(seen[3].path, "/balloon");
        assert_eq!(seen[3].body, Some(json!({"amount_mib":512})));
        assert_eq!(seen[4].path, "/actions");
        assert_eq!(seen[4].body, Some(json!({"action_type":"SendCtrlAltDel"})));
    }

    #[tokio::test]
    async fn missing_socket_is_an_io_error()
    {
        let directory = tempfile::tempdir().unwrap();
        let api = FirecrackerApi::new(directory.path().join("absent.socket"));
        assert!(matches!(
            api.instance_info().await,
            Err(SandboxError::Io { .. })
        ));
    }

    #[test]
    fn request_bodies_match_the_firecracker_schema()
    {
        assert_eq!(
            serde_json::to_value(NetworkInterface {
                iface_id: "eth0".into(),
                host_dev_name: "qtap0".into(),
                guest_mac: Some("06:00:0a:14:00:05".into()),
            })
            .unwrap(),
            json!({"iface_id":"eth0","host_dev_name":"qtap0","guest_mac":"06:00:0a:14:00:05"})
        );
        assert_eq!(
            serde_json::to_value(Balloon {
                amount_mib: 0,
                deflate_on_oom: true,
                stats_polling_interval_s: 5,
            })
            .unwrap(),
            json!({"amount_mib":0,"deflate_on_oom":true,"stats_polling_interval_s":5})
        );
        assert_eq!(
            serde_json::to_value(InstanceAction {
                action_type: ActionType::FlushMetrics
            })
            .unwrap(),
            json!({"action_type":"FlushMetrics"})
        );
        assert_eq!(
            serde_json::to_value(Vsock {
                guest_cid: 3,
                uds_path: "/run/v.sock".into()
            })
            .unwrap(),
            json!({"guest_cid":3,"uds_path":"/run/v.sock"})
        );
    }
}
