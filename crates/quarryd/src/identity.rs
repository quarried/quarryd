use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use hyper_util::rt::TokioIo;
use proto::v1::EnrollRequest;
use proto::v1::agent_gateway_client::AgentGatewayClient;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::info;

const CERT_FILE: &str = "node.crt";
const KEY_FILE: &str = "node.key";
const EXPIRY_FILE: &str = "node.expires";

#[derive(Clone)]
pub struct NodeIdentity
{
    pub certificate_pem: String,
    pub key_pem: String,
    pub expires_at_unix: u64,
}

impl NodeIdentity
{
    pub fn load(dir: &Path) -> Result<Option<NodeIdentity>>
    {
        let cert_path = dir.join(CERT_FILE);
        if !cert_path.exists()
        {
            return Ok(None);
        }
        let certificate_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(dir.join(KEY_FILE))?;
        let expires_at_unix = std::fs::read_to_string(dir.join(EXPIRY_FILE))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0);
        Ok(Some(NodeIdentity {
            certificate_pem,
            key_pem,
            expires_at_unix,
        }))
    }

    pub fn save(&self, dir: &Path) -> Result<()>
    {
        std::fs::create_dir_all(dir)?;
        write_private(&dir.join(KEY_FILE), self.key_pem.as_bytes())?;
        write_atomic(&dir.join(CERT_FILE), self.certificate_pem.as_bytes())?;
        write_atomic(
            &dir.join(EXPIRY_FILE),
            self.expires_at_unix.to_string().as_bytes(),
        )?;
        Ok(())
    }

    pub fn needs_rotation(&self, now_unix: u64) -> bool
    {
        if self.expires_at_unix == 0
        {
            return true;
        }
        let remaining = self.expires_at_unix.saturating_sub(now_unix);
        remaining < Duration::from_secs(8 * 3600).as_secs()
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()>
{
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()>
{
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

pub fn now_unix() -> u64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub struct Transport
{
    ca_pem: String,
    identity_dir: PathBuf,
    node_id: String,
}

impl Transport
{
    pub fn new(ca_pem: String, identity_dir: PathBuf, node_id: String) -> Transport
    {
        Transport {
            ca_pem,
            identity_dir,
            node_id,
        }
    }

    pub fn identity(&self) -> Result<Option<NodeIdentity>>
    {
        NodeIdentity::load(&self.identity_dir)
    }

    pub async fn connect(&self, endpoint: &str, identity: Option<&NodeIdentity>)
    -> Result<Channel>
    {
        let config = client_config(&self.ca_pem, identity)?;
        connect_channel(endpoint, config).await
    }

    pub async fn ensure_identity(
        &self,
        endpoint: &str,
        join_token: Option<&str>,
    ) -> Result<NodeIdentity>
    {
        let existing = self.identity()?;
        match existing
        {
            Some(identity) if !identity.needs_rotation(now_unix()) => Ok(identity),
            Some(identity) => self.enroll(endpoint, Some(&identity), "").await,
            None =>
            {
                let token = join_token
                    .ok_or_else(|| anyhow!("no node certificate and no join token configured"))?;
                self.enroll(endpoint, None, token).await
            }
        }
    }

    pub async fn enroll(
        &self,
        endpoint: &str,
        current: Option<&NodeIdentity>,
        join_token: &str,
    ) -> Result<NodeIdentity>
    {
        let key_pair = rcgen::KeyPair::generate().context("generating node key")?;
        let mut params =
            rcgen::CertificateParams::new(vec![self.node_id.clone()]).context("building CSR")?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, self.node_id.clone());
        let csr = params.serialize_request(&key_pair).context("signing CSR")?;
        let channel = self.connect(endpoint, current).await?;
        let mut client = AgentGatewayClient::new(channel);
        let response = client
            .enroll(EnrollRequest {
                node_id: self.node_id.clone(),
                join_token: join_token.to_string(),
                csr_pem: csr.pem().context("encoding CSR")?,
            })
            .await
            .context("enrolling with the control plane")?
            .into_inner();
        if response.certificate_pem.is_empty()
        {
            bail!("control plane returned an empty certificate");
        }
        let identity = NodeIdentity {
            certificate_pem: response.certificate_pem,
            key_pem: key_pair.serialize_pem(),
            expires_at_unix: response.expires_at_unix,
        };
        identity.save(&self.identity_dir)?;
        info!(
            expires_at_unix = identity.expires_at_unix,
            rotated = current.is_some(),
            "node certificate issued"
        );
        Ok(identity)
    }
}

pub fn client_config(ca_pem: &str, identity: Option<&NodeIdentity>) -> Result<ClientConfig>
{
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes())
    {
        roots.add(certificate.context("parsing pinned CA")?)?;
    }
    if roots.is_empty()
    {
        bail!("pinned CA bundle contains no certificates");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots);
    let mut config = match identity
    {
        Some(identity) =>
        {
            let chain = CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("parsing node certificate")?;
            let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes())
                .context("parsing node key")?;
            builder.with_client_auth_cert(chain, key)?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

async fn connect_channel(endpoint: &str, config: ClientConfig) -> Result<Channel>
{
    let uri: Uri = endpoint
        .parse()
        .with_context(|| format!("invalid endpoint {endpoint}"))?;
    if uri.scheme_str() != Some("https")
    {
        bail!("endpoint {endpoint} must use https");
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("endpoint {endpoint} has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    let server_name = ServerName::try_from(host.clone()).context("invalid server name")?;
    let connector = TlsConnector::from(Arc::new(config));
    let plain_uri = format!("http://{host}:{port}");
    let channel = Endpoint::from_shared(plain_uri)?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .connect_with_connector(service_fn(move |_: Uri| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            let address = (host.clone(), port);
            async move {
                let tcp = TcpStream::connect(address).await?;
                tcp.set_nodelay(true)?;
                let stream = connector.connect(server_name, tcp).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| format!("connecting to {endpoint}"))?;
    Ok(channel)
}
