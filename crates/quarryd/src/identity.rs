use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use hyper_util::rt::TokioIo;
use proto::v1::EnrollRequest;
use proto::v1::agent_gateway_client::AgentGatewayClient;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::{info, warn};

const CERT_FILE: &str = "node.crt";
const KEY_FILE: &str = "node.key";
const EXPIRY_FILE: &str = "node.expires";
const IDENTITY_FILE: &str = "identity.json";
const PREVIOUS_IDENTITY_FILE: &str = "identity.previous.json";
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Deserialize, Serialize)]
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
        let mut failure = None;
        for name in [IDENTITY_FILE, PREVIOUS_IDENTITY_FILE]
        {
            match Self::load_bundle(&dir.join(name))
            {
                Ok(Some(identity)) => return Ok(Some(identity)),
                Ok(None) =>
                {}
                Err(error) =>
                {
                    failure.get_or_insert(error);
                }
            }
        }
        match Self::load_legacy(dir)
        {
            Ok(Some(identity)) => Ok(Some(identity)),
            Ok(None) => match failure
            {
                Some(error) => Err(error),
                None => Ok(None),
            },
            Err(error) => Err(failure.unwrap_or(error)),
        }
    }

    fn load_bundle(path: &Path) -> Result<Option<NodeIdentity>>
    {
        let bytes = match std::fs::read(path)
        {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        // Serde errors can include field contents. Never include bundle contents
        // in an error, since the bundle contains the private key.
        let identity: NodeIdentity = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("invalid identity bundle at {}", path.display()))?;
        identity.validate()?;
        Ok(Some(identity))
    }

    fn load_legacy(dir: &Path) -> Result<Option<NodeIdentity>>
    {
        let cert_path = dir.join(CERT_FILE);
        let certificate_pem = match std::fs::read_to_string(&cert_path)
        {
            Ok(certificate) => certificate,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading legacy node certificate"),
        };
        let key_pem = std::fs::read_to_string(dir.join(KEY_FILE))?;
        let expires_at_unix = std::fs::read_to_string(dir.join(EXPIRY_FILE))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0);
        let identity = NodeIdentity {
            certificate_pem,
            key_pem,
            expires_at_unix,
        };
        identity.validate()?;
        Ok(Some(identity))
    }

    pub fn save(&self, dir: &Path) -> Result<()>
    {
        self.validate()?;
        let directory = std::path::absolute(dir).context("resolving node identity directory")?;
        let dir = directory.as_path();
        let previous = Self::load(dir)?;
        std::fs::create_dir_all(dir)?;
        // Persist directory entries too, including directories created by the
        // caller immediately before the initial enrollment.
        for parent in dir
            .ancestors()
            .skip(1)
            .filter(|path| !path.as_os_str().is_empty())
        {
            sync_directory(parent)?;
        }
        if let Some(previous) = previous
        {
            // This must be durable before activation. It also migrates legacy
            // credentials without modifying any of the legacy files.
            write_private(
                &dir.join(PREVIOUS_IDENTITY_FILE),
                &serde_json::to_vec(&previous)?,
            )?;
        }
        write_private(&dir.join(IDENTITY_FILE), &serde_json::to_vec(self)?)?;
        Ok(())
    }

    fn validate(&self) -> Result<()>
    {
        let chain = CertificateDer::pem_slice_iter(self.certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("parsing node certificate")?;
        let key =
            PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes()).context("parsing node key")?;
        let certified = rustls::sign::CertifiedKey::from_der(
            chain,
            key,
            &rustls::crypto::ring::default_provider(),
        )
        .context("validating node certificate and key")?;
        certified
            .keys_match()
            .context("matching node certificate and key")
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

fn sync_directory(path: &Path) -> Result<()>
{
    std::fs::File::open(path)?
        .sync_all()
        .with_context(|| format!("syncing identity directory {}", path.display()))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()>
{
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .context("identity bundle has no parent directory")?;
    let (temporary, mut file) = loop
    {
        let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".identity-{}-{sequence}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating staged node identity"),
        }
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err()
    {
        let _ = std::fs::remove_file(&temporary);
    }
    result
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
            Some(identity) => match self.enroll(endpoint, Some(&identity), "").await
            {
                Ok(rotated) => Ok(rotated),
                Err(_) if identity.expires_at_unix > now_unix() =>
                {
                    warn!("node certificate rotation failed; retaining the current identity");
                    Ok(identity)
                }
                Err(error) => Err(error),
            },
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
        if identity.expires_at_unix <= now_unix()
        {
            bail!("control plane returned an expired certificate");
        }
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
