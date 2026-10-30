use crate::StubError;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::time::ASN1Time;

/// Lifetime of client certificates issued by [`TestPki::issue_client`] and `Enroll`.
pub const CLIENT_CERT_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

const CA_CERT_FILE: &str = "ca.pem";
const CA_KEY_FILE: &str = "ca-key.pem";
const SERVER_CERT_FILE: &str = "server.pem";
const SERVER_KEY_FILE: &str = "server-key.pem";

/// Self-signed CA plus a server certificate for the stub's TLS listener.
#[derive(Debug, Clone)]
pub struct TestPki
{
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

/// Certificate issued for a CSR.
#[derive(Debug, Clone)]
pub(crate) struct IssuedCertificate
{
    pub(crate) certificate_pem: String,
    pub(crate) expires_at_unix: u64,
}

impl TestPki
{
    /// Generates a CA and a server certificate whose SANs are `server_names`
    /// (DNS names or IP addresses).
    pub fn generate(server_names: &[&str]) -> Result<TestPki, StubError>
    {
        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = common_name("quarry stub CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate()?;
        let mut server_params = CertificateParams::new(
            server_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )?;
        server_params.distinguished_name =
            common_name(server_names.first().copied().unwrap_or("localhost"));
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params.signed_by(&server_key, &issuer)?;

        Ok(TestPki {
            ca_cert_pem: ca_cert.pem(),
            ca_key_pem: ca_key.serialize_pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
        })
    }

    /// Issues a client certificate and key, `(cert_pem, key_pem)`, with
    /// CN = `node_id`, valid for [`CLIENT_CERT_VALIDITY`].
    pub fn issue_client(&self, node_id: &str) -> Result<(String, String), StubError>
    {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = common_name(node_id);
        let issued = self.sign(&mut params, &key)?;
        Ok((issued.certificate_pem, key.serialize_pem()))
    }

    /// Writes the four PEM files into `dir`, creating it if needed.
    pub fn write_to(&self, dir: &Path) -> Result<(), StubError>
    {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(CA_CERT_FILE), &self.ca_cert_pem)?;
        fs::write(dir.join(CA_KEY_FILE), &self.ca_key_pem)?;
        fs::write(dir.join(SERVER_CERT_FILE), &self.server_cert_pem)?;
        fs::write(dir.join(SERVER_KEY_FILE), &self.server_key_pem)?;
        Ok(())
    }

    /// Reads PEM files previously written by [`TestPki::write_to`].
    pub fn read_from(dir: &Path) -> Result<TestPki, StubError>
    {
        Ok(TestPki {
            ca_cert_pem: fs::read_to_string(dir.join(CA_CERT_FILE))?,
            ca_key_pem: fs::read_to_string(dir.join(CA_KEY_FILE))?,
            server_cert_pem: fs::read_to_string(dir.join(SERVER_CERT_FILE))?,
            server_key_pem: fs::read_to_string(dir.join(SERVER_KEY_FILE))?,
        })
    }

    /// Whether `dir` contains a PKI written by [`TestPki::write_to`].
    pub fn exists_in(dir: &Path) -> bool
    {
        dir.join(CA_CERT_FILE).is_file()
    }

    pub(crate) fn sign_csr(
        &self,
        csr: &CertificateSigningRequestParams,
    ) -> Result<IssuedCertificate, StubError>
    {
        let mut params = csr.params.clone();
        self.sign(&mut params, &csr.public_key)
    }

    fn sign(
        &self,
        params: &mut CertificateParams,
        public_key: &impl rcgen::PublicKeyData,
    ) -> Result<IssuedCertificate, StubError>
    {
        let not_before = unix_now();
        let not_after = not_before + CLIENT_CERT_VALIDITY.as_secs();
        params.not_before = asn1_time(not_before)?.to_datetime();
        params.not_after = asn1_time(not_after)?.to_datetime();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let ca_key = KeyPair::from_pem(&self.ca_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_cert_pem, ca_key)?;
        let certificate = params.signed_by(public_key, &issuer)?;
        Ok(IssuedCertificate {
            certificate_pem: certificate.pem(),
            expires_at_unix: not_after,
        })
    }
}

/// Common name of a CSR subject, if it has a string-valued one.
pub(crate) fn csr_common_name(csr: &CertificateSigningRequestParams) -> Option<String>
{
    match csr.params.distinguished_name.get(&DnType::CommonName)?
    {
        DnValue::Utf8String(name) => Some(name.clone()),
        DnValue::PrintableString(name) => Some(name.as_str().to_owned()),
        DnValue::Ia5String(name) => Some(name.as_str().to_owned()),
        _ => None,
    }
}

/// Common name of a DER certificate subject.
pub(crate) fn certificate_common_name(der: &[u8]) -> Option<String>
{
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let name = certificate
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?;
    Some(name.to_owned())
}

fn common_name(name: &str) -> DistinguishedName
{
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, name);
    distinguished_name
}

fn unix_now() -> u64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn asn1_time(unix_seconds: u64) -> Result<ASN1Time, StubError>
{
    let seconds = i64::try_from(unix_seconds).map_err(|_| StubError::Clock)?;
    ASN1Time::from_timestamp(seconds).map_err(|_| StubError::Clock)
}
