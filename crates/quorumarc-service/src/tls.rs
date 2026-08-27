use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use rustix::fs::OFlags;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// Typed TLS configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsConfigError {
    InvalidRootStore,
    InvalidCertificateChain,
    InvalidPrivateKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMaterialError {
    InvalidFile,
    UnsafePrivateKey,
    MaterialTooLarge,
    InvalidCertificate,
    InvalidPrivateKey,
    InvalidConfig,
}

const MAX_TLS_MATERIAL_SIZE: u64 = 1_048_576;

/// rustls server configuration that always requires a client certificate.
#[derive(Debug)]
pub struct MtlsServerConfig {
    config: ServerConfig,
}

impl MtlsServerConfig {
    #[must_use]
    pub fn into_server_config(self) -> ServerConfig {
        self.config
    }

    #[must_use]
    pub fn into_arc(self) -> Arc<ServerConfig> {
        Arc::new(self.config)
    }
}

pub fn load_mtls_server_config(
    certificate_chain: &Path,
    private_key: &Path,
    trusted_roots: &Path,
) -> Result<MtlsServerConfig, TlsMaterialError> {
    let certificates = load_certificates(certificate_chain)?;
    let key = load_private_key(private_key)?;
    let roots = load_certificates(trusted_roots)?;
    server_mtls_config(certificates, key, roots).map_err(|_error| TlsMaterialError::InvalidConfig)
}

pub fn load_mtls_client_config(
    certificate_chain: &Path,
    private_key: &Path,
    trusted_roots: &Path,
) -> Result<ClientConfig, TlsMaterialError> {
    let certificates = load_certificates(certificate_chain)?;
    let key = load_private_key(private_key)?;
    let roots = load_certificates(trusted_roots)?;
    client_mtls_config(certificates, key, roots).map_err(|_error| TlsMaterialError::InvalidConfig)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsMaterialError> {
    let bytes = read_material(path, false)?;
    let mut reader = BufReader::new(bytes.as_slice());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_error| TlsMaterialError::InvalidCertificate)?;
    if certificates.is_empty() {
        return Err(TlsMaterialError::InvalidCertificate);
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsMaterialError> {
    let bytes = read_material(path, true)?;
    let mut reader = BufReader::new(bytes.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_error| TlsMaterialError::InvalidPrivateKey)?
        .ok_or(TlsMaterialError::InvalidPrivateKey)
}

fn read_material(path: &Path, private: bool) -> Result<Vec<u8>, TlsMaterialError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_error| {
            if private {
                TlsMaterialError::UnsafePrivateKey
            } else {
                TlsMaterialError::InvalidFile
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|_error| TlsMaterialError::InvalidFile)?;
    if !metadata.is_file() {
        return Err(if private {
            TlsMaterialError::UnsafePrivateKey
        } else {
            TlsMaterialError::InvalidFile
        });
    }
    if private && metadata.permissions().mode() & 0o077 != 0 {
        return Err(TlsMaterialError::UnsafePrivateKey);
    }
    if metadata.len() > MAX_TLS_MATERIAL_SIZE {
        return Err(TlsMaterialError::MaterialTooLarge);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_TLS_MATERIAL_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| TlsMaterialError::InvalidFile)?;
    if bytes.len() as u64 > MAX_TLS_MATERIAL_SIZE {
        return Err(TlsMaterialError::MaterialTooLarge);
    }
    Ok(bytes)
}

/// Builds an mTLS server configuration requiring client certificates signed by trusted roots.
pub fn server_mtls_config(
    server_certificates: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    trusted_client_roots: Vec<CertificateDer<'static>>,
) -> Result<MtlsServerConfig, TlsConfigError> {
    if server_certificates.is_empty() || trusted_client_roots.is_empty() {
        return Err(TlsConfigError::InvalidCertificateChain);
    }
    let mut root_store = RootCertStore::empty();
    for root in trusted_client_roots {
        root_store
            .add(root)
            .map_err(|_error| TlsConfigError::InvalidRootStore)?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|_error| TlsConfigError::InvalidRootStore)?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certificates, server_key)
        .map_err(|_error| TlsConfigError::InvalidPrivateKey)?;
    Ok(MtlsServerConfig { config })
}

/// Builds an mTLS client configuration presenting a certificate signed by a trusted authority.
pub fn client_mtls_config(
    client_certificates: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    trusted_server_roots: Vec<CertificateDer<'static>>,
) -> Result<ClientConfig, TlsConfigError> {
    if client_certificates.is_empty() || trusted_server_roots.is_empty() {
        return Err(TlsConfigError::InvalidCertificateChain);
    }
    let mut root_store = RootCertStore::empty();
    for root in trusted_server_roots {
        root_store
            .add(root)
            .map_err(|_error| TlsConfigError::InvalidRootStore)?;
    }
    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certificates, client_key)
        .map_err(|_error| TlsConfigError::InvalidPrivateKey)
}
