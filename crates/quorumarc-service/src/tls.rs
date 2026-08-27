use std::sync::Arc;

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

/// Builds an mTLS server configuration requiring client certificates signed by trusted roots.
pub fn server_mtls_config(
    server_certificates: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    trusted_client_roots: Vec<CertificateDer<'static>>,
) -> Result<ServerConfig, TlsConfigError> {
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
    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certificates, server_key)
        .map_err(|_error| TlsConfigError::InvalidPrivateKey)
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
