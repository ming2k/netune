//! Self-signed TLS identities and the test-only "accept any certificate"
//! verifier.
//!
//! A mock TLS layer would test the mock. These helpers generate a real
//! certificate and build real `rustls` configurations, so a suite can assert
//! what an operator depends on: the negotiated ALPN, the certificate the peer
//! was asked for, and the handshake's completion.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

/// A generated self-signed identity: the certificate the server presents, a
/// server configuration that presents it, and a client configuration that
/// trusts exactly it.
#[derive(Clone)]
pub struct TestIdentity {
    /// The leaf certificate, for a suite that wants to inspect or re-trust it.
    pub certificate: CertificateDer<'static>,
    /// The leaf's private key (PKCS#8 DER), for a suite that wants its own
    /// server configuration (a pinned version line or cipher suite).
    pub key: Vec<u8>,
    /// A server configuration with no client authentication.
    pub server: Arc<ServerConfig>,
    /// A client configuration whose only trust anchor is `certificate`.
    pub client: Arc<ClientConfig>,
}

impl std::fmt::Debug for TestIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestIdentity")
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

impl TestIdentity {
    /// A client that trusts this identity's certificate and offers `alpn`.
    pub fn verified_client(&self, alpn: &[&[u8]]) -> Arc<ClientConfig> {
        verified_client_config(self.certificate.clone(), alpn)
    }

    /// A client that accepts any certificate and offers `alpn`.
    pub fn dangerous_client(&self, alpn: &[&[u8]], early_data: bool) -> Arc<ClientConfig> {
        dangerous_client_config(alpn, early_data)
    }
}

/// Generate a self-signed identity for `names`, advertising `alpn`.
pub fn identity(names: &[&str], alpn: &[&[u8]]) -> TestIdentity {
    assert!(!names.is_empty(), "an identity needs at least one name");
    let generated = rcgen::generate_simple_self_signed(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .expect("generate self-signed certificate");
    let certificate = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("server certificate");
    server.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    TestIdentity {
        certificate: certificate.clone(),
        key: generated.signing_key.serialize_der(),
        server: Arc::new(server),
        client: verified_client_config(certificate, alpn),
    }
}

/// A client configuration that trusts exactly `certificate` and offers `alpn`.
pub fn verified_client_config(
    certificate: CertificateDer<'static>,
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).expect("trust anchor");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    client.enable_early_data = false;
    Arc::new(client)
}

/// A client configuration that accepts any server certificate and offers
/// `alpn`. `early_data` mirrors the QUIC 0-RTT suites.
pub fn dangerous_client_config(alpn: &[&[u8]], early_data: bool) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    client.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    client.enable_early_data = early_data;
    Arc::new(client)
}

/// A verifier that accepts every certificate and signature.
///
/// Test-only by construction: the type lives in a `publish = false` crate that
/// no production manifest may depend on. It must never be copied into a
/// shipping crate.
#[derive(Debug)]
pub struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_builds_both_sides() {
        let identity = identity(&["localhost"], &[b"h2", b"http/1.1"]);
        let expected = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        assert_eq!(identity.server.alpn_protocols, expected);
        assert_eq!(identity.client.alpn_protocols, expected);
        assert!(!identity.certificate.as_ref().is_empty());
    }

    #[test]
    fn the_dangerous_client_accepts_early_data_when_asked() {
        let client = dangerous_client_config(&[b"h3"], true);
        assert!(client.enable_early_data);
        assert_eq!(client.alpn_protocols, vec![b"h3"]);
    }
}
