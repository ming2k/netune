// SPDX-License-Identifier: MIT

//! `rustls` QUIC handshake wrapper.
//!
//! This is the only place where the owned engine touches the TLS state
//! machine. TLS records never cross the QUIC wire; `write_hs` bytes become
//! CRYPTO frame payloads and `read_hs` consumes peer CRYPTO payloads.

use std::sync::Arc;

use rustls::quic::{KeyChange, Version};
use rustls::{ClientConfig, ServerConfig};

use super::packet::CryptoError;

/// A client or server QUIC TLS session.
pub enum TlsSession {
    Client(rustls::quic::ClientConnection),
    Server(rustls::quic::ServerConnection),
}

impl TlsSession {
    /// Create a client TLS session. `transport_parameters` is the encoded
    /// QUIC transport-parameters extension.
    pub fn client(
        config: Arc<ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        transport_parameters: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let session = rustls::quic::ClientConnection::new(
            config,
            Version::V1,
            server_name,
            transport_parameters,
        )
        .map_err(CryptoError::from)?;
        Ok(Self::Client(session))
    }

    /// Create a server TLS session.
    pub fn server(
        config: Arc<ServerConfig>,
        transport_parameters: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let session =
            rustls::quic::ServerConnection::new(config, Version::V1, transport_parameters)
                .map_err(CryptoError::from)?;
        Ok(Self::Server(session))
    }

    /// Feed peer CRYPTO bytes into TLS.
    pub fn read_handshake(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Client(session) => session.read_hs(data),
            Self::Server(session) => session.read_hs(data),
        }
        .map_err(CryptoError::from)
    }

    /// Emit TLS handshake bytes and any new key set.
    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange> {
        match self {
            Self::Client(session) => session.write_hs(out),
            Self::Server(session) => session.write_hs(out),
        }
    }

    /// The peer's transport-parameters extension, once authenticated.
    pub fn peer_transport_parameters(&self) -> Option<Vec<u8>> {
        match self {
            Self::Client(session) => session.quic_transport_parameters(),
            Self::Server(session) => session.quic_transport_parameters(),
        }
        .map(Vec::from)
    }

    /// True until TLS reports the handshake complete.
    pub fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(session) => session.is_handshaking(),
            Self::Server(session) => session.is_handshaking(),
        }
    }

    /// The fatal alert, if TLS failed.
    pub fn alert(&self) -> Option<rustls::AlertDescription> {
        match self {
            Self::Client(session) => session.alert(),
            Self::Server(session) => session.alert(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAnyCert;

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
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let cert_chain = vec![CertificateDer::from(cert.cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("cert");
        server.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h3".to_vec()];
        (Arc::new(client), Arc::new(server))
    }

    fn flights(session: &mut TlsSession) -> Vec<(Vec<u8>, Option<KeyChange>)> {
        let mut flights = Vec::new();
        loop {
            let mut chunk = Vec::new();
            let change = session.write_handshake(&mut chunk);
            let advanced = !chunk.is_empty() || change.is_some();
            flights.push((chunk, change));
            if !advanced {
                break;
            }
        }
        flights
    }

    fn feed(peer: &mut TlsSession, flights: Vec<(Vec<u8>, Option<KeyChange>)>) -> Vec<KeyChange> {
        let mut keys = Vec::new();
        for (data, change) in flights {
            if !data.is_empty() {
                peer.read_handshake(&data).expect("handshake segment");
            }
            if let Some(change) = change {
                keys.push(change);
            }
        }
        keys
    }

    fn has_handshake(keys: &[KeyChange]) -> bool {
        keys.iter()
            .any(|key| matches!(key, KeyChange::Handshake { .. }))
    }

    fn has_one_rtt(keys: &[KeyChange]) -> bool {
        keys.iter()
            .any(|key| matches!(key, KeyChange::OneRtt { .. }))
    }

    #[test]
    fn handshake_produces_handshake_and_one_rtt_keys() {
        let (client_config, server_config) = configs();
        let mut client = TlsSession::client(
            client_config,
            ServerName::try_from("localhost").expect("name"),
            b"client-params".to_vec(),
        )
        .expect("client");
        let mut server =
            TlsSession::server(server_config, b"server-params".to_vec()).expect("server");

        let client_hello = flights(&mut client);
        assert!(client_hello.iter().any(|(data, _)| !data.is_empty()));
        let client_keys = feed(&mut server, client_hello);
        assert!(client_keys.is_empty());
        assert_eq!(
            server.peer_transport_parameters().as_deref(),
            Some(b"client-params".as_slice())
        );

        let server_flight = flights(&mut server);
        let server_keys = feed(&mut client, server_flight);
        assert!(has_handshake(&server_keys));
        assert!(has_one_rtt(&server_keys));
        assert_eq!(
            client.peer_transport_parameters().as_deref(),
            Some(b"server-params".as_slice())
        );

        let client_flight = flights(&mut client);
        let client_keys = feed(&mut server, client_flight);
        assert!(has_handshake(&client_keys));
        assert!(has_one_rtt(&client_keys));

        let server_tail = flights(&mut server);
        let _ = feed(&mut client, server_tail);
        assert!(!client.is_handshaking());
    }
}
