// SPDX-License-Identifier: MIT

//! Minimal WebTransport echo origin used by external interop clients.
//!
//! Prints `PORT=<port>` on stdout, accepts one H3 WebTransport session, echoes
//! one bidirectional stream, then exits after a short grace period.

use std::sync::Arc;

use netune_quic::owned::{Endpoint, ServerConfigOwned};
use netune_quic::wire::transport_parameters::TransportParameters;
use netune_webtransport::{WebTransportServer, WebTransportSettings};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("interop_server: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params.not_before = rcgen::date_time_ymd(2026, 11, 9);
    params.not_after = rcgen::date_time_ymd(2026, 11, 20);
    let signing_key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&signing_key)?;
    let cert_path = std::env::temp_dir().join("netune-webtransport-interop-cert.der");
    std::fs::write(&cert_path, cert.der())?;
    let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = Endpoint::server(
        "127.0.0.1:0",
        ServerConfigOwned {
            tls: Arc::new(tls),
            transport: TransportParameters {
                initial_max_data: Some(16 * 1024 * 1024),
                initial_max_stream_data_bidi_local: Some(1 << 20),
                initial_max_stream_data_bidi_remote: Some(1 << 20),
                initial_max_stream_data_uni: Some(1 << 20),
                initial_max_streams_bidi: Some(100),
                initial_max_streams_uni: Some(100),
                max_datagram_frame_size: Some(65_535),
                reset_stream_at: true,
                ..TransportParameters::default()
            },
            retry: false,
            congestion: netune_quic::CongestionAlgorithm::NewReno,
            enable_early_data: false,
        },
    )
    .await?;
    println!("PORT={}", endpoint.local_addr().port());
    println!("CERT={}", cert_path.display());
    use std::io::Write;
    std::io::stdout().flush()?;

    let connection = endpoint.accept().await.map_err(|error| error.to_string())?;
    let mut webtransport = WebTransportServer::new(connection, WebTransportSettings::default())
        .await
        .map_err(|error| error.to_string())?;
    let mut session = webtransport
        .accept()
        .await
        .map_err(|error| error.to_string())?
        .ok_or("no WebTransport session")?;
    let mut stream = session
        .accept_bidi()
        .await
        .map_err(|error| error.to_string())?;
    let data = stream
        .recv
        .read(1024)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("empty peer stream")?;
    println!("GOT={}", String::from_utf8_lossy(&data));
    stream.send.write_all(b"pong from netune").await?;
    stream.send.finish().await?;

    let mut uni = session
        .accept_uni()
        .await
        .map_err(|error| error.to_string())?;
    let data = uni
        .read(1024)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("empty peer unidirectional stream")?;
    println!("UNI={}", String::from_utf8_lossy(&data));
    let mut reply = session
        .open_uni()
        .await
        .map_err(|error| error.to_string())?;
    reply
        .write_all(b"pong uni from netune")
        .await
        .map_err(|error| error.to_string())?;
    reply.finish().await.map_err(|error| error.to_string())?;

    let data = session
        .next_datagram()
        .await
        .map_err(|error| error.to_string())?;
    println!("DATAGRAM={}", String::from_utf8_lossy(&data));
    session
        .send_datagram(b"pong datagram from netune")
        .await
        .map_err(|error| error.to_string())?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok(())
}
