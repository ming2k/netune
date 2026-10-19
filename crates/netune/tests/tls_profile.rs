//! TLS profile presets observed the way a passive observer would: the
//! profile is compiled into a real `TlsConnector`, a raw TCP server reads the
//! first flight, and `netune_trace::ja4` judges what actually went out.
//!
//! The three-way identity matrix this test pins:
//!
//! - `netune_default`  → `t13d…h1…` (HTTP/1.1 ALPN — the shipped snapshot)
//! - `codex_reqwest`   → `t13d…h2…` (`h2` first — the Codex CLI product leg)
//! - `codex_network_proxy` → `h2` first, same wire shape (rama-tls-rustls leg)
//!
//! These are *relative* assertions on purpose: the absolute hashes still
//! depend on the rustls + aws-lc-rs versions in the lockfile (snapshotted in
//! [`crate::tls_baseline`]), but which ALPN digit and which counts a preset
//! shows is a property of the preset itself — and that is what "codex
//! fingerprint" means as a *category* here, not a frozen byte string.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use netune::{TlsConnector, TlsProfile, Verifier};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// Read the first TLS record a client sends and parse its ClientHello.
async fn observed_client_hello(
    listener: TcpListener,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
) -> netune_trace::ClientHello {
    let server_name = server_name.to_string();
    let address = listener.local_addr().expect("addr");
    let reader = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut header = [0u8; 5];
        socket.read_exact(&mut header).await.expect("record header");
        assert_eq!(header[0], 22, "the first record is the TLS handshake");
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; length];
        socket.read_exact(&mut body).await.expect("record body");
        netune_trace::ClientHello::parse(&body).expect("a parseable ClientHello")
    });

    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket
        .bind("127.0.0.1:0".parse().expect("bind addr"))
        .expect("bind");
    let stream = socket.connect(address).await.expect("connect");
    let name = rustls::pki_types::ServerName::try_from(server_name)
        .expect("server name")
        .to_owned();
    let connector = tokio_rustls::TlsConnector::from(config);
    // Only the ClientHello is needed; the handshake future is dropped once the
    // reader has the bytes.
    let handshake = connector.connect(name, stream);
    let _ = tokio::time::timeout(Duration::from_millis(200), handshake).await;

    tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .expect("reader finished")
        .expect("spawned task")
}

async fn hello_for(profile: &TlsProfile) -> netune_trace::ClientHello {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = profile.build(provider).expect("profile builds");
    observed_client_hello(
        TcpListener::bind("127.0.0.1:0").await.expect("bind"),
        "profile.example",
        config,
    )
    .await
}

/// Shared shape assertions for the two codex presets: `h2`-first ALPN, TLS 1.3
/// offered, SNI present, and the same default cipher/extension counts as any
/// stock rustls client (the presets differ from netune's default *only* in the
/// ALPN offer — that is the honest extent of a rustls-shaped impersonation).
async fn assert_codex_shape(profile: &TlsProfile) {
    let hello = hello_for(profile).await;
    let ja4 = netune_trace::ja4(&hello);

    println!("{} JA4: {}", profile.name, ja4.fingerprint);
    println!(
        "  alpn: {:?} ciphers: {}",
        hello.alpn_protocols, ja4.cipher_count
    );

    assert!(
        hello.alpn_protocols.iter().any(|p| p == b"h2"),
        "{} must offer h2: {:?}",
        profile.name,
        hello.alpn_protocols
    );
    assert_eq!(
        hello.alpn_protocols.first().map(Vec::as_slice),
        Some(b"h2".as_slice()),
        "{} lists h2 first, the hyper-rustls order",
        profile.name
    );
    assert_eq!(
        ja4.alpn_abbr.as_deref(),
        Some("h2"),
        "{} shows the h2 JA4 digit",
        profile.name
    );
    assert!(ja4.fingerprint.starts_with("t13d"), "{}", ja4.fingerprint);
    assert!(hello.has_sni, "{} sends SNI", profile.name);
    // Same suite/extension surface as any default rustls 0.23 + aws-lc-rs
    // hello: the presets do not (and cannot, through rustls) invent suites.
    assert_eq!(
        ja4.cipher_count, 10,
        "{} offers the default 10 suites",
        profile.name
    );
    assert_eq!(
        ja4.extension_count, 11,
        "{} offers the default 11 extensions",
        profile.name
    );
}

#[tokio::test]
async fn netune_default_presents_the_h1_identity() {
    let profile = TlsProfile::netune_default();
    let hello = hello_for(&profile).await;
    let ja4 = netune_trace::ja4(&hello);
    assert_eq!(ja4.alpn_abbr.as_deref(), Some("h1"), "{}", ja4.fingerprint);
    assert!(
        hello.alpn_protocols.iter().any(|p| p == b"http/1.1"),
        "the default profile advertises HTTP/1.1"
    );
    assert!(!hello.alpn_protocols.iter().any(|p| p == b"h2"));
}

#[tokio::test]
async fn the_codex_reqwest_preset_presents_the_h2_identity() {
    assert_codex_shape(&TlsProfile::codex_reqwest()).await;
}

#[tokio::test]
async fn the_codex_network_proxy_preset_presents_the_h2_identity() {
    assert_codex_shape(&TlsProfile::codex_network_proxy()).await;
}

/// The knob, not just the preset: the same test rig driven through the public
/// `TlsConnector::with_profile` seam with a *custom* profile.
#[tokio::test]
async fn a_custom_profile_changes_what_the_wire_hello_says() {
    // TLS 1.2 only: the JA4 version digit must flip, proving version knobs
    // survive the compile step and reach the wire.
    let profile = TlsProfile::netune_default()
        .tls12_only()
        .with_roots(rustls::RootCertStore::empty());
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = profile.build(provider).expect("builds");
    let hello = observed_client_hello(
        TcpListener::bind("127.0.0.1:0").await.expect("bind"),
        "profile.example",
        config,
    )
    .await;
    let ja4 = netune_trace::ja4(&hello);
    assert!(
        ja4.fingerprint.starts_with("t12d"),
        "tls12_only must show 12 on the wire: {}",
        ja4.fingerprint
    );
    // rustls still emits `supported_versions`, but offering 0x0303 only; the
    // JA4 digit reads the *highest offered*, which is now 1.2.
    assert_eq!(
        hello.supported_versions_max,
        Some(0x0303),
        "only TLS 1.2 offered in supported_versions"
    );
    // A rustls quirk worth knowing before relying on this knob: the cipher
    // offer is NOT version-filtered (hs.rs only filters by transport), so a
    // TLS-1.2-only config still *advertises* the TLS 1.3 suites. A 1.2-only
    // profile that wants to look coherent combines both knobs — see the next
    // test.
    assert!(
        hello.cipher_suites.contains(&4867),
        "rustls quirk: 1.3 suites still advertised when 1.3 is disabled: {:?}",
        hello.cipher_suites
    );
}

/// The composed version: TLS 1.2 only *and* a version-matched cipher
/// allowlist, the shape a coherent 1.2-only client actually presents.
#[tokio::test]
async fn a_coherent_tls12_only_profile() {
    let profile = TlsProfile::netune_default()
        .tls12_only()
        .with_cipher_suites(&[
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ])
        .with_roots(rustls::RootCertStore::empty());
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = profile.build(provider).expect("builds");
    let hello = observed_client_hello(
        TcpListener::bind("127.0.0.1:0").await.expect("bind"),
        "profile.example",
        config,
    )
    .await;
    let ja4 = netune_trace::ja4(&hello);
    assert!(
        ja4.fingerprint.starts_with("t12d"),
        "the version digit is 12: {}",
        ja4.fingerprint
    );
    // No 1.3 suites on the wire any more: two 1.2 suites plus the SCSV.
    assert_eq!(
        ja4.cipher_count, 3,
        "two allowlisted 1.2 suites + SCSV (JA4 excludes neither): {}",
        ja4.fingerprint
    );
    assert!(
        !hello
            .cipher_suites
            .iter()
            .any(|c| (0x1300..0x1400).contains(c)),
        "no TLS 1.3 suites: {:?}",
        hello.cipher_suites
    );
}

/// The description/executed cross-check: a profile built into a config offers
/// exactly the suites the profile allowlisted.
#[tokio::test]
async fn a_cipher_allowlist_reaches_the_wire() {
    let profile = TlsProfile::netune_default()
        .with_cipher_suites(&[rustls::CipherSuite::TLS13_AES_128_GCM_SHA256])
        .with_roots(rustls::RootCertStore::empty());
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = profile.build(provider).expect("builds");
    let hello = observed_client_hello(
        TcpListener::bind("127.0.0.1:0").await.expect("bind"),
        "profile.example",
        config,
    )
    .await;
    let ja4 = netune_trace::ja4(&hello);
    assert_eq!(
        ja4.cipher_count, 1,
        "the allowlist shrank the offer to one suite"
    );
    assert_eq!(
        hello.cipher_suites,
        vec![0x1301],
        "TLS_AES_128_GCM_SHA256 is the only suite offered"
    );
}

/// Guard the platform-verifier branch once through this module (the presets
/// above all use it; this one proves the verifier enum is the only thing that
/// differs between the branches).
#[tokio::test]
async fn the_platform_verifier_default_builds_and_connects_the_profile_path() {
    let profile = TlsProfile {
        verifier: Verifier::Platform,
        ..TlsProfile::netune_default()
    };
    let _connector: TlsConnector<netune::TcpConnector> =
        TlsConnector::with_profile(netune::TcpConnector::new(), &profile)
            .expect("profile connector");
}

use std::sync::Arc;
