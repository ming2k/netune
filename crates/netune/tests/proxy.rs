//! Proxy end to end: HTTP `CONNECT` and SOCKS5, against hermetic proxies.
//!
//! Each proxy is a real server that performs the real handshake and then pumps
//! bytes, so the assertions cover the whole path: the client tunnels, the
//! origin's response arrives, the trace records the tunnel, and the credentials
//! (when configured) actually appear on the wire.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use http::Method;
use netune::{
    Client, ClientConfig, Pool, Proxy, ProxyConnector, RequestHead, Target, TcpConnector,
};
use netune_trace::{EventKind, Recorder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that answers one request with a fixed body.
async fn origin(listener: TcpListener, body: &'static str) {
    let (mut socket, _) = listener.accept().await.expect("origin accept");
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await.expect("origin read");
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    socket
        .write_all(response.as_bytes())
        .await
        .expect("origin write");
    socket.flush().await.expect("origin flush");
}

/// An HTTP `CONNECT` proxy. Records every `CONNECT` line it sees.
async fn http_proxy(listener: TcpListener, seen: Arc<Mutex<Vec<String>>>) {
    let (mut client, _) = listener.accept().await.expect("proxy accept");
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = client.read(&mut buffer).await.expect("proxy read");
        if read == 0 {
            return;
        }
        head.extend_from_slice(&buffer[..read]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    seen.lock().expect("seen").push(text.clone());

    let authority = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("CONNECT target")
        .to_string();
    let mut upstream = TcpStream::connect(&authority)
        .await
        .expect("proxy upstream");
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .expect("proxy reply");
    client.flush().await.expect("proxy flush");
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// A SOCKS5 proxy supporting no-auth and user/pass, recording the auth it saw.
async fn socks5_proxy(listener: TcpListener, seen: Arc<Mutex<Vec<String>>>, require_auth: bool) {
    let (mut client, _) = listener.accept().await.expect("socks accept");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.expect("greeting");
    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods).await.expect("methods");
    let method = if require_auth { 0x02 } else { 0x00 };
    client
        .write_all(&[0x05, method])
        .await
        .expect("method reply");

    if method == 0x02 {
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await.expect("auth header");
        let mut user = vec![0u8; header[1] as usize];
        client.read_exact(&mut user).await.expect("auth user");
        let mut length = [0u8; 1];
        client.read_exact(&mut length).await.expect("auth length");
        let mut password = vec![0u8; length[0] as usize];
        client
            .read_exact(&mut password)
            .await
            .expect("auth password");
        seen.lock().expect("seen").push(format!(
            "{}:{}",
            String::from_utf8_lossy(&user),
            String::from_utf8_lossy(&password)
        ));
        client.write_all(&[0x01, 0x00]).await.expect("auth ok");
    }

    // VER, CMD, RSV, ATYP, then the domain length.
    let mut request = [0u8; 5];
    client.read_exact(&mut request).await.expect("request");
    let mut host = vec![0u8; request[4] as usize];
    client.read_exact(&mut host).await.expect("request host");
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await.expect("request port");
    let authority = format!(
        "{}:{}",
        String::from_utf8_lossy(&host),
        u16::from_be_bytes(port)
    );
    seen.lock().expect("seen").push(authority.clone());

    let mut upstream = TcpStream::connect(&authority)
        .await
        .expect("socks upstream");
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("socks reply");
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn bind() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    (listener, address)
}

async fn fetch_through(proxy: Proxy, origin_address: &str) -> (String, Arc<Mutex<Recorder>>) {
    let client = Client::new(
        ProxyConnector::new(TcpConnector::new(), proxy),
        Pool::default(),
        ClientConfig::default(),
    );
    let recorder = Arc::new(Mutex::new(Recorder::start(1024)));
    let mut response = client
        .send(
            &Target::plain(origin_address),
            Arc::clone(&recorder),
            RequestHead::new(Method::GET, "/through-proxy"),
            None,
        )
        .await
        .expect("send through proxy");
    assert_eq!(response.head.status, http::StatusCode::OK);
    let body =
        String::from_utf8_lossy(&response.body.read_to_end().await.expect("body")).to_string();
    (body, recorder)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_connect_tunnel_carries_the_request_and_is_traced() {
    let (origin_listener, origin_address) = bind().await;
    let (proxy_listener, proxy_address) = bind().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, "through the tunnel"));
    let proxy_task = tokio::spawn(http_proxy(proxy_listener, Arc::clone(&seen)));

    let proxy = Proxy::parse(&format!("http://{proxy_address}")).expect("proxy");
    let (body, recorder) = fetch_through(proxy, &origin_address).await;
    assert_eq!(body, "through the tunnel");

    let seen = seen.lock().expect("seen").clone();
    assert!(
        seen[0].starts_with(&format!("CONNECT {origin_address} HTTP/1.1")),
        "{:?}",
        seen[0]
    );
    let kinds: Vec<EventKind> = recorder
        .lock()
        .expect("recorder")
        .log()
        .iter()
        .map(|event| event.kind)
        .collect();
    assert!(kinds.contains(&EventKind::ProxyTunnel), "tunnel traced");

    let _ = (origin_task.await, proxy_task.await);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_proxy_credentials_reach_the_wire() {
    let (origin_listener, origin_address) = bind().await;
    let (proxy_listener, proxy_address) = bind().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, "ok"));
    let proxy_task = tokio::spawn(http_proxy(proxy_listener, Arc::clone(&seen)));

    let proxy = Proxy::parse(&format!("http://user:secret@{proxy_address}")).expect("proxy");
    let (body, _) = fetch_through(proxy, &origin_address).await;
    assert_eq!(body, "ok");

    let seen = seen.lock().expect("seen").clone();
    // base64("user:secret")
    assert!(
        seen[0].contains("proxy-authorization: Basic dXNlcjpzZWNyZXQ=")
            || seen[0].contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ="),
        "{:?}",
        seen[0]
    );
    let _ = (origin_task.await, proxy_task.await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socks5_tunnel_carries_the_request() {
    let (origin_listener, origin_address) = bind().await;
    let (proxy_listener, proxy_address) = bind().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, "via socks"));
    let proxy_task = tokio::spawn(socks5_proxy(proxy_listener, Arc::clone(&seen), false));

    let proxy = Proxy::parse(&format!("socks5://{proxy_address}")).expect("proxy");
    let (body, recorder) = fetch_through(proxy, &origin_address).await;
    assert_eq!(body, "via socks");
    assert_eq!(seen.lock().expect("seen").as_slice(), &[origin_address]);
    let kinds: Vec<EventKind> = recorder
        .lock()
        .expect("recorder")
        .log()
        .iter()
        .map(|event| event.kind)
        .collect();
    assert!(kinds.contains(&EventKind::ProxyTunnel));
    let _ = (origin_task.await, proxy_task.await);
}

#[tokio::test(flavor = "multi_thread")]
async fn socks5_user_pass_authentication_is_negotiated() {
    let (origin_listener, origin_address) = bind().await;
    let (proxy_listener, proxy_address) = bind().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, "authenticated"));
    let proxy_task = tokio::spawn(socks5_proxy(proxy_listener, Arc::clone(&seen), true));

    let proxy = Proxy::parse(&format!("socks5://alice:hunter2@{proxy_address}")).expect("proxy");
    let (body, _) = fetch_through(proxy, &origin_address).await;
    assert_eq!(body, "authenticated");
    assert_eq!(
        seen.lock().expect("seen").first().map(String::as_str),
        Some("alice:hunter2")
    );
    let _ = (origin_task.await, proxy_task.await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_tunnel_is_an_error_not_a_truncated_stream() {
    // A proxy that answers 403 to every CONNECT.
    let (proxy_listener, proxy_address) = bind().await;
    let refusing = tokio::spawn(async move {
        let (mut socket, _) = proxy_listener.accept().await.expect("accept");
        let mut buffer = [0u8; 1024];
        let _ = socket.read(&mut buffer).await;
        socket
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .await
            .expect("refuse");
    });

    let proxy = Proxy::parse(&format!("http://{proxy_address}")).expect("proxy");
    let client = Client::new(
        ProxyConnector::new(TcpConnector::new(), proxy),
        Pool::default(),
        ClientConfig::default(),
    );
    let error = client
        .send(
            &Target::plain("127.0.0.1:9"),
            Arc::new(Mutex::new(Recorder::start(64))),
            RequestHead::new(Method::GET, "/"),
            None,
        )
        .await
        .err()
        .expect("refused");
    assert_eq!(error.class(), "connect");
    assert!(error.to_string().contains("403"), "{error}");
    let _ = refusing.await;
}
