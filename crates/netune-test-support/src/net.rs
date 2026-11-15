//! Loopback socket fixtures.

use tokio::net::{TcpListener, TcpStream};

/// A connected loopback pair with `TCP_NODELAY` set on both ends.
///
/// The pair is established before it is returned, so a test never races its
/// own connect.
pub async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("loopback address");
    let connecting =
        tokio::spawn(async move { TcpStream::connect(address).await.expect("connect") });
    let (server, _) = listener.accept().await.expect("accept");
    let client = connecting.await.expect("join connector");
    client.set_nodelay(true).expect("nodelay client");
    server.set_nodelay(true).expect("nodelay server");
    (client, server)
}

/// A loopback address that was just released, so a connect to it is refused.
pub fn closed_address() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    address.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_pair_is_connected_and_writable() {
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(b"ping").await.expect("write");
        let mut buffer = [0u8; 4];
        server.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"ping");
    }
}
