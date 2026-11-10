// SPDX-License-Identifier: MIT

//! Fetch one plaintext HTTP resource.
//!
//! ```text
//! cargo run -p netune --example fetch -- http://127.0.0.1:8080/health
//! ```
//!
//! The example keeps the library's error model: failures stay typed and are
//! printed through `Display`, never unwrapped into a panic.

use std::error::Error;
use std::io::Write;

use http::Method;
use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("fetch: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let url = std::env::args()
        .nth(1)
        .ok_or("usage: fetch http://host:port[/path]")?;
    let rest = url
        .strip_prefix("http://")
        .ok_or("only plaintext http:// URLs are supported")?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };

    let client = Client::new(
        TcpConnector::new(),
        Pool::default(),
        ClientConfig::default(),
    );
    let mut response = client
        .request(
            &Target::plain(authority),
            RequestHead::new(Method::GET, path),
            None,
        )
        .await?;
    let body = response.body.read_to_end().await?;

    eprintln!("status {}", response.head.status);
    std::io::stdout().write_all(&body)?;
    Ok(())
}
