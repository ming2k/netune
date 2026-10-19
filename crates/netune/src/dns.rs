//! Asynchronous DNS resolution abstraction and implementations (ADR-0006).
//!
//! Standard network stacks delegate to the operating system's blocking resolver,
//! which leaks DNS queries over unencrypted UDP, precludes custom split-horizon
//! routing, and ties the transport to the host's DNS attribution.
//!
//! This module decouples resolution from TCP establishment:
//! - [`DnsResolver`] is an asynchronous, non-blocking trait.
//! - [`SystemResolver`] is the default platform delegate (`tokio::net::lookup_host`).
//! - [`StaticResolver`] provides an in-memory hosts table to bypass network DNS,
//!   prevent attribution leakage, and guarantee deterministic destination IPs in tests.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use crate::error::NetError;

/// Asynchronous resolver for network authorities (`host` or `host:port`).
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    /// Resolve `host` to one or more socket addresses with the target `port`.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, NetError>> + Send + 'a>>;
}

/// The default system resolver delegating to `tokio::net::lookup_host`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, NetError>> + Send + 'a>> {
        Box::pin(async move {
            let authority = format!("{host}:{port}");
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&authority)
                .await
                .map_err(|error| NetError::Resolve(format!("{host}: {error}")))?
                .collect();

            if addrs.is_empty() {
                Err(NetError::Resolve(format!("no addresses found for {host}")))
            } else {
                Ok(addrs)
            }
        })
    }
}

/// In-memory static host table resolver.
///
/// Bypasses network DNS completely to eliminate query attribution leakage,
/// pin target backend IPs, and support hermetic testing.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    table: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    fallback: Option<Arc<dyn DnsResolver>>,
}

impl StaticResolver {
    /// Create a new empty static resolver.
    pub fn new() -> Self {
        Self {
            table: Arc::new(RwLock::new(HashMap::new())),
            fallback: None,
        }
    }

    /// Map `host` to a single IP address.
    pub fn with_host(self, host: impl Into<String>, ip: IpAddr) -> Self {
        let mut table = self.table.write().unwrap_or_else(|e| e.into_inner());
        table
            .entry(host.into().to_ascii_lowercase())
            .or_default()
            .push(ip);
        drop(table);
        self
    }

    /// Configure a fallback resolver for hosts not present in the static table.
    pub fn with_fallback<R: DnsResolver + 'static>(mut self, fallback: R) -> Self {
        self.fallback = Some(Arc::new(fallback));
        self
    }

    /// Insert a host-to-IP mapping at runtime.
    pub fn insert(&self, host: impl Into<String>, ip: IpAddr) {
        let mut table = self.table.write().unwrap_or_else(|e| e.into_inner());
        table
            .entry(host.into().to_ascii_lowercase())
            .or_default()
            .push(ip);
    }
}

impl DnsResolver for StaticResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, NetError>> + Send + 'a>> {
        Box::pin(async move {
            let key = host.to_ascii_lowercase();
            let ips = {
                let table = self.table.read().unwrap_or_else(|e| e.into_inner());
                table.get(&key).cloned()
            };

            if let Some(ips) = ips
                && !ips.is_empty()
            {
                return Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect());
            }

            if let Some(fallback) = &self.fallback {
                fallback.resolve(host, port).await
            } else {
                Err(NetError::Resolve(format!(
                    "static table has no entry for '{host}'"
                )))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_resolver_maps_configured_hosts() {
        let resolver = StaticResolver::new()
            .with_host("example.local", "127.0.0.1".parse().unwrap())
            .with_host("example.local", "127.0.0.2".parse().unwrap());

        let addrs = resolver
            .resolve("EXAMPLE.LOCAL", 8080)
            .await
            .expect("resolve");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "127.0.0.1:8080".parse().unwrap());
        assert_eq!(addrs[1], "127.0.0.2:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn static_resolver_falls_back_when_configured() {
        let resolver = StaticResolver::new()
            .with_host("custom.local", "127.0.0.1".parse().unwrap())
            .with_fallback(SystemResolver);

        let addrs = resolver
            .resolve("localhost", 80)
            .await
            .expect("fallback resolve");
        assert!(!addrs.is_empty());
    }

    #[tokio::test]
    async fn static_resolver_errors_on_unmapped_host_without_fallback() {
        let resolver = StaticResolver::new();
        let result = resolver.resolve("unknown.domain", 80).await;
        assert!(matches!(result, Err(NetError::Resolve(_))));
    }
}
