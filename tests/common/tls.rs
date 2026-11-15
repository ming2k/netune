//! TLS fixtures shared by the external suites.

#![allow(unused_imports)]

pub use test_support::tls::{
    AcceptAnyCert, TestIdentity, dangerous_client_config, identity, verified_client_config,
};
