//! netfyr-test-utils: helpers for integration tests requiring network namespaces.

pub mod dnsmasq;
pub mod netns;

pub use dnsmasq::DnsmasqGuard;
pub use netns::NetnsGuard;
