//! netfyr-test-utils: helpers for integration tests requiring network namespaces.

pub mod netns;

pub use netns::NetnsGuard;
