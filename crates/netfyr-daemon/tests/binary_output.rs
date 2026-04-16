//! Tests for SPEC-001 acceptance criteria: Daemon crate produces a binary.
//!
//! Verifies that:
//! - The `netfyr-daemon` binary exists in the target directory after building.
//! - The binary is executable.
//!
//! NOTE (spec discrepancy): SPEC-001 states "running the binary prints 'netfyr'
//! to stdout". The actual implementation is a full daemon that starts a Varlink
//! server and does not print "netfyr" and exit. The stub behaviour described in
//! the spec was the initial placeholder; the implementation has progressed beyond
//! that stub. The verify phase should update the acceptance criterion or revert
//! the binary to stub behaviour for this story.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Returns the path to the compiled `netfyr-daemon` binary.
fn netfyr_daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_netfyr-daemon"))
}

// ---------------------------------------------------------------------------
// Scenario: Daemon crate produces a binary
// ---------------------------------------------------------------------------

/// AC: A binary named "netfyr-daemon" is produced in the target directory.
#[test]
fn test_daemon_binary_exists_in_target_directory() {
    let bin = netfyr_daemon_bin();
    assert!(
        bin.exists(),
        "Expected netfyr-daemon binary to exist at {:?}",
        bin
    );
}

/// AC: The binary file is non-empty (sanity check that it was linked properly).
#[test]
fn test_daemon_binary_is_non_empty() {
    let bin = netfyr_daemon_bin();
    let metadata = std::fs::metadata(&bin)
        .unwrap_or_else(|e| panic!("Failed to stat {:?}: {}", bin, e));
    assert!(
        metadata.len() > 0,
        "netfyr-daemon binary at {:?} must be non-empty",
        bin
    );
}

/// AC: Running the binary prints "netfyr" to stdout.
///
/// NOTE: This test encodes the SPEC-001 stub behaviour ("fn main() { println!(\"netfyr\"); }").
/// The current implementation is a full daemon — it starts a Varlink server and
/// does not emit "netfyr" to stdout. This test will fail until either:
///   (a) the spec is updated to reflect the daemon's actual startup behaviour, or
///   (b) the daemon is modified to print "netfyr" when a suitable flag is passed.
///
/// The test uses a short timeout and an explicit socket/policy dir so the daemon
/// does not pollute the host, and kills the subprocess after capturing output.
#[test]
fn test_daemon_binary_prints_netfyr_to_stdout() {
    use std::io::Read;

    // Provide required env vars so the daemon does not try to access real paths.
    let socket_dir = tempfile::tempdir().expect("failed to create temp socket dir");
    let policy_dir = tempfile::tempdir().expect("failed to create temp policy dir");
    let socket_path = socket_dir.path().join("netfyr-test.sock");

    let mut child = Command::new(netfyr_daemon_bin())
        .env("NETFYR_SOCKET_PATH", socket_path.as_os_str())
        .env("NETFYR_POLICY_DIR", policy_dir.path())
        .env("RUST_LOG", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn netfyr-daemon binary");

    // Give the process a short window to emit any startup output.
    std::thread::sleep(Duration::from_millis(300));

    // Kill the daemon (it is a long-running server; we only care about startup output).
    let _ = child.kill();

    let mut stdout_bytes = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut stdout_bytes);
    }
    let _ = child.wait();

    let stdout = String::from_utf8_lossy(&stdout_bytes);

    // NOTE: This assertion will fail for the current implementation.
    // See module-level doc comment for the spec discrepancy.
    assert!(
        stdout.contains("netfyr"),
        "Expected 'netfyr' in netfyr-daemon stdout, got: {:?}",
        stdout
    );
}
