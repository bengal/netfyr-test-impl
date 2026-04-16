//! Tests for SPEC-001 acceptance criteria: CLI crate produces a binary.
//!
//! Verifies that:
//! - The `netfyr-cli` binary exists in the target directory after building.
//! - Running the binary with no arguments prints "netfyr" to stdout and exits 0.

use std::path::PathBuf;
use std::process::Command;

/// Returns the path to the compiled `netfyr-cli` binary.
fn netfyr_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_netfyr-cli"))
}

// ---------------------------------------------------------------------------
// Scenario: CLI crate produces a binary
// ---------------------------------------------------------------------------

/// AC: A binary named "netfyr-cli" is produced in the target directory.
#[test]
fn test_cli_binary_exists_in_target_directory() {
    let bin = netfyr_bin();
    assert!(
        bin.exists(),
        "Expected netfyr-cli binary to exist at {:?}",
        bin
    );
}

/// AC: Running the binary prints "netfyr" to stdout.
///
/// The CLI prints "netfyr" when invoked with no subcommand (see src/main.rs).
#[test]
fn test_cli_binary_prints_netfyr_to_stdout_when_no_args_given() {
    let output = Command::new(netfyr_bin())
        .output()
        .expect("Failed to spawn netfyr-cli binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("netfyr"),
        "Expected 'netfyr' in stdout when running netfyr-cli with no arguments, got: {:?}",
        stdout
    );
}

/// AC: The binary exits with code 0 when invoked with no arguments.
#[test]
fn test_cli_binary_exits_zero_with_no_args() {
    let status = Command::new(netfyr_bin())
        .status()
        .expect("Failed to spawn netfyr-cli binary");

    assert!(
        status.success(),
        "Expected netfyr-cli to exit with code 0 when called with no arguments, got: {:?}",
        status.code()
    );
}
