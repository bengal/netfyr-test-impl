#!/bin/bash
# 001-binary-daemon.sh
# Verify that the netfyr-daemon crate produces an executable binary named
# "netfyr-daemon" and that running it prints "netfyr" as the first line of
# stdout.
#
# The daemon is a long-running process. This test starts it with a temporary
# socket path and policy dir, captures the first line of stdout, then kills it.
#
# Prerequisite: cargo build must have been run before this script.
#
# Usage: bash tests/001-binary-daemon.sh
#   Override binary path: NETFYR_DAEMON_BIN=/path/to/netfyr-daemon bash tests/001-binary-daemon.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

# Prerequisite: binary must exist and be executable.
if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 001-binary-daemon: netfyr-daemon binary not found or not executable at $NETFYR_DAEMON_BIN" >&2
    echo "      Build first with: cargo build -p netfyr-daemon" >&2
    exit 1
fi

# Create a temporary directory for the daemon's socket and policy store so the
# daemon can start without needing system paths.
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

SOCKET_PATH="$TMPDIR_TEST/netfyr-test.sock"
POLICY_DIR="$TMPDIR_TEST/policies"
mkdir -p "$POLICY_DIR"

# Start the daemon in the background. Redirect stderr to /dev/null to avoid
# tracing output cluttering the test output. Capture stdout via a pipe.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" >"$TMPDIR_TEST/stdout.txt" 2>/dev/null &
DAEMON_PID=$!

# Give the daemon a moment to print its first line.
sleep 0.5

# Kill the daemon now that we've captured what we need.
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# Read the first line of stdout.
first_line=$(head -n 1 "$TMPDIR_TEST/stdout.txt" 2>/dev/null || echo "")

# The spec requires that the daemon binary prints "netfyr" to stdout on startup.
if [[ "$first_line" != "netfyr" ]]; then
    echo "FAIL: 001-binary-daemon: expected first stdout line 'netfyr', got: '$first_line'" >&2
    exit 1
fi

echo "PASS: 001-binary-daemon"
