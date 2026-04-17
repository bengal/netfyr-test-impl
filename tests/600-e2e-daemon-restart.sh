#!/bin/bash
# 600-e2e-daemon-restart.sh -- End-to-end: policy persists across daemon restart.
#
# Requires: unshare, ip (iproute2)
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/600-e2e-daemon-restart.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 600-e2e-daemon-restart: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi
if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 600-e2e-daemon-restart: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
    exit 1
fi

netns_setup "$@"

# ---------- Inside the namespace ----------

TMPDIR_TEST=$(mktemp -d)
DAEMON_PID=""
trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT

SOCKET_PATH="$TMPDIR_TEST/netfyr.sock"
POLICY_DIR="$TMPDIR_TEST/policies"
mkdir -p "$POLICY_DIR"

create_veth veth-e2e0 veth-e2e1

# Helper: wait for the daemon socket to appear (up to 5 seconds).
wait_for_socket() {
    local waited=0
    while [[ ! -S "$SOCKET_PATH" ]]; do
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "FAIL: 600-e2e-daemon-restart: daemon exited before socket appeared" >&2
            exit 1
        fi
        if (( waited >= 50 )); then
            echo "FAIL: 600-e2e-daemon-restart: daemon socket did not appear within 5 seconds" >&2
            exit 1
        fi
        sleep 0.1
        (( waited++ )) || true
    done
}

# ── First daemon start ────────────────────────────────────────────────────────

NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

wait_for_socket

# Apply a static policy setting mtu=1400 on veth-e2e0.
POLICY_FILE="$TMPDIR_TEST/policy.yaml"
cat > "$POLICY_FILE" <<'EOF'
kind: policy
name: e2e-restart
factory: static
priority: 100
state:
  type: ethernet
  name: veth-e2e0
  mtu: 1400
EOF

APPLY_EXIT=0
NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_FILE" || APPLY_EXIT=$?
if [[ $APPLY_EXIT -ne 0 ]]; then
    echo "FAIL: 600-e2e-daemon-restart: initial apply exited with code $APPLY_EXIT" >&2
    exit 1
fi

assert_mtu veth-e2e0 1400

# ── Restart the daemon ────────────────────────────────────────────────────────

# Stop the daemon gracefully (SIGTERM).
kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

# Remove stale socket so the new daemon can bind.
rm -f "$SOCKET_PATH"

# Reset the kernel MTU to default so we can verify the daemon re-applies it.
ip link set dev veth-e2e0 mtu 1500

# Start a new daemon instance with the same persistent policy directory.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

wait_for_socket

# The daemon reloads persisted policies on startup and runs initial reconciliation.
# No explicit `netfyr apply` needed — mtu=1400 must be restored automatically.
assert_mtu veth-e2e0 1400

echo "PASS: 600-e2e-daemon-restart"
