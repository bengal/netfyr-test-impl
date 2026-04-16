#!/bin/bash
# 401-dhcpv4-daemon-restart.sh
# Integration test: DHCP lease is re-acquired after daemon restart.
# Mapped to acceptance criteria: "DHCP lease survives daemon restart".
#
# Requires: unshare, ip (iproute2), dnsmasq
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/401-dhcpv4-daemon-restart.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "SKIP: netfyr binary not found at $NETFYR_BIN; run 'cargo build -p netfyr-cli' first"
    exit 0
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "SKIP: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN; run 'cargo build -p netfyr-daemon' first"
    exit 0
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "SKIP: dnsmasq not found; install dnsmasq to run DHCP integration tests"
    exit 0
fi

# Enter an unprivileged user+network namespace.
netns_setup "$@" || { echo "SKIP: unshare --user --net not available; skipping namespace test"; exit 0; }

# ---------- Inside the namespace ----------

TMPDIR_TEST=$(mktemp -d)
DAEMON_PID=""
trap 'kill "${DAEMON_PID:-}" 2>/dev/null; rm -rf "$TMPDIR_TEST"' EXIT

SOCKET_PATH="$TMPDIR_TEST/netfyr.sock"
POLICY_DIR="$TMPDIR_TEST/policies"
mkdir -p "$POLICY_DIR"

# Create veth pair for DHCP.
create_veth veth-dhcp0 veth-dhcp1
add_address veth-dhcp1 10.99.0.1/24

# Start dnsmasq (remains running across the daemon restart).
start_dnsmasq veth-dhcp1 10.99.0.1 10.99.0.100 10.99.0.200 120

# Write the DHCP policy to disk (persisted for daemon reload).
cat > "$POLICY_DIR/dhcp.yaml" <<'EOF'
kind: policy
name: eth0-dhcp
factory: dhcpv4
selector:
  name: veth-dhcp0
EOF

# Helper: wait for daemon socket to appear.
wait_for_socket() {
    local waited=0
    while [[ ! -S "$SOCKET_PATH" ]]; do
        if (( waited >= 50 )); then
            echo "FAIL: 401-dhcpv4-daemon-restart: daemon socket did not appear within 5 seconds" >&2
            exit 1
        fi
        sleep 0.1
        (( waited++ )) || true
    done
}

# Helper: wait for DHCP address on veth-dhcp0.
wait_for_dhcp_address() {
    local waited=0
    while ! ip addr show dev veth-dhcp0 2>/dev/null | grep -q "10.99.0."; do
        if (( waited >= 100 )); then
            echo "FAIL: 401-dhcpv4-daemon-restart: veth-dhcp0 did not acquire a DHCP address within 10 seconds" >&2
            echo "      ip addr show veth-dhcp0:" >&2
            ip addr show dev veth-dhcp0 >&2 || true
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

# Submit the DHCP policy.
NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_DIR/dhcp.yaml"

# Wait for initial lease.
wait_for_dhcp_address
assert_has_address veth-dhcp0 "10.99.0."

# ── Restart the daemon ────────────────────────────────────────────────────────

# Stop the daemon gracefully.
kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

# Remove stale socket.
rm -f "$SOCKET_PATH"

# Clear the interface address so re-acquisition is detectable.
ip addr flush dev veth-dhcp0 2>/dev/null || true

# Restart the daemon with the same policy directory.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

wait_for_socket

# The daemon reloads the persisted policy on startup — no explicit apply needed.
# Wait for the re-acquired lease.
wait_for_dhcp_address
assert_has_address veth-dhcp0 "10.99.0."

echo "PASS: 401-dhcpv4-daemon-restart"
