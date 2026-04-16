#!/bin/bash
# 401-dhcpv4-acquire-lease.sh
# Integration test: DHCPv4 factory acquires a lease in an unprivileged namespace.
# Mapped to acceptance criteria: "Factory acquires a DHCP lease" and
# "Acquire DHCP lease in namespace".
#
# Requires: unshare, ip (iproute2), dnsmasq
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/401-dhcpv4-acquire-lease.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
    exit 1
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "FAIL: dnsmasq not found; install dnsmasq to run DHCP integration tests" >&2
    exit 1
fi

# Enter an unprivileged user+network namespace (re-executes this script inside).
netns_setup "$@"

# ---------- Inside the namespace ----------

TMPDIR_TEST=$(mktemp -d)
trap 'kill "${DAEMON_PID:-}" 2>/dev/null; rm -rf "$TMPDIR_TEST"' EXIT

SOCKET_PATH="$TMPDIR_TEST/netfyr.sock"
POLICY_DIR="$TMPDIR_TEST/policies"
mkdir -p "$POLICY_DIR"

# Create veth pair for DHCP: veth-dhcp0 (client) / veth-dhcp1 (server side).
create_veth veth-dhcp0 veth-dhcp1

# Configure the server-side interface with a static address.
add_address veth-dhcp1 10.99.0.1/24

# Start dnsmasq on veth-dhcp1 serving range 10.99.0.100-10.99.0.200.
start_dnsmasq veth-dhcp1 10.99.0.1 10.99.0.100 10.99.0.200 120

# Write the DHCPv4 policy file.
cat > "$POLICY_DIR/dhcp.yaml" <<'EOF'
kind: policy
name: eth0-dhcp
factory: dhcpv4
selector:
  name: veth-dhcp0
EOF

# Start the daemon in background.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

# Wait for daemon socket to appear (poll up to 5 seconds).
SOCKET_WAIT=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 401-dhcpv4-acquire-lease: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# Submit the DHCP policy to the daemon.
NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_DIR/dhcp.yaml"

# Wait up to 10 seconds for the DHCP lease (poll ip addr show).
LEASE_WAIT=0
while ! ip addr show dev veth-dhcp0 2>/dev/null | grep -q "10.99.0."; do
    if (( LEASE_WAIT >= 100 )); then
        echo "FAIL: 401-dhcpv4-acquire-lease: veth-dhcp0 did not acquire a DHCP address within 10 seconds" >&2
        echo "      ip addr show veth-dhcp0:" >&2
        ip addr show dev veth-dhcp0 >&2 || true
        exit 1
    fi
    sleep 0.1
    (( LEASE_WAIT++ )) || true
done

# Assert the address is in the expected range.
assert_has_address veth-dhcp0 "10.99.0."

echo "PASS: 401-dhcpv4-acquire-lease"
