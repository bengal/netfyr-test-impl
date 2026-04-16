#!/bin/bash
# 401-dhcpv4-unmanaged-interface.sh
# Integration test: A DHCPv4 policy for one interface does not disturb another
# unmanaged interface's configuration.
# Mapped to acceptance criteria: "DHCP does not tear down unmanaged interfaces".
#
# Requires: unshare, ip (iproute2), dnsmasq
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/401-dhcpv4-unmanaged-interface.sh

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
trap 'kill "${DAEMON_PID:-}" 2>/dev/null; rm -rf "$TMPDIR_TEST"' EXIT

SOCKET_PATH="$TMPDIR_TEST/netfyr.sock"
POLICY_DIR="$TMPDIR_TEST/policies"
mkdir -p "$POLICY_DIR"

# Create the DHCP veth pair.
create_veth veth-dhcp0 veth-dhcp1
add_address veth-dhcp1 10.99.0.1/24

# Create the unmanaged veth pair with a custom MTU.
create_veth veth-other0 veth-other1
ip link set dev veth-other0 mtu 1400

# Start dnsmasq on the DHCP server interface.
start_dnsmasq veth-dhcp1 10.99.0.1 10.99.0.100 10.99.0.200 120

# Write DHCP policy for veth-dhcp0 ONLY — no policy for veth-other0.
cat > "$POLICY_DIR/dhcp.yaml" <<'EOF'
kind: policy
name: eth0-dhcp
factory: dhcpv4
selector:
  name: veth-dhcp0
EOF

# Start the daemon.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

# Wait for daemon socket.
SOCKET_WAIT=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 401-dhcpv4-unmanaged-interface: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# Submit the DHCP policy.
NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_DIR/dhcp.yaml"

# Wait up to 10 seconds for veth-dhcp0 to acquire a lease.
LEASE_WAIT=0
while ! ip addr show dev veth-dhcp0 2>/dev/null | grep -q "10.99.0."; do
    if (( LEASE_WAIT >= 100 )); then
        echo "FAIL: 401-dhcpv4-unmanaged-interface: veth-dhcp0 did not acquire a DHCP address within 10 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( LEASE_WAIT++ )) || true
done

# Assert veth-dhcp0 has a DHCP address.
assert_has_address veth-dhcp0 "10.99.0."

# Assert veth-other0 is still UP and has mtu 1400.
assert_link_up veth-other0

OTHER_MTU=$(ip link show dev veth-other0 | grep -oP 'mtu \K[0-9]+' || echo "unknown")
if [[ "$OTHER_MTU" != "1400" ]]; then
    echo "FAIL: 401-dhcpv4-unmanaged-interface: veth-other0 mtu changed from 1400 to $OTHER_MTU" >&2
    echo "      ip link show veth-other0:" >&2
    ip link show dev veth-other0 >&2 || true
    exit 1
fi

echo "PASS: 401-dhcpv4-unmanaged-interface"
