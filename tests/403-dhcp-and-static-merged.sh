#!/bin/bash
# 403-dhcp-and-static-merged.sh
# Integration test: Static policy fields and DHCP-acquired fields are merged
# correctly on the same interface. Both the static MTU and the DHCP address must
# appear simultaneously.
# Mapped to acceptance criteria:
#   "Lease acquisition triggers reconciliation"
#   "eth0 gets mtu=9000 (from static) and address (from DHCP)"
#
# Requires: unshare, ip (iproute2), dnsmasq
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/403-dhcp-and-static-merged.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 403-dhcp-and-static-merged: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 403-dhcp-and-static-merged: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
    exit 1
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "FAIL: 403-dhcp-and-static-merged: dnsmasq not found; install dnsmasq to run DHCP tests" >&2
    exit 1
fi

# Enter an unprivileged user+network namespace (re-executes this script inside).
netns_setup "$@"

# ---------- Inside the namespace ----------

TMPDIR_TEST=$(mktemp -d)
DAEMON_PID=""
trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT

SOCKET_PATH="$TMPDIR_TEST/netfyr.sock"
POLICY_DIR="$TMPDIR_TEST/policies"
mkdir -p "$POLICY_DIR"

# Create DHCP veth pair: veth-dhcp0 (client) / veth-dhcp1 (server side).
create_veth veth-dhcp0 veth-dhcp1
add_address veth-dhcp1 10.99.0.1/24

# Start dnsmasq on the server side.
start_dnsmasq veth-dhcp1 10.99.0.1 10.99.0.100 10.99.0.200 120

# Start the daemon.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

# Poll for daemon socket (up to 5 seconds).
SOCKET_WAIT=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: 403-dhcp-and-static-merged: daemon exited before socket appeared" >&2
        exit 1
    fi
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 403-dhcp-and-static-merged: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# Write a policy directory with two policies for the same interface:
#   1. Static policy setting mtu=1400 (use 1400 rather than 9000 to stay within
#      default veth peer MTU limits).
#   2. DHCPv4 policy for address acquisition.
POLICY_SUBDIR="$TMPDIR_TEST/merged-policies"
mkdir -p "$POLICY_SUBDIR"

cat > "$POLICY_SUBDIR/static-mtu.yaml" <<'EOF'
kind: policy
name: veth-dhcp0-mtu
factory: static
priority: 100
state:
  type: ethernet
  name: veth-dhcp0
  mtu: 1400
EOF

cat > "$POLICY_SUBDIR/dhcp.yaml" <<'EOF'
kind: policy
name: veth-dhcp0-dhcp
factory: dhcpv4
selector:
  name: veth-dhcp0
EOF

# Submit both policies from the directory via a single `netfyr apply`.
NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_SUBDIR"
APPLY_EXIT=$?
if [[ $APPLY_EXIT -ne 0 ]]; then
    echo "FAIL: 403-dhcp-and-static-merged: netfyr apply exited with code $APPLY_EXIT" >&2
    exit 1
fi

# Wait up to 10 seconds for the DHCP lease to appear.
LEASE_WAIT=0
while ! ip addr show dev veth-dhcp0 2>/dev/null | grep -q "10.99.0."; do
    if (( LEASE_WAIT >= 100 )); then
        echo "FAIL: 403-dhcp-and-static-merged: veth-dhcp0 did not acquire a DHCP address within 10 seconds" >&2
        echo "      ip addr show veth-dhcp0:" >&2
        ip addr show dev veth-dhcp0 >&2 || true
        exit 1
    fi
    sleep 0.1
    (( LEASE_WAIT++ )) || true
done

# Assert DHCP address is present.
assert_has_address veth-dhcp0 "10.99.0."

# Assert the static MTU is also applied (both static and DHCP fields merged).
LINK_OUTPUT=$(ip link show veth-dhcp0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1400"; then
    echo "FAIL: 403-dhcp-and-static-merged: veth-dhcp0 does not have mtu 1400 (static field missing after DHCP merge)" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

echo "PASS: 403-dhcp-and-static-merged"
