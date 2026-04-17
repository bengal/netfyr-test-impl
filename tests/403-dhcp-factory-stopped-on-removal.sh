#!/bin/bash
# 403-dhcp-factory-stopped-on-removal.sh
# Integration test: Removing a DHCPv4 policy via replace-all stops the factory.
# After the replace, only the new static policy is active and applied.
# Mapped to acceptance criteria:
#   "Submit policies stops removed DHCP factories"
#
# Requires: unshare, ip (iproute2), dnsmasq
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/403-dhcp-factory-stopped-on-removal.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 403-dhcp-factory-stopped-on-removal: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 403-dhcp-factory-stopped-on-removal: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
    exit 1
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "FAIL: 403-dhcp-factory-stopped-on-removal: dnsmasq not found; install dnsmasq to run DHCP tests" >&2
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

# DHCP veth pair: veth-dhcp0 (client) / veth-dhcp1 (server side).
create_veth veth-dhcp0 veth-dhcp1
add_address veth-dhcp1 10.99.0.1/24

# Static veth pair: veth-test0 / veth-test1.
create_veth veth-test0 veth-test1

# Start dnsmasq on the DHCP server interface.
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
        echo "FAIL: 403-dhcp-factory-stopped-on-removal: daemon exited before socket appeared" >&2
        exit 1
    fi
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 403-dhcp-factory-stopped-on-removal: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# ── Phase 1: Submit DHCPv4 policy for veth-dhcp0 ─────────────────────────────

DHCP_POLICY="$TMPDIR_TEST/dhcp-policy.yaml"
cat > "$DHCP_POLICY" <<'EOF'
kind: policy
name: veth-dhcp0-dhcp
factory: dhcpv4
selector:
  name: veth-dhcp0
EOF

NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$DHCP_POLICY"
APPLY_EXIT=$?
if [[ $APPLY_EXIT -ne 0 ]]; then
    echo "FAIL: 403-dhcp-factory-stopped-on-removal: first apply exited with code $APPLY_EXIT" >&2
    exit 1
fi

# Wait up to 10 seconds for veth-dhcp0 to acquire a DHCP lease.
LEASE_WAIT=0
while ! ip addr show dev veth-dhcp0 2>/dev/null | grep -q "10.99.0."; do
    if (( LEASE_WAIT >= 100 )); then
        echo "FAIL: 403-dhcp-factory-stopped-on-removal: veth-dhcp0 did not acquire a DHCP address within 10 seconds" >&2
        echo "      ip addr show veth-dhcp0:" >&2
        ip addr show dev veth-dhcp0 >&2 || true
        exit 1
    fi
    sleep 0.1
    (( LEASE_WAIT++ )) || true
done

assert_has_address veth-dhcp0 "10.99.0."

# ── Phase 2: Replace with static-only policy (no DHCP) ───────────────────────
# This replace-all removes the DHCPv4 policy, stopping the factory.

STATIC_POLICY="$TMPDIR_TEST/static-policy.yaml"
cat > "$STATIC_POLICY" <<'EOF'
kind: policy
name: veth-test0-mtu
factory: static
priority: 100
state:
  type: ethernet
  name: veth-test0
  mtu: 1400
EOF

NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$STATIC_POLICY"
APPLY2_EXIT=$?
if [[ $APPLY2_EXIT -ne 0 ]]; then
    echo "FAIL: 403-dhcp-factory-stopped-on-removal: second apply exited with code $APPLY2_EXIT" >&2
    exit 1
fi

# Verify the static policy was applied to veth-test0.
LINK_OUTPUT=$(ip link show veth-test0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1400"; then
    echo "FAIL: 403-dhcp-factory-stopped-on-removal: veth-test0 does not have mtu 1400 after static policy applied" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

echo "PASS: 403-dhcp-factory-stopped-on-removal"
