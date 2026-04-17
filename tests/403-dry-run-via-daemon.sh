#!/bin/bash
# 403-dry-run-via-daemon.sh
# Integration test: `netfyr apply --dry-run` routed through the daemon computes
# the diff without modifying kernel state.
# Mapped to acceptance criteria:
#   "Dry-run computes diff without applying"
#   "The current system state is unchanged"
#
# Requires: unshare, ip (iproute2)
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/403-dry-run-via-daemon.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 403-dry-run-via-daemon: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 403-dry-run-via-daemon: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
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

# Create a veth pair whose MTU we will NOT change (dry-run only).
create_veth veth-test0 veth-test1

# Start the daemon.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

# Poll for the daemon socket to appear (up to 5 seconds).
SOCKET_WAIT=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: 403-dry-run-via-daemon: daemon exited before socket appeared" >&2
        exit 1
    fi
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 403-dry-run-via-daemon: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# Write a policy that would set mtu=1400 on veth-test0 (default kernel MTU is 1500).
POLICY_FILE="$TMPDIR_TEST/policy.yaml"
cat > "$POLICY_FILE" <<'EOF'
kind: policy
name: test-mtu-dryrun
factory: static
priority: 100
state:
  type: ethernet
  name: veth-test0
  mtu: 1400
EOF

# Run --dry-run via the daemon socket.
# Expected exit code is 1: changes are pending but were NOT applied.
DRY_RUN_EXIT=0
NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply --dry-run "$POLICY_FILE" \
    || DRY_RUN_EXIT=$?

if [[ $DRY_RUN_EXIT -ne 1 ]]; then
    echo "FAIL: 403-dry-run-via-daemon: expected exit code 1 from --dry-run, got $DRY_RUN_EXIT" >&2
    exit 1
fi

# The kernel MTU must remain at the default 1500 — dry-run must not apply changes.
LINK_OUTPUT=$(ip link show veth-test0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1500"; then
    echo "FAIL: 403-dry-run-via-daemon: veth-test0 MTU was changed by --dry-run (expected mtu 1500)" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

# Verify the daemon policy store is still empty (dry-run must not persist policies).
# Submit a query — if the daemon applied no policies it reports the real system state.
QUERY_OUTPUT=$(NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" query -s name=veth-test0 2>&1) || true
if echo "$QUERY_OUTPUT" | grep -q "mtu: 1400"; then
    echo "FAIL: 403-dry-run-via-daemon: daemon query shows mtu 1400 after dry-run (state was modified)" >&2
    echo "      query output: $QUERY_OUTPUT" >&2
    exit 1
fi

echo "PASS: 403-dry-run-via-daemon"
