#!/bin/bash
# 403-daemon-graceful-shutdown.sh
# Integration test: SIGTERM causes clean daemon exit; applied network config
# survives shutdown (the system keeps working).
# Mapped to acceptance criteria:
#   "Daemon shuts down gracefully"
#   "Applied network configuration is left in place"
#
# Requires: unshare, ip (iproute2)
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/403-daemon-graceful-shutdown.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 403-daemon-graceful-shutdown: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 403-daemon-graceful-shutdown: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
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

# Create a veth pair to configure.
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
        echo "FAIL: 403-daemon-graceful-shutdown: daemon exited before socket appeared" >&2
        exit 1
    fi
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 403-daemon-graceful-shutdown: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# Apply a static mtu policy.
POLICY_FILE="$TMPDIR_TEST/mtu-policy.yaml"
cat > "$POLICY_FILE" <<'EOF'
kind: policy
name: test-mtu-shutdown
factory: static
priority: 100
state:
  type: ethernet
  name: veth-test0
  mtu: 1400
EOF

NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_FILE"
APPLY_EXIT=$?
if [[ $APPLY_EXIT -ne 0 ]]; then
    echo "FAIL: 403-daemon-graceful-shutdown: netfyr apply exited with code $APPLY_EXIT" >&2
    exit 1
fi

# Verify mtu was applied.
LINK_OUTPUT=$(ip link show veth-test0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1400"; then
    echo "FAIL: 403-daemon-graceful-shutdown: veth-test0 does not have mtu 1400 after apply" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

# Send SIGTERM to trigger graceful shutdown.
kill -TERM "$DAEMON_PID"

# The daemon removes the socket file on shutdown — poll for its disappearance
# (confirms stop_all() and shutdown sequence completed).
SHUTDOWN_WAIT=0
while [[ -S "$SOCKET_PATH" ]]; do
    if (( SHUTDOWN_WAIT >= 50 )); then
        echo "FAIL: 403-daemon-graceful-shutdown: socket still exists 5 seconds after SIGTERM" >&2
        exit 1
    fi
    sleep 0.1
    (( SHUTDOWN_WAIT++ )) || true
done

# Collect exit status — must be 0 (clean shutdown).
wait "$DAEMON_PID"
DAEMON_EXIT=$?
DAEMON_PID=""
if [[ $DAEMON_EXIT -ne 0 ]]; then
    echo "FAIL: 403-daemon-graceful-shutdown: daemon exited with code $DAEMON_EXIT (expected 0)" >&2
    exit 1
fi

# Verify applied network configuration is still in place after the daemon stopped.
LINK_OUTPUT=$(ip link show veth-test0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1400"; then
    echo "FAIL: 403-daemon-graceful-shutdown: mtu 1400 was removed from veth-test0 after shutdown" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

echo "PASS: 403-daemon-graceful-shutdown"
