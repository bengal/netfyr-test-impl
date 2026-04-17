#!/bin/bash
# 600-e2e-conflict.sh -- End-to-end: conflicting policies produce a warning and exit code 1.
#
# Requires: unshare, ip (iproute2)
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/600-e2e-conflict.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 600-e2e-conflict: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi
if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 600-e2e-conflict: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
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

# Start the daemon.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

# Poll for daemon socket (up to 5 seconds).
SOCKET_WAIT=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: 600-e2e-conflict: daemon exited before socket appeared" >&2
        exit 1
    fi
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 600-e2e-conflict: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# Write two policies at the same priority for the same interface with conflicting mtu values.
CONFLICT_DIR="$TMPDIR_TEST/conflict-policies"
mkdir -p "$CONFLICT_DIR"

cat > "$CONFLICT_DIR/policy-a.yaml" <<'EOF'
kind: policy
name: conflict-a
factory: static
priority: 100
state:
  type: ethernet
  name: veth-e2e0
  mtu: 1400
EOF

cat > "$CONFLICT_DIR/policy-b.yaml" <<'EOF'
kind: policy
name: conflict-b
factory: static
priority: 100
state:
  type: ethernet
  name: veth-e2e0
  mtu: 1300
EOF

# Apply both policies from the directory atomically.
# Both policies submitted together — without this, replace-all would hide the conflict.
APPLY_EXIT=0
APPLY_OUTPUT=$(NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$CONFLICT_DIR" 2>&1) \
    || APPLY_EXIT=$?

# Conflicting policies must cause exit code 1.
if [[ $APPLY_EXIT -ne 1 ]]; then
    echo "FAIL: 600-e2e-conflict: expected exit code 1 for conflicting policies, got $APPLY_EXIT" >&2
    echo "      output: $APPLY_OUTPUT" >&2
    exit 1
fi

# Output must mention the conflict.
if ! echo "$APPLY_OUTPUT" | grep -qi "conflict"; then
    echo "FAIL: 600-e2e-conflict: apply output does not mention 'conflict'" >&2
    echo "      output: $APPLY_OUTPUT" >&2
    exit 1
fi

# Output must mention the conflicting field.
if ! echo "$APPLY_OUTPUT" | grep -qi "mtu"; then
    echo "FAIL: 600-e2e-conflict: apply output does not mention 'mtu'" >&2
    echo "      output: $APPLY_OUTPUT" >&2
    exit 1
fi

echo "PASS: 600-e2e-conflict"
