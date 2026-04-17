#!/bin/bash
# 403-replace-all.sh
# Integration test: A second `netfyr apply` replaces the entire policy set
# (replace-all semantics), not appends to it.
# Mapped to acceptance criteria:
#   "Submit policies replaces entire set"
#   "Replace-all removes old policies in namespace"
#
# Requires: unshare, ip (iproute2)
# Usage:
#   NETFYR_BIN=./target/debug/netfyr \
#   NETFYR_DAEMON_BIN=./target/debug/netfyr-daemon \
#   bash tests/403-replace-all.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
NETFYR_DAEMON_BIN="${NETFYR_DAEMON_BIN:-$SCRIPT_DIR/../target/debug/netfyr-daemon}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 403-replace-all: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

if [[ ! -x "$NETFYR_DAEMON_BIN" ]]; then
    echo "FAIL: 403-replace-all: netfyr-daemon binary not found at $NETFYR_DAEMON_BIN" >&2
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

# Create a veth pair.
create_veth veth-test0 veth-test1

# Start the daemon.
NETFYR_SOCKET_PATH="$SOCKET_PATH" \
NETFYR_POLICY_DIR="$POLICY_DIR" \
    "$NETFYR_DAEMON_BIN" &
DAEMON_PID=$!

# Poll for daemon socket (up to 5 seconds).
SOCKET_WAIT=0
while [[ ! -S "$SOCKET_PATH" ]]; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: 403-replace-all: daemon exited before socket appeared" >&2
        exit 1
    fi
    if (( SOCKET_WAIT >= 50 )); then
        echo "FAIL: 403-replace-all: daemon socket did not appear within 5 seconds" >&2
        exit 1
    fi
    sleep 0.1
    (( SOCKET_WAIT++ )) || true
done

# ── Phase 1: Apply policy A (mtu=1400) ───────────────────────────────────────

POLICY_A="$TMPDIR_TEST/policy-a.yaml"
cat > "$POLICY_A" <<'EOF'
kind: policy
name: mtu-policy-a
factory: static
priority: 100
state:
  type: ethernet
  name: veth-test0
  mtu: 1400
EOF

NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_A"
APPLY_A_EXIT=$?
if [[ $APPLY_A_EXIT -ne 0 ]]; then
    echo "FAIL: 403-replace-all: first apply exited with code $APPLY_A_EXIT" >&2
    exit 1
fi

LINK_OUTPUT=$(ip link show veth-test0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1400"; then
    echo "FAIL: 403-replace-all: after policy A, veth-test0 does not have mtu 1400" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

# ── Phase 2: Apply policy B (mtu=1300, different name) replacing policy A ─────

POLICY_B="$TMPDIR_TEST/policy-b.yaml"
cat > "$POLICY_B" <<'EOF'
kind: policy
name: mtu-policy-b
factory: static
priority: 100
state:
  type: ethernet
  name: veth-test0
  mtu: 1300
EOF

NETFYR_SOCKET_PATH="$SOCKET_PATH" "$NETFYR_BIN" apply "$POLICY_B"
APPLY_B_EXIT=$?
if [[ $APPLY_B_EXIT -ne 0 ]]; then
    echo "FAIL: 403-replace-all: second apply exited with code $APPLY_B_EXIT" >&2
    exit 1
fi

# Replace-all means the daemon now has only policy B (mtu=1300).
LINK_OUTPUT=$(ip link show veth-test0)
if ! echo "$LINK_OUTPUT" | grep -q "mtu 1300"; then
    echo "FAIL: 403-replace-all: after policy B, veth-test0 does not have mtu 1300" >&2
    echo "      ip link output: $LINK_OUTPUT" >&2
    exit 1
fi

echo "PASS: 403-replace-all"
