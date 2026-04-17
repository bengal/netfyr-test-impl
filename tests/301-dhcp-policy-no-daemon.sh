#!/bin/bash
# 301-dhcp-policy-no-daemon.sh
# AC: "DHCP policy without daemon fails with clear error"
#
# When a dhcpv4 policy is loaded and no daemon socket is reachable,
# run_apply must exit with code 2 and print a message mentioning
# "requires the netfyr daemon" and "systemctl start netfyr".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 301-dhcp-policy-no-daemon: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

# Force daemon-free mode: socket path points to a location that does not exist.
export NETFYR_SOCKET_PATH=/nonexistent

POLICY_FILE=$(mktemp --suffix=.yaml)
cat > "$POLICY_FILE" <<'EOF'
kind: policy
name: eth0-dhcp
factory: dhcpv4
priority: 100
selector:
  name: eth0
EOF

EXIT_CODE=0
OUTPUT=$("$NETFYR_BIN" apply "$POLICY_FILE" 2>&1) || EXIT_CODE=$?

rm -f "$POLICY_FILE"

if [[ $EXIT_CODE -ne 2 ]]; then
    echo "FAIL: 301-dhcp-policy-no-daemon: expected exit code 2, got $EXIT_CODE" >&2
    echo "      output: $OUTPUT" >&2
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "requires the netfyr daemon"; then
    echo "FAIL: 301-dhcp-policy-no-daemon: output does not mention 'requires the netfyr daemon'" >&2
    echo "      output: $OUTPUT" >&2
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "systemctl start netfyr"; then
    echo "FAIL: 301-dhcp-policy-no-daemon: output does not mention 'systemctl start netfyr'" >&2
    echo "      output: $OUTPUT" >&2
    exit 1
fi

echo "PASS: 301-dhcp-policy-no-daemon"
