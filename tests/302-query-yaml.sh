#!/bin/bash
# 302-query-yaml.sh
# Integration test: Query a veth interface using default YAML output (no -o flag)
# and verify the YAML-formatted field values.
# Mapped to spec acceptance scenario: "Query with YAML output in namespace".
#
# Usage:
#   NETFYR_BIN=./target/debug/netfyr bash tests/302-query-yaml.sh
#   bash tests/302-query-yaml.sh   (uses target/debug/netfyr fallback)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

# Enter an unprivileged user+network namespace (re-executes this script inside).
netns_setup "$@"

# ---------- Inside the namespace ----------

# Create a veth pair and set a custom MTU on veth-test0.
create_veth veth-test0 veth-test1
ip link set dev veth-test0 mtu 1400

# Query by name with default YAML output (no -o flag) — exercises the serde_yaml
# serialization path and the all-entity-types iteration with a name filter.
output=$("$NETFYR_BIN" query -s name=veth-test0)

# Assert: interface name appears in YAML output.
if ! echo "$output" | grep -q 'veth-test0'; then
    echo "FAIL: 302-query-yaml: output does not contain 'veth-test0'" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: MTU appears in YAML format (bare integer, not quoted).
if ! echo "$output" | grep -q 'mtu: 1400'; then
    echo "FAIL: 302-query-yaml: output does not contain 'mtu: 1400'" >&2
    echo "Output: $output" >&2
    exit 1
fi

echo "PASS: 302-query-yaml"
