#!/bin/bash
# 302-query-veth-by-name.sh
# Integration test: Query a veth interface by name using only the name selector
# (no type= prefix), verifying MTU and address in JSON output.
# Mapped to spec acceptance scenario: "Query veth interface in namespace".
#
# Usage:
#   NETFYR_BIN=./target/debug/netfyr bash tests/302-query-veth-by-name.sh
#   bash tests/302-query-veth-by-name.sh   (uses target/debug/netfyr fallback)

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

# Create a veth pair and configure veth-test0 with a custom MTU and address.
create_veth veth-test0 veth-test1
ip link set dev veth-test0 mtu 1400
add_address veth-test0 10.99.0.1/24

# Query the specific interface using only the name selector (no type= filter).
# This exercises the all-entity-types iteration path in run_query_local.
output=$("$NETFYR_BIN" query -s name=veth-test0 -o json)

# Assert: interface name is present.
if ! echo "$output" | grep -q '"veth-test0"'; then
    echo "FAIL: 302-query-veth-by-name: output does not contain interface name 'veth-test0'" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: MTU is 1400 (as configured above).
if ! echo "$output" | grep -q '"mtu": 1400'; then
    echo "FAIL: 302-query-veth-by-name: output does not show mtu=1400" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: the configured address appears in the output.
if ! echo "$output" | grep -q '10.99.0.1/24'; then
    echo "FAIL: 302-query-veth-by-name: output does not contain address 10.99.0.1/24" >&2
    echo "Output: $output" >&2
    exit 1
fi

echo "PASS: 302-query-veth-by-name"
