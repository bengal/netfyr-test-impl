#!/bin/bash
# 102-query-veth-by-name.sh
# Integration test: Query a veth interface by name, verifying MTU and address.
# Mapped to spec acceptance scenario: "Query veth interface in namespace".
#
# Usage:
#   NETFYR_BIN=./target/debug/netfyr bash tests/102-query-veth-by-name.sh
#   bash tests/102-query-veth-by-name.sh   (uses target/debug/netfyr fallback)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "SKIP: netfyr binary not found at $NETFYR_BIN; run 'cargo build -p netfyr-cli' first"
    exit 0
fi

# Enter an unprivileged user+network namespace (re-executes this script inside).
# Falls back to SKIP if unshare is unavailable or namespaces are disabled.
netns_setup "$@" || { echo "SKIP: unshare --user --net not available; skipping namespace test"; exit 0; }

# ---------- Inside the namespace ----------

# Create a veth pair and configure veth-test0 with a custom MTU and address.
create_veth veth-test0 veth-test1
ip link set dev veth-test0 mtu 1400
add_address veth-test0 10.99.0.1/24

# Query the specific interface via the CLI in daemon-free mode (no socket → netlink).
output=$("$NETFYR_BIN" query \
    --selector type=ethernet \
    --selector name=veth-test0 \
    --output json)

# Assert: interface name is present.
if ! echo "$output" | grep -q '"veth-test0"'; then
    echo "FAIL: 102-query-veth-by-name: output does not contain interface name 'veth-test0'" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: MTU is 1400 (as configured above).
if ! echo "$output" | grep -q '"mtu": 1400'; then
    echo "FAIL: 102-query-veth-by-name: output does not show mtu=1400" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: the configured address appears in the addresses list.
if ! echo "$output" | grep -q '10.99.0.1/24'; then
    echo "FAIL: 102-query-veth-by-name: output does not contain address 10.99.0.1/24" >&2
    echo "Output: $output" >&2
    exit 1
fi

echo "PASS: 102-query-veth-by-name"
