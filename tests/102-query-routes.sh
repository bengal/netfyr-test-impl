#!/bin/bash
# 102-query-routes.sh
# Integration test: Query an ethernet interface and verify the "routes" field is
# present in the output and contains the connected subnet route.
# Mapped to spec acceptance scenario: "Query ethernet interface includes routes".
#
# Usage:
#   NETFYR_BIN=./target/debug/netfyr bash tests/102-query-routes.sh
#   bash tests/102-query-routes.sh   (uses target/debug/netfyr fallback)

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

# Create a veth pair and configure an address on veth-test0.
# Adding 10.99.0.1/24 automatically installs a connected route 10.99.0.0/24
# via the kernel (proto kernel scope link).
create_veth veth-test0 veth-test1
add_address veth-test0 10.99.0.1/24

# Query the specific interface in daemon-free mode.
output=$("$NETFYR_BIN" query \
    --selector type=ethernet \
    --selector name=veth-test0 \
    --output json)

# Assert: "routes" key is present in the output.
if ! echo "$output" | grep -q '"routes"'; then
    echo "FAIL: 102-query-routes: output does not contain 'routes' field" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: the connected subnet route for 10.99.0.0/24 appears in the routes list.
# The kernel installs this route automatically when the address 10.99.0.1/24 is added.
if ! echo "$output" | grep -q '10\.99\.0'; then
    echo "FAIL: 102-query-routes: output does not contain the connected route 10.99.0.0/24" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: each route entry has a "destination" field (spec: routes have destination,
# gateway (if applicable), and metric fields).
if ! echo "$output" | grep -q '"destination"'; then
    echo "FAIL: 102-query-routes: route entries do not contain 'destination' field" >&2
    echo "Output: $output" >&2
    exit 1
fi

echo "PASS: 102-query-routes"
