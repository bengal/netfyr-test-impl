#!/bin/bash
# 302-query-all.sh
# Integration test: Query all interfaces without any selector and verify both
# ends of a veth pair appear in the JSON output.
# Mapped to spec acceptance scenario: "Query all interfaces in namespace returns
# both veth ends".
#
# Usage:
#   NETFYR_BIN=./target/debug/netfyr bash tests/302-query-all.sh
#   bash tests/302-query-all.sh   (uses target/debug/netfyr fallback)

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

# Create a veth pair; both ends are brought up by create_veth.
create_veth veth-a veth-b

# Query all interfaces with no selector — exercises the query_all codepath where
# run_query_local iterates all supported entity types without any filter.
output=$("$NETFYR_BIN" query -o json)

# Assert: both ends of the veth pair are present.
if ! echo "$output" | grep -q '"veth-a"'; then
    echo "FAIL: 302-query-all: output does not contain 'veth-a'" >&2
    echo "Output: $output" >&2
    exit 1
fi

if ! echo "$output" | grep -q '"veth-b"'; then
    echo "FAIL: 302-query-all: output does not contain 'veth-b'" >&2
    echo "Output: $output" >&2
    exit 1
fi

echo "PASS: 302-query-all"
