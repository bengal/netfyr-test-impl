#!/bin/bash
# 001-helpers-functions.sh
# Verify that tests/helpers.sh exists and defines all functions required by
# spec-001: netns_setup, create_veth, add_address, start_dnsmasq, cleanup.
# Also verifies that assert_eq, assert_match, assert_has_address, assert_link_up
# are defined as specified.
#
# Usage: bash tests/001-helpers-functions.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPERS="$SCRIPT_DIR/helpers.sh"

# Prerequisite: helpers.sh must exist.
if [[ ! -f "$HELPERS" ]]; then
    echo "FAIL: 001-helpers-functions: tests/helpers.sh does not exist" >&2
    exit 1
fi

failed=0

# Required functions defined in the spec.
required_functions=(
    "netns_setup"
    "create_veth"
    "add_address"
    "start_dnsmasq"
    "cleanup"
    "assert_eq"
    "assert_match"
    "assert_has_address"
    "assert_link_up"
)

for fn in "${required_functions[@]}"; do
    # Each function should appear as a shell function definition: "fn_name()" or "fn_name ()".
    if ! grep -qE "^${fn}\s*\(\)" "$HELPERS"; then
        echo "FAIL: 001-helpers-functions: function '$fn' not defined in helpers.sh" >&2
        failed=1
    fi
done

# helpers.sh must be a valid bash script (syntax check).
if ! bash -n "$HELPERS" 2>/dev/null; then
    echo "FAIL: 001-helpers-functions: helpers.sh has bash syntax errors" >&2
    failed=1
fi

if [[ "$failed" -eq 1 ]]; then
    exit 1
fi

echo "PASS: 001-helpers-functions"
