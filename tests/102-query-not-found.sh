#!/bin/bash
# 102-query-not-found.sh
# Integration test: Querying a non-existent interface by name returns an empty
# result (BackendError::NotFound is mapped to an empty list at the CLI layer).
# Mapped to spec acceptance scenario: "Query for non-existent interface returns NotFound".
#
# Usage:
#   NETFYR_BIN=./target/debug/netfyr bash tests/102-query-not-found.sh
#   bash tests/102-query-not-found.sh   (uses target/debug/netfyr fallback)

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

# In a fresh network namespace only the loopback device "lo" exists.
# "eth99" is guaranteed not to exist.

# The CLI treats BackendError::NotFound as an empty match (exit 0, empty list).
output=$("$NETFYR_BIN" query \
    --selector type=ethernet \
    --selector name=eth99 \
    --output json)

exit_code=$?

# Assert: command exits with code 0 (not-found is not a CLI-level error).
if [[ $exit_code -ne 0 ]]; then
    echo "FAIL: 102-query-not-found: expected exit code 0 for not-found, got $exit_code" >&2
    echo "Output: $output" >&2
    exit 1
fi

# Assert: output is an empty JSON array (no entity matched the selector).
if [[ "$output" != "[]" ]]; then
    echo "FAIL: 102-query-not-found: expected empty JSON array '[]', got: $output" >&2
    exit 1
fi

echo "PASS: 102-query-not-found"
