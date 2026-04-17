#!/bin/bash
# 301-no-args-error.sh
# AC: "No path arguments shows error"
#
# Clap requires at least one path argument (paths is required = true).
# Running "netfyr apply" with no arguments must exit with code 2.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 301-no-args-error: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

EXIT_CODE=0
"$NETFYR_BIN" apply 2>/dev/null || EXIT_CODE=$?

if [[ $EXIT_CODE -ne 2 ]]; then
    echo "FAIL: 301-no-args-error: expected exit code 2 from clap usage error, got $EXIT_CODE" >&2
    exit 1
fi

echo "PASS: 301-no-args-error"
