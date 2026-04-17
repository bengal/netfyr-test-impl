#!/bin/bash
# 301-path-not-found.sh
# AC: "Path does not exist shows error"
#
# When a nonexistent path is passed to "netfyr apply", the CLI must exit
# with code 2 and print a message containing "path not found".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 301-path-not-found: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

# Force daemon-free mode.
export NETFYR_SOCKET_PATH=/nonexistent

EXIT_CODE=0
OUTPUT=$("$NETFYR_BIN" apply /nonexistent/path/that/does/not/exist.yaml 2>&1) || EXIT_CODE=$?

if [[ $EXIT_CODE -ne 2 ]]; then
    echo "FAIL: 301-path-not-found: expected exit code 2, got $EXIT_CODE" >&2
    echo "      output: $OUTPUT" >&2
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "path not found"; then
    echo "FAIL: 301-path-not-found: output does not mention 'path not found'" >&2
    echo "      output: $OUTPUT" >&2
    exit 1
fi

echo "PASS: 301-path-not-found"
