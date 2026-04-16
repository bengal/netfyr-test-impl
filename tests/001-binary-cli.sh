#!/bin/bash
# 001-binary-cli.sh
# Verify that the netfyr-cli crate produces an executable binary named
# "netfyr-cli" and that running it with no arguments prints "netfyr" to stdout.
#
# Prerequisite: cargo build must have been run before this script.
#
# Usage: bash tests/001-binary-cli.sh
#   Override binary path: NETFYR_CLI_BIN=/path/to/netfyr-cli bash tests/001-binary-cli.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

NETFYR_CLI_BIN="${NETFYR_CLI_BIN:-$SCRIPT_DIR/../target/debug/netfyr-cli}"

# Prerequisite: binary must exist and be executable.
if [[ ! -x "$NETFYR_CLI_BIN" ]]; then
    echo "FAIL: 001-binary-cli: netfyr-cli binary not found or not executable at $NETFYR_CLI_BIN" >&2
    echo "      Build first with: cargo build -p netfyr-cli" >&2
    exit 1
fi

# Run the binary with no arguments and capture stdout.
output=$("$NETFYR_CLI_BIN" 2>/dev/null || true)

# The spec requires that the binary prints "netfyr" to stdout when no subcommand
# is given.
if [[ "$output" != "netfyr" ]]; then
    echo "FAIL: 001-binary-cli: expected stdout 'netfyr', got: '$output'" >&2
    exit 1
fi

echo "PASS: 001-binary-cli"
