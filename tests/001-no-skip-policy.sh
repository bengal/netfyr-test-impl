#!/bin/bash
# 001-no-skip-policy.sh
# Verify that helpers.sh enforces the no-skip policy:
#   - When 'unshare' is unavailable, netns_setup must exit 1 (never 0)
#   - When 'dnsmasq' is unavailable, start_dnsmasq must exit 1 (never 0)
#
# These checks inspect helpers.sh source to confirm the correct exit codes are
# used when prerequisites are missing.
#
# Usage: bash tests/001-no-skip-policy.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPERS="$SCRIPT_DIR/helpers.sh"

# Prerequisite: helpers.sh must exist.
if [[ ! -f "$HELPERS" ]]; then
    echo "FAIL: 001-no-skip-policy: tests/helpers.sh does not exist" >&2
    exit 1
fi

failed=0

# helpers.sh must call "exit 1" when unshare is not found (not "exit 0").
# The check looks for "exit 1" within the unshare-not-found block.
if ! grep -A5 'unshare.*not found\|not found.*unshare\|command -v unshare' "$HELPERS" | grep -q 'exit 1'; then
    echo "FAIL: 001-no-skip-policy: helpers.sh does not 'exit 1' when unshare is missing" >&2
    failed=1
fi

# helpers.sh must call "exit 1" when dnsmasq is not found (not "exit 0").
if ! grep -A5 'dnsmasq.*not found\|not found.*dnsmasq\|command -v dnsmasq' "$HELPERS" | grep -q 'exit 1'; then
    echo "FAIL: 001-no-skip-policy: helpers.sh does not 'exit 1' when dnsmasq is missing" >&2
    failed=1
fi

# Neither missing-prerequisite block should contain "exit 0" — that would mean
# the test silently skips rather than failing.
# Check that immediately after the unshare-check block, there is no "exit 0".
if grep -A3 'command -v unshare' "$HELPERS" | grep -q 'exit 0'; then
    echo "FAIL: 001-no-skip-policy: helpers.sh uses 'exit 0' in unshare-check block (must be 'exit 1')" >&2
    failed=1
fi

if grep -A3 'command -v dnsmasq' "$HELPERS" | grep -q 'exit 0'; then
    echo "FAIL: 001-no-skip-policy: helpers.sh uses 'exit 0' in dnsmasq-check block (must be 'exit 1')" >&2
    failed=1
fi

if [[ "$failed" -eq 1 ]]; then
    exit 1
fi

echo "PASS: 001-no-skip-policy"
