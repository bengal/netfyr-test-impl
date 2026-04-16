#!/bin/bash
# 001-test-naming-convention.sh
# Verify that test scripts in tests/ follow the NNN-description.sh naming
# convention (where NNN is a spec number prefix of one or more digits) and that
# helpers.sh is the only non-numbered .sh file in the tests/ directory.
#
# Usage: bash tests/001-test-naming-convention.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

failed=0
non_numbered_count=0

for f in "$SCRIPT_DIR"/*.sh; do
    basename_f="$(basename "$f")"

    # helpers.sh is the only allowed non-numbered file.
    if [[ "$basename_f" == "helpers.sh" ]]; then
        non_numbered_count=$((non_numbered_count + 1))
        continue
    fi

    # Every other .sh file must start with one or more digits followed by a
    # hyphen: NNN-description.sh
    if [[ ! "$basename_f" =~ ^[0-9]+-[a-z] ]]; then
        echo "FAIL: 001-test-naming-convention: '$basename_f' does not follow NNN-description.sh naming convention" >&2
        failed=1
    fi
done

# helpers.sh must exist (it is the shared helper sourced by all tests).
if [[ ! -f "$SCRIPT_DIR/helpers.sh" ]]; then
    echo "FAIL: 001-test-naming-convention: helpers.sh is missing from tests/" >&2
    failed=1
fi

# There should be exactly one non-numbered file (helpers.sh).
if [[ "$non_numbered_count" -gt 1 ]]; then
    echo "FAIL: 001-test-naming-convention: more than one non-numbered .sh file found in tests/" >&2
    failed=1
fi

if [[ "$failed" -eq 1 ]]; then
    exit 1
fi

echo "PASS: 001-test-naming-convention"
