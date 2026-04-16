#!/bin/bash
# 001-workspace-features.sh
# Verify that the root Cargo.toml defines workspace features: dhcp, systemd,
# varlink — each with an empty dependency list as required by spec-001.
#
# Usage: bash tests/001-workspace-features.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

PROJECT_ROOT="$SCRIPT_DIR/.."
CARGO_TOML="$PROJECT_ROOT/Cargo.toml"

# Prerequisite: Cargo.toml must exist.
if [[ ! -f "$CARGO_TOML" ]]; then
    echo "FAIL: 001-workspace-features: Cargo.toml not found at $CARGO_TOML" >&2
    exit 1
fi

failed=0

# Check that the [workspace.features] section is present.
if ! grep -q '^\[workspace\.features\]' "$CARGO_TOML"; then
    echo "FAIL: 001-workspace-features: [workspace.features] section missing from Cargo.toml" >&2
    failed=1
fi

# Check each required feature is defined with an empty list value.
required_features=("dhcp" "systemd" "varlink")
for feature in "${required_features[@]}"; do
    if ! grep -qE "^${feature}\s*=\s*\[\]" "$CARGO_TOML"; then
        echo "FAIL: 001-workspace-features: feature '$feature = []' not found in Cargo.toml" >&2
        failed=1
    fi
done

if [[ "$failed" -eq 1 ]]; then
    exit 1
fi

echo "PASS: 001-workspace-features"
