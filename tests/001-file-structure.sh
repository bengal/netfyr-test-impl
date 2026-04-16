#!/bin/bash
# 001-file-structure.sh
# Verify that each crate has the correct files required by spec-001:
#   - Library crates: Cargo.toml and src/lib.rs
#   - Binary crates (netfyr-cli, netfyr-daemon): Cargo.toml and src/main.rs
#
# Usage: bash tests/001-file-structure.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

PROJECT_ROOT="$SCRIPT_DIR/.."
CRATES_DIR="$PROJECT_ROOT/crates"

# Prerequisite: crates directory must exist.
if [[ ! -d "$CRATES_DIR" ]]; then
    echo "FAIL: 001-file-structure: crates/ directory not found at $CRATES_DIR" >&2
    exit 1
fi

failed=0

# Library crates must have Cargo.toml and src/lib.rs.
library_crates=(
    "netfyr-state"
    "netfyr-reconcile"
    "netfyr-backend"
    "netfyr-policy"
    "netfyr-varlink"
)

for crate in "${library_crates[@]}"; do
    crate_dir="$CRATES_DIR/$crate"

    if [[ ! -f "$crate_dir/Cargo.toml" ]]; then
        echo "FAIL: 001-file-structure: $crate/Cargo.toml does not exist" >&2
        failed=1
    fi

    if [[ ! -f "$crate_dir/src/lib.rs" ]]; then
        echo "FAIL: 001-file-structure: $crate/src/lib.rs does not exist" >&2
        failed=1
    fi
done

# Binary crates must have Cargo.toml and src/main.rs.
binary_crates=(
    "netfyr-cli"
    "netfyr-daemon"
)

for crate in "${binary_crates[@]}"; do
    crate_dir="$CRATES_DIR/$crate"

    if [[ ! -f "$crate_dir/Cargo.toml" ]]; then
        echo "FAIL: 001-file-structure: $crate/Cargo.toml does not exist" >&2
        failed=1
    fi

    if [[ ! -f "$crate_dir/src/main.rs" ]]; then
        echo "FAIL: 001-file-structure: $crate/src/main.rs does not exist" >&2
        failed=1
    fi
done

# Verify each crate's Cargo.toml has edition = "2021" and version = "0.1.0".
all_spec_crates=(
    "netfyr-state"
    "netfyr-reconcile"
    "netfyr-backend"
    "netfyr-policy"
    "netfyr-varlink"
    "netfyr-cli"
    "netfyr-daemon"
)

for crate in "${all_spec_crates[@]}"; do
    crate_toml="$CRATES_DIR/$crate/Cargo.toml"
    if [[ ! -f "$crate_toml" ]]; then
        # Already reported above.
        continue
    fi

    if ! grep -q 'edition = "2021"' "$crate_toml"; then
        echo "FAIL: 001-file-structure: $crate/Cargo.toml missing 'edition = \"2021\"'" >&2
        failed=1
    fi

    if ! grep -q 'version = "0.1.0"' "$crate_toml"; then
        echo "FAIL: 001-file-structure: $crate/Cargo.toml missing 'version = \"0.1.0\"'" >&2
        failed=1
    fi
done

if [[ "$failed" -eq 1 ]]; then
    exit 1
fi

echo "PASS: 001-file-structure"
