#!/bin/bash
# 301-yaml-parse-error.sh
# AC: "YAML parse error returns exit code 2"
#
# When an invalid YAML file is given, the CLI must exit with code 2.
# The error output must reference the file path (propagated by the loader).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"

if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 301-yaml-parse-error: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

# Force daemon-free mode.
export NETFYR_SOCKET_PATH=/nonexistent

POLICY_FILE=$(mktemp --suffix=.yaml)
# Write YAML that cannot be parsed (unmatched brackets).
cat > "$POLICY_FILE" <<'EOF'
: invalid yaml [ unclosed bracket
  - broken: structure
EOF

EXIT_CODE=0
OUTPUT=$("$NETFYR_BIN" apply "$POLICY_FILE" 2>&1) || EXIT_CODE=$?

rm -f "$POLICY_FILE"

if [[ $EXIT_CODE -ne 2 ]]; then
    echo "FAIL: 301-yaml-parse-error: expected exit code 2, got $EXIT_CODE" >&2
    echo "      output: $OUTPUT" >&2
    exit 1
fi

echo "PASS: 301-yaml-parse-error"
