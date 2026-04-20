## Status
PASS

## Test Results
All tests passed after 2 fixes. 

- cargo test: all tests pass (hundreds of unit/integration tests across all crates)
- make integration-test SPEC=301: all 13 shell integration tests pass

### Tests that required fixes

**`test_cli_binary_exits_zero_with_no_args`** and **`test_cli_binary_prints_netfyr_to_stdout_when_no_args_given`** (in `crates/netfyr-cli/tests/binary_output.rs`):
These SPEC-001 tests asserted exit code 0 and "netfyr" on stdout when invoked with no arguments. SPEC-301 mandates exit code 2 and uses clap `SubcommandRequiredElseHelp` which writes help to stderr. These tests were outdated; updated to expect exit code 2 and check stderr.

**`301-apply-no-changes.sh`** integration test:
The test expected "No changes needed" when applying a policy with `mtu: 1500` to an interface already at mtu 1500. The regular apply path used `state_diff.is_empty()` which treated kernel-managed fields (IPv6 link-local addresses, routes present in actual but absent from the policy) as actionable changes. Fixed by aligning the no-changes check with dry-run semantics.

## Changes Made

### 1. `crates/netfyr-cli/tests/binary_output.rs`
Updated two outdated SPEC-001 tests to match SPEC-301 behavior:
- `test_cli_binary_exits_zero_with_no_args`: now asserts exit code 2 (not 0). SPEC-301 specifies `SubcommandRequiredElseHelp` which exits 2.
- `test_cli_binary_prints_netfyr_to_stdout_when_no_args_given`: now checks stderr (not stdout) for "netfyr". Clap writes help to stderr when a required subcommand is missing.

### 2. `crates/netfyr-cli/src/apply.rs`
Changed the "no changes" detection in the regular apply path from `state_diff.is_empty()` to `!reconcile_diff.has_meaningful_changes()`.

**Why:** `compute_state_diff` (netfyr_state) does a simple field-by-field comparison without schema awareness. When a policy only specifies `mtu: 1500` but the actual interface also has kernel-assigned IPv6 link-local addresses and routes, `state_diff` is not empty (it wants to remove those unspecified fields). `reconcile_diff.has_meaningful_changes()` correctly ignores `Unset`-only diffs — fields in actual that are absent from the policy are kernel-managed and not user-configurable, so they don't constitute a "meaningful change." This matches the dry-run path which was already correct.

## Remaining Issues
None.
