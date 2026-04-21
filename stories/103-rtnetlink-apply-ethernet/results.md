## Status
PASS

## Test Results
All unit tests passed (561 total across all crates). All 4 integration tests passed:
- `103-apply-add-remove-address.sh` — required a fix (see below)
- `103-apply-add-route.sh` — passed
- `103-apply-query-roundtrip.sh` — passed
- `103-apply-set-mtu.sh` — passed

No clippy warnings in project code.

## Changes Made

**Fix: `has_meaningful_changes()` now correctly treats `Unset` field changes as actionable**

File: `crates/netfyr-reconcile/src/diff.rs`

The `has_meaningful_changes()` method previously excluded `Unset` field changes from its definition of "meaningful", meaning that when a writable field (e.g., `addresses`) existed in actual state but was absent from the new policy, the CLI would report "No changes needed" and skip the apply entirely. This caused the address-removal test to fail: after applying a policy without the `addresses` field, the address remained on the interface.

The fix extends the method to also return `true` when any `Unset` field change is present. This is safe because `generate_diff` already uses the schema registry to filter out truly read-only fields (`carrier`, `speed`, `mac`, `driver`) before they can produce `Unset` changes. Any `Unset` change that reaches `has_meaningful_changes()` is therefore for a writable field that the backend will act on (removing addresses, routes, etc.).

Also removed a now-incorrect comment in `crates/netfyr-cli/src/apply.rs` that described the old behavior.

## Remaining Issues
None.
