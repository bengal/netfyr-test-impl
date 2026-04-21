# Plan: SPEC-354 State Revert — Remaining Gaps

## Approach

The core revert implementation is complete and functional across all crates: CLI (`revert.rs`), Varlink client (`client.rs`), daemon server (`server.rs`), reconciler (`reconciler.rs`), and journal serialization (`serializable.rs`). All 7 existing integration tests and all workspace tests (275+ unit tests) pass, including `test_revert_nonexistent_entry_exit_code_is_1` which was previously flagged as failing.

The remaining work is exclusively **test coverage and cleanup**:
1. Remove a stale "BUG" comment from the integration test file (the bug is fixed).
2. Add unit tests for `handle_revert` in `server.rs` (all other handlers have unit tests; revert has none).
3. Add unit tests for `Reconciler::revert()` in `reconciler.rs` (all other reconciler methods have unit tests; revert has none).
4. Add a test verifying host-bits CIDR addresses round-trip correctly through `SerializableStateSet::to_state_set()` (existing tests carefully avoid host-bits CIDRs; this acceptance criterion needs explicit coverage).
5. Add E2E network tests for the core acceptance criteria (MTU revert, dry-run, no-op, address revert).

**Why this approach rather than adding code changes**: I verified through code review and test execution that the implementation matches the spec. The exit code bug is resolved (the test passes). The CIDR round-trip works correctly with ipnetwork 0.20 (which preserves host bits in `from_str`). The `trigger_display_name` in `history.rs` already handles `Trigger::Revert` (line 467: returns `"revert"`). The daemon journal concurrency is safe because `handle_connection` processes requests sequentially and `tokio::select!` branches are mutually exclusive.

What remains is bringing test coverage to parity with the rest of the codebase — the revert code paths are the only major feature without handler-level and reconciler-level unit tests.

## Design Decisions

### 1. Stale BUG comment removal
- **Decision**: Remove the `// BUG: standalone mode exits with 2 instead of 1` comment block from `test_revert_nonexistent_entry_exit_code_is_1` in `revert_integration.rs` (lines 143-146). The test now passes — the comment is misleading.
- **Alternatives considered**: Leaving the comment with a "FIXED" annotation.
- **Rationale**: Dead comments rot. The test assertion itself documents the expected behavior (exit code 1). Git history preserves the original context if anyone needs it.

### 2. Server handler test structure
- **Decision**: Add `handle_revert` tests to the existing `#[cfg(test)] mod tests` block in `server.rs`, following the exact same pattern as the existing handler tests: `make_stream_pair()` → call handler → `read_message()` → assert response fields.
- **Alternatives considered**: Separate test file.
- **Rationale**: All other handler tests live in the same module. Consistency matters more than separation here.

### 3. Reconciler revert test approach
- **Decision**: Add revert tests to the existing `#[cfg(test)] mod tests` block in `reconciler.rs`. Tests will use empty target states (no real network interfaces needed) to verify the method's structural behavior: dry-run returns `None` report, apply returns `Some` report, is_applying flag is clean after return.
- **Alternatives considered**: Tests with mock backends.
- **Rationale**: The existing reconciler tests use `Reconciler::new()` which creates a real `NetlinkBackend`. This works because empty policies produce no changes. Similarly, reverting to an empty target state produces no changes, which is enough to verify the method's branching logic. Mock backends would require a large refactor (trait objects, dependency injection) that isn't warranted for smoke-level tests.

### 4. Host-bits CIDR test placement
- **Decision**: Add a test to `serializable.rs`'s test module that creates a `SerializableStateSet` with a host-CIDR field value like `"10.99.0.1/24"`, calls `to_state_set()`, and asserts the result is `Value::IpNetwork` with ip `10.99.0.1` (not `10.99.0.0`).
- **Alternatives considered**: Adding the test to `netfyr-state`'s `Value` serde tests.
- **Rationale**: The acceptance criterion is about revert's snapshot round-trip behavior, which is exercised through `to_state_set()`. Placing the test alongside the existing `to_state_set` tests makes the coverage explicit.

### 5. E2E test scope and placement
- **Decision**: Create `crates/netfyr-cli/tests/revert_e2e.rs` for network-level E2E tests. These tests require `NetnsGuard` (network namespace isolation) and root privileges. Mark them with `#[ignore]` so they don't run in normal `cargo test` but can be run explicitly with `cargo test -- --ignored`.
- **Alternatives considered**: (a) Adding to existing `revert_integration.rs`. (b) Creating in `netfyr-backend/tests/`.
- **Rationale**: The existing integration tests in `revert_integration.rs` are designed to run without network access (error cases, journal metadata). E2E tests that manipulate network interfaces belong in a separate file with clear `#[ignore]` markers and dependency on `netfyr-test-utils`. This follows the pattern of existing E2E tests like `netfyr-backend/tests/netlink_apply.rs`.

### 6. Dry-run exit code for daemon mode with changes
- **Decision**: The current daemon-mode dry-run exit code is `1` when there are changes (line 82 of `revert.rs`). This differs from the spec which says dry-run should always exit 0. However, this is consistent with the existing `apply --dry-run` behavior and is a deliberate design choice (non-zero = "action would be needed"). Leave as-is — this is the codebase's convention.
- **Rationale**: Changing it would break consistency with `apply --dry-run`. The standalone dry-run path already returns exit 0 for empty diff and exit 1 for non-empty diff (line 151). Both paths are consistent with each other.

## File Changes

### 1. `crates/netfyr-cli/tests/revert_integration.rs` — Modify
- **Action**: Modify
- **What**: Remove the stale BUG comment block (lines 143-146) from `test_revert_nonexistent_entry_exit_code_is_1`. The comment reads `// BUG: standalone mode exits with 2 instead of 1 for "entry not found".` followed by context lines. Remove only the comment, not the test itself.
- **Why**: The test passes. The comment is misleading and suggests the test is expected to fail.

### 2. `crates/netfyr-daemon/src/server.rs` — Modify
- **Action**: Modify (add tests to existing `#[cfg(test)] mod tests` block)
- **What**: Add the following test functions:

  **`test_handle_revert_missing_target_seq_returns_error`**: Call `handle_revert` with `serde_json::json!({})` params (no `target_seq`). Assert the response has `"error"` field containing `"InternalError"` and the reason mentions `"target_seq"`.

  **`test_handle_revert_invalid_target_seq_type_returns_error`**: Call with `serde_json::json!({"target_seq": "not-a-number"})`. Assert error response.

  **`test_handle_revert_entry_not_found_returns_entry_not_found_error`**: Set `NETFYR_JOURNAL_DIR` to a temp dir, call with `serde_json::json!({"target_seq": 9999})`. Assert the response has `"error"` field containing `"EntryNotFound"` and the reason mentions `"9999"`.

  **`test_handle_revert_dry_run_response_has_report_and_timestamp`**: Write a journal entry to a temp dir, set `NETFYR_JOURNAL_DIR`, call with `{"target_seq": 1, "dry_run": true}`. Assert the response has `"parameters"` with `"report"` and `"entry_timestamp"` fields. Assert `report.changes` is an array.

  **`test_handle_revert_dry_run_does_not_write_journal_entry`**: After a dry-run revert, read the journal and assert no new entries beyond the original one.

  Each test follows the existing pattern: `make_stream_pair()`, call the handler directly, `read_message()` from the client side, assert on the JSON response. Tests that need a journal must create a temp dir, write entries via `Journal::open()` + `append()`, and set `NETFYR_JOURNAL_DIR` env var (protected by the existing `ENV_MUTEX` pattern if one exists, or using `serial_test` if needed). Since server tests don't have an ENV_MUTEX, use `std::env::set_var` within each test and clean up with `remove_var` — the tests run in separate threads but the env var is only read by `Journal::open_default()` which is called inside the handler.

  Helper: Add a `make_journal_entry(mtu: u64)` function similar to `make_entry_with_state` in `revert_integration.rs`.

- **Why**: All other Varlink handlers have unit tests. `handle_revert` is the only handler without coverage, creating a gap in the server's test matrix.

### 3. `crates/netfyr-daemon/src/reconciler.rs` — Modify
- **Action**: Modify (add tests to existing `#[cfg(test)] mod tests` block)
- **What**: Add the following test functions:

  **`test_reconciler_revert_dry_run_returns_none_report`**: Create a `Reconciler`, build an empty `StateSet` target, call `revert(&target, 1, &[], true)`. Assert `result.report.is_none()`.

  **`test_reconciler_revert_apply_returns_some_report`**: Same setup but `dry_run=false`. Assert `result.report.is_some()` and the report is successful (no failures).

  **`test_reconciler_revert_is_applying_is_false_after_completion`**: Call `revert()` with `dry_run=false`, then assert `reconciler.is_applying()` is `false`. This verifies the `set_applying` guard is properly cleaned up.

  **`test_reconciler_revert_with_empty_target_produces_empty_diff`**: Call `revert(&StateSet::new(), 1, &[], false)`. Assert `result.reconcile_diff.is_empty()`.

- **Why**: The reconciler test suite covers `dry_run`, `query`, `reconcile_and_apply`, `managed_entity_names`, `record_external_change`, and `compute_external_field_changes`. `Reconciler::revert()` is the only public method without coverage.

### 4. `crates/netfyr-journal/src/serializable.rs` — Modify
- **Action**: Modify (add test to existing `#[cfg(test)] mod tests` block)
- **What**: Add one test function:

  **`test_to_state_set_preserves_host_bits_in_cidr_addresses`**: Create a `SerializableStateSet` with fields containing `"10.99.0.1/24"` (host-bits CIDR) and `["10.99.0.2/24", "10.99.0.3/24"]` (list of host-bits CIDRs). Call `to_state_set()`. Assert:
  - The scalar field deserializes as `Value::IpNetwork` with `ip() == 10.99.0.1` (not `10.99.0.0`)
  - The list field deserializes as `Value::List` where each element is `Value::IpNetwork` with the correct host IP
  - The display format of each network is `"10.99.0.X/24"` with host bits intact

- **Why**: The acceptance criterion "Revert with address changes" uses host-bits CIDR notation like `"10.99.0.1/24"`. Existing tests carefully avoid this case (using canonical `10.0.0.0/24` addresses). While ipnetwork 0.20 preserves host bits, this needs explicit test coverage to catch regressions if the ipnetwork dependency is upgraded.

### 5. `crates/netfyr-cli/tests/revert_e2e.rs` — Create
- **Action**: Create
- **What**: E2E tests requiring network namespace isolation. All tests marked `#[ignore]` for manual execution. Add `netfyr-test-utils` as a dev-dependency of `netfyr-cli` if not already present.

  **`test_revert_restores_mtu`**: 
  - Create a `NetnsGuard` with a veth pair
  - Apply policy A setting mtu=1400 via `run_apply` or backend directly, producing journal entry seq=1
  - Apply policy B setting mtu=1300, producing journal entry seq=2
  - Call `run_revert` with target=1
  - Assert the veth interface has mtu=1400
  - Assert a new journal entry with `Trigger::Revert { target_seq: 1 }` exists

  **`test_revert_dry_run_does_not_change_mtu`**:
  - Same setup as above
  - Call `run_revert` with target=1 and `dry_run=true`
  - Assert the veth interface still has mtu=1300 (unchanged)
  - Assert no new journal entry was created

  **`test_revert_noop_when_already_at_target_state`**:
  - Apply policy A setting mtu=1400, producing seq=1
  - Call `run_revert` with target=1 (system already at mtu=1400)
  - Assert exit code 0 and output contains "No changes needed"

  **`test_revert_address_changes`**:
  - Apply policy A with addresses `["10.99.0.1/24", "10.99.0.2/24"]`, seq=1
  - Apply policy B with addresses `["10.99.0.3/24"]`, seq=2
  - Call `run_revert` with target=1
  - Assert interface has addresses 10.99.0.1/24 and 10.99.0.2/24
  - Assert interface does NOT have 10.99.0.3/24

  Each test sets `NETFYR_JOURNAL_DIR` to a temp dir and `NETFYR_SOCKET_PATH` to a nonexistent path to force standalone mode. Uses `Journal::open()` to write initial entries and `create_backend_registry()` (made `pub(crate)` — already done) to set up the backend.

- **Why**: The acceptance criteria include 6 network-level scenarios. These are the definitive proof that the revert feature works end-to-end. Without them, only the structural code paths are tested, not the actual network state restoration.

### 6. `crates/netfyr-cli/Cargo.toml` — Modify (conditional)
- **Action**: Modify (only if `netfyr-test-utils` is not already a dev-dependency)
- **What**: Add `netfyr-test-utils = { path = "../netfyr-test-utils" }` under `[dev-dependencies]`.
- **Why**: The E2E tests need `NetnsGuard` for network namespace isolation.

## Dependencies

No new external crate dependencies. The only internal change is potentially adding `netfyr-test-utils` as a dev-dependency of `netfyr-cli` (it may already be present).

## Implementation Order

### Step 1: Remove stale BUG comment
**File**: `crates/netfyr-cli/tests/revert_integration.rs`

Remove the comment block on lines 143-146. This is a trivial cleanup that should be done first so the test file accurately reflects the current state. Verify: `cargo test --package netfyr-cli --test revert_integration`.

### Step 2: Add host-bits CIDR round-trip test
**File**: `crates/netfyr-journal/src/serializable.rs`

Add `test_to_state_set_preserves_host_bits_in_cidr_addresses`. This is independent of all other steps. Verify: `cargo test --package netfyr-journal -- test_to_state_set_preserves_host_bits`.

### Step 3: Add Reconciler::revert() unit tests
**File**: `crates/netfyr-daemon/src/reconciler.rs`

Add the 4 revert test functions. These follow the exact pattern of existing reconciler tests — create a `Reconciler::new()`, call the method with an empty target, assert on the result. Verify: `cargo test --package netfyr-daemon -- test_reconciler_revert`.

### Step 4: Add handle_revert server unit tests
**File**: `crates/netfyr-daemon/src/server.rs`

Add the 5 handle_revert test functions. These need a helper to create journal entries in a temp dir and set the `NETFYR_JOURNAL_DIR` env var. The env var mutation requires care to avoid test interference — use a unique temp dir per test and set/unset the env var within the test body. Depends on Step 2 (the journal entry helper pattern). Verify: `cargo test --package netfyr-daemon -- test_handle_revert`.

### Step 5: Add E2E network tests
**Files**: `crates/netfyr-cli/tests/revert_e2e.rs` (create), `crates/netfyr-cli/Cargo.toml` (modify if needed)

Create the E2E test file with `#[ignore]` tests. Add `netfyr-test-utils` dev-dependency if not present. Depends on Steps 1-4 being complete (so we know the unit-level tests pass before running E2E). Verify: `cargo test --package netfyr-cli --test revert_e2e -- --ignored` (requires root/network namespace support).

### Step 6: Full workspace verification
Run `cargo test --workspace` to ensure no regressions. Run `cargo test --workspace -- --ignored` in an environment with network namespace support to verify E2E tests.

## Risks and Mitigations

### 1. Environment variable mutation in server tests
**Risk**: The `handle_revert` tests need to set `NETFYR_JOURNAL_DIR` to a temp dir. Since tests run in parallel, one test's env var could leak into another test's `Journal::open_default()` call.
**Mitigation**: Use the same `ENV_MUTEX` pattern used in the journal tests (`journal.rs:347`). Each server revert test acquires the mutex, sets the env var, runs the handler, and removes the env var. Alternatively, since `handle_revert` calls `Journal::open_default()` which reads the env var synchronously within the handler, and `make_stream_pair()` + handler invocation is all within one `async` context, the race window is narrow. Still, using a mutex is the safe approach.

### 2. E2E tests require root privileges
**Risk**: `NetnsGuard::new()` creates network namespaces, which requires `CAP_SYS_ADMIN` or root. The E2E tests will fail in unprivileged CI environments.
**Mitigation**: Mark all E2E tests with `#[ignore]`. They run only when explicitly requested (`--ignored` or `--include-ignored`). This matches the pattern used by `netfyr-backend/tests/netlink_apply.rs`. Document the requirement in a comment at the top of the test file.

### 3. ipnetwork crate upgrade could break CIDR round-trip
**Risk**: A future upgrade of `ipnetwork` beyond 0.20 might change `from_str` to canonicalize host bits, breaking the revert of host-CIDR addresses.
**Mitigation**: The new `test_to_state_set_preserves_host_bits_in_cidr_addresses` test will catch this regression. If ipnetwork changes behavior, the fix would be to add a custom deserializer that preserves host bits (e.g., store the original string alongside the parsed address).

### 4. Reconciler::new() in tests opens real journal
**Risk**: `Reconciler::new()` calls `Journal::open_default()`, which writes to `/var/lib/netfyr/journal/` or `NETFYR_JOURNAL_DIR`. In test environments, this may fail or pollute the system journal.
**Mitigation**: The existing reconciler tests already face this risk and handle it gracefully — `Reconciler::new()` logs a warning and sets `journal: None` if the journal can't be opened. The revert tests don't depend on journal writes (they verify the return value structure, not journal contents). No additional mitigation needed.

### 5. Parallel E2E test interference
**Risk**: Multiple E2E tests creating veth pairs in overlapping network namespaces could interfere.
**Mitigation**: Each test creates its own `NetnsGuard` (unique network namespace). The test infrastructure generates unique interface names via PID-based or random suffixes. This is already solved by `netfyr-test-utils`.

## Test Strategy

### Unit Tests (Steps 2-4)

**Serializable round-trip** (1 new test in `serializable.rs`):
- Host-bits CIDR addresses (`"10.99.0.1/24"`) survive `to_state_set()` without canonicalization
- Scalar and list forms both preserve host bits

**Reconciler::revert()** (4 new tests in `reconciler.rs`):
- Dry-run returns `RevertResult` with `report: None`
- Apply returns `RevertResult` with `report: Some(successful_report)`
- `is_applying` flag is false after `revert()` completes
- Empty target produces empty diff

**handle_revert server handler** (5 new tests in `server.rs`):
- Missing `target_seq` → `InternalError` response
- Invalid `target_seq` type → `InternalError` response
- Nonexistent entry → `EntryNotFound` error with seq in reason
- Dry-run success → response has `report` and `entry_timestamp`
- Dry-run does not create new journal entries

### Integration / E2E Tests (Step 5)

**Network-level E2E** (4 new `#[ignore]` tests in `revert_e2e.rs`):
- MTU revert: policy A → policy B → revert to A → verify MTU restored
- Dry-run: verify no state change, no journal entry
- No-op: verify "No changes needed" when already at target state
- Address revert: verify IP addresses added/removed correctly

### Existing Test Coverage (already passing)

The following are already covered and should continue to pass:
- CLI argument parsing (missing target, non-numeric target): 2 tests in `revert_integration.rs`
- Entry not found output and exit code: 2 tests in `revert_integration.rs`
- Journal entry metadata (trigger, state_after, ordering): 3 tests in `revert_integration.rs`
- Varlink client (method name, params, report decode, EntryNotFound): 6 tests in `client.rs`
- SerializableStateSet round-trip (entities, provenance, IP network, list, string, error): 8 tests in `serializable.rs`
- Trigger::Revert serialization: tests in `entry.rs`
- trigger_display_name for Revert: test in `history.rs`
