# Plan: SPEC-353 External Change Detection

## Approach

The implementation of SPEC-353 is **complete**. All production code — the netlink monitor, self-change exclusion, event loop integration, external diff computation, journal entry recording, and CLI history display — is fully implemented and already has comprehensive unit tests.

The only remaining gap is one missing end-to-end test: the spec's acceptance criterion "Monitor ignores unmanaged interfaces" is validated at the unit-test level (via `managed_entity_names` and `record_external_change` tests in `reconciler.rs`) and via the `managed_entities.contains(name)` filter in `server.rs`, but the full end-to-end path — where a netlink event arrives for an unmanaged interface and produces no journal entry — is not covered by `tests/600-e2e-external-change.sh`.

The plan is therefore to add a single new phase to the existing e2e test script that creates a second veth pair (unmanaged — no policy covers it), makes an external change on it, waits for the debounce window, and asserts that no new `external_change` journal entry was recorded.

**Why modify the existing test file instead of creating a new one?** The `600-e2e-external-change.sh` test already sets up the full daemon environment (network namespace, veth pair, daemon process, policy, journal directory) needed for this scenario. Adding a new phase at the end avoids duplicating all that setup and keeps the test suite organized — all external change detection e2e tests live in one file.

**Why not modify any production code?** Every acceptance criterion in the spec maps to implemented, tested code:

| Criterion | Implementation Location |
|---|---|
| Monitor detects MTU change | `netlink_monitor.rs` RTM_NEWLINK → `reconciler.rs` `record_external_change` |
| Diff shows mtu: old → new | `reconciler.rs` `compute_external_field_changes` |
| Outcome is `observed` | `reconciler.rs` line 234: `ApplyOutcome::Observed` |
| `changed_entities` includes interface name | `reconciler.rs` line 226: `Trigger::ExternalChange { changed_entities }` |
| Address addition detection | `netlink_monitor.rs` RTM_NEWADDR → `ChangeKind::AddressAdded` |
| Address removal detection | `netlink_monitor.rs` RTM_DELADDR → `ChangeKind::AddressRemoved` |
| Self-changes excluded | `reconciler.rs` `set_applying`/`is_applying` + `server.rs` line 829 guard |
| Burst changes coalesced | `netlink_monitor.rs` 500ms sliding debounce in `monitor_task` |
| No re-reconciliation | `server.rs` branch 5 calls `record_external_change`, not `reconcile_and_apply` |
| Unmanaged interfaces ignored | `server.rs` line 835: `managed_entities.contains(name)` filter |

## Design Decisions

### 1. Test phase placement: append to existing test file
- **Decision**: Add a "Phase 4: Unmanaged interface" section at the end of `tests/600-e2e-external-change.sh`, before the final policy_apply count assertion.
- **Alternatives**: (a) Create a separate `601-e2e-unmanaged-interface.sh` test. (b) Add a Rust integration test in `crates/netfyr-daemon/tests/`.
- **Rationale**: The existing test already has the full daemon environment set up. A separate file would duplicate ~70 lines of setup boilerplate. A Rust integration test would require the daemon binary and network namespace setup that the shell tests already handle well. Appending a phase keeps the test suite lean and follows the established pattern.

### 2. Unmanaged interface: second veth pair
- **Decision**: Create a second veth pair (`veth-unmanaged0`/`veth-unmanaged1`) inside the same network namespace. No policy covers `veth-unmanaged0`.
- **Alternatives**: (a) Use the loopback interface — but its MTU changes might interact with the kernel differently. (b) Use a dummy interface — simpler but veths are already the established pattern in this test suite.
- **Rationale**: A veth pair is consistent with the existing test infrastructure (`create_veth` helper exists). The name `veth-unmanaged0` makes the intent obvious. The pair must be created after the daemon starts (or at least before the unmanaged-interface test phase) to ensure the daemon's netlink monitor sees the interface but doesn't track it.

### 3. Assertion strategy: count-based
- **Decision**: Record the count of `external_change` journal entries before the unmanaged-interface change, wait for debounce, then assert the count hasn't increased.
- **Alternatives**: (a) Assert that no entry mentions `veth-unmanaged0` — more specific but doesn't catch the case where the filter fails and a generic entry is written. (b) Use a timeout-based "wait and hope" approach.
- **Rationale**: Count-based assertion is the simplest correct approach. The test already uses this pattern for the policy_apply count check. After the 1-second sleep (covering the 500ms debounce window), the count should be unchanged. We also add a secondary assertion that no entry mentions the unmanaged interface name, for defense in depth.

### 4. Timing: 1-second sleep after unmanaged change
- **Decision**: Use `sleep 1` after the `ip link set` command, consistent with other phases in the test.
- **Alternatives**: A shorter sleep (e.g., 600ms) would be sufficient for the 500ms debounce, but 1 second provides margin against CI jitter.
- **Rationale**: Consistency with other test phases and robustness on slow CI runners.

## File Changes

### `tests/600-e2e-external-change.sh`
- **Action**: Modify
- **What**: Add a new test phase between Phase 3 (address removal) and the final policy_apply count assertion. The new phase:
  1. Creates a second veth pair: `create_veth veth-unmanaged0 veth-unmanaged1`
  2. Records the current count of `external_change` entries from the journal
  3. Runs `ip link set veth-unmanaged0 mtu 1500` — an MTU change on an interface not covered by any policy
  4. Sleeps 1 second (debounce window)
  5. Asserts the `external_change` count has not increased
  6. Asserts that no journal entry mentions `veth-unmanaged0` in its diff operations
- **Why**: Covers the "Monitor ignores unmanaged interfaces" acceptance criterion end-to-end, completing the test coverage for SPEC-353.

## Dependencies

No new dependencies are needed. All production code and existing dependencies are already in place.

## Implementation Order

### Step 1: Add unmanaged interface test phase to `tests/600-e2e-external-change.sh`
This is the only step. The test file already exists and compiles/runs. The new phase is appended before the final assertion block. After this step, all acceptance criteria have e2e coverage.

The change is self-contained — it has no dependencies on other code changes because all production code is already implemented.

## Risks and Mitigations

### 1. Veth creation triggers netlink events that cause a spurious external_change entry
**Risk**: Creating `veth-unmanaged0` generates RTM_NEWLINK events. If the daemon's debounce window is still open from Phase 3 and the new veth is somehow in the managed set, this could produce an unexpected entry.
**Mitigation**: The veth pair is created *after* all Phase 3 assertions complete (including the 1-second sleep), so the debounce window from Phase 3 has already fired. The daemon filters by `managed_entities`, which does not include `veth-unmanaged0`. Even if a netlink event fires, it will be dropped by the filter. As an additional safeguard, the test records the `external_change` count *after* the veth creation and a brief pause, before making the MTU change.

### 2. Test timing sensitivity on slow CI
**Risk**: The 1-second sleep might not be enough on extremely slow CI runners.
**Mitigation**: The existing phases already use 1-second sleeps and pass in CI. The unmanaged interface test is *less* timing-sensitive because we're asserting that something does NOT happen — we just need enough time for it to have happened if the filter were broken.

### 3. veth-unmanaged0 default MTU already equals 1500
**Risk**: If the default MTU of a new veth is already 1500, `ip link set veth-unmanaged0 mtu 1500` would be a no-op at the kernel level and might not generate a netlink event.
**Mitigation**: Use a non-default MTU value (e.g., 9000 or 1400) for the test change. Alternatively, set the MTU to a known value first, then change it. The simplest approach: `ip link set veth-unmanaged0 mtu 1400` — veth default MTU is 1500, so changing to 1400 is guaranteed to be a real change that generates a netlink event.

## Test Strategy

### What to test
The single new test phase validates the end-to-end path: kernel netlink event → daemon monitor receives it → `managed_entities` filter drops it → no journal entry written.

### Assertions
1. **Count-based**: The number of `external_change` entries in the journal does not increase after the unmanaged-interface change.
2. **Name-based**: No journal entry's `diff.operations` references `veth-unmanaged0`.

### What NOT to test
- The filtering logic itself (already unit-tested in `reconciler.rs::tests::test_managed_entity_names_excludes_non_policy_interfaces`)
- The monitor's ability to receive netlink events (already e2e-tested in Phases 1-3)
- The debounce mechanism (already e2e-tested in Phase 2's address additions)
