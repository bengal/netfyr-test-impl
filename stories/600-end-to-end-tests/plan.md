# SPEC-600: End-to-End Integration Tests — Implementation Plan

## Approach

26 of 27 specified test scripts already exist and are fully implemented. The single remaining script is `tests/600-e2e-external-change.sh` (scenario 26), which tests the daemon's external network change detection pipeline end-to-end.

This test exercises the `NetlinkMonitor` → `record_external_change` → journal entry path. The daemon subscribes to `RTNLGRP_LINK` and `RTNLGRP_IPV4_IFADDR` netlink multicast groups, debounces notifications (500ms sliding window, per `DEBOUNCE_MS` in `netlink_monitor.rs:46`), then queries current state and writes an `ExternalChange` journal entry. The test verifies three external-change phases in sequence: MTU change, address additions, and address removal — each followed by a 1-second sleep (2x the debounce window) and journal assertions via `jq`.

The script follows the exact same structural pattern as `600-e2e-revert.sh` and `600-e2e-journal-apply.sh`: boilerplate header, binary+jq checks, `netns_setup`, temp dirs with `JOURNAL_DIR`, single veth pair, daemon startup with socket poll, initial policy apply to establish managed state, then the external-change phases. No dnsmasq is needed, so the EXIT trap follows the non-DHCP pattern (`kill daemon; rm tmpdir`).

The key design challenge is the "no re-reconcile" assertion. The daemon's `is_applying` flag (set during its own apply cycles) prevents `record_external_change` from firing during daemon-initiated changes. For externally-initiated changes, the daemon only records them — it does not re-apply the original policy state. The test verifies this negatively: after each external change, assert the external state persists (e.g., mtu stays 1500, not reverted to 1400).

## Design Decisions

1. **Decision**: Use `sleep 1` between external changes and journal assertions.
   - **Alternatives considered**: (a) 500ms sleep matching the exact debounce window; (b) polling loop that checks journal until entry appears.
   - **Rationale**: The spec mandates `sleep 1`, which is 2x the 500ms debounce window — a comfortable margin. A polling loop would be more robust but deviates from the spec and adds complexity. If timing proves flaky in CI, the sleep can be increased.

2. **Decision**: Count journal entries cumulatively across phases using `jq -rs '[.[] | select(.trigger.type == "external_change")] | length'` rather than expecting exactly one new entry per phase.
   - **Alternatives considered**: Capture entry count before each phase and assert exactly +1 after.
   - **Rationale**: The debounce logic may coalesce two rapid `ip addr add` commands into a single journal entry. Asserting cumulative minimums (>= 1 after phase 1, >= 2 after phase 2, >= 3 after phase 3) is resilient to coalescing. However, since we have a 1-second gap between phases, coalescing across phases is unlikely. The test will capture the count before each phase and assert it increased by at least 1.

3. **Decision**: Verify diff content of the latest `external_change` entry after each phase, not just the trigger type.
   - **Alternatives considered**: Only check trigger type exists.
   - **Rationale**: The spec explicitly requires verifying the diff shows "mtu 1400→1500", "address additions", and "address removal". Checking diff content validates the full pipeline from netlink event to journal entry.

4. **Decision**: The "no re-apply" assertion is expressed as positive state checks — `ip link show veth-e2e0` still shows `mtu=1500` after all phases.
   - **Alternatives considered**: Check that no `policy_apply` journal entry appears after the initial one.
   - **Rationale**: The spec says "Verify `ip link show veth-e2e0` still shows mtu=1500 (daemon did not re-reconcile)." A direct `assert_mtu` check is the clearest expression of this requirement. Additionally, checking no extra `policy_apply` entries exist provides a second signal.

5. **Decision**: Use `jq -rs` (raw-output + slurp) for all journal queries, consistent with existing tests.
   - **Alternatives considered**: Line-by-line `jq` processing.
   - **Rationale**: `current.ndjson` is newline-delimited JSON. `jq -rs` slurps all lines into a JSON array, allowing array operations like filtering, counting, and extracting the last element. This matches the exact pattern used in `600-e2e-revert.sh` (line 94) and `600-e2e-journal-apply.sh` (line 97).

6. **Decision**: No `cleanup` call in EXIT trap — no dnsmasq is used.
   - **Alternatives considered**: Call `cleanup` defensively.
   - **Rationale**: Following the established convention: tests without dnsmasq use `trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT` (see `600-e2e-revert.sh:37`). The `cleanup` function only kills dnsmasq PIDs.

## File Changes

### `tests/600-e2e-external-change.sh`
- **Action**: create
- **What**: Shell test script (~180 lines) with the following structure:

  **Header/preamble** (lines 1-31, matching `600-e2e-revert.sh`):
  - Shebang, `set -euo pipefail`, source helpers.sh
  - Binary checks for `$NETFYR_BIN` and `$NETFYR_DAEMON_BIN`
  - `jq` availability check
  - `netns_setup "$@"`

  **Setup** (lines ~32-66):
  - `TMPDIR_TEST=$(mktemp -d)` with EXIT trap: `kill daemon; rm tmpdir`
  - `SOCKET_PATH`, `POLICY_DIR`, `JOURNAL_DIR` variables, `mkdir -p`
  - `create_veth veth-e2e0 veth-e2e1`
  - Start daemon with `NETFYR_SOCKET_PATH`, `NETFYR_POLICY_DIR`, `NETFYR_JOURNAL_DIR`
  - Socket poll loop (up to 5 seconds)

  **Initial apply** (lines ~67-90):
  - Write policy YAML: `kind: policy`, `name: e2e-external`, `factory: static`, `priority: 100`, state `type: ethernet`, `name: veth-e2e0`, `mtu: 1400`
  - `netfyr apply` with exit code capture and assertion
  - `assert_mtu veth-e2e0 1400`
  - Record initial `policy_apply` count: `INITIAL_APPLY_COUNT=$(jq -rs '[.[] | select(.trigger.type == "policy_apply")] | length' "$JOURNAL_DIR/current.ndjson")`

  **Phase 1: External MTU change** (lines ~91-120):
  - `ip link set veth-e2e0 mtu 1500`
  - `sleep 1`
  - Count external_change entries: `EC_COUNT=$(jq -rs '[.[] | select(.trigger.type == "external_change")] | length' "$JOURNAL_DIR/current.ndjson")`
  - Assert `EC_COUNT >= 1`
  - Extract latest external_change entry: `EC_ENTRY=$(jq -rs '[.[] | select(.trigger.type == "external_change")] | last' "$JOURNAL_DIR/current.ndjson")`
  - Assert diff contains an operation for `veth-e2e0` with a field change for `mtu`: `echo "$EC_ENTRY" | jq '[.diff.operations[] | select(.entity_name == "veth-e2e0") | .field_changes[] | select(.field_name == "mtu")] | length'` >= 1
  - Assert mtu is still 1500 (daemon did not re-reconcile): `assert_mtu veth-e2e0 1500`

  **Phase 2: External address additions** (lines ~121-150):
  - `ip addr add 10.99.0.1/24 dev veth-e2e0`
  - `ip addr add 10.99.0.2/24 dev veth-e2e0`
  - `sleep 1`
  - Count external_change entries, assert `>= 2`
  - Extract latest external_change entry
  - Assert diff mentions `veth-e2e0` (at minimum: an operation for veth-e2e0 exists in the latest entry)
  - `assert_has_address veth-e2e0 10.99.0.1/24`
  - `assert_has_address veth-e2e0 10.99.0.2/24`
  - Assert mtu is still 1500: `assert_mtu veth-e2e0 1500`

  **Phase 3: External address removal** (lines ~151-180):
  - `ip addr del 10.99.0.1/24 dev veth-e2e0`
  - `sleep 1`
  - Count external_change entries, assert `>= 3`
  - Extract latest external_change entry
  - Assert diff mentions `veth-e2e0`
  - `assert_has_address veth-e2e0 10.99.0.2/24`
  - `assert_not_has_address veth-e2e0 10.99.0.1/24`
  - Assert mtu is still 1500: `assert_mtu veth-e2e0 1500`

  **Final no-re-apply check** (lines ~181-190):
  - Count `policy_apply` entries after all phases: `FINAL_APPLY_COUNT=$(jq -rs '[.[] | select(.trigger.type == "policy_apply")] | length' "$JOURNAL_DIR/current.ndjson")`
  - Assert `FINAL_APPLY_COUNT == INITIAL_APPLY_COUNT` (no new policy applies happened during external changes)
  - `echo "PASS: 600-e2e-external-change"`

- **Why**: This is the only missing test script out of 27 specified in the spec. It validates the daemon's external change detection pipeline: netlink monitoring → debounced event processing → journal recording, and confirms the daemon does not re-apply policies in response to external changes.

## Dependencies

No new crate dependencies. No Rust code changes. No Makefile changes. No `helpers.sh` changes.

**External tool dependency**: `jq` is required for journal assertions. The script checks `command -v jq` at startup and exits with `FAIL` if absent.

## Implementation Order

1. **Create `tests/600-e2e-external-change.sh`** — Single file, single step. The script is self-contained and follows the established pattern from existing 600-series tests. No other files need to be created or modified.

This produces a compilable (well, runnable) state immediately. The Makefile auto-discovers tests via the `tests/[0-9]*.sh` glob.

## Risks and Mitigations

1. **Risk**: Debounce timing — the 500ms debounce window uses a sliding-window design (each new event resets the timer). If the `ip link set` and `ip addr add` commands trigger additional kernel-internal netlink messages (e.g., link state changes when MTU changes), the debounce window could extend beyond 1 second.
   - **Impact**: Journal entry not yet written when the test reads `current.ndjson`.
   - **Mitigation**: The spec uses `sleep 1` (2x the debounce window). In practice, the sliding window resets from the *last* event, so even if there are 2-3 events from a single `ip` command, they complete in <100ms, and the debounce fires at ~600ms. If flaky in CI, increase sleep to 2 seconds.

2. **Risk**: Address events may be batched with the preceding MTU debounce window if phase 2 starts before phase 1's debounce fires (unlikely given the 1s sleep, but theoretically possible under extreme CPU contention).
   - **Impact**: Phase 1's external_change entry might include address changes from phase 2.
   - **Mitigation**: The 1-second sleep between phases ensures the previous debounce window (500ms) has fired and the journal entry has been written. Under normal conditions, there is no cross-phase batching.

3. **Risk**: The `is_applying` flag may suppress external change recording if the initial `netfyr apply` hasn't fully completed before the daemon processes the netlink events from its own apply cycle.
   - **Impact**: The daemon might still be processing its own apply notifications when the test does `ip link set mtu 1500`, causing the external change to be incorrectly attributed to the daemon's apply and discarded.
   - **Mitigation**: The `netfyr apply` CLI returns only after receiving the Varlink response, which is sent after `set_applying(false)`. So by the time the test script proceeds past the apply command, the daemon has already lowered the flag. Any netlink events from the apply cycle have already been processed (and discarded) during the apply window.

4. **Risk**: The daemon startup itself generates a journal entry (`DaemonStartup` trigger), which could interfere with entry counting if we count total entries rather than filtering by trigger type.
   - **Impact**: Assertions on total entry count would be off by one.
   - **Mitigation**: All counting uses `select(.trigger.type == "external_change")` to filter specifically for external change entries, unaffected by startup or policy-apply entries.

5. **Risk**: The netlink monitor's `ifname` resolution for address events depends on having previously seen a `RTM_NEWLINK` message for that interface index (via the `name_cache`). If the daemon starts before the veth pair is created, it may have the name cached from the creation event. If the daemon starts after, it may not have the name cached.
   - **Impact**: The journal entry's `changed_entities` list might use the interface index instead of the name, causing `select(.entity_name == "veth-e2e0")` to fail.
   - **Mitigation**: The test creates the veth pair *before* starting the daemon, but the daemon's monitor sees the initial `RTM_NEWLINK` from the namespace setup. More importantly, when the initial `netfyr apply` runs, it generates `RTM_NEWLINK` messages that populate the name cache. By the time phase 1 starts, the cache is warm. Additionally, the reconciler's `record_external_change` receives entity *names* (not indices) from the server loop, which resolves names before calling the reconciler.

6. **Risk**: `jq` not installed in the test environment.
   - **Impact**: Script exits with `FAIL` immediately.
   - **Mitigation**: Each script checks `command -v jq` at startup with a clear FAIL message. CI environments typically have `jq` installed.

## Test Strategy

This story produces a single shell test script — no Rust code. The verification strategy is:

1. **Primary: `make integration-test`** — Run all shell integration tests including the new `600-e2e-external-change.sh`. It must print `PASS: 600-e2e-external-change` and exit 0.

2. **Individual script testing** — `bash tests/600-e2e-external-change.sh` for iterative development.

3. **Regression: `cargo test`** — Sanity check that no Rust code was inadvertently broken (this story adds no Rust code).

### What to test (in the single script):
- **Phase 1 (MTU)**: External MTU change from 1400→1500 produces a journal entry with `trigger.type == "external_change"`, diff referencing `veth-e2e0` with an mtu field change. Interface retains mtu=1500 (no re-reconcile).
- **Phase 2 (Address additions)**: Two external `ip addr add` commands produce at least one new external_change journal entry with diff referencing `veth-e2e0`. Both addresses present on interface.
- **Phase 3 (Address removal)**: External `ip addr del` produces a new external_change journal entry. Removed address gone, remaining address present.
- **Cross-cutting**: No new `policy_apply` entries appear after the initial apply (daemon never re-applied). MTU stays at 1500 throughout all phases.

### Behaviors to verify per phase:
| Phase | External action | Journal assertion | State assertion |
|-------|----------------|-------------------|-----------------|
| 1 | `ip link set mtu 1500` | `external_change` entry with mtu field change | mtu=1500 persists |
| 2 | `ip addr add` x2 | `external_change` entry for veth-e2e0 | Both addresses present |
| 3 | `ip addr del` x1 | `external_change` entry for veth-e2e0 | Only 10.99.0.2/24 remains |
| Final | (none) | No new `policy_apply` entries | mtu=1500, only 10.99.0.2/24 |
