# SPEC-600: End-to-End Integration Tests — Implementation Plan

## Approach

All 8 end-to-end test scripts and the required `helpers.sh` additions already exist in `tests/`. The implementation is complete — no files need to be created or modified. This plan documents the existing design and focuses on verification.

The 600-series tests exercise the full user workflow: write YAML policy → start daemon → `netfyr apply` → verify with both `ip` commands and `netfyr query`. They are structurally identical to the 403-series tests but differ in scope: each scenario combines multiple features and verifies kernel state with `ip` (not just daemon responses). This provides regression coverage for cross-cutting interactions that per-story tests miss.

The design follows existing test conventions exactly: `set -euo pipefail`, source `helpers.sh`, check binaries before `netns_setup`, use `NETFYR_SOCKET_PATH` env var for both daemon and CLI, poll for socket with a tight loop, use `trap` for cleanup. A developer reading 403-series tests can read 600-series tests with zero learning curve.

The helpers `assert_not_has_address`, `assert_mtu`, and `wait_for_address` were added to `helpers.sh` rather than inlined because: (1) all are used by multiple 600-series tests, (2) future tests will need them, (3) they follow the same style as existing `assert_has_address` and are backwards-compatible.

## Design Decisions

### 1. Helpers in `helpers.sh` vs inline in each test

- **Decision**: `assert_not_has_address`, `assert_mtu`, and `wait_for_address` live in `tests/helpers.sh`.
- **Alternatives considered**: Inline the logic in each test script.
- **Rationale**: `assert_mtu` is used in 7 of 8 tests; `wait_for_address` in 2 DHCP tests; `assert_not_has_address` in replace-all. Inlining would cause 10+ instances of duplicated logic. Existing helpers (`assert_has_address`, `assert_link_up`) set the precedent.

### 2. SIGTERM for daemon restart (not SIGKILL)

- **Decision**: Send `SIGTERM` via `kill "$DAEMON_PID"` to stop the daemon gracefully in `600-e2e-daemon-restart.sh`, then `wait` for exit.
- **Alternatives considered**: `kill -9` (SIGKILL) — would leave socket file behind and skip cleanup.
- **Rationale**: SIGTERM triggers the daemon's graceful shutdown path, matching `systemctl restart` behavior.

### 3. Dry-run exit code expectation

- **Decision**: Expect exit code 1 from `netfyr apply --dry-run` when changes would be applied.
- **Alternatives considered**: Exit code 0.
- **Rationale**: `apply.rs` returns exit code 1 for non-empty dry-run diffs. The existing `403-dry-run-via-daemon.sh` already asserts this. Consistency requires the 600-series test to match.

### 4. Conflict test uses daemon mode

- **Decision**: Run `600-e2e-conflict.sh` with the daemon running, submitting two policies via `netfyr apply $DIR`.
- **Alternatives considered**: Test in daemon-free mode.
- **Rationale**: The spec says "start the daemon." The daemon path exercises the full pipeline including `PolicyStore.replace_all`, `Reconciler.reconcile_and_apply`, and the Varlink round-trip for conflict reporting.

### 5. Conflict test: both policies in a single directory

- **Decision**: Write both conflicting policies into a single directory and pass it to `netfyr apply $DIR`.
- **Alternatives considered**: Two separate `apply` calls; single YAML with both policies.
- **Rationale**: `submit_policies` uses replace-all semantics — two separate `apply` calls would make the second replace the first, hiding the conflict. They must be submitted together. A directory is the natural way.

### 6. Replace-all verifies address removal

- **Decision**: Verify that `10.99.0.1/24` is absent using `assert_not_has_address` after replacing policy A with policy B.
- **Alternatives considered**: Only verify MTU changed.
- **Rationale**: The entire point of this test is replace-all semantics. MTU change is necessary but not sufficient — address removal proves old policy effects are fully unwound.

### 7. Daemon restart resets kernel MTU before restarting

- **Decision**: After killing the daemon, reset veth-e2e0 MTU to 1500 via `ip link set dev veth-e2e0 mtu 1500` before starting the new daemon.
- **Alternatives considered**: Don't reset MTU, just verify it's still 1400.
- **Rationale**: Without resetting, the test can't distinguish between "daemon re-applied the policy" and "the kernel still had the old value." Resetting MTU to default then asserting 1400 proves the new daemon actively re-applied persisted policies on startup.

### 8. Unmanaged test uses different subnet for DHCP

- **Decision**: The unmanaged test uses `10.99.3.0/24` for DHCP (not `10.99.1.0/24` like the DHCP+static test).
- **Alternatives considered**: Reuse the same subnet.
- **Rationale**: Avoids any confusion if tests run in the same namespace (they don't, but distinct subnets make the test self-documenting). The unmanaged interface uses `10.99.2.0/24`, so three distinct subnets clarify which interface is which.

## File Changes

All files below already exist. No modifications are needed.

### 1. `tests/helpers.sh` — already complete

Contains all functions needed by the 600-series:
- `netns_setup()` — `unshare --user --net --map-root-user` re-entry loop
- `create_veth()`, `add_address()` — veth pair creation and IP assignment
- `start_dnsmasq()` — hard-fails if dnsmasq missing; stores PID for cleanup
- `cleanup()` — EXIT trap, kills dnsmasq PIDs
- `assert_eq()`, `assert_match()`, `assert_has_address()`, `assert_link_up()` — basic assertions
- `assert_not_has_address()` (line 143) — inverse of `assert_has_address`
- `assert_mtu()` (line 156) — verifies interface MTU via `ip link show`
- `wait_for_address()` (line 169) — polls every 0.1s up to timeout, hard-fails on timeout

### 2. `tests/600-e2e-static-apply.sh` — already complete

Tests basic static policy workflow. Creates veth pair, writes static policy (mtu=1400, address 10.99.0.1/24), starts daemon, applies via CLI, verifies with `ip link`, `ip addr`, and `netfyr query -o json`.

### 3. `tests/600-e2e-dhcp-and-static.sh` — already complete

Tests DHCP and static coexistence. Creates two veth pairs, starts dnsmasq, applies both policy types, verifies each interface is correctly configured and no cross-contamination occurs.

### 4. `tests/600-e2e-replace-all.sh` — already complete

Tests replace-all semantics. Applies policy A (mtu=1400, address), verifies, then applies policy B (mtu=1300, no address). Verifies MTU changed and address removed.

### 5. `tests/600-e2e-daemon-restart.sh` — already complete

Tests policy persistence across restart. Applies policy, kills daemon, resets kernel MTU to 1500, starts new daemon with same policy dir, verifies MTU restored to 1400 without explicit re-apply.

### 6. `tests/600-e2e-conflict.sh` — already complete

Tests conflict detection. Submits two policies at priority 100 with different MTU values for the same interface. Verifies exit code 1 and output mentions "conflict" and "mtu".

### 7. `tests/600-e2e-dry-run.sh` — already complete

Tests dry-run. Applies `--dry-run` with mtu=1400 policy. Verifies exit code 1, output mentions "mtu", and kernel MTU remains at 1500.

### 8. `tests/600-e2e-apply-directory.sh` — already complete

Tests directory-based apply. Creates two veth pairs, writes two policy files in a directory, applies the directory. Verifies each interface has the correct MTU.

### 9. `tests/600-e2e-unmanaged.sh` — already complete

Tests unmanaged interfaces. Creates three veth pairs, manually configures one, applies policies for the other two. Verifies unmanaged interface is untouched.

## Dependencies

No new Rust crate dependencies. All test scripts use only existing system tools: `bash`, `ip`, `unshare`, `grep`, `mktemp`, `kill`, `sleep`, `cat`. DHCP tests additionally require `dnsmasq`.

## Implementation Order

All files already exist. No implementation steps are needed. The only remaining work is verification:

1. **Run `make integration-test`** to confirm all 8 tests pass. This validates that the underlying Rust implementations (SPEC-103, 201–203, 301–302, 401–403) behave correctly end-to-end.

2. If any test fails, the failure indicates a bug in the Rust code (daemon, CLI, backend, reconciler) rather than a test problem — investigate the specific component indicated by the failure message.

## Risks and Mitigations

### 1. Daemon may not re-apply on startup

**Risk**: `600-e2e-daemon-restart.sh` relies on the new daemon automatically re-applying mtu=1400 from persisted policies without an explicit `netfyr apply`. If the daemon only reconciles on incoming `submit_policies` RPC, the test fails.

**Mitigation**: The daemon's `main.rs` loads policies from `NETFYR_POLICY_DIR` on startup and runs initial reconciliation. The existing `403-daemon-starts-and-listens.sh` validates this. The test resets kernel MTU to 1500 between instances to ensure the re-application is real.

### 2. Conflict exit code contract

**Risk**: `600-e2e-conflict.sh` expects exit code 1. If `run_apply` returns 0 with a printed warning, the test fails.

**Mitigation**: The code in `apply.rs` checks `!report.conflicts.is_empty()` and returns `ExitCode::FAILURE` when conflicts exist. This is the correct behavior per existing 403-series tests.

### 3. DHCP test timeout in CI

**Risk**: DHCP lease acquisition depends on dnsmasq responding within 10 seconds. In heavily loaded CI environments, the timeout may be insufficient.

**Mitigation**: Uses the same 10-second timeout as existing `403-dhcp-and-static-merged.sh` and `401-dhcpv4-*` tests. If flakiness appears, the timeout can be increased per-test.

### 4. Daemon socket stale file between restart phases

**Risk**: After `kill "$DAEMON_PID"`, the daemon may not remove the socket file before the new daemon starts.

**Mitigation**: The script explicitly runs `rm -f "$SOCKET_PATH"` after waiting for the old daemon to exit (line 97), then starts the new daemon. This handles both the case where the daemon cleans up and where it doesn't.

### 5. JSON mtu grep pattern fragility

**Risk**: `600-e2e-static-apply.sh` uses `grep -q '"mtu".*1400'` on JSON output. If the serializer emits `"mtu":1400` (no space) or reorders keys, the match fails.

**Mitigation**: The pattern `'"mtu".*1400'` allows any whitespace or separators between `"mtu"` and `1400`. Key reordering is tolerated because the pattern doesn't require adjacency. `serde_json` serializers consistently emit `"mtu": 1400` with a space after the colon in pretty-print mode.

### 6. dnsmasq availability

**Risk**: Two tests (`dhcp-and-static`, `unmanaged`) hard-fail if dnsmasq is absent.

**Mitigation**: Per SPEC-001, this is correct behavior — never silently skip. CI environments must have dnsmasq installed. The check occurs before `netns_setup` so the failure message is clear.

### 7. Replace-all may not remove addresses from kernel

**Risk**: The netlink apply path may not actively remove addresses absent from the desired state.

**Mitigation**: The test verifies actual kernel behavior. If addresses aren't removed, the test fails, surfacing a genuine bug in the reconciliation/apply path. The existing `103-apply-add-remove-address.sh` test validates this capability at the backend level.

## Test Strategy

This story *is* the tests. The 8 scripts are the deliverable. Verification is running `make integration-test` (or `make integration-test SPEC=600` for just the 600-series).

### Coverage by scenario

| Test | Components exercised | Key assertion |
|------|---------------------|---------------|
| static-apply | daemon + CLI apply + netlink + CLI query | `ip` and JSON both show mtu=1400, address present |
| dhcp-and-static | daemon + DHCP factory + static factory + reconciler | Both interfaces correct, no cross-contamination |
| replace-all | daemon + replace-all semantics + address removal | Address absent after policy replacement |
| daemon-restart | PolicyStore persistence + startup reconciliation | MTU restored without explicit re-apply |
| conflict | reconciler merge + conflict detection + CLI exit code | Exit 1, output mentions "conflict" and "mtu" |
| dry-run | daemon dry-run path + CLI display | Exit 1, output mentions "mtu", kernel unchanged |
| apply-directory | CLI directory loading + daemon apply | Two interfaces with distinct MTUs |
| unmanaged | reconciler entity filtering | Unmanaged interface MTU and address unchanged |

### Failure diagnosis

Each test uses descriptive `FAIL:` messages with context (actual `ip link` output, exit codes, captured command output). The assertion helpers all print the failing interface's state on failure.

### Running tests

- All 600-series: `make integration-test SPEC=600`
- Single test: `bash tests/600-e2e-static-apply.sh`
- Full suite (including 600): `make integration-test`
