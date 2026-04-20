# SPEC-403: Daemon Architecture — Implementation Plan

## Approach

All daemon Rust source code is fully implemented and tested (unit tests pass). The remaining work is creating `tests/403-*.sh` shell integration tests so that `make integration-test SPEC=403` exercises the daemon's lifecycle, policy submission, DHCP factory management, and query/dry-run APIs end-to-end in unprivileged network namespaces.

The test scripts follow the established pattern from `tests/401-*.sh` and `tests/404-*.sh`: each script sources `helpers.sh`, calls `netns_setup "$@"` to enter a `unshare --user --net` namespace, starts the daemon as a background process with `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR` overrides pointing at temp directories, polls for socket readiness, then exercises the daemon through `netfyr apply` / `netfyr query` and verifies kernel state via `ip link show` / `ip addr show`.

**Why shell scripts over Rust integration tests:** The spec mandates shell scripts in `tests/[0-9]*.sh` discovered by the Makefile's `integration-test` target. These run via `make integration-test SPEC=403` and exercise the compiled binaries as a user would, catching issues that Rust-level tests cannot (binary startup, signal handling, environment variable plumbing, CLI-to-daemon round-trip). The existing 401/404 tests demonstrate this pattern works well and provides high confidence in the full stack.

**Test selection rationale:** The acceptance criteria list ~14 scenarios. Several overlap with existing 401/404 tests (e.g., DHCP lease acquisition, unmanaged interface preservation, replace-all semantics). The 403 scripts must still be created independently because `make integration-test SPEC=403` only runs the `403-` prefix. However, we can keep overlapping tests concise — they validate the same behavior from SPEC-403's perspective without duplicating complex setup. We consolidate related scenarios into fewer scripts where practical (e.g., one script for "daemon starts + listens + loads persisted policies" rather than three separate scripts).

## Design Decisions

### 1. Test script granularity
- **Decision:** 8 scripts, each covering 1-3 related acceptance criteria. Group tightly-coupled scenarios (e.g., "daemon starts and listens" + "loads persisted policies on startup" in one script since the second requires the first).
- **Alternatives:** One script per acceptance criterion (14 scripts) or one monolithic script.
- **Rationale:** 14 scripts would have massive boilerplate overlap (each needs daemon setup). One monolithic script would make failures hard to diagnose. 8 scripts balances isolation with reduced boilerplate.

### 2. Socket readiness polling pattern
- **Decision:** Poll for socket file existence with `[[ ! -S "$SOCKET_PATH" ]]` in a loop, 50 iterations × 100ms sleep = 5s timeout. Check `kill -0 "$DAEMON_PID"` each iteration to detect early daemon exit.
- **Alternatives:** Use `systemd-notify` or a readiness file.
- **Rationale:** Matches the pattern used in all existing tests (401/404). The daemon does call `sd_notify(READY=1)` but there's no `$NOTIFY_SOCKET` set in test environments, so socket existence is the reliable signal. Adding the `kill -0` check (used in 404 tests but not 401 tests) catches daemon crashes during startup.

### 3. DHCP lease wait pattern
- **Decision:** Poll `ip addr show dev $IFACE` for the expected address prefix, 100 iterations × 100ms = 10s timeout.
- **Alternatives:** Shorter timeout, or query via `netfyr query`.
- **Rationale:** DHCP negotiation in the namespace takes 1-3 seconds typically, but we allow 10s for slow CI. Polling kernel state directly (via `ip addr show`) is more authoritative than querying the daemon, which might report the lease before it's applied.

### 4. Graceful shutdown verification
- **Decision:** Send `SIGTERM` to daemon PID, then poll for socket file disappearance (the daemon removes the socket on shutdown), then `wait "$DAEMON_PID"` to collect exit status, then verify kernel state is preserved.
- **Alternatives:** Just `kill` and `wait` without checking socket removal.
- **Rationale:** Socket removal is the daemon's explicit shutdown signal (implemented in `server.rs` lines 467-472). Waiting for socket disappearance ensures the daemon completed its shutdown sequence (including `factory_manager.stop_all()`) before we check kernel state. This avoids a race where we check state before shutdown completes.

### 5. GetStatus and DryRun testing
- **Decision:** Omit dedicated shell test scripts for GetStatus and DryRun. These are tested via the existing Rust unit tests in `server.rs` (GetStatus handler tests) and `reconciler.rs` (dry-run tests), plus the CLI's `--dry-run` flag testing in 301-*.sh scripts.
- **Alternatives:** Write shell scripts that parse JSON responses from the daemon.
- **Rationale:** Testing GetStatus and DryRun from shell would require parsing JSON output, which is fragile and adds `jq` as a dependency. The Rust unit tests already cover the handler logic thoroughly. The 403 shell tests should focus on behaviors only observable from outside the process: kernel state changes, signal handling, policy persistence across restarts.

### 6. DHCP + static merged test
- **Decision:** Create a test that submits both a static policy (mtu=9000) and a DHCPv4 policy for the same interface, then verifies both the MTU and the DHCP address are applied.
- **Alternatives:** Rely on separate static and DHCP tests.
- **Rationale:** This tests the reconciliation merge path (combining PolicyInputs from different sources), which is a core daemon responsibility not covered by the separate static-only and DHCP-only tests.

### 7. Lease expiry test omission
- **Decision:** Omit a lease-expiry shell test from the 403 suite.
- **Alternatives:** Set dnsmasq lease time to minimum (2m) and wait.
- **Rationale:** Minimum dnsmasq lease time is 2 minutes (`120` in the config, which dnsmasq interprets as 120 seconds minimum). Waiting 2+ minutes makes the test suite unacceptably slow. The lease expiry re-reconciliation path is exercised by the same code as lease acquisition (both call `reconciler.reconcile_and_apply`), and the factory event handling is covered by unit tests.

## File Changes

### `tests/403-daemon-starts-and-listens.sh`
- **Action:** Create
- **What:** Test that the daemon starts, creates the Varlink socket, and loads pre-persisted policies on startup.
  - Pre-write a static policy YAML to the policy directory before starting the daemon
  - Create a veth pair
  - Start the daemon with env var overrides
  - Poll for socket appearance (5s timeout)
  - Verify the daemon is reachable by running `netfyr query` through it
  - Verify that the pre-persisted policy was applied on startup (check kernel mtu via `ip link show`) without any explicit `netfyr apply`
- **Why:** Covers acceptance criteria: "Daemon starts and listens on Varlink socket", "Daemon loads persisted policies on startup"

### `tests/403-daemon-graceful-shutdown.sh`
- **Action:** Create
- **What:** Test that SIGTERM causes clean exit and applied config survives.
  - Create veth pair, start daemon, wait for socket
  - Submit a static mtu policy via `netfyr apply`
  - Verify mtu is applied via `ip link show`
  - Send SIGTERM to daemon PID
  - Wait for daemon to exit (poll for socket removal, then `wait "$DAEMON_PID"`)
  - Verify the exit status is 0 (clean exit)
  - Verify kernel mtu is STILL the applied value (config survives shutdown)
- **Why:** Covers acceptance criteria: "Daemon shuts down gracefully", "applied network configuration is left in place"

### `tests/403-apply-static-policy.sh`
- **Action:** Create
- **What:** Test static MTU policy applied through the daemon in a namespace.
  - Create veth pair veth-test0/veth-test1
  - Start daemon, wait for socket
  - Write a policy YAML with mtu=1400 for veth-test0
  - Run `netfyr apply policy.yaml`
  - Verify `netfyr apply` exits 0
  - Verify `ip link show veth-test0` shows mtu 1400
- **Why:** Covers acceptance criteria: "Daemon applies static policy in namespace"

### `tests/403-replace-all.sh`
- **Action:** Create
- **What:** Test replace-all semantics: a second `netfyr apply` replaces the entire policy set.
  - Create veth pair, start daemon, wait for socket
  - Apply policy A with mtu=1400, verify kernel mtu is 1400
  - Apply policy B with mtu=1300 (different policy name), verify kernel mtu is 1300
  - The key assertion is that the second apply replaces (not appends to) the policy set
- **Why:** Covers acceptance criteria: "Replace-all removes old policies in namespace", "Submit policies replaces entire set"

### `tests/403-apply-dhcp-policy.sh`
- **Action:** Create
- **What:** Test DHCP lease acquisition through the daemon.
  - Create veth pair veth-dhcp0/veth-dhcp1
  - Add address 10.99.0.1/24 to veth-dhcp1
  - Start dnsmasq on veth-dhcp1 serving 10.99.0.100-10.99.0.200
  - Start daemon, wait for socket
  - Submit DHCPv4 policy for veth-dhcp0 via `netfyr apply`
  - Poll up to 10s for veth-dhcp0 to acquire an address in 10.99.0.0/24
  - Assert address is present and link is UP
- **Why:** Covers acceptance criteria: "Daemon handles DHCP policy in namespace", "Submit policies starts new DHCP factories"

### `tests/403-dhcp-unmanaged-interface.sh`
- **Action:** Create
- **What:** Test that a DHCP policy for one interface does not disturb another unmanaged interface.
  - Create two veth pairs: veth-dhcp0/veth-dhcp1 and veth-other0/veth-other1
  - Set veth-other0 mtu=1400 (manually, before daemon starts)
  - Add address 10.99.0.1/24 to veth-dhcp1, start dnsmasq
  - Start daemon, submit DHCPv4 policy for veth-dhcp0 ONLY
  - Wait for DHCP lease on veth-dhcp0
  - Assert veth-other0 is still UP and mtu is still 1400
- **Why:** Covers acceptance criteria: "DHCP policy does not tear down other interfaces"

### `tests/403-dhcp-and-static-merged.sh`
- **Action:** Create
- **What:** Test that static and DHCP policies for the same interface are merged correctly.
  - Create veth pair veth-dhcp0/veth-dhcp1
  - Add address 10.99.0.1/24 to veth-dhcp1, start dnsmasq
  - Start daemon, wait for socket
  - Write a multi-document YAML or two YAML files: one static policy setting mtu=9000 on veth-dhcp0, one DHCPv4 policy for veth-dhcp0
  - Submit both via `netfyr apply`
  - Wait for DHCP lease
  - Assert veth-dhcp0 has mtu=9000 (from static) AND has an address in 10.99.0.0/24 (from DHCP)
- **Why:** Covers acceptance criteria: "Lease acquisition triggers reconciliation", "eth0 gets mtu=9000 (from static) and address 10.0.1.50/24 (from DHCP)"

### `tests/403-dhcp-factory-stopped-on-removal.sh`
- **Action:** Create
- **What:** Test that removing a DHCP policy stops the factory.
  - Create veth pair veth-dhcp0/veth-dhcp1 and veth-test0/veth-test1
  - Start dnsmasq, start daemon, submit DHCPv4 policy for veth-dhcp0
  - Wait for lease acquisition
  - Submit a SECOND `netfyr apply` with ONLY a static policy for veth-test0 (no DHCP policy)
  - This replaces the policy set, removing the DHCP policy
  - Verify that the daemon accepted the new policy (check exit code)
  - Verify the static policy was applied (check veth-test0 mtu)
- **Why:** Covers acceptance criteria: "Submit policies stops removed DHCP factories"

## Dependencies

No new crate dependencies are needed. The shell tests use only the compiled `netfyr` and `netfyr-daemon` binaries plus standard system tools (`ip`, `unshare`, `bash`, `dnsmasq`).

## Implementation Order

### Step 1: Create `tests/403-apply-static-policy.sh`
The simplest test — static policy, no DHCP. Validates the basic daemon lifecycle (start, accept policy, apply, verify kernel state). This establishes the boilerplate pattern for all subsequent tests.
**Verification:** `make integration-test SPEC=403` runs this script and passes.

### Step 2: Create `tests/403-daemon-starts-and-listens.sh`
Tests startup with pre-persisted policies. Depends on step 1's pattern. Validates that the daemon loads policies from disk on startup without requiring `netfyr apply`.
**Verification:** Script passes. Validates policy persistence path.

### Step 3: Create `tests/403-daemon-graceful-shutdown.sh`
Tests SIGTERM handling. Depends on step 1's pattern. Validates that applied config survives daemon shutdown.
**Verification:** Script passes. SIGTERM handling works correctly.

### Step 4: Create `tests/403-replace-all.sh`
Tests replace-all semantics. Depends on step 1's pattern. Two sequential `netfyr apply` calls, second replaces first.
**Verification:** Script passes. MTU changes from first to second policy.

### Step 5: Create `tests/403-apply-dhcp-policy.sh`
First DHCP test. Introduces dnsmasq setup. Tests lease acquisition through the daemon.
**Verification:** Script passes. Requires `dnsmasq` installed.

### Step 6: Create `tests/403-dhcp-unmanaged-interface.sh`
DHCP test with unmanaged interface. Depends on step 5's DHCP pattern. Verifies isolation.
**Verification:** Script passes. Unmanaged interface untouched.

### Step 7: Create `tests/403-dhcp-and-static-merged.sh`
Merges static + DHCP policies. Most complex test — validates the reconciliation merge path.
**Verification:** Script passes. Both MTU and DHCP address applied.

### Step 8: Create `tests/403-dhcp-factory-stopped-on-removal.sh`
Tests DHCP factory stop on policy removal. Replace DHCP policy set with static-only set.
**Verification:** Script passes. Static policy applied after DHCP removal.

### Step 9: Run full suite
`make integration-test SPEC=403` — all 8 scripts pass.
`cargo test -p netfyr-daemon` — all existing Rust unit tests still pass.
`cargo clippy` — no warnings.

## Risks and Mitigations

### Risk 1: Daemon startup race with pre-persisted DHCP policies
- **Problem:** In `403-daemon-starts-and-listens.sh`, if the pre-persisted policy is a DHCP policy, the daemon tries to start a factory on startup before the test has created the veth pair. The interface won't exist yet.
- **Mitigation:** Use only static policies for the pre-persistence test. DHCP policies are tested in separate scripts where the veth pair is created before daemon start.

### Risk 2: MTU 9000 in merged DHCP+static test
- **Problem:** Setting MTU=9000 on a veth interface may fail if the peer's MTU is lower. Veth interfaces have a default MTU of 1500.
- **Mitigation:** Set MTU on both ends of the veth pair, or use a value like 1400 that's below the default. Actually, the simpler approach: use mtu=1400 for the static policy in the merged test instead of 9000. The spec's example uses 9000, but the test only needs to verify that the static MTU is applied alongside the DHCP address — any non-default value works. Use 1400 to avoid veth MTU constraints.

### Risk 3: dnsmasq not available
- **Problem:** DHCP tests require `dnsmasq`. If not installed, the test must fail with exit 1, not silently pass.
- **Mitigation:** Each DHCP test checks `command -v dnsmasq` early and exits 1 with a clear message if not found. This follows the convention from existing 401 tests and the spec's "No skip" rule.

### Risk 4: Overlap with 401/404 tests
- **Problem:** Several 403 tests cover scenarios already tested by 401/404 (DHCP acquisition, unmanaged interface, replace-all).
- **Mitigation:** This is intentional — `make integration-test SPEC=403` must be self-sufficient. The 403 tests can be slightly simpler than their 401/404 counterparts since they're confirming the same behavior from a different story's perspective.

### Risk 5: DHCP factory stop verification
- **Problem:** In `403-dhcp-factory-stopped-on-removal.sh`, after replacing the DHCP policy with a static-only policy, we can't easily verify that the factory was stopped (no external observable signal other than the lease not being renewed). We can only verify that the new policy was applied.
- **Mitigation:** The test verifies the replace-all semantics work (static policy applied) and the daemon accepted the change (exit code 0). The factory stop is internal behavior tested by Rust unit tests. The shell test focuses on the externally observable outcome.

### Risk 6: Test cleanup on failure
- **Problem:** If a test fails mid-execution, the daemon process and temp directory must still be cleaned up.
- **Mitigation:** Every test uses `trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT` immediately after creating the temp dir. The `netns_setup` function also registers `cleanup` as an EXIT trap for dnsmasq processes. The `|| true` ensures cleanup doesn't fail if the daemon already exited.

## Test Strategy

All testing for this story is shell integration tests (`tests/403-*.sh`). No new Rust test code is needed.

### What to test (8 shell scripts):

1. **Daemon lifecycle:** starts, creates socket, loads pre-persisted policies and applies them on startup
2. **Graceful shutdown:** SIGTERM exits cleanly, applied config survives
3. **Static policy:** MTU applied through daemon in namespace
4. **Replace-all:** Second apply replaces first policy set
5. **DHCP acquisition:** Lease acquired through daemon
6. **Unmanaged isolation:** DHCP policy doesn't touch other interfaces
7. **Static + DHCP merge:** Both static fields and DHCP fields applied to same interface
8. **DHCP removal:** Removing DHCP policy via replace-all stops factory

### What NOT to test in 403 shell scripts:
- **GetStatus/DryRun:** Covered by Rust unit tests; parsing JSON from shell is fragile
- **Lease renewal/expiry:** Requires long waits; covered by Rust unit tests and same code path as acquisition
- **Wire protocol correctness:** Covered by `server.rs` unit tests
- **Policy persistence internals:** Covered by `policy_store.rs` unit tests (30+ tests)
- **Reconciliation merge logic:** Covered by `netfyr-reconcile` unit tests

### Test conventions (from existing tests and SPEC-001):
- Script naming: `403-description.sh`
- Source `helpers.sh`, call `netns_setup "$@"` early
- Binary path via `NETFYR_BIN` / `NETFYR_DAEMON_BIN` env vars, defaulting to `$SCRIPT_DIR/../target/debug/netfyr` / `netfyr-daemon`
- Check binary existence with `[[ ! -x "$NETFYR_BIN" ]]` → exit 1
- Missing prerequisites (dnsmasq) → exit 1, never exit 0
- `set -euo pipefail` (inherited from helpers.sh)
- Temp dir with trap for cleanup
- Socket readiness polling: 50 × 100ms with `kill -0` check
- DHCP lease polling: 100 × 100ms
- Assert helpers: `assert_eq`, `assert_match`, `assert_has_address`, `assert_link_up`
- Print `PASS: 403-<name>` on success
