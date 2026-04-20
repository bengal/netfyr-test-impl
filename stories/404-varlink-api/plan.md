# SPEC-404: Varlink API — Implementation Plan

## Approach

All Rust code for this story is already complete. The `netfyr-varlink` crate (`client.rs`, `types.rs`, `io.netfyr.varlink`), the daemon server (`server.rs`), and all unit tests are fully implemented and passing. The only remaining work is creating two shell integration test scripts that exercise the full CLI-to-daemon round-trip through the Varlink API.

The two tests will run inside unprivileged network namespaces (via `unshare --user --net --map-root-user`), create veth pairs, start the daemon, and exercise `netfyr apply` and `netfyr query` to verify end-to-end behavior. This validates that the Varlink wire protocol, type conversions, daemon server dispatch, reconciliation, and netlink apply all work together correctly.

**Why shell tests instead of Rust integration tests?** The spec mandates shell scripts in `tests/` discoverable by the Makefile via `tests/[0-9]*.sh`. This matches the existing test infrastructure (`helpers.sh`). Shell tests exercise the actual compiled binaries as a user would, testing argument parsing, process lifecycle, socket creation/cleanup, and signal handling — none of which are reachable from `#[tokio::test]`.

## Design Decisions

### 1. Inline daemon lifecycle management (not a helpers.sh function)
- **Decision**: Each test script manages daemon start/stop inline rather than adding a helper to `helpers.sh`.
- **Alternatives considered**: Adding `start_daemon`/`stop_daemon` to `helpers.sh`.
- **Rationale**: Only two scripts need the daemon. Adding a helper creates coupling and premature abstraction. The daemon lifecycle is simple (4 lines to start, 1 to kill). If future stories add more daemon tests, a helper can be extracted then.

### 2. Extend `cleanup()` via trap to kill daemon
- **Decision**: Each script stores the daemon PID in a variable and adds a trap that kills it on EXIT, rather than modifying the `cleanup` function in `helpers.sh`.
- **Alternatives considered**: (a) Modifying `cleanup()` in helpers.sh to accept PIDs; (b) Appending to the existing EXIT trap.
- **Rationale**: The `netns_setup` function already registers `cleanup` as the EXIT trap. We must not overwrite it. Instead, we define a custom cleanup function in each script that kills the daemon AND calls the original `cleanup`. We pass this to `trap` after `netns_setup` returns (inside the namespace, after the trap is set). Actually, the simplest approach: define a wrapper function and re-register the trap after `netns_setup`. This is the pattern used when scripts need additional cleanup beyond what `helpers.sh` provides.

### 3. Socket path in a temp directory
- **Decision**: Use `mktemp -d` for the socket directory, set `NETFYR_SOCKET_PATH` to `$tmpdir/netfyr.sock`. Export the variable so both the daemon and CLI inherit it.
- **Alternatives considered**: Using a fixed path like `/tmp/netfyr-test-$$.sock`.
- **Rationale**: `mktemp -d` avoids collisions between parallel test runs. Both the daemon (`main.rs:42-43`) and CLI (`apply.rs:37-39`, `query.rs:20-25`) read `NETFYR_SOCKET_PATH` from the environment.

### 4. Daemon startup: env var, not CLI flag
- **Decision**: The daemon is started with `NETFYR_SOCKET_PATH` set in the environment. There is no `--socket` CLI flag.
- **Alternatives considered**: None — this is how the daemon is implemented (`main.rs:42-43` uses `std::env::var`).
- **Rationale**: The daemon has no CLI argument parser. It reads `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR` from environment variables.

### 5. Policy dir set to a temp directory
- **Decision**: Set `NETFYR_POLICY_DIR` to a temp directory (or the same `mktemp -d` directory) to prevent the daemon from trying to read `/var/lib/netfyr/policies` (which doesn't exist in the namespace).
- **Alternatives considered**: Ignoring it and relying on the daemon's fallback to an empty store on load failure.
- **Rationale**: The daemon logs an error on policy dir load failure but continues with an empty store. This works, but setting a valid empty dir avoids noisy error output and is cleaner.

### 6. Poll-loop for socket readiness
- **Decision**: After starting the daemon in the background, poll for the socket file with `[[ -S "$socket" ]]` in a loop with `sleep 0.2`, up to 5 seconds (25 iterations).
- **Alternatives considered**: (a) `sleep 2` — wasteful and fragile; (b) `inotifywait` — not universally installed.
- **Rationale**: The daemon creates the socket asynchronously during startup. A poll loop is the most portable approach. 5 seconds is generous enough for slow CI environments.

### 7. MTU assertion via `ip link show` parsing
- **Decision**: Extract MTU from `ip link show <iface>` output using `grep -oP 'mtu \K[0-9]+'`. Assert with `assert_eq`.
- **Alternatives considered**: (a) `ip -j link show` (JSON output) + `jq` — more robust but requires `jq`; (b) parsing YAML from `netfyr query`.
- **Rationale**: `ip link show` is always available. The `mtu \K[0-9]+` pattern is reliable — `ip link show` always outputs `mtu <number>` on the first line. This gives ground-truth kernel verification independent of the netfyr stack.

### 8. Query output assertion via grep
- **Decision**: Assert `netfyr query` output contains the expected MTU value by grepping the YAML output for `mtu: <value>`.
- **Alternatives considered**: Parsing YAML with `yq` — not universally installed.
- **Rationale**: The query output format is `- type: ethernet\n  name: ...\n  mtu: 1400\n  ...`. Grepping for `mtu: 1400` is sufficient for the acceptance criteria. We're not testing YAML parsing — we're testing that the Varlink round-trip delivers correct values.

### 9. Two separate test scripts (not one combined script)
- **Decision**: Create `tests/404-varlink-round-trip.sh` and `tests/404-varlink-replace-all.sh` as separate scripts.
- **Alternatives considered**: One combined script with both scenarios.
- **Rationale**: The spec's acceptance criteria define two distinct scenarios. Separate scripts provide clearer pass/fail granularity, and each test gets a clean namespace.

## File Changes

### 1. `tests/404-varlink-round-trip.sh`
- **Action**: Create
- **What**: Shell integration test for the "Full round-trip in namespace" acceptance scenario. The script should:
  1. Source `helpers.sh` and call `netns_setup` to enter an unprivileged user+network namespace.
  2. Locate binaries: `NETFYR_BIN` defaults to `$SCRIPT_DIR/../target/debug/netfyr`, `NETFYR_DAEMON_BIN` defaults to `$SCRIPT_DIR/../target/debug/netfyr-daemon`. Check both are executable; `exit 1` if not.
  3. Create a temp directory with `mktemp -d`. Set `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR` exports.
  4. Re-register the EXIT trap to add daemon cleanup (kill `$DAEMON_PID` then call original `cleanup`).
  5. Create a veth pair: `create_veth veth-test0 veth-test1`.
  6. Write a static policy YAML file to the temp dir. The policy should set `mtu: 1400` on `veth-test0`. Format:
     ```yaml
     kind: policy
     name: test-mtu
     factory: static
     priority: 100
     state:
       type: ethernet
       name: veth-test0
       mtu: 1400
     ```
  7. Start the daemon in the background: `"$NETFYR_DAEMON_BIN" &`. Store PID.
  8. Poll-wait for socket file to appear (up to 5 seconds).
  9. Run `"$NETFYR_BIN" apply "$policy_file"` — should exit 0.
  10. Run `"$NETFYR_BIN" query -s name=veth-test0` — capture output, grep for `mtu: 1400`.
  11. Run `ip link show veth-test0` — extract MTU, `assert_eq` it is `1400`.
  12. Exit 0 on success (the trap handles daemon kill + cleanup).
- **Why**: Fulfills the "Full round-trip in namespace" acceptance criterion. Verifies that `netfyr apply` submits policies via Varlink, the daemon reconciles and applies via netlink, `netfyr query` retrieves the state via Varlink, and the kernel state matches.

### 2. `tests/404-varlink-replace-all.sh`
- **Action**: Create
- **What**: Shell integration test for the "Replace-all semantics via Varlink" acceptance scenario. The script should:
  1. Same setup as the round-trip test (source helpers, netns_setup, locate binaries, temp dir, veth pair, start daemon).
  2. Write policy A YAML: `mtu: 1400` on `veth-test0`.
  3. Run `"$NETFYR_BIN" apply "$policy_a_file"`.
  4. Extract MTU from `ip link show veth-test0`, `assert_eq` it is `1400`.
  5. Write policy B YAML: `mtu: 1300` on `veth-test0` (different policy name, e.g., `test-mtu-b`).
  6. Run `"$NETFYR_BIN" apply "$policy_b_file"`.
  7. Extract MTU from `ip link show veth-test0`, `assert_eq` it is `1300`.
  8. This verifies replace-all semantics: the second apply replaces the first policy entirely, and the new MTU is applied.
  9. Exit 0 on success.
- **Why**: Fulfills the "Replace-all semantics via Varlink" acceptance criterion. Verifies that `SubmitPolicies` replaces the entire policy set (not appends), and the daemon re-reconciles with only the new policy.

## Dependencies

No new crate dependencies needed. The Rust implementation is complete. The shell tests only depend on:
- `bash`, `ip` (iproute2), `unshare` (util-linux) — already required by `helpers.sh`
- `grep` — standard POSIX utility
- The compiled `netfyr` and `netfyr-daemon` binaries (built by `cargo build` via Makefile)

## Implementation Order

### Step 1: Create `tests/404-varlink-round-trip.sh`
Write the round-trip test script. This can be verified independently with `bash tests/404-varlink-round-trip.sh` (after `cargo build`). The script must be executable (`chmod +x`).

### Step 2: Create `tests/404-varlink-replace-all.sh`
Write the replace-all test script. This shares the same setup pattern as step 1 but adds the two-phase apply logic. Must also be executable.

Both steps are independent and can be implemented in parallel. Neither has Rust compilation dependencies — the crate is already complete.

### Step 3: Verify with `make integration-test SPEC=404`
Run the Makefile target to confirm both scripts pass. This is the spec's required verification step.

## Risks and Mitigations

### 1. Daemon startup race condition
**Risk**: The daemon starts asynchronously. If the poll loop times out (socket doesn't appear within 5 seconds), the test fails even though the Varlink layer is correct.
**Mitigation**: Use a generous 5-second timeout with 0.2-second intervals (25 attempts). If this is still insufficient on slow CI, increase the timeout. Also, check if the daemon process is still alive during polling — if it exited early, fail immediately with the daemon's stderr output rather than waiting the full timeout.

### 2. Netlink MTU apply inside unprivileged namespace
**Risk**: `unshare --user --net --map-root-user` grants apparent root inside the namespace, which is needed for `ip link set mtu`. Some kernel configurations (`kernel.unprivileged_userns_clone=0` or restrictive AppArmor/SELinux) may prevent this. The netlink apply would fail, causing an incorrect MTU assertion failure.
**Mitigation**: The `netns_setup` helper in `helpers.sh` already handles this — if `unshare` is unavailable, it exits 1 with a clear message. The veth creation via `ip link add` also requires namespace capabilities. If that succeeds, MTU changes should also work. If the daemon's apply fails, the `netfyr apply` command will exit non-zero, and the test will fail at that assertion before reaching the MTU check — providing a clear error.

### 3. Daemon stderr output polluting test output
**Risk**: The daemon writes tracing output to stderr. This may make test output noisy.
**Mitigation**: Redirect daemon stderr to a log file in the temp directory: `"$NETFYR_DAEMON_BIN" 2>"$TMPDIR/daemon.log" &`. If the test fails, cat the log file to stderr for debugging. If it passes, the log is silently cleaned up with the temp dir.

### 4. Daemon not stopping cleanly on test exit
**Risk**: If the test script exits before killing the daemon (e.g., due to `set -e` triggering on a failing assertion), the daemon process could linger.
**Mitigation**: The EXIT trap ensures `kill $DAEMON_PID` runs on any exit path. Using `kill "$DAEMON_PID" 2>/dev/null || true` prevents the kill itself from causing a trap failure if the daemon already exited.

### 5. `netfyr query` output format may not contain `mtu` as a simple field
**Risk**: The query output format is YAML. The MTU value might be formatted differently than expected (e.g., as a string `"1400"` vs integer `1400`).
**Mitigation**: Looking at `query.rs:state_to_flat_map`, `Value::U64(1400)` serializes via `serde_json::to_value` as `1400` (number). When printed as YAML via `serde_yaml::to_string`, numbers are printed without quotes. So `grep "mtu: 1400"` will match. Add `|| grep "mtu: '1400'"` as a fallback, or use a more permissive pattern like `grep -E "mtu:.*1400"`.

### 6. Binary name mismatch
**Risk**: The Cargo.toml for `netfyr-cli` defines two binary targets: `netfyr-cli` and `netfyr`. The test should use `netfyr`, which is the user-facing binary name.
**Mitigation**: Confirmed in `crates/netfyr-cli/Cargo.toml:16`: `name = "netfyr"`. The binary at `target/debug/netfyr` is correct. Similarly, `crates/netfyr-daemon/Cargo.toml:6`: `name = "netfyr-daemon"` confirms `target/debug/netfyr-daemon`.

## Test Strategy

This story's remaining work IS the test implementation. The tests verify:

### Shell integration test 1: `404-varlink-round-trip.sh`
- **What it tests**: End-to-end Varlink API round trip — apply policies via CLI, daemon processes them, query returns applied state, kernel state matches.
- **Behaviors verified**: VarlinkClient connect, SubmitPolicies serialization/deserialization, daemon server dispatch, reconciliation, netlink apply, Query response, CLI output formatting.
- **Edge cases**: None tested here — this is the golden path.

### Shell integration test 2: `404-varlink-replace-all.sh`
- **What it tests**: Replace-all semantics — a second `netfyr apply` replaces (not appends to) the policy set, and the system state reflects only the new policy.
- **Behaviors verified**: `PolicyStore::replace_all`, factory re-sync, re-reconciliation with changed desired state, netlink apply of updated MTU.
- **Edge cases**: Verifies that the first policy's effects are superseded by the second policy.

### Already-covered by existing unit tests (no additional tests needed)
- Type conversion round-trips (Policy, Selector, State, ApplyReport, StateDiff) — covered in `types.rs` tests
- Client connect success/failure — covered in `client.rs` tests
- Error response parsing (InvalidPolicy, BackendError, InternalError) — covered in `client.rs` tests
- Wire protocol helpers (read_message, write_message, write_error, write_success) — covered in `server.rs` tests
- GetStatus handler — covered in `server.rs` tests
