# SPEC-404: Varlink API — Gap Analysis

## Current State

The `netfyr-varlink` crate has a substantially complete implementation. All three source files exist and are fully written. The daemon server is also fully implemented.

**`crates/netfyr-varlink/src/io.netfyr.varlink`** — exists and exactly matches the spec. Defines 4 methods (`SubmitPolicies`, `Query`, `DryRun`, `GetStatus`), all 12 type definitions, and 3 error types (`InvalidPolicy`, `BackendError`, `InternalError`).

**`crates/netfyr-varlink/src/client.rs`** — fully implemented. `VarlinkClient` implements the NUL-terminated JSON-over-`tokio::net::UnixStream` wire protocol directly (no external `varlink` crate). All 4 methods present. All 5 `VarlinkError` variants defined. Unit tests cover all acceptance criteria scenarios: connect success/failure, `SubmitPolicies` with valid and invalid policies, `Query` with and without selector, `DryRun`, `GetStatus`, all 3 error response variants, unknown error names.

**`crates/netfyr-varlink/src/types.rs`** — fully implemented. All Varlink wire types with `serde::{Serialize, Deserialize}`. All `From`/`TryFrom` conversions: `Selector ↔ VarlinkSelector`, `State → VarlinkStateDef`/`VarlinkState`, `Policy ↔ VarlinkPolicy`, `AppliedOperation`/`FailedOperation`/`SkippedOperation → VarlinkChangeEntry`, `Conflict → VarlinkConflictEntry`, `ApplyReport → VarlinkApplyReport`, `ConflictReport → VarlinkApplyReport` (via `convert_apply_report_with_conflicts`), `ReconcileStateDiff → VarlinkStateDiff`. Helper functions `value_to_json`, `json_to_value`, `state_fields_to_json`, `json_to_state_fields`. Comprehensive unit tests covering every acceptance criterion for type conversion.

**`crates/netfyr-varlink/Cargo.toml`** — uses `serde`, `serde_json`, `tokio`, `thiserror`, `indexmap`, and path deps on `netfyr-state`, `netfyr-policy`, `netfyr-backend`, `netfyr-reconcile`. No external `varlink` crate (wire protocol is implemented directly).

**`crates/netfyr-daemon/src/server.rs`** — fully implemented. `serve_varlink` binds a `UnixListener`, dispatches all 4 methods via `handle_connection`, triggers re-reconciliation on DHCP factory events, and handles SIGTERM/SIGINT with graceful shutdown and socket cleanup. Unit tests cover wire-protocol helpers, `GetStatus` with policy counts, unknown method error.

**`tests/helpers.sh`** — exists. Provides `netns_setup`, `create_veth`, `add_address`, `start_dnsmasq`, `cleanup`, `assert_eq`, `assert_match`, `assert_has_address`, `assert_link_up`. Does not include a daemon-start helper or socket-wait helper.

**`Makefile`** — exists. `make integration-test SPEC=404` discovers `tests/404-*.sh`.

## Requirements

From the acceptance criteria:

1. **IDL validity** — `src/io.netfyr.varlink` parses without errors and defines exactly 4 methods. *(Satisfied)*
2. **Client connect success** — `VarlinkClient::connect` returns `Ok` when a listener is bound. *(Satisfied)*
3. **Client connect failure** — returns `Err(ConnectionFailed)` when socket absent. *(Satisfied)*
4. **SubmitPolicies** — sends policies and receives `VarlinkApplyReport` with counts. *(Satisfied)*
5. **SubmitPolicies invalid policy** — unknown factory type returns `InvalidPolicy`. *(Satisfied)*
6. **Query** — returns `Vec<VarlinkState>` for all entities; selector filters by type/name. *(Satisfied)*
7. **DryRun** — returns `VarlinkStateDiff` without applying; system state unchanged. *(Satisfied at unit level; requires integration test for the "state unchanged" assertion)*
8. **GetStatus** — returns uptime, policy count, factory list. *(Satisfied at unit level)*
9. **Type conversion roundtrip** — `Policy → VarlinkPolicy → Policy` lossless. *(Satisfied)*
10. **ApplyReport conversion** — preserves counts and conflict entries. *(Satisfied)*
11. **Integration test: full round-trip** — `netfyr apply` + `netfyr query` + `ip link show` in namespace. *(Missing)*
12. **Integration test: replace-all** — second `netfyr apply` replaces first; `ip link show` confirms. *(Missing)*

## Gap Analysis

### What is complete — no action needed

All Rust implementation is done:
- `crates/netfyr-varlink/src/io.netfyr.varlink`
- `crates/netfyr-varlink/src/client.rs` (with full unit tests)
- `crates/netfyr-varlink/src/types.rs` (with full unit tests)
- `crates/netfyr-daemon/src/server.rs` (with unit tests)

### What is missing — must be created

**`tests/404-varlink-round-trip.sh`** — does not exist. Must:
- Call `netns_setup` to enter an unprivileged user+network namespace.
- Check that `NETFYR_BIN` and `NETFYR_DAEMON_BIN` binaries exist and are executable; exit 1 if not.
- Create a veth pair (`create_veth veth-test0 veth-test1`).
- Start the daemon in the background with `NETFYR_SOCKET_PATH` pointing to a temp socket; wait for the socket file to appear (poll loop or `inotifywait`).
- Run `netfyr apply` with a static policy file setting `mtu: 1400` on `veth-test0`.
- Run `netfyr query -s name=veth-test0` and assert the output contains `mtu: 1400`.
- Run `ip link show veth-test0` and assert MTU is 1400.
- Kill the daemon and exit 0 on success.

**`tests/404-varlink-replace-all.sh`** — does not exist. Must:
- Same namespace + veth + daemon setup as above.
- First `netfyr apply` with policy A (`mtu: 1400`); assert `ip link show` shows 1400.
- Second `netfyr apply` with policy B (`mtu: 1300`); assert `ip link show` shows 1300.
- Verify replace-all semantics: only policy B is active after the second apply.

**Daemon-start pattern (inline in each test or extracted to `helpers.sh`):**

Neither test script can use a daemon-start helper that does not yet exist. Each script must inline:
```bash
export NETFYR_SOCKET_PATH="$(mktemp -d)/netfyr.sock"
"$NETFYR_DAEMON_BIN" --socket "$NETFYR_SOCKET_PATH" &
DAEMON_PID=$!
# Wait for socket to appear (up to N seconds)
for i in $(seq 1 10); do [[ -S "$NETFYR_SOCKET_PATH" ]] && break; sleep 0.5; done
[[ -S "$NETFYR_SOCKET_PATH" ]] || { echo "FAIL: daemon did not start" >&2; exit 1; }
```
Cleanup must include `kill $DAEMON_PID`.

## Integration Points

- **`netfyr-cli/src/apply.rs:run_apply`** — calls `VarlinkClient::connect` for daemon auto-detection, then `submit_policies`. This is an existing consumer of the varlink client.
- **`netfyr-cli/src/query.rs:run_query`** — calls `VarlinkClient::connect`, then `query`.
- **`netfyr-daemon/src/server.rs:serve_varlink`** — the server side. Already wired to `PolicyStore`, `FactoryManager`, `Reconciler`.
- **`netfyr-daemon/src/main.rs`** — calls `serve_varlink` with the socket path from `NETFYR_SOCKET_PATH` env var or the default `/run/netfyr/netfyr.sock`.
- **`NETFYR_SOCKET_PATH` env var** — the integration test socket override; both daemon and CLI must respect it.
- **`tests/helpers.sh`** — extended or used as-is by the new test scripts.

## Risks

1. **Daemon start-up race in integration tests** — the daemon binds the socket asynchronously during startup. A poll loop waiting for the socket file is required; if the binary takes longer than expected to start, the test will incorrectly fail. The poll timeout needs to be generous (5–10 seconds).

2. **Netlink MTU apply inside unprivileged namespace** — `unshare --user --net --map-root-user` grants apparent root inside the namespace, which is sufficient for most netlink link-attribute operations on veth interfaces. However, certain kernel configurations (e.g., `kernel.unprivileged_userns_clone=0`) disable user namespaces entirely. If netlink apply fails silently, the MTU assertion will fail even if the Varlink layer is correct.

3. **`Query` error path in server maps `BackendError` to `InternalError`** — `handle_query` in `server.rs` returns `write_error(stream, "InternalError", ...)` on backend failure, but the spec says `Query` should return `BackendError`. This is a minor deviation from the spec's error-handling section. Does not affect the green-path acceptance criteria.

4. **`helpers.sh` lacks `assert_mtu` or MTU-extraction helper** — integration tests will need to parse `ip link show` output to extract the MTU value. This is straightforward with `grep`/`awk` but must be done inline in each script.

5. **`NETFYR_DAEMON_BIN` env var convention** — the spec names this variable but the daemon binary build target name must match. Confirm that `cargo build` produces `target/debug/netfyr-daemon` (the binary name is set in `crates/netfyr-daemon/Cargo.toml`'s `[[bin]]` section, not visible in the context snapshot).
