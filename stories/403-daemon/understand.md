# Gap Analysis: SPEC-403 Daemon Architecture

## Current State

All four Rust source modules called out in the spec are **fully implemented** with inline unit tests.

**`crates/netfyr-daemon/src/main.rs`** — Complete startup sequence: tracing init, env-var path overrides (`NETFYR_SOCKET_PATH`, `NETFYR_POLICY_DIR`), socket dir creation, `PolicyStore::load`, `FactoryManager::sync`, initial `reconciler.reconcile_and_apply`, `sd_notify(READY=1)`, `serve_varlink` call, graceful shutdown via `factory_manager.stop_all()` on SIGTERM/SIGINT.

**`crates/netfyr-daemon/src/server.rs`** — Full Varlink IPC server: NUL-terminated JSON wire protocol (`read_message`/`write_message`), four request handlers (`handle_submit_policies`, `handle_query`, `handle_dry_run`, `handle_get_status`), `serve_varlink` event loop with `tokio::select!` across incoming connections, factory events (`FactoryEvent::LeaseAcquired/LeaseRenewed/LeaseExpired/Error`), SIGTERM, and SIGINT. Socket file removed on shutdown. Unit tests cover wire protocol correctness and `GetStatus` handler.

**`crates/netfyr-daemon/src/factory_manager.rs`** — Complete `FactoryManager`: `sync` (start new, stop removed, leave running), `produced_states`, `stop_all`, `next_event`, `factory_statuses`. Uses `rtnetlink` via `netfyr_backend::interface_exists` to validate interfaces before starting factories. Extensive unit tests cover empty sets, static-only policies, DHCPv4 without selector, nonexistent interfaces, and idempotency.

**`crates/netfyr-daemon/src/reconciler.rs`** — Complete `Reconciler`: `reconcile_and_apply` (builds `PolicyInput` list from static factory outputs and DHCP factory-produced states, calls `merge`, filters actual state to managed entities only, applies `netfyr_state::diff::diff`), `dry_run` (returns `(ReconcileStateDiff, ConflictReport)` via `generate_diff`), `query`. `build_policy_inputs` assembles both static and DHCP-produced inputs. `ApplyResult` struct wraps `ApplyReport` and `ConflictReport`. Unit tests for dry-run repeatability, query, and construction smoke test.

**`crates/netfyr-daemon/src/policy_store.rs`** — Complete `PolicyStore` (from SPEC-402): disk-backed load, atomic `.yaml.tmp` → rename writes, replace-all semantics, crash recovery, ephemeral mode. 30+ unit tests.

**Existing integration tests covering daemon behavior** (not prefixed 403):
- `tests/401-dhcpv4-acquire-lease.sh` — daemon + DHCP policy, lease acquisition
- `tests/401-dhcpv4-daemon-restart.sh` — policy persistence through daemon restart
- `tests/401-dhcpv4-unmanaged-interface.sh` — unmanaged interfaces left untouched
- `tests/404-varlink-round-trip.sh` — daemon + static policy MTU apply + query verify
- `tests/404-varlink-replace-all.sh` — replace-all semantics via daemon

**No `tests/403-*.sh` files exist.** `make integration-test SPEC=403` discovers scripts via `tests/403-*.sh` glob; with zero matching files it prints a notice and exits 0 (vacuously passes without validating anything).

## Requirements

From the acceptance criteria, these behaviors must be verified by `403-*.sh` shell integration tests:

1. Daemon starts, creates socket, is reachable.
2. Daemon loads pre-persisted policies on startup and applies them without a second `netfyr apply`.
3. SIGTERM causes clean exit; applied network configuration is left in place.
4. `SubmitPolicies` with policies C+D when A+B were active → only C+D remain active and on disk.
5. Submitting a DHCPv4 policy starts a factory; lease is acquired; interface comes up.
6. Removing a DHCPv4 policy stops the factory; lease is released.
7. Lease acquisition triggers re-reconciliation; combined static+DHCP state is applied (e.g., mtu from static policy, address from DHCP).
8. Query returns current system state (backend queried through daemon).
9. Dry-run computes diff without applying; system state unchanged.
10. GetStatus returns policy count and factory status.
11. Static policy in namespace: veth pair + mtu=1400 → `ip link show` confirms mtu 1400.
12. DHCP policy in namespace: veth pair + dnsmasq + dhcpv4 policy → address in range acquired; link UP.
13. DHCP policy does not touch other interfaces: unmanaged veth with mtu/UP state stays untouched.
14. Replace-all changes effective policy: mtu=1400 → submit mtu=1300 → kernel confirms 1300.

## Gap Analysis

### Missing: `tests/403-*.sh` integration tests

No `tests/403-*.sh` files exist. The following scripts must be created to satisfy `make integration-test SPEC=403`:

| Script | Acceptance criteria covered |
|---|---|
| `tests/403-daemon-starts-and-listens.sh` | Socket created; daemon reachable after start |
| `tests/403-daemon-loads-persisted-policies.sh` | Startup applies pre-persisted policy without `netfyr apply` |
| `tests/403-daemon-graceful-shutdown.sh` | SIGTERM exits cleanly; applied MTU survives shutdown |
| `tests/403-apply-static-policy.sh` | Static MTU policy applied in namespace (mtu 1400) |
| `tests/403-replace-all.sh` | Replace-all changes effective policy (mtu 1400 → 1300) |
| `tests/403-apply-dhcp-policy.sh` | DHCP lease acquired via daemon in namespace |
| `tests/403-dhcp-unmanaged-interface.sh` | Unmanaged interface not modified when DHCP policy targets a different interface |
| `tests/403-dhcp-and-static-merged.sh` | After lease acquisition, static mtu and DHCP address both applied |

Each script must follow `tests/helpers.sh` conventions:
- Source `helpers.sh`; call `netns_setup "$@"` early.
- Check binary existence with `[[ ! -x "$NETFYR_BIN" ]]` → `exit 1`. Same for `NETFYR_DAEMON_BIN`.
- Locate binaries via `NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"`.
- Missing prerequisites (`dnsmasq`) → `echo "FAIL: ..." >&2; exit 1`. Never `exit 0` on failure.
- Manage `DAEMON_PID` with `trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT`.
- Poll for socket readiness (up to 5 s) before running `netfyr apply`.

### Not missing: Rust implementation

All daemon Rust modules are complete. No Rust source files need to be created or modified for this story.

### Potentially out of scope: systemd unit files

The spec defines `netfyr.service` and `netfyr.socket`. No such files exist in the project. These are installation artifacts, not part of the shell test suite or Rust build. Their inclusion depends on the story's definition of done; they are not required to make `make integration-test SPEC=403` pass.

## Integration Points

- **`tests/helpers.sh`**: all 403 scripts must source this for `netns_setup`, `create_veth`, `add_address`, `start_dnsmasq`, `cleanup`, and assertion helpers.
- **`netfyr` CLI binary**: `run_apply` routes through `VarlinkClient` when `NETFYR_SOCKET_PATH` is set; shell tests depend on this path working end-to-end.
- **`netfyr-daemon` binary**: shell tests start it as a subprocess with `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR` overrides.
- **`netfyr_varlink`**: server-side JSON wire protocol in `server.rs` is symmetric to `VarlinkClient`; any change to wire format in either must be coordinated.
- **`netfyr_backend::interface_exists`**: used in `FactoryManager::sync` to validate interfaces before starting factories; tests using nonexistent interfaces will see the factory fail gracefully.

## Risks

1. **Overlap with 401/404 tests**: Several 403 scenarios (DHCP lease, unmanaged interface, static MTU) are already covered by `401-*.sh` and `404-*.sh`. The 403 scripts must still be created independently because `make integration-test SPEC=403` only runs the `403-` prefix.

2. **Managed-entity removal boundary**: `reconciler.rs` restricts diffs to entities present in the effective desired state. When a policy is removed entirely, previously-configured fields on the interface linger until another policy touches that entity. The `403-replace-all.sh` test must verify the new effective value (mtu change within the same entity) rather than testing full entity removal.

3. **Lease expiry test timing**: Verifying `LeaseExpired` re-reconciliation requires a short lease time (dnsmasq minimum is `30s`) and a polling wait. This test may be slow. It is acceptable to omit a lease-expiry shell test from the 403 suite and rely on the 401 test that already covers this scenario.

4. **Daemon startup race**: The existing 401/404 tests poll for socket existence (50 × 100 ms = 5 s). The 403 tests must follow the same pattern. The daemon sends `sd_notify(READY=1)` but tests cannot easily wait on sd_notify; socket existence is the reliable signal.

5. **Graceful shutdown test**: Verifying that applied config survives SIGTERM requires sending SIGTERM to the daemon, waiting for it to exit, then checking `ip link show`. The daemon removes the socket file on shutdown, so absence of the socket is the exit signal. This is straightforward but must be implemented carefully to avoid a race.

6. **Single-connection serialization**: `serve_varlink` accepts one connection at a time in the `tokio::select!` loop. Concurrent CLI invocations will queue. This is a known limitation of the implementation and does not affect the shell tests (which are sequential), but should be noted.

