# Understand: SPEC-600 End-to-End Integration Tests

## Current State

All 16 test scripts specified in SPEC-600 already exist in `tests/`:

| File | Scenario |
|---|---|
| `tests/600-e2e-static-apply.sh` | Static policy apply + `ip` and `netfyr query -o json` verification |
| `tests/600-e2e-dhcp-and-static.sh` | DHCP and static coexistence on separate interfaces |
| `tests/600-e2e-replace-all.sh` | Second apply fully replaces first policy set (removes old address) |
| `tests/600-e2e-daemon-restart.sh` | Policy persistence and re-apply across daemon restart |
| `tests/600-e2e-conflict.sh` | Conflicting mtu policies → exit 1, output mentions "conflict" and "mtu" |
| `tests/600-e2e-dry-run.sh` | `--dry-run` → output mentions mtu change, kernel MTU unchanged |
| `tests/600-e2e-apply-directory.sh` | Directory of policies configures multiple interfaces |
| `tests/600-e2e-unmanaged.sh` | Manually configured interface is untouched by policy apply |
| `tests/600-e2e-addr-single.sh` | Single address applied and verified via `ip` and `netfyr query` |
| `tests/600-e2e-addr-five.sh` | 5 addresses applied in YAML order |
| `tests/600-e2e-addr-twenty.sh` | 20 addresses applied in YAML order (stress) |
| `tests/600-e2e-addr-replace.sh` | Old address set replaced by new one in order |
| `tests/600-e2e-addr-idempotent.sh` | Same addresses applied twice, no duplicates |
| `tests/600-e2e-addr-duplicate-reject.sh` | Duplicate in YAML → non-zero exit, error message, nothing applied |
| `tests/600-e2e-addr-overlapping-subnets.sh` | Addresses on different subnets coexist in order |
| `tests/600-e2e-addr-removal.sh` | Replace-all with no-address policy removes all addresses |

`tests/helpers.sh` (232 lines) provides all helpers referenced by these scripts:
- **Setup/teardown**: `netns_setup`, `create_veth`, `add_address`, `start_dnsmasq`, `cleanup` (kills dnsmasq PIDs)
- **Assertions**: `assert_eq`, `assert_match`, `assert_has_address`, `assert_not_has_address`, `assert_mtu`, `assert_link_up`, `assert_address_count`, `assert_json_address_order`
- **Polling**: `wait_for_address`

The Makefile already discovers and runs all `tests/[0-9]*.sh` via the `integration-test` target.

No Rust code changes are required by this story.

## Requirements

16 end-to-end shell test scripts, each exercising a full user workflow through the running daemon. All structural requirements are already met by the existing scripts:
- `set -euo pipefail`; source `helpers.sh`; check both binaries; fail if missing
- `netns_setup "$@"` for isolation via `unshare --user --net`
- Temp dir for socket and policy store; EXIT trap kills daemon and removes temp dir
- Daemon started with `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR` env vars
- Socket poll loop (50 × 0.1 s); hard-fail if socket does not appear
- Print `PASS: 600-e2e-<name>` on success; all failure paths `exit 1`

## Gap Analysis

**No new files need to be created.** All 16 scripts exist.

The only functional gap is a **dnsmasq process leak** in the two DHCP tests:

- `tests/600-e2e-dhcp-and-static.sh` (line 37)
- `tests/600-e2e-unmanaged.sh` (line 37)

Both scripts set their EXIT trap after `netns_setup`, which overrides the `trap cleanup EXIT` that `netns_setup` installs. As a result, `cleanup` is never called, and dnsmasq PIDs in `_DNSMASQ_PIDS` are not killed. The spec explicitly warns: "Leaked dnsmasq processes hold pipes open and cause the test runner to hang indefinitely."

Fix in both files — change:
```bash
trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT
```
to:
```bash
trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; cleanup; rm -rf "$TMPDIR_TEST"' EXIT
```

No other files need modification. The spec template references `kill_dnsmasq` as a named helper, but `helpers.sh` implements that functionality in `cleanup`; the existing tests already use `cleanup`, so no new helper function is needed.

## Integration Points

| Component | Role |
|---|---|
| `target/debug/netfyr-daemon` | Started per-test; applies policies on `submit_policies` RPC |
| `target/debug/netfyr` (`apply`) | `run_apply` in `crates/netfyr-cli/src/apply.rs`; exit codes 0/1/2 tested |
| `target/debug/netfyr` (`query -o json`) | `run_query` in `crates/netfyr-cli/src/query.rs`; `addresses` array order must match applied order |
| `netfyr-backend` netlink apply | `apply_ethernet` in `crates/netfyr-backend/src/netlink/apply.rs`; applies addresses in order, removes addresses not in desired state |
| `netfyr-state` schema validation | `SchemaRegistry::validate` in `crates/netfyr-state/src/schema.rs`; duplicate address list entries must be rejected |
| `tests/helpers.sh` | All scripts source it; `cleanup` must be called in DHCP test EXIT traps |
| `Makefile` `integration-test` | Auto-discovers new scripts by `tests/[0-9]*.sh` naming convention |

## Risks

1. **dnsmasq leak (confirmed gap)**: The two DHCP tests do not call `cleanup` in their EXIT traps. In a non-interactive bash shell, background jobs do not receive SIGHUP on shell exit, so dnsmasq outlives the test. This can cause the Makefile test loop to hang waiting on a pipe. This is the only change needed to complete this story.

2. **Duplicate-address exit code**: `600-e2e-addr-duplicate-reject.sh` checks for any non-zero exit code rather than specifically exit code 2. The comment in the file explains this is intentional resilience. This diverges from the acceptance criterion (`exit code is 2`) but is a reasonable trade-off.

3. **Address ordering (environment-dependent)**: The five address-ordering tests (`addr-five`, `addr-twenty`, `addr-replace`, `addr-idempotent`, `addr-overlapping-subnets`) use `assert_json_address_order` to verify `netfyr query` returns addresses in YAML insertion order. This requires `apply_ethernet` to insert in declaration order and `query_ethernet` to return in kernel insertion order. If either reorders, these tests fail.

4. **Daemon restart timing**: `600-e2e-daemon-restart.sh` resets the MTU to 1500 after killing the daemon and asserts mtu=1400 is restored immediately after the new daemon's socket appears — with no additional sleep. If the daemon defers initial reconciliation, the assertion may race.

