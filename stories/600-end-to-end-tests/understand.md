# Understand: SPEC-600 End-to-End Integration Tests

## Current State

All 8 specified end-to-end test scripts already exist and are implemented in `tests/`:

| File | Scenarios covered | Present |
|------|------------------|---------|
| `tests/600-e2e-static-apply.sh` | Static policy → ip + query JSON verification | Yes |
| `tests/600-e2e-dhcp-and-static.sh` | DHCP + static coexistence, cross-contamination checks | Yes |
| `tests/600-e2e-replace-all.sh` | Second apply removes state from first policy set | Yes |
| `tests/600-e2e-daemon-restart.sh` | Policy persistence and re-application across restart | Yes |
| `tests/600-e2e-conflict.sh` | Conflicting mtu policies → exit 1 + conflict output | Yes |
| `tests/600-e2e-dry-run.sh` | --dry-run → pending diff output, kernel unchanged | Yes |
| `tests/600-e2e-apply-directory.sh` | Directory of policies → multiple interfaces configured | Yes |
| `tests/600-e2e-unmanaged.sh` | Manually-configured interface untouched by apply | Yes |

**`tests/helpers.sh`** is present and complete. It provides all functions needed by the 600-series:
- `netns_setup()` — `unshare --user --net --map-root-user` re-entry loop
- `create_veth()`, `add_address()`
- `start_dnsmasq()` — hard-fails (exit 1) if dnsmasq not installed; stores PID in `_DNSMASQ_PIDS` for `cleanup()`
- `cleanup()` — EXIT trap, kills dnsmasq PIDs
- `assert_eq()`, `assert_match()`, `assert_has_address()`, `assert_link_up()`, `assert_not_has_address()`, `assert_mtu()`
- `wait_for_address()` — polls with 0.1 s interval up to a caller-specified second timeout

The **Makefile** `integration-test` target discovers `tests/[0-9]*.sh` automatically; the 600-series scripts are already included.

No Rust code exists for this story and none is required.

## Requirements

The spec calls for 8 shell test scripts exercising the full pipeline (write YAML → start daemon → apply → verify with `ip` and `netfyr query`). Concrete technical requirements derived from acceptance criteria:

1. Each script must: use `set -euo pipefail`; source `helpers.sh`; check both binaries with `[[ ! -x ]]` before `netns_setup`; use `trap` for cleanup; print `PASS: <name>` on success.
2. Binary paths default to `$SCRIPT_DIR/../target/debug/{netfyr,netfyr-daemon}`, overridable via `NETFYR_BIN` / `NETFYR_DAEMON_BIN`.
3. Daemon must be started with `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR` env vars pointing to temp dirs.
4. CLI must receive the socket path via `NETFYR_SOCKET_PATH` env var.
5. Daemon socket poll must hard-fail (exit 1) if socket does not appear, not silently continue.
6. DHCP tests must hard-fail if `dnsmasq` is not installed (no `exit 0` skip).
7. `600-e2e-conflict.sh` must verify exit code 1 from `netfyr apply`.
8. `600-e2e-dry-run.sh` must verify exit code 1 from `netfyr apply --dry-run` (changes pending) and kernel MTU unchanged.
9. `600-e2e-replace-all.sh` must verify address removal using `assert_not_has_address`.
10. `600-e2e-daemon-restart.sh` must reset kernel MTU to 1500 between daemon instances to prove the new daemon re-applies it.

## Gap Analysis

**No files need to be created or modified.** All 8 test scripts and the supporting `helpers.sh` are implemented and structurally match the specification:

- Binary validation, `netns_setup`, trap registration, temp dir, socket poll pattern: present in all 8 scripts.
- `assert_not_has_address` (needed by replace-all): exists in `helpers.sh` (line 143–154).
- `assert_mtu` (needed by 7 of 8 scripts): exists in `helpers.sh` (line 156–167).
- `wait_for_address` (needed by DHCP tests): exists in `helpers.sh` (line 169–187).
- DHCP hard-fail: present in `600-e2e-dhcp-and-static.sh` (line 26–29) and `600-e2e-unmanaged.sh` (line 26–29).
- Conflict exit code check: present in `600-e2e-conflict.sh` (line 95–99).
- Dry-run exit code check and mtu unchanged: present in `600-e2e-dry-run.sh` (line 80–93).
- Kernel MTU reset between restarts: present in `600-e2e-daemon-restart.sh` (line 100).
- `assert_not_has_address` for replace-all: present in `600-e2e-replace-all.sh` (line 113).

The Makefile `integration-test` target requires no changes (glob already covers 600-series).

The only outstanding work is **running** `make integration-test` to confirm all 8 tests pass. This validates that the underlying Rust implementations (SPEC-103, 201–203, 301–302, 401–403) behave correctly end-to-end.

## Integration Points

The tests exercise these components together:

- **`netfyr-daemon`** (`crates/netfyr-daemon`): started via subprocess; reads `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR`; `PolicyStore::load()` must reload persisted policies on restart; initial reconciliation must apply loaded policies without an explicit `netfyr apply` call (required by daemon-restart test).
- **`netfyr-cli`** (`crates/netfyr-cli`): `run_apply` (with and without `--dry-run`) and `run_query` (with `-s name=<iface> -o json`); must read `NETFYR_SOCKET_PATH` from the environment to connect to the test daemon socket; must return `ExitCode::FAILURE` (1) for conflicts and for non-empty dry-run diffs.
- **`netfyr-varlink`** (`crates/netfyr-varlink`): `VarlinkClient::connect`, `submit_policies`, `dry_run`, `query`; JSON serialization of state fields must produce `"mtu": 1400` matchable by `grep -q '"mtu".*1400'`.
- **`netfyr-backend`** (`crates/netfyr-backend`): `NetlinkBackend` must remove addresses not in desired state (replace-all test); `Dhcpv4Factory` must acquire a lease within 10 s (DHCP tests); neither must modify interfaces absent from the desired state (unmanaged test).
- **`netfyr-reconcile`** (`crates/netfyr-reconcile`): `merge()` must surface conflicts when two policies at the same priority set the same field to different values.
- **`tests/helpers.sh`**: all assertion and setup functions consumed directly by the 8 scripts.

## Risks

1. **Daemon restart re-applies on startup**: `600-e2e-daemon-restart.sh` relies on the new daemon instance automatically re-applying mtu=1400 from persisted policies, with no explicit `netfyr apply`. If the daemon only reconciles on incoming `submit_policies` RPC (not on startup), the test fails. This is a behavioral contract that must be satisfied by `netfyr-daemon/src/main.rs` or `reconciler.rs`.

2. **Conflict exit code contract**: `600-e2e-conflict.sh` expects exit code 1 from `netfyr apply`. `run_apply` in `netfyr-cli/src/apply.rs` must return `ExitCode::FAILURE` when `ConflictReport` is non-empty. If it returns 0 with a printed warning, the test fails.

3. **Dry-run exit code**: `600-e2e-dry-run.sh` expects exit code 1 when `--dry-run` shows pending changes. `run_apply` must return `ExitCode::FAILURE` (1) for a non-empty dry-run diff, not 0.

4. **Replace-all address removal**: `600-e2e-replace-all.sh` verifies that `10.99.0.1/24` is removed when policy A is replaced by policy B (which has no address field). The netlink apply path (SPEC-103) must actively remove addresses not in the desired state, not only add/modify.

5. **DHCP lease timing**: `wait_for_address` polls for up to 10 s (100 × 0.1 s). In slow CI environments or under emulated networking, DHCP negotiation may exceed this window, causing `600-e2e-dhcp-and-static.sh` and `600-e2e-unmanaged.sh` to flake.

6. **JSON mtu grep pattern**: `600-e2e-static-apply.sh` uses `grep -q '"mtu".*1400'` on the JSON query output. If the serializer emits `"mtu":1400` (no space after colon) or different key ordering, the match fails. The pattern tolerates whitespace between `"mtu"` and `1400` but not key reordering.

7. **dnsmasq availability**: Two of eight tests hard-fail if `dnsmasq` is absent. These tests will not pass in minimal CI environments. Per SPEC-001, this is correct behavior — but it constrains CI environment requirements.

8. **`start_dnsmasq` binding race**: `start_dnsmasq` sleeps 1 s after starting dnsmasq. If dnsmasq takes longer to bind in some environments, the DHCP client may not receive a response, causing the `wait_for_address` poll to exhaust its 10 s budget.
