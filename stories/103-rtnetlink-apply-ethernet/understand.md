# Understand: SPEC-103 — rtnetlink Apply for Ethernet Interfaces

## Current State

The implementation is **substantially complete**. All Rust logic prescribed by the spec is present and correct. The only gap is the shell integration test scripts.

### `crates/netfyr-backend/src/netlink/apply.rs` — fully implemented

Both public entry points exist with full logic:

- `apply_ethernet(handle, diff)` — iterates `StateDiff` ops, filters to `entity_type == "ethernet"`, dispatches to `apply_add` / `apply_modify` / `apply_remove`. Never returns `Err`; per-operation errors land in `ApplyReport.failed` (continue-and-report mode).
- `dry_run_ethernet(handle, diff)` — same dispatch but queries current state to build `PlannedChange` entries; non-existent interfaces appear in `report.skipped`, not a separate `failed` collection.

`apply_modify_fields` implements the prescribed three-phase ordering:
1. **Link-level**: `mtu` (with idempotency skip when value equals current value), `operstate` up/down.
2. **Addresses**: full desired-vs-current delta; adds before removes; EEXIST → skip "already present"; not-found on delete → skip "not present".
3. **Routes**: same delta pattern; EEXIST → skip; not-found on delete → skip "not present".

Read-only fields (`carrier`, `speed`, `mac`, `driver`, `name`) produce `SkippedOperation` with reason `"read-only field"`.

Remove operations: delete all addresses, all routes (IPv4 + IPv6 via two route dump calls), then set link down via `LinkUnspec::new_with_index(index).down()`. Physical interfaces are never deleted from the kernel.

Error mapping: EPERM (1) / EACCES (13) → `BackendError::PermissionDenied`; ENODEV (19) → `BackendError::NotFound`; all others → `BackendError::ApplyFailed`. `extract_errno` reads `ErrorMessage.code` as `Option<NonZeroI32>` (negative kernel errno) and negates it.

Idempotency: MTU skip uses explicit value comparison; address EEXIST detection uses `is_eexist()`; route EEXIST detection uses `is_eexist_backend()` which downcasts `ApplyFailed.source`; "not present" skips use `is_not_found_error()` matching errnos 2, 3, 19, 99.

### `crates/netfyr-backend/src/netlink/mod.rs` — fully implemented

`NetlinkBackend::apply` and `NetlinkBackend::dry_run` open a fresh `Handle` via `establish_connection()` and delegate to `apply_ethernet` / `dry_run_ethernet`. Wired to the `NetworkBackend` trait via `async-trait`.

### `crates/netfyr-backend/src/report.rs` — fully implemented

All required types exist with unit tests: `ApplyReport`, `AppliedOperation`, `FailedOperation`, `SkippedOperation`, `DryRunReport`, `PlannedChange`, `FieldChange`, `FieldChangeKind`, `DiffOpKind`.

`ApplyReport::is_success()` → `failed.is_empty()`; `is_partial()` → `!succeeded.is_empty() && !failed.is_empty()`; `is_total_failure()` → `succeeded.is_empty() && !failed.is_empty()`.

`DryRunReport` holds `changes: Vec<PlannedChange>` and `skipped: Vec<SkippedOperation>`. Skipped-because-not-found operations appear in `skipped`, consistent with the spec's "would fail with NotFound" acceptance criterion.

### `crates/netfyr-backend/src/trait_.rs` — fully implemented

`NetworkBackend` trait declares `async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError>` and `async fn dry_run(&self, diff: &StateDiff) -> Result<DryRunReport, BackendError>`.

### `crates/netfyr-backend/tests/netlink_apply.rs` — fully implemented

Rust integration tests using `NetnsGuard` + veth pairs cover every acceptance criterion scenario: MTU set and idempotent-skip, address add/remove/idempotent-add/idempotent-remove, route add/remove, read-only field skip, non-existent interface → `NotFound`, partial failure → `is_partial()`, remove without deleting physical interface, field application ordering, dry-run planned changes, dry-run on non-existent interface → `skipped`, non-ethernet ops filtered, `is_total_failure()`, apply-then-query round-trip.

### Shell integration tests — **absent**

`tests/` contains `helpers.sh`, `001-*.sh` (meta), `102-*.sh` (query), and `401-*.sh` (DHCP) scripts. There are **no `103-*.sh` files**. The spec's "Integration tests for ethernet apply" Gherkin scenarios require shell scripts exercising `netfyr apply` via the CLI with `ip` command assertions.

---

## Requirements

### Shell integration test scripts

Four shell scripts matching the Gherkin scenarios in the spec:

1. **`tests/103-apply-set-mtu.sh`**  
   Create veth pair in netns; write YAML policy setting `mtu: 1400` on veth-test0; run `$NETFYR_BIN apply`; assert `ip link show veth-test0` shows `mtu 1400`.

2. **`tests/103-apply-add-remove-address.sh`**  
   Create veth pair; apply policy with `addresses: ["10.99.0.1/24"]`; verify `ip addr show` contains `10.99.0.1/24`; apply policy without addresses field; verify address is gone.

3. **`tests/103-apply-add-route.sh`**  
   Create veth pair; bring veth-test0 up with address `10.99.0.1/24`; apply policy adding route `destination: 10.100.0.0/24, gateway: 10.99.0.2`; assert `ip route` shows the route.

4. **`tests/103-apply-query-roundtrip.sh`**  
   Apply policy with `mtu: 1400` and `addresses: ["10.99.0.1/24"]` on veth-test0; run `$NETFYR_BIN query --selector type=ethernet --selector name=veth-test0 --output json`; grep output for `mtu` of 1400 and `10.99.0.1/24`.

Each script must:
- Set `SCRIPT_DIR` and source `$SCRIPT_DIR/helpers.sh`
- Set `NETFYR_BIN` with fallback to `$SCRIPT_DIR/../target/debug/netfyr`
- Check `[[ ! -x "$NETFYR_BIN" ]]` and `exit 1` if binary missing (no `exit 0`)
- Call `netns_setup "$@"` to enter an unprivileged user+network namespace
- Use `create_veth` helper for veth pair setup
- Write a temporary YAML policy file
- Run `$NETFYR_BIN apply <policy-file>`
- Assert system state with `ip` commands; emit `FAIL: ...` on stderr and `exit 1` on failure
- Emit `PASS: <script-name>` on success

### No Rust changes needed

All Rust types, functions, and logic prescribed by the spec are implemented and covered by unit and Rust integration tests.

---

## Gap Analysis

| Artifact | Status | Action |
|---|---|---|
| `crates/netfyr-backend/src/netlink/apply.rs` | Complete | None |
| `crates/netfyr-backend/src/netlink/mod.rs` | Complete | None |
| `crates/netfyr-backend/src/report.rs` | Complete | None |
| `crates/netfyr-backend/src/trait_.rs` | Complete | None |
| `crates/netfyr-backend/tests/netlink_apply.rs` | Complete | None |
| `tests/103-apply-set-mtu.sh` | **Missing** | Create |
| `tests/103-apply-add-remove-address.sh` | **Missing** | Create |
| `tests/103-apply-add-route.sh` | **Missing** | Create |
| `tests/103-apply-query-roundtrip.sh` | **Missing** | Create |

---

## Integration Points

### `tests/helpers.sh`

All scripts must source `$SCRIPT_DIR/helpers.sh` and use:
- `netns_setup "$@"` — re-executes script inside `unshare --user --net --map-root-user`; also registers `cleanup` as EXIT trap
- `create_veth VETH0 VETH1` — `ip link add` + `ip link set up` for both ends
- `add_address IFACE CIDR` — `ip addr add`
- `assert_eq`, `assert_match`, `assert_has_address`, `assert_link_up` — shared assertion helpers

The established pattern from `102-query-veth-by-name.sh` must be followed exactly for binary detection and namespace entry.

### `netfyr apply` CLI (`crates/netfyr-cli/src/apply.rs`)

Scripts invoke `$NETFYR_BIN apply <policy-file>`. When no daemon socket is present at `/run/netfyr/netfyr.sock`, `VarlinkClient::connect` returns `VarlinkError::ConnectionFailed` and execution falls through to daemon-free mode: loads policies → `StaticFactory::produce` → `merge` → `query_all` → `compute_state_diff` → `registry.apply`. This exercises the full apply pipeline end-to-end.

### YAML policy format (`crates/netfyr-policy`)

The policy format is consumed by `parse_policy_yaml`. The exact schema is only visible in the policy crate's parser source (not in the public API signatures). The shell scripts must use the correct policy YAML structure. Known fields for ethernet: `mtu` (u64), `addresses` (list of CIDR strings), `routes` (list of maps with `destination` and `gateway`), `operstate` (string). The plan phase must verify the exact YAML schema against the policy parser before writing scripts.

### `netfyr query` CLI (`crates/netfyr-cli/src/query.rs`)

The round-trip script uses `$NETFYR_BIN query --selector type=ethernet --selector name=veth-test0 --output json`. The flags `--selector` and `--output json` are present in the `102-query-veth-by-name.sh` reference test. JSON output format includes `"mtu": 1400` and CIDR strings in an addresses list.

### `BackendRegistry` (`crates/netfyr-backend/src/registry.rs`)

`apply` on the registry iterates registered backends, calls `backend.apply(diff)`, and merges reports via `ApplyReport::merge`. `NetlinkBackend` is the only registered backend in daemon-free mode.

---

## Risks

### YAML policy schema not visible from API snapshots

The most significant risk for shell scripts is writing syntactically correct YAML that produces the expected `StateDiff` operations. If field names or nesting levels are wrong, `netfyr apply` may report "No changes needed" rather than an error, producing misleading test failures. The plan phase must read the policy crate's YAML parser source to confirm the exact schema.

### Route test requires link-up and a local address

`103-apply-add-route.sh` must bring veth-test0 up and assign a local address (`10.99.0.1/24`) before applying the route policy; otherwise the kernel may reject the route with `ENETUNREACH` because `10.99.0.2` is not reachable. The script must use `add_address` before calling `netfyr apply`.

### MTU upper bound in network namespaces

veth MTU is capped at 65535 by the kernel. The scripts use MTU=1400 (safely below the 1500 default). Scripts must not use jumbo-frame values (9000) as that is the default Jumbo Ethernet MTU and is not universally supported in all veth+namespace configurations.

### `ip route` output variability

`ip route` may include `proto static scope link` and `metric` annotations that vary across kernel versions and configurations. Scripts should match route entries with `grep -q "10.100.0.0/24 via 10.99.0.2"` rather than an exact-line match to remain portable.

### Daemon socket interference

If a stale `/run/netfyr/netfyr.sock` is present in the test environment, `netfyr apply` will attempt to connect to the daemon and may fail or route through unexpected code paths. The CLI falls back gracefully on `VarlinkError::ConnectionFailed`, but scripts should ensure the socket path is absent or set `NETFYR_SOCKET_PATH` to a non-existent path to force daemon-free mode.

### Address removal in round-trip test

The second scenario in `103-apply-add-remove-address.sh` applies a policy without the `addresses` field to trigger removal. The diff engine will generate a `Remove` or `Modify` op for the `addresses` field. This requires that the policy produces a state with no addresses, which depends on how `StaticFactory` handles absent fields. If `addresses` is simply omitted from the policy YAML, the field may not appear in the desired state at all, which could prevent the diff from generating a removal. The plan phase must verify this behavior.
