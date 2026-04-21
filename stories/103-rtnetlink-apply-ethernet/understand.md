# Understand: SPEC-103 — rtnetlink Apply for Ethernet Interfaces

## Current State

The implementation is **substantially complete**. All Rust logic and all four shell integration test scripts are present.

### `crates/netfyr-backend/src/netlink/apply.rs` — fully implemented

Both public entry points exist with full logic:

- `apply_ethernet(handle, diff)` — iterates `StateDiff` ops, filters to `entity_type == "ethernet"`, dispatches to `apply_add` / `apply_modify` / `apply_remove`. Never returns `Err`; per-operation errors land in `ApplyReport.failed` (continue-and-report mode).
- `dry_run_ethernet(handle, diff)` — same dispatch but queries current state to build `PlannedChange` entries; non-existent interfaces appear in `report.skipped`.

`apply_modify_fields` implements field changes in three phases:
1. **Link-level**: `mtu` (with idempotency skip when value equals current), `operstate` up/down.
2. **Addresses**: desired-vs-current delta. **Adds new addresses first, then removes old ones.** EEXIST → skip "already present"; not-found on delete → skip "not present".
3. **Routes**: same delta pattern; EEXIST → skip; not-found on delete → skip "not present".

Read-only fields (`carrier`, `speed`, `mac`, `driver`, `name`) produce `SkippedOperation` with reason `"read-only field"`.

Remove operations: delete all addresses, all routes (IPv4 + IPv6), then set link down via `LinkUnspec::new_with_index(index).down()`. Physical interfaces are not deleted from the kernel.

Error mapping: EPERM/EACCES → `BackendError::PermissionDenied`; ENODEV → `BackendError::NotFound`; others → `BackendError::ApplyFailed`.

Idempotency: MTU uses value comparison; address uses `is_eexist()`; route uses `is_eexist_backend()` (downcasts `ApplyFailed.source`); "not present" uses `is_not_found_error()` matching errnos 2, 3, 19, 99.

Unit tests cover all pure functions: `parse_cidr`, `extract_route_fields`, `build_planned_changes`, `READONLY_FIELDS`.

### `crates/netfyr-backend/src/netlink/mod.rs` — fully implemented

`NetlinkBackend::apply` and `NetlinkBackend::dry_run` open a fresh `Handle` via `establish_connection()` and delegate to `apply_ethernet` / `dry_run_ethernet`. Wired to the `NetworkBackend` trait via `async-trait`.

### `crates/netfyr-backend/src/report.rs` — fully implemented

All required types with unit tests: `ApplyReport` (`is_success`, `is_partial`, `is_total_failure`, `summary`, `merge`), `DryRunReport` (`changes`, `skipped`), `AppliedOperation`, `FailedOperation`, `SkippedOperation`, `PlannedChange`, `FieldChange`, `FieldChangeKind`, `DiffOpKind`.

### `crates/netfyr-backend/src/trait_.rs` — fully implemented

`NetworkBackend` trait declares `async fn apply` and `async fn dry_run`.

### Shell integration tests — present (unverified)

All four spec-required scripts exist in `tests/`:
- `tests/103-apply-set-mtu.sh` — veth MTU set to 1400; asserts `ip link show` shows `mtu 1400`.
- `tests/103-apply-add-remove-address.sh` — adds `10.99.0.1/24`, then re-applies policy without `addresses` field to trigger removal; verifies presence then absence.
- `tests/103-apply-add-route.sh` — pre-assigns `10.99.0.1/24` via `add_address`, then applies policy adding route `10.100.0.0/24 via 10.99.0.2`; asserts `ip route` contains the route.
- `tests/103-apply-query-roundtrip.sh` — applies mtu=1400 + address, queries via `netfyr query --output json`, greps for `"mtu": 1400` and `10.99.0.1/24`.

All scripts use `netns_setup`, `create_veth`, `add_address` from `tests/helpers.sh`. All check `$NETFYR_BIN` and `exit 1` (not `exit 0`) on failure. All export `NETFYR_SOCKET_PATH=/nonexistent` to force daemon-free mode.

---

## Requirements

From the acceptance criteria, the following behaviors must work end-to-end:

1. **Modify MTU** — resolve interface index, skip if already at desired value, otherwise `link().change(...mtu...)`.
2. **Add address** — for each new CIDR in desired state, call `address().add()`; skip on EEXIST.
3. **Remove address** — find `AddressMessage` for unwanted CIDR, call `address().del()`; skip if absent.
4. **Add route** — `RouteMessageBuilder` with destination prefix + gateway + OIF; skip on EEXIST.
5. **Remove route** — find `RouteMessage` by destination+gateway, call `route().del()`; skip if absent.
6. **operstate** — `link().change()` with `.up()` or `.down()`.
7. **Read-only field skipping** — carrier, speed, mac, driver → `SkippedOperation` with reason `"read-only field"`.
8. **Idempotency** — adding present address → skip; removing absent address → skip; mtu at desired value → skip.
9. **Not-found → FailedOperation** — interface lookup failure → `BackendError::NotFound`.
10. **Permission denied → FailedOperation** — EPERM/EACCES → `BackendError::PermissionDenied`.
11. **Continue-and-report** — each operation runs independently.
12. **Remove deconfigures, does not delete** — removes addresses + routes + sets link down; interface remains.
13. **Partial failure** — `is_partial()` true when ≥1 succeeded and ≥1 failed.
14. **Dry-run** — returns `DryRunReport` with `PlannedChange` entries; no kernel state modified; not-found → `skipped`.
15. **Field-application ordering** — link changes first, then addresses, then routes.
16. **Integration tests pass** — all four `103-*.sh` scripts exit 0 under `make integration-test SPEC=103`.

---

## Gap Analysis

### Gap 1: Address replacement ordering diverges from spec

**File**: `crates/netfyr-backend/src/netlink/apply.rs`, `apply_modify_fields`, Phase 2 (~lines 594–673).

The spec states:
> "When replacing the address set: remove old addresses first, then add new addresses in the order they appear in the desired state list. This ensures the kernel's address order matches the YAML order, and the first address in the list becomes the primary (source) address."

The current code does the **opposite** — it adds new addresses before removing old ones (comment: "to avoid transient loss of all addresses"). This violates the spec's guarantee that kernel address order matches YAML order. When an interface already has addresses and the policy replaces the full set, existing addresses remain present during the add phase, so the first YAML entry is not necessarily the primary.

The `103-apply-add-remove-address.sh` test does not catch this because it tests add-to-empty then remove-all (two separate applies), not in-place replacement with an interface that already has addresses.

**Required change**: Swap address phase order to remove-then-add (or drain existing addresses first), accepting the transient address loss that the current code attempts to avoid.

### Gap 2: DryRunReport has no typed failure collection for not-found

**File**: `crates/netfyr-backend/src/report.rs` and `apply.rs`, `dry_run_ethernet`.

The spec acceptance criterion says "the DryRunReport indicates the operation would fail with NotFound." `DryRunReport` only has `changes` and `skipped` — no `failed` field. The implementation places not-found into `skipped` with reason `"interface not found: {name}"`. The distinction between "skipped because already in desired state" and "skipped because interface does not exist" is only recoverable by string inspection. This may or may not be adequate; it is an ambiguity the DESIGN phase must resolve.

### Gap 3: Integration tests unverified

All four shell scripts are written and structurally correct, but they have not been executed. They depend on:
- `target/debug/netfyr` binary being compiled (`cargo build -p netfyr-cli`).
- `unshare --user --net` available (Linux, `kernel.unprivileged_userns_clone = 1`).
- `ip` command available.

Verification requires `make integration-test SPEC=103`. This is a verification gap, not a code gap.

### No gap: All other behaviors

- MTU set/skip implemented correctly.
- Address add/remove idempotency implemented.
- Route add/remove idempotency implemented.
- Read-only field skipping implemented.
- Remove deconfigures without deleting.
- `is_success`, `is_partial`, `is_total_failure` correct.
- ENODEV/EPERM error mapping implemented.
- Per-operation continue-and-report implemented.
- All three `DiffOp` variants handled.
- `fail_op` and `make_field_failure` helpers implemented.
- Unit tests cover pure functions.

---

## Integration Points

### `crates/netfyr-state`
- `StateDiff` / `DiffOp` — the input. `DiffOp::Modify` carries `changed_fields: IndexMap<String, FieldValue>` and `removed_fields: Vec<String>`.
- `Value` enum — field values may be `Value::IpNetwork` (from YAML policy) or `Value::String` (from kernel query). `value_to_str` in `apply.rs` handles both via a match on variants.
- `Selector.name` — used to identify the target interface.

### `crates/netfyr-backend/src/netlink/ethernet`
- `query_ethernet(handle, Some(&sel))` — called by `get_current_state` inside `apply_modify_fields` and `dry_run_ethernet` to read current field values before computing deltas.

### `crates/netfyr-backend/src/netlink/query`
- `establish_connection()` — called by `NetlinkBackend::apply` and `NetlinkBackend::dry_run` in `mod.rs` to obtain the `Handle`.

### `crates/netfyr-backend/src/registry`
- `BackendRegistry::apply` calls `NetworkBackend::apply` on registered backends and merges per-backend `ApplyReport` values via `ApplyReport::merge`.

### `crates/netfyr-daemon/src/reconciler`
- `Reconciler::reconcile_and_apply` and `Reconciler::dry_run` are the top-level callers of the apply path in daemon mode.

### `crates/netfyr-cli/src/apply`
- `run_apply` is the user-facing entry point. When no daemon socket is found, it enters daemon-free mode: loads policies → produces desired state → diffs against actual → calls `registry.apply`. Shell tests exercise this exact path.

### `tests/helpers.sh`
- `netns_setup "$@"` — re-executes the script inside `unshare --user --net --map-root-user`; registers `cleanup` as EXIT trap.
- `create_veth VETH0 VETH1` — creates and brings up a veth pair.
- `add_address IFACE CIDR` — assigns address to interface (used in route test to pre-configure the local subnet).

---

## Risks

### R1: Address ordering semantic correctness (Gap 1)
The spec-vs-code divergence on address replacement order means the primary address guarantee is violated when replacing all addresses on an interface that already has addresses. The existing shell tests do not exercise this case. A test that starts with an address and replaces it with a different address in the same apply would expose this bug.

### R2: Route matching for deletion
`find_route_message` matches on destination prefix and optional gateway by string comparison. Routes to the same destination with different metrics or preferences are indistinguishable. If multiple routes to the same prefix exist, the wrong one may be deleted. The spec does not model `metric`; this is an unspecified edge case.

### R3: `FailedOperation` collapse in Modify
`apply_modify` only reports the **first** failure from `apply_modify_fields` and discards subsequent ones. If mtu fails AND address fails in the same entity, only the first error appears in the report. This means per-field continue-and-report within a single entity is not fully implemented.

### R4: IPv6 addresses not guarded
The spec says "Only IPv4 addresses are supported" but `apply_modify_fields` accepts any CIDR parseable by `parse_cidr`, including IPv6. There is no explicit IPv4-only guard; the kernel determines whether IPv6 is accepted or rejected.

### R5: `value_to_str` silent gaps
`value_to_str` covers `Value::String`, `Value::IpNetwork`, `Value::IpAddr` and returns `None` for all other variants silently. A `Value::List` or incorrectly-typed address value would be silently ignored without an error, causing the address to be treated as absent.

### R6: Unprivileged namespace availability in CI
The shell tests require `unshare --user --net`. If the build environment has `kernel.unprivileged_userns_clone = 0` (common in some container runtimes), all four shell tests will fail with a system-level error. This is an environment risk, not a code risk.
