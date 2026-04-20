# SPEC-301: CLI Apply Command — Gap Analysis

## Current State

The `netfyr-cli` crate already contains a substantial implementation.

**`crates/netfyr-cli/src/apply.rs`** (~1033 lines):
- `ApplyArgs` with `paths: Vec<PathBuf>` and `dry_run: bool`
- `run_apply(args: ApplyArgs) -> Result<ExitCode>` — full daemon-detect → daemon-free/daemon dispatch
- `load_policies(&[PathBuf]) -> Result<PolicySet>` — file/dir loading with missing-path detection
- `policies_to_inputs` — converts static policies via `StaticFactory` to `PolicyInput`
- `create_backend_registry()` — registers `NetlinkBackend`
- `determine_exit_code` and `daemon_exit_code` — 0/1/2 exit code mapping
- Display functions: `display_apply_report`, `display_dry_run_report`, `display_varlink_apply_report`, `display_varlink_diff`, `print_conflicts`
- 30+ unit tests covering exit codes, `load_policies`, DHCP-without-daemon scenario

**`crates/netfyr-cli/src/lib.rs`**:
- `Cli` struct with `command: Option<Commands>` — `Option`, not required
- `Commands` enum with `Apply(ApplyArgs)` and `Query(QueryArgs)` variants
- Missing `#[command(subcommand_required = true, arg_required_else_help = true)]`

**`crates/netfyr-cli/src/main.rs`**:
- Parses `Cli`, dispatches on `cli.command`
- `None` arm prints `"netfyr"` and returns `ExitCode::from(0u8)` — exits 0 instead of 2

**`tests/`** — all 8 shell integration tests for SPEC-301 already exist:
- `301-apply-static-mtu.sh` — MTU apply in namespace (applies mtu=1400, verifies with `ip link`)
- `301-apply-with-address.sh` — MTU + address in namespace (verifies `ip addr`)
- `301-apply-dry-run.sh` — dry-run does not mutate kernel state
- `301-dhcp-policy-no-daemon.sh` — DHCP policy exits 2 with required message text
- `301-dry-run-no-changes.sh` — dry-run exits 0 when policy matches current state
- `301-no-args-error.sh` — `netfyr apply` with no paths exits 2
- `301-path-not-found.sh` — nonexistent path exits 2 with "path not found"
- `301-yaml-parse-error.sh` — invalid YAML exits 2

All shell tests follow SPEC-001 conventions: binary check, `NETFYR_SOCKET_PATH=/nonexistent` override, source `helpers.sh`, `netns_setup`, no `exit 0` on failure.

---

## Requirements

Concrete technical requirements from the acceptance criteria:

1. Socket detection via `NETFYR_SOCKET_PATH` env var, defaulting to `/run/netfyr/netfyr.sock`; `VarlinkError::ConnectionFailed` → daemon-free fallback.
2. Policy loading: `load_policy_file` / `load_policy_dir`; bare state YAML auto-wrapped (filename → policy name, priority 100, `FactoryType::Static`).
3. Daemon-free DHCP guard: any `factory_type != Static` → error containing `"requires the netfyr daemon"` and `"systemctl start netfyr"`, exit 2.
4. Reconciliation: `merge(Vec<PolicyInput>)` → `ReconciliationResult.effective_state` + `.conflicts`.
5. Dual diff: `generate_diff(desired, actual, managed_entities, schema)` for display; `compute_state_diff(actual, desired)` for `registry.apply()`.
6. Dry-run: display diff, never call `apply()`, exit 1 if changes pending, 0 if none.
7. Apply: `registry.apply(&state_diff)`, display `ApplyReport`, print conflict warnings.
8. Exit codes: 0 = success/no changes; 1 = partial failure or conflicts; 2 = total failure or fatal error (including YAML parse errors, DHCP without daemon).
9. **No subcommand**: `netfyr` with no args prints usage help and exits 2 (via clap `SubcommandRequiredElseHelp`).
10. **No path args**: `netfyr apply` with no paths triggers clap required-arg error, exits 2.
11. Daemon mode: submit `Vec<VarlinkPolicy>` via `client.submit_policies()` or `client.dry_run()`; display `VarlinkApplyReport`.

---

## Gap Analysis

### GAP 1 — `lib.rs`: Missing `subcommand_required = true, arg_required_else_help = true`; `command` is `Option<Commands>` (MUST FIX)

**File**: `crates/netfyr-cli/src/lib.rs`

Current:
```rust
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}
```

Required by spec:
```rust
#[command(subcommand_required = true, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
```

Without these attributes, clap does not print help and exit 2 when no subcommand is given. The AC "No subcommand shows usage help, exit code 2" fails.

### GAP 2 — `main.rs`: `None` arm exits 0 instead of 2 (MUST FIX)

**File**: `crates/netfyr-cli/src/main.rs`

Current `None =>` arm:
```rust
None => {
    println!("netfyr");
    ExitCode::from(0u8)
}
```

When GAP 1 is fixed (`command` becomes `Commands`, not `Option<Commands>`), this arm must be removed. Alternatively, if `Option<Commands>` is kept for xtask compatibility, this arm must call `Cli::command().print_help()` and return `ExitCode::from(2u8)`.

### GAP 3 — Potential compile error: `DiffReport::operations` direct field access

**File**: `crates/netfyr-cli/src/apply.rs:342`

`display_dry_run_report` accesses `report.operations.len()` directly. The public API snapshot for `netfyr-reconcile::DiffReport` lists only methods (`format_text`, `format_yaml`, `format_json`, `is_empty`) — no `operations` field. If this field is not `pub`, the code will not compile. The implementation phase must read `crates/netfyr-reconcile/src/report.rs` to verify field visibility and adjust accordingly (e.g., use `format_text()` line count or a new `len()` method).

### GAP 4 — Potential compile error: `ConflictReport::conflicts` field and `Conflict` struct field access

**File**: `crates/netfyr-cli/src/apply.rs:313–331`

`print_conflicts` iterates `conflicts.conflicts` and accesses `c.entity_key`, `c.field_name`, `c.priority`, `c.contributions`. The `ConflictReport` public API shows only `new`, `is_empty`, `len`, `by_entity`, `summary` — no public `conflicts` field. If these fields are private, compilation fails.

The same issue affects the unit test helper `conflict_report_with_one` at line 689, which constructs:
```rust
ConflictReport { conflicts: vec![Conflict { entity_key: ..., field_name: ..., priority: ..., contributions: vec![] }] }
```

### GAP 5 — Potential compile error: `ConflictContribution::value.value` access

**File**: `crates/netfyr-cli/src/apply.rs:318`

```rust
format!("policy \"{}\" sets {}", cc.policy_id, cc.value.value)
```

`ConflictContribution` is listed in the public API with no shown fields. If `FieldValue` wraps the actual value in a private inner field, this double-deref fails.

### GAP 6 — Missing shell integration test for "No subcommand shows usage help"

The AC scenario "No subcommand shows usage help, exit code 2" (running bare `netfyr`) has no corresponding `301-no-subcommand.sh` test. The existing `301-no-args-error.sh` tests `netfyr apply` with no paths — a different clap error path. A test for the bare `netfyr` invocation is absent.

### No gap in: Apply flow logic, daemon detection, policy loading, all display functions

The functional logic in `run_apply`, `run_apply_daemon`, `load_policies`, exit code mapping, and all display functions is present and matches the spec. All 8 required shell integration test scripts exist.

---

## Integration Points

| Component | Role | Interface |
|---|---|---|
| `netfyr-policy` | `load_policy_file`, `load_policy_dir`, `PolicySet`, `FactoryType`, `StaticFactory`, `StateFactory::produce` | Imported in `apply.rs` |
| `netfyr-reconcile` | `merge`, `PolicyInput`, `PolicyId`, `ConflictReport`, `generate_diff`, `DiffReport` | Imported in `apply.rs` |
| `netfyr-state` | `diff::diff` (aliased `compute_state_diff`), `SchemaRegistry`, `StateDiff` | Imported in `apply.rs` |
| `netfyr-backend` | `BackendRegistry`, `NetlinkBackend`, `ApplyReport`, `DiffOpKind` | Imported in `apply.rs` |
| `netfyr-varlink` | `VarlinkClient`, `VarlinkPolicy`, `VarlinkApplyReport`, `VarlinkStateDiff`, `VarlinkError` | Imported in `apply.rs` |
| `xtask` | Calls `Cli::command()` via `CommandFactory` for man-page generation | Depends on `netfyr-cli` lib |
| `tests/helpers.sh` | `netns_setup`, `create_veth`, `assert_has_address` | Sourced by all 301 shell tests |

The `NETFYR_SOCKET_PATH` env var is the critical seam between daemon and daemon-free mode; all integration tests override it to `/nonexistent`.

---

## Risks

1. **`DiffReport` field access** (GAP 3): If `operations` is not public on `DiffReport`, the fix requires either: (a) adding `pub fn len(&self) -> usize` to `DiffReport` in `netfyr-reconcile`, or (b) rewriting `display_dry_run_report` to derive the count from `format_text()`. This touches `netfyr-reconcile` which is outside the `netfyr-cli` crate boundary.

2. **`ConflictReport` / `Conflict` private fields** (GAP 4 & 5): If fields are private, both the display function and the unit test must be rewritten to use the public `by_entity()` method. This is a moderate refactor. The struct construction in the unit test will need to use `ConflictReport::new()` with a mock-friendly alternative or a test constructor.

3. **`subcommand_required` vs xtask compatibility** (GAP 1): `xtask` imports `Cli` to call `Cli::command()` for man-page generation. If `command: Option<Commands>` is changed to `command: Commands`, xtask code that calls `.command` directly may break. The implementation phase must check `xtask/src/main.rs` before modifying `Cli`.

4. **Unsafe `set_var` in async tests**: The test at line 854 uses `unsafe { std::env::set_var("NETFYR_SOCKET_PATH", ...) }`. In multi-threaded tokio runtimes, concurrent env mutation is unsound. Rust 1.81+ treats `set_var` in multithreaded contexts as unsafe. This may produce warnings or lint failures in CI.

5. **Bare-state auto-wrapping is a `netfyr-policy` concern**: The spec says bare state YAML (no `kind` field) is auto-wrapped using the filename as the policy name. This logic lives in `load_policy_file` in `netfyr-policy` (SPEC-008). The CLI's `load_policies` just delegates to that function. If SPEC-008 is not implemented in `netfyr-policy`, the shell tests `301-apply-static-mtu.sh` and `301-apply-with-address.sh` will fail even though the CLI code is correct.

6. **No `tests/301-no-subcommand.sh`**: The AC "No subcommand shows usage help" is only verifiable via a shell script that runs bare `netfyr` and checks exit 2. Without this test, `make integration-test SPEC=301` will not catch regressions in that scenario.
