# Plan: SPEC-354 State Revert

## Approach

The revert feature adds a `netfyr revert <seq>` CLI command that restores system state to match a journal snapshot. The design mirrors the existing `apply` command's dual-mode architecture: daemon-free mode applies directly via a local `BackendRegistry`, while daemon mode delegates to a new `io.netfyr.Revert` Varlink method.

The core data flow is: read journal entry -> convert `SerializableStateSet` back to `StateSet` -> query current system state -> compute diff (target vs actual) -> apply diff -> record revert journal entry. This requires one new conversion method (`SerializableStateSet::to_state_set()`), one new `Reconciler` method for daemon-mode apply, and the standard CLI/Varlink/server wiring.

**Why this design over alternatives:**

1. **Reuse `netfyr_state::diff::diff` + `BackendRegistry::apply` directly** rather than going through reconciliation. The reconciliation pipeline (`merge` -> `generate_diff` -> apply) is designed for policy merging with conflict detection. Revert has no policies to merge and no conflicts — it's a direct "make system match this snapshot" operation. Using the raw state diff is simpler, avoids unnecessary reconciliation overhead, and matches the semantic intent (state manipulation, not policy reconciliation).

2. **Add a `Reconciler::revert()` method** rather than exposing `backend_registry` publicly. The Reconciler owns the backend registry, journal, schema registry, and the `is_applying` flag — all needed for revert. A dedicated method keeps the backend private, handles the `set_applying` guard correctly, and follows the existing pattern where server handlers call Reconciler methods rather than reaching into its internals.

3. **Compute two diffs** (reconcile diff for journal/display, state diff for apply) matching the pattern in `reconcile_and_apply`. The journal stores `SerializableDiff` which comes from `ReconcileStateDiff`, while `BackendRegistry::apply` takes `netfyr_state::StateDiff`. Both are needed.

4. **Return `VarlinkApplyReport` from the Varlink method** for both dry_run and apply. For dry_run, populate `VarlinkChangeEntry` items with `status: "planned"` and descriptive text. The CLI knows `args.dry_run` and formats output accordingly. This avoids defining a new response type while still conveying enough information.

## Design Decisions

### 1. SerializableStateSet::to_state_set() placement and implementation
- **Decision**: Add `to_state_set()` as a method on `SerializableStateSet` in `netfyr-journal/src/serializable.rs`. Use `serde_json::from_value::<Value>()` to deserialize each field value, leveraging `Value`'s existing `Deserialize` implementation.
- **Alternatives considered**: (a) Add a `json_to_value` function to `netfyr-state` crate and call it from journal. (b) Copy the `json_to_value` from `netfyr-varlink/src/types.rs`.
- **Rationale**: `Value` already derives `Serialize` and `Deserialize`. The `SerializableStateSet::from(&StateSet)` impl uses `serde_json::to_value(&fv.value)` to serialize fields, so the inverse is `serde_json::from_value::<Value>(json_val)`. This is a one-liner per field — no need to duplicate or factor out a helper function. `netfyr-journal` already depends on `serde_json`, so no new dependencies are needed.

### 2. Provenance for restored fields
- **Decision**: All fields in the restored `StateSet` use `Provenance::UserConfigured { policy_ref: "revert".into() }`.
- **Alternatives considered**: `Provenance::KernelDefault`, a new `Provenance::Revert` variant.
- **Rationale**: The spec explicitly mandates `UserConfigured { policy_ref: "revert" }`. This variant already exists in the `Provenance` enum. It accurately conveys that these values are being intentionally set by the operator, not discovered from the kernel.

### 3. Reconciler method for daemon-mode revert
- **Decision**: Add `pub async fn revert(&self, target_state: &StateSet, target_seq: SequenceId, policies: &[Policy], dry_run: bool) -> anyhow::Result<RevertResult>` to `Reconciler`. `RevertResult` contains both the reconcile diff (for display/journal) and an optional apply report (None if dry_run).
- **Alternatives considered**: (a) Expose `backend_registry` via a getter. (b) Add separate `revert_dry_run()` and `revert_apply()` methods.
- **Rationale**: A single method with a `dry_run` flag is simplest. The method shares the query+diff logic regardless of dry_run, only branching at the apply step. Exposing the backend would break the existing encapsulation pattern. Two methods would duplicate the query+diff logic.

### 4. Managed entities for diff computation
- **Decision**: The managed entity set for revert is `target_state.entities()` — exactly the entities present in the historical snapshot.
- **Alternatives considered**: Using all entities from both target and actual states.
- **Rationale**: Revert should only touch entities that were in the snapshot. Entities that exist on the system but aren't in the snapshot are left alone (we don't know what they should be). This matches `generate_diff`'s semantics: only entities in `managed_entities` can produce Remove operations. Entities in the target but missing from the system get Add operations. Entities in both get Modify operations if fields differ.

### 5. Varlink response format
- **Decision**: The `Revert` Varlink method returns `{ report: VarlinkApplyReport, entry_timestamp: String }`. For dry_run, the report has `succeeded=0, failed=0, skipped=0` and changes with `status: "planned"`. For apply, it's a normal report. The `entry_timestamp` is included so the CLI can print "Reverting to state from entry #N (timestamp UTC)" without a separate round-trip.
- **Alternatives considered**: (a) Return `VarlinkStateDiff` for dry_run (like the existing DryRun method). (b) Make the CLI fetch the entry separately via `GetJournalEntry`.
- **Rationale**: Returning a single response type simplifies the client. The `VarlinkChangeEntry` description field carries enough info for dry_run display (e.g., "mtu: 9000 -> 1500"). Including `entry_timestamp` avoids a second Varlink round-trip.

### 6. CLI daemon detection
- **Decision**: Follow the exact same pattern as `apply.rs`: try `VarlinkClient::connect()`, on `ConnectionFailed` fall through to daemon-free mode.
- **Rationale**: Consistency with existing code. The pattern is well-tested and handles edge cases (socket exists but daemon is down, etc.).

### 7. Exit codes
- **Decision**: Revert uses the same exit code semantics as apply: 0 = success or no-op, 1 = partial failure, 2 = total failure. "Entry not found" is an error that propagates via `anyhow` and results in exit code 2 (the default error handler in main.rs).
- **Rationale**: Matches spec and existing conventions. No special exit code handling is needed.

### 8. Shared helpers between apply.rs and revert.rs
- **Decision**: Make `create_backend_registry()` and `determine_exit_code()` `pub(crate)` in `apply.rs` so `revert.rs` can reuse them. Also make `display_apply_report` available (it's already `pub`). Move `daemon_socket_path()` from `apply.rs` to `lib.rs` (it's already declared there but the one in apply.rs shadows it — verify during implementation; if `lib.rs` already exports it, just use that).
- **Alternatives considered**: Duplicating the functions, or extracting to a shared module.
- **Rationale**: Making existing functions `pub(crate)` is the minimal change. These are small utility functions that don't warrant a separate module.

### 9. Policy drift warning
- **Decision**: Print the warning to stderr after any successful daemon-mode revert (not dry_run). In daemon-free mode, print the same warning since the user may start the daemon later.
- **Alternatives considered**: Only warn in daemon mode.
- **Rationale**: The spec only shows the warning in daemon mode, but in daemon-free mode the same drift risk exists if the daemon is started afterward. However, following the spec strictly: only warn when the daemon is running (daemon mode). In daemon-free mode, there's no daemon to re-apply, so the warning is misleading. Follow the spec.

### 10. Error handling for to_state_set()
- **Decision**: Return `Result<StateSet, String>` from `to_state_set()`. Errors can come from `serde_json::from_value` if a stored JSON value can't be deserialized back to `Value` (shouldn't happen in practice but defensive coding).
- **Rationale**: Using `String` error type keeps it simple — this is a conversion function, not a complex error hierarchy. The callers wrap it in `anyhow` anyway.

## File Changes

### 1. `crates/netfyr-journal/src/serializable.rs` — Modify

**What**: Add a `pub fn to_state_set(&self) -> Result<StateSet, String>` method on `SerializableStateSet`. The method iterates over `self.entities`, and for each `SerializableState`:
- Creates a `Selector::with_name(&entity.selector_name)`.
- Parses `entity.fields` (a `serde_json::Value::Object`) by iterating over its key-value pairs.
- For each field, calls `serde_json::from_value::<netfyr_state::Value>(json_val)` to deserialize the value.
- Wraps each value in `FieldValue { value, provenance: Provenance::UserConfigured { policy_ref: "revert".into() } }`.
- Constructs a `State` with `entity_type`, `selector`, `fields`, `metadata: StateMetadata::new()`, `policy_ref: Some("revert".into())`, `priority: 100`.
- Inserts into a `StateSet`.

Add the necessary imports: `netfyr_state::{FieldValue, Provenance, Selector, State, StateMetadata, StateSet, Value}`.

**Why**: This is the critical missing piece — converting a journal snapshot back to a live `StateSet` for diff computation. Without this, revert cannot determine what changes to apply.

### 2. `crates/netfyr-daemon/src/reconciler.rs` — Modify

**What**: Add a `RevertResult` struct and a `pub async fn revert()` method to `Reconciler`.

```
pub struct RevertResult {
    pub reconcile_diff: ReconcileStateDiff,
    pub report: Option<ApplyReport>,  // None if dry_run
}
```

The `revert` method signature:
```
pub async fn revert(
    &self,
    target_state: &StateSet,
    target_seq: SequenceId,
    policies: &[Policy],
    dry_run: bool,
) -> Result<RevertResult>
```

Method behavior:
1. Query actual system state via `self.backend_registry.query_all()`.
2. Compute `managed_entities: HashSet<EntityKey>` from `target_state.entities()`.
3. Compute `reconcile_diff` via `generate_diff(target_state, &actual_state, &managed_entities, &self.schema_registry)`.
4. Compute `managed_actual` as `intersection(&actual_state, target_state)`.
5. Compute `state_diff` via `netfyr_state::diff::diff(&managed_actual, target_state)`.
6. If `dry_run`: return `RevertResult { reconcile_diff, report: None }`.
7. If `state_diff.is_empty()`: append a journal entry with `ApplyOutcome::Applied { 0, 0, 0 }`, return `RevertResult { reconcile_diff, report: Some(ApplyReport::new()) }`.
8. Set `self.is_applying` to true (guard).
9. Call `self.backend_registry.apply(&state_diff)`.
10. Set `self.is_applying` to false.
11. Append journal entry with `Trigger::Revert { target_seq }`, the reconcile diff, target_state as state_after, and the outcome from the apply report.
12. Return `RevertResult { reconcile_diff, report: Some(apply_report) }`.

The journal append for revert uses `summarize_policies(policies)` for the `active_policies` field, consistent with other journal entries.

Add imports: `netfyr_journal::SequenceId`, `netfyr_policy::Policy`.

**Why**: The daemon handler needs to perform revert through the Reconciler to access the private backend registry, schema registry, journal, and is_applying flag.

### 3. `crates/netfyr-varlink/src/client.rs` — Modify

**What**: Add a `pub async fn revert(&mut self, target_seq: u64, dry_run: bool) -> Result<(VarlinkApplyReport, String), VarlinkError>` method to `VarlinkClient`. The method:
- Calls `self.call("io.netfyr.Revert", json!({ "target_seq": target_seq, "dry_run": dry_run }))`.
- Extracts `report` from the response parameters and deserializes to `VarlinkApplyReport`.
- Extracts `entry_timestamp` as a String.
- Returns `(report, entry_timestamp)`.

Handle errors: if the response contains an `"io.netfyr.EntryNotFound"` error, map it to a specific `VarlinkError` variant. Use the existing `VarlinkError::Internal` variant for this (with a descriptive message), or add a new `EntryNotFound(String)` variant — use the existing pattern where all errors from the daemon are mapped to `VarlinkError::Internal` or `VarlinkError::Backend` based on the error name.

**Why**: The CLI daemon-mode path needs a client method to send the revert request.

### 4. `crates/netfyr-daemon/src/server.rs` — Modify

**What**: Add a `handle_revert` async function and wire it into the method dispatch in `handle_connection`.

`handle_revert` signature:
```
async fn handle_revert(
    stream: &mut UnixStream,
    params: &serde_json::Value,
    policy_store: &PolicyStore,
    reconciler: &Reconciler,
) -> Result<()>
```

Behavior:
1. Parse `target_seq` (u64) and `dry_run` (bool) from params. Return error if missing.
2. Open journal via `Journal::open_default()`.
3. Read the target entry via `journal.read_entry(target_seq)`.
4. If entry is None, return `write_error(stream, "EntryNotFound", &format!("Entry #{} not found", target_seq))`.
5. Call `entry.state_after.to_state_set()`. On error, return Internal error.
6. Extract entry timestamp as ISO 8601 string for the response.
7. Call `reconciler.revert(&target_state, target_seq, policy_store.policies(), dry_run)`.
8. Convert result to `VarlinkApplyReport`:
   - If `result.report` is Some (apply mode): use `VarlinkApplyReport::from(report)` (the existing conversion, without conflicts since revert has none).
   - If `result.report` is None (dry_run mode): build a `VarlinkApplyReport` with `succeeded=0, failed=0, skipped=0` and populate `changes` from the reconcile diff operations with `status: "planned"`.
9. Return `write_success(stream, json!({ "report": varlink_report, "entry_timestamp": timestamp_str }))`.

Wire into dispatch: add `"io.netfyr.Revert" => handle_revert(stream, &params, policy_store, reconciler).await` to the `match method.as_str()` block in `handle_connection`.

Add imports: `netfyr_journal::Journal`, `netfyr_varlink::VarlinkApplyReport`, `netfyr_varlink::VarlinkChangeEntry`.

**Why**: The daemon must handle the Revert Varlink method to support daemon-mode revert.

### 5. `crates/netfyr-cli/src/revert.rs` — Create

**What**: New module implementing the revert CLI command. Contains:

- `pub struct RevertArgs` with `pub target: u64` and `#[arg(long)] pub dry_run: bool`.
- `pub async fn run_revert(args: RevertArgs) -> Result<ExitCode>` — main entry point.

`run_revert` flow:
1. Detect daemon mode: try `VarlinkClient::connect(&daemon_socket_path())`.
2. **Daemon mode** (connect succeeds):
   - Call `client.revert(args.target, args.dry_run)`.
   - On `VarlinkError::Internal` with "not found" in the message: print "Entry #N not found", return `ExitCode::from(1)`.
   - Print "Reverting to state from entry #N (timestamp UTC)" using the returned `entry_timestamp`.
   - If dry_run: format the report's changes as "Changes that would be applied:" (iterate changes, print each with `~`/`+`/`-` prefix based on `kind`, include `description`). If no changes, print "No changes needed."
   - If apply: display the report using `display_varlink_apply_report_simple()` (a local helper that prints per-change lines and summary, similar to `display_varlink_apply_report` but without policy count). Print policy drift warning to stderr.
   - Return exit code based on the report.
3. **Daemon-free mode** (connect fails with `ConnectionFailed`):
   - Open journal via `Journal::open_default()`.
   - Read target entry via `journal.read_entry(args.target)`. If None, bail with "Entry #N not found".
   - Print "Reverting to state from entry #N (timestamp UTC)".
   - Convert `entry.state_after.to_state_set()`.
   - Create backend registry via `create_backend_registry()` (from apply.rs, made pub(crate)).
   - Query current state via `registry.query_all()`.
   - Create `SchemaRegistry::default()`.
   - Compute managed entities from `target_state.entities()`.
   - Compute `reconcile_diff` via `generate_diff(&target_state, &actual_state, &managed_entities, &schema)`.
   - Compute `managed_actual` via `intersection(&actual_state, &target_state)`.
   - Compute `state_diff` via `compute_state_diff(&managed_actual, &target_state)`.
   - If dry_run:
     - If diff is empty: print "No changes needed. System is already in the target state.", return exit 0.
     - Else: display the diff using `DiffReport::new(reconcile_diff, &target_state, &actual_state)` and the existing `display_dry_run_report`-style formatting (or build a simpler inline display). Print "Changes that would be applied:" and iterate over reconcile diff operations showing field changes. Return exit 0.
   - If apply:
     - If state_diff is empty: print "No changes needed. System is already in the target state.", return exit 0.
     - Apply via `registry.apply(&state_diff)`.
     - Record journal entry with `Trigger::Revert { target_seq: args.target }`, empty `active_policies`, the reconcile diff, target_state as state_after, and the outcome from the apply report.
     - Display results using `display_apply_report(&report, &ConflictReport::new())`.
     - Return exit code via `determine_exit_code(&report, &ConflictReport::new())`.

Local helper functions:
- `fn display_revert_dry_run(diff: &ReconcileDiff)` — formats reconcile diff for dry_run display. Shows entity-level headers with `+`/`~`/`-` prefix and field-level changes (field: old -> new). Reuse formatting patterns from `display_varlink_diff` in apply.rs.
- `fn display_revert_report(report: &ApplyReport)` — thin wrapper calling `display_apply_report(report, &ConflictReport::new())`.
- `fn display_revert_varlink_report(report: &VarlinkApplyReport, dry_run: bool)` — for daemon mode display. If dry_run, shows planned changes from `report.changes`. If apply, shows applied changes.

**Why**: The CLI needs a new subcommand module. Follows the same structure as `apply.rs`.

### 6. `crates/netfyr-cli/src/apply.rs` — Modify

**What**: Change visibility of two functions from private to `pub(crate)`:
- `fn create_backend_registry() -> BackendRegistry` → `pub(crate) fn create_backend_registry()`
- `fn determine_exit_code(report: &ApplyReport, conflicts: &ConflictReport) -> ExitCode` → `pub(crate) fn determine_exit_code()`
- `fn daemon_socket_path() -> String` → verify whether `lib.rs` already exports this. If yes, use from lib.rs in revert.rs. If the one in apply.rs is the canonical version, make it `pub(crate)`.

**Why**: Revert needs the same backend registry construction and exit code logic. Sharing avoids duplication.

### 7. `crates/netfyr-cli/src/lib.rs` — Modify

**What**:
- Add `pub mod revert;` to the module declarations.
- Add `pub use revert::run_revert;` to the re-exports.
- Add `Revert(revert::RevertArgs)` variant to the `Commands` enum, with a doc comment: `/// Revert system state to match a journal snapshot`.

**Why**: Wires the new revert module into the CLI's command structure.

### 8. `crates/netfyr-cli/src/main.rs` (or `netfyr_cli_main.rs`) — Modify

**What**: Add a match arm for `Commands::Revert(args)` in the command dispatch:
```
Commands::Revert(args) => run_revert(args).await.unwrap_or_else(|e| {
    eprintln!("Error: {:#}", e);
    ExitCode::from(2u8)
}),
```

**Why**: Dispatches the revert subcommand to its handler.

## Dependencies

No new external crate dependencies are needed. All required functionality is available from existing dependencies:
- `serde_json` (already in `netfyr-journal`, `netfyr-cli`, `netfyr-daemon`)
- `chrono` (already in `netfyr-cli`, `netfyr-journal`)
- `anyhow` (already in `netfyr-cli`, `netfyr-daemon`)
- `clap` (already in `netfyr-cli`)
- `colored` (already in `netfyr-cli`)
- `netfyr-state`, `netfyr-journal`, `netfyr-reconcile`, `netfyr-backend`, `netfyr-varlink` (already in `netfyr-cli` and `netfyr-daemon`)

## Implementation Order

### Step 1: `SerializableStateSet::to_state_set()`
**File**: `crates/netfyr-journal/src/serializable.rs`

Add the `to_state_set()` method. This is the foundational building block — every other step depends on being able to convert a journal snapshot back to a `StateSet`.

The crate should compile after this step. Run `cargo check -p netfyr-journal` to verify.

### Step 2: `Reconciler::revert()` method
**File**: `crates/netfyr-daemon/src/reconciler.rs`

Add `RevertResult` struct and the `revert()` method. Depends on step 1 for `to_state_set()` (used by the caller, not directly by this method — the method receives an already-converted `StateSet`).

Run `cargo check -p netfyr-daemon` to verify.

### Step 3: `VarlinkClient::revert()` method
**File**: `crates/netfyr-varlink/src/client.rs`

Add the client-side revert method. Independent of steps 1-2 (client doesn't call `to_state_set` or `Reconciler`).

Run `cargo check -p netfyr-varlink` to verify.

### Step 4: `handle_revert()` in server.rs
**File**: `crates/netfyr-daemon/src/server.rs`

Add the handler and wire it into the dispatch. Depends on step 1 (`to_state_set` called here) and step 2 (`reconciler.revert()` called here).

Run `cargo check -p netfyr-daemon` to verify.

### Step 5: CLI revert module and wiring
**Files**: `crates/netfyr-cli/src/revert.rs` (create), `crates/netfyr-cli/src/apply.rs` (modify visibility), `crates/netfyr-cli/src/lib.rs` (modify), `crates/netfyr-cli/src/main.rs` (modify)

Create the revert module and wire it into the CLI. Depends on step 1 (daemon-free mode calls `to_state_set`) and step 3 (daemon mode calls `client.revert()`).

Run `cargo check -p netfyr-cli` to verify.

### Step 6: Full build verification
Run `cargo build` to verify the entire workspace compiles.

## Risks and Mitigations

### 1. Value deserialization round-trip fidelity
**Risk**: `serde_json::from_value::<Value>()` may deserialize an IP address string (e.g., "192.168.1.1") as `Value::String` rather than `Value::IpAddr`, since JSON has no native IP type. The serialization path (`serde_json::to_value`) might serialize `Value::IpAddr(addr)` as a plain string, and the deserialization may not know to parse it back as an IP.

**Mitigation**: Check how `Value`'s `Serialize`/`Deserialize` impls handle variant tagging. If `Value` uses serde's tagged enum representation (e.g., `#[serde(tag = "type")]`), then the JSON will include a discriminator and round-tripping will be exact. If it uses untagged representation, IP addresses may become strings. In the untagged case, add post-deserialization heuristics in `to_state_set()`: for any `Value::String(s)`, try parsing as `Ipv4Network` then `Ipv4Addr`, converting on success. This matches the YAML deserialization heuristics described in the spec.

**Implementation note**: Examine `Value`'s derive attributes. If `#[serde(untagged)]` is present, implement the heuristic. If tagged, the round-trip is safe as-is.

### 2. Reconciler journal locking under concurrent access
**Risk**: The daemon handler opens a fresh `Journal` for reading the target entry, while the `Reconciler::revert()` method writes via its internal `Mutex<Option<Journal>>`. If another reconciliation event fires concurrently (e.g., DHCP event), both try to write to the journal.

**Mitigation**: The daemon processes requests sequentially within `handle_connection` (one request at a time per connection), and the event loop processes one branch at a time in `tokio::select!`. There's no true concurrent access — the DHCP event handler and the Varlink handler never run simultaneously. The journal's file-level atomicity (write to temp file, rename) provides additional safety. No code change needed, but worth noting in review.

### 3. Empty snapshot revert
**Risk**: A journal entry with an empty `state_after` (no entities) would produce an empty target `StateSet`. The diff would have no managed entities, resulting in a "no changes needed" result even if the system has many entities.

**Mitigation**: This is correct behavior — if the historical snapshot was empty, reverting to it means "no managed entities, no changes." The only scenario where this is surprising is if the journal entry was corrupted. No mitigation needed beyond clear error messages.

### 4. Backend apply for Add operations in revert
**Risk**: Revert may produce `DiffOp::Add` operations (entity in target snapshot but not on current system). For ethernet interfaces, "adding" an interface that doesn't exist in the kernel is not a valid operation — you can only modify existing interfaces.

**Mitigation**: The `BackendRegistry::apply()` and `apply_ethernet()` already handle this case — they attempt the operation and report failure in `ApplyReport::failed` rather than panicking. The revert output will show the failure. This is acceptable: if an interface was removed between the snapshot and now, it genuinely can't be restored via netlink (it would need to be re-created at a higher level). The partial failure will be reflected in the exit code (1 or 2).

### 5. Schema filtering of read-only fields
**Risk**: `generate_diff()` uses the `SchemaRegistry` to exclude read-only fields (carrier, speed, mac, driver) from the diff. If the historical snapshot includes these fields, they should NOT be included in the diff because they can't be set via netlink.

**Mitigation**: `generate_diff` already handles this — it checks `schema.field_info(entity_type, field)` and skips read-only fields. As long as we pass a `SchemaRegistry::default()` (which has the ethernet schema registered), the filtering is automatic. The state diff (`netfyr_state::diff::diff`) does NOT filter read-only fields, but `BackendRegistry::apply` -> `apply_ethernet` only writes fields it knows how to set (mtu, addresses, etc.), so read-only fields in the state diff are harmlessly ignored.

### 6. `daemon_socket_path` function location
**Risk**: Both `apply.rs` and `lib.rs` define `daemon_socket_path()`. Using the wrong one could cause confusion.

**Mitigation**: During implementation, verify which is the canonical source. The `lib.rs` version is marked `pub(crate)` and is the one other modules should use. If `apply.rs` has its own copy, the revert module should use the `lib.rs` version. If they're the same function, this is a non-issue.

## Test Strategy

### Unit tests for `SerializableStateSet::to_state_set()`

**Location**: `crates/netfyr-journal/src/serializable.rs` (test module)

Tests needed:
- **Round-trip**: Create a `StateSet` with entities containing various value types (String, U64, Bool, IpAddr, IpNetwork, List, Map), convert to `SerializableStateSet`, then call `to_state_set()`. Assert the resulting `StateSet` has the same entities with equivalent field values.
- **Provenance**: Verify all fields in the result have `Provenance::UserConfigured { policy_ref: "revert" }`.
- **Multiple entities**: StateSet with 3+ entities of different types round-trips correctly.
- **Empty StateSet**: Empty `SerializableStateSet` produces empty `StateSet` without error.
- **Invalid JSON field**: A `SerializableState` with a field value that can't deserialize to `Value` returns an error (not a panic).

### Unit tests for `Reconciler::revert()`

**Location**: `crates/netfyr-daemon/src/reconciler.rs` (test module)

Tests needed:
- **Dry-run returns no report**: Call `revert(target, seq, &[], true)` with an empty target; verify `result.report` is `None`.
- **Apply returns report**: Call `revert(target, seq, &[], false)` with an empty target; verify `result.report` is `Some(ApplyReport)` and report is successful.
- **is_applying guard**: Verify `is_applying` is false before and after `revert()` completes (the guard cleans up).

### Unit tests for `handle_revert`

**Location**: `crates/netfyr-daemon/src/server.rs` (test module)

Tests needed:
- **Missing target_seq returns error**: Call with `{}` params, verify error response.
- **Entry not found returns EntryNotFound error**: Call with a seq that doesn't exist in journal.

### Unit tests for `VarlinkClient::revert()`

Client tests are integration tests by nature (need a server). The existing test patterns in `server.rs` (using `UnixStream::pair()`) provide the model.

### Unit tests for CLI revert module

**Location**: `crates/netfyr-cli/src/revert.rs` (test module)

Tests needed:
- **Display functions don't panic**: Smoke tests for the display helpers with various report shapes (empty, succeeded, failed, planned).

### Integration tests (end-to-end)

**Location**: Existing e2e test infrastructure

Tests matching the acceptance criteria scenarios:
- Revert to a previous state (MTU change undone)
- Revert dry-run previews changes without applying
- Revert when already at target state ("no changes needed")
- Revert to nonexistent entry (error message, exit code 1)
- Revert with address changes
- Revert records journal entry with correct trigger
- Revert journal entry metadata (trigger, diff, state_after, outcome)

These require the test namespace infrastructure (`NetnsGuard`, `DnsmasqGuard`) and should follow the patterns established by existing e2e tests.
