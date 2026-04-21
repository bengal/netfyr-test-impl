# Gap Analysis: SPEC-351 Journal Infrastructure

## Current State

### What exists

The workspace contains seven crates: `netfyr-state`, `netfyr-reconcile`, `netfyr-backend`, `netfyr-policy`, `netfyr-varlink`, `netfyr-cli`, and `netfyr-daemon`. None of them include any journaling or audit-trail code.

**Relevant apply paths:**

- `crates/netfyr-cli/src/apply.rs:run_apply()` — the standalone apply path. After `registry.apply(&state_diff)` at line 173 it immediately calls `display_apply_report()` and returns an exit code. No journal write exists.
- `crates/netfyr-daemon/src/reconciler.rs:Reconciler::reconcile_and_apply()` — the daemon apply path. Signature is `pub async fn reconcile_and_apply(&self, policy_store: &PolicyStore, factory_manager: &FactoryManager) -> Result<ApplyResult>`. No `trigger` parameter, no journal field.
- `crates/netfyr-daemon/src/server.rs:serve_varlink()` — the main event loop. Calls `reconcile_and_apply()` in five distinct call sites: startup (`main.rs:93`), `handle_submit_policies` (line 144), DHCP `LeaseAcquired` (line 417), `LeaseRenewed` (line 427), and `LeaseExpired` (line 435).

**State and diff types:**

Two distinct `StateDiff` types coexist:
- `netfyr_state::StateDiff` (lean, apply-oriented): `DiffOp::Modify` carries `changed_fields: IndexMap<String, FieldValue>` (desired values only) and `removed_fields: Vec<String>` (names only, no old values).
- `netfyr_reconcile::StateDiff` (rich, display-oriented): `DiffOperation` carries `FieldChangeKind::Set { current: Option<FieldValue>, desired: FieldValue }` and `FieldChangeKind::Unset { current: FieldValue }`, preserving old values.

In `run_apply()` both diffs are already computed: `reconcile_diff: ReconcileDiff` (rich) and `state_diff: StateDiffState` (lean). The daemon's `reconcile_and_apply()` only computes the lean diff.

**Policy type:**
`netfyr_policy::Policy` has `name: String`, `factory_type: FactoryType`, `priority: u32`, `state: Option<State>`, `states: Option<Vec<State>>`, `selector: Option<Selector>`.

**Serialization infrastructure:**
`serde`, `serde_json`, `chrono` are already used in several crates. `flate2` is not present anywhere in the workspace.

**No existing `netfyr-journal` crate.** The workspace `Cargo.toml` lists no such member.

---

## Requirements

### New crate: `netfyr-journal`

1. **`entry.rs`** — define `JournalEntry`, `Trigger` (tagged enum with `serde(tag = "type", rename_all = "snake_case")`), `PolicySummary`, `ApplyOutcome`.
2. **`serializable.rs`** — define `SerializableDiff`, `SerializableDiffOp`, `SerializableFieldChange`, `SerializableStateSet`, `SerializableState` with full `serde` support. Implement `From<&netfyr_reconcile::StateDiff>` for `SerializableDiff` (rich diff, preserves old values) and `From<&StateSet>` for `SerializableStateSet`.
3. **`journal.rs`** — define `Journal` struct with `dir: PathBuf`, `current_path: PathBuf`, `seq: SequenceId`, `entry_count: usize`. Implement `open_default()`, `open(dir)`, `append()`, `read_recent(count)`, `read_entry(seq)`, `latest_state_for(entity_name)`, `rotate()`, `cleanup_archives(retention_days)`. NDJSON format, gzip compression for archives, `.seq` file for sequence persistence, env-var-driven thresholds.
4. **`lib.rs`** — re-export public API.

### Modified files

5. **`Cargo.toml` (workspace root)** — add `"crates/netfyr-journal"` to `members`.
6. **`crates/netfyr-journal/Cargo.toml`** — dependencies: `serde` (derive), `serde_json`, `chrono` (serde feature), `flate2`, `thiserror`, `netfyr-state`, `netfyr-reconcile`.
7. **`crates/netfyr-cli/src/apply.rs`** — in `run_apply()` after `registry.apply()` succeeds (daemon-free path only), open journal and append entry with `Trigger::PolicyApply`. Journal errors are warnings only.
8. **`crates/netfyr-daemon/src/reconciler.rs`** — add `journal` field to `Reconciler`; change `reconcile_and_apply` signature to accept `trigger: Trigger`; compute the rich `netfyr_reconcile::StateDiff` inside `reconcile_and_apply` (currently only the lean diff is computed); append journal entry after successful apply.
9. **`crates/netfyr-daemon/src/server.rs`** — pass `Trigger` variant to each `reconcile_and_apply` call site: `DaemonStartup` (main.rs), `PolicyApply { source: "daemon" }` (SubmitPolicies), `DhcpEvent { policy_name, event_kind }` for each DHCP event variant.
10. **`crates/netfyr-daemon/src/main.rs`** — pass `Trigger::DaemonStartup` to initial `reconcile_and_apply` call.

### Behavioral requirements

- Sequence numbers: 1-based, monotonically increasing across rotations, persisted in `.seq`.
- Rotation: triggered at entry count threshold (env `NETFYR_JOURNAL_MAX_ENTRIES`, default 10,000) or file size threshold (env `NETFYR_JOURNAL_MAX_SIZE`, default 50 MB). Archive naming: `archive/journal-{timestamp}.ndjson.gz`.
- Retention: archives older than `NETFYR_JOURNAL_RETENTION_DAYS` (default 90) deleted on `open()` and `cleanup_archives()`.
- Journal directory: `NETFYR_JOURNAL_DIR` env var, default `/var/lib/netfyr/journal/`.
- Write failure: non-fatal; logged at `warn` level.
- Standalone mode: fcntl advisory locking on `current.ndjson` for concurrent `netfyr apply` invocations.

---

## Gap Analysis

### Files to create

| File | Status |
|------|--------|
| `crates/netfyr-journal/Cargo.toml` | Does not exist |
| `crates/netfyr-journal/src/lib.rs` | Does not exist |
| `crates/netfyr-journal/src/entry.rs` | Does not exist |
| `crates/netfyr-journal/src/journal.rs` | Does not exist |
| `crates/netfyr-journal/src/serializable.rs` | Does not exist |

### Files to modify

| File | Change required |
|------|----------------|
| `Cargo.toml` | Add `"crates/netfyr-journal"` to `[workspace].members` |
| `crates/netfyr-cli/Cargo.toml` | Add `netfyr-journal` as a dependency |
| `crates/netfyr-daemon/Cargo.toml` | Add `netfyr-journal` as a dependency |
| `crates/netfyr-cli/src/apply.rs` | Add journal write block after `registry.apply()` in daemon-free path |
| `crates/netfyr-daemon/src/reconciler.rs` | Add `journal` field to `Reconciler`; add `trigger: Trigger` to `reconcile_and_apply`; compute rich diff; append entry |
| `crates/netfyr-daemon/src/server.rs` | Thread `Trigger` variants through all five `reconcile_and_apply` call sites |
| `crates/netfyr-daemon/src/main.rs` | Pass `Trigger::DaemonStartup` to startup reconciliation |

### Types to define (all new)

- `SequenceId = u64`
- `struct JournalEntry` (with all spec fields)
- `enum Trigger` (5 variants: PolicyApply, DhcpEvent, ExternalChange, DaemonStartup, Revert)
- `struct PolicySummary { name, factory_type, priority }`
- `enum ApplyOutcome` (Applied { succeeded, failed, skipped }, Observed)
- `struct SerializableDiff { operations: Vec<SerializableDiffOp> }`
- `struct SerializableDiffOp { kind, entity_type, entity_name, field_changes }`
- `struct SerializableFieldChange { field_name, change_kind, current, desired }`
- `struct SerializableStateSet { entities: Vec<SerializableState> }`
- `struct SerializableState { entity_type, selector_name, fields: serde_json::Value }`
- `struct Journal { dir, current_path, seq, entry_count }`
- `type Result<T> = std::result::Result<T, JournalError>` (or `anyhow`)

---

## Integration Points

### `crates/netfyr-cli/src/apply.rs`

Integration is straightforward in the daemon-free path. After line 173 (`registry.apply(&state_diff).await?`), both `reconcile_diff` (rich, `netfyr_reconcile::StateDiff`) and `reconciliation.effective_state` are already in scope. The journal entry can use `reconcile_diff` for `SerializableDiff::from(&reconcile_diff)` and `&reconciliation.effective_state` for the state snapshot.

The daemon-mode path (`run_apply_daemon`) cannot write to the journal because the `ApplyReport` returned from Varlink lacks per-field change details. The daemon writes its own entry; the CLI should not write a duplicate.

`summarize_policies()` helper is needed to convert `PolicySet` → `Vec<PolicySummary>`.

### `crates/netfyr-daemon/src/reconciler.rs`

`reconcile_and_apply()` currently takes `&self` and computes only the lean `netfyr_state::StateDiff`. Two changes are needed simultaneously:

1. Add `trigger: Trigger` parameter.
2. Compute the rich `netfyr_reconcile::StateDiff` alongside the lean one (or derive from it). The lean diff drives the backend apply; the rich diff populates the journal. The managed entities set is already computed in `build_policy_inputs()` context but not in `reconcile_and_apply()` — it will need to be derived from the policy inputs before `merge()` consumes them.

The `journal` field requires interior mutability because `serve_varlink()` passes `&reconciler` to `handle_connection()`, which in turn passes `reconciler: &Reconciler` to `handle_submit_policies()`. Changing to `&mut self` would require plumbing `&mut Reconciler` through the server's connection handler. Using `Mutex<Option<Journal>>` is cleaner without restructuring the server.

### `crates/netfyr-daemon/src/server.rs`

Five `reconcile_and_apply()` call sites:
- Line 93 (main.rs): `Trigger::DaemonStartup`
- Line 144 (handle_submit_policies): `Trigger::PolicyApply { source: "daemon".into() }`
- Line 417 (LeaseAcquired): `Trigger::DhcpEvent { policy_name: policy_name.clone(), event_kind: "lease_acquired".into() }`
- Line 427 (LeaseRenewed): `Trigger::DhcpEvent { ..., event_kind: "lease_renewed".into() }`
- Line 435 (LeaseExpired): `Trigger::DhcpEvent { ..., event_kind: "lease_expired".into() }`

`Trigger` must be imported in `server.rs` and `main.rs` from `netfyr_journal`.

---

## Risks

### 1. Which `StateDiff` for serialization

The spec's `SerializableDiff` has `field_changes` with `current` and `desired` values — a structure that maps to `netfyr_reconcile::FieldChangeKind`, not `netfyr_state::DiffOp`. The lean `DiffOp::Modify` only carries desired values (`changed_fields`) and removed field names, not old values.

The daemon's `reconcile_and_apply()` currently computes only the lean diff. Producing the rich diff inside `reconcile_and_apply()` requires calling `generate_diff()` with a `managed_entities` set, which means `build_policy_inputs()` must surface that information. This is extra work that `dry_run()` already does — the implementation must replicate that logic or refactor `build_policy_inputs` to also return the managed entities set.

Alternative: implement `From<&netfyr_state::StateDiff>` instead, accepting that `current` values will be `None` for all Modify operations. This loses audit fidelity but avoids the structural change.

### 2. Reconciler mutability and `journal` field

`serve_varlink()` holds `reconciler: Reconciler` and passes `&reconciler` to handlers. Changing `reconcile_and_apply` to `&mut self` would require `&mut reconciler` threading through `handle_connection` and `handle_submit_policies`, breaking their current signatures. A `Mutex<Option<Journal>>` inside `Reconciler` allows `&self` throughout. Alternatively, the journal could be passed separately to `reconcile_and_apply` as `Option<&mut Journal>`, avoiding any Reconciler struct change — but this shifts the ownership burden to every call site.

### 3. Daemon-mode apply in CLI does not write journal

When the CLI runs in daemon mode (`run_apply_daemon`), it submits policies via Varlink and receives only a summarized `VarlinkApplyReport`. It has no access to the diff or state snapshot needed for a journal entry. The daemon must write the entry. The CLI should not attempt to write in daemon mode. The spec's standalone scenario covers this correctly, but tests must confirm the daemon path does not produce duplicate or missing entries.

### 4. `flate2` dependency not in workspace

`flate2` is the only external dependency not currently in the workspace. It must be added to `crates/netfyr-journal/Cargo.toml`. No workspace-level `[workspace.dependencies]` table exists, so this is a direct crate-level dependency addition.

### 5. fcntl advisory locking on Linux

The spec calls for `fcntl` advisory file locking for concurrent CLI invocations. The `libc` crate is already in `netfyr-backend`. The journal crate will either re-use `libc` or add it. Advisory locking (`F_SETLKW`) is Linux-only and the crate is already Linux-targeted (no cross-platform concern).

### 6. Sequence number file TOCTOU under rotation

Rotation reads `.seq`, renames the active file, writes the archive, and starts fresh. If the process crashes between these steps, the `.seq` file and the new `current.ndjson` may be out of sync. The implementation should write `.seq` atomically (write to `.seq.tmp`, rename) and handle the case where `.seq` contains a number higher than the entry count of `current.ndjson` (the safe direction — gaps in sequence are acceptable, duplicates are not).

### 7. `read_recent` spanning rotated archives

The spec's `read_recent(count)` must return the most recent N entries in reverse order. If `current.ndjson` has fewer than N entries, the implementation must decompress and read archived files in reverse rotation order. The spec does not detail this behavior explicitly, but it is implied by the "most recent first" requirement.

### 8. Daemon startup sequence ordering

In `main.rs`, `reconciler.reconcile_and_apply()` is called at line 92 before `serve_varlink()` constructs the journal (if journal initialization is deferred to `serve_varlink`). The journal must be opened before or during `Reconciler::new()`, or the startup `reconcile_and_apply` call must receive the journal handle separately. The spec's `Trigger::DaemonStartup` entry will be missing if the journal is not yet open at startup.
