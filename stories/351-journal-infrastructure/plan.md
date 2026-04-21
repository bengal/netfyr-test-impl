# Implementation Plan: SPEC-351 Journal Infrastructure

## Approach

The journal crate (`netfyr-journal`) is a pure infrastructure layer: it defines entry types, converts domain types to a serializable form, and handles NDJSON file I/O with rotation and archival. The crate depends on `netfyr-state` and `netfyr-reconcile` (for the `From` conversions) but nothing depends on it except the two integration points (`netfyr-cli` and `netfyr-daemon`).

The design separates concerns across three modules: `entry.rs` (data model), `serializable.rs` (domain→JSON bridge), and `journal.rs` (file I/O). This keeps the data model testable in isolation from file system operations and lets the serializable conversions be tested without standing up a journal directory.

An alternative would be to put all types in a single module. That was rejected because the journal file I/O logic (rotation, locking, archive compression) is substantial enough to warrant its own module with its own error type. Another alternative — making journal writes async — was rejected because NDJSON appends are small sequential writes that complete in microseconds; adding tokio fs overhead and an async boundary would complicate the API for no real benefit. The `Journal` struct is synchronous; callers in async contexts call it directly (it's fast enough to not block the runtime).

For the daemon integration, the key design choice is how to thread the `Journal` into the `Reconciler`. The `Reconciler` is currently passed by `&self` (immutable reference) through the server's connection handler chain. Rather than restructuring the server to pass `&mut self`, the `Journal` is wrapped in `std::sync::Mutex<Option<Journal>>` inside `Reconciler`, allowing mutation through a shared reference. The `Option` handles the case where the journal fails to open (degraded mode). This is safe because the daemon's `tokio::select!` loop processes events sequentially — there is no concurrent access to the reconciler.

For the rich diff in the daemon path: `reconcile_and_apply()` currently computes only the lean `netfyr_state::StateDiff`. The journal needs the rich `netfyr_reconcile::StateDiff` with old values. Rather than restructuring `build_policy_inputs` or adding a new method, `reconcile_and_apply` will compute managed_entities before `merge()` consumes the inputs, then call `generate_diff()` (same as `dry_run()` already does) to produce the rich diff alongside the lean diff. The lean diff still drives `registry.apply()`.

## Design Decisions

1. **Decision**: Use `netfyr_reconcile::StateDiff` (rich diff) for journal serialization, not `netfyr_state::StateDiff` (lean diff).
   - **Alternatives considered**: The lean diff lacks `current` (old) values for Modify operations, which would make the journal useless for answering "what was the value before this change?". We could store both diffs, but that's redundant.
   - **Rationale**: The spec's `SerializableFieldChange` has `current` and `desired` fields, which maps directly to `FieldChangeKind::Set { current, desired }` from the reconcile diff. This is the whole point of the audit trail.

2. **Decision**: Synchronous `Journal` API (no async).
   - **Alternatives considered**: `tokio::fs` async file operations.
   - **Rationale**: Journal writes are append-only to a single file, typically < 10KB per entry. The write latency is sub-millisecond. Making it async would require `&mut self` to be held across an `.await` boundary, complicating the borrow model. The daemon's event loop is already sequential, so blocking briefly is fine.

3. **Decision**: `Mutex<Option<Journal>>` inside `Reconciler` for the daemon.
   - **Alternatives considered**: (a) Change `reconcile_and_apply` to `&mut self` — would require `&mut Reconciler` plumbing through `handle_connection` and `handle_submit_policies`, breaking their signatures. (b) Pass `Option<&mut Journal>` as a parameter — shifts ownership burden to every call site and requires threading through `handle_connection`. (c) Make `Journal` a separate field in `serve_varlink` and pass it directly — cleaner but changes more call sites.
   - **Rationale**: `Mutex<Option<Journal>>` is the least invasive change. The mutex is never contended (sequential event loop). The `Option` handles journal-open failure gracefully.

4. **Decision**: Use `serde_json::to_value(&fv.value)` for serializing `Value` → `serde_json::Value` in `SerializableState` and `SerializableFieldChange`.
   - **Alternatives considered**: Custom conversion function, or re-using `netfyr_varlink::value_to_json`.
   - **Rationale**: `netfyr_state::Value` already derives `Serialize`, so `serde_json::to_value()` works directly. Adding a dependency on `netfyr-varlink` just for `value_to_json` would create a circular dependency concern and couple the journal to the IPC layer. The one-liner `serde_json::to_value(v).unwrap_or(serde_json::Value::Null)` is trivial to replicate.

5. **Decision**: `fcntl` advisory locking via the `libc` crate for standalone mode concurrency.
   - **Alternatives considered**: `fs2` crate (provides cross-platform file locking), `flock` system call.
   - **Rationale**: The project is Linux-only (already depends on `libc` in `netfyr-backend`). `fcntl(F_SETLKW)` is the standard Linux advisory lock. Adding `libc` to the journal crate is acceptable since it's already in the workspace. No need for a cross-platform abstraction.

6. **Decision**: Compute `managed_entities` and rich diff inside `reconcile_and_apply()` by extracting from inputs before `merge()` consumes them, then calling `generate_diff()`.
   - **Alternatives considered**: (a) Refactor `build_policy_inputs` to return managed_entities — would change the method signature. (b) Re-derive managed_entities from the merged result — not possible because merge consumes inputs and the effective_state doesn't distinguish managed vs unmanaged.
   - **Rationale**: This mirrors the pattern already used in `dry_run()` and `run_apply()`. Computing managed_entities before merge is a well-established pattern in this codebase.

7. **Decision**: Journal directory defaults to `/var/lib/netfyr/journal/` with `NETFYR_JOURNAL_DIR` override.
   - **Alternatives considered**: XDG base directory, `/var/log/netfyr/`.
   - **Rationale**: The spec explicitly mandates this. `/var/lib/` is consistent with the existing `NETFYR_POLICY_DIR` default (`/var/lib/netfyr/policies`).

8. **Decision**: `thiserror` for `JournalError` rather than `anyhow`.
   - **Alternatives considered**: `anyhow::Error` (used in the daemon and CLI).
   - **Rationale**: `netfyr-journal` is a library crate. Library crates should define their own error types for downstream matching. `thiserror` is already used in `netfyr-state` and `netfyr-backend`.

9. **Decision**: The `.seq` file stores just the last-assigned sequence number as a decimal text string.
   - **Alternatives considered**: JSON metadata file, embedded in NDJSON header.
   - **Rationale**: Simplest possible format. Easy to inspect and recover from. Atomic update via write-to-temp-then-rename.

10. **Decision**: `Trigger` type is defined in `netfyr-journal`, not in a shared crate.
    - **Alternatives considered**: Define in `netfyr-state` or a new shared types crate.
    - **Rationale**: `Trigger` is journal-specific. The daemon imports `netfyr-journal` for the journal anyway, so importing `Trigger` from there is natural. The CLI also imports `netfyr-journal`. No circular dependency.

11. **Decision**: `read_recent()` reads only from `current.ndjson` in this spec, not from archives.
    - **Alternatives considered**: Spanning archives for complete history.
    - **Rationale**: SPEC-352 (history inspection) will need archive reading. This spec is about infrastructure — the read methods are provided for testing and basic inspection. `read_recent` will read from `current.ndjson` only. A TODO comment can note that archive spanning will be added in SPEC-352. `read_entry()` similarly searches only `current.ndjson` for now.

12. **Decision**: `summarize_policies()` is a free function in `netfyr-journal` (not a method on PolicySet).
    - **Alternatives considered**: Method on PolicySet, or trait impl.
    - **Rationale**: Adding a method to PolicySet would require `netfyr-policy` to depend on `netfyr-journal` (circular). A free function `fn summarize_policies(policies: &[Policy]) -> Vec<PolicySummary>` in the journal crate takes a slice of policies and is usable from both CLI and daemon.

## File Changes

### New Files

#### `crates/netfyr-journal/Cargo.toml`
- **Action**: Create
- **What**: Standard Cargo.toml for the `netfyr-journal` crate. Dependencies: `netfyr-state` (path), `netfyr-reconcile` (path), `netfyr-policy` (path, for `Policy` type in `summarize_policies`), `serde` (derive), `serde_json`, `chrono` (serde feature), `flate2`, `thiserror`, `libc`, `tracing`.
- **Why**: New crate for journal infrastructure.

#### `crates/netfyr-journal/src/lib.rs`
- **Action**: Create
- **What**: Module declarations (`mod entry`, `mod journal`, `mod serializable`) and public re-exports. Re-export: `JournalEntry`, `Trigger`, `PolicySummary`, `ApplyOutcome`, `SequenceId` from `entry`; `SerializableDiff`, `SerializableDiffOp`, `SerializableFieldChange`, `SerializableStateSet`, `SerializableState` from `serializable`; `Journal`, `JournalError` from `journal`; `summarize_policies` free function.
- **Why**: Standard Rust crate entry point with clean public API.

#### `crates/netfyr-journal/src/entry.rs`
- **Action**: Create
- **What**: 
  - `pub type SequenceId = u64;`
  - `pub struct JournalEntry { seq: SequenceId, timestamp: DateTime<Utc>, trigger: Trigger, active_policies: Vec<PolicySummary>, diff: SerializableDiff, state_after: SerializableStateSet, outcome: ApplyOutcome }` — all fields public, derives `Debug, Clone, Serialize, Deserialize`.
  - `pub enum Trigger` — five variants (`PolicyApply { source: String }`, `DhcpEvent { policy_name: String, event_kind: String }`, `ExternalChange { changed_entities: Vec<String> }`, `DaemonStartup`, `Revert { target_seq: SequenceId }`) with `#[serde(tag = "type", rename_all = "snake_case")]`.
  - `pub struct PolicySummary { name: String, factory_type: String, priority: u32 }` — derives `Debug, Clone, Serialize, Deserialize`.
  - `pub enum ApplyOutcome` — two variants (`Applied { succeeded: u32, failed: u32, skipped: u32 }`, `Observed`) with `#[serde(tag = "kind", rename_all = "snake_case")]`.
  - `pub fn summarize_policies(policies: &[netfyr_policy::Policy]) -> Vec<PolicySummary>` — maps each policy to a `PolicySummary` using `format!("{:?}", policy.factory_type).to_lowercase()` for the factory_type string.
- **Why**: Core data model for journal entries. Separated from I/O so it can be tested independently.

#### `crates/netfyr-journal/src/serializable.rs`
- **Action**: Create
- **What**:
  - `pub struct SerializableDiff { pub operations: Vec<SerializableDiffOp> }` — derives `Debug, Clone, Serialize, Deserialize`.
  - `pub struct SerializableDiffOp { pub kind: String, pub entity_type: String, pub entity_name: String, pub field_changes: Vec<SerializableFieldChange> }` — derives same.
  - `pub struct SerializableFieldChange { pub field_name: String, pub change_kind: String, pub current: Option<serde_json::Value>, pub desired: Option<serde_json::Value> }` — derives same.
  - `pub struct SerializableStateSet { pub entities: Vec<SerializableState> }` — derives same.
  - `pub struct SerializableState { pub entity_type: String, pub selector_name: String, pub fields: serde_json::Value }` — derives same.
  - `impl From<&netfyr_reconcile::StateDiff> for SerializableDiff` — iterates `operations`, maps `DiffKind` to `"add"/"modify"/"remove"` string, maps each `FieldChange` to `SerializableFieldChange`. For `FieldChangeKind::Set { current, desired }`: `change_kind = "set"`, `current` = `current.as_ref().map(|fv| serde_json::to_value(&fv.value).unwrap_or_default())`, `desired` = `Some(serde_json::to_value(&desired.value).unwrap_or_default())`. For `FieldChangeKind::Unset { current }`: `change_kind = "unset"`, `current` = `Some(...)`, `desired` = `None`. For `FieldChangeKind::Unchanged { value }`: `change_kind = "unchanged"`, `current` = `Some(...)`, `desired` = `None`. The `entity_name` is extracted via `op.selector.key()`.
  - `impl From<&netfyr_state::StateSet> for SerializableStateSet` — iterates the `StateSet`, for each `State`: `entity_type` from `state.entity_type`, `selector_name` from `state.selector.key()`, `fields` from `serde_json::Value::Object(state.fields.iter().map(|(k, fv)| (k.clone(), serde_json::to_value(&fv.value).unwrap_or_default())).collect())`.
- **Why**: Decouples on-disk JSON format from internal type evolution. Field values stored as `serde_json::Value` so the journal format is forward-compatible even if `netfyr_state::Value` adds new variants.

#### `crates/netfyr-journal/src/journal.rs`
- **Action**: Create
- **What**:
  - `pub enum JournalError` — variants: `Io(std::io::Error)`, `Json(serde_json::Error)`, `InvalidSequence(String)`. Derives `Debug` and uses `thiserror::Error`.
  - `pub type Result<T> = std::result::Result<T, JournalError>;`
  - `pub struct Journal { dir: PathBuf, current_path: PathBuf, archive_dir: PathBuf, seq: SequenceId, entry_count: usize, max_entries: usize, max_size: u64, retention_days: u64 }`
  - `impl Journal`:
    - `pub fn open_default() -> Result<Self>` — reads `NETFYR_JOURNAL_DIR` env var, defaults to `/var/lib/netfyr/journal/`, calls `Self::open()`.
    - `pub fn open(dir: &Path) -> Result<Self>` — creates `dir` and `dir/archive/` if they don't exist. Reads `.seq` file to get last sequence number (0 if missing). Counts lines in `current.ndjson` to set `entry_count`. Reads env vars `NETFYR_JOURNAL_MAX_ENTRIES` (default 10000), `NETFYR_JOURNAL_MAX_SIZE` (default 50*1024*1024), `NETFYR_JOURNAL_RETENTION_DAYS` (default 90). Calls `cleanup_archives()` on open.
    - `pub fn append(&mut self, mut entry: JournalEntry) -> Result<()>` — acquires fcntl write lock on `current.ndjson`, increments `self.seq`, sets `entry.seq = self.seq`, serializes to JSON, appends line to `current.ndjson`, writes updated seq to `.seq` atomically (write `.seq.tmp`, rename to `.seq`), increments `entry_count`, releases lock. Then checks rotation thresholds: if `entry_count >= max_entries` or file size >= `max_size`, calls `rotate()`.
    - `pub fn read_recent(&self, count: usize) -> Result<Vec<JournalEntry>>` — reads all lines from `current.ndjson`, parses each as `JournalEntry`, collects into a Vec, reverses, truncates to `count`. Returns in reverse chronological order (most recent first).
    - `pub fn read_entry(&self, seq: SequenceId) -> Result<Option<JournalEntry>>` — reads all lines from `current.ndjson`, parses each, returns the one with matching `seq`, or `None`.
    - `pub fn latest_state_for(&self, entity_name: &str) -> Result<Option<SerializableState>>` — reads entries in reverse, searches `state_after.entities` for one with matching `selector_name`, returns first match.
    - `fn rotate(&mut self) -> Result<()>` — generates archive filename `archive/journal-{UTC timestamp as %Y%m%dT%H%M%SZ}.ndjson.gz`, reads `current.ndjson`, compresses with `flate2::write::GzEncoder` (default compression), writes to archive file, truncates/recreates `current.ndjson`, resets `entry_count` to 0. Sequence number is NOT reset.
    - `pub fn cleanup_archives(&self, retention_days: u64) -> Result<()>` — lists files in `archive/`, parses timestamps from filenames, removes files older than `retention_days` from now.
    - Private helper: `fn lock_file(&self, file: &std::fs::File) -> Result<()>` — uses `libc::fcntl` with `F_SETLKW` and `F_WRLCK` on the file descriptor. 
    - Private helper: `fn unlock_file(&self, file: &std::fs::File) -> Result<()>` — uses `libc::fcntl` with `F_SETLK` and `F_UNLCK`.
    - Private helper: `fn write_seq_atomic(&self, seq: SequenceId) -> Result<()>` — writes to `.seq.tmp`, then renames to `.seq`.
    - Private helper: `fn read_seq(dir: &Path) -> Result<SequenceId>` — reads `.seq`, parses as u64, returns 0 if file missing.
    - Private helper: `fn count_lines(path: &Path) -> Result<usize>` — counts newlines in file, returns 0 if file missing.
- **Why**: Core I/O engine. NDJSON is human-readable, greppable, and trivially appendable. Rotation prevents unbounded growth. Gzip compression for archives is the spec requirement. fcntl locking prevents corruption from concurrent standalone applies.

### Modified Files

#### `Cargo.toml` (workspace root)
- **Action**: Modify
- **What**: Add `"crates/netfyr-journal"` to the `[workspace].members` array.
- **Why**: Register the new crate in the workspace.

#### `crates/netfyr-cli/Cargo.toml`
- **Action**: Modify
- **What**: Add `netfyr-journal = { path = "../netfyr-journal" }` and `tracing = "0.1"` and `chrono = { version = "0.4", features = ["serde"] }` to `[dependencies]`.
- **Why**: The CLI needs to create and append journal entries after standalone apply. `tracing` is needed for `tracing::warn!` on journal write failure. `chrono` is needed for `Utc::now()`.

#### `crates/netfyr-daemon/Cargo.toml`
- **Action**: Modify
- **What**: Add `netfyr-journal = { path = "../netfyr-journal" }` to `[dependencies]`.
- **Why**: The daemon needs the `Journal`, `JournalEntry`, `Trigger`, and conversion types.

#### `crates/netfyr-cli/src/apply.rs`
- **Action**: Modify
- **What**: After `registry.apply(&state_diff).await?` succeeds (line 173) and before `display_apply_report()` (line 176), insert a block that:
  1. Calls `Journal::open_default()`.
  2. On success, constructs a `JournalEntry` with: `seq: 0` (assigned by append), `timestamp: Utc::now()`, `trigger: Trigger::PolicyApply { source: <display string of paths> }`, `active_policies: summarize_policies(...)` by collecting policies from `policy_set`, `diff: SerializableDiff::from(&reconcile_diff)`, `state_after: SerializableStateSet::from(&effective_state)` (note: `effective_state` is `&reconciliation.effective_state` already in scope at line 122), `outcome: ApplyOutcome::Applied { succeeded: apply_report.succeeded.len() as u32, failed: apply_report.failed.len() as u32, skipped: apply_report.skipped.len() as u32 }`.
  3. Calls `journal.append(entry)`.
  4. On any error (open or append), logs `tracing::warn!("...")` and continues.
  - The `source` string for `Trigger::PolicyApply` should be a comma-separated list of the input path strings from `args.paths`.
  - Add the necessary `use` imports at the top: `chrono::Utc`, `netfyr_journal::{Journal, JournalEntry, Trigger, ApplyOutcome, SerializableDiff, SerializableStateSet, summarize_policies}`, `tracing`.
  - The `summarize_policies` function takes `&[Policy]`, so collect from `policy_set.iter()` into a temporary slice/vec.
- **Why**: Standalone apply must record a journal entry. Journal failure is non-fatal (the apply already succeeded).

#### `crates/netfyr-daemon/src/reconciler.rs`
- **Action**: Modify
- **What**:
  1. Add `use std::sync::Mutex;` and imports for `netfyr_journal::{Journal, JournalEntry, Trigger, ApplyOutcome, SerializableDiff, SerializableStateSet, summarize_policies}` and `chrono::Utc` and `std::collections::HashSet`.
  2. Add field to `Reconciler` struct: `journal: Mutex<Option<Journal>>`.
  3. In `Reconciler::new()`: attempt `Journal::open_default()`. On success, store `Mutex::new(Some(journal))`. On failure, log warning and store `Mutex::new(None)`.
  4. Change signature of `reconcile_and_apply` to: `pub async fn reconcile_and_apply(&self, policy_store: &PolicyStore, factory_manager: &FactoryManager, trigger: Trigger) -> Result<ApplyResult>`.
  5. Inside `reconcile_and_apply`, before `merge(inputs)`:
     - Compute `managed_entities: HashSet<EntityKey>` from `inputs.iter().flat_map(|i| i.state_set.entities()).collect()` (same pattern as `dry_run()` and `run_apply()`).
  6. After `merge(inputs)` and `query_all()`, compute the rich diff:
     - `let reconcile_diff = generate_diff(&effective_state, &actual_state, &managed_entities, &self.schema_registry);`
  7. After `registry.apply(&state_diff)` succeeds, append journal entry:
     - Lock `self.journal`, if `Some(journal)`, construct `JournalEntry` with the trigger, `summarize_policies(policy_store.policies())`, `SerializableDiff::from(&reconcile_diff)`, `SerializableStateSet::from(&effective_state)`, and the apply outcome from the report. Call `journal.append(entry)`. On error, `tracing::warn!`.
  8. Also handle the empty-diff short-circuit path (line 95-101): still append a journal entry if the trigger is `DaemonStartup` (to record that the daemon started, even if no changes were needed). For other triggers with empty diff, skip the journal write (no state change occurred). Actually, re-reading the spec: the spec says "append entry after reconcile_and_apply" — but if the diff is empty, there's no meaningful entry to record. The acceptance criteria say "a journal entry is recorded" for specific scenarios that do have changes. For startup with no changes, it's still useful to record. Decision: always write the journal entry when trigger is `DaemonStartup`, even if diff is empty. For other triggers, only write when the diff is non-empty. Wait — the spec says "the reconciler appends an entry after each reconcile_and_apply()". This implies always. Let me be consistent: always append, even if the diff is empty. The outcome will show succeeded=0, failed=0, skipped=0, which is a valid "no changes needed" record. This is useful for audit: "the daemon reconciled at this time and found nothing to do." Revised decision: always append.
  9. For the empty-diff early return: compute the rich diff and managed_entities BEFORE the early return check. Move the managed_entities and `generate_diff` computation above the `if state_diff.is_empty()` check. In the early return, still append a journal entry with the empty reconcile_diff, the effective_state snapshot, and `ApplyOutcome::Applied { succeeded: 0, failed: 0, skipped: 0 }`.
- **Why**: The daemon must record every reconciliation event for audit trail purposes.

#### `crates/netfyr-daemon/src/server.rs`
- **Action**: Modify
- **What**: At each `reconcile_and_apply()` call site, add the `trigger` argument:
  1. Line 144-145 (`handle_submit_policies`): `reconciler.reconcile_and_apply(policy_store, factory_manager, Trigger::PolicyApply { source: "daemon".into() }).await`
  2. Line 416-419 (`FactoryEvent::LeaseAcquired`): `reconciler.reconcile_and_apply(&policy_store, &factory_manager, Trigger::DhcpEvent { policy_name: policy_name.clone(), event_kind: "lease_acquired".into() }).await`
  3. Line 425-428 (`FactoryEvent::LeaseRenewed`): same with `event_kind: "lease_renewed".into()`
  4. Line 434-437 (`FactoryEvent::LeaseExpired`): same with `event_kind: "lease_expired".into()`
  - Add `use netfyr_journal::Trigger;` to imports.
- **Why**: Each call site must specify what triggered the reconciliation so the journal entry records the correct trigger.

#### `crates/netfyr-daemon/src/main.rs`
- **Action**: Modify
- **What**: At line 92-94, change the `reconcile_and_apply` call to include the trigger:
  `reconciler.reconcile_and_apply(&policy_store, &factory_manager, Trigger::DaemonStartup).await`
  - Add `use netfyr_journal::Trigger;` to imports (or use fully qualified path).
- **Why**: The startup reconciliation must be recorded as `DaemonStartup` trigger.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `flate2` | `"1"` | Gzip compression for archive rotation. The Rust standard library has no compression support. `flate2` is the de facto standard (40M+ downloads), well-maintained, and has a minimal dependency tree. The spec explicitly requires gzip for archives. |
| `libc` | `"0.2"` | `fcntl` advisory file locking for concurrent standalone applies. Already used in `netfyr-backend`. Needed for `F_SETLKW`/`F_WRLCK` on Linux. |
| `tracing` | `"0.1"` | Logging warnings on journal write failure. Already used in `netfyr-backend` and `netfyr-daemon`. Added to `netfyr-journal` for internal warnings and to `netfyr-cli` for the journal integration warning. |
| `serde` | `"1"` (derive) | Serialization of entry types. Already in workspace. |
| `serde_json` | `"1"` | NDJSON serialization. Already in workspace. |
| `chrono` | `"0.4"` (serde) | UTC timestamps. Already in workspace. |
| `thiserror` | `"1"` | Error type derivation. Already in workspace. |
| `netfyr-state` | path | `StateSet`, `State`, `Value`, `FieldValue` types for conversion. |
| `netfyr-reconcile` | path | `StateDiff`, `DiffOperation`, `FieldChange`, `FieldChangeKind`, `DiffKind` for diff conversion. `EntityKey` for managed entities. |
| `netfyr-policy` | path | `Policy` type for `summarize_policies()`. `FactoryType` for string conversion. |

## Implementation Order

### Step 1: Workspace setup and `Cargo.toml` files
Create `crates/netfyr-journal/Cargo.toml` with all dependencies. Add `"crates/netfyr-journal"` to workspace `Cargo.toml` members. Create empty `crates/netfyr-journal/src/lib.rs` with just module declarations commented out. Verify `cargo check -p netfyr-journal` compiles.

### Step 2: Entry types (`entry.rs`)
Implement `SequenceId`, `JournalEntry`, `Trigger`, `PolicySummary`, `ApplyOutcome`, and `summarize_policies()`. Add `mod entry` and re-exports to `lib.rs`. Verify `cargo check -p netfyr-journal` compiles.

### Step 3: Serializable types (`serializable.rs`)
Implement `SerializableDiff`, `SerializableDiffOp`, `SerializableFieldChange`, `SerializableStateSet`, `SerializableState`, and the `From` impls. Add `mod serializable` and re-exports to `lib.rs`. Verify `cargo check -p netfyr-journal` compiles. This step depends on step 2 (serializable types are used in `JournalEntry`).

### Step 4: Journal I/O (`journal.rs`)
Implement `JournalError`, `Journal` struct, and all its methods (`open_default`, `open`, `append`, `read_recent`, `read_entry`, `latest_state_for`, `rotate`, `cleanup_archives`, locking helpers, seq helpers). Add `mod journal` and re-exports to `lib.rs`. Verify `cargo check -p netfyr-journal` compiles. This step depends on steps 2 and 3 (journal appends `JournalEntry` which contains serializable types).

### Step 5: CLI integration
Modify `crates/netfyr-cli/Cargo.toml` to add `netfyr-journal`, `tracing`, and `chrono` dependencies. Modify `crates/netfyr-cli/src/apply.rs` to append a journal entry after standalone apply. Verify `cargo check -p netfyr-cli` compiles.

### Step 6: Daemon integration
Modify `crates/netfyr-daemon/Cargo.toml` to add `netfyr-journal` dependency. Modify `crates/netfyr-daemon/src/reconciler.rs` to add the journal field and append entries. Modify `crates/netfyr-daemon/src/server.rs` and `main.rs` to pass `Trigger` to `reconcile_and_apply`. Verify `cargo check -p netfyr-daemon` compiles. Verify `cargo test` passes (existing tests need updating for the new `trigger` parameter in `reconcile_and_apply`).

**Note on step 6**: Existing tests in `reconciler.rs` call `reconcile_and_apply(&store, &factory_manager)` without a trigger. These must be updated to pass a trigger, e.g., `Trigger::DaemonStartup`. Similarly, `server.rs` tests that call handlers which internally call `reconcile_and_apply` will need the reconciler to have the updated signature. Since tests use `Reconciler::new()`, and the updated `new()` will attempt `Journal::open_default()` which may fail in test environments (no `/var/lib/netfyr/journal/`), the journal will be `None` in tests, which is the correct degraded behavior.

## Risks and Mitigations

### 1. Daemon tests fail because `Journal::open_default()` tries to create `/var/lib/netfyr/journal/`
**Risk**: In CI/test environments, creating `/var/lib/netfyr/journal/` will fail (no permissions). `Reconciler::new()` will log a warning and set `journal: Mutex::new(None)`.
**Mitigation**: This is the correct behavior — journal is optional. Tests pass because journal writes are skipped when journal is `None`. The warning is logged but doesn't cause test failure. Alternatively, set `NETFYR_JOURNAL_DIR` to a temp directory in tests, but this isn't necessary since `None` is handled.

### 2. `reconcile_and_apply` signature change breaks existing tests
**Risk**: All existing tests calling `reconcile_and_apply` will fail to compile.
**Mitigation**: Update all call sites (5 in `server.rs`, 1 in `main.rs`, multiple in `reconciler.rs` tests) to pass a `Trigger::DaemonStartup` (or appropriate variant). This is a straightforward mechanical change.

### 3. Sequence number file corruption or TOCTOU
**Risk**: If the process crashes between writing the NDJSON entry and updating `.seq`, the sequence file is stale. On restart, the next entry gets seq = stale+1, which may duplicate a seq already in the journal file.
**Mitigation**: Write the entry to NDJSON first, then update `.seq`. On crash, `.seq` is behind: the next append will re-read `.seq`, get the stale value, and increment. The resulting seq will be a duplicate. To handle this: in `open()`, after reading `.seq`, also scan the last line of `current.ndjson` to get the actual last seq. Use `max(seq_file_value, last_line_seq)` as the starting seq. This ensures correctness even after a crash.

### 4. Large `state_after` snapshots
**Risk**: If the system has many interfaces, each journal entry's `state_after` could be large (tens of KB), leading to rapid journal growth.
**Mitigation**: The default rotation threshold (50 MB / 10,000 entries) and gzip compression handle this. A typical entry with 10 interfaces and a small diff is ~2-5 KB. At 10,000 entries, that's ~20-50 MB, which is within the threshold. The spec's retention policy (90 days) bounds total disk usage.

### 5. `flate2` compression adds latency during rotation
**Risk**: Compressing a 50 MB file could take noticeable time.
**Mitigation**: Rotation is rare (every 10,000 entries). Gzip default compression of 50 MB of JSON takes < 1 second. The daemon's event loop will block briefly, which is acceptable given the rarity.

### 6. CLI standalone apply concurrent writes
**Risk**: Two simultaneous `netfyr apply` invocations could corrupt the journal.
**Mitigation**: `fcntl(F_SETLKW)` advisory locking on `current.ndjson`. The second writer blocks until the first releases the lock. Sequence numbers are read under lock, so no duplicates.

### 7. `effective_state` availability in CLI after apply
**Risk**: In `run_apply()`, after `registry.apply(&state_diff)`, the `effective_state` variable (from `reconciliation.effective_state`) is still in scope but represents the *desired* state, not the *actual post-apply* state. If some operations failed, the actual state differs.
**Mitigation**: This is acceptable. The journal records the *desired* state after the change, not the actual. The `outcome` field records how many operations succeeded/failed, so readers can interpret accordingly. Re-querying actual state after apply would add latency and complexity. The spec shows `state_after` as the effective state, which aligns with this approach.

### 8. `generate_diff` in `reconcile_and_apply` adds overhead
**Risk**: Computing the rich diff in addition to the lean diff doubles the diff computation work.
**Mitigation**: `generate_diff` is O(n) in the number of entities and fields. For typical workloads (< 100 entities), this is microseconds. The same computation is already done in `dry_run()` without issue.

## Test Strategy

### Unit Tests (in `netfyr-journal`)

**Entry types (`entry.rs`)**:
- Round-trip serialization: serialize a `JournalEntry` to JSON, deserialize back, assert equality. Cover all `Trigger` variants.
- Verify each `Trigger` variant produces the correct `"type"` discriminator in JSON.
- Verify `ApplyOutcome::Applied` and `ApplyOutcome::Observed` serialize with correct `"kind"` tag.
- Test `summarize_policies` with empty input, single policy, multiple policies with different factory types.

**Serializable conversions (`serializable.rs`)**:
- Test `From<&netfyr_reconcile::StateDiff>` with a diff containing Add, Modify, and Remove operations. Verify kind strings, entity names, and field change kinds.
- Test `From<&StateSet>` with an empty StateSet and one with multiple entities. Verify entity types, selector names, and fields are present.
- Test that provenance is NOT included in `SerializableState.fields` (only `value` is serialized, not the `FieldValue` wrapper).
- Test field values of different `Value` variants (String, U64, Bool, IpAddr, List, Map) serialize correctly as JSON.

**Journal I/O (`journal.rs`)**:
- `open` creates directory structure (dir + archive/).
- `open` on empty dir initializes seq=0 and entry_count=0.
- `append` assigns monotonically increasing seq numbers.
- `append` + `read_recent` round-trip: append N entries, read_recent(N) returns all in reverse order.
- Sequence persistence: open journal, append 3 entries, drop journal, re-open, append 1 more, verify seq=4.
- Rotation at entry count: set max_entries=10 (via env var in test), append 11, verify current.ndjson has 1 entry, archive/ has one .gz file. Decompress and verify 10 entries.
- Rotation at file size: set max_size to a small value, append until rotation triggers.
- `read_entry(seq)` returns correct entry, `read_entry(nonexistent)` returns None.
- `latest_state_for(entity_name)` returns the most recent matching entity, None for nonexistent.
- `cleanup_archives`: create fake archive files with old timestamps, call cleanup, verify old files deleted and recent files kept.
- Atomic seq write: verify `.seq` file content after append.
- Open with existing `.seq` and `current.ndjson`: verify seq continuity.

### Integration Tests

**CLI integration** (these would be end-to-end tests, potentially in a test namespace):
- After `netfyr apply` with a valid policy, verify `current.ndjson` exists in the journal dir and contains an entry with `trigger.type = "policy_apply"`.
- With `NETFYR_JOURNAL_DIR` pointing to a read-only directory, verify apply succeeds (exit code 0) and a warning is logged.

**Daemon integration** (harder to test without a running daemon, covered by unit tests on `reconcile_and_apply`):
- Test `reconcile_and_apply` with `Trigger::DaemonStartup` and an empty store, verify no panic and journal is written (or skipped if journal is None).
- Test that all `Trigger` variants compile and are accepted by `reconcile_and_apply`.

### Test Infrastructure
- All journal I/O tests should use `tempfile::tempdir()` for the journal directory to avoid polluting the filesystem.
- Set `NETFYR_JOURNAL_MAX_ENTRIES` and `NETFYR_JOURNAL_MAX_SIZE` env vars in rotation tests to small values for quick testing.
- For archive cleanup tests, create fake `.ndjson.gz` files with known timestamps in the archive directory.
- Existing daemon tests (`reconciler.rs`, `server.rs`) need mechanical updates to pass a `Trigger` argument to `reconcile_and_apply`. Use `Trigger::DaemonStartup` as a default for existing test cases.
