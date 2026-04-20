# Understand: SPEC-101 — Backend Trait and Registry

## Current State

### `netfyr-backend` crate
`crates/netfyr-backend/src/lib.rs` contains a single doc-comment line (`//! netfyr-backend crate`) and nothing else. `Cargo.toml` has no dependencies. The crate is empty.

### `netfyr-state` crate (dependency foundation)
The following types relevant to this story already exist and are fully implemented:

| Type | Location | Notes |
|---|---|---|
| `State` | `netfyr-state/src/lib.rs` | Top-level entity record with `entity_type: String`, `selector: Selector`, `fields: IndexMap<String, FieldValue>` |
| `Selector` | `netfyr-state/src/lib.rs` | Identifies an entity; `key()`, `matches()`, `is_specific()` |
| `Value` | `netfyr-state/src/lib.rs` | Enum of all field value variants |
| `StateSet` | `netfyr-state/src/set.rs` | Keyed collection of `State`; `insert`, `get`, `remove`, `iter`, `len`, `entities` |
| `StateDiff` | `netfyr-state/src/diff.rs` | Ordered `Vec<DiffOp>`; `ops()`, `is_empty()`, `summary()` |
| `DiffOp` | `netfyr-state/src/diff.rs` | `Add { entity_type, selector, fields }`, `Modify { entity_type, selector, changed_fields, removed_fields }`, `Remove { entity_type, selector }` |
| `FieldValue` | `netfyr-state/src/lib.rs` | `value: Value` + `provenance: Provenance` |

**`EntityType` does not exist anywhere in the codebase.** The spec uses `EntityType` throughout the trait signatures, but the current `State` struct stores `entity_type` as a plain `String`. There is no type alias or newtype for it.

### Other crates
`netfyr-reconcile`, `netfyr-policy`, `netfyr-varlink`, `netfyr-cli`, `netfyr-daemon`, and `netfyr-test-utils` all have empty `lib.rs` / `main.rs` files with no relevant content.

### Tests
No tests exist in `netfyr-backend`. All existing tests are in `netfyr-state`.

---

## Requirements

### New type: `EntityType`
The spec uses `EntityType` as a distinct type in all trait and registry signatures. Since the existing codebase uses `String` for `entity_type`, this must be resolved: either define `EntityType` as a `String` newtype (or type alias) in `netfyr-state` (preferred — aligns with SPEC-002/004 dependency note) or define it locally in `netfyr-backend`. The spec says this story depends on `EntityType` being defined in `netfyr-state`, but it isn't yet. A decision is required before the type signatures can compile.

### `BackendError` enum (`src/lib.rs`)
Variants:
- `UnsupportedEntityType(EntityType)`
- `QueryFailed { entity_type: EntityType, source: Box<dyn std::error::Error + Send + Sync> }`
- `ApplyFailed { operation: String, source: Box<dyn std::error::Error + Send + Sync> }`
- `NotFound { entity_type: EntityType, selector: Selector }`
- `PermissionDenied(String)`
- `Internal(String)`

Must implement `std::error::Error` (via `thiserror`).

### `ApplyReport` and friends (`src/report.rs`)
Structs needed:
- `AppliedOperation { operation: DiffOpKind, entity_type: EntityType, selector: Selector, fields_changed: Vec<String> }`
- `FailedOperation { operation: DiffOpKind, entity_type: EntityType, selector: Selector, error: BackendError, fields: Vec<String> }`
- `SkippedOperation { operation: DiffOpKind, entity_type: EntityType, selector: Selector, reason: String }`
- `ApplyReport { succeeded: Vec<AppliedOperation>, failed: Vec<FailedOperation>, skipped: Vec<SkippedOperation> }`

Methods on `ApplyReport`:
- `is_success() -> bool` — `failed.is_empty()`
- `is_partial() -> bool` — `!succeeded.is_empty() && !failed.is_empty()`
- `is_total_failure() -> bool` — `succeeded.is_empty() && !failed.is_empty()`
- `summary() -> String`

An operation kind enum (`DiffOpKind` or similar: `Add`, `Modify`, `Remove`) is needed to avoid carrying the full `DiffOp` payload in report structs.

### `DryRunReport` and friends (`src/report.rs`)
Structs needed:
- `FieldChangeKind` enum: `Set`, `Unset`, `Modify`
- `FieldChange { field: String, current: Option<Value>, desired: Option<Value>, kind: FieldChangeKind }`
- `PlannedChange { operation: DiffOpKind, entity_type: EntityType, selector: Selector, field_changes: Vec<FieldChange> }`
- `DryRunReport { changes: Vec<PlannedChange> }`

Methods on `DryRunReport`:
- `is_empty() -> bool`
- `summary() -> String`

### `NetworkBackend` trait (`src/trait_.rs`)
```rust
#[async_trait]
pub trait NetworkBackend: Send + Sync {
    async fn query(&self, entity_type: &EntityType, selector: Option<&Selector>) -> Result<StateSet, BackendError>;
    async fn query_all(&self) -> Result<StateSet, BackendError>;
    async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError>;
    async fn dry_run(&self, diff: &StateDiff) -> Result<DryRunReport, BackendError>;
    fn supported_entities(&self) -> &[EntityType];
}
```

Requires `async-trait` crate.

### `BackendRegistry` (`src/registry.rs`)
```rust
pub struct BackendRegistry {
    backends: HashMap<EntityType, Arc<dyn NetworkBackend>>,
}
```

Methods:
- `new() -> Self`
- `register(&mut self, backend: Arc<dyn NetworkBackend>) -> Result<(), BackendError>` — iterates `backend.supported_entities()`, errors on duplicate entity type
- `get(&self, entity_type: &EntityType) -> Option<Arc<dyn NetworkBackend>>`
- `query(&self, entity_type: &EntityType, selector: Option<&Selector>) -> Result<StateSet, BackendError>`
- `query_all(&self) -> Result<StateSet, BackendError>` — queries all unique backends, merges `StateSet`s (requires `StateSet::union` or iteration)
- `apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError>` — partitions `DiffOp`s by `entity_type`, dispatches, merges `ApplyReport`s
- `supported_entities(&self) -> Vec<EntityType>`

### `Cargo.toml` changes for `netfyr-backend`
Must add:
- `async-trait` (for the trait)
- `thiserror` (for `BackendError`)
- `netfyr-state` (path dependency, for `StateSet`, `StateDiff`, `Selector`, `Value`, etc.)
- `tokio` or similar async runtime (at least as `dev-dependency` for tests; the crate itself is runtime-agnostic)

### Tests (`src/lib.rs` or `tests/`)
The acceptance criteria require a `MockBackend` that implements `NetworkBackend`. Tests must cover:
- Compilation of a type implementing the full trait (object safety check: `dyn NetworkBackend`)
- `query` returning `Ok(StateSet)`
- `query` with selector filtering
- `query` for unsupported entity type returning `BackendError::UnsupportedEntityType`
- `apply` returning `ApplyReport` with correct partitioning into `succeeded`/`failed`/`skipped`
- `ApplyReport` helper methods (`is_success`, `is_partial`, `is_total_failure`)
- `dry_run` returning `DryRunReport` with `PlannedChange`/`FieldChange` entries
- `DryRunReport::is_empty` for a zero-op diff
- `BackendRegistry::register`, `get`, conflict detection
- `BackendRegistry::query_all` merging results
- `BackendRegistry::apply` dispatching by entity type and handling unknown entity types
- `BackendRegistry::supported_entities`

---

## Gap Analysis

### Files to create (all in `crates/netfyr-backend/src/`)

| File | Contents |
|---|---|
| `src/lib.rs` | `BackendError` enum (thiserror), `pub mod` declarations, re-exports |
| `src/trait_.rs` | `NetworkBackend` trait with `async-trait` |
| `src/report.rs` | `ApplyReport`, `DryRunReport`, operation structs, `DiffOpKind`, `FieldChange`, `FieldChangeKind`, `PlannedChange` |
| `src/registry.rs` | `BackendRegistry` struct and all methods |

### Files to modify

| File | Change |
|---|---|
| `crates/netfyr-backend/Cargo.toml` | Add `async-trait`, `thiserror`, `netfyr-state` (path dep), `tokio` (dev-dep) |
| `crates/netfyr-state/src/lib.rs` | **Possibly** add `EntityType` type (newtype or alias for `String`) — required before `netfyr-backend` can compile against it. If not added here, it must be defined in `netfyr-backend` itself |

### Unresolved: `EntityType` location
The spec says `EntityType` comes from `netfyr-state` (via SPEC-002), but it does not exist there yet. The PLAN phase must decide:
1. Add `EntityType` to `netfyr-state` (preferred by spec's dependency statement), or
2. Define it locally in `netfyr-backend` (simpler, avoids touching another crate).

---

## Integration Points

### `netfyr-state` public API consumed by `netfyr-backend`
- `StateSet` — returned by `query`/`query_all`; merged in `BackendRegistry::query_all`
- `StateDiff` / `DiffOp` — taken by `apply` and `dry_run`; `DiffOp` variants destructured in registry dispatch
- `Selector` — parameter to `query`; stored in report structs
- `Value` — stored in `FieldChange::current` / `FieldChange::desired`
- `StateSet::union` — needed by `BackendRegistry::query_all` to merge results across backends

### `StateSet::union` returns `Result<StateSet, ConflictError>`
`BackendRegistry::query_all` merges multiple `StateSet`s from independent backends. Since different backends handle disjoint entity types, conflicts should not arise in practice, but the merge must handle the `ConflictError` case — either propagating it as `BackendError::Internal` or panicking with a debug message.

### Object safety of `NetworkBackend`
The trait must be object-safe (`dyn NetworkBackend`). Async methods via `async-trait` macro satisfy this. `supported_entities() -> &[EntityType]` returns a reference to data stored in the implementing struct — implementors must store `EntityType` values as an owned slice or `Vec` and return a slice reference.

---

## Risks

1. **`EntityType` not defined**: This is a blocking gap. The trait, registry, error, and report types all reference `EntityType`. If it is just a `type EntityType = String` alias, the diff between using it vs. `String` is minimal. If it is a newtype, the existing `State::entity_type: String` field in `netfyr-state` is incompatible and will require conversion methods or a migration of that field's type — a potentially disruptive change.

2. **`BackendRegistry::apply` partitioning**: `DiffOp` carries `entity_type: String` (not `EntityType`). The registry must look up the backend by converting this `String` to the `EntityType` key. If `EntityType` is a newtype, this requires a `From<String>` or `AsRef<str>` impl.

3. **Merging `ApplyReport`s**: The spec says reports are "merged," but does not define merge semantics precisely. The natural interpretation is concatenating the `succeeded`, `failed`, and `skipped` vectors across all per-backend reports. The helper method semantics (`is_partial`, `is_total_failure`) assume a global view across all operations — this is consistent with concatenation.

4. **`query_all` deduplication**: `BackendRegistry` holds `Arc<dyn NetworkBackend>` per entity type, so the same backend instance can be registered under multiple entity types. `query_all` must call `query_all()` on each unique backend instance once, not once per registered entity type — otherwise backends that cover multiple entity types are queried multiple times and results double-counted.

5. **`dry_run` field change detail**: The spec requires `FieldChange { current, desired }` values, but `StateDiff::DiffOp::Modify` only carries `changed_fields` (the new `FieldValue`s) and `removed_fields` (names only, without the old values). To populate `FieldChange::current` for a `Modify` op, the backend's `dry_run` implementation needs access to the current system state. `MockBackend` in tests can satisfy this via internally stored state, but the trait signature does not provide the `from` `StateSet` — only the `StateDiff`. This may make `dry_run` awkward to implement correctly without calling `query_all` internally.

6. **Async runtime**: The crate defines async trait methods but does not specify a runtime. Tests will need `tokio::test` or a similar async test executor added as a dev-dependency.
