# Plan: SPEC-101 — Backend Trait and Registry

## Approach

The `netfyr-backend` crate will provide the trait-based abstraction layer between the pure state/reconciliation engine and the system-touching I/O layer. The design centres on four concepts: the `NetworkBackend` async trait (the contract backends implement), two report types (`ApplyReport` and `DryRunReport` that capture operation outcomes with field-level detail), an error enum (`BackendError`), and a `BackendRegistry` that maps entity types to backend instances for dispatch.

The crate is structured as four source files mirroring the spec: `lib.rs` (error types, module declarations, re-exports), `trait_.rs` (the async trait), `report.rs` (all report/operation structs and helper enums), and `registry.rs` (the registry). All types are defined purely in terms of types from `netfyr-state` (`StateSet`, `StateDiff`, `DiffOp`, `Selector`, `Value`) and standard library types. The async trait uses the `async-trait` crate for object safety (`dyn NetworkBackend`). Error types use `thiserror` for ergonomic `std::error::Error` impls.

The `BackendRegistry` stores a `HashMap<EntityType, Arc<dyn NetworkBackend>>` for O(1) entity-type lookup. Since one backend can support multiple entity types, the same `Arc` appears under multiple keys. Operations that touch all backends (`query_all`, `apply` partitioning) deduplicate by `Arc` pointer identity before dispatching. The registry's `apply` constructs per-backend `StateDiff` sub-partitions and merges the resulting `ApplyReport`s by concatenating their `succeeded`/`failed`/`skipped` vectors.

Two small changes to `netfyr-state` are required: (1) a `pub type EntityType = String` alias to give the entity-type concept a named type as the spec expects, and (2) a `pub fn new(ops: Vec<DiffOp>) -> Self` constructor on `StateDiff` so the registry can construct per-backend sub-diffs. Both are additive and non-breaking.

## Design Decisions

### 1. EntityType as type alias, not newtype
- **Decision**: Define `pub type EntityType = String` in `netfyr-state/src/lib.rs`.
- **Alternatives considered**: (a) A newtype `pub struct EntityType(String)` with `Deref`, `Display`, `From<String>`, etc. (b) Define `EntityType` locally in `netfyr-backend`.
- **Rationale**: The spec says EntityType comes from SPEC-002 (netfyr-state), so it must live there — rules out (b). A type alias is zero-cost and fully compatible with the existing `State::entity_type: String` field, `DiffOp::Add { entity_type: String, .. }`, and all code that uses strings for entity types. A newtype would require adding conversion impls to `State`, `DiffOp`, `StateSet`, and all existing code — a large, disruptive change that is outside the scope of this story. The alias provides the named type the spec needs while preserving compatibility. It can be upgraded to a newtype in a future story if type safety becomes a priority.

### 2. DiffOpKind as a separate lightweight enum
- **Decision**: Define `pub enum DiffOpKind { Add, Modify, Remove }` in `report.rs` to capture operation kind in report structs without carrying the full `DiffOp` payload.
- **Alternatives considered**: (a) Store `DiffOp` directly in report structs. (b) Add a `kind()` method to `DiffOp` in netfyr-state.
- **Rationale**: Report structs need the operation *kind* but not the full field data (which belongs to the original diff). Storing `DiffOp` would duplicate field data and create awkward ownership. Adding `kind()` to `DiffOp` in netfyr-state would require a `DiffOpKind` type there, which is backend-specific. Defining it locally keeps the dependency clean. Implement `From<&DiffOp> for DiffOpKind` in `report.rs` for easy conversion.

### 3. BackendError source uses `Box<dyn Error + Send + Sync>`
- **Decision**: Error variants with sources (`QueryFailed`, `ApplyFailed`) use `Box<dyn std::error::Error + Send + Sync>` rather than plain `Box<dyn Error>`.
- **Alternatives considered**: `Box<dyn Error>` (not `Send + Sync`), `String` (losing the error chain).
- **Rationale**: The `NetworkBackend` trait is `Send + Sync`, and errors cross async boundaries. `Send + Sync` on the error source prevents foot-guns when errors are held across await points. This also means `BackendError` itself is `Send + Sync`.

### 4. ApplyReport and related structs are not Clone
- **Decision**: `ApplyReport`, `FailedOperation`, and `BackendError` do not derive `Clone`.
- **Alternatives considered**: Using `Arc<dyn Error>` in BackendError to enable Clone, or storing error messages as `String` in FailedOperation.
- **Rationale**: `Box<dyn Error + Send + Sync>` is not `Clone`. The spec requires `FailedOperation` to hold `BackendError`, which contains these boxes. Reports are consumed once (logged, displayed, or inspected) — cloning is not needed. `Debug` is derived on all types for diagnostics.

### 5. Registry deduplication via Arc pointer identity
- **Decision**: `query_all` and internal dispatch collect unique backends by comparing `Arc::as_ptr()` cast to `*const ()`, using a `HashSet`.
- **Alternatives considered**: (a) Storing a separate `Vec<Arc<dyn NetworkBackend>>` of unique backends alongside the HashMap. (b) Calling `query_all` once per entity type instead of per backend.
- **Rationale**: The HashMap-based storage matches the spec. Pointer dedup at call time is simple, correct, and avoids dual-bookkeeping. Calling per entity type would invoke `query_all` multiple times on the same backend, producing duplicate state.

### 6. StateDiff constructor for sub-diff construction
- **Decision**: Add `pub fn new(ops: Vec<DiffOp>) -> Self` to `StateDiff` in `netfyr-state/src/diff.rs`.
- **Alternatives considered**: (a) Making the `ops` field public. (b) Having the registry pass individual `DiffOp`s instead of a `StateDiff` to backends.
- **Rationale**: The registry must partition a diff by entity type and pass sub-diffs to each backend. The backend trait takes `&StateDiff`, not `&[DiffOp]`. Currently `StateDiff::ops` is private and there's no public constructor. A `new()` constructor is the minimal, idiomatic change. Making the field public would break encapsulation.

### 7. DiffOp helper method for entity_type extraction
- **Decision**: Add `pub fn entity_type(&self) -> &str` to `DiffOp` in `netfyr-state/src/diff.rs`.
- **Alternatives considered**: Pattern matching at every call site in the registry.
- **Rationale**: All three `DiffOp` variants carry `entity_type: String`. A helper method avoids repetitive match expressions in the registry's partitioning logic. It's a one-line method that belongs naturally on `DiffOp`.

### 8. Registry apply merges reports by concatenation
- **Decision**: Merge `ApplyReport`s from multiple backends by concatenating `succeeded`, `failed`, and `skipped` vectors.
- **Alternatives considered**: Nested/tree-structured reports, or per-backend sub-reports.
- **Rationale**: The spec describes a single flat `ApplyReport`. The helper methods (`is_success`, `is_partial`, `is_total_failure`) assume a global view across all operations. Concatenation produces this flat view naturally. Order is deterministic (HashMap iteration order per entity type, then per-backend report order).

### 9. Registry apply does not short-circuit on unknown entity types
- **Decision**: Unknown entity types produce `FailedOperation` entries in the merged report. Known entity types are still dispatched normally.
- **Alternatives considered**: Returning `Err(BackendError::UnsupportedEntityType)` immediately.
- **Rationale**: The acceptance criteria explicitly state "wifi operation is reported as failed ... ethernet operations are still applied normally." This requires best-effort dispatch with partial failure reporting.

### 10. ApplyReport::is_partial semantics
- **Decision**: `is_partial()` returns `true` when there are both succeeded and failed operations (i.e., `!succeeded.is_empty() && !failed.is_empty()`). Skipped operations do not affect this check.
- **Alternatives considered**: Including skipped in the partial check.
- **Rationale**: The spec defines `is_partial` as "some succeeded, some failed." Skipped operations are a distinct category (dependency failures, already-in-desired-state). Including them would conflate "partial application" with "nothing to do."

## File Changes

### 1. `crates/netfyr-state/src/lib.rs` — modify

- **What**: Add `pub type EntityType = String;` after the existing type definitions (before `Selector`). Add a re-export: `pub use diff::EntityType;` — actually no, define the alias here in `lib.rs` since it's a foundational type, and re-export it.
- Actually, define it directly in `lib.rs`:
  ```
  pub type EntityType = String;
  ```
  No additional re-export needed since it's directly in `lib.rs`.
- **Why**: The spec and trait signatures use `EntityType` throughout. Defining it in `netfyr-state` satisfies the SPEC-002 dependency. As a type alias, it's zero-cost and backward-compatible.

### 2. `crates/netfyr-state/src/diff.rs` — modify

- **What**:
  - Add `pub fn new(ops: Vec<DiffOp>) -> Self` to `impl StateDiff`. Constructs a `StateDiff` from a pre-built ops vector.
  - Add `pub fn entity_type(&self) -> &str` to `impl DiffOp` (new impl block). Returns a reference to the `entity_type` field regardless of variant, via a match on `self` that returns `&entity_type` for `Add`, `Modify`, and `Remove`.
- **Why**: The registry needs to construct per-backend sub-diffs from a partitioned ops list (`StateDiff::new`). The registry also needs to extract entity_type from each op for partitioning (`DiffOp::entity_type`). Both are simple accessor additions.

### 3. `crates/netfyr-backend/Cargo.toml` — modify

- **What**: Add dependencies:
  - `netfyr-state = { path = "../netfyr-state" }` — for `StateSet`, `StateDiff`, `DiffOp`, `Selector`, `Value`, `EntityType`
  - `async-trait = "0.1"` — for object-safe async trait methods
  - `thiserror = "1"` — for `BackendError` error derive
  - Under `[dev-dependencies]`:
    - `tokio = { version = "1", features = ["macros", "rt"] }` — async test runtime
- **Why**: The crate's trait methods are async (needs `async-trait`), error types use `thiserror`, and all data types come from `netfyr-state`. Tests need `tokio` for `#[tokio::test]`.

### 4. `crates/netfyr-backend/src/lib.rs` — modify (rewrite)

- **What**:
  - Module declarations: `pub mod trait_; pub mod report; pub mod registry;`
  - Re-exports: re-export all public types from submodules for flat access:
    - From `trait_`: `NetworkBackend`
    - From `report`: `ApplyReport`, `AppliedOperation`, `FailedOperation`, `SkippedOperation`, `DryRunReport`, `PlannedChange`, `FieldChange`, `FieldChangeKind`, `DiffOpKind`
    - From `registry`: `BackendRegistry`
  - Define `BackendError` enum with `#[derive(Debug, thiserror::Error)]`:
    - `UnsupportedEntityType(EntityType)` — `#[error("unsupported entity type: {0}")]`
    - `QueryFailed { entity_type: EntityType, #[source] source: Box<dyn std::error::Error + Send + Sync> }` — `#[error("query failed for entity type {entity_type}")]`
    - `ApplyFailed { operation: String, #[source] source: Box<dyn std::error::Error + Send + Sync> }` — `#[error("apply failed for operation: {operation}")]`
    - `NotFound { entity_type: EntityType, selector: Selector }` — `#[error("entity not found: {entity_type} {selector:?}")]` (uses Debug for Selector since it lacks Display)
    - `PermissionDenied(String)` — `#[error("permission denied: {0}")]`
    - `Internal(String)` — `#[error("internal error: {0}")]`
  - `BackendError` must be `Send + Sync` (verified by the `Box<dyn Error + Send + Sync>` sources and all other fields being `Send + Sync`).
- **Why**: Central module that ties together the crate's public API. Error types are defined here because they're used across all submodules.

### 5. `crates/netfyr-backend/src/report.rs` — create

- **What**:
  - `pub enum DiffOpKind { Add, Modify, Remove }` — derives `Debug, Clone, Copy, PartialEq, Eq`. Lightweight operation kind for report structs.
  - `impl fmt::Display for DiffOpKind` — returns `"add"`, `"modify"`, or `"remove"`.
  - `impl From<&DiffOp> for DiffOpKind` — pattern matches on the DiffOp variant and returns the corresponding kind.
  - `pub struct AppliedOperation` — fields: `pub operation: DiffOpKind`, `pub entity_type: EntityType`, `pub selector: Selector`, `pub fields_changed: Vec<String>`. Derives `Debug`.
  - `pub struct FailedOperation` — fields: `pub operation: DiffOpKind`, `pub entity_type: EntityType`, `pub selector: Selector`, `pub error: BackendError`, `pub fields: Vec<String>`. Derives `Debug`.
  - `pub struct SkippedOperation` — fields: `pub operation: DiffOpKind`, `pub entity_type: EntityType`, `pub selector: Selector`, `pub reason: String`. Derives `Debug`.
  - `pub struct ApplyReport` — fields: `pub succeeded: Vec<AppliedOperation>`, `pub failed: Vec<FailedOperation>`, `pub skipped: Vec<SkippedOperation>`. Derives `Debug`.
  - `impl ApplyReport`:
    - `pub fn new() -> Self` — empty report.
    - `pub fn is_success(&self) -> bool` — `self.failed.is_empty()`
    - `pub fn is_partial(&self) -> bool` — `!self.succeeded.is_empty() && !self.failed.is_empty()`
    - `pub fn is_total_failure(&self) -> bool` — `self.succeeded.is_empty() && !self.failed.is_empty()`
    - `pub fn summary(&self) -> String` — format: `"{n} succeeded, {n} failed, {n} skipped"`
    - `pub fn merge(&mut self, other: ApplyReport)` — extends `self.succeeded`, `self.failed`, `self.skipped` with `other`'s vectors. Used by the registry to combine per-backend reports.
  - `pub enum FieldChangeKind { Set, Unset, Modify }` — derives `Debug, Clone, Copy, PartialEq, Eq`.
  - `pub struct FieldChange` — fields: `pub field: String`, `pub current: Option<Value>`, `pub desired: Option<Value>`, `pub kind: FieldChangeKind`. Derives `Debug, Clone`.
  - `pub struct PlannedChange` — fields: `pub operation: DiffOpKind`, `pub entity_type: EntityType`, `pub selector: Selector`, `pub field_changes: Vec<FieldChange>`. Derives `Debug`.
  - `pub struct DryRunReport` — fields: `pub changes: Vec<PlannedChange>`. Derives `Debug`.
  - `impl DryRunReport`:
    - `pub fn new() -> Self` — empty report.
    - `pub fn is_empty(&self) -> bool` — `self.changes.is_empty()`
    - `pub fn summary(&self) -> String` — format: `"{n} changes planned"` or `"no changes"` if empty, with a breakdown of add/modify/remove counts.
- **Why**: Report types capture the outcome of apply/dry-run operations with field-level detail. The `merge` method on `ApplyReport` supports the registry's multi-backend dispatch pattern.

### 6. `crates/netfyr-backend/src/trait_.rs` — create

- **What**:
  - Import `async_trait::async_trait`, types from `netfyr_state`, and `BackendError` from `crate`.
  - Define the `NetworkBackend` trait:
    ```
    #[async_trait]
    pub trait NetworkBackend: Send + Sync {
        async fn query(&self, entity_type: &EntityType, selector: Option<&Selector>) -> Result<StateSet, BackendError>;
        async fn query_all(&self) -> Result<StateSet, BackendError>;
        async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError>;
        async fn dry_run(&self, diff: &StateDiff) -> Result<DryRunReport, BackendError>;
        fn supported_entities(&self) -> &[EntityType];
    }
    ```
  - The trait is object-safe: all methods are either `&self` async (handled by `async-trait` boxing) or `&self` returning a reference. `supported_entities` returns `&[EntityType]` — implementors store a `Vec<EntityType>` and return a slice.
- **Why**: Core abstraction. The `async-trait` macro desugars async methods to return `Pin<Box<dyn Future>>`, enabling `dyn NetworkBackend` to be used as a trait object.

### 7. `crates/netfyr-backend/src/registry.rs` — create

- **What**:
  - `pub struct BackendRegistry` — field: `backends: HashMap<EntityType, Arc<dyn NetworkBackend>>`. Derives `Default`.
  - `impl BackendRegistry`:
    - `pub fn new() -> Self` — empty registry.
    - `pub fn register(&mut self, backend: Arc<dyn NetworkBackend>) -> Result<(), BackendError>` — iterates `backend.supported_entities()`, checks if each entity type is already registered. If a conflict is found (entity type already mapped to a *different* backend, checked by `Arc::ptr_eq` — note: for trait objects, compare `Arc::as_ptr() as *const ()` since fat pointers have distinct vtable components), returns `BackendError::Internal` with a message naming the conflicting entity type. If no conflicts, inserts all entity types. All-or-nothing: check all first, then insert.
    - `pub fn get(&self, entity_type: &EntityType) -> Option<Arc<dyn NetworkBackend>>` — clones the `Arc` from the map.
    - `pub async fn query(&self, entity_type: &EntityType, selector: Option<&Selector>) -> Result<StateSet, BackendError>` — looks up backend, returns `UnsupportedEntityType` if not found, otherwise delegates to `backend.query()`.
    - `pub async fn query_all(&self) -> Result<StateSet, BackendError>` — collects unique backends (deduplicate by `Arc::as_ptr() as *const ()`), calls `query_all()` on each, merges `StateSet`s using `StateSet::union`. Converts `ConflictError` to `BackendError::Internal` (should not happen since backends cover disjoint entity types, but handle gracefully).
    - `pub async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError>` — partitions `diff.ops()` by `entity_type` (using `DiffOp::entity_type()`). For each group: if a backend is registered, constructs a sub-`StateDiff` via `StateDiff::new(ops)` and calls `backend.apply(&sub_diff)`. If no backend is registered, creates `FailedOperation` entries for each op in the group with `BackendError::UnsupportedEntityType`. Merges all `ApplyReport`s via `ApplyReport::merge`. Returns `Ok(merged_report)` (never returns `Err` — all failures are captured in the report).
    - `pub fn supported_entities(&self) -> Vec<EntityType>` — collects and returns all keys from the HashMap.
  - Note: `query`, `query_all`, and `apply` are async but `BackendRegistry` itself is not a `NetworkBackend` implementor — it's a dispatcher, not a backend.
- **Why**: The registry is the dispatch layer that routes operations to the correct backend. It enables the reconciliation engine to work with a single entry point regardless of how many backends are active.

## Dependencies

| Crate | Version | Justification |
|---|---|---|
| `async-trait` | `0.1` | Required for object-safe async trait methods. Rust's native async fn in traits (1.75+) does not support `dyn Trait` — `async-trait` boxes the futures. No std alternative. |
| `thiserror` | `1` | Ergonomic `#[derive(Error)]` for `BackendError`. Alternative is hand-writing `Display` and `Error` impls — `thiserror` is already used in `netfyr-state`. |
| `netfyr-state` | path dep | All data types (`StateSet`, `StateDiff`, `DiffOp`, `Selector`, `Value`, `EntityType`) come from this crate. |
| `tokio` (dev) | `1` (features: `macros`, `rt`) | Async test runtime for `#[tokio::test]`. Only in dev-dependencies — the crate itself is runtime-agnostic. |

No other external crates are needed. `std::collections::HashMap`, `std::sync::Arc`, and `std::collections::HashSet` provide everything else.

## Implementation Order

### Step 1: Modify `netfyr-state` (foundational additions)
- Add `pub type EntityType = String;` to `crates/netfyr-state/src/lib.rs`.
- Add re-export to the pub use block in `lib.rs`.
- Add `pub fn new(ops: Vec<DiffOp>) -> Self` to `impl StateDiff` in `crates/netfyr-state/src/diff.rs`.
- Add `impl DiffOp` with `pub fn entity_type(&self) -> &str` in `crates/netfyr-state/src/diff.rs`.
- **Compile check**: `cargo build -p netfyr-state` — should compile with zero breakage since all changes are additive.

### Step 2: Update `netfyr-backend/Cargo.toml`
- Add all dependencies (`netfyr-state`, `async-trait`, `thiserror`, `tokio` dev-dep).
- **Compile check**: `cargo check -p netfyr-backend` — trivially compiles (lib.rs is still a doc comment).

### Step 3: Create `src/lib.rs` with `BackendError` and module declarations
- Define `BackendError` enum.
- Declare `pub mod trait_; pub mod report; pub mod registry;` — these files will be created next.
- Create placeholder files for `trait_.rs`, `report.rs`, `registry.rs` (empty or with minimal content to compile).
- **Compile check**: `cargo check -p netfyr-backend`.

### Step 4: Create `src/report.rs`
- Define `DiffOpKind`, all report structs, and their methods.
- Implement `From<&DiffOp> for DiffOpKind`.
- **Compile check**: `cargo check -p netfyr-backend`.

### Step 5: Create `src/trait_.rs`
- Define `NetworkBackend` trait with `#[async_trait]`.
- **Compile check**: `cargo check -p netfyr-backend` — requires report types from step 4.

### Step 6: Create `src/registry.rs`
- Define `BackendRegistry` with all methods.
- **Compile check**: `cargo check -p netfyr-backend` — requires trait from step 5.

### Step 7: Add re-exports to `src/lib.rs`
- Add `pub use` statements for all public types.
- **Compile check**: `cargo check -p netfyr-backend` — full crate compiles.

### Step 8: Verify with workspace build
- `cargo build --workspace` — ensure no cross-crate breakage.

## Risks and Mitigations

### 1. `Arc<dyn NetworkBackend>` pointer comparison for deduplication
- **Risk**: Fat pointers for trait objects consist of a data pointer and a vtable pointer. Two `Arc`s cloned from the same source will have the same data pointer but potentially different vtable pointers if the compiler monomorphizes differently.
- **Mitigation**: Compare only the data pointer via `Arc::as_ptr() as *const ()`. This strips the vtable, leaving only the allocation address. Two `Arc`s cloned from the same original will always share the same allocation address. This is the standard idiom for trait object identity comparison.

### 2. `StateDiff` ops partitioning clones `DiffOp`s
- **Risk**: The registry partitions `diff.ops()` (a `&[DiffOp]` slice) into per-backend groups, then constructs new `StateDiff` values. This requires cloning each `DiffOp`, which clones `IndexMap<String, FieldValue>`, `Selector`, etc. For large diffs, this has non-trivial allocation cost.
- **Mitigation**: Acceptable for now. Network configuration diffs are small (tens of operations, not thousands). If profiling reveals this as a bottleneck, the trait could be extended with an `apply_ops(&self, ops: &[DiffOp])` method, but premature optimization is not warranted.

### 3. `StateSet::union` error in `query_all`
- **Risk**: `StateSet::union` returns `Err(ConflictError)` if two backends produce entities with the same `(entity_type, selector_key)` and conflicting field values at equal priority. This should not happen if backends cover disjoint entity types, but a misconfigured backend could cause it.
- **Mitigation**: Convert `ConflictError` to `BackendError::Internal` with a descriptive message. The registry's `query_all` returns this as an `Err`, letting the caller decide how to handle it.

### 4. `supported_entities` returning `&[EntityType]` requires stored data
- **Risk**: The trait method `fn supported_entities(&self) -> &[EntityType]` returns a borrowed slice. Implementors must store entity types as an owned `Vec<EntityType>` and return a slice reference. If an implementor tries to construct the list on the fly, it cannot return a reference to a local.
- **Mitigation**: This is a trait design constraint, not a bug. Document in the trait that implementors must store the entity type list. The `MockBackend` in tests will demonstrate the pattern.

### 5. DiffOp entity_type is `String`, not `EntityType` in the current code
- **Risk**: Since `EntityType` is a type alias for `String`, there is no actual type mismatch. But if `EntityType` is later changed to a newtype, `DiffOp::entity_type` would need updating.
- **Mitigation**: The type alias decision (Decision #1) explicitly defers the newtype migration. When/if that migration happens, it will be a separate story that updates all usages comprehensively.

### 6. Async methods require a runtime for testing
- **Risk**: Tests using `#[tokio::test]` require the `tokio` runtime. The crate itself must remain runtime-agnostic.
- **Mitigation**: `tokio` is only a dev-dependency. The crate's public API uses `async-trait`'s boxing, which works with any executor. Tests use `#[tokio::test]` with `features = ["macros", "rt"]` — the minimal feature set.

## Test Strategy

### Unit Tests (in `src/report.rs` or as `#[cfg(test)] mod tests` blocks)

**ApplyReport helper methods**:
- `is_success()` returns `true` when `failed` is empty (even if `skipped` is non-empty).
- `is_success()` returns `false` when `failed` is non-empty.
- `is_partial()` returns `true` when both `succeeded` and `failed` are non-empty.
- `is_partial()` returns `false` when only `succeeded` is non-empty (full success).
- `is_partial()` returns `false` when only `failed` is non-empty (total failure).
- `is_total_failure()` returns `true` when `succeeded` is empty and `failed` is non-empty.
- `is_total_failure()` returns `false` when `succeeded` is non-empty.
- `summary()` produces correctly formatted output.
- `merge()` concatenates all three vectors from both reports.

**DryRunReport**:
- `is_empty()` returns `true` for a report with zero changes.
- `is_empty()` returns `false` for a report with changes.
- `summary()` produces formatted output.

**DiffOpKind**:
- `From<&DiffOp>` conversion for each variant (Add, Modify, Remove).
- `Display` impl produces expected strings.

### Integration Tests (in `tests/` directory or end of `registry.rs`)

Requires a `MockBackend` struct that implements `NetworkBackend`. The mock should:
- Store a configurable list of `EntityType`s it supports.
- Store a `StateSet` that it returns from `query`/`query_all`.
- Have configurable behavior for `apply` (which ops succeed/fail/skip).
- Support selector filtering in `query`.

**Trait object safety**:
- Construct a `MockBackend`, wrap in `Arc<dyn NetworkBackend>`, call all methods — verifies object safety.

**Query behavior**:
- `query` with supported entity type returns `Ok(StateSet)`.
- `query` with selector filters results (mock filters its internal StateSet).
- `query` with unsupported entity type returns `Err(BackendError::UnsupportedEntityType)`.
- `query_all` returns all entities across supported types.

**Apply behavior**:
- `apply` with a diff produces an `ApplyReport` with correct succeeded/failed/skipped counts.
- `ApplyReport::is_partial` is `true` when some succeed and some fail.
- Each `FailedOperation` contains the original operation's entity_type, selector, and error.
- Each `SkippedOperation` contains a reason string.

**Dry-run behavior**:
- `dry_run` returns `DryRunReport` with `PlannedChange` entries.
- `FieldChange` entries contain correct current/desired values and kind.
- `dry_run` on an empty diff returns an empty `DryRunReport`.

**BackendRegistry**:
- `register` + `get`: register a mock, look it up by each supported entity type.
- `get` for unregistered entity type returns `None`.
- Register two mocks with disjoint entity types — both are retrievable.
- Register a conflicting entity type — returns error, original registration preserved.
- `query_all` queries all unique backends and merges results.
- `apply` partitions a multi-entity-type diff and dispatches to correct backends.
- `apply` with unknown entity type in diff — unknown ops appear as `FailedOperation`, known ops still dispatched.
- `supported_entities` returns all registered entity types.

### What NOT to test here
- `StateSet::union` correctness (tested in `netfyr-state`).
- `StateDiff::new` correctness (trivial constructor, tested implicitly by registry tests).
- Actual kernel I/O (that's for concrete backend implementations, not the trait definition).
