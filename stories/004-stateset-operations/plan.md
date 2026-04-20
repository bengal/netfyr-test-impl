# Plan: SPEC-004 StateSet Operations

## Approach

The design introduces two new modules within the existing `netfyr-state` crate: `set.rs` for the `StateSet` collection and the three set-algebraic operations (`union`, `intersection`, `complement`), and `diff.rs` for the `diff` function and its output types (`StateDiff`, `DiffOp`). Both modules are re-exported through `lib.rs` so downstream consumers see a flat public API.

`StateSet` is a thin wrapper around `IndexMap<(String, String), State>` keyed by `(entity_type, selector.key())`. The wrapper provides ergonomic CRUD methods and enforces the invariant that the key always matches the stored `State`'s own `entity_type` and `selector`. The three set operations (`union`, `intersection`, `complement`) are free functions, not methods on `StateSet`, because they are symmetric binary operations — making them methods would artificially privilege one operand. `diff` is also a free function with clear `from`/`to` semantics.

The alternative of putting everything in a single large file was rejected because `set.rs` and `diff.rs` have distinct responsibilities and the separation mirrors the spec's own structure. Making operations methods on `StateSet` (e.g., `a.union(&b)`) was considered but rejected because free functions make the symmetry explicit and match mathematical convention.

Error handling uses `thiserror` for `ConflictError` (the only error type). This is the spec-mandated approach and is preferable to hand-rolling `Display`/`Error` impls for a type that carries structured conflict data.

All set operations work per-field by iterating over the `fields: IndexMap<String, FieldValue>` on each `State`. For `union`, priority comes from `State.priority` (the parent state's priority applies uniformly to all its fields). The result `State` objects in `union`'s output get freshly-generated `StateMetadata` since they represent a new merged entity, not an original source entity. The `entity_type`, `selector`, and `priority` are carried over (for `union` on merged entities, the higher-priority state's metadata/policy_ref is used when priorities differ; when equal, `a`'s is used).

## Design Decisions

1. **Decision**: `StateSet` stores `IndexMap<(String, String), State>` using owned `String` tuple keys.
   - **Alternatives considered**: Using a newtype key struct; using `HashMap`.
   - **Rationale**: The spec explicitly mandates `IndexMap` for deterministic ordering. A tuple of `(String, String)` is the simplest key that works with `IndexMap::get` via the `(entity_type, selector_key)` pair. A newtype would add boilerplate for no gain since the key is only ever entity_type + selector_key.

2. **Decision**: Set operations (`union`, `intersection`, `complement`) are free functions, not methods.
   - **Alternatives considered**: Methods on `StateSet` (e.g., `a.union(&b)`).
   - **Rationale**: Free functions match the spec's notation (`union(a, b)`) and make the symmetry of the operation explicit. The spec defines these as standalone operations.

3. **Decision**: `union` collects ALL conflicts before returning `Err`, rather than short-circuiting on the first conflict.
   - **Alternatives considered**: Fail-fast on first conflict.
   - **Rationale**: The spec's pseudocode implies collecting all conflicts (the error type contains `Vec<Conflict>`), and returning all conflicts at once is far more useful for diagnostics. The implementation iterates all entities and all fields, accumulating conflicts into a `Vec<Conflict>`, and only returns `Err` after completing the full scan.

4. **Decision**: For `union` merged entities, the result `State` gets new `StateMetadata` (fresh UUID, timestamp).
   - **Alternatives considered**: Copying metadata from `a` or `b`; picking the higher-priority state's metadata.
   - **Rationale**: A merged state is a new logical entity — it doesn't correspond to either input. Fresh metadata avoids misleading provenance. The `policy_ref` on the merged `State` is set to `None` (it came from multiple sources), and `priority` is set to the maximum of the two input priorities (since the merged state logically carries at least that authority).

5. **Decision**: `intersection` returns fields from `a` when values match (for provenance/priority).
   - **Alternatives considered**: Fields from `b`, or constructing a new `FieldValue`.
   - **Rationale**: The spec says "regardless of priority/provenance" for matching, so either side's `FieldValue` is acceptable. Consistently taking `a`'s is deterministic, simple, and documented.

6. **Decision**: `complement` checks field presence by name only (not value equality).
   - **Alternatives considered**: Excluding only fields with matching values.
   - **Rationale**: Spec is explicit: "fields in `a` that are not in `b`" — this is a name-only check. The deletion-detection use case confirms this: if `b` has a field with a different value, it's still "present" and the field is excluded from the complement.

7. **Decision**: `DiffOp::Modify::changed_fields` includes fields that are new in `to` (added fields) as well as fields present in both with different values.
   - **Alternatives considered**: Separate `added_fields` in the Modify variant.
   - **Rationale**: The spec's acceptance criteria show "changed_fields includes 'routes' being added" in a Modify scenario. The spec treats both cases (value change and field addition) under `changed_fields`. This is simpler and the downstream consumer (backend) doesn't need to distinguish "new field on existing entity" from "changed field on existing entity."

8. **Decision**: Use `thiserror = "1"` (not 2.x).
   - **Alternatives considered**: `thiserror = "2"`.
   - **Rationale**: The spec explicitly requests `thiserror` for error types and the understanding analysis recommends version 1. Version 1.x is stable and widely used; 2.x is newer and may not be necessary.

9. **Decision**: `ConflictError` implements `std::fmt::Display` with a human-readable summary, and `std::error::Error` via thiserror.
   - **Alternatives considered**: Manual `Display` impl.
   - **Rationale**: `thiserror`'s `#[error(...)]` attribute is the idiomatic approach and the whole reason for the dependency.

10. **Decision**: `StateSet` lookup methods (`get`, `remove`) take `entity_type: &str, selector_key: &str` as two separate parameters rather than a tuple.
    - **Alternatives considered**: Taking `&(String, String)` or a key struct.
    - **Rationale**: The spec defines the API this way. Two `&str` parameters are more ergonomic for callers. Internally, the methods construct the tuple key to do the lookup. `IndexMap` supports lookup via `(&str, &str)` through `IndexMap::get` when the key implements the right `Borrow`/`Equivalent` traits — but since `IndexMap<(String, String), _>` doesn't natively support `&(&str, &str)` lookup, we'll use `.iter().find()` or convert to owned strings. The cleanest approach is to use `indexmap`'s `Equivalent` trait or simply construct owned keys: `self.inner.get(&(entity_type.to_owned(), selector_key.to_owned()))`. Given these are small string keys used in config, the allocation cost is negligible. Alternatively, we can use `IndexMap::get_full` with an iterator — but owned key construction is simpler and more readable.

## File Changes

### 1. `crates/netfyr-state/Cargo.toml`
- **Action**: Modify
- **What**: Add `thiserror = "1"` to the `[dependencies]` section.
- **Why**: `ConflictError` uses `thiserror`'s derive macro for `Error` and `Display` implementations, as mandated by the spec.

### 2. `crates/netfyr-state/src/set.rs`
- **Action**: Create
- **What**:
  - **`Conflict` struct**: Public struct with fields `entity_type: String`, `selector_key: String`, `field: String`, `value_a: Value`, `value_b: Value`, `priority: u32`. Derives `Clone, Debug, PartialEq`.
  - **`ConflictError` struct**: Public struct wrapping `pub conflicts: Vec<Conflict>`. Derives `Debug, Clone` and uses `#[derive(thiserror::Error)]` with a `#[error("...")]` attribute that produces a message like `"field conflicts in union: {count} conflict(s)"` plus entity/field details. Implements `std::error::Error` via thiserror.
  - **`StateSet` struct**: Public struct containing a private `inner: IndexMap<(String, String), State>`. Derives `Clone, Debug, Default`.
  - **`StateSet::new() -> Self`**: Returns an empty `StateSet`.
  - **`StateSet::insert(&mut self, state: State)`**: Computes key as `(state.entity_type.clone(), state.selector.key())` and inserts into the inner map, replacing any existing entry with the same key.
  - **`StateSet::get(&self, entity_type: &str, selector_key: &str) -> Option<&State>`**: Looks up a state by constructing an owned key tuple.
  - **`StateSet::remove(&mut self, entity_type: &str, selector_key: &str) -> Option<State>`**: Removes and returns the state for the given key. Uses `IndexMap::shift_remove` to preserve order of remaining elements.
  - **`StateSet::iter(&self) -> impl Iterator<Item = &State>`**: Returns `self.inner.values()`.
  - **`StateSet::len(&self) -> usize`**: Returns `self.inner.len()`.
  - **`StateSet::is_empty(&self) -> bool`**: Returns `self.inner.is_empty()`.
  - **`StateSet::entities(&self) -> Vec<(String, String)>`**: Returns `self.inner.keys().cloned().collect()`.
  - **`pub fn union(a: &StateSet, b: &StateSet) -> Result<StateSet, ConflictError>`**: Iterates the union of keys from both sets. For each key: if only in one set, clones the state into the result. If in both, performs per-field merge: iterates the union of field names; for fields only in one state, includes them; for fields in both, compares values — if equal, takes from `a`; if different, compares `state.priority` — higher priority wins; equal priority with different values adds to conflicts vec. After processing ALL entities/fields, if any conflicts exist, returns `Err(ConflictError)`. Otherwise constructs merged `State` objects with fresh `StateMetadata`, `policy_ref: None`, and `priority: max(a.priority, b.priority)`.
  - **`pub fn intersection(a: &StateSet, b: &StateSet) -> StateSet`**: For each key present in both `a` and `b`, iterates fields: includes only fields present in both states where `a_field.value == b_field.value`. Takes `FieldValue` from `a`. Constructs a new `State` with the intersecting fields, using `a`'s metadata/selector/priority. Excludes entities with zero intersecting fields from the result.
  - **`pub fn complement(a: &StateSet, b: &StateSet) -> StateSet`**: For each key in `a`: if not present in `b`, include the entire `State` from `a`. If present in `b`, include only fields whose name does NOT appear in `b`'s state for that entity. Constructs new `State` with remaining fields (using `a`'s metadata/selector/priority). Excludes entities with zero remaining fields.
- **Why**: This file implements the `StateSet` collection and the three set-algebraic operations required by the spec. Grouping them together reflects their tight coupling (all three operate on `StateSet`).

### 3. `crates/netfyr-state/src/diff.rs`
- **Action**: Create
- **What**:
  - **`DiffOp` enum**: Public enum with three variants:
    - `Add { entity_type: String, selector: Selector, fields: IndexMap<String, FieldValue> }` — entity in `to` but not `from`.
    - `Modify { entity_type: String, selector: Selector, changed_fields: IndexMap<String, FieldValue>, removed_fields: Vec<String> }` — entity in both but with differences.
    - `Remove { entity_type: String, selector: Selector }` — entity in `from` but not `to`.
    Derives `Clone, Debug, PartialEq`.
  - **`StateDiff` struct**: Public struct wrapping a private `ops: Vec<DiffOp>`. Derives `Clone, Debug, Default`.
  - **`StateDiff::ops(&self) -> &[DiffOp]`**: Returns a slice of the operations.
  - **`StateDiff::is_empty(&self) -> bool`**: Returns `self.ops.is_empty()`.
  - **`StateDiff::summary(&self) -> String`**: Counts the number of `Add`, `Modify`, and `Remove` ops and returns a string formatted as `"{n} added, {n} modified, {n} removed"`.
  - **`pub fn diff(from: &StateSet, to: &StateSet) -> StateDiff`**: Iterates all keys from both sets:
    - Key only in `to`: emits `DiffOp::Add` with that entity's fields.
    - Key only in `from`: emits `DiffOp::Remove` with that entity's selector.
    - Key in both: compares fields. `changed_fields` = fields in `to` that are either not in `from` or have a different `value`. `removed_fields` = field names in `from` that are not in `to`. If both are empty, no op is emitted. Otherwise emits `DiffOp::Modify`.
  - A private constructor or `From<Vec<DiffOp>>` impl to allow `diff()` to build a `StateDiff`.
- **Why**: Separates diff computation from set algebra. The `diff` function depends on `StateSet` (imports from `set.rs`), keeping the dependency direction clean (diff → set, not circular).

### 4. `crates/netfyr-state/src/lib.rs`
- **Action**: Modify
- **What**:
  - Add `pub mod set;` and `pub mod diff;` declarations after the existing imports.
  - Add re-exports for all new public types and functions:
    ```
    pub use set::{StateSet, Conflict, ConflictError, union, intersection, complement};
    pub use diff::{StateDiff, DiffOp, diff};
    ```
- **Why**: Makes the new types available at the crate root (`netfyr_state::StateSet`, etc.) as the spec requires.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `thiserror` | `"1"` | Derive macro for `ConflictError`'s `Error` and `Display` impls. The alternative is hand-writing `impl Display` and `impl Error` — `thiserror` is more concise and idiomatic for structured error types. The spec explicitly requires this dependency. |

No other new dependencies are needed. `indexmap` and `serde` are already present in `Cargo.toml`.

## Implementation Order

1. **Add `thiserror` dependency to `Cargo.toml`.**
   No code depends on this yet, but it must be present before `set.rs` can compile. After this step the crate compiles with no changes to source.

2. **Create `src/set.rs` with types only (`Conflict`, `ConflictError`, `StateSet` struct and its inherent methods).**
   Do NOT implement the three free functions yet. This establishes the core data structures. Add `pub mod set;` to `lib.rs` at this point. The crate should compile after this step.

3. **Implement `union` in `src/set.rs`.**
   Depends on step 2 for `StateSet`, `Conflict`, and `ConflictError`. Requires understanding of `State.priority` and `FieldValue.value` equality (both available from `lib.rs`). The crate should compile.

4. **Implement `intersection` and `complement` in `src/set.rs`.**
   Depends on step 2 for `StateSet`. Simpler than `union` (no error path). Can be done together since they don't depend on each other. The crate should compile.

5. **Create `src/diff.rs` with `DiffOp`, `StateDiff`, and the `diff` function.**
   Depends on step 2 for `StateSet` (imported from `super::set`). Add `pub mod diff;` to `lib.rs`. The crate should compile.

6. **Add re-exports to `lib.rs`.**
   All public types and functions from `set.rs` and `diff.rs` are re-exported at the crate root. The crate should compile and `cargo doc` should show the new types.

7. **Run `cargo check` and `cargo test` to verify everything compiles and existing tests still pass.**

## Risks and Mitigations

1. **Risk**: `IndexMap` key lookup with `&str` pairs.
   - **Detail**: `IndexMap<(String, String), State>` doesn't natively support `.get(&("foo", "bar"))` where the arguments are `&str`. The `get` method requires the key type to implement `Equivalent<(String, String)>`.
   - **Mitigation**: Construct owned `(String, String)` keys in `get()` and `remove()`. The allocation cost is negligible for configuration-sized data. Alternatively, if `indexmap` 2.x supports `Equivalent` for `(&str, &str)` via its `equivalent` feature, use that — but owned keys are simpler and guaranteed to work.

2. **Risk**: `Value` equality is order-sensitive for `Map` and `List` variants.
   - **Detail**: Two `IndexMap`s with the same key-value pairs in different insertion order compare as unequal under `PartialEq`. This affects `intersection` (which requires value equality) and `union` (same-value check).
   - **Mitigation**: Accept this behavior as correct. The spec doesn't require order-insensitive comparison, and `IndexMap`'s ordered semantics are intentional (it's used for deterministic serialization). Document this in code comments.

3. **Risk**: `union` must not short-circuit — must collect all conflicts.
   - **Detail**: A naive implementation might return `Err` on the first conflict, but the spec requires all conflicts to be reported.
   - **Mitigation**: Accumulate conflicts in a `Vec<Conflict>` during the full iteration. Only check the vec after processing all entities and fields. The implementation plan above explicitly calls this out.

4. **Risk**: Constructing merged `State` in `union` requires fresh `StateMetadata`.
   - **Detail**: `StateMetadata::new()` generates UUIDs and timestamps, which is appropriate for merged entities but means the result is not deterministic across runs (UUIDs differ each time).
   - **Mitigation**: This is acceptable and correct — merged states ARE new entities. Tests that check `union` results should compare fields, entity_type, selector, and priority, NOT metadata UUIDs.

5. **Risk**: `diff` comparing `FieldValue` — should it compare the whole `FieldValue` (including provenance) or just `value`?
   - **Detail**: The spec says `diff` detects "fields with different values" and "fields in `from` but not in `to`". The word "values" suggests comparing `FieldValue.value`, not the full `FieldValue` including provenance.
   - **Mitigation**: Compare `FieldValue.value` only for determining whether a field has changed. A field whose `value` is the same but `provenance` differs is NOT a change — provenance is metadata about origin, not the configuration itself. This matches the reconciliation use case: the backend only cares about value changes, not which policy contributed a field.

6. **Risk**: `complement` semantics are field-name-only, which may surprise callers.
   - **Detail**: A field present in both `a` and `b` with different values is still excluded from the complement (because it "exists in b" by name).
   - **Mitigation**: This is the spec-mandated behavior and is correct for the deletion-detection use case. Document it clearly in the function's doc comment.

7. **Risk**: `Selector` and `State` need `Clone` for constructing result sets — verified that both derive `Clone` already.
   - **Mitigation**: No action needed; just confirmed.

## Test Strategy

Tests should be placed in `#[cfg(test)] mod tests` blocks within each new file (`set.rs` and `diff.rs`), following the existing pattern in `lib.rs`.

### Test infrastructure needed
- A helper function to quickly build a `State` for testing, e.g., `fn make_state(entity_type: &str, name: &str, fields: Vec<(&str, Value)>, priority: u32) -> State`. This avoids verbose `State` construction in every test. Place this helper in the `tests` module of `set.rs` (and re-use via `use super::*` in `diff.rs` tests, or duplicate the helper since tests are module-private).

### `StateSet` CRUD tests (in `set.rs`)
- Insert a state and retrieve it with `get()` — verify entity_type, selector, fields match.
- `len()` returns 1 after one insert, 0 when empty.
- `is_empty()` returns true for new set, false after insert.
- Insert two states with the same key — second replaces first, `len()` remains 1, `get()` returns the second state's fields.
- `remove()` returns `Some(state)` for existing key, `None` for missing key. `len()` decreases.
- `entities()` returns correct `(entity_type, selector_key)` pairs.
- `iter()` yields all inserted states.

### `union` tests (in `set.rs`)
- Disjoint entities: both present in result with original fields.
- Same entity, disjoint fields: merged state has all fields.
- Same entity, same field, same value, same priority: succeeds, field included.
- Same entity, same field, different value, different priority: higher-priority field wins.
- Same entity, same field, different value, same priority: returns `ConflictError` with correct `Conflict` details.
- Multiple conflicts across different entities/fields: all conflicts reported in the error.
- One set empty: result equals the other set (structurally).

### `intersection` tests (in `set.rs`)
- Overlapping entity, some fields with same value, some with different: only same-value fields included.
- Disjoint entities: result is empty.
- Entity where no fields have matching values: entity excluded from result.
- Identical states: all fields included.

### `complement` tests (in `set.rs`)
- Entity in `a` with some fields also in `b`: only non-overlapping fields remain.
- Entity in `a` but not in `b`: entire entity included.
- Identical sets: result is empty.
- Entity in `a` where all fields appear in `b`: entity excluded from result.
- Field with same name but different value in `b`: field still excluded (name-only check).

### `diff` tests (in `diff.rs`)
- Empty `from`, non-empty `to`: all ops are `Add`.
- Non-empty `from`, empty `to`: all ops are `Remove`.
- Same entity with changed field values: `Modify` with `changed_fields`.
- Same entity with removed fields: `Modify` with `removed_fields`.
- Same entity with both added and removed fields: single `Modify` op.
- Identical sets: `is_empty()` returns true, no ops.
- Mixed adds, modifies, removes: `summary()` returns correct counts.
- `summary()` format: `"{n} added, {n} modified, {n} removed"`.
