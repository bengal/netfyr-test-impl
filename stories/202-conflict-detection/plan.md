# Plan: SPEC-202 — Conflict Detection During Reconciliation

## Approach

The `netfyr-reconcile` crate already has a working merge algorithm with rudimentary conflict detection — it finds same-priority disagreements, records them as `FieldConflict`, and omits conflicted fields from the effective state. The core merge logic is correct. What's needed is (1) reshaping the conflict types to match the spec (adding `priority`, switching from raw `(PolicyId, Value)` tuples to typed `ConflictContribution` with full `FieldValue`, renaming `field` to `field_name`), (2) adding `by_entity()` and `summary()` to `ConflictReport`, (3) implementing order-insensitive list comparison for conflict detection, and (4) extracting these types into a dedicated `conflict.rs` module.

The design is a **refactor-and-extend** pattern rather than a ground-up rewrite. The merge algorithm in `lib.rs` stays in place with surgical modifications to its Phase 2 conflict-recording path. The new types live in `conflict.rs` and are re-exported from `lib.rs`, replacing the inline `FieldConflict` and `ConflictReport`. This avoids unnecessary churn in the merge logic while achieving the spec's type signatures.

An alternative would be to keep everything in `lib.rs` and just rename/extend the existing types in-place. The spec explicitly requires `src/conflict.rs`, so that alternative is ruled out. Another alternative would be to move the merge algorithm itself into a separate module, but the spec doesn't call for this and it would increase the diff surface without benefit.

## Design Decisions

1. **Decision**: Extract conflict types to `src/conflict.rs`, remove `FieldConflict` and `ConflictReport` from `lib.rs`, re-export from `conflict.rs`.
   - **Alternatives considered**: Keep types inline in `lib.rs` and just rename them.
   - **Rationale**: Spec explicitly mandates `src/conflict.rs`. Separating concerns is also good practice — the conflict module has its own display logic (`summary()`) that would clutter `lib.rs`.

2. **Decision**: The new `Conflict` type replaces `FieldConflict` entirely. `FieldConflict` is removed, not kept alongside.
   - **Alternatives considered**: Keep `FieldConflict` as a deprecated alias.
   - **Rationale**: No downstream consumers exist (CLI/daemon are stubs). Clean replacement avoids confusion. The two tests that reference `FieldConflict` fields will be updated.

3. **Decision**: `ConflictContribution.value` stores `FieldValue` (not `Value`), preserving provenance.
   - **Alternatives considered**: Store just `Value` as the current code does.
   - **Rationale**: Spec explicitly says `pub value: FieldValue`. Provenance data is already available in the merge contender tuples, so this is a mechanical change. Richer data in the contribution enables future features (e.g., showing which policy configured vs. discovered the value).

4. **Decision**: Order-insensitive list comparison implemented as a standalone helper function `values_equal_for_conflict(a: &Value, b: &Value) -> bool` in `conflict.rs`.
   - **Alternatives considered**: (a) Implement a custom `PartialEq` on `Value` — rejected because it would change equality semantics everywhere, breaking other code. (b) Add the helper inline in the merge function — rejected because it's logically a conflict-detection concern and testable in isolation.
   - **Rationale**: The helper is used in exactly one place (the `all_agree` check in merge Phase 2). Putting it in `conflict.rs` keeps the merge algorithm clean and makes the function independently testable. For `Value::List`, the function sorts cloned elements by their `Display` representation and compares. For all other variants, it delegates to `PartialEq`.

5. **Decision**: List set-comparison sorts by `Display` representation of each element.
   - **Alternatives considered**: (a) Use `Hash` — `Value` doesn't implement `Hash` and adding it would require `Hash` on `IpNetwork`, `IndexMap`, etc. (b) Use `PartialOrd` — `Value` doesn't implement it and floating-point-like semantics make it tricky. (c) Sort by debug representation — `Display` is already implemented and produces deterministic, human-readable output for all variants.
   - **Rationale**: `Display` is the simplest available total ordering proxy. All `Value` variants implement `Display`. For conflict detection purposes, two elements that have the same `Display` representation are the same value (this is already true given the `Value` enum structure — no two distinct values share a display string). Sorting and comparing the sorted vecs is O(n log n) which is fine for the small lists in network config.

6. **Decision**: `by_entity()` returns `HashMap<EntityKey, Vec<&Conflict>>` (borrows from `self`).
   - **Alternatives considered**: Return owned `HashMap<EntityKey, Vec<Conflict>>` with clones.
   - **Rationale**: Spec defines the signature with `&Conflict`. Borrowing avoids unnecessary cloning. The lifetime is straightforward — it's bounded by `&self`.

7. **Decision**: `summary()` output format matches the spec's illustrative example closely, grouping by entity type + selector name.
   - **Alternatives considered**: Flat list without grouping.
   - **Rationale**: The spec shows a grouped format under `CONFLICTS:` with entity headers. The acceptance criteria require entity, field, policy names, and values to appear. Matching the spec example provides the best user experience.

8. **Decision**: `ConflictReport` keeps `#[derive(Clone, Debug, Default)]` and the `conflicts` field remains `pub`.
   - **Alternatives considered**: Make `conflicts` private with accessor methods.
   - **Rationale**: Existing tests and the `ReconciliationResult` struct directly access `conflicts.conflicts`. Keeping it public maintains backward compatibility. The spec also shows `pub conflicts: Vec<Conflict>`.

## File Changes

### 1. `crates/netfyr-reconcile/src/conflict.rs` — CREATE

This new file contains the conflict types and display logic.

**Types:**

- `ConflictContribution` — struct with `pub policy_id: PolicyId` and `pub value: FieldValue`. Derives `Clone, Debug`.
- `Conflict` — struct with `pub entity_key: EntityKey`, `pub field_name: FieldName`, `pub priority: u32`, `pub contributions: Vec<ConflictContribution>`. Derives `Clone, Debug`.
- `ConflictReport` — struct with `pub conflicts: Vec<Conflict>`. Derives `Clone, Debug, Default`.

**Methods on `ConflictReport`:**

- `pub fn new() -> Self` — returns `Self::default()`.
- `pub fn is_empty(&self) -> bool` — delegates to `self.conflicts.is_empty()`.
- `pub fn len(&self) -> usize` — delegates to `self.conflicts.len()`.
- `pub fn by_entity(&self) -> HashMap<EntityKey, Vec<&Conflict>>` — iterates `self.conflicts`, groups by `entity_key` clone, collects references. Returns the map.
- `pub fn summary(&self) -> String` — produces a human-readable multi-line string. Uses `by_entity()` internally. Format:
  ```
  CONFLICTS:
    {entity_type} {selector_key}:
      {field_name}: policy "{policy_a}" sets {value_a}, policy "{policy_b}" sets {value_b} (both priority {priority})
  ```
  For 3+ contributions on a single field, list all of them comma-separated before the priority note. If no conflicts, returns an empty string.

**Free function:**

- `pub fn values_equal_for_conflict(a: &Value, b: &Value) -> bool` — conflict-aware equality. If both are `Value::List`, clones both vecs, sorts each by the `Display` representation of elements, then compares with `==`. Otherwise, uses standard `PartialEq` (`a == b`). This function is `pub` so it can be used from `lib.rs`'s merge algorithm and tested independently.

**Imports:**

- `use std::collections::HashMap;`
- `use netfyr_state::{FieldValue, Value};`
- `use crate::{EntityKey, FieldName, PolicyId};` (imports from parent module via `crate::`)

**Why:** The spec requires these types in `src/conflict.rs`. Separating them from the merge algorithm provides clean module boundaries and makes the display logic self-contained.

### 2. `crates/netfyr-reconcile/src/lib.rs` — MODIFY

**Changes:**

1. **Add module declaration**: Add `pub mod conflict;` near the top, alongside existing imports.

2. **Add re-exports**: Add `pub use conflict::{Conflict, ConflictContribution, ConflictReport, values_equal_for_conflict};`.

3. **Remove `FieldConflict`**: Delete the entire `FieldConflict` struct definition (lines 73-81) and its doc comment.

4. **Remove `ConflictReport`**: Delete the entire `ConflictReport` struct, its `impl` block, and the `Default` derive (lines 84-105). These are now in `conflict.rs`.

5. **Update merge Phase 2 conflict path** (around lines 233-244):
   - Change the `all_agree` check from `top.iter().all(|(_, _, fv)| &fv.value == first_value)` to `top.iter().all(|(_, _, fv)| values_equal_for_conflict(&fv.value, first_value))`. Import `values_equal_for_conflict` from the conflict module.
   - Change the conflict construction from building `Vec<(PolicyId, Value)>` contenders to building `Vec<ConflictContribution>`, storing the full `FieldValue` (not just `fv.value`).
   - Change `FieldConflict { entity_key, field, contenders }` to `Conflict { entity_key, field_name, priority: max_priority, contributions }`.
   - Update the `conflict_list` type from `Vec<FieldConflict>` to `Vec<Conflict>`.

6. **Update tests** (two tests need field name changes):
   - `test_same_priority_different_values_reports_conflict_and_omits_field` (line 674): Change `conflict.field` to `conflict.field_name`. Change `conflict.contenders.iter().map(|(_, v)| v)` to `conflict.contributions.iter().map(|c| &c.value.value)` (accessing the `Value` inside `FieldValue` inside `ConflictContribution`).
   - `test_field_sources_does_not_include_conflicted_fields` (line 716): This test doesn't access conflict fields directly — it only checks `field_sources` and `get_source`. Verify it compiles with the new types; no changes expected.

**Why:** The merge algorithm is the sole producer of conflict data. It must construct the new types. The old types are removed to avoid duplication.

## Dependencies

No new external crate dependencies are needed. The spec explicitly states "Dependencies (external crates): none." All required functionality (HashMap, String formatting, Vec sorting) is available in `std`. The `netfyr_state` crate already provides `FieldValue`, `Value`, `PolicyId` types.

## Implementation Order

1. **Create `crates/netfyr-reconcile/src/conflict.rs`** with `ConflictContribution`, `Conflict`, `ConflictReport` (with all methods), and `values_equal_for_conflict`. This file compiles independently — it only depends on `netfyr_state` types and the `EntityKey`/`FieldName`/`PolicyId` types from the parent `lib.rs` (accessed via `crate::`).

2. **Modify `crates/netfyr-reconcile/src/lib.rs`**:
   - Add `pub mod conflict;` and re-exports.
   - Remove `FieldConflict` and old `ConflictReport`.
   - Update the merge algorithm's conflict path to use new types and `values_equal_for_conflict`.
   - Update the two affected test functions.

   This must happen after step 1 because it imports from `conflict.rs`. After this step, `cargo check -p netfyr-reconcile` and `cargo test -p netfyr-reconcile` should both pass.

## Risks and Mitigations

1. **Risk: Breaking existing tests that access conflict internals.**
   - Two tests access `conflict.field` and `conflict.contenders`. These must be updated to `conflict.field_name` and `conflict.contributions` respectively, with the value access pattern changed from `(_, v)` tuple destructuring to `c.value.value` (FieldValue → Value).
   - **Mitigation**: The understanding analysis already identified exactly which tests and which lines need updating. The changes are mechanical renames.

2. **Risk: `values_equal_for_conflict` sort stability for list comparison.**
   - If two different `Value` variants produce the same `Display` output, the comparison could yield false equality. In practice, `Value::U64(1500)` displays as `"1500"` and `Value::String("1500")` displays as `"1500"`, so they would compare as equal.
   - **Mitigation**: This is acceptable because within a single field, all values should be the same type (enforced by schema validation). Cross-type comparison within a list is not a realistic scenario in network configuration. If it ever becomes a concern, the sort key can be changed to `format!("{:?}", elem)` (Debug representation, which includes the variant name). For now, `Display` is sufficient and matches the spec's intent.

3. **Risk: Name collision between `netfyr_reconcile::Conflict` and `netfyr_state::Conflict`.**
   - Both exist but are in different crates with different purposes. `netfyr_reconcile` does not import `netfyr_state::Conflict`.
   - **Mitigation**: Use explicit imports in `conflict.rs` — only import specific items from `netfyr_state`, never use glob imports.

4. **Risk: `by_entity()` cloning `EntityKey` for HashMap keys.**
   - `EntityKey` is `(String, String)`, so cloning it allocates. For the small number of conflicts expected in practice (single digits), this is negligible.
   - **Mitigation**: None needed. If performance ever matters, `EntityKey` could be interned, but that's premature optimization.

5. **Risk: `summary()` format not matching spec example exactly.**
   - The acceptance criteria only assert that entity, field, policy names, and values appear — not exact formatting.
   - **Mitigation**: Match the spec's illustrative format as closely as reasonable. Tests should assert on content presence (contains substrings) rather than exact string equality, giving flexibility for minor formatting tweaks.

6. **Risk: Merge algorithm's `first_value` reference used in `values_equal_for_conflict` when the winning list value could be in a different order than other agreeing lists.**
   - When `all_agree` is true for list fields, the "winner" value stored in the effective state is `top[0]`'s value (preserving its original order). This is correct — we just need the comparison to be order-insensitive, not the stored value.
   - **Mitigation**: No special handling needed. The stored value keeps its original order; only the equality check is order-insensitive.

## Test Strategy

Tests are needed at two levels:

### Unit tests for `conflict.rs`

- **`values_equal_for_conflict` function**:
  - Two identical scalar values → true
  - Two different scalar values → false
  - Two lists with same elements, same order → true
  - Two lists with same elements, different order → true (the key new behavior)
  - Two lists with different elements → false
  - Two lists with different lengths → false
  - Empty lists → true
  - Non-list values (maps, strings, numbers) → delegates to PartialEq correctly

- **`ConflictReport::by_entity()`**:
  - Empty report → empty HashMap
  - Multiple conflicts on same entity → grouped under one key
  - Conflicts on different entities → separate keys
  - Mixed: two fields on entity A, one field on entity B → correct grouping and counts

- **`ConflictReport::summary()`**:
  - Empty report → empty string (or "no conflicts" — match implementation choice)
  - Single conflict → output contains entity type, selector key, field name, both policy names, both values, priority
  - Multiple conflicts on same entity → grouped under one entity header
  - Three-way conflict → all three policy names and values appear

### Integration tests via `merge()` (in `lib.rs` tests)

These test the full merge pipeline with the new conflict types:

- **Three-way conflict**: 3 policies at same priority, different values → `Conflict` has 3 contributions, field excluded
- **Lower priority conflict irrelevant when higher priority exists**: policies at 100 disagree, policy at 200 wins → no conflict reported
- **List fields order-insensitive**: same addresses in different order → no conflict
- **List fields genuinely different**: different addresses → conflict reported
- **Multiple conflicts across entities**: 2 entities each with conflicting field → `len() == 2`
- **Conflict includes priority field**: verify `conflict.priority` equals the expected `max_priority`
- **ConflictContribution stores FieldValue**: verify `contribution.value` is a `FieldValue` with the expected inner `Value`

### Existing tests (must continue to pass)

All 12 existing tests in `lib.rs` must pass after the refactor. Two tests are updated with new field names; the other 10 are unchanged and serve as regression tests for the merge algorithm.

### Test infrastructure

No new test infrastructure (fixtures, mocks, helpers) is needed. The existing `fv()`, `make_state()`, and `make_input()` helpers are sufficient. New tests in `conflict.rs` can construct `Conflict` and `ConflictReport` values directly without going through the merge algorithm.
