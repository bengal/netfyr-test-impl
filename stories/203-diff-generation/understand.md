# Understand: SPEC-203 Diff Generation Between Desired and Actual State

## Current State

Both target files (`crates/netfyr-reconcile/src/diff.rs` and `crates/netfyr-reconcile/src/report.rs`) already exist and are substantially implemented. The previous understand.md was written before those files were created.

### `crates/netfyr-reconcile/src/diff.rs` — exists, partially complete

All core types match the spec exactly:
- `DiffKind` — `Add`, `Remove`, `Modify`
- `FieldChangeKind` — `Set { current: Option<FieldValue>, desired: FieldValue }`, `Unset { current: FieldValue }`, `Unchanged { value: FieldValue }`
- `FieldChange { field_name: FieldName, change: FieldChangeKind }`
- `DiffOperation { kind, entity_type, selector, field_changes }`
- `StateDiff { operations: Vec<DiffOperation> }` with `is_empty()`, `len()`, `additions()`, `removals()`, `modifications()`

`generate_diff` is implemented with the two-pass algorithm. **Current signature:**
```rust
pub fn generate_diff(desired: &StateSet, actual: &StateSet, schema: &SchemaRegistry) -> StateDiff
```

**The spec requires:**
```rust
pub fn generate_diff(desired: &StateSet, actual: &StateSet, managed_entities: &HashSet<EntityKey>) -> StateDiff
```

This is the central divergence. Pass 1 (desired entities) correctly handles Add and Modify with per-field logic. Pass 2 (actual entities absent from desired) generates Remove for **all** such entities — no managed-entity filtering exists yet. Read-only field exclusion (carrier, speed, mac) for Modify operations is implemented via the schema parameter.

Existing tests cover: Add, Remove, Modify, field-added-to-existing, field-removed-from-existing, identical-states-no-op, empty-actual, empty-desired, read-only exclusion, diff accessor filtering, unknown entity type treatment.

### `crates/netfyr-reconcile/src/report.rs` — exists, fully matches spec

`DiffReport` is complete and matches the spec precisely:
- Fields: `operations: Vec<DiffOperation>`, `unchanged_entities: Vec<EntityKey>`
- `new(diff: StateDiff, desired: &StateSet, actual: &StateSet)` — computes `unchanged_entities` from set intersection minus operated keys, sorted
- `is_empty()`, `format_text()`, `format_yaml()`, `format_json()` — all implemented

All formatting scenarios from the spec are tested: `+`/`-`/`~` prefixes, `→` arrow, 4-space unchanged context, `No changes:` footer.

### `crates/netfyr-daemon/src/reconciler.rs` — calls `generate_diff` with schema

`Reconciler::dry_run` currently calls:
```rust
generate_diff(&effective_state, &actual_state, &self.schema_registry)
```
It does not compute or pass a `managed_entities` set. `Reconciler::reconcile_and_apply` uses `netfyr_state::diff::diff` (the lean backend diff) — not affected.

---

## Requirements

Breaking the spec's acceptance criteria into concrete technical requirements:

1. **`managed_entities` parameter on `generate_diff`**: replace `schema: &SchemaRegistry` with `managed_entities: &HashSet<EntityKey>`.

2. **Remove filtering in Pass 2**: skip Remove generation if the entity's `(entity_type, selector.key())` is not in `managed_entities`. Unmanaged entities produce no operation and do not appear in `unchanged_entities`.

3. **Read-only field exclusion must be preserved** for Modify operations: fields in actual not in desired that are schema-read-only must not generate Unset changes. The mechanism must be determined since schema is being removed from the signature.

4. **New test scenarios** (entirely absent from current test suite):
   - Unmanaged entity in actual → no operation, not in `unchanged_entities`
   - Managed entity in actual absent from desired → Remove
   - Empty desired with mixed managed/unmanaged actual → only managed become Remove
   - Explicit managed_entities in the multi-entity mixed-operations scenario

5. **Existing tests that contradict the spec** must be updated to pass a `managed_entities` set:
   - `test_remove_entity_in_actual_not_in_desired_generates_remove_operation`
   - `test_remove_operation_unsets_all_fields_with_current_value`
   - `test_empty_desired_produces_remove_operations_for_all_actual`
   - `test_multiple_entities_with_mixed_operations_produces_three_ops`
   - `test_multiple_entities_correct_selectors_per_operation_kind`
   - `test_diff_accessors_filter_by_operation_kind_with_2_add_1_modify_1_remove`

6. **Reconciler caller update**: `reconciler.rs::dry_run` must compute `managed_entities` from `PolicyInput` state sets and pass it to `generate_diff`.

7. **`DiffReport` requires no changes** — already matches the spec exactly.

---

## Gap Analysis

### `crates/netfyr-reconcile/src/diff.rs`

| Item | Current | Required |
|---|---|---|
| `generate_diff` signature | `(desired, actual, schema: &SchemaRegistry)` | `(desired, actual, managed_entities: &HashSet<EntityKey>)` |
| Pass 2 Remove guard | None — removes all actual-only entities | Skip if entity key not in `managed_entities` |
| Read-only field handling | `schema.field_info(entity_type, field_name)` | Mechanism TBD (see Risks) |
| `use` import | `use netfyr_state::{FieldValue, SchemaRegistry, Selector, StateSet}` | Replace `SchemaRegistry` with `std::collections::HashSet`; add `crate::EntityKey` |
| Test: Remove scenarios | Schema-based, no managed filter | Must add `managed_entities` set to each Remove test |
| Test: Unmanaged entity | Missing | Must add |
| Test: Mixed managed/unmanaged actual | Missing | Must add |

### `crates/netfyr-reconcile/src/report.rs`

No changes needed. All types, constructors, formatters, and tests match the spec exactly.

### `crates/netfyr-daemon/src/reconciler.rs`

`Reconciler::dry_run` must:
1. Collect `managed_entities: HashSet<EntityKey>` by iterating all `PolicyInput.state_set` items and extracting `(entity_type, selector.key())` pairs.
2. Pass `&managed_entities` to `generate_diff` in place of `&self.schema_registry`.

No other callers of `generate_diff` exist in the codebase.

---

## Integration Points

- **`netfyr_state::StateSet::entities()`** — used by `generate_diff` to enumerate entities. No change.
- **`netfyr_state::SchemaRegistry`** — currently used inside `generate_diff` for read-only field checking; its role after the signature change depends on resolution of Risk #1.
- **`netfyr_reconcile::lib.rs` re-exports** — `pub use diff::{generate_diff, ...}` exposes the updated signature. The daemon is the only caller.
- **`netfyr_varlink/src/types.rs`** — `VarlinkStateDiff` wraps `ReconcileStateDiff` (aliased from `netfyr_reconcile::StateDiff`). `StateDiff.operations` field does not change; no structural update needed.
- **`netfyr_backend::BackendRegistry::apply`** — takes `&netfyr_state::StateDiff` (the lean diff). Not affected; `reconcile_and_apply` uses `netfyr_state::diff::diff`, not `generate_diff`.

---

## Risks

### 1. Read-only field exclusion after schema removal (high impact, must resolve)

The current `generate_diff` Pass 1 uses `schema.field_info(entity_type, field_name).map(|i| !i.writable)` to skip Unset changes for read-only fields in Modify operations. The spec replaces the schema parameter with `managed_entities`. The spec's edge case still requires this exclusion ("Read-only fields in actual but not in desired: excluded from diff").

Without schema, the two viable options are:

**Option A** — Keep schema alongside managed_entities: signature becomes `(desired, actual, managed_entities, schema)`. Schema handles read-only; managed_entities handles Remove filtering. Matches current behavior most closely.

**Option B** — Remove schema; rely on the invariant that the policy/factory layer never populates read-only fields in desired state. Under this invariant, Pass 1's Modify path only generates Unset for fields present in actual but absent from desired — and if desired state never contains carrier/speed/mac, no Unset is generated for them. This requires verifying the invariant holds throughout the pipeline.

The existing read-only tests use `SchemaRegistry::new()` (which must load ethernet schemas via `Default` for those tests to pass). If schema is removed entirely, those tests must be rewritten to verify the invariant-based approach instead.

### 2. Existing Remove tests assert unconditional Remove behavior

Six existing tests pass no managed_entities set because the current implementation has no filter. After the signature change, these tests must be updated to include the tested entities in `managed_entities`. None of these tests are testing wrong behavior — they test the simpler pre-filter version and will simply need the new parameter threaded through.

### 3. `managed_entities` computation scope for factory policies

The spec states: "a policy may manage an entity before it produces any state (e.g., a DHCPv4 factory that hasn't acquired a lease yet)." Computing managed_entities from `PolicyInput.state_set` items (as done in the reconciler's `build_policy_inputs`) only captures entities where state has already been produced. Factory policies targeting entities by selector before lease acquisition would not appear. This may be out of scope for this story but is worth flagging for the reconciler update.

### 4. `HashSet<EntityKey>` import

`diff.rs` must import `std::collections::HashSet` and use `crate::EntityKey` (defined in `lib.rs` as `(String, String)`). The `EntityKey` type is already accessible within the crate.

### 5. Value equality for list fields

The current `generate_diff` uses strict `PartialEq` for field value comparison (order-sensitive for lists). The conflict detection code uses order-insensitive comparison. The spec does not specify which to use for diffing. Order-sensitive is conservative (may generate spurious Modify for reordered address lists) but consistent with the current implementation. No change is required unless the spec clarifies otherwise.
