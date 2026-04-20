# Gap Analysis: SPEC-202 — Conflict Detection During Reconciliation

## Current State

### `crates/netfyr-reconcile/src/lib.rs`

The reconcile crate already contains a working merge algorithm and partial conflict infrastructure:

**Conflict types (already exist, but differ from spec):**
- `FieldConflict` — represents one field-level conflict. Fields: `entity_key: EntityKey`, `field: FieldName`, `contenders: Vec<(PolicyId, Value)>`. Missing: `priority` field, no `ConflictContribution` newtype.
- `ConflictReport` — wraps `Vec<FieldConflict>` as `pub conflicts`. Has `new()`, `is_empty()`, `len()`. Missing: `by_entity()` and `summary()`.

**Merge algorithm (`fn merge`):**
- Phase 1 collects per-entity, per-field contenders as `Vec<(PolicyId, u32, FieldValue)>`.
- Phase 2 resolves each field: finds `max_priority`, filters to `top` tier, checks `all_agree` with `PartialEq` on `Value`. Unanimous ties take the first value; disagreements produce a `FieldConflict` and omit the field.
- **The `priority` captured during resolution is NOT stored in `FieldConflict`.**
- **`all_agree` uses `Value::PartialEq` which is order-sensitive for `Value::List`.**
- Conflict contenders store only `Value` (discarding `FieldValue` provenance).

**Tests (in the same file):**
- 12 existing tests covering the merge algorithm, including two tests that assert on conflict output: `test_same_priority_different_values_reports_conflict_and_omits_field` and `test_field_sources_does_not_include_conflicted_fields`. Both reference `conflict.field` and `conflict.contenders` — the current field names.

### `crates/netfyr-state/src/set.rs`

Contains its own unrelated `Conflict` and `ConflictError` types for the `union()` function. These are separate from reconcile-level conflict detection and are not consumed by `netfyr-reconcile`.

### `crates/netfyr-state/src/lib.rs`

Exports `Conflict` and `ConflictError` from `set.rs`. The `netfyr-reconcile` crate does **not** import these.

---

## Requirements

### New types in `src/conflict.rs`

1. **`ConflictContribution`** — typed pair replacing raw `(PolicyId, Value)` tuple:
   ```rust
   pub struct ConflictContribution {
       pub policy_id: PolicyId,
       pub value: FieldValue,   // full FieldValue, preserving provenance
   }
   ```

2. **`Conflict`** — replaces `FieldConflict`, adding `priority` and using `contributions`:
   ```rust
   pub struct Conflict {
       pub entity_key: EntityKey,
       pub field_name: FieldName,   // was `field`
       pub priority: u32,           // new: must be stored during merge
       pub contributions: Vec<ConflictContribution>,  // was `contenders: Vec<(PolicyId, Value)>`
   }
   ```

3. **`ConflictReport`** — extended with two new methods:
   ```rust
   pub fn by_entity(&self) -> HashMap<EntityKey, Vec<&Conflict>>;
   pub fn summary(&self) -> String;
   ```
   `summary()` must produce the display format shown in the spec (entity/selector grouping, field name, policy names, values, priority).

### Merge algorithm changes

4. **Store `max_priority` in each `Conflict`** — the `max_priority` value computed per-field during Phase 2 must be written into the new `Conflict` struct.

5. **Order-insensitive list comparison** — the `all_agree` check must be upgraded for `Value::List`: two list values are equal for conflict-detection purposes if they contain the same elements regardless of order. This requires a helper function (e.g., `values_equal_for_conflict`) distinct from `PartialEq`. Non-list values continue to use `PartialEq`.

6. **Store full `FieldValue` in contributions** — contenders currently store `fv.value.clone()` (stripping provenance). Must change to store the full `FieldValue` to populate `ConflictContribution::value`.

### Module wiring

7. `src/lib.rs` must declare `pub mod conflict` and re-export `Conflict`, `ConflictContribution`, `ConflictReport` from it. The existing inline definitions of `FieldConflict` and `ConflictReport` must be removed from `lib.rs`.

### Tests

8. All 12 existing tests in `lib.rs` must continue to pass. Two tests directly access conflict internals using current field names (`conflict.field`, `conflict.contenders`) and must be updated to use `conflict.field_name` and `conflict.contributions`.

9. New tests required for all acceptance criteria scenarios not already covered:
   - Three-way conflict with 3 contributions
   - Conflict at lower priority is irrelevant when higher priority exists
   - List fields: order-insensitive equality (no conflict for reordered list)
   - List fields: genuinely different lists → conflict
   - Multiple conflicts across different entities; `ConflictReport::len()` returns 2
   - `ConflictReport::summary()` produces readable output including entity, field, policy names, values
   - `ConflictReport::by_entity()` groups correctly (2 keys, correct per-key counts)
   - No-conflict case: `is_empty()` true, `len()` 0

---

## Gap Analysis

### Files to create

| File | What to create |
|---|---|
| `crates/netfyr-reconcile/src/conflict.rs` | `ConflictContribution`, `Conflict`, and the augmented `ConflictReport` (with `by_entity`, `summary`). |

### Files to modify

| File | What to change |
|---|---|
| `crates/netfyr-reconcile/src/lib.rs` | (1) Remove `FieldConflict` and the existing `ConflictReport` definitions. (2) Add `pub mod conflict` and import the new types. (3) Update merge Phase 2: pass `max_priority` into `Conflict`, store full `FieldValue` in contributions, and apply list-aware equality check. (4) Update two existing tests that reference `conflict.field` and `conflict.contenders`. |

### No changes required

- `crates/netfyr-state/` — no changes; `Conflict`/`ConflictError` in `set.rs` are for `union()` and are unrelated.
- `Cargo.toml` files — no new external dependencies per spec.
- `crates/netfyr-backend/`, `crates/netfyr-policy/`, `crates/netfyr-cli/`, `crates/netfyr-daemon/` — out of scope for this story.

---

## Integration Points

- **`netfyr_state::FieldValue`** — `ConflictContribution::value` holds a `FieldValue`; the merge algorithm already has `FieldValue` references in the contender tuples, so the provenance data is available without additional queries.
- **`PolicyId`, `EntityKey`, `FieldName`** — defined in `lib.rs`; `conflict.rs` must import them from the parent module or `super`.
- **`fn merge`** — the sole consumer that builds `ConflictReport`. No external callers of `merge` are visible in the codebase snapshot (daemon/cli crates are empty stubs), so the type change does not break any downstream caller today, but the public API changes to `Conflict` fields must be treated as a breaking change for any future consumer.
- **`ConflictReport` public API** — `is_empty()` and `len()` already exist with the correct signatures and must be preserved. `new()` and the `conflicts` field are also used in tests and must remain.

---

## Risks

1. **Name collision**: The new `Conflict` type in `netfyr-reconcile` has the same name as `netfyr_state::Conflict` (from `set.rs`). Since `netfyr-reconcile/src/lib.rs` does not currently import `netfyr_state::Conflict`, there is no immediate collision, but any future `use netfyr_state::*` import would create ambiguity. The `conflict.rs` module must use explicit imports to avoid this.

2. **List set-comparison semantics**: The spec requires order-insensitive comparison for `Value::List` fields only (e.g., `addresses`). `Value::Map` uses deep equality without order-insensitivity. The helper function must match exactly on variant: apply set logic only when both values are `Value::List`; fall through to `PartialEq` otherwise. Nested lists (lists of lists) are not addressed by the spec — the comparison should be shallow (sort outer elements only by their `Display` or hash representation).

3. **`ConflictContribution::value` type is `FieldValue`**: The spec defines `ConflictContribution.value` as `FieldValue`. The existing `contenders` in the merge result stored raw `Value`. The change requires passing the full `FieldValue` (including provenance) through, which is already present in the `FieldContenders` tuple as the third element. No data is lost — the fix is purely mechanical.

4. **`priority` field in `Conflict`**: The `max_priority` is computed locally in Phase 2 as a `let` binding. It needs to be captured into the `Conflict` struct. This is straightforward but the field did not exist in `FieldConflict`, so all test assertions that pattern-match or destructure the old struct need updating.

5. **`by_entity()` lifetime**: The return type `HashMap<EntityKey, Vec<&Conflict>>` borrows from `self`. The implementation must use `&self` lifetime correctly. No complexity beyond standard borrowing.

6. **`summary()` format**: The spec gives an illustrative display format but the acceptance criteria only test that entity, field name, policy names, and values all appear. The exact format (spacing, punctuation) is not asserted by tests. The implementation should match the spec's example format closely for user-facing consistency.

7. **Conflict lower-priority scenario edge case**: The spec explicitly states "conflict at lower priority tier does not matter when higher priority exists." The existing merge algorithm already handles this correctly (it filters `top` to `max_priority` before checking agreement), so no logic change is needed for this edge case — only a test is missing.
