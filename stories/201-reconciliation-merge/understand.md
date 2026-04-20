# SPEC-201: Reconciliation Engine — Per-Field Priority Merge
## Gap Analysis

---

## Current State

### `netfyr-reconcile` crate
- `crates/netfyr-reconcile/src/lib.rs` — exists but is empty (one doc comment line).
- `Cargo.toml` — exists with no dependencies declared.
- No `engine.rs`, `merge.rs`, or any other source files.

### `netfyr-policy` crate
- `crates/netfyr-policy/src/lib.rs` — empty stub.
- No `PolicyId` type defined anywhere in the workspace.

### `netfyr-state` crate (fully implemented — relevant to this story)
- `State` struct: `entity_type: String`, `selector: Selector`, `fields: IndexMap<String, FieldValue>`, `metadata: StateMetadata`, `policy_ref: Option<String>`, `priority: u32`.
- `FieldValue`: `{ value: Value, provenance: Provenance }`.
- `Selector`: keyed by `selector.key()` which produces a stable `String` (name when set, otherwise a deterministic encoding of other fields). MAC addresses are stored as `[u8; 6]`, making comparison inherently case-insensitive.
- `StateSet`: `IndexMap<(String, String), State>` — keyed by `(entity_type, selector.key())`.
- `StateSet::iter()`, `entities()`, `get()`, `insert()`, `remove()`, `len()`, `is_empty()` — all available.
- `set::union` / `intersection` / `complement` — implemented with per-field priority logic. `union` already performs priority-based field merging between two `StateSet`s but uses `State.priority` (a single priority per entity, not per policy input).

### `netfyr-backend` crate (irrelevant to this story)
- `ApplyReport`, `DryRunReport`, `BackendRegistry` — not consumed by the reconcile engine.

### Tests
- No tests exist in `netfyr-reconcile`.
- Comprehensive unit tests exist in `netfyr-state` for `StateSet`, `union`, `intersection`, `complement`, `Selector`, `Value`, and `State` types.

---

## Requirements

### Types to create

1. **`PolicyId`** — a newtype or type alias for a policy identifier string. Must be `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash` (needed as map key). Location: `src/engine.rs` (or potentially `netfyr-policy`, but the spec says `netfyr-reconcile` with no cross-crate dependency added; defining it locally in `netfyr-reconcile` is consistent with the spec's "no external crate dependencies" statement).

2. **`EntityKey`** — a tuple type `(EntityType, String)` i.e. `(entity_type, selector.key())` used as the key in `field_sources`. The spec calls this a "tuple of `(EntityType, Selector)`" but since `Selector` is not `Hash`/`Eq`, the key must be the canonical `(entity_type, selector_key_string)` pair. Must be `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`.

3. **`FieldName`** — type alias for `String`.

4. **`PolicyInput`** (`src/engine.rs`):
   ```rust
   pub struct PolicyInput {
       pub policy_id: PolicyId,
       pub priority: u32,
       pub state_set: StateSet,
   }
   ```

5. **`ReconciliationResult`** (`src/engine.rs`):
   ```rust
   pub struct ReconciliationResult {
       pub effective_state: StateSet,
       pub field_sources: HashMap<(EntityKey, FieldName), PolicyId>,
       pub conflicts: ConflictReport,  // from SPEC-202; placeholder needed
   }
   ```
   The `ConflictReport` type is referenced but defined in SPEC-202. This story must decide how to handle the dependency: either define a placeholder `ConflictReport` struct in `netfyr-reconcile` or leave `conflicts` as an empty/unit type until SPEC-202 lands.

6. **`ConflictReport`** — a placeholder type that will be extended by SPEC-202. At minimum it must be constructible (empty) for this story's acceptance criteria, which only check "no conflict is reported."

### Functions to create

7. **`fn merge(inputs: Vec<PolicyInput>) -> ReconciliationResult`** (`src/merge.rs`) — the core merge algorithm as described in the spec.

### Module structure to create
- `src/engine.rs` — `PolicyInput`, `ReconciliationResult`, `EntityKey`, `PolicyId`, `FieldName`, `ConflictReport`.
- `src/merge.rs` — `fn merge(inputs: Vec<PolicyInput>) -> ReconciliationResult`.
- `src/lib.rs` — `pub mod engine; pub mod merge;` with re-exports.

### `Cargo.toml` changes
- Add `netfyr-state = { path = "../netfyr-state" }` as a dependency.
- The spec says "no external crate dependencies," but `indexmap` and `std::collections::HashMap` are needed. `indexmap` is a transitive dependency via `netfyr-state`; it must be added explicitly to `netfyr-reconcile/Cargo.toml` if used directly in `merge.rs`.

### Tests to create
- Unit tests for all 9 Gherkin acceptance scenarios directly in `src/merge.rs` or a `tests/` module.

---

## Gap Analysis

| Item | Status | Action Required |
|---|---|---|
| `netfyr-reconcile/src/lib.rs` | Stub only | Replace with `pub mod engine; pub mod merge;` and re-exports |
| `netfyr-reconcile/src/engine.rs` | Missing | Create: `PolicyId`, `EntityKey`, `FieldName`, `PolicyInput`, `ReconciliationResult`, `ConflictReport` |
| `netfyr-reconcile/src/merge.rs` | Missing | Create: `fn merge(inputs: Vec<PolicyInput>) -> ReconciliationResult` with full algorithm |
| `netfyr-reconcile/Cargo.toml` | Missing dependency | Add `netfyr-state` dependency; add `indexmap` if used directly |
| `PolicyId` type | Missing (no definition anywhere in workspace) | Define in `src/engine.rs` |
| `ConflictReport` type | Missing (belongs to SPEC-202) | Define a minimal placeholder in `src/engine.rs` |
| Tests for merge scenarios | Missing | Add inside `src/merge.rs` `#[cfg(test)]` block |

---

## Integration Points

### `netfyr-state` types consumed by the merge engine
- `StateSet` — input and output container; accessed via `.iter()` and `.insert()`.
- `State` — iterated to extract fields; a new `State` is constructed per entity for the effective result.
- `FieldValue` — cloned wholesale as the winning value; the `provenance` field is preserved from the winning policy's `FieldValue`.
- `Selector` — used only to re-create the effective `State`; `selector.key()` produces the `EntityKey`'s second component.
- `StateMetadata` — the effective `State` will need fresh metadata (`StateMetadata::new()`), since it is a merged logical entity.
- `EntityType` (`String`) — first component of `EntityKey`.
- `Provenance` — not modified by the merge engine; carried through from the winning `FieldValue`.

### Key behavioral notes from existing `set::union`
The existing `set::union` already implements per-field priority merge between two `StateSet`s using `State.priority`. The new `merge` function in `netfyr-reconcile` differs in that:
- It takes `Vec<PolicyInput>` (N policies, each with explicit `priority: u32` and `policy_id`) rather than two `StateSet`s.
- Priority is supplied at the `PolicyInput` level (not `State.priority`), so all `State`s from a given `PolicyInput` share one priority.
- It produces `field_sources` tracking which `PolicyId` won each field.
- It handles N-way merges (not just 2-way).

The `merge` function **does not reuse `set::union`** as a building block — it implements its own N-way traversal to correctly track per-field winners and populate `field_sources`.

### Future integration (not in scope for this story)
- `netfyr-cli` — will call `merge` during `netfyr apply`.
- `netfyr-daemon` — will call `merge` when policies change.
- SPEC-202 (`ConflictReport`) — will extend the `conflicts` field of `ReconciliationResult`.

---

## Risks

1. **`PolicyId` location ambiguity.** The spec says `PolicyId` is a type but does not define which crate owns it. If `netfyr-policy` is intended to own `PolicyId` eventually, defining it there now would require `netfyr-reconcile` to depend on `netfyr-policy`. The spec says `netfyr-reconcile` has no external crate dependencies (only `netfyr-state`), so `PolicyId` must be defined within `netfyr-reconcile` itself for now, or `netfyr-policy` must be listed as an allowed dependency.

2. **`ConflictReport` forward dependency on SPEC-202.** `ReconciliationResult` references `ConflictReport` which is defined in SPEC-202. The implementation must either: (a) define a minimal stub `ConflictReport { conflicts: Vec<...> }` in this story, or (b) define the full type preemptively. The acceptance criteria for this story only require verifying that no conflict is reported; a minimal stub suffices.

3. **N-way priority tie-breaking.** The spec says "if multiple policies share the highest priority and provide the same value: that value wins (no conflict)." The acceptance criteria cover the same-value case (Scenario 7). The merge algorithm must correctly handle N > 2 policies at equal priority with the same value without treating it as a conflict.

4. **Effective `State.priority` value.** When constructing the merged `State` in the `effective_state`, what value should `State.priority` carry? The spec does not address this directly. The existing `set::union` uses `max(a.priority, b.priority)`; the same convention is reasonable but needs a decision.

5. **`Selector` normalization.** The spec mentions "selectors must be compared canonically." `Selector::key()` already handles MAC case-insensitivity (bytes stored, not strings) and name trimming is not done — names are stored as-is from user input. Whitespace-trimmed names are an open edge case not currently enforced anywhere in `netfyr-state`.

6. **`field_sources` key type.** The spec calls `EntityKey` "a tuple of `(EntityType, Selector)`" but `Selector` is not `Hash` or `Eq`, so it cannot be used as a `HashMap` key directly. The key must be `(String, String)` i.e. `(entity_type, selector.key())`. This is a straightforward resolution but may need a distinct named type to make the API self-documenting.

7. **`StateSet` internal field is private.** The merge function must iterate each `PolicyInput`'s `StateSet` using the public `iter()` API (which yields `&State`), then access `state.fields` (public field on `State`). All required fields are public, so no access issues exist.
