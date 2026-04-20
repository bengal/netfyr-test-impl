# SPEC-201: Reconciliation Engine — Per-Field Priority Merge — Implementation Plan

## Approach

The reconciliation engine is a pure, synchronous function that takes N policy inputs, each providing a `StateSet` at a given priority, and produces a single merged `StateSet` plus a map tracking which policy contributed each winning field. This is an N-way generalization of the existing 2-way `set::union` in `netfyr-state`, but with two critical differences: (1) priority is per-`PolicyInput` rather than per-`State`, and (2) the engine tracks per-field provenance via a `field_sources` map that `set::union` does not produce.

The design uses a two-phase approach: **collect** then **resolve**. In the collect phase, we iterate every `PolicyInput`'s `StateSet`, grouping all `(policy_id, priority, field_name, field_value)` tuples by entity key `(entity_type, selector_key)`. In the resolve phase, we iterate each entity's collected fields, pick the winner for each field name by highest priority (with same-value tie resolution), build the merged `State`, and populate `field_sources`. This is implemented as a single `merge()` function in `src/merge.rs`.

Why not fold `set::union` N-1 times? Because `set::union` (a) uses `State.priority` rather than an external priority, (b) does not produce `field_sources`, (c) returns `Err` on equal-priority conflicts rather than collecting them, and (d) loses track of which original policy contributed each field after the first fold. A purpose-built N-way merge is simpler, more efficient (single pass), and directly produces all required outputs.

Why not reuse/extend `set::union`? Modifying `set::union` would change its public API in `netfyr-state` which is a foundational crate used by other stories. The reconcile engine is the correct layer for this higher-level operation.

## Design Decisions

1. **Decision**: Define `PolicyId` as a newtype `struct PolicyId(String)` in `netfyr-reconcile`, not in `netfyr-policy`.
   - **Alternatives**: Type alias `type PolicyId = String`; define in `netfyr-policy` and add it as a dependency.
   - **Rationale**: The spec says `netfyr-reconcile` has no external crate dependencies beyond `netfyr-state`. A newtype over `String` gives type safety (prevents mixing with arbitrary strings) and derives `Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd` for use as map keys. If `netfyr-policy` later defines its own `PolicyId`, we can either re-export it or migrate via a `From` impl — but that's a future story.

2. **Decision**: Define `EntityKey` as a type alias `type EntityKey = (String, String)` representing `(entity_type, selector.key())`, not a newtype struct.
   - **Alternatives**: Newtype struct `EntityKey { entity_type: String, selector_key: String }`.
   - **Rationale**: The spec calls it "a tuple of (EntityType, Selector)" and the existing `StateSet` already keys on `(String, String)`. A type alias is zero-overhead and aligns with `StateSet::entities()` return type. The tuple components are self-documenting in the context of `field_sources: HashMap<(EntityKey, FieldName), PolicyId>` where the outer tuple makes the two-level key explicit.

3. **Decision**: Define `FieldName` as `type FieldName = String`.
   - **Alternatives**: Newtype.
   - **Rationale**: Fields are plain strings everywhere in `netfyr-state` (`IndexMap<String, FieldValue>`). A type alias documents intent without adding conversion friction.

4. **Decision**: Define a minimal `ConflictReport` placeholder with `conflicts: Vec<FieldConflict>` and a `FieldConflict` struct that records the entity key, field name, and the conflicting `(PolicyId, Value)` pairs.
   - **Alternatives**: Empty unit struct `struct ConflictReport;`; full SPEC-202 implementation.
   - **Rationale**: The acceptance criteria require checking "no conflict is reported" and the spec's merge algorithm explicitly produces conflicts when multiple policies at the highest priority provide different values. A minimal but structurally correct type lets us implement the conflict-detection path of the merge algorithm (step 2b) and makes SPEC-202 an extension rather than a rewrite. The `FieldConflict` struct captures the essential information (entity, field, competing values with their policy sources) without prescribing SPEC-202's resolution strategy.

5. **Decision**: When constructing the merged `State` for the effective `StateSet`, set `priority` to the maximum priority among all contributing policies for that entity, and set `policy_ref` to `None`.
   - **Alternatives**: Use priority 0; use the priority of the "dominant" policy (most fields won).
   - **Rationale**: Consistent with existing `set::union` behavior (`max(a.priority, b.priority)`). `policy_ref = None` because the merged state is contributed by multiple policies — no single policy_ref is accurate. Provenance for individual fields is tracked in `field_sources`.

6. **Decision**: Set `Provenance` on each winning `FieldValue` to `Provenance::UserConfigured { policy_ref: policy_id.0.clone() }` — overwriting whatever provenance the original `FieldValue` carried.
   - **Alternatives**: Preserve the original `FieldValue`'s provenance unchanged.
   - **Rationale**: The provenance should reflect the reconciliation result. The winning field came from a specific policy, and `Provenance::UserConfigured` with the policy_id as the ref is the most accurate description. However, on reflection, the spec does not mandate provenance rewriting and the acceptance criteria do not test it. The safer choice is to **preserve the original provenance unchanged** — it was set by whatever produced the policy's `StateSet` (YAML loader, DHCP, etc.) and is more informative than overwriting. We'll go with preserving original provenance.

7. **Decision**: The `field_sources` key is `(EntityKey, FieldName)` which expands to `((String, String), String)`. When multiple policies at the same highest priority provide the same value, pick the first policy (by input order) for `field_sources` — this is deterministic and doesn't affect correctness since the values are identical.
   - **Alternatives**: Pick the last; pick alphabetically by policy_id.
   - **Rationale**: Input order is the simplest deterministic rule. The acceptance criteria for the same-value scenario only check "no conflict is reported," not which policy_id is recorded.

8. **Decision**: Use `std::collections::HashMap` for `field_sources` and internal working maps. Do not add `indexmap` as a direct dependency of `netfyr-reconcile`.
   - **Alternatives**: Use `IndexMap` everywhere for determinism; add `indexmap` dependency.
   - **Rationale**: `field_sources` is a lookup structure, not user-facing output — insertion order doesn't matter. The effective `StateSet` uses `IndexMap` internally (via `StateSet::insert`), so output determinism is preserved. Minimizing dependencies follows the spec's guidance.

9. **Decision**: `merge` is a free function `pub fn merge(inputs: Vec<PolicyInput>) -> ReconciliationResult`, not a method on a struct.
   - **Alternatives**: `ReconcileEngine` struct with `.merge()` method.
   - **Rationale**: The spec defines it as `fn merge(...)`. There's no state to carry between merge calls — it's a pure function. A struct would add needless complexity.

10. **Decision**: Use fresh `StateMetadata::new()` for each merged `State` in the effective `StateSet`.
    - **Alternatives**: Copy metadata from the highest-priority contributing state.
    - **Rationale**: Consistent with `set::union` behavior. The merged state is a new logical entity — it gets a new UUIDv7 id, timeline_id, and timestamp.

## File Changes

### `crates/netfyr-reconcile/Cargo.toml`
- **Action**: modify
- **What**: Add `netfyr-state = { path = "../netfyr-state" }` to `[dependencies]`.
- **Why**: The merge function operates on `StateSet`, `State`, `FieldValue`, `Value`, `Selector`, `StateMetadata`, and `Provenance` — all from `netfyr-state`.

### `crates/netfyr-reconcile/src/engine.rs`
- **Action**: create
- **What**: Core types for the reconciliation engine:
  - `PolicyId`: newtype `pub struct PolicyId(pub String)` deriving `Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord`. Implement `Display` (delegates to inner string), `From<String>`, `From<&str>`, and an `as_str(&self) -> &str` accessor.
  - `EntityKey`: type alias `pub type EntityKey = (String, String)` — `(entity_type, selector_key)`.
  - `FieldName`: type alias `pub type FieldName = String`.
  - `PolicyInput`: struct with `pub policy_id: PolicyId`, `pub priority: u32`, `pub state_set: StateSet`. Derive `Clone, Debug`.
  - `FieldConflict`: struct with `pub entity_key: EntityKey`, `pub field: FieldName`, `pub contenders: Vec<(PolicyId, Value)>` — lists all policies at the tied highest priority that provide different values. Derive `Clone, Debug`.
  - `ConflictReport`: struct with `pub conflicts: Vec<FieldConflict>`. Derive `Clone, Debug, Default`. Methods: `fn new() -> Self` (empty), `fn is_empty(&self) -> bool`, `fn len(&self) -> usize`.
  - `ReconciliationResult`: struct with `pub effective_state: StateSet`, `pub field_sources: HashMap<(EntityKey, FieldName), PolicyId>`, `pub conflicts: ConflictReport`. Derive `Clone, Debug`.
- **Why**: These types are the public API of the reconcile crate. They need to be in a dedicated module so `merge.rs` can import them and `lib.rs` can re-export them.

### `crates/netfyr-reconcile/src/merge.rs`
- **Action**: create
- **What**: The merge algorithm as a single public function:
  - `pub fn merge(inputs: Vec<PolicyInput>) -> ReconciliationResult`
  - Algorithm:
    1. If `inputs` is empty, return an empty `ReconciliationResult` immediately.
    2. Build an entity map: `HashMap<EntityKey, Vec<(PolicyId, u32, &State)>>` by iterating each `PolicyInput`'s `state_set.iter()` and keying by `(state.entity_type, state.selector.key())`. Each entry accumulates all (policy_id, priority, state_ref) tuples that target that entity.
    3. For each entity in the entity map:
       a. Collect all fields across all contributing states into a field map: `HashMap<FieldName, Vec<(PolicyId, u32, FieldValue)>>` — for each contributing `(policy_id, priority, state)`, iterate `state.fields` and accumulate `(policy_id, priority, field_value)` per field name.
       b. For each field name in the field map:
          - Find the maximum priority among all tuples.
          - Filter to only tuples at that max priority.
          - If exactly one tuple at max priority, or all tuples at max priority have the same `value`: that value wins. Record the first policy_id (by input order) in `field_sources`. Insert the winning `FieldValue` (cloned from the winner) into the merged fields.
          - If multiple tuples at max priority have different values: record a `FieldConflict` with all contenders. Do NOT include this field in the merged output (it's unresolvable without SPEC-202's conflict resolution). This is the safest default — omitting a conflicted field is better than picking an arbitrary winner.
       c. Compute `max_priority` across all contributing policies for this entity (for the merged `State.priority`).
       d. Pick the `Selector` from any contributing state (they all share the same entity key, so their selectors produce the same `key()` — use the first one encountered).
       e. Build the merged `State` with: `entity_type` from the key, `selector` from step (d), `fields` from the winning fields, `metadata: StateMetadata::new()`, `policy_ref: None`, `priority: max_priority`.
       f. Insert the merged `State` into the effective `StateSet`.
    4. Return `ReconciliationResult { effective_state, field_sources, conflicts }`.
  - Note on conflict handling (step 3b): The spec says conflicts are "handled by SPEC-202" but the merge algorithm must detect them. By omitting conflicted fields from the merged state and recording them in `ConflictReport`, we keep the effective state consistent (no arbitrary values) while providing the information SPEC-202 needs.
  - Internal helper: Consider an intermediate struct or type alias for the per-entity field accumulation to keep the code readable, but do not over-abstract — the function body should be straightforward.
- **Why**: This is the core logic of SPEC-201. It must be correct, deterministic, and produce all three outputs (effective_state, field_sources, conflicts).

### `crates/netfyr-reconcile/src/lib.rs`
- **Action**: modify (replace the single doc comment line)
- **What**: Module declarations and re-exports:
  ```
  pub mod engine;
  pub mod merge;
  pub use engine::{
      PolicyId, EntityKey, FieldName, PolicyInput,
      ReconciliationResult, ConflictReport, FieldConflict,
  };
  pub use merge::merge;
  ```
  Keep the existing doc comment (`//! netfyr-reconcile crate`).
- **Why**: Makes all public types accessible from the crate root, following the pattern used by `netfyr-state` and `netfyr-backend`.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `netfyr-state` | `{ path = "../netfyr-state" }` | Provides `StateSet`, `State`, `FieldValue`, `Value`, `Selector`, `StateMetadata`, `Provenance` — all types the merge function operates on. |

No other external dependencies needed. `std::collections::HashMap` provides the map type for `field_sources` and internal working structures. `std::fmt` provides `Display` for `PolicyId`.

## Implementation Order

1. **Cargo.toml**: Add `netfyr-state` dependency. After this step, `cargo check -p netfyr-reconcile` should succeed (the crate is otherwise empty).

2. **`src/engine.rs`**: Define all types (`PolicyId`, `EntityKey`, `FieldName`, `PolicyInput`, `FieldConflict`, `ConflictReport`, `ReconciliationResult`). After this step, the types compile but are unused.

3. **`src/lib.rs`**: Add `pub mod engine; pub mod merge;` and re-exports. This step will fail to compile until `merge.rs` exists, so create `merge.rs` as an empty module (just the `use` imports and a stub `pub fn merge(...) -> ...` that returns empty results) in the same step.

4. **`src/merge.rs`**: Implement the full `merge()` function. After this step, `cargo check -p netfyr-reconcile` and `cargo test -p netfyr-reconcile` should pass (though no tests exist yet).

Steps 2-4 can be done in a single pass since they're tightly coupled. The key constraint is that step 1 must come first (dependency resolution), and `lib.rs` + `merge.rs` must exist simultaneously (module declarations require the files).

## Risks and Mitigations

1. **Risk**: Conflicted fields are omitted from the effective state, which means a conflict between two policies silently drops a field rather than failing loudly.
   - **Mitigation**: `ConflictReport` records every conflict. Callers (CLI, daemon) must check `conflicts.is_empty()` before treating the effective state as complete. The acceptance criteria for this story only test non-conflict scenarios, so this is safe. SPEC-202 will add resolution strategies.

2. **Risk**: The `State` struct's `Selector` is not `Hash` or `Eq`, so entity identity relies on `selector.key()` producing consistent strings. If two selectors with different internal structure produce the same key, they'll be treated as the same entity.
   - **Mitigation**: `Selector::key()` is already the canonical identity used by `StateSet`. The merge function uses the same keying, so consistency is guaranteed. No new risk introduced.

3. **Risk**: Performance with many policies and large `StateSet`s — the algorithm is O(P * E * F) where P = policies, E = entities per policy, F = fields per entity. With realistic numbers (< 100 policies, < 1000 entities, < 50 fields), this is trivially fast.
   - **Mitigation**: No optimization needed for this story. If profiling later shows issues, the collect phase could be parallelized, but that's speculative.

4. **Risk**: `PolicyId` defined in `netfyr-reconcile` may conflict with a future `PolicyId` in `netfyr-policy`.
   - **Mitigation**: If `netfyr-policy` defines its own `PolicyId`, we can add a `From` conversion or re-export. The newtype pattern makes this migration straightforward.

5. **Risk**: Acceptance criteria scenario 7 (same priority, same value) requires that the merge function correctly identifies value equality across policies. `Value` derives `PartialEq`, and the existing `set::union` tests confirm value comparison works correctly for all variants including `List` and `Map`.
   - **Mitigation**: Rely on `Value::PartialEq`. No special handling needed.

6. **Risk**: The `field_sources` key type `((String, String), String)` is verbose and could be confusing.
   - **Mitigation**: The type aliases `EntityKey` and `FieldName` make the signature readable: `HashMap<(EntityKey, FieldName), PolicyId>`. Document in the struct's doc comment that `EntityKey` is `(entity_type, selector_key)`.

## Test Strategy

### Unit tests (in `src/merge.rs` `#[cfg(test)]` block)

Tests should cover all 9 acceptance scenarios from the spec, plus edge cases:

1. **Single policy passthrough**: One `PolicyInput` → effective state matches its `StateSet` exactly; `field_sources` maps every field to that policy.

2. **Two policies, disjoint fields, same entity**: Both fields appear in effective state; each maps to its source policy in `field_sources`.

3. **Higher priority overrides**: Two policies, same entity, same field, different priorities → higher priority wins; `field_sources` points to the winner.

4. **Partial override**: Higher priority policy provides only one field; lower priority's other fields survive in the effective state with correct `field_sources` entries.

5. **Three-policy cascade**: Three priorities (50, 100, 200) with overlapping fields → each field won by its highest-priority contributor.

6. **Disjoint entities**: Policies targeting different entities → both appear in effective state independently.

7. **Same priority, same value**: Two policies at equal priority provide identical value → no conflict, value included in effective state.

8. **Empty input**: `merge(vec![])` → empty effective state, empty field_sources, empty conflicts.

9. **Multi-entity policy**: One policy with 3 entities → all 3 appear in effective state.

10. **Lower priority fields survive**: A low-priority policy provides 3 fields; a high-priority policy overrides 1 → the other 2 survive from the low-priority policy.

Additional edge case tests:

11. **Same priority, different values (conflict)**: Two policies at priority 100 provide different values for the same field → field is omitted from effective state, conflict is recorded in `ConflictReport`.

12. **Many policies, same field, cascading priorities**: Verify that only the maximum-priority value wins regardless of the number of lower-priority contenders.

13. **Policy with empty StateSet**: `PolicyInput` with an empty `StateSet` → no contribution to the effective state.

### Test infrastructure

- A helper function `make_policy_input(id: &str, priority: u32, entities: Vec<State>) -> PolicyInput` that constructs a `PolicyInput` from a list of states.
- Reuse the `make_state` pattern from `netfyr-state`'s tests: `make_state(entity_type, name, fields, priority)` → `State`.
- No mocks needed — all types are owned values with no I/O.
- No integration tests needed for this story — the merge function is a pure computation with no external dependencies.
