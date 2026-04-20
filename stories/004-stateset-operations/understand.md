# Understand: SPEC-004 StateSet Operations

## Current State

The `netfyr-state` crate (`crates/netfyr-state/src/lib.rs`) is the only crate with substantive implementation. It provides:

- **`MacAddr`** / **`MacAddrParseError`** — 6-byte hardware address with parse/display/serde support.
- **`Selector`** — entity targeting struct with `name`, `entity_type`, `driver`, `pci_path`, `mac`, `labels`. Key methods: `new()`, `with_name()`, `matches()`, `is_specific()`, `key()`. `key()` produces a stable composite string used as the lookup key in the future `StateSet`.
- **`Value`** — untagged enum covering `Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `List`, `Map`, `String` with full serde, `Display`, `From` impls, and typed accessors.
- **`Provenance`** — tagged enum: `UserConfigured`, `KernelDefault`, `ExternalTool`, `Derived`.
- **`FieldValue`** — `{ value: Value, provenance: Provenance }`.
- **`StateMetadata`** — `{ id: Uuid, timeline_id: Uuid, created_at: DateTime<Utc>, labels: HashMap<String, String>, description: Option<String> }`.
- **`State`** — top-level entity: `{ entity_type: String, selector: Selector, fields: IndexMap<String, FieldValue>, metadata: StateMetadata, policy_ref: Option<String>, priority: u32 }`.

All types above have comprehensive unit tests in `lib.rs`. No `set.rs`, `diff.rs`, or any `StateSet`/`StateDiff`/`DiffOp`/`ConflictError` types exist yet. No `thiserror` dependency is present in `Cargo.toml`.

The remaining crates (`netfyr-reconcile`, `netfyr-backend`, `netfyr-policy`, `netfyr-varlink`, `netfyr-cli`, `netfyr-daemon`, `netfyr-test-utils`) are not yet implemented; their `lib.rs`/`main.rs` files contain no public API relevant to this story.

## Requirements

### Types to create

**`StateSet`** (`src/set.rs`) — collection keyed by `(entity_type, selector.key())`:
- Internal storage: `IndexMap<(String, String), State>` (insertion-order preserving).
- `insert(state: State)` — add or replace; key derived from `(state.entity_type.clone(), state.selector.key())`.
- `get(entity_type: &str, selector_key: &str) -> Option<&State>`.
- `remove(entity_type: &str, selector_key: &str) -> Option<State>`.
- `iter() -> impl Iterator<Item = &State>`.
- `len() -> usize` and `is_empty() -> bool`.
- `entities() -> Vec<(String, String)>` — all `(entity_type, selector_key)` pairs.

**`ConflictError`** (`src/set.rs`) — `thiserror`-derived error containing `Vec<Conflict>`.

**`Conflict`** (`src/set.rs`) — `{ entity_type: String, selector_key: String, field: String, value_a: Value, value_b: Value, priority: u32 }`.

**`StateDiff`** (`src/diff.rs`) — wrapper over `Vec<DiffOp>`:
- `ops() -> &[DiffOp]`
- `is_empty() -> bool`
- `summary() -> String` — e.g., `"2 added, 1 modified, 0 removed"`.

**`DiffOp`** (`src/diff.rs`) — enum:
- `Add { entity_type: String, selector: Selector, fields: IndexMap<String, FieldValue> }`
- `Modify { entity_type: String, selector: Selector, changed_fields: IndexMap<String, FieldValue>, removed_fields: Vec<String> }`
- `Remove { entity_type: String, selector: Selector }`

### Functions to create

- **`union(a: &StateSet, b: &StateSet) -> Result<StateSet, ConflictError>`** (`src/set.rs`) — per-field merge with priority-based conflict resolution; equal-priority + different-value → `ConflictError`; equal-priority + same-value → include (no conflict).
- **`intersection(a: &StateSet, b: &StateSet) -> StateSet`** (`src/set.rs`) — fields present in both sets for the same entity with matching values (value equality only, provenance/priority ignored). Entities with zero matching fields are excluded.
- **`complement(a: &StateSet, b: &StateSet) -> StateSet`** (`src/set.rs`) — fields in `a` not present (by field name) in `b` for the same entity. Entities with zero remaining fields are excluded.
- **`diff(from: &StateSet, to: &StateSet) -> StateDiff`** (`src/diff.rs`) — entity-level diff: `Add` for entities only in `to`, `Remove` for entities only in `from`, `Modify` for entities in both with field differences. Entities with identical fields produce no op.

### Dependency additions

- `thiserror = "1"` must be added to `crates/netfyr-state/Cargo.toml`.

### Re-exports

`src/lib.rs` must add `pub mod set`, `pub mod diff` and re-export the new public types at the crate root:
- From `set`: `StateSet`, `ConflictError`, `Conflict`, `union`, `intersection`, `complement`.
- From `diff`: `StateDiff`, `DiffOp`, `diff`.

### Tests to write

Comprehensive unit tests covering every Gherkin scenario in the spec (at minimum):
- `StateSet` CRUD: insert, get, replace-on-same-key, remove, len, is_empty, entities.
- `union`: disjoint entities, field merge of same entity, priority resolution, same-value agreement, equal-priority conflict → `ConflictError`.
- `intersection`: overlapping fields with same/different values, disjoint entities, entity excluded when no matching fields.
- `complement`: partial field exclusion, identical sets → empty, entities entirely absent from B retained fully.
- `diff`: Add, Remove, Modify (changed + removed fields), identical sets → empty diff, `summary()` format.

## Gap Analysis

| Item | Status | Action |
|------|--------|--------|
| `crates/netfyr-state/src/set.rs` | Missing | **Create**: `StateSet`, `Conflict`, `ConflictError`, `union`, `intersection`, `complement` |
| `crates/netfyr-state/src/diff.rs` | Missing | **Create**: `StateDiff`, `DiffOp`, `diff` |
| `crates/netfyr-state/src/lib.rs` | Exists | **Modify**: add `pub mod set; pub mod diff;` and re-export new public items |
| `crates/netfyr-state/Cargo.toml` | Exists | **Modify**: add `thiserror = "1"` to `[dependencies]` |
| Unit tests for `set.rs` | Missing | **Create** inside `set.rs` `#[cfg(test)]` block |
| Unit tests for `diff.rs` | Missing | **Create** inside `diff.rs` `#[cfg(test)]` block |

## Integration Points

### `State` fields consumed by the new code
- `state.entity_type: String` — first element of the composite storage key.
- `state.selector.key(): String` — second element of the composite storage key; the existing `Selector::key()` implementation is used directly, no changes required to `Selector`.
- `state.fields: IndexMap<String, FieldValue>` — iterated for per-field merge in `union`, `intersection`, `complement`, and `diff`.
- `state.priority: u32` — read by `union` to determine which `FieldValue` wins when the same field appears in both sets with different values.
- `FieldValue.value: Value` — compared for equality (using the existing `PartialEq` impl on `Value`) in `union` (same-value check) and `intersection`.
- `FieldValue.provenance: Provenance` — carried through unchanged in the winning field for `union`; included in `DiffOp::Add`/`Modify` payloads.

### Interfaces that must not break
- All existing public types and functions in `lib.rs` remain unchanged.
- The `State` struct is consumed immutably (cloned when building result sets); no mutations to `State` or its fields.

### Future consumers (not yet implemented)
- `netfyr-reconcile`: will call `union` to merge policy `StateSet` outputs and `complement`/`diff` for reconciliation.
- `netfyr-cli` (`apply --dry-run`): will call `diff` and format `StateDiff`.

## Risks

1. **`Value` equality for intersection/union same-value check** — `Value` derives `PartialEq`, but `IpNetwork` and `IpAddr` comparisons depend on the underlying `ipnetwork`/`std` implementations. These are standard and correct, but `List` and `Map` equality is recursive and order-sensitive for `Map` (IndexMap preserves insertion order). Two maps with the same key-value pairs in different insertion order will compare as unequal. The spec does not address this; the safe interpretation is structural equality as implemented.

2. **Priority semantics for `intersection`** — the spec says intersection compares values "regardless of priority/provenance". This means two `FieldValue`s with different `provenance` but the same `value` are considered matching. The result field's provenance is unspecified by the spec; either `a`'s or `b`'s could be used. The implementation must choose one (convention: take from `a`).

3. **`complement` compares by field name only** — the spec states fields are excluded from the complement if they "appear in `b`" for the same entity. This is a name-only check (not value equality), which means a field with the same name but different value in `b` will still be excluded from the complement. This asymmetry is intentional per the spec's deletion-detection use case but could surprise callers.

4. **`union` accumulates all conflicts before returning** — the pseudocode implies collecting all conflicts across all fields and all entities before returning `Err`. The implementation must not short-circuit on the first conflict. This is important for useful error messages but requires careful implementation.

5. **`Modify` vs no-op in `diff`** — when an entity exists in both `from` and `to` but fields are identical, no `DiffOp` should be emitted. The implementation must check both `changed_fields` and `removed_fields` are empty before deciding to skip the entity entirely.

6. **`thiserror` version compatibility** — `thiserror = "1"` is the requested version. The project uses Rust edition 2021; `thiserror` 1.x is compatible. No conflict expected with existing deps, but workspace-level `Cargo.toml` (if present) may need updating if `thiserror` is declared there.

7. **`IndexMap` import in new files** — `set.rs` and `diff.rs` will need `use indexmap::IndexMap;`. The `indexmap` crate is already a dependency of `netfyr-state`, so no new dep is needed, but the import must be explicit in each new file.
