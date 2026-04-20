# Gap Analysis: SPEC-007 — Policy Types and Static Factory

## Current State

### `crates/netfyr-policy`
The crate exists in the workspace but is effectively empty:
- `src/lib.rs`: contains only a crate-level doc comment (`//! netfyr-policy crate`).
- `Cargo.toml`: declares the package with no dependencies at all.

No types, traits, functions, or tests exist in this crate.

### `crates/netfyr-state` (relevant existing API)
The following types and functions from `netfyr-state` are directly required by this story:

- **`State`** (`lib.rs:461`): has `entity_type: String`, `selector: Selector`, `fields: IndexMap<String, FieldValue>`, `policy_ref: Option<String>`, `priority: u32`, `metadata: StateMetadata`. Derives `Clone, Debug, PartialEq, Serialize, Deserialize` with the internal struct format — **not** the flat user-facing YAML format.
- **`StateSet`** (`set.rs:43`): `insert`, `get`, `remove`, `iter`, `len`, `is_empty`, `entities`.
- **`union(a: &StateSet, b: &StateSet) -> Result<StateSet, ConflictError>`** (`set.rs:112`): per-field priority merge; returns `Err(ConflictError)` on equal-priority value conflicts. Priority is read from the `State::priority` field.
- **`ConflictError`** (`set.rs:32`): `pub conflicts: Vec<Conflict>`, where `Conflict` has `entity_type`, `selector_key`, `field`, `value_a`, `value_b`, `priority`.
- **`Selector`** (`lib.rs:108`): derives `Serialize, Deserialize`; has `name: Option<String>` and other fields.
- **`Provenance`** (`lib.rs:399`): `UserConfigured { policy_ref: String }` variant is what `StaticFactory` must set on each field.
- **`FieldValue`** (`lib.rs:417`): `pub value: Value`, `pub provenance: Provenance`.
- **`parse_yaml(input: &str) -> Result<Vec<State>, YamlError>`** (`yaml.rs:281`): multi-document YAML parser for the flat state format. Accepts `kind: state` or absent `kind`; rejects `kind: policy` with `YamlError::InvalidKind`.
- **`deserialize_value(v: &serde_yaml::Value) -> Result<Value, YamlError>`** (`yaml.rs:89`): public — converts raw serde_yaml values to `Value`.

The private function `parse_raw_to_state(raw: serde_yaml::Value)` (`yaml.rs:185`) implements the flat-format state parsing logic but is **not exported**.

### `crates/netfyr-reconcile`
Contains `PolicyId`, `PolicyInput`, and `merge`. Not directly consumed by this story, but `PolicyId` is a conceptually adjacent newtype. This story defines its own `Policy` type, which is unrelated to `PolicyInput`.

---

## Requirements

### Types

1. **`FactoryType` enum** — variants `Static` and `Dhcpv4`. Must implement `PartialEq` (needed for filter in `produce_all_static`), `Clone`, `Debug`, `Serialize`, `Deserialize`. Serializes as `"static"` / `"dhcpv4"` (lowercase).

2. **`Policy` struct** — fields:
   - `name: String`
   - `factory_type: FactoryType` — serialized as `factory` in YAML (rename needed)
   - `priority: u32` — default 100
   - `state: Option<State>` — flat-format nested mapping in YAML
   - `states: Option<Vec<State>>` — list of flat-format nested mappings
   - `selector: Option<Selector>`

3. **`FactoryError` enum** — `thiserror`-based:
   - `MissingState { policy_name: String }`
   - `InvalidFactory { policy_name: String, factory_type: String, reason: String }`
   - `ConflictError(ConflictError)` — wraps `netfyr_state::set::ConflictError`
   - `Other { message: String }`

4. **`StateFactory` trait**:
   ```rust
   pub trait StateFactory {
       fn produce(&self, policy: &Policy) -> Result<StateSet, FactoryError>;
   }
   ```

5. **`StaticFactory` struct** — implements `StateFactory`. Reads `policy.state` and/or `policy.states`, clones each `State`, sets `priority` and `policy_ref`, rewrites all `FieldValue::provenance` to `Provenance::UserConfigured { policy_ref: policy.name.clone() }`, inserts into a `StateSet`, returns `MissingState` if both are `None`.

6. **`PolicySet` struct** — `IndexMap<String, Policy>` keyed by name. Methods: `insert`, `get`, `remove`, `iter`, `len`, `is_empty`, `produce_all_static`.

7. **`parse_policy_yaml(input: &str) -> Result<Vec<Policy>, PolicyYamlError>`** (or reusing a unified error type) — multi-document YAML parser. For each document:
   - `kind: policy` → parse as `Policy`
   - No `kind` or `kind: state` → SPEC-008 (out of scope; must decide how to handle — error or skip)
   - Other `kind` → error

### Behavior

- `StaticFactory::produce` must error with `MissingState` when both `policy.state` and `policy.states` are `None`.
- `PolicySet::produce_all_static` iterates only `FactoryType::Static` policies, calls `StaticFactory::produce` on each, unions results with `netfyr_state::set::union`, maps `ConflictError` to `FactoryError::ConflictError`. Priority-based conflict resolution flows from `State::priority` through the existing `union` implementation.
- Default priority must be 100 (use `#[serde(default = "...")]` or a `default` fn).
- `FactoryType` must serialize/deserialize as lowercase strings.

---

## Gap Analysis

### Files to create

| File | Content |
|------|---------|
| `crates/netfyr-policy/src/lib.rs` | Public re-exports for all types and functions |
| `crates/netfyr-policy/src/policy.rs` | `Policy`, `FactoryType`, `PolicySet` |
| `crates/netfyr-policy/src/factory.rs` | `StateFactory` trait, `FactoryError` |
| `crates/netfyr-policy/src/static_factory.rs` | `StaticFactory` impl |

### `Cargo.toml` update required

`crates/netfyr-policy/Cargo.toml` must add:
```toml
netfyr-state = { path = "../netfyr-state" }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
thiserror = "1"
tracing = "0.1"
indexmap = { version = "2", features = ["serde"] }
```

### Core challenge: `Policy` YAML deserialization with flat `state`/`states`

`State` derives `Serialize, Deserialize` in its **internal** struct format (`entity_type`, `selector`, `fields`, `metadata`, `policy_ref`, `priority`). The user-facing YAML format for states is **flat** (`type: ethernet`, `name: eth0`, `mtu: 1500`).

This means `Policy` **cannot use a plain `#[derive(Deserialize)]`** for the `state` / `states` fields. Options are:

1. **Manual parsing via raw `serde_yaml::Value`**: `parse_policy_yaml` iterates documents, extracts the `state`/`states` mappings as raw `serde_yaml::Value`, and replicates the flat-to-`State` conversion logic from `netfyr-state/src/yaml.rs::parse_raw_to_state` (which is currently private).

2. **Expose `parse_raw_to_state` from `netfyr-state`**: Make the function public (or add a new public `parse_state_from_yaml_value(serde_yaml::Value) -> Result<State, YamlError>`) in `netfyr-state`. This avoids duplicating logic but requires modifying `netfyr-state`.

3. **Serialize sub-document back to string**: Extract the nested mapping, serialize it to YAML string, call `parse_yaml()`. Works but is roundabout.

The implementer must choose one approach. Option 2 is cleanest long-term; option 1 avoids touching `netfyr-state`.

### YAML field name: `factory` vs `factory_type`

The YAML key is `factory:` but the struct field is `factory_type`. Requires `#[serde(rename = "factory")]` on the field.

### SPEC-008 delegation in `parse_policy_yaml`

The spec says documents without `kind` or with `kind: state` are "delegated to SPEC-008". The function signature `-> Result<Vec<Policy>>` has no way to return non-policy items. For this story, the behavior for those documents must be explicitly decided: return an error, silently skip, or panic. The acceptance criteria only cover `kind: policy` documents so this is a boundary condition to clarify.

---

## Integration Points

1. **`netfyr-state::StateSet`** — `StaticFactory::produce` builds and returns one; `produce_all_static` unions multiple.

2. **`netfyr-state::union`** — called in `produce_all_static`; signature `union(a: &StateSet, b: &StateSet) -> Result<StateSet, ConflictError>`. The `ConflictError` wraps into `FactoryError::ConflictError`.

3. **`netfyr-state::State`** — `Policy.state` and `Policy.states` are of type `State`. Cloned and mutated in `StaticFactory::produce` to set `priority`, `policy_ref`, and field provenances.

4. **`netfyr-state::Provenance`** — `StaticFactory` sets `Provenance::UserConfigured { policy_ref }` on every `FieldValue` in the produced states.

5. **`netfyr-state::yaml::parse_yaml`** — may be reused for parsing nested state documents within a policy YAML document (option 3 above), or the private `parse_raw_to_state` logic must be replicated/exposed.

6. **`netfyr-state::set::ConflictError`** — must be imported and wrapped by `FactoryError::ConflictError`. The `Conflict` struct's fields (`entity_type`, `selector_key`, `field`) are public, allowing the error scenario test to introspect conflicts.

---

## Risks

1. **Flat-format `State` deserialization inside Policy YAML**: The biggest implementation risk. `State`'s serde impl uses internal struct layout, not the flat format. Custom deserialization is unavoidable for `state`/`states` fields. If `parse_raw_to_state` is not exposed from `netfyr-state`, the logic must be duplicated or the sub-document round-tripped through a string — both have maintenance cost.

2. **`priority` default value**: `serde` does not recognize Rust default values automatically for non-`Default` scalars. `#[serde(default = "default_priority")]` with a `fn default_priority() -> u32 { 100 }` helper is needed, or `Policy` implements `Default`.

3. **`produce_all_static` conflict scenario vs. priority resolution scenario**: The spec includes two acceptance criteria that seem contradictory: one expects `Err(FactoryError::ConflictError)` for two policies at priority 100 with the same entity/field at different values, and another expects `Ok` when one policy is at priority 200 and the other at 100. These map directly to the `union` semantics (equal priority → conflict; unequal priority → higher wins), so they will work correctly as long as `StaticFactory` copies `policy.priority` to each `State::priority`. This is not a risk so much as a correctness invariant to verify.

4. **`produce_all_static` iteration order**: The spec does not mandate a deterministic output ordering. `PolicySet` should use `IndexMap` to preserve insertion order, ensuring stable test behavior.

5. **`FactoryType` equality**: `PartialEq` must be derived for `FactoryType` so that `.filter(|p| p.factory_type == FactoryType::Static)` compiles.

6. **SPEC-008 boundary**: `parse_policy_yaml` encountering a `kind: state` or bare document is out of scope but must not panic. A clear error is safer than a silent skip for this story.

7. **`StaticFactory::produce` empty-fields state**: The spec does not forbid a `State` with zero fields from being in `policy.state`. The pseudocode inserts it regardless. The `StateSet` will accept it. This edge case is not tested but should not break anything.
