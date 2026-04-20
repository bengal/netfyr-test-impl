# Implementation Plan: SPEC-007 — Policy Types and Static Factory

## Approach

This story builds the policy layer in the empty `netfyr-policy` crate. The design centers on three concepts: a `Policy` struct (the data model for user-authored policy YAML), a `StateFactory` trait (the interface all factories implement), and a `PolicySet` collection (keyed by policy name, with a `produce_all_static` convenience method).

The main architectural challenge is YAML deserialization. `State` in `netfyr-state` derives `Serialize`/`Deserialize` for its **internal struct format** (nested `entity_type`, `selector`, `fields` map), but the user-facing policy YAML embeds states in the **flat format** (`type`, `name`, `mtu` all at the same level). The flat-to-`State` conversion logic lives in `netfyr_state::yaml::parse_raw_to_state`, which is currently **private**. Rather than duplicating that non-trivial logic (selector extraction, field classification, `deserialize_value` calls), we will expose it as a public function `parse_state_value(serde_yaml::Value) -> Result<State, YamlError>` in `netfyr-state`. This is a one-line visibility change with a thin public wrapper and is the cleanest path — it avoids code duplication, avoids the overhead of serializing back to a YAML string just to re-parse it, and establishes a reusable API that SPEC-008 will also need.

With that exposed, `parse_policy_yaml` in `netfyr-policy` will: (1) iterate multi-document YAML, (2) inspect the `kind` field of each document, (3) for `kind: policy` documents, extract the top-level policy fields manually from the raw `serde_yaml::Mapping`, (4) pass the `state`/`states` sub-documents through the newly-exposed `parse_state_value`, and (5) construct `Policy` structs. This manual extraction approach (rather than `#[derive(Deserialize)]` on `Policy`) is necessary because the `state`/`states` fields require the flat-format parser, not serde's default `State` deserializer. The remaining policy fields (`name`, `factory`, `priority`, `selector`) are simple scalars/structs that can be extracted from the raw mapping with straightforward pattern matching.

## Design Decisions

1. **Decision**: Expose `parse_raw_to_state` from `netfyr-state` as `pub fn parse_state_value(raw: serde_yaml::Value) -> Result<State, YamlError>`.
   - **Alternatives considered**: (a) Duplicate the flat-format parsing logic in `netfyr-policy`. (b) Round-trip: serialize the sub-document back to a YAML string, call `parse_yaml()`. (c) Use `#[derive(Deserialize)]` on `Policy` with a custom deserializer for the `state` field.
   - **Rationale**: Option (a) creates a maintenance burden — `parse_raw_to_state` is ~90 lines with selector extraction, field classification, and MAC parsing. Option (b) works but is wasteful (serialize then immediately re-parse). Option (c) is complex because `State`'s derived deserializer expects internal format, so we'd need a custom `Deserialize` impl that shadows it. Exposing the existing function is one line of visibility change plus a thin public wrapper, and SPEC-008 will need the same function.

2. **Decision**: Parse `Policy` from raw `serde_yaml::Value` manually rather than using `#[derive(Deserialize)]`.
   - **Alternatives considered**: Derive `Deserialize` on `Policy` with `#[serde(deserialize_with)]` for `state`/`states`.
   - **Rationale**: The `state` field in YAML is a flat-format mapping, not a `State` struct. A custom serde deserializer would need to intercept the raw value and call `parse_state_value` — essentially doing the same manual work but wrapped in serde's visitor API with more boilerplate. Direct extraction from `serde_yaml::Mapping` is simpler and more explicit. We will still derive `Serialize` on `Policy` for testing/debugging (using `#[serde(skip)]` on state/states to avoid serializing them with the wrong format), but primary serialization of policies is not a requirement of this story.

3. **Decision**: `Policy` will derive `Clone, Debug, PartialEq` but **not** `Serialize`/`Deserialize` (via derive). Serialization is not needed for this story, and the flat state format makes derive-based round-tripping incorrect.
   - **Alternatives considered**: Deriving `Serialize`/`Deserialize` with custom logic.
   - **Rationale**: The spec only requires parsing (deserialization). Adding serialization would add complexity for no current use case. If needed later, it can be added.

4. **Decision**: `FactoryType` serializes/deserializes as lowercase strings using `#[serde(rename_all = "lowercase")]`.
   - **Alternatives considered**: Custom `Serialize`/`Deserialize` impls.
   - **Rationale**: `rename_all = "lowercase"` maps `Static` to `"static"` and `Dhcpv4` to `"dhcpv4"` exactly as spec requires. No custom code needed. Note: `Dhcpv4` → `"dhcpv4"` — serde's `lowercase` converts `Dhcpv4` to `"dhcpv4"` which is correct.

5. **Decision**: `PolicySet` uses `IndexMap<String, Policy>` internally, keyed by policy name.
   - **Alternatives considered**: `HashMap`, `BTreeMap`.
   - **Rationale**: `IndexMap` preserves insertion order (deterministic iteration for `produce_all_static` and test stability), consistent with `StateSet`'s design.

6. **Decision**: For `parse_policy_yaml`, documents with `kind: state` or no `kind` field will return an error (not silently skip).
   - **Alternatives considered**: Silently skip non-policy documents. Return them as a separate type.
   - **Rationale**: The spec says these are "delegated to SPEC-008", but the function signature is `-> Result<Vec<Policy>>` which cannot represent non-policy items. Silent skipping is dangerous — a user typo (forgetting `kind: policy`) would silently lose a document. Returning an error with a clear message ("expected 'kind: policy', found ...") is safer for this story. SPEC-008 will likely change `parse_policy_yaml` to return a richer type that can represent both policies and bare states.

7. **Decision**: `FactoryError` uses `thiserror` with four variants matching the spec exactly.
   - **Alternatives considered**: Combining with `YamlError` into a single error type.
   - **Rationale**: Factory errors and YAML parse errors have different causes and callers. Keeping them separate follows the existing crate pattern (`YamlError` in `netfyr-state`, `BackendError` in `netfyr-backend`). `parse_policy_yaml` will have its own error type that can wrap `YamlError`.

8. **Decision**: Introduce `PolicyError` as the error type for `parse_policy_yaml`, separate from `FactoryError`.
   - **Alternatives considered**: Reusing `FactoryError` for parsing errors, or using `YamlError` directly.
   - **Rationale**: Parse errors (missing fields, invalid kind, YAML syntax) are conceptually different from factory errors (missing state, conflict). `PolicyError` wraps `YamlError` for the YAML-level issues and adds policy-specific variants like `InvalidKind` and `MissingPolicyName`. This keeps error types focused and actionable.

9. **Decision**: `StaticFactory` is a unit struct (no fields). It reads everything it needs from the `Policy` argument.
   - **Alternatives considered**: Storing configuration in the factory.
   - **Rationale**: The static factory is stateless — it just copies state from the policy. A unit struct keeps it simple and matches the spec pseudocode.

10. **Decision**: `Selector` deserialization within policy YAML (for DHCPv4's `selector:` field) uses serde's derived `Deserialize` on `Selector`, since the YAML format matches the struct format directly.
    - **Rationale**: Unlike `State`, `Selector`'s YAML representation matches its struct layout — `name`, `driver`, etc. are direct fields. `serde_yaml::from_value::<Selector>(raw_value)` works correctly.

## File Changes

### 1. `crates/netfyr-state/src/yaml.rs`
- **Action**: modify
- **What**: Add a public function `pub fn parse_state_value(raw: serde_yaml::Value) -> Result<State, YamlError>` that delegates to the existing private `parse_raw_to_state`. This is a thin public wrapper — it calls `parse_raw_to_state(raw)` directly. The private function stays as-is.
- **Why**: `netfyr-policy` needs to convert flat-format YAML mappings (embedded as `state`/`states` inside a policy document) into `State` values. This exposes the existing logic without duplication.

### 2. `crates/netfyr-state/src/lib.rs`
- **Action**: modify
- **What**: Add `parse_state_value` to the `pub use yaml::...` re-export line.
- **Why**: Makes the new function accessible as `netfyr_state::parse_state_value`.

### 3. `crates/netfyr-policy/Cargo.toml`
- **Action**: modify
- **What**: Add dependencies:
  ```toml
  netfyr-state = { path = "../netfyr-state" }
  serde = { version = "1", features = ["derive"] }
  serde_yaml = "0.9"
  thiserror = "1"
  tracing = "0.1"
  indexmap = { version = "2", features = ["serde"] }
  ```
- **Why**: `netfyr-state` for `State`, `StateSet`, `union`, `Selector`, `Provenance`, etc. `serde`/`serde_yaml` for `FactoryType` serialization and raw YAML parsing. `thiserror` for error types. `tracing` for logging in factory operations. `indexmap` for `PolicySet` internal storage.

### 4. `crates/netfyr-policy/src/lib.rs`
- **Action**: modify (overwrite the stub)
- **What**: Module declarations and public re-exports:
  ```
  pub mod policy;
  pub mod factory;
  pub mod static_factory;
  pub mod parse;
  
  pub use policy::{Policy, FactoryType, PolicySet};
  pub use factory::{StateFactory, FactoryError};
  pub use static_factory::StaticFactory;
  pub use parse::{parse_policy_yaml, PolicyError};
  ```
- **Why**: Standard crate entry point pattern, matching `netfyr-state` and `netfyr-backend`.

### 5. `crates/netfyr-policy/src/policy.rs`
- **Action**: create
- **What**:
  - `FactoryType` enum with variants `Static` and `Dhcpv4`. Derives `Clone, Debug, PartialEq, Serialize, Deserialize`. Uses `#[serde(rename_all = "lowercase")]` for YAML representation.
  - `Policy` struct with fields: `name: String`, `factory_type: FactoryType`, `priority: u32`, `state: Option<State>`, `states: Option<Vec<State>>`, `selector: Option<Selector>`. Derives `Clone, Debug, PartialEq`. Does NOT derive `Serialize`/`Deserialize` (construction is manual from raw YAML).
  - `fn default_priority() -> u32` returning `100`, used for default construction.
  - `PolicySet` struct wrapping `IndexMap<String, Policy>`. Methods:
    - `new() -> Self` — empty set
    - `insert(policy: Policy)` — inserts/replaces by `policy.name`
    - `get(name: &str) -> Option<&Policy>` — lookup by name
    - `remove(name: &str) -> Option<Policy>` — remove by name
    - `iter() -> impl Iterator<Item = &Policy>` — iterate values in insertion order
    - `len() -> usize`
    - `is_empty() -> bool`
    - `produce_all_static(&self) -> Result<StateSet, FactoryError>` — filters to `FactoryType::Static` policies, calls `StaticFactory.produce()` on each, unions results with `netfyr_state::union`. Maps `ConflictError` to `FactoryError::ConflictError`. Returns combined `StateSet`.
- **Why**: Core data model for the policy layer. `PolicySet::produce_all_static` is the main entry point for CLI daemon-free mode.

### 6. `crates/netfyr-policy/src/factory.rs`
- **Action**: create
- **What**:
  - `StateFactory` trait with one method: `fn produce(&self, policy: &Policy) -> Result<StateSet, FactoryError>`.
  - `FactoryError` enum (derives `Debug, thiserror::Error`):
    - `MissingState { policy_name: String }` — display: `"static factory for policy '{policy_name}' has neither 'state' nor 'states' defined"`
    - `InvalidFactory { policy_name: String, factory_type: String, reason: String }` — display: `"invalid factory configuration for policy '{policy_name}' (type: {factory_type}): {reason}"`
    - `ConflictError(#[from] netfyr_state::ConflictError)` — wraps the state-level conflict error
    - `Other { message: String }` — display: `"{message}"`
- **Why**: The trait defines the factory contract. `FactoryError` provides structured error reporting for all factory operations.

### 7. `crates/netfyr-policy/src/static_factory.rs`
- **Action**: create
- **What**:
  - `StaticFactory` — a public unit struct (no fields).
  - Implements `StateFactory` for `StaticFactory`. The `produce` method:
    1. Creates a new `StateSet`.
    2. If `policy.state` is `Some`, clones the state, sets `priority` to `policy.priority`, sets `policy_ref` to `Some(policy.name.clone())`, iterates all fields and sets each `FieldValue.provenance` to `Provenance::UserConfigured { policy_ref: policy.name.clone() }`, then inserts into the set.
    3. If `policy.states` is `Some`, does the same for each state in the vec.
    4. If both `state` and `states` are `None`, returns `Err(FactoryError::MissingState { policy_name: policy.name.clone() })`.
    5. Returns `Ok(set)`.
  - A private helper `fn apply_policy_to_state(state: &State, policy: &Policy) -> State` that performs the clone-and-mutate logic to avoid duplication between the single-state and multi-state branches.
- **Why**: The simplest factory — copies inline state definitions into a `StateSet` with policy metadata applied.

### 8. `crates/netfyr-policy/src/parse.rs`
- **Action**: create
- **What**:
  - `PolicyError` enum (derives `Debug, thiserror::Error`):
    - `Yaml(#[from] netfyr_state::YamlError)` — wraps YAML-level parse errors
    - `MissingField { field: String }` — required field missing from policy document
    - `InvalidKind { kind: String }` — `kind` is present but not `"policy"` (and not `"state"` / absent, which are SPEC-008)
    - `UnsupportedKind { kind: String }` — `kind: state` or absent `kind` encountered (SPEC-008 not yet implemented)
    - `InvalidFieldType { field: String, expected: String }` — field has wrong YAML type (e.g., `name` is not a string)
    - `UnknownFactory { factory: String }` — `factory` value doesn't match any `FactoryType` variant
    - `Serde(#[from] serde_yaml::Error)` — serde-level deserialization error (for `Selector`, `FactoryType`)
  - `pub fn parse_policy_yaml(input: &str) -> Result<Vec<Policy>, PolicyError>`:
    1. Uses `serde_yaml::Deserializer::from_str(input)` to iterate multi-document YAML.
    2. For each document, deserializes to `serde_yaml::Value`.
    3. Skips `Value::Null` documents (trailing `---`).
    4. Checks the `kind` field:
       - `"policy"` → continue parsing as a policy (below).
       - `"state"` or absent → return `Err(PolicyError::UnsupportedKind)` with a message indicating SPEC-008.
       - Any other value → return `Err(PolicyError::InvalidKind)`.
    5. Extracts `name` (required string), `factory` (required string → deserialize to `FactoryType` via `serde_yaml::from_value`), `priority` (optional u64, default 100).
    6. Extracts `selector` (optional mapping → deserialize to `Selector` via `serde_yaml::from_value`).
    7. Extracts `state` (optional mapping → pass to `netfyr_state::parse_state_value`).
    8. Extracts `states` (optional sequence → iterate, pass each mapping to `netfyr_state::parse_state_value`).
    9. Constructs `Policy { name, factory_type, priority, state, states, selector }`.
    10. Collects all policies into a `Vec<Policy>`.
- **Why**: Handles the YAML parsing layer, converting raw multi-document YAML into typed `Policy` values. Separated from `policy.rs` to keep data model and parsing logic in distinct files.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `netfyr-state` | `{ path = "../netfyr-state" }` | Core types: `State`, `StateSet`, `union`, `ConflictError`, `Selector`, `Provenance`, `FieldValue`, `YamlError`, `parse_state_value` |
| `serde` | `1` (with `derive` feature) | `FactoryType` derives `Serialize`/`Deserialize` for lowercase mapping |
| `serde_yaml` | `0.9` | Raw YAML document iteration and value extraction in `parse_policy_yaml` |
| `thiserror` | `1` | Ergonomic error type definitions for `FactoryError` and `PolicyError` |
| `tracing` | `0.1` | Logging in factory operations (e.g., `tracing::debug!` when producing state) |
| `indexmap` | `2` (with `serde` feature) | `PolicySet` internal storage for insertion-order-preserving map |

All are already used elsewhere in the workspace. No new external crates are introduced.

## Implementation Order

### Step 1: Expose `parse_state_value` from `netfyr-state`
- Add `pub fn parse_state_value(raw: serde_yaml::Value) -> Result<State, YamlError>` to `yaml.rs` that delegates to `parse_raw_to_state`.
- Add `parse_state_value` to the re-exports in `lib.rs`.
- **Compilable**: yes. Existing tests continue to pass.

### Step 2: Update `netfyr-policy/Cargo.toml`
- Add all dependencies listed above.
- **Compilable**: yes (empty lib.rs still compiles).

### Step 3: Create `factory.rs` — `StateFactory` trait and `FactoryError`
- Define the trait and error type. No dependencies on other new files.
- Update `lib.rs` with `pub mod factory` and re-exports.
- **Compilable**: yes. `FactoryError::ConflictError` wraps `netfyr_state::ConflictError` which is available.

### Step 4: Create `policy.rs` — `Policy`, `FactoryType`, `PolicySet`
- Define all three types. `PolicySet::produce_all_static` depends on `StaticFactory` which doesn't exist yet — temporarily import it but the method body can reference `StaticFactory` once step 5 is done. **Alternative**: implement `produce_all_static` in this step by importing `StaticFactory` (which will be created in step 5). To keep this step compilable, either: (a) add a stub `static_factory.rs` with just `pub struct StaticFactory;` and no trait impl, making `produce_all_static` call a method that doesn't compile, or (b) implement steps 4 and 5 together.
- **Resolution**: Implement steps 4 and 5 together. The `produce_all_static` method needs `StaticFactory` and `StateFactory` trait. Create both files, then update `lib.rs`.
- Update `lib.rs` with `pub mod policy` and re-exports.
- **Compilable**: only when combined with step 5.

### Step 5: Create `static_factory.rs` — `StaticFactory`
- Implement the unit struct and `StateFactory` trait impl.
- Update `lib.rs` with `pub mod static_factory` and re-exports.
- **Compilable**: yes (with step 4). Together, steps 4+5 form the first fully-functional unit.

### Step 6: Create `parse.rs` — `parse_policy_yaml` and `PolicyError`
- Implement the YAML parsing function. Depends on `Policy` (step 4), `parse_state_value` (step 1), `Selector` (from `netfyr-state`), `FactoryType` (step 4).
- Update `lib.rs` with `pub mod parse` and re-exports.
- **Compilable**: yes. All dependencies are in place from prior steps.

### Step 7: Final `lib.rs` cleanup
- Ensure all re-exports are correct and the crate's public API is clean.
- Run `cargo check -p netfyr-policy` and `cargo check --workspace` to verify.
- **Compilable**: yes.

## Risks and Mitigations

### Risk 1: `serde(rename_all = "lowercase")` behavior with `Dhcpv4`
Serde's `lowercase` transforms `Dhcpv4` by lowercasing each character: `"dhcpv4"`. This is the desired output. However, if the variant were `DHCPv4` (all caps), `lowercase` would produce `"dhcpv4"` which is also correct but the variant name convention matters.

**Mitigation**: Use variant name `Dhcpv4` (PascalCase) and verify with a unit test that it serializes to `"dhcpv4"`.

### Risk 2: `parse_state_value` may need the `kind` check relaxed
The existing `parse_raw_to_state` rejects `kind: policy` with `InvalidKind`. When called from `parse_policy_yaml`, the `state`/`states` sub-documents should not have a `kind` field (they're just flat state mappings without a `kind` wrapper). If a user accidentally includes `kind: state` inside a `state:` block, `parse_raw_to_state` will accept it and strip it. If they include `kind: policy`, it will error — which is correct behavior.

**Mitigation**: None needed. The existing behavior is correct for our use case.

### Risk 3: Priority field type (`u64` vs `u32`)
YAML numbers deserialize as `u64` by default in `serde_yaml`. The `Policy.priority` field is `u32` per spec and `State.priority` is `u32`. When extracting from raw YAML, we get a `u64` and must convert to `u32`.

**Mitigation**: Use `as_u64()` on the YAML number, then `try_into::<u32>()` with an error for overflow. Values above `u32::MAX` are nonsensical for priority.

### Risk 4: `produce_all_static` conflict scenario with union semantics
The acceptance criteria include both a conflict scenario (same priority, different values → error) and a priority resolution scenario (different priority → higher wins). These depend on `StaticFactory` correctly copying `policy.priority` to each `State.priority` before the states enter `union`.

**Mitigation**: The `apply_policy_to_state` helper ensures `state.priority = policy.priority` is always set. The `union` function in `netfyr-state` uses `State.priority` for conflict resolution, which is exactly what we need.

### Risk 5: Both `state` and `states` present in the same policy
The spec doesn't explicitly forbid a policy having both `state` and `states`. The pseudocode handles both — it processes `state` first, then `states`, inserting all into the same `StateSet`.

**Mitigation**: Allow both. If there's a key collision between the single `state` and one of the `states`, `StateSet::insert` will replace the earlier entry (last writer wins within a single policy). This is reasonable — the user probably made a mistake, but it doesn't crash.

### Risk 6: Empty `states` list `(states: [])`
If `states` is an empty sequence, the factory receives `Some(vec![])`. Combined with `state: None`, this would pass the "neither state nor states" check (since `states` is `Some`), but produce an empty `StateSet`.

**Mitigation**: Treat `Some(vec![])` as equivalent to `None` for the MissingState check. Check `policy.states.as_ref().map_or(true, |v| v.is_empty())` instead of just `policy.states.is_none()`.

## Test Strategy

### Unit tests for `FactoryType` (in `policy.rs`)
- Serialization: `FactoryType::Static` serializes to `"static"`, `FactoryType::Dhcpv4` serializes to `"dhcpv4"`.
- Deserialization: `"static"` → `FactoryType::Static`, `"dhcpv4"` → `FactoryType::Dhcpv4`.
- Round-trip: serialize then deserialize yields the same variant.
- Unknown factory string returns a deserialization error.

### Unit tests for `StaticFactory` (in `static_factory.rs`)
- **Single state**: Policy with `state: Some(...)` produces a `StateSet` with one entry. Verify `priority`, `policy_ref`, and `Provenance::UserConfigured` on all fields.
- **Multiple states**: Policy with `states: Some(vec![...])` produces a `StateSet` with the correct count. Verify all entries have the policy's priority and policy_ref.
- **Missing state**: Policy with both `state: None` and `states: None` returns `Err(FactoryError::MissingState)` containing the policy name.
- **Empty states vec**: Policy with `states: Some(vec![])` and `state: None` returns `Err(FactoryError::MissingState)`.
- **Field preservation**: All field values (U64, String, List, Map, IpNetwork) survive the factory pass-through unchanged.
- **Provenance overwrite**: Fields with any initial provenance are overwritten to `UserConfigured` with the correct `policy_ref`.

### Unit tests for `PolicySet` (in `policy.rs`)
- `insert` + `get` round-trip.
- `insert` replaces existing policy with same name.
- `remove` returns `Some` for existing, `None` for non-existent.
- `len` and `is_empty` correctness.
- `iter` yields all policies.
- `produce_all_static` with multiple static policies returns unioned `StateSet`.
- `produce_all_static` skips non-static (`Dhcpv4`) policies.
- `produce_all_static` returns `FactoryError::ConflictError` on equal-priority conflicts.
- `produce_all_static` resolves by priority when priorities differ.

### Unit tests for `parse_policy_yaml` (in `parse.rs`)
- Single policy document: verify `name`, `factory_type`, `priority`, `state` fields.
- Multi-entity policy (`states`): verify correct count and entity types.
- DHCPv4 policy with `selector`: verify `factory_type`, `selector`, and absence of `state`/`states`.
- Default priority: omitting `priority` yields 100.
- Multi-document YAML (two policies separated by `---`): verify both are returned.
- Invalid `kind` value (e.g., `kind: foobar`): verify error.
- `kind: state` or missing `kind`: verify `UnsupportedKind` error (SPEC-008 boundary).
- Missing `name` field: verify error.
- Missing `factory` field: verify error.
- Trailing `---` (null document): silently skipped, not an error.

### Integration-level tests
- Parse a policy YAML string, then run `StaticFactory::produce` on the result, and verify the output `StateSet` matches expectations. This end-to-end test validates that the flat-format state parsing and factory logic work together correctly.

### Test infrastructure needed
- Helper functions to build `Policy` and `State` values programmatically (similar to `make_state` in `set.rs` tests).
- No external test fixtures or mocks needed — everything is in-memory string parsing and struct construction.
