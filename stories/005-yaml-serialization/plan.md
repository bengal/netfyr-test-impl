# Plan: SPEC-005 YAML Serialization

## Status: Implementation Complete

All functional requirements from SPEC-005 are already implemented and tested. The `netfyr-state` crate contains fully working YAML serialization/deserialization in `src/yaml.rs`, file/directory loading in `src/loader.rs`, and correct re-exports in `src/lib.rs`. All 225 unit tests pass (verified via `cargo test -p netfyr-state --lib`). The only remaining work is cleaning up two stale test comments that describe a bug that has already been fixed.

## Approach

The implementation uses a raw `serde_yaml::Value` conversion layer in `src/yaml.rs` to bridge the flat user-facing YAML format and the nested internal `State` struct. This avoids conflicting with the existing `#[derive(Serialize, Deserialize)]` on `State` (which produces a nested JSON-style representation). Top-level YAML keys are classified into entity type (`type`), selector properties (`name`, `driver`, `mac`, `pci_path`), meta properties (`kind`), and configuration fields (everything else). Value deserialization uses a heuristic: bool → Bool, int≥0 → U64, int<0 → I64, string with `/` → try IpNetwork, string without `/` → try IpAddr, fallback String, sequence → List, mapping → Map.

The alternative of implementing custom `Serialize`/`Deserialize` traits on `State` was correctly rejected — it would risk breaking the existing JSON serialization path. A separate `YamlState` DTO was also rejected to avoid type duplication. The raw-value approach is simpler, testable, and isolated.

Directory loading in `src/loader.rs` uses `walkdir` for recursive traversal with `filter_entry` to skip hidden files/directories. Duplicate entity detection uses `StateSet::get()` before `insert()` since `insert()` silently replaces.

## Design Decisions

1. **Module naming: `yaml` not `serde`**
   - **Decision**: The module is named `yaml` (file: `src/yaml.rs`), not `serde` as the spec's implementation details section suggests.
   - **Alternatives considered**: `serde.rs` (spec suggestion), `yaml_serde.rs`.
   - **Rationale**: `pub mod serde;` in `lib.rs` would conflict with the external `serde` crate name used via `use serde::{Serialize, Deserialize}`. Rust's module resolution would shadow the crate. `yaml` is clear and idiomatic. This deviation from the spec is cosmetic — all public API signatures match.

2. **Raw `serde_yaml::Value` conversion instead of custom Deserialize impl**
   - **Decision**: Parse YAML into `serde_yaml::Value`, then manually convert to `State` via `parse_raw_to_state()`.
   - **Alternatives considered**: Custom `Deserialize` impl on `State`, `FlatState` DTO.
   - **Rationale**: A custom `Deserialize` on `State` would break JSON deserialization. A DTO adds type duplication. Raw value conversion is straightforward and testable.

3. **Error type: `YamlError` enum using `thiserror`**
   - **Decision**: `pub enum YamlError` in `yaml.rs` with 9 variants: `Parse`, `Io`, `MissingType`, `InvalidKind`, `InvalidMac`, `DuplicateKey`, `InvalidValue`, `ExpectedMapping`, `ExpectedString`.
   - **Alternatives considered**: Single struct with kind enum; `anyhow::Error`.
   - **Rationale**: `thiserror` enum is idiomatic for library crates. Distinct variants allow callers to match on error types. Already a dependency.

4. **Unknown `kind` values are errors**
   - **Decision**: If `kind` is present and not `"state"`, `parse_yaml` returns `InvalidKind` error.
   - **Alternatives considered**: Skip unknown kinds silently.
   - **Rationale**: Erroring is safer — prevents typos like `kind: stat`. When SPEC-007 (policies) needs `kind: policy`, the policy loader handles its own parsing path, not `parse_yaml`.

5. **Two separate serialization functions instead of a boolean parameter**
   - **Decision**: `state_to_yaml()` for bare format, `state_to_yaml_explicit()` for `kind: state` format. Internal helpers `serialize_state_to_value()` (public, for policy embedding) and `serialize_state_to_value_explicit()` (private).
   - **Alternatives considered**: Single function with boolean `explicit` parameter.
   - **Rationale**: Two functions avoids boolean-argument ambiguity. `serialize_state_to_value()` is public so `netfyr-policy` can embed flat-format states in policy YAML.

6. **`parse_state_value` as public entry point**
   - **Decision**: `pub fn parse_state_value(raw: serde_yaml::Value) -> Result<State, YamlError>` wraps `parse_raw_to_state` as a public API for SPEC-007 policy embedding.
   - **Alternatives considered**: Making `parse_raw_to_state` public directly.
   - **Rationale**: Provides a stable public API name distinct from the internal implementation function, even though they're currently identical. SPEC-007's policy parser needs to convert embedded `state:` sub-documents without re-serializing to strings.

7. **`Selector.entity_type` not populated from YAML**
   - **Decision**: The flat YAML `type` key maps only to `State.entity_type`. `Selector.entity_type` remains `None`.
   - **Alternatives considered**: Copy `type` into both.
   - **Rationale**: `Selector.entity_type` is for runtime matching, not user configuration. The spec's `SELECTOR_KEYS` constant deliberately excludes `entity_type`.

8. **IP address heuristic: `/` guard prevents bare IPs from matching IpNetwork**
   - **Decision**: Before attempting `Ipv4Network::from_str`, check if the string contains `/`. Only attempt IpNetwork parse if `/` is present.
   - **Alternatives considered**: Always try IpNetwork first (the `ipnetwork` crate accepts bare IPs as /32 host routes).
   - **Rationale**: Without the guard, `"10.0.1.1"` would parse as `IpNetwork(10.0.1.1/32)` instead of `IpAddr(10.0.1.1)`, violating the spec. The `/` guard ensures bare IPs fall through to the `IpAddr` branch. This is implemented at `yaml.rs:110`.

9. **Empty YAML documents silently skipped**
   - **Decision**: In `parse_yaml`, `serde_yaml::Value::Null` documents (from `---` separators with nothing between them) are skipped.
   - **Alternatives considered**: Error on empty documents.
   - **Rationale**: Users commonly have trailing `---` separators. Erroring would be annoying. Skipping is harmless.

10. **Hidden file filtering: depth-0 root always included**
    - **Decision**: `filter_entry` in `load_dir` always returns `true` for `entry.depth() == 0`. Hidden-name filtering only applies at depth > 0.
    - **Alternatives considered**: Filter at all depths.
    - **Rationale**: If the user explicitly names a hidden directory (e.g., `load_dir(".policies/")`), they intend to load it. Only skip hidden entries found during recursion.

## File Changes

### `crates/netfyr-state/Cargo.toml`
- **Action**: no change needed (already has `serde_yaml = "0.9"` and `walkdir = "2"`)

### `crates/netfyr-state/src/yaml.rs`
- **Action**: modify (cleanup only)
- **What**: Fix two stale test comments that describe a bug that has already been fixed by the `/` guard at line 110:
  1. `test_deserialize_value_ip_addr_string_becomes_ip_addr` (line ~467-475): Remove the "BUG:" comment block that says "will fail until the heuristic is fixed." The heuristic IS fixed. The test passes.
  2. `test_round_trip_yaml_ip_addr_becomes_ip_network_bug` (line ~962-969): Remove the "BUG:" comment and rename the test to `test_round_trip_yaml_ip_addr_preserves_correctly` (or similar). The comment claims the result is `Value::IpNetwork` but the assertion correctly expects `Value::IpAddr`, and the test passes. Also update the comment in `test_round_trip_yaml_various_field_types` (line ~905-912) that references this "bug" — remove the mention since it's not a bug anymore.
- **Why**: Stale comments claiming bugs exist in working code mislead future developers. The tests themselves are correct and pass; only the comments are wrong.

### `crates/netfyr-state/src/loader.rs`
- **Action**: no change needed (fully implemented)

### `crates/netfyr-state/src/lib.rs`
- **Action**: no change needed (all re-exports present)

## Dependencies

No new dependencies needed. Both required crates are already in `Cargo.toml`:

| Crate | Version | Status |
|-------|---------|--------|
| `serde_yaml` | `"0.9"` | Already present |
| `walkdir` | `"2"` | Already present |

## Implementation Order

1. **Fix stale test comment in `test_deserialize_value_ip_addr_string_becomes_ip_addr`** — Remove the misleading "BUG:" comment block (lines ~468-475). The heuristic works correctly with the `/` guard at line 110.

2. **Fix stale test name and comment in `test_round_trip_yaml_ip_addr_becomes_ip_network_bug`** — Rename to `test_round_trip_yaml_ip_addr_round_trips_correctly`. Remove the "BUG:" comment block (lines ~962-969) that claims the result is `IpNetwork`. The assertion already correctly expects `Value::IpAddr`.

3. **Fix reference to the "bug" in `test_round_trip_yaml_various_field_types`** — Update the doc comment (lines ~905-912) that says IpAddr is omitted "because of the IpNetwork heuristic bug." Add IpAddr to the test's field set since round-trip now works correctly.

4. **Run `cargo test -p netfyr-state --lib`** — Verify all tests still pass after the comment/name changes.

Each step results in a compilable, test-passing state.

## Risks and Mitigations

### 1. False confidence from stale comments
**Risk**: The stale "BUG" comments could lead a developer to "fix" working code, thinking it's broken.
**Mitigation**: This is exactly what the cleanup addresses. Removing the misleading comments prevents this.

### 2. IpAddr round-trip precision
**Risk**: `Value::IpAddr(10.0.1.1)` serializes as string `"10.0.1.1"`, re-parses as `Value::IpAddr` thanks to the `/` guard. If the guard were removed, this would break.
**Mitigation**: The guard at `yaml.rs:110` is well-commented explaining why it exists. Tests explicitly verify this behavior.

### 3. `kind` boundary with SPEC-007
**Risk**: `parse_yaml` errors on `kind: policy`. Policy files must NOT be passed to `parse_yaml`.
**Mitigation**: SPEC-007's policy loader already uses its own parsing path (`parse_policy_from_value` in `netfyr-policy`), calling `parse_state_value()` only for embedded state sub-documents. The boundary is clean.

### 4. Intra-file duplicate detection
**Risk**: Two states with identical selectors within a single multi-document file result in the second silently replacing the first via `StateSet::insert`. The spec only requires cross-file duplicate detection.
**Mitigation**: Acceptable per spec. Intra-file duplicates are an edge case that could be addressed in a future story if needed.

### 5. YAML 1.1 boolean ambiguity
**Risk**: `serde_yaml` 0.9 uses YAML 1.1 which treats `yes`, `no`, `on`, `off` as booleans. A user writing `mode: on` gets `Value::Bool(true)`.
**Mitigation**: Known YAML 1.1 behavior. Users must quote: `mode: "on"`. No code change needed.

## Test Strategy

All tests are already implemented and passing. The existing test suite covers:

### Unit tests in `yaml.rs` (35+ tests)
- **Value deserialization heuristic**: bool true/false, positive/negative integers, zero, IP addresses, CIDR networks, plain strings, null (error), sequences, mappings
- **State parsing**: bare format, explicit `kind: state`, multi-document, driver selector, route objects, selector exclusion from fields, missing type error, invalid kind error, trailing separator skip, provenance verification
- **State serialization**: flat format contains type/name/mtu at top level, no `kind:` in bare format, no `selector:`/`fields:` nesting, explicit format has `kind: state` before `type:`
- **Round-trip**: preserves entity_type, selector.name, field values; metadata.id regenerated; various field types (string, U64, bool, IpNetwork, list, map); IpAddr round-trip

### Unit tests in `loader.rs` (7 tests)
- `load_dir`: three files (.yaml + .yml), multi-document file, hidden file skip, duplicate key error, invalid YAML error, empty directory, non-YAML file ignore
- `load_file`: single document, nonexistent path error

### After cleanup (step 3)
- `test_round_trip_yaml_various_field_types` should be extended to include `Value::IpAddr` in its field set, since the IpAddr round-trip now works correctly. This validates the fix that was already applied.

### No additional test infrastructure needed
- Tests use `std::env::temp_dir()` with unique names (PID + atomic counter) for filesystem tests — no `tempfile` dev-dependency needed
- Helper function `make_state()` and `make_fv()` already exist for constructing test fixtures
