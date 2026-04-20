# Plan: SPEC-005 YAML Serialization

## Approach

The implementation adds two new modules to the `netfyr-state` crate: `yaml.rs` for custom flat-format serialization/deserialization logic, and `loader.rs` for file/directory loading. These are re-exported from `lib.rs`.

The core design challenge is that the YAML user-facing format is *flat* (all keys at the top level) while the internal `State` struct is *nested* (entity_type, selector, fields are separate). The existing `#[derive(Serialize, Deserialize)]` on `State` produces a nested JSON-style representation — it cannot be reused for YAML. Similarly, `Value`'s `#[serde(untagged)]` derive doesn't handle the IP-address-vs-string ambiguity in YAML (where IPs arrive as plain YAML strings, not typed values). Therefore, we build a manual conversion layer that operates on raw `serde_yaml::Value` objects, classifying keys by role (entity type, selector, meta, config) and applying type-inference heuristics for values. This avoids fighting serde's derive system and keeps the existing JSON serialization entirely untouched.

The alternative — implementing custom `Serialize`/`Deserialize` traits on `State` with format-switching logic — would be more complex and risk breaking the existing JSON path. Another alternative — creating a separate `YamlState` DTO struct — would add unnecessary type duplication. The raw-value approach is simpler: parse YAML into `serde_yaml::Value`, manually extract fields by classification, and construct `State` directly.

For directory loading, `walkdir` provides recursive traversal with `DirEntry`-level filtering for hidden files. Since `StateSet::insert()` silently replaces duplicates, `load_dir` must pre-check with `StateSet::get()` before each insert to detect and error on duplicate entity keys across files.

## Design Decisions

1. **Module naming: `yaml` not `serde`**
   - **Decision**: Name the module `yaml` (file: `src/yaml.rs`), not `serde` as the spec suggests.
   - **Alternatives considered**: `serde.rs` (spec suggestion), `yaml_serde.rs`, `serde_yaml_support.rs`.
   - **Rationale**: `pub mod serde;` in `lib.rs` conflicts with the external `serde` crate name that is used extensively via `use serde::{Serialize, Deserialize}`. Rust's module resolution would shadow the crate. `yaml` is short, clear, and idiomatic.

2. **Raw `serde_yaml::Value` conversion instead of custom Deserialize impl**
   - **Decision**: Parse YAML into `serde_yaml::Value`, then manually convert to `State` via `parse_raw_to_state()`. Do not implement `serde::Deserialize` for a YAML-specific `State` representation.
   - **Alternatives considered**: Custom `Deserialize` impl on `State` (or a `FlatState` DTO).
   - **Rationale**: A custom `Deserialize` on `State` would break JSON deserialization or require `#[serde(deserialize_with)]` gymnastics. A DTO adds type duplication. Raw value conversion is straightforward, testable, and isolated from the existing serde derives.

3. **Error type: `YamlError` enum using `thiserror`**
   - **Decision**: Define `pub enum YamlError` in `yaml.rs` with variants for parse errors, IO errors, missing fields, invalid kind, MAC parse failures, and duplicate keys. Use `thiserror` (already a dependency) for `Display`/`Error` derives.
   - **Alternatives considered**: A single struct with an error kind enum; `anyhow::Error`.
   - **Rationale**: `thiserror` enum is idiomatic for library crates. Distinct variants allow callers to match on error types. `anyhow` is inappropriate for a library crate — it erases error types.

4. **Unknown `kind` values are errors**
   - **Decision**: If `kind` is present and is not `"state"`, `parse_yaml` returns an error.
   - **Alternatives considered**: Skip unknown kinds silently (to be forwards-compatible with SPEC-007's `kind: policy`).
   - **Rationale**: The spec says "return error (or skip, depending on context)" and SPEC-007 is not yet implemented. Erroring is safer — when SPEC-007 lands, it can adjust `parse_yaml` to handle `kind: policy` or the caller can pre-filter documents. Silent skipping could mask typos like `kind: stat`.

5. **Explicit format serialization via a boolean parameter**
   - **Decision**: Provide `pub fn serialize_state(state: &State) -> serde_yaml::Value` (bare, no `kind`) and `pub fn serialize_state_explicit(state: &State) -> serde_yaml::Value` (with `kind: state`). Alternatively, a single function `pub fn state_to_yaml(state: &State, explicit: bool) -> String` that calls the appropriate internal function and renders to a YAML string.
   - **Alternatives considered**: A format enum (`YamlFormat::Bare | Explicit`), builder pattern.
   - **Rationale**: Two use cases exist (bare for user output, explicit for policy embedding). A boolean or two functions is the simplest representation. A format enum is overkill for a two-option toggle. Choose two functions for clarity and to avoid boolean-argument ambiguity.

6. **`Selector.mac` stored as `Option<MacAddr>`, parsed from YAML string**
   - **Decision**: When the YAML contains `mac: "aa:bb:cc:dd:ee:ff"`, parse it via `MacAddr::from_str()` and store in `selector.mac`. Propagate parse errors as `YamlError::InvalidMac`.
   - **Alternatives considered**: Store MAC as a string in the selector.
   - **Rationale**: `Selector.mac` is already `Option<MacAddr>`, so we must parse. The existing `MacAddr::from_str` handles validation.

7. **`Selector.entity_type` left as `None` in YAML deserialization**
   - **Decision**: The flat YAML `type` key maps to `State.entity_type` only. `Selector.entity_type` is not populated from YAML.
   - **Alternatives considered**: Copy `type` into both `State.entity_type` and `Selector.entity_type`.
   - **Rationale**: The understanding analysis identifies that `Selector.entity_type` is for runtime matching, not user configuration. The spec's `SELECTOR_KEYS` constant deliberately excludes `entity_type`. Populating it would conflate two distinct uses.

8. **`Selector.labels` not populated from YAML**
   - **Decision**: YAML deserialization does not populate `Selector.labels`. Labels are not in `SELECTOR_KEYS`.
   - **Alternatives considered**: Treating a top-level `labels` key as selector labels.
   - **Rationale**: The spec defines the selector keys as `["name", "driver", "mac", "pci_path"]`. A `labels` key in YAML would go into `fields`, not the selector. This matches the property classification rules.

9. **Hidden file filtering applies to file names and directory names**
   - **Decision**: Skip any `walkdir` entry whose file name (final path component) starts with `.`. This applies to both files and directories, effectively skipping hidden directories entirely.
   - **Alternatives considered**: Only skip hidden files, descend into hidden directories.
   - **Rationale**: Hidden directories (`.git`, `.backup/`) are conventionally excluded from configuration loading. `walkdir` supports `filter_entry` which skips entire subtrees, which is both correct and efficient.

10. **Floating-point YAML numbers produce an error**
    - **Decision**: If a YAML number is floating-point (e.g., `1500.0`), return a `YamlError` indicating that float values are not supported.
    - **Alternatives considered**: Truncate to integer, store as string, add a `Float` variant.
    - **Rationale**: The `Value` enum has no float variant. Silently truncating could lose data. The spec doesn't mention floats. Erroring is the safest behavior and guides users to use integers.

11. **YAML null values produce an error**
    - **Decision**: A YAML `null` value in a field position returns an error.
    - **Alternatives considered**: Skip null fields, map to an empty string.
    - **Rationale**: `Value` has no null/none variant. Skipping silently could mask user intent. An explicit error is clearer.

12. **Duplicate key error in `load_dir` includes filenames**
    - **Decision**: Track which file each state came from. On duplicate, the error message includes both the entity key and the file path where the duplicate was found.
    - **Alternatives considered**: Just report the entity key without file paths.
    - **Rationale**: Users need to know which files conflict to fix the issue. We track `(entity_type, selector_key) -> PathBuf` in a HashMap during loading.

## File Changes

### `crates/netfyr-state/Cargo.toml`
- **Action**: modify
- **What**: Add two new dependencies:
  - `serde_yaml = "0.9"` — YAML parsing and emission
  - `walkdir = "2"` — recursive directory traversal
- **Why**: These are required by the spec. `serde_yaml` 0.9 provides `serde_yaml::Deserializer::from_str` for multi-document parsing and `serde_yaml::Value` for raw value manipulation. `walkdir` provides `WalkDir` with `filter_entry` for hidden-file skipping.

### `crates/netfyr-state/src/yaml.rs`
- **Action**: create
- **What**: This module contains all YAML-specific serialization and deserialization logic.

  **Constants**:
  - `const SELECTOR_KEYS: &[&str] = &["name", "driver", "mac", "pci_path"];`
  - `const META_KEYS: &[&str] = &["kind", "type"];`

  **Error type**:
  - `pub enum YamlError` with variants:
    - `Parse(serde_yaml::Error)` — YAML syntax error
    - `Io { path: PathBuf, source: std::io::Error }` — file read error
    - `MissingType` — document has no `type` key
    - `InvalidKind(String)` — `kind` is present but not `"state"`
    - `InvalidMac { value: String, source: MacAddrParseError }` — `mac` key can't be parsed
    - `DuplicateKey { entity_type: String, selector_key: String, path: PathBuf }` — duplicate entity in directory load
    - `InvalidValue(String)` — unsupported YAML value (null, float)
    - `ExpectedMapping` — document is not a YAML mapping
    - `ExpectedString { key: String }` — a selector key or `type` is not a string
  - Implement `std::fmt::Display` and `std::error::Error` via `#[derive(thiserror::Error)]`.

  **Value conversion functions**:
  - `pub fn deserialize_value(v: &serde_yaml::Value) -> Result<Value, YamlError>` — Converts a `serde_yaml::Value` to the crate's `Value` enum using the heuristic:
    1. `Value::Bool` if YAML bool
    2. `Value::Number` → check `as_u64()` first (returns `Value::U64`), then `as_i64()` (returns `Value::I64`), then error if float
    3. YAML string → try `IpNetwork::from_str()`, then `IpAddr::from_str()`, fall back to `Value::String`
    4. YAML sequence → `Value::List` (recurse on each element)
    5. YAML mapping → `Value::Map` (recurse on each value; keys must be strings)
    6. YAML null → error
    7. YAML tagged → error (not expected)

  - `pub fn serialize_value(v: &Value) -> serde_yaml::Value` — Converts the crate's `Value` to a `serde_yaml::Value`:
    - `Value::Bool(b)` → `serde_yaml::Value::Bool(b)`
    - `Value::U64(n)` → `serde_yaml::Value::Number(n.into())`
    - `Value::I64(n)` → `serde_yaml::Value::Number(n.into())`
    - `Value::String(s)` → `serde_yaml::Value::String(s.clone())`
    - `Value::IpAddr(ip)` → `serde_yaml::Value::String(ip.to_string())`
    - `Value::IpNetwork(net)` → `serde_yaml::Value::String(net.to_string())`
    - `Value::List(items)` → `serde_yaml::Value::Sequence(items.iter().map(serialize_value).collect())`
    - `Value::Map(map)` → `serde_yaml::Value::Mapping(...)` (recurse on values)

  **State parsing**:
  - `fn parse_raw_to_state(raw: serde_yaml::Value) -> Result<State, YamlError>` — Takes a single YAML document as a `serde_yaml::Value`:
    1. Verify it's a Mapping, else return `ExpectedMapping`.
    2. Check for `kind` key: if present and not `"state"`, return `InvalidKind`.
    3. Extract `type` key as string → `entity_type`. Return `MissingType` if absent.
    4. Build `Selector`: iterate `SELECTOR_KEYS`, extract each if present. For `mac`, call `MacAddr::from_str()`. For others, extract as string. Leave `entity_type`, `labels` as defaults on Selector.
    5. Build `fields: IndexMap<String, FieldValue>`: iterate all mapping entries, skip those whose key is in `META_KEYS` or `SELECTOR_KEYS`. For each remaining entry, call `deserialize_value()` on the value, wrap in `FieldValue { value, provenance: Provenance::UserConfigured { policy_ref: "".to_string() } }`.
    6. Construct and return `State { entity_type, selector, fields, metadata: StateMetadata::new(), policy_ref: None, priority: 100 }`.

  **Multi-document parsing**:
  - `pub fn parse_yaml(input: &str) -> Result<Vec<State>, YamlError>` — Uses `serde_yaml::Deserializer::from_str(input)` to iterate over YAML documents. For each document, deserialize into `serde_yaml::Value`, then call `parse_raw_to_state()`. Collect results into a `Vec<State>`. Return empty vec for empty input.

  **State serialization**:
  - `pub fn state_to_yaml(state: &State) -> Result<String, YamlError>` — Calls `serialize_state_to_value(state)` and renders to a YAML string via `serde_yaml::to_string()`.
  - `pub fn state_to_yaml_explicit(state: &State) -> Result<String, YamlError>` — Same but inserts `kind: state` as the first key.
  - `fn serialize_state_to_value(state: &State) -> serde_yaml::Value` — Builds a `serde_yaml::Mapping`:
    1. Insert `"type"` → entity_type.
    2. For each selector field (`name`, `driver`, `mac`, `pci_path`): if `Some`, insert the key with the string value. For `mac`, use `MacAddr::to_string()`.
    3. For each entry in `state.fields`: insert the key with `serialize_value(&fv.value)`.
    4. Return as `serde_yaml::Value::Mapping`.
  - `fn serialize_state_to_value_explicit(state: &State) -> serde_yaml::Value` — Same as above but inserts `"kind": "state"` before `"type"`.

- **Why**: This module encapsulates the flat-format YAML logic, keeping it separate from the existing serde derives. The raw-value approach avoids conflicting with `State`'s existing `Serialize`/`Deserialize` impls.

### `crates/netfyr-state/src/loader.rs`
- **Action**: create
- **What**: File and directory loading functions.

  - `pub fn load_file(path: &Path) -> Result<Vec<State>, YamlError>` — Reads the file contents via `std::fs::read_to_string()`, wraps IO errors with the file path (using `YamlError::Io`), then calls `parse_yaml()` on the contents.

  - `pub fn load_dir(path: &Path) -> Result<StateSet, YamlError>` — Recursively loads a directory:
    1. Create `WalkDir::new(path)` with `filter_entry` that skips entries whose file name starts with `.` (hidden files/directories). This uses `entry.file_name().to_str().map_or(false, |s| !s.starts_with('.'))` as the filter predicate. Note: the root directory itself should not be filtered (it's the path the user specified), so the filter only applies to entries below the root — `walkdir` handles this correctly since the root entry's file name is the directory name, which typically doesn't start with `.`.
    2. For each file entry (skip directories): check if the extension is `"yaml"` or `"yml"`. Skip others.
    3. Call `load_file()` on each matching file.
    4. For each `State` returned, compute the key `(entity_type, selector.key())`. Check if `StateSet::get(entity_type, selector_key)` returns `Some` — if so, return `YamlError::DuplicateKey` with the entity key and the current file path. Otherwise, call `StateSet::insert()`.
    5. Return the populated `StateSet`.

  - Note on WalkDir error handling: `walkdir` entries can themselves be errors (permission denied, broken symlinks). These should be propagated as IO errors with path context.

- **Why**: Separating file I/O from parsing logic keeps `yaml.rs` focused on data transformation and `loader.rs` focused on filesystem interaction. This separation makes `yaml.rs` independently testable without filesystem fixtures.

### `crates/netfyr-state/src/lib.rs`
- **Action**: modify
- **What**:
  1. Add `pub mod yaml;` and `pub mod loader;` module declarations after the existing `pub mod set;`.
  2. Add re-exports:
     - `pub use yaml::{parse_yaml, state_to_yaml, state_to_yaml_explicit, deserialize_value, serialize_value, YamlError};`
     - `pub use loader::{load_file, load_dir};`
- **Why**: Makes the YAML parsing and loading functions part of the crate's public API, accessible as `netfyr_state::parse_yaml(...)` etc.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `serde_yaml` | `"0.9"` | Required for YAML parsing and emission. Provides `serde_yaml::Deserializer::from_str` for multi-document iteration, `serde_yaml::Value` for raw value manipulation, and `serde_yaml::to_string` for rendering. No std alternative exists. |
| `walkdir` | `"2"` | Required for recursive directory traversal in `load_dir`. `std::fs::read_dir` is not recursive and would require manual recursion with hidden-file filtering. `walkdir` provides `filter_entry` for efficient subtree pruning and handles symlinks and permission errors. |

## Implementation Order

1. **Add dependencies to `Cargo.toml`** — Add `serde_yaml` and `walkdir`. This enables all subsequent steps to compile.

2. **Create `src/yaml.rs` with error type and constants** — Define `YamlError`, `SELECTOR_KEYS`, `META_KEYS`. These are prerequisites for all functions. Compilable: yes (the error type stands alone).

3. **Implement `deserialize_value` and `serialize_value` in `yaml.rs`** — The value conversion functions. These depend on the `Value` enum from `lib.rs` and `serde_yaml::Value`. No dependency on `State`. Compilable: yes.

4. **Implement `parse_raw_to_state` and `parse_yaml` in `yaml.rs`** — These depend on step 3 for value conversion and on `State`, `Selector`, `FieldValue`, `Provenance`, `StateMetadata`, `MacAddr` from `lib.rs`. Compilable: yes.

5. **Implement `state_to_yaml` and `state_to_yaml_explicit` in `yaml.rs`** — These depend on step 3 for `serialize_value`. Compilable: yes.

6. **Create `src/loader.rs` with `load_file` and `load_dir`** — Depends on steps 2-4 for `parse_yaml`, `YamlError`, and `StateSet`. Compilable: yes.

7. **Update `src/lib.rs` with module declarations and re-exports** — Depends on steps 2-6 (all modules must exist). Compilable: yes. This step can be partially done earlier (adding `pub mod yaml;` after step 2, `pub mod loader;` after step 6) or done all at once at the end.

## Risks and Mitigations

### 1. `serde_yaml` 0.9 API stability
**Risk**: `serde_yaml` 0.9 is marked as a pre-1.0 release. Some APIs (particularly around `Value::Number` internals) may differ between 0.9.x patch versions.
**Mitigation**: Pin to `"0.9"` (any 0.9.x). The APIs used (`Deserializer::from_str`, `Value` enum, `to_string`) are stable across 0.9.x. The `Number` type's `as_u64()` and `as_i64()` methods are stable.

### 2. `serde_yaml` Number type details
**Risk**: `serde_yaml` 0.9 uses `serde_yaml::Number` which wraps `serde_json::Number` internally (in some versions). The behavior of `as_u64()` for large numbers or `as_f64()` for integers needs care.
**Mitigation**: Check `as_u64()` first (returns `Some` for non-negative integers that fit), then `as_i64()` (returns `Some` for negative integers that fit). If both return `None`, the number is a float — return an error. This covers all integer cases correctly.

### 3. YAML boolean vs. string ambiguity
**Risk**: YAML 1.1 (which `serde_yaml` 0.9 uses) treats `yes`, `no`, `on`, `off`, `y`, `n` as booleans. A user writing `mode: on` would get `Value::Bool(true)` instead of `Value::String("on")`.
**Mitigation**: This is a known YAML 1.1 behavior. Users must quote such values: `mode: "on"`. Document this in error messages or user-facing docs if needed. No code mitigation is required — the heuristic correctly processes the `serde_yaml::Value` as-is.

### 4. Round-trip fidelity for IP addresses
**Risk**: After round-tripping, a plain string like `"10.0.1.1"` will be deserialized as `Value::IpAddr` rather than `Value::String`. This is by design (the heuristic), but means `Value::String("10.0.1.1")` cannot survive a YAML round-trip.
**Mitigation**: This is the intended behavior per spec. The spec explicitly states: "a string value is first attempted as IpNetwork, then as IpAddr, and falls back to String." When schema validation is available (SPEC-006), it provides type hints to disambiguate. No code change needed.

### 5. `walkdir` root entry filtering
**Risk**: If the user passes a path like `/etc/netfyr/.policies/`, the directory name starts with `.`, and naive hidden-file filtering would skip the root directory itself.
**Mitigation**: The `filter_entry` predicate should only skip hidden entries at depth > 0, or more simply, `walkdir` processes the root entry first and hidden-name filtering on the root is safe because `WalkDir::new` always yields the root regardless. Actually, the cleanest approach: apply the hidden-file filter only to the file name component. If the root directory name starts with `.`, the user explicitly asked to load it, so we should process it. The `filter_entry` callback receives entries including the root — only apply the hidden check to non-root entries (check `entry.depth() > 0`).

### 6. File ordering in `load_dir` affecting duplicate detection
**Risk**: `walkdir` iteration order is not guaranteed to be deterministic across platforms. If two files have the same entity key, which one is reported as the "duplicate" depends on traversal order.
**Mitigation**: The error reports the path of the file that triggered the duplicate detection. The first file processed "wins" and the second triggers the error. Since both files are incorrect (they shouldn't both exist), the exact ordering of the error message is acceptable. For fully deterministic behavior, sort file paths before processing — but this is not required by the spec.

### 7. Empty YAML documents
**Risk**: A YAML file might contain `---` separators with empty documents between them (e.g., `---\n---`). `serde_yaml::Deserializer` yields `Value::Null` for these.
**Mitigation**: In `parse_yaml`, check if the deserialized value is `Value::Null` and skip it silently (an empty document is not an error, just nothing to parse). This prevents confusing errors when users have trailing `---` separators.

### 8. Large files or deeply nested values
**Risk**: Very large YAML files or deeply nested structures could cause stack overflow in the recursive `deserialize_value`.
**Mitigation**: Practical network config files are shallow (routes have 2-3 levels max). No mitigation needed for the MVP. If this becomes a concern, an iterative approach can be added later.

## Test Strategy

### Unit tests for `yaml.rs`

**Value deserialization heuristic** (most important to test exhaustively):
- YAML bool `true`/`false` → `Value::Bool`
- YAML non-negative integer → `Value::U64`
- YAML negative integer → `Value::I64`
- YAML string that is a valid IP → `Value::IpAddr`
- YAML string that is a valid CIDR → `Value::IpNetwork`
- YAML string that is not an IP → `Value::String`
- YAML sequence → `Value::List` with recursion
- YAML mapping → `Value::Map` with recursion
- YAML null → error
- YAML float → error
- Nested structures (list of maps, map of lists)
- Edge cases: `"0.0.0.0"` (valid IP), `"::1"` (IPv6), `"10.0.0.0/8"` (IPv4 network), `"802.3ad"` (looks numeric-ish but is a string), empty string

**Value serialization**:
- Each `Value` variant round-trips correctly through serialize → deserialize
- `IpAddr` and `IpNetwork` serialize as strings
- Nested structures serialize correctly

**State parsing (`parse_yaml`)**:
- Bare state (no `kind`) with `type`, `name`, and config fields
- Explicit state (`kind: state`) produces identical result to bare
- Multi-document YAML (two documents separated by `---`)
- Missing `type` → error
- Invalid `kind` (e.g., `kind: policy`) → error
- Selector properties (`name`, `driver`, `mac`, `pci_path`) go into `Selector`, not `fields`
- MAC address parsing (valid and invalid)
- `entity_type` key in YAML goes to `State.entity_type`, not `Selector.entity_type`
- Empty document (just `---`) is skipped
- Fields get `Provenance::UserConfigured { policy_ref: "" }`
- `metadata` is freshly generated
- `priority` is 100

**State serialization (`state_to_yaml`)**:
- Output is flat YAML (no `selector:`, `fields:`, `metadata:` keys)
- Contains `type`, selector fields, and config fields at top level
- `kind` is absent in bare format
- `kind: state` is present in explicit format
- MAC address serializes as string
- Field order: `type` first, then selectors, then config fields

**Round-trip tests**:
- Parse → serialize → parse produces equivalent data (except metadata, which is regenerated)

### Unit tests for `loader.rs`

These require filesystem fixtures (temp directories with YAML files). Use `std::fs` and `tempfile` (or `std::env::temp_dir` + manual cleanup) to create test directories.

- `load_file` with a valid single-document YAML file
- `load_file` with a multi-document YAML file
- `load_file` with a nonexistent path → IO error
- `load_file` with invalid YAML → parse error with filename context
- `load_dir` with multiple `.yaml` and `.yml` files
- `load_dir` skips hidden files (`.backup.yaml`)
- `load_dir` skips hidden directories (`.git/`)
- `load_dir` skips non-YAML files (`.txt`, `.json`)
- `load_dir` with multi-document files in directory
- `load_dir` with duplicate entity keys across files → `DuplicateKey` error
- `load_dir` with empty directory → empty `StateSet`
- `load_dir` recursive traversal (nested subdirectories)

### Test infrastructure
- A helper function similar to `set.rs`'s `make_state()` for constructing test `State` values
- `tempfile` crate (or manual temp dir management) for filesystem tests in `loader.rs`. If `tempfile` is not desired as a dev-dependency, use `std::env::temp_dir()` with unique directory names and cleanup in a `Drop` guard. The `tempfile` crate is cleaner — add it as a `[dev-dependencies]` entry.
- No mocking needed — all I/O is filesystem-based and easily tested with real temp files
