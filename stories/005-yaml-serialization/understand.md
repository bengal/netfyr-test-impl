# SPEC-005: YAML Serialization — Gap Analysis

## Current State

The `netfyr-state` crate (`crates/netfyr-state/`) contains a complete data model with no YAML-specific code:

**Types (all in `src/lib.rs`):**
- `State` — top-level entity with `entity_type: String`, `selector: Selector`, `fields: IndexMap<String, FieldValue>`, `metadata: StateMetadata`, `policy_ref: Option<String>`, `priority: u32`. Derives standard `Serialize`/`Deserialize` (nested/structured format).
- `Selector` — has fields `name`, `entity_type`, `driver`, `pci_path`, `mac: Option<MacAddr>`, `labels: HashMap<String, String>`. Note: `Selector` has its own `entity_type` field distinct from `State.entity_type`.
- `Value` — enum with `Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `List`, `Map`, `String` variants. Uses `#[serde(untagged)]`, with variant order optimized for JSON disambiguation (Bool first, then numerics, then IP types before String). This ordering does not work for YAML strings (IP-looking strings are YAML strings, not native YAML types).
- `FieldValue` — wraps `value: Value` plus `provenance: Provenance`. Standard `Serialize`/`Deserialize` emits both fields as a JSON object — not the flat plain-value format required for YAML.
- `StateMetadata` — UUIDv7 id/timeline_id, `created_at`, `labels`, `description`. Derives `Serialize`/`Deserialize`.
- `MacAddr` — custom `Serialize`/`Deserialize` as a lowercase colon-separated string.
- `StateSet`, `Conflict`, `ConflictError` in `src/set.rs`. `StateSet.insert()` replaces on duplicate key — it does not error.
- `StateDiff`, `DiffOp` in `src/diff.rs`.

**Existing serialization:** JSON only via `serde_json`. `serde_yaml` and `walkdir` are absent from `Cargo.toml`.

**Tests:** Extensive tests in `src/lib.rs` and `src/set.rs` covering all existing types. No YAML-related tests exist.

**No files** `src/serde.rs` or `src/loader.rs` exist yet.

---

## Requirements

### Functional

1. **`parse_yaml(input: &str) -> Result<Vec<State>>`** — Parse a multi-document YAML string into a vector of `State` values. Each document produces one `State`. Bare format (no `kind`) and explicit format (`kind: state`) are both accepted. `kind` with any other value is an error.

2. **`load_file(path: &Path) -> Result<Vec<State>>`** — Read a file and call `parse_yaml` on its contents; wrap errors with filename context.

3. **`load_dir(path: &Path) -> Result<StateSet>`** — Recursively walk a directory, load all `.yaml`/`.yml` files (excluding hidden files with names starting with `.`), collect all `State` values into a `StateSet`, and error on duplicate `(entity_type, selector_key)` pairs or parse failures. Empty directory returns an empty `StateSet`.

4. **YAML deserialization for `State`** — Flat mapping: `type` → `entity_type`; `name`, `driver`, `mac`, `pci_path` → `Selector` fields; everything else (excluding `kind`) → `fields`. Each field value becomes `FieldValue` with `Provenance::UserConfigured { policy_ref: "".to_string() }`. `StateMetadata` is regenerated via `StateMetadata::new()`.

5. **YAML serialization for `State`** — Produce a flat YAML mapping: `type`, then set selector fields (`name`, `driver`, `mac`, `pci_path`), then configuration fields (only the `value` portion of each `FieldValue`). No `kind:`, no `selector:`, no `fields:`, no `metadata:` keys in output.

6. **`Value` YAML deserialization heuristic** — Custom deserialization function `deserialize_value(v: serde_yaml::Value) -> Result<Value>`:
   - YAML bool → `Value::Bool`
   - YAML integer ≥ 0 → `Value::U64`
   - YAML integer < 0 → `Value::I64`
   - YAML string → try parse as `IpNetwork`, then `IpAddr`, then keep as `Value::String`
   - YAML sequence → `Value::List` (recurse)
   - YAML mapping → `Value::Map` (recurse)

7. **`Value` YAML serialization** — `serialize_value(v: &Value) -> serde_yaml::Value`: IpAddr and IpNetwork serialize as YAML strings; all others map naturally to their YAML equivalents.

8. **Explicit format with `kind: state`** — Serialization optionally includes `kind: state` as the first field (required for the "explicit format" serialization scenario).

### Types needed

- An error type (e.g., `YamlLoadError`) covering: IO errors, YAML parse errors (with filename), duplicate key errors, missing `type` field, unknown `kind` value.

### Constants

```rust
const SELECTOR_KEYS: &[&str] = &["name", "driver", "mac", "pci_path"];
const META_KEYS: &[&str] = &["kind", "type"];
```

### New Cargo dependencies

- `serde_yaml = "0.9"` (provides `serde_yaml::Deserializer::from_str` for multi-document parsing)
- `walkdir = "2"` (recursive directory traversal)

---

## Gap Analysis

### Files to create

**`crates/netfyr-state/src/serde.rs`** (new file):
- `pub fn deserialize_value(v: serde_yaml::Value) -> Result<Value, ...>` — heuristic deserialization
- `pub fn serialize_value(v: &Value) -> serde_yaml::Value` — flat value serialization
- `fn parse_raw_to_state(raw: serde_yaml::Value) -> Result<State, ...>` — flat-map-to-State conversion
- Supporting constants: `SELECTOR_KEYS`, `META_KEYS`

**`crates/netfyr-state/src/loader.rs`** (new file):
- `pub fn parse_yaml(input: &str) -> Result<Vec<State>, YamlLoadError>` — multi-document YAML parser
- `pub fn load_file(path: &Path) -> Result<Vec<State>, YamlLoadError>` — file reader
- `pub fn load_dir(path: &Path) -> Result<StateSet, YamlLoadError>` — recursive directory loader
- Error type: `pub enum YamlLoadError` (or `pub struct YamlLoadError` using `thiserror`)

### Files to modify

**`crates/netfyr-state/src/lib.rs`**:
- Add `pub mod serde_yaml_support;` (or `pub mod serde;`, but `serde` conflicts with the crate name — use a distinct name like `pub mod yaml;`)
- Add `pub mod loader;`
- Re-export: `pub use loader::{parse_yaml, load_file, load_dir};`
- Re-export error type

**`crates/netfyr-state/Cargo.toml`**:
- Add `serde_yaml = "0.9"`
- Add `walkdir = "2"`

### What does NOT need to change

- `State`, `Selector`, `Value`, `FieldValue`, `StateMetadata`, `Provenance` struct/enum definitions — the existing types and their existing derives are preserved as-is.
- `src/set.rs`, `src/diff.rs` — no changes needed.
- Existing JSON serialization behavior is unaffected.

---

## Integration Points

### `State` struct construction during deserialization
`parse_raw_to_state` must construct `State` by directly setting public fields:
- `entity_type`: from `type` key
- `selector`: from `SELECTOR_KEYS` keys; `selector.mac` requires `MacAddr::from_str` parsing
- `fields`: `IndexMap<String, FieldValue>` — each entry wraps a `deserialize_value(v)?` result in `FieldValue { value, provenance: Provenance::UserConfigured { policy_ref: "".to_string() } }`
- `metadata`: `StateMetadata::new()`
- `policy_ref`: `None`
- `priority`: `100` (default)

### `StateSet` in `load_dir`
`StateSet.insert()` silently replaces on duplicate key. To implement the "error on duplicate" requirement, `load_dir` must check for existence before inserting: use `StateSet.get(entity_type, selector_key)` to detect duplicates and return an error rather than calling `insert`.

### `Selector.entity_type` field
The flat YAML format's `type` key maps to `State.entity_type`, not `Selector.entity_type`. The `SELECTOR_KEYS` constant deliberately excludes `entity_type`. The `Selector.entity_type` field is left `None` when loading from YAML (it exists for runtime matching, not user configuration).

### `MacAddr` in YAML selector
The `mac` selector key in YAML is a string (e.g., `"aa:bb:cc:dd:ee:ff"`). The parser must call `MacAddr::from_str` and propagate parse errors as a `YamlLoadError`.

### `Value` enum existing serde derives
The existing `#[serde(untagged)]` on `Value` does NOT apply to YAML correctly because YAML has no native IP address type — all IP-like values arrive as YAML strings. The custom `deserialize_value` function bypasses the derive entirely by working with raw `serde_yaml::Value` variants directly. The existing derive is kept for JSON use.

---

## Risks

### 1. `Value` untagged deserialization conflict with YAML
The existing `#[serde(untagged)] Value` derive attempts IpNetwork/IpAddr parsing only because those types' own `Deserialize` impls try to parse from strings. In `serde_yaml` 0.9, YAML boolean `true`/`false` are deserialized as booleans at the `serde_yaml::Value` level, but this layer is bypassed by `#[serde(untagged)]`. Using the custom `deserialize_value` function on raw `serde_yaml::Value` is the correct approach and avoids this ambiguity, but the new module must be careful not to reuse `Value`'s own `Deserialize` impl when processing YAML input.

### 2. `FieldValue` serialization cannot be derived for flat YAML
`FieldValue` derives `Serialize` producing `{"value": ..., "provenance": ...}`. The flat YAML format must emit only the plain value. Custom serialization via `serialize_value(&field_value.value)` is required in `serialize_state`. There is no easy way to reuse the derived impl here.

### 3. YAML integer width and `serde_yaml` representation
`serde_yaml` 0.9 uses `serde_yaml::Value::Number` for all numeric values. The number may internally be i64, u64, or f64. The `deserialize_value` function must inspect the number type carefully: `Number::as_u64()` returns `None` for negative numbers, `Number::as_i64()` for negative values. Floating-point YAML numbers (e.g., `1500.0`) are an edge case not covered by the spec — behavior should be documented or explicitly errored.

### 4. `kind` field handling for future SPEC-007
The spec says "If other kind: return error (or skip, depending on context)." Since SPEC-007 (policy) wraps states inside documents with `kind: policy`, and `parse_yaml` may be called with such documents, the behavior for unknown `kind` values needs to be defined precisely. Erroring is the safe default, but this may need revisiting.

### 5. `Selector.mac` parsing error propagation
The YAML `mac` key is a string that must be parsed via `MacAddr::from_str`. A malformed MAC address string must produce a descriptive error rather than silently being skipped or stored as `None`.

### 6. Module name conflict
`pub mod serde;` conflicts with the `serde` external crate name in Rust. The new module must use a different name (e.g., `pub mod yaml_serde;` or `pub mod yaml;`). The spec names the file `src/serde.rs` but this requires either renaming the module or using `#[path]` attribute.

### 7. Duplicate detection in `load_dir`
`StateSet.insert()` replaces rather than errors on duplicates. Duplicate detection requires checking `StateSet.get()` before `insert()`, or maintaining a separate `HashSet` of seen keys during loading. The error message must identify both the entity key and the conflicting filenames.

### 8. Hidden file detection
The spec says "skip hidden files (starting with `.`)". This applies to the filename component, not the full path. `walkdir` yields `DirEntry` objects; the check must be on `entry.file_name()` (the final path component), not the full path string, so that files inside hidden directories are also excluded (or the spec should clarify whether to skip entire hidden directories).
