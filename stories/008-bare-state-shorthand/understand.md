# SPEC-008 Gap Analysis: Bare State Shorthand

## Current State

### netfyr-policy crate

**`crates/netfyr-policy/src/lib.rs`** — the only source file; contains:
- `FactoryType` enum (`Static`, `Dhcpv4`) with serde round-trip
- `Policy` struct with fields: `name`, `factory_type`, `priority`, `state`, `states`, `selector`
- `PolicySet` (keyed `IndexMap<String, Policy>`): `insert`, `get`, `remove`, `iter`, `len`, `is_empty`, `produce_all_static`
- `StateFactory` trait and `StaticFactory` impl
- `FactoryError` and `PolicyError` error enums (thiserror-based)
- `parse_policy_yaml(input: &str) -> Result<Vec<Policy>, PolicyError>` — parses multi-document YAML strings; **explicitly rejects** bare state documents (`kind: state` or absent `kind:`) with `PolicyError::UnsupportedKind`, citing SPEC-008 in comments
- Full test suite (in-module `#[cfg(test)]`)

**`crates/netfyr-policy/Cargo.toml`** — current dependencies:
- `netfyr-state`, `serde`, `serde_yaml`, `thiserror`, `tracing`, `indexmap`
- **`walkdir` is absent** — needed for directory traversal

**No `loader.rs` exists** in `crates/netfyr-policy/src/`.

### netfyr-state crate (dependency)

- `parse_state_value(raw: serde_yaml::Value) -> Result<State, YamlError>` — parses a flat-format state from an already-deserialized `serde_yaml::Value`. This is the correct entry point for the loader; it avoids re-serializing values back to strings.
- `YamlError` — imported into `PolicyError::Yaml` already.
- `parse_yaml(input: &str) -> Result<Vec<State>, YamlError>` — parses a YAML string; not the right fit here since the loader already has a deserialized `Value`.

---

## Requirements

From the acceptance criteria, the following concrete behaviors are required:

1. **`load_policy_file(path: &Path) -> Result<Vec<Policy>, LoaderError>`**
   - Reads the file content; iterates over YAML documents via `serde_yaml::Deserializer::from_str`
   - Per document, inspects the `kind:` field:
     - `None` or `Some("state")` → bare state: parse with `parse_state_value`, wrap in `Policy`
     - `Some("policy")` → parse as an explicit policy (reusing inner logic from `parse_policy_yaml`)
     - `Some(other)` → return error: `"Unknown kind '{}' in {}"`, containing the unknown kind value and the file path
   - Naming for bare states:
     - Single bare state document in the file → name is the file stem (e.g., `eth0.yaml` → `"eth0"`)
     - Multiple documents in the file (any mix) → bare state documents get names `"{stem}-{N}"` where N is the document's 1-based index among all documents
     - `kind: policy` documents always use their own explicit `name:` field regardless
   - Emits `tracing::info!` for each auto-wrapped bare state: `"Wrapping bare state from {filename} as static policy \"{name}\" with priority 100"`
   - Null/empty documents (trailing `---`) are silently skipped

2. **`load_policy_dir(path: &Path) -> Result<PolicySet, LoaderError>`**
   - Traverses the directory recursively with `walkdir`
   - Filters: files only, non-hidden (name does not start with `.`), extensions `.yaml` or `.yml`
   - Calls `load_policy_file` for each file and collects all returned `Policy` values
   - Rejects duplicate policy names across files with an error naming the duplicate key and the file that caused the collision
   - Returns a `PolicySet`

3. **`LoaderError`** error type (thiserror-based, consistent with codebase style):
   - I/O error variant (wrapping `std::io::Error`)
   - YAML parse error variant (wrapping `serde_yaml::Error`)
   - State parse error variant (wrapping `YamlError` or `PolicyError`)
   - Unknown kind variant
   - Duplicate policy name variant
   - WalkDir error variant (wrapping `walkdir::Error`)

4. **`policy_name_from_path(path: &Path) -> String`** — internal helper:
   - Returns `path.file_stem().and_then(|s| s.to_str()).unwrap_or("unnamed").to_string()`

5. **Re-exports in `lib.rs`**: `pub mod loader` declaration plus `pub use loader::{load_policy_file, load_policy_dir}`

6. **`walkdir` added to `Cargo.toml`**

---

## Gap Analysis

### Files to create

**`crates/netfyr-policy/src/loader.rs`** — entirely new file:
- `fn policy_name_from_path(path: &Path) -> String`
- `pub enum LoaderError` (thiserror) with variants for I/O, YAML, state parse, unknown kind, duplicate name, walkdir
- `pub fn load_policy_file(path: &Path) -> Result<Vec<Policy>, LoaderError>`
- `pub fn load_policy_dir(path: &Path) -> Result<PolicySet, LoaderError>`
- Internal helper for parsing a `serde_yaml::Value` into a `Policy` when `kind: policy` (currently this logic is embedded as string-level parsing in `parse_policy_yaml`; the loader operates on already-deserialized values)

### Files to modify

**`crates/netfyr-policy/src/lib.rs`**:
- Add `pub mod loader;` declaration
- Add `pub use loader::{load_policy_file, load_policy_dir};` re-export

**`crates/netfyr-policy/Cargo.toml`**:
- Add `walkdir = "2"` to `[dependencies]`

### Tests to add

Unit tests for the loader should go in `loader.rs` or as a dedicated integration test under `crates/netfyr-policy/tests/`. The acceptance criteria map to test cases for:
- Single bare state file → policy name from file stem, priority 100, `FactoryType::Static`
- `kind: state` file → same as bare state
- Multi-document bare state file → names `"{stem}-1"`, `"{stem}-2"`, etc.
- `kind: policy` document → explicit name/priority preserved, not overridden
- Mixed file → bare state named with index, explicit policy retains its own name
- Unknown kind → error
- Directory loading → collects all files, correct count
- Duplicate name across files → error
- Hidden files skipped

---

## Integration Points

1. **`parse_state_value` from `netfyr-state::yaml`** — already imported in `lib.rs` via `use netfyr_state::{parse_state_value, ...}`. The loader will call this to parse the `serde_yaml::Value` of each bare state document directly.

2. **Inner policy parsing logic from `parse_policy_yaml`** — the loader needs to parse a `kind: policy` `serde_yaml::Value` into a `Policy`. Currently `parse_policy_yaml` accepts a `&str`. The loader must either:
   - Re-serialize the `serde_yaml::Value` back to a string and call `parse_policy_yaml`, or
   - Extract the per-document parsing logic into a shared private function `parse_policy_from_value(raw: serde_yaml::Value) -> Result<Policy, PolicyError>` callable from both `parse_policy_yaml` and the loader.
   The second approach is cleaner and avoids an unnecessary re-serialization round-trip.

3. **`PolicySet::insert`** — does not check for duplicates (silently overwrites). The loader must call `PolicySet::get` before `insert` to detect collisions for the duplicate-name error case in `load_policy_dir`.

4. **`tracing::info!`** — already a dependency; the loader uses it for the auto-wrap log message. No new dependency needed.

5. **`walkdir::WalkDir`** — new dependency; must be added to `Cargo.toml`.

---

## Risks

1. **Single-document naming without two-pass**: The spec names a single-document file without a suffix, and multi-document files with `-N` suffixes. To implement this correctly without two passes, the loader must either pre-collect all documents into a `Vec` first (to count them), then apply naming based on the total count, or apply suffixes lazily with a post-processing step. Pre-collecting is simpler and avoids complexity around streaming.

2. **Mixed-file suffix indexing**: In a mixed file (bare state + `kind: policy`), the spec example ("mixed-1" for the first document) implies the index is the overall document position, not the count of bare states. This is consistent with the pseudocode's `doc_index` counter, but must be validated against the acceptance criteria. The mixed-file scenario has 2 total documents; the bare state is document 1 and gets suffix `-1`. Confirming: the suffix is the overall document index, not the bare-state-only count.

3. **Refactoring `parse_policy_yaml` internal logic**: Extracting a `parse_policy_from_value` helper requires modifying `lib.rs`. Care is needed to keep `parse_policy_yaml`'s existing behavior unchanged (it must continue to return `UnsupportedKind` for bare states when called directly) while the loader handles them differently. The split should be clean: `parse_policy_from_value` handles only `kind: policy` documents, and the loader's dispatch logic handles the `None`/`Some("state")` cases.

4. **`walkdir` version alignment**: Other crates in the workspace (e.g., `netfyr-state`) already depend on `walkdir = "2"`. Using the same major version avoids duplication in the lock file.

5. **`LoaderError` vs reusing `PolicyError`**: The loader must surface I/O errors and walkdir errors that `PolicyError` doesn't currently model. A new `LoaderError` type is needed, or `PolicyError` must be extended. Extending `PolicyError` risks polluting the in-memory parse API with file-system concerns; a separate `LoaderError` is the cleaner boundary.

6. **Duplicate name detection semantics**: `PolicySet::insert` silently overwrites on duplicate names. The loader must detect and reject duplicates explicitly in `load_policy_dir`. The acceptance criteria requires an error; the detection must happen before inserting.
