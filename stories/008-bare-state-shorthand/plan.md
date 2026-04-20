# Plan: SPEC-008 — Bare State Shorthand

## Approach

The implementation adds a policy loader module (`crates/netfyr-policy/src/loader.rs`) that serves as the unified entry point for loading policy files from disk. It sits above both the existing `parse_policy_yaml` function (which handles `kind: policy` documents) and the `parse_state_value` function from `netfyr-state` (which handles bare state documents). The loader reads YAML files, inspects each document's `kind` field, and dispatches accordingly — wrapping bare states into `Policy` structs with default values, or delegating to the existing policy parser for `kind: policy` documents.

The key architectural choice is to **extract the per-document policy parsing logic** from `parse_policy_yaml` in `lib.rs` into a shared internal function `parse_policy_from_value(raw: serde_yaml::Value) -> Result<Policy, PolicyError>`. This avoids the loader needing to re-serialize `serde_yaml::Value` back to a string just to call `parse_policy_yaml`, and keeps the parsing logic in one place. The existing `parse_policy_yaml` becomes a thin wrapper that iterates documents and calls this shared function. The loader calls the same function for `kind: policy` documents and handles bare states directly.

An alternative would be to have the loader re-serialize values to strings and call `parse_policy_yaml`, but this is wasteful and fragile (round-trip through serde_yaml serialization could subtly change values). Another alternative would be to duplicate the policy parsing logic in the loader, but that violates DRY and creates a maintenance burden. The extraction approach is cleanest — one code path for policy parsing, two callers.

The `load_policy_dir` function mirrors the existing `load_dir` pattern in `netfyr-state/src/loader.rs` (walkdir traversal, hidden file filtering, extension checking) but with policy-specific duplicate name detection instead of duplicate entity key detection.

## Design Decisions

1. **Decision**: Extract per-document parsing from `parse_policy_yaml` into `parse_policy_from_value`.
   - **Alternatives considered**: (a) Re-serialize `Value` to string and call `parse_policy_yaml`; (b) duplicate parsing logic in loader.
   - **Rationale**: Avoids wasteful round-trip serialization and keeps parsing logic DRY. The existing `parse_policy_yaml` becomes a thin loop that calls the extracted function, so its behavior is unchanged. The extraction is purely structural.

2. **Decision**: Create a separate `LoaderError` type rather than extending `PolicyError`.
   - **Alternatives considered**: Adding I/O and walkdir variants to `PolicyError`.
   - **Rationale**: `PolicyError` represents in-memory YAML parsing errors. Mixing file-system concerns (I/O, walkdir, duplicate names across files) into it would pollute the API for callers who only parse strings. `LoaderError` wraps `PolicyError` and `YamlError` for the file-system layer. This matches the existing separation in `netfyr-state` where `YamlError` has an `Io` variant but is also the parse error type (though in that crate the separation is less clean). For `netfyr-policy`, a dedicated loader error is better because `PolicyError` is already well-scoped.

3. **Decision**: Two-pass approach for multi-document naming — collect all documents into a `Vec` first, then assign names based on total count.
   - **Alternatives considered**: Single-pass with post-processing rename, streaming with lazy suffix application.
   - **Rationale**: The spec requires no suffix for single-document files and `-N` suffixes for multi-document files. You can't know if a file has one or multiple documents until you've parsed them all. Collecting into a `Vec<(Option<String>, serde_yaml::Value)>` (where `Option<String>` is the kind) first, then iterating to construct policies, is the simplest correct approach. The memory overhead is negligible — YAML documents are small.

4. **Decision**: The `-N` suffix uses the 1-based index of the document among *all* documents in the file, not just among bare state documents.
   - **Alternatives considered**: Index only among bare states.
   - **Rationale**: The spec pseudocode shows a single `doc_index` counter incremented for every document. The mixed-file acceptance criterion confirms: a 2-document file with a bare state as document 1 produces `"mixed-1"`. Using overall document index is simpler and avoids confusion about which numbering scheme is in use.

5. **Decision**: `kind: policy` documents in multi-document files use their explicit `name` field and are NOT given a suffix.
   - **Alternatives considered**: N/A — the spec is clear on this.
   - **Rationale**: Only bare states need auto-generated names; explicit policies always use their declared name.

6. **Decision**: `parse_policy_from_value` handles only `kind: policy` documents. It does NOT accept bare states.
   - **Alternatives considered**: Having it handle all kinds with a flag.
   - **Rationale**: The existing `parse_policy_yaml` explicitly rejects bare states with `UnsupportedKind`. The extracted function should preserve this behavior so that `parse_policy_yaml`'s contract is unchanged. The loader's dispatch logic handles bare states separately before calling the shared function.

7. **Decision**: Null/empty YAML documents (trailing `---`) are silently skipped and do not increment the document index for naming purposes.
   - **Alternatives considered**: Counting them in the index.
   - **Rationale**: The existing `parse_policy_yaml` already skips null documents. Including them in the count would produce confusing gaps in naming (e.g., `foo-1`, `foo-3` if document 2 is null). Since null documents carry no content, they shouldn't affect naming.

8. **Decision**: `kind: state` is stripped from the value before passing to `parse_state_value`.
   - **Alternatives considered**: Letting `parse_state_value` → `parse_raw_to_state` handle it (which it already does — it accepts and ignores `kind: state`).
   - **Rationale**: Actually, `parse_raw_to_state` in `netfyr-state/src/yaml.rs` already handles `kind: state` correctly (lines 193-199) — it checks the kind field and accepts "state" or absent. So the loader does NOT need to strip it. Just pass the raw value directly to `parse_state_value`. This is simpler and avoids duplicating validation logic.

## File Changes

### 1. `crates/netfyr-policy/src/loader.rs` — **CREATE**

New file containing:

- **`fn policy_name_from_path(path: &Path) -> String`** (private)
  - Extracts the file stem from the path, converts to string.
  - Falls back to `"unnamed"` if the path has no file stem or contains non-UTF-8 characters.
  - Signature: `fn policy_name_from_path(path: &Path) -> String`

- **`pub enum LoaderError`** (thiserror-derived)
  - Variants:
    - `Io { path: PathBuf, source: std::io::Error }` — file read failure
    - `Yaml(serde_yaml::Error)` — YAML syntax error during deserialization
    - `State(YamlError)` — state parsing error (from `parse_state_value`)
    - `Policy(PolicyError)` — policy parsing error (from `parse_policy_from_value`)
    - `UnknownKind { kind: String, path: PathBuf }` — unrecognized `kind` value
    - `DuplicatePolicyName { name: String, path: PathBuf }` — two policies with the same name in `load_policy_dir`
    - `WalkDir(walkdir::Error)` — directory traversal error
  - Implements `std::fmt::Display` via thiserror `#[error(...)]` attributes.
  - Each variant has a descriptive error message that includes the relevant context (file path, kind value, policy name).

- **`pub fn load_policy_file(path: &Path) -> Result<Vec<Policy>, LoaderError>`**
  - Reads the file to a string, wrapping I/O errors with the path.
  - Computes `base_name` via `policy_name_from_path`.
  - **First pass**: iterates `serde_yaml::Deserializer::from_str(&content)`, deserializing each document to `serde_yaml::Value`. Skips null documents. Collects non-null documents into a `Vec<serde_yaml::Value>`.
  - Determines `is_multi = collected.len() > 1`.
  - **Second pass**: iterates the collected values with 1-based index. For each:
    - Extracts `kind` by checking `raw.get("kind")` and converting to `Option<&str>`.
    - `match kind`:
      - `None | Some("state")` → bare state path:
        - Calls `parse_state_value(raw)` to get a `State`.
        - Computes the policy name: if `is_multi`, `format!("{base_name}-{index}")`, else `base_name.clone()`.
        - Emits `tracing::info!("Wrapping bare state from {} as static policy \"{}\" with priority 100", filename, name)` where `filename` is `path.file_name().unwrap().to_string_lossy()`.
        - Constructs `Policy { name, factory_type: FactoryType::Static, priority: 100, state: Some(parsed_state), states: None, selector: None }`.
      - `Some("policy")` → calls `parse_policy_from_value(raw)` (the extracted helper from `lib.rs`), mapping `PolicyError` to `LoaderError::Policy`.
      - `Some(other)` → returns `Err(LoaderError::UnknownKind { kind: other.to_string(), path: path.to_path_buf() })`.
  - Returns `Ok(policies)`.

- **`pub fn load_policy_dir(path: &Path) -> Result<PolicySet, LoaderError>`**
  - Uses `walkdir::WalkDir::new(path)` with `filter_entry` to skip hidden entries (same pattern as `netfyr-state/src/loader.rs`).
  - For each file entry with `.yaml` or `.yml` extension:
    - Calls `load_policy_file(entry.path())`.
    - For each returned policy, checks `policy_set.get(&policy.name)`. If `Some`, returns `Err(LoaderError::DuplicatePolicyName { name, path })`.
    - Otherwise, inserts into the `PolicySet`.
  - Returns `Ok(policy_set)`.

**Why**: This file is the core of SPEC-008. It provides the unified entry point that handles both bare states and explicit policies from files and directories.

### 2. `crates/netfyr-policy/src/lib.rs` — **MODIFY**

- Add `pub mod loader;` declaration (after the existing `use` statements, following the module convention).
- Add `pub use loader::{load_policy_file, load_policy_dir, LoaderError};` re-export.
- **Extract** the body of the `for document in ...` loop inside `parse_policy_yaml` (lines 247-406) into a new `pub(crate) fn parse_policy_from_value(raw: serde_yaml::Value) -> Result<Policy, PolicyError>` function. This function:
  - Takes a non-null `serde_yaml::Value`.
  - Validates `kind` is `"policy"` (returns `UnsupportedKind` for absent/state, `InvalidKind` for other).
  - Extracts `name`, `factory`, `priority`, `selector`, `state`, `states` — the exact same logic currently inline in `parse_policy_yaml`.
  - Returns `Ok(Policy { ... })`.
- **Rewrite** `parse_policy_yaml` to:
  - Iterate documents via `serde_yaml::Deserializer::from_str`.
  - Skip null documents.
  - Call `parse_policy_from_value(raw)?` for each.
  - Collect into `Vec<Policy>`.
  - This is a pure refactor — behavior is identical.

**Why**: Extracting the shared helper avoids duplicating policy parsing logic between `parse_policy_yaml` and the loader. The loader needs to parse `kind: policy` documents from already-deserialized values.

### 3. `crates/netfyr-policy/Cargo.toml` — **MODIFY**

- Add `walkdir = "2"` to `[dependencies]`.

**Why**: Required for recursive directory traversal in `load_policy_dir`. Version `"2"` matches the version used by `netfyr-state`, avoiding lock file duplication.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `walkdir` | `"2"` | Recursive directory traversal for `load_policy_dir`. The standard library has no recursive directory walker. Already used by `netfyr-state` at the same major version. |

No other new dependencies are needed. `tracing`, `serde_yaml`, `thiserror`, and `netfyr-state` are already in `Cargo.toml`.

## Implementation Order

### Step 1: Add `walkdir` to `Cargo.toml`

Add the dependency. This is a prerequisite for step 3.

**Compilable state**: Yes (unused dependency warning, but compiles).

### Step 2: Extract `parse_policy_from_value` in `lib.rs`

Extract the per-document parsing logic from `parse_policy_yaml` into `pub(crate) fn parse_policy_from_value`. Rewrite `parse_policy_yaml` to call it. Add `pub mod loader;` and re-exports (the module file will be created in step 3).

**Dependencies**: None (pure refactor of existing code).

**Compilable state**: No — `pub mod loader` references a file that doesn't exist yet. Either create an empty `loader.rs` stub in this step (with just `// TODO` or the error type), or combine steps 2 and 3. The safer approach is to create a minimal `loader.rs` stub in this step so the crate compiles.

### Step 3: Implement `loader.rs`

Create `crates/netfyr-policy/src/loader.rs` with:
1. `LoaderError` enum
2. `policy_name_from_path` helper
3. `load_policy_file` function
4. `load_policy_dir` function

**Dependencies**: Requires the `parse_policy_from_value` helper from step 2 and `walkdir` from step 1.

**Compilable state**: Yes — full implementation in place.

### Step 4: Verify existing tests pass

Run `cargo test -p netfyr-policy` to ensure the refactoring in step 2 didn't break any existing tests. All existing tests for `parse_policy_yaml` should pass unchanged since the refactoring is behavior-preserving.

**Compilable state**: Yes.

## Risks and Mitigations

### 1. Refactoring `parse_policy_yaml` could change behavior

**Risk**: The extraction of `parse_policy_from_value` could subtly change the behavior of `parse_policy_yaml` if the refactoring is not exact.

**Mitigation**: The existing test suite for `parse_policy_yaml` (18+ tests in `lib.rs`) covers all documented behaviors including error cases (`UnsupportedKind`, `InvalidKind`, `MissingField`, etc.). Running these tests after the refactoring provides strong confidence. The extraction is mechanical — move code into a function, replace inline code with a function call.

### 2. Multi-document naming with mixed content

**Risk**: In a mixed file (bare states + `kind: policy`), the document index must be the overall position, not per-kind. Getting this wrong would produce incorrect policy names.

**Mitigation**: The two-pass approach (collect all documents first, then iterate with index) makes this straightforward. The `enumerate()` gives the position among all non-null documents. The acceptance test for mixed files explicitly checks the naming.

### 3. `parse_state_value` behavior with `kind: state`

**Risk**: When passing a `kind: state` document to `parse_state_value`, the `kind` field might end up as a field in the `State` struct.

**Mitigation**: Already verified — `parse_raw_to_state` in `yaml.rs` (line 193-199) checks the `kind` field and accepts `"state"` as valid. The `kind` key is in `META_KEYS` (line 18-19: `const META_KEYS: &[&str] = &["kind", "type"];`), so it is excluded from fields (line 251). No issue.

### 4. `PolicySet::insert` silently overwrites duplicates

**Risk**: If `load_policy_dir` doesn't check for duplicates before inserting, it would silently overwrite policies with the same name from different files.

**Mitigation**: The implementation explicitly calls `policy_set.get(&policy.name)` before `insert` and returns a `DuplicatePolicyName` error if a collision is detected. This matches the acceptance criterion.

### 5. Null documents affecting index numbering

**Risk**: If null documents (from trailing `---`) are counted in the document index, naming could produce unexpected gaps.

**Mitigation**: The first pass filters out null documents before collecting. The index is computed over the filtered (non-null) documents only. This is consistent with how `parse_policy_yaml` and `parse_yaml` handle null documents.

### 6. `kind` field as non-string type

**Risk**: A YAML document could have `kind: 42` (a number). The loader must handle this gracefully.

**Mitigation**: When extracting `kind`, use `.and_then(|v| v.as_str())`. If the `kind` value exists but is not a string, treat it as an unknown kind and return an error. Specifically: `raw.get("kind")` returns `Some(non-string)`, `.as_str()` returns `None`, which falls through to the `None` match arm and would be treated as a bare state. This is wrong — a non-string `kind` should be an error. The implementation must check: if `raw.get("kind")` is `Some` but `.as_str()` is `None`, return `UnknownKind { kind: "<non-string>" }`. This matches the pattern in `parse_policy_yaml` (line 276-279).

## Test Strategy

### Unit tests (in `loader.rs` `#[cfg(test)]` module)

Tests should use temporary directories and files, following the pattern established in `netfyr-state/src/loader.rs` (atomic counter + `temp_dir` helper).

**Behaviors to test**:

1. **Single bare state file** → returns 1 policy, name matches file stem, priority 100, `FactoryType::Static`, state has correct entity_type and fields.
2. **`kind: state` file** → same result as bare state (explicit marker is equivalent).
3. **Multi-document bare state file** → returns N policies with names `"{stem}-1"`, `"{stem}-2"`, etc.
4. **Single `kind: policy` document** → returns 1 policy with explicit name/priority/factory (not overridden by file stem).
5. **Mixed file** (bare state + `kind: policy`) → bare state gets indexed name, explicit policy keeps its declared name.
6. **Unknown `kind` value** → returns `LoaderError::UnknownKind`.
7. **Non-string `kind` value** → returns error.
8. **Trailing `---` (null document)** → skipped silently, doesn't affect count or naming.
9. **File with single bare state and trailing `---`** → only 1 non-null document, no suffix.
10. **Policy name from various filenames** → `eth0.yaml` → `"eth0"`, `bond0-vlan100.yml` → `"bond0-vlan100"`, edge case with no extension.
11. **`load_policy_dir` with multiple files** → collects all policies, correct total count.
12. **`load_policy_dir` with duplicate policy names** → returns `DuplicatePolicyName` error.
13. **`load_policy_dir` skips hidden files** → `.backup.yaml` is not loaded.
14. **`load_policy_dir` skips non-YAML files** → `.txt`, `.json` ignored.
15. **`load_policy_dir` on empty directory** → returns empty `PolicySet`.
16. **I/O error** → non-existent file path returns `LoaderError::Io`.
17. **Info log emitted for bare states** — this is hard to test directly in unit tests without a tracing subscriber. Consider documenting that log testing is covered at the integration level, or use `tracing-test` if available. Since the spec lists it as an acceptance criterion, the test should at minimum verify the function succeeds (log emission is a side effect).

### Integration tests (optional, under `crates/netfyr-policy/tests/`)

If more complex scenarios are needed (e.g., nested directories, symlinks), they can go here. But the unit tests above cover all acceptance criteria.

### Existing tests

All existing tests in `crates/netfyr-policy/src/lib.rs` must continue to pass unchanged after the `parse_policy_from_value` extraction. No test modifications should be needed.
