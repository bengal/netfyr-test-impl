# Plan: SPEC-402 — Policy Store

## Approach

The PolicyStore is a disk-backed container that persists policies as individual YAML files in a directory, supporting atomic replace-all semantics and graceful crash recovery. The design is intentionally simple: a `Vec<Policy>` in memory, an `Option<PathBuf>` for the backing directory (None = ephemeral), and straightforward filesystem operations for persistence.

The main architectural challenge is **serializing a `Policy` to the flat YAML format** that `parse_policy_yaml` can read back. `Policy` does not derive `Serialize`, and `State`'s serde-derived representation is nested (includes `selector`, `fields` with `FieldValue`/`Provenance` wrappers), not the flat user-facing format (`type`, `name`, `mtu` all at the top level). The existing `serialize_state_to_value()` function in `netfyr-state/src/yaml.rs` already converts a `State` to the correct flat `serde_yaml::Value`, but it is currently private. The plan makes it public and uses it from a `serialize_policy_to_string()` helper in `policy_store.rs` that manually constructs the full `kind: policy` YAML document as a `serde_yaml::Value` mapping. This approach avoids adding `Serialize` to `Policy` (which would produce wrong output), keeps `netfyr-policy` unmodified, and reuses the proven flat-format serializer.

An alternative was to reconstruct the flat state format manually in the daemon crate, but that would duplicate ~40 lines of serialization logic from `netfyr-state` and risk divergence. Another alternative was to call `state_to_yaml()` (which returns a `String`) and then re-parse it to `serde_yaml::Value` — wasteful and fragile. Making the internal function public is a one-word change and provides a natural public API that pairs with the already-public `parse_state_value`.

## Design Decisions

1. **Decision**: Serialize policies by manually constructing `serde_yaml::Value` in `policy_store.rs`, using the now-public `serialize_state_to_value()` for embedded states.
   - **Alternatives considered**: (a) Add `#[derive(Serialize)]` to `Policy` — produces wrong nested format with provenance metadata. (b) Add `policy_to_yaml()` to `netfyr-policy` — modifies a crate not in scope. (c) Call `state_to_yaml()` to get a string then re-parse — wasteful double-serialization.
   - **Rationale**: Minimal upstream change (one function made public), correct flat format, no provenance leakage, round-trips through `parse_policy_yaml`.

2. **Decision**: Use `anyhow::Error` for the `PolicyStore` error type, not a custom enum.
   - **Alternatives considered**: Define `PolicyStoreError` with `thiserror` to match other crates' convention.
   - **Rationale**: Spec explicitly mandates `anyhow`. The daemon is a binary crate where `anyhow` is idiomatic. The error messages are surfaced to logs and CLI responses, not programmatically matched. Future IPC error reporting (varlink) can use `anyhow`'s `Display` for the message and a simple error code.

3. **Decision**: Name sanitization replaces any character NOT matching `[a-z0-9_-]` with `_`. No collision detection.
   - **Alternatives considered**: (a) Error on collision — overly strict, policy names rarely collide after sanitization. (b) Append a numeric suffix on collision — adds complexity for an edge case.
   - **Rationale**: The spec says "sanitized by replacing invalid characters with underscores" and does not define collision behavior. Last-write-wins is the natural outcome of sequential file writes. A `tracing::warn!` if two policies sanitize to the same name is sufficient.

4. **Decision**: `replace_all` writes ALL temp files first, then renames ALL, then removes stale files, then cleans up old `.tmp` files. On any write/rename error, return `Err` immediately without updating in-memory state.
   - **Alternatives considered**: Write-and-rename each file atomically one at a time — fewer temp files on the filesystem, but less consistent: a crash between two rename operations leaves the directory in a mixed old/new state.
   - **Rationale**: The spec explicitly describes this two-phase approach (write all .tmp, then rename all). The crash-recovery semantics are well-defined: a crash during writes leaves old `.yaml` files intact; a crash during renames leaves a superset.

5. **Decision**: The ephemeral store's `replace_all` always returns `Ok(previous)` — no disk I/O, no possible error.
   - **Alternatives considered**: Return the same `Result` type but never error.
   - **Rationale**: Same return type for API uniformity. The `Ok` path is trivial.

6. **Decision**: `load()` sorts filenames lexicographically and stores policies in that order. `replace_all()` accepts policies in submission order but the ordering is only preserved until the next restart (when `load` re-sorts).
   - **Alternatives considered**: Embed an ordering index in the filename (e.g., `001-office-network.yaml`) to preserve submission order across restarts.
   - **Rationale**: Spec explicitly states "policies are loaded in lexicographic filename order." The daemon and consumers must tolerate order changes across restarts. Adding index prefixes would complicate file naming and conflict with the spec's filename examples.

7. **Decision**: Add `netfyr-state` as a direct dependency of `netfyr-daemon` (for `serialize_state_to_value`).
   - **Alternatives considered**: Re-export it through `netfyr-policy`.
   - **Rationale**: `netfyr-daemon` will eventually need `netfyr-state` types anyway (for `StateSet`, `State`, etc. in the reconciliation loop). Direct dependency is cleaner than re-export chains.

## File Changes

### 1. `crates/netfyr-state/src/yaml.rs`
- **Action**: modify
- **What**: Change `fn serialize_state_to_value(state: &State) -> serde_yaml::Value` (line 308) from private to `pub fn`. No other changes to this function.
- **Why**: The policy store needs to embed flat-format state sub-documents inside policy YAML files. This function is the canonical flat-format serializer and is the inverse of the already-public `parse_state_value`. Making it public enables reuse without duplicating logic.

### 2. `crates/netfyr-state/src/lib.rs`
- **Action**: modify
- **What**: Add `serialize_state_to_value` to the `pub use yaml::{...}` re-export list (line 16-19).
- **Why**: Consistent with how all other public yaml functions are re-exported.

### 3. `crates/netfyr-daemon/Cargo.toml`
- **Action**: modify
- **What**: Add the following dependencies:
  ```toml
  [dependencies]
  netfyr-policy = { path = "../netfyr-policy" }
  netfyr-state = { path = "../netfyr-state" }
  serde_yaml = "0.9"
  anyhow = "1"
  tracing = "0.1"

  [dev-dependencies]
  tempfile = "3"
  ```
- **Why**: `netfyr-policy` provides `Policy`, `parse_policy_yaml`, `FactoryType`. `netfyr-state` provides `serialize_state_to_value` and `serialize_value`. `serde_yaml` for YAML I/O. `anyhow` for error handling per spec. `tracing` for structured logging on skipped files. `tempfile` for test fixtures.

### 4. `crates/netfyr-daemon/src/main.rs`
- **Action**: modify
- **What**: Add `mod policy_store;` before `fn main()`. Make the module public (`pub mod policy_store;`) so types are accessible from the daemon's other modules in the future.
- **Why**: Registers the new module with the crate.

### 5. `crates/netfyr-daemon/src/policy_store.rs`
- **Action**: create
- **What**: The core implementation file containing:

#### `fn sanitize_policy_name(name: &str) -> String`
- Private helper function
- Iterates over each character in the input, replacing any character not matching `[a-z0-9_-]` with `_`
- Returns the sanitized string
- Edge case: if the name is empty after sanitization (unlikely but possible), use `"_unnamed"` as fallback

#### `fn serialize_policy_to_string(policy: &Policy) -> anyhow::Result<String>`
- Private helper function
- Constructs a `serde_yaml::Mapping` with keys in this order:
  1. `kind: policy` (literal string)
  2. `name: <policy.name>` (string)
  3. `factory: <factory_type>` — serialize `FactoryType` via `serde_yaml::to_value(&policy.factory_type)`
  4. `priority: <priority>` — as u64 number
  5. `selector: <...>` — if `policy.selector.is_some()`, serialize via `serde_yaml::to_value(&selector)` (Selector derives Serialize, skip_serializing_if annotations produce clean output)
  6. `state: <...>` — if `policy.state.is_some()`, call `netfyr_state::serialize_state_to_value(&state)` to get flat format
  7. `states: <...>` — if `policy.states.is_some()`, build a `serde_yaml::Value::Sequence` where each element is `serialize_state_to_value(&state)` for each state in the list
- Calls `serde_yaml::to_string(&mapping)` and returns the resulting string
- Uses `anyhow::Context` for error wrapping

#### `pub struct PolicyStore`
- Fields:
  - `dir: Option<PathBuf>` — backing directory, None for ephemeral
  - `policies: Vec<Policy>` — current policy set, in load/submission order

#### `impl PolicyStore`

**`pub fn load(dir: &Path) -> anyhow::Result<Self>`**
- Call `fs::create_dir_all(dir)` with `anyhow::Context` for error message
- Read directory entries with `fs::read_dir(dir)`, collect into a `Vec<DirEntry>`, filter to files only (not dirs/symlinks)
- Filter to entries whose filename ends with `.yaml` (NOT `.yaml.tmp`, NOT `.yml` — spec says store writes `.yaml` only, and load_policy_dir handles `.yml` but the store never creates them)
- Sort filenames lexicographically
- For each file:
  - Read contents with `fs::read_to_string`
  - Parse with `netfyr_policy::parse_policy_yaml(&contents)`
  - On parse error: `tracing::warn!("Skipping malformed policy file {}: {}", filename, err)`, continue to next file
  - On success: extend the policies Vec with all parsed policies (typically one per file, but `parse_policy_yaml` supports multi-doc)
- Return `Ok(PolicyStore { dir: Some(dir.to_path_buf()), policies })`

**`pub fn ephemeral(policies: Vec<Policy>) -> Self`**
- Returns `PolicyStore { dir: None, policies }`

**`pub fn replace_all(&mut self, new_policies: Vec<Policy>) -> anyhow::Result<Vec<Policy>>`**
- If `self.dir.is_none()` (ephemeral): swap `self.policies` with `new_policies` using `std::mem::replace`, return `Ok(old_policies)`
- Otherwise, let `dir = self.dir.as_ref().unwrap()`:
  1. Compute new filenames: for each policy, `sanitize_policy_name(&policy.name) + ".yaml"`. Collect into a `HashSet<String>` for the new set.
  2. Write phase: for each policy, serialize to string with `serialize_policy_to_string`, write to `dir.join(format!("{}.yaml.tmp", sanitized_name))`. On any write error, return `Err` (don't update in-memory state). Use `anyhow::Context` with the filename.
  3. Rename phase: for each sanitized name, `fs::rename(dir.join(name.yaml.tmp), dir.join(name.yaml))`. On any rename error, return `Err`.
  4. Remove stale files: read directory entries, find `.yaml` files whose names are NOT in the new filenames set, and `fs::remove_file` each. Log warnings on removal errors but do not return Err (best-effort cleanup, spec says stale files are harmless).
  5. Clean up `.tmp` files: read directory entries, find any remaining `.yaml.tmp` files, `fs::remove_file` each. Again best-effort, log warnings.
  6. Replace `self.policies` with `new_policies` using `std::mem::replace`, return `Ok(old_policies)`.
- Critical invariant: `self.policies` is only updated AFTER all writes and renames succeed (step 6). Steps 4-5 are cleanup and their failures do not roll back.

**`pub fn policies(&self) -> &[Policy]`**
- Returns `&self.policies`

**`pub fn is_empty(&self) -> bool`**
- Returns `self.policies.is_empty()`

**`pub fn len(&self) -> usize`**
- Returns `self.policies.len()`

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `netfyr-policy` | `{ path = "../netfyr-policy" }` | Provides `Policy`, `parse_policy_yaml`, `FactoryType` — the core types this module persists |
| `netfyr-state` | `{ path = "../netfyr-state" }` | Provides `serialize_state_to_value` for flat-format state serialization |
| `serde_yaml` | `0.9` | YAML serialization/deserialization. Version matches `netfyr-policy` and `netfyr-state` to avoid type conflicts |
| `anyhow` | `1` | Spec-mandated error handling for the daemon crate |
| `tracing` | `0.1` | Structured logging for warnings on skipped/malformed files |
| `tempfile` | `3` (dev-dependency) | Creates temporary directories for unit tests |

No new external crates beyond what the spec requires. `serde_yaml`, `tracing`, and `anyhow` are all already used by other crates in the workspace (or are standard Rust ecosystem crates). `tempfile` is a dev-only dependency already used by `netfyr-policy` tests.

## Implementation Order

1. **Make `serialize_state_to_value` public** (modify `crates/netfyr-state/src/yaml.rs` and `crates/netfyr-state/src/lib.rs`). This is a prerequisite for the serialization helper. Compile-check: `cargo check -p netfyr-state`. No behavioral change; existing tests pass.

2. **Add dependencies to `netfyr-daemon/Cargo.toml`**. Compile-check: `cargo check -p netfyr-daemon`. The daemon is a stub, so this just verifies dependency resolution.

3. **Create `policy_store.rs` with the struct, constructors, and accessors** (`PolicyStore`, `load`, `ephemeral`, `policies`, `is_empty`, `len`). Add `mod policy_store;` to `main.rs`. Depends on step 1 (for the `netfyr-state` import) and step 2 (for dependencies). Compile-check: `cargo check -p netfyr-daemon`.

4. **Add the serialization helper** (`sanitize_policy_name`, `serialize_policy_to_string`). Depends on step 3 (the module must exist). These are private functions used by `replace_all`. Compile-check: `cargo check -p netfyr-daemon`.

5. **Implement `replace_all`**. Depends on step 4 (serialization helper). This completes the full implementation. Compile-check: `cargo check -p netfyr-daemon`.

## Risks and Mitigations

### 1. Policy YAML round-trip fidelity
**Risk**: The serialized YAML may not parse back identically through `parse_policy_yaml`. For example, `serde_yaml::to_value(&FactoryType::Static)` might produce a tagged value instead of a plain string.
**Mitigation**: `FactoryType` derives `Serialize` with `#[serde(rename_all = "lowercase")]`, which serializes to plain strings (`"static"`, `"dhcpv4"`). `Selector` uses `#[serde(skip_serializing_if)]` annotations that produce clean YAML. The test strategy includes explicit round-trip tests: serialize a policy, parse it back with `parse_policy_yaml`, and verify equality.

### 2. serde_yaml `Selector` serialization format mismatch
**Risk**: `serde_yaml::to_value(&selector)` produces a mapping with all fields (including empty `labels: {}`), which `parse_policy_from_value` might not handle.
**Mitigation**: `Selector` has `#[serde(skip_serializing_if = "Option::is_none")]` on all Option fields and `#[serde(skip_serializing_if = "HashMap::is_empty")]` on `labels`. This produces clean output. The parser (`parse_policy_from_value` line 360-368) deserializes the selector with `serde_yaml::from_value::<Selector>(v.clone())`, which works with the same serde format.

### 3. Policy name collision after sanitization
**Risk**: Two policies with names like `"my policy"` and `"my/policy"` both sanitize to `"my_policy"`, causing one to silently overwrite the other.
**Mitigation**: This is an edge case that the spec does not define. The implementation uses last-write-wins semantics (natural result of sequential writes). A `tracing::warn!` is emitted when a collision is detected during `replace_all`. This is acceptable because policy names in practice are user-chosen identifiers that rarely collide after sanitization.

### 4. `fs::rename` not atomic across filesystems
**Risk**: If the `.tmp` file and the final `.yaml` file are on different filesystems, `fs::rename` will fail.
**Mitigation**: Both files are in the same directory (`self.dir`), so they are guaranteed to be on the same filesystem. `fs::rename` within a single directory is atomic on all supported platforms (Linux).

### 5. Partial write failure leaves orphaned `.tmp` files
**Risk**: If writing the 3rd of 5 temp files fails, the first 2 `.tmp` files remain on disk.
**Mitigation**: These are cleaned up on the next successful `replace_all` (step 6 cleans all `.tmp` files) or are harmlessly ignored by the next `load` (which only reads `*.yaml`, not `*.yaml.tmp`).

### 6. Directory permissions
**Risk**: The daemon may not have write permissions to the store directory, or the directory may be on a read-only filesystem.
**Mitigation**: `load()` fails with a clear error if `create_dir_all` fails. `replace_all` fails with a clear error on write failures. The error message includes the path for diagnosis. The systemd unit file's `StateDirectory=netfyr` normally handles directory creation and permissions.

### 7. Empty or very long policy names
**Risk**: An empty policy name sanitizes to an empty string, producing a file named `.yaml`. A very long name could exceed filesystem limits.
**Mitigation**: Empty names fall back to `"_unnamed"`. For long names, the filesystem itself enforces limits (typically 255 bytes on ext4) and `fs::write` will return an error that propagates naturally. This is an unlikely edge case.

## Test Strategy

### Unit tests (in `policy_store.rs` `#[cfg(test)] mod tests`)

All tests use `tempfile::TempDir` for isolation. No real filesystem paths (no `/var/lib/netfyr/`). Tests create policy YAML files using string literals matching the format produced by `serialize_policy_to_string`.

**Load tests:**
- Load from directory with 3 valid YAML files → `len() == 3`, policies in lexicographic filename order
- Load from empty directory → `is_empty() == true`, `len() == 0`
- Load creates directory if missing → directory exists after `load`, `is_empty() == true`
- Load skips malformed YAML files → store contains only the valid policy, no error returned
- Load ignores `.tmp` files → only `.yaml` files are loaded
- Load ignores non-YAML files → `.txt`, `.json` files in the directory are skipped

**Replace-all tests:**
- Replace-all persists new files and removes old → `C.yaml` and `D.yaml` exist, `A.yaml` and `B.yaml` are gone
- Replace-all returns previous policy set → returned vec matches the original policies
- Replace-all with empty vec clears all → `is_empty() == true`, no `.yaml` files in directory
- Replace-all cleans up leftover `.tmp` files → pre-existing `stale.yaml.tmp` is removed
- Replace-all on read-only directory returns error, in-memory state unchanged → `policies()` still returns original set (use `fs::set_permissions` to make dir read-only)

**Crash recovery tests (simulated by manually creating files):**
- Directory with `.yaml.tmp` files alongside `.yaml` files → `load` ignores `.tmp`, loads only `.yaml`
- Directory with extra `.yaml` files (simulating post-rename pre-cleanup crash) → `load` returns superset, next `replace_all` cleans up extras

**File naming tests:**
- `sanitize_policy_name("office-network")` → `"office-network"`
- `sanitize_policy_name("my policy/v2")` → `"my_policy_v2"`
- `sanitize_policy_name("UPPERCASE")` → `"_________"` (all uppercase replaced since only lowercase allowed)
- Policy with name `"office-network"` persists as `office-network.yaml`

**Ephemeral store tests:**
- `ephemeral(policies)` → `policies()` returns them, no directory created
- `replace_all` on ephemeral store → updates in-memory, returns `Ok(previous)`, no filesystem changes

**Round-trip tests:**
- Create a static policy with `state` (eth0, mtu=1500, addresses), persist via `replace_all`, load via `PolicyStore::load`, verify the loaded policy matches: name, factory_type, priority, state entity_type, state selector, state fields
- Create a static policy with `states` (multi-entity), round-trip, verify all states are present
- Create a DHCPv4 policy with selector, round-trip, verify factory_type and selector

### What NOT to test
- Actual crash behavior (process kill mid-write) — untestable in unit tests, covered by the crash-safety design
- Concurrent access — spec says single-threaded, no locking needed
- Filesystem-level atomicity of `fs::rename` — this is an OS guarantee
