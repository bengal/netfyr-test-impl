# Understand: SPEC-402 — Policy Store

## Current State

The project has **no `PolicyStore` implementation**. The relevant existing code is:

### `crates/netfyr-policy/src/lib.rs`
- `Policy` struct: `name: String`, `factory_type: FactoryType`, `priority: u32`, `state: Option<State>`, `states: Option<Vec<State>>`, `selector: Option<Selector>`. Derives `Clone, Debug, PartialEq` — **does not derive `Serialize`**.
- `PolicySet`: `IndexMap<String, Policy>` wrapper with `insert`, `get`, `remove`, `iter`, `len`, `is_empty`, `produce_all_static`.
- `parse_policy_yaml(input: &str) -> Result<Vec<Policy>, PolicyError>`: parses `kind: policy` YAML documents.
- `load_policy_file(path: &Path) -> Result<Vec<Policy>, LoaderError>`: handles both bare-state and `kind: policy` documents.
- `load_policy_dir(path: &Path) -> Result<PolicySet, LoaderError>`: walks a directory, deduplication-checked.
- `FactoryType`: derives `Serialize, Deserialize`.

### `crates/netfyr-state/src/yaml.rs`
- `state_to_yaml(state: &State) -> Result<String, YamlError>`: serializes a `State` to YAML string.
- `state_to_yaml_explicit(state: &State) -> Result<String, YamlError>`: same with explicit type tags.
- `State` itself does not appear to derive `Serialize` — serialization goes through these helper functions.

### `crates/netfyr-daemon/src/main.rs`
Stub: `fn main() { println!("netfyr"); }`. No modules declared.

### `crates/netfyr-daemon/Cargo.toml`
Empty `[dependencies]` section — no crate dependencies declared.

### `crates/netfyr-varlink/src/lib.rs`
Empty stub. No `SubmitPolicies` IPC interface exists yet.

### Tests
No tests exist in `netfyr-daemon`. The acceptance criteria are entirely unimplemented.

---

## Requirements

From the acceptance criteria, the following concrete technical requirements are needed:

### Struct
```rust
pub struct PolicyStore {
    dir: Option<PathBuf>,
    policies: Vec<Policy>,
}
```

### Constructors
- `PolicyStore::load(dir: &Path) -> Result<Self>` — creates the directory if absent (`fs::create_dir_all`), scans for `*.yaml` files (non-recursive), sorts lexicographically, parses each with the SPEC-007 parser (`parse_policy_yaml`), logs warnings and skips on parse error, ignores `*.yaml.tmp` files.
- `PolicyStore::ephemeral(policies: Vec<Policy>) -> Self` — in-memory only, `dir: None`, no disk I/O.

### Mutation
- `PolicyStore::replace_all(&mut self, policies: Vec<Policy>) -> Result<Vec<Policy>>` — write each to `{name}.yaml.tmp`, atomically rename to `{name}.yaml`, remove stale `.yaml` files not in the new set, clean up any leftover `.tmp` files, update `self.policies`. Returns previous policy set. On any write/rename failure: return error **without** updating `self.policies`.

### Accessors
- `fn policies(&self) -> &[Policy]`
- `fn is_empty(&self) -> bool`
- `fn len(&self) -> usize`

### File naming
- Filename: `{sanitized_name}.yaml` where sanitization replaces any character not matching `[a-z0-9\-_]` with `_`.

### Serialization
- Each persisted file must be a valid `kind: policy` YAML document parseable by `parse_policy_yaml`.
- The serialized format must include: `kind`, `name`, `factory`, `priority`, and `state`/`states`/`selector` as applicable.

### Error type
- A new `PolicyStoreError` (or use `anyhow::Error` as the spec prescribes) covering: directory creation failure, write failure, rename failure. Parse errors during `load` are non-fatal (warn + skip).

### Tests
- Unit tests covering all Gherkin scenarios:
  - Load from populated directory → 3 policies in lexicographic order
  - Load from empty directory → 0 policies, `is_empty()` true
  - Load creates missing directory → directory created, 0 policies
  - Load skips malformed files with warning
  - Load ignores `.tmp` files
  - `replace_all` persists new and removes old `.yaml` files
  - `replace_all` returns previous policy set
  - `replace_all` write atomicity (tmp → rename → remove stale)
  - `replace_all` with empty vec clears all
  - `replace_all` on read-only directory returns error, in-memory state unchanged
  - `replace_all` cleans up leftover `.tmp` files
  - Crash recovery: `.tmp` files ignored on next load (previous `.yaml` intact)
  - Crash recovery: superset loaded when rename succeeded but old files not yet removed
  - Policy name maps to filename (`office-network` → `office-network.yaml`)
  - Invalid characters in name are sanitized (`my policy/v2` → `my_policy_v2.yaml`)
  - Ephemeral store: no disk I/O
  - Ephemeral `replace_all`: updates in-memory only
  - Persisted file parses back via `parse_policy_yaml`

---

## Gap Analysis

### New file: `crates/netfyr-daemon/src/policy_store.rs`
The entire `PolicyStore` implementation must be created from scratch. Nothing exists.

### Modified file: `crates/netfyr-daemon/src/main.rs`
Must add `mod policy_store;` (or `pub mod policy_store;`) to register the new module. Currently the file has only a `fn main()`.

### Modified file: `crates/netfyr-daemon/Cargo.toml`
Must add all dependencies. Currently empty. Required additions:
```toml
netfyr-policy = { path = "../netfyr-policy" }
serde_yaml = "0.9"
anyhow = "1"          # per spec; or thiserror "1" to match project convention
tracing = "0.1"
tempfile = "3"        # [dev-dependencies] for tests
```

### Missing: Policy serialization capability
`Policy` does not implement `Serialize` and there is no `policy_to_yaml` function in `netfyr-policy`. Writing a `Policy` to a YAML file requires one of:
- Adding `#[derive(Serialize)]` to `Policy` and all its fields in `netfyr-policy/src/lib.rs` (field types: `FactoryType` already derives `Serialize`; `State` and `Selector` need verification), or
- Adding a `pub fn policy_to_yaml(policy: &Policy) -> Result<String, YamlError>` function to `netfyr-policy/src/lib.rs`, or
- Constructing `serde_yaml::Value` manually in the policy store.

This is a **blocker**: `policy_store.rs` cannot write YAML without a serialization path for `Policy`. The gap analysis identifies a required change in `crates/netfyr-policy/src/lib.rs`.

---

## Integration Points

| Component | Role | Interface constraint |
|-----------|------|----------------------|
| `netfyr_policy::Policy` | The data type stored and persisted | `Policy::name` is the key for file naming; struct must become serializable |
| `netfyr_policy::parse_policy_yaml` | Used during `load` to parse each `.yaml` file | Must handle `kind: policy` documents (which is what the store writes) |
| `netfyr_policy::FactoryType` | Already `Serialize`/`Deserialize` | Used in YAML output |
| `netfyr_state::yaml::{state_to_yaml, state_to_yaml_explicit}` | May be needed if Policy serialization is implemented by composing state YAML | Produces `String` from `State` |
| `tracing` crate | Structured logging for warnings on skipped files | `tracing::warn!` calls in `load` |
| Daemon event loop (future) | Will call `PolicyStore::load` on startup and `replace_all` on `SubmitPolicies` | `PolicyStore` is not `Send`/`Sync` — single-threaded access within `tokio::select!` per spec; no locking needed |

---

## Risks

### 1. Policy serialization is unimplemented (blocker)
`Policy` has no `Serialize` impl and no `to_yaml` helper. The implementation phase must either add `#[derive(Serialize)]` to `Policy` (and verify that `State`, `Selector`, `FieldValue`, `Value`, `Provenance` are all serializable via serde in a way that round-trips through `parse_policy_yaml`) or write a manual YAML construction function. The serde round-trip is non-trivial: `State` fields use `FieldValue` which contains `Provenance` — a loaded-from-disk policy should drop provenance metadata when re-serialized, since provenance is runtime-assigned by `StaticFactory::produce`. The stored file format (per the spec example) has no provenance fields — it matches what a user would write, not what a `StaticFactory`-produced `State` looks like internally.

### 2. `anyhow` vs `thiserror` inconsistency
The spec mandates `anyhow` for error handling in the daemon. All other crates use `thiserror`. Using `anyhow` is fine for a binary/application crate, but the implementation phase should be aware of the convention break. `replace_all`'s error type must be inspectable enough to distinguish "write failure" from "directory missing" if the daemon needs to report structured errors over the varlink IPC later.

### 3. Crash-recovery scenarios are not unit-testable as written
The acceptance criteria include scenarios that require simulating a mid-operation crash. These cannot be tested with standard Rust unit tests. The implementation should use `tempfile`-based tests to verify the *observable outcomes* after simulated partial states (e.g., manually write `.tmp` files before calling `load`, or manually write extra `.yaml` files to simulate a post-rename pre-cleanup crash).

### 4. `replace_all` on ephemeral store semantics
The spec says `replace_all` on an ephemeral store updates in-memory only. The implementation must check `self.dir.is_none()` and skip all disk I/O. The failure behavior (write errors) is moot for ephemeral stores, but the return type `Result<Vec<Policy>>` still applies — ephemeral `replace_all` should always return `Ok(previous)`.

### 5. Lexicographic load order vs. submission order
`PolicyStore::load` produces policies in lexicographic filename order (per spec). But `replace_all` receives policies in submission order and writes them in that order. After a restart, the load order may differ from the original submission order. The spec explicitly states `policies()` returns them in lexicographic filename order after load — this is a semantic change across a restart cycle that the daemon (and any consumer of `policies()`) must tolerate.

### 6. Policy name collision after sanitization
Two policies with names `"my policy"` and `"my/policy"` would both sanitize to `"my_policy"`, producing the same filename. `replace_all` with both policies would silently overwrite one. The spec does not define behavior for this edge case; the implementation phase should decide whether to detect and error or silently last-write-wins.

### 7. `serde_yaml` version alignment
`netfyr-policy` uses `serde_yaml = "0.9"`. The daemon Cargo.toml must use the same version to avoid type-level incompatibilities (e.g., `serde_yaml::Value` being a different type across major versions in a workspace).
