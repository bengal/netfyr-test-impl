## Current State

The `netfyr-state` crate (`crates/netfyr-state/src/lib.rs`) is the only crate relevant to this story. It contains:

- A placeholder `Selector` struct with a single field `name: Option<String>`, marked `#[non_exhaustive]` and annotated with a comment that SPEC-003 will replace it.
- Two constructors: `Selector::new()` and `Selector::with_name(name)`. No `matches()`, `is_specific()`, or `key()` methods.
- `State` struct that embeds `Selector` via `pub selector: Selector`.
- `StateMetadata` which has its own `labels: HashMap<String, String>` field (separate from the Selector).
- All serde, chrono, uuid, ipnetwork, and indexmap dependencies are already declared in `Cargo.toml`.
- No `MacAddr` type exists anywhere in the codebase.
- No `selector.rs` module file exists; all code is in `lib.rs`.
- No tests exist for `Selector` behavior.

The other crates (`netfyr-reconcile`, `netfyr-backend`, `netfyr-policy`, `netfyr-varlink`, `netfyr-cli`, `netfyr-daemon`, `netfyr-test-utils`) have no observable public API surface relevant to this story.

## Requirements

### Types

1. **`MacAddr`** — newtype wrapping `[u8; 6]`:
   - `Display`: lowercase hex with colons (`"aa:bb:cc:dd:ee:ff"`)
   - `FromStr`: case-insensitive, colon-separated hex (`"AA:BB:CC:DD:EE:FF"`)
   - `Serialize`/`Deserialize`: as string via Display/FromStr
   - `Clone`, `Debug`, `PartialEq`

2. **`Selector`** — full struct replacing the placeholder:
   - Fields: `name: Option<String>`, `entity_type: Option<String>`, `driver: Option<String>`, `pci_path: Option<String>`, `mac: Option<MacAddr>`, `labels: HashMap<String, String>`
   - Derives: `Clone`, `Debug`, `Default`, `Serialize`, `Deserialize`, `PartialEq`
   - Serde: `skip_serializing_if = "Option::is_none"` on all `Option` fields; `default, skip_serializing_if = "HashMap::is_empty"` on `labels`

### Methods on `Selector`

3. **`matches(&self, other: &Selector) -> bool`**: AND logic — every `Some` field in `self` must equal the corresponding field in `other` (which must also be `Some` with the same value); `self.labels` must be a subset of `other.labels` (all keys present with equal values).

4. **`is_specific(&self) -> bool`**: returns `self.name.is_some()`.

5. **`key(&self) -> String`**: if `name` is `Some(n)`, return `n.clone()`; otherwise build a deterministic semicolon-separated string from all set fields sorted alphabetically (e.g. `"driver=ixgbe;entity_type=ethernet;labels.role=uplink"`).

### Constructors (preserve existing API)

6. `Selector::new() -> Self` — all fields `None`/empty.
7. `Selector::with_name(name: impl Into<String>) -> Self` — sets `name`, rest default.

### Tests

8. Unit tests covering all acceptance criteria scenarios (17 scenarios specified).

## Gap Analysis

### New file to create

**`crates/netfyr-state/src/selector.rs`**
- Define `MacAddr([u8; 6])` newtype with `Display`, `FromStr`, `Serialize`, `Deserialize`, `Clone`, `Debug`, `PartialEq`.
- Define the full `Selector` struct (replacing the placeholder fields).
- Implement `Selector::new()`, `Selector::with_name()`, `Default`.
- Implement `Selector::matches()`, `Selector::is_specific()`, `Selector::key()`.
- Unit tests for all 17 acceptance criteria scenarios.

### File to modify

**`crates/netfyr-state/src/lib.rs`**
- Remove the existing `Selector` struct definition, its `impl Selector` block, and its `impl Default for Selector` block (lines 12–42).
- Add `mod selector;` and `pub use selector::{MacAddr, Selector};`.
- The `use std::collections::HashMap;` import already exists; no new dependency imports are needed.

### No dependency changes needed

All required external crates (`serde`, `serde_json`, `chrono`, `uuid`, `ipnetwork`, `indexmap`) are already present in `Cargo.toml`. `HashMap` is already imported in `lib.rs` from `std::collections`. No new external dependencies are required.

## Integration Points

- **`State` struct** (`lib.rs:273`): embeds `pub selector: Selector`. Once `Selector` is replaced, `State` continues to compile without changes because all public fields remain (field additions are not breaking given `#[non_exhaustive]` — however, `#[non_exhaustive]` will be removed from the new `Selector` since it is no longer a placeholder).
- **`Selector::new()` and `Selector::with_name()`**: these constructors must be preserved with identical signatures to avoid breaking any downstream crate that already calls them.
- **Serde round-trip**: `State` is serialized/deserialized through `Selector`, so `Selector`'s serde attributes must produce clean YAML/JSON (skip `None` fields and empty `labels`).
- **`StateMetadata.labels`**: a separate `HashMap<String, String>` on `StateMetadata` — no conflict, but implementers should be aware these are distinct label maps.

## Risks

1. **`#[non_exhaustive]` removal**: The placeholder `Selector` is `#[non_exhaustive]`, which prevents struct literal construction outside the crate. The new `Selector` spec does not mention `#[non_exhaustive]`. Removing the attribute is correct but constitutes a semver change (it loosens the API). Since this is still pre-1.0 development, this is acceptable; however, the implementation should confirm no downstream crate constructs `Selector` via struct literals before removing the attribute.

2. **`key()` format for labels**: The spec example shows `"labels.role=uplink"`. When a selector has multiple labels, their ordering within the key string must itself be deterministic. Since `HashMap` iteration order is non-deterministic, labels must be sorted alphabetically by key when building the key string.

3. **MAC address case-insensitive comparison**: `MacAddr` stores raw bytes (`[u8; 6]`), so byte-level `PartialEq` is automatically case-insensitive (the bytes are the same regardless of how the string was parsed). The `matches()` scenario for MAC addresses is therefore handled correctly as long as `FromStr` normalizes both cases to bytes.

4. **`key()` for the empty selector**: An empty selector (all `None`, no labels) produces an empty string `""` from the deterministic-key algorithm. The spec doesn't define this case explicitly; the implementation should decide whether to return `""` or a sentinel like `"*"`.

5. **`with_name()` constructor field initialization**: The new `Selector` has six fields. `with_name()` must initialize the five new fields to their defaults (`None`/empty) in addition to setting `name`.

6. **Existing `Selector` tests**: The existing test suite has no tests for `Selector`, so there is no risk of existing selector tests breaking. There is a risk that `State`-level serialization tests (if added later) will rely on `Selector` serde behavior — the `skip_serializing_if` attributes must be applied correctly from the start.
