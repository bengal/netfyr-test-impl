# Plan: SPEC-003 Selectors

## Approach

This story replaces the placeholder `Selector` struct in `netfyr-state` with a full multi-field selector supporting AND-logic matching, and introduces a `MacAddr` newtype. The design follows a single-module extraction pattern: all selector-related types move into a new `src/selector.rs` file, re-exported from `lib.rs`. This keeps `lib.rs` focused on the core state model while giving the selector logic room to grow.

The key architectural choice is **storing `MacAddr` as raw bytes (`[u8; 6]`)** and using serde's `serialize_with`/`deserialize_with` (or a manual `Serialize`/`Deserialize` impl) to represent it as a colon-separated hex string in serialized form. This makes equality comparison automatically case-insensitive (bytes are identical regardless of input casing) and avoids storing redundant string representations. The `Selector` itself uses public fields (matching the spec's struct definition) with serde skip attributes to produce clean YAML/JSON. The `matches()` method is a straightforward field-by-field AND check with subset matching on labels. The `key()` method provides a stable string identifier for indexing -- using the name directly when available, or a deterministic semicolon-delimited encoding of set fields when not.

An alternative would be to keep everything in `lib.rs`, but that file is already ~300 lines of Value/Provenance/FieldValue/State definitions plus tests. A separate module is cleaner and matches what the spec explicitly requests (`src/selector.rs`). Another alternative for `MacAddr` would be to use an external crate like `macaddr`, but the spec says no new dependencies, and the type is simple enough (6 bytes, `Display`, `FromStr`, serde) that a hand-rolled newtype is appropriate and avoids a transitive dependency.

## Design Decisions

1. **Decision**: Remove `#[non_exhaustive]` from the new `Selector`.
   - **Alternatives considered**: Keep `#[non_exhaustive]` for future-proofing.
   - **Rationale**: The spec defines the full struct without `#[non_exhaustive]`. The attribute was explicitly documented in the placeholder as temporary ("for SPEC-003"). Removing it allows downstream crates to use struct literal syntax (`Selector { name: Some(...), ..Default::default() }`), which is more ergonomic. This is pre-1.0 so semver concerns are moot.

2. **Decision**: Implement `MacAddr` serde via manual `Serialize`/`Deserialize` impls that delegate to the `Display`/`FromStr` impls.
   - **Alternatives considered**: (a) Use `#[serde(with = "...")]` helper module. (b) Store as `String` internally and parse on access.
   - **Rationale**: Manual impls are the most direct approach for a newtype that serializes as a string. They avoid creating a separate helper module and keep all `MacAddr` logic co-located. Storing as bytes is correct because the spec says it's a "6-byte hardware address" and equality must be case-insensitive.

3. **Decision**: `MacAddr` derives `Eq` and `Hash` in addition to the spec-required traits.
   - **Alternatives considered**: Only derive what the spec lists (`Clone, Debug, PartialEq`).
   - **Rationale**: `[u8; 6]` supports `Eq` and `Hash` trivially. Adding them costs nothing and may be needed in the future (e.g., using `MacAddr` as a HashMap key). `Selector` itself should NOT derive `Eq`/`Hash` because `HashMap` doesn't implement `Hash`, and the spec doesn't require it.

4. **Decision**: `key()` returns an empty string `""` for a fully-empty selector.
   - **Alternatives considered**: Return a sentinel like `"*"` or `"__empty__"`.
   - **Rationale**: The spec says "a hash of the selector fields if no name is set." With zero fields set, the deterministic encoding produces `""`. A sentinel would be an invention not in the spec. An empty selector matching everything is a valid (if unusual) use case, and `""` is a valid HashMap key. The implementation phase should include a brief comment noting this edge case.

5. **Decision**: For `key()`, MAC addresses are formatted as lowercase hex in the key string (e.g., `mac=aa:bb:cc:dd:ee:ff`).
   - **Alternatives considered**: Use raw bytes or uppercase.
   - **Rationale**: Consistency with `Display` impl. The key must be deterministic; lowercase is the canonical `Display` format.

6. **Decision**: Labels in `key()` are sorted by key name and formatted as `labels.{key}={value}`, each as a separate entry in the semicolon-delimited string.
   - **Alternatives considered**: Serialize labels as a single JSON blob.
   - **Rationale**: The spec example explicitly shows `"labels.role=uplink"` format. Sorting by key ensures determinism despite `HashMap`'s non-deterministic iteration.

7. **Decision**: `FromStr` for `MacAddr` returns a custom error type (`MacAddrParseError`) rather than a generic string error.
   - **Alternatives considered**: Use `String` as the error type, or `Box<dyn Error>`.
   - **Rationale**: A dedicated error type is idiomatic Rust for `FromStr` and allows callers to match on the error. It should be a simple unit struct or enum with a `Display` impl describing the expected format.

8. **Decision**: The `Selector::with_name()` constructor keeps its existing signature `(name: impl Into<String>) -> Self` and initializes all new fields to defaults.
   - **Alternatives considered**: Add builder methods for each field.
   - **Rationale**: The spec says to preserve the existing API. Builder methods are not requested and can be added later if needed. Users can set fields directly since they're `pub`.

## File Changes

### 1. `crates/netfyr-state/src/selector.rs` (CREATE)

This is the main implementation file. It should contain:

**Imports**: `serde::{Deserialize, Serialize, Serializer, Deserializer}`, `std::collections::HashMap`, `std::fmt`, `std::str::FromStr`.

**`MacAddrParseError`** (struct):
- A unit struct (or simple struct) implementing `fmt::Display` and `std::error::Error`.
- `Display` should say something like `"invalid MAC address; expected format AA:BB:CC:DD:EE:FF"`.

**`MacAddr`** (newtype struct):
- Definition: `pub struct MacAddr(pub [u8; 6])` with derives `Clone, Debug, PartialEq, Eq, Hash`.
- `fmt::Display` impl: formats as `"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}"` from the inner bytes.
- `FromStr` impl: splits input on `':'`, verifies exactly 6 parts, parses each as `u8::from_str_radix(part, 16)`, returns `MacAddrParseError` on failure.
- `Serialize` impl: serializes as a string using `Display` formatting (call `serializer.serialize_str(&self.to_string())`).
- `Deserialize` impl: deserializes a string and parses via `FromStr` (use `String::deserialize(deserializer)?` then `.parse()`).

**`Selector`** (struct):
- Exact field layout from the spec (name, entity_type, driver, pci_path, mac, labels) with the serde attributes specified.
- Derives: `Clone, Debug, Default, PartialEq, Serialize, Deserialize`.
- **No** `#[non_exhaustive]`.

**`Selector::new()`**: Returns `Self::default()` (all None, empty HashMap).

**`Selector::with_name(name: impl Into<String>)`**: Returns `Self { name: Some(name.into()), ..Default::default() }`.

**`Selector::matches(&self, other: &Selector) -> bool`**:
- For each of the five `Option` fields (`name`, `entity_type`, `driver`, `pci_path`, `mac`): if `self.field` is `Some(v)`, check that `other.field` is `Some(ref ov)` and `v == ov`. If not, return `false`.
- For `labels`: iterate `self.labels` entries; for each `(k, v)`, check `other.labels.get(k) == Some(v)`. If any fails, return `false`.
- Return `true`.

**`Selector::is_specific(&self) -> bool`**: Returns `self.name.is_some()`.

**`Selector::key(&self) -> String`**:
- If `self.name` is `Some(ref n)`, return `n.clone()`.
- Otherwise, build a `Vec<String>` of `"field=value"` entries for each set field, in alphabetical order by field name: `driver`, `entity_type`, `mac`, `pci_path`. For labels, add `"labels.{k}={v}"` for each label entry, with labels sorted by key. Join all entries with `";"` and return.

**Why this file**: The spec explicitly requests `src/selector.rs`. Extracting the selector into its own module keeps `lib.rs` clean and groups all selector logic (including `MacAddr`) in one place.

### 2. `crates/netfyr-state/src/lib.rs` (MODIFY)

**Remove**: Lines 12-42 (the placeholder `Selector` struct, its `impl Selector` block, and `impl Default for Selector`). This includes the `// ── Selector ──` comment block.

**Add** (near the top, after the existing `use` statements):
- `mod selector;`
- `pub use selector::{MacAddr, MacAddrParseError, Selector};`

**Why**: Re-exports the new types from the module so the public API surface remains at the crate root. Downstream code using `netfyr_state::Selector` continues to work. `MacAddr` and `MacAddrParseError` are new public types needed by consumers.

## Dependencies

No new crate dependencies are needed. The existing `serde` (with `derive` feature) provides everything required for `Serialize`/`Deserialize`. `HashMap` is from `std::collections`. The `MacAddr` type is hand-rolled with no external crate.

## Implementation Order

1. **Create `crates/netfyr-state/src/selector.rs`** with `MacAddrParseError`, `MacAddr` (struct + Display + FromStr + Serialize + Deserialize), and the full `Selector` struct with all methods (`new`, `with_name`, `matches`, `is_specific`, `key`). This file compiles independently as a module.

2. **Modify `crates/netfyr-state/src/lib.rs`**: Remove the placeholder `Selector` (lines 12-42). Add `mod selector;` and `pub use selector::{MacAddr, MacAddrParseError, Selector};`. After this step, the crate compiles and all existing code that references `Selector` (including the `State` struct on line 278) continues to work because the public API is preserved (`Selector` still has a `name: Option<String>` field, `new()`, and `with_name()`).

3. **Verify**: Run `cargo check -p netfyr-state` to confirm compilation. Run `cargo test -p netfyr-state` to confirm existing tests still pass (none of them test `Selector` behavior, but they do construct `State` which embeds `Selector`).

Steps 1 and 2 can be done in either order, but both must be complete before step 3. The most natural flow is to write `selector.rs` first, then wire it into `lib.rs`.

## Risks and Mitigations

1. **Risk**: Removing `#[non_exhaustive]` could break downstream crates that use `Selector` struct literals with `..` syntax if they relied on the attribute to mean "more fields may come."
   - **Mitigation**: The attribute was preventing struct literal construction outside the crate, so no downstream code could have been using struct literals. Only `Selector::new()` and `Selector::with_name()` were available. Removing the attribute is safe.

2. **Risk**: The `State` struct has `pub selector: Selector`. Adding fields to `Selector` means any code that constructs `State` with a struct literal must now account for those fields.
   - **Mitigation**: `Selector` derives `Default`, so existing `State` construction using `Selector::new()` or `Selector::with_name()` continues to work. Direct struct literal construction of `State` (if any exists) would need `selector: Selector { name: ..., ..Default::default() }`. Check the existing tests -- none construct `State` directly, so this is not a current concern.

3. **Risk**: `HashMap` iteration order is non-deterministic, which could make `key()` non-deterministic if labels aren't sorted.
   - **Mitigation**: The `key()` implementation must collect label entries into a `Vec`, sort by key, then format. This is called out explicitly in the spec and in the implementation description above.

4. **Risk**: `MacAddr` serde round-trip could fail if `Deserialize` impl doesn't handle error messages well.
   - **Mitigation**: The `Deserialize` impl should use `serde::de::Error::custom()` to wrap the `MacAddrParseError`, producing a clear error message.

5. **Risk**: The field order in `key()` must be truly alphabetical and stable. The fields in alphabetical order are: `driver`, `entity_type`, `mac`, `pci_path`. Labels (as `labels.{key}`) sort among these.
   - **Mitigation**: The implementation should either hardcode the field check order (they're static field names) or collect all parts into a `Vec<String>` and sort it. The latter approach is simpler and automatically handles labels interleaving with regular fields. Use the collect-and-sort approach.

6. **Risk**: Empty selector `key()` returns `""`, which could collide if two empty selectors are used as keys in a `HashMap`.
   - **Mitigation**: This is correct behavior -- two empty selectors are semantically identical and should map to the same key. Document this in a code comment.

## Test Strategy

Tests should be unit tests in `crates/netfyr-state/src/selector.rs` inside a `#[cfg(test)] mod tests` block. No integration tests or external test infrastructure is needed. No mocks are required.

**MacAddr tests:**
- Parse a valid uppercase MAC string (`"AA:BB:CC:DD:EE:FF"`) and verify it succeeds.
- Verify `Display` output is lowercase with colons (`"aa:bb:cc:dd:ee:ff"`).
- Parse an invalid string (`"not-a-mac"`) and verify it returns `Err`.
- Parse strings with wrong number of octets (e.g., `"AA:BB:CC"`) and verify failure.
- Parse strings with invalid hex (e.g., `"GG:HH:II:JJ:KK:LL"`) and verify failure.
- Round-trip: parse -> display -> parse produces the same value.
- Serde round-trip: serialize to JSON string, deserialize back, verify equality.

**Selector::matches() tests** (one test per acceptance scenario):
- Exact name match (self=eth0, other=eth0+driver -> true).
- Name mismatch (self=eth0, other=eth1 -> false).
- Multi-field AND success (self=driver+entity_type, other has both plus more -> true).
- Multi-field AND failure on one mismatch (entity_type differs -> false).
- Unspecified fields match anything (self=driver only, other has many fields -> true).
- Empty selector matches everything (self=default, any other -> true).
- Label subset match success (self has 1 label, other has 2 including that one -> true).
- Label subset match failure on missing label (self has 2 labels, other has only 1 -> false).
- Label value mismatch (same key, different value -> false).
- MAC address matching (both parsed from different cases -> true).

**Selector::is_specific() tests:**
- Named selector returns `true`.
- Unnamed selector (driver only) returns `false`.
- Empty selector returns `false`.

**Selector::key() tests:**
- Named selector returns the name string.
- Unnamed selector with driver+entity_type returns a deterministic string containing both fields.
- Call `key()` twice on the same selector and verify identical output.
- Selector with labels produces `labels.{key}={value}` in the key string.
- Empty selector returns `""`.
- Verify field ordering is alphabetical (e.g., `driver` before `entity_type`).

**Serde tests:**
- Serialize a name-only selector to JSON/YAML; verify only `name` appears, no `driver`/`pci_path`/`mac`/`labels`.
- Deserialize a JSON object with `name` only into `Selector`; verify other fields are `None`/empty.
- Round-trip a fully-populated selector through JSON.
- Verify `MacAddr` serializes as a string in JSON, not as an array of bytes.

**Constructor tests:**
- `Selector::new()` produces all-None, empty labels.
- `Selector::with_name("eth0")` sets name, everything else default.
- `Selector::default()` equals `Selector::new()`.
