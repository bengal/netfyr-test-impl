# Plan: SPEC-002 Entity State Types

## Approach

This story builds the foundational data model for netfyr in the `netfyr-state` crate. The crate is currently an empty stub with no dependencies or types. We will create six new source files — one per type/concept — plus update `lib.rs` for module declarations and re-exports, and `Cargo.toml` for dependencies. The design is a straightforward "flat module" layout: each type gets its own file for clarity, and `lib.rs` re-exports everything so downstream crates use `netfyr_state::State`, `netfyr_state::Value`, etc. without knowing the internal module structure.

The type graph is acyclic and shallow: `State` depends on `Selector`, `FieldValue`, and `StateMetadata`; `FieldValue` depends on `Value` and `Provenance`; `Value` depends on `IndexMap`, `IpAddr`, and `IpNetwork`; the remaining types are leaf types. This makes the implementation order natural — build leaves first, composites last.

The key architectural choice is how serde represents `Value` and `Provenance` enums. Both need to round-trip through JSON (and later YAML for SPEC-005). I'm choosing **internally tagged** representation for `Provenance` (`#[serde(tag = "source")]`) because its variants have named fields and the tag makes JSON self-documenting. For `Value`, I'm choosing **untagged** representation (`#[serde(untagged)]`) because it produces the most natural JSON/YAML: strings serialize as strings, numbers as numbers, bools as bools, lists as arrays — matching what users expect in config files. The downside of untagged is ambiguity during deserialization (e.g., is `42` a `U64` or `I64`?), which I handle with careful variant ordering (see Design Decisions below). An alternative would be externally tagged (`{"U64": 42}`) which is unambiguous but produces ugly YAML for a config-file-oriented tool.

## Design Decisions

1. **Decision**: Use `#[serde(untagged)]` for `Value` enum.
   - **Alternatives considered**: Externally tagged (serde default — `{"String": "hello"}`), internally tagged, adjacently tagged.
   - **Rationale**: Untagged produces natural JSON/YAML (`"hello"`, `42`, `true`, `[1,2,3]`). This is critical because these values will appear in user-facing YAML config files (SPEC-005) and CLI output (SPEC-302). The trade-off is deserialization ambiguity: serde tries variants in declaration order, so we must order variants carefully to avoid misparse (e.g., `Bool` before `U64` since JSON bools are distinct; `U64` before `I64` since positive integers should prefer unsigned; `IpAddr` and `IpNetwork` before `String` since IP strings would otherwise match `String` first). `Map` must come before any scalar to avoid ambiguity with JSON objects. `List` before scalars for the same reason. The ordering will be: `Map`, `List`, `Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `String`. `IpNetwork` before `IpAddr` because a CIDR string like `"10.0.0.0/24"` should parse as `IpNetwork`, while a bare IP like `"10.0.0.1"` should parse as `IpAddr` — the `ipnetwork` crate's deserializer requires the `/prefix` suffix, so this ordering works correctly.

2. **Decision**: Use `#[serde(tag = "source")]` (internally tagged) for `Provenance` enum.
   - **Alternatives considered**: Untagged (ambiguous since `KernelDefault` has no fields), externally tagged.
   - **Rationale**: Internally tagged is self-documenting in JSON (`{"source": "KernelDefault"}`, `{"source": "UserConfigured", "policy_ref": "..."}`). It handles unit-like variants (`KernelDefault`) cleanly. Externally tagged would also work but is slightly more verbose.

3. **Decision**: Use `#[serde(rename_all = "snake_case")]` on `Provenance` variants.
   - **Alternatives considered**: Keep PascalCase variant names in serialized form.
   - **Rationale**: `snake_case` produces more natural YAML/JSON keys (`"user_configured"` vs `"UserConfigured"`), aligning with the config-file-oriented design. This is a judgment call — either works, but snake_case is conventional for config files.

4. **Decision**: `Selector` placeholder as a named-field struct with `name: Option<String>`, with `#[non_exhaustive]`.
   - **Alternatives considered**: Type alias to `String`, tuple struct, unit struct.
   - **Rationale**: Spec explicitly says `name: Option<String>`. Using `#[non_exhaustive]` on the struct means SPEC-003 can add fields without a semver-breaking change. Named-field struct is the only choice that supports this.

5. **Decision**: `serde_json` as a regular dependency (not dev-only).
   - **Alternatives considered**: `serde_json` as `[dev-dependencies]` only.
   - **Rationale**: The spec says "needed for Value conversions and testing". While the acceptance criteria only test JSON round-trips, having `serde_json` as a regular dep allows other crates to use `netfyr_state` types with JSON serialization. This matches the spec's explicit dependency list. However, if strictly following the principle of minimal dependencies, `serde_json` could be dev-only since the `Value` conversions don't inherently require it — the `From` impls and accessors are pure Rust. I'll follow the spec and keep it as a regular dependency.

6. **Decision**: No `Default` impl for `State`.
   - **Alternatives considered**: Deriving or implementing `Default`.
   - **Rationale**: Spec does not require it, and a defaulted `State` with empty `entity_type` and default `Selector` would be semantically meaningless. `StateMetadata` also should not derive `Default` since `new()` has side effects (UUID generation, timestamp). Neither type should be default-constructible.

7. **Decision**: `Display` format for `Value::Map` will use `{key: val, key2: val2}`.
   - **Alternatives considered**: JSON-style with quoted keys, Python dict-style.
   - **Rationale**: Spec specifies `[a, b, c]` for lists, which is bracket-delimited without quotes on inner values. Extending this pattern to maps gives `{key: val}` which is readable and consistent. Keys are unquoted (they're always strings), values use their own `Display`.

8. **Decision**: Typed accessors for `List` and `Map` will be `as_list() -> Option<&Vec<Value>>` and `as_map() -> Option<&IndexMap<String, Value>>`.
   - **Alternatives considered**: Returning slices, returning iterators, not providing them.
   - **Rationale**: The spec explicitly names `as_str`, `as_u64`, `as_bool` etc., but doesn't mention `as_list` or `as_map`. However, for API completeness and consistency, every variant should have an accessor. Returning borrowed references avoids cloning.

9. **Decision**: `as_ip_addr() -> Option<&IpAddr>` and `as_ip_network() -> Option<&IpNetwork>` return references.
   - **Alternatives considered**: Return by value (both types are `Copy`).
   - **Rationale**: `IpAddr` is `Copy` so either works, but returning a reference is consistent with `as_str()` which must return a reference. `IpNetwork` is also `Copy`. For consistency across all accessors, use references for non-primitive types and values for primitives (`u64`, `i64`, `bool`). This matches the pattern: `as_str() -> Option<&str>`, `as_u64() -> Option<u64>`, `as_bool() -> Option<bool>`, `as_ip_addr() -> Option<&IpAddr>`, `as_ip_network() -> Option<&IpNetwork>`.

10. **Decision**: Place `Selector` in its own file `src/selector.rs`.
    - **Alternatives considered**: Inline in `entity.rs` since it's a placeholder.
    - **Rationale**: SPEC-003 will expand `Selector` significantly. Giving it its own file now avoids having to extract it later and makes the module boundary clear.

## File Changes

### 1. `crates/netfyr-state/Cargo.toml`
- **Action**: Modify
- **What**: Add all six external dependencies under `[dependencies]`:
  - `serde = { version = "1", features = ["derive"] }`
  - `serde_json = "1"`
  - `chrono = { version = "0.4", features = ["serde"] }`
  - `uuid = { version = "1", features = ["v7", "serde"] }`
  - `ipnetwork = { version = "0.20", features = ["serde"] }`
  - `indexmap = { version = "2", features = ["serde"] }`
- **Why**: These are the exact dependencies listed in the spec, with features needed for derive macros, serialization, and UUIDv7 generation.

### 2. `crates/netfyr-state/src/lib.rs`
- **Action**: Modify (replace the single doc comment line)
- **What**: 
  - Keep the `//! netfyr-state crate` doc comment (or expand it slightly).
  - Add `mod` declarations for: `entity`, `field`, `value`, `provenance`, `metadata`, `selector`.
  - Add `pub use` re-exports for all public types: `State`, `FieldValue`, `Value`, `Provenance`, `StateMetadata`, `Selector`.
- **Why**: Flat re-export surface so downstream crates use `netfyr_state::State` etc. without knowing the module layout.

### 3. `crates/netfyr-state/src/value.rs`
- **Action**: Create
- **What**:
  - `Value` enum with 8 variants: `String(String)`, `U64(u64)`, `I64(i64)`, `Bool(bool)`, `IpAddr(std::net::IpAddr)`, `IpNetwork(ipnetwork::IpNetwork)`, `List(Vec<Value>)`, `Map(IndexMap<String, Value>)`.
  - Derive `Clone`, `Debug`, `PartialEq`, `Serialize`, `Deserialize`.
  - `#[serde(untagged)]` on the enum.
  - Variant declaration order for correct untagged deserialization: `Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `List`, `Map`, `String`. (Bool first because JSON bools are syntactically distinct and won't conflict. Numerics next. IpNetwork before IpAddr because IpNetwork's deserializer requires `/prefix` so it won't swallow bare IPs. Both before String because IP-format strings should be parsed as IPs when deserializing. List and Map before String because they're structurally distinct in JSON. String last as the fallback.)
  - **Wait — reconsider ordering**: With `untagged`, serde tries each variant's deserializer in order. For JSON: `true` is distinct (Bool works). `42` is a number — `U64` will try first (good). `-1` — `U64` will fail, `I64` will succeed (good). `"10.0.0.0/24"` is a JSON string — if `String` variant comes first, it would match and IpNetwork would never be tried. So `String` must come AFTER `IpNetwork` and `IpAddr`. But `IpNetwork` and `IpAddr` both deserialize from strings — `IpNetwork` requires `/prefix`, `IpAddr` doesn't. So order: `IpNetwork` then `IpAddr` then `String`. For arrays: `List` deserializes from JSON array, distinct from other types. For objects: `Map` deserializes from JSON object, distinct. Final order: `Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `List`, `Map`, `String`.
  - `From` impls: `From<String>`, `From<&str>` (converts to owned String), `From<u64>`, `From<i64>`, `From<bool>`, `From<std::net::IpAddr>`, `From<ipnetwork::IpNetwork>`.
  - `Display` impl: match on each variant:
    - `String(s)` => write `s` (the raw string, no quotes)
    - `U64(n)` => write the number
    - `I64(n)` => write the number
    - `Bool(b)` => write `true`/`false`
    - `IpAddr(ip)` => use `IpAddr`'s own `Display`
    - `IpNetwork(net)` => use `IpNetwork`'s own `Display`
    - `List(items)` => format as `[item1, item2, ...]` using each item's `Display`
    - `Map(map)` => format as `{key: val, key2: val2}` iterating the IndexMap
  - Typed accessors (all `&self` methods):
    - `as_str(&self) -> Option<&str>` — returns `Some(s)` for `String(s)`, `None` otherwise
    - `as_u64(&self) -> Option<u64>` — returns `Some(n)` for `U64(n)`, `None` otherwise
    - `as_i64(&self) -> Option<i64>` — returns `Some(n)` for `I64(n)`, `None` otherwise
    - `as_bool(&self) -> Option<bool>` — returns `Some(b)` for `Bool(b)`, `None` otherwise
    - `as_ip_addr(&self) -> Option<&std::net::IpAddr>` — returns `Some(ip)` for `IpAddr(ip)`, `None` otherwise
    - `as_ip_network(&self) -> Option<&ipnetwork::IpNetwork>` — returns `Some(net)` for `IpNetwork(net)`, `None` otherwise
    - `as_list(&self) -> Option<&Vec<Value>>` — returns `Some(list)` for `List(list)`, `None` otherwise
    - `as_map(&self) -> Option<&IndexMap<String, Value>>` — returns `Some(map)` for `Map(map)`, `None` otherwise
- **Why**: Core value type used by every other type in the crate. Must support all network config data types and be ergonomic to construct and inspect.

### 4. `crates/netfyr-state/src/provenance.rs`
- **Action**: Create
- **What**:
  - `Provenance` enum with 4 variants:
    - `UserConfigured { policy_ref: String }`
    - `KernelDefault`
    - `ExternalTool { tool: String, detected_at: chrono::DateTime<chrono::Utc> }`
    - `Derived { reason: String }`
  - Derive `Clone`, `Debug`, `PartialEq`, `Serialize`, `Deserialize`.
  - `#[serde(tag = "source", rename_all = "snake_case")]` on the enum.
- **Why**: Tracks the origin of each field value, enabling "where did this come from?" queries that are a key differentiator of netfyr.

### 5. `crates/netfyr-state/src/metadata.rs`
- **Action**: Create
- **What**:
  - `StateMetadata` struct with fields:
    - `id: uuid::Uuid`
    - `timeline_id: uuid::Uuid`
    - `created_at: chrono::DateTime<chrono::Utc>`
    - `labels: std::collections::HashMap<String, String>`
    - `description: Option<String>`
  - Derive `Clone`, `Debug`, `PartialEq`, `Serialize`, `Deserialize`.
  - `impl StateMetadata` with `pub fn new() -> Self` that generates UUIDv7 for both `id` and `timeline_id`, sets `created_at` to `Utc::now()`, initializes `labels` to empty HashMap, `description` to `None`. Exact implementation per spec snippet.
- **Why**: Provides identity and tracking metadata for each state instance, with time-ordered UUIDs for natural chronological sorting.

### 6. `crates/netfyr-state/src/field.rs`
- **Action**: Create
- **What**:
  - `FieldValue` struct with fields:
    - `value: Value`
    - `provenance: Provenance`
  - Derive `Clone`, `Debug`, `PartialEq`, `Serialize`, `Deserialize`.
  - Uses `crate::value::Value` and `crate::provenance::Provenance`.
- **Why**: Pairs a value with its provenance, enabling per-field tracking of origin.

### 7. `crates/netfyr-state/src/selector.rs`
- **Action**: Create
- **What**:
  - `Selector` struct with `#[non_exhaustive]` attribute and field:
    - `name: Option<String>`
  - Derive `Clone`, `Debug`, `PartialEq`, `Serialize`, `Deserialize`.
  - Provide a `pub fn new() -> Self` that initializes `name` to `None` (since `#[non_exhaustive]` prevents external struct literal construction).
  - Provide a `pub fn with_name(name: impl Into<String>) -> Self` convenience constructor that sets `name` to `Some(name.into())`.
- **Why**: Placeholder for SPEC-003. `#[non_exhaustive]` ensures future fields can be added without breaking downstream crates. Constructors are needed because `#[non_exhaustive]` prevents struct literal syntax outside the defining crate.

### 8. `crates/netfyr-state/src/entity.rs`
- **Action**: Create
- **What**:
  - `State` struct with fields:
    - `entity_type: String`
    - `selector: Selector`
    - `fields: IndexMap<String, FieldValue>`
    - `metadata: StateMetadata`
    - `policy_ref: Option<String>`
    - `priority: u32`
  - Derive `Clone`, `Debug`, `PartialEq`, `Serialize`, `Deserialize`.
  - Uses `crate::selector::Selector`, `crate::field::FieldValue`, `crate::metadata::StateMetadata`, and `indexmap::IndexMap`.
- **Why**: Top-level type representing one network entity's configuration. All other types compose into this.

## Dependencies

| Crate | Version | Features | Justification |
|---|---|---|---|
| `serde` | `1` | `derive` | Serialization framework; `derive` enables `#[derive(Serialize, Deserialize)]`. No std alternative for structured serialization. |
| `serde_json` | `1` | (none) | JSON serialization for Value conversions and testing. Spec explicitly lists this. |
| `chrono` | `0.4` | `serde` | Timestamp type for `created_at` and `detected_at`. std's `SystemTime` lacks timezone awareness, formatting, and serde support. `serde` feature enables `Serialize`/`Deserialize` for `DateTime<Utc>`. |
| `uuid` | `1` | `v7`, `serde` | UUIDv7 generation for time-ordered unique IDs. No std equivalent. `v7` enables `Uuid::now_v7()`. `serde` enables serialization. |
| `ipnetwork` | `0.20` | `serde` | CIDR network representation (`10.0.0.0/24`). std has `IpAddr` but no CIDR/prefix-length type. `serde` enables serialization. |
| `indexmap` | `2` | `serde` | Ordered map preserving insertion order. std's `HashMap` does not preserve order, and `BTreeMap` sorts by key rather than preserving insertion order. `serde` enables serialization. |

## Implementation Order

1. **Update `Cargo.toml`** — Add all six dependencies. After this step the crate compiles (lib.rs is just a doc comment, no code to break).

2. **Create `src/value.rs`** — Implement `Value` enum with all variants, derives, serde attribute, `From` impls, `Display` impl, and typed accessors. This is a leaf type with no intra-crate dependencies. After this step, the file compiles standalone (though not yet referenced from `lib.rs`).

3. **Create `src/provenance.rs`** — Implement `Provenance` enum. Leaf type, no intra-crate dependencies.

4. **Create `src/metadata.rs`** — Implement `StateMetadata` struct and `new()` constructor. Leaf type.

5. **Create `src/selector.rs`** — Implement `Selector` placeholder. Leaf type.

6. **Create `src/field.rs`** — Implement `FieldValue` struct. Depends on `Value` (step 2) and `Provenance` (step 3).

7. **Create `src/entity.rs`** — Implement `State` struct. Depends on `Selector` (step 5), `FieldValue` (step 6), and `StateMetadata` (step 4).

8. **Update `src/lib.rs`** — Add `mod` declarations for all six modules and `pub use` re-exports for all public types. After this step, `cargo build -p netfyr-state` compiles successfully and all types are accessible at the crate root.

Steps 2-5 are independent and can be done in parallel. Step 6 depends on 2 and 3. Step 7 depends on 4, 5, and 6. Step 8 depends on all prior steps. In practice, an implementer working linearly should follow the numbered order since it results in a compilable state at step 8.

## Risks and Mitigations

1. **Untagged serde deserialization ordering for `Value`**.
   - **Risk**: If variants are ordered incorrectly, deserializing JSON values will match the wrong variant (e.g., an IP address string matching `String` instead of `IpAddr`).
   - **Mitigation**: The ordering specified above (`Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `List`, `Map`, `String`) handles this correctly because: JSON bools are syntactically distinct; JSON numbers are syntactically distinct from strings; `IpNetwork` requires `/prefix` so won't match bare IPs; `IpAddr` parsing will fail on non-IP strings, falling through to `String`. The test strategy includes a round-trip test to verify this.

2. **`ipnetwork` crate version compatibility**.
   - **Risk**: The `serde` feature name or availability could differ across versions.
   - **Mitigation**: `ipnetwork 0.20` is the current stable version and has had the `serde` feature since 0.17. Pin to `0.20` to be explicit.

3. **`uuid` crate v7 feature availability**.
   - **Risk**: `Uuid::now_v7()` was stabilized in uuid 1.6.0. An older version would fail.
   - **Mitigation**: Specifying `version = "1"` allows any 1.x; uuid is currently at 1.11+. No workspace version pin exists to conflict.

4. **`#[non_exhaustive]` on `Selector` prevents struct literal construction in tests**.
   - **Risk**: Test code in other crates (or integration tests) can't write `Selector { name: Some("eth0".into()) }`.
   - **Mitigation**: Provide `Selector::new()` and `Selector::with_name()` constructors. Tests within `netfyr-state` can use struct literals since `#[non_exhaustive]` only applies to external crates. If tests are in the same crate, no issue. For integration tests in `tests/`, the constructors are needed.

5. **`Value` containing `IpAddr` and `IpNetwork` — Display and Serialize correctness**.
   - **Risk**: `IpAddr::Display` and `IpNetwork::Display` might not produce the expected format.
   - **Mitigation**: `std::net::IpAddr` displays as `10.0.0.1`, and `ipnetwork::IpNetwork` displays as `10.0.0.0/24`. Both are the expected formats. Verified by the round-trip serde test.

6. **`chrono::DateTime<Utc>` deserialization format**.
   - **Risk**: Default chrono serde format is RFC 3339. If downstream YAML config needs a different format, this could cause issues later.
   - **Mitigation**: RFC 3339 is the standard; no reason to deviate. Future specs can customize with `#[serde(with = "...")]` if needed. This is outside scope for SPEC-002.

7. **Heterogeneous `Value::List` deserialization with untagged enum**.
   - **Risk**: A JSON array like `[1, "hello", true]` needs each element to be deserialized as a `Value` independently. With `untagged`, each element goes through the variant-matching logic.
   - **Mitigation**: This works correctly because serde's untagged enum deserialization applies per-element within `Vec<Value>`. Each element is independently tried against the variant list. No special handling needed.

## Test Strategy

Tests will be written by the test phase, not the implementation phase. Here's what to test:

### Unit Tests (per module, using `#[cfg(test)] mod tests`)

**`value.rs` tests:**
- Construct each of the 8 variants and verify `Clone` + `PartialEq` (clone and assert equality).
- `From` trait: `Value::from("hello")` produces `Value::String("hello".into())`, `Value::from(42u64)` produces `Value::U64(42)`, `Value::from(-1i64)` produces `Value::I64(-1)`, `Value::from(true)` produces `Value::Bool(true)`, `Value::from(IpAddr)` and `Value::from(IpNetwork)` produce correct variants.
- Typed accessors: For each variant, call the matching accessor and assert `Some`, call non-matching accessors and assert `None`.
- `Display`: Verify formatting for each variant. String outputs raw text, numbers output digits, bools output `true`/`false`, IpAddr outputs dotted notation, IpNetwork outputs CIDR, List outputs `[a, b, c]`, Map outputs `{key: val}`.
- `Debug`: Verify `format!("{:?}", val)` is non-empty for at least one variant.

**`provenance.rs` tests:**
- Construct each of the 4 variants and verify field access.
- `UserConfigured` has `policy_ref`, `KernelDefault` has no fields, `ExternalTool` has `tool` and `detected_at`, `Derived` has `reason`.

**`metadata.rs` tests:**
- Call `StateMetadata::new()` twice, assert `id` fields differ, `timeline_id` fields differ.
- Assert `created_at` is within 1 second of `Utc::now()`.
- Assert `labels` is empty, `description` is `None`.

**`selector.rs` tests:**
- `Selector::new()` has `name: None`.
- `Selector::with_name("eth0")` has `name: Some("eth0".into())`.

**`field.rs` tests:**
- Construct a `FieldValue` with a `Value::U64(9000)` and `Provenance::UserConfigured { policy_ref: "bond0".into() }`, verify both fields accessible.

**`entity.rs` tests:**
- Construct a fully populated `State` with all fields set, clone it, assert clone equals original.
- Assert `format!("{:?}", state)` is non-empty.

### Integration Tests (in `tests/` directory or as comprehensive tests in a module)

**Serde round-trip:**
- Construct a fully populated `State` (with nested `FieldValue`s containing various `Value` variants and `Provenance` types).
- Serialize to JSON with `serde_json::to_string`.
- Assert the JSON is valid (serialization didn't panic).
- Deserialize back to `State` with `serde_json::from_str`.
- Assert the deserialized value equals the original.

**Insertion order preservation:**
- Construct a `State` with `fields` inserted in a specific order (e.g., "mtu", "addresses", "routes").
- Iterate `fields.keys()` and assert they appear in insertion order.

**Value serde round-trip for each variant:**
- Test that each `Value` variant survives a JSON round-trip. Pay special attention to `IpAddr` and `IpNetwork` (serialize as strings, must deserialize back to the correct variant, not `Value::String`).

### Test Infrastructure Needed
- No mocks or fixtures needed. All types are constructible with simple values.
- `serde_json` is available as a dependency for serialization tests.
- `chrono::Utc::now()` for timestamp comparisons.
- `std::net::IpAddr` parsed from `"10.0.1.1".parse::<IpAddr>()`.
- `ipnetwork::IpNetwork` parsed from `"10.0.1.0/24".parse::<IpNetwork>()`.
