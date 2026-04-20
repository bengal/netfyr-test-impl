# Understand: SPEC-002 Entity State Types

## Current State

The project is a Rust workspace with eight crates, all essentially empty skeleton stubs:

- `crates/netfyr-state/src/lib.rs` — single doc comment line, no types defined
- `crates/netfyr-state/Cargo.toml` — no dependencies declared
- All other crates (`netfyr-reconcile`, `netfyr-backend`, `netfyr-policy`, `netfyr-varlink`, `netfyr-test-utils`) — single doc comment stubs
- `netfyr-cli` and `netfyr-daemon` — trivial `main()` that prints `"netfyr"`
- Workspace `Cargo.toml` — declares members and three feature flags (`dhcp`, `systemd`, `varlink`), no workspace-level dependencies

No types, traits, tests, or modules exist anywhere in the project. SPEC-001 (which this story depends on) has already been satisfied to the extent that the workspace skeleton compiles.

## Requirements

### Types to implement (all in `netfyr-state`)

| Type | Kind | Required derives/impls |
|---|---|---|
| `State` | struct | `Clone, Debug, Serialize, Deserialize, PartialEq` |
| `FieldValue` | struct | `Clone, Debug, Serialize, Deserialize, PartialEq` |
| `Value` | enum | `Clone, Debug, Serialize, Deserialize, PartialEq` + `From` impls + `Display` + typed accessors |
| `Provenance` | enum | `Clone, Debug, Serialize, Deserialize, PartialEq` |
| `StateMetadata` | struct | `Clone, Debug, Serialize, Deserialize, PartialEq` + `new()` constructor |
| `Selector` | struct (placeholder) | `Clone, Debug, Serialize, Deserialize, PartialEq` |

### `State` fields
- `entity_type: String`
- `selector: Selector`
- `fields: IndexMap<String, FieldValue>`
- `metadata: StateMetadata`
- `policy_ref: Option<String>`
- `priority: u32` (default 100)

### `FieldValue` fields
- `value: Value`
- `provenance: Provenance`

### `Value` variants
- `String(String)`
- `U64(u64)`
- `I64(i64)`
- `Bool(bool)`
- `IpAddr(std::net::IpAddr)`
- `IpNetwork(ipnetwork::IpNetwork)`
- `List(Vec<Value>)`
- `Map(IndexMap<String, Value>)`

### `Value` additional requirements
- `From<String>`, `From<&str>`, `From<u64>`, `From<i64>`, `From<bool>`, `From<IpAddr>`, `From<IpNetwork>`
- `Display` impl: IP addresses as dotted notation, lists as `[a, b, c]`
- Typed accessors: `as_str() -> Option<&str>`, `as_u64() -> Option<u64>`, `as_i64() -> Option<i64>`, `as_bool() -> Option<bool>`, `as_ip_addr() -> Option<IpAddr>`, `as_ip_network() -> Option<IpNetwork>`

### `Provenance` variants
- `UserConfigured { policy_ref: String }`
- `KernelDefault`
- `ExternalTool { tool: String, detected_at: chrono::DateTime<chrono::Utc> }`
- `Derived { reason: String }`

### `StateMetadata` fields
- `id: uuid::Uuid` (UUIDv7)
- `timeline_id: uuid::Uuid` (UUIDv7)
- `created_at: chrono::DateTime<chrono::Utc>`
- `labels: HashMap<String, String>`
- `description: Option<String>`

### `StateMetadata::new()`
Must call `Uuid::now_v7()` for both `id` and `timeline_id`, `Utc::now()` for `created_at`, initialize `labels` to empty `HashMap`, `description` to `None`.

### `Selector` (placeholder)
- `name: Option<String>`
- Will be expanded in SPEC-003; must be structurally compatible with future extension

### New source files required
- `src/entity.rs` — `State`
- `src/field.rs` — `FieldValue`
- `src/value.rs` — `Value`
- `src/provenance.rs` — `Provenance`
- `src/metadata.rs` — `StateMetadata`
- `src/selector.rs` — `Selector` placeholder (implied by spec; no explicit file named, but needed for clean module organization)
- `src/lib.rs` — updated to `mod` declare all modules and `pub use` re-export all public types

### Dependency additions required in `crates/netfyr-state/Cargo.toml`
- `serde` with `derive` feature
- `serde_json` (for tests and Value conversions)
- `chrono` with `serde` feature
- `uuid` with `v7` and `serde` features
- `ipnetwork` with `serde` feature
- `indexmap` with `serde` feature

### Tests required (acceptance criteria)
All scenarios must be covered. Tests can live in each module (`#[cfg(test)]`) or in a dedicated `tests/` integration test file:
1. Construct a fully populated `State`, verify `Clone` and `PartialEq`
2. Construct `FieldValue`, verify field access
3. Construct all `Value` variants
4. `From` trait conversions on `Value`
5. Typed accessors returning `Some`/`None` correctly
6. All `Provenance` variants and their fields
7. `StateMetadata::new()` uniqueness and timestamp check (two instances have different UUIDs, `created_at` within 1 second of now)
8. Round-trip `serde_json` serialize/deserialize of `State`
9. `IndexMap` field insertion order preserved on iteration

## Gap Analysis

Everything in this story must be created from scratch. No relevant code exists yet.

### Files to create
| File | Contents |
|---|---|
| `crates/netfyr-state/src/value.rs` | `Value` enum, `From` impls, `Display`, typed accessors |
| `crates/netfyr-state/src/provenance.rs` | `Provenance` enum |
| `crates/netfyr-state/src/metadata.rs` | `StateMetadata` struct, `StateMetadata::new()` |
| `crates/netfyr-state/src/field.rs` | `FieldValue` struct |
| `crates/netfyr-state/src/selector.rs` | `Selector` placeholder struct |
| `crates/netfyr-state/src/entity.rs` | `State` struct |

### Files to modify
| File | Change |
|---|---|
| `crates/netfyr-state/src/lib.rs` | Add `mod` declarations and `pub use` re-exports for all types |
| `crates/netfyr-state/Cargo.toml` | Add all six external dependencies with correct features |

### No changes needed in other crates
Other crates (`netfyr-policy`, `netfyr-reconcile`, `netfyr-backend`, `netfyr-daemon`) will eventually depend on `netfyr-state`, but that wiring is outside this story's scope.

## Integration Points

- **`netfyr-policy`** — will consume `State`, `FieldValue`, `Value`, `Provenance` to produce states from policy definitions (SPEC-005)
- **`netfyr-reconcile`** — will compare `State` instances and use `priority` for conflict resolution
- **`netfyr-backend`** — will read `State.fields` and apply them to the kernel/iproute2
- **`netfyr-daemon`** — will hold collections of `State` in memory
- **`netfyr-varlink`** — will serialize `State` for IPC
- **`Selector`** — SPEC-003 will replace the placeholder; the placeholder must use a struct (not a type alias or enum) so it can be extended with additional fields without breaking downstream code

The public re-export surface from `lib.rs` is the only interface other crates will see. All types must be reachable via `netfyr_state::TypeName` without needing to know the module layout.

## Risks

1. **`Selector` placeholder compatibility**: The placeholder struct must use `#[non_exhaustive]` or be explicitly designed for field addition; using a tuple struct or unit struct would force a breaking change in SPEC-003. A named-field struct (`name: Option<String>`) is the right shape per spec.

2. **`IpNetwork` serde representation**: `ipnetwork::IpNetwork` serializes as a CIDR string by default with the `serde` feature enabled; this should be verified to round-trip correctly and produce human-readable JSON.

3. **`Value::Map` key ordering in serde**: `IndexMap` preserves insertion order in memory, but JSON object key order is technically unspecified. The serde round-trip test (acceptance criterion 8) must verify that deserialized `IndexMap` key order matches the original — this works correctly when using `indexmap`'s serde support, but the test must be explicit.

4. **UUIDv7 availability**: `uuid::Uuid::now_v7()` requires the `v7` feature flag. If the workspace has a pinned `uuid` version that predates v7 support (stable since uuid 1.6.0), this would fail at compile time. The workspace does not currently pin any versions, so this is low risk.

5. **`Display` for nested `Value` types**: The `List` and `Map` variants require recursive `Display` formatting. The spec specifies `[a, b, c]` for lists but does not specify the format for `Map`. The implementation should choose a consistent format (e.g., `{key: val, ...}`) and the tests should be written against whatever format is chosen.

6. **`Value::List` containing heterogeneous types**: The `List(Vec<Value>)` variant permits mixed-type lists (e.g., `[String("a"), U64(1)]`). Serde deserialization must handle this correctly; since `Value` is an enum, the serde representation needs explicit tagging or untagged deserialization. The spec does not specify the serde representation — this is an implementation decision with downstream YAML compatibility implications (SPEC-005).

7. **No `Default` impl specified for `State`**: The spec does not require `Default`, and constructing a valid `State` requires a meaningful `entity_type` and `selector`. Tests must construct instances explicitly rather than using default values.
