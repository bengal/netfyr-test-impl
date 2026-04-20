# Plan: SPEC-006 Entity Schema Validation

## Approach

The implementation adds a `schema` module to `netfyr-state` containing a `SchemaRegistry` that embeds JSON Schema files at compile time and validates `State` instances against them. The core data flow is: `State` -> extract `entity_type` -> look up compiled `Validator` -> convert `State.fields` to `serde_json::Value` -> run JSON Schema validation -> collect errors -> optionally check writable metadata -> return `Result<(), ValidationErrors>`.

The design splits into two layers: (1) a JSON Schema validation layer powered by the `jsonschema` crate, which handles structural validation (type checking, range constraints, required fields, unknown field rejection via `additionalProperties: false`), and (2) a metadata layer that parses custom `x-netfyr-writable` extensions from the schema JSON to enforce writable/read-only semantics, which the standard JSON Schema validator ignores. The `SchemaRegistry` pre-parses both layers at construction time — the compiled `Validator` for fast validation, and a `HashMap<String, FieldSchemaInfo>` per entity type for programmatic field queries and writable checks.

The alternative of hand-rolling validation without JSON Schema was rejected because it would duplicate constraint logic and miss the extensibility benefits of a standard schema format. The alternative of using JSON Schema for everything (including writability) via a custom keyword validator was rejected because the `jsonschema` crate's custom keyword extension API is complex and unnecessary — a simple post-validation pass over field metadata is cleaner and more maintainable.

The `Value -> serde_json::Value` conversion is implemented as `impl From<&Value> for serde_json::Value` in `schema.rs` (not in `lib.rs`) to keep the JSON-specific conversion co-located with its only consumer and avoid coupling the core types to `serde_json` semantics beyond what already exists.

## Design Decisions

1. **`jsonschema` crate version: pin to `"0.26"`**
   - **Decision**: Use `jsonschema = "0.26"` rather than the latest 0.46.x.
   - **Alternatives considered**: `0.46.x` (latest), `0.18.x`.
   - **Rationale**: The `0.26.x` line has a stable, well-documented API with `JSONSchema::compile()`, `iter_errors()` returning `ValidationError` with public `instance_path` (a `JSONPointer` type) and `kind` (a `ValidationErrorKind` enum). Version 0.46 underwent major API restructuring (renamed to `Validator`, changed error types to `ValidationError` with methods like `instance_path()` returning `Location`, removed public `kind` field). The 0.26 API is simpler to map to our error types because `ValidationErrorKind` directly tells us whether an error is a type mismatch, range violation, etc. If 0.26 is unavailable or causes dependency issues, fall back to 0.28 which has the same API. **UPDATE**: If the implementer finds 0.26 has dependency conflicts, use the latest available version and adapt — the key requirement is `iter_errors()` + access to instance path + some way to classify error kind.

2. **`FieldType` enum uses `Integer` not `U32`/`U64`**
   - **Decision**: Define `FieldType` with a single `Integer` variant instead of separate `U32` and `U64`.
   - **Alternatives considered**: `U32` + `U64` as separate variants (per spec), keeping `U64` only.
   - **Rationale**: The `Value` enum has `U64` and `I64` but no `U32`. JSON Schema uses `"type": "integer"` for all integers — range is expressed via `minimum`/`maximum` constraints, not type width. Having `FieldType::U32` would be misleading since nothing in the pipeline produces or validates 32-bit specifically. A single `Integer` variant with range constraints in `FieldConstraints` is cleaner and matches how JSON Schema actually works. The spec lists `U32` in the `FieldType` enum, but also says `mtu` has `min: 68, max: 65535` — the constraints do the real work, not the type width.

3. **`ValidationErrorKind` includes `UnknownEntityType`**
   - **Decision**: Add `UnknownEntityType` to the `ValidationErrorKind` enum even though the spec doesn't explicitly list it.
   - **Alternatives considered**: Using a separate `Result` type for entity type lookup, returning `ValidationErrorKind::ConstraintViolation` for unknown types.
   - **Rationale**: The acceptance criteria require `validate()` on an unknown entity type to return `ValidationErrors` containing an error about the unknown type. A dedicated variant makes the error programmatically distinguishable. The `field` for this error will be empty string `""` since it's an entity-level error, not field-level.

4. **`Value` to `serde_json::Value` conversion placed in `schema.rs`**
   - **Decision**: Implement `From<&Value> for serde_json::Value` in `schema.rs`, not `lib.rs`.
   - **Alternatives considered**: Adding the impl in `lib.rs` next to the `Value` definition, creating a separate conversion module.
   - **Rationale**: The conversion is only needed for schema validation. Placing it in `schema.rs` keeps it co-located with its consumer. Rust's orphan rules allow this since both types are foreign but `Value` is defined in the same crate. Actually — `Value` is in this crate and `serde_json::Value` is foreign, so `impl From<&Value> for serde_json::Value` is allowed in any module of this crate.

5. **Fields map conversion strips `FieldValue` wrapper**
   - **Decision**: When converting `State.fields` for validation, extract `field_value.value` from each `FieldValue` and discard the `provenance`. The JSON object passed to the validator contains only field names mapped to their values.
   - **Alternatives considered**: Including provenance in the JSON object.
   - **Rationale**: The JSON Schema defines the shape of configuration data, not metadata. Provenance is orthogonal to validation. Including it would cause `additionalProperties: false` to reject it or require schema changes.

6. **Error path format: dot-notation with bracket indices**
   - **Decision**: Convert JSON Pointer paths from `jsonschema` (e.g., `/routes/0/destination`) to dot-bracket notation (e.g., `routes[0].destination`).
   - **Alternatives considered**: Using JSON Pointer directly, using only dot notation.
   - **Rationale**: The spec's example output uses `routes[0].gateway` format. JSON Pointer format (`/routes/0/destination`) is not user-friendly. The conversion is a straightforward string transformation: split on `/`, skip leading empty segment, join with `.` but wrap numeric segments in `[]`.

7. **`ValidationErrors` implements `Display` and `std::error::Error`**
   - **Decision**: Derive `thiserror::Error` on `ValidationErrors` with a `Display` impl that lists all errors.
   - **Alternatives considered**: Manual `impl Error`, no `Error` impl.
   - **Rationale**: `ValidationErrors` is used as the `Err` variant of a `Result` — it should implement `Error` for ergonomic `?` propagation and error reporting. `thiserror` is already a dependency.

8. **`FieldConstraints` uses `Option<i64>` for min/max**
   - **Decision**: Use `Option<i64>` for both `min` and `max` in `FieldConstraints`, even though most constraints are non-negative.
   - **Alternatives considered**: `Option<u64>`, `Option<f64>`, separate types for integer vs string constraints.
   - **Rationale**: JSON Schema `minimum`/`maximum` can be negative (though unlikely here). Using `i64` avoids lossy conversions. JSON Schema numbers in the schema file itself will be parsed via `serde_json` which uses `i64`/`f64`. Since all our constraints are integral, `i64` is the right fit.

9. **Schema draft: use draft 2020-12 in the JSON file, but compile with draft auto-detection**
   - **Decision**: Write the ethernet.json schema with `"$schema": "https://json-schema.org/draft/2020-12/schema"` and let the `jsonschema` crate auto-detect the draft from the `$schema` keyword.
   - **Alternatives considered**: Forcing draft-07 for broader compatibility, explicitly selecting draft in code.
   - **Rationale**: The spec explicitly says "draft 2020-12 or 07". Draft 2020-12 is the modern standard. The `jsonschema` crate (both 0.26 and 0.46) supports draft 2020-12. Auto-detection is the simplest code path.

10. **Route sub-object `x-netfyr-writable` inheritance**
    - **Decision**: Fields inside route objects do not have individual `x-netfyr-writable` annotations. The `routes` field itself is writable, and its sub-fields inherit that status. The `validate_writable()` check only operates on top-level fields of the entity.
    - **Alternatives considered**: Recursive writable checking on nested fields.
    - **Rationale**: The spec's field table only assigns writable/read-only at the top level. Route sub-fields (destination, gateway, metric) don't have a writable column — they're implicitly writable because `routes` is writable. Checking only top-level fields is simpler and matches the spec.

## File Changes

### 1. `crates/netfyr-state/src/schemas/ethernet.json` — CREATE

**What**: A JSON Schema file (draft 2020-12) defining the ethernet entity type. Contains:
- Top-level: `$schema`, `title: "ethernet"`, `description`, `type: "object"`, `additionalProperties: false`
- Properties:
  - `mtu`: `{ "type": "integer", "minimum": 68, "maximum": 65535, "x-netfyr-writable": true }`
  - `addresses`: `{ "type": "array", "items": { "type": "string", "pattern": "<CIDR regex>" }, "x-netfyr-writable": true }`
  - `mac`: `{ "type": "string", "pattern": "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", "x-netfyr-writable": false }`
  - `carrier`: `{ "type": "boolean", "x-netfyr-writable": false }`
  - `speed`: `{ "type": "integer", "minimum": 0, "x-netfyr-writable": false }`
  - `routes`: `{ "type": "array", "items": { route object schema }, "x-netfyr-writable": true }`
- Route object schema (inline in `routes.items`): `type: "object"`, `additionalProperties: false`, `required: ["destination"]`, properties: `destination` (string, CIDR pattern), `gateway` (string, IP pattern), `metric` (integer, minimum 0)
- CIDR pattern regex: `^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$` — a basic structural check (full IP validation happens at the Value type level; the schema just ensures the string looks like CIDR). For IPv6 support, use a more permissive pattern or two patterns via `anyOf`. Decision: use a permissive pattern that accepts both IPv4 and IPv6 CIDR — `^.+/.+$` is too loose; use a pattern that requires at least a slash: `^[0-9a-fA-F:.]+/[0-9]{1,3}$`.
- Gateway IP pattern: `^[0-9a-fA-F:.]+$` — accepts both IPv4 dotted-decimal and IPv6 colon-hex.

**Why**: The spec requires schemas to be embedded as JSON files. This is the first (and currently only) schema.

### 2. `crates/netfyr-state/src/schema.rs` — CREATE

**What**: The main schema validation module. Contains the following types and functions:

**Types:**

- `pub enum FieldType` — variants: `String`, `Integer`, `Bool`, `Array`, `Object`, `IpAddress`, `IpNetwork`, `MacAddress`. Derives `Debug, Clone, PartialEq`.

- `pub struct FieldConstraints` — fields: `pub min: Option<i64>`, `pub max: Option<i64>`, `pub pattern: Option<String>`. Derives `Debug, Clone, PartialEq`.

- `pub struct FieldSchemaInfo` — fields: `pub field_type: FieldType`, `pub required: bool`, `pub writable: bool`, `pub constraints: Option<FieldConstraints>`, `pub description: Option<String>`. Derives `Debug, Clone`.

- `pub enum ValidationErrorKind` — variants: `InvalidType`, `OutOfRange`, `UnknownField`, `MissingRequired`, `ReadOnlyField`, `InvalidFormat`, `ConstraintViolation`, `UnknownEntityType`. Derives `Debug, Clone, PartialEq`.

- `pub struct ValidationError` — fields: `pub field: String`, `pub message: String`, `pub kind: ValidationErrorKind`. Derives `Debug, Clone`.

- `pub struct ValidationErrors` — wraps `Vec<ValidationError>`. Implements `std::fmt::Display` (lists all errors, one per line) and `std::error::Error` via `thiserror`. Has methods:
  - `pub fn errors(&self) -> &[ValidationError]`
  - `pub fn len(&self) -> usize`
  - `pub fn is_empty(&self) -> bool`

- `pub struct EntitySchema` — fields: `validator: jsonschema::JSONSchema` (or `Validator` depending on crate version — the compiled schema), `fields: HashMap<String, FieldSchemaInfo>` (parsed metadata for each field), `raw: serde_json::Value` (the raw schema JSON for reference). Methods:
  - `fn field_info(&self, field: &str) -> Option<&FieldSchemaInfo>`

- `pub struct SchemaRegistry` — fields: `schemas: HashMap<String, EntitySchema>`. Methods detailed below.

**Constant:**
- `const ETHERNET_SCHEMA: &str = include_str!("schemas/ethernet.json");` — embeds the ethernet schema at compile time.

**`SchemaRegistry` methods:**

- `pub fn new() -> Self` — Creates the registry, parses and compiles all embedded schemas. For each schema: parse the JSON string via `serde_json::from_str`, extract the `title` field as the entity type name, compile the JSON Schema via the `jsonschema` crate, parse field metadata from `properties` (extracting `type`, `minimum`, `maximum`, `pattern`, `x-netfyr-writable`, `description`, and checking `required` array), store in the `schemas` map. Panics if an embedded schema is malformed (these are compile-time constants, so a panic is a build-time bug).

- `pub fn validate(&self, state: &State) -> Result<(), ValidationErrors>` — Looks up the schema by `state.entity_type`. If not found, returns `ValidationErrors` with a single `UnknownEntityType` error. Otherwise, converts `state.fields` to a `serde_json::Value` object (a JSON object mapping field names to converted values), runs the compiled validator's `iter_errors()`, maps each `jsonschema` error to a `ValidationError` (converting the instance path and classifying the error kind), and returns all collected errors.

- `pub fn validate_writable(&self, state: &State) -> Result<(), ValidationErrors>` — Calls `validate()` first. If that fails, starts with those errors. Then additionally iterates `state.fields` and checks each field name against the `EntitySchema.fields` metadata: if a field has `writable: false`, adds a `ReadOnlyField` error. Returns all errors combined.

- `pub fn get_schema(&self, entity_type: &str) -> Option<&EntitySchema>` — Simple lookup in the `schemas` map.

- `pub fn entity_types(&self) -> Vec<&str>` — Returns keys of the `schemas` map as `&str` references.

- `pub fn field_info(&self, entity_type: &str, field: &str) -> Option<FieldSchemaInfo>` — Looks up the entity schema, then the field within it. Returns a cloned `FieldSchemaInfo` if found.

**Helper functions (private):**

- `fn fields_to_json(fields: &IndexMap<String, FieldValue>) -> serde_json::Value` — Iterates `fields`, extracts `field_value.value` from each `FieldValue`, converts via `From<&Value> for serde_json::Value`, assembles a `serde_json::Map`.

- `fn json_pointer_to_field_path(pointer: &str) -> String` — Converts a JSON Pointer like `/routes/0/destination` to `routes[0].destination`. Algorithm: split on `/`, skip first empty segment, for each segment check if it's a pure integer (wrap in `[N]` and append to previous) or a field name (join with `.`).

- `fn classify_error(error: &jsonschema::ValidationError) -> ValidationErrorKind` — Maps the `jsonschema` error's kind/type to `ValidationErrorKind`. Mapping: type mismatch -> `InvalidType`, minimum/maximum violation -> `OutOfRange`, pattern mismatch -> `InvalidFormat`, additional properties -> `UnknownField`, required property missing -> `MissingRequired`, everything else -> `ConstraintViolation`.

**`impl From<&Value> for serde_json::Value`:**
- `Value::String(s)` -> `serde_json::Value::String(s.clone())`
- `Value::U64(n)` -> `serde_json::Value::Number(n.into())`
- `Value::I64(n)` -> `serde_json::Value::Number(n.into())`
- `Value::Bool(b)` -> `serde_json::Value::Bool(b)`
- `Value::IpAddr(ip)` -> `serde_json::Value::String(ip.to_string())`
- `Value::IpNetwork(net)` -> `serde_json::Value::String(net.to_string())`
- `Value::List(v)` -> `serde_json::Value::Array(v.iter().map(|x| x.into()).collect())`
- `Value::Map(m)` -> `serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), v.into())).collect())`

**Why**: This is the core of the story — all schema validation types and logic live here.

### 3. `crates/netfyr-state/src/lib.rs` — MODIFY

**What**: Add `pub mod schema;` declaration and re-export the public types:
```
pub use schema::{
    EntitySchema, FieldConstraints, FieldSchemaInfo, FieldType, SchemaRegistry,
    ValidationError, ValidationErrorKind, ValidationErrors,
};
```

**Why**: Makes schema types part of the `netfyr-state` public API, consistent with how `diff`, `loader`, `set`, and `yaml` modules are re-exported.

### 4. `crates/netfyr-state/Cargo.toml` — MODIFY

**What**: Add `jsonschema` dependency. Use version `"0.26"` as primary choice; if dependency resolution fails (e.g., due to conflicting `serde_json` version requirements), try `"0.28"` or the latest compatible version.

**Why**: Required for JSON Schema compilation and validation. No std alternative exists for JSON Schema validation.

## Dependencies

| Crate | Version | Justification |
|---|---|---|
| `jsonschema` | `"0.26"` (or latest compatible) | JSON Schema validation — compiling schemas and validating JSON instances against them. The Rust standard library has no JSON Schema support. This is the most widely used JSON Schema crate in the Rust ecosystem. |

All other required crates (`serde_json`, `thiserror`, `indexmap`) are already dependencies.

## Implementation Order

1. **Create `src/schemas/ethernet.json`** — The JSON Schema file. No Rust code depends on this compiling yet, but having it first lets us verify the schema is valid JSON. No compilation step needed.

2. **Add `jsonschema` to `Cargo.toml`** — Required before `schema.rs` can reference it. After this step, `cargo check` should still pass (no new Rust code yet).

3. **Create `src/schema.rs` with types only** — Define all public types (`FieldType`, `FieldConstraints`, `FieldSchemaInfo`, `ValidationErrorKind`, `ValidationError`, `ValidationErrors`, `EntitySchema`, `SchemaRegistry`) with their struct/enum definitions and basic impls (`Display` for `ValidationErrors`, `From<&Value> for serde_json::Value`). Add the `ETHERNET_SCHEMA` constant. Leave `SchemaRegistry` methods as `todo!()` stubs. This step depends on step 1 (the JSON file must exist for `include_str!` to compile) and step 2 (the `jsonschema` crate must be available).

4. **Update `src/lib.rs`** — Add `pub mod schema;` and re-exports. After this step, `cargo check` should pass with `todo!()` stubs.

5. **Implement `SchemaRegistry::new()` and schema parsing** — Parse the embedded JSON, compile via `jsonschema`, extract field metadata from the `properties` object. This is the most complex function — it must correctly parse `type`, `minimum`, `maximum`, `pattern`, `x-netfyr-writable`, `description`, and the `required` array from the JSON Schema.

6. **Implement `validate()` and helper functions** — `fields_to_json()`, `json_pointer_to_field_path()`, `classify_error()`, and `validate()`. Depends on step 5 (needs a constructed registry to validate against).

7. **Implement `validate_writable()`** — Builds on `validate()` from step 6, adds the read-only field check pass.

8. **Implement `get_schema()`, `entity_types()`, `field_info()`** — Simple accessors. Can be done in parallel with steps 6-7 but logically completes the API.

## Risks and Mitigations

1. **`jsonschema` crate API instability across versions**
   - **Risk**: The `jsonschema` crate has undergone significant API changes. Version 0.26 uses `JSONSchema::compile()` + `ValidationError` with `instance_path: JSONPointer` and `kind: ValidationErrorKind`. Version 0.46 restructured to `Validator` + different error types.
   - **Mitigation**: Pin to `"0.26"`. If 0.26 has dependency conflicts with the existing `serde_json = "1"`, try 0.28 (same API). If neither works, use the latest version and adapt the `classify_error()` function to work with the available error API — the core validation flow (compile schema, iterate errors, extract path) is conceptually the same across versions. The implementer should check `cargo check` after adding the dependency and adapt if needed.

2. **`Value::IpAddr` and `Value::IpNetwork` serialize as strings but schema expects strings**
   - **Risk**: The `Value` enum has typed IP variants, but the JSON Schema defines these fields as `"type": "string"` with patterns. The conversion must produce JSON strings, not some other representation.
   - **Mitigation**: The `From<&Value> for serde_json::Value` impl explicitly calls `.to_string()` for `IpAddr` and `IpNetwork`, producing JSON strings that match the schema's string type and pattern constraints.

3. **CIDR and IP address regex patterns may be too strict or too loose**
   - **Risk**: A regex like `^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$` matches `999.999.999.999/99` which isn't valid. But a fully correct IPv4+IPv6 CIDR regex is extremely complex.
   - **Mitigation**: Use a reasonable structural pattern in the JSON Schema for basic format validation. Deep IP validation happens at the `Value` type level (the YAML parser already produces `Value::IpNetwork` which is validated by the `ipnetwork` crate). The schema pattern is a first line of defense against obviously wrong strings, not a replacement for type-level validation.

4. **`jsonschema` error kind mapping may be incomplete**
   - **Risk**: The `jsonschema` crate may produce error kinds not anticipated in `classify_error()`, leading to unexpected `ConstraintViolation` fallback.
   - **Mitigation**: The `ConstraintViolation` variant serves as a catch-all. The most important kinds to map correctly are: type mismatch (`InvalidType`), min/max violation (`OutOfRange`), additional properties (`UnknownField`), required (`MissingRequired`), and pattern (`InvalidFormat`). Log or include the original error message in the `ValidationError.message` field so users still get useful information even if the kind mapping is imprecise.

5. **`include_str!` path resolution**
   - **Risk**: `include_str!("schemas/ethernet.json")` resolves relative to the source file (`src/schema.rs`), so the JSON file must be at `src/schemas/ethernet.json`.
   - **Mitigation**: This is straightforward — just ensure the directory structure is correct. The compiler will produce a clear error if the file doesn't exist.

6. **Empty `State.fields` validation**
   - **Risk**: A `State` with no fields should pass validation (no fields are required in the ethernet schema). But if the `fields_to_json()` function produces something unexpected for an empty map, it could fail.
   - **Mitigation**: An empty `IndexMap` converts to an empty JSON object `{}`, which is valid against the ethernet schema since no fields are marked as required.

7. **`validate_writable()` interaction with `validate()` errors**
   - **Risk**: If `validate()` returns errors (e.g., type mismatch on `mtu`), `validate_writable()` should still report read-only field errors in addition. If it short-circuits on validation failure, it would miss reporting `ReadOnlyField` errors.
   - **Mitigation**: `validate_writable()` collects validation errors from the JSON Schema pass AND read-only field errors independently, then combines them. It does not short-circuit.

## Test Strategy

### Unit tests (in `schema.rs` `#[cfg(test)]` module)

**SchemaRegistry construction:**
- `new()` returns a registry where `entity_types()` includes `"ethernet"`
- `get_schema("ethernet")` returns `Some`
- `get_schema("nonexistent")` returns `None`

**Value to JSON conversion:**
- Each `Value` variant converts to the expected `serde_json::Value`
- `IpAddr` and `IpNetwork` produce JSON strings
- Nested `List` and `Map` values convert recursively

**JSON pointer path conversion:**
- `/mtu` -> `mtu`
- `/routes/0/destination` -> `routes[0].destination`
- `/routes/0` -> `routes[0]`
- Empty path -> empty string

**Ethernet validation — valid states:**
- State with only `mtu: 1500` passes
- State with `addresses: ["10.0.1.50/24"]` passes
- State with all writable fields passes
- State with `mac` and `carrier` (read-only) passes `validate()` (read-only is allowed in regular validation)
- State with routes containing valid route objects passes
- Empty fields state passes (no required fields)

**Ethernet validation — invalid states:**
- `mtu: 10` (below minimum 68) -> `OutOfRange` error for "mtu"
- `mtu: 99999` (above maximum 65535) -> `OutOfRange` error for "mtu"
- `mtu: "not a number"` (wrong type) -> `InvalidType` error for "mtu"
- Unknown field `"mtt": 1500` -> `UnknownField` error for "mtt"
- Route missing required `destination` -> `MissingRequired` error
- Multiple errors collected simultaneously (e.g., bad `mtu` + unknown field)

**Writable validation:**
- State with `mac: "aa:bb:cc:dd:ee:ff"` fails `validate_writable()` with `ReadOnlyField`
- State with `carrier: true` fails `validate_writable()` with `ReadOnlyField`
- State with only writable fields passes `validate_writable()`
- Read-only errors combined with structural errors (e.g., bad `mtu` + `mac` present)

**Unknown entity type:**
- `validate()` on entity_type `"nonexistent"` returns `ValidationErrors` with `UnknownEntityType`

**Field info queries:**
- `field_info("ethernet", "mtu")` returns `Some` with `FieldType::Integer`, writable: true, required: false, constraints with min=68, max=65535
- `field_info("ethernet", "carrier")` returns `Some` with `FieldType::Bool`, writable: false
- `field_info("ethernet", "mac")` returns `Some` with `FieldType::MacAddress` (or `String` if we can't distinguish — see note), writable: false, pattern constraint present
- `field_info("ethernet", "nonexistent")` returns `None`
- `field_info("nonexistent_type", "mtu")` returns `None`

### Integration-level behaviors to verify
- A `State` constructed via `parse_yaml()` (from SPEC-005) can be validated by `SchemaRegistry::validate()` — this verifies the two systems compose correctly. (This can be a test in a later story or tested manually.)

### Test infrastructure needed
- A helper function to construct a `State` with given entity_type and fields for concise test setup (e.g., `fn make_state(entity_type: &str, fields: Vec<(&str, Value)>) -> State`). This avoids boilerplate around `Selector`, `StateMetadata`, `FieldValue`, and `Provenance` in every test.

### What NOT to test
- The `jsonschema` crate's own correctness — we trust it validates JSON Schema correctly.
- Serialization/deserialization of schema types — these are internal, not serialized over the wire.
