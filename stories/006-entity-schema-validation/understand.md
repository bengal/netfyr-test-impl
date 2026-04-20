# SPEC-006: Entity Schema Validation — Gap Analysis

## Current State

### netfyr-state crate (`crates/netfyr-state/`)

**Source files present:**
- `src/lib.rs` — defines `State`, `Value`, `FieldValue`, `Selector`, `Provenance`, `StateMetadata`, `MacAddr`, `EntityType`
- `src/diff.rs` — `DiffOp`, `StateDiff`, `diff()`
- `src/loader.rs` — `load_file()`, `load_dir()`
- `src/set.rs` — `StateSet`, `Conflict`, `ConflictError`, set operations
- `src/yaml.rs` — `YamlError`, YAML serialization/deserialization

**No schema module exists.** There is no `src/schema.rs`, no `src/schemas/` directory, and no schema-related types anywhere in the codebase.

**Key existing types relevant to this story:**

- `State` (`lib.rs`): has `entity_type: String` and `fields: IndexMap<String, FieldValue>`. The `fields` map stores `FieldValue` (value + provenance), not bare `Value`.
- `Value` (`lib.rs`): enum with variants `Bool`, `U64`, `I64`, `IpNetwork`, `IpAddr`, `List(Vec<Value>)`, `Map(IndexMap<String, Value>)`, `String`. Has no `Into<serde_json::Value>` conversion.
- `FieldValue` (`lib.rs`): `{ value: Value, provenance: Provenance }`.

**Dependencies already present in `Cargo.toml`:**
- `serde_json = "1"` — already a dependency; usable for JSON Schema handling.
- `thiserror = "1"` — already available for error derivation.

**Missing dependency:**
- `jsonschema` — not in `Cargo.toml`. Must be added.

---

## Requirements

### Types to create

1. **`SchemaRegistry`** (`src/schema.rs`)
   - Holds compiled schemas for all known entity types, pre-loaded at construction.
   - Methods: `new()`, `validate(&State) -> Result<(), ValidationErrors>`, `validate_writable(&State) -> Result<(), ValidationErrors>`, `get_schema(&str) -> Option<&EntitySchema>`, `entity_types() -> Vec<&str>`, `field_info(&str, &str) -> Option<FieldSchemaInfo>`.

2. **`EntitySchema`** (`src/schema.rs`)
   - Holds the raw `serde_json::Value` for the compiled JSON Schema and a parsed map of `field_name -> FieldSchemaInfo` for programmatic access.

3. **`FieldSchemaInfo`** (`src/schema.rs`)
   - `field_type: FieldType`, `required: bool`, `writable: bool`, `constraints: Option<FieldConstraints>`, `description: Option<String>`.

4. **`FieldType`** (`src/schema.rs`)
   - Enum: `String`, `U32`, `U64`, `Bool`, `Array`, `Object`, `IpAddress`, `IpNetwork`, `MacAddress`.

5. **`FieldConstraints`** (`src/schema.rs`)
   - Holds `min: Option<i64>`, `max: Option<i64>`, `pattern: Option<String>`, and optionally item schema info.

6. **`ValidationErrors`** (`src/schema.rs`)
   - A collection wrapper around `Vec<ValidationError>`. Implements `std::error::Error`.

7. **`ValidationError`** (`src/schema.rs`)
   - `field: String`, `message: String`, `kind: ValidationErrorKind`.

8. **`ValidationErrorKind`** (`src/schema.rs`)
   - Enum: `InvalidType`, `OutOfRange`, `UnknownField`, `MissingRequired`, `ReadOnlyField`, `InvalidFormat`, `ConstraintViolation`, `UnknownEntityType`.

### Schema file to create

- **`src/schemas/ethernet.json`** — JSON Schema (draft 2020-12) with `x-netfyr-writable` extension annotations for: `mtu` (integer, 68–65535, writable), `addresses` (array of CIDR strings, writable), `mac` (string, MAC pattern, read-only), `carrier` (boolean, read-only), `speed` (integer, min 0, read-only), `routes` (array of objects with required `destination`, optional `gateway` and `metric`, writable). Must include `"additionalProperties": false`.

### Conversion to add

- **`Value` → `serde_json::Value`** (`src/lib.rs` or `src/schema.rs`): A function or `impl From<&Value> for serde_json::Value` to convert the internal `Value` enum into JSON for schema validation. Conversion: `IpAddr` and `IpNetwork` → JSON string; all others map naturally.

### File modifications

- **`crates/netfyr-state/Cargo.toml`**: add `jsonschema` dependency.
- **`crates/netfyr-state/src/lib.rs`**: add `pub mod schema;` and re-export the public schema types.

---

## Gap Analysis

| Item | Status | Action Required |
|---|---|---|
| `src/schema.rs` | Does not exist | Create with all schema types |
| `src/schemas/ethernet.json` | Does not exist | Create with full ethernet schema |
| `jsonschema` dependency | Missing | Add to `Cargo.toml` |
| `Value -> serde_json::Value` conversion | Missing | Implement (in `schema.rs` or `lib.rs`) |
| `lib.rs` module declaration | Missing `schema` | Add `pub mod schema` and re-exports |

---

## Integration Points

### `State` struct
Validation consumes `&State`. The implementation must extract:
- `state.entity_type` — to look up the schema in the registry.
- `state.fields` — `IndexMap<String, FieldValue>`. Each `FieldValue.value` must be extracted and converted to `serde_json::Value` to assemble the JSON object passed to the `jsonschema` validator.

### `Value` enum
The conversion from `Value` to `serde_json::Value` must handle:
- `Value::IpAddr` and `Value::IpNetwork`: convert to string representation (no native JSON type; the schema uses `"type": "string"` with pattern).
- `Value::U64` and `Value::I64`: map to `serde_json::Number`.
- `Value::List` and `Value::Map`: recurse.

### `jsonschema` crate
The crate returns errors with `instance_path` as a JSON Pointer (e.g., `/routes/0/destination`). These must be converted to the display format required by the spec (e.g., `"routes[0].destination"`). The `kind` field on `jsonschema::ValidationError` must be mapped to `ValidationErrorKind`.

### `x-netfyr-writable` extension
Standard JSON Schema validators ignore unknown extension keywords. The `validate_writable()` method cannot rely on the JSON Schema engine to enforce writability. It must be implemented as a separate post-validation pass: after standard validation passes, iterate `state.fields` and check each field's `writable` flag in the parsed `EntitySchema` metadata.

### `lib.rs` re-exports
The schema types must be added to `lib.rs` alongside the existing re-exports from `diff`, `loader`, `set`, and `yaml`.

---

## Risks

1. **`FieldType::U32` vs `Value::U64`**: The spec defines `FieldType::U32` for `mtu` and `speed`, but the existing `Value` enum has no `U32` variant — only `U64` and `I64`. Integer values from YAML will deserialize as `Value::U64`. The `FieldType` enum should use `U64` (or validate `U32` as a range subset of `U64`) to avoid type mismatches.

2. **`jsonschema` version API surface**: The `jsonschema` crate has undergone breaking API changes between versions (v0.17 vs v0.18+). The error type structure and compilation API differ. The implementation must pick and pin a version; the validation error `kind` field structure varies significantly between versions.

3. **JSON Pointer to display path mapping**: `jsonschema` reports paths as JSON Pointers (`/routes/0/destination`). The spec acceptance criteria reference `"routes[0].destination"`. A path conversion function is needed; the exact format should be confirmed before implementation.

4. **Multiple error collection from `jsonschema`**: The spec requires collecting all errors (not just the first). The `jsonschema` crate's `validate()` returns an iterator of errors, which is suitable, but early-exit patterns must be avoided.

5. **`additionalProperties: false` and field extraction**: The `State.fields` `IndexMap` only contains fields the user/system set. There are no "extra" provenance or metadata fields in the JSON object that gets validated — only the extracted `value` portion of each `FieldValue`. This is correct, but the implementation must ensure the validated JSON object contains only field values, not `FieldValue` wrappers.

6. **Unknown entity type error representation**: The spec requires `validate()` on an unknown entity type to return `ValidationErrors` with an error about the unknown type. The `ValidationErrorKind` enum must include a variant for this (e.g., `UnknownEntityType`), which is not explicitly listed in the spec's `ValidationErrorKind` variants but is implied by the acceptance criteria.

7. **Route sub-object field path in errors**: For `routes[0].destination` errors, the `jsonschema` crate will report these relative to the root object. The path translation must handle both top-level fields and nested array-of-object fields.

8. **Schema embedding with `include_str!`**: The path used in `include_str!("schemas/ethernet.json")` is relative to the source file, which is `src/schema.rs`. The schema file must therefore be at `src/schemas/ethernet.json`. This is consistent with the spec but must be verified during implementation since `include_str!` resolves at compile time relative to the file, not the crate root.
