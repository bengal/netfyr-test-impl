# SPEC-006: Entity Schema Validation — Gap Analysis

## Current State

The implementation is substantially complete. All types, methods, and the JSON Schema file exist in the codebase.

### `crates/netfyr-state/src/schema.rs`

All spec-required types are implemented:
- `FieldType` — uses `Integer` (not the spec's `U32`/`U64`; a single variant with a documented rationale)
- `FieldConstraints` — `min`, `max`, `pattern`
- `FieldSchemaInfo` — `field_type`, `required`, `writable`, `constraints`, `description`
- `ValidationErrorKind` — all seven spec variants plus `UnknownEntityType` added to handle the unknown entity type acceptance scenario
- `ValidationError` — `field`, `message`, `kind`
- `ValidationErrors` — collection with `Display` and `std::error::Error` impls
- `EntitySchema` — holds a compiled `jsonschema::Validator`, parsed field metadata, and the raw schema value; exposes `field_info()`
- `SchemaRegistry` — `new()`, `validate()`, `validate_writable()`, `get_schema()`, `entity_types()`, `field_info()`, `Default`
- Private helpers: `fields_to_json()`, `value_to_json()`, `json_pointer_to_field_path()`, `classify_error_kind()`, `parse_field_metadata()`, `parse_field_type()`, `parse_constraints()`
- Unit test suite covering almost all acceptance criteria scenarios (see Gap 3 below)

### `crates/netfyr-state/src/schemas/ethernet.json`

Present with all spec-required fields (`mtu`, `addresses`, `mac`, `carrier`, `speed`, `routes`) plus two extra fields not in the spec table: `operstate` and `dns_servers`. The schema uses `additionalProperties: false`, correct `x-netfyr-writable` annotations, and the route sub-schema with `required: ["destination"]`.

The `addresses` items pattern is `^[0-9a-fA-F:.]+/[0-9]{1,3}$`, which accepts both IPv4 and IPv6 CIDR notation because `:` is in the character class.

### `crates/netfyr-state/src/lib.rs`

Re-exports all schema types via `pub use schema::{EntitySchema, FieldConstraints, FieldSchemaInfo, FieldType, SchemaRegistry, ValidationError, ValidationErrorKind, ValidationErrors}`.

### `crates/netfyr-state/Cargo.toml`

`jsonschema = "0.26"` and `serde_json = "1"` are already present.

---

## Requirements

From the acceptance criteria, these behaviors are required:

1. `SchemaRegistry::new()` loads the embedded ethernet schema; `entity_types()` returns `["ethernet"]`; `get_schema("nonexistent")` returns `None` ✓
2. `validate()` accepts valid ethernet states and rejects: MTU out of range, unknown fields, missing required route fields, and other structural errors; collects all errors ✓
3. `validate()` accepts read-only fields (mac, carrier, speed) without error ✓
4. `validate_writable()` additionally rejects fields where `x-netfyr-writable: false` ✓
5. `validate()` rejects duplicate entries in `addresses` with a `ConstraintViolation` naming the duplicate — **NOT YET IMPLEMENTED**
6. `validate()` rejects IPv6 addresses in `addresses` with an `InvalidFormat` error stating IPv6 is not supported — **NOT YET IMPLEMENTED**
7. `validate()` on an unknown entity type returns `ValidationErrors` with `UnknownEntityType` kind ✓
8. `field_info()` returns correct metadata; `None` for unknown fields or entity types ✓

---

## Gap Analysis

### Gap 1: Custom duplicate-address validation (missing)

**File:** `crates/netfyr-state/src/schema.rs` — `validate()` method

`validate()` delegates all checking to the `jsonschema` crate. The ethernet.json schema has no `"uniqueItems": true` on `addresses`, and even if it did, the jsonschema crate would emit a generic message without identifying the specific duplicate string. The spec requires a `ConstraintViolation` with a message mentioning the exact duplicated CIDR value.

**Required change:** After JSON Schema validation, inspect the `addresses` field value. For each string that appears more than once in the list, append:
```rust
ValidationError {
    field: "addresses".to_string(),
    kind: ValidationErrorKind::ConstraintViolation,
    message: format!("duplicate address \"{}\"", addr),
}
```
Guard against the field being absent or not a `Value::List`.

### Gap 2: Custom IPv6-rejection validation (missing)

**File:** `crates/netfyr-state/src/schema.rs` — `validate()` method

The `addresses` pattern `^[0-9a-fA-F:.]+/[0-9]{1,3}$` includes `:` in the character class, so IPv6 CIDRs like `fe80::1/64` match and pass JSON Schema validation. The spec requires an `InvalidFormat` error explicitly stating that IPv6 is not supported.

**Required change:** After JSON Schema validation, inspect the `addresses` field. For each string item containing `:` (before the `/`), append:
```rust
ValidationError {
    field: "addresses".to_string(),
    kind: ValidationErrorKind::InvalidFormat,
    message: format!("IPv6 address \"{}\" is not supported; use IPv4 CIDR format", addr),
}
```
Guard against the field being absent or not a `Value::List`.

### Gap 3: Missing tests for the two custom validation scenarios

**File:** `crates/netfyr-state/src/schema.rs` — test module

Two acceptance-criteria scenarios have no corresponding tests:

- **"Duplicate addresses are rejected"** — expects `ConstraintViolation` for field `"addresses"` with a message mentioning the duplicated CIDR string
- **"IPv6 addresses are rejected"** — expects `InvalidFormat` for field `"addresses"` with a message mentioning IPv6 not supported

All other scenarios from the spec are already covered by the existing test suite.

### Minor: `addresses` JSON Schema pattern accepts IPv6

**File:** `crates/netfyr-state/src/schemas/ethernet.json`

The addresses item pattern `^[0-9a-fA-F:.]+/[0-9]{1,3}$` is too broad. Since the spec explicitly requires a custom code check for IPv6 (not a JSON Schema pattern rejection), this pattern permissiveness may be intentional — the custom code is the authoritative gate. However, if the pattern were tightened to IPv4 only (e.g., `^(\d{1,3}\.){3}\d{1,3}/\d{1,3}$`), the behavior would be consistent: IPv6 would first fail the pattern (emitting an `InvalidFormat` from JSON Schema) AND the custom check would also catch it. The two paths could produce duplicate errors for the same field, so the implementor must decide whether to tighten the pattern or keep the permissive pattern and rely solely on custom code.

---

## Integration Points

- **`State.fields`** (`IndexMap<String, FieldValue>`) — `validate()` already reads this via `fields_to_json()`. The custom duplicate/IPv6 checks will also read it directly, extracting `FieldValue.value` as a `Value::List`.
- **`Value` enum** — `value_to_json()` handles all variants. Custom validation will additionally need `Value::as_list()` and `Value::as_str()` accessors, both of which already exist.
- **`validate_writable()`** — calls `validate()` internally and then appends read-only errors. Once Gap 1 and Gap 2 are fixed in `validate()`, `validate_writable()` will inherit those checks automatically.
- **No callers in the current codebase** wire `validate()` / `validate_writable()` into the apply or dry-run flow. The spec scopes this story to `netfyr-state` only; CLI integration is not required here.

---

## Risks

1. **Double-error risk for IPv6 addresses**: If the ethernet.json addresses pattern is left permissive, IPv6 strings pass JSON Schema validation but are caught by the custom check. If the pattern is tightened to IPv4 only, an IPv6 input would produce both a JSON Schema `InvalidFormat` (pattern mismatch) AND a custom `InvalidFormat` (IPv6 not supported) for the same field. The implementor must choose: tighten the pattern and suppress the JSON Schema pattern error for addresses, keep the permissive pattern and use only the custom check, or accept both errors appearing (which may confuse users).

2. **Custom check ordering**: The spec says to "run netfyr-specific validation rules beyond what JSON Schema covers." If an `addresses` field fails a type check (e.g., the value is not an array), the JSON Schema will emit a type error. The custom duplicate/IPv6 checks must guard against non-list values to avoid panicking.

3. **Duplicate detection semantics**: The spec says "report a ConstraintViolation for each duplicate." It is ambiguous whether this means one error per unique duplicated value (if `"10.0.0.1/24"` appears three times, one error) or one error per extra occurrence (two errors). The simpler interpretation — one error per unique duplicated value — is the most user-friendly.

4. **`operstate` and `dns_servers` in ethernet.json**: These fields exist in the schema but are not in the spec table. Tests that check `entity_types()` or iterate fields must not assume only the six spec-listed fields are present. The extra fields do not break any acceptance criteria but add surface area.

5. **`FieldType::Integer` vs. spec's `U32`/`U64`**: The spec lists `U32` and `U64` as distinct variants, but the implementation uses a single `Integer`. No downstream consumers exist yet; if future code pattern-matches on `FieldType::U32` or `FieldType::U64`, it will fail at compile time.
