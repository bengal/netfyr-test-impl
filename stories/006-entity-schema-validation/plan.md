# Plan: SPEC-006 — Entity Schema Validation

## Approach

The implementation is nearly complete. All types (`SchemaRegistry`, `EntitySchema`, `FieldSchemaInfo`, `ValidationError`, `ValidationErrors`, `FieldType`, `FieldConstraints`, `ValidationErrorKind`), the JSON Schema file (`ethernet.json`), the core validation flow (`validate`, `validate_writable`), the lib.rs re-exports, and the Cargo.toml dependency on `jsonschema = "0.26"` are already in place and correct. Two spec-required custom validation rules are missing from the `validate()` method:

1. **Duplicate address detection** in the `addresses` array field — spec requires a `ConstraintViolation` error naming the specific duplicated CIDR string.
2. **IPv6 rejection** for entries in the `addresses` array field — spec requires an `InvalidFormat` error stating that IPv6 is not supported.

The design adds a post-JSON-Schema validation pass inside `SchemaRegistry::validate()` that inspects the `addresses` field directly from `State.fields` using the existing `Value::as_list()` and `Value::as_str()` accessors. This keeps all validation logic in one method, and `validate_writable()` inherits both checks automatically since it delegates to `validate()` internally. Custom checks run *after* JSON Schema validation and append to the same error vector, so users see all errors (structural + custom) in a single report.

The alternative of encoding these rules in JSON Schema was rejected. JSON Schema's `uniqueItems` produces generic messages without naming the duplicate. Tightening the `addresses` item pattern to IPv4-only would cause double errors for IPv6 inputs (one from JSON Schema pattern mismatch + one from the custom check). The current permissive pattern (`^[0-9a-fA-F:.]+/[0-9]{1,3}$`) lets IPv6 strings pass JSON Schema so that only the custom check produces a single, clear "IPv6 not supported" message.

## Design Decisions

1. **Decision**: Keep the permissive `addresses` item pattern in `ethernet.json` unchanged; reject IPv6 only via custom code in `validate()`.
   - **Alternatives considered**: (a) Tighten the pattern to IPv4-only and also add the custom check. (b) Rely solely on a tighter pattern without custom code.
   - **Rationale**: Option (a) produces two errors for the same IPv6 input — a pattern-mismatch `InvalidFormat` from JSON Schema and an "IPv6 not supported" `InvalidFormat` from the custom check — confusing users. Option (b) gives a generic "pattern mismatch" message instead of the spec-required "IPv6 is not supported" message. The current permissive pattern lets IPv6 strings pass JSON Schema, and the custom check provides the single, clear error the spec requires.

2. **Decision**: Run custom validation checks only when the `addresses` field is present and is a `Value::List`. If the field is absent, skip (it's optional). If it has the wrong type, JSON Schema already emitted a type error; skip custom checks to avoid cascading errors.
   - **Alternatives considered**: Run custom checks unconditionally with defensive type-matching.
   - **Rationale**: If `addresses` is not an array, JSON Schema already emitted an `InvalidType` error. Adding duplicate/IPv6 checks on a non-list value would either panic or produce confusing secondary errors.

3. **Decision**: Emit one `ConstraintViolation` error per unique duplicated address string. If `"10.0.0.1/24"` appears three times, emit one error for that string.
   - **Alternatives considered**: One error per extra occurrence (two errors for three occurrences of the same address).
   - **Rationale**: The spec says "report a ConstraintViolation for each duplicate" which is ambiguous. One-per-unique-value is more user-friendly and matches common validator behavior.

4. **Decision**: Detect IPv6 by checking if the address string (the part before `/`, or the whole string if no `/`) contains `:`.
   - **Alternatives considered**: Parse with `std::net::IpAddr`, use a regex.
   - **Rationale**: IPv4 addresses never contain colons; all IPv6 addresses do. The `addresses` field is string-typed at this point (MAC addresses are in a separate field), so there's no false-positive risk. The `:` check is trivial and avoids unnecessary parsing overhead.

5. **Decision**: Place custom validation logic in a private helper function `run_custom_checks(state: &State) -> Vec<ValidationError>` that dispatches to `check_ethernet_addresses(state: &State) -> Vec<ValidationError>`.
   - **Alternatives considered**: Inline the logic directly in `validate()`.
   - **Rationale**: A dispatch helper keeps `validate()` readable and provides a clean extension point for future entity types without modifying the main validation method.

6. **Decision**: Do not modify `ethernet.json`.
   - **Alternatives considered**: Add `"uniqueItems": true` to `addresses`.
   - **Rationale**: The `jsonschema` crate's `uniqueItems` produces generic messages without identifying the specific duplicate. The spec requires the message to mention the duplicated CIDR string. Custom code is the only way.

## File Changes

### 1. `crates/netfyr-state/src/schema.rs` — modify

**What changes:**

- **Add `use std::collections::HashSet;`** to the existing import block at the top of the file (line 10 area, alongside `HashMap`).

- **New private function `run_custom_checks`**: Signature: `fn run_custom_checks(state: &State) -> Vec<ValidationError>`. Matches on `state.entity_type.as_str()`: for `"ethernet"`, delegates to `check_ethernet_addresses(state)`. For all other entity types, returns an empty `Vec`. This function is only called for known entity types (the unknown-entity-type early return in `validate()` happens before this call).

- **New private function `check_ethernet_addresses`**: Signature: `fn check_ethernet_addresses(state: &State) -> Vec<ValidationError>`. Implements:
  1. Extract the `addresses` field from `state.fields`. If absent or not `Value::List`, return empty vec.
  2. Collect all string items from the list using `Value::as_str()` (skip non-string items — JSON Schema already reported type errors for those).
  3. **Duplicate detection**: Use a `HashSet<&str>` to track seen addresses and a second `HashSet<&str>` for already-reported duplicates. For each address string: if already in `seen`, and not yet in `reported`, push a `ValidationError { field: "addresses".into(), kind: ConstraintViolation, message: format!("duplicate address \"{}\"", addr) }` and add to `reported`. Otherwise add to `seen`.
  4. **IPv6 rejection**: For each address string, split on `'/'` and check if the prefix part contains `':'`. If so, push a `ValidationError { field: "addresses".into(), kind: InvalidFormat, message: format!("IPv6 address \"{}\" is not supported; use IPv4 CIDR format", addr) }`.
  5. Return the collected errors.

  Both functions should be placed after the existing private helpers (after `parse_constraints`, before the `#[cfg(test)]` module), maintaining the existing code organization.

- **Modify `validate()` method** (lines 199-248): Change the `errors` binding on line 220 from `let errors: Vec<ValidationError>` to `let mut errors: Vec<ValidationError>`. After the `.collect()` on line 241, add: `errors.extend(run_custom_checks(state));`. The rest of the method (the empty check and return) remains unchanged.

**Why**: Closes Gap 1 (duplicate addresses) and Gap 2 (IPv6 rejection) from the understanding analysis. These are the only two acceptance criteria not yet satisfied.

### 2. `crates/netfyr-state/src/schemas/ethernet.json` — no change

No modifications. The permissive `addresses` pattern is intentional (see Design Decision 1).

### 3. `crates/netfyr-state/src/lib.rs` — no change

All schema types are already re-exported. No new public types are being added.

### 4. `crates/netfyr-state/Cargo.toml` — no change

`jsonschema = "0.26"` and `serde_json = "1"` are already present.

## Dependencies

No new crate dependencies are needed. The implementation uses only:
- `std::collections::HashSet` (standard library) — for tracking seen/reported addresses during duplicate detection.
- Existing `Value::as_list()` and `Value::as_str()` accessors already defined on the `Value` enum in `lib.rs`.
- Existing `state.fields` `IndexMap<String, FieldValue>` access pattern already used by `fields_to_json()`.

## Implementation Order

1. **Add `HashSet` import and the two private helper functions** (`run_custom_checks` and `check_ethernet_addresses`) in `schema.rs`, placed after the existing private helpers and before the `#[cfg(test)]` module. At this point the functions are dead code — the project compiles but they are unused.

2. **Modify `validate()` to call `run_custom_checks`**: Change `let errors` to `let mut errors` and add `errors.extend(run_custom_checks(state))` after the JSON Schema error collection. After this step, all acceptance criteria are satisfied at the code level.

3. **Add unit tests** for the two new scenarios in the existing `#[cfg(test)] mod tests` block. These verify the acceptance criteria end-to-end. (Described in Test Strategy below.)

Each step results in a compilable state. Steps 1 and 2 are the functional changes; step 3 is verification.

## Risks and Mitigations

1. **Risk: `Value::List` items might not be `Value::String`**.
   - If an address list item is a non-string value (e.g., `Value::U64(42)`), JSON Schema catches it as an `InvalidType` error. The custom check uses `Value::as_str()`, which returns `None` for non-strings — those items are silently skipped.
   - **Mitigation**: Guard each item with `if let Some(addr_str) = item.as_str()`.

2. **Risk: `FieldValue` wrapper around `Value`**.
   - `state.fields` is `IndexMap<String, FieldValue>`, not `IndexMap<String, Value>`. The custom check must access `fv.value` to get the `Value`.
   - **Mitigation**: Access as `state.fields.get("addresses").map(|fv| &fv.value)`, following the pattern already used by `fields_to_json`.

3. **Risk: An address string with no `/` delimiter**.
   - If someone provides `"10.0.0.1"` (no CIDR prefix), `split_once('/')` returns `None`. The IPv6 check should still work by examining the entire string.
   - **Mitigation**: Use `addr.split_once('/').map_or(addr, |(prefix, _)| prefix).contains(':')` to handle both cases.

4. **Risk: Interaction between JSON Schema errors and custom errors for the same field**.
   - If `addresses` has an item that fails the JSON Schema pattern AND is IPv6, the user could see two errors. However, because the addresses pattern is permissive (accepts `:`), IPv6 strings actually *pass* the pattern check. Only the custom "IPv6 not supported" error appears. This is the intended behavior.
   - **Mitigation**: No action needed — the permissive pattern prevents double errors.

5. **Risk: `operstate` and `dns_servers` fields in ethernet.json are not in the spec table**.
   - These extra fields are already present and do not affect any acceptance criteria. They should not be removed as they may be used by other parts of the system.
   - **Mitigation**: Do not modify `ethernet.json`. Tests should not assume only the six spec-listed fields exist.

## Test Strategy

**Unit tests** in `crates/netfyr-state/src/schema.rs` (inside the existing `mod tests` block). All tests use the existing `make_state` helper function. No new test infrastructure is needed.

Tests to add for the two missing acceptance-criteria scenarios:

1. **Duplicate addresses are rejected**: Create a state with `addresses: ["10.0.1.50/24", "10.0.1.50/24"]`. Call `validate()`. Assert `Err`. Assert errors contain an error with `field == "addresses"`, `kind == ConstraintViolation`, and `message` containing the string `"10.0.1.50/24"`.

2. **IPv6 addresses are rejected**: Create a state with `addresses: ["fe80::1/64"]`. Call `validate()`. Assert `Err`. Assert errors contain an error with `field == "addresses"`, `kind == InvalidFormat`, and `message` containing "IPv6" and "not supported".

3. **Non-duplicate IPv4 addresses pass**: Create a state with `addresses: ["10.0.1.50/24", "10.0.1.51/24"]`. Call `validate()`. Assert `Ok`.

4. **Mixed custom and JSON Schema errors collected together**: Create a state with `mtu: 99999` (out of range) and `addresses: ["10.0.1.50/24", "10.0.1.50/24"]` (duplicate). Call `validate()`. Assert errors contain both an `OutOfRange` for `mtu` and a `ConstraintViolation` for `addresses`.

5. **Empty addresses list passes**: Create a state with `addresses: []`. Call `validate()`. Assert `Ok`.

6. **IPv6 in `validate_writable()` also caught**: Create a state with `addresses: ["fe80::1/64"]`. Call `validate_writable()`. Assert errors include `InvalidFormat` for `addresses` (inherited from `validate()`).

7. **Triple duplicate emits one error**: Create a state with `addresses: ["10.0.0.1/24", "10.0.0.1/24", "10.0.0.1/24"]`. Call `validate()`. Assert exactly one `ConstraintViolation` error for `addresses` (not two).

8. **Duplicate and IPv6 combined**: Create a state with `addresses: ["fe80::1/64", "fe80::1/64"]`. Call `validate()`. Assert errors include both a `ConstraintViolation` (duplicate) and an `InvalidFormat` (IPv6) for `addresses`.
