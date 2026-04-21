# Plan: SPEC-002 Entity State Types

## Approach

The five core types (`State`, `FieldValue`, `Value`, `Provenance`, `StateMetadata`) and the `Selector` type are **already fully implemented** in `crates/netfyr-state/src/lib.rs`. Multiple downstream crates (`netfyr-backend`, `netfyr-reconcile`, `netfyr-daemon`, `netfyr-varlink`, `netfyr-cli`) already consume these types in production code. Integration tests for `State` construction, serde round-trip, and field insertion order already exist in `crates/netfyr-state/tests/entity_state_types.rs`.

This plan addresses **one real gap**: the `Value` enum currently uses dual-stack `std::net::IpAddr` and `ipnetwork::IpNetwork`, but the spec requires IPv4-only types (`std::net::Ipv4Addr` and `ipnetwork::Ipv4Network`). This is a cross-crate breaking change that affects `Value` construction, accessors, `From` impls, and all downstream code that pattern-matches on `Value::IpAddr` or `Value::IpNetwork`.

The file layout gap (spec asks for `entity.rs`, `field.rs`, `value.rs`, `provenance.rs`, `metadata.rs` as separate files) will **not** be addressed. All types currently live in `lib.rs` alongside `MacAddr`, `MacAddrParseError`, `Selector`, and `EntityType`. The file is ~1300 lines with clear section headers — small enough that splitting would add indirection without benefit. More importantly, `Selector` is already the complete SPEC-003 implementation (with `driver`, `pci_path`, `mac`, `labels` fields used by downstream crates) — the spec's suggestion of a "placeholder with `name: Option<String>`" is outdated. Splitting would require deciding where `MacAddr`, `Selector`, and `EntityType` live, creating coupling risk with no behavioral gain.

## Design Decisions

1. **Decision**: Change `Value::IpAddr` inner type from `std::net::IpAddr` to `std::net::Ipv4Addr`, and `Value::IpNetwork` inner type from `ipnetwork::IpNetwork` to `ipnetwork::Ipv4Network`.
   - **Alternatives considered**: (a) Keep dual-stack types and add a lint/doc comment saying "only IPv4 used for now". (b) Remove IP variants entirely and use strings.
   - **Rationale**: The spec is explicit: "IPv4 only; IPv6 is not supported in this version." Using `Ipv4Addr`/`Ipv4Network` makes this constraint type-level, preventing accidental IPv6 usage. This is a compile-time guarantee rather than a runtime convention. The downstream crate `netfyr-backend/src/netlink/ethernet.rs` uses `std::net::IpAddr` directly (not through `Value`) for its `route_address_to_ip` function — that code is independent and does not need to change.

2. **Decision**: Do NOT split types into separate files. Keep all types in `lib.rs`.
   - **Alternatives considered**: Follow spec's file layout (`entity.rs`, `field.rs`, `value.rs`, `provenance.rs`, `metadata.rs`).
   - **Rationale**: The types are already correctly implemented and tested in `lib.rs`. Splitting is purely structural with zero behavioral effect. The `lib.rs` file is well-organized (~1300 lines) with clear section delimiters. Splitting would require moving `MacAddr`, `MacAddrParseError`, `Selector`, `EntityType` to appropriate files and adding re-exports — all risk with no value. The spec's file layout assumes an empty crate, which is no longer the case.

3. **Decision**: Do NOT regress `Selector` to a placeholder.
   - **Alternatives considered**: Replace current full `Selector` with a placeholder `{ name: Option<String> }` per spec.
   - **Rationale**: The current `Selector` is the complete SPEC-003 implementation with `name`, `entity_type`, `driver`, `pci_path`, `mac`, `labels`. Downstream crates (`netfyr-backend`, `netfyr-varlink`) already use the full field set. Regressing would break the build. The spec's "placeholder" guidance was written before the current implementation existed.

4. **Decision**: Keep `From<IpAddr>` as a convenience alongside `From<Ipv4Addr>` — actually no, remove the `From<IpAddr>` impl entirely. Only `From<Ipv4Addr>` and `From<Ipv4Network>` should exist.
   - **Alternatives considered**: Keep both `From<IpAddr>` and `From<Ipv4Addr>`.
   - **Rationale**: Keeping `From<IpAddr>` would require converting `IpAddr::V4(addr)` to `Ipv4Addr` internally, and would need to handle/panic on `IpAddr::V6`. This defeats the purpose of the IPv4-only constraint. Clean API means only `From<Ipv4Addr>`.

5. **Decision**: The serde round-trip bug for `Value::IpAddr` (documented in `test_value_ip_addr_serde_bug`) persists after this change.
   - **Alternatives considered**: Fix the bug by implementing a custom deserializer for `Value`.
   - **Rationale**: The bug exists because `#[serde(untagged)]` tries `Ipv4Network` before `Ipv4Addr`, and `Ipv4Network` accepts bare IPs as /32. The YAML parser (`yaml.rs`) already works around this with a `contains('/')` check. The JSON serde path still has the bug. Fixing it requires a custom `Deserialize` impl for `Value`, which is out of scope for this story. The existing test documents the behavior. Note: the yaml.rs custom parsing path is the primary consumer and is already correct.

6. **Decision**: `netfyr-backend/src/netlink/ethernet.rs` keeps its own `std::net::IpAddr` usage unchanged.
   - **Alternatives considered**: Change `route_address_to_ip` to return `Ipv4Addr` and drop IPv6 route handling.
   - **Rationale**: This function converts `RouteAddress` variants from netlink into `IpAddr`. It handles both `Inet(Ipv4Addr)` and `Inet6(Ipv6Addr)`. This is internal to the netlink layer and does NOT flow through `Value::IpAddr`. The function's callers convert to strings before storing in `Value::String`. Changing this would break route handling for no benefit to the `Value` type change.

## File Changes

### 1. `crates/netfyr-state/src/lib.rs`
- **Action**: Modify
- **What**:
  - Change import `use ipnetwork::IpNetwork;` → `use ipnetwork::Ipv4Network;`
  - Change import `use std::net::IpAddr;` → `use std::net::Ipv4Addr;`
  - Change `Value::IpNetwork(IpNetwork)` → `Value::IpNetwork(Ipv4Network)` in enum definition
  - Change `Value::IpAddr(IpAddr)` → `Value::IpAddr(Ipv4Addr)` in enum definition
  - Change `impl From<IpAddr> for Value` → `impl From<Ipv4Addr> for Value`, updating body accordingly
  - Change `impl From<IpNetwork> for Value` → `impl From<Ipv4Network> for Value`, updating body accordingly
  - Change `as_ip_addr(&self) -> Option<&IpAddr>` → `as_ip_addr(&self) -> Option<&Ipv4Addr>`
  - Change `as_ip_network(&self) -> Option<&IpNetwork>` → `as_ip_network(&self) -> Option<&Ipv4Network>`
  - Update re-exports: the existing `pub use` for `Value` covers the type itself; no change to re-exports needed since the inner types are standard library / ipnetwork types, not re-exported
  - Update all `#[cfg(test)]` tests:
    - Remove `use std::net::{IpAddr, Ipv4Addr};` → `use std::net::Ipv4Addr;`
    - Change `IpAddr::V4(Ipv4Addr::new(x,y,z,w))` → `Ipv4Addr::new(x,y,z,w)` everywhere
    - Change `IpNetwork` → `Ipv4Network` in test assertions and construction
    - Change `"10.0.1.0/24".parse::<IpNetwork>()` → `"10.0.1.0/24".parse::<Ipv4Network>()`
    - Change `"10.0.0.0/8".parse::<IpNetwork>()` → `"10.0.0.0/8".parse::<Ipv4Network>()`
- **Why**: Core of the IPv4-only requirement. All other file changes cascade from this.

### 2. `crates/netfyr-state/src/yaml.rs`
- **Action**: Modify
- **What**:
  - Change import `use ipnetwork::IpNetwork;` → `use ipnetwork::Ipv4Network;`
  - Change import `use std::net::IpAddr;` → `use std::net::Ipv4Addr;`
  - In `deserialize_value`: change `IpNetwork::from_str(s)` → `Ipv4Network::from_str(s)` (line ~111)
  - In `deserialize_value`: change `IpAddr::from_str(s)` → `Ipv4Addr::from_str(s)` (line ~115)
  - In `serialize_value`: the `Value::IpAddr(ip)` and `Value::IpNetwork(net)` match arms call `.to_string()` — no change to logic, but the bound variable types change from `&IpAddr`/`&IpNetwork` to `&Ipv4Addr`/`&Ipv4Network`. Pattern matching still works as-is.
  - Update all tests in this file:
    - Change `IpAddr`/`IpNetwork` imports to `Ipv4Addr`/`Ipv4Network`
    - Change `IpAddr::V4(Ipv4Addr::new(...))` to `Ipv4Addr::new(...)`
    - Change `.parse::<IpNetwork>()` to `.parse::<Ipv4Network>()`
  - **Behavioral change**: IPv6 address strings (e.g., `"::1"`) and IPv6 CIDR strings (e.g., `"::1/128"`) will no longer deserialize as `Value::IpAddr`/`Value::IpNetwork`. They will fall through to `Value::String`. This is correct per spec: "IPv6 is not supported in this version."
- **Why**: The YAML parser is the primary path for constructing `Value::IpAddr` and `Value::IpNetwork` from user input. Must match the new types.

### 3. `crates/netfyr-state/src/schema.rs`
- **Action**: Modify (minimal)
- **What**:
  - In `value_to_json` function (~line 337-338): the `Value::IpAddr(ip)` and `Value::IpNetwork(net)` match arms call `ip.to_string()` and `net.to_string()`. Both `Ipv4Addr` and `Ipv4Network` implement `Display`, so the code compiles unchanged. **No modification required** — the match patterns are generic over the inner type.
  - However: verify this compiles. If the compiler requires explicit type annotation, no code change is needed since pattern variables are inferred.
- **Why**: This file only uses `Value::IpAddr`/`Value::IpNetwork` in pattern matches that call `.to_string()`. The inner type change is transparent.

### 4. `crates/netfyr-backend/src/netlink/apply.rs`
- **Action**: Modify (minimal)
- **What**:
  - In `value_to_str` function (~line 1100-1107): the `Value::IpNetwork(net)` and `Value::IpAddr(ip)` match arms call `.to_string()`. Same as schema.rs — the inner type change is transparent. **No modification required.**
  - The `extract_route_fields` function uses `std::net::IpAddr` directly (not through `Value`), so no change needed.
  - The `parse_cidr` function uses `std::net::IpAddr` directly, so no change needed.
- **Why**: This file only uses `Value::IpAddr`/`Value::IpNetwork` in pattern matches that call `.to_string()`. The inner type change is transparent.

### 5. `crates/netfyr-state/tests/entity_state_types.rs`
- **Action**: Modify
- **What**:
  - Change `use std::net::{IpAddr, Ipv4Addr};` (if present in any test) — actually this file doesn't import IpAddr/Ipv4Addr directly. It uses `ipnetwork::IpNetwork`.
  - Change `ipnetwork::IpNetwork` to `ipnetwork::Ipv4Network` on line 114.
  - The `test_value_ip_addr_serde_bug` test (lines 341-368) uses `std::net::{IpAddr, Ipv4Addr}`:
    - Change `IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))` → `Ipv4Addr::new(10, 0, 1, 1)` (just `use std::net::Ipv4Addr;`)
    - Change `Value::IpAddr(ip)` construction to use `Ipv4Addr` directly
    - Change `"10.0.1.1/32".parse().unwrap()` to parse as `Ipv4Network` — the bug assertion value
  - The `test_state_serde_round_trip` test uses `ipnetwork::IpNetwork` — change to `Ipv4Network`.
- **Why**: Integration tests must use the new IPv4-only types.

### 6. `crates/netfyr-varlink/src/types.rs`
- **Action**: No modification needed
- **What**: The `value_to_json` and `json_to_value` functions use `serde_json::to_value`/`serde_json::from_value`, which delegate to `Value`'s derived `Serialize`/`Deserialize`. No direct pattern matching on IP variants. Comment on line 482 mentions "IpNetwork, IpAddr" — optionally update this comment to say "Ipv4Network, Ipv4Addr" for accuracy.
- **Why**: Wire serialization is handled entirely through serde derive; inner type changes are transparent.

### 7. `crates/netfyr-backend/src/netlink/ethernet.rs`
- **Action**: No modification needed
- **What**: Uses `std::net::IpAddr` directly for netlink route handling (`route_address_to_ip` function). This is independent of `Value::IpAddr`. The function handles both IPv4 and IPv6 routes from the kernel — this is correct behavior for the netlink query layer even when the `Value` type only supports IPv4.
- **Why**: Netlink queries must handle whatever the kernel reports. IPv6 routes are simply not stored as `Value::IpAddr`; they'd be stored as `Value::String` or filtered out upstream.

## Dependencies

No new dependencies needed. All required crates are already in `Cargo.toml`:
- `serde = { version = "1", features = ["derive"] }` — already present
- `serde_json = "1"` — already present
- `chrono = { version = "0.4", features = ["serde"] }` — already present
- `uuid = { version = "1", features = ["v7", "serde"] }` — already present
- `ipnetwork = { version = "0.20", features = ["serde"] }` — already present (provides both `IpNetwork` and `Ipv4Network`)
- `indexmap = { version = "2", features = ["serde"] }` — already present

## Implementation Order

1. **Modify `crates/netfyr-state/src/lib.rs`** — Change the `Value` enum definition, `From` impls, accessors, and imports from dual-stack to IPv4-only. Update all unit tests in the `#[cfg(test)]` module. After this step, `netfyr-state` itself compiles and its unit tests pass, but downstream crates may fail to compile if they construct `Value::IpAddr(IpAddr::V4(...))`.

2. **Modify `crates/netfyr-state/src/yaml.rs`** — Update the `deserialize_value` and `serialize_value` functions and their tests to use `Ipv4Addr`/`Ipv4Network`. Depends on step 1 (the Value enum must already have the new inner types).

3. **Modify `crates/netfyr-state/tests/entity_state_types.rs`** — Update integration test imports and assertions. Depends on step 1.

4. **Verify `crates/netfyr-state/src/schema.rs` compiles** — The `value_to_json` function's pattern matches should compile without changes because they only call `.to_string()`. Verify, and if needed, update imports. Depends on step 1.

5. **Verify `crates/netfyr-backend/src/netlink/apply.rs` compiles** — Same pattern-match transparency as schema.rs. Verify. Depends on step 1.

6. **Run full workspace build** — `cargo build --workspace` to catch any remaining compilation errors. Fix any that arise.

7. **Run full test suite** — `cargo test --workspace` to verify all tests pass. The serde round-trip bug test should be updated but should still pass (documenting the same bug, just with `Ipv4Network` instead of `IpNetwork`).

Steps 2, 3, 4, 5 are independent of each other (all depend only on step 1) and can be done in parallel.

## Risks and Mitigations

1. **IPv4-only change breaks downstream construction sites not caught by the exploration**.
   - **Risk**: Some file that wasn't checked may construct `Value::IpAddr(IpAddr::V4(...))` and fail to compile.
   - **Mitigation**: The exploration was thorough, but step 6 (workspace build) will catch any missed sites. The fix for each site is mechanical: replace `IpAddr::V4(Ipv4Addr::new(...))` with `Ipv4Addr::new(...)`.

2. **`Ipv4Network::from_str` behavior differs from `IpNetwork::from_str`**.
   - **Risk**: Edge cases in parsing (e.g., "0.0.0.0/0") might behave differently between `Ipv4Network` and `IpNetwork`.
   - **Mitigation**: `Ipv4Network` is a strict subset of `IpNetwork` for IPv4 addresses. All valid IPv4 CIDR strings parse identically. The only difference is that IPv6 CIDR strings are rejected by `Ipv4Network` (which is the desired behavior).

3. **`Ipv4Addr::from_str` rejects IPv6 addresses where `IpAddr::from_str` accepted them**.
   - **Risk**: If any YAML config file contains IPv6 addresses, they will now deserialize as `Value::String` instead of `Value::IpAddr`.
   - **Mitigation**: This is the correct behavior per spec ("IPv6 is not supported in this version"). Any IPv6 addresses in existing configs will still parse — just as strings. No data loss occurs.

4. **Serde round-trip bug for `Value::IpAddr` persists**.
   - **Risk**: The documented bug where `Value::IpAddr(x)` deserializes as `Value::IpNetwork(x/32)` through JSON still exists with `Ipv4Addr`/`Ipv4Network`. Test `test_value_ip_addr_serde_bug` must be updated but should still demonstrate the same behavior.
   - **Mitigation**: The bug is documented and tested. The YAML parser (`yaml.rs`) already has a correct workaround via the `contains('/')` check. Fix is deferred.

5. **UUIDv7 collision in `StateMetadata` tests**.
   - **Risk**: `Uuid::now_v7()` called twice in rapid succession could theoretically produce the same value.
   - **Mitigation**: UUIDv7 includes a random component alongside the timestamp, making collisions astronomically unlikely. The existing test has been passing reliably. No action needed.

## Test Strategy

### Existing Tests (already passing, will be updated)

**Unit tests in `crates/netfyr-state/src/lib.rs` (module `tests`):**
- All `Value` construction, `From`, accessor, and `Display` tests — update IP-related tests to use `Ipv4Addr`/`Ipv4Network`
- `Provenance`, `FieldValue`, `StateMetadata` tests — no changes needed
- `MacAddr` and `Selector` tests — no changes needed

**Integration tests in `crates/netfyr-state/tests/entity_state_types.rs`:**
- `test_state_all_fields_populated_clone_partialeq` — no change
- `test_state_serde_round_trip` — update `IpNetwork` to `Ipv4Network`
- `test_state_fields_preserve_insertion_order` — no change
- `test_value_ip_addr_serde_bug` — update to use `Ipv4Addr`/`Ipv4Network`

**YAML tests in `crates/netfyr-state/src/yaml.rs`:**
- IP address and CIDR parsing tests — update expected types from `IpAddr`/`IpNetwork` to `Ipv4Addr`/`Ipv4Network`

### New Tests Needed

None. All acceptance criteria from the spec are already covered by existing tests. The only work is updating existing tests to use the new IPv4-only types.

### Test Infrastructure Needed

No new infrastructure. Existing test helpers (`make_full_state()`) don't use IP types and need no changes.

### Verification Approach

After all changes:
1. `cargo test -p netfyr-state` — all unit and integration tests pass
2. `cargo test --workspace` — no downstream breakage
3. `cargo build --workspace` — clean compilation
