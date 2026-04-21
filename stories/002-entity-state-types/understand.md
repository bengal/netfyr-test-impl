# Understand: SPEC-002 Entity State Types

## Current State

All five types named in the spec (`State`, `FieldValue`, `Value`, `Provenance`, `StateMetadata`) are **already implemented and fully tested** in `crates/netfyr-state/src/lib.rs`. The companion `Selector` type is also present in the same file and is significantly more complete than a placeholder — it already has `name`, `entity_type`, `driver`, `pci_path`, `mac`, and `labels` fields with full `matches()`, `is_specific()`, and `key()` methods.

All required external dependencies (`serde`, `serde_json`, `chrono`, `uuid`, `ipnetwork`, `indexmap`) are present in `crates/netfyr-state/Cargo.toml` with the correct feature flags.

Tests covering `MacAddr`, `Selector`, `Value`, `Provenance`, `FieldValue`, and `StateMetadata` are extensive and in `lib.rs`. **No unit tests exist for `State` itself** (construction, serde round-trip, field order).

The module structure contains only `diff.rs`, `loader.rs`, `schema.rs`, `set.rs`, `yaml.rs`, and `lib.rs`. The `schemas/` subdirectory appears to contain YAML schema definition files, not Rust source.

The codebase is well beyond the empty-stub state described in the previous version of this file. Multiple downstream crates (`netfyr-backend`, `netfyr-reconcile`, `netfyr-daemon`, `netfyr-varlink`, `netfyr-cli`) already use these types in production code.

## Requirements

From the acceptance criteria, the following concrete requirements must be satisfied:

1. **`State` struct** with fields `entity_type: String`, `selector: Selector`, `fields: IndexMap<String, FieldValue>`, `metadata: StateMetadata`, `policy_ref: Option<String>`, `priority: u32`. Must derive `Clone`, `Debug`, `Serialize`, `Deserialize`, `PartialEq`. — *Already satisfied.*

2. **`FieldValue` struct** with `value: Value` and `provenance: Provenance`. Must derive same traits. — *Already satisfied.*

3. **`Value` enum** with variants: `String`, `U64`, `I64`, `Bool`, `IpAddr(Ipv4Addr)`, `IpNetwork(Ipv4Network)`, `List`, `Map`. Must implement `From` for each scalar type, `Display`, and typed accessors. — *Exists but uses `IpAddr`/`IpNetwork` (dual-stack) instead of `Ipv4Addr`/`Ipv4Network` (IPv4-only per spec).*

4. **`Provenance` enum** with variants: `UserConfigured { policy_ref }`, `KernelDefault`, `ExternalTool { tool, detected_at }`, `Derived { reason }`. — *Already satisfied.*

5. **`StateMetadata` struct** with `id`, `timeline_id`, `created_at`, `labels`, `description`. `new()` generates UUIDv7 IDs and sets `created_at = Utc::now()`. — *Already satisfied.*

6. **Missing `State` tests**: Three acceptance criteria are not covered:
   - Construct a fully-populated `State`, clone it, assert `PartialEq`, check non-empty `Debug` output.
   - Serialize a `State` to JSON with `serde_json`, deserialize it back, assert equality.
   - Insert `"mtu"`, `"addresses"`, `"routes"` into `fields`, iterate, assert insertion order is preserved.

7. **File layout**: spec requires separate modules (`entity.rs`, `field.rs`, `value.rs`, `provenance.rs`, `metadata.rs`). Currently all types live in `lib.rs`. — *Not satisfied, but has no behavioral effect.*

## Gap Analysis

Most of this story is already implemented. Three concrete gaps remain:

### Gap 1 — IPv4-only types in `Value` (behavioral, breaking)

The spec requires `Value::IpAddr(Ipv4Addr)` and `Value::IpNetwork(Ipv4Network)`. The current implementation uses `IpAddr` and `IpNetwork` (dual-stack).

| Item | File:Line | Current | Required |
|------|-----------|---------|----------|
| `Value::IpAddr` inner type | `lib.rs:249` | `std::net::IpAddr` | `std::net::Ipv4Addr` |
| `Value::IpNetwork` inner type | `lib.rs:249` | `ipnetwork::IpNetwork` | `ipnetwork::Ipv4Network` |
| `From<IpAddr> for Value` | `lib.rs:321` | `impl From<IpAddr>` | `impl From<Ipv4Addr>` |
| `From<IpNetwork> for Value` | `lib.rs:327` | `impl From<IpNetwork>` | `impl From<Ipv4Network>` |
| `Value::as_ip_addr()` return | `lib.rs:362` | `Option<&IpAddr>` | `Option<&Ipv4Addr>` |
| `Value::as_ip_network()` return | `lib.rs:369` | `Option<&IpNetwork>` | `Option<&Ipv4Network>` |

### Gap 2 — Missing `State` unit tests

In `crates/netfyr-state/src/lib.rs`, the `#[cfg(test)]` module has no tests for the `State` struct. The following tests must be added:
- Fully-populated `State` construction, clone equality, non-empty Debug output.
- `serde_json` serialize → deserialize round-trip equality.
- `IndexMap` field insertion order (`"mtu"` → `"addresses"` → `"routes"`) preserved on iteration.

### Gap 3 — File layout (structural only, no behavioral effect)

The spec designates `entity.rs`, `field.rs`, `value.rs`, `provenance.rs`, `metadata.rs` as separate source files. Currently all five types live in `lib.rs`. This gap has no impact on behavior or downstream consumers (re-exports in `lib.rs` are unchanged). Whether to split is an implementation decision for the Plan phase.

## Integration Points

The IPv4-only change to `Value` (Gap 1) is a **breaking API change** affecting every crate that constructs or pattern-matches on `Value::IpAddr` or `Value::IpNetwork`:

- **`crates/netfyr-state/src/yaml.rs`** — `deserialize_value` and `serialize_value` handle IP addresses and CIDR networks; must switch from `IpAddr`/`IpNetwork` to `Ipv4Addr`/`Ipv4Network`.
- **`crates/netfyr-backend/src/netlink/query.rs`** — Ethernet query functions produce `Value::IpAddr`/`Value::IpNetwork` from netlink data; these pass `IpAddr`/`IpNetwork` values today.
- **`crates/netfyr-backend/src/dhcp/mod.rs`** — `lease_to_state` creates `Value::IpAddr` and `Value::IpNetwork` for DHCP lease addresses.
- **`crates/netfyr-varlink/src/types.rs`** — `value_to_json` and `json_to_value` handle `Value::IpAddr`/`Value::IpNetwork` conversions for wire format.

The file-layout split (Gap 3) is purely internal to `netfyr-state`. Re-exports in `lib.rs` keep the public API identical; no downstream crate changes are required.

The `Selector` type is already beyond the placeholder stage. Downstream crates (`netfyr-backend/query.rs`, `netfyr-varlink/types.rs`) use the full Selector with `driver`, `pci_path`, `mac`, and `labels` fields. This must not be regressed.

## Risks

1. **IPv4-only change scope**: Changing `IpAddr` → `Ipv4Addr` requires auditing and updating all four downstream sites (yaml.rs, netlink/query.rs, dhcp/mod.rs, varlink/types.rs). If any site silently wraps an IPv6 address into `Value::IpAddr` today, that path will fail to compile after the change — which is the correct outcome but must be verified. The current test suite uses `IpAddr::V4(Ipv4Addr::new(...))` which will need to change to bare `Ipv4Addr::new(...)`.

2. **`yaml.rs` deserialization variant ordering**: `Value` uses `#[serde(untagged)]`. Switching to `Ipv4Network` means IPv6 CIDR strings (e.g., `"::1/128"`) will no longer deserialize as `IpNetwork` — they will fall through to `Value::String`. This is correct per spec but is a silent behavioral change in the YAML parser for any existing YAML that contains IPv6 addresses.

3. **`Selector` must not regress**: The spec describes `Selector` as a "placeholder with `name: Option<String>`", but the current implementation is already the full SPEC-003 Selector used by downstream crates. Reducing it to a placeholder would be a regression. The plan phase must recognize this is already complete.

4. **UUIDv7 collision in `StateMetadata` tests**: `Uuid::now_v7()` called twice in rapid succession can theoretically produce the same value within a single nanosecond tick. The uniqueness test may flake under very fast clock resolution. This is extremely low probability but worth noting.

5. **`IndexMap` insertion order in serde round-trip**: `serde_json` preserves JSON object key order when deserializing into `IndexMap` (because `indexmap`'s serde impl uses a sequence-preserving visitor). This is correct but depends on implementation details of both crates. The test must validate actual iteration order, not just equality.
