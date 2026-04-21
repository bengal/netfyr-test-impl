# Gap Analysis: SPEC-353 External Change Detection

## Current State

The implementation of SPEC-353 is **substantially complete**. All primary components described in the spec exist and are wired together.

### `crates/netfyr-daemon/src/netlink_monitor.rs` (complete)
- `enum ChangeKind { LinkChanged, AddressAdded, AddressRemoved }` — all three variants present
- `struct NetlinkChange { ifindex, ifname, kind }` — matches spec
- `struct NetlinkMonitor { change_rx, task }` — matches spec
- `NetlinkMonitor::start()` — subscribes to `RTNLGRP_LINK` (group 1) and `RTNLGRP_IPV4_IFADDR` (group 5) via `netlink-sys::Socket` wrapped in `tokio::io::unix::AsyncFd`
- `NetlinkMonitor::next_change()` / `stop()` — present
- 500 ms sliding-window debounce with per-ifindex coalescing; duplicate `ChangeKind` per window deduplicated
- Raw netlink message parsing for RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR, RTM_DELADDR using fixed-size struct offsets
- ifindex→ifname name cache so address messages resolve interface names from prior link messages
- Full unit test suite: ChangeKind variants, `kind_eq`, `process_buffer` edge cases, RTM_* parsing, name cache propagation, coalescing, and debounce deadline reset

### `crates/netfyr-daemon/src/reconciler.rs` (complete)
- `Reconciler.is_applying: Arc<AtomicBool>` — thread-safe self-change flag
- `set_applying(bool)` / `is_applying()` — both present, use `SeqCst` ordering
- `managed_entity_names(policy_store, factory_manager) -> HashSet<String>` — returns interface names covered by active policies
- `record_external_change(changed_entity_names, policy_store)` — queries backend for current state of each named entity (`"ethernet"` entity type hardcoded), compares to `journal.latest_state_for()`, produces `SerializableFieldChange` entries, appends `JournalEntry { trigger: ExternalChange, outcome: Observed }`
- `compute_external_field_changes(last, current)` — private helper, diffs journal snapshot fields against live state; handles new, changed, and removed fields
- Unit tests: `is_applying` flag lifecycle (defaults false, set/clear, toggle), `managed_entity_names` with zero/one/many policies, `record_external_change` with empty and nonexistent entity lists

### `crates/netfyr-daemon/src/server.rs` (complete)
- `NetlinkMonitor::start()` called in `serve_varlink`; failure is non-fatal (daemon continues without external change detection)
- `managed_entities: HashSet<String>` maintained in the event loop, refreshed after every Varlink connection (in case `SubmitPolicies` was called) and after every DHCP event
- Branch 5 `tokio::select!` arm: guards on `reconciler.is_applying()`, deduplicates changed names (via `HashSet`), filters to `managed_entities`, calls `reconciler.record_external_change()`
- `handle_submit_policies` sets `set_applying(true)` before apply and `set_applying(false)` after — self-change suppression wired
- DHCP event branches (LeaseAcquired, LeaseRenewed, LeaseExpired) also bracket `reconcile_and_apply()` with `set_applying(true/false)`
- `server_trigger_type_str()` returns `"external_change"` for `Trigger::ExternalChange`

### `crates/netfyr-journal/src/entry.rs` (complete)
- `Trigger::ExternalChange { changed_entities: Vec<String> }` — present with `serde(tag = "type", rename_all = "snake_case")` yielding `"type": "external_change"`
- `ApplyOutcome::Observed` — present with `"kind": "observed"` serialization
- Both have full unit tests including serialization round-trips

### `crates/netfyr-journal/src/journal.rs`
- `Journal::latest_state_for(entity_name: &str) -> Result<Option<SerializableState>>` — present, used by `record_external_change`

### `crates/netfyr-cli/src/history.rs` (complete)
- `trigger_display_name(Trigger::ExternalChange { .. })` returns `"external_change"`
- `matches_trigger` handles "external" as a substring match
- Text/JSON formatters handle all trigger variants

### `tests/600-e2e-external-change.sh` (exists)
- Tests MTU change detection (RTM_NEWLINK path)
- Tests address addition detection (two addresses in quick succession — exercises coalescing)
- Tests address removal detection (RTM_DELADDR path)
- Verifies daemon does not re-reconcile (interface retains externally-set values)
- Verifies no new `policy_apply` entries are written during external-change phases

## Requirements

All spec acceptance criteria map to implemented code:

| Criterion | Status |
|---|---|
| Monitor detects MTU change → `external_change` journal entry | Implemented |
| Diff shows mtu: old → new | Implemented via `compute_external_field_changes` |
| Outcome is `observed` | Implemented |
| `changed_entities` includes the interface name | Implemented |
| Monitor detects address addition | Implemented (RTM_NEWADDR → AddressAdded → backend re-query) |
| Monitor detects address removal | Implemented (RTM_DELADDR → AddressRemoved → backend re-query) |
| Self-changes excluded | Implemented via `set_applying` flag on `Reconciler` |
| Burst changes coalesced into one entry | Implemented via 500ms sliding debounce |
| External changes do not trigger re-reconciliation | Implemented (only `record_external_change`, not `reconcile_and_apply`) |
| Unmanaged interfaces ignored | Implemented via `managed_entities.contains(name)` filter in `server.rs` |

## Gap Analysis

**No code creation or modification is required** to satisfy the spec's acceptance criteria. The implementation is complete.

**One coverage gap** remains: the spec's acceptance criterion "Monitor ignores unmanaged interfaces" has no e2e test. The underlying logic is tested at the unit level (via `managed_entity_names` and `record_external_change` tests in `reconciler.rs`) but the full end-to-end path — where a netlink event for an unmanaged interface arrives and produces no journal entry — is not covered by `tests/600-e2e-external-change.sh`. Adding this phase to the e2e test is the only item not yet implemented.

## Integration Points

All integration points are already active in the current implementation:

- `Journal::latest_state_for(&str)` — called in `record_external_change` to get the previous snapshot per entity; used to detect actual field-level drift
- `BackendRegistry::query(&EntityType, Option<&Selector>)` — called in `record_external_change` with `entity_type = "ethernet"` and `Selector::with_name(entity_name)` to get current live state
- `Journal::append(JournalEntry)` — called inside `record_external_change` through the `Mutex<Option<Journal>>` lock; seq is assigned by `append`
- `SerializableDiff`, `SerializableDiffOp`, `SerializableFieldChange`, `SerializableStateSet`, `SerializableState` — all constructed in `record_external_change`
- `summarize_policies(policy_store.policies())` — used in the external change entry's `active_policies` field
- `NetlinkMonitor` is created once in `serve_varlink` and its `next_change()` is polled in Branch 5 of the `tokio::select!` loop alongside the existing branches for Varlink connections, factory events, and signals

## Risks

**Race condition in self-change suppression**: `set_applying(false)` is called synchronously after `backend_registry.apply()` returns, but netlink notifications arrive asynchronously from the kernel. If the OS delivers notifications more than 500 ms after `set_applying(false)` (i.e., after the debounce window fires), those notifications will appear as external changes even though they were caused by netfyr. This is inherent to a flag-based approach and acknowledged in the spec.

**Entity type hardcoded to `"ethernet"`**: `record_external_change` issues backend queries only for `entity_type = "ethernet"`. Changes to future entity types (bonds, bridges, VLANs) would not be detected without modifying this function.

**`latest_state_for` skips entities with no prior journal entry**: On a freshly-started daemon, or immediately after journal rotation, the function returns `None` for entities not yet in `current.ndjson`. The first external change on such an entity goes undetected. This is intentional per the spec ("entities in the current state but not in the journal are ignored") but creates a blind spot in the startup window.

**Address field representation**: Address addition/removal detection depends on the ethernet backend representing IP addresses as a serialized field in `StateSet`. If the address list is not captured as a distinct field in the snapshot, `compute_external_field_changes` would produce an empty list and no journal entry would be written even after an address change.

**Missing e2e coverage for unmanaged interface scenario**: The `"Monitor ignores unmanaged interfaces"` acceptance criterion is not validated end-to-end, only at unit-test level.
