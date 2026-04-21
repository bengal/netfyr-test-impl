# Gap Analysis: SPEC-353 External Change Detection

## Current State

### Journal infrastructure (complete)
`netfyr-journal/src/entry.rs` already contains:
- `Trigger::ExternalChange { changed_entities: Vec<String> }` — serializes as `"type": "external_change"`
- `ApplyOutcome::Observed` — serializes as `"kind": "observed"`
- Both variants have full unit-test coverage (serialization round-trips, discriminator values)

`netfyr-journal/src/journal.rs` already contains:
- `Journal::latest_state_for(entity_name: &str) -> Result<Option<SerializableState>>` — scans `current.ndjson` newest-first for the most recent state snapshot of the named entity

### CLI display (complete)
`netfyr-cli/src/history.rs` already handles `ExternalChange` in:
- `trigger_display_name()` → returns `"external"`
- `matches_trigger()` → matches filter string `"external"`
- `format_text_detail()` → shows `changed_entities` list and diff

### Daemon server (partial)
`netfyr-daemon/src/server.rs`:
- `server_trigger_type_str()` already has an arm for `Trigger::ExternalChange { .. }` → `"external_change"`
- `serve_varlink()` has a 4-branch `tokio::select!` loop (connection accept, factory events, SIGTERM, SIGINT)
- **No netlink monitor branch exists**

### Reconciler (missing applying flag)
`netfyr-daemon/src/reconciler.rs`:
- `Reconciler` holds `BackendRegistry`, `SchemaRegistry`, and `Mutex<Option<Journal>>`
- Has `reconcile_and_apply()`, `dry_run()`, `query()`, and a private `append_journal_entry()`
- **No `is_applying` / `set_applying` flag exists**
- The journal is private to `Reconciler`; external change entries cannot be written from outside without a new method

### Dependencies
- `netlink-sys` v0.8.8 is in `Cargo.lock` as a transitive dependency via `rtnetlink` (used in `netfyr-backend`)
- `netfyr-daemon/Cargo.toml` does **not** list `netlink-sys` as a direct dependency; it would need to be added for `netlink_sys::Socket`
- `rtnetlink` and `netlink-packet-route` appear only in `[dev-dependencies]` of `netfyr-daemon`

---

## Requirements

1. **`NetlinkMonitor` struct** — opens a raw netlink socket subscribed to `RTNLGRP_LINK` (group 1) and `RTNLGRP_IPV4_IFADDR` (group 5); runs a background tokio task; debounces notifications into 500ms windows; emits `Vec<NetlinkChange>` per window.

2. **`NetlinkChange` / `ChangeKind`** — typed structs representing a single netlink notification: interface index, optional name, and kind (`LinkChanged`, `AddressAdded`, `AddressRemoved`).

3. **Self-change exclusion flag** — `AtomicBool` on `Reconciler` exposing `set_applying(bool)` and `is_applying() -> bool`; the event loop sets it around `reconcile_and_apply()` calls; the monitor branch discards notifications while it is set.

4. **External change journal write** — a new `Reconciler` method (or the event loop itself, if the journal is made accessible) that:
   - Queries the current state of the changed interface via the backend registry
   - Looks up the last known state via `journal.latest_state_for()`
   - Computes a field-level diff between the two
   - Writes a `JournalEntry` with `Trigger::ExternalChange`, `ApplyOutcome::Observed`, and the computed diff

5. **Managed-entity filter** — only write a journal entry if the changed interface is covered by an active policy (i.e., present in the effective desired state), to satisfy the "monitor ignores unmanaged interfaces" acceptance criterion.

6. **New `tokio::select!` branch** in `serve_varlink()` for `netlink_monitor.next_change()`.

7. **`netlink-sys` direct dependency** — added to `netfyr-daemon/Cargo.toml`.

8. **End-to-end tests** — new scenarios in `crates/netfyr-daemon/tests/` covering: MTU change detection, address addition/removal detection, self-change exclusion, burst coalescing, no re-reconciliation, and unmanaged interface filtering.

---

## Gap Analysis

### New file: `crates/netfyr-daemon/src/netlink_monitor.rs`
Does not exist. Must be created from scratch.

Contents:
- `pub struct NetlinkMonitor` with `change_rx: mpsc::Receiver<Vec<NetlinkChange>>` and `task: JoinHandle<()>`
- `pub struct NetlinkChange { ifindex: u32, ifname: Option<String>, kind: ChangeKind }`
- `pub enum ChangeKind { LinkChanged, AddressAdded, AddressRemoved }`
- `impl NetlinkMonitor { pub async fn start() -> Result<Self>; pub async fn next_change(&mut self) -> Option<Vec<NetlinkChange>>; pub async fn stop(self); }`
- Background task: reads raw `NETLINK_ROUTE` socket messages, classifies them as `RTM_NEWLINK`/`RTM_DELLINK`/`RTM_NEWADDR`/`RTM_DELADDR`, accumulates by ifindex, fires the 500ms debounce timer

### Modify: `crates/netfyr-daemon/src/reconciler.rs`
- Add `is_applying: Arc<AtomicBool>` field to `Reconciler`
- Add `pub fn set_applying(&self, v: bool)` and `pub fn is_applying(&self) -> bool`
- Add a new public method (e.g., `pub fn record_external_change(...)`) that writes a journal entry with `Trigger::ExternalChange` and `ApplyOutcome::Observed`, so the journal's private `Mutex` is accessed from within the reconciler rather than from `serve_varlink`

### Modify: `crates/netfyr-daemon/src/server.rs`
- Add a 5th `tokio::select!` branch: `Some(changes) = netlink_monitor.next_change() => { ... }`
- Branch logic:
  1. Skip if `reconciler.is_applying()`
  2. For each `NetlinkChange` with a known `ifname`, check if the interface is managed (present in policy-derived state)
  3. Query current state via `reconciler.query(Some("ethernet"), Some(&selector))`
  4. Call `reconciler.record_external_change(...)` for any managed interface whose state differs from the last journal snapshot
- Wrap `reconcile_and_apply()` calls with `set_applying(true)` / `set_applying(false)` in all three existing factory-event arms (`LeaseAcquired`, `LeaseRenewed`, `LeaseExpired`) and in `handle_submit_policies()`
- Instantiate `NetlinkMonitor::start().await` before the loop and pass it into the loop (or construct it inside `serve_varlink`)
- `serve_varlink`'s signature may need to accept or internally construct `NetlinkMonitor`

### Modify: `crates/netfyr-daemon/src/main.rs`
- Add `mod netlink_monitor;` declaration

### Modify: `crates/netfyr-daemon/Cargo.toml`
- Add `netlink-sys = "0.8"` to `[dependencies]` for direct use of `Socket`, `SocketAddr`, `protocols::NETLINK_ROUTE`

---

## Integration Points

- **`BackendRegistry::query(entity_type, selector)`** — used to fetch current state of a changed interface. Already accessible via `Reconciler::query()`. The selector must be constructed as `Selector::with_name(ifname)`.
- **`Journal::latest_state_for(entity_name)`** — used to find the last known state. Already implemented. Only searches `current.ndjson`; archives are not scanned.
- **`Journal::append(entry)`** — used to write the `Observed` entry. Already implemented. Access must go through `Reconciler`'s mutex.
- **`JournalEntry`/`SerializableDiff`/`SerializableStateSet`** — already fully defined. The external change diff must be built from `SerializableState` fields by comparing `current` (journal snapshot) to `desired` (actual live state), with `change_kind: "set"`.
- **`summarize_policies(policy_store.policies())`** — already used in `append_journal_entry`; the same call will populate `active_policies` in the external change entry.
- **`FactoryManager::next_event()`** — the existing Branch 2 in `tokio::select!`; the new Branch 5 for netlink events must not interfere with this.

---

## Risks

1. **Blocking socket in async runtime**: `netlink_sys::Socket` is a synchronous, blocking file descriptor. Reading it in the monitor task requires either `tokio::task::spawn_blocking` or wrapping it in `tokio::io::unix::AsyncFd`. The spec does not specify which; the wrong choice can block the tokio thread pool.

2. **Journal access from `serve_varlink`**: The `Journal` is behind a private `Mutex` inside `Reconciler`. The external change write path must go through a new `Reconciler` method, not directly from `serve_varlink`. This requires adding API surface to `Reconciler` that was not present before.

3. **Self-change exclusion timing**: The `AtomicBool` flag is set synchronously around `reconcile_and_apply()`, but the 500ms debounce means notifications generated during a slow apply could arrive after the flag is cleared. Specifically, if `reconcile_and_apply` takes <500ms but the OS delivers netlink messages after it returns, those messages will still be debounced into a window that fires after `is_applying` is `false`. This is inherent to a flag-based approach.

4. **`latest_state_for` only searches `current.ndjson`**: On a freshly-started daemon (or immediately after journal rotation), the method returns `None` for interfaces not yet in the current journal file. These interfaces will not produce external-change entries until a reconcile-and-apply writes them. The spec says "entities in the current state but not in the journal are ignored" — this is intentional but means the first external change after a rotation goes undetected.

5. **Managed-entity check requires effective state computation**: To determine whether a changed interface is "managed", the event loop must know which entities are covered by active policies. This requires either calling `merge(inputs)` (expensive, runs the full policy merge) or maintaining a cached set of managed entity names. The spec does not prescribe how to compute this; naive re-running `build_policy_inputs` + `merge` on every netlink event is functionally correct but inefficient.

6. **`rtnetlink` version compatibility with `netlink-sys`**: `netfyr-backend` uses `rtnetlink = "0.20"` which depends on `netlink-sys 0.8.8`. Adding `netlink-sys = "0.8"` directly must resolve to the same version; a mismatch would cause duplicate crate instances.

7. **Interface name availability in netlink messages**: `RTM_NEWLINK` messages include the interface name as `IFLA_IFNAME`. `RTM_NEWADDR` messages include the interface index but not always the name. The monitor must handle the case where `ifname` is absent (the spec says skip such changes), meaning address-only changes on interfaces not also generating link changes may be silently dropped.
