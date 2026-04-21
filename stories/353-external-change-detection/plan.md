# Plan: SPEC-353 External Change Detection

## Approach

The design adds a netlink monitor as a long-lived background task in the daemon that listens for kernel-originated network state change notifications and records them as journal entries. The monitor is structurally independent from the reconciliation engine — it feeds events into the same `tokio::select!` loop that already handles Varlink connections, DHCP factory events, and signals, and the reconciler's journal-write path is reused for persisting external change entries.

The key architectural choice is to use `netlink-sys` directly for raw socket subscription rather than `rtnetlink`'s higher-level connection. **Why**: `rtnetlink::new_connection()` creates a socket bound to unicast only; it doesn't subscribe to multicast groups. The `netlink-sys` crate (already a transitive dependency via `rtnetlink`) provides `Socket` with `add_membership()` for group subscription and raw `recv()` for reading messages. An alternative would be to use `rtnetlink`'s listener module (if it existed), but it does not — there is no notification/subscription API in `rtnetlink 0.20`. Another alternative would be `tokio::io::unix::AsyncFd` wrapping the raw fd, which we will use to avoid blocking the async runtime (see Design Decision #2).

The monitor parses only the message header (type + interface index) and relevant attributes (IFLA_IFNAME for link messages, IFA_LABEL/interface index for address messages). It does not need to parse the full attribute tree — it just needs to identify *which interface* changed and *what kind* of change (link vs address). The actual state comparison is done by re-querying the backend and comparing against the journal's last known snapshot, which reuses existing infrastructure.

For self-change exclusion, an `Arc<AtomicBool>` flag on the `Reconciler` is set before and cleared after every `reconcile_and_apply()` call. The monitor branch in the select loop checks this flag and discards events when it is set. This is a simple, race-minimal approach — the 500ms debounce window provides natural tolerance for the flag-clearing timing.

## Design Decisions

### 1. Raw `netlink-sys` socket vs. higher-level crate
- **Decision**: Use `netlink_sys::Socket` for the monitor socket, subscribing to multicast groups via `add_membership()`.
- **Alternatives**: (a) Use `rtnetlink` — but it has no multicast subscription API. (b) Use `neli` or `genetlink` — these are not in the dependency tree and would add new external crates. (c) Implement raw socket via `libc` — possible but `netlink-sys` already wraps the boilerplate.
- **Rationale**: `netlink-sys 0.8` is already a transitive dependency (via `rtnetlink 0.20`). Using it directly avoids new dependencies while providing a clean, type-safe socket API.

### 2. Async integration via `tokio::io::unix::AsyncFd`
- **Decision**: Wrap the `netlink_sys::Socket` file descriptor in `tokio::io::unix::AsyncFd` for non-blocking reads.
- **Alternatives**: (a) `tokio::task::spawn_blocking` — works but wastes a thread from the blocking pool. (b) Polling with `tokio::time::sleep` — introduces latency and wastes CPU cycles.
- **Rationale**: `AsyncFd` integrates directly with tokio's I/O reactor (epoll), providing immediate notification when data is available without consuming a blocking thread. The socket fd is obtained via `Socket::as_raw_fd()`.

### 3. Message parsing: minimal header-only parsing
- **Decision**: Parse only the nlmsghdr (message type), the ifinfomsg/ifaddrmsg header (interface index), and extract IFLA_IFNAME from link messages via `netlink-packet-route`'s `LinkMessage::parse()`.
- **Alternatives**: (a) Full attribute parsing using `netlink-packet-route` for both link and address messages. (b) Manual byte parsing of the netlink message.
- **Rationale**: We already depend on `netlink-packet-route` in dev-dependencies. We should add it as a regular dependency for the daemon to parse `LinkMessage` from raw bytes, which gives us `IFLA_IFNAME` reliably. For address messages, we only need the interface index (from the `ifaddrmsg` header), which is at a fixed offset — we can use `netlink-packet-route::address::AddressMessage::parse()` for this. This avoids manual byte parsing while keeping the parsing minimal.

### 4. Debounce strategy: per-interface timer with single 500ms window
- **Decision**: Accumulate all changes into a `HashMap<u32, Vec<ChangeKind>>` keyed by ifindex. On first event, start a 500ms `tokio::time::sleep` timer. When the timer fires, drain the map and emit the batch. Reset the timer on each new event only if the timer is not already running.
- **Alternatives**: (a) Per-interface timers — more complex, not needed since changes to different interfaces in the same burst should be coalesced into one journal entry anyway. (b) Fixed polling interval — wastes resources during quiet periods.
- **Rationale**: A single debounce timer is simpler and aligns with the spec's intent: "coalesces burst changes into one journal entry per interface per event." The 500ms window is hardcoded per spec.

### 5. Self-change exclusion: `AtomicBool` flag
- **Decision**: Add `is_applying: Arc<AtomicBool>` to `Reconciler`. The event loop sets it to `true` before `reconcile_and_apply()` and `false` after. The monitor branch checks the flag and discards events when set.
- **Alternatives**: (a) Channel-based coordination — overengineered for a boolean state. (b) Timestamp-based exclusion (ignore events within N ms of last apply) — fragile and harder to reason about. (c) Comparing old/new state to detect self-changes — would still produce spurious journal entries showing "no change" if timing works out.
- **Rationale**: `AtomicBool` is the simplest correct approach. The 500ms debounce window provides natural tolerance: self-change netlink events arrive almost immediately after the apply call, well within the debounce window. Even if a race occurs (apply finishes quickly, flag clears, then debounce fires), the state comparison step will show no diff (the applied state matches the desired state in the journal) so no external-change entry is written.

### 6. Managed-entity filter: cache effective entity names
- **Decision**: Maintain a `HashSet<String>` of managed entity names (interface names from effective desired state) in the event loop, updated whenever `reconcile_and_apply()` runs. The monitor branch checks this set to skip unmanaged interfaces.
- **Alternatives**: (a) Re-run full policy merge on each netlink event — correct but expensive. (b) Check if the interface has any journal entry — would miss the "unmanaged" case where an interface was never touched by netfyr.
- **Rationale**: The managed set only changes when policies change (SubmitPolicies) or when factories produce new state (DHCP lease). Both already call `reconcile_and_apply()`, making it natural to update the cached set at that point.

### 7. External diff computation: compare current state against journal snapshot
- **Decision**: For each changed managed interface, query the backend for current state, look up `journal.latest_state_for(ifname)`, and build a `SerializableDiff` by comparing field values. This happens inside a new `Reconciler` method `record_external_change()` to access the journal mutex.
- **Alternatives**: (a) Compute diff outside the reconciler and pass the journal handle — breaks encapsulation since `journal` is private. (b) Make the journal public — leaks internal state.
- **Rationale**: A new method on `Reconciler` keeps journal access encapsulated. The method takes the changed entity names, queries the backend internally, reads from the journal, builds the diff, and writes the entry.

### 8. `state_after` snapshot: query full system state or only changed entities
- **Decision**: The `state_after` field in the journal entry should contain the current state of **only the changed entities** (not all managed entities). The `active_policies` field is populated from the policy store as usual.
- **Alternatives**: Querying `query_all()` for every external change — expensive and produces a large snapshot for a small change.
- **Rationale**: External changes affect specific interfaces. Including only the changed entities' state in `state_after` keeps journal entries small and focused. The `latest_state_for()` method searches `state_after.entities` by name, so as long as the changed entity is present, future lookups will find it.

### 9. `netlink-packet-route` as regular dependency for daemon
- **Decision**: Add `netlink-packet-route = "0.28"` to `netfyr-daemon/Cargo.toml` `[dependencies]` (currently only in `[dev-dependencies]`).
- **Alternatives**: Manual byte parsing of netlink messages — error-prone and unnecessary.
- **Rationale**: The crate is already in the workspace's lockfile at version 0.28 and used extensively in `netfyr-backend`. Promoting it to a regular dependency for the daemon lets us parse `LinkMessage` and `AddressMessage` from raw netlink bytes reliably.

## File Changes

### `crates/netfyr-daemon/Cargo.toml`
- **Action**: Modify
- **What**: Add `netlink-sys = "0.8"` and `netlink-packet-route = "0.28"` to `[dependencies]`. Move `netlink-packet-route` out of `[dev-dependencies]` if it's there (it is).
- **Why**: `netlink-sys` provides the raw netlink socket with multicast group subscription. `netlink-packet-route` provides message parsing for link and address notifications.

### `crates/netfyr-daemon/src/netlink_monitor.rs`
- **Action**: Create
- **What**: New module containing:
  - `pub enum ChangeKind { LinkChanged, AddressAdded, AddressRemoved }` — classifies the netlink notification type.
  - `pub struct NetlinkChange { pub ifindex: u32, pub ifname: Option<String>, pub kind: ChangeKind }` — a single parsed notification.
  - `pub struct NetlinkMonitor` — owns:
    - `change_rx: mpsc::Receiver<Vec<NetlinkChange>>` — receives debounced batches
    - `task: JoinHandle<()>` — handle to the background monitor task
  - `impl NetlinkMonitor`:
    - `pub async fn start() -> anyhow::Result<Self>` — creates a `netlink_sys::Socket` bound to `NETLINK_ROUTE`, subscribes to `RTNLGRP_LINK` (1) and `RTNLGRP_IPV4_IFADDR` (5) via `add_membership()`, wraps the fd in `tokio::io::unix::AsyncFd`, spawns a tokio task that:
      1. Reads raw bytes from the socket using `AsyncFd::readable()` + non-blocking `recv()`
      2. Parses the nlmsghdr to get message type (`RTM_NEWLINK`, `RTM_DELLINK`, `RTM_NEWADDR`, `RTM_DELADDR`)
      3. For link messages: parses via `netlink_packet_route::link::LinkMessage` to extract `ifindex` and `IFLA_IFNAME`
      4. For address messages: parses via `netlink_packet_route::address::AddressMessage` to extract `ifindex`; `ifname` is `None` (resolved later by the event loop or from the link message cache)
      5. Accumulates changes in a `HashMap<u32, (Option<String>, Vec<ChangeKind>)>` keyed by ifindex
      6. On first event, starts a 500ms debounce timer using `tokio::time::sleep`
      7. Uses `tokio::select!` between the socket read and the timer; when timer fires, drains the map, sends the batch via `mpsc::Sender<Vec<NetlinkChange>>`, and resets
    - `pub async fn next_change(&mut self) -> Option<Vec<NetlinkChange>>` — delegates to `self.change_rx.recv()`
    - `pub async fn stop(self)` — aborts the task handle and drops the receiver

  Internal helper functions:
  - `fn parse_link_message(buf: &[u8]) -> Option<(u32, Option<String>)>` — extracts ifindex and ifname from a raw RTM_NEWLINK/RTM_DELLINK message using `netlink-packet-route`
  - `fn parse_addr_message(buf: &[u8]) -> Option<u32>` — extracts ifindex from a raw RTM_NEWADDR/RTM_DELADDR message
  - `fn classify_message_type(nlmsg_type: u16) -> Option<ChangeKind>` — maps RTM_NEWLINK/RTM_DELLINK to `LinkChanged`, RTM_NEWADDR to `AddressAdded`, RTM_DELADDR to `AddressRemoved`

- **Why**: Implements the core netlink monitoring functionality specified in SPEC-353.

### `crates/netfyr-daemon/src/reconciler.rs`
- **Action**: Modify
- **What**:
  1. Add `use std::sync::atomic::{AtomicBool, Ordering};` and `use std::sync::Arc;` (Arc is already imported).
  2. Add field `is_applying: Arc<AtomicBool>` to `Reconciler` struct.
  3. Initialize it in `Reconciler::new()` as `Arc::new(AtomicBool::new(false))`.
  4. Add two public methods:
     - `pub fn set_applying(&self, applying: bool)` — stores the value with `Ordering::SeqCst`
     - `pub fn is_applying(&self) -> bool` — loads with `Ordering::SeqCst`
  5. Add a new public method:
     - `pub async fn record_external_change(&self, changed_entity_names: Vec<String>, policy_store: &PolicyStore) -> anyhow::Result<()>`:
       - For each entity name, query the backend via `self.backend_registry.query(&"ethernet".to_string(), Some(&Selector::with_name(&name)))` to get the current state
       - Lock the journal mutex
       - For each entity name, call `journal.latest_state_for(&name)` to get the last known state
       - Compare current state fields against last known state fields to build `Vec<SerializableDiffOp>` with `kind: "modify"`, `change_kind: "set"`, showing old→new values for each field that differs
       - If no actual field differences are found (state hasn't meaningfully changed), return early without writing a journal entry
       - Build a `SerializableStateSet` containing only the current states of the changed entities
       - Build a `JournalEntry` with `Trigger::ExternalChange { changed_entities }`, `ApplyOutcome::Observed`, the computed diff, and active policies from `summarize_policies(policy_store.policies())`
       - Append the entry to the journal
       - Log at info level: "External change detected on: {entity_names}"

- **Why**: The `is_applying` flag enables self-change exclusion. The `record_external_change` method encapsulates journal access for external change entries, keeping the journal private to the reconciler.

### `crates/netfyr-daemon/src/server.rs`
- **Action**: Modify
- **What**:
  1. Add `use crate::netlink_monitor::NetlinkMonitor;` import.
  2. In `serve_varlink()`, before the main loop:
     - Instantiate the netlink monitor: `let mut netlink_monitor = NetlinkMonitor::start().await?;`
     - Initialize `managed_entities: std::collections::HashSet<String>` as empty
  3. Add a helper function or inline logic to update `managed_entities` from the result of policy merge. This should be called:
     - After initial reconciliation (extract entity names from the policy store's static policies + factory states)
     - After every `reconcile_and_apply()` call inside the event loop
     
     Implementation: a closure or function `update_managed_set(policy_store: &PolicyStore, factory_manager: &FactoryManager) -> HashSet<String>` that iterates static policies and factory states, collecting entity selector names.
  4. Add a 5th branch to the `tokio::select!` loop:
     ```
     Some(changes) = netlink_monitor.next_change() => {
         if reconciler.is_applying() {
             continue;
         }
         
         let changed_names: Vec<String> = changes
             .into_iter()
             .filter_map(|c| c.ifname)
             .filter(|name| managed_entities.contains(name))
             .collect::<std::collections::HashSet<_>>()
             .into_iter()
             .collect();
         
         if !changed_names.is_empty() {
             if let Err(e) = reconciler
                 .record_external_change(changed_names, &policy_store)
                 .await
             {
                 error!("Failed to record external change: {}", e);
             }
         }
     }
     ```
  5. Wrap every `reconcile_and_apply()` call site with `set_applying(true)` before and `set_applying(false)` after. There are four call sites:
     - `handle_submit_policies()` — this is called from `handle_connection()`, not directly from the select loop. The `reconciler` reference is passed in. Need to add `set_applying` calls around the `reconcile_and_apply()` call inside this function.
     - Three factory event arms (LeaseAcquired, LeaseRenewed, LeaseExpired) — add `set_applying` calls around each `reconcile_and_apply()`.
  6. After each successful `reconcile_and_apply()`, update `managed_entities` by extracting entity names from policy/factory state.
  7. In the graceful shutdown section, add `netlink_monitor.stop().await;` before removing the socket file.
  8. Note: `handle_submit_policies` currently takes `&Reconciler`. The `set_applying` method works on `&self` via `AtomicBool`, so no signature change is needed.

- **Why**: Integrates the netlink monitor into the daemon's event loop, implements the self-change exclusion, and manages the set of monitored entities.

### `crates/netfyr-daemon/src/main.rs`
- **Action**: Modify
- **What**: Add `mod netlink_monitor;` declaration alongside the existing module declarations.
- **Why**: Registers the new module with the crate.

## Dependencies

### `netlink-sys = "0.8"`
- **Crate**: `netlink-sys`
- **Version**: `0.8` (resolves to 0.8.8, matching the existing lockfile entry from transitive `rtnetlink` dependency)
- **Why**: Provides `Socket` with `add_membership()` for subscribing to netlink multicast groups (`RTNLGRP_LINK`, `RTNLGRP_IPV4_IFADDR`). The standard library has no netlink socket API. This crate is already transitively depended upon.
- **Section**: `[dependencies]` of `netfyr-daemon/Cargo.toml`

### `netlink-packet-route = "0.28"` (promote from dev-dependencies)
- **Crate**: `netlink-packet-route`
- **Version**: `0.28` (already in lockfile)
- **Why**: Provides `LinkMessage` and `AddressMessage` parsing from raw netlink bytes, including extraction of `IFLA_IFNAME` (interface name) and interface index. Already used in `netfyr-backend` and in daemon's dev-dependencies.
- **Section**: Move from `[dev-dependencies]` to `[dependencies]` of `netfyr-daemon/Cargo.toml`

### `netlink-packet-core` (version determined by `netlink-packet-route`)
- **Crate**: `netlink-packet-core`
- **Version**: Whatever `netlink-packet-route 0.28` depends on (already in lockfile)
- **Why**: Provides `NetlinkMessage` and `NetlinkPayload` for parsing the outer netlink envelope of raw messages received from the socket. Needed to extract the message type (RTM_NEWLINK, etc.) and deserialize the inner payload.
- **Section**: `[dependencies]` of `netfyr-daemon/Cargo.toml`

No other new external dependencies are needed. `tokio` (channels, timers, AsyncFd), `chrono`, `anyhow`, `tracing`, and `serde_json` are already direct dependencies of `netfyr-daemon`.

## Implementation Order

### Step 1: Add dependencies to `Cargo.toml`
Add `netlink-sys`, `netlink-packet-route`, and `netlink-packet-core` to `netfyr-daemon/Cargo.toml` `[dependencies]`. Remove `netlink-packet-route` from `[dev-dependencies]` if present. This is a standalone change that compiles immediately.

### Step 2: Add `is_applying` flag to `Reconciler`
Modify `reconciler.rs` to add the `AtomicBool` field, initialize it in `new()`, and add the `set_applying()` / `is_applying()` methods. This compiles independently — no callers yet.

### Step 3: Add `record_external_change()` method to `Reconciler`
Add the method that takes entity names, queries backend, compares with journal, and writes the entry. This depends on Step 2 (same file). Compiles independently — no callers yet.

### Step 4: Create `netlink_monitor.rs`
Create the new file with `NetlinkMonitor`, `NetlinkChange`, `ChangeKind`, and all internal parsing/debounce logic. Add `mod netlink_monitor;` to `main.rs`. This compiles independently — the monitor is self-contained and not yet wired into the event loop.

### Step 5: Integrate into `server.rs` event loop
Wire everything together: instantiate the monitor, add the select branch, wrap `reconcile_and_apply()` calls with `set_applying`, maintain the `managed_entities` set, and add shutdown logic. This depends on Steps 2-4.

## Risks and Mitigations

### 1. `AsyncFd` with `netlink-sys::Socket`
**Risk**: `netlink_sys::Socket` uses `socket2::Socket` internally. The fd may not be set to non-blocking mode by default, causing `AsyncFd` reads to block.
**Mitigation**: After creating the socket, explicitly set it to non-blocking mode via `socket.set_non_blocking(true)` (the `netlink-sys` crate exposes this) or via `libc::fcntl(fd, F_SETFL, O_NONBLOCK)` before wrapping in `AsyncFd`. Test this in the implementation.

### 2. Self-change exclusion timing with debounce
**Risk**: If `reconcile_and_apply()` completes in <500ms, the `is_applying` flag clears before the debounce window fires. Self-generated netlink events would then pass the flag check.
**Mitigation**: The state-comparison step in `record_external_change()` acts as a second defense: after a self-apply, the current state matches the journal's `state_after` from the just-written entry, so the diff is empty and no external-change entry is written. This makes the system correct even if the flag timing is imperfect.

### 3. `RTM_NEWADDR` messages lack interface name
**Risk**: Address notifications include the interface index but not always the name. If no `RTM_NEWLINK` arrives in the same burst, the monitor can't map ifindex to ifname.
**Mitigation**: Maintain an `ifindex_to_name: HashMap<u32, String>` cache in the monitor task, populated from `RTM_NEWLINK` messages. For address messages, look up the index in this cache. If the cache misses (rare — would require an address change on an interface that never had a link event), the change is discarded. This is acceptable — the spec says "skip such changes."

### 4. Journal `latest_state_for()` returns `None` after rotation
**Risk**: After journal rotation, `latest_state_for()` searches only `current.ndjson`, which may be empty. External changes on interfaces that were only in the archived journal would be missed.
**Mitigation**: This is spec-intentional ("entities in the current state but not in the journal are ignored"). The first `reconcile_and_apply()` after rotation writes a new entry with `state_after`, repopulating the current journal file. The window of missed detection is short (rotation is rare and followed by a reconcile).

### 5. `netlink-sys` version mismatch
**Risk**: Adding `netlink-sys = "0.8"` directly could resolve to a different patch version than what `rtnetlink` depends on, causing duplicate crate instances.
**Mitigation**: The `Cargo.lock` already pins `netlink-sys` to `0.8.8`. Specifying `"0.8"` in the manifest will resolve to the same version. Verify after `cargo build` that there's only one `netlink-sys` instance in the lockfile.

### 6. Monitor task panic / socket error
**Risk**: If the netlink socket encounters an error (e.g., buffer overflow, kernel busy), the monitor task could panic or exit, causing `next_change()` to return `None` and silently disabling monitoring.
**Mitigation**: The monitor task should log errors and continue rather than panicking. Socket read errors should be logged at `warn` level and the read retried. If the socket becomes permanently unusable, `next_change()` returns `None`, and the daemon continues operating without monitoring (degraded but functional). Log a message at `error` level if the monitor task exits.

### 7. Netlink buffer overflow
**Risk**: Under heavy network event load, the kernel's netlink socket buffer could overflow, causing the kernel to drop messages (ENOBUFS).
**Mitigation**: Increase the socket receive buffer size via `setsockopt(SO_RCVBUF)` to a reasonable value (e.g., 1MB). Log ENOBUFS at warn level if received. Missed events are acceptable — external change detection is best-effort, and the next event will trigger a fresh state comparison.

## Test Strategy

### Unit Tests (in `netlink_monitor.rs`)

- **`ChangeKind` / `NetlinkChange` construction**: Verify the types can be created and accessed.
- **`classify_message_type`**: Test that RTM_NEWLINK/RTM_DELLINK → `LinkChanged`, RTM_NEWADDR → `AddressAdded`, RTM_DELADDR → `AddressRemoved`, and unknown types → `None`.
- **Debounce logic**: If debounce is factored into a testable component (e.g., a separate struct), test that:
  - A single event produces a single batch after 500ms
  - Multiple events within 500ms produce one batch
  - Events on different interfaces are batched together

### Unit Tests (in `reconciler.rs`)

- **`set_applying` / `is_applying`**: Verify the flag toggles correctly (`false` → `set(true)` → `is_applying() == true` → `set(false)` → `is_applying() == false`).
- **`record_external_change` with no journal**: Verify the method returns Ok (no-op) when the journal is `None`.

### Integration Tests (in `crates/netfyr-daemon/tests/`)

These tests require network namespace support (same as existing `netns_*` tests):

- **MTU change detection**: Start daemon with policy setting MTU on a veth, run `ip link set veth mtu 1500` externally, query journal via Varlink `GetHistory` and verify an entry with trigger `external_change` exists showing the MTU diff.
- **Self-change exclusion**: Submit a policy via Varlink, verify only a `policy_apply` journal entry (no `external_change` entry).
- **Burst coalescing**: Change MTU and add an address in quick succession, verify a single journal entry covers both.
- **Unmanaged interface**: Change MTU on an interface not covered by any policy, verify no journal entry is recorded.
- **No re-reconciliation**: After an external change, verify the interface retains the externally-set value (daemon did not re-apply).

### Test Infrastructure

- Reuse existing `NetnsGuard` and `DnsmasqGuard` from `netfyr-test-utils`.
- Reuse existing `DaemonProcess` test helper from `server_integration.rs`.
- Journal entries can be queried via the `io.netfyr.GetHistory` Varlink method (already implemented).
- External changes can be triggered via `Command::new("ip")` inside the network namespace.
- Add a small sleep (e.g., 1 second) after the external change to allow the 500ms debounce window to fire and the journal entry to be written.
