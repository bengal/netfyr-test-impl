# Plan: SPEC-102 — rtnetlink Query for Ethernet Interfaces

## Approach

This story implements the `NetworkBackend::query` method for ethernet interfaces using the `rtnetlink` crate, enabling the system to discover and report the current state of ethernet interfaces from the Linux kernel. The design uses a three-file module structure within `crates/netfyr-backend/src/netlink/`: `mod.rs` (backend struct + trait impl), `query.rs` (shared netlink/sysfs utilities), and `ethernet.rs` (ethernet-specific query logic). This separation exists because the backend will eventually support other entity types (bonds, vlans, etc.) that share the connection and sysfs utilities in `query.rs` but have their own query logic.

The query pipeline follows a bulk-then-index pattern: enumerate all links in a single netlink dump, filter by link type and selector, then bulk-dump addresses and routes (one call each, not per-interface) and index them by interface index for O(1) lookup during State assembly. This is preferable to per-interface queries because netlink's `RTM_GETLINK` dump is cheaper than N individual `RTM_GETLINK` calls, and address/route dumps can't be filtered by interface index at the kernel level anyway — the kernel returns all of them and we filter in userspace. The three-dump approach (links, addresses, routes) keeps netlink round-trips constant regardless of interface count.

All field values are tagged with `Provenance::KernelDefault` because they represent observed system state, not user-configured intent. The `NetlinkBackend` creates a fresh netlink connection per query rather than holding one persistently — this avoids stale-socket issues, keeps `NetlinkBackend::new()` synchronous, and netlink socket creation (a single `socket()`+`bind()` syscall pair) is negligible relative to the enumeration work.

## Design Decisions

1. **Decision**: Create a new netlink connection per query call rather than holding a persistent `Handle` in `NetlinkBackend`.
   - **Alternatives considered**: Store `Handle` in the struct (requires async constructor or `Option<Handle>` with lazy init); connection pool.
   - **Rationale**: Netlink socket creation is two syscalls and negligible cost. A persistent connection requires managing connection lifecycle, detecting stale sockets, and making the constructor async (which complicates `BackendRegistry` registration). Per-query connections are simpler and equally correct.

2. **Decision**: Include veth interfaces in ethernet query results, exclude all other virtual types (bridge, bond, vlan, vxlan, dummy, macvlan, macvtap, ipvlan, ipvtap, tun, sit, gre, gre6, ipip, wireguard, vrf, nlmon).
   - **Alternatives considered**: Exclude all virtual types including veth; use a positive allowlist instead of a negative blocklist.
   - **Rationale**: The spec says "physical NICs and veth" are ethernet. veth pairs are the primary test vehicle (integration tests use `unshare --user --net` with veth pairs). A blocklist is safer than an allowlist because new kernel link types will be excluded by default rather than silently included — but veth must be explicitly allowed. Physical NICs have no `IFLA_INFO_KIND` attribute at all, so they pass through naturally.

3. **Decision**: Filter links by `LinkLayerType::Ether` (ARPHRD_ETHER = 1) as the first filter, then by `IFLA_INFO_KIND` as the second filter.
   - **Alternatives considered**: Only check `IFLA_INFO_KIND`; check device type flags.
   - **Rationale**: ARPHRD_ETHER excludes non-ethernet link types (loopback is ARPHRD_LOOPBACK = 772, tunnels may have their own types). The KIND check then distinguishes physical ethernet from virtual ethernet devices like bridges and bonds. Two-stage filtering is both correct and clear in intent.

4. **Decision**: Bulk-dump all addresses and routes, then index by interface index, rather than querying per-interface.
   - **Alternatives considered**: Per-interface `handle.address().get().set_link_index_filter(idx)` calls; lazy loading.
   - **Rationale**: The netlink address and route dump APIs return all entries regardless — there's no kernel-side filtering by interface for `RTM_GETADDR` dumps. Indexing the full dump into a `HashMap<u32, Vec<...>>` is O(n) total work vs. O(n*m) for repeated per-interface dumps that each scan the full kernel table. This is the standard pattern for netlink tools like `ip addr show`.

5. **Decision**: Read `speed` and `driver` from sysfs (`/sys/class/net/<name>/speed`, `/sys/class/net/<name>/device/driver`) rather than netlink attributes.
   - **Alternatives considered**: Use `IFLA_INFO_DATA` or ethtool netlink (`ETHTOOL_MSG_LINKMODES_GET`).
   - **Rationale**: The standard `IFLA_*` attributes don't include link speed or driver name. The ethtool netlink family exists but requires the `genetlink` crate and a separate netlink connection. Sysfs reads are simple, reliable, and the standard approach used by tools like `ip link show` and `ethtool`. They return `None` gracefully for interfaces without PCI devices (veth) or with link down (speed returns -1).

6. **Decision**: `speed` field is omitted (not set to 0 or -1) when sysfs returns -1 or the file doesn't exist.
   - **Alternatives considered**: Set to 0; set to a sentinel value; use `Value::Null`.
   - **Rationale**: The spec says "speed field is None (omitted)" for link-down interfaces. Omitting the field from the `IndexMap<String, FieldValue>` is the idiomatic way to represent "not available" in this data model — downstream consumers check for field presence, not sentinel values.

7. **Decision**: `NotFound` error is only emitted when `selector.is_specific()` returns true AND the result set is empty.
   - **Alternatives considered**: Always return `NotFound` on empty result; never return `NotFound` (always return empty `StateSet`).
   - **Rationale**: `is_specific()` returns true only when `name` is set — meaning the user asked for a specific, named interface. A wildcard query (e.g., just `driver="ixgbe"`) returning zero results is a valid "no matches" scenario, not an error. This matches the spec's acceptance criteria: `NotFound` is specified for `name=eth99`, not for MAC-only or driver-only selectors.

8. **Decision**: Route values are `Value::Map` with string keys `destination`, `gateway` (optional), `metric`.
   - **Alternatives considered**: Flat string representation (`"10.0.1.0/24 via 10.0.1.1"`); dedicated Route struct.
   - **Rationale**: The spec explicitly lists "destination, gateway (if applicable), and metric fields" — a map with named keys is the natural representation. A dedicated struct would require schema changes and doesn't add value since `Value::Map` already provides type-safe access via `as_map()`.

9. **Decision**: Shell integration tests use `--output json` and `grep` for assertions rather than `jq` or YAML parsing.
   - **Alternatives considered**: Default YAML output with `grep`; require `jq` as a dependency.
   - **Rationale**: JSON has deterministic quoting (`"key": value`) making `grep` assertions reliable. YAML can have ambiguous string quoting. Avoiding `jq` keeps the test dependency footprint minimal — only standard Unix tools (`bash`, `grep`, `awk`, `ip`) are required.

10. **Decision**: Shell tests hard-fail (`exit 1`) when prerequisites are missing (binary, `unshare`), per SPEC-001 rules.
    - **Alternatives considered**: Skip with `exit 0`; use `exit 77` (autotools skip convention).
    - **Rationale**: The spec explicitly states "No skip: if a prerequisite is missing, the script must `echo "FAIL: ..." >&2; exit 1`. Never `exit 0` on failure." This ensures CI never silently passes without actually running the tests.

## File Changes

### 1. `crates/netfyr-backend/src/netlink/query.rs` — modify

Contains shared netlink and sysfs utilities used by `ethernet.rs` (and future entity type modules).

**Functions to implement:**

- `pub async fn establish_connection() -> Result<Handle, BackendError>`: Call `rtnetlink::new_connection()`, spawn the connection future on the tokio runtime via `tokio::spawn(connection)`, return the `Handle`. Map `io::ErrorKind::PermissionDenied` to `BackendError::PermissionDenied`; all other errors to `BackendError::QueryFailed { entity_type: "ethernet" }`.

- `pub fn build_discovered_selector(name: &str, mac: Option<[u8; 6]>, driver: Option<&str>, pci_path: Option<&str>) -> Selector`: Construct a `Selector` with the provided fields, wrapping MAC bytes in `MacAddr([u8; 6])`, converting string slices to owned `String`. Used by `ethernet.rs` to build the "discovered" selector that user selectors are matched against via `Selector::matches()`.

- `pub fn read_sysfs_speed(name: &str) -> Option<u64>`: Read `/sys/class/net/<name>/speed` as a string, trim, parse as `i64`. Return `None` if the file doesn't exist, can't be read, can't be parsed, or the value is negative (kernel sentinel -1 for "no speed"). Otherwise return `Some(value as u64)`.

- `pub fn read_sysfs_driver(name: &str) -> Option<String>`: Read the symlink at `/sys/class/net/<name>/device/driver` via `std::fs::read_link`, return the basename of the target (e.g., `"ixgbe"`). Return `None` for virtual interfaces without a PCI device.

- `pub fn read_sysfs_pci_path(name: &str) -> Option<String>`: Read the symlink at `/sys/class/net/<name>/device` via `std::fs::read_link`, return the basename of the target (e.g., `"0000:03:00.0"`). Return `None` for virtual interfaces.

- `pub fn operstate_to_str(state: u8) -> &'static str`: Map kernel `IF_OPER_*` constants: 0→"unknown", 1→"not_present", 2→"down", 3→"lower_layer_down", 4→"testing", 5→"dormant", 6→"up", all others→"unknown".

**Unit tests (in `#[cfg(test)] mod tests`):**
- All `operstate_to_str` values (0–6) map correctly; out-of-range values map to "unknown"; all defined values return non-empty strings.
- `build_discovered_selector` correctly sets name, mac, driver, pci_path individually and all together.
- Selector matching: name match/mismatch, MAC match/mismatch, driver match/mismatch, pci_path match/mismatch, AND logic (name+mac both match, name+mac one mismatch, driver+name both match).
- `read_sysfs_speed`, `read_sysfs_driver`, `read_sysfs_pci_path` return `None` for non-existent interface names.

**Why**: These utilities are shared infrastructure. `establish_connection` centralizes netlink socket creation and error mapping. `build_discovered_selector` centralizes the selector construction pattern. The sysfs helpers encapsulate the fragile filesystem reads with graceful fallbacks.

### 2. `crates/netfyr-backend/src/netlink/ethernet.rs` — modify

Contains the main ethernet query function. Currently has the `query_ethernet` function signature; needs full implementation.

**Functions to implement:**

- **Private helper `is_excluded_kind(kind: &InfoKind) -> bool`**: Returns `true` for `InfoKind::Bridge | Bond | Vlan | Vxlan | Dummy | MacVlan | MacVtap | IpVlan | IpVtap | Tun | SitTun | GreTun | GreTun6 | IpIp | Wireguard | Vrf | Nlmon`. Returns `false` for `Veth` and all unrecognized kinds.

- **Private helpers for link attribute extraction**: `extract_link_name(msg: &LinkMessage) -> Option<String>`, `extract_link_mac(msg: &LinkMessage) -> Option<[u8; 6]>`, `extract_link_mtu(msg: &LinkMessage) -> Option<u32>`, `extract_link_carrier(msg: &LinkMessage) -> Option<u8>`, `extract_link_operstate(msg: &LinkMessage) -> u8` (default 0), `extract_link_kind(msg: &LinkMessage) -> Option<InfoKind>`. Each iterates `msg.attributes` looking for the matching `LinkAttribute` variant.

- **Private helper `format_mac(bytes: &[u8; 6]) -> String`**: Format as lowercase colon-separated hex: `"aa:bb:cc:dd:ee:ff"`.

- **Private helper `route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr>`**: Convert `RouteAddress::Inet(v4)` to `IpAddr::V4`, `RouteAddress::Inet6(v6)` to `IpAddr::V6`, others to `None`.

- **Private helper `build_route_value(destination: &str, gateway: Option<&str>, metric: u32) -> Value`**: Build a `Value::Map` with keys `destination` (always), `gateway` (if Some), `metric` (as `Value::U64`).

- **Private helper `kd(value: Value) -> FieldValue`**: Create `FieldValue { value, provenance: Provenance::KernelDefault }`.

- **Private async `dump_addresses(handle: &Handle) -> Result<HashMap<u32, Vec<String>>, BackendError>`**: Call `handle.address().get().execute()`, stream all results, extract `AddressAttribute::Address(ip)` and prefix length from each message, format as `"{ip}/{prefix_len}"`, index by `msg.header.index`.

- **Private async `dump_routes(handle: &Handle, known_indices: &HashSet<u32>) -> Result<HashMap<u32, Vec<Value>>, BackendError>`**: For each of IPv4 and IPv6: construct a `RouteMessage::default()`, set `header.address_family` to `Inet`/`Inet6`, call `handle.route().get(route_msg).execute()`. For each route message, call `parse_route_message` which extracts `RouteAttribute::Destination`, `RouteAttribute::Gateway`, `RouteAttribute::Priority` (metric), and `RouteAttribute::Oif` (output interface). Skip routes whose OIF is not in `known_indices`. Build destination as CIDR string (`"{ip}/{prefix_len}"`), defaulting to `"0.0.0.0/0"` or `"::/0"` for default routes. Index by OIF.

- **`pub async fn query_ethernet(handle: &Handle, selector: Option<&Selector>) -> Result<StateSet, BackendError>`**: The 8-step pipeline:
  1. Enumerate all links via `handle.link().get().execute()` into a `Vec<LinkMessage>`.
  2. Filter to `LinkLayerType::Ether`, exclude links whose `extract_link_kind` returns an excluded kind. Collect into a local struct with `index`, `name`, `mac`, `mtu`, `carrier`, `operstate`.
  3. For each filtered link, call `build_discovered_selector` (with sysfs driver/pci_path) and test `selector.matches(&discovered)`. Retain only matching links.
  4. Build a `HashSet<u32>` of matched interface indices for route pre-filtering.
  5. Call `dump_addresses(handle)` to get `HashMap<u32, Vec<String>>`.
  6. Call `dump_routes(handle, &known_indices)` to get `HashMap<u32, Vec<Value>>`.
  7. For each matched link, assemble a `State` with: `entity_type = "ethernet"`, `selector = Selector::with_name(name)`, fields `name` (always), `mtu` (if present), `mac` (if present, formatted), `carrier` (bool, default false), `operstate` (string from `operstate_to_str`), `speed` (optional, from sysfs), `driver` (optional, from sysfs), `addresses` (list, may be empty), `routes` (list, may be empty). All fields tagged `KernelDefault`. Insert into `StateSet`.
  8. If `selector.is_specific()` and `state_set.is_empty()`, return `Err(BackendError::NotFound { entity_type, selector })`. Otherwise return `Ok(state_set)`.

**Why**: This is the core implementation of the story. The pipeline structure keeps each concern (enumeration, filtering, enrichment, assembly) in its own step, making the logic easy to follow and debug.

### 3. `crates/netfyr-backend/src/netlink/mod.rs` — modify

**Changes:**
- `NetlinkBackend` struct: holds `supported_entities: Vec<EntityType>`, initialized to `vec!["ethernet".to_string()]` in `new()`.
- `NetworkBackend` trait impl:
  - `supported_entities()` returns `&self.supported_entities`.
  - `query()` matches on `entity_type.as_str()`: `"ethernet"` → call `establish_connection()` then `ethernet::query_ethernet(&handle, selector)`; anything else → `Err(BackendError::UnsupportedEntityType)`.
  - `query_all()` iterates `self.supported_entities`, calls `self.query()` for each, merges results by inserting all states into a single `StateSet`.
  - `apply()` and `dry_run()` delegate to `apply::apply_ethernet` / `apply::dry_run_ethernet` (pre-existing, SPEC-103 scope).
- Implement `Default for NetlinkBackend` delegating to `new()`.

**Why**: This is the entry point that routes entity-type-dispatched calls to the correct query function and implements the `NetworkBackend` trait contract.

### 4. `crates/netfyr-backend/tests/netlink_ethernet.rs` — create

Integration tests using `NetnsGuard` from `netfyr-test-utils`. Each test creates an unprivileged network namespace, sets up veth pairs with known configuration, and exercises `query_ethernet` or `NetlinkBackend` methods.

**Tests to implement (24 total):**

| # | Test name | What it verifies |
|---|---|---|
| 1 | `test_query_all_veth_pair_returns_two_entities` | Two veth ends → StateSet with 2 entries, each has name/mtu/mac |
| 2 | `test_query_by_name_selector_returns_one_entity` | Name selector returns exactly 1 entity |
| 3 | `test_query_includes_ip_addresses` | `addresses` field contains assigned CIDR |
| 4 | `test_all_fields_have_kernel_default_provenance` | Every field has `Provenance::KernelDefault` |
| 5 | `test_query_nonexistent_interface_returns_not_found` | `BackendError::NotFound` for `name=eth99` |
| 6 | `test_mtu_reported_correctly` | MTU=1400 after `set_mtu` is reported correctly |
| 7 | `test_query_by_mac_address` | MAC selector → correct interface only |
| 8 | `test_link_down_carrier_false_and_no_speed` | carrier=false, speed absent, name/mtu/mac present |
| 9 | `test_query_all_returns_ethernet_interfaces` | `query_all` includes veth interfaces |
| 10 | `test_and_selector_logic` | name+mac AND logic: match and non-match |
| 11 | `test_query_veth_spec_comprehensive_scenario` | mtu=1400, address=10.99.0.1/24, all KernelDefault |
| 12 | `test_query_excludes_loopback_interface_in_fresh_namespace` | Loopback excluded |
| 13 | `test_query_includes_connected_subnet_route` | `routes` field contains subnet route |
| 14 | `test_query_all_returned_entities_have_ethernet_type` | entity_type="ethernet" on all |
| 15 | `test_query_excludes_bridge_interface` | Bridge excluded, veth present |
| 16 | `test_query_nonexistent_interface_error_captures_entity_type` | NotFound has correct entity_type and selector |
| 17 | `test_query_all_via_backend_matches_direct_query` | `query_all` via trait matches direct call |
| 18 | `test_query_excludes_bond_interface` | Bond excluded |
| 19 | `test_query_excludes_vlan_interface` | Vlan excluded |
| 20 | `test_carrier_is_true_when_both_veth_ends_are_up` | carrier=true when both ends up |
| 21 | `test_query_includes_route_with_gateway_field` | Default route with gateway + KernelDefault |
| 22 | `test_netlinkbackend_supports_ethernet_entity_type` | `supported_entities()` contains "ethernet" |
| 23 | `test_addresses_field_is_always_a_list` | `addresses` always present as `Value::List` |
| 24 | `test_routes_field_is_always_a_list` | `routes` always present as `Value::List` |

Tests that need namespace features (veth creation, etc.) should use a `require_netns!` macro that skips gracefully when unprivileged namespaces are unavailable.

**Why**: These tests cover all acceptance criteria at the API level, using real kernel interactions in isolated namespaces rather than mocks.

### 5. `tests/102-query-veth-by-name.sh` — create

Shell integration test: "Query veth interface in namespace".

- Source `helpers.sh`, locate binary via `$NETFYR_BIN` (fallback `$SCRIPT_DIR/../target/debug/netfyr`), hard-fail if missing.
- Call `netns_setup "$@"` to enter unprivileged user+net namespace.
- `create_veth veth-test0 veth-test1`, set mtu 1400, add address 10.99.0.1/24.
- Run `$NETFYR_BIN query --selector type=ethernet --selector name=veth-test0 --output json`.
- Assert output contains `"veth-test0"`, `"mtu": 1400`, `10.99.0.1/24`.
- Print `PASS: 102-query-veth-by-name`.

**Why**: End-to-end CLI test verifying argument parsing → netlink query → JSON serialization for the name-selector case.

### 6. `tests/102-query-all-veth-pair.sh` — create

Shell integration test: "Query returns both ends of a veth pair".

- Source `helpers.sh`, locate binary, hard-fail if missing.
- Call `netns_setup "$@"`, create veth pair `veth-a`/`veth-b`.
- Run `$NETFYR_BIN query --selector type=ethernet --output json`.
- Assert output contains both `"veth-a"` and `"veth-b"`.
- Print `PASS: 102-query-all-veth-pair`.

**Why**: Verifies that query without a name selector returns all ethernet interfaces.

### 7. `tests/102-query-by-mac.sh` — create

Shell integration test: "Query by MAC address in namespace".

- Source `helpers.sh`, locate binary, hard-fail if missing.
- Call `netns_setup "$@"`, create veth pair `veth-test0`/`veth-test1`.
- Capture MAC of veth-test0 via `ip link show dev veth-test0 | awk '/link\/ether/ {print $2}'`. Fail if empty.
- Run `$NETFYR_BIN query --selector type=ethernet --selector mac=$MAC --output json`.
- Assert output contains `"veth-test0"` and does NOT contain `"veth-test1"`.
- Print `PASS: 102-query-by-mac`.

**Why**: Verifies MAC-based selector filtering through the full CLI pipeline.

## Dependencies

No new crate dependencies are needed. All required crates are already in `crates/netfyr-backend/Cargo.toml`:

- `rtnetlink = "0.20"` — async netlink interface for link/address/route enumeration
- `netlink-packet-route = "0.28"` — netlink message types (`LinkMessage`, `LinkAttribute`, `RouteAttribute`, etc.)
- `tokio = "1"` — async runtime for spawning the netlink connection task
- `futures = "0.3"` — `TryStreamExt` for consuming netlink message streams
- `tracing = "0.1"` — `warn!` for logging attribute parse failures
- `indexmap = "2"` — ordered map for `State.fields`

The test file uses `netfyr-test-utils` which is already a dev-dependency.

## Implementation Order

1. **Step 1: `query.rs` — shared utilities.** Implement `establish_connection`, `build_discovered_selector`, `read_sysfs_speed`, `read_sysfs_driver`, `read_sysfs_pci_path`, `operstate_to_str`, and their unit tests. This compiles independently and the unit tests can run immediately (`cargo test -p netfyr-backend`).

2. **Step 2: `ethernet.rs` — query implementation.** Implement all private helpers and `query_ethernet`. This depends on step 1 (imports `build_discovered_selector`, `operstate_to_str`, etc. from `query.rs`). Compiles but requires step 3 to be callable via the trait.

3. **Step 3: `mod.rs` — trait implementation.** Wire `NetlinkBackend::query` to dispatch `"ethernet"` to `query_ethernet`, implement `query_all`, add `Default` impl. After this step, the full query pipeline is callable. Run `cargo build -p netfyr-backend` to verify.

4. **Step 4: Integration tests.** Create `tests/netlink_ethernet.rs` with all 24 tests. Depends on steps 1–3. Run `cargo test -p netfyr-backend` (tests that need namespaces will skip gracefully if unavailable).

5. **Step 5: Shell integration tests.** Create the three `tests/102-*.sh` scripts. Depends on the binary being buildable (steps 1–3). Run `cargo build -p netfyr-cli && bash tests/102-query-veth-by-name.sh` etc.

## Risks and Mitigations

### 1. Driver and pci_path selectors are not integration-testable in network namespaces
**Risk**: veth pairs have no PCI device, so `/sys/class/net/<name>/device/driver` doesn't exist. The driver and pci_path selector paths cannot be covered by integration tests.
**Mitigation**: These paths are covered by unit tests in `query.rs` (`test_build_discovered_selector_driver_match`, etc.) which test the matching logic directly. The sysfs read functions are tested for the "not found" case. Real-world driver filtering requires physical hardware.

### 2. `is_specific()` only checks `name` — MAC-only selectors return empty set, not NotFound
**Risk**: A user querying `--selector mac=aa:bb:cc:dd:ee:ff` for a non-existent MAC gets an empty result set (exit 0) rather than a `NotFound` error.
**Mitigation**: This is intentional and matches the spec. The `NotFound` acceptance criterion specifies `name=eth99`, not MAC-only. MAC/driver selectors are "filter" queries where zero results is a valid outcome, while name selectors are "lookup" queries where zero results is an error.

### 3. Sysfs reads are performed twice per matched interface (during filtering and assembly)
**Risk**: Minor inefficiency — `read_sysfs_driver` is called in step 3 (selector filtering) and again in step 7 (field assembly).
**Mitigation**: This is negligible. Sysfs reads are cached in the page cache after the first read. The alternative (caching driver/pci_path in the `LinkInfo2` struct) adds complexity for no measurable performance gain given typical interface counts (< 100).

### 4. Route API uses `RouteMessage::default()` not `IpVersion` enum
**Risk**: The spec describes `handle.route().get(IpVersion::V4)` but rtnetlink 0.20's `get()` takes a `RouteMessage`, not `IpVersion`.
**Mitigation**: The implementation constructs `RouteMessage::default()` and sets `header.address_family` to `AddressFamily::Inet` or `Inet6`. This is the correct API for rtnetlink 0.20.

### 5. Shell tests require compiled binary
**Risk**: Running shell tests before `cargo build` produces a confusing failure.
**Mitigation**: Each script checks `[[ ! -x "$NETFYR_BIN" ]]` and exits with `FAIL: netfyr binary not found` immediately. The Makefile's `integration-test` target should build before running tests.

### 6. Unprivileged user namespaces may be disabled
**Risk**: `unshare --user --net` fails on kernels with `unprivileged_userns_clone=0` or in restricted container environments.
**Mitigation**: Shell tests fail explicitly via `netns_setup` failure path. Rust integration tests use `require_netns!` macro to skip gracefully. CI environments should ensure user namespace support.

### 7. CLI uses `--selector type=ethernet`, not positional `ethernet` argument
**Risk**: Shell tests written with the spec's `netfyr query ethernet --selector name=eth0` syntax would fail because the actual CLI takes `--selector type=ethernet`.
**Mitigation**: All shell tests must use the actual CLI syntax: `netfyr query --selector type=ethernet --selector name=eth0 --output json`. This is the implemented interface.

## Test Strategy

### Unit tests (in `query.rs`)
- **What to test**: Pure functions (`operstate_to_str`, `build_discovered_selector`, sysfs readers) and selector matching logic.
- **Infrastructure**: Standard `#[cfg(test)]` module, no special fixtures needed. Sysfs tests use known-nonexistent interface names to verify `None` returns.
- **Coverage targets**: All `IF_OPER_*` values, all selector fields individually and in AND combinations, match and mismatch scenarios, out-of-range values.

### Integration tests (in `tests/netlink_ethernet.rs`)
- **What to test**: The full query pipeline against real kernel state in isolated network namespaces.
- **Infrastructure**: `NetnsGuard` from `netfyr-test-utils` for namespace creation, `create_veth_pair`/`set_mtu`/`add_address`/`set_link_up` for setup. A `require_netns!` macro to skip gracefully when namespaces are unavailable.
- **Coverage targets**: All acceptance criteria from the Gherkin spec — two-NIC query, name/MAC/AND selectors, address/route fields, provenance, NotFound, virtual type exclusion (bridge/bond/vlan/loopback), carrier state, query_all, entity type correctness.
- **Edge cases**: Link down with no speed, empty addresses/routes lists, fresh namespace with only loopback.

### Shell integration tests (in `tests/102-*.sh`)
- **What to test**: End-to-end CLI pipeline: argument parsing, backend construction, netlink query, JSON output serialization, exit codes.
- **Infrastructure**: `tests/helpers.sh` (existing) providing `netns_setup`, `create_veth`, `add_address`. Compiled `netfyr` binary.
- **Coverage targets**: Query by name with MTU/address verification, query-all returning both veth ends, query by dynamically-captured MAC address with positive and negative assertions.
- **Assertion approach**: `grep` on JSON output for deterministic string matching. No external JSON parsing tools required.
