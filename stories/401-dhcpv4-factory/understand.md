# Gap Analysis: SPEC-401 DHCPv4 Factory

## Current State

The codebase contains substantial implementation for this story. Most components are complete; one critical gap exists in `client.rs`.

### `crates/netfyr-backend/src/dhcp/`

**`lease.rs`** — Complete.
- `DhcpLease` struct: `ip`, `subnet_mask`, `gateway`, `dns_servers`, `lease_time`, `renewal_time`, `rebind_time`, `server_id`, `acquired_at`.
- `subnet_mask_to_prefix()` — `leading_ones()` on 32-bit mask.
- `is_expired()`, `time_until_renewal()`, `time_until_rebind()`, `time_until_expiry()` — all use `saturating_sub` on elapsed time.
- 15 unit tests covering expiry detection, timer ordering, prefix conversion, clone/debug.

**`mod.rs`** — Complete.
- `FactoryEvent` enum: `LeaseAcquired { policy_name, state }`, `LeaseRenewed { policy_name, state }`, `LeaseExpired { policy_name }`, `Error { policy_name, error }`. Uses `policy_name: String` (not `PolicyId`).
- `Dhcpv4Factory` struct: `interface: String`, `state: Arc<Mutex<Option<State>>>`, `stop_tx: Option<oneshot::Sender<()>>`, `task_handle: Option<JoinHandle<()>>`.
- `start()` — sets pending state synchronously before spawning the background task.
- `stop()` — sends stop signal, awaits task join; idempotent.
- `current_state()` — returns `Option<State>` (owned clone, not reference).
- `interface()` — returns `&str`.
- `lease_to_state(lease, interface, policy_name, priority)` — public free function; produces `operstate: "up"`, `addresses: ["ip/prefix"]`, conditional `routes` and `dns_servers`; all fields carry `Provenance::UserConfigured`.
- `pending_state()` (private) — returns state with only `operstate: "up"`.
- `interface_exists()` — uses `rtnetlink` (`LinkGet` by name), not sysfs.
- 18 unit tests covering all non-network acceptance criteria scenarios.

**`client.rs`** — Partially implemented. The DORA + lease-maintenance state machine logic is complete, but the socket layer uses the wrong socket type. See Gap Analysis.

Notable correct details in `client.rs`:
- `get_interface_mac()` uses `rtnetlink` (`LinkGet` + `LinkAttribute::Address`), not `/sys/class/net/`.
- Exponential backoff 1s → 60s with jitter on DISCOVER timeout or ACK failure.
- `parse_ack()` extracts IP, subnet mask, gateway, DNS servers, lease/T1/T2 times; T1 defaults to 50%, T2 to 87.5% of lease time when absent.
- `send_release()` sends DHCPRELEASE to the server unicast address.
- Stop signal is handled correctly in all `tokio::select!` arms.

### `crates/netfyr-policy/src/lib.rs`

`FactoryType::Dhcpv4` variant exists, serializes as `"dhcpv4"`. `Policy.selector: Option<Selector>` carries the interface name.

### `crates/netfyr-daemon/`

**`factory_manager.rs`** — Complete.
- `FactoryManager`: `HashMap<String, Dhcpv4Factory>` keyed by policy name, single shared `mpsc` channel.
- `sync()` — stops removed factories, starts new ones; pre-validates interface existence via `netfyr_backend::interface_exists()` (rtnetlink, not sysfs).
- `produced_states()`, `stop_all()`, `next_event()`, `factory_statuses()` implemented.
- `factory_statuses()` correctly distinguishes pending (no `addresses` field) from full-lease states.
- 14 unit tests.

**`reconciler.rs`** — Complete.
- `reconcile_and_apply()` restricts the actual `StateSet` to only entities present in the effective desired state before diffing, preventing `Remove` operations for unmanaged interfaces.
- `build_policy_inputs()` includes both static policy states and factory `produced_states()`.

**`main.rs`** — Complete. Startup sequence: load policies → factory sync → initial reconcile → sd_notify → event loop. Overridable via `NETFYR_SOCKET_PATH` and `NETFYR_POLICY_DIR`.

**`policy_store.rs`** — Complete. `replace_all()` persists policies as YAML with atomic writes; `load()` reads all `*.yaml` files enabling daemon-restart recovery.

### `tests/`

All three required shell integration tests are fully written and follow spec conventions (no skip-on-missing, correct binary path resolution, `FAIL:` on error, `netns_setup` for isolation):
- `401-dhcpv4-acquire-lease.sh`
- `401-dhcpv4-unmanaged-interface.sh`
- `401-dhcpv4-daemon-restart.sh`

`helpers.sh` provides all required helpers: `netns_setup`, `create_veth`, `add_address`, `start_dnsmasq`, `cleanup`, `assert_has_address`, `assert_link_up`.

---

## Requirements

From the spec's acceptance criteria, the technical requirements break down as:

1. **Dual-socket DHCP client** (critical): Packet socket (`AF_PACKET/SOCK_DGRAM/ETH_P_IP`) for the pre-IP DORA phase; UDP socket (`AF_INET/SOCK_DGRAM`) for post-IP renewals. Socket transition on DHCPACK.
2. **Packet socket send path**: Manual IP+UDP+DHCP frame. 20-byte IP header (src `0.0.0.0`, dst `255.255.255.255`, DF, proto UDP) + 8-byte UDP header (src 68, dst 67). RFC 1071 checksums. Send via `sockaddr_ll` with broadcast MAC `ff:ff:ff:ff:ff:ff`.
3. **Packet socket receive path**: Read IP+UDP+DHCP. Parse IHL. Userspace filter: drop non-UDP, fragmented, dst-port≠68, op≠BOOTREPLY(2), bad magic cookie (`0x63825363`). Validate checksums.
4. **UDP renewal socket**: Bind to acquired client IP on port 68 with `SO_BINDTODEVICE`. Unicast T1 renewal to `server_id:67`; broadcast T2 rebind.
5. **Socket transition on DHCPACK**: Drain packet socket, create UDP socket, close packet socket. On lease loss: close UDP, create fresh packet socket, restart DORA.
6. All other items (`DhcpLease`, `Dhcpv4Factory`, `lease_to_state`, daemon integration, tests) are already implemented.

---

## Gap Analysis

**Single gap**: `crates/netfyr-backend/src/dhcp/client.rs` — socket architecture.

### The problem

`create_dhcp_socket()` creates an `AF_INET/SOCK_DGRAM` UDP socket:

```rust
// client.rs:661
fn create_dhcp_socket(interface: &str) -> Result<UdpSocket, BackendError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
```

When `veth-dhcp0` has no IP address (the initial state in integration tests), the Linux kernel does not deliver broadcast UDP packets to this socket. The `recv_from` call in `recv_dhcp_response()` will block indefinitely — the integration tests will hang waiting for a DHCPOFFER that never arrives.

The spec states this explicitly: *"Using AF_INET/SOCK_DGRAM (a regular UDP socket) for the initial exchange will silently fail — the DISCOVER is sent but the OFFER never arrives at the application."*

Additionally, `DhcpContext.socket` is typed as `UdpSocket`, which can only hold an `AF_INET` socket; it cannot hold a packet socket.

### What must change in `client.rs`

1. **Replace `create_dhcp_socket()`** with two functions:
   - `create_packet_socket(ifindex: i32) -> Result<socket2::Socket, BackendError>` — `AF_PACKET/SOCK_DGRAM`, binds via `sockaddr_ll` (`sll_ifindex`, `sll_protocol = htons(ETH_P_IP)`).
   - `create_udp_renewal_socket(client_ip: Ipv4Addr, interface: &str) -> Result<tokio::net::UdpSocket, BackendError>` — `AF_INET/SOCK_DGRAM`, bind to `client_ip:68`, `SO_BINDTODEVICE`.

2. **Replace `DhcpContext.socket: UdpSocket`** with a type that can hold a packet socket. Since `tokio::net::UdpSocket` wraps only `AF_INET`/`AF_INET6`, the packet socket must be wrapped as `tokio::io::unix::AsyncFd<socket2::Socket>` (set to non-blocking mode first).

3. **Add raw frame construction**:
   - `build_ip_udp_dhcp(dhcp_payload: &[u8]) -> Vec<u8>` — prepends 20-byte IP header + 8-byte UDP header with correct checksums.
   - `ip_checksum(header: &[u8]) -> u16` — RFC 1071.
   - `udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp: &[u8]) -> u16` — includes pseudo-header.

4. **Add `sockaddr_ll` send**: `socket2::Socket::send_to()` does not accept `sockaddr_ll`. Sending requires `unsafe { libc::sendto(..., &sockaddr_ll as *const _, size_of::<libc::sockaddr_ll>()) }`.

5. **Add packet socket receive and filter**:
   - Read raw IP+UDP+DHCP using `AsyncFd::readable()` + `socket2::Socket::recv()`.
   - Parse IP IHL (byte 0 & 0x0F, scaled by 4) to locate UDP header.
   - Userspace filter: proto≠UDP(17), MF or fragment offset set, dst port≠68, DHCP op byte≠2, magic≠0x63825363.
   - Extract DHCP payload (after UDP 8 bytes), decode via `dhcproto`.

6. **Rewrite `run_state_machine()`** to split into two phases:
   - Phase 1: packet socket for DISCOVER/OFFER/REQUEST/ACK.
   - On DHCPACK: drain packet socket (bounded time), create UDP socket bound to acquired IP, close packet socket.
   - Phase 2: UDP socket for T1/T2 renewal and DHCPRELEASE.
   - On lease loss: close UDP socket, create fresh packet socket, loop back to Phase 1.

7. **Interface index lookup**: `sockaddr_ll` requires `sll_ifindex`. Use `unsafe { libc::if_nametoindex(c_name) }` — this is simpler than an extra rtnetlink query and safe for nametoindex purposes.

8. **`libc` dependency**: `netfyr-backend/Cargo.toml` does not list `libc` as a direct dependency (it is transitive via `socket2`). The `libc::sendto`, `libc::sockaddr_ll`, and `libc::if_nametoindex` calls require it as an explicit dependency.

### Files that do NOT need changes

| File | Status |
|------|--------|
| `dhcp/lease.rs` | Complete |
| `dhcp/mod.rs` | Complete |
| `daemon/factory_manager.rs` | Complete |
| `daemon/reconciler.rs` | Complete |
| `daemon/main.rs` | Complete |
| `daemon/policy_store.rs` | Complete |
| `daemon/server.rs` | Complete |
| `netfyr-policy/src/lib.rs` | Complete |
| `tests/401-*.sh` | Complete |
| `tests/helpers.sh` | Complete |

---

## Integration Points

### `mod.rs` → `client.rs`

`Dhcpv4Factory::start()` (mod.rs:107) spawns the background task calling `client::run_dhcp_client()`. The function signature must remain:
```rust
pub(crate) async fn run_dhcp_client(
    interface: String, policy_name: String, priority: u32,
    state_tx: mpsc::Sender<FactoryEvent>,
    shared_state: Arc<Mutex<Option<State>>>,
    stop_rx: oneshot::Receiver<()>,
)
```

The pending state is set in `Dhcpv4Factory::start()` before the task is spawned — the task must not reset `shared_state` to `None` at startup.

### `client.rs` → `mod.rs`

`run_dhcp_client()` calls `crate::dhcp::lease_to_state()` after every DHCPACK (initial and renewal) and calls `crate::dhcp::FactoryEvent::*` variants. These remain unchanged.

### `lease_to_state()` field contract

Fields in the `State` produced by `lease_to_state()` are applied by `netlink/apply.rs`. Field names (`"operstate"`, `"addresses"`, `"routes"`, `"dns_servers"`) and value shapes (`Value::String("ip/prefix")`, `Value::Map { "destination", "gateway" }`) must match the ethernet schema exactly.

### `FactoryManager` → `Reconciler`

`FactoryManager::produced_states()` is called from `Reconciler::build_policy_inputs()`. States include the pending state (operstate only) before lease acquisition, and the full state after. The reconciler doesn't distinguish them; both are valid desired states for the `"ethernet"` entity.

### `BackendRegistry` scope

`Dhcpv4Factory` does NOT implement `NetworkBackend` and is not registered with `BackendRegistry`. It interacts with the reconciliation loop only via factory-produced `State` objects fed into `merge()`.

---

## Risks

### 1. `sockaddr_ll` construction requires `unsafe` Rust

Sending via a packet socket to a broadcast MAC requires constructing a `libc::sockaddr_ll` struct and calling `libc::sendto()`. This is `unsafe`. Incorrect zero-initialization or wrong field values (e.g., wrong byte order for `sll_protocol`) will silently fail — packets are sent but not delivered.

### 2. `AsyncFd` pattern for packet socket in tokio

`tokio::net::UdpSocket` cannot wrap `AF_PACKET` sockets. Using `tokio::io::unix::AsyncFd<socket2::Socket>` requires setting the socket to non-blocking mode before wrapping, and polling `readable()` before each `recv()`. The `async_fd.readable().await?.try_io(|s| s.get_ref().recv(...))` pattern is correct but less familiar than `UdpSocket::recv_from()`.

### 3. Checksum correctness

RFC 1071 IP and UDP checksums must be computed correctly. Common bugs: incorrect handling of odd-length payloads (padding byte must be 0 and included in the sum but not the length field), carry propagation, and the UDP pseudo-header field order. A wrong checksum causes silent drops by dnsmasq.

### 4. Packet socket drain boundary

The spec requires draining the packet socket before closing it on DHCPACK. The drain must be time-bounded. If dnsmasq retransmits a DHCPACK after the client has transitioned to UDP mode, the packet socket fd may have residual data. An unbounded drain would hang; no drain risks lingering fds.

### 5. Port 68 conflict on non-test systems

The UDP renewal socket binds to `client_ip:68`. In production, if `systemd-networkd`, `dhclient`, or another DHCP client is active on the same interface, it will also bind port 68 (or they will share it via `SO_REUSEPORT`). Integration tests avoid this via network namespaces; production deployment requires exclusive interface management.

### 6. `libc` as explicit dependency

`libc` is currently transitive via `socket2`. Adding direct calls to `libc::sendto`, `libc::sockaddr_ll`, and `libc::if_nametoindex` requires adding `libc` as an explicit `Cargo.toml` dependency to avoid relying on transitive version resolution.

### 7. Interface UP race condition

The DHCP background task opens its packet socket immediately on spawn, before reconciliation has a chance to bring the interface up in response to the pending state. If the interface is link-down when the task starts, the first DISCOVER may be sent before the link establishes, triggering the first backoff cycle. This is not a correctness issue (the backoff retry handles it) but adds latency to initial lease acquisition.
