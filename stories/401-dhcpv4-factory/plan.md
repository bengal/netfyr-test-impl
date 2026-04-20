# Implementation Plan: SPEC-401 DHCPv4 Factory

## Approach

Most of this story is already implemented. `DhcpLease` (`lease.rs`), `Dhcpv4Factory`/`FactoryEvent`/`lease_to_state` (`mod.rs`), daemon integration (`factory_manager.rs`, `reconciler.rs`, `main.rs`, `policy_store.rs`), and all three shell integration test scripts are complete and correct. The DHCP client state machine logic in `client.rs` — DORA handshake flow, lease maintenance timers, exponential backoff, release — is structurally correct.

**The single critical gap** is the socket layer in `client.rs`. The current implementation uses `AF_INET/SOCK_DGRAM` (a standard UDP socket via `create_dhcp_socket()` at line 661) for all DHCP communication. This fundamentally cannot work: when an interface has no IP address (the initial state), the Linux kernel does not deliver broadcast UDP packets to `AF_INET` sockets bound to that interface. The DHCPOFFER from dnsmasq arrives at the kernel but is never delivered to userspace. The integration tests will hang indefinitely at `recv_dhcp_response()` (line 458) waiting for a DHCPOFFER that never arrives.

The fix implements the **dual-socket architecture** from the spec:

1. **Phase 1 (DORA)**: Use an `AF_PACKET/SOCK_DGRAM/ETH_P_IP` packet socket. This receives raw IP packets at the link layer, bypassing the kernel's IP stack. The application must construct IP+UDP headers manually when sending (with RFC 1071 checksums) and parse/filter them when receiving. The packet socket is wrapped in `tokio::io::unix::AsyncFd<OwnedFd>` since `tokio::net::UdpSocket` only supports `AF_INET`/`AF_INET6`.

2. **Phase 2 (Renewal/Rebind/Release)**: After DHCPACK, transition to an `AF_INET/SOCK_DGRAM` UDP socket bound to the acquired client IP on port 68. This is simpler (no manual framing) and supports unicast T1 renewal to the server.

The alternative — using only a packet socket for the entire lifecycle — would work functionally but adds unnecessary complexity to the renewal phase when the client already has a valid IP. The dual-socket approach matches production DHCP clients (dhclient, NetworkManager, n-dhcp4) and the spec requirement.

## Design Decisions

### 1. Packet socket type: `AF_PACKET/SOCK_DGRAM`, not `SOCK_RAW`
- **Decision**: Use `SOCK_DGRAM` for the packet socket.
- **Alternatives**: `SOCK_RAW` gives raw Ethernet frames including the Ethernet header.
- **Rationale**: `SOCK_DGRAM` has the kernel strip/add Ethernet headers automatically, so we only construct IP+UDP headers, not full Ethernet frames. Simpler, works with any link layer. Mandated by the spec.

### 2. Async wrapper: `AsyncFd<OwnedFd>` for the packet socket
- **Decision**: Wrap the packet socket fd in `tokio::io::unix::AsyncFd<OwnedFd>`.
- **Alternatives**: (a) `tokio::net::UdpSocket` — impossible, only wraps `AF_INET`/`AF_INET6`. (b) Blocking I/O on a spawned blocking thread — harder to integrate with `tokio::select!` for stop signals and timeouts.
- **Rationale**: `AsyncFd` integrates cleanly with tokio's event loop and `select!`. We wrap an `OwnedFd` for clean ownership semantics and automatic fd close on drop. Socket must be set non-blocking before wrapping.

### 3. Sending: `libc::sendto()` with `sockaddr_ll`
- **Decision**: Use raw `libc::sendto()` with a manually constructed `sockaddr_ll` struct.
- **Alternatives**: `socket2::Socket::send_to()` — its `SockAddr` type does not support `sockaddr_ll` (only `AF_INET`/`AF_INET6`/`AF_UNIX`).
- **Rationale**: Direct `libc::sendto()` is the only way to specify a `sockaddr_ll` destination with the broadcast MAC (`ff:ff:ff:ff:ff:ff`). Requires `unsafe` but is a well-understood, minimal pattern.

### 4. Interface index: `libc::if_nametoindex()`
- **Decision**: Use `libc::if_nametoindex()` to get `sll_ifindex`.
- **Alternatives**: Query via rtnetlink `LinkGet` — adds an async call and connection setup for a single integer.
- **Rationale**: `if_nametoindex()` is synchronous, simple, and namespace-aware. It works correctly inside `unshare --user --net` (it queries the calling process's network namespace via netlink internally).

### 5. Socket state representation: enum, not two Options
- **Decision**: Do NOT use a `SocketState` enum in `DhcpContext`. Instead, restructure the state machine so each phase creates its own socket locally. The DORA phase creates and owns a packet socket; after DHCPACK, it drops the packet socket and creates a UDP socket that it passes to `run_lease_maintenance()`.
- **Alternatives**: (a) `enum SocketState { Packet(AsyncFd<OwnedFd>), Udp(UdpSocket) }` in `DhcpContext` — adds match arms everywhere. (b) Two `Option` fields — allows invalid states.
- **Rationale**: The cleanest approach is to let each phase own its socket on the stack. The DORA loop uses a packet socket variable; on DHCPACK success, it drops the packet socket, creates a UDP socket, and passes it to `run_lease_maintenance()`. If the lease expires, `run_lease_maintenance` returns, the UDP socket is dropped, and the outer loop creates a new packet socket. This matches the existing code structure where `run_state_machine` calls `run_lease_maintenance` with a socket reference.

### 6. Checksum and framing functions: inline in `client.rs`
- **Decision**: `ip_checksum()`, `udp_checksum()`, and `build_ip_udp_frame()` are private functions in `client.rs`.
- **Alternatives**: Separate `framing.rs` module.
- **Rationale**: These are small (~20 lines each), used only by the DHCP packet socket code. A separate module would be premature abstraction.

### 7. Packet socket drain on DHCPACK: bounded loop
- **Decision**: After DHCPACK, drain the packet socket with a bounded non-blocking loop (up to 10 reads) before dropping it.
- **Alternatives**: (a) No drain — risk of kernel warnings on close with unread data. (b) Unbounded drain — could theoretically hang if traffic is continuous.
- **Rationale**: Bounded drain is safe and handles the common case of dnsmasq retransmitting. 10 reads is generous enough; after the DORA handshake, there should be at most 1-2 retransmitted ACKs.

### 8. Preserve `run_dhcp_client()` signature
- **Decision**: The public entry point signature remains unchanged.
- **Alternatives**: N/A — changing it would break `mod.rs` callers.
- **Rationale**: `mod.rs` (line 128) calls `client::run_dhcp_client()` with `(interface, policy_name, priority, state_tx, shared_state, stop_rx)`. This signature is correct and must not change.

## File Changes

### 1. `crates/netfyr-backend/Cargo.toml`
- **Action**: Modify
- **What**: Add `libc = "0.2"` to `[dependencies]`.
- **Why**: Required for direct calls to `libc::socket()` (AF_PACKET), `libc::bind()` with `sockaddr_ll`, `libc::sendto()` with `sockaddr_ll`, `libc::recv()`, `libc::if_nametoindex()`, `libc::fcntl()` (F_SETFL, O_NONBLOCK), and constants (`AF_PACKET`, `SOCK_DGRAM`, `ETH_P_IP`, etc.). While `libc` is a transitive dependency via `socket2`/`rtnetlink`, direct use of its symbols requires an explicit dependency.

### 2. `crates/netfyr-backend/src/dhcp/client.rs`
- **Action**: Modify (substantial rewrite of socket and I/O layer; state machine structure and all DHCP message building/parsing functions preserved)

**Imports to change**:
- Add: `std::os::fd::{AsRawFd, OwnedFd, FromRawFd}`, `std::io`, `std::ffi::CString`, `tokio::io::unix::AsyncFd`
- Remove from top-level: the unconditional `use tokio::net::UdpSocket` (still used locally in the renewal phase)
- Add: `use tokio::net::UdpSocket` where needed for the renewal socket

**New function `get_ifindex(interface: &str) -> Result<i32, BackendError>`**:
- Convert interface name to `CString`.
- Call `unsafe { libc::if_nametoindex(c_name.as_ptr()) }`.
- Returns 0 on failure → map to `BackendError::Internal("interface not found: {interface}")`.
- Cast the nonzero result to `i32` for use in `sockaddr_ll.sll_ifindex`.

**New function `create_packet_socket(ifindex: i32) -> Result<AsyncFd<OwnedFd>, BackendError>`**:
- Call `unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, (libc::ETH_P_IP as u16).to_be() as i32) }`.
  - Note: `sll_protocol` and the socket protocol argument must be in network byte order (big-endian). Use `.to_be()` on the host value.
- Check fd >= 0; on error, return `io::Error::last_os_error()`.
- Build `libc::sockaddr_ll` (zero-initialized via `std::mem::zeroed()`):
  - `sll_family = libc::AF_PACKET as u16`
  - `sll_protocol = (libc::ETH_P_IP as u16).to_be()`
  - `sll_ifindex = ifindex`
  - All other fields zero (sll_hatype, sll_pkttype, sll_halen, sll_addr).
- Call `unsafe { libc::bind(fd, &sockaddr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) }`.
- Set non-blocking: `unsafe { libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK) }`.
- Wrap: `let owned = unsafe { OwnedFd::from_raw_fd(fd) }; AsyncFd::new(owned)`.
- On any error after `socket()` succeeds, close the fd before returning (or rely on `OwnedFd` drop if already wrapped).

**New function `create_udp_renewal_socket(client_ip: Ipv4Addr, interface: &str) -> Result<UdpSocket, BackendError>`**:
- Create via `socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))`.
- Set `SO_REUSEADDR`, `SO_BROADCAST`.
- Set `SO_BINDTODEVICE` to `interface` via `socket.bind_device(Some(interface.as_bytes()))`.
- Bind to `SocketAddrV4::new(client_ip, 68)`.
- Set non-blocking, convert to `tokio::net::UdpSocket`.
- This replaces `create_dhcp_socket()` for the renewal phase. The key difference: binds to `client_ip:68` instead of `0.0.0.0:68`.

**New function `ip_checksum(data: &[u8]) -> u16`**:
- RFC 1071 one's-complement checksum.
- Sum all 16-bit words as `u32`. If data has odd length, treat the last byte as `(byte << 8)` (MSB of a zero-padded 16-bit word).
- Fold carries: while accumulator > 0xFFFF, add the upper 16 bits to the lower 16 bits.
- Return the bitwise complement (`!sum as u16`).

**New function `udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_header_and_payload: &[u8]) -> u16`**:
- Build a 12-byte pseudo-header: `src_ip` (4 bytes, network order), `dst_ip` (4 bytes, network order), zero byte, protocol=17, UDP length (2 bytes, network order, = `udp_header_and_payload.len()`).
- Concatenate pseudo-header bytes + `udp_header_and_payload` into a temporary buffer.
- Compute `ip_checksum()` over the concatenation.
- If result is 0, return 0xFFFF (per RFC 768: transmitted checksum of zero means "no checksum computed"; to distinguish, an actual zero result must be encoded as all-ones).

**New function `build_ip_udp_frame(dhcp_payload: &[u8]) -> Vec<u8>`**:
- Total frame size: 20 (IP header) + 8 (UDP header) + `dhcp_payload.len()`.
- **IP header** (20 bytes at offset 0):
  - Byte 0: `0x45` (version=4, IHL=5, no options)
  - Byte 1: `0x00` (TOS/DSCP)
  - Bytes 2-3: total length = `(28 + dhcp_payload.len()) as u16`, big-endian
  - Bytes 4-5: identification = `rand::random::<u16>()`, big-endian
  - Bytes 6-7: flags + fragment offset = `0x0000` (no flags, no fragmentation). Note: the DF flag (0x4000) is optional here — dnsmasq accepts either. Using 0x0000 is simpler and works.
  - Byte 8: TTL = 64
  - Byte 9: protocol = 17 (UDP)
  - Bytes 10-11: header checksum = 0 (placeholder, computed next)
  - Bytes 12-15: source IP = `0.0.0.0`
  - Bytes 16-19: destination IP = `255.255.255.255`
  - Compute `ip_checksum(&frame[0..20])`, write result at bytes 10-11 (big-endian).
- **UDP header** (8 bytes at offset 20):
  - Bytes 20-21: source port = 68, big-endian
  - Bytes 22-23: destination port = 67, big-endian
  - Bytes 24-25: UDP length = `(8 + dhcp_payload.len()) as u16`, big-endian
  - Bytes 26-27: UDP checksum = 0 (placeholder)
  - Copy `dhcp_payload` starting at offset 28.
  - Compute `udp_checksum(0.0.0.0, 255.255.255.255, &frame[20..])`, write at bytes 26-27 (big-endian).

**New function `send_via_packet_socket(async_fd: &AsyncFd<OwnedFd>, ifindex: i32, frame: &[u8]) -> Result<(), BackendError>`**:
- Build `libc::sockaddr_ll` (zero-initialized):
  - `sll_family = libc::AF_PACKET as u16`
  - `sll_protocol = (libc::ETH_P_IP as u16).to_be()`
  - `sll_ifindex = ifindex`
  - `sll_halen = 6`
  - `sll_addr = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]` (broadcast MAC, padded to 8 bytes)
- Use `async_fd.writable().await` then `try_io(|inner| { ... })`.
- Inside `try_io`: `unsafe { libc::sendto(inner.get_ref().as_raw_fd(), frame.as_ptr() as *const libc::c_void, frame.len(), 0, &sockaddr_ll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) }`.
- Check return value; -1 means error → `io::Error::last_os_error()`.
- Map `WouldBlock` to retry (handled by `try_io`).

**New function `recv_from_packet_socket(async_fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize>`**:
- Use `async_fd.readable().await?.try_io(|inner| { ... })`.
- Inside `try_io`: `unsafe { libc::recv(inner.get_ref().as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) }`.
- Return value < 0 → `Err(io::Error::last_os_error())`. Return value 0 → `Err(UnexpectedEof)` or treat as empty read.
- The `try_io` pattern automatically handles `WouldBlock` by re-registering for readability.

**New function `recv_dhcp_from_packet(async_fd: &AsyncFd<OwnedFd>, buf: &mut [u8], xid: u32, expected_type: MessageType, timeout: Duration) -> Result<Message, String>`**:
- This replaces `recv_dhcp_response` for the packet socket phase.
- Loop with deadline (same timeout pattern as existing `recv_dhcp_response`):
  - Call `recv_from_packet_socket()` with a timeout.
  - **Parse and filter the IP+UDP+DHCP packet**:
    1. Check minimum size >= 28 bytes (IP + UDP minimum). Skip if too small.
    2. IP version check: `(buf[0] >> 4) == 4`. Skip if not IPv4.
    3. Extract IHL: `(buf[0] & 0x0F) as usize * 4`. Skip if IHL < 20 or IHL > n.
    4. Check IP protocol: `buf[9] == 17` (UDP). Skip if not UDP.
    5. Check fragmentation: bytes 6-7 big-endian as u16. If `(flags_frag & 0x1FFF) != 0` (fragment offset nonzero) OR `(flags_frag & 0x2000) != 0` (MF flag), skip. (We cannot reassemble fragments.)
    6. Check minimum size for UDP header: `n >= ihl + 8`. Skip if too small.
    7. Extract UDP dst_port: `u16::from_be_bytes([buf[ihl+2], buf[ihl+3]])`. Skip if not 68.
    8. Extract DHCP payload: `&buf[ihl+8..n]`.
    9. Check DHCP minimum: payload length >= 240 (minimum DHCP message). Skip if too small.
    10. Check DHCP op: `payload[0] == 2` (BOOTREPLY). Skip if not.
    11. Check magic cookie: `payload[236..240] == [0x63, 0x82, 0x53, 0x63]`. Skip if not.
    12. Decode via `Message::decode(&mut Decoder::new(payload))`. Skip on decode error.
  - **XID and message type filtering** (same as existing code):
    - Check `msg.xid() == xid`. Skip if mismatch.
    - Check for NAK → return error.
    - Check for expected message type → return `Ok(msg)`.

**Rewrite `run_state_machine()`**:
- Remove `DhcpContext.socket` field. Replace with `ifindex: i32`.
- The outer retry loop becomes:
  ```
  loop {
      // Create packet socket for this DORA attempt
      let packet_socket = create_packet_socket(ifindex)?;

      // DISCOVER: encode → build_ip_udp_frame → send_via_packet_socket
      // OFFER: recv_dhcp_from_packet(packet_socket, ..., Offer, timeout)
      //   On timeout → send Error event, backoff, drop packet_socket, continue loop
      // REQUEST: encode → build_ip_udp_frame → send_via_packet_socket
      // ACK: recv_dhcp_from_packet(packet_socket, ..., Ack, timeout)
      //   On timeout → send Error event, backoff, drop packet_socket, continue loop

      // DHCPACK received — transition sockets
      drain_packet_socket(&packet_socket);
      drop(packet_socket);

      let udp_socket = create_udp_renewal_socket(lease.ip, &interface)?;

      // Update shared state, send LeaseAcquired
      // ...

      // Lease maintenance on UDP socket
      let outcome = run_lease_maintenance(&udp_socket, mac, ..., stop_rx, lease).await;
      match outcome {
          Stop => { /* DHCPRELEASE sent inside run_lease_maintenance */ return; }
          Expired => { /* drop udp_socket, send LeaseExpired, continue outer loop */ }
      }
  }
  ```

- The key structural change: the packet socket is created at the top of each iteration of the outer loop and dropped after DHCPACK. The UDP socket is created after DHCPACK and dropped on lease expiry. This naturally implements the socket lifecycle.

**Update `run_dhcp_client()` entry point** (line 50):
- After `get_interface_mac()` succeeds, call `get_ifindex(&interface)` to get the interface index.
- Remove the `create_dhcp_socket()` call (lines 75-86).
- Pass `ifindex` to the state machine context instead of `socket`.
- Error handling for `get_ifindex` failure: send `FactoryEvent::Error` and return (same pattern as MAC failure).

**Update `run_lease_maintenance()`** (line 330):
- The function signature stays the same: it takes `socket: &UdpSocket`. But now this is specifically the renewal UDP socket, not the DORA socket.
- `attempt_renewal()` and `send_release()` continue to use `UdpSocket` — no changes needed since they operate in Phase 2 when we have a valid IP.

**Delete `create_dhcp_socket()`** (lines 661-694):
- Replaced by `create_packet_socket()` and `create_udp_renewal_socket()`.

**New function `drain_packet_socket(async_fd: &AsyncFd<OwnedFd>)`**:
- Non-blocking loop: up to 10 iterations.
- Each iteration: attempt `try_io` recv. On `WouldBlock` or any error, stop.
- Discard all received data. This is best-effort cleanup before closing the fd.

**Functions that remain UNCHANGED** (preserving their current correct implementations):
- `get_interface_mac()` (line 703) — already uses rtnetlink, correct
- `build_discover()` (line 505) — DHCP message construction is socket-agnostic
- `build_request()` (line 528) — same
- `build_renew_request()` (line 561) — same
- `build_release()` (line 573) — same
- `parse_ack()` (line 590) — lease parsing from DHCPACK is unchanged
- `extract_msg_type()` (line 488) — option extraction, unchanged
- `extract_server_id()` (line 496) — same
- `extract_u32()` (line 634) — same
- `extract_ipv4()` (line 644) — same
- `encode_message()` (line 743) — DHCP encoding, unchanged
- `run_lease_maintenance()` (line 330) — structure unchanged, still receives `&UdpSocket`
- `attempt_renewal()` (line 405) — uses UDP socket for renewal, unchanged
- `send_release()` (line 430) — uses UDP socket for release, unchanged
- `recv_dhcp_response()` (line 444) — still used by `attempt_renewal` for UDP recv during renewal phase; unchanged
- All constants (lines 30-42) — unchanged

**Why this file**: This is the only file with a correctness gap. Every other file in the DHCP, daemon, policy, CLI, and test layers is complete.

### Files that do NOT need changes

| File | Status | Reason |
|------|--------|--------|
| `dhcp/lease.rs` | Complete | All fields, methods, 15 unit tests |
| `dhcp/mod.rs` | Complete | `Dhcpv4Factory`, `FactoryEvent`, `lease_to_state`, `pending_state`, `interface_exists`, 18 unit tests |
| `lib.rs` (backend) | Complete | Re-exports correct |
| `daemon/factory_manager.rs` | Complete | Factory lifecycle, 14 tests |
| `daemon/reconciler.rs` | Complete | Restricts actual set to managed entities |
| `daemon/main.rs` | Complete | Startup sequence and event loop |
| `daemon/policy_store.rs` | Complete | Policy persistence and reload |
| `daemon/server.rs` | Complete | Varlink server |
| `netfyr-policy/src/lib.rs` | Complete | `FactoryType::Dhcpv4` variant |
| `tests/401-dhcpv4-acquire-lease.sh` | Complete | Correct test topology |
| `tests/401-dhcpv4-unmanaged-interface.sh` | Complete | Verifies unmanaged untouched |
| `tests/401-dhcpv4-daemon-restart.sh` | Complete | Verifies policy reload |
| `tests/helpers.sh` | Complete | All helpers present |

## Dependencies

### New: `libc = "0.2"`

**Justification**: Required for:
- `libc::socket()` with `AF_PACKET`, `SOCK_DGRAM`, `ETH_P_IP` — `socket2` does not support `AF_PACKET` domain sockets.
- `libc::sockaddr_ll` — the packet socket address structure, not modeled by `socket2::SockAddr`.
- `libc::bind()` with `sockaddr_ll` — `socket2::Socket::bind()` only accepts `SockAddr`.
- `libc::sendto()` with `sockaddr_ll` destination — `socket2::Socket::send_to()` doesn't support `sockaddr_ll`.
- `libc::recv()` — for reading from the packet socket fd.
- `libc::if_nametoindex()` — get interface index for `sll_ifindex`.
- `libc::fcntl()` with `F_SETFL`/`O_NONBLOCK` — set non-blocking before `AsyncFd` wrapping.

`libc` is already a transitive dependency (via `socket2`, `rtnetlink`, `tokio`, etc.) so it adds no new compiled code.

### Existing dependencies (unchanged)

- `socket2 = "0.5"` — still used for the UDP renewal socket.
- `dhcproto = "0.14"` — DHCP message encoding/decoding.
- `tokio` with `"net"` feature — provides `AsyncFd` (already enabled).
- `rand = "0.9"` — XID generation and IP identification field.

## Implementation Order

### Step 1: Add `libc` dependency
Add `libc = "0.2"` to `crates/netfyr-backend/Cargo.toml` `[dependencies]`.

**Compilable**: Yes — unused dependency is harmless.

### Step 2: Add checksum and IP+UDP framing functions
Add `ip_checksum()`, `udp_checksum()`, and `build_ip_udp_frame()` as private functions in `client.rs`. These are pure computation with no I/O.

**Compilable**: Yes — new unused private functions. (Clippy will warn about dead code; suppress with `#[allow(dead_code)]` temporarily, or proceed directly to Step 5.)

### Step 3: Add packet socket creation and I/O functions
Add `get_ifindex()`, `create_packet_socket()`, `send_via_packet_socket()`, `recv_from_packet_socket()`, `recv_dhcp_from_packet()`, and `drain_packet_socket()` as private functions.

**Compilable**: Yes — new unused private functions.
**Depends on**: Step 1 (libc types and constants), Step 2 (checksums for framing).

### Step 4: Add `create_udp_renewal_socket()`
Add the UDP renewal socket factory function. Structurally similar to the existing `create_dhcp_socket()` but binds to a specific `client_ip:68`.

**Compilable**: Yes — new unused private function.

### Step 5: Rewrite `run_dhcp_client()` and `run_state_machine()`
This is the core integration step:
- Update `run_dhcp_client()`: add `get_ifindex()` call, remove `create_dhcp_socket()` call, pass `ifindex` to state machine.
- Rewrite `run_state_machine()`: packet socket for DORA phase, socket transition on DHCPACK, UDP socket for lease maintenance.
- Delete `create_dhcp_socket()`.

**Depends on**: Steps 2, 3, 4 (all helper functions must exist).
**Compilable**: Yes — the external signature of `run_dhcp_client()` is unchanged. `mod.rs` calls it with the same parameters.

### Step 6: Build and run unit tests
Run `cargo test -p netfyr-backend` and `cargo clippy -p netfyr-backend`. Fix any compilation errors or warnings. Existing unit tests in `lease.rs` and `mod.rs` must all pass (they don't touch the socket layer).

**Depends on**: Step 5.

### Step 7: Run integration tests
Run `make integration-test SPEC=401`. The three shell scripts validate end-to-end DHCP lease acquisition with dnsmasq in a user namespace. These are the definitive test — they will hang with the old UDP-only code and succeed with the packet socket.

**Depends on**: Step 6.

## Risks and Mitigations

### 1. `unsafe` code correctness in `sockaddr_ll` construction
**Risk**: Wrong byte order for `sll_protocol`, uninitialized fields, or incorrect struct size cause silent send/recv failures.
**Mitigation**: Zero-initialize with `std::mem::zeroed()`. Use `.to_be()` consistently for protocol fields. Check all libc return values. The integration tests with dnsmasq are the ultimate validation — if framing is wrong, the test times out with a clear failure message.

### 2. Checksum correctness
**Risk**: Wrong IP or UDP checksum causes dnsmasq to silently drop packets. Common bugs: odd-length handling, carry folding, pseudo-header field order.
**Mitigation**: Implement RFC 1071 precisely. Key details: odd-byte padding `(byte << 8)` not `(byte)`, iterative carry folding `while sum > 0xFFFF`, UDP zero → 0xFFFF. Add unit tests with known-good checksum values for a representative DHCP discover packet.

### 3. `AsyncFd` usage pattern
**Risk**: Misusing `readable()`/`try_io()` could cause busy-loops or hangs.
**Mitigation**: Always follow the canonical pattern: `async_fd.readable().await?.try_io(|fd| { ... })`. The `try_io` closure must return `Err(WouldBlock)` when the inner operation would block, which `libc::recv` does naturally (returns -1 with `errno = EAGAIN`). Map `EAGAIN`/`EWOULDBLOCK` to `io::ErrorKind::WouldBlock`.

### 4. Interface UP race condition
**Risk**: Packet socket DISCOVER is sent before reconciliation brings the interface UP (from pending state). The packet may be dropped.
**Mitigation**: This is handled by existing exponential backoff. First DISCOVER may timeout (1s), retry fires after backoff. By then, reconciliation has applied `operstate: up`. Adds ~1-2s to initial acquisition. Not a correctness issue.

### 5. Port 68 conflict
**Risk**: Another DHCP client binding port 68 on the same interface.
**Mitigation**: `SO_REUSEADDR` is set. Integration tests run in isolated namespaces. Production expects exclusive interface management.

### 6. `tokio` feature gates
**Risk**: `AsyncFd` requires tokio's `"net"` feature.
**Mitigation**: Already enabled: `tokio = { version = "1", features = ["rt", "net", "sync", "time", "macros"] }`. Verified in `Cargo.toml`.

### 7. Large DHCP response packets
**Risk**: A DHCP response larger than the recv buffer (1500 bytes) would be truncated.
**Mitigation**: Use a 2048-byte buffer for packet socket recv (matching typical Ethernet MTU with margin). DHCP messages rarely exceed ~576 bytes. The packet socket receives at the IP layer (no Ethernet header with `SOCK_DGRAM`), so 2048 bytes is more than sufficient.

## Test Strategy

### New unit tests needed (in `client.rs`)

**Checksum functions**:
- `ip_checksum()` with a known 20-byte IP header → verify against a precomputed checksum value.
- `ip_checksum()` with odd-length data → verify correct padding behavior.
- `udp_checksum()` with known src/dst IPs and payload → verify against precomputed value.
- `udp_checksum()` edge case: result of 0 → verify it returns 0xFFFF.

**IP+UDP framing**:
- `build_ip_udp_frame()` with a small test payload → verify: IP version/IHL byte is 0x45, total length field correct, protocol is 17, src is 0.0.0.0, dst is 255.255.255.255, UDP src port is 68, dst port is 67, UDP length correct, checksum fields are non-zero, payload bytes are at correct offset.

### Existing unit tests (must continue to pass)

- 15 tests in `lease.rs` — prefix conversion, expiry detection, timer calculations
- 18 tests in `mod.rs` — `lease_to_state` field correctness, pending state, factory lifecycle, error events
- 14 tests in `factory_manager.rs` — sync idempotency, factory start/stop, produced states
- Daemon tests in `reconciler.rs`, `server.rs`
- CLI tests for error message format
- Policy tests for `FactoryType::Dhcpv4`

### Integration tests (existing, must pass)

All three shell scripts validate end-to-end correctness:

1. **`401-dhcpv4-acquire-lease.sh`**: veth pair + dnsmasq + daemon + apply → verify DHCP address on client interface. This is the critical test that will fail with UDP-only and pass with packet socket.

2. **`401-dhcpv4-unmanaged-interface.sh`**: Same + additional veth pair with no policy → verify unmanaged interface retains UP state and MTU.

3. **`401-dhcpv4-daemon-restart.sh`**: Acquire lease → stop daemon → flush addresses → restart daemon → verify re-acquisition from persisted policy.

No new integration test scripts are needed.
