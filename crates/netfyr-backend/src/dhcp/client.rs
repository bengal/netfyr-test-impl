//! DHCPv4 client state machine.
//!
//! This module implements the full DORA (Discover-Offer-Request-Acknowledge)
//! handshake plus lease maintenance (renew/rebind/expire/release) as a
//! long-running tokio task. It is spawned by `Dhcpv4Factory::start()` and
//! communicates via `FactoryEvent` messages and a shared `Arc<Mutex<Option<State>>>`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use futures::TryStreamExt;
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::new_connection;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use netfyr_state::State;

use crate::dhcp::lease::DhcpLease;
use crate::dhcp::{lease_to_state, FactoryEvent};
use crate::BackendError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Timeout for a single DHCP discover/request attempt.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(5);

/// Initial backoff delay on DHCP discovery failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum backoff delay between retry attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// DHCP client port (source port for client messages).
const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP server port (destination port for client messages).
const DHCP_SERVER_PORT: u16 = 67;

// ── Main client task ──────────────────────────────────────────────────────────

/// Entry point for the background DHCP client task.
///
/// Runs the full DHCP state machine: DORA handshake, lease maintenance
/// (renew/rebind/expire), and DHCPRELEASE on stop signal.
pub(crate) async fn run_dhcp_client(
    interface: String,
    policy_name: String,
    priority: u32,
    state_tx: mpsc::Sender<FactoryEvent>,
    shared_state: Arc<Mutex<Option<State>>>,
    stop_rx: oneshot::Receiver<()>,
) {
    let mut stop_rx = stop_rx;

    // Read the interface MAC address for chaddr field.
    let mac = match get_interface_mac(&interface).await {
        Ok(m) => m,
        Err(e) => {
            let _ = state_tx
                .send(FactoryEvent::Error {
                    policy_name: policy_name.clone(),
                    error: format!("failed to read MAC address for {interface}: {e}"),
                })
                .await;
            return;
        }
    };

    // Create and configure the DHCP socket.
    let socket = match create_dhcp_socket(&interface) {
        Ok(s) => s,
        Err(e) => {
            let _ = state_tx
                .send(FactoryEvent::Error {
                    policy_name: policy_name.clone(),
                    error: format!("failed to create DHCP socket on {interface}: {e}"),
                })
                .await;
            return;
        }
    };

    // Run the DHCP state machine.
    let ctx = DhcpContext {
        socket,
        mac,
        interface,
        policy_name,
        priority,
        state_tx,
        shared_state,
    };
    run_state_machine(ctx, &mut stop_rx).await;
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Context passed to the DHCP state machine. Groups parameters to avoid
/// exceeding clippy's too_many_arguments limit.
struct DhcpContext {
    socket: UdpSocket,
    mac: [u8; 6],
    interface: String,
    policy_name: String,
    priority: u32,
    state_tx: mpsc::Sender<FactoryEvent>,
    shared_state: Arc<Mutex<Option<State>>>,
}

async fn run_state_machine(
    ctx: DhcpContext,
    stop_rx: &mut oneshot::Receiver<()>,
) {
    let DhcpContext {
        socket,
        mac,
        interface,
        policy_name,
        priority,
        state_tx,
        shared_state,
    } = ctx;
    let mut backoff = INITIAL_BACKOFF;
    let broadcast_addr: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT));

    loop {
        // ── Discovery phase ───────────────────────────────────────────────────
        let xid: u32 = rand::random();
        let discover = build_discover(xid, mac);

        let encoded = match encode_message(&discover) {
            Ok(b) => b,
            Err(e) => {
                let _ = state_tx
                    .send(FactoryEvent::Error {
                        policy_name: policy_name.clone(),
                        error: format!("failed to encode DHCPDISCOVER: {e}"),
                    })
                    .await;
                return;
            }
        };

        if let Err(e) = socket.send_to(&encoded, broadcast_addr).await {
            let _ = state_tx
                .send(FactoryEvent::Error {
                    policy_name: policy_name.clone(),
                    error: format!("failed to send DHCPDISCOVER: {e}"),
                })
                .await;
            return;
        }

        // Wait for DHCPOFFER.
        let offer_result = tokio::select! {
            biased;
            _ = &mut *stop_rx => return,
            r = recv_dhcp_response(&socket, xid, MessageType::Offer, DISCOVER_TIMEOUT) => r,
        };

        let offer = match offer_result {
            Ok(msg) => {
                backoff = INITIAL_BACKOFF;
                msg
            }
            Err(e) => {
                let _ = state_tx
                    .send(FactoryEvent::Error {
                        policy_name: policy_name.clone(),
                        error: format!("DHCP discovery timeout or error: {e}"),
                    })
                    .await;
                let jitter = Duration::from_millis(u64::from(rand::random::<u16>()) % 1000);
                tokio::select! {
                    biased;
                    _ = &mut *stop_rx => return,
                    _ = tokio::time::sleep(backoff + jitter) => {},
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        // Extract offered IP and server ID from DHCPOFFER.
        let offered_ip = offer.yiaddr();
        let server_id = extract_server_id(offer.opts()).unwrap_or_else(|| offer.siaddr());

        // ── Request phase ─────────────────────────────────────────────────────
        let request = build_request(xid, mac, offered_ip, server_id);
        let encoded = match encode_message(&request) {
            Ok(b) => b,
            Err(e) => {
                let _ = state_tx
                    .send(FactoryEvent::Error {
                        policy_name: policy_name.clone(),
                        error: format!("failed to encode DHCPREQUEST: {e}"),
                    })
                    .await;
                return;
            }
        };

        if let Err(e) = socket.send_to(&encoded, broadcast_addr).await {
            let _ = state_tx
                .send(FactoryEvent::Error {
                    policy_name: policy_name.clone(),
                    error: format!("failed to send DHCPREQUEST: {e}"),
                })
                .await;
            return;
        }

        // Wait for DHCPACK.
        let ack_result = tokio::select! {
            biased;
            _ = &mut *stop_rx => return,
            r = recv_dhcp_response(&socket, xid, MessageType::Ack, DISCOVER_TIMEOUT) => r,
        };

        let ack = match ack_result {
            Ok(msg) => msg,
            Err(e) => {
                let _ = state_tx
                    .send(FactoryEvent::Error {
                        policy_name: policy_name.clone(),
                        error: format!("DHCPACK not received: {e}"),
                    })
                    .await;
                let jitter = Duration::from_millis(u64::from(rand::random::<u16>()) % 1000);
                tokio::select! {
                    biased;
                    _ = &mut *stop_rx => return,
                    _ = tokio::time::sleep(backoff + jitter) => {},
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        // Parse the lease from DHCPACK.
        let lease = match parse_ack(&ack) {
            Ok(l) => l,
            Err(e) => {
                let _ = state_tx
                    .send(FactoryEvent::Error {
                        policy_name: policy_name.clone(),
                        error: format!("failed to parse DHCPACK: {e}"),
                    })
                    .await;
                let jitter = Duration::from_millis(u64::from(rand::random::<u16>()) % 1000);
                tokio::select! {
                    biased;
                    _ = &mut *stop_rx => return,
                    _ = tokio::time::sleep(backoff + jitter) => {},
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        // Build State and store it.
        let state = lease_to_state(&lease, &interface, &policy_name, priority);
        {
            let mut guard = shared_state.lock().unwrap();
            *guard = Some(state.clone());
        }

        // Send LeaseAcquired event.
        if state_tx
            .send(FactoryEvent::LeaseAcquired {
                policy_name: policy_name.clone(),
                state,
            })
            .await
            .is_err()
        {
            return; // Daemon has dropped the receiver; shut down.
        }

        // ── Lease maintenance loop ────────────────────────────────────────────
        let outcome = run_lease_maintenance(
            &socket,
            mac,
            &interface,
            &policy_name,
            priority,
            &state_tx,
            &shared_state,
            stop_rx,
            lease,
        )
        .await;

        match outcome {
            LeaseMaintOutcome::Stop => {
                let mut guard = shared_state.lock().unwrap();
                *guard = None;
                return;
            }
            LeaseMaintOutcome::Expired => {
                {
                    let mut guard = shared_state.lock().unwrap();
                    *guard = None;
                }
                let _ = state_tx
                    .send(FactoryEvent::LeaseExpired {
                        policy_name: policy_name.clone(),
                    })
                    .await;
                backoff = INITIAL_BACKOFF;
            }
        }
    }
}

// ── Lease maintenance ─────────────────────────────────────────────────────────

enum LeaseMaintOutcome {
    Stop,
    Expired,
}

#[allow(clippy::too_many_arguments)]
async fn run_lease_maintenance(
    socket: &UdpSocket,
    mac: [u8; 6],
    interface: &str,
    policy_name: &str,
    priority: u32,
    state_tx: &mpsc::Sender<FactoryEvent>,
    shared_state: &Arc<Mutex<Option<State>>>,
    stop_rx: &mut oneshot::Receiver<()>,
    mut lease: DhcpLease,
) -> LeaseMaintOutcome {
    loop {
        let renewal_wait = lease.time_until_renewal();
        let rebind_wait = lease.time_until_rebind();
        let expiry_wait = lease.time_until_expiry();

        tokio::select! {
            biased;

            // Stop signal: send DHCPRELEASE and exit.
            _ = &mut *stop_rx => {
                send_release(socket, mac, lease.ip, lease.server_id).await;
                return LeaseMaintOutcome::Stop;
            }

            // T1: attempt unicast renewal.
            _ = tokio::time::sleep(renewal_wait), if !renewal_wait.is_zero() => {
                if let Some(updated) = attempt_renewal(socket, mac, &lease, false).await {
                    lease = updated;
                    let state = lease_to_state(&lease, interface, policy_name, priority);
                    {
                        let mut guard = shared_state.lock().unwrap();
                        *guard = Some(state.clone());
                    }
                    let _ = state_tx
                        .send(FactoryEvent::LeaseRenewed {
                            policy_name: policy_name.to_string(),
                            state,
                        })
                        .await;
                }
                // If unicast renewal failed, continue; rebind timer will fire.
            }

            // T2: attempt broadcast rebinding.
            _ = tokio::time::sleep(rebind_wait), if !rebind_wait.is_zero() => {
                if let Some(updated) = attempt_renewal(socket, mac, &lease, true).await {
                    lease = updated;
                    let state = lease_to_state(&lease, interface, policy_name, priority);
                    {
                        let mut guard = shared_state.lock().unwrap();
                        *guard = Some(state.clone());
                    }
                    let _ = state_tx
                        .send(FactoryEvent::LeaseRenewed {
                            policy_name: policy_name.to_string(),
                            state,
                        })
                        .await;
                }
                // If rebind also failed, expiry timer will fire.
            }

            // Lease expiry.
            _ = tokio::time::sleep(expiry_wait) => {
                return LeaseMaintOutcome::Expired;
            }
        }
    }
}

/// Attempt a DHCP renewal or rebinding.
///
/// `broadcast = false` → unicast DHCPREQUEST to `lease.server_id`.
/// `broadcast = true`  → broadcast DHCPREQUEST to 255.255.255.255.
async fn attempt_renewal(
    socket: &UdpSocket,
    mac: [u8; 6],
    lease: &DhcpLease,
    broadcast: bool,
) -> Option<DhcpLease> {
    let xid: u32 = rand::random();
    let request = build_renew_request(xid, mac, lease.ip, lease.server_id);
    let encoded = encode_message(&request).ok()?;

    let dest: SocketAddr = if broadcast {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT))
    } else {
        SocketAddr::V4(SocketAddrV4::new(lease.server_id, DHCP_SERVER_PORT))
    };

    socket.send_to(&encoded, dest).await.ok()?;

    recv_dhcp_response(socket, xid, MessageType::Ack, DISCOVER_TIMEOUT)
        .await
        .ok()
        .and_then(|ack| parse_ack(&ack).ok())
}

/// Send a DHCPRELEASE to the server.
async fn send_release(socket: &UdpSocket, mac: [u8; 6], client_ip: Ipv4Addr, server_id: Ipv4Addr) {
    let release = build_release(mac, client_ip, server_id);
    if let Ok(encoded) = encode_message(&release) {
        let dest: SocketAddr = SocketAddr::V4(SocketAddrV4::new(server_id, DHCP_SERVER_PORT));
        let _ = socket.send_to(&encoded, dest).await;
    }
}

// ── Receive helper ────────────────────────────────────────────────────────────

/// Receive and validate a DHCP response matching `xid` and `expected_type`.
///
/// Ignores packets that don't match. Returns an error if the timeout elapses
/// or if a DHCPNAK is received.
async fn recv_dhcp_response(
    socket: &UdpSocket,
    xid: u32,
    expected_type: MessageType,
    timeout: Duration,
) -> Result<Message, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0u8; 1500];

    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| "DHCP response timeout".to_string())?;

        let n = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| "DHCP response timeout".to_string())?
            .map_err(|e| format!("socket recv error: {e}"))?
            .0;

        let msg = Message::decode(&mut Decoder::new(&buf[..n]))
            .map_err(|e| format!("failed to decode DHCP message: {e}"))?;

        // Filter by XID.
        if msg.xid() != xid {
            continue;
        }

        // Check for DHCPNAK — abort immediately.
        let msg_type = extract_msg_type(msg.opts());
        if msg_type == Some(MessageType::Nak) {
            return Err("received DHCPNAK from server".to_string());
        }

        // Check expected message type.
        if msg_type == Some(expected_type) {
            return Ok(msg);
        }
    }
}

// ── Option extraction helpers ─────────────────────────────────────────────────

/// Extract the MessageType option from DhcpOptions.
fn extract_msg_type(opts: &dhcproto::v4::DhcpOptions) -> Option<MessageType> {
    match opts.get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(mt)) => Some(*mt),
        _ => None,
    }
}

/// Extract the ServerIdentifier option from DhcpOptions.
fn extract_server_id(opts: &dhcproto::v4::DhcpOptions) -> Option<Ipv4Addr> {
    match opts.get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

// ── Packet builders ───────────────────────────────────────────────────────────

fn build_discover(xid: u32, mac: [u8; 6]) -> Message {
    let mut msg = Message::default();
    msg.set_xid(xid)
        .set_flags(Flags::default().set_broadcast())
        .set_chaddr(&mac);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(mac.to_vec()));
    msg.opts_mut()
        .insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::DomainNameServer,
            OptionCode::DomainName,
            OptionCode::AddressLeaseTime,
            OptionCode::ServerIdentifier,
            OptionCode::Renewal,
            OptionCode::Rebinding,
        ]));
    msg
}

fn build_request(
    xid: u32,
    mac: [u8; 6],
    requested_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) -> Message {
    let mut msg = Message::default();
    msg.set_xid(xid)
        .set_flags(Flags::default().set_broadcast())
        .set_chaddr(&mac);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(DhcpOption::RequestedIpAddress(requested_ip));
    msg.opts_mut()
        .insert(DhcpOption::ServerIdentifier(server_id));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(mac.to_vec()));
    msg.opts_mut()
        .insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::DomainNameServer,
            OptionCode::DomainName,
            OptionCode::AddressLeaseTime,
            OptionCode::ServerIdentifier,
            OptionCode::Renewal,
            OptionCode::Rebinding,
        ]));
    msg
}

/// Build a DHCPREQUEST for renewal/rebinding. Sets `ciaddr` to the current IP.
fn build_renew_request(xid: u32, mac: [u8; 6], ciaddr: Ipv4Addr, server_id: Ipv4Addr) -> Message {
    let mut msg = Message::default();
    msg.set_xid(xid).set_ciaddr(ciaddr).set_chaddr(&mac);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(DhcpOption::ServerIdentifier(server_id));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(mac.to_vec()));
    msg
}

fn build_release(mac: [u8; 6], client_ip: Ipv4Addr, server_id: Ipv4Addr) -> Message {
    let mut msg = Message::default();
    msg.set_ciaddr(client_ip).set_chaddr(&mac);
    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Release));
    msg.opts_mut()
        .insert(DhcpOption::ServerIdentifier(server_id));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(mac.to_vec()));
    msg
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

/// Parse a DHCPACK message into a `DhcpLease`.
///
/// Returns an error string if required options (lease time) are missing.
fn parse_ack(msg: &Message) -> Result<DhcpLease, String> {
    let ip = msg.yiaddr();
    if ip.is_unspecified() {
        return Err("DHCPACK has no yiaddr (your IP)".to_string());
    }

    let opts = msg.opts();

    let lease_time = extract_u32(opts, OptionCode::AddressLeaseTime)
        .ok_or_else(|| "DHCPACK missing lease time (option 51)".to_string())?;

    let subnet_mask = extract_ipv4(opts, OptionCode::SubnetMask)
        .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));

    let gateway = match opts.get(OptionCode::Router) {
        Some(DhcpOption::Router(routers)) => routers.first().copied(),
        _ => None,
    };

    let dns_servers = match opts.get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(servers)) => servers.clone(),
        _ => vec![],
    };

    let server_id = extract_server_id(opts).unwrap_or_else(|| msg.siaddr());

    // T1 defaults to 50% of lease_time; T2 defaults to 87.5% of lease_time.
    let renewal_time = extract_u32(opts, OptionCode::Renewal).unwrap_or(lease_time / 2);
    let rebind_time = extract_u32(opts, OptionCode::Rebinding).unwrap_or(lease_time * 7 / 8);

    Ok(DhcpLease {
        ip,
        subnet_mask,
        gateway,
        dns_servers,
        lease_time,
        renewal_time,
        rebind_time,
        server_id,
        acquired_at: Instant::now(),
    })
}

/// Extract a u32 value from a DhcpOption.
fn extract_u32(opts: &dhcproto::v4::DhcpOptions, code: OptionCode) -> Option<u32> {
    match opts.get(code) {
        Some(DhcpOption::AddressLeaseTime(t)) => Some(*t),
        Some(DhcpOption::Renewal(t)) => Some(*t),
        Some(DhcpOption::Rebinding(t)) => Some(*t),
        _ => None,
    }
}

/// Extract an Ipv4Addr from single-IP options (SubnetMask, ServerIdentifier, etc.).
fn extract_ipv4(opts: &dhcproto::v4::DhcpOptions, code: OptionCode) -> Option<Ipv4Addr> {
    match opts.get(code) {
        Some(DhcpOption::SubnetMask(ip)) => Some(*ip),
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    }
}

// ── Socket setup ──────────────────────────────────────────────────────────────

/// Create and configure a UDP socket for DHCP client use.
///
/// - Sets `SO_BROADCAST` to send to 255.255.255.255.
/// - Sets `SO_BINDTODEVICE` (Linux) to restrict I/O to `interface`.
/// - Binds to `0.0.0.0:68` (standard DHCP client port).
/// - Converts to a non-blocking `tokio::net::UdpSocket`.
fn create_dhcp_socket(interface: &str) -> Result<UdpSocket, BackendError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| BackendError::Internal(format!("socket creation failed: {e}")))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| BackendError::Internal(format!("SO_REUSEADDR failed: {e}")))?;

    socket
        .set_broadcast(true)
        .map_err(|e| BackendError::Internal(format!("SO_BROADCAST failed: {e}")))?;

    // SO_BINDTODEVICE: Linux-only, restricts socket I/O to the named interface.
    #[cfg(target_os = "linux")]
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|e| BackendError::Internal(format!("SO_BINDTODEVICE failed: {e}")))?;

    let addr: std::net::SocketAddr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        DHCP_CLIENT_PORT,
    ));
    socket
        .bind(&addr.into())
        .map_err(|e| BackendError::Internal(format!("bind to 0.0.0.0:{DHCP_CLIENT_PORT} failed: {e}")))?;

    socket
        .set_nonblocking(true)
        .map_err(|e| BackendError::Internal(format!("set_nonblocking failed: {e}")))?;

    let std_socket = std::net::UdpSocket::from(socket);
    UdpSocket::from_std(std_socket)
        .map_err(|e| BackendError::Internal(format!("tokio UdpSocket conversion failed: {e}")))
}

// ── MAC address discovery ─────────────────────────────────────────────────────

/// Read the interface's MAC address via rtnetlink.
///
/// Uses the netlink API instead of `/sys/class/net/` because sysfs is not
/// network-namespace-aware in all environments (e.g., containers, unshare).
/// Netlink queries are always scoped to the calling process's network namespace.
async fn get_interface_mac(interface: &str) -> Result<[u8; 6], BackendError> {
    let (conn, handle, _) = new_connection()
        .map_err(|e| BackendError::Internal(format!("netlink connection failed: {e}")))?;
    tokio::spawn(conn);

    let mut links = handle
        .link()
        .get()
        .match_name(interface.to_string())
        .execute();

    let msg = links
        .try_next()
        .await
        .map_err(|e| {
            BackendError::Internal(format!(
                "netlink query failed for {interface}: {e}"
            ))
        })?
        .ok_or_else(|| {
            BackendError::Internal(format!("interface not found: {interface}"))
        })?;

    for attr in &msg.attributes {
        if let LinkAttribute::Address(bytes) = attr {
            if bytes.len() == 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(bytes);
                return Ok(mac);
            }
        }
    }

    Err(BackendError::Internal(format!(
        "no MAC address found for interface {interface}"
    )))
}

// ── Encoding helper ───────────────────────────────────────────────────────────

fn encode_message(msg: &Message) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc)
        .map_err(|e| format!("DHCP encode error: {e}"))?;
    Ok(buf)
}
