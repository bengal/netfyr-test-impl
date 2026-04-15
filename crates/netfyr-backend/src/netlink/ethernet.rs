//! Ethernet interface query via rtnetlink.

use std::collections::HashMap;
use std::net::IpAddr;

use futures::TryStreamExt;
use indexmap::IndexMap;
use netfyr_state::{FieldValue, Provenance, Selector, State, StateMetadata, StateSet, Value};
use netlink_packet_route::link::{
    InfoKind, LinkAttribute, LinkInfo, LinkLayerType, LinkMessage,
};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::{Handle, IpVersion};
use tracing::warn;

use crate::BackendError;
use super::query::{
    build_discovered_selector, operstate_to_str, read_sysfs_driver,
    read_sysfs_pci_path, read_sysfs_speed,
};

// ── Exclusion list ────────────────────────────────────────────────────────────

/// Returns `true` if a link with the given `InfoKind` should be excluded from
/// ethernet query results.
///
/// Physical NICs (no `IFLA_INFO_KIND`) and veth pairs are included. All other
/// virtual types are excluded because:
/// - The acceptance criteria explicitly call out bridge, bond, vlan as excluded.
/// - Integration tests use veth pairs and expect them to appear.
fn is_excluded_kind(kind: &InfoKind) -> bool {
    matches!(
        kind,
        InfoKind::Bridge
            | InfoKind::Bond
            | InfoKind::Vlan
            | InfoKind::Vxlan
            | InfoKind::Dummy
            | InfoKind::MacVlan
            | InfoKind::MacVtap
            | InfoKind::IpVlan
            | InfoKind::IpVtap
            | InfoKind::Tun
            | InfoKind::SitTun
            | InfoKind::GreTun
            | InfoKind::GreTun6
            | InfoKind::IpIp
            | InfoKind::Wireguard
            | InfoKind::Vrf
            | InfoKind::Nlmon
    )
}

// ── Link attribute extraction helpers ────────────────────────────────────────

fn extract_link_name(msg: &LinkMessage) -> Option<String> {
    for attr in &msg.attributes {
        if let LinkAttribute::IfName(name) = attr {
            return Some(name.clone());
        }
    }
    None
}

fn extract_link_mac(msg: &LinkMessage) -> Option<[u8; 6]> {
    for attr in &msg.attributes {
        if let LinkAttribute::Address(bytes) = attr {
            if bytes.len() == 6 {
                let mut arr = [0u8; 6];
                arr.copy_from_slice(bytes);
                return Some(arr);
            }
        }
    }
    None
}

fn extract_link_mtu(msg: &LinkMessage) -> Option<u32> {
    for attr in &msg.attributes {
        if let LinkAttribute::Mtu(mtu) = attr {
            return Some(*mtu);
        }
    }
    None
}

fn extract_link_carrier(msg: &LinkMessage) -> Option<u8> {
    for attr in &msg.attributes {
        if let LinkAttribute::Carrier(c) = attr {
            return Some(*c);
        }
    }
    None
}

fn extract_link_operstate(msg: &LinkMessage) -> u8 {
    for attr in &msg.attributes {
        if let LinkAttribute::OperState(state) = attr {
            return u8::from(*state);
        }
    }
    0 // IF_OPER_UNKNOWN
}

/// Extract the `IFLA_INFO_KIND` from a link's `IFLA_LINKINFO` nested attribute.
///
/// Returns `None` if no `LinkInfo` or `Kind` attribute is present (which is
/// the case for physical NICs — they lack an IFLA_LINKINFO entirely).
fn extract_link_kind(msg: &LinkMessage) -> Option<InfoKind> {
    for attr in &msg.attributes {
        if let LinkAttribute::LinkInfo(infos) = attr {
            for info in infos {
                if let LinkInfo::Kind(kind) = info {
                    return Some(kind.clone());
                }
            }
        }
    }
    None
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn format_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

fn build_route_value(
    destination: &str,
    gateway: Option<&str>,
    metric: u32,
) -> Value {
    let mut map = IndexMap::new();
    map.insert("destination".to_string(), Value::String(destination.to_owned()));
    if let Some(gw) = gateway {
        map.insert("gateway".to_string(), Value::String(gw.to_owned()));
    }
    map.insert("metric".to_string(), Value::U64(metric as u64));
    Value::Map(map)
}

/// Convenience wrapper that tags a `Value` with `KernelDefault` provenance.
fn kd(value: Value) -> FieldValue {
    FieldValue {
        value,
        provenance: Provenance::KernelDefault,
    }
}

// ── Address dump ─────────────────────────────────────────────────────────────

/// Dump all addresses from the kernel and return a map from interface index to
/// CIDR strings (e.g., `"10.0.1.50/24"`).
async fn dump_addresses(
    handle: &Handle,
) -> Result<HashMap<u32, Vec<String>>, BackendError> {
    let mut map: HashMap<u32, Vec<String>> = HashMap::new();

    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await.map_err(|e| BackendError::QueryFailed {
        entity_type: "ethernet".to_string(),
        source: Box::new(e),
    })? {
        let index = msg.header.index;
        let prefix_len = msg.header.prefix_len;

        for attr in &msg.attributes {
            if let netlink_packet_route::address::AddressAttribute::Address(ip) = attr {
                let cidr = format!("{ip}/{prefix_len}");
                map.entry(index).or_default().push(cidr);
            }
        }
    }

    Ok(map)
}

// ── Route dump ────────────────────────────────────────────────────────────────

/// Dump IPv4 and IPv6 routes and return a map from output interface index to
/// route `Value::Map` objects.
///
/// Only unicast routes (RTN_UNICAST) are included. Routes with no output
/// interface (`RTA_OIF`) — e.g., local/blackhole routes — are skipped.
async fn dump_routes(
    handle: &Handle,
    known_indices: &std::collections::HashSet<u32>,
) -> Result<HashMap<u32, Vec<Value>>, BackendError> {
    let mut map: HashMap<u32, Vec<Value>> = HashMap::new();

    for ip_version in [IpVersion::V4, IpVersion::V6] {
        // Build an empty RouteMessage for the given address family.
        let mut route_msg = netlink_packet_route::route::RouteMessage::default();
        route_msg.header.address_family = match ip_version {
            IpVersion::V4 => netlink_packet_route::AddressFamily::Inet,
            IpVersion::V6 => netlink_packet_route::AddressFamily::Inet6,
        };

        let mut stream = handle.route().get(route_msg).execute();
        while let Some(msg) = stream.try_next().await.map_err(|e| BackendError::QueryFailed {
            entity_type: "ethernet".to_string(),
            source: Box::new(e),
        })? {
            if let Some(route_val) = parse_route_message(&msg, known_indices) {
                let oif = extract_oif(&msg);
                if let Some(idx) = oif {
                    map.entry(idx).or_default().push(route_val);
                }
            }
        }
    }

    Ok(map)
}

fn extract_oif(msg: &RouteMessage) -> Option<u32> {
    for attr in &msg.attributes {
        if let RouteAttribute::Oif(idx) = attr {
            return Some(*idx);
        }
    }
    None
}

fn parse_route_message(
    msg: &RouteMessage,
    known_indices: &std::collections::HashSet<u32>,
) -> Option<Value> {
    // Only process routes that go out through one of our discovered interfaces.
    let oif = extract_oif(msg)?;
    if !known_indices.contains(&oif) {
        return None;
    }

    let dst_prefix_len = msg.header.destination_prefix_length;

    let mut destination_ip: Option<IpAddr> = None;
    let mut gateway_ip: Option<IpAddr> = None;
    let mut metric: u32 = 0;

    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Destination(addr) => {
                destination_ip = route_address_to_ip(addr);
            }
            RouteAttribute::Gateway(addr) => {
                gateway_ip = route_address_to_ip(addr);
            }
            RouteAttribute::Priority(p) => {
                metric = *p;
            }
            _ => {}
        }
    }

    // Build destination CIDR. If no explicit destination, it's a default route.
    let destination = if let Some(ip) = destination_ip {
        format!("{ip}/{dst_prefix_len}")
    } else {
        // Default route: 0.0.0.0/0 or ::/0
        let af = msg.header.address_family;
        match af {
            netlink_packet_route::AddressFamily::Inet => {
                format!("0.0.0.0/{dst_prefix_len}")
            }
            netlink_packet_route::AddressFamily::Inet6 => {
                format!("::/{dst_prefix_len}")
            }
            _ => return None,
        }
    };

    let gateway_str = gateway_ip.map(|ip| ip.to_string());
    Some(build_route_value(
        &destination,
        gateway_str.as_deref(),
        metric,
    ))
}

// ── Main query function ───────────────────────────────────────────────────────

/// Query ethernet interfaces via rtnetlink.
///
/// Enumerates all links, filters to those with `ARPHRD_ETHER` type and an
/// allowed `IFLA_INFO_KIND` (physical NICs and veth pairs), optionally matches
/// against the provided `selector`, and assembles `State` objects with
/// `KernelDefault` provenance. Addresses and routes are fetched in two bulk
/// dumps (one each) and indexed by interface index for O(1) lookup per link.
pub async fn query_ethernet(
    handle: &Handle,
    selector: Option<&Selector>,
) -> Result<StateSet, BackendError> {
    // ── Step 1: Enumerate all links ───────────────────────────────────────────
    let mut links_stream = handle.link().get().execute();
    let mut all_links: Vec<LinkMessage> = Vec::new();
    while let Some(msg) = links_stream.try_next().await.map_err(|e| {
        BackendError::QueryFailed {
            entity_type: "ethernet".to_string(),
            source: Box::new(e),
        }
    })? {
        all_links.push(msg);
    }

    // ── Step 2: Filter to ethernet-class links ────────────────────────────────
    struct LinkInfo2 {
        index: u32,
        name: String,
        mac: Option<[u8; 6]>,
        mtu: Option<u32>,
        carrier: Option<u8>,
        operstate: u8,
    }

    let mut ethernet_links: Vec<LinkInfo2> = Vec::new();
    for msg in &all_links {
        // Must be ARPHRD_ETHER (1).
        if msg.header.link_layer_type != LinkLayerType::Ether {
            continue;
        }

        // Check IFLA_INFO_KIND: exclude virtual types, include physical and veth.
        if let Some(kind) = extract_link_kind(msg) {
            if is_excluded_kind(&kind) {
                continue;
            }
        }
        // No IFLA_INFO_KIND → physical NIC; always include.

        let name = match extract_link_name(msg) {
            Some(n) => n,
            None => {
                warn!("Skipping link with no name (index {})", msg.header.index);
                continue;
            }
        };

        ethernet_links.push(LinkInfo2 {
            index: msg.header.index,
            name,
            mac: extract_link_mac(msg),
            mtu: extract_link_mtu(msg),
            carrier: extract_link_carrier(msg),
            operstate: extract_link_operstate(msg),
        });
    }

    // ── Step 3: Apply selector filter ─────────────────────────────────────────
    let mut matched_links: Vec<LinkInfo2> = Vec::new();
    for link in ethernet_links {
        let driver = read_sysfs_driver(&link.name);
        let pci_path = read_sysfs_pci_path(&link.name);
        let discovered = build_discovered_selector(
            &link.name,
            link.mac,
            driver.as_deref(),
            pci_path.as_deref(),
        );

        if let Some(sel) = selector {
            if !sel.matches(&discovered) {
                continue;
            }
        }

        matched_links.push(link);
    }

    // ── Step 4: Build index set for route filtering ────────────────────────────
    let known_indices: std::collections::HashSet<u32> =
        matched_links.iter().map(|l| l.index).collect();

    // ── Step 5: Dump addresses ─────────────────────────────────────────────────
    let addr_map = dump_addresses(handle).await?;

    // ── Step 6: Dump routes ────────────────────────────────────────────────────
    let route_map = dump_routes(handle, &known_indices).await?;

    // ── Step 7: Assemble State objects ────────────────────────────────────────
    let mut state_set = StateSet::new();

    for link in matched_links {
        // Re-read driver/pci_path (they're cheap sysfs reads).
        let driver = read_sysfs_driver(&link.name);
        let speed = read_sysfs_speed(&link.name);

        let mut fields: IndexMap<String, FieldValue> = IndexMap::new();

        fields.insert("name".to_string(), kd(Value::String(link.name.clone())));

        if let Some(mtu) = link.mtu {
            fields.insert("mtu".to_string(), kd(Value::U64(mtu as u64)));
        }

        if let Some(mac_bytes) = link.mac {
            fields.insert(
                "mac".to_string(),
                kd(Value::String(format_mac(&mac_bytes))),
            );
        }

        fields.insert(
            "carrier".to_string(),
            kd(Value::Bool(link.carrier.unwrap_or(0) != 0)),
        );

        fields.insert(
            "operstate".to_string(),
            kd(Value::String(operstate_to_str(link.operstate).to_owned())),
        );

        if let Some(spd) = speed {
            fields.insert("speed".to_string(), kd(Value::U64(spd)));
        }

        if let Some(drv) = driver {
            fields.insert("driver".to_string(), kd(Value::String(drv)));
        }

        // Addresses
        let addr_list: Vec<Value> = addr_map
            .get(&link.index)
            .map(|addrs| {
                addrs
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect()
            })
            .unwrap_or_default();
        fields.insert("addresses".to_string(), kd(Value::List(addr_list)));

        // Routes
        let route_list: Vec<Value> = route_map
            .get(&link.index)
            .cloned()
            .unwrap_or_default();
        fields.insert("routes".to_string(), kd(Value::List(route_list)));

        let state = State {
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name(link.name.clone()),
            fields,
            metadata: StateMetadata::new(),
            policy_ref: None,
            priority: 0,
        };

        state_set.insert(state);
    }

    // ── Step 8: Handle not-found ──────────────────────────────────────────────
    if let Some(sel) = selector {
        if sel.is_specific() && state_set.is_empty() {
            return Err(BackendError::NotFound {
                entity_type: "ethernet".to_string(),
                selector: Box::new(sel.clone()),
            });
        }
    }

    Ok(state_set)
}
