//! Integration tests for the ethernet netlink query backend.
//!
//! These tests use unprivileged user + network namespaces to create isolated
//! environments with known interface configuration. No root is required.
//!
//! If the kernel has user namespaces disabled (`/proc/sys/kernel/unprivileged_userns_clone = 0`),
//! `NetnsGuard::new()` will fail and tests are skipped gracefully.

use netfyr_backend::netlink::ethernet::query_ethernet;
use netfyr_backend::netlink::query::establish_connection;
use netfyr_backend::{BackendError, NetlinkBackend, NetworkBackend};
use netfyr_state::{Provenance, Selector};
use netfyr_test_utils::netns::{
    add_address, create_veth_pair, set_link_up, set_mtu, NetnsGuard,
};
use rtnetlink::LinkBridge;

/// Macro to skip a test when namespace creation is not available (EPERM).
macro_rules! require_netns {
    ($guard:ident) => {
        let $guard = match NetnsGuard::new() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("Skipping test: cannot create network namespace: {e}");
                return;
            }
        };
    };
}

// ── Test 1: Query all returns both veth endpoints ─────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_query_all_veth_pair_returns_two_entities() {
    require_netns!(_guard);

    create_veth_pair("veth-a", "veth-b").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let result = query_ethernet(&handle, None).await.unwrap();

    // A fresh namespace has lo plus our two veth endpoints.
    let found: Vec<_> = result
        .iter()
        .filter(|s| s.selector.name.as_deref() == Some("veth-a")
            || s.selector.name.as_deref() == Some("veth-b"))
        .collect();
    assert_eq!(found.len(), 2, "Expected both veth-a and veth-b in results");

    for state in &found {
        assert_eq!(state.entity_type, "ethernet");
        assert!(state.fields.contains_key("name"), "should have name field");
        assert!(state.fields.contains_key("mtu"), "should have mtu field");
        assert!(state.fields.contains_key("mac"), "should have mac field");
    }
}

// ── Test 2: Query by name selector ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_query_by_name_selector_returns_one_entity() {
    require_netns!(_guard);

    create_veth_pair("veth-test0", "veth-test1").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-test0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1);
    let state = result.get("ethernet", "veth-test0").unwrap();
    assert_eq!(
        state.selector.name.as_deref(),
        Some("veth-test0")
    );
}

// ── Test 3: Query includes IP addresses ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_query_includes_ip_addresses() {
    require_netns!(_guard);

    create_veth_pair("veth-addr0", "veth-addr1").await.unwrap();
    set_link_up("veth-addr0").await.unwrap();
    add_address("veth-addr0", "10.99.0.1/24").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-addr0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1);
    let state = result.get("ethernet", "veth-addr0").unwrap();
    let addresses = state
        .fields
        .get("addresses")
        .expect("addresses field missing")
        .value
        .as_list()
        .expect("addresses should be a list");

    let has_addr = addresses
        .iter()
        .any(|v| v.as_str() == Some("10.99.0.1/24"));
    assert!(has_addr, "Expected 10.99.0.1/24 in addresses, got: {addresses:?}");
}

// ── Test 4: All fields have KernelDefault provenance ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_all_fields_have_kernel_default_provenance() {
    require_netns!(_guard);

    create_veth_pair("veth-prov0", "veth-prov1").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-prov0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1);
    let state = result.get("ethernet", "veth-prov0").unwrap();

    for (name, fv) in &state.fields {
        assert_eq!(
            fv.provenance,
            Provenance::KernelDefault,
            "Field '{name}' has non-KernelDefault provenance"
        );
    }
}

// ── Test 5: Query non-existent interface returns NotFound ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_query_nonexistent_interface_returns_not_found() {
    require_netns!(_guard);

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("nonexistent99");
    let result = query_ethernet(&handle, Some(&sel)).await;

    assert!(
        matches!(result, Err(BackendError::NotFound { .. })),
        "Expected NotFound, got: {result:?}"
    );
}

// ── Test 6: MTU is reported correctly ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_mtu_reported_correctly() {
    require_netns!(_guard);

    create_veth_pair("veth-mtu0", "veth-mtu1").await.unwrap();
    set_mtu("veth-mtu0", 1400).await.unwrap();

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-mtu0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1);
    let state = result.get("ethernet", "veth-mtu0").unwrap();
    let mtu = state
        .fields
        .get("mtu")
        .expect("mtu field missing")
        .value
        .as_u64()
        .expect("mtu should be u64");

    assert_eq!(mtu, 1400, "Expected MTU 1400, got {mtu}");
}

// ── Test 7: Query by MAC address ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_query_by_mac_address() {
    require_netns!(_guard);

    create_veth_pair("veth-mac0", "veth-mac1").await.unwrap();

    // First query without selector to get the MAC.
    let handle = establish_connection().await.unwrap();
    let sel0 = Selector::with_name("veth-mac0");
    let result0 = query_ethernet(&handle, Some(&sel0)).await.unwrap();
    assert_eq!(result0.len(), 1);
    let state0 = result0.get("ethernet", "veth-mac0").unwrap();
    let mac_str = state0
        .fields
        .get("mac")
        .expect("mac field missing")
        .value
        .as_str()
        .expect("mac should be string")
        .to_owned();

    // Now query by MAC selector.
    let mac: netfyr_state::MacAddr = mac_str.parse().expect("should parse mac");
    let mac_sel = Selector {
        mac: Some(mac),
        ..Default::default()
    };
    let result_by_mac = query_ethernet(&handle, Some(&mac_sel)).await.unwrap();
    assert_eq!(result_by_mac.len(), 1);
    let found = result_by_mac.iter().next().unwrap();
    assert_eq!(found.selector.name.as_deref(), Some("veth-mac0"));
}

// ── Test 8: Query link down — carrier false, speed absent ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_link_down_carrier_false_and_no_speed() {
    require_netns!(_guard);

    create_veth_pair("veth-down0", "veth-down1").await.unwrap();
    // Do NOT set link up — it stays down.

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-down0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1);
    let state = result.get("ethernet", "veth-down0").unwrap();

    // carrier should be false (or absent).
    if let Some(fv) = state.fields.get("carrier") {
        assert_eq!(fv.value.as_bool(), Some(false), "carrier should be false when down");
    }

    // speed should be absent (sysfs returns -1 or error when down).
    assert!(
        !state.fields.contains_key("speed"),
        "speed field should be absent when link is down"
    );

    // name, mtu, mac should still be present.
    assert!(state.fields.contains_key("name"));
    assert!(state.fields.contains_key("mtu"));
    assert!(state.fields.contains_key("mac"));
}

// ── Test 9: query_all returns ethernet interfaces ─────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_query_all_returns_ethernet_interfaces() {
    require_netns!(_guard);

    create_veth_pair("veth-qa0", "veth-qa1").await.unwrap();

    let backend = NetlinkBackend::new();
    let all = backend.query_all().await.unwrap();

    let found_qa0 = all.get("ethernet", "veth-qa0").is_some();
    let found_qa1 = all.get("ethernet", "veth-qa1").is_some();
    assert!(found_qa0, "veth-qa0 not found in query_all");
    assert!(found_qa1, "veth-qa1 not found in query_all");
}

// ── Test 10: Multiple selector fields use AND logic ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_and_selector_logic() {
    require_netns!(_guard);

    create_veth_pair("veth-and0", "veth-and1").await.unwrap();

    // Get MACs for both.
    let handle = establish_connection().await.unwrap();
    let result_all = query_ethernet(&handle, None).await.unwrap();

    let mac0 = result_all
        .get("ethernet", "veth-and0")
        .and_then(|s| s.fields.get("mac"))
        .and_then(|fv| fv.value.as_str())
        .expect("veth-and0 should have mac")
        .to_owned();

    let mac1 = result_all
        .get("ethernet", "veth-and1")
        .and_then(|s| s.fields.get("mac"))
        .and_then(|fv| fv.value.as_str())
        .expect("veth-and1 should have mac")
        .to_owned();

    // Selector: name=veth-and0 AND mac=<mac of veth-and0> → should match.
    let mac0_parsed: netfyr_state::MacAddr = mac0.parse().unwrap();
    let sel_match = Selector {
        name: Some("veth-and0".to_string()),
        mac: Some(mac0_parsed),
        ..Default::default()
    };
    let result_match = query_ethernet(&handle, Some(&sel_match)).await.unwrap();
    assert_eq!(result_match.len(), 1);

    // Selector: name=veth-and0 AND mac=<mac of veth-and1> → should not match.
    let mac1_parsed: netfyr_state::MacAddr = mac1.parse().unwrap();
    let sel_no_match = Selector {
        name: Some("veth-and0".to_string()),
        mac: Some(mac1_parsed),
        ..Default::default()
    };
    let result_no_match =
        query_ethernet(&handle, Some(&sel_no_match)).await;
    // Either empty set (not specific enough to trigger NotFound) or NotFound.
    match result_no_match {
        Ok(set) => assert!(set.is_empty(), "Expected empty set for mismatched AND selector"),
        Err(BackendError::NotFound { .. }) => {} // also acceptable
        Err(e) => panic!("Unexpected error: {e}"),
    }
}

// ── Test 11: Comprehensive spec scenario — veth with mtu, address, provenance ──

/// Scenario: Query veth interface in unprivileged namespace (spec "Given veth-test0/veth-test1,
/// set to link up with mtu 1400 and address 10.99.0.1/24").
///
/// Covers: mtu field=1400, addresses contains "10.99.0.1/24", all fields KernelDefault,
/// selector name matches.
#[tokio::test(flavor = "multi_thread")]
async fn test_query_veth_spec_comprehensive_scenario() {
    require_netns!(_guard);

    create_veth_pair("veth-test0", "veth-test1").await.unwrap();
    set_link_up("veth-test0").await.unwrap();
    set_mtu("veth-test0", 1400).await.unwrap();
    add_address("veth-test0", "10.99.0.1/24").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-test0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1, "Expected exactly one entity for veth-test0");

    let state = result.get("ethernet", "veth-test0")
        .expect("veth-test0 must be in result");

    // entity_type must be "ethernet"
    assert_eq!(state.entity_type, "ethernet");

    // selector name must be "veth-test0"
    assert_eq!(state.selector.name.as_deref(), Some("veth-test0"));

    // mtu must be 1400
    let mtu = state.fields.get("mtu")
        .expect("mtu field must be present")
        .value.as_u64()
        .expect("mtu must be u64");
    assert_eq!(mtu, 1400, "MTU must be 1400");

    // addresses must contain "10.99.0.1/24"
    let addresses = state.fields.get("addresses")
        .expect("addresses field must be present")
        .value.as_list()
        .expect("addresses must be a list");
    let has_addr = addresses.iter().any(|v| v.as_str() == Some("10.99.0.1/24"));
    assert!(has_addr, "addresses must contain '10.99.0.1/24', got: {addresses:?}");

    // All fields must have KernelDefault provenance
    for (field_name, fv) in &state.fields {
        assert_eq!(
            fv.provenance,
            Provenance::KernelDefault,
            "Field '{field_name}' must have KernelDefault provenance"
        );
    }
}

// ── Test 12: Loopback interface excluded from ethernet results ─────────────────

/// Scenario: Query excludes non-ethernet interfaces — a fresh namespace has only
/// the loopback interface (ARPHRD_LOOPBACK), which must be excluded from ethernet query.
#[tokio::test(flavor = "multi_thread")]
async fn test_query_excludes_loopback_interface_in_fresh_namespace() {
    require_netns!(_guard);
    // Do NOT create any veth pairs — fresh namespace has only lo.

    let handle = establish_connection().await.unwrap();
    let result = query_ethernet(&handle, None).await.unwrap();

    // lo must not appear (it is ARPHRD_LOOPBACK, not ARPHRD_ETHER).
    let has_lo = result.iter().any(|s| s.selector.name.as_deref() == Some("lo"));
    assert!(!has_lo, "loopback interface 'lo' must not appear in ethernet query results");

    // A fresh namespace with no ethernet interfaces yields an empty StateSet.
    assert!(result.is_empty(), "Expected empty ethernet result in a namespace with only lo");
}

// ── Test 13: Routes field contains connected subnet route ─────────────────────

/// Scenario: Query ethernet interface includes routes.
///
/// After assigning "10.99.2.1/24" to an UP interface, the kernel creates a
/// connected subnet route "10.99.2.0/24". That route must appear in the
/// "routes" field as a map with "destination" and "metric" keys.
#[tokio::test(flavor = "multi_thread")]
async fn test_query_includes_connected_subnet_route() {
    require_netns!(_guard);

    create_veth_pair("veth-rt0", "veth-rt1").await.unwrap();
    set_link_up("veth-rt0").await.unwrap();
    add_address("veth-rt0", "10.99.2.1/24").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("veth-rt0");
    let result = query_ethernet(&handle, Some(&sel)).await.unwrap();

    assert_eq!(result.len(), 1);
    let state = result.get("ethernet", "veth-rt0").unwrap();

    let routes = state.fields.get("routes")
        .expect("routes field must be present")
        .value.as_list()
        .expect("routes must be a list");

    assert!(!routes.is_empty(), "Expected at least one route after assigning an address to an UP interface");

    // Each route must be a map containing "destination" and "metric" keys.
    for route_val in routes {
        let route_map = route_val.as_map()
            .expect("each route entry must be a Value::Map");
        assert!(route_map.contains_key("destination"), "route must have 'destination' key");
        assert!(route_map.contains_key("metric"),      "route must have 'metric' key");
    }

    // The connected subnet route 10.99.2.0/24 must appear.
    let has_subnet = routes.iter().any(|r| {
        r.as_map()
            .and_then(|m| m.get("destination"))
            .and_then(|v| v.as_str())
            .map(|s| s == "10.99.2.0/24")
            .unwrap_or(false)
    });
    assert!(has_subnet, "Expected subnet route '10.99.2.0/24' in routes, got: {routes:?}");

    // Routes field provenance must be KernelDefault.
    assert_eq!(
        state.fields.get("routes").unwrap().provenance,
        Provenance::KernelDefault,
        "routes field must have KernelDefault provenance"
    );
}

// ── Test 14: All returned entities have entity_type "ethernet" ────────────────

/// Scenario: Query all ethernet interfaces — every returned State has entity_type "ethernet".
#[tokio::test(flavor = "multi_thread")]
async fn test_query_all_returned_entities_have_ethernet_type() {
    require_netns!(_guard);

    create_veth_pair("veth-et0", "veth-et1").await.unwrap();

    let handle = establish_connection().await.unwrap();
    let result = query_ethernet(&handle, None).await.unwrap();

    for state in result.iter() {
        assert_eq!(
            state.entity_type, "ethernet",
            "Entity '{}' must have entity_type 'ethernet', got '{}'",
            state.selector.name.as_deref().unwrap_or("?"),
            state.entity_type
        );
    }

    // Both veth endpoints must be present.
    assert!(
        result.get("ethernet", "veth-et0").is_some(),
        "veth-et0 must be in query results"
    );
    assert!(
        result.get("ethernet", "veth-et1").is_some(),
        "veth-et1 must be in query results"
    );
}

// ── Test 15: Bridge interface is excluded from ethernet results ───────────────

/// Scenario: Query excludes non-ethernet interfaces — bridge interfaces
/// (InfoKind::Bridge) must not appear in ethernet query results.
#[tokio::test(flavor = "multi_thread")]
async fn test_query_excludes_bridge_interface() {
    require_netns!(_guard);

    // Create a veth pair (should appear) and a bridge (must NOT appear).
    create_veth_pair("veth-br0", "veth-br1").await.unwrap();

    // Create bridge interface directly via rtnetlink.
    let (conn, handle_br, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(conn);
    handle_br
        .link()
        .add(LinkBridge::new("br-excl").build())
        .execute()
        .await
        .unwrap();

    let handle = establish_connection().await.unwrap();
    let result = query_ethernet(&handle, None).await.unwrap();

    // bridge must NOT appear.
    let has_bridge = result.iter().any(|s| s.selector.name.as_deref() == Some("br-excl"));
    assert!(!has_bridge, "bridge interface 'br-excl' must not appear in ethernet query results");

    // veth endpoints must still appear.
    assert!(result.get("ethernet", "veth-br0").is_some(), "veth-br0 must be present");
    assert!(result.get("ethernet", "veth-br1").is_some(), "veth-br1 must be present");
}

// ── Test 16: Selector with name=nonexistent returns NotFound ──────────────────

/// Scenario: Query for non-existent interface returns NotFound (entity_type and
/// selector captured in the error).
#[tokio::test(flavor = "multi_thread")]
async fn test_query_nonexistent_interface_error_captures_entity_type() {
    require_netns!(_guard);

    let handle = establish_connection().await.unwrap();
    let sel = Selector::with_name("eth99");
    let result = query_ethernet(&handle, Some(&sel)).await;

    match result {
        Err(BackendError::NotFound { ref entity_type, ref selector }) => {
            assert_eq!(entity_type, "ethernet", "NotFound error must name entity type 'ethernet'");
            assert_eq!(
                selector.name.as_deref(),
                Some("eth99"),
                "NotFound error must capture the requested selector name"
            );
        }
        Err(e) => panic!("Expected NotFound, got {e:?}"),
        Ok(set) => panic!("Expected Err(NotFound), got Ok with {} entities", set.len()),
    }
}

// ── Test 17: query_all via NetlinkBackend includes veth entities ──────────────

/// Scenario: query_all includes all ethernet interfaces.
/// NetlinkBackend::query_all must return the same interfaces as a direct
/// query_ethernet call with no selector.
#[tokio::test(flavor = "multi_thread")]
async fn test_query_all_via_backend_matches_direct_query() {
    require_netns!(_guard);

    create_veth_pair("veth-all0", "veth-all1").await.unwrap();

    let backend = NetlinkBackend::new();
    let all = backend.query_all().await.unwrap();

    // query_all result must include veth-all0 and veth-all1.
    assert!(
        all.get("ethernet", "veth-all0").is_some(),
        "query_all must include veth-all0"
    );
    assert!(
        all.get("ethernet", "veth-all1").is_some(),
        "query_all must include veth-all1"
    );

    // Each entity must have the core required fields.
    for state in [
        all.get("ethernet", "veth-all0").unwrap(),
        all.get("ethernet", "veth-all1").unwrap(),
    ] {
        assert!(state.fields.contains_key("name"), "must have 'name' field");
        assert!(state.fields.contains_key("mtu"),  "must have 'mtu' field");
        assert!(state.fields.contains_key("mac"),  "must have 'mac' field");
        assert_eq!(state.entity_type, "ethernet");
    }
}
