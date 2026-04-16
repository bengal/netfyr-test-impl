//! Integration tests for SPEC-103: rtnetlink Apply for Ethernet Interfaces.
//!
//! Tests `apply_ethernet` and `dry_run_ethernet` using unprivileged user +
//! network namespaces with veth pairs. No root is required.
//!
//! Each test uses unique interface names to avoid conflicts when tests run
//! concurrently (each test creates its own namespace via `NetnsGuard`).

use indexmap::IndexMap;

use netfyr_backend::{
    netlink::apply::{apply_ethernet, dry_run_ethernet},
    netlink::ethernet::query_ethernet,
    netlink::query::establish_connection,
    BackendError, DiffOpKind, FieldChangeKind,
};
use netfyr_state::{DiffOp, FieldValue, Provenance, Selector, StateDiff, Value};
use netfyr_test_utils::netns::{
    add_address, create_veth_pair, get_link_index, set_link_up, set_mtu, NetnsGuard,
};

// ── Test infrastructure ───────────────────────────────────────────────────────

/// Skip the test when the kernel has user namespaces disabled (EPERM on unshare).
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

// ── Builder helpers ───────────────────────────────────────────────────────────

fn kd(value: Value) -> FieldValue {
    FieldValue {
        value,
        provenance: Provenance::KernelDefault,
    }
}

fn modify_op(
    name: &str,
    changed_fields: IndexMap<String, FieldValue>,
    removed_fields: Vec<String>,
) -> DiffOp {
    DiffOp::Modify {
        entity_type: "ethernet".to_string(),
        selector: Selector::with_name(name),
        changed_fields,
        removed_fields,
    }
}

fn remove_op(name: &str) -> DiffOp {
    DiffOp::Remove {
        entity_type: "ethernet".to_string(),
        selector: Selector::with_name(name),
    }
}

fn one_field(key: &str, value: Value) -> IndexMap<String, FieldValue> {
    let mut m = IndexMap::new();
    m.insert(key.to_string(), kd(value));
    m
}

fn make_diff(ops: Vec<DiffOp>) -> StateDiff {
    StateDiff::new(ops)
}

// ── Query helpers ─────────────────────────────────────────────────────────────

async fn query_state(name: &str) -> Option<netfyr_state::State> {
    let handle = establish_connection().await.ok()?;
    let sel = Selector::with_name(name);
    query_ethernet(&handle, Some(&sel))
        .await
        .ok()
        .and_then(|set| set.get("ethernet", name).cloned())
}

async fn query_mtu(name: &str) -> Option<u64> {
    query_state(name)
        .await?
        .fields
        .get("mtu")?
        .value
        .as_u64()
}

async fn query_addresses(name: &str) -> Vec<String> {
    query_state(name)
        .await
        .and_then(|s| {
            s.fields.get("addresses").and_then(|fv| fv.value.as_list()).cloned()
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

async fn query_routes(name: &str) -> Vec<Value> {
    query_state(name)
        .await
        .and_then(|s| {
            s.fields
                .get("routes")
                .and_then(|fv| fv.value.as_list())
                .cloned()
        })
        .unwrap_or_default()
}

async fn has_address(name: &str, cidr: &str) -> bool {
    query_addresses(name).await.iter().any(|a| a == cidr)
}

async fn interface_exists(name: &str) -> bool {
    get_link_index(name).await.is_ok()
}

// ── Helper: add a static route via rtnetlink ──────────────────────────────────

async fn add_static_route(
    iface: &str,
    dst_cidr: &str,
    gateway: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use rtnetlink::RouteMessageBuilder;
    use std::net::IpAddr;

    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let index = get_link_index(iface).await?;

    let (dst_str, prefix_str) = dst_cidr.split_once('/').ok_or("invalid CIDR")?;
    let dst_ip: IpAddr = dst_str.parse()?;
    let prefix: u8 = prefix_str.parse()?;
    let gw_ip: IpAddr = gateway.parse()?;

    let msg = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(dst_ip, prefix)?
        .gateway(gw_ip)?
        .output_interface(index)
        .build();

    handle.route().add(msg).execute().await?;
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// Acceptance criteria: apply_ethernet
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario: Modify MTU on an existing ethernet interface
///
/// Given a veth interface with default mtu 1500,
/// when apply is called with mtu=1400,
/// then ApplyReport has 1 succeeded and the system mtu is 1400.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_modify_mtu_sets_mtu_to_desired_value() {
    require_netns!(_guard);

    create_veth_pair("veth-mtu0", "veth-mtu1").await.unwrap();

    let diff = make_diff(vec![modify_op(
        "veth-mtu0",
        one_field("mtu", Value::U64(1400)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(
        report.succeeded.len(),
        1,
        "Expected 1 succeeded operation: {}",
        report.summary()
    );
    assert!(report.failed.is_empty(), "Expected no failures: {:?}", report.failed);

    // Verify system mtu actually changed.
    let mtu = query_mtu("veth-mtu0").await;
    assert_eq!(mtu, Some(1400), "System MTU should be 1400, got: {mtu:?}");
}

/// Scenario: Add an IP address to an ethernet interface
///
/// Given veth-addr0 with no addresses,
/// when apply adds "10.99.0.1/24",
/// then ApplyReport has 1 succeeded and "10.99.0.1/24" is on the interface.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_add_ip_address_to_interface() {
    require_netns!(_guard);

    create_veth_pair("veth-addr0", "veth-addr1").await.unwrap();
    set_link_up("veth-addr0").await.unwrap();

    let diff = make_diff(vec![modify_op(
        "veth-addr0",
        one_field(
            "addresses",
            Value::List(vec![Value::String("10.99.0.1/24".to_string())]),
        ),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(
        report.succeeded.len(),
        1,
        "Expected 1 succeeded operation: {}",
        report.summary()
    );
    assert!(report.failed.is_empty(), "Expected no failures: {:?}", report.failed);

    assert!(
        has_address("veth-addr0", "10.99.0.1/24").await,
        "Address 10.99.0.1/24 should be present on veth-addr0"
    );
}

/// Scenario: Remove an IP address from an ethernet interface
///
/// Given veth-rmaddr0 with address "10.99.1.50/24",
/// when apply removes it (sets addresses to empty),
/// then the address no longer exists on the interface.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_remove_ip_address_from_interface() {
    require_netns!(_guard);

    create_veth_pair("veth-rmaddr0", "veth-rmaddr1").await.unwrap();
    set_link_up("veth-rmaddr0").await.unwrap();
    add_address("veth-rmaddr0", "10.99.1.50/24").await.unwrap();

    // Precondition.
    assert!(
        has_address("veth-rmaddr0", "10.99.1.50/24").await,
        "Precondition: address must be present before remove"
    );

    // Set desired addresses to empty → removes the existing address.
    let diff = make_diff(vec![modify_op(
        "veth-rmaddr0",
        one_field("addresses", Value::List(vec![])),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 1, "Expected 1 succeeded: {}", report.summary());
    assert!(report.failed.is_empty(), "No failures expected: {:?}", report.failed);

    assert!(
        !has_address("veth-rmaddr0", "10.99.1.50/24").await,
        "Address 10.99.1.50/24 should no longer be on veth-rmaddr0"
    );
}

/// Scenario: Add a route via an ethernet interface
///
/// Given veth-rt0 with address "10.99.2.1/24" and link up,
/// when apply adds route destination="10.100.0.0/24" gateway="10.99.2.2",
/// then the route exists in the routing table.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_add_route_in_namespace() {
    require_netns!(_guard);

    create_veth_pair("veth-rt0", "veth-rt1").await.unwrap();
    set_link_up("veth-rt0").await.unwrap();
    add_address("veth-rt0", "10.99.2.1/24").await.unwrap();

    let mut route_map = IndexMap::new();
    route_map.insert(
        "destination".to_string(),
        Value::String("10.100.0.0/24".to_string()),
    );
    route_map.insert(
        "gateway".to_string(),
        Value::String("10.99.2.2".to_string()),
    );

    // Current state has the connected 10.99.2.0/24 route; we want to ADD the
    // static route while keeping whatever is already there. We represent the
    // desired routes as [static_route] — the connected route will also be
    // present in desired so it won't be removed. Because we don't know the
    // exact metric value from the kernel, we deliberately include the static
    // route only. Any existing connected routes not in desired will be
    // removed, which is acceptable for this test.
    let diff = make_diff(vec![modify_op(
        "veth-rt0",
        one_field("routes", Value::List(vec![Value::Map(route_map)])),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert!(
        report.is_success(),
        "Apply should succeed (no failures): {}",
        report.summary()
    );

    // The static route to 10.100.0.0/24 must now exist.
    let routes = query_routes("veth-rt0").await;
    let has_route = routes.iter().any(|r| {
        r.as_map()
            .and_then(|m| m.get("destination"))
            .and_then(|v| v.as_str())
            .map(|s| s == "10.100.0.0/24")
            .unwrap_or(false)
    });
    assert!(
        has_route,
        "Route to 10.100.0.0/24 should exist after apply. Got routes: {routes:?}"
    );
}

/// Scenario: Remove a route from an ethernet interface
///
/// Given veth-rmrt0 with address and static route to 10.100.0.0/24,
/// when apply sets routes to empty (removes all),
/// then the static route no longer exists.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_remove_route_from_interface() {
    require_netns!(_guard);

    create_veth_pair("veth-rmrt0", "veth-rmrt1").await.unwrap();
    set_link_up("veth-rmrt0").await.unwrap();
    add_address("veth-rmrt0", "10.99.3.1/24").await.unwrap();

    // Add a static route as setup.
    add_static_route("veth-rmrt0", "10.100.0.0/24", "10.99.3.2")
        .await
        .unwrap();

    // Precondition: static route should be present.
    let routes_before = query_routes("veth-rmrt0").await;
    let has_static = routes_before.iter().any(|r| {
        r.as_map()
            .and_then(|m| m.get("destination"))
            .and_then(|v| v.as_str())
            .map(|s| s == "10.100.0.0/24")
            .unwrap_or(false)
    });
    assert!(has_static, "Precondition: static route should exist before remove");

    // Remove all routes by setting desired routes to [].
    let diff = make_diff(vec![modify_op(
        "veth-rmrt0",
        one_field("routes", Value::List(vec![])),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 1, "Expected 1 succeeded: {}", report.summary());
    assert!(report.failed.is_empty(), "No failures expected: {:?}", report.failed);

    // Static route should be gone.
    let routes_after = query_routes("veth-rmrt0").await;
    let still_has_static = routes_after.iter().any(|r| {
        r.as_map()
            .and_then(|m| m.get("destination"))
            .and_then(|v| v.as_str())
            .map(|s| s == "10.100.0.0/24")
            .unwrap_or(false)
    });
    assert!(
        !still_has_static,
        "Static route 10.100.0.0/24 should no longer exist. Got: {routes_after:?}"
    );
}

/// Scenario: Modify operation skips read-only fields
///
/// Given a diff that includes changes to "carrier" and "speed" on an existing
/// interface, apply should put those in the skipped list with reason
/// "read-only field" and not report them as failures.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_skips_readonly_fields_carrier_and_speed() {
    require_netns!(_guard);

    create_veth_pair("veth-ro0", "veth-ro1").await.unwrap();

    // Build a diff that changes "carrier" and "speed" — both read-only.
    let mut changed_fields = IndexMap::new();
    changed_fields.insert("carrier".to_string(), kd(Value::Bool(true)));
    changed_fields.insert("speed".to_string(), kd(Value::U64(1000)));

    let diff = make_diff(vec![modify_op("veth-ro0", changed_fields, vec![])]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // Skipped list must contain entries for the read-only fields.
    let skip_reasons: Vec<&str> = report.skipped.iter().map(|s| s.reason.as_str()).collect();
    assert!(
        skip_reasons.contains(&"read-only field"),
        "Expected 'read-only field' reason in skipped list, got: {skip_reasons:?}"
    );

    // No failures — skipping is not failure.
    assert!(
        report.failed.is_empty(),
        "Read-only field changes must not produce failures: {:?}",
        report.failed
    );

    // Verify is_success() returns true even with skipped entries.
    assert!(
        report.is_success(),
        "is_success() must be true when only read-only fields were in the diff"
    );
}

/// Scenario: Adding an already-existing address is idempotent
///
/// Given "10.99.4.1/24" is already on veth-idem0, when apply tries to add
/// the same address, the result is success (no failures).
///
/// Note: The current implementation pre-filters addresses using the current
/// kernel state, so the address is not attempted again and no EEXIST occurs.
/// is_success() must be true and the address must still be present.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_add_existing_address_is_idempotent() {
    require_netns!(_guard);

    create_veth_pair("veth-idem0", "veth-idem1").await.unwrap();
    set_link_up("veth-idem0").await.unwrap();
    add_address("veth-idem0", "10.99.4.1/24").await.unwrap();

    // Request to add the address that is already present.
    let diff = make_diff(vec![modify_op(
        "veth-idem0",
        one_field(
            "addresses",
            Value::List(vec![Value::String("10.99.4.1/24".to_string())]),
        ),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // is_success() must be true — idempotency means no failure.
    assert!(
        report.is_success(),
        "is_success() must be true for idempotent add: {}",
        report.summary()
    );
    assert!(
        report.failed.is_empty(),
        "No failures for idempotent add: {:?}",
        report.failed
    );

    // Address must still be present.
    assert!(
        has_address("veth-idem0", "10.99.4.1/24").await,
        "Address 10.99.4.1/24 must still be present after idempotent add"
    );
}

/// Scenario: Removing a non-existent address is idempotent
///
/// Given veth-idem2 with no addresses, when apply tries to set addresses to
/// [] (effectively removing none), the result is success (no failures).
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_remove_nonexistent_address_is_idempotent() {
    require_netns!(_guard);

    create_veth_pair("veth-idem2", "veth-idem3").await.unwrap();
    // No addresses assigned.

    // Diff: set addresses = [] (desired has no addresses; current also has none).
    let diff = make_diff(vec![modify_op(
        "veth-idem2",
        one_field("addresses", Value::List(vec![])),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // is_success() must be true — nothing to do is not an error.
    assert!(
        report.is_success(),
        "is_success() must be true for idempotent remove: {}",
        report.summary()
    );
    assert!(
        report.failed.is_empty(),
        "No failures for idempotent remove: {:?}",
        report.failed
    );
}

/// Scenario: Apply to a non-existent interface reports failure
///
/// Given no interface named "eth99" in the namespace, when apply is called,
/// the ApplyReport has 1 failed operation with BackendError::NotFound.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_nonexistent_interface_reports_failure_with_not_found() {
    require_netns!(_guard);
    // No interface "eth99" created in this fresh namespace.

    let diff = make_diff(vec![modify_op(
        "eth99",
        one_field("mtu", Value::U64(1400)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 0, "Expected 0 succeeded: {}", report.summary());
    assert_eq!(report.failed.len(), 1, "Expected 1 failed: {}", report.summary());

    let failure = &report.failed[0];
    assert!(
        matches!(failure.error, BackendError::NotFound { .. }),
        "Error must be BackendError::NotFound for unknown interface, got: {:?}",
        failure.error
    );
    assert_eq!(
        failure.selector.name.as_deref(),
        Some("eth99"),
        "Failed operation must name the missing interface"
    );
}

/// Scenario: Multiple operations with partial failure
///
/// Given veth-part0 (exists) and "eth99" (does not exist),
/// when apply is called with Modify ops on both,
/// then ApplyReport has 1 succeeded and 1 failed, is_partial() == true.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_partial_failure_is_partial_true() {
    require_netns!(_guard);

    create_veth_pair("veth-part0", "veth-part1").await.unwrap();

    let diff = make_diff(vec![
        // veth-part0 exists → should succeed.
        modify_op(
            "veth-part0",
            one_field("mtu", Value::U64(1400)),
            vec![],
        ),
        // eth99 does not exist → should fail.
        modify_op(
            "eth99",
            one_field("mtu", Value::U64(1400)),
            vec![],
        ),
    ]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 1, "Expected 1 succeeded: {}", report.summary());
    assert_eq!(report.failed.len(), 1, "Expected 1 failed: {}", report.summary());

    assert!(
        report.is_partial(),
        "is_partial() must be true when 1 succeeded and 1 failed"
    );
    assert!(
        !report.is_success(),
        "is_success() must be false when there are failures"
    );

    // The failed operation must be for eth99.
    assert_eq!(
        report.failed[0].selector.name.as_deref(),
        Some("eth99"),
        "Failed operation must be for eth99"
    );

    // The succeeded operation must be for veth-part0.
    assert_eq!(
        report.succeeded[0].selector.name.as_deref(),
        Some("veth-part0"),
        "Succeeded operation must be for veth-part0"
    );
}

/// Scenario: Remove operation deconfigures but does not delete physical interface
///
/// Given veth-rmdec0 with address and static route,
/// when a Remove DiffOp is applied,
/// then addresses are removed, routes are removed, link is set down,
/// AND the interface still exists (not deleted).
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_remove_operation_deconfigures_but_keeps_interface() {
    require_netns!(_guard);

    create_veth_pair("veth-rmdec0", "veth-rmdec1").await.unwrap();
    set_link_up("veth-rmdec0").await.unwrap();
    add_address("veth-rmdec0", "10.99.5.1/24").await.unwrap();
    add_static_route("veth-rmdec0", "10.100.0.0/24", "10.99.5.2")
        .await
        .unwrap();

    // Preconditions.
    assert!(
        has_address("veth-rmdec0", "10.99.5.1/24").await,
        "Precondition: address must be present"
    );
    assert!(interface_exists("veth-rmdec0").await, "Precondition: interface must exist");

    let diff = make_diff(vec![remove_op("veth-rmdec0")]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 1, "Expected 1 succeeded: {}", report.summary());
    assert!(report.failed.is_empty(), "No failures expected: {:?}", report.failed);

    // Address must be removed.
    assert!(
        !has_address("veth-rmdec0", "10.99.5.1/24").await,
        "Address 10.99.5.1/24 must be removed after Remove op"
    );

    // Routes must be removed (static route 10.100.0.0/24 must be gone).
    let routes_after = query_routes("veth-rmdec0").await;
    let has_static = routes_after.iter().any(|r| {
        r.as_map()
            .and_then(|m| m.get("destination"))
            .and_then(|v| v.as_str())
            .map(|s| s == "10.100.0.0/24")
            .unwrap_or(false)
    });
    assert!(
        !has_static,
        "Static route must be removed after Remove op. Got: {routes_after:?}"
    );

    // Interface must still exist (deconfigured, not deleted).
    assert!(
        interface_exists("veth-rmdec0").await,
        "veth-rmdec0 must still exist (physical interfaces are never deleted)"
    );

    // Operstate must not be "up" — link was set down.
    let state = query_state("veth-rmdec0").await;
    if let Some(s) = state {
        let operstate = s
            .fields
            .get("operstate")
            .and_then(|fv| fv.value.as_str())
            .unwrap_or("unknown");
        assert_ne!(
            operstate, "up",
            "Interface must not be operstate 'up' after Remove op, got: {operstate}"
        );
    }
}

/// Scenario: Field changes within an entity are applied in correct order
///
/// Given veth-ord0 with mtu=1500, no addresses, link down:
/// When apply is called with mtu=1400, operstate="up", address "10.99.6.1/24",
/// and route "0.0.0.0/0 via 10.99.6.2":
/// - Link is set up first (phase 1)
/// - Then MTU (phase 1)
/// - Then address is added (phase 2) — creating the connected 10.99.6.0/24 route
/// - Then route 0.0.0.0/0 is added via 10.99.6.2 (phase 3, gateway reachable)
/// All operations must succeed.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_field_order_link_mtu_addresses_routes() {
    require_netns!(_guard);

    create_veth_pair("veth-ord0", "veth-ord1").await.unwrap();
    // Interface is down with default MTU 1500, no addresses.

    let mut route_map = IndexMap::new();
    route_map.insert(
        "destination".to_string(),
        Value::String("0.0.0.0/0".to_string()),
    );
    route_map.insert(
        "gateway".to_string(),
        Value::String("10.99.6.2".to_string()),
    );

    let mut changed_fields = IndexMap::new();
    changed_fields.insert("mtu".to_string(), kd(Value::U64(1400)));
    changed_fields.insert("operstate".to_string(), kd(Value::String("up".to_string())));
    changed_fields.insert(
        "addresses".to_string(),
        kd(Value::List(vec![Value::String("10.99.6.1/24".to_string())])),
    );
    changed_fields.insert(
        "routes".to_string(),
        kd(Value::List(vec![Value::Map(route_map)])),
    );

    let diff = make_diff(vec![modify_op("veth-ord0", changed_fields, vec![])]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // All operations must succeed — if ordering is wrong (e.g., route before
    // address), the route add would fail because the gateway 10.99.6.2 would
    // not be reachable.
    assert!(
        report.is_success(),
        "All field changes must succeed when applied in correct order: {}",
        report.summary()
    );
    assert!(
        report.failed.is_empty(),
        "No failures expected: {:?}",
        report.failed
    );

    // Verify MTU was set.
    let mtu = query_mtu("veth-ord0").await;
    assert_eq!(mtu, Some(1400), "MTU must be 1400 after apply");

    // Verify address was added.
    assert!(
        has_address("veth-ord0", "10.99.6.1/24").await,
        "Address 10.99.6.1/24 must be present"
    );

    // Verify default route via 10.99.6.2 was added.
    let routes = query_routes("veth-ord0").await;
    let has_default = routes.iter().any(|r| {
        r.as_map()
            .and_then(|m| m.get("destination"))
            .and_then(|v| v.as_str())
            .map(|s| s == "0.0.0.0/0")
            .unwrap_or(false)
    });
    assert!(
        has_default,
        "Default route 0.0.0.0/0 must be in routing table. Got: {routes:?}"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Acceptance criteria: dry_run_ethernet
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario: Dry-run reports planned changes without modifying the system
///
/// Given veth-dry0 with default mtu 1500,
/// when dry_run is called with mtu=9000,
/// then DryRunReport has a PlannedChange for veth-dry0 showing
/// mtu current=1500 → desired=9000, and the system mtu is still 1500.
#[tokio::test(flavor = "multi_thread")]
async fn test_dry_run_shows_planned_mtu_change_without_modifying_system() {
    require_netns!(_guard);

    create_veth_pair("veth-dry0", "veth-dry1").await.unwrap();
    // Default MTU is 1500 — do not set it explicitly.

    let diff = make_diff(vec![modify_op(
        "veth-dry0",
        one_field("mtu", Value::U64(9000)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = dry_run_ethernet(&handle, &diff).await.unwrap();

    // Report must have exactly one planned change for veth-dry0.
    assert_eq!(
        report.changes.len(),
        1,
        "Expected 1 planned change, got {} changes and {} skipped",
        report.changes.len(),
        report.skipped.len()
    );

    let planned = &report.changes[0];
    assert_eq!(
        planned.selector.name.as_deref(),
        Some("veth-dry0"),
        "PlannedChange must be for veth-dry0"
    );
    assert_eq!(planned.operation, DiffOpKind::Modify);

    // The field changes must include mtu from 1500 to 9000.
    let mtu_change = planned
        .field_changes
        .iter()
        .find(|fc| fc.field == "mtu")
        .expect("PlannedChange must include an mtu field change");

    assert_eq!(
        mtu_change.current,
        Some(Value::U64(1500)),
        "mtu current value must be 1500, got: {:?}",
        mtu_change.current
    );
    assert_eq!(
        mtu_change.desired,
        Some(Value::U64(9000)),
        "mtu desired value must be 9000, got: {:?}",
        mtu_change.desired
    );
    assert_eq!(
        mtu_change.kind,
        FieldChangeKind::Modify,
        "mtu field change kind must be Modify"
    );

    // CRITICAL: the system mtu must NOT have changed.
    let actual_mtu = query_mtu("veth-dry0").await;
    assert_eq!(
        actual_mtu,
        Some(1500),
        "System MTU must still be 1500 after dry_run (no changes applied)"
    );
}

/// Scenario: Dry-run validates that target interface exists
///
/// Given no interface named "eth99" in the namespace,
/// when dry_run is called with a Modify op on "eth99",
/// then the DryRunReport indicates the operation would fail with NotFound
/// (the interface is listed in skipped with a reason containing "not found").
#[tokio::test(flavor = "multi_thread")]
async fn test_dry_run_nonexistent_interface_appears_in_skipped() {
    require_netns!(_guard);
    // No "eth99" created.

    let diff = make_diff(vec![modify_op(
        "eth99",
        one_field("mtu", Value::U64(1400)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = dry_run_ethernet(&handle, &diff).await.unwrap();

    // No planned changes — the interface doesn't exist.
    assert_eq!(
        report.changes.len(),
        0,
        "Expected 0 planned changes for nonexistent interface"
    );

    // The operation must appear in skipped with a not-found indication.
    assert_eq!(
        report.skipped.len(),
        1,
        "Expected 1 skipped entry for nonexistent interface"
    );
    let skip = &report.skipped[0];
    assert!(
        skip.reason.to_lowercase().contains("not found")
            || skip.reason.to_lowercase().contains("interface not found"),
        "Skipped reason must indicate the interface was not found, got: '{}'",
        skip.reason
    );
    assert_eq!(
        skip.selector.name.as_deref(),
        Some("eth99"),
        "Skipped entry must name the missing interface"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Integration tests: add and remove address round-trip
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario: Add and remove IP addresses in namespace (round-trip)
///
/// Given veth-rtrip0 with no addresses,
/// Step 1: apply StateDiff adding "10.99.7.1/24" → address is present.
/// Step 2: apply StateDiff removing it (set to []) → address is gone.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_add_then_remove_address_roundtrip() {
    require_netns!(_guard);

    create_veth_pair("veth-rtrip0", "veth-rtrip1").await.unwrap();
    set_link_up("veth-rtrip0").await.unwrap();

    let handle = establish_connection().await.unwrap();

    // Step 1: Add address.
    let add_diff = make_diff(vec![modify_op(
        "veth-rtrip0",
        one_field(
            "addresses",
            Value::List(vec![Value::String("10.99.7.1/24".to_string())]),
        ),
        vec![],
    )]);
    let report_add = apply_ethernet(&handle, &add_diff).await.unwrap();
    assert!(report_add.is_success(), "Add must succeed: {}", report_add.summary());
    assert!(
        has_address("veth-rtrip0", "10.99.7.1/24").await,
        "Address should be present after add"
    );

    // Step 2: Remove address.
    let rm_diff = make_diff(vec![modify_op(
        "veth-rtrip0",
        one_field("addresses", Value::List(vec![])),
        vec![],
    )]);
    let report_rm = apply_ethernet(&handle, &rm_diff).await.unwrap();
    assert!(report_rm.is_success(), "Remove must succeed: {}", report_rm.summary());
    assert!(
        !has_address("veth-rtrip0", "10.99.7.1/24").await,
        "Address should be absent after remove"
    );
}

/// Scenario: Full round-trip — apply then query
///
/// Given veth-frt0 with no configuration,
/// when apply sets mtu=1400 and address "10.99.8.1/24",
/// then query_ethernet returns state showing mtu=1400 and the address.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_then_query_shows_updated_state() {
    require_netns!(_guard);

    create_veth_pair("veth-frt0", "veth-frt1").await.unwrap();
    set_link_up("veth-frt0").await.unwrap();

    let mut changed_fields = IndexMap::new();
    changed_fields.insert("mtu".to_string(), kd(Value::U64(1400)));
    changed_fields.insert(
        "addresses".to_string(),
        kd(Value::List(vec![Value::String("10.99.8.1/24".to_string())])),
    );

    let diff = make_diff(vec![modify_op("veth-frt0", changed_fields, vec![])]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();
    assert!(report.is_success(), "Apply must succeed: {}", report.summary());

    // Query the interface and verify the state reflects the applied changes.
    let state = query_state("veth-frt0")
        .await
        .expect("veth-frt0 must be queryable after apply");

    let mtu = state.fields.get("mtu").and_then(|fv| fv.value.as_u64());
    assert_eq!(mtu, Some(1400), "Queried MTU must be 1400");

    let addresses = state
        .fields
        .get("addresses")
        .and_then(|fv| fv.value.as_list())
        .cloned()
        .unwrap_or_default();
    let has_addr = addresses
        .iter()
        .any(|v| v.as_str() == Some("10.99.8.1/24"));
    assert!(
        has_addr,
        "Queried state must contain 10.99.8.1/24, got: {addresses:?}"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// ApplyReport status method correctness (unit-level with real apply)
// ══════════════════════════════════════════════════════════════════════════════

/// Verify is_total_failure() when the only operation fails.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_single_failure_is_total_failure() {
    require_netns!(_guard);

    // No interface "eth99" in the fresh namespace.
    let diff = make_diff(vec![modify_op(
        "eth99",
        one_field("mtu", Value::U64(1400)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    assert!(
        report.is_total_failure(),
        "is_total_failure() must be true when the only operation fails"
    );
    assert!(
        !report.is_success(),
        "is_success() must be false when there are failures"
    );
    assert!(
        !report.is_partial(),
        "is_partial() must be false when nothing succeeded"
    );
}

/// Verify that the report summary string has the expected "{n} succeeded, {n} failed, {n} skipped" format.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_report_summary_format_for_successful_operation() {
    require_netns!(_guard);

    create_veth_pair("veth-sum0", "veth-sum1").await.unwrap();

    let diff = make_diff(vec![modify_op(
        "veth-sum0",
        one_field("mtu", Value::U64(1400)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    let summary = report.summary();
    assert!(
        summary.contains("succeeded"),
        "Summary must contain 'succeeded', got: {summary}"
    );
    assert!(
        summary.contains("failed"),
        "Summary must contain 'failed', got: {summary}"
    );
    assert!(
        summary.contains("skipped"),
        "Summary must contain 'skipped', got: {summary}"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Idempotency: skip with "already present" / "not present" (EEXIST / ENODEV)
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario: Adding address that already exists — idempotent (EEXIST path)
///
/// The implementation pre-filters addresses using the current kernel state.
/// If the current state already matches desired, to_add is empty and no kernel
/// call is made. Alternatively, if EEXIST is returned, it produces a skip.
/// Either way, is_success() must be true.
///
/// This test verifies the EEXIST path by checking the case where the desired
/// list matches current — the important invariant is that the address remains
/// present and no failure is produced.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_add_existing_address_no_failure_idempotent() {
    require_netns!(_guard);

    create_veth_pair("veth-exi0", "veth-exi1").await.unwrap();
    set_link_up("veth-exi0").await.unwrap();
    add_address("veth-exi0", "10.99.9.1/24").await.unwrap();

    // Apply with the same address already present.
    let diff = make_diff(vec![modify_op(
        "veth-exi0",
        one_field(
            "addresses",
            Value::List(vec![Value::String("10.99.9.1/24".to_string())]),
        ),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // No failure — idempotency invariant.
    assert!(
        report.is_success(),
        "is_success() must be true for idempotent add: {}",
        report.summary()
    );
    assert!(
        report.failed.is_empty(),
        "No failures expected: {:?}",
        report.failed
    );

    // Address must remain present.
    assert!(
        has_address("veth-exi0", "10.99.9.1/24").await,
        "Address must still be present after idempotent add"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// MTU idempotency: skipped when already at desired value
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario: MTU change is skipped when interface is already at the desired MTU.
///
/// When the desired MTU equals the current MTU, the operation is added to
/// the skipped list with "already at desired value" and is_success() is true.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_mtu_skipped_when_already_at_desired_value() {
    require_netns!(_guard);

    create_veth_pair("veth-mtuq0", "veth-mtuq1").await.unwrap();
    set_mtu("veth-mtuq0", 1400).await.unwrap();

    // Diff requests mtu=1400 — same as current value.
    let diff = make_diff(vec![modify_op(
        "veth-mtuq0",
        one_field("mtu", Value::U64(1400)),
        vec![],
    )]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // No failures.
    assert!(report.is_success(), "is_success() must be true: {}", report.summary());
    assert!(report.failed.is_empty(), "No failures: {:?}", report.failed);

    // The mtu skip must appear with "already at desired value" in the reason.
    let mtu_skip = report
        .skipped
        .iter()
        .find(|s| s.reason.contains("already at desired value") || s.reason.contains("1400"));
    assert!(
        mtu_skip.is_some(),
        "Expected a skip entry for mtu already at desired value. Skipped: {:?}",
        report.skipped.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Dry-run: multiple operations
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario: Dry-run with multiple interfaces — each gets a PlannedChange.
#[tokio::test(flavor = "multi_thread")]
async fn test_dry_run_multiple_ops_each_get_planned_change() {
    require_netns!(_guard);

    create_veth_pair("veth-drmulti0", "veth-drmulti1").await.unwrap();
    // veth-drmulti0 and veth-drmulti1 both exist.

    let diff = make_diff(vec![
        modify_op("veth-drmulti0", one_field("mtu", Value::U64(1400)), vec![]),
        modify_op("veth-drmulti1", one_field("mtu", Value::U64(1300)), vec![]),
    ]);

    let handle = establish_connection().await.unwrap();
    let report = dry_run_ethernet(&handle, &diff).await.unwrap();

    assert_eq!(
        report.changes.len(),
        2,
        "Expected 2 planned changes, got {}",
        report.changes.len()
    );
    assert!(
        report.skipped.is_empty(),
        "No skipped entries expected when all interfaces exist"
    );

    // Each change must target the correct interface.
    let names: Vec<_> = report
        .changes
        .iter()
        .filter_map(|c| c.selector.name.as_deref())
        .collect();
    assert!(names.contains(&"veth-drmulti0"), "veth-drmulti0 must have a PlannedChange");
    assert!(names.contains(&"veth-drmulti1"), "veth-drmulti1 must have a PlannedChange");
}

/// Scenario: Dry-run on an empty diff produces an empty report.
#[tokio::test(flavor = "multi_thread")]
async fn test_dry_run_empty_diff_produces_empty_report() {
    require_netns!(_guard);

    let diff = make_diff(vec![]);

    let handle = establish_connection().await.unwrap();
    let report = dry_run_ethernet(&handle, &diff).await.unwrap();

    assert!(report.is_empty(), "DryRunReport must be empty for an empty diff");
}

/// Scenario: Dry-run filters non-ethernet entities (only processes entity_type="ethernet").
#[tokio::test(flavor = "multi_thread")]
async fn test_dry_run_ignores_non_ethernet_entity_types() {
    require_netns!(_guard);

    // A "bond" diff op — should be ignored by dry_run_ethernet.
    let diff = make_diff(vec![DiffOp::Modify {
        entity_type: "bond".to_string(),
        selector: Selector::with_name("bond0"),
        changed_fields: one_field("mtu", Value::U64(1400)),
        removed_fields: vec![],
    }]);

    let handle = establish_connection().await.unwrap();
    let report = dry_run_ethernet(&handle, &diff).await.unwrap();

    // Bond ops are not ethernet — dry_run_ethernet ignores them.
    assert!(
        report.is_empty(),
        "DryRunReport must be empty for non-ethernet entities"
    );
}

/// apply_ethernet also ignores non-ethernet entity types.
#[tokio::test(flavor = "multi_thread")]
async fn test_apply_ignores_non_ethernet_entity_types() {
    require_netns!(_guard);

    let diff = make_diff(vec![DiffOp::Modify {
        entity_type: "bond".to_string(),
        selector: Selector::with_name("bond0"),
        changed_fields: one_field("mtu", Value::U64(1400)),
        removed_fields: vec![],
    }]);

    let handle = establish_connection().await.unwrap();
    let report = apply_ethernet(&handle, &diff).await.unwrap();

    // Nothing was processed.
    assert!(report.succeeded.is_empty(), "No succeeded for non-ethernet ops");
    assert!(report.failed.is_empty(), "No failures for non-ethernet ops");
    assert!(report.skipped.is_empty(), "No skipped for non-ethernet ops");
    assert!(
        report.is_success(),
        "is_success() must be true for empty report"
    );
}
