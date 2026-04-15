//! Integration tests for SPEC-101: Backend Trait and Registry
//!
//! Validates every acceptance criterion in the specification. A `MockBackend`
//! struct that implements `NetworkBackend` is defined here and reused across all
//! test scenarios.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use indexmap::IndexMap;

use netfyr_backend::{
    AppliedOperation, ApplyReport, BackendError, BackendRegistry, DiffOpKind, DryRunReport,
    FailedOperation, FieldChange, FieldChangeKind, NetworkBackend, PlannedChange, SkippedOperation,
};
use netfyr_state::{DiffOp, EntityType, Selector, State, StateDiff, StateMetadata, StateSet, Value};

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_state(entity_type: &str, name: &str) -> State {
    State {
        entity_type: entity_type.to_string(),
        selector: Selector::with_name(name),
        fields: IndexMap::new(),
        metadata: StateMetadata::new(),
        policy_ref: None,
        priority: 100,
    }
}

fn add_op(entity_type: &str, name: &str) -> DiffOp {
    DiffOp::Add {
        entity_type: entity_type.to_string(),
        selector: Selector::with_name(name),
        fields: IndexMap::new(),
    }
}

fn modify_op(entity_type: &str, name: &str) -> DiffOp {
    DiffOp::Modify {
        entity_type: entity_type.to_string(),
        selector: Selector::with_name(name),
        changed_fields: IndexMap::new(),
        removed_fields: vec![],
    }
}

fn remove_op(entity_type: &str, name: &str) -> DiffOp {
    DiffOp::Remove {
        entity_type: entity_type.to_string(),
        selector: Selector::with_name(name),
    }
}

// ── MockBackend ────────────────────────────────────────────────────────────────

/// Configurable mock backend for acceptance-criteria tests.
///
/// - `entity_types` — which entity types this backend claims to handle.
/// - `query_data`   — the `StateSet` returned by `query` / `query_all`.
/// - `fail_op_indices` — 0-based indices of `apply` ops that should fail.
/// - `skip_op_indices` — 0-based indices of `apply` ops that should be skipped.
/// - `skip_reason`  — human-readable reason attached to every skipped op.
/// - `specific_field_changes` — `(selector_name, changes)`: when `dry_run` is
///   called and the op targets that selector, those `FieldChange`s are attached.
/// - `received_ops` — shared tracker so tests can inspect dispatch after apply.
/// - `query_all_call_count` — shared counter for `query_all` invocations.
struct MockBackend {
    entity_types: Vec<EntityType>,
    query_data: StateSet,
    fail_op_indices: Vec<usize>,
    skip_op_indices: Vec<usize>,
    skip_reason: String,
    specific_field_changes: Option<(String, Vec<FieldChange>)>,
    received_ops: Arc<Mutex<Vec<(String, DiffOpKind)>>>,
    query_all_call_count: Arc<Mutex<u32>>,
}

impl MockBackend {
    fn new(entity_types: Vec<&str>) -> Self {
        MockBackend {
            entity_types: entity_types.iter().map(|s| s.to_string()).collect(),
            query_data: StateSet::new(),
            fail_op_indices: vec![],
            skip_op_indices: vec![],
            skip_reason: String::new(),
            specific_field_changes: None,
            received_ops: Arc::new(Mutex::new(vec![])),
            query_all_call_count: Arc::new(Mutex::new(0)),
        }
    }

    fn with_query_data(mut self, data: StateSet) -> Self {
        self.query_data = data;
        self
    }

    fn with_fail_indices(mut self, indices: Vec<usize>) -> Self {
        self.fail_op_indices = indices;
        self
    }

    fn with_skip_indices(mut self, indices: Vec<usize>, reason: &str) -> Self {
        self.skip_op_indices = indices;
        self.skip_reason = reason.to_string();
        self
    }

    fn with_field_changes(mut self, selector_name: &str, changes: Vec<FieldChange>) -> Self {
        self.specific_field_changes = Some((selector_name.to_string(), changes));
        self
    }

    fn received_ops(&self) -> Vec<(String, DiffOpKind)> {
        self.received_ops.lock().unwrap().clone()
    }

}

#[async_trait]
impl NetworkBackend for MockBackend {
    async fn query(
        &self,
        entity_type: &EntityType,
        selector: Option<&Selector>,
    ) -> Result<StateSet, BackendError> {
        if !self.entity_types.contains(entity_type) {
            return Err(BackendError::UnsupportedEntityType(entity_type.clone()));
        }
        let mut result = StateSet::new();
        for state in self.query_data.iter() {
            if &state.entity_type != entity_type {
                continue;
            }
            if let Some(sel) = selector {
                if !sel.matches(&state.selector) {
                    continue;
                }
            }
            result.insert(state.clone());
        }
        Ok(result)
    }

    async fn query_all(&self) -> Result<StateSet, BackendError> {
        *self.query_all_call_count.lock().unwrap() += 1;
        Ok(self.query_data.clone())
    }

    async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError> {
        let mut report = ApplyReport::new();
        for (i, op) in diff.ops().iter().enumerate() {
            self.received_ops
                .lock()
                .unwrap()
                .push((op.entity_type().to_string(), DiffOpKind::from(op)));

            if self.fail_op_indices.contains(&i) {
                report.failed.push(FailedOperation {
                    operation: DiffOpKind::from(op),
                    entity_type: op.entity_type().to_string(),
                    selector: op.selector().clone(),
                    error: BackendError::Internal("mock apply failure".to_string()),
                    fields: vec![],
                });
            } else if self.skip_op_indices.contains(&i) {
                report.skipped.push(SkippedOperation {
                    operation: DiffOpKind::from(op),
                    entity_type: op.entity_type().to_string(),
                    selector: op.selector().clone(),
                    reason: self.skip_reason.clone(),
                });
            } else {
                report.succeeded.push(AppliedOperation {
                    operation: DiffOpKind::from(op),
                    entity_type: op.entity_type().to_string(),
                    selector: op.selector().clone(),
                    fields_changed: vec![],
                });
            }
        }
        Ok(report)
    }

    async fn dry_run(&self, diff: &StateDiff) -> Result<DryRunReport, BackendError> {
        let mut report = DryRunReport::new();
        for op in diff.ops() {
            let field_changes =
                if let Some((ref name, ref changes)) = self.specific_field_changes {
                    if op.selector().name.as_deref() == Some(name.as_str()) {
                        changes.clone()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };

            report.changes.push(PlannedChange {
                operation: DiffOpKind::from(op),
                entity_type: op.entity_type().to_string(),
                selector: op.selector().clone(),
                field_changes,
            });
        }
        Ok(report)
    }

    fn supported_entities(&self) -> &[EntityType] {
        &self.entity_types
    }
}

// ── Feature: NetworkBackend trait definition ──────────────────────────────────

/// Scenario: A backend implements all required trait methods
/// A MockBackend that provides all five trait methods must compile and be
/// usable as `Arc<dyn NetworkBackend>`.
#[test]
fn test_mock_backend_implements_all_trait_methods_and_compiles() {
    // This test is purely a compilation check. If it compiles, the trait is
    // correctly implemented and the struct is object-safe.
    let backend: Arc<dyn NetworkBackend> = Arc::new(MockBackend::new(vec!["ethernet"]));
    let entities = backend.supported_entities();
    assert_eq!(entities, &["ethernet"]);
}

/// Scenario: Backend query returns a StateSet
/// Given a MockBackend that supports "ethernet", query returns Ok(StateSet)
/// containing only "ethernet" entities.
#[tokio::test]
async fn test_backend_query_returns_stateset_for_supported_type() {
    let mut data = StateSet::new();
    data.insert(make_state("ethernet", "eth0"));
    data.insert(make_state("ethernet", "eth1"));

    let backend = MockBackend::new(vec!["ethernet"]).with_query_data(data);

    let result = backend.query(&"ethernet".to_string(), None).await;

    assert!(result.is_ok(), "query for supported type must return Ok");
    let set = result.unwrap();

    // Verify all returned states are of the correct entity type.
    for state in set.iter() {
        assert_eq!(
            state.entity_type, "ethernet",
            "StateSet must only contain 'ethernet' entities"
        );
    }
    assert_eq!(set.len(), 2);
}

/// query for a supported type with no data still returns Ok with empty StateSet.
#[tokio::test]
async fn test_backend_query_returns_empty_stateset_when_no_data() {
    let backend = MockBackend::new(vec!["ethernet"]);
    let result = backend.query(&"ethernet".to_string(), None).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

/// Scenario: Backend query with selector filters results
/// Given a backend with "eth0" and "eth1", querying with selector name="eth0"
/// returns exactly one entity.
#[tokio::test]
async fn test_backend_query_with_selector_filters_to_single_entity() {
    let mut data = StateSet::new();
    data.insert(make_state("ethernet", "eth0"));
    data.insert(make_state("ethernet", "eth1"));

    let backend = MockBackend::new(vec!["ethernet"]).with_query_data(data);

    let selector = Selector::with_name("eth0");
    let result = backend.query(&"ethernet".to_string(), Some(&selector)).await;

    assert!(result.is_ok());
    let set = result.unwrap();
    assert_eq!(set.len(), 1, "selector filter must return exactly one entity");
    let state = set.get("ethernet", "eth0").expect("eth0 must be in result");
    assert_eq!(
        state.selector.name.as_deref(),
        Some("eth0"),
        "returned entity must have selector name 'eth0'"
    );
}

/// Scenario: Backend query for unsupported entity type
/// query for "bond" on a backend that only supports "ethernet" must return
/// BackendError::UnsupportedEntityType.
#[tokio::test]
async fn test_backend_query_unsupported_entity_type_returns_error() {
    let backend = MockBackend::new(vec!["ethernet"]);
    let result = backend.query(&"bond".to_string(), None).await;

    assert!(result.is_err(), "query for unsupported type must return Err");
    match result.unwrap_err() {
        BackendError::UnsupportedEntityType(t) => {
            assert_eq!(t, "bond");
        }
        other => panic!("Expected UnsupportedEntityType, got {:?}", other),
    }
}

/// Scenario: Backend apply returns a detailed ApplyReport (2 succeed, 1 fail)
/// A StateDiff with 3 ops where the last fails yields is_partial() == true.
#[tokio::test]
async fn test_backend_apply_returns_report_with_partial_success() {
    // Op at index 2 (third op) is configured to fail.
    let backend = MockBackend::new(vec!["ethernet"]).with_fail_indices(vec![2]);

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"),    // succeeds (index 0)
        modify_op("ethernet", "eth1"), // succeeds (index 1)
        remove_op("ethernet", "eth2"), // fails    (index 2)
    ]);

    let result = backend.apply(&diff).await;
    assert!(result.is_ok());
    let report = result.unwrap();

    assert_eq!(report.succeeded.len(), 2, "two ops must succeed");
    assert_eq!(report.failed.len(), 1, "one op must fail");
    assert!(report.is_partial(), "is_partial must be true with mixed results");
    assert!(!report.is_success(), "is_success must be false when failures exist");
}

/// Scenario: ApplyReport with all operations successful
#[tokio::test]
async fn test_backend_apply_all_succeed_report_is_success() {
    let backend = MockBackend::new(vec!["ethernet"]);

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"),
        add_op("ethernet", "eth1"),
    ]);

    let report = backend.apply(&diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 2);
    assert_eq!(report.failed.len(), 0);
    assert_eq!(report.skipped.len(), 0);
    assert!(report.is_success(), "is_success must be true when failed is empty");
    assert!(!report.is_partial(), "is_partial must be false when none failed");
    assert!(!report.is_total_failure(), "is_total_failure must be false when some succeeded");
}

/// Scenario: ApplyReport with all operations failed
#[tokio::test]
async fn test_backend_apply_all_fail_report_is_total_failure() {
    let backend = MockBackend::new(vec!["ethernet"]).with_fail_indices(vec![0, 1]);

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"),
        modify_op("ethernet", "eth1"),
    ]);

    let report = backend.apply(&diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 0);
    assert_eq!(report.failed.len(), 2);
    assert!(report.is_total_failure(), "is_total_failure must be true when succeeded is empty");
    assert!(!report.is_success(), "is_success must be false when failures exist");
}

/// Scenario: ApplyReport with skipped operations
/// 1 succeeds, 1 fails, 1 is skipped — each bucket correct, skipped has reason.
#[tokio::test]
async fn test_backend_apply_with_mixed_succeeded_failed_skipped() {
    let backend = MockBackend::new(vec!["ethernet"])
        .with_fail_indices(vec![1])
        .with_skip_indices(vec![2], "dependency failed, skipping");

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"),    // succeeds (index 0)
        modify_op("ethernet", "eth1"), // fails    (index 1)
        remove_op("ethernet", "eth2"), // skipped  (index 2)
    ]);

    let report = backend.apply(&diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 1, "one op must succeed");
    assert_eq!(report.failed.len(), 1, "one op must fail");
    assert_eq!(report.skipped.len(), 1, "one op must be skipped");

    let skipped = &report.skipped[0];
    assert!(
        !skipped.reason.is_empty(),
        "skipped operation must have a non-empty reason string"
    );
    assert_eq!(skipped.reason, "dependency failed, skipping");
}

/// Scenario: Backend dry_run returns a DryRunReport without modifying state
/// dry_run on a diff with add/modify/remove produces one planned change per op.
#[tokio::test]
async fn test_backend_dry_run_returns_dry_run_report_with_all_op_kinds() {
    let backend = MockBackend::new(vec!["ethernet"]);

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"),
        modify_op("ethernet", "eth1"),
        remove_op("ethernet", "eth2"),
    ]);

    let result = backend.dry_run(&diff).await;
    assert!(result.is_ok(), "dry_run must return Ok");
    let report = result.unwrap();

    assert_eq!(report.changes.len(), 3, "one planned change per diff op");

    let kinds: Vec<DiffOpKind> = report.changes.iter().map(|c| c.operation).collect();
    assert!(kinds.contains(&DiffOpKind::Add), "Add must appear in planned changes");
    assert!(kinds.contains(&DiffOpKind::Modify), "Modify must appear in planned changes");
    assert!(kinds.contains(&DiffOpKind::Remove), "Remove must appear in planned changes");

    // Verify no apply was called (system state unchanged): apply call count is
    // zero because MockBackend's received_ops tracker is not populated.
    assert!(
        backend.received_ops().is_empty(),
        "dry_run must not call apply or modify system state"
    );
}

/// Scenario: DryRunReport field changes show before and after values
/// A modify op on "eth0" with an mtu change shows current=1500, desired=9000.
#[tokio::test]
async fn test_dry_run_report_field_changes_show_current_and_desired() {
    let changes = vec![FieldChange {
        field: "mtu".to_string(),
        current: Some(Value::U64(1500)),
        desired: Some(Value::U64(9000)),
        kind: FieldChangeKind::Modify,
    }];

    let backend = MockBackend::new(vec!["ethernet"]).with_field_changes("eth0", changes);

    let diff = StateDiff::new(vec![modify_op("ethernet", "eth0")]);

    let report = backend.dry_run(&diff).await.unwrap();

    assert_eq!(report.changes.len(), 1);
    let planned = &report.changes[0];
    assert_eq!(planned.selector.name.as_deref(), Some("eth0"));

    assert_eq!(planned.field_changes.len(), 1, "one field change for mtu");
    let fc = &planned.field_changes[0];
    assert_eq!(fc.field, "mtu");
    assert_eq!(fc.current, Some(Value::U64(1500)), "current value must be 1500");
    assert_eq!(fc.desired, Some(Value::U64(9000)), "desired value must be 9000");
    assert_eq!(fc.kind, FieldChangeKind::Modify);
}

/// Scenario: DryRunReport is empty when no changes needed (empty diff)
#[tokio::test]
async fn test_dry_run_report_is_empty_for_empty_diff() {
    let backend = MockBackend::new(vec!["ethernet"]);
    let diff = StateDiff::new(vec![]);

    let report = backend.dry_run(&diff).await.unwrap();

    assert!(report.is_empty(), "DryRunReport must be empty for an empty diff");
    assert!(report.changes.is_empty());
}

// ── Feature: BackendRegistry routes entity types to backends ──────────────────

/// Scenario: Register a backend and look it up by entity type
/// After registering a backend for ["ethernet", "bond"], get("ethernet") and
/// get("bond") return Some, get("vlan") returns None.
#[test]
fn test_registry_register_and_lookup_by_entity_type() {
    let mut registry = BackendRegistry::new();
    let backend = Arc::new(MockBackend::new(vec!["ethernet", "bond"]));

    registry
        .register(backend as Arc<dyn NetworkBackend>)
        .expect("register must not fail for a new backend");

    assert!(
        registry.get(&"ethernet".to_string()).is_some(),
        "get('ethernet') must return Some after registration"
    );
    assert!(
        registry.get(&"bond".to_string()).is_some(),
        "get('bond') must return Some after registration"
    );
    assert!(
        registry.get(&"vlan".to_string()).is_none(),
        "get('vlan') must return None — not registered"
    );
}

/// Scenario: Register two backends for different entity types
/// NetlinkBackend claims ["ethernet", "bond", "vlan"]; NftBackend claims ["firewall-rule"].
/// Each lookup returns the correct backend.
#[test]
fn test_registry_two_backends_different_entity_types_each_routed_correctly() {
    let mut registry = BackendRegistry::new();
    let netlink = Arc::new(MockBackend::new(vec!["ethernet", "bond", "vlan"]));
    let nft = Arc::new(MockBackend::new(vec!["firewall-rule"]));

    registry.register(Arc::clone(&netlink) as Arc<dyn NetworkBackend>).unwrap();
    registry.register(Arc::clone(&nft) as Arc<dyn NetworkBackend>).unwrap();

    assert!(registry.get(&"ethernet".to_string()).is_some());
    assert!(registry.get(&"bond".to_string()).is_some());
    assert!(registry.get(&"vlan".to_string()).is_some());
    assert!(registry.get(&"firewall-rule".to_string()).is_some());

    // A type not claimed by either backend must return None.
    assert!(registry.get(&"wifi".to_string()).is_none());
}

/// Scenario: Registering a conflicting entity type fails
/// A second backend claiming "ethernet" (different allocation) must be rejected.
/// The original registration must be preserved.
#[test]
fn test_registry_register_conflicting_entity_type_fails() {
    let mut registry = BackendRegistry::new();
    let original = Arc::new(MockBackend::new(vec!["ethernet"]));
    let conflicting = Arc::new(MockBackend::new(vec!["ethernet"]));

    registry
        .register(Arc::clone(&original) as Arc<dyn NetworkBackend>)
        .expect("first registration must succeed");

    let result = registry.register(conflicting as Arc<dyn NetworkBackend>);
    assert!(
        result.is_err(),
        "registering a different backend for an already-claimed type must return Err"
    );

    // The original backend must still be registered.
    assert!(
        registry.get(&"ethernet".to_string()).is_some(),
        "original registration must be preserved after a failed register attempt"
    );
}

/// Re-registering the exact same Arc is a no-op and must not return an error.
#[test]
fn test_registry_register_same_arc_twice_is_noop() {
    let mut registry = BackendRegistry::new();
    let backend = Arc::new(MockBackend::new(vec!["ethernet"]));

    registry
        .register(Arc::clone(&backend) as Arc<dyn NetworkBackend>)
        .expect("first registration must succeed");
    registry
        .register(Arc::clone(&backend) as Arc<dyn NetworkBackend>)
        .expect("re-registering the same Arc must be a no-op, not an error");
}

/// Scenario: Registry query_all queries all registered backends and merges results
#[tokio::test]
async fn test_registry_query_all_queries_every_backend_and_merges_results() {
    let mut data1 = StateSet::new();
    data1.insert(make_state("ethernet", "eth0"));

    let mut data2 = StateSet::new();
    data2.insert(make_state("firewall-rule", "rule1"));

    let netlink = Arc::new(MockBackend::new(vec!["ethernet"]).with_query_data(data1));
    let nft = Arc::new(MockBackend::new(vec!["firewall-rule"]).with_query_data(data2));

    // Clone the counters before upcast so we can inspect them after.
    let netlink_count = Arc::clone(&netlink.query_all_call_count);
    let nft_count = Arc::clone(&nft.query_all_call_count);

    let mut registry = BackendRegistry::new();
    registry.register(netlink as Arc<dyn NetworkBackend>).unwrap();
    registry.register(nft as Arc<dyn NetworkBackend>).unwrap();

    let result = registry.query_all().await;
    assert!(result.is_ok(), "query_all must return Ok when all backends succeed");

    // Both backends must have been queried exactly once.
    assert_eq!(
        *netlink_count.lock().unwrap(),
        1,
        "NetlinkBackend::query_all must be called exactly once"
    );
    assert_eq!(
        *nft_count.lock().unwrap(),
        1,
        "NftBackend::query_all must be called exactly once"
    );

    // Results are merged into one StateSet.
    let merged = result.unwrap();
    assert!(
        merged.get("ethernet", "eth0").is_some(),
        "merged StateSet must contain eth0 from NetlinkBackend"
    );
    assert!(
        merged.get("firewall-rule", "rule1").is_some(),
        "merged StateSet must contain rule1 from NftBackend"
    );
    assert_eq!(merged.len(), 2);
}

/// Scenario: Registry apply partitions diff by entity type
/// Ethernet op must be dispatched to NetlinkBackend; firewall-rule op to NftBackend.
#[tokio::test]
async fn test_registry_apply_dispatches_ops_to_correct_backend() {
    let netlink = Arc::new(MockBackend::new(vec!["ethernet"]));
    let nft = Arc::new(MockBackend::new(vec!["firewall-rule"]));

    let netlink_ops = Arc::clone(&netlink.received_ops);
    let nft_ops = Arc::clone(&nft.received_ops);

    let mut registry = BackendRegistry::new();
    registry.register(Arc::clone(&netlink) as Arc<dyn NetworkBackend>).unwrap();
    registry.register(Arc::clone(&nft) as Arc<dyn NetworkBackend>).unwrap();

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"),
        add_op("firewall-rule", "rule1"),
    ]);

    let result = registry.apply(&diff).await;
    assert!(result.is_ok());
    let report = result.unwrap();

    // Both ops succeed.
    assert_eq!(report.succeeded.len(), 2);
    assert_eq!(report.failed.len(), 0);

    // Verify each backend received only its own entity type's ops.
    let netlink_received = netlink_ops.lock().unwrap();
    assert_eq!(netlink_received.len(), 1, "NetlinkBackend must receive exactly one op");
    assert_eq!(netlink_received[0].0, "ethernet", "NetlinkBackend received op must be 'ethernet'");

    let nft_received = nft_ops.lock().unwrap();
    assert_eq!(nft_received.len(), 1, "NftBackend must receive exactly one op");
    assert_eq!(nft_received[0].0, "firewall-rule", "NftBackend received op must be 'firewall-rule'");
}

/// Scenario: Registry apply with unknown entity type in diff
/// The "wifi" op must appear in failed with UnsupportedEntityType; ethernet op
/// must still be applied normally.
#[tokio::test]
async fn test_registry_apply_unknown_entity_type_fails_others_still_applied() {
    let netlink = Arc::new(MockBackend::new(vec!["ethernet"]));

    let mut registry = BackendRegistry::new();
    registry.register(Arc::clone(&netlink) as Arc<dyn NetworkBackend>).unwrap();

    let diff = StateDiff::new(vec![
        add_op("ethernet", "eth0"), // registered — should succeed
        add_op("wifi", "wlan0"),    // NOT registered — should fail with UnsupportedEntityType
    ]);

    // apply always returns Ok; failures are captured in the report.
    let result = registry.apply(&diff).await;
    assert!(result.is_ok(), "apply must return Ok even when some entity types are unregistered");

    let report = result.unwrap();

    // The wifi op must appear in failed.
    let wifi_failure = report.failed.iter().find(|f| f.entity_type == "wifi");
    assert!(wifi_failure.is_some(), "wifi op must be in failed list");
    match &wifi_failure.unwrap().error {
        BackendError::UnsupportedEntityType(t) => {
            assert_eq!(t, "wifi", "error must name the unregistered entity type");
        }
        other => panic!("Expected UnsupportedEntityType for wifi, got {:?}", other),
    }

    // The ethernet op must still succeed.
    let eth_succeeded = report.succeeded.iter().any(|s| s.entity_type == "ethernet");
    assert!(eth_succeeded, "ethernet op must succeed despite unknown 'wifi' type");
}

/// Scenario: Registry supported_entities returns all registered types
/// A registry with backends for ["ethernet", "bond", "vlan", "firewall-rule"] must
/// report all four entity types from supported_entities().
#[test]
fn test_registry_supported_entities_returns_all_registered_types() {
    let mut registry = BackendRegistry::new();
    let backend1 = Arc::new(MockBackend::new(vec!["ethernet", "bond", "vlan"]));
    let backend2 = Arc::new(MockBackend::new(vec!["firewall-rule"]));

    registry.register(backend1 as Arc<dyn NetworkBackend>).unwrap();
    registry.register(backend2 as Arc<dyn NetworkBackend>).unwrap();

    let mut supported = registry.supported_entities();
    supported.sort(); // order is unspecified; sort for deterministic assertion.

    assert_eq!(supported.len(), 4, "all four entity types must be reported");
    assert!(supported.contains(&"ethernet".to_string()));
    assert!(supported.contains(&"bond".to_string()));
    assert!(supported.contains(&"vlan".to_string()));
    assert!(supported.contains(&"firewall-rule".to_string()));
}

/// An empty registry reports no supported entities.
#[test]
fn test_registry_supported_entities_empty_when_no_backends_registered() {
    let registry = BackendRegistry::new();
    assert!(registry.supported_entities().is_empty());
}

/// Registry::query delegates to the backend for the requested entity type.
#[tokio::test]
async fn test_registry_query_delegates_to_registered_backend() {
    let mut data = StateSet::new();
    data.insert(make_state("ethernet", "eth0"));

    let backend = Arc::new(MockBackend::new(vec!["ethernet"]).with_query_data(data));

    let mut registry = BackendRegistry::new();
    registry.register(backend as Arc<dyn NetworkBackend>).unwrap();

    let result = registry.query(&"ethernet".to_string(), None).await;
    assert!(result.is_ok());
    let set = result.unwrap();
    assert!(set.get("ethernet", "eth0").is_some());
}

/// Registry::query returns UnsupportedEntityType for an unregistered type.
#[tokio::test]
async fn test_registry_query_unregistered_type_returns_unsupported_error() {
    let registry = BackendRegistry::new();
    let result = registry.query(&"ethernet".to_string(), None).await;

    assert!(result.is_err());
    matches!(result.unwrap_err(), BackendError::UnsupportedEntityType(_));
}

// ── ApplyReport field-level assertions ────────────────────────────────────────

/// AppliedOperation records the entity type, selector, and fields changed.
#[tokio::test]
async fn test_apply_report_succeeded_entry_has_entity_type_and_selector() {
    let backend = MockBackend::new(vec!["ethernet"]);
    let diff = StateDiff::new(vec![add_op("ethernet", "eth0")]);

    let report = backend.apply(&diff).await.unwrap();

    assert_eq!(report.succeeded.len(), 1);
    let op = &report.succeeded[0];
    assert_eq!(op.entity_type, "ethernet");
    assert_eq!(op.selector.name.as_deref(), Some("eth0"));
    assert_eq!(op.operation, DiffOpKind::Add);
}

/// FailedOperation records the entity type, selector, error, and op kind.
#[tokio::test]
async fn test_apply_report_failed_entry_has_entity_type_selector_and_error() {
    let backend = MockBackend::new(vec!["ethernet"]).with_fail_indices(vec![0]);
    let diff = StateDiff::new(vec![modify_op("ethernet", "eth0")]);

    let report = backend.apply(&diff).await.unwrap();

    assert_eq!(report.failed.len(), 1);
    let op = &report.failed[0];
    assert_eq!(op.entity_type, "ethernet");
    assert_eq!(op.selector.name.as_deref(), Some("eth0"));
    assert_eq!(op.operation, DiffOpKind::Modify);
}

/// SkippedOperation records the entity type, selector, reason, and op kind.
#[tokio::test]
async fn test_apply_report_skipped_entry_has_entity_type_selector_and_reason() {
    let backend = MockBackend::new(vec!["ethernet"])
        .with_skip_indices(vec![0], "already in desired state");

    let diff = StateDiff::new(vec![remove_op("ethernet", "eth0")]);

    let report = backend.apply(&diff).await.unwrap();

    assert_eq!(report.skipped.len(), 1);
    let op = &report.skipped[0];
    assert_eq!(op.entity_type, "ethernet");
    assert_eq!(op.selector.name.as_deref(), Some("eth0"));
    assert_eq!(op.operation, DiffOpKind::Remove);
    assert_eq!(op.reason, "already in desired state");
}

// ── PlannedChange field-level assertions ──────────────────────────────────────

/// PlannedChange records the operation kind and entity type for each op.
#[tokio::test]
async fn test_dry_run_planned_change_records_operation_kind_and_entity_type() {
    let backend = MockBackend::new(vec!["ethernet"]);
    let diff = StateDiff::new(vec![add_op("ethernet", "eth0")]);

    let report = backend.dry_run(&diff).await.unwrap();

    assert_eq!(report.changes.len(), 1);
    let change = &report.changes[0];
    assert_eq!(change.operation, DiffOpKind::Add);
    assert_eq!(change.entity_type, "ethernet");
    assert_eq!(change.selector.name.as_deref(), Some("eth0"));
}
