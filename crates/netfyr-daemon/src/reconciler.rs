//! Reconciliation engine wrapper for the daemon.
//!
//! `Reconciler` is stateless except for the `BackendRegistry` and
//! `SchemaRegistry` it holds at construction time. It can be called from both
//! the Varlink request handler and the factory event handler without locking.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use netfyr_backend::{ApplyReport, BackendRegistry, NetlinkBackend};
use netfyr_policy::{FactoryType, StaticFactory, StateFactory};
use netfyr_reconcile::{
    generate_diff, merge, ConflictReport, EntityKey, PolicyId, PolicyInput,
    StateDiff as ReconcileStateDiff,
};
use netfyr_state::{Selector, SchemaRegistry, StateSet};

use crate::factory_manager::FactoryManager;
use crate::policy_store::PolicyStore;

// ── ApplyResult ───────────────────────────────────────────────────────────────

/// The result of a full reconciliation and apply cycle.
pub struct ApplyResult {
    pub report: ApplyReport,
    pub conflicts: ConflictReport,
}

// ── Reconciler ────────────────────────────────────────────────────────────────

/// Coordinates reconciliation: merges policy inputs, diffs against actual
/// system state, and applies changes via the backend registry.
pub struct Reconciler {
    backend_registry: BackendRegistry,
    schema_registry: SchemaRegistry,
}

impl Reconciler {
    /// Create a `Reconciler` with the standard backend and schema registries.
    pub fn new() -> Self {
        let mut registry = BackendRegistry::new();
        let netlink = Arc::new(NetlinkBackend::new());
        if let Err(e) = registry.register(netlink) {
            tracing::error!("Failed to register NetlinkBackend: {}", e);
        }
        Self {
            backend_registry: registry,
            schema_registry: SchemaRegistry::default(),
        }
    }

    /// Run full reconciliation and apply the resulting diff to the system.
    ///
    /// Steps:
    /// 1. Build `PolicyInput` list from static policies and factory states.
    /// 2. Run `merge()` to produce the effective desired state.
    /// 3. Query actual system state via the backend registry.
    /// 4. Compute `netfyr_state::StateDiff` (the apply-level diff).
    /// 5. If the diff is empty, short-circuit and return an empty report.
    /// 6. Apply the diff; return the report and any conflicts.
    pub async fn reconcile_and_apply(
        &self,
        policy_store: &PolicyStore,
        factory_manager: &FactoryManager,
    ) -> Result<ApplyResult> {
        let inputs = self.build_policy_inputs(policy_store, factory_manager);
        let merged = merge(inputs);
        let effective_state = merged.effective_state;
        let conflicts = merged.conflicts;

        let actual_state = self.backend_registry.query_all().await?;

        // Restrict the actual state to only the entities present in the effective
        // desired state before computing the diff. This prevents the daemon from
        // generating Remove operations for interfaces not covered by any policy —
        // the daemon must not tear down or bring down unmanaged interfaces.
        //
        // Consequence: when a policy is removed entirely, the previously-configured
        // fields (e.g., addresses from a DHCP lease) will linger on the interface
        // until the lease expires or the interface is reconfigured. Individual field
        // removal within a still-managed entity is handled correctly via Modify ops.
        let mut managed_actual = StateSet::new();
        for (entity_type, selector_key) in effective_state.entities() {
            if let Some(state) = actual_state.get(&entity_type, &selector_key) {
                managed_actual.insert(state.clone());
            }
        }

        // Use netfyr_state::diff::diff (the apply-level diff, not the rich display diff).
        // diff(from=managed_actual, to=desired) produces Add/Modify operations for the
        // managed entities only — no Remove ops are generated for unmanaged interfaces.
        let state_diff = netfyr_state::diff::diff(&managed_actual, &effective_state);

        if state_diff.is_empty() {
            tracing::debug!("Reconciliation: no changes needed");
            return Ok(ApplyResult {
                report: ApplyReport::new(),
                conflicts,
            });
        }

        let report = self.backend_registry.apply(&state_diff).await?;
        Ok(ApplyResult { report, conflicts })
    }

    /// Compute what changes *would* be made without applying them.
    ///
    /// Returns the rich `netfyr_reconcile::StateDiff` (with per-field old→new
    /// values) suitable for Varlink serialization, along with any conflicts.
    pub async fn dry_run(
        &self,
        policy_store: &PolicyStore,
        factory_manager: &FactoryManager,
    ) -> Result<(ReconcileStateDiff, ConflictReport)> {
        let inputs = self.build_policy_inputs(policy_store, factory_manager);
        // Compute managed_entities before merge() consumes the inputs.
        // Only entities with produced state are counted; factory policies that have
        // not yet produced state cannot be removed anyway (nothing to remove).
        let managed_entities: HashSet<EntityKey> = inputs
            .iter()
            .flat_map(|input| input.state_set.entities())
            .collect();
        let merged = merge(inputs);
        let effective_state = merged.effective_state;
        let conflicts = merged.conflicts;

        let actual_state = self.backend_registry.query_all().await?;

        // Use generate_diff for the rich display diff (with per-field change details).
        // Note argument order: generate_diff(desired, actual, managed_entities, schema).
        let reconcile_diff =
            generate_diff(&effective_state, &actual_state, &managed_entities, &self.schema_registry);

        Ok((reconcile_diff, conflicts))
    }

    /// Query current system state via the backend registry.
    ///
    /// If `entity_type` is `Some`, only that backend is queried.
    /// If `None`, all backends are queried and their results merged.
    pub async fn query(
        &self,
        entity_type: Option<&str>,
        selector: Option<&Selector>,
    ) -> Result<StateSet> {
        if let Some(et) = entity_type {
            let state_set = self
                .backend_registry
                .query(&et.to_string(), selector)
                .await?;
            Ok(state_set)
        } else {
            let state_set = self.backend_registry.query_all().await?;
            Ok(state_set)
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Build the `Vec<PolicyInput>` fed into `merge()`.
    ///
    /// - For each **static** policy: call `StaticFactory.produce(policy)` to
    ///   get its `StateSet`, then wrap in `PolicyInput`.
    /// - For each **factory-produced** state: wrap the single state in a
    ///   `StateSet` and create a `PolicyInput` using the policy's priority
    ///   (falling back to 100 if the policy is no longer in the store).
    ///
    /// Policies whose `StaticFactory.produce()` call fails are logged and
    /// skipped rather than aborting the entire reconciliation.
    fn build_policy_inputs(
        &self,
        policy_store: &PolicyStore,
        factory_manager: &FactoryManager,
    ) -> Vec<PolicyInput> {
        let static_factory = StaticFactory;
        let mut inputs = Vec::new();

        // Static policies
        for policy in policy_store.policies() {
            if policy.factory_type != FactoryType::Static {
                continue;
            }
            match static_factory.produce(policy) {
                Ok(state_set) => {
                    inputs.push(PolicyInput {
                        policy_id: PolicyId(policy.name.clone()),
                        priority: policy.priority,
                        state_set,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        policy = %policy.name,
                        error = %e,
                        "Failed to produce state from static policy; skipping"
                    );
                }
            }
        }

        // Factory-produced states (DHCPv4 leases)
        for (policy_name, state) in factory_manager.produced_states() {
            let priority = policy_store
                .policies()
                .iter()
                .find(|p| p.name == policy_name)
                .map(|p| p.priority)
                .unwrap_or(100);

            let mut state_set = StateSet::new();
            state_set.insert(state);

            inputs.push(PolicyInput {
                policy_id: PolicyId(policy_name),
                priority,
                state_set,
            });
        }

        inputs
    }
}

// ── Reconciler tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_manager::FactoryManager;
    use crate::policy_store::PolicyStore;

    // ── Feature: Reconciler initialization ────────────────────────────────────

    /// Smoke test: Reconciler::new() must not panic.
    #[test]
    fn test_reconciler_new_does_not_panic() {
        let _reconciler = Reconciler::new();
    }

    // ── Feature: Dry-run with empty policy store ───────────────────────────────

    /// Scenario: Dry-run computes diff without applying — empty store returns Ok.
    #[tokio::test]
    async fn test_reconciler_dry_run_with_empty_ephemeral_store_returns_ok() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();
        let result = reconciler.dry_run(&store, &factory_manager).await;
        assert!(
            result.is_ok(),
            "dry_run with empty store must succeed: {:?}",
            result.err()
        );
    }

    /// Scenario: Dry-run with empty store produces no conflicts.
    #[tokio::test]
    async fn test_reconciler_dry_run_with_empty_store_produces_no_conflicts() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();
        let (_, conflicts) = reconciler
            .dry_run(&store, &factory_manager)
            .await
            .unwrap();
        assert!(
            conflicts.is_empty(),
            "empty policy store must produce no conflicts"
        );
    }

    /// Scenario: Dry-run does not modify system state (result is not applied).
    /// We verify this by running dry_run twice and getting identical results.
    #[tokio::test]
    async fn test_reconciler_dry_run_is_repeatable() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();

        let (diff1, _) = reconciler.dry_run(&store, &factory_manager).await.unwrap();
        let (diff2, _) = reconciler.dry_run(&store, &factory_manager).await.unwrap();
        // Both dry-runs should see the same number of operations (system unchanged).
        assert_eq!(
            diff1.len(),
            diff2.len(),
            "dry_run must not alter system state: both runs must produce the same diff length"
        );
    }

    // ── Feature: Query via daemon ──────────────────────────────────────────────

    /// Scenario: Query returns current system state — query with no filter succeeds.
    #[tokio::test]
    async fn test_reconciler_query_all_returns_ok() {
        let reconciler = Reconciler::new();
        let result = reconciler.query(None, None).await;
        assert!(
            result.is_ok(),
            "query with no entity type filter must succeed: {:?}",
            result.err()
        );
    }

    /// Scenario: Query returns a StateSet (possibly empty, possibly with interfaces).
    #[tokio::test]
    async fn test_reconciler_query_returns_state_set() {
        let reconciler = Reconciler::new();
        let state_set = reconciler.query(None, None).await.unwrap();
        // In any environment the query must succeed. The returned set may be empty
        // (in minimal test environments) or non-empty (host with real interfaces).
        // We only verify the call succeeds and the result is a valid StateSet.
        let _len = state_set.len(); // just verify it's usable
    }

    // ── Feature: Full reconcile_and_apply ─────────────────────────────────────

    /// Scenario: reconcile_and_apply with empty store is a no-op and returns Ok.
    ///
    /// With an empty desired state the diff is empty, so nothing is applied.
    /// This smoke-tests the full reconcile_and_apply path without needing
    /// a real interface or write permissions.
    #[tokio::test]
    async fn test_reconciler_reconcile_and_apply_empty_store_returns_ok() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();
        let result = reconciler.reconcile_and_apply(&store, &factory_manager).await;
        assert!(
            result.is_ok(),
            "reconcile_and_apply with empty store must succeed: {:?}",
            result.err()
        );
    }

    /// Scenario: reconcile_and_apply with empty store produces no conflicts.
    #[tokio::test]
    async fn test_reconciler_reconcile_and_apply_empty_store_no_conflicts() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();
        let apply_result = reconciler
            .reconcile_and_apply(&store, &factory_manager)
            .await
            .unwrap();
        assert!(
            apply_result.conflicts.is_empty(),
            "empty policy store must produce no conflicts during reconcile_and_apply"
        );
    }

    /// Scenario: reconcile_and_apply with empty store produces a successful report
    /// (no failures — the empty-diff short-circuit returns a fresh ApplyReport).
    #[tokio::test]
    async fn test_reconciler_reconcile_and_apply_empty_store_report_has_no_failures() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();
        let apply_result = reconciler
            .reconcile_and_apply(&store, &factory_manager)
            .await
            .unwrap();
        assert!(
            apply_result.report.is_success(),
            "empty policy store must produce a successful (no-failure) apply report"
        );
    }

    // ── Feature: Dry-run with policy ──────────────────────────────────────────

    /// Scenario: Dry-run with a static policy for a nonexistent interface returns Ok.
    ///
    /// The dry-run path only reads system state and generates a diff — it does not
    /// apply anything. So it must succeed even when the target interface is absent.
    #[tokio::test]
    async fn test_reconciler_dry_run_with_static_policy_returns_ok() {
        use netfyr_policy::parse_policy_yaml;
        let reconciler = Reconciler::new();
        let yaml = "kind: policy\nname: test\nfactory: static\npriority: 100\n\
                    state:\n  type: ethernet\n  name: nonexistent-eth99\n  mtu: 1400\n";
        let policies = parse_policy_yaml(yaml).unwrap();
        let store = PolicyStore::ephemeral(policies);
        let factory_manager = FactoryManager::new();
        let result = reconciler.dry_run(&store, &factory_manager).await;
        assert!(
            result.is_ok(),
            "dry_run with a static policy must succeed: {:?}",
            result.err()
        );
    }

    /// Scenario: Dry-run does not alter state — calling reconcile_and_apply
    /// before and after dry_run produces identical results, confirming dry_run
    /// is truly read-only.
    #[tokio::test]
    async fn test_reconciler_dry_run_does_not_alter_system_state() {
        let reconciler = Reconciler::new();
        let store = PolicyStore::ephemeral(vec![]);
        let factory_manager = FactoryManager::new();

        // Take a snapshot of system state before dry_run.
        let before = reconciler.query(None, None).await.unwrap();
        // Run dry_run (which must be a no-op for the system).
        let _ = reconciler.dry_run(&store, &factory_manager).await.unwrap();
        // Snapshot after.
        let after = reconciler.query(None, None).await.unwrap();

        assert_eq!(
            before.len(),
            after.len(),
            "dry_run must not change the number of system entities"
        );
    }
}
