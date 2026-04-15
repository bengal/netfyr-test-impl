//! netfyr-reconcile crate — per-field priority merge for network policy reconciliation.

use std::collections::HashMap;
use std::fmt;

use netfyr_state::{FieldValue, Selector, State, StateMetadata, StateSet, Value};

// ── PolicyId ──────────────────────────────────────────────────────────────────

/// Unique identifier for a policy.
///
/// A newtype over `String` that prevents accidentally mixing policy IDs with
/// arbitrary strings while deriving all traits needed for use as a map key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyId(pub String);

impl PolicyId {
    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PolicyId {
    fn from(s: String) -> Self {
        PolicyId(s)
    }
}

impl From<&str> for PolicyId {
    fn from(s: &str) -> Self {
        PolicyId(s.to_owned())
    }
}

// ── EntityKey / FieldName ─────────────────────────────────────────────────────

/// Canonical key for an entity: `(entity_type, selector.key())`.
///
/// Aligns with the existing `StateSet` keying convention.
pub type EntityKey = (String, String);

/// A field name (e.g., `"mtu"`, `"addresses"`).
pub type FieldName = String;

// ── PolicyInput ───────────────────────────────────────────────────────────────

/// Input to the reconciliation engine from a single policy.
#[derive(Clone, Debug)]
pub struct PolicyInput {
    /// Unique identifier for this policy.
    pub policy_id: PolicyId,
    /// Priority of this policy. Higher numbers win in per-field priority resolution.
    /// The conventional default is 100.
    pub priority: u32,
    /// The state set produced by this policy.
    pub state_set: StateSet,
}

// ── FieldConflict / ConflictReport ────────────────────────────────────────────

/// A field-level conflict detected during reconciliation.
///
/// Occurs when two or more policies at the same (highest) priority provide
/// different values for the same field on the same entity.  The conflicted field
/// is **omitted** from the effective state pending SPEC-202 resolution.
#[derive(Clone, Debug)]
pub struct FieldConflict {
    /// The entity where the conflict occurred: `(entity_type, selector_key)`.
    pub entity_key: EntityKey,
    /// The name of the conflicting field.
    pub field: FieldName,
    /// All `(policy_id, value)` pairs at the tied highest priority.
    pub contenders: Vec<(PolicyId, Value)>,
}

/// A collection of field-level conflicts detected during a reconciliation run.
#[derive(Clone, Debug, Default)]
pub struct ConflictReport {
    /// Each element represents one unresolvable field conflict.
    pub conflicts: Vec<FieldConflict>,
}

impl ConflictReport {
    /// Returns a new, empty `ConflictReport`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if no conflicts were detected.
    pub fn is_empty(&self) -> bool {
        self.conflicts.is_empty()
    }

    /// Returns the number of conflicts.
    pub fn len(&self) -> usize {
        self.conflicts.len()
    }
}

// ── ReconciliationResult ──────────────────────────────────────────────────────

/// The output of the reconciliation engine.
#[derive(Clone, Debug)]
pub struct ReconciliationResult {
    /// The merged desired state of the entire system.
    pub effective_state: StateSet,
    /// Maps `((entity_type, selector_key), field_name)` to the policy that
    /// provided the winning value for that field.
    ///
    /// Conflicted fields (omitted from `effective_state`) are absent from this map.
    pub field_sources: HashMap<(EntityKey, FieldName), PolicyId>,
    /// Field conflicts detected during reconciliation.
    pub conflicts: ConflictReport,
}

// ── Merge algorithm ───────────────────────────────────────────────────────────

/// Merges N policy inputs into a single effective `StateSet` using per-field priority.
///
/// # Algorithm
///
/// 1. **Collect**: iterate every `PolicyInput`'s `StateSet`, grouping all field
///    contenders by entity key `(entity_type, selector.key())`.
/// 2. **Resolve**: for each entity, iterate each field name and pick the winner:
///    - Highest priority wins.
///    - Tie at the same priority with the **same value**: first policy (by input
///      order) is recorded in `field_sources`; no conflict is raised.
///    - Tie at the same priority with **different values**: a `FieldConflict` is
///      recorded and the field is **omitted** from the effective state.
/// 3. Build the effective `StateSet` from all winning fields and return a
///    `ReconciliationResult`.
pub fn merge(inputs: Vec<PolicyInput>) -> ReconciliationResult {
    if inputs.is_empty() {
        return ReconciliationResult {
            effective_state: StateSet::new(),
            field_sources: HashMap::new(),
            conflicts: ConflictReport::new(),
        };
    }

    // Phase 1 ── collect per-entity data.
    //
    // For each entity key we track:
    //   - The `Selector` (from the first state seen for that entity).
    //   - The maximum policy priority among all contributing policies.
    //   - Per-field: Vec<(PolicyId, policy_priority, FieldValue)>.
    type FieldContenders = Vec<(PolicyId, u32, FieldValue)>;

    struct EntityData {
        selector: Selector,
        max_policy_priority: u32,
        fields: HashMap<FieldName, FieldContenders>,
    }

    let mut entity_map: HashMap<EntityKey, EntityData> = HashMap::new();

    for input in &inputs {
        for state in input.state_set.iter() {
            let key: EntityKey = (state.entity_type.clone(), state.selector.key());

            let entry = entity_map.entry(key).or_insert_with(|| EntityData {
                selector: state.selector.clone(),
                max_policy_priority: 0,
                fields: HashMap::new(),
            });

            // Track the highest contributing policy priority for this entity.
            entry.max_policy_priority = entry.max_policy_priority.max(input.priority);

            // Accumulate per-field contenders.
            for (field_name, field_value) in &state.fields {
                entry
                    .fields
                    .entry(field_name.clone())
                    .or_default()
                    .push((input.policy_id.clone(), input.priority, field_value.clone()));
            }
        }
    }

    // Phase 2 ── resolve per-entity, per-field.
    let mut effective_state = StateSet::new();
    let mut field_sources: HashMap<(EntityKey, FieldName), PolicyId> = HashMap::new();
    let mut conflict_list: Vec<FieldConflict> = Vec::new();

    for (entity_key, entity_data) in entity_map {
        // Process field names in sorted order so the merged State's fields are
        // in a deterministic order (alphabetical by field name).
        let mut field_names: Vec<&FieldName> = entity_data.fields.keys().collect();
        field_names.sort();

        let mut merged_state = State {
            entity_type: entity_key.0.clone(),
            selector: entity_data.selector,
            fields: Default::default(),
            metadata: StateMetadata::new(),
            policy_ref: None,
            priority: entity_data.max_policy_priority,
        };

        for field_name in field_names {
            let contenders = &entity_data.fields[field_name];

            // Find the maximum priority among all contenders for this field.
            let max_priority = contenders
                .iter()
                .map(|(_, p, _)| *p)
                .max()
                .unwrap_or(0);

            // Keep only the contenders at the maximum priority.
            let top: Vec<&(PolicyId, u32, FieldValue)> = contenders
                .iter()
                .filter(|(_, p, _)| *p == max_priority)
                .collect();

            let first_value: &Value = &top[0].2.value;
            let all_agree = top.iter().all(|(_, _, fv)| &fv.value == first_value);

            if all_agree {
                // Single winner or unanimous tie — first by input order wins.
                let (winner_id, _, winner_fv) = &top[0];
                merged_state.fields.insert(field_name.clone(), winner_fv.clone());
                field_sources
                    .insert((entity_key.clone(), field_name.clone()), winner_id.clone());
            } else {
                // Irreconcilable conflict — omit the field from effective state.
                let conflict_contenders: Vec<(PolicyId, Value)> = top
                    .iter()
                    .map(|(pid, _, fv)| ((*pid).clone(), fv.value.clone()))
                    .collect();
                conflict_list.push(FieldConflict {
                    entity_key: entity_key.clone(),
                    field: field_name.clone(),
                    contenders: conflict_contenders,
                });
            }
        }

        effective_state.insert(merged_state);
    }

    ReconciliationResult {
        effective_state,
        field_sources,
        conflicts: ConflictReport {
            conflicts: conflict_list,
        },
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{merge, PolicyId, PolicyInput, ReconciliationResult};
    use netfyr_state::{FieldValue, Provenance, Selector, State, StateMetadata, StateSet, Value};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Builds a `FieldValue` with `KernelDefault` provenance (sufficient for merge tests).
    fn fv(v: Value) -> FieldValue {
        FieldValue {
            value: v,
            provenance: Provenance::KernelDefault,
        }
    }

    /// Builds a `State` for a named entity without requiring a direct `indexmap` import.
    fn make_state(entity_type: &str, name: &str, fields: Vec<(&str, Value)>) -> State {
        let mut s = State {
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            fields: Default::default(),
            metadata: StateMetadata::new(),
            policy_ref: None,
            priority: 0,
        };
        for (k, v) in fields {
            s.fields.insert(k.to_string(), fv(v));
        }
        s
    }

    /// Wraps states into a `PolicyInput`.
    fn make_input(id: &str, priority: u32, states: Vec<State>) -> PolicyInput {
        let mut ss = StateSet::new();
        for s in states {
            ss.insert(s);
        }
        PolicyInput {
            policy_id: PolicyId::from(id),
            priority,
            state_set: ss,
        }
    }

    /// Looks up which policy won a given field on a given entity.
    fn get_source<'a>(
        result: &'a ReconciliationResult,
        entity_type: &str,
        selector_key: &str,
        field: &str,
    ) -> Option<&'a PolicyId> {
        result.field_sources.get(&(
            (entity_type.to_string(), selector_key.to_string()),
            field.to_string(),
        ))
    }

    // ── Scenario: Single policy produces effective state unchanged ────────────

    #[test]
    fn test_single_policy_produces_effective_state_unchanged() {
        let addresses = Value::List(vec![Value::String("10.0.1.50/24".to_string())]);
        let input = make_input(
            "eth0-config",
            100,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![("mtu", Value::U64(1500)), ("addresses", addresses.clone())],
            )],
        );

        let result = merge(vec![input]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");
        assert_eq!(eth0.fields["mtu"].value, Value::U64(1500));
        assert_eq!(eth0.fields["addresses"].value, addresses);

        assert_eq!(
            get_source(&result, "ethernet", "eth0", "mtu").map(|p| p.as_str()),
            Some("eth0-config"),
            "mtu should be attributed to eth0-config"
        );
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "addresses").map(|p| p.as_str()),
            Some("eth0-config"),
            "addresses should be attributed to eth0-config"
        );
    }

    // ── Scenario: Two policies contribute different fields to the same entity ─

    #[test]
    fn test_two_policies_contribute_different_fields_to_same_entity() {
        let addresses = Value::List(vec![Value::String("10.0.1.50/24".to_string())]);
        let base = make_input(
            "eth0-base",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))])],
        );
        let dhcp = make_input(
            "eth0-dhcp",
            100,
            vec![make_state("ethernet", "eth0", vec![("addresses", addresses.clone())])],
        );

        let result = merge(vec![base, dhcp]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");
        assert_eq!(eth0.fields["mtu"].value, Value::U64(1500), "mtu from eth0-base");
        assert_eq!(eth0.fields["addresses"].value, addresses, "addresses from eth0-dhcp");

        assert_eq!(
            get_source(&result, "ethernet", "eth0", "mtu").map(|p| p.as_str()),
            Some("eth0-base"),
        );
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "addresses").map(|p| p.as_str()),
            Some("eth0-dhcp"),
        );
    }

    // ── Scenario: Higher priority policy overrides a field from lower priority ─

    #[test]
    fn test_higher_priority_policy_overrides_field_from_lower_priority() {
        let base = make_input(
            "eth0-base",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))])],
        );
        let override_p = make_input(
            "eth0-override",
            200,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))])],
        );

        let result = merge(vec![base, override_p]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");
        assert_eq!(
            eth0.fields["mtu"].value,
            Value::U64(9000),
            "higher-priority policy (200) must override lower-priority (100)"
        );
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "mtu").map(|p| p.as_str()),
            Some("eth0-override"),
            "mtu must be attributed to the overriding policy"
        );
    }

    // ── Scenario: Higher priority overrides only conflicting fields, not all ──

    #[test]
    fn test_higher_priority_overrides_only_conflicting_fields_not_all() {
        let addresses = Value::List(vec![Value::String("10.0.1.50/24".to_string())]);
        let base = make_input(
            "eth0-base",
            100,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![("mtu", Value::U64(1500)), ("addresses", addresses.clone())],
            )],
        );
        let override_p = make_input(
            "eth0-override",
            200,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))])],
        );

        let result = merge(vec![base, override_p]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");
        assert_eq!(eth0.fields["mtu"].value, Value::U64(9000), "mtu overridden by higher priority");
        assert_eq!(
            eth0.fields["addresses"].value, addresses,
            "addresses not overridden; should remain from base policy"
        );
    }

    // ── Scenario: Three policies with cascading priorities ────────────────────

    #[test]
    fn test_three_policies_with_cascading_priorities() {
        let default_addrs = Value::List(vec![Value::String("10.0.0.1/24".to_string())]);
        let emergency_addrs = Value::List(vec![Value::String("192.168.1.1/24".to_string())]);

        let default_p = make_input(
            "default",
            50,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![("mtu", Value::U64(1500)), ("addresses", default_addrs)],
            )],
        );
        let team_p = make_input(
            "team",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))])],
        );
        let emergency_p = make_input(
            "emergency",
            200,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![("addresses", emergency_addrs.clone())],
            )],
        );

        let result = merge(vec![default_p, team_p, emergency_p]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");

        assert_eq!(
            eth0.fields["mtu"].value,
            Value::U64(9000),
            "mtu: team (100) beats default (50)"
        );
        assert_eq!(
            eth0.fields["addresses"].value,
            emergency_addrs,
            "addresses: emergency (200) beats default (50)"
        );

        assert_eq!(
            get_source(&result, "ethernet", "eth0", "mtu").map(|p| p.as_str()),
            Some("team"),
        );
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "addresses").map(|p| p.as_str()),
            Some("emergency"),
        );
    }

    // ── Scenario: Policies targeting different entities do not interact ────────

    #[test]
    fn test_policies_targeting_different_entities_do_not_interact() {
        let eth0_config = make_input(
            "eth0-config",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))])],
        );
        let eth1_config = make_input(
            "eth1-config",
            100,
            vec![make_state("ethernet", "eth1", vec![("mtu", Value::U64(9000))])],
        );

        let result = merge(vec![eth0_config, eth1_config]);

        assert_eq!(result.effective_state.len(), 2, "effective state should contain exactly 2 entities");

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be present");
        assert_eq!(eth0.fields["mtu"].value, Value::U64(1500));

        let eth1 = result
            .effective_state
            .get("ethernet", "eth1")
            .expect("ethernet/eth1 should be present");
        assert_eq!(eth1.fields["mtu"].value, Value::U64(9000));
    }

    // ── Scenario: Same priority, same value is not a conflict ─────────────────

    #[test]
    fn test_same_priority_same_value_is_not_a_conflict() {
        let policy_a = make_input(
            "policy-a",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))])],
        );
        let policy_b = make_input(
            "policy-b",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))])],
        );

        let result = merge(vec![policy_a, policy_b]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");
        assert_eq!(eth0.fields["mtu"].value, Value::U64(1500));
        assert!(
            result.conflicts.is_empty(),
            "agreeing values at equal priority must not produce a conflict; got {:?}",
            result.conflicts.conflicts
        );
    }

    // ── Scenario: Empty policy input produces empty effective state ────────────

    #[test]
    fn test_empty_policy_input_produces_empty_effective_state() {
        let result = merge(vec![]);

        assert!(result.effective_state.is_empty(), "effective state should be empty");
        assert!(result.field_sources.is_empty(), "field_sources should be empty");
        assert!(result.conflicts.is_empty(), "conflicts should be empty");
    }

    // ── Scenario: Policy with multiple entities ───────────────────────────────

    #[test]
    fn test_policy_with_multiple_entities_all_appear_in_effective_state() {
        let addresses = Value::List(vec![Value::String("10.0.1.50/24".to_string())]);
        let servers = Value::List(vec![Value::String("10.0.1.2".to_string())]);
        let input = make_input(
            "network-config",
            100,
            vec![
                make_state(
                    "ethernet",
                    "eth0",
                    vec![("mtu", Value::U64(1500)), ("addresses", addresses.clone())],
                ),
                make_state("ethernet", "eth1", vec![("mtu", Value::U64(9000))]),
                make_state("dns", "global", vec![("servers", servers.clone())]),
            ],
        );

        let result = merge(vec![input]);

        assert_eq!(result.effective_state.len(), 3, "all 3 entities should appear");

        let eth0 = result.effective_state.get("ethernet", "eth0").expect("eth0");
        assert_eq!(eth0.fields["mtu"].value, Value::U64(1500));
        assert_eq!(eth0.fields["addresses"].value, addresses);

        let eth1 = result.effective_state.get("ethernet", "eth1").expect("eth1");
        assert_eq!(eth1.fields["mtu"].value, Value::U64(9000));

        let dns = result.effective_state.get("dns", "global").expect("dns/global");
        assert_eq!(dns.fields["servers"].value, servers);
    }

    // ── Scenario: Lower priority policy fields included when not overridden ───

    #[test]
    fn test_lower_priority_policy_fields_included_when_not_overridden() {
        let addresses = Value::List(vec![Value::String("10.0.1.50/24".to_string())]);
        let routes = Value::List(vec![Value::String("default via 10.0.1.1".to_string())]);
        let base = make_input(
            "base",
            50,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![
                    ("mtu", Value::U64(1500)),
                    ("addresses", addresses.clone()),
                    ("routes", routes.clone()),
                ],
            )],
        );
        let overlay = make_input(
            "overlay",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))])],
        );

        let result = merge(vec![base, overlay]);

        let eth0 = result
            .effective_state
            .get("ethernet", "eth0")
            .expect("ethernet/eth0 should be in effective state");

        assert_eq!(eth0.fields["mtu"].value, Value::U64(9000), "mtu overridden");
        assert_eq!(eth0.fields["addresses"].value, addresses, "addresses kept from base");
        assert_eq!(eth0.fields["routes"].value, routes, "routes kept from base");

        assert_eq!(
            get_source(&result, "ethernet", "eth0", "mtu").map(|p| p.as_str()),
            Some("overlay"),
        );
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "addresses").map(|p| p.as_str()),
            Some("base"),
        );
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "routes").map(|p| p.as_str()),
            Some("base"),
        );
    }

    // ── Extra: same priority, different values → conflict, field omitted ───────

    #[test]
    fn test_same_priority_different_values_reports_conflict_and_omits_field() {
        let policy_a = make_input(
            "policy-a",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))])],
        );
        let policy_b = make_input(
            "policy-b",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))])],
        );

        let result = merge(vec![policy_a, policy_b]);

        // Conflicted field must be absent from field_sources.
        assert!(
            get_source(&result, "ethernet", "eth0", "mtu").is_none(),
            "conflicted field must not appear in field_sources"
        );

        // If the entity appears in the effective state, mtu must be absent.
        if let Some(eth0) = result.effective_state.get("ethernet", "eth0") {
            assert!(
                !eth0.fields.contains_key("mtu"),
                "conflicted mtu field must be omitted from effective state"
            );
        }

        // A conflict must be recorded.
        assert_eq!(result.conflicts.len(), 1, "exactly one conflict should be reported");
        let conflict = &result.conflicts.conflicts[0];
        assert_eq!(conflict.entity_key, ("ethernet".to_string(), "eth0".to_string()));
        assert_eq!(conflict.field, "mtu");
        // Both contending values must be present.
        let values: Vec<&Value> = conflict.contenders.iter().map(|(_, v)| v).collect();
        assert!(values.contains(&&Value::U64(1500)));
        assert!(values.contains(&&Value::U64(9000)));
    }

    // ── Extra: field_sources is absent for conflicted fields ──────────────────

    #[test]
    fn test_field_sources_does_not_include_conflicted_fields() {
        let policy_a = make_input(
            "policy-a",
            100,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![("mtu", Value::U64(1500)), ("speed", Value::U64(1000))],
            )],
        );
        let policy_b = make_input(
            "policy-b",
            100,
            vec![make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))])],
        );

        let result = merge(vec![policy_a, policy_b]);

        // mtu is in conflict — absent from field_sources.
        assert!(
            get_source(&result, "ethernet", "eth0", "mtu").is_none(),
            "conflicted mtu must not appear in field_sources"
        );
        // speed is uncontested — must appear in field_sources.
        assert_eq!(
            get_source(&result, "ethernet", "eth0", "speed").map(|p| p.as_str()),
            Some("policy-a"),
            "uncontested speed field must appear in field_sources"
        );
    }

    // ── Extra: single policy, no conflict report ──────────────────────────────

    #[test]
    fn test_single_policy_produces_no_conflicts() {
        let input = make_input(
            "only-policy",
            100,
            vec![make_state(
                "ethernet",
                "eth0",
                vec![("mtu", Value::U64(1500)), ("speed", Value::U64(1000))],
            )],
        );

        let result = merge(vec![input]);

        assert!(result.conflicts.is_empty(), "a single policy must produce no conflicts");
    }
}
