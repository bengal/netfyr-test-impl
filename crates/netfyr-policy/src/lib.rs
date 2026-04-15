//! netfyr-policy crate — policy data model and factory implementations.
//!
//! A policy is a named factory that produces a `StateSet`. The static factory
//! (`StaticFactory`) is the simplest: it copies inline state definitions from
//! the policy document into a `StateSet`. Dynamic factories (e.g., DHCPv4)
//! run inside the daemon.

use indexmap::IndexMap;
use netfyr_state::{parse_state_value, union, ConflictError, Provenance, Selector, State, StateSet, YamlError};
use serde::de::Deserialize;
use serde::{Deserialize as DeserializeDerive, Serialize};

// ── FactoryType ───────────────────────────────────────────────────────────────

/// The type of factory that produces state for a policy.
///
/// Serializes to/from lowercase strings in YAML (`"static"`, `"dhcpv4"`).
#[derive(Clone, Debug, PartialEq, Serialize, DeserializeDerive)]
#[serde(rename_all = "lowercase")]
pub enum FactoryType {
    /// Produces state from inline YAML definitions inside the policy document.
    Static,
    /// Produces state by acquiring a DHCPv4 lease at runtime (daemon-side).
    Dhcpv4,
}

// ── Policy ────────────────────────────────────────────────────────────────────

/// A named factory that produces a desired `StateSet`.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// Unique policy name (e.g., `"eth0"`, `"eth0-dhcp"`).
    pub name: String,
    /// Which factory type produces the state.
    pub factory_type: FactoryType,
    /// Numeric priority propagated to all generated fields (default: 100).
    pub priority: u32,
    /// Inline state for single-entity static policies.
    pub state: Option<State>,
    /// Inline states for multi-entity static policies.
    pub states: Option<Vec<State>>,
    /// Target selector (e.g., which interface to run DHCP on).
    pub selector: Option<Selector>,
}

// ── PolicySet ─────────────────────────────────────────────────────────────────

/// A collection of `Policy` values keyed by name, preserving insertion order.
#[derive(Clone, Debug, Default)]
pub struct PolicySet {
    inner: IndexMap<String, Policy>,
}

impl PolicySet {
    /// Returns a new, empty `PolicySet`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces a policy by name.
    pub fn insert(&mut self, policy: Policy) {
        self.inner.insert(policy.name.clone(), policy);
    }

    /// Returns a reference to the policy with the given name.
    pub fn get(&self, name: &str) -> Option<&Policy> {
        self.inner.get(name)
    }

    /// Removes and returns the policy with the given name.
    pub fn remove(&mut self, name: &str) -> Option<Policy> {
        self.inner.shift_remove(name)
    }

    /// Iterates over all policies in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Policy> {
        self.inner.values()
    }

    /// Returns the number of policies in the set.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the set contains no policies.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Runs all static factories and unions the results into a single `StateSet`.
    ///
    /// Non-static policies (e.g., `Dhcpv4`) are silently skipped — the daemon
    /// handles those at runtime. Returns `Err(FactoryError::ConflictError)` if
    /// two static policies produce the same entity field at the same priority
    /// with different values.
    pub fn produce_all_static(&self) -> Result<StateSet, FactoryError> {
        let factory = StaticFactory;
        let mut combined = StateSet::new();
        for policy in self.iter().filter(|p| p.factory_type == FactoryType::Static) {
            let state_set = factory.produce(policy)?;
            combined = union(&combined, &state_set).map_err(FactoryError::ConflictError)?;
        }
        Ok(combined)
    }
}

// ── StateFactory trait ────────────────────────────────────────────────────────

/// The interface all policy factories implement.
pub trait StateFactory {
    fn produce(&self, policy: &Policy) -> Result<StateSet, FactoryError>;
}

// ── FactoryError ──────────────────────────────────────────────────────────────

/// Errors that can occur during factory execution.
#[derive(Debug, thiserror::Error)]
pub enum FactoryError {
    /// Static factory but no `state` or `states` field defined in the policy.
    #[error(
        "static factory for policy '{policy_name}' has neither 'state' nor 'states' defined"
    )]
    MissingState { policy_name: String },

    /// Factory misconfiguration (wrong fields for the factory type, etc.).
    #[error(
        "invalid factory configuration for policy '{policy_name}' (type: {factory_type}): {reason}"
    )]
    InvalidFactory {
        policy_name: String,
        factory_type: String,
        reason: String,
    },

    /// Wraps a `StateSet` union conflict (same entity, same field, same priority, different values).
    #[error(transparent)]
    ConflictError(#[from] ConflictError),

    /// Catch-all for unexpected errors.
    #[error("{message}")]
    Other { message: String },
}

// ── StaticFactory ─────────────────────────────────────────────────────────────

/// The simplest factory type: copies inline state definitions from the policy
/// into a `StateSet`, stamping each entity with the policy's priority and name.
pub struct StaticFactory;

impl StateFactory for StaticFactory {
    fn produce(&self, policy: &Policy) -> Result<StateSet, FactoryError> {
        // Reject policies with no state defined (or an empty states list).
        let states_empty = policy.states.as_ref().is_none_or(|v| v.is_empty());
        if policy.state.is_none() && states_empty {
            return Err(FactoryError::MissingState {
                policy_name: policy.name.clone(),
            });
        }

        let mut set = StateSet::new();

        if let Some(state) = &policy.state {
            tracing::debug!(
                policy = %policy.name,
                entity_type = %state.entity_type,
                "static factory inserting single state"
            );
            set.insert(apply_policy_to_state(state, policy));
        }

        if let Some(states) = &policy.states {
            for state in states {
                tracing::debug!(
                    policy = %policy.name,
                    entity_type = %state.entity_type,
                    "static factory inserting state from states list"
                );
                set.insert(apply_policy_to_state(state, policy));
            }
        }

        Ok(set)
    }
}

/// Clones a state and stamps it with the policy's priority, policy_ref, and
/// `UserConfigured` provenance on every field.
fn apply_policy_to_state(state: &State, policy: &Policy) -> State {
    let mut s = state.clone();
    s.priority = policy.priority;
    s.policy_ref = Some(policy.name.clone());
    for field in s.fields.values_mut() {
        field.provenance = Provenance::UserConfigured {
            policy_ref: policy.name.clone(),
        };
    }
    s
}

// ── PolicyError ───────────────────────────────────────────────────────────────

/// Errors that can occur while parsing policy YAML.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// YAML syntax error or flat-format state parse error.
    #[error("YAML error: {0}")]
    Yaml(#[from] YamlError),

    /// A required field is absent from the policy document.
    #[error("missing required field '{field}' in policy document")]
    MissingField { field: String },

    /// The `kind` field is present but not `"policy"`.
    #[error("unknown 'kind' value: '{kind}'; expected 'policy'")]
    InvalidKind { kind: String },

    /// The `kind` field is `"state"` or absent — handled by SPEC-008.
    #[error(
        "unsupported 'kind' value: '{kind}'; bare state documents are not yet supported here"
    )]
    UnsupportedKind { kind: String },

    /// A field has the wrong YAML type.
    #[error("field '{field}' has wrong type; expected {expected}")]
    InvalidFieldType { field: String, expected: String },

    /// The `factory` string does not match any known `FactoryType`.
    #[error("unknown factory type: '{factory}'")]
    UnknownFactory { factory: String },

    /// Serde-level deserialization error (e.g., while decoding `Selector`).
    #[error("serde error: {0}")]
    Serde(#[from] serde_yaml::Error),
}

// ── parse_policy_yaml ─────────────────────────────────────────────────────────

/// Parses a (possibly multi-document) YAML string into a list of `Policy` values.
///
/// Each document must have `kind: policy`. Documents with `kind: state` or no
/// `kind` field return `Err(PolicyError::UnsupportedKind)` — auto-wrapping of
/// bare state documents into policies is handled by SPEC-008. Trailing `---`
/// null documents are silently skipped.
pub fn parse_policy_yaml(input: &str) -> Result<Vec<Policy>, PolicyError> {
    let mut policies = Vec::new();

    for document in serde_yaml::Deserializer::from_str(input) {
        let raw: serde_yaml::Value =
            Deserialize::deserialize(document).map_err(PolicyError::Serde)?;

        // Silently skip null documents (e.g., a trailing `---`).
        if matches!(raw, serde_yaml::Value::Null) {
            continue;
        }

        let map = match &raw {
            serde_yaml::Value::Mapping(m) => m,
            _ => {
                return Err(PolicyError::MissingField {
                    field: "kind".to_string(),
                })
            }
        };

        // ── kind ──────────────────────────────────────────────────────────────

        let kind_key = serde_yaml::Value::String("kind".to_string());
        match map.get(&kind_key) {
            Some(serde_yaml::Value::String(k)) if k == "policy" => {}
            Some(serde_yaml::Value::String(k)) if k == "state" => {
                return Err(PolicyError::UnsupportedKind { kind: k.clone() });
            }
            Some(serde_yaml::Value::String(k)) => {
                return Err(PolicyError::InvalidKind { kind: k.clone() });
            }
            Some(_) => {
                return Err(PolicyError::InvalidKind {
                    kind: "<non-string>".to_string(),
                });
            }
            None => {
                return Err(PolicyError::UnsupportedKind {
                    kind: "<absent>".to_string(),
                });
            }
        }

        // ── name (required string) ────────────────────────────────────────────

        let name_key = serde_yaml::Value::String("name".to_string());
        let name = match map.get(&name_key) {
            Some(serde_yaml::Value::String(s)) => s.clone(),
            Some(_) => {
                return Err(PolicyError::InvalidFieldType {
                    field: "name".to_string(),
                    expected: "string".to_string(),
                })
            }
            None => {
                return Err(PolicyError::MissingField {
                    field: "name".to_string(),
                })
            }
        };

        // ── factory (required string → FactoryType) ───────────────────────────

        let factory_key = serde_yaml::Value::String("factory".to_string());
        let factory_type = match map.get(&factory_key) {
            Some(serde_yaml::Value::String(factory_str)) => {
                serde_yaml::from_value::<FactoryType>(serde_yaml::Value::String(
                    factory_str.clone(),
                ))
                .map_err(|_| PolicyError::UnknownFactory {
                    factory: factory_str.clone(),
                })?
            }
            Some(_) => {
                return Err(PolicyError::InvalidFieldType {
                    field: "factory".to_string(),
                    expected: "string".to_string(),
                })
            }
            None => {
                return Err(PolicyError::MissingField {
                    field: "factory".to_string(),
                })
            }
        };

        // ── priority (optional non-negative integer, default 100) ─────────────

        let priority_key = serde_yaml::Value::String("priority".to_string());
        let priority = match map.get(&priority_key) {
            Some(serde_yaml::Value::Number(n)) => {
                let p = n.as_u64().ok_or_else(|| PolicyError::InvalidFieldType {
                    field: "priority".to_string(),
                    expected: "non-negative integer".to_string(),
                })?;
                u32::try_from(p).map_err(|_| PolicyError::InvalidFieldType {
                    field: "priority".to_string(),
                    expected: "integer within u32 range (0..=4294967295)".to_string(),
                })?
            }
            Some(_) => {
                return Err(PolicyError::InvalidFieldType {
                    field: "priority".to_string(),
                    expected: "integer".to_string(),
                })
            }
            None => 100,
        };

        // ── selector (optional mapping → Selector) ────────────────────────────

        let selector_key_yaml = serde_yaml::Value::String("selector".to_string());
        let selector = match map.get(&selector_key_yaml) {
            Some(v) => {
                let sel =
                    serde_yaml::from_value::<Selector>(v.clone()).map_err(PolicyError::Serde)?;
                Some(sel)
            }
            None => None,
        };

        // ── state (optional flat mapping → State) ─────────────────────────────

        let state_key = serde_yaml::Value::String("state".to_string());
        let state = match map.get(&state_key) {
            Some(v) => {
                let s = parse_state_value(v.clone()).map_err(PolicyError::Yaml)?;
                Some(s)
            }
            None => None,
        };

        // ── states (optional sequence of flat mappings → Vec<State>) ──────────

        let states_key = serde_yaml::Value::String("states".to_string());
        let states = match map.get(&states_key) {
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut result = Vec::new();
                for item in seq {
                    let s = parse_state_value(item.clone()).map_err(PolicyError::Yaml)?;
                    result.push(s);
                }
                Some(result)
            }
            Some(_) => {
                return Err(PolicyError::InvalidFieldType {
                    field: "states".to_string(),
                    expected: "sequence".to_string(),
                })
            }
            None => None,
        };

        policies.push(Policy {
            name,
            factory_type,
            priority,
            state,
            states,
            selector,
        });
    }

    Ok(policies)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use netfyr_state::{FieldValue, StateMetadata, Value};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a `State` with a named selector and the given configuration fields.
    fn make_state(entity_type: &str, name: &str, fields: Vec<(&str, Value)>, priority: u32) -> State {
        let mut field_map: IndexMap<String, FieldValue> = IndexMap::new();
        for (k, v) in fields {
            field_map.insert(
                k.to_string(),
                FieldValue {
                    value: v,
                    provenance: Provenance::KernelDefault,
                },
            );
        }
        State {
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            fields: field_map,
            metadata: StateMetadata::new(),
            policy_ref: None,
            priority,
        }
    }

    /// Build a static `Policy` with a single embedded state.
    fn static_policy(name: &str, priority: u32, state: State) -> Policy {
        Policy {
            name: name.to_string(),
            factory_type: FactoryType::Static,
            priority,
            state: Some(state),
            states: None,
            selector: None,
        }
    }

    /// Build a DHCPv4 `Policy` with a named selector (no inline state).
    fn dhcp_policy(name: &str, interface: &str) -> Policy {
        Policy {
            name: name.to_string(),
            factory_type: FactoryType::Dhcpv4,
            priority: 100,
            state: None,
            states: None,
            selector: Some(Selector::with_name(interface)),
        }
    }

    // ── StaticFactory helper builders ─────────────────────────────────────────

    fn make_state_no_priority(entity_type: &str, name: &str, fields: Vec<(&str, Value)>) -> State {
        make_state(entity_type, name, fields, 100)
    }

    fn static_policy_single(name: &str, priority: u32, state: State) -> Policy {
        static_policy(name, priority, state)
    }

    fn static_policy_multi(name: &str, priority: u32, states: Vec<State>) -> Policy {
        Policy {
            name: name.to_string(),
            factory_type: FactoryType::Static,
            priority,
            state: None,
            states: Some(states),
            selector: None,
        }
    }

    fn empty_static_policy(name: &str) -> Policy {
        Policy {
            name: name.to_string(),
            factory_type: FactoryType::Static,
            priority: 100,
            state: None,
            states: None,
            selector: None,
        }
    }

    // ── Fixture YAML strings ──────────────────────────────────────────────────

    const STATIC_POLICY_YAML: &str = "\
kind: policy
name: eth0-static
factory: static
priority: 150
state:
  type: ethernet
  name: eth0
  mtu: 1500
";

    const MULTI_ENTITY_POLICY_YAML: &str = "\
kind: policy
name: server-network
factory: static
priority: 100
states:
  - type: ethernet
    name: eth0
    mtu: 1500
  - type: dns
    scope: global
    servers:
      - 10.0.1.2
";

    const DHCPV4_POLICY_YAML: &str = "\
kind: policy
name: eth0-dhcp
factory: dhcpv4
priority: 100
selector:
  name: eth0
";

    const NO_PRIORITY_YAML: &str = "\
kind: policy
name: test-policy
factory: static
state:
  type: ethernet
  name: eth0
";

    const MULTI_DOC_YAML: &str = "\
kind: policy
name: eth0-static
factory: static
priority: 100
state:
  type: ethernet
  name: eth0
  mtu: 1500
---
kind: policy
name: eth0-dhcp
factory: dhcpv4
priority: 50
selector:
  name: eth0
";

    // ── Feature: Policy type definitions — FactoryType serialization ──────────

    #[test]
    fn test_factory_type_dhcpv4_serializes_to_dhcpv4_string() {
        let yaml = serde_yaml::to_string(&FactoryType::Dhcpv4).unwrap();
        assert_eq!(yaml.trim(), "dhcpv4");
    }

    #[test]
    fn test_factory_type_static_serializes_to_static_string() {
        let yaml = serde_yaml::to_string(&FactoryType::Static).unwrap();
        assert_eq!(yaml.trim(), "static");
    }

    #[test]
    fn test_factory_type_dhcpv4_deserializes_from_string() {
        let ft: FactoryType = serde_yaml::from_str("dhcpv4").unwrap();
        assert_eq!(ft, FactoryType::Dhcpv4);
    }

    #[test]
    fn test_factory_type_static_deserializes_from_string() {
        let ft: FactoryType = serde_yaml::from_str("static").unwrap();
        assert_eq!(ft, FactoryType::Static);
    }

    // ── Feature: PolicySet collection ─────────────────────────────────────────

    #[test]
    fn test_policy_set_insert_and_get_returns_inserted_policy() {
        let mut set = PolicySet::new();
        let policy = static_policy(
            "eth0",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        );
        set.insert(policy);
        assert!(set.get("eth0").is_some());
    }

    #[test]
    fn test_policy_set_len_returns_one_after_single_insert() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "eth0",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_policy_set_is_empty_before_insert() {
        assert!(PolicySet::new().is_empty());
    }

    #[test]
    fn test_policy_set_get_unknown_name_returns_none() {
        let set = PolicySet::new();
        assert!(set.get("nonexistent").is_none());
    }

    #[test]
    fn test_policy_set_remove_returns_policy_and_decrements_len() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "eth0",
            100,
            make_state("ethernet", "eth0", vec![], 100),
        ));
        let removed = set.remove("eth0");
        assert!(removed.is_some());
        assert_eq!(set.len(), 0);
    }

    // ── Feature: produce_all_static ───────────────────────────────────────────

    #[test]
    fn test_produce_all_static_unions_two_static_policies() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "eth0",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        set.insert(static_policy(
            "dns",
            100,
            make_state(
                "dns",
                "main",
                vec![("servers", Value::List(vec![Value::String("10.0.1.2".to_string())]))],
                100,
            ),
        ));
        let result = set.produce_all_static().unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.get("ethernet", "eth0").is_some());
        assert!(result.get("dns", "main").is_some());
    }

    #[test]
    fn test_produce_all_static_skips_dhcpv4_policies() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "eth0",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        set.insert(dhcp_policy("eth1-dhcp", "eth1"));
        let result = set.produce_all_static().unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.get("ethernet", "eth0").is_some());
    }

    #[test]
    fn test_produce_all_static_equal_priority_conflict_returns_conflict_error() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "a",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        set.insert(static_policy(
            "b",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))], 100),
        ));
        let result = set.produce_all_static();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FactoryError::ConflictError(_)));
    }

    #[test]
    fn test_produce_all_static_conflict_error_identifies_mtu_field_on_ethernet_eth0() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "a",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        set.insert(static_policy(
            "b",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))], 100),
        ));
        match set.produce_all_static().unwrap_err() {
            FactoryError::ConflictError(ce) => {
                assert!(ce.conflicts.iter().any(|c| {
                    c.field == "mtu" && c.entity_type == "ethernet" && c.selector_key == "eth0"
                }));
            }
            other => panic!("expected ConflictError, got {:?}", other),
        }
    }

    #[test]
    fn test_produce_all_static_higher_priority_mtu_wins() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "base",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        set.insert(static_policy(
            "override",
            200,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))], 200),
        ));
        let result = set.produce_all_static().unwrap();
        let state = result.get("ethernet", "eth0").expect("ethernet/eth0 must be in result");
        assert_eq!(state.fields["mtu"].value, Value::U64(9000));
    }

    #[test]
    fn test_produce_all_static_priority_winner_provenance_references_override_policy() {
        let mut set = PolicySet::new();
        set.insert(static_policy(
            "base",
            100,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))], 100),
        ));
        set.insert(static_policy(
            "override",
            200,
            make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))], 200),
        ));
        let result = set.produce_all_static().unwrap();
        let state = result.get("ethernet", "eth0").unwrap();
        match &state.fields["mtu"].provenance {
            Provenance::UserConfigured { policy_ref } => {
                assert_eq!(policy_ref, "override");
            }
            other => panic!("expected UserConfigured provenance, got {:?}", other),
        }
    }

    #[test]
    fn test_produce_all_static_empty_set_returns_empty_stateset() {
        let set = PolicySet::new();
        let result = set.produce_all_static().unwrap();
        assert!(result.is_empty());
    }

    // ── Feature: Static factory produces StateSet ─────────────────────────────

    #[test]
    fn test_static_factory_single_state_produces_one_entity() {
        let policy = static_policy_single(
            "eth0",
            200,
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]),
        );
        let result = StaticFactory.produce(&policy).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_static_factory_single_state_sets_entity_priority() {
        let policy = static_policy_single(
            "eth0",
            200,
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]),
        );
        let result = StaticFactory.produce(&policy).unwrap();
        let state = result.get("ethernet", "eth0").expect("ethernet/eth0 must be in result");
        assert_eq!(state.priority, 200);
    }

    #[test]
    fn test_static_factory_single_state_sets_policy_ref() {
        let policy = static_policy_single(
            "eth0",
            200,
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]),
        );
        let result = StaticFactory.produce(&policy).unwrap();
        let state = result.get("ethernet", "eth0").expect("ethernet/eth0 must be in result");
        assert_eq!(state.policy_ref, Some("eth0".to_string()));
    }

    #[test]
    fn test_static_factory_single_state_field_has_user_configured_provenance() {
        let policy = static_policy_single(
            "eth0",
            200,
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]),
        );
        let result = StaticFactory.produce(&policy).unwrap();
        let state = result.get("ethernet", "eth0").unwrap();
        match &state.fields["mtu"].provenance {
            Provenance::UserConfigured { policy_ref } => {
                assert_eq!(policy_ref, "eth0");
            }
            other => panic!("expected UserConfigured provenance, got {:?}", other),
        }
    }

    #[test]
    fn test_static_factory_multiple_states_returns_two_entities() {
        let state_eth0 =
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]);
        let state_dns = make_state_no_priority("dns", "main", vec![("servers", Value::List(vec![]))]);
        let policy = static_policy_multi("server", 100, vec![state_eth0, state_dns]);
        let result = StaticFactory.produce(&policy).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_static_factory_multiple_states_ethernet_has_correct_priority_and_policy_ref() {
        let state_eth0 =
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]);
        let state_dns = make_state_no_priority("dns", "main", vec![]);
        let policy = static_policy_multi("server", 100, vec![state_eth0, state_dns]);
        let result = StaticFactory.produce(&policy).unwrap();
        let eth0 = result.get("ethernet", "eth0").unwrap();
        assert_eq!(eth0.priority, 100);
        assert_eq!(eth0.policy_ref, Some("server".to_string()));
    }

    #[test]
    fn test_static_factory_multiple_states_dns_has_correct_priority_and_policy_ref() {
        let state_eth0 =
            make_state_no_priority("ethernet", "eth0", vec![("mtu", Value::U64(1500))]);
        let state_dns = make_state_no_priority("dns", "main", vec![]);
        let policy = static_policy_multi("server", 100, vec![state_eth0, state_dns]);
        let result = StaticFactory.produce(&policy).unwrap();
        let dns = result.get("dns", "main").unwrap();
        assert_eq!(dns.priority, 100);
        assert_eq!(dns.policy_ref, Some("server".to_string()));
    }

    #[test]
    fn test_static_factory_no_state_returns_missing_state_error() {
        let policy = empty_static_policy("empty");
        let result = StaticFactory.produce(&policy);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FactoryError::MissingState { .. }));
    }

    #[test]
    fn test_static_factory_missing_state_error_contains_policy_name() {
        let policy = empty_static_policy("empty");
        match StaticFactory.produce(&policy).unwrap_err() {
            FactoryError::MissingState { policy_name } => {
                assert_eq!(policy_name, "empty");
            }
            other => panic!("expected MissingState error, got {:?}", other),
        }
    }

    #[test]
    fn test_static_factory_preserves_all_field_values() {
        let mut route_map: IndexMap<String, Value> = IndexMap::new();
        route_map.insert("destination".to_string(), Value::String("0.0.0.0/0".to_string()));
        route_map.insert("gateway".to_string(), Value::String("10.0.1.1".to_string()));

        let state = make_state_no_priority(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(9000)),
                (
                    "addresses",
                    Value::List(vec![Value::String("10.0.1.50/24".to_string())]),
                ),
                ("routes", Value::List(vec![Value::Map(route_map.clone())])),
            ],
        );
        let policy = static_policy_single("test", 100, state);
        let result = StaticFactory.produce(&policy).unwrap();
        let out = result.get("ethernet", "eth0").expect("ethernet/eth0 must be present");

        assert_eq!(out.fields["mtu"].value, Value::U64(9000));

        let addrs = out.fields["addresses"].value.as_list().unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], Value::String("10.0.1.50/24".to_string()));

        let routes = out.fields["routes"].value.as_list().unwrap();
        assert_eq!(routes.len(), 1);
        let route = routes[0].as_map().unwrap();
        assert_eq!(
            route.get("destination"),
            Some(&Value::String("0.0.0.0/0".to_string()))
        );
        assert_eq!(
            route.get("gateway"),
            Some(&Value::String("10.0.1.1".to_string()))
        );
    }

    #[test]
    fn test_static_factory_empty_states_list_returns_missing_state_error() {
        let policy = Policy {
            name: "empty-list".to_string(),
            factory_type: FactoryType::Static,
            priority: 100,
            state: None,
            states: Some(vec![]),
            selector: None,
        };
        let result = StaticFactory.produce(&policy);
        assert!(matches!(result, Err(FactoryError::MissingState { .. })));
    }

    // ── Feature: Multi-document policy YAML parsing ───────────────────────────

    #[test]
    fn test_parse_static_policy_returns_one_policy() {
        let policies = parse_policy_yaml(STATIC_POLICY_YAML).unwrap();
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn test_parse_static_policy_name_is_eth0_static() {
        let policies = parse_policy_yaml(STATIC_POLICY_YAML).unwrap();
        assert_eq!(policies[0].name, "eth0-static");
    }

    #[test]
    fn test_parse_static_policy_factory_type_is_static() {
        let policies = parse_policy_yaml(STATIC_POLICY_YAML).unwrap();
        assert_eq!(policies[0].factory_type, FactoryType::Static);
    }

    #[test]
    fn test_parse_static_policy_priority_is_150() {
        let policies = parse_policy_yaml(STATIC_POLICY_YAML).unwrap();
        assert_eq!(policies[0].priority, 150);
    }

    #[test]
    fn test_parse_static_policy_state_is_some_with_entity_type_ethernet() {
        let policies = parse_policy_yaml(STATIC_POLICY_YAML).unwrap();
        let state = policies[0].state.as_ref().expect("state should be Some");
        assert_eq!(state.entity_type, "ethernet");
    }

    #[test]
    fn test_parse_multi_entity_policy_returns_one_policy_with_two_states() {
        let policies = parse_policy_yaml(MULTI_ENTITY_POLICY_YAML).unwrap();
        assert_eq!(policies.len(), 1);
        let states = policies[0].states.as_ref().expect("states should be Some");
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn test_parse_dhcpv4_policy_returns_one_policy() {
        let policies = parse_policy_yaml(DHCPV4_POLICY_YAML).unwrap();
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn test_parse_dhcpv4_policy_factory_type_is_dhcpv4() {
        let policies = parse_policy_yaml(DHCPV4_POLICY_YAML).unwrap();
        assert_eq!(policies[0].factory_type, FactoryType::Dhcpv4);
    }

    #[test]
    fn test_parse_dhcpv4_policy_selector_name_is_eth0() {
        let policies = parse_policy_yaml(DHCPV4_POLICY_YAML).unwrap();
        let selector = policies[0].selector.as_ref().expect("selector should be Some");
        assert_eq!(selector.name, Some("eth0".to_string()));
    }

    #[test]
    fn test_parse_dhcpv4_policy_state_is_none() {
        let policies = parse_policy_yaml(DHCPV4_POLICY_YAML).unwrap();
        assert!(policies[0].state.is_none());
    }

    #[test]
    fn test_parse_dhcpv4_policy_states_is_none() {
        let policies = parse_policy_yaml(DHCPV4_POLICY_YAML).unwrap();
        assert!(policies[0].states.is_none());
    }

    #[test]
    fn test_factory_type_dhcpv4_deserializes_via_policy_yaml() {
        let policies = parse_policy_yaml(DHCPV4_POLICY_YAML).unwrap();
        assert_eq!(policies[0].factory_type, FactoryType::Dhcpv4);
    }

    #[test]
    fn test_factory_type_static_deserializes_via_policy_yaml() {
        let policies = parse_policy_yaml(STATIC_POLICY_YAML).unwrap();
        assert_eq!(policies[0].factory_type, FactoryType::Static);
    }

    #[test]
    fn test_parse_default_priority_is_100_when_field_absent() {
        let policies = parse_policy_yaml(NO_PRIORITY_YAML).unwrap();
        assert_eq!(policies[0].priority, 100);
    }

    #[test]
    fn test_parse_multidoc_yaml_returns_two_policies() {
        let policies = parse_policy_yaml(MULTI_DOC_YAML).unwrap();
        assert_eq!(policies.len(), 2);
    }

    #[test]
    fn test_parse_multidoc_yaml_first_policy_name_and_factory() {
        let policies = parse_policy_yaml(MULTI_DOC_YAML).unwrap();
        assert_eq!(policies[0].name, "eth0-static");
        assert_eq!(policies[0].factory_type, FactoryType::Static);
    }

    #[test]
    fn test_parse_multidoc_yaml_second_policy_name_and_factory() {
        let policies = parse_policy_yaml(MULTI_DOC_YAML).unwrap();
        assert_eq!(policies[1].name, "eth0-dhcp");
        assert_eq!(policies[1].factory_type, FactoryType::Dhcpv4);
    }

    #[test]
    fn test_parse_multidoc_yaml_first_policy_has_state_second_does_not() {
        let policies = parse_policy_yaml(MULTI_DOC_YAML).unwrap();
        assert!(policies[0].state.is_some());
        assert!(policies[1].state.is_none());
    }

    #[test]
    fn test_parse_trailing_separator_skipped() {
        let yaml = "\
kind: policy
name: eth0-static
factory: static
state:
  type: ethernet
  name: eth0
---
";
        let policies = parse_policy_yaml(yaml).unwrap();
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn test_parse_unknown_factory_type_returns_error() {
        let yaml = "\
kind: policy
name: test
factory: magic
state:
  type: ethernet
  name: eth0
";
        let result = parse_policy_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::UnknownFactory { .. }));
    }

    #[test]
    fn test_parse_missing_name_returns_error() {
        let yaml = "\
kind: policy
factory: static
state:
  type: ethernet
  name: eth0
";
        let result = parse_policy_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::MissingField { .. }));
    }

    #[test]
    fn test_parse_kind_state_returns_unsupported_kind_error() {
        let yaml = "\
kind: state
type: ethernet
name: eth0
";
        let result = parse_policy_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::UnsupportedKind { .. }));
    }

    #[test]
    fn test_parse_no_kind_returns_unsupported_kind_error() {
        let yaml = "\
type: ethernet
name: eth0
mtu: 1500
";
        let result = parse_policy_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::UnsupportedKind { .. }));
    }
}
