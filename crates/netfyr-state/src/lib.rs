//! netfyr-state crate — foundational data model for network entity configuration.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use uuid::Uuid;

// ── Selector ──────────────────────────────────────────────────────────────────

/// Identifies which system entity a state targets.
///
/// This is a placeholder for SPEC-003. Marked `#[non_exhaustive]` so that
/// adding fields in SPEC-003 is not a semver-breaking change for downstream crates.
/// Constructors are provided because `#[non_exhaustive]` prevents struct literal
/// syntax outside the defining crate.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Selector {
    pub name: Option<String>,
}

impl Selector {
    pub fn new() -> Self {
        Self { name: None }
    }

    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
        }
    }
}

impl Default for Selector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Value ─────────────────────────────────────────────────────────────────────

/// The set of possible field values in a network entity's configuration.
///
/// Uses `#[serde(untagged)]` to produce natural JSON/YAML (strings as strings,
/// numbers as numbers, etc.) rather than tagged envelopes. Variant declaration
/// order matters for untagged deserialization — serde tries each in order:
/// Bool first (syntactically distinct in JSON), then numerics, then IP types
/// (before String so IP-format strings don't match String first), then
/// List/Map (structurally distinct), then String as the fallback.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    U64(u64),
    I64(i64),
    // IpNetwork before IpAddr: the ipnetwork deserializer requires a `/prefix`,
    // so it will fail on bare IPs and fall through to IpAddr.
    IpNetwork(IpNetwork),
    IpAddr(IpAddr),
    List(Vec<Value>),
    Map(IndexMap<String, Value>),
    // String is last — it matches any JSON string, so it must come after all
    // other string-like types (IpNetwork, IpAddr).
    String(String),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::String(s) => write!(f, "{s}"),
            Value::U64(n) => write!(f, "{n}"),
            Value::I64(n) => write!(f, "{n}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::IpAddr(ip) => write!(f, "{ip}"),
            Value::IpNetwork(net) => write!(f, "{net}"),
            Value::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            Value::Map(map) => {
                write!(f, "{{")?;
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::U64(n)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::I64(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<IpAddr> for Value {
    fn from(ip: IpAddr) -> Self {
        Value::IpAddr(ip)
    }
}

impl From<IpNetwork> for Value {
    fn from(net: IpNetwork) -> Self {
        Value::IpNetwork(net)
    }
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::I64(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_ip_addr(&self) -> Option<&IpAddr> {
        match self {
            Value::IpAddr(ip) => Some(ip),
            _ => None,
        }
    }

    pub fn as_ip_network(&self) -> Option<&IpNetwork> {
        match self {
            Value::IpNetwork(net) => Some(net),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self {
            Value::List(list) => Some(list),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&IndexMap<String, Value>> {
        match self {
            Value::Map(map) => Some(map),
            _ => None,
        }
    }
}

// ── Provenance ────────────────────────────────────────────────────────────────

/// Tracks where a field value originated.
///
/// Uses internally tagged serde representation (`{"source": "kernel_default"}` etc.)
/// which is self-documenting in JSON/YAML and handles unit-like variants cleanly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Provenance {
    /// Explicitly set by a user in a policy.
    UserConfigured { policy_ref: String },
    /// Never changed; reflects the kernel's initial value.
    KernelDefault,
    /// Change detected from an external tool (e.g., iproute2, NetworkManager).
    ExternalTool {
        tool: String,
        detected_at: DateTime<Utc>,
    },
    /// Computed by netfyr (e.g., auto-calculated broadcast address).
    Derived { reason: String },
}

// ── FieldValue ────────────────────────────────────────────────────────────────

/// A field's value paired with its provenance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FieldValue {
    pub value: Value,
    pub provenance: Provenance,
}

// ── StateMetadata ─────────────────────────────────────────────────────────────

/// Identity and tracking metadata for a state instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateMetadata {
    /// UUIDv7 (time-ordered) unique identifier for this state instance.
    pub id: Uuid,
    /// Stable across versions of the same logical entity.
    pub timeline_id: Uuid,
    /// When this state was created.
    pub created_at: DateTime<Utc>,
    /// User-defined key-value labels.
    pub labels: HashMap<String, String>,
    /// Optional human-readable description.
    pub description: Option<String>,
}

impl StateMetadata {
    pub fn new() -> Self {
        Self {
            id: Uuid::now_v7(),
            timeline_id: Uuid::now_v7(),
            created_at: Utc::now(),
            labels: HashMap::new(),
            description: None,
        }
    }
}

impl Default for StateMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// ── State ─────────────────────────────────────────────────────────────────────

/// The top-level type representing one network entity's configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// The kind of entity (e.g., `"ethernet"`, `"bond"`, `"vlan"`).
    pub entity_type: String,
    /// Identifies which system entity this targets.
    pub selector: Selector,
    /// Ordered key-value configuration fields.
    ///
    /// `IndexMap` is used to preserve insertion order, which matters for
    /// deterministic YAML serialization and user-facing output.
    pub fields: IndexMap<String, FieldValue>,
    /// Identity and tracking metadata.
    pub metadata: StateMetadata,
    /// Name of the policy that produced this state.
    pub policy_ref: Option<String>,
    /// Numeric priority for field-level conflict resolution (higher wins).
    pub priority: u32,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use indexmap::IndexMap;
    use std::net::{IpAddr, Ipv4Addr};

    // ── Value tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_value_all_variants_constructable() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        let net: IpNetwork = "10.0.1.0/24".parse().unwrap();
        let mut map = IndexMap::new();
        map.insert("key".to_string(), Value::String("val".to_string()));

        let _s = Value::String("eth0".to_string());
        let _u = Value::U64(1500);
        let _i = Value::I64(-1);
        let _b = Value::Bool(true);
        let _ip = Value::IpAddr(ip);
        let _net = Value::IpNetwork(net);
        let _list = Value::List(vec![
            Value::String("a".to_string()),
            Value::String("b".to_string()),
        ]);
        let _map = Value::Map(map);
    }

    #[test]
    fn test_value_all_variants_clone_debug_partialeq() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        let net: IpNetwork = "10.0.1.0/24".parse().unwrap();
        let mut map = IndexMap::new();
        map.insert("key".to_string(), Value::String("val".to_string()));

        let variants = vec![
            Value::String("eth0".to_string()),
            Value::U64(1500),
            Value::I64(-1),
            Value::Bool(true),
            Value::IpAddr(ip),
            Value::IpNetwork(net),
            Value::List(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string()),
            ]),
            Value::Map(map),
        ];

        for v in &variants {
            let cloned = v.clone();
            assert_eq!(v, &cloned, "Clone and PartialEq must agree for {:?}", v);
            assert!(!format!("{:?}", v).is_empty(), "Debug must produce non-empty output");
        }
    }

    #[test]
    fn test_value_from_str_slice() {
        assert_eq!(Value::from("hello"), Value::String("hello".to_string()));
    }

    #[test]
    fn test_value_from_string() {
        assert_eq!(
            Value::from("hello".to_string()),
            Value::String("hello".to_string())
        );
    }

    #[test]
    fn test_value_from_u64() {
        assert_eq!(Value::from(42u64), Value::U64(42));
    }

    #[test]
    fn test_value_from_i64() {
        assert_eq!(Value::from(-7i64), Value::I64(-7));
    }

    #[test]
    fn test_value_from_bool_true() {
        assert_eq!(Value::from(true), Value::Bool(true));
    }

    #[test]
    fn test_value_from_bool_false() {
        assert_eq!(Value::from(false), Value::Bool(false));
    }

    #[test]
    fn test_value_from_ip_addr() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Value::from(ip), Value::IpAddr(ip));
    }

    #[test]
    fn test_value_from_ip_network() {
        let net: IpNetwork = "192.168.1.0/24".parse().unwrap();
        assert_eq!(Value::from(net), Value::IpNetwork(net));
    }

    #[test]
    fn test_value_u64_as_u64_returns_some() {
        assert_eq!(Value::U64(1500).as_u64(), Some(1500));
    }

    #[test]
    fn test_value_u64_as_str_returns_none() {
        assert_eq!(Value::U64(1500).as_str(), None);
    }

    #[test]
    fn test_value_u64_as_bool_returns_none() {
        assert_eq!(Value::U64(1500).as_bool(), None);
    }

    #[test]
    fn test_value_u64_as_i64_returns_none() {
        assert_eq!(Value::U64(1500).as_i64(), None);
    }

    #[test]
    fn test_value_u64_as_ip_addr_returns_none() {
        assert_eq!(Value::U64(1500).as_ip_addr(), None);
    }

    #[test]
    fn test_value_string_as_str_returns_some() {
        assert_eq!(Value::String("eth0".to_string()).as_str(), Some("eth0"));
    }

    #[test]
    fn test_value_string_as_u64_returns_none() {
        assert_eq!(Value::String("eth0".to_string()).as_u64(), None);
    }

    #[test]
    fn test_value_bool_as_bool_returns_some() {
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
    }

    #[test]
    fn test_value_i64_as_i64_returns_some() {
        assert_eq!(Value::I64(-1).as_i64(), Some(-1));
    }

    #[test]
    fn test_value_ip_addr_accessor_returns_some() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        assert_eq!(Value::IpAddr(ip).as_ip_addr(), Some(&ip));
    }

    #[test]
    fn test_value_ip_addr_accessor_returns_none_for_other() {
        assert_eq!(Value::U64(1).as_ip_addr(), None);
    }

    #[test]
    fn test_value_ip_network_accessor_returns_some() {
        let net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert_eq!(Value::IpNetwork(net).as_ip_network(), Some(&net));
    }

    #[test]
    fn test_value_ip_network_accessor_returns_none_for_other() {
        assert_eq!(Value::Bool(true).as_ip_network(), None);
    }

    #[test]
    fn test_value_list_accessor_returns_some() {
        let list = vec![Value::String("a".to_string())];
        assert_eq!(Value::List(list.clone()).as_list(), Some(&list));
    }

    #[test]
    fn test_value_list_accessor_returns_none_for_other() {
        assert_eq!(Value::U64(1).as_list(), None);
    }

    #[test]
    fn test_value_map_accessor_returns_some() {
        let mut map = IndexMap::new();
        map.insert("k".to_string(), Value::Bool(false));
        assert_eq!(Value::Map(map.clone()).as_map(), Some(&map));
    }

    #[test]
    fn test_value_map_accessor_returns_none_for_other() {
        assert_eq!(Value::String("x".to_string()).as_map(), None);
    }

    #[test]
    fn test_value_display_string() {
        assert_eq!(format!("{}", Value::String("eth0".to_string())), "eth0");
    }

    #[test]
    fn test_value_display_u64() {
        assert_eq!(format!("{}", Value::U64(1500)), "1500");
    }

    #[test]
    fn test_value_display_i64() {
        assert_eq!(format!("{}", Value::I64(-1)), "-1");
    }

    #[test]
    fn test_value_display_bool() {
        assert_eq!(format!("{}", Value::Bool(true)), "true");
    }

    #[test]
    fn test_value_display_ip_addr() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        assert_eq!(format!("{}", Value::IpAddr(ip)), "10.0.1.1");
    }

    #[test]
    fn test_value_display_ip_network() {
        let net: IpNetwork = "10.0.1.0/24".parse().unwrap();
        assert_eq!(format!("{}", Value::IpNetwork(net)), "10.0.1.0/24");
    }

    #[test]
    fn test_value_display_list() {
        let list = Value::List(vec![
            Value::String("a".to_string()),
            Value::String("b".to_string()),
        ]);
        assert_eq!(format!("{}", list), "[a, b]");
    }

    #[test]
    fn test_value_display_map() {
        let mut map = IndexMap::new();
        map.insert("key".to_string(), Value::String("val".to_string()));
        assert_eq!(format!("{}", Value::Map(map)), "{key: val}");
    }

    // ── Provenance tests ──────────────────────────────────────────────────────

    #[test]
    fn test_provenance_user_configured_policy_ref() {
        let p = Provenance::UserConfigured {
            policy_ref: "my-policy".to_string(),
        };
        match p {
            Provenance::UserConfigured { policy_ref } => {
                assert_eq!(policy_ref, "my-policy");
            }
            _ => panic!("Expected UserConfigured"),
        }
    }

    #[test]
    fn test_provenance_kernel_default_has_no_additional_fields() {
        let p = Provenance::KernelDefault;
        assert!(matches!(p, Provenance::KernelDefault));
    }

    #[test]
    fn test_provenance_external_tool_fields() {
        let ts = Utc::now();
        let p = Provenance::ExternalTool {
            tool: "iproute2".to_string(),
            detected_at: ts,
        };
        match p {
            Provenance::ExternalTool { tool, detected_at } => {
                assert_eq!(tool, "iproute2");
                assert_eq!(detected_at, ts);
            }
            _ => panic!("Expected ExternalTool"),
        }
    }

    #[test]
    fn test_provenance_derived_reason() {
        let p = Provenance::Derived {
            reason: "auto-broadcast".to_string(),
        };
        match p {
            Provenance::Derived { reason } => {
                assert_eq!(reason, "auto-broadcast");
            }
            _ => panic!("Expected Derived"),
        }
    }

    #[test]
    fn test_provenance_clone_debug_partialeq() {
        let variants = vec![
            Provenance::UserConfigured {
                policy_ref: "p".to_string(),
            },
            Provenance::KernelDefault,
            Provenance::ExternalTool {
                tool: "t".to_string(),
                detected_at: Utc::now(),
            },
            Provenance::Derived {
                reason: "r".to_string(),
            },
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(v, &cloned);
            assert!(!format!("{:?}", v).is_empty());
        }
    }

    // ── FieldValue tests ──────────────────────────────────────────────────────

    #[test]
    fn test_field_value_stores_value_and_provenance() {
        let fv = FieldValue {
            value: Value::U64(9000),
            provenance: Provenance::UserConfigured {
                policy_ref: "bond0".to_string(),
            },
        };

        assert_eq!(fv.value, Value::U64(9000));
        assert_eq!(
            fv.provenance,
            Provenance::UserConfigured {
                policy_ref: "bond0".to_string()
            }
        );
    }

    #[test]
    fn test_field_value_clone_debug_partialeq() {
        let fv = FieldValue {
            value: Value::U64(9000),
            provenance: Provenance::KernelDefault,
        };
        let cloned = fv.clone();
        assert_eq!(fv, cloned);
        assert!(!format!("{:?}", fv).is_empty());
    }

    // ── StateMetadata tests ───────────────────────────────────────────────────

    #[test]
    fn test_state_metadata_ids_are_unique() {
        let m1 = StateMetadata::new();
        let m2 = StateMetadata::new();
        assert_ne!(m1.id, m2.id, "Two StateMetadata instances must have different id values");
        assert_ne!(
            m1.timeline_id, m2.timeline_id,
            "Two StateMetadata instances must have different timeline_id values"
        );
    }

    #[test]
    fn test_state_metadata_created_at_is_recent() {
        let before = Utc::now();
        let m = StateMetadata::new();
        let after = Utc::now();
        assert!(
            m.created_at >= before && m.created_at <= after,
            "created_at must be within the current moment: {:?} not in [{:?}, {:?}]",
            m.created_at,
            before,
            after
        );
    }

    #[test]
    fn test_state_metadata_labels_is_empty() {
        let m = StateMetadata::new();
        assert!(m.labels.is_empty(), "labels must be empty by default");
    }

    #[test]
    fn test_state_metadata_description_is_none() {
        let m = StateMetadata::new();
        assert!(m.description.is_none(), "description must be None by default");
    }

    #[test]
    fn test_state_metadata_ids_are_uuidv7() {
        let m = StateMetadata::new();
        assert_eq!(m.id.get_version_num(), 7, "id must be a UUIDv7");
        assert_eq!(m.timeline_id.get_version_num(), 7, "timeline_id must be a UUIDv7");
    }

    #[test]
    fn test_state_metadata_clone_debug_partialeq() {
        let m = StateMetadata::new();
        let cloned = m.clone();
        assert_eq!(m, cloned);
        assert!(!format!("{:?}", m).is_empty());
    }

    #[test]
    fn test_state_metadata_default_equals_new() {
        let m = StateMetadata::default();
        assert!(m.labels.is_empty());
        assert!(m.description.is_none());
        assert_eq!(m.id.get_version_num(), 7);
    }
}
