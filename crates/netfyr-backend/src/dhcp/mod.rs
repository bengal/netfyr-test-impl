//! DHCPv4 factory — produces `State` from a DHCP lease.
//!
//! `Dhcpv4Factory` starts a background tokio task that runs the full DHCP
//! state machine and sends `FactoryEvent` messages to the daemon via an
//! `mpsc` channel. The factory does NOT implement `NetworkBackend` — its
//! lifecycle is managed by the daemon (SPEC-403), not `BackendRegistry`.

pub mod client;
pub mod lease;

pub use lease::DhcpLease;

use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use netfyr_state::{FieldValue, Provenance, Selector, State, StateMetadata, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::BackendError;

// ── FactoryEvent ──────────────────────────────────────────────────────────────

/// Events sent by the DHCP client task to the daemon.
#[derive(Debug)]
pub enum FactoryEvent {
    /// A new DHCP lease was successfully acquired.
    LeaseAcquired {
        policy_name: String,
        state: State,
    },
    /// An existing DHCP lease was renewed (T1 or T2 renewal succeeded).
    LeaseRenewed {
        policy_name: String,
        state: State,
    },
    /// The DHCP lease expired without successful renewal or rebinding.
    LeaseExpired {
        policy_name: String,
    },
    /// A non-fatal error occurred (e.g., discovery timeout). The factory retries.
    Error {
        policy_name: String,
        error: String,
    },
}

// ── Dhcpv4Factory ─────────────────────────────────────────────────────────────

/// A factory that runs a DHCP client on a named interface and produces `State`
/// objects from acquired leases.
///
/// # Lifecycle
///
/// 1. Call [`Dhcpv4Factory::start`] to spawn the background DHCP client task.
/// 2. Monitor the `state_tx` channel for `FactoryEvent` messages.
/// 3. Call [`Dhcpv4Factory::stop`] to gracefully release the lease and terminate.
pub struct Dhcpv4Factory {
    /// The network interface this factory is managing.
    interface: String,
    /// Shared reference to the latest produced State, if any.
    /// Updated by the background task; read by `current_state()`.
    state: Arc<Mutex<Option<State>>>,
    /// One-shot channel sender for sending the stop signal to the background task.
    stop_tx: Option<oneshot::Sender<()>>,
    /// Handle to the background task, used to await clean termination.
    task_handle: Option<JoinHandle<()>>,
}

impl Dhcpv4Factory {
    /// Start a DHCP client on `interface`.
    ///
    /// Returns immediately; lease acquisition runs in a background tokio task.
    /// Lease state changes are communicated via `state_tx`.
    ///
    /// # Parameters
    /// - `interface`: Network interface name (e.g., `"eth0"`).
    /// - `policy_name`: Name of the policy that produced this factory (used
    ///   for `Provenance::UserConfigured` and event identification).
    /// - `priority`: Field priority for conflict resolution (higher wins).
    /// - `state_tx`: Channel for sending `FactoryEvent` messages to the daemon.
    pub async fn start(
        interface: &str,
        policy_name: String,
        priority: u32,
        state_tx: mpsc::Sender<FactoryEvent>,
    ) -> Result<Self, BackendError> {
        let shared_state: Arc<Mutex<Option<State>>> = Arc::new(Mutex::new(None));
        let (stop_tx, stop_rx) = oneshot::channel();

        let task_shared_state = Arc::clone(&shared_state);
        let task_interface = interface.to_string();
        let task_policy_name = policy_name.clone();

        let task_handle = tokio::spawn(async move {
            client::run_dhcp_client(
                task_interface,
                task_policy_name,
                priority,
                state_tx,
                task_shared_state,
                stop_rx,
            )
            .await;
        });

        Ok(Self {
            interface: interface.to_string(),
            state: shared_state,
            stop_tx: Some(stop_tx),
            task_handle: Some(task_handle),
        })
    }

    /// Stop the DHCP client and release the active lease (DHCPRELEASE).
    ///
    /// Idempotent: calling `stop()` on an already-stopped factory returns `Ok(())`.
    pub async fn stop(&mut self) -> Result<(), BackendError> {
        // Send the stop signal, if the task is still running.
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }

        // Wait for the background task to finish.
        if let Some(handle) = self.task_handle.take() {
            handle.await.map_err(|e| {
                BackendError::Internal(format!("DHCP task join error: {e}"))
            })?;
        }

        Ok(())
    }

    /// Returns a clone of the current lease state, or `None` if no lease has
    /// been acquired yet.
    ///
    /// Returns an owned `State` rather than `&State` to avoid holding the
    /// mutex across caller code (which would require a lock guard in the API).
    pub fn current_state(&self) -> Option<State> {
        self.state.lock().unwrap().clone()
    }

    /// Returns the network interface name this factory manages.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

// ── State conversion ──────────────────────────────────────────────────────────

/// Convert a DHCP lease into a `State` with `UserConfigured` provenance.
///
/// Follows the exact field naming, value types, and map structure used by
/// `netlink/ethernet.rs` to ensure reconciliation compatibility:
/// - Addresses stored as `Value::String("ip/prefix")`.
/// - Routes stored as `Value::Map` with `"destination"` and `"gateway"` keys.
/// - DNS servers stored as `Value::List` of `Value::String`.
pub fn lease_to_state(
    lease: &DhcpLease,
    interface: &str,
    policy_name: &str,
    priority: u32,
) -> State {
    let prov = Provenance::UserConfigured {
        policy_ref: policy_name.to_string(),
    };

    let fv = |value: Value| FieldValue {
        value,
        provenance: prov.clone(),
    };

    let mut fields: IndexMap<String, FieldValue> = IndexMap::new();

    // Addresses field: ["ip/prefix"]
    let cidr = format!("{}/{}", lease.ip, lease.subnet_mask_to_prefix());
    fields.insert(
        "addresses".to_string(),
        fv(Value::List(vec![Value::String(cidr)])),
    );

    // Routes field: [{destination: "0.0.0.0/0", gateway: "gw_ip"}]
    if let Some(gateway) = lease.gateway {
        let mut route_map = IndexMap::new();
        route_map.insert(
            "destination".to_string(),
            Value::String("0.0.0.0/0".to_string()),
        );
        route_map.insert(
            "gateway".to_string(),
            Value::String(gateway.to_string()),
        );
        fields.insert(
            "routes".to_string(),
            fv(Value::List(vec![Value::Map(route_map)])),
        );
    }

    // DNS servers field: ["server1", "server2", ...]
    if !lease.dns_servers.is_empty() {
        let dns_list: Vec<Value> = lease
            .dns_servers
            .iter()
            .map(|s| Value::String(s.to_string()))
            .collect();
        fields.insert("dns_servers".to_string(), fv(Value::List(dns_list)));
    }

    State {
        entity_type: "ethernet".to_string(),
        selector: Selector::with_name(interface),
        fields,
        metadata: StateMetadata::new(),
        policy_ref: Some(policy_name.to_string()),
        priority,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use netfyr_state::{Provenance, Value};
    use tokio::sync::mpsc;

    use super::{lease_to_state, Dhcpv4Factory, FactoryEvent};
    use crate::dhcp::lease::DhcpLease;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn make_full_lease() -> DhcpLease {
        DhcpLease {
            ip: Ipv4Addr::new(10, 0, 1, 50),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(10, 0, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(10, 0, 1, 2)],
            lease_time: 3600,
            renewal_time: 1800,
            rebind_time: 3150,
            server_id: Ipv4Addr::new(10, 0, 1, 1),
            acquired_at: Instant::now(),
        }
    }

    fn make_minimal_lease() -> DhcpLease {
        DhcpLease {
            ip: Ipv4Addr::new(10, 0, 1, 50),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: None,
            dns_servers: vec![],
            lease_time: 3600,
            renewal_time: 1800,
            rebind_time: 3150,
            server_id: Ipv4Addr::new(10, 0, 1, 1),
            acquired_at: Instant::now(),
        }
    }

    // ── lease_to_state: addresses field ──────────────────────────────────────

    /// Scenario: Lease produces correct State fields
    /// Given IP=10.0.1.50, mask=255.255.255.0 → addresses=["10.0.1.50/24"]
    #[test]
    fn test_lease_to_state_addresses_contains_cidr() {
        let state = lease_to_state(&make_full_lease(), "eth0", "test-policy", 100);

        let addresses = state
            .fields
            .get("addresses")
            .expect("addresses field must exist")
            .value
            .as_list()
            .expect("addresses must be a list");

        assert_eq!(addresses.len(), 1, "must have exactly one address");
        assert_eq!(
            addresses[0].as_str(),
            Some("10.0.1.50/24"),
            "address must be formatted as ip/prefix"
        );
    }

    // ── lease_to_state: routes field ─────────────────────────────────────────

    /// Scenario: State has routes with destination="0.0.0.0/0" gateway="10.0.1.1"
    #[test]
    fn test_lease_to_state_routes_contain_default_gateway() {
        let state = lease_to_state(&make_full_lease(), "eth0", "test-policy", 100);

        let routes = state
            .fields
            .get("routes")
            .expect("routes field must exist when gateway is provided")
            .value
            .as_list()
            .expect("routes must be a list");

        assert_eq!(routes.len(), 1, "must have exactly one route");

        let route_map = routes[0].as_map().expect("route entry must be a map");
        assert_eq!(
            route_map
                .get("destination")
                .and_then(Value::as_str),
            Some("0.0.0.0/0"),
            "default route destination must be 0.0.0.0/0"
        );
        assert_eq!(
            route_map.get("gateway").and_then(Value::as_str),
            Some("10.0.1.1"),
            "gateway must match lease gateway"
        );
    }

    // ── lease_to_state: dns_servers field ────────────────────────────────────

    /// Scenario: State has dns_servers=["10.0.1.2"]
    #[test]
    fn test_lease_to_state_dns_servers_field() {
        let state = lease_to_state(&make_full_lease(), "eth0", "test-policy", 100);

        let dns = state
            .fields
            .get("dns_servers")
            .expect("dns_servers field must exist")
            .value
            .as_list()
            .expect("dns_servers must be a list");

        assert_eq!(dns.len(), 1);
        assert_eq!(
            dns[0].as_str(),
            Some("10.0.1.2"),
            "DNS server must match lease dns_servers"
        );
    }

    /// Multiple DNS servers are all listed in order.
    #[test]
    fn test_lease_to_state_multiple_dns_servers() {
        let lease = DhcpLease {
            ip: Ipv4Addr::new(10, 0, 1, 50),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: None,
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            lease_time: 3600,
            renewal_time: 1800,
            rebind_time: 3150,
            server_id: Ipv4Addr::new(10, 0, 1, 1),
            acquired_at: Instant::now(),
        };
        let state = lease_to_state(&lease, "eth0", "test-policy", 100);

        let dns = state
            .fields
            .get("dns_servers")
            .expect("dns_servers must exist")
            .value
            .as_list()
            .expect("dns_servers must be a list");

        assert_eq!(dns.len(), 2);
        assert_eq!(dns[0].as_str(), Some("8.8.8.8"));
        assert_eq!(dns[1].as_str(), Some("8.8.4.4"));
    }

    // ── lease_to_state: absent optional fields ────────────────────────────────

    /// When no gateway is present, the routes field must not exist.
    #[test]
    fn test_lease_to_state_no_gateway_produces_no_routes_field() {
        let state = lease_to_state(&make_minimal_lease(), "eth0", "test-policy", 100);
        assert!(
            state.fields.get("routes").is_none(),
            "routes field must be absent when no gateway provided"
        );
    }

    /// When no DNS servers are present, dns_servers must not exist.
    #[test]
    fn test_lease_to_state_no_dns_produces_no_dns_servers_field() {
        let state = lease_to_state(&make_minimal_lease(), "eth0", "test-policy", 100);
        assert!(
            state.fields.get("dns_servers").is_none(),
            "dns_servers field must be absent when no DNS servers provided"
        );
    }

    // ── lease_to_state: entity_type and selector ─────────────────────────────

    #[test]
    fn test_lease_to_state_entity_type_is_ethernet() {
        let state = lease_to_state(&make_minimal_lease(), "eth0", "test-policy", 100);
        assert_eq!(state.entity_type, "ethernet");
    }

    #[test]
    fn test_lease_to_state_selector_name_matches_interface() {
        let state = lease_to_state(&make_minimal_lease(), "veth-test", "test-policy", 100);
        assert_eq!(
            state.selector.name.as_deref(),
            Some("veth-test"),
            "selector name must match the interface argument"
        );
    }

    #[test]
    fn test_lease_to_state_policy_ref_matches_policy_name() {
        let state = lease_to_state(&make_minimal_lease(), "eth0", "my-dhcp-policy", 100);
        assert_eq!(
            state.policy_ref.as_deref(),
            Some("my-dhcp-policy"),
            "policy_ref must match the policy_name argument"
        );
    }

    /// Provenance of all fields must be UserConfigured with the given policy name.
    #[test]
    fn test_lease_to_state_provenance_is_user_configured() {
        let state = lease_to_state(&make_full_lease(), "eth0", "my-policy", 100);

        for (field_name, fv) in &state.fields {
            assert!(
                matches!(
                    fv.provenance,
                    Provenance::UserConfigured { ref policy_ref } if policy_ref == "my-policy"
                ),
                "field '{field_name}' must have UserConfigured provenance with the correct policy_ref"
            );
        }
    }

    /// Priority is stored correctly.
    #[test]
    fn test_lease_to_state_priority_is_stored() {
        let state = lease_to_state(&make_minimal_lease(), "eth0", "p", 200);
        assert_eq!(state.priority, 200);
    }

    // ── Dhcpv4Factory: current_state before lease ─────────────────────────────

    /// Scenario: current_state returns None before lease
    /// Given a newly started factory
    /// When current_state() is called before any lease is acquired
    /// Then it returns None
    #[tokio::test]
    async fn test_current_state_returns_none_before_lease_acquired() {
        let (tx, _rx) = mpsc::channel::<FactoryEvent>(10);
        // Use a nonexistent interface — start() itself always succeeds (task is spawned
        // asynchronously); current_state() is None because no lease has been acquired.
        let factory =
            Dhcpv4Factory::start("nonexistent-iface-xyz99", "test-policy".to_string(), 100, tx)
                .await
                .expect("start() must succeed (task spawned, not executed synchronously)");

        // Check immediately — the spawned task hasn't run yet in the current-thread
        // runtime, so shared_state is still None.
        assert!(
            factory.current_state().is_none(),
            "current_state() must return None before any lease is acquired"
        );
    }

    /// Scenario: interface() returns the configured interface name.
    #[tokio::test]
    async fn test_factory_interface_returns_configured_name() {
        let (tx, _rx) = mpsc::channel::<FactoryEvent>(10);
        let factory =
            Dhcpv4Factory::start("eth-unit-test", "test-policy".to_string(), 100, tx)
                .await
                .expect("start() must succeed");
        assert_eq!(factory.interface(), "eth-unit-test");
    }

    /// Scenario: stop() is idempotent — calling it twice must not panic or error.
    #[tokio::test]
    async fn test_factory_stop_is_idempotent() {
        let (tx, _rx) = mpsc::channel::<FactoryEvent>(10);
        let mut factory =
            Dhcpv4Factory::start("nonexistent-iface-xyz99", "test-policy".to_string(), 100, tx)
                .await
                .expect("start() must succeed");
        factory.stop().await.expect("first stop() must succeed");
        factory.stop().await.expect("second stop() must succeed (idempotent)");
    }

    /// Scenario: Factory sends FactoryEvent::Error when the interface is not found.
    ///
    /// The background task fails to read the MAC from sysfs and sends an Error event.
    #[tokio::test]
    async fn test_factory_sends_error_event_when_interface_not_found() {
        let (tx, mut rx) = mpsc::channel::<FactoryEvent>(10);
        let _factory =
            Dhcpv4Factory::start("nonexistent-iface-xyz99", "test-policy".to_string(), 100, tx)
                .await
                .expect("start() must succeed");

        // Yield to allow the background task to run and send an event.
        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("Error event must be received within 5 seconds")
            .expect("channel must not close before an event is sent");

        match event {
            FactoryEvent::Error { policy_name, error } => {
                assert_eq!(policy_name, "test-policy");
                assert!(
                    !error.is_empty(),
                    "Error event must contain a non-empty error message"
                );
            }
            other => panic!(
                "Expected FactoryEvent::Error for nonexistent interface, got {:?}",
                other
            ),
        }
    }
}
