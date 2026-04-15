//! Integration tests for the netfyr Varlink API.
//!
//! These tests validate the complete client–server protocol round-trip using a
//! minimal in-process mock Varlink server, communicating over a real Unix socket
//! via `tokio`. They cover the multi-request session behavior and replace-all
//! semantics described in the acceptance criteria:
//!
//! - "Scenario: Full round-trip in unprivileged namespace"
//! - "Scenario: Replace-all semantics via Varlink"
//!
//! Note: The full end-to-end scenarios that require a running daemon and a network
//! namespace (with actual netlink apply) cannot be tested here because the daemon
//! binary does not yet implement the Varlink server. These tests validate the
//! Varlink protocol layer — wire format, multi-request sessions, and client
//! serialisation — using a mock server that simulates the daemon's responses.

use netfyr_varlink::{VarlinkClient, VarlinkPolicy, VarlinkSelector, VarlinkStateDef};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

// ── Wire-format helpers ───────────────────────────────────────────────────────

/// Read one NUL-terminated Varlink message from the stream and parse it as JSON.
async fn read_varlink_message(stream: &mut tokio::net::UnixStream) -> serde_json::Value {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("read byte from stream");
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    serde_json::from_slice(&buf).expect("request must be valid JSON")
}

/// Write a NUL-terminated Varlink message to the stream.
async fn write_varlink_message(stream: &mut tokio::net::UnixStream, body: serde_json::Value) {
    let mut bytes = serde_json::to_vec(&body).expect("serialize message");
    bytes.push(0);
    stream.write_all(&bytes).await.expect("write message to stream");
}

/// Build a temporary Unix socket path inside a `TempDir`.
fn temp_socket(dir: &tempfile::TempDir) -> String {
    dir.path().join("test.sock").to_string_lossy().into_owned()
}

/// Spawn a background mock server that handles one connection and processes
/// `responses.len()` sequential request/response pairs. Returns a `JoinHandle`
/// that resolves to the list of parsed request JSON objects (in order received).
///
/// Each element of `responses` is the value placed inside `{"parameters": ...}`
/// in the Varlink success response. The server reads one request, sends one
/// response, then repeats for the next pair.
///
/// **Important**: `UnixListener::bind` is called *synchronously* before
/// `tokio::spawn` so that the socket file exists on the filesystem by the time
/// this function returns. This avoids the race condition where the client tries
/// to connect before the server task has had a chance to run and bind.
fn spawn_sequential_mock_server(
    socket_path: String,
    responses: Vec<serde_json::Value>,
) -> tokio::task::JoinHandle<Vec<serde_json::Value>> {
    // Bind synchronously — only `accept()` is async. The socket file now exists
    // on the filesystem before the client attempts to connect.
    let listener = UnixListener::bind(&socket_path).expect("bind listener");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept connection");
        let mut received = Vec::with_capacity(responses.len());
        for response_params in responses {
            let req = read_varlink_message(&mut stream).await;
            received.push(req);
            let response = serde_json::json!({ "parameters": response_params });
            write_varlink_message(&mut stream, response).await;
        }
        received
    })
}

/// Construct a `VarlinkPolicy` (static factory) that sets `mtu` on the named interface.
fn make_static_mtu_policy(name: &str, interface: &str, mtu: u64) -> VarlinkPolicy {
    let mut fields = serde_json::Map::new();
    fields.insert("mtu".to_string(), serde_json::json!(mtu));
    VarlinkPolicy {
        name: name.to_string(),
        factory: "static".to_string(),
        priority: Some(100),
        selector: None,
        state: Some(VarlinkStateDef {
            entity_type: "ethernet".to_string(),
            selector: VarlinkSelector {
                name: Some(interface.to_string()),
                ..Default::default()
            },
            fields,
        }),
        states: None,
    }
}

// ── Scenario: Full round-trip ─────────────────────────────────────────────────

/// Scenario: Full round-trip — submit a policy then query the resulting state.
///
/// Simulates the daemon receiving a `SubmitPolicies` request, applying a policy
/// that sets `mtu=1400` on `veth0`, and then returning the updated interface state
/// when queried. Validates:
/// - Both calls succeed over a single persistent connection.
/// - The `ApplyReport` reflects the applied change (succeeded=1, entity_name="veth0").
/// - The subsequent `Query` returns a state with `mtu=1400`.
/// - Request sequence is correct: SubmitPolicies then Query.
#[tokio::test]
async fn test_full_round_trip_submit_policies_then_query_returns_updated_state() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = temp_socket(&dir);

    let responses = vec![
        // SubmitPolicies → ApplyReport (daemon applied the mtu=1400 policy)
        serde_json::json!({
            "report": {
                "succeeded": 1,
                "failed": 0,
                "skipped": 0,
                "changes": [
                    {
                        "kind": "modify",
                        "entity_type": "ethernet",
                        "entity_name": "veth0",
                        "description": "changed fields: mtu",
                        "status": "applied"
                    }
                ],
                "conflicts": []
            }
        }),
        // Query → entity list showing veth0 with mtu=1400
        serde_json::json!({
            "entities": [
                {
                    "entity_type": "ethernet",
                    "selector": { "name": "veth0" },
                    "fields": { "mtu": 1400 }
                }
            ]
        }),
    ];

    let server = spawn_sequential_mock_server(path.clone(), responses);
    let mut client = VarlinkClient::connect(&path).await.expect("client must connect");

    // --- Step 1: Submit a static policy that sets mtu=1400 ---
    let policy = make_static_mtu_policy("set-mtu-1400", "veth0", 1400);
    let report = client
        .submit_policies(vec![policy])
        .await
        .expect("submit_policies must succeed");

    assert_eq!(report.succeeded, 1, "submit must report 1 succeeded operation");
    assert_eq!(report.failed, 0, "submit must report 0 failed operations");
    assert_eq!(report.changes.len(), 1, "must have 1 change entry");
    assert_eq!(
        report.changes[0].entity_name, "veth0",
        "change entry must reference veth0"
    );
    assert_eq!(
        report.changes[0].status, "applied",
        "change entry status must be 'applied'"
    );

    // --- Step 2: Query — daemon returns the interface with mtu=1400 ---
    let selector = VarlinkSelector {
        entity_type: Some("ethernet".to_string()),
        name: Some("veth0".to_string()),
        ..Default::default()
    };
    let entities = client
        .query(Some(&selector))
        .await
        .expect("query must succeed");

    assert_eq!(entities.len(), 1, "query must return 1 entity");
    assert_eq!(entities[0].entity_type, "ethernet");
    assert_eq!(
        entities[0].selector.name.as_deref(),
        Some("veth0"),
        "returned entity must be veth0"
    );
    assert_eq!(
        entities[0].fields.get("mtu"),
        Some(&serde_json::json!(1400u64)),
        "queried mtu must be 1400 after applying the policy"
    );

    // Verify the server saw requests in the correct order.
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2, "server must have received exactly 2 requests");
    assert_eq!(
        requests[0]["method"].as_str(),
        Some("io.netfyr.SubmitPolicies"),
        "first request must be SubmitPolicies"
    );
    assert_eq!(
        requests[1]["method"].as_str(),
        Some("io.netfyr.Query"),
        "second request must be Query"
    );
}

// ── Scenario: Replace-all semantics ──────────────────────────────────────────

/// Scenario: Replace-all semantics via Varlink — submitting a new policy set
/// replaces the previous one.
///
/// The Varlink client must send each `submit_policies` call as an independent
/// complete policy set. The second call must contain ONLY `policy-b`; `policy-a`
/// must not be present. This validates the replace-all contract at the protocol
/// level: the client sends the full desired state, not an incremental diff.
///
/// From the acceptance criteria:
/// "Given the daemon is running in a namespace with policy A (mtu=1400)
///  When the client submits policy B (mtu=1300)
///  Then policy A is removed
///  And the interface mtu is 1300"
#[tokio::test]
async fn test_replace_all_semantics_second_submit_replaces_first_policy_set() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = temp_socket(&dir);

    // Server handles two sequential SubmitPolicies requests.
    let responses = vec![
        // First SubmitPolicies response: policy-a (mtu=1400) applied
        serde_json::json!({
            "report": {
                "succeeded": 1,
                "failed": 0,
                "skipped": 0,
                "changes": [],
                "conflicts": []
            }
        }),
        // Second SubmitPolicies response: policy-b (mtu=1300) applied
        serde_json::json!({
            "report": {
                "succeeded": 1,
                "failed": 0,
                "skipped": 0,
                "changes": [],
                "conflicts": []
            }
        }),
    ];

    let server = spawn_sequential_mock_server(path.clone(), responses);
    let mut client = VarlinkClient::connect(&path).await.expect("client must connect");

    let policy_a = make_static_mtu_policy("policy-a", "veth0", 1400);
    let policy_b = make_static_mtu_policy("policy-b", "veth0", 1300);

    // First submission: only policy-a.
    let first_report = client
        .submit_policies(vec![policy_a])
        .await
        .expect("first submit_policies must succeed");
    assert_eq!(first_report.succeeded, 1, "first report: 1 succeeded");

    // Second submission: only policy-b (replaces policy-a).
    let second_report = client
        .submit_policies(vec![policy_b])
        .await
        .expect("second submit_policies must succeed");
    assert_eq!(second_report.succeeded, 1, "second report: 1 succeeded");

    // Inspect the raw requests the server received.
    let requests = server.await.unwrap();
    assert_eq!(
        requests.len(),
        2,
        "server must have received exactly 2 SubmitPolicies requests"
    );

    // ── First request: must contain only policy-a with mtu=1400 ──────────────
    let first_policies = requests[0]["parameters"]["policies"]
        .as_array()
        .expect("first request must have a 'policies' array");
    assert_eq!(
        first_policies.len(),
        1,
        "first submit must send exactly 1 policy (policy-a)"
    );
    assert_eq!(
        first_policies[0]["name"].as_str(),
        Some("policy-a"),
        "first submit must contain policy-a"
    );
    assert_eq!(
        first_policies[0]["state"]["fields"]["mtu"].as_u64(),
        Some(1400),
        "policy-a must carry mtu=1400"
    );

    // ── Second request: must contain only policy-b with mtu=1300 ─────────────
    // policy-a must NOT be present — this proves replace-all (not accumulate) semantics.
    let second_policies = requests[1]["parameters"]["policies"]
        .as_array()
        .expect("second request must have a 'policies' array");
    assert_eq!(
        second_policies.len(),
        1,
        "second submit must send exactly 1 policy (replace-all: policy-a must be absent)"
    );
    assert_eq!(
        second_policies[0]["name"].as_str(),
        Some("policy-b"),
        "second submit must contain policy-b"
    );
    assert_eq!(
        second_policies[0]["state"]["fields"]["mtu"].as_u64(),
        Some(1300),
        "policy-b must carry mtu=1300"
    );

    // Explicitly assert policy-a is absent from the second request.
    let second_names: Vec<&str> = second_policies
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert!(
        !second_names.contains(&"policy-a"),
        "replace-all: policy-a must not appear in the second SubmitPolicies request, \
         but found names: {second_names:?}"
    );
}

// ── Scenario: Multi-method session ───────────────────────────────────────────

/// Scenario: A single connection handles multiple different method calls sequentially.
///
/// Verifies that the client maintains its connection across different Varlink method
/// calls and correctly serialises/deserialises each method's request and response.
/// Tests the DryRun → GetStatus call sequence.
#[tokio::test]
async fn test_multi_method_session_dry_run_then_get_status() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = temp_socket(&dir);

    let responses = vec![
        // DryRun → StateDiff showing mtu would change from 1500 → 1400
        serde_json::json!({
            "diff": {
                "operations": [
                    {
                        "kind": "modify",
                        "entity_type": "ethernet",
                        "entity_name": "veth0",
                        "field_changes": [
                            {
                                "field_name": "mtu",
                                "change_kind": "set",
                                "current": 1500,
                                "desired": 1400
                            }
                        ]
                    }
                ]
            }
        }),
        // GetStatus → DaemonStatus
        serde_json::json!({
            "status": {
                "uptime_seconds": 120,
                "active_policies": 3,
                "running_factories": []
            }
        }),
    ];

    let server = spawn_sequential_mock_server(path.clone(), responses);
    let mut client = VarlinkClient::connect(&path).await.expect("client must connect");

    // --- DryRun ---
    let policy = make_static_mtu_policy("set-mtu", "veth0", 1400);
    let diff = client
        .dry_run(vec![policy])
        .await
        .expect("dry_run must succeed");

    assert_eq!(diff.operations.len(), 1, "diff must have 1 operation");
    assert_eq!(diff.operations[0].kind, "modify");
    assert_eq!(diff.operations[0].entity_type, "ethernet");
    assert_eq!(diff.operations[0].entity_name, "veth0");
    assert_eq!(diff.operations[0].field_changes.len(), 1);
    assert_eq!(diff.operations[0].field_changes[0].field_name, "mtu");
    assert_eq!(diff.operations[0].field_changes[0].change_kind, "set");

    // --- GetStatus (same connection) ---
    let status = client
        .get_status()
        .await
        .expect("get_status must succeed");

    assert!(
        status.uptime_seconds >= 60,
        "uptime must be >= 60, got {}",
        status.uptime_seconds
    );
    assert_eq!(status.active_policies, 3, "active_policies must be 3");

    // Verify method names in request sequence.
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2, "server must have received 2 requests");
    assert_eq!(
        requests[0]["method"].as_str(),
        Some("io.netfyr.DryRun"),
        "first request must be DryRun"
    );
    assert_eq!(
        requests[1]["method"].as_str(),
        Some("io.netfyr.GetStatus"),
        "second request must be GetStatus"
    );
}

// ── Scenario: Submit with multiple policies ───────────────────────────────────

/// Scenario: submit_policies correctly serialises multiple policies in one request.
///
/// Verifies that when the caller submits N policies, all N appear in the request's
/// `policies` array, preserving names and mtu values.
#[tokio::test]
async fn test_submit_policies_serialises_multiple_policies_in_single_request() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = temp_socket(&dir);

    let responses = vec![serde_json::json!({
        "report": {
            "succeeded": 2,
            "failed": 0,
            "skipped": 0,
            "changes": [],
            "conflicts": []
        }
    })];

    let server = spawn_sequential_mock_server(path.clone(), responses);
    let mut client = VarlinkClient::connect(&path).await.expect("client must connect");

    let policy_a = make_static_mtu_policy("eth0-policy", "eth0", 1500);
    let policy_b = make_static_mtu_policy("eth1-policy", "eth1", 9000);

    let report = client
        .submit_policies(vec![policy_a, policy_b])
        .await
        .expect("submit_policies must succeed");

    assert_eq!(report.succeeded, 2);
    assert_eq!(report.failed, 0);

    // Inspect the raw request.
    let requests = server.await.unwrap();
    let policies_arr = requests[0]["parameters"]["policies"]
        .as_array()
        .expect("must have policies array");

    assert_eq!(policies_arr.len(), 2, "must send both policies in one request");

    let names: Vec<&str> = policies_arr.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(names.contains(&"eth0-policy"), "eth0-policy must be in request");
    assert!(names.contains(&"eth1-policy"), "eth1-policy must be in request");
}

// ── Scenario: Query without selector ─────────────────────────────────────────

/// Scenario: query(None) sends null selector and receives all entities.
///
/// Verifies the wire format for an unfiltered query and that all returned
/// entities have the expected entity_type, selector, and fields.
#[tokio::test]
async fn test_query_without_selector_returns_all_entities_with_correct_fields() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = temp_socket(&dir);

    let responses = vec![serde_json::json!({
        "entities": [
            {
                "entity_type": "ethernet",
                "selector": { "name": "eth0" },
                "fields": { "mtu": 1500, "speed": 1000 }
            },
            {
                "entity_type": "ethernet",
                "selector": { "name": "eth1" },
                "fields": { "mtu": 9000, "speed": 10000 }
            }
        ]
    })];

    let server = spawn_sequential_mock_server(path.clone(), responses);
    let mut client = VarlinkClient::connect(&path).await.expect("client must connect");

    let entities = client.query(None).await.expect("query must succeed");

    // Each entity must have entity_type, selector, and fields.
    assert_eq!(entities.len(), 2, "must receive 2 entities");
    for entity in &entities {
        assert_eq!(entity.entity_type, "ethernet", "entity_type must be 'ethernet'");
        assert!(entity.selector.name.is_some(), "entity selector must have a name");
        assert!(!entity.fields.is_empty(), "entity fields must not be empty");
    }

    assert_eq!(entities[0].selector.name.as_deref(), Some("eth0"));
    assert_eq!(entities[0].fields.get("mtu"), Some(&serde_json::json!(1500u64)));

    assert_eq!(entities[1].selector.name.as_deref(), Some("eth1"));
    assert_eq!(entities[1].fields.get("mtu"), Some(&serde_json::json!(9000u64)));

    // Wire: selector must be null when None is passed.
    let requests = server.await.unwrap();
    assert!(
        requests[0]["parameters"]["selector"].is_null(),
        "null selector must appear as JSON null in the request"
    );
}
