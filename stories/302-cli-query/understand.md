# Understand: SPEC-302 — CLI Query Command

## Current State

The implementation is **complete**. All production code, unit tests, and integration test scripts already exist.

### `crates/netfyr-cli/src/query.rs` (826 lines, fully implemented)
- `pub enum OutputFormat { Yaml, Json }` — clap `ValueEnum`, short flag `-o`, default `"yaml"`.
- `pub struct QueryArgs` — `selector: Vec<(String, String)>` (short `-s`, value_parser `parse_selector`) and `output: OutputFormat`.
- `pub async fn run_query(args: QueryArgs) -> Result<ExitCode>` — daemon detection via `NETFYR_SOCKET_PATH` env var (default `/run/netfyr/netfyr.sock`), routes to `run_query_daemon` or `run_query_local`.
- `fn parse_selector` — validates key against `VALID_SELECTOR_KEYS = ["type", "name", "driver", "mac", "pci_path"]` at clap parse time; rejects missing `=` and invalid keys.
- `fn extract_type_and_selector` — splits `type=X`; builds `Selector` with `name`, `driver`, `pci_path`, `mac` fields; parses MAC via `MacAddr::from_str`.
- `fn build_varlink_selector` — returns `None` when both args are `None` (query-all), otherwise merges into `VarlinkSelector`.
- `async fn run_query_local` — iterates `registry.supported_entities()` (sorted), calls `registry.query(&et, selector)` per type, handles `BackendError::UnsupportedEntityType` (exit 2) and `BackendError::NotFound` (empty, exit 0).
- `async fn run_query_daemon` — calls `VarlinkClient::query(Option<&VarlinkSelector>)`, converts via `varlink_state_to_flat_map`.
- `fn state_to_flat_map` — `IndexMap` with `"type"` first, then all fields (strips `FieldValue` wrapper).
- `fn varlink_state_to_flat_map` — same shape from `VarlinkState.fields: serde_json::Map`.
- `fn print_output` — YAML via `serde_yaml::to_string` (`print!`), JSON via `serde_json::to_string_pretty` (`println!`).
- Comprehensive unit tests covering all acceptance criteria.

### `crates/netfyr-cli/src/lib.rs` (fully wired)
- `mod query` declared; `pub use query::run_query` exported.
- `Commands::Query(query::QueryArgs)` registered in the clap subcommand enum.

### Integration test scripts (all exist)
- `tests/302-query-all.sh` — `netfyr query -o json` in a namespace with veth pair; asserts both ends appear.
- `tests/302-query-veth-by-name.sh` — `netfyr query -s name=veth-test0 -o json`; asserts mtu=1400 and address `10.99.0.1/24`.
- `tests/302-query-yaml.sh` — `netfyr query -s name=veth-test0` (YAML default); asserts `mtu: 1400`.
- `tests/helpers.sh` — shared helpers providing `netns_setup`, `create_veth`, `add_address`, etc.

All three scripts:
- Use `NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"` and `exit 1` if binary missing.
- Source `helpers.sh`.
- Call `netns_setup` for namespace entry.
- Follow the no-skip rule (no `|| exit 0` on prerequisite failures).

## Requirements

From the acceptance criteria:

1. `netfyr query` with no args → all entities in YAML
2. `--selector type=ethernet` → filter by entity type
3. `--selector name=eth0` → filter by name
4. `--selector driver=ixgbe` → filter by driver
5. Multiple `--selector` flags → AND logic
6. Default output format is YAML; `--output json` / `-o json` for JSON
7. No matching entities → empty list, exit 0
8. Invalid selector key → error listing valid keys, exit 2
9. Invalid type value → error listing valid entity types, exit 2
10. JSON output is jq-compatible (pretty-printed array)
11. Short flags `-s` and `-o` work
12. Daemon mode: connect to socket, delegate to `VarlinkClient::query`
13. Integration test scripts: `302-query-all.sh`, `302-query-veth-by-name.sh`, `302-query-yaml.sh`

## Gap Analysis

**No gaps found.** All requirements are fully implemented and the integration tests exist.

| Requirement | Status |
|---|---|
| `QueryArgs` with `-s`/`--selector` and `-o`/`--output` | Complete |
| `parse_selector` validates keys at parse time | Complete |
| `extract_type_and_selector` splits `type=` | Complete |
| Daemon-free mode via `BackendRegistry` per-type iteration | Complete |
| Daemon mode via `VarlinkClient::query` | Complete |
| Mode detection via socket connection attempt | Complete |
| YAML output (default) | Complete |
| JSON output (pretty-printed) | Complete |
| Empty result → exit 0 | Complete |
| Invalid key → exit 2 with valid key list | Complete |
| Unknown type → exit 2 with valid type list | Complete |
| `NETFYR_SOCKET_PATH` env var override | Complete |
| 3 integration test scripts (302-*.sh) | Complete |
| Unit tests for all acceptance criteria | Complete |

**Remaining verification step**: Run `make integration-test SPEC=302` against a built binary to confirm the shell scripts pass end-to-end. The code exists; runtime pass/fail is unknown until executed.

## Integration Points

### Backend
- `BackendRegistry::query(&EntityType, Option<&Selector>)` — per-type query with optional selector; selector's `driver`/`mac`/`pci_path` fields are evaluated by the netlink backend via sysfs reads.
- `BackendRegistry::supported_entities()` — used to enumerate registered entity types in daemon-free mode.
- `BackendError::UnsupportedEntityType` — triggers exit 2 with valid-types message.
- `BackendError::NotFound` — treated as empty result (exit 0), not an error.
- `NetlinkBackend` — registered as the sole backend via `create_backend_registry()`.

### Varlink
- `VarlinkClient::connect(socket_path)` — mode detection; `VarlinkError::ConnectionFailed` triggers daemon-free fallback; other errors propagate fatally.
- `VarlinkClient::query(Option<&VarlinkSelector>)` — daemon query; `None` means query-all.
- `VarlinkSelector` — `entity_type` serialized as `"type"` on wire via `#[serde(rename = "type")]`.
- `VarlinkState` — `entity_type: String`, `fields: serde_json::Map<String, serde_json::Value>`.

### State types
- `Selector` — public fields `name`, `driver`, `mac: Option<MacAddr>`, `pci_path`, `entity_type`, `labels`.
- `State` — `entity_type`, `fields: IndexMap<String, FieldValue>`.
- `FieldValue.value: Value` — serialized to `serde_json::Value` via `serde_json::to_value`; IP types serialize as strings.

### CLI wiring
- `Commands::Query(query::QueryArgs)` in `lib.rs`; `main.rs` / `netfyr_cli_main.rs` dispatch to `run_query`.

## Risks

1. **`unshare --user --net` availability**: Integration tests require unprivileged user namespaces. On kernels with `kernel.unprivileged_userns_clone=0` (some hardened distros), tests will fail rather than skip. The scripts correctly `exit 1` on failure, which is spec-compliant but means CI environments need to support user namespaces.

2. **`serde_json::to_value` for IP/network types**: `Value::IpNetwork` and `Value::IpAddr` serialize as strings via their serde impls. The integration test expects `"10.99.0.1/24"` as a string in the `addresses` array — correct if the backend populates `addresses` as `Value::List(Vec<Value::IpNetwork>)`. This is an implicit dependency on the netlink backend's field representation.

3. **Daemon-mode type filtering delegated to daemon**: When daemon mode is active, `entity_type` from `--selector type=X` is sent to the daemon as `VarlinkSelector.entity_type`. If the daemon does not filter by entity type, the selector is silently ignored. This is a SPEC-404 dependency, not a CLI gap.

4. **`BackendError::NotFound` vs silent empty result**: `NotFound` is treated as an empty result (exit 0). If the backend raises `NotFound` for reasons other than "no matching entity" (e.g., sysfs unreadable), the operator sees an empty list with no error indication. This is a spec-level decision.

5. **No post-filter fallback**: `run_query_local` passes the full selector to each backend's `query()` call. If a future backend does not support selector matching natively, it would need to be handled there or a post-filter layer added. Currently only `NetlinkBackend` is registered; this is a future extensibility concern.
