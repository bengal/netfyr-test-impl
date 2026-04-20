# Understand: SPEC-302 — CLI Query Command

## Current State

The Rust implementation of `netfyr query` is **fully complete**. All production code and unit tests are already in place:

### `crates/netfyr-cli/src/query.rs` (fully implemented)
- `pub enum OutputFormat { Yaml, Json }` — clap `ValueEnum`, short flag `-o`, default `"yaml"`.
- `pub struct QueryArgs` — `selector: Vec<(String, String)>` (short `-s`, value_parser `parse_selector`) and `output: OutputFormat`.
- `pub async fn run_query(args: QueryArgs) -> Result<ExitCode>` — daemon detection via `NETFYR_SOCKET_PATH` env var (default `/run/netfyr/netfyr.sock`), routes to `run_query_daemon` or `run_query_local`.
- `fn parse_selector(s: &str) -> Result<(String, String), String>` — validates key against `VALID_SELECTOR_KEYS = ["type", "name", "driver", "mac", "pci_path"]` at clap parse time.
- `fn extract_type_and_selector(selectors) -> Result<(Option<String>, Option<Selector>)>` — splits `type=X` out; builds `Selector` with public fields (`name`, `driver`, `pci_path`, `mac`); parses MAC via `MacAddr::from_str`.
- `fn build_varlink_selector(entity_type, selector) -> Option<VarlinkSelector>` — returns `None` when both are `None` (query-all semantics), otherwise merges into a `VarlinkSelector`.
- `async fn run_query_local(...)` — iterates `registry.supported_entities()` sorted, calls `registry.query(&et, selector)` per entity type, collects `IndexMap<String, serde_json::Value>` via `state_to_flat_map`. Handles `BackendError::UnsupportedEntityType` (exit 2) and `BackendError::NotFound` (empty result, exit 0).
- `async fn run_query_daemon(...)` — calls `VarlinkClient::query(Option<&VarlinkSelector>)`, converts via `varlink_state_to_flat_map`.
- `fn state_to_flat_map(state: &State)` — `IndexMap` with `"type"` first, then all fields from `state.fields` (strips `FieldValue` wrapper via `serde_json::to_value(&fv.value)`).
- `fn varlink_state_to_flat_map(vs: &VarlinkState)` — same shape, from `VarlinkState.fields` which is already `serde_json::Map`.
- `fn print_output(maps, format)` — YAML via `serde_yaml::to_string`, JSON via `serde_json::to_string_pretty`.
- Comprehensive unit tests covering: `parse_selector`, `extract_type_and_selector`, `build_varlink_selector`, `state_to_flat_map`, YAML/JSON serialization of empty and non-empty lists.

### `crates/netfyr-cli/src/lib.rs` (fully wired)
- `mod query` declared; `pub use query::run_query` exported.
- `Commands::Query(query::QueryArgs)` registered in the clap subcommand enum.

### Supporting infrastructure (already exists)
- `netfyr_state::Selector` — public fields: `name`, `entity_type`, `driver`, `pci_path`, `mac`, `labels`. Implements `Default`.
- `netfyr_state::MacAddr` — `FromStr`, `Display` (lowercase colon-separated).
- `netfyr_backend::BackendRegistry::query(&EntityType, Option<&Selector>)` and `query_all()`.
- `netfyr_varlink::VarlinkClient::query(Option<&VarlinkSelector>) -> Result<Vec<VarlinkState>, VarlinkError>`.
- `VarlinkError::ConnectionFailed` variant used for daemon-not-running detection.
- `Makefile` with `integration-test` target discovering `tests/[0-9]*.sh`.

### What does NOT exist
- `tests/` directory — no shell integration test scripts of any kind exist in the project.
- `tests/helpers.sh` — referenced by the spec as providing `netns_setup`, `create_veth`, `add_address`, `cleanup`, and assertion functions; does not exist.
- `tests/302-*.sh` — the three integration scenarios required by the spec do not exist.

## Requirements

From the acceptance criteria, the following concrete technical requirements apply:

1. **Shell integration test: query veth interface by name** (`tests/302-*.sh`)
   - `unshare --user --net` namespace with veth pair `veth-test0`/`veth-test1`, mtu 1400, address `10.99.0.1/24` on `veth-test0`.
   - `netfyr query -s name=veth-test0 -o json` must exit 0, return one entity with `name="veth-test0"`, `mtu=1400`, addresses containing `"10.99.0.1/24"`.

2. **Shell integration test: query all interfaces** (`tests/302-*.sh`)
   - Same namespace; `netfyr query -o json` must return at least 2 entities (both veth ends).

3. **Shell integration test: YAML output** (`tests/302-*.sh`)
   - `netfyr query -s name=veth-test0` (default YAML) must produce valid YAML containing `"mtu: 1400"`.

4. **helpers.sh** providing at minimum:
   - `netns_setup` — enters unprivileged user+net namespace.
   - `create_veth` — creates a veth pair via `ip link`.
   - `add_address` — assigns an IP address to an interface.
   - `cleanup` — teardown/trap.
   - Assertion functions (e.g., `assert_exit_code`, `assert_json_field`, `assert_contains`).

5. **Binary locator convention**: scripts must use `NETFYR_BIN="${NETFYR_BIN:-$(dirname "$0")/../target/debug/netfyr}"` and fail with `exit 1` if the binary is missing.

6. **No-skip rule**: scripts must `exit 1` on missing prerequisites (unshare, ip), never `exit 0`.

## Gap Analysis

### Files to create

| File | Status | Notes |
|------|--------|-------|
| `tests/helpers.sh` | Missing | Shared shell helpers for all integration tests; must provide netns setup, veth creation, address assignment, cleanup, assertions |
| `tests/302-query-name.sh` | Missing | Tests `netfyr query -s name=veth-test0 -o json` in a namespace |
| `tests/302-query-all.sh` | Missing | Tests `netfyr query -o json` returns ≥2 entities |
| `tests/302-query-yaml.sh` | Missing | Tests default YAML output contains `mtu: 1400` |

### Files to modify
None — all Rust production code and unit tests are complete.

### Rust code gaps
None. The implementation matches the spec precisely:
- Daemon-free mode: per-entity-type iteration with selector passed to backend.
- Daemon mode: `VarlinkClient::query` with merged `VarlinkSelector`.
- Error paths: invalid key (clap-level), invalid MAC (in `extract_type_and_selector`), unsupported type (exit 2), no match (exit 0, empty list).
- Output: YAML (serde_yaml, `print!`) and JSON (serde_json pretty, `println!`).
- Env var: `NETFYR_SOCKET_PATH` with `/run/netfyr/netfyr.sock` default.

## Integration Points

- **`netfyr_backend::BackendRegistry`**: `run_query_local` calls `registry.query(&et, selector)` passing an `Option<&Selector>`. The selector's non-`type` fields (`name`, `driver`, `mac`, `pci_path`) are passed directly to the netlink backend which reads sysfs for driver/pci_path matching.
- **`netfyr_varlink::VarlinkClient::query`**: accepts `Option<&VarlinkSelector>` where `None` means query-all. The `VarlinkSelector` carries `entity_type` (serialized as `"type"` on the wire per the varlink client test), `name`, `driver`, `mac`, `pci_path`.
- **`netfyr_state::State`**: `state_to_flat_map` reads `state.entity_type` and iterates `state.fields: IndexMap<String, FieldValue>`, accessing `fv.value: Value` which serializes naturally via `serde_json::to_value`.
- **`netfyr_varlink::VarlinkState`**: `varlink_state_to_flat_map` reads `vs.entity_type: String` and `vs.fields: serde_json::Map<String, serde_json::Value>`.
- **Makefile**: discovers tests via `tests/[0-9]*.sh` glob; `make integration-test SPEC=302` runs only `tests/302-*.sh`.

## Risks

1. **`unshare --user --net` privileges**: Integration tests rely on unprivileged user namespaces. Some Linux distros/kernels disable this (`sysctl kernel.unprivileged_userns_clone=0`). The spec mandates `exit 1` (not `exit 0`) if the prerequisite is unavailable, which is correct — tests must not silently pass.

2. **`serde_json::to_value(&fv.value)` for IP types**: `Value::IpNetwork` and `Value::IpAddr` are serialized by their serde impls as strings (e.g., `"10.99.0.1/24"`, `"10.0.0.1"`). The JSON test scenario expects `addresses` to contain `"10.99.0.1/24"` as a string inside an array — this depends on the backend populating `addresses` as `Value::List(Vec<Value::IpNetwork>)`, which the spec output examples confirm. No mismatch expected, but this is implicit.

3. **`BackendError::NotFound` vs empty result**: `run_query_local` treats `NotFound` as an empty result (exit 0). If the backend returns `NotFound` for a known entity type with a non-matching selector (e.g., `name=eth99`), the correct empty-list behavior is implemented. If the backend raises `NotFound` for other reasons (e.g., sysfs unreadable), the operator may see a silent empty result instead of an error. This is a spec decision, not a bug to fix here.

4. **Daemon-mode type filtering**: When daemon mode is active, the `entity_type` extracted from selectors is encoded as `VarlinkSelector.entity_type` and sent to the daemon. The daemon is responsible for filtering — the CLI does no post-filter. If the daemon does not implement type filtering, `--selector type=ethernet` in daemon mode would return all entity types. This is a dependency on SPEC-404 (Varlink API), not a CLI gap.

5. **`VarlinkSelector.entity_type` wire serialization**: The varlink client test asserts `sel["type"]` (not `sel["entity_type"]`), confirming the field is renamed to `"type"` in JSON. The `build_varlink_selector` in `query.rs` sets `entity_type: entity_type.map(str::to_string)` — if `VarlinkSelector` renames this to `"type"` via `#[serde(rename = "type")]`, the wire format is correct. This is not visible from the query.rs code alone but is confirmed by the varlink client tests.

6. **Integration test helpers.sh scope**: SPEC-302 is the first story requiring shell integration tests. If `helpers.sh` does not exist yet, it must be created as part of this story. Its API must be stable enough for subsequent integration test stories to reuse — but the spec only requires what 302 needs, so scope it to that.
