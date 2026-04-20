# Plan: SPEC-302 — CLI Query Command

## Approach

All Rust production code for `netfyr query` is already complete and fully wired into the CLI binary. The `crates/netfyr-cli/src/query.rs` module implements daemon detection (via `NETFYR_SOCKET_PATH` env var), selector parsing with key validation, daemon-free mode (netlink via `BackendRegistry`), daemon mode (Varlink via `VarlinkClient`), and YAML/JSON output formatting. The `Commands::Query` variant is registered in `lib.rs`, and `main.rs` dispatches to `run_query`. Fourteen unit tests in `query.rs` cover parsing, selector extraction, varlink selector building, flat-map conversion, and serialization edge cases.

The remaining work is exclusively **three shell integration test scripts** in `tests/302-*.sh`. The test infrastructure (`tests/helpers.sh`) already exists and provides `netns_setup`, `create_veth`, `add_address`, `cleanup`, `assert_eq`, and `assert_match`. No modifications to `helpers.sh` or any Rust source files are needed.

The design follows the established pattern from the existing `102-query-*.sh` tests exactly: enter an unprivileged network namespace via `netns_setup`, create veth pairs, configure MTU and addresses via `ip` commands, invoke `netfyr query` with the appropriate flags, and verify output with `grep` assertions. Each test script is self-contained and runs in its own namespace.

**Why no Rust changes**: The understanding analysis confirmed every function in `query.rs` matches the spec. The `run_query` function handles daemon detection, `extract_type_and_selector` splits `type=` from other selector keys, `run_query_local` iterates `supported_entities()` with per-entity-type queries (delegating selector matching to the backend), `run_query_daemon` routes through `VarlinkClient`, and `print_output` serializes via `serde_yaml`/`serde_json`. Error paths produce the correct exit codes: invalid key → clap error (exit 2), invalid type → stderr message + exit 2, no match → empty list + exit 0.

## Design Decisions

### 1. Three separate scripts (one per spec scenario)
- **Decision**: Create `302-query-veth-by-name.sh`, `302-query-all.sh`, and `302-query-yaml.sh` as independent scripts.
- **Alternatives considered**: One monolithic `302-cli-query.sh` testing all three scenarios in sequence.
- **Rationale**: The existing test convention uses one script per scenario (see `102-query-veth-by-name.sh`, `102-query-all-veth-pair.sh`, `102-query-routes.sh`). This gives clearer pass/fail reporting and avoids cascading failures. The Makefile's `SPEC=302` glob collects all of them.

### 2. Use `grep` for assertions (not `jq`)
- **Decision**: Use `grep` for JSON and YAML field assertions.
- **Alternatives considered**: Pipe through `jq` for structured JSON validation.
- **Rationale**: All existing 102 tests use `grep` and never depend on `jq`. The spec's no-skip rule means adding `jq` as a prerequisite would require failing if it's missing, which is unnecessarily restrictive. Simple `grep` checks for field presence and values are sufficient — structural JSON/YAML validity is already proven by the unit tests.

### 3. Omit type selector in `302-query-all.sh`
- **Decision**: Run `netfyr query -o json` without `--selector type=ethernet`.
- **Alternatives considered**: Include `--selector type=ethernet` as in the 102 tests.
- **Rationale**: The spec scenario says "Query all interfaces" — the point is to exercise the no-type-filter codepath where `run_query_local` iterates all `supported_entities()`. This differentiates the test from the existing `102-query-all-veth-pair.sh` (which uses `--selector type=ethernet`).

### 4. Omit type selector in `302-query-yaml.sh`
- **Decision**: Run `netfyr query -s name=veth-test0` without `-o` flag and without `type=`.
- **Alternatives considered**: Add `--selector type=ethernet`.
- **Rationale**: The spec scenario says `netfyr query -s name=veth-test0` — testing default YAML output. Omitting the type selector also exercises the all-entity-types iteration path with a name filter.

### 5. No modifications to helpers.sh
- **Decision**: Use existing helpers as-is.
- **Alternatives considered**: Add new assertion helpers (e.g., `assert_json_contains`).
- **Rationale**: The existing `grep`-based assertion pattern used by all 102 tests is sufficient. The helpers already provide `netns_setup`, `create_veth`, `add_address`, and `assert_eq`. Adding helpers for this story would be premature — if a future story needs structured JSON assertions, that's the time to add them.

### 6. No Rust code changes
- **Decision**: Zero modifications to any `.rs` file or `Cargo.toml`.
- **Alternatives considered**: N/A.
- **Rationale**: The understanding analysis confirmed all production code and unit tests are complete and match the spec. The integration tests provide the missing end-to-end coverage.

## File Changes

### 1. `tests/302-query-veth-by-name.sh`
- **Action**: Create
- **What**: Shell integration test. Boilerplate: `set -euo pipefail`, sources `helpers.sh`, locates binary via `NETFYR_BIN` with fallback to `$SCRIPT_DIR/../target/debug/netfyr`, checks binary exists with `[[ ! -x ]]` → `exit 1`, calls `netns_setup "$@"`. Inside namespace: calls `create_veth veth-test0 veth-test1`, runs `ip link set dev veth-test0 mtu 1400`, runs `add_address veth-test0 10.99.0.1/24`. Captures output of `$NETFYR_BIN query -s name=veth-test0 -o json`. Asserts via `grep`: output contains `"veth-test0"`, contains `"mtu": 1400`, contains `10.99.0.1/24`. Prints `PASS: 302-query-veth-by-name`.
- **Why**: Maps to spec acceptance scenario "Query veth interface in namespace". Tests the full daemon-free pipeline: binary → clap → selector parsing → netlink backend → JSON serialization. Verifies name filtering, MTU, and address values.

### 2. `tests/302-query-all.sh`
- **Action**: Create
- **What**: Shell integration test. Same boilerplate. Creates veth pair `veth-a`/`veth-b` via `create_veth`. Runs `$NETFYR_BIN query -o json` (no selector at all). Asserts: output contains `"veth-a"` and `"veth-b"`. Prints `PASS: 302-query-all`.
- **Why**: Maps to spec acceptance scenario "Query all interfaces in namespace returns both veth ends". Exercises the `query_all` codepath where `run_query_local` iterates all supported entity types without any filter.

### 3. `tests/302-query-yaml.sh`
- **Action**: Create
- **What**: Shell integration test. Same boilerplate. Creates veth pair `veth-test0`/`veth-test1`. Runs `ip link set dev veth-test0 mtu 1400`. Runs `$NETFYR_BIN query -s name=veth-test0` (default YAML output, no `-o` flag). Asserts: exit code 0; output contains `mtu: 1400` (YAML format); output contains `veth-test0`. Prints `PASS: 302-query-yaml`.
- **Why**: Maps to spec acceptance scenario "Query with YAML output in namespace". Tests the default output format path (`serde_yaml::to_string`) and verifies field values appear in human-readable YAML.

## Dependencies

No new dependencies. The integration tests are pure shell scripts using:
- `bash` — test runner
- `unshare` from util-linux — namespace creation (via `netns_setup`)
- `ip` from iproute2 — veth creation, MTU/address configuration
- `grep` — output assertions

All are already required by the existing `102-*.sh` and `301-*.sh` test scripts.

## Implementation Order

1. **Create `tests/302-query-veth-by-name.sh`** — The most comprehensive test; validates name selector, MTU, and address in JSON. No dependencies on other new files.

2. **Create `tests/302-query-all.sh`** — Tests the unfiltered query path. Independent of step 1.

3. **Create `tests/302-query-yaml.sh`** — Tests default YAML output. Independent of steps 1 and 2.

Steps 1-3 are independent and can be implemented in any order or in parallel. Each script follows the identical boilerplate pattern from the existing `102-query-veth-by-name.sh`.

4. **Verify** — Run `cargo build && make integration-test SPEC=302`. Also run `cargo test -p netfyr-cli` and `cargo clippy` to confirm nothing regressed. All three scripts must pass.

## Risks and Mitigations

### 1. `unshare --user --net --map-root-user` unavailable in CI
- **Risk**: Containers or kernels with `kernel.unprivileged_userns_clone=0` will fail to create the namespace.
- **Mitigation**: `netns_setup` in `helpers.sh` checks for `unshare` and exits 1 if missing. The spec's no-skip policy ensures failures are visible. This is an environment constraint, not a code issue.

### 2. Loopback interface appearing in `302-query-all.sh` output
- **Risk**: Inside `unshare --net`, the `lo` interface exists but may or may not be returned by the ethernet backend query. If the backend classifies `lo` differently, the test could see unexpected entity counts.
- **Mitigation**: The test only asserts that `"veth-a"` and `"veth-b"` appear — it does not assert an exact count. Extra interfaces (lo or otherwise) don't cause failure.

### 3. MTU format in JSON/YAML output
- **Risk**: If `serde_json` serializes `u64` as `1400.0` or `"1400"`, the `grep '"mtu": 1400'` assertion would fail.
- **Mitigation**: `serde_json` serializes `u64` as bare integers (e.g., `1400`). The existing `102-query-veth-by-name.sh` uses the identical `'"mtu": 1400'` pattern and passes, confirming this format.

### 4. YAML scalar format for MTU
- **Risk**: `serde_yaml` might quote the integer (`mtu: "1400"`) or use a different representation.
- **Mitigation**: `serde_yaml::to_string` serializes `serde_json::Value::Number(1400)` as the bare integer `1400`. The grep pattern `'mtu: 1400'` is a substring match, tolerant of surrounding whitespace.

### 5. Address format in output
- **Risk**: The address `10.99.0.1/24` might appear differently (e.g., without prefix length).
- **Mitigation**: The backend stores addresses as `Value::IpNetwork`, which serializes as `"addr/prefix"`. The existing `102-query-veth-by-name.sh` asserts `'10.99.0.1/24'` and passes.

## Test Strategy

All new testing for this story is **shell integration tests**. No additional Rust unit tests are needed.

### Integration tests to create

| Script | Scenario | Key Assertions |
|--------|----------|----------------|
| `302-query-veth-by-name.sh` | Query specific interface by name, JSON output | Name present, MTU=1400, address `10.99.0.1/24` |
| `302-query-all.sh` | Query all interfaces, JSON output | Both `veth-a` and `veth-b` present |
| `302-query-yaml.sh` | Query by name, default YAML output | `mtu: 1400` in YAML format, name present |

### What each test validates
- **Binary existence**: Every script checks `[[ ! -x "$NETFYR_BIN" ]]` and exits 1 if missing.
- **Exit codes**: All scripts implicitly assert exit 0 (due to `set -e` from helpers.sh; a non-zero exit would abort the script before reaching PASS).
- **Output format**: JSON tests verify field names/values with `grep`; YAML test verifies YAML-formatted field values.
- **Selector filtering**: By-name test confirms only the requested interface appears; all-query test confirms no filtering occurs.
- **Field values**: MTU, address, and interface name are verified against known configuration set up via `ip` commands.

### Behaviors already covered by existing unit tests (no integration test needed)
- Invalid selector key → error with valid keys list, exit 2
- Invalid MAC address → error, exit 2
- Empty result serialization → `[]` (JSON) or empty YAML sequence
- Daemon mode routing (covered by SPEC-403/404 integration tests)
- Provenance stripping from output
- `build_varlink_selector` correctness

### Verification command
```bash
cargo build && make integration-test SPEC=302
```
