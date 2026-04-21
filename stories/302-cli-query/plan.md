# Plan: SPEC-302 — CLI Query Command

## Status: FULLY IMPLEMENTED

All production code, unit tests, and integration test scripts for SPEC-302 are already complete. **No code changes are needed.** The implement phase should verify the existing implementation compiles, passes tests, and passes clippy — then report completion.

## Approach

The `netfyr query` command is fully implemented in `crates/netfyr-cli/src/query.rs` (826 lines including 493 lines of unit tests). The design uses a two-mode architecture matching the `apply` command: daemon detection via socket connection attempt, with fallback to direct kernel queries via netlink.

The key architectural choice is treating `type` as a special selector key that gets extracted before the backend query (since the backend registry dispatches by entity type), while all other selector keys (`name`, `driver`, `mac`, `pci_path`) are passed through to the backend's native selector matching. In daemon-free mode, when no `type` selector is specified, the code iterates all `supported_entities()` from the registry and queries each type individually — this delegates selector matching to the backend rather than doing a post-filter, which is important because fields like `driver` and `mac` require sysfs reads that only the backend can perform.

Output formatting converts `State` objects to flat `IndexMap<String, serde_json::Value>` maps with `"type"` as the first key, then serializes via `serde_yaml::to_string` (YAML) or `serde_json::to_string_pretty` (JSON). This flat-map approach strips the internal `FieldValue` wrapper (which contains provenance metadata) so the output is clean for human and programmatic consumption.

## Design Decisions

### 1. `type` as a pseudo-selector key (not a positional argument)
- **Decision**: `type=ethernet` is passed via `--selector` like any other filter, then extracted by `extract_type_and_selector` before the backend query.
- **Alternatives considered**: A positional `[entity_type]` argument or a separate `--type` flag.
- **Rationale**: The spec explicitly requires `--selector` for all filtering including entity type, keeping the CLI uniform. This matches the user's mental model: `type` is just another filter dimension.

### 2. Per-entity-type iteration in daemon-free mode (no post-filter)
- **Decision**: When no `type` selector is given, `run_query_local` iterates `registry.supported_entities()` and calls `registry.query(&et, selector)` for each type.
- **Alternatives considered**: Call `registry.query_all()` then post-filter by selector fields.
- **Rationale**: The `Selector` struct stored on `State` only carries `name` — fields like `driver`, `mac`, and `pci_path` are not stored on the returned `State` objects. Only the backend can evaluate these fields (via sysfs reads during the query). Post-filtering would silently ignore driver/mac/pci_path selectors.

### 3. Selector key validation at clap parse time
- **Decision**: `parse_selector` validates keys against `VALID_SELECTOR_KEYS` before the async runtime starts.
- **Alternatives considered**: Defer validation to `extract_type_and_selector`.
- **Rationale**: Early validation produces better error messages (clap-style) and fails fast. Value validation (e.g., MAC address format) is still deferred to `extract_type_and_selector` since it requires more context.

### 4. `BackendError::NotFound` treated as empty result (exit 0)
- **Decision**: When the backend returns `NotFound`, the code returns an empty list with exit code 0.
- **Alternatives considered**: Treating it as an error (exit 2).
- **Rationale**: The spec says "No matching entities returns empty result" with exit 0. `NotFound` from the backend means no entity matched the selector, which is the expected "no match" case.

### 5. `VarlinkError::ConnectionFailed` triggers daemon-free fallback; other errors propagate
- **Decision**: Only `ConnectionFailed` causes fallback to daemon-free mode. Other Varlink errors (protocol errors, unexpected disconnects) are fatal.
- **Alternatives considered**: Falling back for any connection error.
- **Rationale**: `ConnectionFailed` means the daemon isn't running (socket doesn't exist or connection refused). Other errors mean the daemon is running but something went wrong — silently falling back would mask real problems.

### 6. Flat map output format (not nested)
- **Decision**: Each entity is serialized as a flat map with `type`, `name`, `mtu`, etc. all at the top level.
- **Alternatives considered**: Nesting fields under a `config` or `fields` key, or grouping by entity type.
- **Rationale**: The spec's output examples show flat structure. This is simpler for `jq`/`yq` consumption (e.g., `jq '.[].mtu'` works directly).

## File Changes

### 1. `crates/netfyr-cli/src/query.rs`
- **Action**: No changes needed (already complete)
- **What**: Contains `OutputFormat` enum, `QueryArgs` struct, `run_query` entry point, `parse_selector` clap value parser, `extract_type_and_selector`, `run_query_local`, `run_query_daemon`, `build_varlink_selector`, `state_to_flat_map`, `varlink_state_to_flat_map`, `print_output`, and 27 unit tests.
- **Why**: Implements the full query command per SPEC-302.

### 2. `crates/netfyr-cli/src/lib.rs`
- **Action**: No changes needed (already complete)
- **What**: Declares `pub mod query`, exports `pub use query::run_query`, registers `Commands::Query(query::QueryArgs)` in the clap subcommand enum.
- **Why**: Wires the query module into the CLI framework.

### 3. `crates/netfyr-cli/src/netfyr_cli_main.rs`
- **Action**: No changes needed (already complete)
- **What**: Dispatches `Commands::Query(args)` to `run_query(args).await`, wrapping errors with exit code 2.
- **Why**: Main binary entry point for the query subcommand.

### 4. `tests/302-query-veth-by-name.sh`
- **Action**: No changes needed (already complete)
- **What**: Creates veth pair `veth-test0`/`veth-test1` in an unprivileged namespace, sets MTU 1400 and address `10.99.0.1/24` on `veth-test0`, runs `netfyr query -s name=veth-test0 -o json`, asserts name, MTU, and address in output.
- **Why**: Maps to spec scenario "Query veth interface in namespace".

### 5. `tests/302-query-all.sh`
- **Action**: No changes needed (already complete)
- **What**: Creates veth pair `veth-a`/`veth-b`, runs `netfyr query -o json` with no selectors, asserts both ends appear.
- **Why**: Maps to spec scenario "Query all interfaces in namespace returns both veth ends".

### 6. `tests/302-query-yaml.sh`
- **Action**: No changes needed (already complete)
- **What**: Creates veth pair `veth-test0`/`veth-test1`, sets MTU 1400, runs `netfyr query -s name=veth-test0` (default YAML), asserts `mtu: 1400` and `veth-test0` in output.
- **Why**: Maps to spec scenario "Query with YAML output in namespace".

## Dependencies

No new dependencies needed. All required crates are already in `crates/netfyr-cli/Cargo.toml`:
- `clap` (CLI parsing, `Args` derive, `ValueEnum`)
- `serde_yaml` (YAML output)
- `serde_json` (JSON output, `Value` for flat maps)
- `anyhow` (error handling)
- `indexmap` (ordered maps for deterministic output)
- `netfyr-backend` (kernel queries via `BackendRegistry`, `NetlinkBackend`)
- `netfyr-varlink` (daemon queries via `VarlinkClient`)
- `netfyr-state` (`Selector`, `State`, `MacAddr`, `Value`)

## Implementation Order

Since all code is already complete, the implement phase should:

1. **Verify compilation**: Run `cargo build` to confirm the project compiles without errors.
2. **Run unit tests**: Run `cargo test -p netfyr-cli` to confirm all 27 query unit tests pass.
3. **Run clippy**: Run `cargo clippy -p netfyr-cli` to confirm no lint warnings.
4. **Run integration tests**: Run `make integration-test SPEC=302` to confirm all three shell scripts pass end-to-end.

If any step fails, investigate and fix the issue. Based on the code review, no failures are expected.

## Risks and Mitigations

### 1. `unshare --user --net` unavailable in CI
- **Risk**: Containers or kernels with `kernel.unprivileged_userns_clone=0` will fail to create the namespace.
- **Mitigation**: `netns_setup` in `helpers.sh` handles this and exits 1 if `unshare` fails. The spec's no-skip policy ensures failures are visible. This is an environment constraint, not a code issue.

### 2. Loopback interface in `302-query-all.sh` output
- **Risk**: Inside `unshare --net`, the `lo` interface exists but may or may not be returned by the ethernet backend.
- **Mitigation**: The test only asserts that `"veth-a"` and `"veth-b"` appear — it does not assert exact entity count.

### 3. serde serialization format assumptions
- **Risk**: If `serde_json` serialized `u64` differently (e.g., `1400.0`) or `serde_yaml` quoted integers, grep assertions would fail.
- **Mitigation**: `serde_json` serializes `u64` as bare integers. The identical grep patterns are used by existing `102-*.sh` tests that already pass, confirming the format.

### 4. Address format in output
- **Risk**: The address `10.99.0.1/24` might appear without prefix length.
- **Mitigation**: The backend stores addresses as `Value::IpNetwork`, which serializes as `"addr/prefix"`. Existing `102-query-veth-by-name.sh` uses the same assertion pattern and passes.

### 5. Daemon-mode type filtering depends on SPEC-404
- **Risk**: When daemon mode is active, `entity_type` from `--selector type=X` is sent as `VarlinkSelector.entity_type`. If the daemon doesn't filter by entity type, the selector is silently ignored.
- **Mitigation**: This is a SPEC-404 dependency documented in the spec. The CLI correctly sends the filter; the daemon is responsible for honoring it.

## Test Strategy

All testing is already complete:

### Unit tests (27 tests in `query.rs`)
- `parse_selector`: invalid key error lists valid keys, missing `=` rejected, all valid keys accepted, empty value accepted
- `extract_type_and_selector`: empty input → (None, None), type-only → entity type extracted, name-only → Selector built, combined type+name → correctly split, driver/mac/pci_path → Selector fields set, invalid MAC → error
- `build_varlink_selector`: both None → None (query-all), entity_type only → set, selector only → set, combined → merged, mac serialized to string, pci_path forwarded
- `state_to_flat_map`: type is first key, type value correct, all fields at top level, no provenance, empty fields → only type
- `varlink_state_to_flat_map`: type first, type value correct, all fields at top level, empty fields → only type
- `daemon_socket_path`: default path, env var override
- Serialization: YAML produces valid sequence, JSON produces valid array, empty input → empty sequence/array, JSON is pretty-printed and jq-compatible

### Integration tests (3 shell scripts in `tests/302-*.sh`)
| Script | Scenario | Key Assertions |
|--------|----------|----------------|
| `302-query-veth-by-name.sh` | Query by name, JSON output | Name present, MTU=1400, address `10.99.0.1/24` |
| `302-query-all.sh` | Query all, JSON output | Both `veth-a` and `veth-b` present |
| `302-query-yaml.sh` | Query by name, YAML output | `mtu: 1400`, name present |

### Verification command
```bash
cargo build && cargo test -p netfyr-cli && cargo clippy -p netfyr-cli && make integration-test SPEC=302
```
