# Plan: SPEC-103 — rtnetlink Apply for Ethernet Interfaces

## Approach

All Rust implementation is complete: `apply_ethernet`, `dry_run_ethernet`, the `NetworkBackend` trait impl, report types, and Rust integration tests (`crates/netfyr-backend/tests/netlink_apply.rs`) are fully written and cover every acceptance criterion. The only remaining work is creating four shell integration test scripts in `tests/`.

The shell scripts exercise the **full CLI pipeline end-to-end**: YAML policy file → `load_policy_file` (auto-wraps bare states into static policies) → `StaticFactory::produce` → `merge` → `compute_state_diff` → `registry.apply` → netlink kernel calls. This is a different testing layer than the Rust integration tests, which call `apply_ethernet` directly with hand-built `StateDiff` objects. The shell scripts verify that policy parsing, diff generation, and CLI reporting all compose correctly.

Each script runs inside `unshare --user --net --map-root-user` (unprivileged network namespace), creates veth pairs as synthetic ethernet interfaces, writes a temporary YAML policy file, invokes `$NETFYR_BIN apply`, and asserts kernel state via `ip` commands. The daemon socket path is forced to a non-existent path to guarantee daemon-free mode.

The **bare state YAML format** (no `kind:` field) is used for all test policies. When `load_policy_file` encounters a document without `kind: policy`, it auto-wraps it as a static policy with priority 100 and a name derived from the filename. This is the simplest format: `type: ethernet\nname: veth-test0\nmtu: 1400\n` becomes a complete policy. I verified this behavior by reading `crates/netfyr-policy/src/lib.rs:560-588` where the `None | Some("state")` match arm performs the wrapping.

An alternative was to use the explicit `kind: policy` format with `factory: static` and `state:` block, but the bare format is shorter, less error-prone, and exercises a realistic user workflow. Both paths are extensively tested in Rust unit tests.

## Design Decisions

1. **Decision**: Use bare state YAML format (no `kind: policy` wrapper) for all test policies.
   - **Alternatives considered**: Explicit `kind: policy` format with `factory: static` and `state:` block.
   - **Rationale**: Bare state is shorter, less error-prone, and exercises the auto-wrapping path in `load_policy_file`. The existing 401-DHCP tests use explicit `kind: policy` for `factory: dhcpv4`, but for static ethernet policies, bare state is idiomatic and tests the common user workflow.

2. **Decision**: Force daemon-free mode by setting `export NETFYR_SOCKET_PATH=/nonexistent` in each script.
   - **Alternatives considered**: Rely on the default socket not existing; add a `--no-daemon` CLI flag (does not exist).
   - **Rationale**: If a daemon happens to be running on the host, the CLI would connect to it via Unix socket (which passes through the user-net namespace since no mount namespace is used). Setting an invalid path guarantees `VarlinkError::ConnectionFailed` → daemon-free fallback, making the test deterministic. The `daemon_socket_path()` function at `crates/netfyr-cli/src/apply.rs:36-39` reads `NETFYR_SOCKET_PATH` first.

3. **Decision**: Use MTU 1400 (not 9000) for MTU tests.
   - **Alternatives considered**: MTU 9000 (jumbo frames) as mentioned in the spec's acceptance criteria.
   - **Rationale**: veth interfaces in unprivileged namespaces support MTU values below the default 1500 universally. Values above 1500 may fail in some kernel/namespace configurations. MTU 1400 is safe, below default, and produces a visible change.

4. **Decision**: For address removal test, apply a second bare-state policy with no `addresses` field (not `addresses: []`).
   - **Alternatives considered**: Use `addresses: []` (explicit empty list); use `addresses` field removal via `removed_fields`.
   - **Rationale**: The spec scenario says "a second policy without the address is applied". When the desired state from the second policy has no `addresses` field, the diff engine (`crates/netfyr-state/src/diff.rs:146-149`) puts `addresses` into `removed_fields`. The apply engine (`crates/netfyr-backend/src/netlink/apply.rs:545-547`) checks `addr_in_removed` and sets `desired_addrs = vec![]`, which triggers removal of all current addresses. This exercises the `removed_fields` code path — the more realistic scenario where a user removes a field from their policy file. Other fields from the actual state (mtu, mac, carrier, speed, driver, operstate) also go into `removed_fields` but are handled safely: read-only fields get skipped, and mtu/operstate are only processed from `changed_fields` (not `removed_fields`).

5. **Decision**: Use `grep -q` with partial string matching for `ip` command output assertions.
   - **Alternatives considered**: Exact string comparison with `assert_eq`.
   - **Rationale**: `ip link show` and `ip route` output formats vary across kernel versions (different ordering, annotations like `proto kernel scope link`). Partial matching with `grep -q` is robust and follows the pattern in existing 102-series tests.

6. **Decision**: Four separate scripts, one per spec Gherkin scenario.
   - **Alternatives considered**: One combined script; two scripts (apply and round-trip).
   - **Rationale**: The Makefile discovers tests via `tests/[0-9]*.sh` and runs each independently. Separate scripts provide better error isolation — one failure doesn't block others. This matches the 102-series pattern (five separate scripts for five query scenarios).

7. **Decision**: Route test pre-configures the interface address with `add_address` helper before calling `netfyr apply`, AND includes the address in the policy.
   - **Alternatives considered**: Rely solely on `netfyr apply` to add the address first; use two sequential apply calls.
   - **Rationale**: The `add_address` helper ensures the address is present before the apply call, as a safety net. The policy also includes `addresses: ["10.99.0.1/24"]` so the diff engine won't try to remove the address (which would break gateway reachability for the route). The apply engine's idempotent address handling means the pre-existing address is silently skipped. This is more robust than relying on ordering within a single apply (though the spec guarantees addresses are applied before routes).

8. **Decision**: The round-trip test uses `--output json` for query verification, matching the 102-series pattern.
   - **Alternatives considered**: YAML output; default human-readable format.
   - **Rationale**: JSON is machine-parseable and `grep`-friendly. The 102-series tests already validate JSON output format, establishing the pattern. Checking for `"mtu": 1400` in JSON output is unambiguous.

## File Changes

### `tests/103-apply-set-mtu.sh`
- **Action**: Create
- **What**: Shell script that tests setting MTU on a veth interface via `netfyr apply`.
  - Preamble: set `SCRIPT_DIR`, source `helpers.sh`, set `NETFYR_BIN` with fallback, check binary exists, export `NETFYR_SOCKET_PATH=/nonexistent`, call `netns_setup "$@"`
  - Body: `create_veth veth-test0 veth-test1`, write bare state YAML to temp file (`type: ethernet`, `name: veth-test0`, `mtu: 1400`), run `$NETFYR_BIN apply $POLICY_FILE`, check exit code 0, assert `ip link show veth-test0` contains `mtu 1400`
  - Success: emit `PASS: 103-apply-set-mtu`
- **Why**: Covers spec shell Gherkin scenario "Set MTU on a veth interface in namespace". Validates the simplest end-to-end apply path.

### `tests/103-apply-add-remove-address.sh`
- **Action**: Create
- **What**: Shell script that tests adding then removing an IP address across two apply calls.
  - Preamble: same as above
  - Phase 1: `create_veth veth-test0 veth-test1`, write bare state with `addresses: ["10.99.0.1/24"]` to temp file, apply, assert `ip addr show veth-test0` contains `10.99.0.1/24`
  - Phase 2: write bare state with only `type` and `name` (no addresses field) to a DIFFERENT temp file, apply, assert `ip addr show veth-test0` does NOT contain `10.99.0.1/24`
  - Success: emit `PASS: 103-apply-add-remove-address`
- **Why**: Covers spec shell Gherkin scenario "Add and remove IP addresses in namespace". Tests address addition via `changed_fields` and address removal via `removed_fields`.

### `tests/103-apply-add-route.sh`
- **Action**: Create
- **What**: Shell script that tests adding a static route via `netfyr apply`.
  - Preamble: same as above
  - Body: `create_veth veth-test0 veth-test1`, `add_address veth-test0 10.99.0.1/24` (pre-configure for gateway reachability), write bare state with `addresses: ["10.99.0.1/24"]` and `routes: [{destination: "10.100.0.0/24", gateway: "10.99.0.2"}]`, apply, assert `ip route` contains `10.100.0.0/24 via 10.99.0.2`
  - Success: emit `PASS: 103-apply-add-route`
- **Why**: Covers spec shell Gherkin scenario "Add a route in namespace". The pre-configured address ensures gateway 10.99.0.2 is reachable via the connected /24 subnet, and including the address in the policy prevents the diff from generating an address removal.

### `tests/103-apply-query-roundtrip.sh`
- **Action**: Create
- **What**: Shell script that applies a policy and verifies the result via `netfyr query`.
  - Preamble: same as above
  - Body: `create_veth veth-test0 veth-test1`, write bare state with `mtu: 1400` and `addresses: ["10.99.0.1/24"]`, apply, then run `$NETFYR_BIN query --selector type=ethernet --selector name=veth-test0 --output json`, assert output contains `"mtu": 1400`, assert output contains `10.99.0.1/24`
  - Success: emit `PASS: 103-apply-query-roundtrip`
- **Why**: Covers spec shell Gherkin scenario "Full round-trip: apply then query". Verifies that applied changes are reflected in the query layer's output.

## Dependencies

No new crate dependencies are needed. The shell scripts use only system tools (`bash`, `ip`, `grep`, `unshare`, `mktemp`) and the pre-built `netfyr` binary.

## Implementation Order

1. **Create `tests/103-apply-set-mtu.sh`** — Simplest test. Validates that the CLI apply pipeline works end-to-end (policy parsing → diff → apply → kernel). If this doesn't work, nothing else will. Run `make integration-test SPEC=103` to verify.

2. **Create `tests/103-apply-add-remove-address.sh`** — Adds address management. Exercises two applies in sequence and the `removed_fields` diff path for field deletion. Independent from step 3-4.

3. **Create `tests/103-apply-add-route.sh`** — Adds route management. More complex setup (pre-existing address for gateway reachability). Independent from step 2.

4. **Create `tests/103-apply-query-roundtrip.sh`** — Combines apply + query CLI paths. Exercises JSON output format. Independent from steps 2-3.

Steps 2-4 can be implemented in parallel since they are independent. Each step should be verified with `make integration-test SPEC=103`.

## Risks and Mitigations

### R1: Bare state policy triggering excessive field removals
**Risk**: A bare state policy with only `mtu: 1400` produces a desired state missing all other fields. The diff engine puts ALL actual-state fields not in desired into `removed_fields`, which could trigger unintended side effects.
**Mitigation**: Verified by reading the apply code that only `addresses` and `routes` are actionable from `removed_fields` (`crates/netfyr-backend/src/netlink/apply.rs:544-547` and `667-669`). Link-level fields (`mtu`, `operstate`) are only processed from `changed_fields` (lines 461-539). Read-only fields (`carrier`, `speed`, `mac`, `driver`, `name`) produce harmless skip entries (lines 448-457). For the route test, the policy includes the `addresses` field to prevent address removal during route application.

### R2: Route test gateway reachability
**Risk**: Adding a route with `gateway: 10.99.0.2` requires that 10.99.0.2 be reachable through the interface's connected subnet. If the address 10.99.0.1/24 is not on the interface when the route is added, the kernel rejects with ENETUNREACH.
**Mitigation**: Two safeguards: (1) The script pre-configures the address via `add_address` before calling `netfyr apply`. (2) The policy includes `addresses: ["10.99.0.1/24"]` so the diff engine sees the address as "desired" and doesn't remove it. The apply engine processes addresses (phase 2) before routes (phase 3), per `apply_modify_fields` at lines 459-782.

### R3: Daemon socket interference
**Risk**: If `/run/netfyr/netfyr.sock` exists (daemon running on host), and `unshare --user --net` doesn't create a mount namespace, the CLI connects to the daemon instead of using daemon-free mode.
**Mitigation**: All scripts set `export NETFYR_SOCKET_PATH=/nonexistent` to force `VarlinkError::ConnectionFailed` → daemon-free fallback.

### R4: `ip route` output format variability
**Risk**: `ip route` output format varies across kernel versions (e.g., `10.100.0.0/24 via 10.99.0.2 dev veth-test0 proto static` vs. `10.100.0.0/24 via 10.99.0.2 dev veth-test0`).
**Mitigation**: Use `grep -q "10.100.0.0/24 via 10.99.0.2"` which matches the prefix regardless of trailing annotations.

### R5: Connected route removal during address removal test
**Risk**: When the address is removed in the second phase of `103-apply-add-remove-address.sh`, the kernel auto-removes the connected route for 10.99.0.0/24. The apply engine also tries to remove routes (since `routes` is in `removed_fields` for the bare policy). If the connected route is already gone, a not-found error could occur.
**Mitigation**: The apply code at `crates/netfyr-backend/src/netlink/apply.rs:745-752` handles not-found routes as skips (`is_not_found_error(e)` → skip with "not present"). So already-removed routes are silently skipped, and the operation succeeds.

### R6: Second apply showing "No changes needed" instead of removing address
**Risk**: If the diff engine doesn't detect the absent `addresses` field as a removal, the second apply would output "No changes needed" and the address would persist.
**Mitigation**: Verified by reading `crates/netfyr-state/src/diff.rs:146-149`: fields in `from` (actual) absent in `to` (desired) are explicitly added to `removed_fields`. Then `crates/netfyr-backend/src/netlink/apply.rs:544-547`: `addr_in_removed` check triggers the removal path with `desired_addrs = vec![]`. The `compute_state_diff(actual, desired)` call at `crates/netfyr-cli/src/apply.rs:129` correctly passes actual as `from` and desired as `to`.

### R7: `netfyr apply` exit code for operations with only skipped entries
**Risk**: If an apply produces only skipped entries (e.g., read-only field changes) and no succeeded/failed, the exit code logic might not behave as expected.
**Mitigation**: `determine_exit_code` at `crates/netfyr-cli/src/apply.rs:278-286` returns `ExitCode::SUCCESS` when `!is_total_failure()` and `!is_partial()` and no conflicts. An empty `failed` list means `is_total_failure()` is false and `is_partial()` is false, so exit code is 0. For the MTU and address tests, the report always has at least one `succeeded` entry, so this edge case doesn't apply. But it's worth noting for awareness.

## Test Strategy

### Shell integration tests (the deliverable)

Four scripts matching the spec's shell-test Gherkin scenarios:

1. **103-apply-set-mtu.sh**: Verifies MTU change via `ip link show` after `netfyr apply`. Assertion: output contains `mtu 1400`.

2. **103-apply-add-remove-address.sh**: Two-phase test. Phase 1: apply policy with address, verify with `ip addr show` that `10.99.0.1/24` is present. Phase 2: apply policy without address field, verify with `ip addr show` that `10.99.0.1/24` is absent.

3. **103-apply-add-route.sh**: Verifies route addition via `ip route` after `netfyr apply` with pre-configured address. Assertion: output contains `10.100.0.0/24 via 10.99.0.2`.

4. **103-apply-query-roundtrip.sh**: Verifies `netfyr query --output json` reflects applied changes. Assertions: output contains `"mtu": 1400` and `10.99.0.1/24`.

### Script structure (common pattern from 102-series)

Each script follows this exact structure:
```bash
#!/bin/bash
# 103-<name>.sh
# <one-line description>

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

NETFYR_BIN="${NETFYR_BIN:-$SCRIPT_DIR/../target/debug/netfyr}"
if [[ ! -x "$NETFYR_BIN" ]]; then
    echo "FAIL: 103-<name>: netfyr binary not found at $NETFYR_BIN" >&2
    exit 1
fi

export NETFYR_SOCKET_PATH=/nonexistent

netns_setup "$@"

# ---------- Inside the namespace ----------
# test body...

echo "PASS: 103-<name>"
```

### What NOT to test in shell scripts (already covered by Rust integration tests)

- Read-only field skipping
- Idempotent add/remove edge cases
- Non-existent interface error reporting
- Partial failure across multiple operations
- Remove operation (deconfigure)
- Field ordering correctness
- Dry-run reporting
- Permission denied error mapping

### Verification command

```
make integration-test SPEC=103
```

All four scripts must emit `PASS: 103-*` and exit 0. The Makefile runs `cargo build` first, then each matching script via `bash`.
