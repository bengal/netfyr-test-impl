# Understand: SPEC-600 — End-to-End Integration Tests

## Current State

### Test infrastructure
`tests/helpers.sh` (232 lines) — fully implemented shared library providing:
- `netns_setup` — unprivileged user+network namespace re-exec guard
- `create_veth`, `add_address`, `start_dnsmasq`, `cleanup` (kills all dnsmasq PIDs)
- `wait_for_address` — polls until address appears on interface
- Assertion functions: `assert_eq`, `assert_match`, `assert_has_address`, `assert_not_has_address`, `assert_mtu`, `assert_link_up`, `assert_address_count`, `assert_json_address_order`

Note: `helpers.sh` has no `kill_dnsmasq` function. The spec template refers to it, but the actual convention is `cleanup` (which kills all dnsmasq instances started via `start_dnsmasq`). Existing DHCP tests call `cleanup` in their EXIT traps.

`Makefile` — `integration-test` target discovers tests via `tests/[0-9]*.sh` glob. No changes needed.

### Existing 600-series test scripts (26 of 27 required)
All 26 are fully implemented (82–167 lines each):

| File | Status |
|---|---|
| `tests/600-e2e-static-apply.sh` | ✓ exists |
| `tests/600-e2e-dhcp-and-static.sh` | ✓ exists |
| `tests/600-e2e-replace-all.sh` | ✓ exists |
| `tests/600-e2e-daemon-restart.sh` | ✓ exists |
| `tests/600-e2e-conflict.sh` | ✓ exists |
| `tests/600-e2e-dry-run.sh` | ✓ exists |
| `tests/600-e2e-apply-directory.sh` | ✓ exists |
| `tests/600-e2e-addr-single.sh` | ✓ exists |
| `tests/600-e2e-addr-five.sh` | ✓ exists |
| `tests/600-e2e-addr-twenty.sh` | ✓ exists |
| `tests/600-e2e-addr-replace.sh` | ✓ exists |
| `tests/600-e2e-addr-idempotent.sh` | ✓ exists |
| `tests/600-e2e-addr-duplicate-reject.sh` | ✓ exists |
| `tests/600-e2e-addr-overlapping-subnets.sh` | ✓ exists |
| `tests/600-e2e-addr-removal.sh` | ✓ exists |
| `tests/600-e2e-journal-apply.sh` | ✓ exists |
| `tests/600-e2e-journal-seq.sh` | ✓ exists |
| `tests/600-e2e-history-list.sh` | ✓ exists |
| `tests/600-e2e-history-show.sh` | ✓ exists |
| `tests/600-e2e-history-json.sh` | ✓ exists |
| `tests/600-e2e-history-filter.sh` | ✓ exists |
| `tests/600-e2e-revert.sh` | ✓ exists |
| `tests/600-e2e-revert-dry-run.sh` | ✓ exists |
| `tests/600-e2e-revert-noent.sh` | ✓ exists |
| `tests/600-e2e-revert-addr.sh` | ✓ exists |
| `tests/600-e2e-unmanaged.sh` | ✓ exists |
| **`tests/600-e2e-external-change.sh`** | **✗ MISSING** |

### Daemon env-var surface
The daemon honors `NETFYR_SOCKET_PATH`, `NETFYR_POLICY_DIR`, and `NETFYR_JOURNAL_DIR` env vars. All tests that need journal isolation pass `NETFYR_JOURNAL_DIR` pointing to a temp directory. `Journal::open_default()` in `crates/netfyr-journal/src/journal.rs` reads this env var, falling back to `/var/lib/netfyr/journal/`.

---

## Requirements

26 of 27 scenarios are already implemented. The single remaining requirement is:

**Scenario 26 — External change detection** (`600-e2e-external-change.sh`):

The test exercises three external-change phases in sequence:

1. **MTU change**: Start daemon, apply policy setting `mtu=1400` on `veth-e2e0`. Externally run `ip link set veth-e2e0 mtu 1500`. Sleep 1 s (debounce window). Assert latest journal entry has `trigger.type == "external_change"` and diff shows `mtu 1400→1500`. Assert `ip link show` still reports `mtu=1500` (no re-reconcile).

2. **Address additions**: Externally run `ip addr add 10.99.0.1/24 dev veth-e2e0` and `ip addr add 10.99.0.2/24 dev veth-e2e0`. Sleep 1 s. Assert new `external_change` journal entry with address-addition diff. Assert both addresses are present.

3. **Address removal**: Externally run `ip addr del 10.99.0.1/24 dev veth-e2e0`. Sleep 1 s. Assert new `external_change` journal entry with address-removal diff. Assert only `10.99.0.2/24` remains.

4. **No re-reconcile**: Throughout all phases, verify the daemon never re-applied `mtu=1400`.

The script requires `jq` (same pattern as `600-e2e-revert.sh`). No DHCP needed. No `kill_dnsmasq`.

---

## Gap Analysis

### Files to create
- **`tests/600-e2e-external-change.sh`** — the only missing file. Approximately 160–200 lines following the established pattern: binary checks, `jq` check, `netns_setup`, temp dirs with `JOURNAL_DIR`, single veth pair, daemon start with socket poll and `NETFYR_JOURNAL_DIR` set, three sequential external-change phases each followed by a `sleep 1` and journal assertions, final no-re-apply check.

### Files to modify
None. No Rust code, no helpers.sh changes, no Makefile changes are required.

---

## Integration Points

| Component | How the new test interacts |
|---|---|
| `target/debug/netfyr-daemon` | Started with `NETFYR_SOCKET_PATH`, `NETFYR_POLICY_DIR`, `NETFYR_JOURNAL_DIR`; must implement `NetlinkMonitor`-based external-change detection (SPEC-353) writing `trigger.type = "external_change"` journal entries |
| `target/debug/netfyr apply` | Used to establish initial managed state (mtu=1400) before external changes |
| `tests/helpers.sh` — `create_veth`, `cleanup` | Used for veth pair setup and EXIT trap |
| `Journal::open_default()` | Creates `current.ndjson` in `NETFYR_JOURNAL_DIR`; assertions parse this file with `jq` |
| `tests/[0-9]*.sh` glob | New script auto-discovered by `make integration-test`; no Makefile changes needed |

---

## Risks

1. **Debounce timing**: The spec uses `sleep 1` between external changes and journal assertions. If the daemon's netlink debounce window is longer than 1 second, assertions will fail because the journal entry has not yet been written. The sleep duration must match or exceed the actual debounce interval.

2. **Address vs. link events**: The `NetlinkMonitor` must watch both link-level events (MTU) and address-level events (add/del). If it only monitors link events, phases 2 and 3 will not produce journal entries and the test will fail. This is a dependency on SPEC-353's implementation scope.

3. **Batched journal entries**: Multiple external changes in rapid succession (e.g., two `ip addr add` commands) may be coalesced into a single journal entry by the debounce logic. The test should count cumulative journal entries across phases (not require exactly one new entry per individual `ip` command) or insert a deliberate pause between each command.

4. **No-re-apply assertion is a negative**: Verifying "daemon did not re-apply mtu=1400" is expressed as a positive check that `ip link show veth-e2e0` still reports `mtu=1500` after each phase. This is correct behavior to assert but does not catch cases where re-application happened and then the daemon reverted itself.

5. **jq availability**: The script must check `command -v jq` at startup and `exit 1` with a clear FAIL message, consistent with `600-e2e-revert.sh` line 26–29.

6. **`kill_dnsmasq` spec artifact**: The spec template mentions `kill_dnsmasq` in EXIT traps. The new script does not involve DHCP, so this is irrelevant. The EXIT trap should follow the non-DHCP pattern: `kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"` (no `cleanup` needed since no dnsmasq is started).
