# SPEC-354: State Revert — Gap Analysis

## Current State

The implementation is nearly complete. All primary code paths exist, are wired up, and have unit-test coverage. The prior gap analysis (recorded in this file) described a state that no longer exists — all the "missing" items have been implemented.

**`crates/netfyr-journal`**
- `Trigger::Revert { target_seq: SequenceId }` — `entry.rs:27`
- `JournalEntry.state_after: SerializableStateSet` — `entry.rs:16`
- `SerializableStateSet::to_state_set() -> Result<StateSet, String>` — `serializable.rs:50–91`
- `Journal::open_default()` reads `NETFYR_JOURNAL_DIR` env var — `journal.rs:46–49`
- Unit tests: round-trips (bool, u64, string, IpNetwork, list of networks), provenance, error on non-object — `serializable.rs:387–610`
- Unit tests: all `Trigger` variants including `Revert` serialize with correct discriminator — `entry.rs:139–205`

**`crates/netfyr-cli`**
- `RevertArgs { target: u64, dry_run: bool }` — `revert.rs:29–37`
- `run_revert()` — probes daemon socket, delegates to daemon or standalone path — `revert.rs:42–58`
- `run_revert_standalone()` — opens journal, reads entry, converts snapshot, queries backend, diffs, applies, records journal entry — `revert.rs:97–186`
- `run_revert_daemon()` — sends `io.netfyr.Revert` via Varlink, displays report, prints policy-drift warning to stderr — `revert.rs:63–93`
- `Commands::Revert` arm dispatched in `main.rs:33–39`
- `mod revert` and `pub use revert::run_revert` exported from `lib.rs`

**`crates/netfyr-varlink`**
- `VarlinkClient::revert(target_seq, dry_run) -> Result<(VarlinkApplyReport, String), VarlinkError>` — `client.rs:206–221`
- `VarlinkError::EntryNotFound(String)` — `client.rs:59–61`
- `io.netfyr.Revert(target_seq: int, dry_run: bool) -> (report: ApplyReport, entry_timestamp: string)` — `io.netfyr.varlink:15`
- `error EntryNotFound (reason: string)` — `io.netfyr.varlink:105`
- Unit tests: correct method name, params, dry_run forwarding, report decode, timestamp fallback, EntryNotFound mapping — `client.rs:751–913`

**`crates/netfyr-daemon`**
- `RevertResult { reconcile_diff, report: Option<ApplyReport> }` — `reconciler.rs:36–43`
- `Reconciler::revert(target_state, target_seq, policies, dry_run)` — diffs, applies or dry-runs, records journal entry — `reconciler.rs:368–443`
- `handle_revert()` — reads journal entry, converts snapshot, delegates to reconciler, serializes dry-run diff as `VarlinkApplyReport` — `server.rs:403–529`
- `"io.netfyr.Revert"` dispatched in `handle_connection()` — `server.rs:641–643`

**`crates/netfyr-cli/tests/revert_integration.rs`**
- Tests: missing target arg, non-numeric target, entry-not-found output, journal metadata, trigger serialization, revert entry ordering.
- `test_revert_nonexistent_entry_exit_code_is_1` is **explicitly marked as a known failing test** (exit code 2 instead of 1) with a `// BUG` comment.

---

## Requirements

From the acceptance criteria, these concrete behaviors must be satisfied:

1. `netfyr revert <seq>` restores system state to the target snapshot, records a journal entry with `trigger.type = "revert"` and `trigger.target_seq = <seq>`, exits 0 on success.
2. `netfyr revert <seq> --dry-run` shows the diff without applying, writes no journal entry, exits 0.
3. "No changes needed" message and exit 0 when diff is empty.
4. "Entry #N not found" output and **exit code 1** for missing entries.
5. After revert, `netfyr history -n 1` shows the revert entry with correct trigger.
6. Daemon mode: delegates via Varlink `Revert`, prints policy-drift warning to stderr.
7. Daemon dry-run: no journal entry written, no changes applied.
8. Snapshot round-trip: `to_state_set()` recovers scalar, boolean, string, IP address, IP network, and list field types.
9. Address list order preserved through round-trip.

---

## Gap Analysis

### Gap 1 — Failing test: exit code for "entry not found" in standalone mode

**File**: `crates/netfyr-cli/tests/revert_integration.rs:131`  
**Test**: `test_revert_nonexistent_entry_exit_code_is_1`

The test asserts exit code 1 but receives exit code 2. The code at `revert.rs:106–109` correctly returns `Ok(ExitCode::from(1u8))` for the "not found" branch. The test should exercise that branch, since it sets `NETFYR_JOURNAL_DIR` to a temp dir and `NETFYR_SOCKET_PATH` to a nonexistent socket, pointing to the standalone path.

The likely root cause is that `Journal::open_default()` at `revert.rs:98` fails before the "not found" check is reached. When `open_default()` returns `Err`, the `?` operator propagates it to `run_revert` → `main()`, which maps all `Err` to `ExitCode::from(2u8)`.

**What needs to change**: Either:
- `crates/netfyr-cli/src/revert.rs` — catch `Journal::open_default()` failure separately and emit exit code 1 (or 2, if the failure is environmental rather than "entry not found"), OR
- `crates/netfyr-journal/src/journal.rs` — confirm `Journal::open()` initializes successfully given only a writable temp dir without a pre-existing `current` file, and that the test's pre-creation of only the `archive` subdir is sufficient.

### Gap 2 — Host-bits CIDR addresses do not round-trip correctly through `to_state_set()`

**File**: `crates/netfyr-journal/src/serializable.rs:50–91`

The acceptance criterion "Revert with address changes" uses addresses like `"10.99.0.1/24"` — host addresses expressed in CIDR notation. The `ipnetwork` crate's `Ipv4Network` type canonicalizes these to network addresses (`10.99.0.0/24`), zeroing the host bits. The existing round-trip tests in `serializable.rs` explicitly use canonical network addresses and note this limitation in comments (e.g., `"192.168.0.0/24"` instead of `"192.168.1.1/24"`).

When a policy applied `addresses: ["10.99.0.1/24"]` is stored in a journal `state_after`, the JSON field contains `"10.99.0.1/24"`. When `to_state_set()` deserializes this via `serde_json::from_value::<Value>(...)`, the `Value` deserializer tries `Ipv4Network` (untagged enum priority), which canonicalizes to `"10.99.0.0/24"`. The reverted state would apply the wrong address.

**What needs to change**: The `to_state_set()` implementation or the `Value` deserialization strategy must handle host-CIDR notation. Options:
- Try `Ipv4Addr` before `Ipv4Network` in deserialization order.
- Parse with host-bits awareness: if the parsed `Ipv4Network` differs from interpreting as an `Ipv4Addr`+prefix, keep the host address.
- Confirm against how `netfyr-backend/src/netlink/apply.rs` stores addresses (`IpAddr` vs `IpNetwork` vs `String`) to understand whether this is actually the address format in journal snapshots.

### Gap 3 — Missing E2E network tests for core acceptance criteria

**Files**: No file — needs creation.

The acceptance criteria include six network-level scenarios requiring actual interface manipulation:
- Revert restores MTU on a veth pair
- Dry-run shows correct field diff without applying
- No-op when already at target state
- Address revert (add/remove IPs)
- Journal entry recorded after revert
- Daemon mode revert via Varlink

None are present. The closest existing examples are `crates/netfyr-backend/tests/netlink_apply.rs` (uses `NetnsGuard`) and `crates/netfyr-cli/tests/apply_integration.rs`.

**What needs to be created**: A test file (e.g., `crates/netfyr-cli/tests/revert_e2e.rs` or `crates/netfyr-backend/tests/revert_netns.rs`) that:
1. Uses `NetnsGuard` to create an isolated network namespace with a veth pair.
2. Applies policy A (mtu=1400) via `run_apply` or the backend directly, producing journal entry seq=1.
3. Applies policy B (mtu=1300), producing journal entry seq=2.
4. Calls `run_revert_standalone` (or the binary) and asserts MTU=1400 and a revert journal entry is recorded.
5. Covers dry-run, no-op, and address-change sub-scenarios.

### Gap 4 — Missing unit tests for `handle_revert` in `server.rs`

**File**: `crates/netfyr-daemon/src/server.rs`

All other handlers (`handle_submit_policies`, `handle_dry_run`, `handle_query`, `handle_get_status`) have unit tests in `server.rs:876–1385`. `handle_revert` has none. The following cases need coverage:
- Missing `target_seq` parameter → `InternalError` response
- Invalid `target_seq` type → `InternalError` response
- Entry not found → `EntryNotFound` error response with correct name
- Dry-run response contains `changes` array and `entry_timestamp`

**What needs to be created**: Unit tests for `handle_revert` following the existing `make_stream_pair()` + handler call + `read_message()` assertion pattern. These tests will need a temp journal directory with pre-written entries (similar to `make_entry_with_state` in the CLI integration tests).

### Gap 5 — Missing unit tests for `Reconciler::revert()`

**File**: `crates/netfyr-daemon/src/reconciler.rs`

The reconciler test suite covers `dry_run`, `query`, `reconcile_and_apply`, `managed_entity_names`, `record_external_change`, and `compute_external_field_changes`. `Reconciler::revert()` has no unit tests.

**What needs to be created**: Smoke-level unit tests for `Reconciler::revert()`:
- `revert()` with empty `target_state` and `dry_run=false` returns `Ok(RevertResult { report: Some(_) })`
- `revert()` with `dry_run=true` returns `Ok(RevertResult { report: None })`
- `revert()` with an empty diff (current state already matches target) returns a successful report with zero changes

---

## Integration Points

| Component | Interface | How revert interacts |
|-----------|-----------|----------------------|
| `netfyr-journal` | `Journal::open_default()`, `read_entry(seq)`, `append(entry)` | Reads target snapshot; writes revert entry |
| `netfyr-journal` | `SerializableStateSet::to_state_set()` | Converts stored JSON snapshot to live `StateSet` |
| `netfyr-journal` | `Trigger::Revert { target_seq }` | Identifies revert entries in `netfyr history` output |
| `netfyr-backend` | `BackendRegistry::query_all()`, `apply(&StateDiff)` | Queries current state; applies diff to system |
| `netfyr-state` | `diff::diff(&actual, &target)` | Lean `StateDiff` for backend apply |
| `netfyr-reconcile` | `generate_diff(&target, &actual, &managed, &schema)` | Rich diff for display and journal recording |
| `netfyr-varlink` | `VarlinkClient::revert()` / `io.netfyr.Revert` | CLI↔daemon IPC; reuses `VarlinkApplyReport` |
| `netfyr-cli/apply.rs` | `create_backend_registry()`, `determine_exit_code()`, `display_apply_report()` | Reused in standalone path |
| `netfyr-cli/history.rs` | `trigger_display_name()` | Must handle `Trigger::Revert` for history display |

`Reconciler::revert()` correctly calls `set_applying(true/false)` around the backend apply to suppress false-positive netlink monitor events — this is already implemented.

---

## Risks

1. **Failing test is a spec violation observable by users**: `test_revert_nonexistent_entry_exit_code_is_1` documents that exit code 2 is returned instead of 1 for a missing entry. Scripts that test `$?` after `netfyr revert <missing>` will break. Must be fixed.

2. **Host-bits CIDR canonicalization breaks address revert**: `"10.99.0.1/24"` becomes `"10.99.0.0/24"` after round-trip through `to_state_set()`. The "Revert with address changes" acceptance criterion requires applying the original host address. If `Value`'s serde deserialization canonicalizes network addresses, this scenario silently applies the wrong IP. Severity: high if the backend uses host-CIDR notation; low if it stores plain `Ipv4Addr`.

3. **Policy drift after daemon revert is unavoidable**: The daemon's next DHCP or policy event will overwrite the reverted state. The stderr warning is the only mitigation. This is by design but requires clear user communication.

4. **Daemon journal concurrency**: `handle_revert` in the server calls `Journal::open_default()` for reading and `Reconciler`'s internal journal mutex for writing. If two Varlink connections are open simultaneously (unlikely but possible), concurrent appends may contend on the file. The reconciler's mutex serializes daemon-side appends, but the server's on-demand open in `handle_revert` bypasses it. The implementation should be verified to not write outside the reconciler's mutex.

5. **`history.rs` trigger display coverage**: If `trigger_display_name()` in `crates/netfyr-cli/src/history.rs` uses a wildcard `_ =>` arm rather than an exhaustive match, `Trigger::Revert` entries may display with a generic label in `netfyr history` output. This should be verified to meet the acceptance criterion "the most recent entry has trigger 'revert'".
