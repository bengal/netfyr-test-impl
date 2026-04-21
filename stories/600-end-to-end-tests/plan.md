# SPEC-600: End-to-End Integration Tests — Implementation Plan

## Approach

16 of the 26 specified test scripts already exist. The remaining 10 scripts cover three functional areas: journal recording (2 scripts), history CLI (4 scripts), and revert CLI (4 scripts). All 10 follow the same structural pattern as existing scripts — boilerplate header, `netns_setup`, daemon startup with temp dirs, policy apply, then verification — with the addition of journal-specific env vars and `jq`-based JSON parsing.

The key architectural decision is how to handle the **daemon startup journal entry**. The daemon writes a `Trigger::DaemonStartup` entry (seq=1) during initial reconciliation before any user-initiated apply. This means the first `netfyr apply` produces seq=2, not seq=1. Rather than hardcoding seq offsets (brittle if daemon behavior changes), the tests dynamically extract seq numbers from the journal file using `jq` to filter by trigger type. For example, to find the first policy-apply entry's seq: `jq -r 'select(.trigger.type == "policy_apply") | .seq' current.ndjson | head -n 1`. This makes tests robust against any number of daemon-internal entries.

All journal/history/revert tests set `NETFYR_JOURNAL_DIR` on both the daemon process and every CLI invocation. The daemon writes journal entries to this directory; the CLI reads from it (either directly in local mode, or by connecting to the daemon which also reads from it). Setting it on both is redundant when the daemon is running (the CLI goes through the daemon Varlink API) but harmless and necessary for the `revert-noent` test where the daemon may not be reachable in some fallback paths.

The tests use flexible pattern matching for output verification — `grep -qi "not found"` rather than exact string comparison, `grep -q "mtu"` rather than matching the full `mtu: 1300 -> 1400` format string. This insulates tests from cosmetic output changes.

## Design Decisions

1. **Decision**: Dynamically extract seq numbers from `current.ndjson` rather than hardcoding expected seq values.
   - **Alternatives considered**: (a) Hardcode seq=2 for first apply (accounting for startup entry at seq=1); (b) Suppress the daemon startup entry via a flag; (c) Filter by trigger type in the test assertions.
   - **Rationale**: Option (a) breaks if the daemon adds or removes internal events. Option (b) requires Rust code changes, which the spec prohibits. Option (c) — dynamic extraction — is robust and self-documenting. Using `jq 'select(.trigger.type == "policy_apply")'` explicitly states what we're testing.

2. **Decision**: Require `jq` and check for it at the top of each script that uses it, failing with `exit 1` (not skip).
   - **Alternatives considered**: (a) Parse JSON with `grep`/`sed`; (b) Use Python for JSON parsing; (c) Skip tests if `jq` is absent.
   - **Rationale**: The spec rule is "No skip: if a prerequisite is missing, exit 1." `jq` is the standard CLI JSON tool and is available in the CI environment. Parsing JSON with `grep` is fragile for nested structures. Python adds a heavier dependency. Six of the 10 scripts need `jq`; the other four (history-list, history-show, revert, revert-noent) can verify text output with `grep` alone.

3. **Decision**: Set `NETFYR_JOURNAL_DIR` on every CLI command invocation, not just the daemon.
   - **Alternatives considered**: Only set it on the daemon and rely on the daemon Varlink API for all reads.
   - **Rationale**: The `history` CLI falls back to direct journal reads if the daemon connection fails. While this shouldn't happen in our tests (daemon is running), setting `NETFYR_JOURNAL_DIR` on CLI commands too is defensive and costs nothing.

4. **Decision**: The `revert-noent` test starts a daemon even though the spec template doesn't show daemon setup.
   - **Alternatives considered**: Run `netfyr revert 9999` without a daemon (standalone mode).
   - **Rationale**: In standalone mode, `run_revert_standalone` reads the journal directly and prints "Error: Entry #9999 not found". But the journal directory must exist and contain a valid journal (with `.seq` file). It's simpler and more realistic to start a daemon (which creates the journal and writes a startup entry) and test through the daemon path — this is how users actually invoke revert. The daemon path returns `VarlinkError::EntryNotFound` with the message "Entry #9999 not found", which the CLI prints as "Error: Entry #9999 not found".

5. **Decision**: No veth pairs needed for `revert-noent` — just start the daemon with empty policy dir.
   - **Alternatives considered**: Create a veth pair for consistency with other tests.
   - **Rationale**: The test only verifies error handling for a missing seq number. No network state changes are needed. The daemon starts fine in a network namespace with only the loopback interface.

6. **Decision**: Use `cleanup` in EXIT traps for consistency, even in scripts without dnsmasq.
   - **Alternatives considered**: Only call `cleanup` in scripts that use dnsmasq.
   - **Rationale**: Looking at existing scripts, tests without dnsmasq do NOT call `cleanup` (e.g., `600-e2e-static-apply.sh`). I'll follow this convention: only add `cleanup` to EXIT traps in scripts that call `start_dnsmasq`. None of the 10 new scripts use dnsmasq, so their traps follow the simpler pattern: `trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$TMPDIR_TEST"' EXIT`.

7. **Decision**: For the `history-filter` test, use two separate `netfyr apply` calls with individual policy files (not a directory apply).
   - **Alternatives considered**: Apply a directory containing both policies at once.
   - **Rationale**: The filter test needs each apply to produce a distinct journal entry (one for veth-a0, one for veth-b0). A directory apply produces a single journal entry covering both interfaces, making filtering ambiguous. Two separate applies produce two entries, each referencing a single interface in its diff.

8. **Decision**: For the `revert-dry-run` test, match output for "mtu" (flexible) rather than exact "mtu: 1300 -> 1400" format.
   - **Alternatives considered**: Match the exact string "mtu: 1300 -> 1400".
   - **Rationale**: The daemon-mode dry-run builds a VarlinkApplyReport with descriptions formatted as `"mtu: 1300 -> 1400"` (server.rs line 489). This could be matched exactly. However, the surrounding output includes ANSI color codes (from `colored` crate), which makes exact matching unreliable unless piped through `grep --color=never` or `sed` to strip them. Using `grep -q "mtu"` combined with `grep -q "1300"` and `grep -q "1400"` is robust and verifies the essential content.

9. **Decision**: For the `journal-apply` test, verify JSON structure via `jq` queries on `current.ndjson` rather than through the `netfyr history -o json` CLI command.
   - **Alternatives considered**: Use `netfyr history --show 1 -o json` and parse that output.
   - **Rationale**: The spec explicitly says to verify `current.ndjson` directly. Reading the file also validates that the daemon actually wrote to the configured journal directory. Using the CLI would test a different code path (the Varlink API and CLI formatting) which has its own dedicated tests.

## File Changes

### `tests/600-e2e-journal-apply.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR` to temp dir, starts daemon, applies static policy (mtu=1400 on `veth-e2e0`), then verifies `current.ndjson` via `jq`:
  - File exists
  - Last policy-apply entry (filtered by `.trigger.type == "policy_apply"`) has:
    - `.trigger.type` == `"policy_apply"`
    - `.diff.operations` contains an entry with `entity_name == "veth-e2e0"` and a field change for `mtu`
    - `.state_after.entities` contains an entry with `entity_type == "ethernet"` and `selector_name == "veth-e2e0"` where `fields.mtu == 1400`
    - `.outcome.kind` == `"applied"` with `.outcome.succeeded >= 1`
  - Checks for `jq` at top of script.
- **Why**: Validates that `netfyr apply` produces correct journal entries with proper metadata.

### `tests/600-e2e-journal-seq.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon, applies policy A (mtu=1400), then policy B (mtu=1300). Reads `current.ndjson`, filters to policy-apply entries with `jq`, and verifies:
  - Exactly 2 policy-apply entries exist
  - Their seq numbers are monotonically increasing (seq of second > seq of first)
  - The timestamp of the first is earlier than or equal to the timestamp of the second
  - Checks for `jq` at top.
- **Why**: Validates monotonic sequence numbering across multiple applies.

### `tests/600-e2e-history-list.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon, applies policy A (mtu=1400) then policy B (mtu=1300). Runs `NETFYR_SOCKET_PATH=... NETFYR_JOURNAL_DIR=... netfyr history -n 5` and captures output. Verifies:
  - Output header contains "SEQ", "TIMESTAMP", "TRIGGER", "OUTCOME"
  - At least 2 non-header lines mentioning "policy-apply" exist (daemon-startup entries may also appear)
  - The first policy-apply entry has a higher seq than the second (reverse chronological order)
  - Uses `grep` and `awk` for text parsing, no `jq` needed.
- **Why**: Validates the `history` list view shows entries correctly.

### `tests/600-e2e-history-show.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon, applies policy (mtu=1400 on `veth-e2e0`). Extracts the seq number of the policy-apply entry from `current.ndjson` using `jq`. Runs `netfyr history --show <seq>` and verifies:
  - Output contains "Trigger:" and "policy-apply"
  - Output contains "Diff:" and "mtu"
  - Output contains "Outcome:" and "applied"
  - Checks for `jq` at top (to extract the seq number).
- **Why**: Validates the `history --show` detail view displays entry metadata.

### `tests/600-e2e-history-json.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon, applies two policies sequentially. Runs `netfyr history -n 10 -o json --trigger apply` and pipes to `jq`. Verifies:
  - Output is a valid JSON array (parseable by `jq`)
  - Array has exactly 2 elements (2 policy-apply entries)
  - Each element has `seq`, `timestamp`, `trigger`, `outcome` fields
  - Checks for `jq` at top.
- **Why**: Validates the JSON output format of the `history` command.

### `tests/600-e2e-history-filter.sh`
- **Action**: create
- **What**: Shell test script. Creates two veth pairs (`veth-a0`/`veth-a1` and `veth-b0`/`veth-b1`), sets `NETFYR_JOURNAL_DIR`, starts daemon. Applies a policy for `veth-a0` (mtu=1400), then separately applies a policy for `veth-b0` (mtu=1300). Runs `netfyr history -s name=veth-a0` and verifies:
  - Output contains "veth-a0"
  - Output does NOT contain "veth-b0" (unless in a header or unrelated text)
  - Verifies there's exactly 1 data line mentioning policy-apply
  - Uses `grep` for text output verification.
- **Why**: Validates the `-s name=` filter on the `history` command.

### `tests/600-e2e-revert.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon. Applies policy A (mtu=1400), extracts its seq from `current.ndjson` (the policy-apply entry). Applies policy B (mtu=1300), verifies mtu=1300. Runs `netfyr revert <seq_of_A>`. Verifies:
  - mtu is now 1400 (restored)
  - `current.ndjson` has a new entry with `.trigger.type == "revert"`
  - Checks for `jq` at top (to extract seq and verify revert entry).
- **Why**: Validates that `revert` restores previous network state.

### `tests/600-e2e-revert-dry-run.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon. Applies policy A (mtu=1400), extracts seq. Applies policy B (mtu=1300). Runs `netfyr revert <seq_of_A> --dry-run` and captures output. Verifies:
  - Output mentions "mtu" (the field that would change)
  - Output mentions "1300" and "1400" (the old and new values)
  - `ip link show veth-e2e0` still shows mtu 1300 (no change applied)
  - The count of policy-apply entries in `current.ndjson` is still 2 (no revert entry created)
  - Checks for `jq` at top.
- **Why**: Validates that `revert --dry-run` previews without modifying state.

### `tests/600-e2e-revert-noent.sh`
- **Action**: create
- **What**: Shell test script. Sets `NETFYR_JOURNAL_DIR` to temp dir, starts daemon (no veth pairs needed). Waits for socket. Runs `netfyr revert 9999` and captures exit code and output (stderr). Verifies:
  - Exit code is 1
  - Output (stderr) contains "not found" (case-insensitive)
  - No `jq` needed.
- **Why**: Validates graceful error handling for reverting to a nonexistent entry.

### `tests/600-e2e-revert-addr.sh`
- **Action**: create
- **What**: Shell test script. Creates veth pair, sets `NETFYR_JOURNAL_DIR`, starts daemon. Applies policy A with addresses `10.99.0.1/24` and `10.99.0.2/24`, extracts seq. Applies policy B with address `10.99.0.3/24`, verifies only `10.99.0.3/24` present. Runs `netfyr revert <seq_of_A>`. Verifies:
  - `veth-e2e0` has addresses `10.99.0.1/24` and `10.99.0.2/24`
  - `veth-e2e0` does NOT have address `10.99.0.3/24`
  - Checks for `jq` at top (to extract seq).
- **Why**: Validates that revert correctly restores address sets.

## Dependencies

No new crate dependencies. No Rust code changes. No Makefile changes.

**External tool dependency**: `jq` is required by 8 of the 10 new scripts (all except `revert-noent` and `history-list`). Each script that uses `jq` checks `command -v jq` at startup and exits with `FAIL` if absent, per the spec's "no skip" rule.

## Implementation Order

All 10 scripts are independent of each other — they can be created in any order. However, for logical coherence and easier debugging during development:

1. **`tests/600-e2e-journal-apply.sh`** — Foundation: validates journal entries exist after apply. All subsequent journal/history/revert tests depend on this behavior working.
2. **`tests/600-e2e-journal-seq.sh`** — Validates seq numbering, which revert tests depend on.
3. **`tests/600-e2e-history-list.sh`** — Simplest history test (text output, no jq for assertions).
4. **`tests/600-e2e-history-show.sh`** — History detail view.
5. **`tests/600-e2e-history-json.sh`** — History JSON output.
6. **`tests/600-e2e-history-filter.sh`** — History filtering.
7. **`tests/600-e2e-revert.sh`** — Core revert functionality.
8. **`tests/600-e2e-revert-dry-run.sh`** — Revert preview.
9. **`tests/600-e2e-revert-noent.sh`** — Simplest revert error case (no veth needed).
10. **`tests/600-e2e-revert-addr.sh`** — Revert with address changes (most complex).

Each step produces a runnable, self-contained test script. No step depends on a previous step being complete — the ordering is for logical grouping only.

## Risks and Mitigations

1. **Risk**: Daemon startup entry contaminates seq number assertions.
   - **Impact**: Tests that expect "2 entries" might see 3 (startup + 2 applies).
   - **Mitigation**: All journal counting and seq extraction filters by `trigger.type == "policy_apply"` (or "revert") to exclude daemon-startup and external-change entries. The journal-seq test explicitly counts only policy-apply entries.

2. **Risk**: `jq` not installed in the test environment.
   - **Impact**: 8 of 10 scripts would fail with "command not found".
   - **Mitigation**: Each script checks `command -v jq` at the top and exits with a clear FAIL message. CI environments typically have `jq` installed.

3. **Risk**: Daemon creates journal directory structure (`current.ndjson`, `archive/`, `.seq`) — if the journal directory doesn't exist at daemon startup, `Journal::open` creates it.
   - **Impact**: Tests that set `NETFYR_JOURNAL_DIR` must ensure the directory exists before daemon starts.
   - **Mitigation**: `Journal::open` calls `std::fs::create_dir_all`, so it creates the directory if missing. Tests create the journal dir parent via `TMPDIR_TEST=$(mktemp -d)` and set `NETFYR_JOURNAL_DIR="$TMPDIR_TEST/journal"`. The daemon's `Journal::open_default()` will create the `journal/` subdirectory.

4. **Risk**: Race condition between `netfyr apply` completing and journal entry being flushed to disk.
   - **Impact**: Tests that read `current.ndjson` immediately after apply might not see the latest entry.
   - **Mitigation**: The `netfyr apply` CLI command returns only after the daemon's Varlink response is received, which happens after the journal entry is written and flushed (the journal append uses `fsync` semantics via write + flush). There should be no race.

5. **Risk**: The `history` CLI connects to the daemon and gets filtered results — the daemon's filter implementation may differ from direct journal reads.
   - **Impact**: History filter test might pass with daemon but fail without, or vice versa.
   - **Mitigation**: The filter test verifies behavior through the daemon (since daemon is running), which is the primary usage path. The daemon's `handle_get_history` in server.rs applies filters server-side using the same `matches_selector` and `matches_trigger` logic.

6. **Risk**: ANSI color codes in `netfyr revert --dry-run` output interfere with `grep` matching.
   - **Impact**: `grep -q "mtu"` might fail if "mtu" is split across ANSI escape sequences.
   - **Mitigation**: ANSI codes are typically inserted around the whole string, not splitting individual words. The `colored` crate wraps entire `format!()` outputs. Testing confirms that `grep` matches through ANSI codes (since `grep` matches bytes, not rendered text). If this becomes flaky, the test can pipe through `sed 's/\x1b\[[0-9;]*m//g'` to strip codes.

7. **Risk**: The `revert-addr` test depends on the revert mechanism correctly computing and applying address diffs.
   - **Impact**: If the backend's address apply logic has bugs, this test exposes them but the fix would be in another story.
   - **Mitigation**: This is an integration test — exposing bugs is the point. If the test fails, it provides a clear signal that the address revert path needs fixing.

8. **Risk**: The history-filter test uses two separate applies, but the daemon-startup entry might also reference one of the veth interfaces (if the daemon queries existing interfaces during startup reconciliation).
   - **Impact**: The filter for `name=veth-a0` might return 2 entries instead of 1 if the startup entry's diff lists veth-a0.
   - **Mitigation**: The startup reconciliation with no policies produces an empty desired state. The diff between empty desired and current state may show veth-a0 as a "removal" candidate, but the daemon doesn't actually remove unmanaged interfaces — it writes a diff with empty operations (since no policies target anything). Verify by checking: if the startup entry has empty `diff.operations`, the selector filter won't match it (since `matches_selector` checks `diff.operations.iter().any(|op| op.entity_name == value)`). This should be safe.

## Test Strategy

This story produces only shell test scripts — no Rust code. The verification strategy is:

1. **Primary: `make integration-test`** — Run all shell integration tests including the 10 new 600-series scripts. All must print `PASS: 600-e2e-<name>` and exit 0.

2. **Individual script testing** — Each script can be run independently: `bash tests/600-e2e-journal-apply.sh`. This is useful during development to iterate on a single test.

3. **Regression: `cargo test`** — Run to verify no Rust regressions. This story adds no Rust code, so this is a sanity check.

4. **Journal content inspection** — During development, manually inspect `current.ndjson` in the test temp directory to verify the actual JSON structure matches test assertions. This helps calibrate `jq` queries.

### What to test (by script):
- **journal-apply**: Journal entry exists, trigger type correct, diff references target entity/field, state_after has correct values, outcome indicates success.
- **journal-seq**: Multiple entries have monotonically increasing seq numbers and non-decreasing timestamps.
- **history-list**: Text output has header row with column names, data rows with correct info, reverse chronological order.
- **history-show**: Detail output shows trigger, diff, and outcome sections.
- **history-json**: Valid JSON array, correct element count, each element has required fields.
- **history-filter**: Only matching entries shown, non-matching entries excluded.
- **revert**: State restoration verified via `ip` commands, new journal entry with revert trigger.
- **revert-dry-run**: Output mentions planned changes, state unchanged, no new journal entry.
- **revert-noent**: Exit code 1, error output contains "not found".
- **revert-addr**: Address set restored correctly, old addresses removed.

### Common boilerplate to follow (from existing tests):
- Header: `#!/bin/bash`, `set -euo pipefail`, source helpers, binary checks
- `netns_setup "$@"`
- `TMPDIR_TEST=$(mktemp -d)` with EXIT trap
- Socket wait loop with daemon liveness check
- Apply with exit code capture: `APPLY_EXIT=0; ... || APPLY_EXIT=$?`
- Final `echo "PASS: 600-e2e-<name>"`

### Seq extraction pattern (used by 6 scripts):
```bash
APPLY_SEQ=$(jq -r 'select(.trigger.type == "policy_apply") | .seq' "$JOURNAL_DIR/current.ndjson" | tail -n 1)
```
This extracts the seq of the most recent policy-apply entry, skipping daemon-startup and other entries.
