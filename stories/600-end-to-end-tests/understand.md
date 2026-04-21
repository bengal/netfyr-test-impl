# Understand: SPEC-600 — End-to-End Integration Tests

## Current State

### Test infrastructure
- `tests/helpers.sh` (232 lines) — shared library providing: `netns_setup`, `create_veth`, `add_address`, `start_dnsmasq`, `cleanup` (kills all dnsmasq PIDs in `_DNSMASQ_PIDS[]`), `wait_for_address`, and assertion functions (`assert_eq`, `assert_match`, `assert_has_address`, `assert_not_has_address`, `assert_mtu`, `assert_link_up`, `assert_address_count`, `assert_json_address_order`).
- `Makefile` — `integration-test` target discovers tests via `tests/[0-9]*.sh`. This glob matches 600-*.sh files (the leading `6` is a digit), so all 600 tests are in the default run.

### Existing 600-series test scripts (16 of 26 required)
| File | Status |
|---|---|
| `tests/600-e2e-static-apply.sh` | exists |
| `tests/600-e2e-dhcp-and-static.sh` | exists |
| `tests/600-e2e-replace-all.sh` | exists |
| `tests/600-e2e-daemon-restart.sh` | exists |
| `tests/600-e2e-conflict.sh` | exists |
| `tests/600-e2e-dry-run.sh` | exists |
| `tests/600-e2e-apply-directory.sh` | exists |
| `tests/600-e2e-addr-single.sh` | exists |
| `tests/600-e2e-addr-five.sh` | exists |
| `tests/600-e2e-addr-twenty.sh` | exists |
| `tests/600-e2e-addr-replace.sh` | exists |
| `tests/600-e2e-addr-idempotent.sh` | exists |
| `tests/600-e2e-addr-duplicate-reject.sh` | exists |
| `tests/600-e2e-addr-overlapping-subnets.sh` | exists |
| `tests/600-e2e-addr-removal.sh` | exists |
| `tests/600-e2e-unmanaged.sh` | exists |
| `tests/600-e2e-journal-apply.sh` | **missing** |
| `tests/600-e2e-journal-seq.sh` | **missing** |
| `tests/600-e2e-history-list.sh` | **missing** |
| `tests/600-e2e-history-show.sh` | **missing** |
| `tests/600-e2e-history-json.sh` | **missing** |
| `tests/600-e2e-history-filter.sh` | **missing** |
| `tests/600-e2e-revert.sh` | **missing** |
| `tests/600-e2e-revert-dry-run.sh` | **missing** |
| `tests/600-e2e-revert-noent.sh` | **missing** |
| `tests/600-e2e-revert-addr.sh` | **missing** |

### NETFYR_JOURNAL_DIR support
`Journal::open_default()` (`crates/netfyr-journal/src/journal.rs:46`) reads `NETFYR_JOURNAL_DIR`, falling back to `/var/lib/netfyr/journal/`. The daemon's `reconciler.rs:67` and `server.rs:305,378,422` all call `Journal::open_default()`, so setting this env var on the daemon process redirects all journal writes. The `history` CLI (`crates/netfyr-cli/src/history.rs:583`) and `revert` CLI (`crates/netfyr-cli/src/revert.rs:98`) also read this env var through the same function.

### Journal file layout
`Journal::open` creates `current.ndjson` and an `archive/` subdirectory inside the configured journal directory. Each apply/revert/startup event appends one JSON line to `current.ndjson`.

### helpers.sh naming vs spec template
The spec template shows `kill_dnsmasq; cleanup` in EXIT traps. The actual `helpers.sh` merges both roles into a single `cleanup()` function. Existing 600 tests (e.g., `600-e2e-dhcp-and-static.sh`) call `cleanup` in their EXIT traps. There is no `kill_dnsmasq` function in `helpers.sh`.

---

## Requirements

The 10 missing scripts cover three functional areas: journal recording, history CLI, and revert CLI.

### Journal tests
- **600-e2e-journal-apply.sh**: After `netfyr apply`, `current.ndjson` must exist; the relevant entry must have a trigger indicating policy apply, reference the target interface and mtu in the diff, include `state_after` with correct mtu, and have an outcome indicating success.
- **600-e2e-journal-seq.sh**: Two sequential applies produce 2 entries in `current.ndjson`; the second entry has a higher seq number; the first entry's timestamp is earlier than the second.

### History CLI tests
- **600-e2e-history-list.sh**: `netfyr history -n 5` after two applies lists 2 entries in reverse chronological order showing SEQ, TIMESTAMP, TRIGGER, OUTCOME columns.
- **600-e2e-history-show.sh**: `netfyr history --show 1` displays trigger, diff, and outcome detail for entry 1.
- **600-e2e-history-json.sh**: `netfyr history -n 5 -o json` emits a valid JSON array with 2 elements each containing `seq`, `timestamp`, `trigger`, `outcome`; parseable by `jq`.
- **600-e2e-history-filter.sh**: `netfyr history -s name=veth-a0` after applies on two different interfaces shows only the entry for `veth-a0`.

### Revert CLI tests
- **600-e2e-revert.sh**: After mtu=1400 (seq=1) then mtu=1300 (seq=2), `netfyr revert 1` restores mtu=1400 and creates a new journal entry with a revert trigger.
- **600-e2e-revert-dry-run.sh**: `netfyr revert 1 --dry-run` outputs the planned mtu change but does not modify the interface or add a journal entry (entry count stays at 2).
- **600-e2e-revert-noent.sh**: `netfyr revert 9999` exits with code 1 and output contains "not found".
- **600-e2e-revert-addr.sh**: After addresses [10.99.0.1/24, 10.99.0.2/24] (seq=1) then [10.99.0.3/24] (seq=2), `netfyr revert 1` restores the two original addresses and removes 10.99.0.3/24.

---

## Gap Analysis

### Files to create (10 new shell scripts)
| File | What to implement |
|---|---|
| `tests/600-e2e-journal-apply.sh` | Apply policy, parse `current.ndjson` with `jq`, assert trigger/diff/state_after/outcome fields |
| `tests/600-e2e-journal-seq.sh` | Apply twice, count lines in `current.ndjson`, assert seq progression and timestamp ordering |
| `tests/600-e2e-history-list.sh` | Apply twice, run `netfyr history -n 5`, assert 2 rows with required columns |
| `tests/600-e2e-history-show.sh` | Apply once, run `netfyr history --show 1`, assert trigger/diff/outcome in output |
| `tests/600-e2e-history-json.sh` | Apply twice, run `netfyr history -n 5 -o json`, pipe to `jq`, assert array length and fields |
| `tests/600-e2e-history-filter.sh` | Apply to two interfaces, run `netfyr history -s name=veth-a0`, assert only veth-a0 entry shown |
| `tests/600-e2e-revert.sh` | Apply A then B, run `netfyr revert 1`, assert mtu restored and new journal entry present |
| `tests/600-e2e-revert-dry-run.sh` | Apply A then B, run `netfyr revert 1 --dry-run`, assert diff in output but mtu unchanged and no new entry |
| `tests/600-e2e-revert-noent.sh` | Run `netfyr revert 9999` (no prior applies needed), assert exit=1 and "not found" in output |
| `tests/600-e2e-revert-addr.sh` | Apply addr-set-A then addr-set-B, revert to 1, assert correct addresses present/absent |

### Files to modify
- **None** — no Rust code changes, no Makefile changes, no helpers.sh changes required.

---

## Integration Points

| Component | How the new tests interact |
|---|---|
| `target/debug/netfyr-daemon` | Started with `NETFYR_SOCKET_PATH`, `NETFYR_POLICY_DIR`, and `NETFYR_JOURNAL_DIR` env vars; all 10 journal/history/revert tests need daemon writes to journal |
| `target/debug/netfyr apply` | `crates/netfyr-cli/src/apply.rs::run_apply` — triggers journal write via daemon Varlink on each apply |
| `target/debug/netfyr history` | `crates/netfyr-cli/src/history.rs::run_history` — reads `NETFYR_JOURNAL_DIR` directly from filesystem, no daemon needed for the read |
| `target/debug/netfyr revert` | `crates/netfyr-cli/src/revert.rs::run_revert` — reads journal for `state_after`, applies diff via daemon Varlink; needs daemon running |
| `Journal::open_default()` | `crates/netfyr-journal/src/journal.rs:46` — creates `current.ndjson` and `archive/` in `NETFYR_JOURNAL_DIR` |
| `tests/helpers.sh` — `cleanup` | New DHCP tests (if any) must call `cleanup` in EXIT trap |

---

## Risks

### Daemon startup journal entry
`reconciler.rs:67` calls `Journal::open_default()` on `Trigger::DaemonStartup`. This means `current.ndjson` may already contain seq=1 as a startup entry before the first `netfyr apply`. The journal-seq test and revert tests that reference specific seq numbers (e.g., "seq=1 is the first apply") must account for the startup entry being seq=1, pushing the first apply to seq=2. This needs verification against actual daemon behavior before writing the assertions.

### jq availability
The history-json and journal-apply tests require `jq` to parse JSON. If `jq` is not installed, scripts fail with a cryptic "command not found" error. Each script that uses `jq` must check `command -v jq` at startup and `exit 1` with a clear FAIL message if absent.

### Journal archive subdirectory
`Journal::open` creates `archive/` inside the journal directory. If the journal directory does not exist, the open fails. Tests must create `TMPDIR_TEST/journal` (or similar) before starting the daemon. The revert-noent test uses no daemon, so it must either pre-create `archive/` itself or use the CLI's own handling of a missing journal (exit code 1 with "not found" or similar).

### Trigger field name in serialized JSON
The spec references `trigger.type` in `current.ndjson`. The actual serialized field names depend on the serde configuration of `Trigger` in `crates/netfyr-journal/src/entry.rs`. Tests must use the actual emitted field names, verified empirically. Using `jq` with flexible queries (e.g., `jq '.trigger | has("type")'`) is safer than hardcoding the exact field path.

### revert-dry-run output format
The spec expects the dry-run output to contain "mtu: 1300 -> 1400". The exact format comes from `DryRunReport::summary()` in `crates/netfyr-backend/src/report.rs`. Tests should match with a flexible pattern (e.g., `assert_match "$OUTPUT" "mtu"`) rather than requiring exact formatting.

### helpers.sh `kill_dnsmasq` naming
The spec template uses `kill_dnsmasq` in EXIT traps. The actual helpers.sh uses `cleanup`. New scripts must use `cleanup`, not `kill_dnsmasq`, to match the existing convention and avoid `command not found` errors.
