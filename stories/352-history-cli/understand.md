# Gap Analysis: SPEC-352 — History CLI and Varlink API

## Current State

The majority of SPEC-352 is already implemented. Relevant code:

### `crates/netfyr-cli/src/history.rs` (fully present)
- `HistoryOutputFormat` (Text, Json), `HistoryArgs` (all fields from spec: count, since, trigger, selector, show, output)
- `run_history()` with daemon-detection: tries Varlink, falls back to local journal read
- `run_history_local()`: handles missing journal dir (exit 1), empty journal, `--show`, listing with filters
- `run_history_daemon()`: delegates to `VarlinkClient::get_history()` / `get_journal_entry()`
- `parse_since()`: relative durations (s/m/h/d) and RFC 3339 timestamps
- `filter_entries()`, `matches_trigger()`, `matches_selector()`: AND-logic filtering
- `format_text_list()`, `format_text_detail()`, `format_json_list()`, `format_json_detail()`
- `trigger_display_name()`, `outcome_summary()`, `entities_summary()`, `changes_summary()`
- `journal_dir_path()` using `NETFYR_JOURNAL_DIR` env var
- Comprehensive unit tests covering parse_since, filter_entries, formatting functions, and integration scenarios

### `crates/netfyr-cli/src/main.rs` and `lib.rs`
- `Commands::History(history::HistoryArgs)` is present in the `Commands` enum
- Dispatch in `main()` calls `run_history(args)` correctly
- `run_history` is re-exported from lib.rs

### `crates/netfyr-varlink/src/client.rs`
- `get_history(count, since, trigger, selector_name)` → `Vec<serde_json::Value>` implemented
- `get_journal_entry(seq)` → `Option<serde_json::Value>` implemented
- `VarlinkError::EntryNotFound` variant present

### `crates/netfyr-daemon/src/server.rs`
- `handle_get_history()` implemented: reads journal, applies filters (since, trigger, selector_name), limits count, returns JSON array
- `handle_get_journal_entry()` implemented: reads by seq, returns entry or null
- Both handlers are wired into `handle_connection()` dispatch table
- `server_parse_since()` and `server_trigger_type_str()` are local duplicates of the CLI helpers

### `crates/netfyr-varlink/src/io.netfyr.varlink`
Present but incomplete — contains `SubmitPolicies`, `Query`, `DryRun`, `GetStatus` only. Missing `GetHistory`, `GetJournalEntry`, `Revert`, and `error EntryNotFound`.

## Requirements

From the acceptance criteria, the complete feature requires:

1. **CLI subcommand** with args: `-n/--count`, `--since`, `--trigger`, `-s/--selector`, `--show`, `-o/--output`
2. **Dual-mode operation**: daemon (Varlink) if socket available, otherwise direct journal read
3. **Text list output**: fixed-width columns SEQ, TIMESTAMP, TRIGGER, ENTITIES, OUTCOME, CHANGES — with CHANGES last, truncated to terminal width (or 120 chars for non-TTY) with `...`
4. **Text detail output** (`--show <seq>`): full entry with trigger details, active policies, diff, outcome, state snapshot
5. **JSON output**: array for list, object for detail; same structure as NDJSON journal
6. **Filter behavior**: time (--since), trigger type (partial/case-insensitive match), entity name (name=X), count limit — all combined with AND logic
7. **Empty/missing journal**: appropriate messages and exit codes
8. **Varlink methods** `GetHistory` and `GetJournalEntry` handled by daemon
9. **Color support**: `+` green, `-` red, `~` yellow in CHANGES and diff output
10. **CHANGES notation**: scalar fields use `+field`/`~field`/`-field`; list fields use `addr(+N)`/`addr(-N)` notation; entity-level ops use `+entity`/`-entity`
11. **Varlink IDL** updated with new methods and types

## Gap Analysis

### GAP-1: Column order in `format_text_list` (functional)

**File**: `crates/netfyr-cli/src/history.rs`, lines 337–356

Current header: `SEQ TIMESTAMP TRIGGER ENTITIES CHANGES OUTCOME`
Spec requires: `SEQ TIMESTAMP TRIGGER ENTITIES OUTCOME CHANGES` (CHANGES last, OUTCOME before it)

The existing test at line 941 verifies column presence but not column order, so it does not catch this mismatch. The column ordering matters because CHANGES is supposed to use all remaining terminal width.

**Fix required**: Swap OUTCOME and CHANGES in both header and data rows in `format_text_list`.

### GAP-2: Terminal width truncation of CHANGES not implemented (functional)

**File**: `crates/netfyr-cli/src/history.rs`

The spec requires CHANGES to be truncated with `...` when the full row would exceed terminal width (or 120 chars when stdout is not a TTY). The current implementation applies a fixed count-based truncation in `changes_summary()` (shows at most 3 changes then `+N more`) but does not measure actual line width or query terminal width.

**Fix required**: After composing each row in `format_text_list`, measure its rendered length and truncate the CHANGES value to fit within `min(terminal_width, 120)` columns, appending `...` if truncated. Use `std::io::IsTerminal` (stable since Rust 1.70) plus an ioctl or a lightweight crate to query terminal width.

### GAP-3: List field notation not implemented in `changes_summary` (functional)

**File**: `crates/netfyr-cli/src/history.rs`, lines 510–570

The spec defines two notation systems:
- **Scalar fields** (mtu, carrier, state, etc.): `+field`, `~field`, `-field`
- **List fields** (addresses, routes): `addr(+N)`, `addr(-N)`, `addr(+N,-M)` — counted additions/removals, never `~`

The current `changes_summary()` applies scalar notation uniformly to all fields. There is no list-field detection. The existing tests only verify scalar notation.

**Fix required**: Detect list-typed fields by checking if `current` or `desired` in `SerializableFieldChange` is a JSON array, then render using count notation. Known list fields per the spec: `addresses`, `routes`.

### GAP-4: Color support not implemented (functional, per spec)

**File**: `crates/netfyr-cli/src/history.rs`

The spec requires `+` indicators to be green, `-` red, `~` yellow in the CHANGES column and the diff block of `--show` output. The `colored` crate is already a dependency of `netfyr-cli`. No color is currently applied in `format_text_list()` or `format_text_detail()`.

**Fix required**: Apply `colored::Colorize` to `+`/`-`/`~` prefixes in `changes_summary()` output and in the diff rendering block of `format_text_detail()`. Color must be conditioned on `colored`'s global override so it respects the `--color`/`NO_COLOR` already wired up in `main()`.

### GAP-5: Missing Varlink client tests for `get_history` and `get_journal_entry`

**File**: `crates/netfyr-varlink/src/client.rs` (tests section, after line 317)

The test suite covers `submit_policies`, `query`, `dry_run`, `get_status`, `revert`, and error variants — but has no tests for `get_history` or `get_journal_entry`. The acceptance criteria include daemon-mode scenarios that depend on these methods.

**Fix required**: Add unit tests using the `spawn_mock_server` pattern already present:
- `test_get_history_sends_correct_method_and_parameters` — verify method name and optional params forwarded correctly
- `test_get_history_returns_entries_array` — verify `entries` JSON array is extracted and returned
- `test_get_journal_entry_returns_entry_when_present` — verify non-null entry becomes `Some(value)`
- `test_get_journal_entry_returns_none_when_entry_is_null` — verify null response becomes `None`

### GAP-6: Missing server-side tests for `handle_get_history` and `handle_get_journal_entry`

**File**: `crates/netfyr-daemon/src/server.rs` (tests section, after line 876)

The server test suite has no coverage for the two new handlers. These handlers call `Journal::open_default()`, making them harder to test in isolation, but the error paths can be verified without a real journal.

**Fix required**: Add unit tests:
- `test_handle_get_history_missing_seq_param_returns_error` — call with `{}`, verify InternalError (missing seq)
- `test_handle_get_journal_entry_missing_seq_parameter_returns_error` — call with `{}`, verify InternalError
- `test_handle_get_history_returns_entries_field_in_parameters` — supply a real journal dir via env var and verify `entries` is an array in the response

### GAP-7: `io.netfyr.varlink` missing `GetHistory`, `GetJournalEntry`, `Revert`, and `EntryNotFound`

**File**: `crates/netfyr-varlink/src/io.netfyr.varlink`

The IDL file documents the public Varlink interface. It is missing:
- `method GetHistory(count: ?int, since: ?string, trigger: ?string, selector_name: ?string) -> (entries: []object)`
- `method GetJournalEntry(seq: int) -> (entry: ?object)`
- `method Revert(target_seq: int, dry_run: bool) -> (report: ApplyReport, entry_timestamp: string)`
- `error EntryNotFound (reason: string)`

The Varlink IDL is not parsed at runtime (the wire protocol is hand-rolled JSON), so this is a documentation/contract gap rather than a runtime functional one. The spec explicitly lists this file as a deliverable.

**Fix required**: Add the missing method declarations and `error EntryNotFound` to the .varlink file. Structured journal types in the IDL may be simplified to `object` since the daemon returns raw serialized JSON.

## Integration Points

- **`netfyr-journal`**: `Journal::open()`, `Journal::open_default()`, `Journal::read_recent()`, `Journal::read_entry()` — used in both CLI local mode and daemon handler. `JournalEntry`, `SerializableDiff`, `SerializableDiffOp`, `SerializableFieldChange`, `SerializableStateSet`, `Trigger`, `ApplyOutcome` are deserialized in the CLI after receiving raw JSON from daemon.
- **`netfyr-varlink`**: `VarlinkClient::get_history()` and `get_journal_entry()` used by `run_history_daemon()`. Return type is `Vec<serde_json::Value>` / `Option<serde_json::Value>` to avoid a journal dependency in the varlink crate; the CLI does final deserialization.
- **`crate::daemon_socket_path()`**: shared helper for daemon detection, same pattern as `apply` and `query`.
- **`colored` crate**: already a dependency of `netfyr-cli`; GAP-4 uses `colored::Colorize` consistent with the `--color` / `NO_COLOR` global already configured by `resolve_color_mode()`.
- **`xtask`**: uses `Cli::command()` for man page generation; `History` is already in `Commands` so the man page is extended automatically.

## Risks

1. **Duplicate duration-parsing logic**: `server_parse_since()` in `server.rs` and `parse_since()` in `history.rs` are near-identical. If one is changed (e.g. new time unit), the other will diverge. Refactoring is blocked by the crate dependency direction (varlink/daemon cannot depend on cli), so this duplication is structural.

2. **Terminal width query portability (GAP-2)**: Querying terminal width requires a platform-specific call. `libc` is already a transitive dependency. If a cross-platform solution is preferred, a lightweight crate (e.g. `terminal_size`) would need to be added to `netfyr-cli/Cargo.toml`.

3. **List field detection (GAP-3)**: `SerializableFieldChange` carries only field name and JSON values — no type metadata. Detecting lists by checking `serde_json::Value::is_array()` on current/desired is practical but could misfire for malformed state. Alternatively, hard-coding known list field names (`addresses`, `routes`) is more robust within the current domain.

4. **Multi-selector ignored in daemon mode**: `run_history_daemon()` passes only `args.selector.first()` to `get_history()` (line 158–159). Multiple `-s` selectors are silently dropped in daemon mode. The spec only demonstrates `name=X` selectors, so this is an edge case, but it creates a behavior difference between daemon and local modes.

5. **Test isolation for env-var-based integration tests**: Tests that call `run_history_local` mutate `NETFYR_JOURNAL_DIR` and are guarded by a global `Mutex<()>`. This is fragile under parallel test execution. The pattern is already established in the existing tests, so the risk is managed but not eliminated.

6. **Color in JSON output**: Applying color in `format_text_detail` is straightforward. Applying color in `format_text_list` to individual cells within a fixed-width format requires care to account for invisible ANSI escape bytes when computing column widths, since `colored` strings include escape sequences in their byte length.
