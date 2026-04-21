# Plan: SPEC-352 — History CLI and Varlink API

## Approach

The `netfyr history` command is a read-only view over the journal infrastructure from SPEC-351. The design follows the established CLI pattern (`apply` and `query`): a clap `Args` struct, a `run_history` async entry point, daemon-detection via Varlink with local fallback, and format-aware output.

The core module is `crates/netfyr-cli/src/history.rs` (new file). It owns all history-specific logic: argument parsing, duration parsing, entry filtering, and text/JSON formatting. The Varlink layer adds two methods (`get_history`, `get_journal_entry`) to the client and two handlers to the daemon server. Since `JournalEntry` already derives `Serialize`/`Deserialize` with a well-defined JSON shape, the Varlink wire format reuses that serialization directly — the daemon serializes `JournalEntry` to `serde_json::Value` and the client deserializes it back. This avoids introducing redundant DTO types while keeping the existing Varlink pattern (JSON values flowing through `call()`).

The alternative of creating separate `VarlinkJournalEntry` / `VarlinkTrigger` / etc. types was considered but rejected: `JournalEntry`'s serde format is already the stable on-disk format (NDJSON files), so coupling the wire format to it is acceptable and significantly reduces code. If the journal format ever changes, a versioning strategy would be needed regardless. The filtering is done client-side in daemon-free mode and server-side in daemon mode (so the daemon doesn't stream unnecessary data over the socket). In both cases, the `Journal` API is read-first-then-filter since `read_recent()` is the only bulk-read method.

For the daemon server, the journal is opened read-only per request rather than sharing the `Reconciler`'s `Mutex<Option<Journal>>`. The reconciler's journal is write-oriented and holds a write lock during append. Opening a fresh read-only `Journal` for history queries avoids contention and is safe because `read_current_entries()` just reads `current.ndjson` — no locking needed for reads. However, `Journal::open()` calls `create_dir_all`, which is fine for the daemon (it has write access to `/var/lib/netfyr/journal`).

## Design Decisions

### 1. Reuse JournalEntry JSON format as Varlink wire format

- **Decision**: Serialize `JournalEntry` directly to `serde_json::Value` for the Varlink response, and deserialize `serde_json::Value` back to `JournalEntry` in the client.
- **Alternatives considered**: Creating dedicated `VarlinkJournalEntry`, `VarlinkTrigger`, `VarlinkPolicySummary`, etc. types with `From` impls.
- **Rationale**: `JournalEntry` already has a stable, well-tested serde representation (the NDJSON format). Creating parallel types would be ~150 lines of boilerplate with no practical benefit. The spec's Varlink type definitions describe the same shape as the existing `JournalEntry` serialization. If the internal format ever changes, migration would be needed at the journal level regardless.

### 2. Separate OutputFormat enum for history

- **Decision**: Define `HistoryOutputFormat` in `history.rs` with variants `Text` (default) and `Json`.
- **Alternatives considered**: Reusing `query::OutputFormat` (has `Yaml` and `Json`, defaults to `Yaml`) or making a shared enum in `lib.rs`.
- **Rationale**: History's default is `Text` (tabular), not `Yaml`. History has no YAML output mode. A shared enum would force both commands to support all variants or require dead-code suppression. Two small enums are cleaner than one leaky abstraction.

### 3. Extract daemon_socket_path() to lib.rs

- **Decision**: Move the `daemon_socket_path()` function from `query.rs` to `lib.rs` as a `pub(crate)` function. Update `query.rs` to import it.
- **Alternatives considered**: Duplicating the function in `history.rs`.
- **Rationale**: Both `query` and `history` (and potentially future commands) need this. Duplication is a maintenance risk for a 3-line function. Moving it is a trivial refactor.

### 4. History selector only accepts name=value

- **Decision**: Define a separate `parse_history_selector` function in `history.rs` that only accepts `name=<value>` (not `type`, `driver`, `mac`, `pci_path`).
- **Alternatives considered**: Reusing `query::parse_selector` (private, accepts 5 keys).
- **Rationale**: The spec explicitly defines `--selector` as filtering by entity name in the diff operations. Supporting `type`, `driver`, etc. would require querying the backend for metadata, which is outside the journal's scope. A simpler parser with a clear error message is better UX.

### 5. Duration parsing in the history module

- **Decision**: Implement `parse_since(s: &str) -> Result<DateTime<Utc>>` that handles both relative durations (`30s`, `5m`, `1h`, `7d`) and ISO 8601 timestamps. Return the absolute cutoff time.
- **Alternatives considered**: Using the `humantime` crate, or `chrono`'s parsing.
- **Rationale**: The format is simple (4 suffixes + ISO 8601). `chrono` is already a dependency and handles ISO 8601 via `DateTime::parse_from_rfc3339`. A 20-line function avoids a new dependency. The function parses the numeric prefix and multiplies by the unit's seconds.

### 6. Server-side journal access: open per request

- **Decision**: In the daemon's `handle_get_history` and `handle_get_journal_entry`, open a `Journal` instance per request using `Journal::open_default()`.
- **Alternatives considered**: (a) Sharing the `Reconciler`'s `Mutex<Option<Journal>>` — requires exposing read methods through `Reconciler`, couples reconciliation with querying. (b) Adding a second `Arc<Mutex<Journal>>` to `serve_varlink` — adds lifetime complexity. (c) Opening read-only per request.
- **Rationale**: Journal reads are cheap (read a single file, parse NDJSON). `Journal::open_default()` is safe to call multiple times — it reads `.seq` and counts lines, but doesn't interfere with the writer. The daemon processes requests sequentially (one connection at a time), so there's no concurrency concern. This keeps the server code simple with no new shared state.

### 7. Server-side filtering for daemon mode

- **Decision**: Apply `--since`, `--trigger`, and `--selector` filters on the server side in `handle_get_history`, not on the client side.
- **Alternatives considered**: Always returning all entries and filtering on the client.
- **Rationale**: The Varlink protocol sends the full JSON of each entry. Filtering server-side reduces data transfer and is consistent with the `GetHistory` API accepting filter parameters. The filter logic is simple and shared (extracted to a helper function used by both local and daemon code paths). Actually — since the filter logic lives in the CLI crate and the daemon crate is separate, we'll apply filters in each location independently. The daemon applies filters in `handle_get_history` using inline logic, and the CLI applies them in local mode using the same logic in `history.rs`. The filter parameters are passed through Varlink as strings.

### 8. Missing journal directory check

- **Decision**: Before calling `Journal::open_default()` in daemon-free mode, check if the journal directory exists using `Path::exists()`. If not, print the error message and exit with code 1.
- **Alternatives considered**: Relying on `Journal::open()` errors — but it calls `create_dir_all`, so it creates the directory rather than failing.
- **Rationale**: The acceptance criteria require: "No journal found at /var/lib/netfyr/journal/" with exit code 1. Since `Journal::open()` auto-creates the directory, we must check before opening. Read the `NETFYR_JOURNAL_DIR` env var (default `/var/lib/netfyr/journal`) and check existence.

### 9. Text formatting: fixed-width columns

- **Decision**: Use `format!` with fixed-width specifiers for the table header and rows. Column widths: SEQ (5), TIMESTAMP (21), TRIGGER (15), ENTITIES (14), CHANGES (16), OUTCOME (20).
- **Alternatives considered**: Using the `prettytable` or `comfy-table` crate.
- **Rationale**: The table is simple (6 columns, predictable content). A dependency for tabular output is unnecessary. `format!("{:<5} {:<21} {:<15} {:<14} {:<16} {}", ...)` is sufficient.

### 10. Filter ordering: since → trigger → selector → count

- **Decision**: Apply filters in this order: (1) `--since` timestamp comparison, (2) `--trigger` substring match, (3) `--selector` entity name match, (4) `--count` as `.take(n)`.
- **Alternatives considered**: Applying count before filters (spec says count is "number of entries to show", applied last).
- **Rationale**: The spec says to read entries, filter, then limit. Applying `--count` last means `read_recent` must return enough raw entries to survive filtering. We'll call `read_recent` with a large count (e.g., 10,000 — the max before rotation) when filters are active, then filter, then take `count`. When no filters are active, `read_recent(count)` is sufficient.

## File Changes

### 1. `crates/netfyr-cli/src/history.rs` — CREATE

New file implementing the history subcommand. Contains:

- **`HistoryOutputFormat`** enum: `Text` (default), `Json`. Derives `Clone, ValueEnum`.
- **`HistoryArgs`** struct (clap `Args`):
  - `count: usize` — `#[arg(long, short = 'n', default_value = "20")]`
  - `since: Option<String>` — `#[arg(long)]`
  - `trigger: Option<String>` — `#[arg(long)]`
  - `selector: Vec<(String, String)>` — `#[arg(long, short = 's', value_parser = parse_history_selector)]`
  - `show: Option<u64>` — `#[arg(long)]`
  - `output: HistoryOutputFormat` — `#[arg(long, short = 'o', default_value = "text")]`
- **`run_history(args: HistoryArgs) -> Result<ExitCode>`**: Main entry point. Detects daemon vs local mode using `daemon_socket_path()`. Dispatches to `run_history_daemon` or `run_history_local`.
- **`run_history_local(args: &HistoryArgs) -> Result<ExitCode>`**: Checks journal directory existence. Opens `Journal::open_default()`. If `--show` is set, calls `journal.read_entry(seq)` and formats/prints. Otherwise calls `journal.read_recent(...)` with appropriate count, filters entries, formats/prints.
- **`run_history_daemon(client: &mut VarlinkClient, args: &HistoryArgs) -> Result<ExitCode>`**: If `--show` is set, calls `client.get_journal_entry(seq)`. Otherwise calls `client.get_history(...)`. Formats/prints results.
- **`parse_since(s: &str) -> Result<DateTime<Utc>>`**: Parses `30s`, `5m`, `1h`, `7d` relative durations (compute `Utc::now() - duration`) or ISO 8601 timestamps via `DateTime::parse_from_rfc3339`. Returns the cutoff time.
- **`parse_history_selector(s: &str) -> Result<(String, String), String>`**: Accepts only `name=<value>`. Returns error for any other key.
- **`filter_entries(entries: Vec<JournalEntry>, args: &HistoryArgs) -> Result<Vec<JournalEntry>>`**: Applies `--since`, `--trigger`, `--selector` filters in order, then `.take(count)`. Uses `has_filters()` helper to decide whether to read more entries.
- **`matches_trigger(entry: &JournalEntry, trigger_filter: &str) -> bool`**: Serializes the entry's trigger to JSON, extracts the `"type"` field, performs case-insensitive substring match. E.g., "apply" matches "policy_apply", "external" matches "external_change".
- **`matches_selector(entry: &JournalEntry, selectors: &[(String, String)]) -> bool`**: Checks if any `diff.operations[].entity_name` matches the selector name. Since the spec only supports `name=X`, this is a simple string comparison.
- **`format_text_list(entries: &[JournalEntry]) -> String`**: Renders the fixed-width column table. Header: `SEQ  TIMESTAMP             TRIGGER         ENTITIES       CHANGES          OUTCOME`. Each row extracts entity names from `diff.operations`, builds a compact change summary (`+field`, `~field`, `-field`), and formats the outcome.
- **`format_text_detail(entry: &JournalEntry) -> String`**: Renders the full detail view for `--show`. Includes: "Entry #{seq} at {timestamp} UTC", "Trigger: {type} (source: {source})", "Active policies:" list, "Diff:" section with per-field changes, "Outcome:" line, "State after:" section.
- **`format_json_list(entries: &[JournalEntry]) -> Result<String>`**: Serializes entries to a JSON array via `serde_json::to_string_pretty`.
- **`format_json_detail(entry: &JournalEntry) -> Result<String>`**: Serializes single entry to a JSON object via `serde_json::to_string_pretty`.
- **`trigger_display_name(trigger: &Trigger) -> &str`**: Returns human-readable trigger type: "policy-apply", "dhcp-lease", "external", "daemon-startup", "revert".
- **`outcome_summary(outcome: &ApplyOutcome) -> String`**: Returns "applied (N ok, M failed, K skipped)" or "observed".
- **`entities_summary(ops: &[SerializableDiffOp]) -> String`**: Returns comma-separated entity names, with "+N more" truncation if > 3.
- **`changes_summary(ops: &[SerializableDiffOp]) -> String`**: Returns compact change notation: `+field` for "add"/"set" with no current, `~field` for "set" with current, `-field` for "unset". Truncated with `+N more` if too many.
- **`journal_dir_path() -> String`**: Returns `NETFYR_JOURNAL_DIR` env var or default `/var/lib/netfyr/journal`.

### 2. `crates/netfyr-cli/src/lib.rs` — MODIFY

- Add `pub mod history;`
- Add `pub use history::run_history;`
- Extract `daemon_socket_path()` from `query.rs` into this file as `pub(crate) fn daemon_socket_path() -> String`.
- Add `History(history::HistoryArgs)` variant to the `Commands` enum with a doc comment matching the style of `Apply` and `Query`:
  ```
  /// Show journal history of state changes
  ///
  /// Display a log of reconciliation events recorded by the journal.
  /// Shows what changed, when, and why. Supports filtering by time,
  /// trigger type, and entity name.
  ///
  /// If the netfyr daemon is running, history is retrieved via Varlink.
  /// Otherwise, journal files are read directly.
  ```
- Update the top-level `Cli` doc comment to include `history` in the subcommand list.

### 3. `crates/netfyr-cli/src/query.rs` — MODIFY

- Remove the private `daemon_socket_path()` function.
- Import it from `crate::daemon_socket_path` instead.
- No other changes.

### 4. `crates/netfyr-cli/src/main.rs` — MODIFY

- Add `run_history` to the import from `netfyr_cli`.
- Add dispatch arm:
  ```
  Commands::History(args) => match run_history(args).await {
      Ok(code) => code,
      Err(e) => {
          eprintln!("Error: {:#}", e);
          ExitCode::from(2u8)
      }
  },
  ```

### 5. `crates/netfyr-cli/src/netfyr_cli_main.rs` — MODIFY

- Same changes as `main.rs`: add `run_history` import and `Commands::History` dispatch arm.

### 6. `crates/netfyr-varlink/src/client.rs` — MODIFY

Add two new public async methods to `VarlinkClient`:

- **`get_history(&mut self, count: Option<usize>, since: Option<String>, trigger: Option<String>, selector_name: Option<String>) -> Result<Vec<serde_json::Value>, VarlinkError>`**:
  Sends `io.netfyr.GetHistory` with parameters `{count, since, trigger, selector_name}` (omitting `None` values). Extracts `response["entries"]` as a `Vec<serde_json::Value>`. Returns the raw JSON values so the CLI can deserialize them as `JournalEntry` — this avoids adding `netfyr-journal` as a dependency of `netfyr-varlink`.

- **`get_journal_entry(&mut self, seq: u64) -> Result<Option<serde_json::Value>, VarlinkError>`**:
  Sends `io.netfyr.GetJournalEntry` with parameters `{seq}`. Extracts `response["entry"]`. Returns `None` if the value is `null`, otherwise returns `Some(value)`.

Note: The return type is `serde_json::Value` rather than `JournalEntry` to avoid adding `netfyr-journal` as a dependency of `netfyr-varlink`. The CLI deserializes the JSON into `JournalEntry` on its end.

### 7. `crates/netfyr-varlink/src/lib.rs` — MODIFY

No changes needed — the new methods are on `VarlinkClient` which is already re-exported.

### 8. `crates/netfyr-daemon/src/server.rs` — MODIFY

Add two new handler functions and wire them into the dispatch:

- **`handle_get_history(stream, params) -> Result<()>`**:
  1. Parse optional parameters: `count` (default 20), `since` (Option<String>), `trigger` (Option<String>), `selector_name` (Option<String>).
  2. Open `Journal::open_default()`. On error, return `InternalError`.
  3. Determine read count: if any filter is present, read up to 10,000 entries; otherwise read `count`.
  4. Call `journal.read_recent(read_count)`.
  5. Apply filters in order: since (parse with same logic as CLI), trigger (case-insensitive substring on serialized type field), selector_name (match against `diff.operations[].entity_name`).
  6. Take first `count` entries.
  7. Serialize each `JournalEntry` to `serde_json::Value`.
  8. Write success response: `{"entries": [...]}`.

- **`handle_get_journal_entry(stream, params) -> Result<()>`**:
  1. Parse required `seq` parameter (u64). If missing, return `InternalError`.
  2. Open `Journal::open_default()`. On error, return `InternalError`.
  3. Call `journal.read_entry(seq)`.
  4. If `Some(entry)`, serialize to `serde_json::Value` and write `{"entry": value}`.
  5. If `None`, write `{"entry": null}`.

- **Dispatch**: Add two arms to the `match method.as_str()` block in `handle_connection`:
  - `"io.netfyr.GetHistory" => handle_get_history(stream, &params).await`
  - `"io.netfyr.GetJournalEntry" => handle_get_journal_entry(stream, &params).await`

Note: These handlers do NOT need `policy_store`, `factory_manager`, or `reconciler` — they only read the journal. This keeps the `handle_connection` signature unchanged.

## Dependencies

No new crate dependencies are needed.

- `chrono` — already in `netfyr-cli/Cargo.toml`, used for `DateTime<Utc>` in duration parsing and timestamp display.
- `serde_json` — already in `netfyr-cli/Cargo.toml`, used for JSON output formatting.
- `netfyr-journal` — already in `netfyr-cli/Cargo.toml`, provides `Journal`, `JournalEntry`, `Trigger`, etc.
- `netfyr-varlink` — already in `netfyr-cli/Cargo.toml`, provides `VarlinkClient`.
- `colored` — already in `netfyr-cli/Cargo.toml`, may optionally be used for the text table header (but not required).

## Implementation Order

### Step 1: Extract daemon_socket_path to lib.rs

Move `daemon_socket_path()` from `query.rs` to `lib.rs`. Update `query.rs` to import it. Both `main.rs` and `netfyr_cli_main.rs` remain unchanged. Verify compilation.

**Produces**: Compilable state. No behavior change.

### Step 2: Create history.rs with CLI args and local mode

Create `crates/netfyr-cli/src/history.rs` with:
- `HistoryOutputFormat` enum
- `HistoryArgs` struct
- `parse_history_selector` function
- `parse_since` function
- `run_history` entry point (local mode only, daemon mode can return a stub/fallback for now)
- `filter_entries` function
- All text and JSON formatting functions
- Empty journal / missing directory handling

Register the module in `lib.rs` and add dispatch in `main.rs` / `netfyr_cli_main.rs`.

**Produces**: Compilable state. `netfyr history` works in daemon-free mode.

**Depends on**: Step 1 (for `daemon_socket_path`).

### Step 3: Add Varlink client methods

Add `get_history` and `get_journal_entry` methods to `VarlinkClient` in `crates/netfyr-varlink/src/client.rs`.

**Produces**: Compilable state. Client methods available but no server to call yet.

**Depends on**: Nothing (independent of Steps 1-2).

### Step 4: Add daemon server handlers

Add `handle_get_history` and `handle_get_journal_entry` to `crates/netfyr-daemon/src/server.rs`. Wire them into the dispatch.

**Produces**: Compilable state. Daemon can serve history requests.

**Depends on**: Nothing (independent of Steps 1-3, but functionally paired with Step 3).

### Step 5: Wire daemon mode into history CLI

Update `run_history` in `history.rs` to detect daemon mode (try Varlink connect) and call `client.get_history()` / `client.get_journal_entry()`. Deserialize `serde_json::Value` responses into `JournalEntry`.

**Produces**: Compilable state. Full feature complete.

**Depends on**: Steps 2, 3.

## Risks and Mitigations

### 1. Archive entries invisible to history

**Risk**: `Journal::read_recent()` and `read_entry()` only scan `current.ndjson`. Entries rotated to gzip archives are not returned. `--since 7d` may miss entries from rotated files.

**Mitigation**: This is a known limitation of the `Journal` API from SPEC-351. The spec does not mention archive traversal. Document this behavior: the history command shows entries from the current journal file only. Entries older than the rotation threshold (~10,000 entries or 50MB) are not shown. This is acceptable for the initial implementation — archive reading can be added to `Journal` in a future spec.

### 2. Journal directory auto-creation

**Risk**: `Journal::open()` calls `create_dir_all()`, so it creates the directory even when we want to detect "no journal exists."

**Mitigation**: Check `Path::exists()` on the journal directory *before* calling `Journal::open_default()`. Read the `NETFYR_JOURNAL_DIR` env var (default `/var/lib/netfyr/journal`) to determine the path. Only call `Journal::open_default()` if the directory exists.

### 3. Large read_recent count with filters

**Risk**: When filters are active, we call `read_recent(10_000)` to get enough entries to filter. If the journal has 10,000 entries, this reads and parses all of them into memory.

**Mitigation**: 10,000 entries × ~500 bytes each ≈ 5MB of JSON text, ~20MB parsed. This is within acceptable memory bounds for a CLI tool. The `Journal` rotation threshold is 10,000 entries, so this is the theoretical maximum. If performance becomes a concern, streaming/lazy parsing can be added later.

### 4. Trigger substring matching false positives

**Risk**: `--trigger apply` could match both `policy_apply` and hypothetical future `re_apply` variants.

**Mitigation**: The current trigger variants are well-differentiated: `policy_apply`, `dhcp_event`, `external_change`, `daemon_startup`, `revert`. Substring matching is specified by the spec. The risk of false positives with the current variant set is zero. If new variants are added, the matching behavior can be refined.

### 5. Two entry point files (main.rs and netfyr_cli_main.rs)

**Risk**: Forgetting to update one of the two entry points.

**Mitigation**: Both files have identical dispatch logic. Both must be updated. The implementation order explicitly calls out updating both files in Step 2.

### 6. Daemon server journal open failures

**Risk**: `Journal::open_default()` in the server handler could fail (permissions, disk full, etc.).

**Mitigation**: Return a Varlink `InternalError` with the error message. The CLI will display the error. This follows the same pattern as other handler error paths.

## Test Strategy

### Unit tests (in `history.rs`)

- **`parse_since` function**:
  - Relative durations: `"30s"`, `"5m"`, `"1h"`, `"7d"` each produce a `DateTime<Utc>` approximately that duration in the past.
  - ISO 8601: `"2026-04-20T14:00:00Z"` parses to the correct timestamp.
  - Invalid input: `"abc"`, `"5x"`, `""` return errors.
  - Edge case: `"0s"` returns approximately `Utc::now()`.

- **`parse_history_selector` function**:
  - `"name=eth0"` returns `Ok(("name", "eth0"))`.
  - `"type=ethernet"` returns error (only `name` is allowed).
  - `"foo=bar"` returns error.
  - Missing `=` returns error.

- **`matches_trigger` function**:
  - `"apply"` matches `Trigger::PolicyApply { .. }` (whose type is `"policy_apply"`).
  - `"dhcp"` matches `Trigger::DhcpEvent { .. }` (whose type is `"dhcp_event"`).
  - `"external"` matches `Trigger::ExternalChange { .. }`.
  - `"startup"` matches `Trigger::DaemonStartup`.
  - `"revert"` matches `Trigger::Revert { .. }`.
  - `"bogus"` matches none.
  - Case insensitivity: `"APPLY"` matches `policy_apply`.

- **`matches_selector` function**:
  - Entry with `diff.operations[0].entity_name = "eth0"` matches `name=eth0`.
  - Entry with only `eth1` does not match `name=eth0`.
  - Entry with multiple operations, one matching, returns true.
  - Empty operations list returns false.

- **`filter_entries` function**:
  - Filters combine with AND logic.
  - `--count` is applied last.
  - With no filters, returns first `count` entries.

- **Text formatting functions**:
  - `format_text_list` produces correct column headers.
  - `format_text_list` with an entry shows SEQ, timestamp, trigger, entities, changes, outcome.
  - `format_text_detail` includes all sections: entry header, trigger, policies, diff, outcome, state after.
  - `entities_summary` truncates with "+N more" when > 3 entities.
  - `changes_summary` uses `+`, `~`, `-` prefixes correctly.
  - `outcome_summary` formats `Applied` and `Observed` correctly.
  - `trigger_display_name` maps all variants correctly.

- **JSON formatting**:
  - `format_json_list` produces a valid JSON array.
  - `format_json_detail` produces a valid JSON object.

### Unit tests (in `client.rs`)

- `get_history` sends `io.netfyr.GetHistory` method with correct parameters and deserializes the `entries` array from the response.
- `get_journal_entry` sends `io.netfyr.GetJournalEntry` with `seq` parameter.
- `get_journal_entry` returns `None` when server responds with `entry: null`.

### Unit tests (in `server.rs`)

- `handle_get_history` with empty journal returns `entries: []`.
- `handle_get_journal_entry` with valid seq returns the entry.
- `handle_get_journal_entry` with invalid seq returns `entry: null`.
- `handle_get_history` with `count` parameter limits results.
- Unknown method dispatch still returns error (existing test, verify no regression).

### Integration-level tests

- The acceptance criteria scenarios (list, count, filter by time, filter by trigger, filter by entity, combine filters, show detail, show nonexistent, JSON output, empty journal) are primarily tested via unit tests on the formatting and filtering functions, using constructed `JournalEntry` instances.
- Full end-to-end testing (CLI binary invocation with a real journal) is out of scope for this plan — the existing e2e test infrastructure can be extended later.
