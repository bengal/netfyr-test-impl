# SPEC-352: History CLI and Varlink API — Gap Analysis

## Current State

### Journal infrastructure (complete)
`crates/netfyr-journal/` is fully implemented by SPEC-351:
- `JournalEntry` struct with `seq`, `timestamp`, `trigger`, `active_policies`, `diff` (`SerializableDiff`), `state_after` (`SerializableStateSet`), `outcome` (`ApplyOutcome`)
- `Trigger` enum: `PolicyApply { source }`, `DhcpEvent { policy_name, event_kind }`, `ExternalChange { changed_entities }`, `DaemonStartup`, `Revert { target_seq }` — all serialized with snaek_case `type` discriminator
- `ApplyOutcome` enum: `Applied { succeeded, failed, skipped }`, `Observed`
- `PolicySummary` struct: `name`, `factory_type`, `priority`
- `Journal` struct: `open_default()` (reads `NETFYR_JOURNAL_DIR`, defaults to `/var/lib/netfyr/journal`), `open(dir)`, `append()`, `read_recent(count)`, `read_entry(seq)`, `latest_state_for(entity_name)`
- `Journal::open()` calls `create_dir_all` — it **always creates** the journal directory rather than returning an error when missing
- `read_recent()` and `read_entry()` only scan `current.ndjson`, not gzip-compressed archives in `archive/`

### CLI (partial)
`crates/netfyr-cli/` has `apply` and `query` subcommands. The `Commands` enum in `lib.rs` contains only `Apply(apply::ApplyArgs)` and `Query(query::QueryArgs)`. No `history` module exists.

`OutputFormat` in `query.rs` has `Yaml` and `Json` variants; the history command needs `Text` and `Json` (distinct enum, since history's default is `text` not `yaml`).

The daemon-detection pattern in `query.rs` is the reference implementation: read `NETFYR_SOCKET_PATH` env var, attempt `VarlinkClient::connect`, fall back to local on `VarlinkError::ConnectionFailed`.

### Varlink client (partial)
`crates/netfyr-varlink/src/client.rs` exposes `connect`, `submit_policies`, `query`, `dry_run`, `get_status`. No `get_history` or `get_journal_entry` methods exist.

`crates/netfyr-varlink/src/types.rs` has Varlink DTO types for states, policies, diffs, and apply reports. No journal-entry Varlink types exist.

There is no `io.netfyr.varlink` IDL file; the protocol is hand-rolled JSON-over-Unix-socket. The spec mentions one but the implementation does not use it — new methods follow the same manual pattern.

### Daemon server (partial)
`crates/netfyr-daemon/src/server.rs` dispatches `SubmitPolicies`, `Query`, `DryRun`, `GetStatus`. No `GetHistory` or `GetJournalEntry` handlers exist. The daemon currently has no `Journal` reference; it would need one added to serve history via Varlink.

---

## Requirements

1. **New CLI module** `crates/netfyr-cli/src/history.rs` implementing:
   - `HistoryArgs` struct (clap `Args`): `count: usize` (default 20), `since: Option<String>`, `trigger: Option<String>`, `selector: Vec<(String, String)>` (key=value, only `name` key is relevant), `show: Option<u64>`, `output: OutputFormat`
   - `OutputFormat` enum: `Text` (default), `Json`
   - `run_history(args: HistoryArgs) -> Result<ExitCode>`
   - `parse_duration(s: &str) -> Result<DateTime<Utc>>` supporting `30s`, `5m`, `1h`, `7d` and ISO 8601
   - Text list formatter: fixed-width columns SEQ / TIMESTAMP / TRIGGER / ENTITIES / CHANGES / OUTCOME
   - Text detail formatter for `--show <seq>`: full entry layout
   - JSON output: array of `serde_json::Value` (entries serialized as-is from `JournalEntry`) for list; single object for `--show`
   - Daemon-detection: try Varlink `GetHistory` / `GetJournalEntry`, fall back to `Journal::open_default()`
   - Missing journal directory: detect and print `"No journal found at /var/lib/netfyr/journal/"`, exit 1
   - Empty journal: print `"No journal entries found."`, exit 0

2. **CLI registration**: add `History(history::HistoryArgs)` variant to `Commands` enum in `lib.rs`; expose `run_history` from `lib.rs`; dispatch in `main.rs`/`netfyr_cli_main.rs`

3. **Varlink client methods** in `crates/netfyr-varlink/src/client.rs`:
   - `get_history(&mut self, count: Option<usize>, since: Option<String>, trigger: Option<String>, selector_name: Option<String>) -> Result<Vec<VarlinkJournalEntry>, VarlinkError>`
   - `get_journal_entry(&mut self, seq: u64) -> Result<Option<VarlinkJournalEntry>, VarlinkError>`

4. **Varlink DTO types** in `crates/netfyr-varlink/src/types.rs`:
   - `VarlinkJournalEntry` (mirrors `JournalEntry` but with JSON-compatible fields)
   - `VarlinkTrigger`, `VarlinkPolicySummary`, `VarlinkApplyOutcome` (or reuse `JournalEntry`'s serde-derived JSON directly)
   - Conversion `From<&JournalEntry> for VarlinkJournalEntry` (or serialize `JournalEntry` to `serde_json::Value` directly since `JournalEntry` already derives `Serialize`)

5. **Daemon server handlers** in `crates/netfyr-daemon/src/server.rs`:
   - `handle_get_history(stream, params, journal) -> Result<()>`
   - `handle_get_journal_entry(stream, params, journal) -> Result<()>`
   - `Journal` (or `Arc<Mutex<Journal>>` / path) threaded through the server or opened on demand per request

6. **Filtering logic** (in `history.rs`, applied post-read):
   - `--since`: compare `entry.timestamp >= cutoff`
   - `--trigger`: case-insensitive substring match against the trigger's `type` field string
   - `--selector name=X`: check if any `diff.operations[].entity_name == X`
   - `--count`: applied last as a `.take(count)` after all filters

---

## Gap Analysis

| File | Status | Change Required |
|------|--------|-----------------|
| `crates/netfyr-cli/src/history.rs` | **Missing** | Create new file with full history command implementation |
| `crates/netfyr-cli/src/lib.rs` | Exists | Add `pub mod history`, `pub use history::run_history`, add `History(history::HistoryArgs)` to `Commands` |
| `crates/netfyr-cli/src/main.rs` | Exists | Add `Commands::History(args) => run_history(args).await` dispatch arm |
| `crates/netfyr-cli/src/netfyr_cli_main.rs` | Exists | Same dispatch if this is the actual entry point (need to confirm which of main.rs / netfyr_cli_main.rs is the true entry) |
| `crates/netfyr-varlink/src/client.rs` | Exists | Add `get_history` and `get_journal_entry` async methods |
| `crates/netfyr-varlink/src/types.rs` | Exists | Add `VarlinkJournalEntry` and related types (or reuse `JournalEntry` JSON serialization) |
| `crates/netfyr-varlink/src/lib.rs` | Exists | Re-export new Varlink journal types |
| `crates/netfyr-daemon/src/server.rs` | Exists | Add `handle_get_history` and `handle_get_journal_entry` handlers; thread `Journal` access into dispatch |
| `crates/netfyr-daemon/src/main.rs` | Exists | Wire `Journal` into server if not already present |

---

## Integration Points

- **`netfyr-journal::Journal`**: The history command reads journal data via `Journal::open_default()` in daemon-free mode. The daemon's server reads via a shared `Journal` instance (to be added). The journal's `read_recent(count)` and `read_entry(seq)` are the primary APIs; all filtering beyond count happens in the CLI layer.
- **`netfyr-varlink::VarlinkClient::call()`**: The private `call()` method is the single entry point for all Varlink requests. New methods (`get_history`, `get_journal_entry`) follow the same pattern: build a `serde_json::json!({...})` params map, call `self.call("io.netfyr.GetHistory", params)`, extract and deserialize the response field.
- **`netfyr-cli::query::OutputFormat`**: The history command needs its own `OutputFormat` enum (`Text` + `Json`, not `Yaml` + `Json`). It should not reuse `query::OutputFormat` since the defaults and variants differ.
- **`netfyr-cli::query::daemon_socket_path()`**: This function is private to `query.rs`. The history module will need either its own copy or for it to be extracted to a shared `cli_util` module or `lib.rs`.
- **`clap` `Commands` enum**: Adding `History` requires updating the doc-comment in `Cli` as well for consistency with existing `apply` and `query` entries.

---

## Risks

1. **Archive reads not implemented**: `Journal::read_recent()` and `read_entry()` only scan `current.ndjson`. Entries rotated to gzip archives are invisible. The `--since` flag with durations longer than the rotation period (e.g., `--since 7d`) will silently miss archived entries. The spec does not mention archive traversal, but operators may expect it. This is a functional gap that should be clarified before implementation.

2. **Journal directory creation on open**: `Journal::open()` calls `create_dir_all`, so calling it to check for a missing journal directory will create it instead of returning an error. The missing-directory error scenario in the acceptance criteria requires a separate existence check (`Path::exists()`) before opening. Alternatively, `Journal::open_default()` must be called only after verifying the directory exists.

3. **Daemon server journal access**: The daemon's `serve_varlink` function currently receives `PolicyStore`, `FactoryManager`, and `Reconciler`. Adding `Journal` access requires plumbing it through `serve_varlink` — either as an `Arc<Mutex<Journal>>` for shared mutable access, or by reopening the journal read-only per request. The journal uses file-level advisory locks (`fcntl F_WRLCK/F_UNLCK`) so concurrent read access from multiple threads opening the same file may require care.

4. **`VarlinkJournalEntry` type design**: `JournalEntry` already derives `Serialize`/`Deserialize` with well-defined JSON shapes. The simplest approach is to serialize `JournalEntry` directly to `serde_json::Value` in the daemon and deserialize from `serde_json::Value` in the client, avoiding a redundant DTO. However, this couples the Varlink wire format to the journal's internal serialization format. The spec defines separate Varlink types — whether to create distinct types or alias is an implementation decision.

5. **Trigger string matching ambiguity**: The spec says `--trigger external` should match `ExternalChange`. The `Trigger` enum serializes with a `type` field using `snake_case` (e.g., `"external_change"`). Partial, case-insensitive substring matching (e.g., `"external"` matches `"external_change"`) is the stated behavior but must be implemented carefully to avoid false matches (e.g., `"apply"` matching both `"policy_apply"` and potentially other variants containing that substring).

6. **Selector parsing reuse**: `query.rs` defines a private `parse_selector` function. The history command accepts only `name=X` selectors (not `type`, `driver`, `mac`, `pci_path`). A copy or shared utility will be needed; the spec's `HistoryArgs` uses `value_parser = parse_selector` suggesting a new history-specific parser that only accepts `name=`.

7. **`main.rs` vs `netfyr_cli_main.rs`**: The CLI has two potential entry-point files. The actual dispatch location must be verified by reading them before adding the `History` dispatch arm.
