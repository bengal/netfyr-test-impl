# Plan: SPEC-352 — History CLI and Varlink API (Gap Closure)

## Approach

The core implementation of `netfyr history` is already in place: CLI args, dual-mode operation, filtering, text/JSON formatting, Varlink client methods, and daemon server handlers all exist and work. This plan closes the remaining gaps between the current implementation and the spec.

There are seven gaps, falling into three categories: (1) text output correctness — column order, terminal-width truncation, list-field notation, and color (GAPs 1-4), (2) Varlink IDL completeness (GAP-7), and (3) test coverage for the Varlink client and daemon server (GAPs 5-6).

The text output gaps (1-4) are all localized to `crates/netfyr-cli/src/history.rs`, specifically `format_text_list`, `changes_summary`, and `format_text_detail`. The approach is to fix these functions in-place rather than restructure, since the existing code is well-organized. For terminal width detection (GAP-2), we add the `terminal_size` crate — the alternative of raw ioctl via `libc` works but `terminal_size` is 50 lines of safe code with zero transitive dependencies, already battle-tested across platforms, and saves us from writing unsafe ioctl calls. For color (GAP-4), we use the `colored` crate already in `Cargo.toml`, applying color via `Colorize` trait methods. The color must be applied carefully: ANSI escape sequences have nonzero byte length but zero display width, so column-width calculations in `format_text_list` must measure display width (without escapes) but emit the colored string. The simplest approach is to compute and truncate the CHANGES string *before* colorizing it, then apply color as a final pass. This avoids the complexity of stripping escapes for width measurement.

The Varlink IDL gap (GAP-7) is documentation-only — the wire protocol is hand-rolled JSON, not generated from the IDL file. We add the missing method declarations and error type to make the `.varlink` file accurately describe the implemented API.

## Design Decisions

### 1. Terminal width: add `terminal_size` crate

- **Decision**: Add `terminal_size = "0.4"` to `netfyr-cli/Cargo.toml`.
- **Alternatives considered**: (a) Raw `libc::ioctl` with `TIOCGWINSZ` — requires `unsafe`, more code, Linux-only without abstraction. (b) `std::io::IsTerminal` for TTY detection + hardcoded 120 — misses the "use actual terminal width" requirement. (c) Reading `$COLUMNS` env var — unreliable, not always set.
- **Rationale**: `terminal_size` is minimal (no transitive deps beyond `libc` which is already in the dep tree), safe, cross-platform, and handles the exact case we need: "terminal width or 120 if not a TTY." One function call replaces ~15 lines of unsafe ioctl code.

### 2. Color application order: colorize after truncation

- **Decision**: In `format_text_list`, compute the CHANGES string as plain text, measure its display width, truncate if needed, then apply color as a post-processing step.
- **Alternatives considered**: Colorizing inline during `changes_summary` construction, then stripping ANSI codes for width measurement.
- **Rationale**: Colorizing-then-stripping is error-prone (must correctly handle all escape sequences) and wasteful (build colored string, strip it, rebuild if truncated). Computing plain text first is simpler and guarantees width accuracy. The color pass is a simple regex-free replacement of `+`, `~`, `-` prefixes.

### 3. List field detection: check JSON value type

- **Decision**: In `changes_summary`, detect list fields by checking if `current` or `desired` in `SerializableFieldChange` is a `serde_json::Value::Array`. When detected, count additions and removals and render as `field(+N)`, `field(-N)`, or `field(+N,-M)`.
- **Alternatives considered**: Hard-coding known list field names (`addresses`, `routes`).
- **Rationale**: Checking `is_array()` on the JSON value is robust and automatically handles any future list-typed fields without code changes. The spec says list fields use count notation — the only reliable signal for "is this a list field" is whether the serialized value is an array. Hard-coding field names would require maintenance when new entity types are added.

### 4. Color in format_text_detail: colorize diff prefixes

- **Decision**: Apply color to the `+`, `~`, `-` prefixes in the diff section of `format_text_detail`, and to the `+`/`~`/`-` field-level prefixes. Use `colored::Colorize` methods: `.green()`, `.red()`, `.yellow()`.
- **Alternatives considered**: Not colorizing detail view (spec explicitly says "Diff output in `--show` also uses colors when enabled").
- **Rationale**: The spec explicitly requires color in both list and detail views. The `colored` crate respects `colored::control::set_override` which is already configured by `resolve_color_mode()` in `main.rs`, so colors are automatically disabled when `--color=never` or `NO_COLOR` is set.

### 5. Changes column width calculation

- **Decision**: In `format_text_list`, compute the total width of all fixed columns (SEQ=5, TIMESTAMP=21, TRIGGER=15, ENTITIES=14, OUTCOME=16, plus 5 inter-column spaces = 76 chars), subtract from the terminal width (or 120), and use the remainder as the max width for CHANGES. If the CHANGES string exceeds this, truncate and append `...`.
- **Alternatives considered**: Using a fixed width for CHANGES (the current approach with count-based truncation).
- **Rationale**: The spec says "CHANGES is placed last so it can use all remaining terminal width." The current implementation uses CHANGES as a middle column with a fixed 16-char width, which both violates the column order spec and wastes space. Placing CHANGES last and computing available width dynamically matches the spec exactly.

### 6. Varlink IDL: use `object` for journal types

- **Decision**: Declare `GetHistory` and `GetJournalEntry` methods in the `.varlink` file using `object` for the entry type rather than defining the full JournalEntry type hierarchy.
- **Alternatives considered**: Defining `JournalEntry`, `Trigger`, `PolicySummary`, `DiffSummary`, etc. types in the IDL.
- **Rationale**: The wire format serializes `JournalEntry` directly via serde. The IDL is documentation-only (not parsed at runtime). Defining parallel types in the IDL would be verbose and could drift from the serde representation. Using `object` is honest about what the wire format actually is: opaque JSON objects whose schema is defined by the Rust `JournalEntry` struct.

## File Changes

### 1. `crates/netfyr-cli/Cargo.toml` — modify

- **What**: Add `terminal_size = "0.4"` to `[dependencies]`.
- **Why**: GAP-2 requires querying terminal width. This crate provides a safe, minimal API for that.

### 2. `crates/netfyr-cli/src/history.rs` — modify

#### GAP-1: Fix column order in `format_text_list`

- **What**: Swap OUTCOME and CHANGES in the header format string and in the per-row format string. The header should be `SEQ  TIMESTAMP  TRIGGER  ENTITIES  OUTCOME  CHANGES` with CHANGES as the last, variable-width column. Change from using a fixed-width specifier for CHANGES to a dynamic-width approach: render fixed columns first with fixed widths, then append CHANGES at the end with no width specifier.
- **Why**: Spec requires `SEQ, TIMESTAMP, TRIGGER, ENTITIES, OUTCOME, CHANGES` order. CHANGES must be last so it can use remaining terminal width.

#### GAP-2: Terminal width truncation of CHANGES

- **What**: Modify `format_text_list` to:
  1. Import `terminal_size::terminal_size` and `terminal_size::Width`.
  2. At the start of the function, determine the available width: call `terminal_size()`, use the width if available, otherwise default to 120.
  3. Compute the fixed-column overhead: SEQ(5) + space + TIMESTAMP(21) + space + TRIGGER(15) + space + ENTITIES(14) + space + OUTCOME(16) + space = 76 chars.
  4. Compute `max_changes_width = terminal_width - 76`. Clamp to a minimum of 10 (so there's always some space for CHANGES).
  5. After computing the `changes` string for each row, check its `len()`. If it exceeds `max_changes_width`, truncate to `max_changes_width - 3` chars and append `...`.
  6. The header's CHANGES column does not need a width specifier since it's the last column.
- **Why**: Spec requires truncation with `...` when CHANGES would exceed terminal width.

#### GAP-3: List field notation in `changes_summary`

- **What**: Modify the field-change loop inside `changes_summary` (the `"modify"` / `_` match arm, around current line 543-550). For each `SerializableFieldChange`:
  1. Check if `fc.current` or `fc.desired` is a `serde_json::Value::Array`.
  2. If yes, this is a list field. Count additions and removals:
     - If `current` is `None` (or not an array) and `desired` is an array: all elements are additions. Render as `field(+N)`.
     - If `current` is an array and `desired` is `None` (or not an array, i.e. `unset`): all elements are removals. Render as `field(-N)`.
     - If both are arrays: additions = `desired.len() - overlap`, removals = `current.len() - overlap`, where overlap is the count of elements present in both (using simple equality). Render as `field(+A,-R)`, omitting zero counts. If both are zero, skip (no visible change).
  3. If no, keep the existing scalar notation: `+field`, `~field`, `-field`.
- **Why**: Spec defines separate notation for list fields: `addr(+2)`, `addr(-1)`, `addr(+1,-1)`. The current code treats all fields as scalar.

**Note on list overlap computation**: Since `serde_json::Value` implements `PartialEq`, we can count overlap by iterating `current` elements and checking if each appears in `desired`. This is O(n*m) but list fields are small (typically 1-5 elements), so this is fine.

#### GAP-4: Color support

- **What**: Add `use colored::Colorize;` import. Modify two functions:

  **In `changes_summary`**: After building each change notation string, apply color to the prefix:
  - Strings starting with `+` (additions): apply `.green()` to the `+` character (or the full `+field` token).
  - Strings starting with `~` (modifications): apply `.yellow()`.
  - Strings starting with `-` (removals): apply `.red()`.
  - For list notation like `field(+N,-M)`: colorize the `+N` part green and `-M` part red.

  However, per Design Decision #2, color is applied *after* width measurement for the CHANGES column in `format_text_list`. So `changes_summary` should return **plain text**, and a new helper function `colorize_changes(plain: &str) -> String` applies color. `format_text_list` calls `changes_summary` to get plain text, measures/truncates, then calls `colorize_changes` on the (possibly truncated) result before appending to the output line.

  **In `format_text_detail`**: Apply color to the diff section prefix characters:
  - Line `"  + ethernet eth0\n"` -> colorize `+` green.
  - Line `"  ~ ethernet eth0\n"` -> colorize `~` yellow.
  - Line `"  - ethernet eth0\n"` -> colorize `-` red.
  - Field lines `"      +mtu: 9000"` -> colorize `+` green.
  - Field lines `"      ~mtu: 1500 -> 9000"` -> colorize `~` yellow.
  - Field lines `"      -mtu: 1500"` -> colorize `-` red.

- **Why**: Spec requires `+` green, `-` red, `~` yellow in CHANGES column and diff output. The `colored` crate is already a dependency and respects the global override set by `resolve_color_mode()`.

**Implementation detail for `colorize_changes`**: This function takes a plain-text changes string (e.g., `"~mtu, +addr, -carrier"`) and returns a colorized version. It splits on `, `, applies color to each token based on its first character, and rejoins. For list notation tokens like `addr(+2,-1)`, it colorizes the `+2` portion green and `-1` portion red. The function should handle the `...` truncation suffix (leave it uncolored) and the `+N more` suffix (leave uncolored). Edge cases: `+entity`, `-entity`, `+N entities` should be colorized green/red respectively.

### 3. `crates/netfyr-varlink/src/io.netfyr.varlink` — modify

- **What**: Add the following declarations after the existing `method GetStatus`:

  ```
  method GetHistory(count: ?int, since: ?string, trigger: ?string, selector_name: ?string) -> (entries: []object)

  method GetJournalEntry(seq: int) -> (entry: ?object)

  method Revert(target_seq: int, dry_run: bool) -> (report: ApplyReport, entry_timestamp: string)
  ```

  And add a new error type after the existing `error InternalError`:

  ```
  error EntryNotFound (reason: string)
  ```

- **Why**: GAP-7. The IDL file documents the Varlink API contract. These methods and the error type are already implemented in the client and server but missing from the IDL.

### 4. `crates/netfyr-varlink/src/client.rs` — modify (tests only)

- **What**: Add unit tests to the `#[cfg(test)] mod tests` block using the existing `spawn_mock_server` pattern:

  - **`test_get_history_sends_correct_method_and_parameters`**: Spawn mock server with `{"entries": [...]}` response. Call `client.get_history(Some(10), Some("1h".into()), Some("apply".into()), Some("eth0".into()))`. Verify the request has `method: "io.netfyr.GetHistory"` and `parameters` contains `count: 10`, `since: "1h"`, `trigger: "apply"`, `selector_name: "eth0"`.

  - **`test_get_history_returns_entries_array`**: Spawn mock server with `{"entries": [{"seq": 1}, {"seq": 2}]}`. Call `client.get_history(None, None, None, None)`. Verify result is `Ok` and contains 2 elements.

  - **`test_get_history_omits_none_parameters`**: Spawn mock server. Call `client.get_history(None, None, None, None)`. Verify the request parameters object does not contain `count`, `since`, `trigger`, or `selector_name` keys.

  - **`test_get_journal_entry_returns_some_when_entry_present`**: Spawn mock server with `{"entry": {"seq": 42, "timestamp": "..."}}`. Call `client.get_journal_entry(42)`. Verify result is `Ok(Some(value))` and `value["seq"] == 42`.

  - **`test_get_journal_entry_returns_none_when_entry_is_null`**: Spawn mock server with `{"entry": null}`. Call `client.get_journal_entry(9999)`. Verify result is `Ok(None)`.

  - **`test_get_journal_entry_sends_correct_method_and_seq`**: Spawn mock server. Call `client.get_journal_entry(42)`. Verify request has `method: "io.netfyr.GetJournalEntry"` and `parameters.seq == 42`.

- **Why**: GAP-5. These methods have no test coverage. The tests follow the same `spawn_mock_server` / `spawn_error_server` pattern used by the existing tests.

### 5. `crates/netfyr-daemon/src/server.rs` — modify (tests only)

- **What**: Add unit tests to the `#[cfg(test)] mod tests` block. These tests use the `make_stream_pair()` helper already present. Note: `handle_get_history` and `handle_get_journal_entry` call `Journal::open_default()`, which reads from `/var/lib/netfyr/journal` (or `NETFYR_JOURNAL_DIR`). For unit tests, we can set `NETFYR_JOURNAL_DIR` to a temp directory.

  - **`test_handle_get_journal_entry_missing_seq_returns_error`**: Call `handle_get_journal_entry` with `params = {}` (no `seq`). Read response and verify it's an error with `"missing or invalid 'seq' parameter"`.

  - **`test_handle_get_journal_entry_with_valid_seq_returns_entry_or_null`**: Set `NETFYR_JOURNAL_DIR` to a temp dir, create a `Journal` and append one entry. Call `handle_get_journal_entry` with `params = {"seq": 1}`. Verify response has `entry` field that is not null. Then call with `params = {"seq": 9999}` and verify `entry` is null.

  - **`test_handle_get_history_returns_entries_array`**: Set `NETFYR_JOURNAL_DIR` to a temp dir, create a `Journal` and append 3 entries. Call `handle_get_history` with `params = {"count": 10}`. Verify response has `entries` as an array with 3 elements.

  - **`test_handle_get_history_with_count_limits_results`**: Set `NETFYR_JOURNAL_DIR` to a temp dir with 5 entries. Call with `params = {"count": 2}`. Verify `entries` array has exactly 2 elements.

- **Why**: GAP-6. The two new handlers have zero test coverage. The existing test suite covers all other handlers.

## Dependencies

| Crate | Version | Justification |
|-------|---------|---------------|
| `terminal_size` | `0.4` | Query terminal width for CHANGES column truncation (GAP-2). No std equivalent. Only transitive dep is `libc` which is already in the dep tree. |

No other new dependencies needed. All other crates (`colored`, `chrono`, `serde_json`, `netfyr-journal`, `netfyr-varlink`) are already in `Cargo.toml`.

## Implementation Order

### Step 1: Fix column order in `format_text_list` (GAP-1)

Swap OUTCOME and CHANGES in the header and row format strings in `format_text_list`. CHANGES becomes the last column with no fixed-width specifier.

**Produces**: Compilable state. Column order matches spec. Existing tests may need minor updates if they assert on column position.

### Step 2: Add `terminal_size` dependency and implement CHANGES truncation (GAP-2)

Add `terminal_size = "0.4"` to `Cargo.toml`. Modify `format_text_list` to query terminal width, compute available CHANGES width, and truncate with `...`.

**Produces**: Compilable state. CHANGES column respects terminal width.

**Depends on**: Step 1 (CHANGES must already be the last column).

### Step 3: Implement list field notation in `changes_summary` (GAP-3)

Modify the field-change processing in `changes_summary` to detect array-typed values and render count notation.

**Produces**: Compilable state. List fields use `field(+N,-M)` notation.

**Independent of**: Steps 1-2 (changes_summary is called by format_text_list but the notation change is orthogonal to column layout).

### Step 4: Implement color support (GAP-4)

Add `colorize_changes` helper. Modify `format_text_list` to colorize CHANGES after truncation. Modify `format_text_detail` to colorize diff prefixes.

**Produces**: Compilable state. Color output when enabled.

**Depends on**: Steps 1-2 (must colorize after truncation to avoid ANSI width issues). Step 3 (list notation tokens need color rules).

### Step 5: Update Varlink IDL (GAP-7)

Add `GetHistory`, `GetJournalEntry`, `Revert` methods and `EntryNotFound` error to `io.netfyr.varlink`.

**Produces**: Compilable state (IDL is not compiled). API contract documented.

**Independent of**: All other steps.

### Step 6: Add Varlink client tests (GAP-5)

Add 6 unit tests to `crates/netfyr-varlink/src/client.rs`.

**Produces**: Compilable state. Tests pass.

**Independent of**: Steps 1-5 (tests exercise existing client methods).

### Step 7: Add daemon server tests (GAP-6)

Add 4 unit tests to `crates/netfyr-daemon/src/server.rs`.

**Produces**: Compilable state. Tests pass.

**Independent of**: Steps 1-6 (tests exercise existing server handlers).

## Risks and Mitigations

### 1. ANSI escape sequences in width calculations

**Risk**: If color is applied before width measurement, the ANSI escape bytes (e.g., `\x1b[32m`) inflate the string length, causing premature truncation.

**Mitigation**: Design Decision #2 mandates computing and truncating the CHANGES string as plain text first, then colorizing. The `changes_summary` function returns plain text; `colorize_changes` is a separate post-processing step called after truncation. This completely eliminates the ANSI-width problem.

### 2. List field overlap computation correctness

**Risk**: Counting list element overlap via `serde_json::Value::eq` could produce wrong results if the same logical value has different JSON representations (e.g., `1` vs `1.0`).

**Mitigation**: `netfyr-state::Value` serializes deterministically via serde — integers are always integers, IPs are always strings with consistent formatting. Round-trip through `value_to_json` is tested. The JSON values in `SerializableFieldChange.current` and `.desired` are produced by the same serializer, so representation is consistent.

### 3. `terminal_size` crate version compatibility

**Risk**: Version `0.4` may have breaking changes or be unavailable.

**Mitigation**: `terminal_size 0.4` is the current stable release as of early 2026. The API surface we use is one function: `terminal_size() -> Option<(Width, Height)>`. This API has been stable since 0.1. If 0.4 is unavailable, 0.3 has the same API.

### 4. Server test environment variable isolation

**Risk**: Tests that set `NETFYR_JOURNAL_DIR` could interfere with each other under parallel execution.

**Mitigation**: The existing CLI history tests already use this pattern with an `ENV_MUTEX`. Server tests should follow the same pattern: use a `Mutex<()>` guard around env var manipulation. Each test creates its own temp directory for journal data.

### 5. Color in non-TTY environments (CI)

**Risk**: Tests that assert on colorized output could fail in CI where the terminal is not a TTY, because `colored` auto-disables colors for non-TTY output.

**Mitigation**: Tests for color output should either: (a) set `colored::control::set_override(true)` before testing and restore after, or (b) test the `colorize_changes` function directly after forcing color on. The existing color tests in `lib.rs` already follow pattern (a). Tests that assert on plain-text output (like the existing `format_text_list` tests) are unaffected.

### 6. Truncation edge case: CHANGES fits exactly

**Risk**: Off-by-one in truncation: if CHANGES is exactly `max_width` chars, it should NOT be truncated. If it's `max_width + 1`, it should be truncated to `max_width - 3` + `...`.

**Mitigation**: The condition is `if changes.len() > max_changes_width`. When `len() == max_changes_width`, no truncation. When `len() > max_changes_width`, truncate to `max_changes_width - 3` and append `...` (total = `max_changes_width`). If `max_changes_width < 3`, just show `...` (3 chars).

## Test Strategy

### Unit tests for GAP-1 (column order)

- Verify the header line has columns in order: SEQ, TIMESTAMP, TRIGGER, ENTITIES, OUTCOME, CHANGES.
- Verify that CHANGES appears after OUTCOME in data rows.
- Existing test `test_format_text_list_contains_header_with_all_column_names` verifies presence but not order. Add a new test that checks OUTCOME appears before CHANGES in the header string (by comparing `find()` positions).

### Unit tests for GAP-2 (truncation)

- Create an entry with a very long CHANGES string (many field changes). Call `format_text_list`. Verify no output line exceeds 120 chars (assuming non-TTY fallback).
- Verify that truncated CHANGES ends with `...`.
- Verify that short CHANGES is not truncated (no `...` suffix).

### Unit tests for GAP-3 (list field notation)

- Create a `SerializableDiffOp` with `field_changes` containing a field where `current = [a, b]` and `desired = [a, b, c]` (one addition). Verify `changes_summary` produces `field(+1)`.
- Field where `current = [a, b, c]` and `desired = [a]` (two removals). Verify `field(-2)`.
- Field where `current = [a, b]` and `desired = [b, c]` (one added, one removed). Verify `field(+1,-1)`.
- Field where both current and desired are non-array (scalar). Verify `~field` notation (unchanged behavior).
- Mixed entry with both scalar and list changes: verify both notations coexist.

### Unit tests for GAP-4 (color)

- Force colors on with `colored::control::set_override(true)`. Call `colorize_changes("+mtu")`. Verify result contains ANSI green escape. Call `colorize_changes("~mtu")`. Verify yellow. Call `colorize_changes("-mtu")`. Verify red.
- Verify `format_text_detail` diff section contains ANSI codes when colors are enabled.
- Restore override after each test.

### Unit tests for GAP-5 (Varlink client)

6 tests as described in File Changes section 4. All use the existing `spawn_mock_server` / `spawn_error_server` infrastructure.

### Unit tests for GAP-6 (daemon server)

4 tests as described in File Changes section 5. Use `make_stream_pair()` and `NETFYR_JOURNAL_DIR` with temp directories.

### No new integration tests needed

The Varlink IDL update (GAP-7) is documentation-only and does not require tests. The existing acceptance-criteria tests in `history.rs` already cover the behavioral requirements.
