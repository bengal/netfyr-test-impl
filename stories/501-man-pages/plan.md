# SPEC-501: Man Pages — Implementation Plan

## Approach

The story is ~90% complete. The xtask crate exists and works, all six man page files are generated, the hand-written `netfyr-examples.7` is complete, and `netfyr-cli` already exports `Cli` as a hybrid lib+bin crate. Three gaps remain:

1. **`.cargo/config.toml` is missing** — `cargo xtask man` fails with "no such subcommand: xtask" because the cargo alias file doesn't exist.
2. **`append_examples` has no dedicated arms for `history` and `revert`** — These subcommands hit the catch-all arm which emits only "See netfyr-\<name\>(1) for usage details" with zero `.nf` blocks. The spec requires at least two real-world usage examples per subcommand.
3. **Top-level SEE ALSO is incomplete** — The `None` arm of `append_see_also` lists only `netfyr-apply(1)`, `netfyr-query(1)`, `netfyr-examples(7)`, and `netfyr.yaml(5)`. It omits `netfyr-history(1)` and `netfyr-revert(1)`, violating the acceptance criterion that the top-level page references all subcommand man pages.

The fix is purely additive: create one new file (`.cargo/config.toml`), add two match arms to `append_examples`, add two entries to the top-level SEE ALSO, add corresponding unit tests, then regenerate the man pages. No new crates, no structural changes, no new dependencies.

## Design Decisions

1. **Decision**: Add dedicated `Some("history")` and `Some("revert")` arms to `append_examples` rather than making the catch-all smarter.
   - **Alternatives considered**: Auto-generating examples from the clap definitions (e.g., using `Arg::get_id()` to build synthetic command lines). This would produce syntactically correct but contextually meaningless examples.
   - **Rationale**: The spec requires "real-world usage examples." Hand-written examples with realistic flag values (like `--since 1h`, `--trigger apply`, actual sequence IDs) are more useful to readers. The existing `apply` and `query` arms follow this same pattern.

2. **Decision**: Use the exact flag names from `HistoryArgs` and `RevertArgs` in examples.
   - **Alternatives considered**: Inventing plausible flag names without verifying.
   - **Rationale**: Verified from source: `HistoryArgs` has `--count`/`-n`, `--since`, `--trigger`, `--selector`/`-s`, `--show`, `--output`/`-o`. `RevertArgs` has `<target>` (positional u64) and `--dry-run`. Examples must use these exact names.

3. **Decision**: Add `netfyr-history(1)` and `netfyr-revert(1)` to the top-level SEE ALSO section.
   - **Alternatives considered**: Leaving it as-is.
   - **Rationale**: The acceptance criterion states "the SEE ALSO section references all subcommand man pages." The SUBCOMMANDS section already lists all four commands, so SEE ALSO should match.

4. **Decision**: Place `.cargo/config.toml` with only the xtask alias.
   - **Alternatives considered**: Adding other aliases or cargo settings.
   - **Rationale**: The spec only requires the xtask alias. Adding unrelated config exceeds scope.

5. **Decision**: Do not add a `Man::date()` call for idempotency.
   - **Alternatives considered**: Pinning the date to ensure byte-identical regeneration.
   - **Rationale**: Inspecting the generated `.TH` lines (e.g., `.TH netfyr 1  "netfyr " `) shows `clap_mangen 0.2` does not embed a date. Regeneration is already idempotent.

6. **Decision**: Use `netfyr history` (space-separated) in example commands, not `netfyr-history`.
   - **Alternatives considered**: Using the hyphenated form.
   - **Rationale**: Users invoke `netfyr history` as a subcommand. The hyphenated form is only for man page naming conventions. Existing `apply` and `query` examples already use space-separated form.

## File Changes

### 1. `.cargo/config.toml` — CREATE

- **What**: A TOML file with a single `[alias]` section containing `xtask = "run --package xtask --"`.
- **Why**: Without this file, `cargo xtask man` fails. This is the standard xtask pattern required by the spec.

### 2. `xtask/src/main.rs` — MODIFY

#### 2a. `append_examples` function (lines 123-186)

Add two new match arms before the catch-all `Some(other)` at line 178:

- `Some("history")`: Two examples in `.nf`/`.fi` blocks following the existing `.PP` / `.RS 4` / `.nf` / command / `.fi` / `.RE` pattern:
  1. Description: "Show the 10 most recent history entries:" → Command: `netfyr history -n 10`
  2. Description: "Show changes from the last hour triggered by policy apply:" → Command: `netfyr history --since 1h --trigger apply`

- `Some("revert")`: Two examples in `.nf`/`.fi` blocks:
  1. Description: "Revert to the state recorded in journal entry 42:" → Command: `netfyr revert 42`
  2. Description: "Preview what a revert would change without applying:" → Command: `netfyr revert --dry-run 42`

#### 2b. `append_see_also` function (lines 189-220)

In the `None` arm (top-level page, lines 192-198), add two lines after the existing `netfyr-query (1),` entry and before `netfyr-examples (7),`:
```
.BR netfyr-history (1),
.BR netfyr-revert (1),
```

#### 2c. Unit tests in `#[cfg(test)] mod tests` (after line 383)

Add six new tests following existing patterns:

- `test_history_examples_has_at_least_two_nf_blocks`: Call `append_examples(buf, Some("history"))`, assert `.nf` count >= 2.
- `test_history_examples_includes_since_flag`: Assert output contains `--since`.
- `test_revert_examples_has_at_least_two_nf_blocks`: Call `append_examples(buf, Some("revert"))`, assert `.nf` count >= 2.
- `test_revert_examples_includes_dry_run_flag`: Assert output contains `--dry-run`.
- `test_see_also_toplevel_references_netfyr_history_1`: Assert top-level SEE ALSO contains `netfyr-history (1)`.
- `test_see_also_toplevel_references_netfyr_revert_1`: Assert top-level SEE ALSO contains `netfyr-revert (1)`.

### 3. `man/netfyr.1`, `man/netfyr-history.1`, `man/netfyr-revert.1` — REGENERATE

These are regenerated by running `cargo xtask man` after the code changes. They are not manually edited. The regenerated files will contain the updated EXAMPLES and SEE ALSO sections.

## Dependencies

No new crate dependencies needed. The existing `clap_mangen = "0.2"`, `clap = "4"`, and `netfyr-cli` dependencies in `xtask/Cargo.toml` are sufficient.

## Implementation Order

1. **Create `.cargo/config.toml`** — No code dependencies. Enables the `cargo xtask` alias immediately. After this step, `cargo xtask man` runs and produces the existing (gap-containing) output.

2. **Add `history` and `revert` arms to `append_examples` in `xtask/src/main.rs`** — Insert two new match arms before the catch-all `Some(other)`. Requires knowing the exact flag names (already verified above).

3. **Add `netfyr-history` and `netfyr-revert` to the top-level `append_see_also` in `xtask/src/main.rs`** — Small change to the `None` arm. Can be done in the same edit as step 2 since they're in the same file.

4. **Add unit tests in `xtask/src/main.rs`** — Depends on steps 2-3 being complete so the tests pass. Add the six tests described above.

5. **Run `cargo test -p xtask`** to verify all tests pass — Depends on step 4.

6. **Run `cargo xtask man`** to regenerate `man/*.1` files — Depends on steps 1-3. The regenerated files will now pass all acceptance criteria.

Each step results in a compilable state. Steps 2-4 can be done in a single edit pass since they're all in `xtask/src/main.rs`.

## Risks and Mitigations

1. **Risk**: The `history` example uses `--since 1h` but the parser might not accept that format.
   - **Mitigation**: Already verified — `parse_since` handles `"1h"` via `parse_relative_duration` (history.rs:237-244). Also covered by test `test_parse_since_1h_returns_time_1_hour_ago`.

2. **Risk**: The `revert` example uses a bare positional argument `42` but `RevertArgs` might require a flag.
   - **Mitigation**: Already verified — `RevertArgs.target` is a positional `u64` with no `#[arg(long)]` annotation (revert.rs:33). The generated synopsis confirms: `netfyr-revert [--dry-run] [-h|--help] <TARGET>`.

3. **Risk**: Running `cargo xtask man` might produce different output on different runs (idempotency).
   - **Mitigation**: Already verified — generated `.TH` headers don't include dates. `clap_mangen 0.2` output is deterministic. Regeneration is idempotent.

4. **Risk**: The `help` subcommand (auto-generated by clap) also goes through the loop and hits the catch-all.
   - **Mitigation**: The catch-all arm produces a generic fallback, which is acceptable for `help` since it's not a real subcommand users need examples for. The spec only requires examples for `apply`, `query`, `history`, and `revert`.

5. **Risk**: Workspace membership of xtask.
   - **Mitigation**: Already verified — `xtask` is listed in `[workspace] members` in root `Cargo.toml` (line 11).

## Test Strategy

### Unit tests (in `xtask/src/main.rs`)

The existing test infrastructure uses a `render` helper that invokes a troff-section function and returns the output as a UTF-8 string. New tests follow this exact pattern:

- **History examples**: Verify `append_examples(buf, Some("history"))` produces at least 2 `.nf` blocks and includes the `--since` flag.
- **Revert examples**: Verify `append_examples(buf, Some("revert"))` produces at least 2 `.nf` blocks and includes the `--dry-run` flag.
- **Top-level SEE ALSO completeness**: Verify `append_see_also(buf, None)` includes `netfyr-history (1)` and `netfyr-revert (1)`.

### Integration validation (manual / CI)

- Run `cargo xtask man` and verify `man/netfyr-history.1` and `man/netfyr-revert.1` contain real examples (`.nf` blocks with `netfyr history` and `netfyr revert` commands).
- Run `man ./man/netfyr.1` and verify all four subcommands appear in SEE ALSO.
- Run `man ./man/netfyr-history.1` and `man ./man/netfyr-revert.1` and verify they render without troff warnings.
- Run `cargo xtask man` twice and diff the output to confirm idempotency.

No new test infrastructure, fixtures, or mocks are needed.
