# Plan: SPEC-301 — CLI Apply Command

## Approach

The core `netfyr apply` implementation is **complete**. The apply flow in `apply.rs` (~1279 lines) is fully implemented: daemon detection via `NETFYR_SOCKET_PATH`, policy loading with bare-state auto-wrapping, DHCP rejection in daemon-free mode, reconciliation, diff generation, apply, journal write-back, display functions with colored output, and exit code mapping. The `Cli` struct in `lib.rs` already has `subcommand_required = true, arg_required_else_help = true` and uses non-optional `Commands`. All 13 shell integration test scripts exist. There are 30+ unit tests.

**Three gaps remain**, all relating to color control:

1. **`lib.rs`**: Missing `--color` global flag (`ColorMode` enum with `ValueEnum` derive, `color: ColorMode` field on `Cli`).
2. **`main.rs`**: Missing color resolution logic — needs to read `NO_COLOR` env var and `cli.color`, then call `colored::control::set_override()` before dispatching subcommands.
3. **`netfyr_cli_main.rs`**: The alternate binary `netfyr-cli` has a manual `if args().len() == 1 { exit(0) }` guard that bypasses clap and exits 0 instead of 2. This must be fixed to match `main.rs` behavior, and it must also apply the same color resolution logic.

**Why this approach**: The `colored` crate (v2.2.0) already respects `NO_COLOR` and detects TTY status by default. For `--color=auto`, we let `colored`'s built-in behavior handle everything (no `set_override` call needed). For `--color=always`, we call `set_override(true)`. For `--color=never`, we call `set_override(false)`. This means `NO_COLOR` is respected for `auto` mode automatically by `colored`, and overridden by explicit `always`/`never`. However, the spec says `NO_COLOR` takes precedence over `--color` regardless — so if `NO_COLOR` is set, we must call `set_override(false)` even if `--color=always` was passed.

**Alternative considered**: Adding an `atty` or `is-terminal` dependency for explicit TTY detection in `auto` mode. Rejected because `colored` already does this internally — adding another crate would be redundant.

## Design Decisions

1. **Decision**: Add `ColorMode` enum and `color` field to the existing `Cli` struct in `lib.rs`.
   - **Alternatives considered**: (a) Put `ColorMode` in its own file. (b) Put it in `main.rs`.
   - **Rationale**: `lib.rs` is where `Cli` and `Commands` live; keeping `ColorMode` there maintains locality. It must be in the `lib` crate (not `main.rs`) because `Cli` is a public struct used by `xtask` for man page generation. The `color` field must be part of `Cli` for clap to generate correct `--help` output.

2. **Decision**: `NO_COLOR` env var overrides `--color` flag unconditionally.
   - **Alternatives considered**: Let `--color=always` override `NO_COLOR`.
   - **Rationale**: The spec explicitly states: "If the `NO_COLOR` environment variable is set (any value), colors are disabled regardless of the `--color` flag." This follows the https://no-color.org/ convention.

3. **Decision**: For `--color=auto` (default), do NOT call `set_override` — let `colored`'s built-in TTY + `NO_COLOR` detection handle it.
   - **Alternatives considered**: Explicitly detect TTY with `std::io::stdout().is_terminal()` (Rust 1.70+ stable) and call `set_override`.
   - **Rationale**: `colored` 2.x already checks `NO_COLOR` and TTY internally. Calling `set_override` for `auto` would bypass `colored`'s `NO_COLOR` check, forcing us to duplicate that logic. By not calling `set_override`, `colored`'s default behavior is exactly what `auto` means. The only case where `NO_COLOR` must be checked explicitly is when `--color=always` is passed, since `set_override(true)` would override `colored`'s `NO_COLOR` check.

4. **Decision**: Color resolution as a standalone function `resolve_color_mode(mode: &ColorMode)` in `lib.rs`, called from both `main.rs` and `netfyr_cli_main.rs`.
   - **Alternatives considered**: Inline the logic in `main.rs` only.
   - **Rationale**: Both binaries (`netfyr` and `netfyr-cli`) need the same color behavior. A shared function in `lib.rs` avoids duplication. Making it public allows both binaries to call it.

5. **Decision**: Fix `netfyr_cli_main.rs` by removing the `if args().len() == 1` guard entirely.
   - **Alternatives considered**: Change the guard to `exit(2)` and print help manually.
   - **Rationale**: With `subcommand_required = true, arg_required_else_help = true` on `Cli`, clap handles the no-subcommand case correctly (prints help, exits 2). The manual guard pre-empts clap and produces wrong behavior. Removing it lets clap handle it consistently. The rest of the file should mirror `main.rs` exactly (parse, resolve color, dispatch).

6. **Decision**: Export `ColorMode` as public from `lib.rs`.
   - **Rationale**: `netfyr_cli_main.rs` (the `netfyr-cli` binary) imports from `netfyr_cli::*`. The `ColorMode` is embedded in `Cli` via clap's derive, so it must be accessible. Additionally, `xtask` uses `Cli::command()` for man page generation, and the `--color` flag must appear in generated man pages. Public export ensures both use cases work.

## File Changes

### `crates/netfyr-cli/src/lib.rs` — Modify

**What**:

1. Add `use clap::ValueEnum;` to the existing clap imports (or add it to the existing `use clap::{Parser, Subcommand};` line).

2. Define `ColorMode` enum before the `Cli` struct:
   ```
   #[derive(Clone, ValueEnum)]
   pub enum ColorMode {
       Auto,
       Always,
       Never,
   }
   ```

3. Add `color` field to `Cli` struct:
   ```rust
   #[arg(long, global = true, default_value = "auto")]
   pub color: ColorMode,
   ```
   Place it before the `command` field.

4. Add a public function `resolve_color_mode(mode: &ColorMode)` that:
   - Checks if `NO_COLOR` env var is set (any value). If so, calls `colored::control::set_override(false)` and returns.
   - If `mode` is `Always`, calls `colored::control::set_override(true)`.
   - If `mode` is `Never`, calls `colored::control::set_override(false)`.
   - If `mode` is `Auto`, does nothing (lets `colored`'s built-in TTY detection handle it).

5. Add `use colored::control::set_override;` import for the resolve function.

6. Add `pub use` for `ColorMode` and `resolve_color_mode` alongside the existing re-exports.

**Why**: Implements GAP 1 (missing `--color` flag) and GAP 2 (missing color resolution). Placing the enum and resolver in `lib.rs` makes them available to both binary targets and to `xtask`.

### `crates/netfyr-cli/src/main.rs` — Modify

**What**:

1. Add `resolve_color_mode` to the import from `netfyr_cli`.
2. After `let cli = Cli::parse();`, add a call to `resolve_color_mode(&cli.color);` before the `match cli.command` block.

**Why**: Ensures color mode is resolved before any output is produced by subcommand handlers. Must happen after `Cli::parse()` (to access the parsed `--color` value) and before dispatching.

### `crates/netfyr-cli/src/netfyr_cli_main.rs` — Modify

**What**:

1. Remove the `if std::env::args().len() == 1 { println!("netfyr"); std::process::exit(0); }` block (lines 8-11).
2. Add `resolve_color_mode` to the import from `netfyr_cli`.
3. After `let cli = Cli::parse();`, add `resolve_color_mode(&cli.color);` before the match block.

The resulting file should be identical to `main.rs` in structure (parse, resolve color, dispatch).

**Why**: Fixes GAP 3 (wrong exit code 0 for no-args). With the manual guard removed, clap's `SubcommandRequiredElseHelp` handles the no-subcommand case correctly (help + exit 2). Adding color resolution ensures `netfyr-cli` binary has the same color behavior as `netfyr`.

## Dependencies

No new crate dependencies needed. The `colored` crate (already in `Cargo.toml`) provides `colored::control::set_override`. The `std::env::var` function handles `NO_COLOR` checking. No additional imports are required beyond what's already available.

## Implementation Order

1. **Modify `crates/netfyr-cli/src/lib.rs`** — Add `ColorMode` enum, `color` field on `Cli`, and `resolve_color_mode()` function. This is the foundational change; steps 2 and 3 depend on these types being available.

2. **Modify `crates/netfyr-cli/src/main.rs`** — Add `resolve_color_mode(&cli.color)` call after parse. Depends on step 1 for the import. After this step, `cargo build` should succeed and `netfyr` binary has correct color behavior.

3. **Modify `crates/netfyr-cli/src/netfyr_cli_main.rs`** — Remove the args-length guard and add color resolution. Depends on step 1. After this step, both binaries behave correctly.

4. **Verify** — Run `cargo test -p netfyr-cli` (unit tests), `cargo build` (compile both binaries), `cargo clippy -p netfyr-cli` (lint). Then run `make integration-test SPEC=301` to verify all 13 shell integration tests pass. The `301-no-subcommand.sh` test specifically validates that bare `netfyr` exits 2 — this test was failing before step 3 if invoked via the `netfyr-cli` binary, but since tests use `NETFYR_BIN` defaulting to `target/debug/netfyr` (from `main.rs`), it should have been passing already. Step 3 fixes the `netfyr-cli` binary for correctness.

## Risks and Mitigations

1. **Risk**: `colored::control::set_override` is a process-global state setter. Unit tests in `apply.rs` that call display functions will see whatever color state was last set.
   - **Impact**: Low. Unit tests don't call `resolve_color_mode()`, so they get `colored`'s default behavior (which respects `NO_COLOR` and TTY). No unit test assertions depend on ANSI escape codes being present or absent.
   - **Mitigation**: No action needed. If a future test needs to assert on colored output, it can call `set_override` in a test fixture, but that's out of scope.

2. **Risk**: `colored` 2.x might change its `NO_COLOR` handling semantics in a patch release.
   - **Impact**: Unlikely but would affect `auto` mode behavior.
   - **Mitigation**: The version is pinned to `"2"` in Cargo.toml. The `resolve_color_mode` function explicitly checks `NO_COLOR` before calling `set_override(true)` for `Always` mode, so even if `colored` changed its internal behavior, the `NO_COLOR`-overrides-everything guarantee is maintained by our code.

3. **Risk**: `xtask` man page generation might render the `--color` flag differently than expected.
   - **Impact**: Cosmetic only. Man pages might show `--color <COLOR_MODE>` with values `auto`, `always`, `never`.
   - **Mitigation**: This is the correct clap behavior for `ValueEnum`. The help text from the doc comment and the enum variant names produce reasonable man page output. No action needed.

4. **Risk**: The `netfyr_cli_main.rs` removal of the args guard could break some undocumented use case of the `netfyr-cli` binary.
   - **Impact**: Low. The `netfyr-cli` binary is an alternate entry point. The primary binary is `netfyr` from `main.rs`. Making them consistent is the right thing.
   - **Mitigation**: Both binaries will have identical behavior after the change.

5. **Risk**: Existing integration tests run with piped stdout (not a TTY), so `colored`'s auto mode disables colors. If any test greps for ANSI escape sequences, it would fail.
   - **Impact**: None. Checked all 13 test scripts — none grep for ANSI codes. They grep for text content like "mtu", "path not found", "usage", etc.
   - **Mitigation**: No action needed.

## Test Strategy

**Unit tests**: No new unit tests needed. The color resolution logic is a thin wrapper around `colored::control::set_override` — testing it would require process-global state manipulation (setting/unsetting `NO_COLOR` env var) which is unsound in multi-threaded test runners. The existing 30+ unit tests in `apply.rs` continue to validate all apply logic. The `ColorMode` enum is tested transitively by clap's derive validation (invalid values produce parse errors).

**Shell integration tests**: All 13 existing test scripts cover the required acceptance criteria:
- `301-apply-static-mtu.sh` — MTU change in namespace (exit 0)
- `301-apply-with-address.sh` — MTU + address in namespace (exit 0)
- `301-apply-dry-run.sh` — dry-run does not change state (exit 1)
- `301-apply-no-changes.sh` — no changes needed (exit 0)
- `301-conflict-warning.sh` — conflict warnings (exit 1)
- `301-dhcp-policy-no-daemon.sh` — DHCP policy without daemon (exit 2)
- `301-dry-run-no-changes.sh` — dry-run with no changes (exit 0)
- `301-no-args-error.sh` — `netfyr apply` with no paths (exit 2)
- `301-no-subcommand.sh` — bare `netfyr` shows help (exit 2)
- `301-partial-failure.sh` — partial failure (exit 1)
- `301-path-not-found.sh` — nonexistent path (exit 2)
- `301-total-failure.sh` — total failure (exit 2)
- `301-yaml-parse-error.sh` — invalid YAML (exit 2)

No new test scripts are needed. The color flag behavior is best verified manually (since it depends on TTY state which is hard to simulate in shell scripts) or by inspecting the code.

**Behaviors to test in existing tests** (already covered): all exit codes, output messages, kernel state changes, dry-run non-mutation, DHCP rejection, conflict reporting, error messages with file paths.

**Verification command**: `make integration-test SPEC=301` runs all `tests/301-*.sh` scripts.
