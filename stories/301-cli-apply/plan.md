# Plan: SPEC-301 — CLI Apply Command

## Approach

The `netfyr apply` implementation is **nearly complete**. The apply flow logic in `apply.rs` (1033 lines) is fully implemented: daemon detection via `NETFYR_SOCKET_PATH`, policy loading with bare-state auto-wrapping, DHCP rejection in daemon-free mode, reconciliation, diff generation, apply, display functions, and exit code mapping. All 8 shell integration tests already exist and cover the spec's acceptance criteria. There are 30+ unit tests covering exit codes, policy loading, and DHCP rejection.

**Three gaps remain**, all in the CLI entry-point layer:

1. **`lib.rs`**: The `Cli` struct uses `command: Option<Commands>` without `subcommand_required`/`arg_required_else_help` attributes. The spec requires that running bare `netfyr` prints usage help and exits with code 2. Without these clap attributes, clap doesn't enforce this behavior — instead the `None` match arm in `main.rs` silently exits 0.

2. **`main.rs`**: The `None =>` arm prints `"netfyr"` and returns `ExitCode::from(0u8)`. Once `lib.rs` is fixed to make the subcommand required, this arm becomes unreachable and must be removed.

3. **Missing shell test**: The AC scenario "No subcommand shows usage help, exit code 2" has no corresponding `301-no-subcommand.sh`. The existing `301-no-args-error.sh` tests `netfyr apply` with no paths (a different clap error path).

**Why this approach over alternatives**: The fix uses clap's built-in `SubcommandRequiredElseHelp` policy, which is the idiomatic way to handle "no subcommand" in clap. The alternative — keeping `Option<Commands>` and manually printing help in the `None` arm — would duplicate clap's help rendering logic and is more fragile. The clap approach also guarantees the correct exit code (2) without any manual plumbing.

**xtask compatibility**: `xtask/src/main.rs` calls `netfyr_cli::Cli::command()` via clap's `CommandFactory` trait (line 56). This returns a `clap::Command` and does not access the `command` field directly. Changing `Option<Commands>` to `Commands` has zero impact on xtask.

## Design Decisions

1. **Decision**: Change `command: Option<Commands>` to `command: Commands` and add `subcommand_required = true, arg_required_else_help = true`.
   - **Alternatives considered**: Keep `Option<Commands>` and fix the `None` arm to call `Cli::command().print_help()` and return exit code 2.
   - **Rationale**: The spec explicitly shows the clap derive approach with non-optional `Commands`. Making it non-optional is simpler — it eliminates a code path entirely (the `None` arm in `main.rs`). Clap handles help rendering and exit code 2 automatically via `SubcommandRequiredElseHelp`. The alternative would require manual help rendering and explicit exit code management.

2. **Decision**: Remove the `None =>` arm from `main.rs` rather than converting it.
   - **Alternatives considered**: Keep the arm with `unreachable!()` for safety.
   - **Rationale**: Once `command` is `Commands` (not `Option<Commands>`), the match is exhaustive over `Commands::Apply` and `Commands::Query` — there is no `None` variant to match. The compiler enforces this. Adding `unreachable!()` is unnecessary noise.

3. **Decision**: Remove `Some()` wrappers from the remaining match arms.
   - **Rationale**: With `command: Commands`, the match is directly on `Commands::Apply(args)` and `Commands::Query(args)`, not `Some(Commands::Apply(args))`. This is a required syntactic change.

4. **Decision**: Add `301-no-subcommand.sh` shell test.
   - **Alternatives considered**: Rely solely on unit tests.
   - **Rationale**: The spec's acceptance criteria explicitly lists "No subcommand shows usage help, exit code 2" as a scenario. Shell integration tests are the verification mechanism for CLI behavior. Unit tests cannot test the clap parse → exit code path through `main()`. The existing `301-no-args-error.sh` tests a different scenario (`netfyr apply` with no paths).

5. **Decision**: The dry-run exit code 1 (when changes exist) is intentional and correct.
   - **Rationale**: `apply.rs:139` returns `ExitCode::from(1)` for non-empty dry-run diffs. This lets scripts detect "something would change" via exit code without parsing output. The spec AC only specifies exit 0 for "no changes" dry-run, and is silent about the "changes pending" case, so exit 1 is a valid choice. The existing `301-apply-dry-run.sh` test already asserts this.

## File Changes

### `crates/netfyr-cli/src/lib.rs` — Modify

**What**: Two changes to the `Cli` struct:

1. Add `#[command(subcommand_required = true, arg_required_else_help = true)]` attribute to the `Cli` struct, alongside the existing `#[command(name = "netfyr", ...)]` attribute.
2. Change `pub command: Option<Commands>` to `pub command: Commands`.

The `#[derive(Parser)]`, doc comments, and `Commands` enum remain unchanged.

**Why**: The spec requires that `netfyr` with no subcommand prints usage help and exits 2. Clap's `SubcommandRequiredElseHelp` policy provides this behavior automatically. Making `command` non-optional is the idiomatic companion change — it means the parsed `Cli` always has a valid subcommand, eliminating the `None` case in `main.rs`.

### `crates/netfyr-cli/src/main.rs` — Modify

**What**: Simplify the `match cli.command` block:

1. Remove the `None => { ... }` arm entirely.
2. Change `Some(Commands::Apply(args))` to `Commands::Apply(args)`.
3. Change `Some(Commands::Query(args))` to `Commands::Query(args)`.

The error handling within each arm (`match run_apply(args).await { ... }`) remains identical.

**Why**: With `command: Commands` (non-optional), the match is directly on `Commands` variants. The `None` arm is gone because `Option` is gone. This eliminates the incorrect exit-0 behavior for bare `netfyr` invocation.

### `tests/301-no-subcommand.sh` — Create

**What**: Shell script that validates running bare `netfyr` (no subcommand) prints help and exits 2.

Structure (following established `301-*.sh` conventions):
- Shebang, `set -euo pipefail`
- Set `SCRIPT_DIR`, source `helpers.sh`
- Set `NETFYR_BIN` with fallback to `$SCRIPT_DIR/../target/debug/netfyr`
- Check binary exists with `[[ ! -x "$NETFYR_BIN" ]]` then `echo "FAIL: ..." >&2; exit 1`
- Export `NETFYR_SOCKET_PATH=/nonexistent`
- NO `netns_setup` (this test doesn't touch network state)
- Run `"$NETFYR_BIN"` with no arguments, capture exit code using `EXIT_CODE=0; "$NETFYR_BIN" 2>&1 || EXIT_CODE=$?` pattern
- Assert `EXIT_CODE` is 2
- Assert captured output contains "Usage" or "usage" (clap's help output)
- Print `PASS: 301-no-subcommand`

**Why**: Satisfies AC scenario "No subcommand shows usage help, exit code 2". This cannot be tested by existing scripts — `301-no-args-error.sh` tests `netfyr apply` with no paths, which is a different clap error path. This test validates the top-level `SubcommandRequiredElseHelp` behavior.

## Dependencies

No new crate dependencies needed. All existing dependencies (`clap`, `tokio`, `anyhow`, `colored`, `netfyr-*` crates) are already in `crates/netfyr-cli/Cargo.toml`.

## Implementation Order

1. **Modify `crates/netfyr-cli/src/lib.rs`** — Add clap attributes and change `Option<Commands>` to `Commands`. This is the foundational change; without it, step 2 won't compile (the match arms reference `Some(...)` patterns on a non-optional type).

2. **Modify `crates/netfyr-cli/src/main.rs`** — Remove `None` arm and `Some()` wrappers. This depends on step 1 — the field type must be `Commands` for the simplified match to compile. After this step, `cargo build` should succeed.

3. **Create `tests/301-no-subcommand.sh`** — Independent of steps 1-2 at the code level, but logically depends on them for correct behavior. Must be created and made executable (`chmod +x`).

4. **Verify** — Run `cargo test -p netfyr-cli` to confirm unit tests pass, then `cargo build` to produce the binary. Steps 1-2 are a compile-time change with no logic changes to `apply.rs`, so existing unit tests should pass unchanged. If `make integration-test SPEC=301` is available, run it to verify all 9 shell tests (8 existing + 1 new) pass.

## Risks and Mitigations

1. **Risk**: Clap's `SubcommandRequiredElseHelp` might exit with a code other than 2.
   - **Impact**: The `301-no-subcommand.sh` test would fail even though the behavior is correct.
   - **Mitigation**: Clap 4.x exits with code 2 for usage errors (including missing required subcommands). This is documented behavior. The existing `301-no-args-error.sh` already relies on clap exiting 2 for missing required arguments and passes, confirming this behavior on the current clap version.

2. **Risk**: Changing `Option<Commands>` to `Commands` could break downstream code that pattern-matches on `cli.command`.
   - **Impact**: Compile failure in crates that depend on `netfyr-cli`.
   - **Mitigation**: Only two consumers exist: `main.rs` (fixed in step 2) and `xtask` (which calls `Cli::command()` — the `CommandFactory` trait method — not `cli.command` the field). I verified `xtask/src/main.rs:56` uses `netfyr_cli::Cli::command()` which is unaffected.

3. **Risk**: The `301-no-subcommand.sh` test doesn't use `netns_setup` — could it interfere with other tests running in parallel?
   - **Impact**: None. The test only runs the `netfyr` binary with no arguments and checks its output/exit code. It performs no network operations, creates no files (besides the implicit tempdir from mktemp if used), and has no side effects.

4. **Risk**: Existing unit tests in `apply.rs` use `unsafe { std::env::set_var(...) }` which is unsound in multi-threaded contexts (Rust 1.81+).
   - **Impact**: Compiler warnings or test failures in CI.
   - **Mitigation**: This is a pre-existing issue, not introduced by this change. The test (`test_run_apply_dhcp_policy_without_daemon_returns_error_with_daemon_message`) already uses `unsafe` and runs under `#[tokio::test]` (single-threaded by default). No changes needed for this story. If it becomes a problem, the fix would be to use `#[tokio::test(flavor = "current_thread")]` explicitly, but that's out of scope.

## Test Strategy

**Unit tests**: The 30+ existing unit tests in `apply.rs` cover exit code logic, policy loading, DHCP rejection, and display functions. No new unit tests are needed — the change is purely in the CLI entry point (clap parse → dispatch), not in the apply logic.

**Shell integration tests**: After adding `301-no-subcommand.sh`, there will be 9 scripts total:
- `301-apply-static-mtu.sh` — MTU change in namespace
- `301-apply-with-address.sh` — MTU + address in namespace
- `301-apply-dry-run.sh` — dry-run does not change state
- `301-dhcp-policy-no-daemon.sh` — DHCP policy exits 2
- `301-dry-run-no-changes.sh` — dry-run exits 0 when no changes
- `301-no-args-error.sh` — `netfyr apply` with no paths exits 2
- `301-no-subcommand.sh` — bare `netfyr` shows help, exits 2 (NEW)
- `301-path-not-found.sh` — nonexistent path exits 2
- `301-yaml-parse-error.sh` — invalid YAML exits 2

**Verification command**: `make integration-test SPEC=301` runs all `tests/301-*.sh` scripts.

**What to watch for**: After the `lib.rs`/`main.rs` changes, run `cargo test --workspace` to ensure no regressions in any crate, especially xtask (which compiles against `netfyr-cli`'s `Cli` type).
