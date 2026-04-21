# UNDERSTAND: SPEC-301 — CLI Apply Command

## Current State

### Core apply implementation — fully present

`crates/netfyr-cli/src/apply.rs` (~1279 lines) is substantially complete:

- **`ApplyArgs`** — `paths: Vec<PathBuf>` (required), `dry_run: bool`, both clap-annotated.
- **`run_apply()`** — complete daemon-detection flow: reads `NETFYR_SOCKET_PATH`, calls `VarlinkClient::connect`, dispatches on `VarlinkError::ConnectionFailed` to daemon-free mode.
- **Daemon-free path** — DHCP gate (errors with `"requires the netfyr daemon"` and `"systemctl start netfyr"`); `policies_to_inputs` via `StaticFactory`; `merge()` for reconciliation; `BackendRegistry::query_all()`; dual diff (`generate_diff` for display, `compute_state_diff` for apply); `registry.apply()`; `Journal::open_default()` write-back.
- **Daemon path** — `run_apply_daemon()` calls `client.dry_run()` or `client.submit_policies()`.
- **`load_policies()`** — handles files and directories, delegates to `load_policy_file` / `load_policy_dir`, checks for missing paths (error contains `"path not found"`), detects duplicate policy names across paths.
- **`validate_policies()`** — runs `SchemaRegistry::validate()` on all states, aggregates all errors.
- **`determine_exit_code()` / `daemon_exit_code()`** — correct 0/1/2 exit code matrix.
- **Display functions** — `display_apply_report`, `display_dry_run_report`, `display_varlink_apply_report`, `display_varlink_diff`, `print_conflicts` — all present, using the `colored` crate.
- **`create_backend_registry()`** — registers `NetlinkBackend`.
- **Unit tests** — 30+ tests covering `load_policies`, `determine_exit_code`, `daemon_exit_code`, `display_apply_report` smoke tests, and the DHCP-without-daemon `run_apply` async path.

### CLI structure — present but missing `--color` flag

`crates/netfyr-cli/src/lib.rs`:
- `Cli` struct with `#[command(subcommand_required = true, arg_required_else_help = true)]` — satisfies "no subcommand shows help, exit 2" via clap.
- `Commands` enum with `Apply`, `Query`, `History`, `Revert`.
- **Missing**: `--color` global flag (`ColorMode` enum, `color: ColorMode` field on `Cli`).

`crates/netfyr-cli/src/main.rs` — correct tokio main using `Cli::parse()` and `Commands` (non-optional), dispatches all four subcommands, maps errors to `ExitCode::from(2u8)`.

`crates/netfyr-cli/src/netfyr_cli_main.rs` — an alternate entry point with a manual `if args().len() == 1 { println!("netfyr"); exit(0) }` guard. This exits 0 instead of 2. Whether this is the installed binary depends on `[[bin]]` Cargo config; `main.rs` appears to be the canonical binary.

### Integration tests — all present

All 13 shell tests for SPEC-301 exist under `tests/301-*.sh`:
`301-apply-static-mtu.sh`, `301-apply-with-address.sh`, `301-apply-dry-run.sh`, `301-apply-no-changes.sh`, `301-conflict-warning.sh`, `301-dhcp-policy-no-daemon.sh`, `301-dry-run-no-changes.sh`, `301-no-args-error.sh`, `301-no-subcommand.sh`, `301-partial-failure.sh`, `301-path-not-found.sh`, `301-total-failure.sh`, `301-yaml-parse-error.sh`.

`tests/helpers.sh` is complete with all required helpers.

---

## Requirements

Concrete technical requirements from the acceptance criteria:

1. `ApplyArgs` with `paths: Vec<PathBuf>` (required) and `--dry-run: bool` — both clap-annotated.
2. `run_apply(args)` returns `Result<ExitCode>` with full two-mode flow.
3. Daemon detection via `NETFYR_SOCKET_PATH` (default `/run/netfyr/netfyr.sock`); `ConnectionFailed` → daemon-free fallback.
4. Daemon-free mode: static-only gate; reconcile; query; diff; apply; journal write.
5. Daemon mode: `submit_policies` or `dry_run` via `VarlinkClient`.
6. Policy loading: files, directories, bare-state auto-wrap (filename stem → policy name, priority 100, `FactoryType::Static`), duplicate detection, "path not found" error.
7. Exit codes: 0 (success/no-op), 1 (partial failure or conflicts), 2 (total failure or fatal error).
8. Colored output for diff lines (`+` green, `~` yellow, `-`/`x` red), gated by `--color` flag and `NO_COLOR` env var.
9. **`--color` global flag** with `ColorMode { Auto, Always, Never }` and `NO_COLOR` env var support.
10. No-subcommand: clap prints usage, exits 2.
11. No-path-argument: clap prints required-arg error, exits 2.

---

## Gap Analysis

### GAP 1 — `--color` global flag and `ColorMode` enum are absent (file: `crates/netfyr-cli/src/lib.rs`)

The spec requires:
```rust
#[arg(long, global = true, default_value = "auto")]
color: ColorMode,

#[derive(Clone, ValueEnum)]
enum ColorMode { Auto, Always, Never }
```

Neither `ColorMode` nor the `color` field exist anywhere in the crate. The `Cli` struct in `lib.rs` currently has no color field.

**What must be created**: `ColorMode` enum (with `ValueEnum` derive), `color: ColorMode` field on `Cli`.

### GAP 2 — `NO_COLOR` env var and color resolution logic absent (file: `crates/netfyr-cli/src/main.rs`)

The spec requires:
- If `NO_COLOR` is set (any value), disable colors regardless of `--color`.
- `auto`: enable when stdout is a TTY.
- `always`/`never`: force on/off.

Currently the `colored` crate is used unconditionally in all display functions. No color resolution or `colored::control::set_override` call exists anywhere. Color mode resolution must be applied in `main.rs` after `Cli::parse()`, before any subcommand handler runs.

**What must be created**: A color-setup function (likely in `lib.rs` or `main.rs`) that checks `NO_COLOR`, then maps `ColorMode` to a `colored::control::set_override(bool)` call (or lets `colored`'s default TTY detection handle `Auto`).

### GAP 3 — `netfyr_cli_main.rs` exits 0 for no-args (file: `crates/netfyr-cli/src/netfyr_cli_main.rs`)

The manual `if args().len() == 1 { exit(0) }` guard bypasses clap entirely and exits 0 instead of 2. If this is the installed `netfyr` binary, the `301-no-subcommand.sh` and `301-no-args-error.sh` tests will fail. Needs resolution based on `[[bin]]` Cargo configuration.

### No gap in: apply flow logic, daemon detection, policy loading, exit codes, display functions, unit tests, integration test scripts

The functional core is implemented. The 13 required shell integration test scripts exist. The unit test suite is comprehensive.

---

## Integration Points

| Component | Role |
|---|---|
| `netfyr_policy::{load_policy_file, load_policy_dir, FactoryType, PolicySet, StaticFactory}` | Policy loading and static production |
| `netfyr_reconcile::{merge, generate_diff, PolicyInput, PolicyId, ConflictReport, DiffReport}` | Reconciliation and display diff |
| `netfyr_state::{diff::diff, StateSet, SchemaRegistry, StateDiff}` | State-level diff for `registry.apply()` |
| `netfyr_backend::{BackendRegistry, NetlinkBackend, ApplyReport, DiffOpKind}` | Netlink query and apply |
| `netfyr_varlink::{VarlinkClient, VarlinkError, VarlinkPolicy, VarlinkApplyReport, VarlinkStateDiff}` | Daemon communication |
| `netfyr_journal::{Journal, JournalEntry, Trigger, ApplyOutcome, summarize_policies}` | Audit log write-back |
| `colored` crate | Terminal color output — must be gated by GAP 1/2 color resolution |
| `NETFYR_SOCKET_PATH` env var | Daemon socket override; critical for all 301 integration tests |

The `--color` flag, once added to `Cli`, must propagate from `main.rs` to a color-setup function before any subcommand handler is dispatched.

---

## Risks

1. **`colored` global state**: `colored::control::set_override` sets a process-global. Unit tests that call display functions will be unaffected (they don't call the setup function), but integration tests will respect `NO_COLOR` if set in the shell environment — which is the correct behavior.

2. **TTY detection for `Auto`**: If color resolution delegates to `colored`'s built-in TTY detection for `Auto` (by not calling `set_override`), no additional `atty` / `IsTerminal` dependency is needed. If the implementation forces `set_override` for `Auto` too, TTY detection must be added explicitly.

3. **`netfyr_cli_main.rs` vs `main.rs` binary target**: If both files are configured as `[[bin]]` targets in `Cargo.toml`, one of them is the installed `netfyr` binary and the other is dead or a secondary binary. The Cargo.toml `[[bin]]` section must be read to resolve which file's behavior is observable by integration tests.

4. **Bare-state auto-wrapping lives in `netfyr-policy`**: The CLI's `load_policies` delegates to `load_policy_file`. If SPEC-008 (bare-state auto-wrap) is not yet implemented in `netfyr-policy`, the `301-apply-static-mtu.sh` and `301-apply-with-address.sh` tests will fail regardless of CLI correctness.

5. **`unsafe { set_var }` in async tests**: The DHCP-without-daemon test (line ~950 in `apply.rs`) uses `unsafe { std::env::set_var(...) }` inside a `#[tokio::test]`. In Rust 1.81+, this emits a safety warning because the tokio runtime is multi-threaded. This may produce CI warnings or lints.

6. **`VarlinkError::ConnectionFailed` match coverage**: Daemon detection only falls back to daemon-free mode on `VarlinkError::ConnectionFailed(_)`. Other connection errors (e.g., permission denied, protocol mismatch) re-surface as fatal errors. This is per-spec but the exact variant names in `netfyr-varlink` must be confirmed to match what `VarlinkClient::connect` actually emits for the "socket not present" case.
