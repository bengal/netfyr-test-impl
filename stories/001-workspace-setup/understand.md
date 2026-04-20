# UNDERSTAND: 001-workspace-setup

## Current State

The project at `/workspace/project/` is a fully implemented Rust workspace — far beyond the stub state described by this story. All required structural elements are present.

**Root `Cargo.toml`** (`/workspace/project/Cargo.toml`):
- `resolver = "2"` — present
- 9 workspace members: the 7 spec crates plus `crates/netfyr-test-utils` and `xtask`
- `[workspace.features]`: `dhcp = []`, `systemd = []`, `varlink = []` — present

**All 7 required crates** exist under `crates/` with full implementations (not stubs):
- `netfyr-state` — full implementation: diff.rs, loader.rs, schema.rs, set.rs, yaml.rs, schemas/
- `netfyr-reconcile` — full implementation: diff.rs, lib.rs, report.rs
- `netfyr-backend` — full implementation: dhcp/ and netlink/ sub-modules, registry.rs, report.rs, trait_.rs
- `netfyr-policy` — full implementation: lib.rs
- `netfyr-varlink` — full implementation: client.rs, types.rs, io.netfyr.varlink
- `netfyr-cli` (binary) — full clap CLI; `Cargo.toml` declares two `[[bin]]` targets (`netfyr-cli` and `netfyr`); `main()` prints `"netfyr"` to stdout when no subcommand is given (the `None` match arm)
- `netfyr-daemon` (binary) — full async daemon; `println!("netfyr")` at the top of `main()` before any I/O or async work

Extra workspace members not in spec (added by later stories): `crates/netfyr-test-utils`, `xtask`.

**`Makefile`** (`/workspace/project/Makefile`):
- `.PHONY: integration-test` declared
- `cargo build` runs first
- `SPEC` variable filter is implemented: `if [ -n "$(SPEC)" ]; then scripts=$$(ls tests/$(SPEC)-*.sh ...); else scripts=$$(ls tests/[0-9]*.sh ...); fi`
- Failure tracking via `failed=0` / `failed=1` / `exit 1`

**`tests/helpers.sh`**:
- Exists; defines all required functions: `netns_setup`, `create_veth`, `add_address`, `start_dnsmasq`, `cleanup`, `assert_eq`, `assert_match`, `assert_has_address`, `assert_link_up`
- No-skip policy enforced: `netns_setup` exits 1 if `unshare` not found; `start_dnsmasq` exits 1 if `dnsmasq` not found
- `start_dnsmasq` uses `--bind-dynamic` (not `--bind-interfaces`)

**Integration test scripts** — 9 scripts named `001-*.sh` cover all acceptance criteria scenarios: `001-workspace-members.sh`, `001-workspace-features.sh`, `001-file-structure.sh`, `001-binary-cli.sh`, `001-binary-daemon.sh`, `001-helpers-functions.sh`, `001-makefile-target.sh`, `001-no-skip-policy.sh`, `001-test-naming-convention.sh`.

**`README.md`**: **does not exist**.

## Requirements

From the acceptance criteria, the concrete technical requirements are:

1. `cargo build` succeeds from the workspace root, compiling all 7 crates.
2. `cargo build -p netfyr-state` succeeds in isolation.
3. Root `Cargo.toml` workspace `members` includes the 7 spec crates with `resolver = "2"`.
4. `[workspace.features]` defines `dhcp = []`, `systemd = []`, `varlink = []`.
5. Each library crate has `Cargo.toml` + `src/lib.rs`; binary crates have `Cargo.toml` + `src/main.rs`.
6. `cargo build -p netfyr-cli` produces a `netfyr-cli` binary that prints `"netfyr"` to stdout when run with no arguments.
7. `cargo build -p netfyr-daemon` produces a `netfyr-daemon` binary that prints `"netfyr"` as its first stdout line.
8. `tests/helpers.sh` defines all required functions; exits 1 (never 0) on missing prerequisites.
9. `make integration-test` runs `cargo build`, discovers `tests/[0-9]*.sh`, exits non-zero on any failure.
10. `make integration-test SPEC=NNN` runs only `tests/NNN-*.sh`.
11. Test scripts follow `NNN-description.sh` naming; `helpers.sh` is the only non-numbered `.sh` file.
12. `README.md` exists and covers: project summary, 7-crate architecture, usage examples (`apply`, `query`, daemon/systemd, `--dry-run`), build instructions, test instructions, license reference.

## Gap Analysis

**One file is missing:**

| File | Status | Action |
|------|--------|--------|
| `README.md` | **Missing** | Create at `/workspace/project/README.md` |

All other required files and behaviors are present and correct:

| Acceptance Criterion | Status | Notes |
|---|---|---|
| Root `Cargo.toml` with resolver 2 | Met | Present |
| 7 required crates as workspace members | Met | Present (plus 2 extras from later stories) |
| `[workspace.features]` dhcp/systemd/varlink | Met | Present |
| All 7 crates have `Cargo.toml` + source file | Met | Full implementations, not stubs |
| CLI binary prints `"netfyr"` with no args | Met | `None` command arm in `netfyr-cli/src/main.rs` |
| Daemon binary prints `"netfyr"` on startup | Met | `println!("netfyr")` at top of `netfyr-daemon/src/main.rs` |
| `tests/helpers.sh` with all required functions | Met | All 9 functions present |
| No-skip policy (exit 1 on missing prereqs) | Met | Enforced in helpers and checked by `001-no-skip-policy.sh` |
| `Makefile` `integration-test` target | Met | .PHONY, cargo build, glob discovery, failure tracking |
| `make integration-test SPEC=NNN` filter | Met | SPEC conditional already implemented in Makefile |
| `--bind-dynamic` in `start_dnsmasq` | Met | Present in helpers.sh |
| Test scripts named `NNN-description.sh` | Met | All 001-*.sh scripts conform |
| `README.md` | **Gap** | File does not exist |

**`README.md` must cover** (per spec):
- One-paragraph project description: declarative Linux network config via netlink, policy-based with per-field priority reconciliation, daemon for DHCP factory lifecycle
- Seven-crate architecture table with one-line role per crate (state, policy, reconcile, backend, varlink, cli, daemon)
- Usage examples: `netfyr apply`, `netfyr query`, daemon mode with systemd, `--dry-run`
- Build section: `cargo build`, `cargo build -p netfyr-state`, `cargo build --features dhcp,systemd`
- Test section: `cargo test`, `make integration-test`, `make integration-test SPEC=NNN`; note that integration tests use `unshare --user --net` and require no root
- License reference

## Integration Points

- `README.md` is a standalone documentation file; it does not integrate with any code module.
- Binary names in usage examples must match the `[[bin]]` entries in `crates/netfyr-cli/Cargo.toml`: the user-facing CLI binary is `netfyr` (not `netfyr-cli`); the daemon binary is `netfyr-daemon`.
- Feature flag names in build examples must match `[workspace.features]` exactly: `dhcp`, `systemd`, `varlink`.
- `make integration-test` and `make integration-test SPEC=NNN` commands in the README must reflect the actual `Makefile` target as it exists.

## Risks

1. **Workspace member count vs. spec literal**: The spec's Gherkin says "exactly 7 entries" but the workspace has 9 members. `001-workspace-members.sh` resolves this pragmatically — it checks for presence of the 7 required members and explicitly notes that extras from later stories are acceptable. No code change needed.

2. **Crate `Cargo.toml` stub compliance**: The spec describes stub crates with empty `[dependencies]` sections. The actual crates have real dependencies since the implementations are complete. The acceptance-criteria tests do not check dependency content. No action needed.

3. **Daemon startup timing in `001-binary-daemon.sh`**: The test starts the daemon binary with a temp socket/policy dir, waits 0.5 s, kills it, and reads the first stdout line. The daemon prints `"netfyr"` synchronously before any async work, so this is reliable under normal conditions. Environment-specific issues (slow process startup) could cause flakes but are not a code gap.

4. **`unshare` kernel restriction**: `netns_setup` exits 1 if `unshare` is not installed, satisfying the no-skip policy. If `unshare` is available but unprivileged user namespaces are blocked at the kernel level (`kernel.unprivileged_userns_clone=0`), the resulting error will not carry a `FAIL:` prefix, which is a minor ambiguity in the spec's no-skip policy coverage.
