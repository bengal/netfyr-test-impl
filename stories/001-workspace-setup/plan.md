# Plan: 001-workspace-setup

## Approach

The project workspace is already fully implemented — all seven required crates exist with complete source code, the root `Cargo.toml` defines the workspace with correct resolver, members, and features, `tests/helpers.sh` provides all required shell functions (including `--bind-dynamic`), the `Makefile` has a working `integration-test` target with `SPEC` filtering, and nine `001-*.sh` test scripts cover the acceptance criteria.

The **only remaining gap** is the missing `README.md` at the project root. The spec's acceptance criteria explicitly require it: "README.md exists and covers key topics" — project summary, seven-crate architecture, usage examples for `apply` and `query`, and build/test instructions.

The design is to create a single new file: `/workspace/project/README.md`. No code changes, no dependency changes, no test script changes. The README will be a concise, developer-facing document following the spec's content requirements exactly. It should be readable in under 5 minutes (per the spec), so it should be approximately 150-250 lines — enough to cover all required topics without bloat.

Why a single flat README rather than a docs/ directory: the spec explicitly lists `README.md` as a deliverable file. There's no requirement for additional documentation files, and a single README is the standard entry point for any Rust project. The seven-crate architecture is simple enough to describe in a short table rather than separate per-crate docs.

## Design Decisions

1. **Decision**: Create `README.md` as a standalone file with all content inline (no links to separate docs).
   - **Alternatives considered**: (a) A `docs/` directory with per-crate documentation linked from the README; (b) Generating docs from `cargo doc`.
   - **Rationale**: The spec lists exactly one file (`README.md`) and says it should be "concise — a single file." Separate docs would be over-engineering for this story. `cargo doc` generates API docs, not the architectural overview and usage guide the spec requires.

2. **Decision**: Use `netfyr` (not `netfyr-cli`) as the binary name in all usage examples.
   - **Alternatives considered**: Using `netfyr-cli`.
   - **Rationale**: The `crates/netfyr-cli/Cargo.toml` defines two `[[bin]]` targets: `netfyr-cli` and `netfyr`. The user-facing binary name is `netfyr` — this is the `name` in the `#[command]` attribute and the natural user-facing name. The spec's example test script also uses `NETFYR_BIN` pointing to `netfyr`.

3. **Decision**: Structure the README with these sections in order: project summary, architecture table, usage examples, building, testing, license.
   - **Alternatives considered**: Different section orderings.
   - **Rationale**: This follows the spec's enumeration verbatim ("Project summary... Architecture... Usage examples... Building... Testing... License") and matches the conventional README structure for Rust projects. A developer skimming the file gets the "what" first, then "how to use it," then "how to build/test."

4. **Decision**: Include `--dry-run` in the usage examples section.
   - **Alternatives considered**: Omitting it or placing it in a separate "Advanced Usage" section.
   - **Rationale**: The spec explicitly lists `--dry-run` as a required usage example topic alongside `netfyr apply`, `netfyr query`, and daemon mode with systemd. It fits naturally as a subsection or variant of the `apply` example.

5. **Decision**: Reference `LICENSE` file without specifying the license type.
   - **Alternatives considered**: Stating a specific license (MIT, Apache-2.0, etc.).
   - **Rationale**: The spec says "reference to the LICENSE file" — no LICENSE file currently exists in the project, so we reference it generically. The spec doesn't prescribe a license type, and choosing one is outside this story's scope.

6. **Decision**: Do not create any new test scripts for the README.
   - **Alternatives considered**: Adding a `001-readme.sh` test script that checks for README.md existence and content.
   - **Rationale**: No existing `001-*.sh` test checks for the README (confirmed by grep), and the acceptance criteria scenario "README.md exists and covers key topics" is a documentation verification, not a shell-testable behavior. The nine existing test scripts already cover all the code/infrastructure acceptance criteria. Adding a test that greps a prose document for keywords would be brittle and of low value.

## File Changes

### 1. `README.md` (create)

**File path**: `README.md` (project root)
**Action**: Create

**What**: A Markdown document with the following sections:

- **Title and project summary** (1 paragraph): Describe netfyr as a declarative network configuration tool for Linux that uses netlink for system interaction, policy-based configuration with per-field priority reconciliation, and a daemon mode for dynamic factory lifecycle (e.g., DHCPv4). Mention that configuration is expressed as YAML policy files.

- **Architecture** section: A table or list of the seven crates with a one-line description of each:
  - `netfyr-state` — Core state types, selectors, values, state sets, YAML parsing, schema validation
  - `netfyr-policy` — Policy types, static and dynamic factories, YAML policy loading
  - `netfyr-reconcile` — Multi-policy reconciliation with per-field priority, conflict detection, diff generation
  - `netfyr-backend` — Backend trait and netlink implementation for querying and applying network state
  - `netfyr-varlink` — Varlink IPC protocol types and client for daemon communication
  - `netfyr-cli` — User-facing CLI binary (`netfyr`) with `apply` and `query` subcommands
  - `netfyr-daemon` — Long-running daemon for dynamic factories (DHCPv4), Varlink server, systemd integration

  Briefly describe the layered dependency flow: state is the foundation, policy and reconcile depend on state, backend depends on state, varlink depends on all library crates, cli and daemon are the top-level binaries.

- **Usage Examples** section with subsections:
  - `netfyr apply <path>` — Apply a policy file or directory. Show a minimal YAML policy example (static ethernet with an address).
  - `netfyr apply --dry-run <path>` — Preview changes without applying.
  - `netfyr query` — Query all current network state.
  - `netfyr query -s type=ethernet -s name=eth0` — Query filtered by selector.
  - Daemon mode — Brief description of running `netfyr-daemon` (reads policies from a directory, listens on a Varlink socket, supports dynamic factories like DHCPv4). Mention systemd integration (sd_notify READY=1). Show that when the daemon is running, `netfyr apply` and `netfyr query` automatically communicate via Varlink.

- **Building** section:
  - `cargo build` — Build all crates
  - `cargo build -p netfyr-state` — Build a single crate
  - `cargo build --features dhcp,systemd` — Build with workspace feature flags
  - Note the three workspace features: `dhcp`, `systemd`, `varlink`

- **Testing** section:
  - `cargo test` — Run Rust unit and integration tests
  - `make integration-test` — Run all shell integration tests (builds first)
  - `make integration-test SPEC=NNN` — Run tests for a specific story/spec
  - Note that integration tests use `unshare --user --net` for unprivileged network namespaces — no root required
  - Note that tests follow a no-skip policy: missing prerequisites cause `FAIL`, never silent skips

- **License** section: Short line referencing the `LICENSE` file (e.g., "See the [LICENSE](LICENSE) file for details.")

**Why**: This is the only remaining gap identified by the understanding analysis. The acceptance criterion "README.md exists and covers key topics" requires this file. It provides the entry point for new developers to understand the project structure, usage, and development workflow.

## Dependencies

No new crate dependencies. The README is a documentation file that requires no code changes.

## Implementation Order

1. **Create `README.md`** at `/workspace/project/README.md` with all sections described above. This is a single file creation with no code dependencies. The workspace remains compilable before, during, and after this step.

2. **Verify**: Run the full verification sequence:
   - `cargo build` — Confirm workspace still compiles
   - `cargo clippy` — Confirm no lint warnings
   - `cargo test` — Confirm Rust tests pass
   - `make integration-test SPEC=001` — Run the nine `001-*.sh` test scripts to confirm all acceptance criteria pass

## Risks and Mitigations

1. **Risk**: The README references commands or features that don't exist or have different syntax.
   - **Mitigation**: All CLI subcommands and flags are verified against the actual source code: `apply` and `query` are defined in `crates/netfyr-cli/src/lib.rs` (Commands enum), `--dry-run` is in `ApplyArgs`, selector flags are in `QueryArgs`. The workspace features (`dhcp`, `systemd`, `varlink`) are confirmed in the root `Cargo.toml`. Binary name `netfyr` is confirmed in the `[[bin]]` target.

2. **Risk**: The README becomes stale as the project evolves.
   - **Mitigation**: This is inherent to documentation. The README covers stable architectural boundaries (the seven-crate structure) and CLI interfaces that are unlikely to change frequently. Future stories that change the CLI interface should update the README as part of their implementation.

3. **Risk**: No automated test validates README content, so it could silently become inaccurate.
   - **Mitigation**: Acceptable risk. Testing prose documentation with grep-based assertions is brittle and low-value. The acceptance criteria scenario is a human-readable check ("When the file README.md is inspected, then it describes what netfyr does..."), not a machine assertion.

4. **Risk**: The spec mentions "License: reference to the LICENSE file" but no LICENSE file exists.
   - **Mitigation**: Reference the LICENSE file path generically without asserting it exists. This is a forward reference — a LICENSE file will presumably be added separately. The README line "See the LICENSE file for details" is accurate regardless of whether the file exists yet.

## Test Strategy

No new tests need to be created. The existing nine `001-*.sh` test scripts cover all code and infrastructure acceptance criteria:

- **`001-workspace-members.sh`** — Verifies all 7 required crates are workspace members
- **`001-workspace-features.sh`** — Verifies `dhcp`, `systemd`, `varlink` features exist
- **`001-file-structure.sh`** — Verifies each crate has the correct source file structure
- **`001-binary-cli.sh`** — Verifies the CLI binary prints `"netfyr"` with no arguments
- **`001-binary-daemon.sh`** — Verifies the daemon binary prints `"netfyr"` on startup
- **`001-helpers-functions.sh`** — Verifies `helpers.sh` defines all required functions
- **`001-makefile-target.sh`** — Verifies the Makefile `integration-test` target structure
- **`001-no-skip-policy.sh`** — Verifies no-skip exit-1 behavior on missing prerequisites
- **`001-test-naming-convention.sh`** — Verifies `NNN-description.sh` naming convention

The README acceptance criterion ("README.md exists and covers key topics") is a documentation review, not a functional test. It is verified by human inspection as part of the acceptance criteria review, not by a shell script.

**Verification command**: `make integration-test SPEC=001` — must pass all 9 tests with exit code 0.
