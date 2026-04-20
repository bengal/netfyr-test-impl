# SPEC-501: Man Pages — Implementation Plan

## Approach

The implementation adds a standard Rust xtask binary that generates troff man pages from the existing clap CLI definitions, plus a hand-written examples man page. The key architectural challenge is that `netfyr-cli` is currently a pure binary crate — its `Cli` and `Commands` types are private and cannot be imported by other crates. We must restructure it into a hybrid lib+bin crate so the xtask can call `Cli::command()` via clap's `CommandFactory` trait.

The xtask uses `clap_mangen` to render the base man page content (NAME, SYNOPSIS, DESCRIPTION, OPTIONS) from the clap `Command` tree, then appends raw troff markup for the sections that `clap_mangen` cannot generate: EXIT STATUS, FILES, EXAMPLES, and SEE ALSO. This "render then append" strategy is simpler than using the individual `render_*` methods because it requires no coordination with `clap_mangen` internals — we just write to the same byte buffer after the library finishes. The hand-written `netfyr-examples.7` is a static troff file committed to the repository; the xtask never touches it.

An alternative considered was using a `build.rs` in `netfyr-cli` instead of an xtask. This was rejected because: (a) `build.rs` runs during every compilation, adding latency to the edit-compile cycle, (b) it conflates build artifacts with developer tooling, and (c) the spec explicitly calls for an xtask pattern. Another alternative was generating man pages at install time via a Makefile — this was rejected because the spec requires `cargo xtask man` as the developer interface and because generating from clap definitions ensures the pages stay in sync with the code.

## Design Decisions

1. **Decision**: Restructure `netfyr-cli` as a hybrid lib+bin crate by creating a new `src/lib.rs` that re-exports `Cli` and `Commands`, with `main.rs` importing from it.
   - **Alternatives considered**: (a) Declare `lib.path = "src/main.rs"` with `[[bin]] path = "src/main.rs"` — this would expose the `main` function as part of the library API, which is incorrect. (b) Use a separate crate just for the clap types — this would split the CLI definition across two crates for no benefit.
   - **Rationale**: The lib+bin pattern is idiomatic Rust. `main.rs` already imports from `apply` and `query` modules; moving `Cli` and `Commands` into `lib.rs` and having `main.rs` import them is a minimal change. The `apply` and `query` modules can remain private to the crate (`pub(crate)`) since only `Cli` and `Commands` need to be public for the xtask.

2. **Decision**: Append raw troff markup to the `clap_mangen`-rendered buffer for EXIT STATUS, FILES, EXAMPLES, and SEE ALSO sections.
   - **Alternatives considered**: (a) Use `Man::render_*` individual section methods and interleave custom sections — more complex, couples us to the rendering order `clap_mangen` expects. (b) Post-process the generated troff with string replacement — fragile and error-prone.
   - **Rationale**: Appending is the simplest approach. `man` renders sections in the order they appear in the troff source, and the standard section ordering (OPTIONS before EXIT STATUS before FILES before EXAMPLES before SEE ALSO) is satisfied by appending in that order after `render()` produces OPTIONS last.

3. **Decision**: Add `long_about` annotations to `Cli` and the subcommand variants so `clap_mangen` generates meaningful DESCRIPTION sections.
   - **Alternatives considered**: Injecting DESCRIPTION text via raw troff after generation — this would require locating and replacing the auto-generated `.SH DESCRIPTION` section, which is fragile.
   - **Rationale**: `clap_mangen` uses `long_about` for the DESCRIPTION section. Adding `long_about` to the clap annotations is the intended mechanism and ensures the text stays with the CLI definition. The current `about` string on `Cli` is too short ("Declarative Linux network configuration") to satisfy the acceptance criterion that the DESCRIPTION mentions `apply` and `query` subcommands.

4. **Decision**: The xtask locates the workspace root by using the `CARGO_MANIFEST_DIR` environment variable (set to `xtask/` when the xtask is compiled) and navigating one directory up.
   - **Alternatives considered**: (a) Using `CARGO_WORKSPACE_DIR` — this is a nightly-only feature. (b) Walking parent directories looking for workspace `Cargo.toml` — over-engineered for this case. (c) Hardcoding a relative path from the current working directory — fragile if `cargo xtask man` is run from a subdirectory.
   - **Rationale**: `CARGO_MANIFEST_DIR` is stable, always set during compilation, and the xtask is always one level below the workspace root. We embed it at compile time via `env!("CARGO_MANIFEST_DIR")` and resolve `../man/` from there.

5. **Decision**: The xtask does NOT guard against overwriting `netfyr-examples.7` — it simply never writes to that filename. The hand-written file is a separate committed artifact.
   - **Alternatives considered**: Adding an existence check before writing — unnecessary since the xtask's generation loop only iterates over clap subcommands, and `netfyr-examples` is not a clap subcommand.
   - **Rationale**: The spec says "the xtask does not generate or overwrite `man/netfyr-examples.7`." Since the generation logic iterates over `cmd.get_subcommands()` (which yields `apply` and `query`), and writes `netfyr.1` for the top-level command, the filename `netfyr-examples.7` never appears in the write path. No guard is needed.

6. **Decision**: The `xtask` binary uses its own `clap::Parser` for argument parsing (with a `man` subcommand), allowing future xtask subcommands to be added.
   - **Alternatives considered**: A simple `main()` that unconditionally generates man pages — this would work now but doesn't scale when more xtask commands are added (the spec mentions this is a pattern for development automation).
   - **Rationale**: The xtask pattern conventionally supports multiple subcommands. Using clap for the xtask's own argument parsing is consistent with the project's existing use of clap and costs almost nothing (clap is already a dependency).

7. **Decision**: Use `write!` / `writeln!` macros to append troff markup to the byte buffer, writing troff macros directly (`.SH`, `.TP`, `.PP`, `.RS`/`.RE`, `.IP`, `.nf`/`.fi`).
   - **Alternatives considered**: Building a troff abstraction or using a troff-generation library — no mature crate exists for this, and the sections are simple enough that raw troff is clearer.
   - **Rationale**: The custom sections are static text with a known structure. Raw troff is readable and maintainable for this volume of content.

## File Changes

### `crates/netfyr-cli/Cargo.toml`
- **Action**: Modify
- **What**: Add a `[lib]` section: `name = "netfyr_cli"`, `path = "src/lib.rs"`. Keep the existing `[[bin]]` section unchanged.
- **Why**: The xtask needs to import `Cli::command()` from the CLI crate. Without a lib target, the crate's types are not importable.

### `crates/netfyr-cli/src/lib.rs`
- **Action**: Create
- **What**: Declare `mod apply;` and `mod query;` (both `pub(crate)` — they don't need to be public to external consumers). Define and export `pub struct Cli` with `#[derive(Parser)]` and `pub enum Commands` with `#[derive(Subcommand)]`. Add `long_about` annotations:
  - `Cli`: `long_about` should be a paragraph mentioning that `netfyr` is a declarative network configuration tool with `apply` and `query` subcommands, and that it can operate standalone or with the netfyr daemon.
  - `Commands::Apply` variant: `long_about` should describe loading YAML policies, reconciling, diffing, and applying, with mention of daemon vs. daemon-free modes and `--dry-run`.
  - `Commands::Query` variant: `long_about` should describe querying current network state with selector filters and output format options.
- **Why**: This is the lib entry point that the xtask imports. The `long_about` annotations feed into `clap_mangen`'s DESCRIPTION generation.

### `crates/netfyr-cli/src/main.rs`
- **Action**: Modify
- **What**: Remove the `Cli` struct, `Commands` enum, and `mod` declarations. Replace with `use netfyr_cli::{Cli, Commands};` and keep the `#[tokio::main] async fn main()` body unchanged. The `mod apply;` and `mod query;` declarations move to `lib.rs`.
- **Why**: `Cli` and `Commands` now live in `lib.rs`. `main.rs` just imports and uses them.

### `Cargo.toml` (workspace root)
- **Action**: Modify
- **What**: Add `"xtask"` to the `[workspace] members` list.
- **Why**: The workspace must know about the xtask crate for `cargo` to build it.

### `.cargo/config.toml`
- **Action**: Create
- **What**: Contains:
  ```toml
  [alias]
  xtask = "run --package xtask --"
  ```
- **Why**: Enables the `cargo xtask man` shorthand. This is the standard xtask convention.

### `xtask/Cargo.toml`
- **Action**: Create
- **What**: Package named `xtask`, `version = "0.1.0"`, `edition = "2021"`, `publish = false`. Dependencies:
  - `clap = { version = "4", features = ["derive"] }` — for the xtask's own CLI parsing
  - `clap_mangen = "0.2"` — man page generation from clap Command trees
  - `netfyr-cli = { path = "crates/netfyr-cli" }` — to access `Cli::command()`
- **Why**: Defines the xtask binary crate and its dependencies.

### `xtask/src/main.rs`
- **Action**: Create
- **What**: The xtask entry point. Contains:
  - A `#[derive(Parser)] struct Xtask` with a `#[derive(Subcommand)] enum XtaskCommand` containing a `Man` variant (no arguments needed).
  - A `fn main()` that parses args and dispatches to `generate_man_pages()`.
  - A `fn generate_man_pages() -> Result<(), Box<dyn std::error::Error>>` that:
    1. Computes the output directory: `env!("CARGO_MANIFEST_DIR")` joined with `../man`, then canonicalize the parent to get the workspace root, then append `man/`.
    2. Creates the `man/` directory with `fs::create_dir_all`.
    3. Calls `netfyr_cli::Cli::command()` to get the top-level `clap::Command`.
    4. Generates the top-level man page (`netfyr.1`):
       - Creates `Man::new(cmd.clone())`, calls `man.render(&mut buf)`.
       - Appends EXIT STATUS section (codes 0, 1, 2).
       - Appends FILES section (`/etc/netfyr/policies/`).
       - Appends EXAMPLES section (two examples: running `netfyr apply` and `netfyr query`).
       - Appends SEE ALSO section referencing `netfyr-apply(1)`, `netfyr-query(1)`, `netfyr-examples(7)`, `netfyr.yaml(5)`.
       - Writes `buf` to `man/netfyr.1`.
    5. Iterates over `cmd.get_subcommands()` and for each subcommand:
       - Clones and renames to `netfyr-{name}` via `.name()`.
       - Creates `Man::new(subcmd)`, calls `man.render(&mut buf)`.
       - Appends EXIT STATUS, FILES, EXAMPLES, SEE ALSO sections specific to that subcommand.
       - Writes to `man/netfyr-{name}.1`.
    6. Prints a summary message listing the generated files.
  - Helper functions for generating the troff content of each custom section:
    - `fn append_exit_status(buf: &mut Vec<u8>, subcommand: Option<&str>)` — writes `.SH "EXIT STATUS"` with `.TP` entries for codes 0, 1, 2. Content is the same for all commands (success/partial/fatal).
    - `fn append_files(buf: &mut Vec<u8>)` — writes `.SH FILES` with `.TP` entries for `/etc/netfyr/policies/` and `/var/lib/netfyr/`.
    - `fn append_examples(buf: &mut Vec<u8>, subcommand: Option<&str>)` — writes `.SH EXAMPLES` with at least two examples per command. For `None` (top-level): examples of `netfyr apply` and `netfyr query`. For `"apply"`: applying a directory and dry-run on a file. For `"query"`: querying all interfaces and querying with selectors.
    - `fn append_see_also(buf: &mut Vec<u8>, subcommand: Option<&str>)` — writes `.SH "SEE ALSO"` with cross-references. Each command references all other man pages and `netfyr.yaml(5)`.
- **Why**: This is the core of the story — the generator that produces man pages from clap definitions with supplementary sections.

### `man/netfyr-examples.7`
- **Action**: Create
- **What**: A hand-written troff man page in section 7. Must include:
  - A comment at the top: `.\" This file is maintained by hand. Do not edit with cargo xtask man.`
  - `.TH NETFYR-EXAMPLES 7 "" "" "Miscellaneous Information Manual"`
  - `.SH NAME` — `netfyr-examples \- configuration examples for netfyr`
  - `.SH DESCRIPTION` — introductory paragraph about what the page contains and where to save files.
  - Seven scenario sections, each as its own `.SH` or `.SS`:
    1. **STATIC IP ON A SINGLE INTERFACE** — YAML example with `type: ethernet`, `name: eth0`, `mtu`, `addresses`, `routes`.
    2. **MULTIPLE INTERFACES IN ONE FILE** — Two YAML documents separated by `---`.
    3. **DHCP ON AN INTERFACE** — Policy YAML with `factory: dhcpv4`.
    4. **MIXED STATIC AND DHCP** — Two separate files, one static and one DHCP policy.
    5. **PRIORITY OVERRIDE** — Two policies with different priorities on the same field.
    6. **SELECTING BY DRIVER** — Using `driver: ixgbe` selector.
    7. **DRY-RUN WORKFLOW** — Shell commands showing `--dry-run` then actual apply.
  - Each scenario section has a prose description paragraph followed by the YAML example in `.nf`/`.fi` (no-fill) blocks with `.RS`/`.RE` indentation.
  - `.SH "SEE ALSO"` referencing `netfyr(1)`, `netfyr-apply(1)`, `netfyr-query(1)`, `netfyr.yaml(5)`.
- **Why**: The spec requires this as a hand-maintained reference page with comprehensive, copy-pasteable examples. All seven scenarios and the exact YAML content are specified in the spec.

## Dependencies

### New crate dependencies

| Crate | Version | Where | Justification |
|-------|---------|-------|---------------|
| `clap_mangen` | `0.2` | `xtask/Cargo.toml` | Required to generate troff man pages from clap `Command` definitions. No std equivalent exists for man page generation. |
| `clap` | `4` (features: `derive`) | `xtask/Cargo.toml` | Already used by the project. Needed for the xtask's own CLI argument parsing. |
| `netfyr-cli` | `path = "crates/netfyr-cli"` | `xtask/Cargo.toml` | Internal dependency to access `Cli::command()`. |

No other new external dependencies are needed. The troff sections are generated with `std::io::Write` / `std::fmt::Write` and `std::fs`.

## Implementation Order

1. **Restructure `netfyr-cli` as a hybrid lib+bin crate.**
   - Create `crates/netfyr-cli/src/lib.rs` with `Cli`, `Commands`, module declarations, and `long_about` annotations.
   - Modify `crates/netfyr-cli/src/main.rs` to import from the lib.
   - Add `[lib]` section to `crates/netfyr-cli/Cargo.toml`.
   - **Verify**: `cargo build -p netfyr-cli` compiles both the library and binary targets. Existing tests pass.

2. **Create the xtask crate skeleton.**
   - Create `xtask/Cargo.toml` and `xtask/src/main.rs` (with a placeholder `main` that prints a message).
   - Add `"xtask"` to workspace `Cargo.toml` members.
   - Create `.cargo/config.toml` with the alias.
   - **Verify**: `cargo xtask` compiles and runs without error. Depends on step 1 for the `netfyr-cli` dependency.

3. **Implement man page generation logic in `xtask/src/main.rs`.**
   - Implement the full `generate_man_pages()` function and all helper functions for appending troff sections.
   - **Verify**: `cargo xtask man` generates `man/netfyr.1`, `man/netfyr-apply.1`, `man/netfyr-query.1`. Each file contains NAME, SYNOPSIS, DESCRIPTION, OPTIONS, EXIT STATUS, FILES, EXAMPLES, and SEE ALSO sections. Running `man ./man/netfyr.1` renders without troff warnings.

4. **Create the hand-written `man/netfyr-examples.7`.**
   - Write the complete troff file with all seven scenario sections.
   - **Verify**: `man ./man/netfyr-examples.7` renders without warnings, all sections are present, YAML examples are properly formatted.

## Risks and Mitigations

### R1 — `netfyr-cli` lib refactor breaks compilation
**Risk**: Moving `Cli` and `Commands` out of `main.rs` could break internal imports or module visibility.
**Mitigation**: The `apply` and `query` modules are declared in `main.rs` with `mod apply; mod query;`. Moving these declarations to `lib.rs` means `main.rs` no longer owns the modules. Since `main.rs` only calls `apply::run_apply` and `query::run_query` indirectly through `Commands` match arms, it needs access via `netfyr_cli::` paths. The key insight: `main.rs` in a hybrid lib+bin crate imports from the lib using `use netfyr_cli::...`, not `use crate::...`. The apply/query modules must be `pub(crate)` so that `main.rs` (which is the bin target, not part of the lib) can... actually, the bin target can access `pub(crate)` items? No — the bin target is a separate crate. The `main.rs` binary can only access `pub` items from the library. However, `main.rs` doesn't need to access `apply` or `query` directly — it only needs `Cli` and `Commands`. The match arms in `main.rs` call `apply::run_apply(args)` — but `apply` is a module of the lib crate, not directly accessible from `main.rs` unless re-exported. **Resolution**: Either (a) make the run functions accessible through the `Commands` enum (add methods), or (b) re-export `run_apply` and `run_query` from `lib.rs` as `pub`. Option (b) is simpler: add `pub use apply::run_apply;` and `pub use query::run_query;` to `lib.rs`, then `main.rs` uses `netfyr_cli::run_apply` etc. The `ApplyArgs` and `QueryArgs` are already `pub`.

### R2 — Troff syntax errors cause `man` rendering warnings
**Risk**: Hand-written troff macros in the xtask output or in `netfyr-examples.7` could contain syntax errors.
**Mitigation**: Use only well-known troff macros (`.SH`, `.TP`, `.PP`, `.RS`, `.RE`, `.IP`, `.nf`, `.fi`, `.BR`). Keep the troff simple — no conditional logic or register manipulation. Verify by running `man -W ./man/netfyr.1` (which reports warnings) during development.

### R3 — `clap_mangen` subcommand naming
**Risk**: Without renaming, subcommand man pages would show `APPLY(1)` instead of `NETFYR-APPLY(1)`.
**Mitigation**: The spec's pseudocode already shows the fix: `subcmd.clone().name("netfyr-apply")`. This is straightforward clap API usage.

### R4 — Idempotency
**Risk**: Generated files could differ between runs (e.g., timestamps, random ordering).
**Mitigation**: `clap_mangen` output is deterministic for a given `Command` tree. The appended sections are static strings. `fs::write` atomically replaces the file. No timestamps or random data are included. Idempotency is inherent.

### R5 — Forward reference to `netfyr.yaml(5)`
**Risk**: SEE ALSO sections reference `netfyr.yaml(5)` from SPEC-503, which doesn't exist yet.
**Mitigation**: `man` does not validate cross-references in SEE ALSO — it just renders them as text. Including the reference now is harmless and will become useful when SPEC-503 is implemented.

### R6 — `clap_mangen` version compatibility
**Risk**: `clap_mangen 0.2` might not be compatible with the project's `clap 4`.
**Mitigation**: `clap_mangen 0.2.x` is specifically designed for `clap 4`. The crate's Cargo.toml declares `clap = "4"` as a dependency, so version resolution will succeed.

## Test Strategy

### Unit tests (in xtask)
Not needed for the xtask itself — it's a developer tool, not shipped code. The acceptance criteria are verified by running `cargo xtask man` and inspecting the output.

### Integration tests (manual / CI verification)
The following should be verified, corresponding to the acceptance criteria:

1. **Generation produces expected files**: After `cargo xtask man`, check that `man/netfyr.1`, `man/netfyr-apply.1`, `man/netfyr-query.1` exist.
2. **Content correctness**: For each generated file, verify:
   - Contains `.SH NAME`, `.SH SYNOPSIS`, `.SH DESCRIPTION`, `.SH OPTIONS`, `.SH "EXIT STATUS"`, `.SH FILES`, `.SH EXAMPLES`, `.SH "SEE ALSO"` sections.
   - `netfyr.1` DESCRIPTION mentions `apply` and `query`.
   - `netfyr-apply.1` OPTIONS includes `--dry-run` and the positional `path` argument.
   - EXIT STATUS lists codes 0, 1, 2.
   - EXAMPLES has at least two examples per page.
   - SEE ALSO includes cross-references to sibling pages and `netfyr.yaml(5)`.
3. **Rendering**: `man ./man/netfyr.1` (and each other page) renders without troff warnings.
4. **Hand-written page**: `man ./man/netfyr-examples.7` renders correctly, NAME contains "netfyr-examples", and all seven scenario sections are present with YAML examples.
5. **Idempotency**: Running `cargo xtask man` twice produces byte-identical files (verify with `diff` or `sha256sum`).
6. **No overwrite of hand-written file**: `man/netfyr-examples.7` is not modified by `cargo xtask man` (it's never in the write path).
7. **Sync with CLI**: If a flag is added to clap definitions, re-running `cargo xtask man` picks it up in the OPTIONS section.
8. **Existing tests still pass**: `cargo test -p netfyr-cli` passes after the lib refactor.

### What NOT to test
- Troff rendering quality (subjective, and `man` is the authority).
- `clap_mangen` internals (third-party crate, not our responsibility).
- The xtask's own CLI parsing (trivial, one subcommand with no arguments).
