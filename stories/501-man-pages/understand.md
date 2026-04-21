## Current State

The `xtask` crate, `man/` directory, and hand-written files are all substantially complete. The story is largely implemented.

### `xtask/` crate

- **`xtask/Cargo.toml`** — exists; declares `clap_mangen = "0.2"`, `clap` with `derive`+`string` features, and `netfyr-cli = { path = "../crates/netfyr-cli" }`. Matches the spec.
- **`xtask/src/main.rs`** — exists and implements the `man` subcommand with `generate_man_pages()`. Iterates `Cli::command().get_subcommands()` to produce one page per subcommand. Four helper functions append manual troff sections: `append_exit_status`, `append_files`, `append_examples`, `append_see_also`. Includes ~50 unit tests covering EXIT STATUS, FILES, EXAMPLES, and SEE ALSO content for the `apply` and `query` subcommands and the top-level page.

### `netfyr-cli` crate

- **`crates/netfyr-cli/src/lib.rs`** — exists and exports `Cli`, `Commands`, `run_apply`, `run_history`, `run_query`, `run_revert`. `Cli` is `pub` and derives `Parser` (making `CommandFactory` available). All four subcommands — `apply`, `query`, `history`, `revert` — are defined.
- `crates/netfyr-cli/Cargo.toml` has a `[lib]` section (implied by the lib.rs existing and being importable from xtask).

### `man/` directory

All seven files already exist at the workspace root:

| File | Type | Lines |
|---|---|---|
| `netfyr.1` | auto-generated | 79 |
| `netfyr-apply.1` | auto-generated | 63 |
| `netfyr-query.1` | auto-generated | 71 |
| `netfyr-history.1` | auto-generated | 72 |
| `netfyr-revert.1` | auto-generated | 52 |
| `netfyr-examples.7` | hand-written | 163 |
| `netfyr.yaml.5` | hand-written | 357 |

`netfyr-examples.7` is complete: it has the hand-maintenance comment, all seven required scenarios (static IP, multiple interfaces, DHCP, mixed static+DHCP, priority override, selecting by driver, dry-run workflow), each with a copy-pasteable YAML example, and a SEE ALSO section referencing all sibling pages.

### `.cargo/config.toml`

Does **not** exist. No files were found under `.cargo/`.

---

## Requirements

From the acceptance criteria, the following must hold:

1. `cargo xtask man` runs and creates/updates the `man/` directory.
2. Produced files: `netfyr.1`, `netfyr-apply.1`, `netfyr-query.1`, `netfyr-history.1`, `netfyr-revert.1`.
3. `netfyr-examples.7` is not overwritten.
4. Each generated page includes EXIT STATUS (codes 0/1/2), FILES (`/etc/netfyr/policies/`), EXAMPLES (≥2 per subcommand), and SEE ALSO.
5. `netfyr-apply.1` OPTIONS documents `--dry-run` and `<path>`.
6. SEE ALSO for `apply` references `netfyr(1)`, `netfyr-query(1)`, `netfyr.yaml(5)`.
7. `netfyr-examples.7` covers all 7 annotated scenarios.
8. `cargo xtask` alias works.
9. Generation is idempotent.

---

## Gap Analysis

### Gap 1 — `.cargo/config.toml` is missing (BLOCKING)

**File to create:** `/workspace/.cargo/config.toml`

Without this file `cargo xtask man` fails with "no such subcommand: xtask". The required content is:

```toml
[alias]
xtask = "run --package xtask --"
```

This is the only entirely absent file mandated by the spec.

### Gap 2 — `append_examples` has no arms for `history` and `revert` (FUNCTIONAL)

**File to modify:** `xtask/src/main.rs`, function `append_examples`

The match covers `None`, `Some("apply")`, `Some("query")`, and a catch-all `Some(other)`. The catch-all emits only:

```
See netfyr-<other>(1) for usage details.
```

This produces **zero** `.nf` blocks. The spec requires at least two real-world usage examples per subcommand. `netfyr-history.1` and `netfyr-revert.1` currently fail this requirement.

Required additions:
- `Some("history")` arm — two examples using real `HistoryArgs` flags (e.g., bare `netfyr history`, and a filtered invocation with `--since` or `--limit`).
- `Some("revert")` arm — two examples using real `RevertArgs` fields (e.g., `netfyr revert <seq>` and `netfyr revert --dry-run <seq>`).

### Gap 3 — No unit tests for `history` and `revert` EXAMPLES (TEST COVERAGE)

**File to modify:** `xtask/src/main.rs`, `#[cfg(test)]` block

No tests assert that `history` or `revert` EXAMPLES sections contain at least two `.nf` blocks or include subcommand-specific content. These should be added once Gap 2 is resolved, following the pattern of `test_apply_examples_has_at_least_two_nf_blocks`.

---

## Integration Points

- **`netfyr-cli::Cli`** (`crates/netfyr-cli/src/lib.rs:50`) — xtask calls `Cli::command()`. `Cli` must remain `pub` with `#[derive(Parser)]`. No changes needed.
- **`ApplyArgs`** (`crates/netfyr-cli/src/apply.rs`) — `--dry-run` and `<path>` are already defined; they flow into OPTIONS automatically via `clap_mangen`. No changes needed.
- **`HistoryArgs`** (`crates/netfyr-cli/src/history.rs`) — flags like `--since`, `--limit`, `--trigger`, `--selector`, `--output` must be reflected accurately in the new EXAMPLES arm. The `parse_since` function accepts duration strings (e.g. `"1h"`, `"24h"`) as well as RFC3339 timestamps.
- **`RevertArgs`** (`crates/netfyr-cli/src/revert.rs`) — accepts a sequence ID positional argument and `--dry-run`. The EXAMPLES arm must match these actual flags.
- **`man/netfyr-examples.7`** — hand-written; the xtask does not generate it (it is not a CLI subcommand and the loop only processes `get_subcommands()`). The `println!` note at the end of `generate_man_pages()` confirms the intent. No code change needed to protect it.

---

## Risks

1. **`HistoryArgs`/`RevertArgs` flag names** — the EXAMPLES text for Gap 2 must use actual flag names. Consulting `history.rs` and `revert.rs` before writing is necessary to avoid documenting flags that don't exist or with wrong syntax.

2. **Idempotency with `clap_mangen` dates** — `clap_mangen 0.2` may embed the current date in the `.TH` macro of the generated troff. If so, running `cargo xtask man` on different days produces different files, violating the idempotency acceptance criterion. This should be verified; the `Man` builder may accept a date override via `Man::date()`.

3. **`netfyr.yaml.5` forward reference** — SEE ALSO sections reference `netfyr.yaml(5)` (SPEC-503). The file already exists in `man/` (357 lines), so this is not a risk — the cross-reference is already satisfied.

4. **`groff`/`man` availability in CI** — the acceptance criterion "man pages render without troff warnings" requires `groff` or `man`. No automated test infrastructure for this exists in the codebase. This criterion can only be validated manually or in a CI job that installs `groff`.

5. **Workspace membership** — the context snapshot shows `xtask/` as a workspace member (it is listed in the module structure and its `Cargo.toml` references the workspace), but the root `Cargo.toml` was not directly verified. If `xtask` is not in `[workspace] members`, `cargo run --package xtask` will fail even with the alias in place.
