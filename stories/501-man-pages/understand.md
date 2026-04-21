## Current State

The story is almost entirely implemented. All infrastructure and most content is already in place.

### `xtask/` crate

- **`xtask/Cargo.toml`** — exists with correct dependencies: `clap_mangen = "0.2"`, `clap` (`derive`+`string` features), `netfyr-cli = { path = "../crates/netfyr-cli" }`.
- **`xtask/src/main.rs`** — fully implemented. Defines `XtaskCommand::Man`, `generate_man_pages()`, and four troff-section helpers: `append_exit_status`, `append_files`, `append_examples`, `append_see_also`. The `append_examples` function has explicit branches for `None` (top-level), `apply`, `query`, `history`, and `revert`. `generate_man_pages()` only writes named files and never touches `netfyr-daemon.8` or `netfyr-examples.7`. The test suite has ~100 unit tests covering EXIT STATUS content, FILES paths, EXAMPLES `.nf` block counts, SEE ALSO cross-references, and the idempotency/non-overwrite property for the five generated pages and both hand-written pages.

### `.cargo/config.toml`

Exists at workspace root with the alias:
```toml
[alias]
xtask = "run --package xtask --"
```

### `man/` directory

Present at workspace root. Contents:

| File | Status |
|---|---|
| `man/netfyr.1` | Auto-generated — exists |
| `man/netfyr-apply.1` | Auto-generated — exists |
| `man/netfyr-query.1` | Auto-generated — exists |
| `man/netfyr-history.1` | Auto-generated — exists |
| `man/netfyr-revert.1` | Auto-generated — exists |
| `man/netfyr-examples.7` | Hand-written — exists, complete |
| `man/netfyr.yaml.5` | Hand-written — exists, complete |
| `man/netfyr-daemon.8` | **MISSING** |

`netfyr-examples.7` is complete: hand-maintenance comment at line 1, `.TH NETFYR-EXAMPLES 7` header, all required scenario sections (static IP, multiple interfaces, DHCP, mixed static+DHCP, priority override, selecting by driver, dry-run workflow, history investigation, external change detection, reverting), each with at least one `.nf` block, and a SEE ALSO section.

---

## Requirements

From the acceptance criteria, the following must be satisfied:

1. `cargo xtask man` generates the five section-1 pages without overwriting `netfyr-daemon.8` or `netfyr-examples.7`.
2. Each generated page includes EXIT STATUS (codes 0/1/2), FILES, EXAMPLES (≥2 `.nf` blocks), and SEE ALSO.
3. `netfyr-apply.1` OPTIONS documents `--dry-run` and the `<path>` positional argument.
4. `man/netfyr-daemon.8` exists as a hand-written section-8 troff file with a hand-maintenance comment.
5. Daemon page sections: NAME, SYNOPSIS, DESCRIPTION, EXTERNAL CHANGE DETECTION, JOURNAL, ENVIRONMENT, FILES, SEE ALSO.
6. EXTERNAL CHANGE DETECTION documents: only managed interfaces monitored, monitored properties (mtu/state/flags/IPv4 addresses), 500ms debounce window, no automatic re-reconciliation.
7. JOURNAL section describes NDJSON format, rotation/retention, and references `netfyr-history(1)` and `netfyr-revert(1)`.
8. ENVIRONMENT section lists all six variables: `NETFYR_SOCKET_PATH`, `NETFYR_POLICY_DIR`, `NETFYR_JOURNAL_DIR`, `NETFYR_JOURNAL_MAX_ENTRIES`, `NETFYR_JOURNAL_MAX_SIZE`, `NETFYR_JOURNAL_RETENTION_DAYS`.
9. Generation is idempotent.

---

## Gap Analysis

**Exactly one file is missing:** `man/netfyr-daemon.8`.

Everything else — xtask crate, Cargo alias, five generated section-1 pages, `netfyr-examples.7`, and `netfyr.yaml.5` — is present and complete. No changes to `xtask/src/main.rs`, `xtask/Cargo.toml`, or `.cargo/config.toml` are needed.

**File to create: `man/netfyr-daemon.8`**

A hand-written troff file. Must contain:
- Opening `.\"` hand-maintenance comment
- `.TH NETFYR-DAEMON 8` header (section 8 per Unix convention for system daemons)
- `.SH NAME` — `netfyr-daemon \- netfyr network configuration daemon`
- `.SH SYNOPSIS` — `netfyr-daemon`
- `.SH DESCRIPTION` — daemon overview including systemd startup note
- `.SH "EXTERNAL CHANGE DETECTION"` — four sub-points: managed-only monitoring, monitored properties, 500ms debounce, no automatic re-reconciliation
- `.SH JOURNAL` — NDJSON format, rotation (10k entries / 50MB), retention (90 days), references to `netfyr-history(1)` and `netfyr-revert(1)`, configurable via environment variables
- `.SH ENVIRONMENT` — `.TP` entries for all six `NETFYR_*` variables with defaults
- `.SH FILES` — four paths: `/run/netfyr/netfyr.sock`, `/var/lib/netfyr/policies/`, `/var/lib/netfyr/journal/`, `/etc/netfyr/policies/`
- `.SH "SEE ALSO"` — `netfyr(1)`, `netfyr-apply(1)`, `netfyr-query(1)`, `netfyr-history(1)`, `netfyr-revert(1)`, `netfyr.yaml(5)`, `netfyr-examples(7)`, `systemd(1)`

The xtask test suite does **not** include automated tests for `netfyr-daemon.8` content; acceptance is by manual `man ./man/netfyr-daemon.8` inspection.

---

## Integration Points

- **`xtask/src/main.rs` `generate_man_pages()`** — already skips `netfyr-daemon.8` (the function only writes explicitly named files). No changes needed.
- **`man/netfyr-examples.7`** — its EXTERNAL CHANGE DETECTION section ends with "See `netfyr-daemon(8)` for full details on limitations." `netfyr-daemon.8` must exist for this cross-reference to resolve with `man`.
- **`man/netfyr.1` SEE ALSO** — currently references the five subcommand pages, `netfyr-examples(7)`, and `netfyr.yaml(5)` but not `netfyr-daemon(8)`. The spec example for the top-level page SEE ALSO also omits `netfyr-daemon(8)`, so this is consistent and requires no change.
- **`xtask` idempotency test** (`test_regeneration_is_idempotent_and_does_not_overwrite_examples_7`) — reads `netfyr-examples.7` before and after calling `generate_man_pages()`. Since `generate_man_pages()` never touches `netfyr-daemon.8`, adding the daemon page does not affect this test.

---

## Risks

1. **troff syntax correctness** — the file must use correct macro sequences. Unescaped hyphens in option names (`\-` required in troff), unescaped single quotes, or missing `.PP` paragraph breaks will produce `man` rendering warnings. The spec example uses `\-` for hyphens in command output; the hand-written file must follow the same convention used in `netfyr-examples.7` and `netfyr.yaml.5`.

2. **Section-8 `.TH` format** — the `.TH` line must explicitly declare section `8`. `clap_mangen` is not used for this file, so the section number is set by hand. A wrong value (e.g. `1` or omitted) would cause `man -s 8` to fail to locate the page after RPM installation.

3. **No automated test guard** — daemon page content can drift from actual daemon behavior (e.g. if debounce window changes from 500ms) without any test failing. This is inherent to hand-written pages and is noted in the spec.

4. **`groff`/`man` availability** — acceptance criteria include rendering without troff warnings, which requires `groff` or `man` to be installed. No automated test infrastructure for this exists; it is a manual verification step.

5. **`netfyr-daemon.8` not excluded in `generate_man_pages()` log message** — the current print at line 89 says "man/netfyr.yaml.5 and man/netfyr-examples.7 are maintained by hand". After this story lands, `netfyr-daemon.8` should be mentioned too. This is cosmetic but may confuse future contributors. Minor fix opportunity in `xtask/src/main.rs` line 89.
