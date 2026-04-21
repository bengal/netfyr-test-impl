# Understand: SPEC-503 — YAML Reference Man Page

## Current State

`man/netfyr.yaml.5` exists and is fully implemented (358 lines of troff). It carries the required hand-maintenance comment on line 1. All spec-required sections are present:

- `.TH "NETFYR.YAML" 5` header (section 5, File Formats Manual)
- `NAME`: "netfyr.yaml — netfyr policy file formats"
- `DESCRIPTION`: overview with multi-doc mention and cross-ref to `netfyr-examples(7)`
- `BARE STATE FORMAT`: flat format described; `type` field documented; one `.nf` example
- `POLICY FORMAT`: all 7 fields (`kind`, `name`, `factory`, `priority`, `selector`, `state`, `states`); factory types `static` and `dhcpv4` each described; three `.nf` examples (static/single, static/multi, dhcpv4)
- `MULTI-DOCUMENT FILES`: `---` separator explained; one `.nf` example
- `SELECTORS`: `name`, `driver`, `pci_path`, `mac`; dhcpv4 collision note
- `FIELDS` → Ethernet subsection: `mtu`, `addresses`, `routes` (with `destination`/`gateway`/`metric` sub-keys), `state`
- `VALUE TYPES`: complete YAML→netfyr type mapping; IPv6 limitation noted
- `FILES`: `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/`
- `SEE ALSO`: `netfyr(1)`, `netfyr-apply(1)`, `netfyr-query(1)`, `netfyr-history(1)`, `netfyr-revert(1)`, `netfyr-examples(7)`

`xtask/src/main.rs` (line 90) explicitly skips `netfyr.yaml.5` during generation. The xtask test suite (lines 522–1021) contains 39 content-level tests that verify every section, field, factory type, and value type mapping in this file.

`netfyr.spec` already installs the file (`install -pm 0644 man/netfyr.yaml.5 %{buildroot}%{_mandir}/man5/`) and declares it in `%files` (`%{_mandir}/man5/netfyr.yaml.5*`).

## Requirements

From the acceptance criteria, the following must hold:

1. `man/netfyr.yaml.5` exists.
2. Renders without troff warnings under `man`/`groff`.
3. NAME section contains "netfyr.yaml".
4. BARE STATE FORMAT documents flat format with `type`, selector fields, and config fields; at least one example.
5. POLICY FORMAT documents `kind`, `name`, `factory`, `priority`, `selector`, `state`, `states`; examples for both `static` and `dhcpv4` factories.
6. MULTI-DOCUMENT FILES explains `---` separator; at least one example.
7. SELECTORS lists `name`, `driver`, `pci_path`, `mac`.
8. FIELDS lists `mtu`, `addresses`, `routes`, `state` for `type: ethernet`.
9. VALUE TYPES shows YAML→netfyr type mapping (Bool, U64, I64, IpAddr, IpNetwork, String, List, Map).
10. FILES lists `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/`.
11. xtask `man` subcommand does not overwrite the file.
12. RPM spec installs it under `man5/`.

## Gap Analysis

**No gaps.** Every requirement is met by the existing implementation. No files need to be created or modified.

The only cosmetic discrepancy: the spec's SEE ALSO example includes `netfyr-daemon(8)` but the current file's SEE ALSO omits it. No acceptance-criteria test enforces this reference, so it is not a blocking gap.

## Integration Points

- **`xtask/src/main.rs`**: `generate_man_pages()` skips `netfyr.yaml.5`; tests read it directly from the `man/` directory. No changes required.
- **Generated section-1 pages** (`netfyr.1`, `netfyr-apply.1`, etc.): all reference `netfyr.yaml(5)` in SEE ALSO via `append_see_also`. Already correct.
- **`netfyr.spec`**: `%install` and `%files` entries for the section-5 page are already present.

## Risks

1. **SEE ALSO omits `netfyr-daemon(8)`**: Cosmetically inconsistent with spec but untested. A future test would fail if added.
2. **No troff CI gate**: Rendering correctness (`groff -man`) is not automated; it remains a manual verification step.
3. **Hand-maintenance bus risk**: If ethernet fields are added or renamed in `netfyr-state/src/schema.rs`, the man page must be updated manually — there is no generation pipeline to catch drift.
