# Understand: SPEC-503 — YAML Reference Man Page

## Current State

`man/netfyr.yaml.5` exists and is fully implemented (358 lines). It is a hand-written troff man page with the required maintenance comment on line 1 (`This file is maintained by hand. Do not edit with cargo xtask man.`).

All sections required by the specification are present and correct:

| Section | Present | Notes |
|---|---|---|
| `.TH NETFYR.YAML 5` header | Yes | Correct section number and title |
| `NAME` — "netfyr.yaml — netfyr policy file formats" | Yes | |
| `DESCRIPTION` | Yes | Overview with multi-doc mention and cross-ref to netfyr-examples(7) |
| `BARE STATE FORMAT` | Yes | Flat format described; one inline example |
| `POLICY FORMAT` | Yes | All 7 fields (kind, name, factory, priority, selector, state, states); 3 examples (static/single, static/multi, dhcpv4); both factory types described |
| `MULTI-DOCUMENT FILES` | Yes | `---` separator explained; one example |
| `SELECTORS` | Yes | name, driver, pci_path, mac; dhcpv4 note present |
| `FIELDS — Ethernet` | Yes | mtu, addresses (IPv4-only, no IPv6), routes (destination/gateway/metric), state (up/down) |
| `VALUE TYPES` | Yes | Full type mapping table; IPv4-only language with explicit IPv6 note |
| `FILES` | Yes | `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/` |
| `SEE ALSO` | Yes | netfyr(1), netfyr-apply(1), netfyr-query(1), netfyr-history(1), netfyr-revert(1), netfyr-examples(7) |

`xtask/src/main.rs` (line 89) prints: `"Note: man/netfyr.yaml.5 and man/netfyr-examples.7 are maintained by hand and were not modified."` The `Man` subcommand doc comment (line 28) explicitly states: `"Does not overwrite man/netfyr.yaml.5 or man/netfyr-examples.7 (maintained by hand)."` Both are correct.

The `xtask/src/main.rs` test suite (lines 516–1016) contains comprehensive content tests for `man/netfyr.yaml.5` covering all acceptance criteria from the spec.

`results.md` records: **Status: PASS** — no changes were required; all tests passed on first run.

## Requirements

All acceptance criteria are satisfied by existing code:

1. `man/netfyr.yaml.5` exists. ✓
2. Renders without troff warnings (verified via `groff -man -Tascii`). ✓
3. NAME section contains "netfyr.yaml". ✓
4. BARE STATE FORMAT: flat format with type/selector/config at top level; one example. ✓
5. POLICY FORMAT: kind, name, factory, priority, selector, state, states; static and dhcpv4 examples. ✓
6. Factory types `static` and `dhcpv4` documented with descriptions. ✓
7. MULTI-DOCUMENT FILES: `---` separator explained with example. ✓
8. SELECTORS: name, driver, pci_path, mac all listed. ✓
9. FIELDS: mtu, addresses, routes, state all listed. ✓
10. VALUE TYPES: full YAML-to-netfyr type mapping; IPv4-only strings map to IpAddr/IpNetwork; IPv6 note. ✓
11. FILES: both `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/` listed. ✓
12. xtask `man` does not overwrite `man/netfyr.yaml.5`. ✓

## Gap Analysis

**No gaps.** The story is fully implemented. All acceptance criteria are met by the existing `man/netfyr.yaml.5` file and the supporting xtask infrastructure.

## Integration Points

- **`xtask/src/main.rs`**: Does not touch `man/netfyr.yaml.5`; mentions it explicitly in the printed note and doc comment. No changes needed.
- **`man/netfyr.1`, `man/netfyr-apply.1`, etc.**: All emit `netfyr.yaml(5)` in SEE ALSO via `append_see_also`. No changes needed.
- **`man/netfyr-examples.7`**: Cross-references `netfyr.yaml(5)`. Already correct.
- **RPM spec (SPEC-502)**: A separate story; `%install` and `%files` entries for `man5/netfyr.yaml.5` belong there, not here.

## Risks

No risks for this story — it is complete. The following are informational notes for future maintainers:

1. **IPv4-only restriction**: The man page correctly documents IPv4-only support. If IPv6 support is added to `deserialize_value` in `netfyr-state/src/yaml.rs` in the future, `man/netfyr.yaml.5` must be updated manually (no auto-generation exists).

2. **No troff CI gate**: Man page rendering correctness is verified manually (or via `groff`). There is no automated CI step that runs `groff` against `man/netfyr.yaml.5`. If troff syntax regressions are a concern, a CI job would need to be added separately.

3. **`state` field name collision**: The ethernet configuration field `state` (values: `up`/`down`) shares its name with the `state:` policy mapping key. The current man page handles this through section separation, which is adequate.
