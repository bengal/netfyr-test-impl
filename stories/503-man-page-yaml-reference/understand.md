# Understand: SPEC-503 — YAML Reference Man Page

## Current State

`man/netfyr.yaml.5` **already exists** at the workspace root. The previous understand.md was incorrect — the file is present and substantially complete. It is a hand-written troff man page with the required hand-maintenance comment on line 1.

The file contains all sections required by the specification:

| Section | Present | Notes |
|---------|---------|-------|
| `.TH NETFYR.YAML 5` header | Yes | Correct section number |
| `NAME` — "netfyr.yaml — netfyr policy file formats" | Yes | |
| `DESCRIPTION` | Yes | Overview with multi-doc mention |
| `BARE STATE FORMAT` | Yes | Flat format, one inline example |
| `POLICY FORMAT` | Yes | All 7 fields; 3 examples (static/single, static/multi, dhcpv4) |
| `MULTI-DOCUMENT FILES` | Yes | `---` separator, one example |
| `SELECTORS` | Yes | name, driver, pci_path, mac; dhcpv4 note |
| `FIELDS` — Ethernet | Yes | mtu, addresses, routes, state |
| `VALUE TYPES` | Yes | Type mapping table |
| `FILES` | Yes | `/etc/netfyr/policies/`, `/var/lib/netfyr/policies/` |
| `SEE ALSO` | Yes | netfyr(1), netfyr-apply(1), netfyr-query(1), netfyr-examples(7) |

The other man pages (`netfyr.1`, `netfyr-apply.1`, `netfyr-query.1`, `netfyr-examples.7`) already cross-reference `netfyr.yaml(5)` via `append_see_also` in `xtask/src/main.rs`.

`xtask/src/main.rs` generates only `.1` pages from clap definitions and does not touch `netfyr.yaml.5`. Its printed note on line 89 mentions only `netfyr-examples.7`.

## Requirements

The acceptance criteria translate into these concrete requirements:

1. **File exists**: `man/netfyr.yaml.5` present in the repository. ✓
2. **Renders without troff warnings**: `man ./man/netfyr.yaml.5` succeeds cleanly.
3. **NAME section** contains "netfyr.yaml". ✓
4. **BARE STATE FORMAT** describes flat format with type/selector/config at top level; at least one example. ✓
5. **POLICY FORMAT** documents kind, name, factory, priority, selector, state, states; examples for static and dhcpv4. ✓
6. **Factory types documented**: `static` and `dhcpv4`. ✓
7. **MULTI-DOCUMENT FILES** explains `---` separator with example. ✓
8. **SELECTORS** lists name, driver, pci_path, mac. ✓
9. **FIELDS** lists mtu, addresses, routes, state. ✓
10. **VALUE TYPES** shows YAML-to-netfyr type mapping. ✓ (with IPv6 accuracy issue — see Gap Analysis)
11. **FILES** lists `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/`. ✓
12. **xtask `man` does not overwrite** `man/netfyr.yaml.5`. ✓ (structurally safe; note incomplete)

## Gap Analysis

The file exists and satisfies the structural acceptance criteria. Two content-level discrepancies against the specification remain:

### Gap 1 — IPv6 language contradicts the spec (content error)

**Location**: `man/netfyr.yaml.5`, lines 265 and 310–318.

**Problem**: The spec is explicit that IPv6 is not supported:
> *"IPv6 is not supported. Strings containing IPv6 addresses (e.g., 'fe80::1') are treated as plain strings and will fail schema validation if used in address fields."*

The current file contradicts this in two places:

- **Line 265** (FIELDS → addresses): *"Both IPv4 and IPv6 addresses are accepted."*
- **Lines 310–316** (VALUE TYPES): Lists `::1` as an example IpAddr and implies IPv6 CIDR prefixes are valid IpNetwork values.

**Required changes to `man/netfyr.yaml.5`**:
- Line 265: Change "Both IPv4 and IPv6 addresses are accepted" to match the spec's IPv4-only CIDR notation language.
- VALUE TYPES rows: Change "YAML string (valid IP address)" → "YAML string (valid IPv4 address)", remove `::1` example; change "YAML string (valid CIDR prefix)" → "YAML string (valid IPv4 CIDR prefix)"; add a note that IPv6 strings are treated as plain strings and fail schema validation.

### Gap 2 — xtask printed note does not mention netfyr.yaml.5 (minor documentation gap)

**Location**: `xtask/src/main.rs`, line 89 and the `Man` subcommand doc comment (lines 26–28).

**Problem**: The note printed after generation only mentions `netfyr-examples.7`. The spec states the xtask `man` subcommand does not generate or overwrite `netfyr.yaml.5`. While the code is already safe (it never writes this file), the comment and output message should name both hand-maintained files.

**Required change to `xtask/src/main.rs`**:
- Update the `println!` on line 89 from mentioning only `netfyr-examples.7` to also mention `netfyr.yaml.5`.
- Update the `Man` subcommand doc comment to note `netfyr.yaml.5` is also maintained by hand.

### No other files need creation or modification.

The man page itself requires only targeted content fixes. No new crates, modules, types, or test files are needed.

## Integration Points

- **`man/netfyr-examples.7`**: Cross-references `netfyr.yaml(5)`. The file already exists, so the reference resolves.
- **`man/netfyr.1`, `man/netfyr-apply.1`, `man/netfyr-query.1`**: All emit `netfyr.yaml(5)` in SEE ALSO via `append_see_also`. No changes needed.
- **`xtask/src/main.rs`**: Minor doc/print update only; no functional changes needed.
- **`netfyr-state/src/yaml.rs` (`deserialize_value`)**: The VALUE TYPES section must accurately reflect what `deserialize_value` actually does with YAML scalars. The IPv4-only restriction in the spec should be verified against the function body before finalising the IPv6 note language.
- **`netfyr-state/src/schemas/`**: Route field optionality (`gateway`, `metric`) is defined in schema JSON files not visible in the context snapshot. The current man page documents `gateway` as optional — this should match the schema definition.
- **RPM spec (SPEC-502)**: No RPM spec file exists yet. When added, it will need `%install` and `%files` entries for `man5/netfyr.yaml.5`. This is out of scope for the current story.

## Risks

1. **IPv4/IPv6 implementation reality**: Before correcting the man page to say IPv6 is unsupported, verify that `deserialize_value` in `yaml.rs` actually rejects IPv6 strings as `IpAddr`. If the implementation does parse IPv6 but schema validation rejects it, the distinction matters for accurate documentation. The function body is not in the context snapshot.

2. **Troff rendering not validated**: The acceptance criteria include verifying `man ./man/netfyr.yaml.5` renders without warnings. The existing file uses `.BR \-\-\-` (line 12) to format `---`; this is correct troff for a literal display, but should be confirmed with `groff`. No CI step currently validates man page rendering.

3. **`state` field name collision in FIELDS**: The ethernet configuration field named `state` (values: "up"/"down") shares its name with the `state:` mapping key in the policy format. The current man page handles this via section separation but does not explicitly call out the collision — readers skimming could confuse the two uses.

4. **Route sub-field optionality**: The man page documents `gateway` as optional for route entries. If the schema marks it as required, the documentation is misleading. The schema files under `crates/netfyr-state/src/schemas/` are not in the context snapshot.

5. **No automated content tests**: The xtask test suite only covers section-1 helper functions. Man page content correctness is verified manually. No test infrastructure for `netfyr.yaml.5` exists or is required by this story.
