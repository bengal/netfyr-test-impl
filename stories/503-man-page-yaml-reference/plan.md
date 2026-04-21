# Plan: SPEC-503 — YAML Reference Man Page

## Approach

The `man/netfyr.yaml.5` troff man page already exists and is structurally complete. It contains all required sections (NAME, DESCRIPTION, BARE STATE FORMAT, POLICY FORMAT, MULTI-DOCUMENT FILES, SELECTORS, FIELDS, VALUE TYPES, FILES, SEE ALSO) with inline examples covering static/single, static/multi, and dhcpv4 factories. The work is a targeted content correction, not a file creation task.

Two discrepancies remain between the current file and the specification:

1. **IPv6 language in the man page contradicts the spec and the implementation.** The spec states IPv6 is not supported. The implementation confirms this: `deserialize_value` in `crates/netfyr-state/src/yaml.rs` (lines 105-119) only uses `Ipv4Network::from_str` and `Ipv4Addr::from_str` — any IPv6 string falls through to `Value::String` and will fail schema validation when used in address fields. The man page incorrectly claims "Both IPv4 and IPv6 addresses are accepted" (line 265) and lists `::1` as an IpAddr example in the VALUE TYPES section (line 314). These must be corrected to match reality.

2. **The xtask printed note and doc comment only mention `netfyr-examples.7` as hand-maintained**, omitting `netfyr.yaml.5`. While the xtask code is already safe (it never writes to `netfyr.yaml.5`), the documentation should be accurate so developers running `cargo xtask man` know both files exist outside the generation pipeline.

No new files, crates, modules, or dependencies are needed.

## Design Decisions

1. **Decision**: Correct the man page to say IPv4-only, matching both the spec and the actual `deserialize_value` implementation.
   - **Alternatives considered**: Leaving the man page as-is and changing the implementation to support IPv6 parsing. However, the spec explicitly states IPv6 is not supported, and the `Value` enum only has `IpAddr(Ipv4Addr)` and `IpNetwork(Ipv4Network)` — adding IPv6 support would be a separate feature story.
   - **Rationale**: Documentation must match behavior. The implementation uses `Ipv4Addr::from_str` (line 115) and `Ipv4Network::from_str` (line 111) exclusively. The spec says IPv4-only. The man page is the outlier.

2. **Decision**: Add a note in the VALUE TYPES section explaining that IPv6 address strings are treated as plain `String` values and will fail schema validation if used in address fields.
   - **Alternatives considered**: Simply removing the IPv6 example without explanation.
   - **Rationale**: The spec explicitly calls for this note ("IPv6 is not supported. Strings containing IPv6 addresses (e.g., 'fe80::1') are treated as plain strings and will fail schema validation if used in address fields."), and it helps users who might try IPv6 addresses understand why they fail.

3. **Decision**: Update both the `println!` message (line 89) and the doc comment (line 28) in `xtask/src/main.rs` to list `netfyr.yaml.5` alongside `netfyr-examples.7`.
   - **Alternatives considered**: Only updating the println. However, the doc comment on the `Man` variant is the developer-facing documentation and should be complete.
   - **Rationale**: Consistency between runtime output and source documentation. Prevents a developer from wondering why the section-5 page wasn't regenerated.

4. **Decision**: Keep the man page's `state` field documentation (administrative state: "up"/"down") even though the ethernet JSON schema (`crates/netfyr-state/src/schemas/ethernet.json`) has `operstate` (read-only) but no writable `state` field.
   - **Alternatives considered**: Removing `state` from the FIELDS section because the schema doesn't have it.
   - **Rationale**: The spec explicitly lists `state` as a documented ethernet field. The apply layer (`apply_ethernet` in `crates/netfyr-backend/src/netlink/apply.rs`) likely handles administrative state at a level above schema validation. This man page documents the user-facing YAML format, not the internal schema.

5. **Decision**: Do not modify the `addresses` field description beyond the IPv6 correction. The spec's language about order preservation and duplicate rejection should be added since the current man page is missing these details.
   - **Alternatives considered**: Keeping the minimal current description.
   - **Rationale**: The spec explicitly says "Order is preserved: the first address becomes the primary (source) address. Duplicate addresses are rejected. IPv6 is not supported." These are user-relevant behavioral details.

## File Changes

### 1. `man/netfyr.yaml.5`
- **Action**: modify
- **What**: Four targeted edits within the existing troff file:

  **Edit A — Line 265 (FIELDS section, `addresses` description)**: Replace `"Both IPv4 and IPv6 addresses are accepted."` with text matching the spec: addresses are in IPv4 CIDR notation, order is preserved with the first address becoming the primary (source) address, duplicate addresses are rejected, and IPv6 is not supported.

  **Edit B — Lines 309-314 (VALUE TYPES section, IpAddr row)**: Change the tag from `"YAML string (valid IP address)"` to `"YAML string (valid IPv4 address)"` and remove the `::1` example, keeping only the `10.0.0.1` example. The `(e.g., ...)` parenthetical should show only `10.0.0.1`.

  **Edit C — Lines 316-320 (VALUE TYPES section, IpNetwork row)**: Change the tag from `"YAML string (valid CIDR prefix)"` to `"YAML string (valid IPv4 CIDR prefix)"`. The existing `10.0.0.0/24` example is already IPv4-only and stays.

  **Edit D — After the current IpNetwork `.TP` entry and before the "YAML string (other)" entry**: Insert a `.PP` paragraph note stating: IPv6 addresses are not supported. Strings containing IPv6 addresses (e.g., "fe80::1") are treated as plain strings and will fail schema validation if used in address fields.

- **Why**: Corrects the IPv6 inaccuracy to match both the spec and the implementation in `deserialize_value` (which uses only `Ipv4Addr` and `Ipv4Network`). Adds the spec-required IPv6 note.

### 2. `xtask/src/main.rs`
- **Action**: modify
- **What**: Two edits:

  **Edit A — Line 28 (doc comment on `Man` variant)**: Change:
  `/// Does not overwrite man/netfyr-examples.7 (maintained by hand).`
  to:
  `/// Does not overwrite man/netfyr.yaml.5 or man/netfyr-examples.7 (maintained by hand).`

  **Edit B — Line 89 (println after generation)**: Change:
  `"Note: man/netfyr-examples.7 is maintained by hand and was not modified."`
  to:
  `"Note: man/netfyr.yaml.5 and man/netfyr-examples.7 are maintained by hand and were not modified."`

- **Why**: Documents that `netfyr.yaml.5` is also a hand-maintained file that xtask does not generate or overwrite.

## Dependencies

No new crate dependencies. This story involves only troff content corrections and a Rust string literal change.

## Implementation Order

1. **Edit `man/netfyr.yaml.5`** — Apply all four edits (A through D) to correct the IPv6 references, update the addresses description, and add the IPv6 note. The file is self-contained troff with no build dependencies.

2. **Edit `xtask/src/main.rs`** — Update the println message and doc comment. Independent of step 1 but logically secondary since the man page is the primary deliverable.

3. **Verify** — Run `cargo build --package xtask` to confirm the xtask still compiles. Run `cargo test --package xtask` to confirm existing tests pass (the tests check SEE ALSO cross-references and other section content; they don't touch the modified println or doc comment, but compilation must succeed).

Steps 1 and 2 are independent and can be done in parallel. Step 3 depends on step 2.

## Risks and Mitigations

1. **Risk: `state` field not in ethernet JSON schema.** The man page documents a `state` field ("up"/"down") but the JSON schema at `crates/netfyr-state/src/schemas/ethernet.json` has `operstate` (read-only) and no writable `state` field. The `additionalProperties: false` in the schema would reject a `state` field.
   - **Mitigation**: The spec explicitly requires documenting this field. If the schema needs updating, that's a separate concern. The man page documents what the spec says; the potential schema-vs-spec gap should be noted in the PR description but is out of scope for this documentation story.

2. **Risk: Troff rendering warnings from new content.** The edits add a new `.PP` paragraph block in the VALUE TYPES section.
   - **Mitigation**: Follow the exact troff patterns already used elsewhere in the file. The `.PP` macro is used throughout (e.g., lines 10, 14, 24, 147, 162, 181, 196, 236) and is simple to get right.

3. **Risk: No automated content tests for man page.** Troff content correctness is verified manually. There is no CI step for man page rendering.
   - **Mitigation**: The acceptance criteria call for manual `man ./man/netfyr.yaml.5` rendering verification. The changes are small and surgical — four edits to an existing file. Visual inspection during review is sufficient.

4. **Risk: IPv6 regex patterns in JSON schema.** The schema patterns for `addresses` items and route fields include `[0-9a-fA-F:.]` which could theoretically match some IPv6-like strings.
   - **Mitigation**: Out of scope for this story. The man page documents the YAML-to-Value conversion layer, not the schema regex. The IPv6 note accurately describes behavior at the `deserialize_value` level.

## Test Strategy

No new tests are needed for this story. The changes are:

1. **Man page content corrections** — Troff is a text format. The existing xtask test suite already verifies SEE ALSO cross-references include `netfyr.yaml(5)`. The content corrections are not programmatically testable in the current test infrastructure.

2. **xtask string changes** — The modified println message and doc comment have no behavioral impact and are not covered by tests.

**Verification steps** (manual, matching the acceptance criteria):
- `man ./man/netfyr.yaml.5` renders without troff warnings
- NAME section contains "netfyr.yaml"
- BARE STATE FORMAT section describes the flat format with type, selector, and config fields at the top level, with at least one example
- POLICY FORMAT section documents kind, name, factory, priority, selector, state, and states; includes examples for static and dhcpv4
- MULTI-DOCUMENT FILES section explains "---" separator with at least one example
- SELECTORS section lists name, driver, pci_path, and mac
- FIELDS section lists mtu, addresses, routes, and state
- VALUE TYPES section shows the YAML-to-netfyr type mapping with IPv4-only language (no IPv6 claims)
- The `::1` example is removed from VALUE TYPES
- A note about IPv6 strings being treated as plain strings is present
- FILES section lists `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/`
- `cargo test --package xtask` passes
- `cargo xtask man` prints a note mentioning both `netfyr.yaml.5` and `netfyr-examples.7`
