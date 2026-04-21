# Plan: SPEC-503 — YAML Reference Man Page

## Status: Already Implemented

The understanding analysis and direct verification confirm that all acceptance criteria for this story are already met. No code changes are required.

## Approach

This story calls for a hand-written `man/netfyr.yaml.5` troff man page documenting netfyr's YAML file formats (bare state, explicit policy, multi-document), along with sections on selectors, fields, value types, and file paths. It must coexist with the auto-generated section-1 man pages from `xtask`, which must not overwrite it.

The chosen design is a single standalone troff file committed to `man/netfyr.yaml.5`, with no code generation or build-time templating. This is the standard Unix approach for section-5 format documentation. The alternative — generating the man page from Rust code or from the JSON schema — was rejected because the content requires hand-written prose, examples, and editorial judgment about what details matter to users. Auto-generation would produce either too little (missing examples and caveats) or too much (schema dump) information.

**Current state**: `man/netfyr.yaml.5` exists as a 358-line troff file containing all required sections with correct content. The xtask infrastructure correctly excludes it from generation and documents this in both the `Man` variant doc comment (line 28) and the post-generation println (line 89). All 42+ related tests in the xtask test suite pass.

## Design Decisions

1. **Decision**: Single hand-written troff file at `man/netfyr.yaml.5`.
   - **Alternatives considered**: Auto-generating from the `SchemaRegistry` or from `ethernet.json`; using mdoc format instead of man macros.
   - **Rationale**: The spec explicitly requires a hand-written file. Troff `man` macros are simpler and more portable than mdoc, and match the auto-generated section-1 pages produced by `clap_mangen`.

2. **Decision**: IPv4-only documentation throughout, with explicit IPv6 rejection note in VALUE TYPES.
   - **Alternatives considered**: Documenting IPv6 as unsupported only in the FIELDS section.
   - **Rationale**: The spec requires the note in VALUE TYPES, and the implementation (`deserialize_value` in `yaml.rs`) only parses `Ipv4Addr` and `Ipv4Network`. The man page must match actual behavior.

3. **Decision**: A maintenance comment on line 1 (`This file is maintained by hand. Do not edit with cargo xtask man.`).
   - **Alternatives considered**: No comment; relying on xtask output alone.
   - **Rationale**: Developers editing the file directly need to see the warning. The xtask output is only visible when running `cargo xtask man`.

4. **Decision**: The xtask `Man` subcommand's doc comment and post-generation println both mention `netfyr.yaml.5` alongside `netfyr-examples.7`.
   - **Alternatives considered**: Only mentioning the file in one location.
   - **Rationale**: Both the developer-facing doc comment and the runtime output should be complete so no one wonders why the section-5 page wasn't regenerated.

5. **Decision**: Document the `state` field (administrative state: "up"/"down") in the FIELDS section despite it not appearing in the ethernet JSON schema.
   - **Alternatives considered**: Omitting it because the schema has `operstate` (read-only) but no writable `state`.
   - **Rationale**: The spec explicitly requires it. The apply layer handles administrative state at a level above schema validation.

## File Changes

### 1. `man/netfyr.yaml.5`
- **Action**: no change needed (already complete)
- **What**: 358-line troff man page with all required sections: NAME, DESCRIPTION, BARE STATE FORMAT (with example), POLICY FORMAT (kind/name/factory/priority/selector/state/states; 3 examples covering static-single, static-multi, dhcpv4), MULTI-DOCUMENT FILES (with example), SELECTORS (name/driver/pci_path/mac with dhcpv4 note), FIELDS (mtu/addresses/routes/state for ethernet), VALUE TYPES (full mapping table with IPv4-only language and IPv6 rejection note), FILES (/etc/netfyr/policies/ and /var/lib/netfyr/policies/), SEE ALSO.
- **Why**: Satisfies all acceptance criteria from the spec.

### 2. `xtask/src/main.rs`
- **Action**: no change needed (already updated)
- **What**: Line 28 doc comment and line 89 println both mention `netfyr.yaml.5` and `netfyr-examples.7` as hand-maintained files. Test suite (lines 516-1016) includes comprehensive content tests for the man page.
- **Why**: Ensures developers know both files are outside the generation pipeline.

## Dependencies

No new crate dependencies. This story involves only a troff file and minor Rust string changes, all already in place.

## Implementation Order

No implementation steps are needed — the story is complete. For reference, the implementation that was done:

1. `man/netfyr.yaml.5` was created with all required sections and examples.
2. `xtask/src/main.rs` was updated with the hand-maintained file note and comprehensive tests.
3. All tests pass: `cargo test -p xtask -- yaml` runs 42+ tests successfully.

## Risks and Mitigations

1. **Risk: `state` field not in ethernet JSON schema.** The man page documents `state` ("up"/"down") but the JSON schema has `operstate` (read-only) and no writable `state`.
   - **Mitigation**: The spec requires documenting this field. Any schema update is out of scope.

2. **Risk: No automated troff rendering CI.** Man page rendering correctness is verified manually.
   - **Mitigation**: The file uses simple, well-established troff macros (`.TH`, `.SH`, `.SS`, `.TP`, `.PP`, `.RS`, `.RE`, `.nf`, `.fi`, `.B`, `.BR`, `.I`) that are unlikely to break. The xtask test suite verifies content strings are present.

3. **Risk: Man page drift if new entity types or fields are added.**
   - **Mitigation**: The line-1 comment warns maintainers. Future feature stories that add entity types or fields must update this file manually.

## Test Strategy

No new tests are needed. The existing xtask test suite (`xtask/src/main.rs` lines 516-1016 and `xtask/tests/man_page_yaml_reference.rs`) provides comprehensive coverage:

- Content presence tests for all sections (NAME, BARE STATE FORMAT, POLICY FORMAT, MULTI-DOCUMENT FILES, SELECTORS, FIELDS, VALUE TYPES, FILES, SEE ALSO)
- Field documentation tests (kind, name, factory, priority, selector, state, states, mtu, addresses, routes)
- Factory type tests (static, dhcpv4)
- Value type mapping tests (Bool, U64, I64, IpAddr, IpNetwork, String, List, Map)
- IPv4-only language verification
- Selector field tests (name, driver, pci_path, mac)
- Cross-reference tests (SEE ALSO entries)
- Hand-maintained comment verification

All 42+ tests pass as of the current state.
