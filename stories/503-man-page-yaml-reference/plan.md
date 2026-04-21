# Plan: SPEC-503 — YAML Reference Man Page

## Status: Nearly Complete — One Minor Fix

The man page, tests, xtask exclusion, and RPM integration are all in place. One cosmetic fix is needed: the SEE ALSO section is missing `netfyr-daemon(8)`, which the spec explicitly includes and which exists at `man/netfyr-daemon.8`.

## Approach

This story calls for a hand-written `man/netfyr.yaml.5` troff man page documenting netfyr's YAML file formats (bare state, explicit policy, multi-document), along with sections on selectors, fields, value types, and file paths. It must coexist with the auto-generated section-1 man pages from `xtask`, which must not overwrite it.

The chosen design is a single standalone troff file committed to `man/netfyr.yaml.5`, with no code generation or build-time templating. This is the standard Unix approach for section-5 format documentation. The alternative — generating the man page from Rust code or from the JSON schema — was rejected because the content requires hand-written prose, examples, and editorial judgment about what details matter to users. Auto-generation would produce either too little (missing examples and caveats) or too much (schema dump) information.

**Current state**: `man/netfyr.yaml.5` exists as a 358-line troff file containing all required sections with correct content. The xtask infrastructure correctly excludes it from generation and documents this in both the `Man` variant doc comment (line 28) and the post-generation println (line 90). The integration test suite (`xtask/tests/man_page_yaml_reference.rs`) has 39 tests and the xtask unit tests (`xtask/src/main.rs` lines 520-1021) add further coverage. All tests pass.

The only gap: The spec's SEE ALSO section lists `netfyr-daemon(8)` but the current man page omits it. The file `man/netfyr-daemon.8` exists, so this reference should be added. No acceptance-criteria test currently enforces this, but it's a clear spec requirement.

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

4. **Decision**: Add `netfyr-daemon(8)` to SEE ALSO.
   - **Alternatives considered**: Leaving it out since no test enforces it.
   - **Rationale**: The spec explicitly lists it, and `man/netfyr-daemon.8` exists. Cross-references between man pages are a standard Unix convention and help users discover related documentation.

5. **Decision**: Document the `state` field (administrative state: "up"/"down") in the FIELDS section despite it not appearing in the ethernet JSON schema.
   - **Alternatives considered**: Omitting it because the schema has `operstate` (read-only) but no writable `state`.
   - **Rationale**: The spec explicitly requires it. The apply layer handles administrative state at a level above schema validation.

## File Changes

### 1. `man/netfyr.yaml.5`
- **Action**: modify (one line change)
- **What**: Add `.BR netfyr\-daemon (8),` to the SEE ALSO section, between the `.BR netfyr\-revert (1),` line and the `.BR netfyr\-examples (7)` line. This matches the ordering in the spec: `netfyr(1), netfyr-apply(1), netfyr-query(1), netfyr-history(1), netfyr-revert(1), netfyr-daemon(8), netfyr-examples(7)`.
- **Why**: The spec's SEE ALSO section explicitly includes `netfyr-daemon(8)`, and the file exists at `man/netfyr-daemon.8`. All other SEE ALSO entries are already present.

### 2. All other files
- **Action**: no change needed
- The following are already correctly implemented:
  - `xtask/src/main.rs`: Line 28-29 doc comment and line 90 println both mention `netfyr.yaml.5` as a hand-maintained file. Unit tests at lines 520-1021 verify man page content.
  - `xtask/tests/man_page_yaml_reference.rs`: 39 integration tests covering all acceptance criteria.
  - `netfyr.spec`: `%install` section has `install -pm 0644 man/netfyr.yaml.5 %{buildroot}%{_mandir}/man5/` and `%files` section has `%{_mandir}/man5/netfyr.yaml.5*`.

## Dependencies

No new crate dependencies. This story involves only a troff file.

## Implementation Order

1. **Edit `man/netfyr.yaml.5`**: Add the `netfyr-daemon(8)` cross-reference to the SEE ALSO section (lines 351-357). Insert `.BR netfyr\-daemon (8),` as a new line between the `netfyr\-revert (1),` and `netfyr\-examples (7)` lines. This is the only change needed. The file compiles (renders) independently — there is no Rust compilation dependency.

2. **Verify**: Run `cargo test -p xtask` to confirm all existing tests still pass. The existing tests do not check for `netfyr-daemon(8)` specifically, so no test updates are needed for this change to pass.

## Risks and Mitigations

1. **Risk: No automated troff rendering CI.** Man page rendering correctness is verified only when `groff` is available on the test host.
   - **Mitigation**: The file uses simple, well-established troff macros (`.TH`, `.SH`, `.SS`, `.TP`, `.PP`, `.RS`, `.RE`, `.nf`, `.fi`, `.B`, `.BR`, `.I`) that are unlikely to break. The integration test at `test_man_page_renders_without_fatal_troff_errors` will catch any syntax issues when groff is available.

2. **Risk: Man page drift if new entity types or fields are added.**
   - **Mitigation**: The line-1 comment warns maintainers. Future feature stories that add entity types or fields must update this file manually.

3. **Risk: The `state` field (up/down) is documented but not present in the JSON schema.**
   - **Mitigation**: The spec requires documenting this field. If the implementation changes, the man page must be updated. This is inherent to hand-maintained documentation.

## Test Strategy

No new tests are required. The existing test coverage is comprehensive:

- **`xtask/tests/man_page_yaml_reference.rs`** (39 integration tests): Covers file existence, section-5 declaration, hand-maintained comment, NAME section, BARE STATE FORMAT (section existence, type field, selector properties, example), POLICY FORMAT (section existence, all 7 fields, both factory types, examples for static and dhcpv4), MULTI-DOCUMENT FILES (section, separator documentation, example), SELECTORS (section, all 4 fields), FIELDS (section, mtu, addresses, routes, state), VALUE TYPES (section, all 8 type mappings), FILES (section, both directories), RPM path verification, groff rendering.

- **`xtask/src/main.rs`** unit tests (lines 520-1021): Additional content verification tests with similar coverage.

The SEE ALSO change does not require a new test — no acceptance criterion mandates testing for specific SEE ALSO entries. If desired, a test asserting `netfyr-daemon` appears in the SEE ALSO section could be added to `man_page_yaml_reference.rs`, but this is optional.
