# Plan: SPEC-503 — YAML Reference Man Page

## Approach

This story creates a single hand-written troff man page at `man/netfyr.yaml.5` that serves as the definitive offline reference for netfyr's YAML file formats. The file is a pure troff/groff source document — no Rust code, no build system changes, no dependencies.

The design follows the conventions already established by the existing hand-written man page `man/netfyr-examples.7`: a comment header marking it as hand-maintained, the same `.TH` header format, identical troff idioms for code blocks (`.RS 4` / `.nf` / `.fi` / `.RE`), tagged-paragraph field lists (`.TP`), and consistent SEE ALSO cross-references using `.BR`. The new page complements `netfyr-examples.7` — the examples page shows "how to use" scenarios while this page provides the exhaustive field-by-field reference.

The content is derived directly from the codebase: the `Value` enum in `netfyr-state/src/lib.rs`, the `Selector` struct fields (`name`, `driver`, `pci_path`, `mac`), the ethernet JSON Schema in `netfyr-state/src/schemas/ethernet.json` (which defines `mtu`, `addresses`, `mac`, `carrier`, `speed`, `routes` with sub-fields `destination` [required], `gateway`, `metric`), and the `FactoryType` enum (`Static`, `Dhcpv4`) in `netfyr-policy/src/lib.rs`. The man page documents only the user-writable configuration surface — read-only fields (`mac`, `carrier`, `speed`) appear in query output but are not documented in the FIELDS section since users cannot set them in policies. The SELECTORS section does document `mac` as a selector field, because users can target interfaces by MAC address even though the MAC field itself is read-only in the entity schema.

An alternative approach would be to auto-generate this page from the JSON Schema and Rust types. This was rejected because: (1) the spec explicitly calls for a hand-written file, (2) format documentation needs narrative prose and contextual examples that auto-generation cannot provide, and (3) the xtask already has a guard for hand-maintained pages.

## Design Decisions

1. **Decision**: Document only writable configuration fields (mtu, addresses, routes, state) in the FIELDS section, not read-only query fields (mac, carrier, speed).
   - **Alternatives considered**: Document all fields with a "read-only" annotation; document read-only fields in a separate subsection.
   - **Rationale**: The spec's acceptance criteria say "FIELDS section lists mtu, addresses, routes, and state" — exactly the writable fields. This is a policy-format reference, not a query-output reference. Users writing YAML files only need to know what they can set. Read-only fields are surfaced by `netfyr query` and would confuse the reference.

2. **Decision**: Use `.TH "NETFYR.YAML" 5 "" "" "File Formats Manual"` as the header, matching the section 5 convention for file format man pages.
   - **Alternatives considered**: `.TH NETFYR.YAML 5` (minimal), `.TH NETFYR.YAML 5 "" "netfyr" "File Formats Manual"` (with source field).
   - **Rationale**: Matches the pattern used by `netfyr-examples.7` which uses `"Miscellaneous Information Manual"` for section 7. The five-argument `.TH` form with the last argument as the manual title is standard and produces the correct header/footer in rendered output.

3. **Decision**: Use quoted section headers (e.g., `.SH "BARE STATE FORMAT"`) for multi-word section names, unquoted for single-word names (e.g., `.SH SELECTORS`).
   - **Alternatives considered**: Quote all section names; use no quotes.
   - **Rationale**: This matches the existing `netfyr-examples.7` convention (e.g., `.SH "STATIC IP ON A SINGLE INTERFACE"` vs `.SH DESCRIPTION`). Quoting is required by troff for multi-word section names; omitting quotes for single-word names is valid and conventional.

4. **Decision**: Document the `state` (admin state) ethernet field as a string with values "up" or "down", disambiguating it from the `state:` mapping key in the policy format.
   - **Alternatives considered**: Rename it or skip it to avoid confusion.
   - **Rationale**: The spec explicitly lists `state` as an ethernet field to document. The disambiguation is handled by context — the FIELDS section describes configuration properties within a state definition, and the field description clearly states it's the administrative state with specific allowed values.

5. **Decision**: Include the `routes` sub-field detail (destination required, gateway and metric optional) directly in the FIELDS section rather than in a separate subsection.
   - **Alternatives considered**: Create a "ROUTE ENTRIES" subsection; use a `.SS` subsection.
   - **Rationale**: The ethernet schema has only one complex field (routes). A dedicated subsection would be premature structure. The spec's example shows route details inline. The JSON Schema confirms `destination` is required and `gateway`/`metric` are optional.

6. **Decision**: Place the hand-maintained comment on the first line using `.\"` troff comment syntax, identical to `netfyr-examples.7`.
   - **Alternatives considered**: Use a different comment style or location.
   - **Rationale**: Direct consistency with the existing hand-written page. The xtask already prints a note about `netfyr-examples.7` being hand-maintained; the same convention applies.

7. **Decision**: Do not modify `xtask/src/main.rs` to add a guard for `netfyr.yaml.5`.
   - **Alternatives considered**: Add a note line like the `netfyr-examples.7` one.
   - **Rationale**: The xtask only generates section 1 pages from clap definitions. It has no code path that would touch a section 5 file. Adding a guard/note is unnecessary defensive coding for a case that cannot arise. If/when a second hand-written page is common enough to warrant a general note, that's a separate change.

8. **Decision**: Escape hyphens in YAML string values within troff source as `\-` where they appear in contexts that troff might interpret as typographic dashes (e.g., `eth0\-dhcp` in policy names).
   - **Alternatives considered**: Use unescaped hyphens everywhere since they're inside `.nf` blocks.
   - **Rationale**: Consistent with `netfyr-examples.7` which escapes hyphens in policy names (e.g., `eth0\-dhcp`). Inside `.nf` blocks some troff implementations still convert `--` to en-dash; escaping prevents this.

## File Changes

### File: `man/netfyr.yaml.5`
- **Action**: Create
- **What**: A hand-written troff man page with the following sections in order:
  1. **Comment header**: `.\" This file is maintained by hand. Do not edit with cargo xtask man.`
  2. **`.TH "NETFYR.YAML" 5 "" "" "File Formats Manual"`**: Page header with section 5 designation.
  3. **`.SH NAME`**: `netfyr.yaml \- netfyr policy file formats`
  4. **`.SH DESCRIPTION`**: Brief intro explaining that netfyr reads YAML files from `/etc/netfyr/policies/`, files may contain multiple YAML documents separated by `---`, and each document is parsed independently. Reference to `netfyr-examples(7)` for worked examples.
  5. **`.SH "BARE STATE FORMAT"`**: Documents the simplest format — a YAML document with no `kind` field. Explains that `type`, selector properties, and configuration properties are all at the top level. Explains auto-wrapping into a static policy with default priority 100 and filename-derived name. Field list using `.TP` entries for `type` (string, required — currently "ethernet"), selector properties (reference to SELECTORS section), and configuration properties (reference to FIELDS section). One inline example showing `type: ethernet` with `name`, `mtu`, and `addresses`.
  6. **`.SH "POLICY FORMAT"`**: Documents the `kind: policy` wrapper. Field list with `.TP` entries:
     - `kind` (string, required — must be "policy")
     - `name` (string, required — unique policy name)
     - `factory` (string, required — "static" or "dhcpv4")
     - `priority` (integer, optional, default 100 — higher wins)
     - `selector` (mapping, required for dhcpv4 — see SELECTORS)
     - `state` (mapping, optional — single entity state, mutually exclusive with `states`)
     - `states` (sequence, optional — multiple entity states, mutually exclusive with `state`)
     Three examples: static/single-state, static/multiple-states, dhcpv4.
  7. **`.SH "MULTI-DOCUMENT FILES"`**: Explains `---` separator. One example showing two ethernet states in one file.
  8. **`.SH SELECTORS`**: Intro explaining AND logic for multiple selectors. `.TP` entries for:
     - `name` (string — exact interface name)
     - `driver` (string — kernel driver name)
     - `pci_path` (string — PCI device path)
     - `mac` (string — colon-separated hex MAC, case-insensitive comparison)
     Note about dhcpv4 policies wrapping selectors at the policy level.
  9. **`.SH FIELDS`**: Intro explaining these are configuration properties. Subsection (`.SS`) for `Ethernet` entity type. `.TP` entries for:
     - `mtu` (integer — MTU, range 68–65535)
     - `addresses` (sequence of strings — CIDR notation)
     - `routes` (sequence of mappings — each with `destination` [required, CIDR], `gateway` [optional, IP], `metric` [optional, integer])
     - `state` (string — administrative state, "up" or "down")
  10. **`.SH "VALUE TYPES"`**: Table (using `.TP` entries) mapping YAML types to netfyr types:
      - YAML boolean → Bool
      - YAML integer >= 0 → U64
      - YAML integer < 0 → I64
      - YAML string matching IP → IpAddr
      - YAML string matching CIDR → IpNetwork
      - YAML string (other) → String
      - YAML sequence → List
      - YAML mapping → Map
  11. **`.SH FILES`**: `.TP` entries for `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/`.
  12. **`.SH "SEE ALSO"`**: `.BR` references to `netfyr(1)`, `netfyr\-apply(1)`, `netfyr\-query(1)`, `netfyr\-examples(7)`.
- **Why**: This is the sole deliverable of the story. Fulfills the forward references already present in all existing man pages, and provides the offline YAML format reference that the spec requires.

## Dependencies

None. This story requires no new crate dependencies. The deliverable is a standalone troff file with no build system integration.

## Implementation Order

1. **Create `man/netfyr.yaml.5`** — Write the complete troff source file. Since this is a single file with no code dependencies, the entire implementation is one step. The file must be syntactically valid troff from the start; there is no compilation step.

2. **Verify rendering** — Run `man ./man/netfyr.yaml.5` (or `mandoc -Tlint man/netfyr.yaml.5` if available) to confirm the page renders without troff warnings and all sections are present and properly formatted. This is a verification step, not a code change.

## Risks and Mitigations

1. **Risk**: Troff syntax errors silently degrade rendering rather than failing. A missing `.fi` or `.RE` will cause the rest of the page to render in monospace or indented, but `man` won't exit with an error.
   - **Mitigation**: Use the exact same troff idioms as `netfyr-examples.7` (which is known-good). Every `.nf` must have a matching `.fi`; every `.RS` must have a matching `.RE`. Keep examples short and use consistent indentation in the troff source to make mismatches visually obvious.

2. **Risk**: The `routes` sub-field documentation could diverge from the actual JSON Schema if the schema is updated later.
   - **Mitigation**: The man page documents what the schema currently defines: `destination` (required), `gateway` (optional), `metric` (optional). This matches the `ethernet.json` schema file exactly. Since this is a hand-maintained file, any schema changes must be accompanied by a man page update — the same is true for `netfyr-examples.7`.

3. **Risk**: The `state` field name collision between the ethernet admin state field and the policy-level `state:` mapping could confuse readers.
   - **Mitigation**: The FIELDS section describes the ethernet `state` field clearly as "Administrative state" with values "up" or "down". The POLICY FORMAT section describes the `state:` key as "A single entity state definition." The two are in different sections with distinct descriptions, matching the spec's structure.

4. **Risk**: No CI validation for man page rendering exists in the repository.
   - **Mitigation**: Manual verification during review. The troff source is simple enough (no macros, no complex tables) that visual inspection of the source catches most errors. A future CI step could run `mandoc -Tlint` but that's out of scope for this story.

5. **Risk**: The SEE ALSO section references `netfyr-examples(7)` which in turn references `netfyr.yaml(5)` — circular cross-references are normal for man pages but should be verified to use consistent naming.
   - **Mitigation**: Use the exact same `.BR` formatting as the existing pages: `.BR netfyr\-examples (7)` with escaped hyphen and space before the section number in parentheses.

## Test Strategy

This story has no Rust code, so there are no unit or integration tests to write. Verification is manual/scripted:

1. **File existence**: Confirm `man/netfyr.yaml.5` exists at the expected path.
2. **Rendering correctness**: Run `man ./man/netfyr.yaml.5` and visually confirm:
   - No troff warnings on stderr
   - NAME section shows "netfyr.yaml"
   - All 8 content sections are present (BARE STATE FORMAT, POLICY FORMAT, MULTI-DOCUMENT FILES, SELECTORS, FIELDS, VALUE TYPES, FILES, SEE ALSO)
   - All inline examples render as monospaced code blocks
3. **Content completeness** (can be checked via grep on the troff source):
   - BARE STATE FORMAT contains at least one example (`.nf` block)
   - POLICY FORMAT contains "static" and "dhcpv4"
   - POLICY FORMAT contains three examples (static/single, static/multi, dhcpv4)
   - SELECTORS lists all four selector fields: `name`, `driver`, `pci_path`, `mac`
   - FIELDS lists all four writable ethernet fields: `mtu`, `addresses`, `routes`, `state`
   - VALUE TYPES contains all 7 netfyr types: Bool, U64, I64, IpAddr, IpNetwork, String, List, Map
   - FILES lists `/etc/netfyr/policies/` and `/var/lib/netfyr/policies/`
   - SEE ALSO references `netfyr(1)`, `netfyr-apply(1)`, `netfyr-query(1)`, `netfyr-examples(7)`
4. **No xtask interference**: Run `cargo xtask man` and confirm `man/netfyr.yaml.5` is not modified or overwritten (check mtime or diff).
5. **Cross-reference consistency**: Confirm the NAME line uses `netfyr.yaml` matching the references in existing man pages.
