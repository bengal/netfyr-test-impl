//! Integration tests for the netfyr.yaml(5) man page (SPEC-503).
//!
//! Each test maps to one or more acceptance criteria from the specification.
//! Tests read the troff source directly and assert that required sections,
//! fields, and examples are present.  A final optional test invokes groff to
//! verify the file renders without fatal errors when the tool is available.

use std::fs;
use std::path::PathBuf;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Absolute path to `man/netfyr.yaml.5` (relative to the workspace root).
fn man_page_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is set by cargo to the directory that contains the
    // Cargo.toml of the crate under test.  For the xtask crate that is
    // `<workspace_root>/xtask`, so `..` gives us the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate must have a parent workspace directory")
        .join("man")
        .join("netfyr.yaml.5")
}

/// Read the man page content, panicking with a helpful message if the file is
/// missing (the existence test below will have already reported the real error).
fn read_man_page() -> String {
    let path = man_page_path();
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {:?}: {}", path, e))
}

/// Extract the raw troff lines that belong to the named top-level section
/// (`.SH`).  Collection starts after the matching `.SH` header and stops at
/// the next `.SH` header (or end of file).  The section name comparison is
/// case-insensitive and exact (not substring), and works for both quoted
/// (`.SH "BARE STATE FORMAT"`) and unquoted (`.SH SELECTORS`) forms.
///
/// Use the full section name as it appears in the troff source, e.g.
/// `"MULTI-DOCUMENT FILES"` rather than just `"MULTI-DOCUMENT"`, so that
/// partial names do not accidentally match longer section headings.
fn extract_section(content: &str, section_name: &str) -> String {
    let needle = section_name.to_uppercase();
    let mut in_section = false;
    let mut buf = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with(".SH") {
            if in_section {
                // Reached the next top-level section — stop.
                break;
            }
            // Everything after ".SH" (may be zero or more chars).
            let rest = trimmed.get(3..).unwrap_or("").trim();
            // Strip surrounding quotes that troff uses for multi-word names.
            let normalized = rest.trim_matches('"').to_uppercase();
            // Use exact equality so that e.g. "FILES" does not match
            // "MULTI-DOCUMENT FILES".
            if normalized == needle {
                in_section = true;
            }
        } else if in_section {
            buf.push_str(line);
            buf.push('\n');
        }
    }

    buf
}

// ── Scenario: Man page exists and renders ─────────────────────────────────────

/// AC: the file man/netfyr.yaml.5 exists in the repository.
#[test]
fn test_man_page_file_exists() {
    assert!(
        man_page_path().exists(),
        "man/netfyr.yaml.5 must exist; path checked: {:?}",
        man_page_path()
    );
}

/// AC: the file is non-empty (a basic sanity check before the content tests).
#[test]
fn test_man_page_is_non_empty() {
    let content = read_man_page();
    assert!(!content.trim().is_empty(), "man/netfyr.yaml.5 must not be empty");
}

/// AC: the NAME section contains "netfyr.yaml".
#[test]
fn test_name_section_contains_netfyr_yaml() {
    let content = read_man_page();
    // The name appears in the .TH header line and/or the .SH NAME body.
    assert!(
        content.contains("netfyr.yaml"),
        "man page must mention 'netfyr.yaml' (NAME section requirement)"
    );
}

/// AC: the page is declared as a section-5 (file formats) man page via .TH.
#[test]
fn test_man_page_is_section_five() {
    let content = read_man_page();
    // .TH "NETFYR.YAML" 5 …  — the second argument to .TH is the section.
    assert!(
        content.contains(".TH"),
        "man page must have a .TH title header macro"
    );
    // Section number "5" must appear in or near the .TH line.
    let th_line = content
        .lines()
        .find(|l| l.trim().starts_with(".TH"))
        .expect("man page must have a .TH line");
    assert!(
        th_line.contains(" 5 ") || th_line.contains("\"5\""),
        ".TH line must declare section 5; got: {th_line}"
    );
}

/// AC: the file begins with the conventional hand-edit warning comment.
#[test]
fn test_man_page_has_hand_maintained_comment() {
    let content = read_man_page();
    // The spec requires a comment noting the file is maintained by hand.
    assert!(
        content.contains("maintained by hand") || content.contains("Do not edit"),
        "man page must contain a comment warning that it is maintained by hand"
    );
}

/// AC: groff renders the man page without fatal errors (skipped when groff is
/// not installed on the host, so CI without groff still passes all other ACs).
#[test]
fn test_man_page_renders_without_fatal_troff_errors() {
    // Probe for groff; skip gracefully if unavailable.
    if std::process::Command::new("groff")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("groff not found — skipping render test");
        return;
    }

    let output = std::process::Command::new("groff")
        .args(["-man", "-T", "utf8", "-w", "all"])
        .arg(man_page_path())
        .output()
        .expect("groff invocation failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // groff distinguishes "warning", "error", and "fatal error".
    // We only fail on hard errors — warnings about missing fonts etc. are benign.
    let has_fatal = stderr.lines().any(|l| l.contains("fatal error:"));
    assert!(
        !has_fatal,
        "groff reported a fatal error rendering man/netfyr.yaml.5:\n{stderr}"
    );
}

// ── Scenario: Bare state format is documented ─────────────────────────────────

/// AC: BARE STATE FORMAT section exists.
#[test]
fn test_bare_state_format_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains("BARE STATE FORMAT"),
        "man page must contain a 'BARE STATE FORMAT' section"
    );
}

/// AC: BARE STATE FORMAT describes the flat format — 'type' field documented.
#[test]
fn test_bare_state_format_documents_type_field() {
    let section = extract_section(&read_man_page(), "BARE STATE FORMAT");
    assert!(
        !section.is_empty(),
        "BARE STATE FORMAT section body must not be empty"
    );
    assert!(
        section.contains("type"),
        "BARE STATE FORMAT must document the 'type' field"
    );
}

/// AC: BARE STATE FORMAT documents selector properties at the top level.
#[test]
fn test_bare_state_format_documents_selector_properties() {
    let section = extract_section(&read_man_page(), "BARE STATE FORMAT");
    // The spec says "selector properties (name, driver, mac, pci_path) identify
    // the target entity" — at least one of them must be mentioned.
    let mentions_selectors = section.contains("selector")
        || section.contains("name")
        || section.contains("driver")
        || section.contains("mac")
        || section.contains("pci_path");
    assert!(
        mentions_selectors,
        "BARE STATE FORMAT must reference selector properties (name, driver, mac, pci_path)"
    );
}

/// AC: BARE STATE FORMAT includes at least one inline example.
#[test]
fn test_bare_state_format_has_example() {
    let section = extract_section(&read_man_page(), "BARE STATE FORMAT");
    // Examples are enclosed in .nf / .fi no-fill blocks.
    assert!(
        section.contains(".nf"),
        "BARE STATE FORMAT must contain at least one .nf example block"
    );
    // The example should show ethernet usage.
    assert!(
        section.contains("ethernet"),
        "BARE STATE FORMAT example must demonstrate 'type: ethernet'"
    );
}

// ── Scenario: Policy format is documented ─────────────────────────────────────

/// AC: POLICY FORMAT section exists.
#[test]
fn test_policy_format_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains("POLICY FORMAT"),
        "man page must contain a 'POLICY FORMAT' section"
    );
}

/// AC: POLICY FORMAT documents the 'kind' field.
#[test]
fn test_policy_format_documents_kind() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("kind"),
        "POLICY FORMAT must document the 'kind' field"
    );
}

/// AC: POLICY FORMAT documents the 'name' field.
#[test]
fn test_policy_format_documents_name() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("name"),
        "POLICY FORMAT must document the 'name' field"
    );
}

/// AC: POLICY FORMAT documents the 'factory' field.
#[test]
fn test_policy_format_documents_factory() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("factory"),
        "POLICY FORMAT must document the 'factory' field"
    );
}

/// AC: POLICY FORMAT documents the 'priority' field.
#[test]
fn test_policy_format_documents_priority() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("priority"),
        "POLICY FORMAT must document the 'priority' field"
    );
}

/// AC: POLICY FORMAT documents the 'selector' field.
#[test]
fn test_policy_format_documents_selector() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("selector"),
        "POLICY FORMAT must document the 'selector' field"
    );
}

/// AC: POLICY FORMAT documents the 'state' field.
#[test]
fn test_policy_format_documents_state() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("state"),
        "POLICY FORMAT must document the 'state' field"
    );
}

/// AC: POLICY FORMAT documents the 'states' field.
#[test]
fn test_policy_format_documents_states() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("states"),
        "POLICY FORMAT must document the 'states' field"
    );
}

// ── Scenario: Factory types are documented ────────────────────────────────────

/// AC: POLICY FORMAT documents the "static" factory type.
#[test]
fn test_policy_format_documents_static_factory() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("static"),
        "POLICY FORMAT must document the 'static' factory type"
    );
}

/// AC: POLICY FORMAT documents the "dhcpv4" factory type.
#[test]
fn test_policy_format_documents_dhcpv4_factory() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("dhcpv4"),
        "POLICY FORMAT must document the 'dhcpv4' factory type"
    );
}

/// AC: POLICY FORMAT includes an example using the static factory.
#[test]
fn test_policy_format_has_static_factory_example() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    // Static example uses "factory: static" (possibly with backslash-escaped hyphen).
    assert!(
        section.contains("factory: static") || section.contains("factory: static"),
        "POLICY FORMAT must include a 'factory: static' example"
    );
    // At least one .nf block must be present for the static example.
    assert!(
        section.contains(".nf"),
        "POLICY FORMAT must contain at least one .nf example block"
    );
}

/// AC: POLICY FORMAT includes an example using the dhcpv4 factory.
#[test]
fn test_policy_format_has_dhcpv4_factory_example() {
    let section = extract_section(&read_man_page(), "POLICY FORMAT");
    assert!(
        section.contains("dhcpv4"),
        "POLICY FORMAT must include a dhcpv4 factory example"
    );
}

// ── Scenario: Multi-document files are documented ─────────────────────────────

/// AC: MULTI-DOCUMENT FILES section exists.
#[test]
fn test_multi_document_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains("MULTI-DOCUMENT"),
        "man page must contain a 'MULTI-DOCUMENT FILES' section"
    );
}

/// AC: the section explains the "---" YAML document separator.
#[test]
fn test_multi_document_section_documents_separator() {
    let section = extract_section(&read_man_page(), "MULTI-DOCUMENT FILES");
    // In troff source "---" is written as \-\-\- (escaped hyphens).
    // Either the literal "---" or the escaped form must appear.
    let mentions_separator = section.contains("---")
        || section.contains(r"\-\-\-")
        || section.contains("separator");
    assert!(
        mentions_separator,
        "MULTI-DOCUMENT FILES section must document the '---' YAML document separator"
    );
}

/// AC: the section includes at least one inline example.
#[test]
fn test_multi_document_section_has_example() {
    let section = extract_section(&read_man_page(), "MULTI-DOCUMENT FILES");
    assert!(
        section.contains(".nf"),
        "MULTI-DOCUMENT FILES section must include at least one .nf example block"
    );
}

// ── Scenario: All selector fields are documented ──────────────────────────────

/// AC: SELECTORS section exists.
#[test]
fn test_selectors_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains("SELECTORS"),
        "man page must contain a 'SELECTORS' section"
    );
}

/// AC: SELECTORS section documents the 'name' field.
#[test]
fn test_selectors_section_documents_name() {
    let section = extract_section(&read_man_page(), "SELECTORS");
    assert!(
        section.contains("name"),
        "SELECTORS section must document the 'name' selector field"
    );
}

/// AC: SELECTORS section documents the 'driver' field.
#[test]
fn test_selectors_section_documents_driver() {
    let section = extract_section(&read_man_page(), "SELECTORS");
    assert!(
        section.contains("driver"),
        "SELECTORS section must document the 'driver' selector field"
    );
}

/// AC: SELECTORS section documents the 'pci_path' field.
#[test]
fn test_selectors_section_documents_pci_path() {
    let section = extract_section(&read_man_page(), "SELECTORS");
    assert!(
        section.contains("pci_path"),
        "SELECTORS section must document the 'pci_path' selector field"
    );
}

/// AC: SELECTORS section documents the 'mac' field.
#[test]
fn test_selectors_section_documents_mac() {
    let section = extract_section(&read_man_page(), "SELECTORS");
    assert!(
        section.contains("mac"),
        "SELECTORS section must document the 'mac' selector field"
    );
}

// ── Scenario: All ethernet fields are documented ──────────────────────────────

/// AC: FIELDS section exists.
#[test]
fn test_fields_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains("FIELDS"),
        "man page must contain a 'FIELDS' section"
    );
}

/// AC: FIELDS section documents the 'mtu' field.
#[test]
fn test_fields_section_documents_mtu() {
    let section = extract_section(&read_man_page(), "FIELDS");
    assert!(
        section.contains("mtu"),
        "FIELDS section must document the 'mtu' ethernet field"
    );
}

/// AC: FIELDS section documents the 'addresses' field.
#[test]
fn test_fields_section_documents_addresses() {
    let section = extract_section(&read_man_page(), "FIELDS");
    assert!(
        section.contains("addresses"),
        "FIELDS section must document the 'addresses' ethernet field"
    );
}

/// AC: FIELDS section documents the 'routes' field.
#[test]
fn test_fields_section_documents_routes() {
    let section = extract_section(&read_man_page(), "FIELDS");
    assert!(
        section.contains("routes"),
        "FIELDS section must document the 'routes' ethernet field"
    );
}

/// AC: FIELDS section documents the 'state' field (up/down).
#[test]
fn test_fields_section_documents_state() {
    let section = extract_section(&read_man_page(), "FIELDS");
    assert!(
        section.contains("state"),
        "FIELDS section must document the 'state' (up/down) ethernet field"
    );
}

// ── Scenario: Value type mapping is documented ────────────────────────────────

/// AC: VALUE TYPES section exists.
#[test]
fn test_value_types_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains("VALUE TYPES"),
        "man page must contain a 'VALUE TYPES' section"
    );
}

/// AC: VALUE TYPES maps YAML boolean → netfyr Bool.
#[test]
fn test_value_types_documents_bool_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("Bool") || section.contains("bool") || section.contains("boolean"),
        "VALUE TYPES section must document the YAML boolean → Bool mapping"
    );
}

/// AC: VALUE TYPES maps non-negative YAML integers → netfyr U64.
#[test]
fn test_value_types_documents_u64_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("U64"),
        "VALUE TYPES section must document the YAML integer >= 0 → U64 mapping"
    );
}

/// AC: VALUE TYPES maps negative YAML integers → netfyr I64.
#[test]
fn test_value_types_documents_i64_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("I64"),
        "VALUE TYPES section must document the YAML integer < 0 → I64 mapping"
    );
}

/// AC: VALUE TYPES maps valid IP-address strings → netfyr IpAddr.
#[test]
fn test_value_types_documents_ipaddr_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("IpAddr") || section.contains("IP address"),
        "VALUE TYPES section must document the YAML string (IP) → IpAddr mapping"
    );
}

/// AC: VALUE TYPES maps valid CIDR strings → netfyr IpNetwork.
#[test]
fn test_value_types_documents_ipnetwork_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("IpNetwork") || section.contains("CIDR"),
        "VALUE TYPES section must document the YAML string (CIDR) → IpNetwork mapping"
    );
}

/// AC: VALUE TYPES maps other strings → netfyr String.
#[test]
fn test_value_types_documents_string_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("String"),
        "VALUE TYPES section must document the YAML string (other) → String mapping"
    );
}

/// AC: VALUE TYPES maps YAML sequences → netfyr List.
#[test]
fn test_value_types_documents_list_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("List") || section.contains("sequence"),
        "VALUE TYPES section must document the YAML sequence → List mapping"
    );
}

/// AC: VALUE TYPES maps YAML mappings → netfyr Map.
#[test]
fn test_value_types_documents_map_mapping() {
    let section = extract_section(&read_man_page(), "VALUE TYPES");
    assert!(
        section.contains("Map") || section.contains("mapping"),
        "VALUE TYPES section must document the YAML mapping → Map mapping"
    );
}

// ── Scenario: FILES section lists config directories ──────────────────────────

/// AC: FILES section exists.
#[test]
fn test_files_section_exists() {
    let content = read_man_page();
    assert!(
        content.contains(".SH FILES"),
        "man page must contain a 'FILES' section (.SH FILES)"
    );
}

/// AC: FILES section lists /etc/netfyr/policies/ as the policy directory.
#[test]
fn test_files_section_lists_etc_netfyr_policies() {
    let section = extract_section(&read_man_page(), "FILES");
    assert!(
        section.contains("/etc/netfyr/policies/"),
        "FILES section must list /etc/netfyr/policies/"
    );
}

/// AC: FILES section lists /var/lib/netfyr/policies/ as the daemon-managed directory.
#[test]
fn test_files_section_lists_var_lib_netfyr_policies() {
    let section = extract_section(&read_man_page(), "FILES");
    assert!(
        section.contains("/var/lib/netfyr/policies/"),
        "FILES section must list /var/lib/netfyr/policies/"
    );
}

// ── Scenario: Man page is installed by RPM ────────────────────────────────────

/// AC: the man page is placed at the path expected by the RPM spec (man/netfyr.yaml.5).
/// The RPM %install section copies this file to %{_mandir}/man5/.  This test
/// verifies the source path that the RPM spec depends on is stable.
#[test]
fn test_man_page_path_matches_rpm_install_source() {
    // The RPM spec line is:
    //   install -Dpm 0644 man/netfyr.yaml.5 %{buildroot}%{_mandir}/man5/netfyr.yaml.5
    // So the file must live at man/netfyr.yaml.5 in the source tree.
    let path = man_page_path();
    assert!(
        path.exists(),
        "man/netfyr.yaml.5 must exist at the path the RPM spec installs from: {:?}",
        path
    );
    // Verify the filename itself is exactly "netfyr.yaml.5".
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("netfyr.yaml.5"),
        "man page file must be named exactly 'netfyr.yaml.5'"
    );
    // Verify it lives in a directory called "man".
    assert_eq!(
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str()),
        Some("man"),
        "man page must be in a directory named 'man'"
    );
}
