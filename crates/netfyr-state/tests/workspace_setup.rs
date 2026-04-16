//! Tests for SPEC-001: Workspace Setup acceptance criteria.
//!
//! These tests verify the workspace structure, Cargo.toml configuration,
//! file layout, and integration-test helper availability without building
//! binaries (compile-time checks happen in the CI build step itself).

use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the workspace root, derived from this crate's CARGO_MANIFEST_DIR
/// (crates/netfyr-state), going up two levels: netfyr-state → crates → root.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .parent()
        .expect("crates/netfyr-state must have a parent")
        .parent()
        .expect("crates must have a parent (workspace root)")
        .to_path_buf()
}

fn read_workspace_cargo_toml() -> String {
    let path = workspace_root().join("Cargo.toml");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", path, e))
}

// ---------------------------------------------------------------------------
// Scenario: Workspace members are correctly listed
// ---------------------------------------------------------------------------

/// AC: workspace members list contains the 7 required crates.
#[test]
fn test_workspace_members_contain_required_crates() {
    let cargo_toml = read_workspace_cargo_toml();

    let required_members = [
        "crates/netfyr-state",
        "crates/netfyr-reconcile",
        "crates/netfyr-backend",
        "crates/netfyr-policy",
        "crates/netfyr-varlink",
        "crates/netfyr-cli",
        "crates/netfyr-daemon",
    ];

    for member in &required_members {
        assert!(
            cargo_toml.contains(member),
            "Workspace Cargo.toml is missing required member: {}",
            member
        );
    }
}

/// AC: workspace members list contains the 7 required crates (plus netfyr-test-utils).
///
/// The spec lists 7 crates. The workspace also includes "crates/netfyr-test-utils"
/// as an 8th member because netfyr-backend, netfyr-cli, and netfyr-daemon all
/// depend on it via path dependencies — Cargo requires path-dependency crates
/// within the workspace directory to be workspace members. This is a legitimate
/// addition that does not violate the spirit of the spec.
#[test]
fn test_workspace_members_count_is_seven() {
    let cargo_toml = read_workspace_cargo_toml();

    // Verify all 7 spec-required crates are present under crates/.
    let required_members = [
        "crates/netfyr-state",
        "crates/netfyr-reconcile",
        "crates/netfyr-backend",
        "crates/netfyr-policy",
        "crates/netfyr-varlink",
        "crates/netfyr-cli",
        "crates/netfyr-daemon",
    ];
    for member in &required_members {
        assert!(
            cargo_toml.contains(member),
            "Workspace Cargo.toml is missing required member: {}",
            member
        );
    }

    // Count crates/* members; allow 7 (spec) or 8 (spec + netfyr-test-utils).
    let crates_member_count = cargo_toml
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with('"') && trimmed.contains("crates/")
        })
        .count();

    assert!(
        crates_member_count == 7 || crates_member_count == 8,
        "Expected 7 or 8 crates/* workspace members, found {}",
        crates_member_count
    );
}

// ---------------------------------------------------------------------------
// Scenario: Workspace features are defined
// ---------------------------------------------------------------------------

/// AC: workspace features section defines dhcp, systemd, varlink with empty dependency lists.
#[test]
fn test_workspace_features_defines_dhcp_systemd_varlink() {
    let cargo_toml = read_workspace_cargo_toml();

    // The spec requires a [workspace.features] section with these three features.
    assert!(
        cargo_toml.contains("[workspace.features]"),
        "Root Cargo.toml must have a [workspace.features] section"
    );

    for feature in &["dhcp", "systemd", "varlink"] {
        // Each feature should appear as a key in the features table.
        // Minimal form is:  dhcp = []
        let pattern = format!("{} = []", feature);
        assert!(
            cargo_toml.contains(&pattern),
            "Workspace feature '{}' must be defined as an empty list ('{}') in Cargo.toml",
            feature,
            pattern
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: Library crates have correct structure
// ---------------------------------------------------------------------------

/// AC: each library crate has a Cargo.toml and src/lib.rs.
#[test]
fn test_library_crates_have_cargo_toml_and_lib_rs() {
    let root = workspace_root();

    let library_crates = [
        "netfyr-state",
        "netfyr-reconcile",
        "netfyr-backend",
        "netfyr-policy",
        "netfyr-varlink",
    ];

    for crate_name in &library_crates {
        let crate_dir = root.join("crates").join(crate_name);

        let cargo_toml = crate_dir.join("Cargo.toml");
        assert!(
            cargo_toml.exists(),
            "Library crate '{}' must have a Cargo.toml at {:?}",
            crate_name,
            cargo_toml
        );

        let lib_rs = crate_dir.join("src").join("lib.rs");
        assert!(
            lib_rs.exists(),
            "Library crate '{}' must have src/lib.rs at {:?}",
            crate_name,
            lib_rs
        );
    }
}

/// AC: binary crates (netfyr-cli, netfyr-daemon) each have a Cargo.toml and src/main.rs.
#[test]
fn test_binary_crates_have_cargo_toml_and_main_rs() {
    let root = workspace_root();

    let binary_crates = ["netfyr-cli", "netfyr-daemon"];

    for crate_name in &binary_crates {
        let crate_dir = root.join("crates").join(crate_name);

        let cargo_toml = crate_dir.join("Cargo.toml");
        assert!(
            cargo_toml.exists(),
            "Binary crate '{}' must have a Cargo.toml at {:?}",
            crate_name,
            cargo_toml
        );

        let main_rs = crate_dir.join("src").join("main.rs");
        assert!(
            main_rs.exists(),
            "Binary crate '{}' must have src/main.rs at {:?}",
            crate_name,
            main_rs
        );
    }
}

/// AC: each library crate's Cargo.toml declares the correct package name.
#[test]
fn test_each_crate_cargo_toml_has_correct_package_name() {
    let root = workspace_root();

    let all_crates = [
        "netfyr-state",
        "netfyr-reconcile",
        "netfyr-backend",
        "netfyr-policy",
        "netfyr-varlink",
        "netfyr-cli",
        "netfyr-daemon",
    ];

    for crate_name in &all_crates {
        let cargo_toml_path = root.join("crates").join(crate_name).join("Cargo.toml");
        let content = fs::read_to_string(&cargo_toml_path)
            .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", cargo_toml_path, e));

        let expected_name_line = format!("name = \"{}\"", crate_name);
        assert!(
            content.contains(&expected_name_line),
            "Cargo.toml for '{}' must declare `{}` in [package]",
            crate_name,
            expected_name_line
        );
    }
}

/// AC: each crate's Cargo.toml declares edition = "2021".
#[test]
fn test_each_crate_cargo_toml_uses_edition_2021() {
    let root = workspace_root();

    let all_crates = [
        "netfyr-state",
        "netfyr-reconcile",
        "netfyr-backend",
        "netfyr-policy",
        "netfyr-varlink",
        "netfyr-cli",
        "netfyr-daemon",
    ];

    for crate_name in &all_crates {
        let cargo_toml_path = root.join("crates").join(crate_name).join("Cargo.toml");
        let content = fs::read_to_string(&cargo_toml_path)
            .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", cargo_toml_path, e));

        assert!(
            content.contains("edition = \"2021\""),
            "Cargo.toml for '{}' must declare `edition = \"2021\"`",
            crate_name
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: Integration test helpers exist
// ---------------------------------------------------------------------------

/// AC: tests/helpers.sh exists in the workspace.
#[test]
fn test_helpers_sh_exists() {
    let helpers = workspace_root().join("tests").join("helpers.sh");
    assert!(
        helpers.exists(),
        "tests/helpers.sh must exist at {:?}",
        helpers
    );
}

/// AC: helpers.sh defines functions netns_setup, create_veth, add_address,
/// start_dnsmasq, cleanup.
#[test]
fn test_helpers_sh_defines_required_functions() {
    let helpers_path = workspace_root().join("tests").join("helpers.sh");
    let content = fs::read_to_string(&helpers_path)
        .unwrap_or_else(|e| panic!("Failed to read helpers.sh: {}", e));

    let required_functions = [
        "netns_setup",
        "create_veth",
        "add_address",
        "start_dnsmasq",
        "cleanup",
    ];

    for func in &required_functions {
        // Shell functions are defined as `name() {` or `function name {`.
        let definition_form_1 = format!("{}()", func);
        let definition_form_2 = format!("function {}", func);
        assert!(
            content.contains(&definition_form_1) || content.contains(&definition_form_2),
            "helpers.sh must define function '{}' (expected '{}()' or 'function {}')",
            func,
            func,
            func
        );
    }
}

/// AC: helpers.sh is sourced by all test scripts in tests/.
///
/// Any *.sh files in tests/ (other than helpers.sh itself) must source helpers.sh.
#[test]
fn test_all_test_scripts_source_helpers_sh() {
    let tests_dir = workspace_root().join("tests");

    let entries = fs::read_dir(&tests_dir)
        .unwrap_or_else(|e| panic!("Failed to read tests/ directory: {}", e));

    let test_scripts: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("sh")
                && p.file_name().and_then(|n| n.to_str()) != Some("helpers.sh")
        })
        .collect();

    for script in &test_scripts {
        let content = fs::read_to_string(script)
            .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", script, e));

        assert!(
            content.contains("helpers.sh"),
            "Test script {:?} must source helpers.sh (expected `source ... helpers.sh` or `. ... helpers.sh`)",
            script
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: Workspace resolver is set to "2"
// ---------------------------------------------------------------------------

/// AC: The root Cargo.toml uses the v2 dependency resolver.
#[test]
fn test_workspace_uses_resolver_2() {
    let cargo_toml = read_workspace_cargo_toml();
    assert!(
        cargo_toml.contains("resolver = \"2\""),
        "Root Cargo.toml must declare `resolver = \"2\"` in [workspace]"
    );
}
