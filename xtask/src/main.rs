//! xtask — workspace development automation for netfyr.
//!
//! Run via: `cargo run --package xtask -- <subcommand>`
//!
//! Subcommands:
//!   man   Generate troff man pages from the clap CLI definitions.

use clap::{CommandFactory, Parser, Subcommand};
use clap_mangen::Man;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// ── CLI for the xtask itself ──────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "xtask", about = "Workspace development automation")]
struct Xtask {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Subcommand)]
enum XtaskCommand {
    /// Generate troff man pages from the clap CLI definitions.
    ///
    /// Outputs man/netfyr.1, man/netfyr-apply.1, man/netfyr-query.1.
    /// Does not overwrite man/netfyr-examples.7 (maintained by hand).
    Man,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = Xtask::parse();
    match args.command {
        XtaskCommand::Man => {
            if let Err(e) = generate_man_pages() {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ── Man page generation ───────────────────────────────────────────────────────

fn generate_man_pages() -> Result<(), Box<dyn std::error::Error>> {
    // CARGO_MANIFEST_DIR is set to the xtask/ directory at compile time.
    // Navigate one level up to reach the workspace root, then into man/.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = manifest_dir.join("../man");

    fs::create_dir_all(&out_dir)?;

    let cmd = netfyr_cli::Cli::command();

    // ── Top-level man page: netfyr.1 ─────────────────────────────────────────
    {
        let mut buf = Vec::new();
        let man = Man::new(cmd.clone());
        man.render(&mut buf)?;
        append_exit_status(&mut buf, None)?;
        append_files(&mut buf)?;
        append_examples(&mut buf, None)?;
        append_see_also(&mut buf, None)?;
        fs::write(out_dir.join("netfyr.1"), &buf)?;
        println!("Generated: man/netfyr.1");
    }

    // ── Subcommand man pages ──────────────────────────────────────────────────
    for subcmd in cmd.get_subcommands() {
        let name = format!("netfyr-{}", subcmd.get_name());
        let subcmd_name = subcmd.get_name().to_string();
        // Clone and rename so the man page header shows NETFYR-APPLY(1) etc.
        let subcmd = subcmd.clone().name(name.clone());
        let man = Man::new(subcmd);
        let mut buf = Vec::new();
        man.render(&mut buf)?;
        append_exit_status(&mut buf, Some(&subcmd_name))?;
        append_files(&mut buf)?;
        append_examples(&mut buf, Some(&subcmd_name))?;
        append_see_also(&mut buf, Some(&subcmd_name))?;
        let filename = format!("{name}.1");
        fs::write(out_dir.join(&filename), &buf)?;
        println!("Generated: man/{filename}");
    }

    println!("Note: man/netfyr-examples.7 is maintained by hand and was not modified.");
    Ok(())
}

// ── Troff section helpers ─────────────────────────────────────────────────────

/// Append `.SH "EXIT STATUS"` with `.TP` entries for codes 0, 1, and 2.
fn append_exit_status(buf: &mut Vec<u8>, _subcommand: Option<&str>) -> std::io::Result<()> {
    writeln!(buf, ".SH \"EXIT STATUS\"")?;
    writeln!(buf, ".TP")?;
    writeln!(buf, ".B 0")?;
    writeln!(buf, "All operations succeeded or no changes needed.")?;
    writeln!(buf, ".TP")?;
    writeln!(buf, ".B 1")?;
    writeln!(buf, "Partial failure or conflicts detected.")?;
    writeln!(buf, ".TP")?;
    writeln!(buf, ".B 2")?;
    writeln!(buf, "Total failure or fatal error.")?;
    Ok(())
}

/// Append `.SH FILES` listing the standard netfyr file paths.
fn append_files(buf: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(buf, ".SH FILES")?;
    writeln!(buf, ".TP")?;
    writeln!(buf, r".I /etc/netfyr/policies/")?;
    writeln!(buf, "Default directory for policy files.")?;
    writeln!(buf, ".TP")?;
    writeln!(buf, r".I /var/lib/netfyr/")?;
    writeln!(buf, "State directory for persistent daemon data.")?;
    Ok(())
}

/// Append `.SH EXAMPLES` with at least two usage examples per command.
fn append_examples(buf: &mut Vec<u8>, subcommand: Option<&str>) -> std::io::Result<()> {
    writeln!(buf, ".SH EXAMPLES")?;
    match subcommand {
        None => {
            // Top-level netfyr — show one example per subcommand.
            writeln!(buf, "Apply all policies in the default directory:")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, ".RS 4")?;
            writeln!(buf, ".nf")?;
            writeln!(buf, "netfyr apply /etc/netfyr/policies/")?;
            writeln!(buf, ".fi")?;
            writeln!(buf, ".RE")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, "Query current network state:")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, ".RS 4")?;
            writeln!(buf, ".nf")?;
            writeln!(buf, "netfyr query")?;
            writeln!(buf, ".fi")?;
            writeln!(buf, ".RE")?;
        }
        Some("apply") => {
            writeln!(buf, "Apply all policies in the default directory:")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, ".RS 4")?;
            writeln!(buf, ".nf")?;
            writeln!(buf, "netfyr apply /etc/netfyr/policies/")?;
            writeln!(buf, ".fi")?;
            writeln!(buf, ".RE")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, "Preview changes before applying:")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, ".RS 4")?;
            writeln!(buf, ".nf")?;
            writeln!(buf, "netfyr apply --dry-run /etc/netfyr/policies/server.yaml")?;
            writeln!(buf, ".fi")?;
            writeln!(buf, ".RE")?;
        }
        Some("query") => {
            writeln!(buf, "Query all network interfaces:")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, ".RS 4")?;
            writeln!(buf, ".nf")?;
            writeln!(buf, "netfyr query")?;
            writeln!(buf, ".fi")?;
            writeln!(buf, ".RE")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, "Query a specific interface by name, output as JSON:")?;
            writeln!(buf, ".PP")?;
            writeln!(buf, ".RS 4")?;
            writeln!(buf, ".nf")?;
            writeln!(buf, "netfyr query -s type=ethernet -s name=eth0 -o json")?;
            writeln!(buf, ".fi")?;
            writeln!(buf, ".RE")?;
        }
        Some(other) => {
            // Fallback for any future subcommands.
            writeln!(buf, "See")?;
            writeln!(buf, ".BR netfyr-{other} (1)")?;
            writeln!(buf, "for usage details.")?;
        }
    }
    Ok(())
}

/// Append `.SH "SEE ALSO"` with cross-references to all netfyr man pages.
fn append_see_also(buf: &mut Vec<u8>, subcommand: Option<&str>) -> std::io::Result<()> {
    writeln!(buf, ".SH \"SEE ALSO\"")?;
    match subcommand {
        None => {
            // Top-level page — reference all subcommand and supplementary pages.
            writeln!(buf, ".BR netfyr-apply (1),")?;
            writeln!(buf, ".BR netfyr-query (1),")?;
            writeln!(buf, ".BR netfyr-examples (7),")?;
            writeln!(buf, r".BR netfyr.yaml (5)")?;
        }
        Some("apply") => {
            writeln!(buf, ".BR netfyr (1),")?;
            writeln!(buf, ".BR netfyr-query (1),")?;
            writeln!(buf, ".BR netfyr-examples (7),")?;
            writeln!(buf, r".BR netfyr.yaml (5)")?;
        }
        Some("query") => {
            writeln!(buf, ".BR netfyr (1),")?;
            writeln!(buf, ".BR netfyr-apply (1),")?;
            writeln!(buf, ".BR netfyr-examples (7),")?;
            writeln!(buf, r".BR netfyr.yaml (5)")?;
        }
        Some(_) => {
            writeln!(buf, ".BR netfyr (1),")?;
            writeln!(buf, ".BR netfyr-apply (1),")?;
            writeln!(buf, ".BR netfyr-query (1),")?;
            writeln!(buf, ".BR netfyr-examples (7),")?;
            writeln!(buf, r".BR netfyr.yaml (5)")?;
        }
    }
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Invoke a troff-section helper and return its output as a UTF-8 string.
    fn render<F: FnOnce(&mut Vec<u8>) -> std::io::Result<()>>(f: F) -> String {
        let mut buf = Vec::new();
        f(&mut buf).expect("helper must not fail");
        String::from_utf8(buf).expect("output must be valid UTF-8")
    }

    // ── EXIT STATUS section ───────────────────────────────────────────────────

    /// AC: EXIT STATUS section header is emitted.
    #[test]
    fn test_exit_status_section_header_present() {
        let out = render(|buf| append_exit_status(buf, None));
        assert!(out.contains(".SH \"EXIT STATUS\""), "EXIT STATUS .SH header must be present");
    }

    /// AC: EXIT STATUS documents exit code 0 (success / no changes needed).
    #[test]
    fn test_exit_status_documents_code_0() {
        let out = render(|buf| append_exit_status(buf, None));
        assert!(out.contains(".B 0"), "EXIT STATUS must contain .B 0 for exit code 0");
        assert!(
            out.contains("succeeded") || out.contains("no changes"),
            "exit code 0 description must mention success or no-change condition"
        );
    }

    /// AC: EXIT STATUS documents exit code 1 (partial failure / conflicts).
    #[test]
    fn test_exit_status_documents_code_1() {
        let out = render(|buf| append_exit_status(buf, None));
        assert!(out.contains(".B 1"), "EXIT STATUS must contain .B 1 for exit code 1");
        let lower = out.to_lowercase();
        assert!(
            lower.contains("partial") || lower.contains("conflict"),
            "exit code 1 description must mention partial failure or conflicts"
        );
    }

    /// AC: EXIT STATUS documents exit code 2 (total failure / fatal error).
    #[test]
    fn test_exit_status_documents_code_2() {
        let out = render(|buf| append_exit_status(buf, None));
        assert!(out.contains(".B 2"), "EXIT STATUS must contain .B 2 for exit code 2");
        let lower = out.to_lowercase();
        assert!(
            lower.contains("total") || lower.contains("fatal") || lower.contains("failure"),
            "exit code 2 description must mention total failure or fatal error"
        );
    }

    /// EXIT STATUS section is emitted identically regardless of subcommand.
    #[test]
    fn test_exit_status_same_for_all_subcommands() {
        let none_out = render(|buf| append_exit_status(buf, None));
        let apply_out = render(|buf| append_exit_status(buf, Some("apply")));
        let query_out = render(|buf| append_exit_status(buf, Some("query")));
        assert_eq!(none_out, apply_out, "EXIT STATUS must be identical for top-level and apply");
        assert_eq!(none_out, query_out, "EXIT STATUS must be identical for top-level and query");
    }

    // ── FILES section ─────────────────────────────────────────────────────────

    /// AC: FILES section header is emitted.
    #[test]
    fn test_files_section_header_present() {
        let out = render(|buf| append_files(buf));
        assert!(out.contains(".SH FILES"), "FILES .SH header must be present");
    }

    /// AC: FILES section lists /etc/netfyr/policies/ (from the spec).
    #[test]
    fn test_files_section_lists_etc_netfyr_policies() {
        let out = render(|buf| append_files(buf));
        assert!(
            out.contains("/etc/netfyr/policies/"),
            "FILES section must list /etc/netfyr/policies/"
        );
    }

    /// FILES section also documents the daemon state directory.
    #[test]
    fn test_files_section_lists_var_lib_netfyr() {
        let out = render(|buf| append_files(buf));
        assert!(
            out.contains("/var/lib/netfyr/"),
            "FILES section must list /var/lib/netfyr/"
        );
    }

    // ── EXAMPLES section — apply subcommand ───────────────────────────────────

    /// AC: EXAMPLES section header is emitted for the apply subcommand.
    #[test]
    fn test_apply_examples_section_header_present() {
        let out = render(|buf| append_examples(buf, Some("apply")));
        assert!(out.contains(".SH EXAMPLES"), "EXAMPLES .SH header must be present for apply");
    }

    /// AC: apply EXAMPLES must contain at least two real-world usage examples.
    /// Each example is enclosed in a .nf / .fi no-fill block.
    #[test]
    fn test_apply_examples_has_at_least_two_nf_blocks() {
        let out = render(|buf| append_examples(buf, Some("apply")));
        let nf_count = out.matches(".nf").count();
        assert!(
            nf_count >= 2,
            "apply EXAMPLES must contain at least 2 usage examples (.nf blocks); found {nf_count}"
        );
    }

    /// AC: apply EXAMPLES must include a --dry-run usage example.
    #[test]
    fn test_apply_examples_includes_dry_run_usage() {
        let out = render(|buf| append_examples(buf, Some("apply")));
        assert!(
            out.contains("--dry-run"),
            "apply EXAMPLES must show a --dry-run usage example"
        );
    }

    /// AC: apply EXAMPLES must include the standard policies directory path.
    #[test]
    fn test_apply_examples_includes_default_policies_directory() {
        let out = render(|buf| append_examples(buf, Some("apply")));
        assert!(
            out.contains("/etc/netfyr/policies/"),
            "apply EXAMPLES must reference /etc/netfyr/policies/"
        );
    }

    // ── EXAMPLES section — query subcommand ───────────────────────────────────

    /// AC: query EXAMPLES must contain at least two real-world usage examples.
    #[test]
    fn test_query_examples_has_at_least_two_nf_blocks() {
        let out = render(|buf| append_examples(buf, Some("query")));
        let nf_count = out.matches(".nf").count();
        assert!(
            nf_count >= 2,
            "query EXAMPLES must contain at least 2 usage examples (.nf blocks); found {nf_count}"
        );
    }

    // ── EXAMPLES section — top-level (None) ──────────────────────────────────

    /// AC: top-level netfyr EXAMPLES must contain at least two usage examples.
    #[test]
    fn test_toplevel_examples_has_at_least_two_nf_blocks() {
        let out = render(|buf| append_examples(buf, None));
        let nf_count = out.matches(".nf").count();
        assert!(
            nf_count >= 2,
            "top-level EXAMPLES must contain at least 2 usage examples (.nf blocks); found {nf_count}"
        );
    }

    // ── SEE ALSO section ──────────────────────────────────────────────────────

    /// AC: SEE ALSO section header is emitted.
    #[test]
    fn test_see_also_section_header_present() {
        let out = render(|buf| append_see_also(buf, None));
        assert!(out.contains(".SH \"SEE ALSO\""), "SEE ALSO .SH header must be present");
    }

    /// AC: apply SEE ALSO must cross-reference netfyr(1).
    #[test]
    fn test_see_also_apply_references_netfyr_1() {
        let out = render(|buf| append_see_also(buf, Some("apply")));
        // clap_mangen emits .BR entries; check the page name and section.
        assert!(
            out.contains("netfyr (1)") || out.contains("netfyr(1)"),
            "apply SEE ALSO must reference netfyr(1); got:\n{out}"
        );
    }

    /// AC: apply SEE ALSO must cross-reference netfyr-query(1).
    #[test]
    fn test_see_also_apply_references_netfyr_query_1() {
        let out = render(|buf| append_see_also(buf, Some("apply")));
        assert!(
            out.contains("netfyr-query (1)") || out.contains("netfyr-query(1)"),
            "apply SEE ALSO must reference netfyr-query(1); got:\n{out}"
        );
    }

    /// AC: apply SEE ALSO must cross-reference netfyr.yaml(5).
    #[test]
    fn test_see_also_apply_references_netfyr_yaml_5() {
        let out = render(|buf| append_see_also(buf, Some("apply")));
        assert!(
            out.contains("netfyr.yaml (5)") || out.contains("netfyr.yaml(5)"),
            "apply SEE ALSO must reference netfyr.yaml(5); got:\n{out}"
        );
    }

    /// AC: top-level SEE ALSO must reference netfyr-apply(1).
    #[test]
    fn test_see_also_toplevel_references_netfyr_apply_1() {
        let out = render(|buf| append_see_also(buf, None));
        assert!(
            out.contains("netfyr-apply (1)") || out.contains("netfyr-apply(1)"),
            "top-level SEE ALSO must reference netfyr-apply(1); got:\n{out}"
        );
    }

    /// AC: top-level SEE ALSO must reference netfyr-query(1).
    #[test]
    fn test_see_also_toplevel_references_netfyr_query_1() {
        let out = render(|buf| append_see_also(buf, None));
        assert!(
            out.contains("netfyr-query (1)") || out.contains("netfyr-query(1)"),
            "top-level SEE ALSO must reference netfyr-query(1); got:\n{out}"
        );
    }

    /// AC: top-level SEE ALSO must reference netfyr-examples(7).
    #[test]
    fn test_see_also_toplevel_references_netfyr_examples_7() {
        let out = render(|buf| append_see_also(buf, None));
        assert!(
            out.contains("netfyr-examples (7)") || out.contains("netfyr-examples(7)"),
            "top-level SEE ALSO must reference netfyr-examples(7); got:\n{out}"
        );
    }

    /// AC: top-level SEE ALSO must also reference netfyr.yaml(5).
    #[test]
    fn test_see_also_toplevel_references_netfyr_yaml_5() {
        let out = render(|buf| append_see_also(buf, None));
        assert!(
            out.contains("netfyr.yaml (5)") || out.contains("netfyr.yaml(5)"),
            "top-level SEE ALSO must reference netfyr.yaml(5); got:\n{out}"
        );
    }

    /// query SEE ALSO must reference both netfyr(1) and netfyr-apply(1).
    #[test]
    fn test_see_also_query_references_netfyr_and_apply() {
        let out = render(|buf| append_see_also(buf, Some("query")));
        assert!(
            out.contains("netfyr (1)") || out.contains("netfyr(1)"),
            "query SEE ALSO must reference netfyr(1)"
        );
        assert!(
            out.contains("netfyr-apply (1)") || out.contains("netfyr-apply(1)"),
            "query SEE ALSO must reference netfyr-apply(1)"
        );
    }
}
