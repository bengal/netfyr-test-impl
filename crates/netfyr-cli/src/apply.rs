//! Implementation of the `netfyr apply` subcommand.
//!
//! Two runtime modes are supported, detected automatically:
//!
//! 1. **Daemon-free**: Connect to daemon fails → static policies only, apply directly.
//! 2. **Daemon**: Connect succeeds → submit policies via Varlink, daemon reconciles.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Args;
use colored::Colorize;

use netfyr_backend::{ApplyReport, BackendRegistry, DiffOpKind, NetlinkBackend};
use netfyr_policy::{
    load_policy_dir, load_policy_file, FactoryType, PolicySet, StaticFactory, StateFactory,
};
use netfyr_reconcile::{
    generate_diff, merge, ConflictReport, DiffReport, EntityKey, PolicyId, PolicyInput,
    StateDiff as ReconcileDiff,
};
// Import the state-level diff function via its full module path to avoid the
// name ambiguity between the `diff` module and the re-exported `diff` function.
use netfyr_state::diff::diff as compute_state_diff;
use netfyr_state::{SchemaRegistry, StateDiff as StateDiffState};
use netfyr_varlink::{
    VarlinkApplyReport, VarlinkClient, VarlinkError, VarlinkPolicy, VarlinkStateDiff,
};

/// Unix socket path for the netfyr daemon's Varlink API.
const SOCKET_PATH: &str = "/run/netfyr/netfyr.sock";

// ── CLI argument struct ───────────────────────────────────────────────────────

#[derive(Args)]
pub struct ApplyArgs {
    /// Paths to YAML files or directories containing policies
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Show what would change without applying
    #[arg(long)]
    pub dry_run: bool,
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Run the `apply` subcommand.
///
/// Loads policies from `args.paths`, detects daemon vs. daemon-free mode,
/// and either applies changes locally or delegates to the daemon via Varlink.
pub async fn run_apply(args: ApplyArgs) -> Result<ExitCode> {
    // 1. Load all policies from the provided paths.
    let policy_set = load_policies(&args.paths)?;

    // 2. Detect runtime mode: try connecting to the daemon socket.
    match VarlinkClient::connect(SOCKET_PATH).await {
        Ok(client) => {
            // Daemon is running — delegate all work to it.
            return run_apply_daemon(client, &policy_set, args.dry_run).await;
        }
        Err(VarlinkError::ConnectionFailed(_)) => {
            // Socket not found or connection refused — fall through to daemon-free mode.
        }
        Err(e) => {
            return Err(anyhow::Error::from(e).context("unexpected error connecting to daemon socket"));
        }
    }

    // ── Daemon-free mode ──────────────────────────────────────────────────────

    // 3. Reject non-static policies — they require the daemon.
    let non_static: Vec<&str> = policy_set
        .iter()
        .filter(|p| p.factory_type != FactoryType::Static)
        .map(|p| p.name.as_str())
        .collect();
    if !non_static.is_empty() {
        bail!(
            "policies {:?} use non-static factories which require the netfyr daemon.\n\
             Start the daemon with: systemctl start netfyr",
            non_static
        );
    }

    // 4. Convert each policy into a PolicyInput for the reconciliation engine.
    let inputs = policies_to_inputs(&policy_set)?;

    // Compute managed_entities before merge() consumes the inputs.
    let managed_entities: HashSet<EntityKey> = inputs
        .iter()
        .flat_map(|input| input.state_set.entities())
        .collect();

    // 5. Reconcile: merge all inputs into an effective state, detecting conflicts.
    let reconciliation = merge(inputs);

    // 6. Query the current system state.
    let registry = create_backend_registry();
    let actual_state = registry
        .query_all()
        .await
        .context("failed to query current system state via netlink")?;

    let effective_state = &reconciliation.effective_state;

    // 7. Compute diffs:
    //    - reconcile diff: rich per-field diff for display (old→new values)
    //    - state diff: lightweight diff consumed by registry.apply()
    //
    // generate_diff(desired, actual, managed_entities, schema) — desired first, then actual
    // compute_state_diff(from, to) — from=actual, to=desired
    let schema = SchemaRegistry::default();
    let reconcile_diff: ReconcileDiff =
        generate_diff(effective_state, &actual_state, &managed_entities, &schema);
    let state_diff: StateDiffState = compute_state_diff(&actual_state, effective_state);

    // 8. Dry-run: display planned changes and exit without applying.
    if args.dry_run {
        let is_empty = reconcile_diff.is_empty();
        if !reconciliation.conflicts.is_empty() {
            print_conflicts(&reconciliation.conflicts);
        }
        let diff_report = DiffReport::new(reconcile_diff, effective_state, &actual_state);
        display_dry_run_report(&diff_report, is_empty);
        let code: u8 = if is_empty { 0 } else { 1 };
        return Ok(ExitCode::from(code));
    }

    // 9. No changes — exit early.
    if state_diff.is_empty() {
        if reconciliation.conflicts.is_empty() {
            println!("No changes needed. System is already in desired state.");
            return Ok(ExitCode::SUCCESS);
        } else {
            // Conflicting fields prevented all desired changes; nothing applicable left.
            print_conflicts(&reconciliation.conflicts);
            return Ok(ExitCode::from(1u8));
        }
    }

    // 10. Apply the diff.
    let apply_report = registry
        .apply(&state_diff)
        .await
        .context("failed to apply changes via netlink")?;

    // 11. Display results.
    display_apply_report(&apply_report, &reconciliation.conflicts);

    // 12. Return exit code.
    Ok(determine_exit_code(&apply_report, &reconciliation.conflicts))
}

// ── Daemon mode ───────────────────────────────────────────────────────────────

async fn run_apply_daemon(
    mut client: VarlinkClient,
    policy_set: &PolicySet,
    dry_run: bool,
) -> Result<ExitCode> {
    let policy_count = policy_set.len();
    let policies: Vec<VarlinkPolicy> = policy_set.iter().map(VarlinkPolicy::from).collect();

    if dry_run {
        let diff = client
            .dry_run(policies)
            .await
            .context("daemon dry-run failed")?;
        let is_empty = diff.operations.is_empty();
        display_varlink_diff(&diff, is_empty);
        return Ok(ExitCode::from(if is_empty { 0u8 } else { 1u8 }));
    }

    let report = client
        .submit_policies(policies)
        .await
        .context("failed to submit policies to daemon")?;

    display_varlink_apply_report(&report, policy_count);
    Ok(daemon_exit_code(&report))
}

// ── Policy loading ────────────────────────────────────────────────────────────

/// Load all policies from the given paths (files or directories).
///
/// For files: parses them directly. For directories: recursively finds all
/// `.yaml`/`.yml` files. Fails on missing paths or duplicate policy names
/// across paths.
fn load_policies(paths: &[PathBuf]) -> Result<PolicySet> {
    let mut policy_set = PolicySet::new();

    for path in paths {
        if !path.exists() {
            bail!("path not found: {}", path.display());
        }

        let policies = if path.is_dir() {
            let set = load_policy_dir(path).with_context(|| {
                format!("failed to load policy directory: {}", path.display())
            })?;
            set.iter().cloned().collect::<Vec<_>>()
        } else {
            load_policy_file(path).with_context(|| {
                format!("failed to load policy file: {}", path.display())
            })?
        };

        for policy in policies {
            if policy_set.get(&policy.name).is_some() {
                bail!(
                    "duplicate policy name '{}' (from {})",
                    policy.name,
                    path.display()
                );
            }
            policy_set.insert(policy);
        }
    }

    Ok(policy_set)
}

// ── Reconciliation helpers ────────────────────────────────────────────────────

/// Convert each static policy in the set into a `PolicyInput` for the
/// reconciliation engine by running it through `StaticFactory`.
fn policies_to_inputs(policy_set: &PolicySet) -> Result<Vec<PolicyInput>> {
    let factory = StaticFactory;
    let mut inputs = Vec::new();

    for policy in policy_set.iter() {
        let state_set = factory.produce(policy).with_context(|| {
            format!("failed to produce state for policy '{}'", policy.name)
        })?;
        inputs.push(PolicyInput {
            policy_id: PolicyId::from(policy.name.clone()),
            priority: policy.priority,
            state_set,
        });
    }

    Ok(inputs)
}

// ── Backend registry ──────────────────────────────────────────────────────────

fn create_backend_registry() -> BackendRegistry {
    let mut registry = BackendRegistry::new();
    // NetlinkBackend is the only backend; registration cannot fail for a single backend.
    registry
        .register(Arc::new(NetlinkBackend::new()))
        .expect("failed to register NetlinkBackend");
    registry
}

// ── Exit code logic ───────────────────────────────────────────────────────────

/// Map `ApplyReport` + `ConflictReport` to an exit code.
///
/// - `2`: total failure (no operations succeeded, at least one failed)
/// - `1`: partial failure or conflicts detected
/// - `0`: all operations succeeded, no conflicts
fn determine_exit_code(report: &ApplyReport, conflicts: &ConflictReport) -> ExitCode {
    if report.is_total_failure() {
        ExitCode::from(2u8)
    } else if report.is_partial() || !conflicts.is_empty() {
        ExitCode::from(1u8)
    } else {
        ExitCode::SUCCESS
    }
}

/// Map `VarlinkApplyReport` to an exit code for daemon mode.
fn daemon_exit_code(report: &VarlinkApplyReport) -> ExitCode {
    if report.failed > 0 && report.succeeded == 0 {
        ExitCode::from(2u8)
    } else if report.failed > 0 || !report.conflicts.is_empty() {
        ExitCode::from(1u8)
    } else {
        ExitCode::SUCCESS
    }
}

// ── Display: daemon-free apply ────────────────────────────────────────────────

/// Print conflict warnings to stderr.
fn print_conflicts(conflicts: &ConflictReport) {
    let n = conflicts.len();
    let word = if n == 1 { "conflict" } else { "conflicts" };
    eprintln!(
        "{}",
        format!(
            "Warning: {} field {} detected. Conflicting fields were not applied.",
            n, word
        )
        .yellow()
    );
    for c in &conflicts.conflicts {
        let (entity_type, entity_name) = &c.entity_key;
        let policies: Vec<String> = c
            .contributions
            .iter()
            .map(|cc| format!("policy \"{}\" sets {}", cc.policy_id, cc.value.value))
            .collect();
        let priority_note = if c.contributions.len() == 2 {
            format!("(both priority {})", c.priority)
        } else {
            format!("(all priority {})", c.priority)
        };
        eprintln!(
            "  {} {} {}: {} {}",
            entity_type,
            entity_name,
            c.field_name,
            policies.join(", "),
            priority_note
        );
    }
}

/// Display the result of a dry-run (daemon-free mode).
fn display_dry_run_report(report: &DiffReport, is_empty: bool) {
    if is_empty {
        println!("No changes needed (dry run).");
        return;
    }
    let n = report.operations.len();
    let word = if n == 1 { "change" } else { "changes" };
    println!(
        "{}",
        format!("Dry run: {} {} would be applied.", n, word).yellow()
    );
    let text = report.format_text();
    if !text.is_empty() {
        // Indent the diff text for readability.
        for line in text.lines() {
            let colored = if line.starts_with('+') {
                format!("  {}", line).green().to_string()
            } else if line.starts_with('-') {
                format!("  {}", line).red().to_string()
            } else if line.starts_with('~') {
                format!("  {}", line).yellow().to_string()
            } else {
                format!("  {}", line)
            };
            println!("{}", colored);
        }
    }
}

/// Display the result of an apply operation (daemon-free mode).
pub fn display_apply_report(report: &ApplyReport, conflicts: &ConflictReport) {
    // Conflicts first.
    if !conflicts.is_empty() {
        print_conflicts(conflicts);
    }

    // Per-operation lines.
    for op in &report.succeeded {
        let prefix = match op.operation {
            DiffOpKind::Add => "+".green().to_string(),
            DiffOpKind::Modify => "~".yellow().to_string(),
            DiffOpKind::Remove => "-".red().to_string(),
        };
        let fields = if op.fields_changed.is_empty() {
            String::new()
        } else {
            format!(": {}", op.fields_changed.join(", "))
        };
        println!("  {} {} {}{}", prefix, op.entity_type, op.selector.key(), fields);
    }
    for op in &report.failed {
        println!(
            "  {} {} {}: {}",
            "x".red(),
            op.entity_type,
            op.selector.key(),
            op.error
        );
    }
    for op in &report.skipped {
        println!(
            "  {} {} {}: {}",
            "s".dimmed(),
            op.entity_type,
            op.selector.key(),
            op.reason
        );
    }

    // Summary line.
    let succeeded = report.succeeded.len();
    let failed = report.failed.len();
    let total = succeeded + failed + report.skipped.len();

    if failed == 0 && succeeded == 0 {
        // Nothing happened (all skipped or empty).
        return;
    }

    if failed == 0 {
        let added = report
            .succeeded
            .iter()
            .filter(|op| op.operation == DiffOpKind::Add)
            .count();
        let modified = report
            .succeeded
            .iter()
            .filter(|op| op.operation == DiffOpKind::Modify)
            .count();
        let removed = report
            .succeeded
            .iter()
            .filter(|op| op.operation == DiffOpKind::Remove)
            .count();

        let mut parts = Vec::new();
        if added > 0 {
            parts.push(format!("{} added", added));
        }
        if modified > 0 {
            parts.push(format!("{} modified", modified));
        }
        if removed > 0 {
            parts.push(format!("{} removed", removed));
        }

        let suffix = if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
        };
        println!("{}", format!("Applied {} changes{}.", succeeded, suffix).green());
    } else if succeeded > 0 {
        println!(
            "{}",
            format!("Applied {} of {} changes. {} failed.", succeeded, total, failed).yellow()
        );
    } else {
        println!(
            "{}",
            format!("All {} changes failed.", failed).red()
        );
    }
}

// ── Display: daemon mode ──────────────────────────────────────────────────────

/// Display the result of a daemon-mode apply.
fn display_varlink_apply_report(report: &VarlinkApplyReport, policy_count: usize) {
    // Conflict warnings first.
    if !report.conflicts.is_empty() {
        let n = report.conflicts.len();
        let word = if n == 1 { "conflict" } else { "conflicts" };
        eprintln!(
            "{}",
            format!(
                "Warning: {} field {} detected. Conflicting fields were not applied.",
                n, word
            )
            .yellow()
        );
        for c in &report.conflicts {
            eprintln!(
                "  {} {} {}: {:?} -> {:?}",
                c.entity_type, c.entity_name, c.field_name, c.policies, c.values
            );
        }
    }

    // Per-change lines.
    for entry in &report.changes {
        let (prefix, colored_line) = match entry.status.as_str() {
            "applied" => {
                let prefix = match entry.kind.as_str() {
                    "add" => "+".green().to_string(),
                    "modify" => "~".yellow().to_string(),
                    "remove" => "-".red().to_string(),
                    _ => "?".normal().to_string(),
                };
                let line = format!(
                    "  {} {} {}: {}",
                    prefix, entry.entity_type, entry.entity_name, entry.description
                );
                (prefix, line)
            }
            "failed" => {
                let prefix = "x".red().to_string();
                let line = format!(
                    "  {} {} {}: {}",
                    prefix, entry.entity_type, entry.entity_name, entry.description
                );
                (prefix, line)
            }
            "skipped" => {
                let prefix = "s".dimmed().to_string();
                let line = format!(
                    "  {} {} {}: {}",
                    prefix, entry.entity_type, entry.entity_name, entry.description
                );
                (prefix, line)
            }
            _ => {
                let prefix = "?".normal().to_string();
                let line = format!(
                    "  {} {} {}",
                    prefix, entry.entity_type, entry.entity_name
                );
                (prefix, line)
            }
        };
        let _ = prefix; // suppress unused warning if colored_line already contains it
        println!("{}", colored_line);
    }

    // Summary line.
    let policy_word = if policy_count == 1 { "policy" } else { "policies" };
    let succeeded = report.succeeded;
    let failed = report.failed;

    if failed == 0 {
        println!(
            "{}",
            format!(
                "Submitted {} {} to daemon. Applied {} changes.",
                policy_count, policy_word, succeeded
            )
            .green()
        );
    } else if succeeded > 0 {
        println!(
            "{}",
            format!(
                "Submitted {} {} to daemon. Applied {} of {} changes. {} failed.",
                policy_count,
                policy_word,
                succeeded,
                succeeded + failed,
                failed
            )
            .yellow()
        );
    } else {
        println!(
            "{}",
            format!(
                "Submitted {} {} to daemon. All {} changes failed.",
                policy_count, policy_word, failed
            )
            .red()
        );
    }
}

/// Display the result of a daemon-mode dry-run.
fn display_varlink_diff(diff: &VarlinkStateDiff, is_empty: bool) {
    if is_empty {
        println!("No changes needed (dry run).");
        return;
    }

    let n = diff.operations.len();
    let word = if n == 1 { "change" } else { "changes" };
    println!(
        "{}",
        format!("Dry run: {} {} would be applied.", n, word).yellow()
    );

    for op in &diff.operations {
        let (prefix, header) = match op.kind.as_str() {
            "add" => (
                "+".green().to_string(),
                format!("+ {} {}", op.entity_type, op.entity_name),
            ),
            "remove" => (
                "-".red().to_string(),
                format!("- {} {}", op.entity_type, op.entity_name),
            ),
            _ => (
                "~".yellow().to_string(),
                format!("~ {} {}", op.entity_type, op.entity_name),
            ),
        };
        let _ = prefix; // already embedded in the header string
        let colored_header = if op.kind == "add" {
            header.green().to_string()
        } else if op.kind == "remove" {
            header.red().to_string()
        } else {
            header.yellow().to_string()
        };
        println!("  {}", colored_header);

        for fc in &op.field_changes {
            match fc.change_kind.as_str() {
                "set" => {
                    if let Some(current) = &fc.current {
                        let line = format!(
                            "~   {}: {} \u{2192} {}",
                            fc.field_name,
                            current,
                            fc.desired.as_ref().map(|v| v.to_string()).unwrap_or_default()
                        );
                        println!("  {}", line.yellow());
                    } else {
                        let line = format!(
                            "+   {}: {}",
                            fc.field_name,
                            fc.desired.as_ref().map(|v| v.to_string()).unwrap_or_default()
                        );
                        println!("  {}", line.green());
                    }
                }
                "unset" => {
                    let line = format!(
                        "-   {}: {}",
                        fc.field_name,
                        fc.current.as_ref().map(|v| v.to_string()).unwrap_or_default()
                    );
                    println!("  {}", line.red());
                }
                "unchanged" => {
                    println!(
                        "      {}: {}",
                        fc.field_name,
                        fc.current.as_ref().map(|v| v.to_string()).unwrap_or_default()
                    );
                }
                _ => {}
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use netfyr_backend::{AppliedOperation, ApplyReport, BackendError, DiffOpKind, FailedOperation};
    use netfyr_reconcile::{Conflict, ConflictReport};
    use netfyr_state::Selector;
    use netfyr_varlink::{VarlinkApplyReport, VarlinkConflictEntry};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_applied(entity_type: &str, name: &str) -> AppliedOperation {
        AppliedOperation {
            operation: DiffOpKind::Modify,
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            fields_changed: vec!["mtu".to_string()],
        }
    }

    fn make_failed(entity_type: &str, name: &str) -> FailedOperation {
        FailedOperation {
            operation: DiffOpKind::Modify,
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            error: BackendError::Internal("interface not found".to_string()),
            fields: vec!["mtu".to_string()],
        }
    }

    fn empty_conflict_report() -> ConflictReport {
        ConflictReport::new()
    }

    fn conflict_report_with_one() -> ConflictReport {
        ConflictReport {
            conflicts: vec![Conflict {
                entity_key: ("ethernet".to_string(), "eth0".to_string()),
                field_name: "mtu".to_string(),
                priority: 100,
                contributions: vec![],
            }],
        }
    }

    fn varlink_report(succeeded: i64, failed: i64, conflict_count: usize) -> VarlinkApplyReport {
        VarlinkApplyReport {
            succeeded,
            failed,
            skipped: 0,
            changes: vec![],
            conflicts: (0..conflict_count)
                .map(|i| VarlinkConflictEntry {
                    entity_type: "ethernet".to_string(),
                    entity_name: format!("eth{}", i),
                    field_name: "mtu".to_string(),
                    policies: vec!["policy-a".to_string(), "policy-b".to_string()],
                    values: vec!["1500".to_string(), "9000".to_string()],
                })
                .collect(),
        }
    }

    // ── determine_exit_code tests ─────────────────────────────────────────────

    /// AC: exit code 0 when all operations succeed with no conflicts.
    #[test]
    fn test_determine_exit_code_all_succeeded_no_conflicts_returns_exit_0() {
        let mut report = ApplyReport::new();
        report.succeeded.push(make_applied("ethernet", "eth0"));
        let conflicts = empty_conflict_report();
        assert_eq!(
            determine_exit_code(&report, &conflicts),
            ExitCode::SUCCESS,
            "all succeeded, no conflicts must return exit 0"
        );
    }

    /// AC: exit code 1 when some operations succeed and some fail (partial failure).
    #[test]
    fn test_determine_exit_code_partial_failure_returns_exit_1() {
        let mut report = ApplyReport::new();
        report.succeeded.push(make_applied("ethernet", "eth0"));
        report.failed.push(make_failed("ethernet", "eth99"));
        let conflicts = empty_conflict_report();
        assert_eq!(
            determine_exit_code(&report, &conflicts),
            ExitCode::from(1u8),
            "partial failure (some succeeded, some failed) must return exit 1"
        );
    }

    /// AC: exit code 2 when all operations fail (total failure).
    #[test]
    fn test_determine_exit_code_total_failure_returns_exit_2() {
        let mut report = ApplyReport::new();
        report.failed.push(make_failed("ethernet", "eth99"));
        let conflicts = empty_conflict_report();
        assert_eq!(
            determine_exit_code(&report, &conflicts),
            ExitCode::from(2u8),
            "total failure (no succeeded, at least one failed) must return exit 2"
        );
    }

    /// AC: exit code 1 when conflicts are detected even if all applicable changes succeeded.
    #[test]
    fn test_determine_exit_code_conflicts_but_no_failures_returns_exit_1() {
        let mut report = ApplyReport::new();
        report.succeeded.push(make_applied("ethernet", "eth0"));
        let conflicts = conflict_report_with_one();
        assert_eq!(
            determine_exit_code(&report, &conflicts),
            ExitCode::from(1u8),
            "conflicts detected must cause exit 1 even when no apply failures"
        );
    }

    /// Edge: empty report with no conflicts exits 0 (no-op is success).
    #[test]
    fn test_determine_exit_code_empty_report_no_conflicts_returns_exit_0() {
        let report = ApplyReport::new();
        let conflicts = empty_conflict_report();
        assert_eq!(
            determine_exit_code(&report, &conflicts),
            ExitCode::SUCCESS,
            "empty report with no conflicts is treated as success"
        );
    }

    /// Edge: conflicts alone (no failures) produce exit 1, not exit 2.
    #[test]
    fn test_determine_exit_code_only_conflicts_no_failures_returns_exit_1_not_2() {
        let report = ApplyReport::new();
        let conflicts = conflict_report_with_one();
        // is_total_failure() is false (no failures at all), so we get exit 1
        assert_eq!(
            determine_exit_code(&report, &conflicts),
            ExitCode::from(1u8),
            "conflicts alone produce exit 1, not exit 2"
        );
    }

    // ── daemon_exit_code tests ────────────────────────────────────────────────

    /// AC: daemon mode exit 0 when all changes applied, no conflicts.
    #[test]
    fn test_daemon_exit_code_all_succeeded_no_conflicts_returns_exit_0() {
        let report = varlink_report(3, 0, 0);
        assert_eq!(
            daemon_exit_code(&report),
            ExitCode::SUCCESS,
            "daemon mode: all succeeded, no conflicts must return exit 0"
        );
    }

    /// AC: daemon mode exit 0 when zero changes and no conflicts (already in desired state).
    #[test]
    fn test_daemon_exit_code_zero_changes_no_conflicts_returns_exit_0() {
        let report = varlink_report(0, 0, 0);
        assert_eq!(
            daemon_exit_code(&report),
            ExitCode::SUCCESS,
            "daemon mode: zero changes and no failures must return exit 0"
        );
    }

    /// AC: daemon mode exit 1 when some operations failed but some succeeded (partial).
    #[test]
    fn test_daemon_exit_code_partial_failure_returns_exit_1() {
        let report = varlink_report(2, 1, 0);
        assert_eq!(
            daemon_exit_code(&report),
            ExitCode::from(1u8),
            "daemon mode partial failure must return exit 1"
        );
    }

    /// AC: daemon mode exit 2 when all operations failed.
    #[test]
    fn test_daemon_exit_code_total_failure_returns_exit_2() {
        let report = varlink_report(0, 1, 0);
        assert_eq!(
            daemon_exit_code(&report),
            ExitCode::from(2u8),
            "daemon mode total failure must return exit 2"
        );
    }

    /// AC: daemon mode exit 1 when conflicts detected even if all changes applied.
    #[test]
    fn test_daemon_exit_code_conflicts_present_returns_exit_1() {
        let report = varlink_report(2, 0, 1);
        assert_eq!(
            daemon_exit_code(&report),
            ExitCode::from(1u8),
            "daemon mode: conflicts present must return exit 1"
        );
    }

    /// Edge: daemon mode with both failures and conflicts still returns exit 1 (partial).
    #[test]
    fn test_daemon_exit_code_partial_failure_with_conflicts_returns_exit_1() {
        let report = varlink_report(1, 1, 1);
        assert_eq!(
            daemon_exit_code(&report),
            ExitCode::from(1u8),
            "daemon mode partial failure with conflicts must return exit 1"
        );
    }
}
