//! Report types for apply and dry-run operations.

use std::fmt;

use netfyr_state::{DiffOp, EntityType, Selector, Value};

use crate::BackendError;

// ── DiffOpKind ────────────────────────────────────────────────────────────────

/// Lightweight operation kind for report structs — carries the discriminant of a
/// `DiffOp` without the associated field data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOpKind {
    Add,
    Modify,
    Remove,
}

impl fmt::Display for DiffOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffOpKind::Add => write!(f, "add"),
            DiffOpKind::Modify => write!(f, "modify"),
            DiffOpKind::Remove => write!(f, "remove"),
        }
    }
}

impl From<&DiffOp> for DiffOpKind {
    fn from(op: &DiffOp) -> Self {
        match op {
            DiffOp::Add { .. } => DiffOpKind::Add,
            DiffOp::Modify { .. } => DiffOpKind::Modify,
            DiffOp::Remove { .. } => DiffOpKind::Remove,
        }
    }
}

// ── ApplyReport and friends ───────────────────────────────────────────────────

/// An operation that completed successfully during an apply.
#[derive(Debug)]
pub struct AppliedOperation {
    pub operation: DiffOpKind,
    pub entity_type: EntityType,
    pub selector: Selector,
    /// Names of fields that were created, updated, or removed.
    pub fields_changed: Vec<String>,
}

/// An operation that failed during an apply.
#[derive(Debug)]
pub struct FailedOperation {
    pub operation: DiffOpKind,
    pub entity_type: EntityType,
    pub selector: Selector,
    pub error: BackendError,
    /// Names of the fields involved in the failed operation.
    pub fields: Vec<String>,
}

/// An operation that was skipped during an apply (e.g., already in desired state
/// or a dependency failed).
#[derive(Debug)]
pub struct SkippedOperation {
    pub operation: DiffOpKind,
    pub entity_type: EntityType,
    pub selector: Selector,
    /// Human-readable explanation of why the operation was skipped.
    pub reason: String,
}

/// The outcome of an `apply` call: categorises every operation as succeeded,
/// failed, or skipped.
#[derive(Debug, Default)]
pub struct ApplyReport {
    pub succeeded: Vec<AppliedOperation>,
    pub failed: Vec<FailedOperation>,
    pub skipped: Vec<SkippedOperation>,
}

impl ApplyReport {
    /// Returns an empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when no operations failed (succeeded and skipped are irrelevant).
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// Returns `true` when at least one operation succeeded AND at least one failed.
    /// Skipped operations do not affect this check.
    pub fn is_partial(&self) -> bool {
        !self.succeeded.is_empty() && !self.failed.is_empty()
    }

    /// Returns `true` when no operations succeeded and at least one failed.
    pub fn is_total_failure(&self) -> bool {
        self.succeeded.is_empty() && !self.failed.is_empty()
    }

    /// Returns a human-readable summary: `"{n} succeeded, {n} failed, {n} skipped"`.
    pub fn summary(&self) -> String {
        format!(
            "{} succeeded, {} failed, {} skipped",
            self.succeeded.len(),
            self.failed.len(),
            self.skipped.len(),
        )
    }

    /// Merges `other` into `self` by appending its vectors. Used by `BackendRegistry`
    /// to combine per-backend reports into a single flat report.
    pub fn merge(&mut self, other: ApplyReport) {
        self.succeeded.extend(other.succeeded);
        self.failed.extend(other.failed);
        self.skipped.extend(other.skipped);
    }
}

// ── DryRunReport and friends ──────────────────────────────────────────────────

/// How a single field would change in a planned operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldChangeKind {
    /// Field does not currently exist and will be created.
    Set,
    /// Field currently exists and will be removed.
    Unset,
    /// Field currently exists and its value will be updated.
    Modify,
}

/// The planned change for a single field within a `PlannedChange`.
#[derive(Debug, Clone)]
pub struct FieldChange {
    pub field: String,
    /// Current value on the system (`None` for `Set` kind).
    pub current: Option<Value>,
    /// Desired value after the change (`None` for `Unset` kind).
    pub desired: Option<Value>,
    pub kind: FieldChangeKind,
}

/// A single planned entity-level operation in a dry-run report.
#[derive(Debug)]
pub struct PlannedChange {
    pub operation: DiffOpKind,
    pub entity_type: EntityType,
    pub selector: Selector,
    pub field_changes: Vec<FieldChange>,
}

/// The outcome of a `dry_run` call: lists every change that would be made
/// without touching system state.
#[derive(Debug, Default)]
pub struct DryRunReport {
    pub changes: Vec<PlannedChange>,
    /// Operations that would be skipped (e.g., interface not found).
    pub skipped: Vec<SkippedOperation>,
}

impl DryRunReport {
    /// Returns an empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when there are no changes and no skipped operations.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.skipped.is_empty()
    }

    /// Returns a human-readable summary with per-kind breakdown.
    pub fn summary(&self) -> String {
        if self.changes.is_empty() && self.skipped.is_empty() {
            return "no changes".to_string();
        }
        let added = self
            .changes
            .iter()
            .filter(|c| c.operation == DiffOpKind::Add)
            .count();
        let modified = self
            .changes
            .iter()
            .filter(|c| c.operation == DiffOpKind::Modify)
            .count();
        let removed = self
            .changes
            .iter()
            .filter(|c| c.operation == DiffOpKind::Remove)
            .count();
        let mut s = format!(
            "{} changes planned ({} add, {} modify, {} remove)",
            self.changes.len(),
            added,
            modified,
            removed,
        );
        if !self.skipped.is_empty() {
            s.push_str(&format!(", {} skipped", self.skipped.len()));
        }
        s
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use netfyr_state::{DiffOp, Selector, Value};

    use crate::BackendError;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_applied(entity_type: &str, name: &str, op: DiffOpKind) -> AppliedOperation {
        AppliedOperation {
            operation: op,
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            fields_changed: vec!["mtu".to_string()],
        }
    }

    fn make_failed(entity_type: &str, name: &str, op: DiffOpKind) -> FailedOperation {
        FailedOperation {
            operation: op,
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            error: BackendError::Internal("test error".to_string()),
            fields: vec!["mtu".to_string()],
        }
    }

    fn make_skipped(entity_type: &str, name: &str, op: DiffOpKind, reason: &str) -> SkippedOperation {
        SkippedOperation {
            operation: op,
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            reason: reason.to_string(),
        }
    }

    // ── DiffOpKind ────────────────────────────────────────────────────────────

    /// Scenario: DiffOpKind Display produces lowercase operation names
    #[test]
    fn test_diff_op_kind_display_add() {
        assert_eq!(DiffOpKind::Add.to_string(), "add");
    }

    #[test]
    fn test_diff_op_kind_display_modify() {
        assert_eq!(DiffOpKind::Modify.to_string(), "modify");
    }

    #[test]
    fn test_diff_op_kind_display_remove() {
        assert_eq!(DiffOpKind::Remove.to_string(), "remove");
    }

    /// DiffOpKind converts from DiffOp::Add
    #[test]
    fn test_diff_op_kind_from_diff_op_add() {
        let op = DiffOp::Add {
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth0"),
            fields: IndexMap::new(),
        };
        assert_eq!(DiffOpKind::from(&op), DiffOpKind::Add);
    }

    /// DiffOpKind converts from DiffOp::Modify
    #[test]
    fn test_diff_op_kind_from_diff_op_modify() {
        let op = DiffOp::Modify {
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth0"),
            changed_fields: IndexMap::new(),
            removed_fields: vec![],
        };
        assert_eq!(DiffOpKind::from(&op), DiffOpKind::Modify);
    }

    /// DiffOpKind converts from DiffOp::Remove
    #[test]
    fn test_diff_op_kind_from_diff_op_remove() {
        let op = DiffOp::Remove {
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth0"),
        };
        assert_eq!(DiffOpKind::from(&op), DiffOpKind::Remove);
    }

    // ── ApplyReport helpers ───────────────────────────────────────────────────

    /// Scenario: ApplyReport::new() produces an empty report
    #[test]
    fn test_apply_report_new_is_empty() {
        let r = ApplyReport::new();
        assert!(r.succeeded.is_empty());
        assert!(r.failed.is_empty());
        assert!(r.skipped.is_empty());
    }

    /// Scenario: ApplyReport with all operations successful — is_success true, others false
    #[test]
    fn test_apply_report_is_success_when_no_failures() {
        let mut r = ApplyReport::new();
        r.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));

        assert!(r.is_success(), "is_success must be true when failed is empty");
        assert!(!r.is_partial(), "is_partial must be false when failed is empty");
        assert!(!r.is_total_failure(), "is_total_failure must be false when succeeded is non-empty");
    }

    /// is_success returns true when succeeded and skipped are non-empty but failed is empty
    #[test]
    fn test_apply_report_is_success_with_skipped_but_no_failures() {
        let mut r = ApplyReport::new();
        r.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));
        r.skipped.push(make_skipped("ethernet", "eth1", DiffOpKind::Modify, "already in desired state"));

        assert!(r.is_success(), "skipped operations do not affect is_success");
    }

    /// Scenario: ApplyReport with all operations failed — is_total_failure true, is_success false
    #[test]
    fn test_apply_report_is_total_failure_when_all_fail() {
        let mut r = ApplyReport::new();
        r.failed.push(make_failed("ethernet", "eth0", DiffOpKind::Add));

        assert!(r.is_total_failure(), "is_total_failure must be true when succeeded is empty and failed is non-empty");
        assert!(!r.is_success(), "is_success must be false when there are failures");
    }

    /// Scenario: ApplyReport with partial results — is_partial true
    #[test]
    fn test_apply_report_is_partial_when_some_succeed_and_some_fail() {
        let mut r = ApplyReport::new();
        r.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));
        r.failed.push(make_failed("ethernet", "eth1", DiffOpKind::Modify));

        assert!(r.is_partial(), "is_partial must be true when at least one succeeded and one failed");
        assert!(!r.is_success(), "is_success must be false when there are failures");
        assert!(!r.is_total_failure(), "is_total_failure must be false when some succeeded");
    }

    /// is_partial returns false when only succeeded (no failures)
    #[test]
    fn test_apply_report_is_partial_false_when_only_succeeded() {
        let mut r = ApplyReport::new();
        r.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));

        assert!(!r.is_partial());
    }

    /// is_partial returns false when only failed (no successes)
    #[test]
    fn test_apply_report_is_partial_false_when_only_failed() {
        let mut r = ApplyReport::new();
        r.failed.push(make_failed("ethernet", "eth0", DiffOpKind::Add));

        assert!(!r.is_partial());
    }

    /// is_partial treats skipped as neither success nor failure
    #[test]
    fn test_apply_report_is_partial_ignores_skipped() {
        let mut r = ApplyReport::new();
        r.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));
        r.skipped.push(make_skipped("ethernet", "eth1", DiffOpKind::Remove, "already absent"));

        assert!(!r.is_partial(), "skipped alone with succeeded must not trigger is_partial");
    }

    /// Scenario: ApplyReport::summary returns "{n} succeeded, {n} failed, {n} skipped"
    #[test]
    fn test_apply_report_summary_format() {
        let mut r = ApplyReport::new();
        r.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));
        r.succeeded.push(make_applied("ethernet", "eth1", DiffOpKind::Add));
        r.failed.push(make_failed("ethernet", "eth2", DiffOpKind::Modify));
        r.skipped.push(make_skipped("ethernet", "eth3", DiffOpKind::Remove, "skipped"));

        assert_eq!(r.summary(), "2 succeeded, 1 failed, 1 skipped");
    }

    /// summary for an all-empty report
    #[test]
    fn test_apply_report_summary_all_zeros() {
        let r = ApplyReport::new();
        assert_eq!(r.summary(), "0 succeeded, 0 failed, 0 skipped");
    }

    /// ApplyReport::merge appends the other report's vectors into self
    #[test]
    fn test_apply_report_merge_combines_reports() {
        let mut a = ApplyReport::new();
        a.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));

        let mut b = ApplyReport::new();
        b.failed.push(make_failed("ethernet", "eth1", DiffOpKind::Modify));
        b.skipped.push(make_skipped("ethernet", "eth2", DiffOpKind::Remove, "reason"));

        a.merge(b);

        assert_eq!(a.succeeded.len(), 1);
        assert_eq!(a.failed.len(), 1);
        assert_eq!(a.skipped.len(), 1);
    }

    /// merge into empty report yields the same counts as the source
    #[test]
    fn test_apply_report_merge_into_empty() {
        let mut a = ApplyReport::new();

        let mut b = ApplyReport::new();
        b.succeeded.push(make_applied("ethernet", "eth0", DiffOpKind::Add));
        b.succeeded.push(make_applied("ethernet", "eth1", DiffOpKind::Remove));

        a.merge(b);
        assert_eq!(a.succeeded.len(), 2);
        assert_eq!(a.failed.len(), 0);
        assert_eq!(a.skipped.len(), 0);
    }

    // ── DryRunReport helpers ──────────────────────────────────────────────────

    /// DryRunReport::new() returns an empty report
    #[test]
    fn test_dry_run_report_new_is_empty() {
        let r = DryRunReport::new();
        assert!(r.is_empty());
        assert!(r.changes.is_empty());
    }

    /// is_empty returns false when changes are present
    #[test]
    fn test_dry_run_report_is_not_empty_when_changes_exist() {
        let mut r = DryRunReport::new();
        r.changes.push(PlannedChange {
            operation: DiffOpKind::Add,
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth0"),
            field_changes: vec![],
        });
        assert!(!r.is_empty());
    }

    /// summary returns "no changes" for empty report
    #[test]
    fn test_dry_run_report_summary_empty_is_no_changes() {
        let r = DryRunReport::new();
        assert_eq!(r.summary(), "no changes");
    }

    /// summary includes counts of each op kind
    #[test]
    fn test_dry_run_report_summary_with_changes() {
        let mut r = DryRunReport::new();
        r.changes.push(PlannedChange {
            operation: DiffOpKind::Add,
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth0"),
            field_changes: vec![],
        });
        r.changes.push(PlannedChange {
            operation: DiffOpKind::Modify,
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth1"),
            field_changes: vec![],
        });
        r.changes.push(PlannedChange {
            operation: DiffOpKind::Remove,
            entity_type: "ethernet".to_string(),
            selector: Selector::with_name("eth2"),
            field_changes: vec![],
        });

        let summary = r.summary();
        assert!(
            summary.contains("3 changes planned"),
            "summary should mention total count, got: {summary}"
        );
        assert!(summary.contains("1 add"), "got: {summary}");
        assert!(summary.contains("1 modify"), "got: {summary}");
        assert!(summary.contains("1 remove"), "got: {summary}");
    }

    // ── FieldChange ───────────────────────────────────────────────────────────

    /// FieldChange stores field name, current, desired, and kind
    #[test]
    fn test_field_change_stores_before_and_after_values() {
        let fc = FieldChange {
            field: "mtu".to_string(),
            current: Some(Value::U64(1500)),
            desired: Some(Value::U64(9000)),
            kind: FieldChangeKind::Modify,
        };
        assert_eq!(fc.field, "mtu");
        assert_eq!(fc.current, Some(Value::U64(1500)));
        assert_eq!(fc.desired, Some(Value::U64(9000)));
        assert_eq!(fc.kind, FieldChangeKind::Modify);
    }

    /// FieldChange with Set kind has no current value
    #[test]
    fn test_field_change_set_kind_has_no_current() {
        let fc = FieldChange {
            field: "speed".to_string(),
            current: None,
            desired: Some(Value::U64(1000)),
            kind: FieldChangeKind::Set,
        };
        assert!(fc.current.is_none());
        assert!(fc.desired.is_some());
        assert_eq!(fc.kind, FieldChangeKind::Set);
    }

    /// FieldChange with Unset kind has no desired value
    #[test]
    fn test_field_change_unset_kind_has_no_desired() {
        let fc = FieldChange {
            field: "speed".to_string(),
            current: Some(Value::U64(1000)),
            desired: None,
            kind: FieldChangeKind::Unset,
        };
        assert!(fc.current.is_some());
        assert!(fc.desired.is_none());
        assert_eq!(fc.kind, FieldChangeKind::Unset);
    }

    /// FieldChange is Clone
    #[test]
    fn test_field_change_clone() {
        let fc = FieldChange {
            field: "mtu".to_string(),
            current: Some(Value::U64(1500)),
            desired: Some(Value::U64(9000)),
            kind: FieldChangeKind::Modify,
        };
        let cloned = fc.clone();
        assert_eq!(fc.field, cloned.field);
        assert_eq!(fc.current, cloned.current);
        assert_eq!(fc.desired, cloned.desired);
        assert_eq!(fc.kind, cloned.kind);
    }
}
