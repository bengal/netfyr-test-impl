//! Diff generation between desired and actual state.
//!
//! [`generate_diff`] compares a desired [`StateSet`] (from reconciliation) against
//! an actual [`StateSet`] (from backend query) and produces a rich [`StateDiff`]
//! describing per-entity, per-field changes. This is richer than `netfyr_state::StateDiff`
//! because it carries old values, new values, and unchanged fields — information
//! needed for meaningful dry-run output.
//!
//! **Read-only field handling**: Fields marked `writable: false` in the
//! [`SchemaRegistry`] that appear in actual state but not in desired state are
//! silently excluded from Modify operations. For entity types not registered in
//! the schema, all fields are conservatively treated as writable.

use netfyr_state::{FieldValue, SchemaRegistry, Selector, StateSet};
use serde::Serialize;

use crate::FieldName;

// ── EntityType alias ──────────────────────────────────────────────────────────

/// A string identifying a category of network entity (e.g., `"ethernet"`, `"bond"`).
///
/// Mirrors `netfyr_state::EntityType` without a cross-crate re-export dependency.
pub type EntityType = String;

// ── DiffKind ──────────────────────────────────────────────────────────────────

/// The kind of change represented by a [`DiffOperation`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DiffKind {
    /// Entity exists in desired state but not in actual state.
    Add,
    /// Entity exists in actual state but not in desired state.
    Remove,
    /// Entity exists in both, with at least one field differing.
    Modify,
}

// ── FieldChangeKind ───────────────────────────────────────────────────────────

/// The nature of a field's change within a [`DiffOperation`].
#[derive(Clone, Debug, Serialize)]
pub enum FieldChangeKind {
    /// Field is being set (added or changed).
    ///
    /// - `current: None` — field did not exist in actual state (new field).
    /// - `current: Some(old)` — field existed but with a different value.
    Set {
        current: Option<FieldValue>,
        desired: FieldValue,
    },
    /// Field is being removed (present in actual, absent in desired).
    Unset { current: FieldValue },
    /// Field value is identical in both states.
    ///
    /// Included only in [`DiffKind::Modify`] operations to provide context in
    /// reports. Not used in Add or Remove operations.
    Unchanged { value: FieldValue },
}

// ── FieldChange ───────────────────────────────────────────────────────────────

/// A field-level change within a single entity operation.
#[derive(Clone, Debug, Serialize)]
pub struct FieldChange {
    pub field_name: FieldName,
    pub change: FieldChangeKind,
}

// ── DiffOperation ─────────────────────────────────────────────────────────────

/// A single entity-level operation in a [`StateDiff`].
#[derive(Clone, Debug, Serialize)]
pub struct DiffOperation {
    pub kind: DiffKind,
    pub entity_type: EntityType,
    pub selector: Selector,
    pub field_changes: Vec<FieldChange>,
}

// ── StateDiff ─────────────────────────────────────────────────────────────────

/// The result of comparing desired state against actual state.
///
/// Contains per-entity operations (Add, Remove, Modify) each with per-field
/// change detail. Entities with identical fields in both states produce no
/// operation and do not appear here.
///
/// This type carries more detail than `netfyr_state::StateDiff` (which is
/// lean and apply-oriented). The two types serve different layers and can be
/// disambiguated with `use netfyr_state::StateDiff as BackendDiff` if both
/// are needed in the same scope.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StateDiff {
    pub operations: Vec<DiffOperation>,
}

impl StateDiff {
    /// Returns `true` if there are no operations (states are identical).
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Returns the total number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Iterates over Add operations (entities in desired, absent from actual).
    pub fn additions(&self) -> impl Iterator<Item = &DiffOperation> {
        self.operations.iter().filter(|op| op.kind == DiffKind::Add)
    }

    /// Iterates over Remove operations (entities in actual, absent from desired).
    pub fn removals(&self) -> impl Iterator<Item = &DiffOperation> {
        self.operations.iter().filter(|op| op.kind == DiffKind::Remove)
    }

    /// Iterates over Modify operations (entities in both with differing fields).
    pub fn modifications(&self) -> impl Iterator<Item = &DiffOperation> {
        self.operations.iter().filter(|op| op.kind == DiffKind::Modify)
    }
}

// ── generate_diff ─────────────────────────────────────────────────────────────

/// Generates a [`StateDiff`] by comparing `desired` state against `actual` state.
///
/// # Algorithm
///
/// **Pass 1** — iterates desired entities:
/// - Entity absent from actual → **Add** operation (all desired fields become `Set`).
/// - Entity present in both → compare per-field:
///   - Field in desired but not actual → `Set { current: None }`.
///   - Field in actual but not desired → `Unset`, unless the field is read-only
///     per the schema (in which case it is silently skipped).
///   - Field in both with different values → `Set { current: Some(old) }`.
///   - Field in both with same value → `Unchanged` (for context only).
///   - If any non-`Unchanged` changes exist → **Modify** operation.
///   - If all fields are `Unchanged` → no operation emitted.
///
/// **Pass 2** — iterates actual entities absent from desired → **Remove** operation
/// (all actual fields become `Unset`).
///
/// # Read-only field handling
///
/// Fields marked `x-netfyr-writable: false` in the [`SchemaRegistry`] (e.g.,
/// `carrier`, `speed`, `mac` on ethernet entities) that appear in actual state
/// but not in desired state are excluded from diff. This prevents spurious
/// Unset changes for informational fields the backend populates automatically.
///
/// For entity types without a registered schema, all fields are treated as
/// writable (conservative: may produce unnecessary Unset ops for truly read-only
/// fields, but will not miss real changes).
///
/// # Selector matching
///
/// Entities are matched by `EntityKey` = `(entity_type, selector.key())`.
/// Callers must ensure both StateSets use resolved (name-based) selectors.
/// If desired state uses driver-based selectors and actual state uses name-based
/// selectors, keys will not match and all entities will appear as Add+Remove.
pub fn generate_diff(desired: &StateSet, actual: &StateSet, schema: &SchemaRegistry) -> StateDiff {
    let mut operations = Vec::new();

    // ── Pass 1: iterate desired entities ─────────────────────────────────────
    for (entity_type, selector_key) in desired.entities() {
        let desired_state = desired.get(&entity_type, &selector_key).expect("key from entities()");

        if let Some(actual_state) = actual.get(&entity_type, &selector_key) {
            // Entity present in both — compare field by field.
            let mut field_changes: Vec<FieldChange> = Vec::new();
            let mut has_real_change = false;

            // Walk desired fields: compare against actual.
            for (field_name, desired_fv) in &desired_state.fields {
                if let Some(actual_fv) = actual_state.fields.get(field_name) {
                    if desired_fv.value == actual_fv.value {
                        // Same value — Unchanged (for context in reports).
                        field_changes.push(FieldChange {
                            field_name: field_name.clone(),
                            change: FieldChangeKind::Unchanged { value: desired_fv.clone() },
                        });
                    } else {
                        // Different values — field is being changed.
                        field_changes.push(FieldChange {
                            field_name: field_name.clone(),
                            change: FieldChangeKind::Set {
                                current: Some(actual_fv.clone()),
                                desired: desired_fv.clone(),
                            },
                        });
                        has_real_change = true;
                    }
                } else {
                    // Field in desired but not actual — field is being added.
                    field_changes.push(FieldChange {
                        field_name: field_name.clone(),
                        change: FieldChangeKind::Set { current: None, desired: desired_fv.clone() },
                    });
                    has_real_change = true;
                }
            }

            // Walk actual fields: any field not in desired is potentially Unset.
            for (field_name, actual_fv) in &actual_state.fields {
                if desired_state.fields.contains_key(field_name) {
                    // Already handled in the desired-fields walk above.
                    continue;
                }

                // Check whether this field is read-only per the schema.
                // If so, skip it — read-only fields are informational and not
                // part of the desired-state contract.
                let is_read_only = schema
                    .field_info(&entity_type, field_name)
                    .map(|info| !info.writable)
                    .unwrap_or(false); // unknown fields treated as writable

                if is_read_only {
                    continue;
                }

                field_changes.push(FieldChange {
                    field_name: field_name.clone(),
                    change: FieldChangeKind::Unset { current: actual_fv.clone() },
                });
                has_real_change = true;
            }

            if has_real_change {
                operations.push(DiffOperation {
                    kind: DiffKind::Modify,
                    entity_type: entity_type.clone(),
                    selector: desired_state.selector.clone(),
                    field_changes,
                });
            }
        } else {
            // Entity in desired but absent from actual → Add.
            let field_changes = desired_state
                .fields
                .iter()
                .map(|(name, fv)| FieldChange {
                    field_name: name.clone(),
                    change: FieldChangeKind::Set { current: None, desired: fv.clone() },
                })
                .collect();

            operations.push(DiffOperation {
                kind: DiffKind::Add,
                entity_type: entity_type.clone(),
                selector: desired_state.selector.clone(),
                field_changes,
            });
        }
    }

    // ── Pass 2: iterate actual entities absent from desired ───────────────────
    for (entity_type, selector_key) in actual.entities() {
        if desired.get(&entity_type, &selector_key).is_some() {
            // Already processed in Pass 1.
            continue;
        }

        let actual_state = actual.get(&entity_type, &selector_key).expect("key from entities()");
        let field_changes = actual_state
            .fields
            .iter()
            .map(|(name, fv)| FieldChange {
                field_name: name.clone(),
                change: FieldChangeKind::Unset { current: fv.clone() },
            })
            .collect();

        operations.push(DiffOperation {
            kind: DiffKind::Remove,
            entity_type: entity_type.clone(),
            selector: actual_state.selector.clone(),
            field_changes,
        });
    }

    StateDiff { operations }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use netfyr_state::{FieldValue, Provenance, SchemaRegistry, Selector, State, StateMetadata, StateSet, Value};

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn fv(v: Value) -> FieldValue {
        FieldValue { value: v, provenance: Provenance::KernelDefault }
    }

    fn make_state(entity_type: &str, name: &str, fields: Vec<(&str, Value)>) -> State {
        let mut s = State {
            entity_type: entity_type.to_string(),
            selector: Selector::with_name(name),
            fields: Default::default(),
            metadata: StateMetadata::new(),
            policy_ref: None,
            priority: 100,
        };
        for (k, v) in fields {
            s.fields.insert(k.to_string(), fv(v));
        }
        s
    }

    fn find_change<'a>(op: &'a DiffOperation, field: &str) -> Option<&'a FieldChangeKind> {
        op.field_changes.iter().find(|fc| fc.field_name == field).map(|fc| &fc.change)
    }

    fn addr_list(addrs: &[&str]) -> Value {
        Value::List(addrs.iter().map(|s| Value::String(s.to_string())).collect())
    }

    // ── Scenario: Entity in desired but not actual → Add ─────────────────────

    #[test]
    fn test_add_entity_in_desired_not_in_actual_generates_add_operation() {
        let mut desired = StateSet::new();
        desired.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let actual = StateSet::new();
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.len(), 1, "should have exactly one operation");
        let op = &diff.operations[0];
        assert_eq!(op.kind, DiffKind::Add, "operation kind must be Add");
        assert_eq!(op.entity_type, "ethernet");
        assert_eq!(op.selector.key(), "eth0");
    }

    #[test]
    fn test_add_operation_sets_all_fields_with_no_current_value() {
        let mut desired = StateSet::new();
        desired.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let actual = StateSet::new();
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);
        let op = &diff.operations[0];

        // mtu: Set(None → 1500)
        let mtu_change = find_change(op, "mtu").expect("mtu must have a change");
        match mtu_change {
            FieldChangeKind::Set { current: None, desired } => {
                assert_eq!(desired.value, Value::U64(1500));
            }
            other => panic!("Expected Set{{current: None, desired: 1500}}, got {:?}", other),
        }

        // addresses: Set(None → [...])
        let addr_change = find_change(op, "addresses").expect("addresses must have a change");
        assert!(
            matches!(addr_change, FieldChangeKind::Set { current: None, .. }),
            "addresses must be Set with current=None for Add operations"
        );
    }

    // ── Scenario: Entity in actual but not desired → Remove ──────────────────

    #[test]
    fn test_remove_entity_in_actual_not_in_desired_generates_remove_operation() {
        let desired = StateSet::new();
        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.len(), 1, "should have exactly one operation");
        let op = &diff.operations[0];
        assert_eq!(op.kind, DiffKind::Remove, "operation kind must be Remove");
        assert_eq!(op.entity_type, "ethernet");
        assert_eq!(op.selector.key(), "eth0");
    }

    #[test]
    fn test_remove_operation_unsets_all_fields_with_current_value() {
        let desired = StateSet::new();
        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);
        let op = &diff.operations[0];

        // mtu: Unset(1500)
        let mtu_change = find_change(op, "mtu").expect("mtu must have a change");
        match mtu_change {
            FieldChangeKind::Unset { current } => {
                assert_eq!(current.value, Value::U64(1500));
            }
            other => panic!("Expected Unset{{current: 1500}}, got {:?}", other),
        }

        // addresses: Unset(...)
        let addr_change = find_change(op, "addresses").expect("addresses must have a change");
        assert!(
            matches!(addr_change, FieldChangeKind::Unset { .. }),
            "addresses must be Unset in Remove operations"
        );
    }

    // ── Scenario: Entity in both with different field values → Modify ─────────

    #[test]
    fn test_modify_entity_with_different_mtu_generates_modify_operation() {
        let mut desired = StateSet::new();
        desired.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(9000)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.len(), 1, "should have exactly one operation");
        let op = &diff.operations[0];
        assert_eq!(op.kind, DiffKind::Modify, "operation kind must be Modify");
        assert_eq!(op.entity_type, "ethernet");
    }

    #[test]
    fn test_modify_operation_shows_mtu_set_with_old_value_and_addresses_unchanged() {
        let mut desired = StateSet::new();
        desired.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(9000)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let schema = SchemaRegistry::new();
        let diff = generate_diff(&desired, &actual, &schema);
        let op = &diff.operations[0];

        // mtu: Set(Some(1500) → 9000)
        let mtu_change = find_change(op, "mtu").expect("mtu must have a change");
        match mtu_change {
            FieldChangeKind::Set { current: Some(old), desired } => {
                assert_eq!(old.value, Value::U64(1500), "old mtu should be 1500");
                assert_eq!(desired.value, Value::U64(9000), "new mtu should be 9000");
            }
            other => panic!("Expected Set{{current: Some(1500), desired: 9000}}, got {:?}", other),
        }

        // addresses: Unchanged (same value in both)
        let addr_change = find_change(op, "addresses").expect("addresses must have a change");
        assert!(
            matches!(addr_change, FieldChangeKind::Unchanged { .. }),
            "addresses with same value should be Unchanged, got {:?}",
            addr_change
        );
    }

    // ── Scenario: Entity in both with identical fields → no operation ─────────

    #[test]
    fn test_identical_entity_in_both_generates_no_operation() {
        let mut desired = StateSet::new();
        desired.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert!(diff.is_empty(), "identical states should produce no operations");
        assert_eq!(diff.len(), 0);
    }

    // ── Scenario: Field added to existing entity ──────────────────────────────

    #[test]
    fn test_field_added_to_existing_entity_generates_set_none_change() {
        let mut desired = StateSet::new();
        desired.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let mut actual = StateSet::new();
        actual.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.len(), 1, "should have one Modify operation");
        let op = &diff.operations[0];
        assert_eq!(op.kind, DiffKind::Modify);

        // addresses: Set(None → [...]) — field is new in desired
        let addr_change = find_change(op, "addresses").expect("addresses must have a change");
        assert!(
            matches!(addr_change, FieldChangeKind::Set { current: None, .. }),
            "newly added field must be Set with current=None, got {:?}",
            addr_change
        );

        // mtu: Unchanged
        let mtu_change = find_change(op, "mtu").expect("mtu must have a change");
        assert!(
            matches!(mtu_change, FieldChangeKind::Unchanged { .. }),
            "unchanged mtu must be Unchanged, got {:?}",
            mtu_change
        );
    }

    // ── Scenario: Field removed from existing entity ──────────────────────────

    #[test]
    fn test_field_removed_from_existing_entity_generates_unset_change() {
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("addresses", addr_list(&["10.0.1.50/24"])),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.len(), 1, "should have one Modify operation");
        let op = &diff.operations[0];
        assert_eq!(op.kind, DiffKind::Modify);

        // addresses: Unset — field present in actual, absent in desired
        let addr_change = find_change(op, "addresses").expect("addresses must have a change");
        assert!(
            matches!(addr_change, FieldChangeKind::Unset { .. }),
            "removed field must be Unset, got {:?}",
            addr_change
        );

        // mtu: Unchanged
        let mtu_change = find_change(op, "mtu").expect("mtu must have a change");
        assert!(
            matches!(mtu_change, FieldChangeKind::Unchanged { .. }),
            "unchanged mtu must be Unchanged, got {:?}",
            mtu_change
        );
    }

    // ── Scenario: Multiple entities with mixed operations ─────────────────────

    #[test]
    fn test_multiple_entities_with_mixed_operations_produces_three_ops() {
        // desired: eth0 (mtu=9000), eth2 (mtu=1500)
        // actual:  eth0 (mtu=1500), eth1 (mtu=1500)
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))]));
        desired.insert(make_state("ethernet", "eth2", vec![("mtu", Value::U64(1500))]));

        let mut actual = StateSet::new();
        actual.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        actual.insert(make_state("ethernet", "eth1", vec![("mtu", Value::U64(1500))]));

        let schema = SchemaRegistry::new();
        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.len(), 3, "should have 3 operations: Modify eth0, Remove eth1, Add eth2");
        assert_eq!(diff.additions().count(), 1, "1 addition expected (eth2)");
        assert_eq!(diff.removals().count(), 1, "1 removal expected (eth1)");
        assert_eq!(diff.modifications().count(), 1, "1 modification expected (eth0)");
    }

    #[test]
    fn test_multiple_entities_correct_selectors_per_operation_kind() {
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))]));
        desired.insert(make_state("ethernet", "eth2", vec![("mtu", Value::U64(1500))]));
        let mut actual = StateSet::new();
        actual.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        actual.insert(make_state("ethernet", "eth1", vec![("mtu", Value::U64(1500))]));

        let schema = SchemaRegistry::new();
        let diff = generate_diff(&desired, &actual, &schema);

        let add_op = diff.additions().next().expect("should have an Add operation");
        assert_eq!(add_op.selector.key(), "eth2", "Add operation should target eth2");

        let remove_op = diff.removals().next().expect("should have a Remove operation");
        assert_eq!(remove_op.selector.key(), "eth1", "Remove operation should target eth1");

        let modify_op = diff.modifications().next().expect("should have a Modify operation");
        assert_eq!(modify_op.selector.key(), "eth0", "Modify operation should target eth0");
    }

    // ── Scenario: Empty desired state removes everything ──────────────────────

    #[test]
    fn test_empty_desired_produces_remove_operations_for_all_actual() {
        let desired = StateSet::new();
        let mut actual = StateSet::new();
        actual.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        actual.insert(make_state("ethernet", "eth1", vec![("mtu", Value::U64(1500))]));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.removals().count(), 2, "should have 2 Remove operations");
        assert_eq!(diff.additions().count(), 0, "should have no Add operations");
        assert_eq!(diff.modifications().count(), 0, "should have no Modify operations");
    }

    // ── Scenario: Empty actual state adds everything ──────────────────────────

    #[test]
    fn test_empty_actual_produces_add_operations_for_all_desired() {
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        desired.insert(make_state("ethernet", "eth1", vec![("mtu", Value::U64(1500))]));
        let actual = StateSet::new();
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.additions().count(), 2, "should have 2 Add operations");
        assert_eq!(diff.removals().count(), 0, "should have no Remove operations");
        assert_eq!(diff.modifications().count(), 0, "should have no Modify operations");
    }

    // ── Scenario: Both states empty produces empty diff ───────────────────────

    #[test]
    fn test_both_states_empty_produces_empty_diff() {
        let desired = StateSet::new();
        let actual = StateSet::new();
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert!(diff.is_empty(), "both-empty diff must return true for is_empty()");
        assert_eq!(diff.len(), 0, "both-empty diff must have len 0");
    }

    // ── Scenario: Read-only fields from actual are excluded from diff ─────────

    #[test]
    fn test_read_only_carrier_and_speed_excluded_from_diff() {
        // desired: eth0 with only mtu=1500
        // actual:  eth0 with mtu=1500, carrier=true, speed=1000
        // carrier and speed are x-netfyr-writable: false in the ethernet schema
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));

        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![
                ("mtu", Value::U64(1500)),
                ("carrier", Value::Bool(true)),
                ("speed", Value::U64(1000)),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        // carrier and speed are read-only → they should not generate a Modify operation
        assert!(
            diff.is_empty(),
            "carrier and speed are read-only and must not generate a Modify operation"
        );
    }

    #[test]
    fn test_read_only_mac_field_excluded_from_diff() {
        // mac is also x-netfyr-writable: false in the ethernet schema
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));

        let mut actual = StateSet::new();
        actual.insert(make_state(
            "ethernet",
            "eth0",
            vec![("mtu", Value::U64(1500)), ("mac", Value::String("aa:bb:cc:dd:ee:ff".to_string()))],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        assert!(
            diff.is_empty(),
            "mac is read-only and must not generate a Modify operation"
        );
    }

    // ── Scenario: Diff accessors filter by operation kind ────────────────────

    #[test]
    fn test_diff_accessors_filter_by_operation_kind_with_2_add_1_modify_1_remove() {
        // Build: 2 Add (eth2, eth3), 1 Modify (eth0 mtu differs), 1 Remove (eth1)
        // desired: eth0(mtu=9000), eth2(mtu=1500), eth3(mtu=1500)
        // actual:  eth0(mtu=1500), eth1(mtu=1500)
        let mut desired = StateSet::new();
        desired.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(9000))]));
        desired.insert(make_state("ethernet", "eth2", vec![("mtu", Value::U64(1500))]));
        desired.insert(make_state("ethernet", "eth3", vec![("mtu", Value::U64(1500))]));

        let mut actual = StateSet::new();
        actual.insert(make_state("ethernet", "eth0", vec![("mtu", Value::U64(1500))]));
        actual.insert(make_state("ethernet", "eth1", vec![("mtu", Value::U64(1500))]));

        let schema = SchemaRegistry::new();
        let diff = generate_diff(&desired, &actual, &schema);

        assert_eq!(diff.additions().count(), 2, "additions() should return 2 items");
        assert_eq!(diff.removals().count(), 1, "removals() should return 1 item");
        assert_eq!(diff.modifications().count(), 1, "modifications() should return 1 item");
        assert_eq!(diff.len(), 4, "len() should return 4 total operations");
    }

    // ── Edge case: writable field in unknown entity type is always diffed ─────

    #[test]
    fn test_unknown_entity_type_fields_treated_as_writable() {
        // "bond" entity type has no registered schema — all fields treated as writable
        let mut desired = StateSet::new();
        desired.insert(make_state("bond", "bond0", vec![("mode", Value::String("802.3ad".to_string()))]));

        let mut actual = StateSet::new();
        actual.insert(make_state(
            "bond",
            "bond0",
            vec![
                ("mode", Value::String("802.3ad".to_string())),
                ("lacp-rate", Value::String("fast".to_string())),
            ],
        ));
        let schema = SchemaRegistry::new();

        let diff = generate_diff(&desired, &actual, &schema);

        // lacp-rate is not in desired and has no schema → treated as writable → Unset
        assert_eq!(diff.len(), 1, "unknown entity type fields treated as writable → Modify");
        let op = &diff.operations[0];
        assert_eq!(op.kind, DiffKind::Modify);
        let lacp_change = find_change(op, "lacp-rate").expect("lacp-rate must have a change");
        assert!(
            matches!(lacp_change, FieldChangeKind::Unset { .. }),
            "unknown entity type field must be Unset (treated as writable)"
        );
    }
}
