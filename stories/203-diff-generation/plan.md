# PLAN: SPEC-203 Diff Generation Between Desired and Actual State

## Approach

This story modifies the existing `generate_diff` function in `netfyr-reconcile/src/diff.rs` to accept a `managed_entities: &HashSet<EntityKey>` parameter and use it to filter Remove operations. Currently, `generate_diff` removes all actual-only entities unconditionally. The spec requires that only entities explicitly targeted by an active policy can be removed — unmanaged entities in the system must be left untouched (no operation, not even listed as "unchanged").

The core change is small: add one parameter to the signature, add one guard in Pass 2, and propagate the parameter to all callers. However, the change touches four files across two crates — diff.rs and report.rs in `netfyr-reconcile` (function + tests), reconciler.rs in `netfyr-daemon`, and apply.rs in `netfyr-cli` — so it requires careful coordination.

The key design tension is the read-only field exclusion. The current implementation uses `SchemaRegistry` to detect read-only fields (carrier, speed, mac) in Modify operations. The spec says the third parameter should be `managed_entities`, not `schema`. But the spec also requires read-only fields to be excluded. I choose **Option A from the understanding analysis**: keep both parameters — `managed_entities` for Remove filtering and `schema` for read-only field filtering. This preserves the existing, well-tested read-only behavior while adding the new managed-entity guard. The alternative (relying on the invariant that desired state never contains read-only fields) is fragile and hard to guarantee across the pipeline. A four-parameter function is slightly wider, but each parameter has a clear, distinct purpose.

The `DiffReport::new` unchanged-entity computation also needs adjustment: the current implementation computes unchanged as the intersection of desired and actual minus operated keys. With managed entities, entities that are in actual but not in desired AND not managed should be completely invisible — they should NOT appear in `unchanged_entities`. The current logic already handles this correctly because it uses `desired_keys.intersection(&actual_keys)`, so actual-only entities never appear in unchanged. No change needed to report.rs.

## Design Decisions

### 1. Keep `schema` parameter alongside `managed_entities`

- **Decision**: `pub fn generate_diff(desired: &StateSet, actual: &StateSet, managed_entities: &HashSet<EntityKey>, schema: &SchemaRegistry) -> StateDiff`
- **Alternatives considered**:
  - (a) Replace `schema` with `managed_entities` entirely, relying on the invariant that desired state never contains read-only fields.
  - (b) Match spec signature exactly with only `managed_entities`, moving read-only filtering to the caller.
- **Rationale**: The spec requires read-only field exclusion (acceptance criteria: "Read-only fields from actual state are excluded from diff"). The existing implementation uses `schema.field_info()` for this. Option (a) is fragile — if a policy accidentally includes a read-only field in desired state, or if a new entity type's schema isn't loaded, spurious Unset changes would appear. Option (b) pushes complexity to every caller. Keeping both parameters is explicit and preserves the battle-tested read-only behavior while adding the new managed-entity guard. The `managed_entities` parameter is listed before `schema` since it's the new, spec-mandated addition.

### 2. Managed entities only affect Pass 2 (Remove operations)

- **Decision**: The `managed_entities` guard applies only in Pass 2 (actual-only entities). Pass 1 (desired entities) is unchanged — if an entity is in desired, it's managed by definition.
- **Alternatives considered**: Using managed_entities to also gate Modify operations.
- **Rationale**: The spec states: "Only managed entities can generate Remove operations." Modify and Add operations are inherently scoped to desired state — if an entity is in desired, some policy is already managing it. The managed_entities filter exists specifically to prevent removing entities the system knows about but no policy targets.

### 3. Unmanaged entities are completely invisible (not in unchanged_entities either)

- **Decision**: Entities present in actual but not in desired and not in managed_entities produce no operation and do not appear in `unchanged_entities`.
- **Alternatives considered**: Listing unmanaged entities in a separate "unmanaged" list.
- **Rationale**: The spec's acceptance criteria explicitly state: "ethernet/eth1 is not in unchanged_entities either (completely ignored)" and "ethernet/eth3 is not in the diff (unmanaged)". The current `DiffReport::new` already handles this correctly — it computes unchanged as `desired ∩ actual - operated`, so actual-only entities never appear. No code change needed in report.rs.

### 4. Caller-side managed_entities computation strategy

- **Decision**: Both callers (daemon's `Reconciler::dry_run` and CLI's `run_apply`) compute managed_entities by iterating all `PolicyInput.state_set` entities and collecting their `(entity_type, selector.key())` pairs.
- **Alternatives considered**: 
  - (a) Computing from Policy selectors directly (would catch factory policies before they produce state).
  - (b) Passing a dedicated `ManagedEntities` type instead of `HashSet`.
- **Rationale**: Computing from PolicyInput state sets is the simplest approach that works for all current use cases. Option (a) is more correct for factory policies (e.g., DHCPv4 that hasn't acquired a lease yet), but it requires resolving selectors to concrete entity keys, which is complex and out of scope for this story. The spec acknowledges this gap: "computed by the caller from the full policy list." A future story can enhance the computation to include factory-targeted selectors. Option (b) adds a type with no additional safety — the HashSet is already semantically clear from the parameter name.

### 5. `generate_diff` does NOT consume managed_entities to produce unchanged_entities

- **Decision**: `generate_diff` returns only `StateDiff` (operations). The `DiffReport::new` computes unchanged entities from the two StateSets and the operations.
- **Alternatives considered**: Having `generate_diff` also return unchanged entity keys, or having it accept managed_entities for unchanged computation.
- **Rationale**: `StateDiff` is the algorithmic output (what changes). `DiffReport` is the presentation wrapper (what to display). Unchanged computation belongs in the presentation layer. This matches the existing design where `DiffReport::new(diff, desired, actual)` does the computation.

## File Changes

### 1. `crates/netfyr-reconcile/src/diff.rs`

- **Action**: Modify
- **What**:
  - **Import change**: Add `use std::collections::HashSet;` and `use crate::EntityKey;`. Keep existing `use netfyr_state::{FieldValue, SchemaRegistry, Selector, StateSet};`.
  - **`generate_diff` signature change**: From `pub fn generate_diff(desired: &StateSet, actual: &StateSet, schema: &SchemaRegistry) -> StateDiff` to `pub fn generate_diff(desired: &StateSet, actual: &StateSet, managed_entities: &HashSet<EntityKey>, schema: &SchemaRegistry) -> StateDiff`.
  - **Pass 2 guard**: In the loop over actual entities absent from desired (lines 259-282), after the `desired.get().is_some()` check, add: if the entity key `(entity_type.clone(), selector_key.clone())` is not in `managed_entities`, skip (continue). This prevents Remove operations for unmanaged entities.
  - **Doc comment update**: Update the `generate_diff` doc comment to describe the `managed_entities` parameter and its role in gating Remove operations. Update the Pass 2 description to mention the managed-entity guard.
  - **Module-level doc comment update**: Update the module-level doc to mention managed_entities.
  - **Tests**: Update ALL existing tests that call `generate_diff` to pass a `managed_entities` parameter. For tests that exercise Remove operations, the tested entities must be in the managed set. For tests that only exercise Add or Modify, an empty set is fine (but including the tested entities is cleaner). Add new test scenarios per spec requirements.
  
  **Existing test updates** (each needs `managed_entities` added to `generate_diff` call):
  - `test_add_entity_in_desired_not_in_actual_generates_add_operation`: Empty managed set (Adds don't need it).
  - `test_add_operation_sets_all_fields_with_no_current_value`: Empty managed set.
  - `test_remove_entity_in_actual_not_in_desired_generates_remove_operation`: managed set containing `("ethernet", "eth0")`.
  - `test_remove_operation_unsets_all_fields_with_current_value`: managed set containing `("ethernet", "eth0")`.
  - `test_modify_entity_with_different_mtu_generates_modify_operation`: Empty or containing eth0.
  - `test_modify_operation_shows_mtu_set_with_old_value_and_addresses_unchanged`: Same.
  - `test_identical_entity_in_both_generates_no_operation`: Same.
  - `test_field_added_to_existing_entity_generates_set_none_change`: Same.
  - `test_field_removed_from_existing_entity_generates_unset_change`: Same.
  - `test_multiple_entities_with_mixed_operations_produces_three_ops`: managed set containing eth0, eth1 (not eth3 if present) — **critically, eth1 must be in managed set to generate Remove**.
  - `test_multiple_entities_correct_selectors_per_operation_kind`: Same managed set as above.
  - `test_empty_desired_produces_remove_operations_for_all_actual`: managed set containing eth0 AND eth1 (both must be managed to generate Removes).
  - `test_empty_actual_produces_add_operations_for_all_desired`: Empty managed set.
  - `test_both_states_empty_produces_empty_diff`: Empty managed set.
  - `test_read_only_carrier_and_speed_excluded_from_diff`: Empty or containing eth0.
  - `test_read_only_mac_field_excluded_from_diff`: Same.
  - `test_diff_accessors_filter_by_operation_kind_with_2_add_1_modify_1_remove`: managed set containing eth1 (to generate Remove).
  - `test_unknown_entity_type_fields_treated_as_writable`: Empty or containing bond0.

  **New tests to add**:
  - `test_unmanaged_entity_in_actual_is_completely_ignored`: actual has eth1 (not in managed_entities), desired is empty, managed_entities is empty. Verify diff is empty.
  - `test_managed_entity_in_actual_not_desired_generates_remove`: actual has eth0, desired is empty, managed_entities contains ("ethernet", "eth0"). Verify 1 Remove.
  - `test_empty_desired_only_removes_managed_entities`: actual has eth0, eth1, eth2. managed_entities contains eth0 and eth1 only. Verify 2 Remove operations (eth0, eth1), not 3.
  - `test_mixed_managed_unmanaged_with_multiple_operation_types`: desired has eth0 (modified), eth2 (new). actual has eth0, eth1, eth3. managed_entities has eth0, eth1, eth2. Verify: Modify eth0, Remove eth1, Add eth2. eth3 absent entirely.

- **Why**: Core spec requirement. The `managed_entities` parameter enables the key behavioral change (gating Remove operations) while the schema parameter preserves the read-only field exclusion that's already implemented and tested.

### 2. `crates/netfyr-reconcile/src/report.rs`

- **Action**: Modify
- **What**:
  - **Tests only**: Update all test calls to `generate_diff` to include the new `managed_entities` parameter. The `DiffReport` struct and all its methods remain unchanged.
  
  **Test updates** (each call to `generate_diff` needs `managed_entities`):
  - `test_format_text_shows_additions_with_plus_prefix`: Empty managed set.
  - `test_format_text_add_with_list_field_shows_list_value`: Empty managed set.
  - `test_format_text_shows_removals_with_minus_prefix`: managed set with `("vlan", "bond0.200")`.
  - `test_format_text_shows_modifications_with_tilde_header`: Empty or with eth0.
  - `test_format_text_shows_field_change_with_arrow`: Same.
  - `test_format_text_shows_added_field_in_modify_with_plus_prefix`: Same.
  - `test_format_text_shows_removed_field_in_modify_with_minus_prefix`: Same.
  - `test_format_text_shows_unchanged_field_in_modify_with_no_prefix`: Same.
  - `test_diff_report_is_empty_when_both_states_empty`: Empty managed set.
  - `test_diff_report_is_empty_when_states_are_identical`: Same.
  - `test_diff_report_is_not_empty_when_there_are_operations`: Empty managed set.
  - `test_diff_report_unchanged_entities_listed_for_identical_entity`: Same.
  - `test_diff_report_unchanged_entities_empty_when_all_entities_changed`: Same.
  - `test_diff_report_unchanged_entities_sorted_deterministically`: Same.
  - `test_format_text_shows_no_changes_footer_for_unchanged_entities`: Same.
  - `test_format_text_shows_no_changes_footer_only_for_unchanged_not_for_changed`: Same.
  - `test_format_yaml_produces_non_empty_string_for_nonempty_diff`: Empty managed set.
  - `test_format_json_produces_valid_json_for_nonempty_diff`: Empty managed set.

- **Why**: These tests compile against `generate_diff` which has a new parameter. The report logic itself is unchanged.

### 3. `crates/netfyr-daemon/src/reconciler.rs`

- **Action**: Modify
- **What**:
  - **Import change**: Add `use std::collections::HashSet;` and `use netfyr_reconcile::EntityKey;` (or construct the tuple type inline).
  - **`dry_run` method**: After `let inputs = self.build_policy_inputs(...)` and before calling `generate_diff`, compute `managed_entities` by iterating all inputs' state sets:
    ```
    let managed_entities: HashSet<EntityKey> = inputs.iter()
        .flat_map(|input| input.state_set.entities())
        .collect();
    ```
    Then change the `generate_diff` call from:
    `generate_diff(&effective_state, &actual_state, &self.schema_registry)`
    to:
    `generate_diff(&effective_state, &actual_state, &managed_entities, &self.schema_registry)`
    
    Note: `managed_entities` must be computed BEFORE `merge(inputs)` consumes the inputs. Currently `merge` takes `Vec<PolicyInput>` by value. The managed_entities computation must happen before the merge call, or the inputs need to be borrowed. Looking at the code, `merge(inputs)` consumes the Vec. So the managed_entities computation must come first, which means reordering: compute managed_entities from `&inputs`, then call `merge(inputs)`.

- **Why**: This is the daemon-side caller of `generate_diff`. The managed_entities set ensures that unmanaged system entities (e.g., interfaces not targeted by any policy) are not removed during dry-run reporting.

### 4. `crates/netfyr-cli/src/apply.rs`

- **Action**: Modify
- **What**:
  - **Import change**: Add `use std::collections::HashSet;` and `use netfyr_reconcile::EntityKey;`.
  - **`run_apply` function**: After `let inputs = policies_to_inputs(&policy_set)?;` (line 89) and before the merge call (line 92), compute managed_entities:
    ```
    let managed_entities: HashSet<EntityKey> = inputs.iter()
        .flat_map(|input| input.state_set.entities())
        .collect();
    ```
    Then change the `generate_diff` call on line 110 from:
    `generate_diff(effective_state, &actual_state, &schema)`
    to:
    `generate_diff(effective_state, &actual_state, &managed_entities, &schema)`
    
    Same ordering concern as reconciler.rs: compute managed_entities before `merge(inputs)` consumes the inputs.

- **Why**: This is the CLI-side (daemon-free mode) caller of `generate_diff`. Must be updated for the new signature.

### 5. `crates/netfyr-reconcile/src/lib.rs`

- **Action**: No changes needed
- **What**: The re-exports on line 6 already include `generate_diff`. The function signature change is transparent to the re-export. No new types need to be exported (EntityKey is already exported).
- **Why**: The existing re-exports handle the updated signature automatically.

## Dependencies

No new crate dependencies are needed. All required crates (`serde`, `serde_json`, `serde_yaml`) are already in `netfyr-reconcile/Cargo.toml`. `std::collections::HashSet` is from the standard library.

## Implementation Order

1. **Modify `crates/netfyr-reconcile/src/diff.rs`**: Change the `generate_diff` signature to add `managed_entities: &HashSet<EntityKey>` as the third parameter (before `schema`). Add the managed-entity guard in Pass 2. Update imports. Update ALL existing test calls to pass the new parameter. Add the four new test scenarios. **This step must come first because it changes the function signature that all other files depend on.** The crate will compile after this step since report.rs tests also call `generate_diff` — so step 2 must happen in the same compilation unit.

2. **Modify `crates/netfyr-reconcile/src/report.rs`**: Update all test calls to `generate_diff` to include the managed_entities parameter. No logic changes to report.rs production code. **Must happen simultaneously with step 1 to maintain compilation.**

3. **Modify `crates/netfyr-daemon/src/reconciler.rs`**: Compute `managed_entities` from policy inputs and pass to `generate_diff`. Reorder to compute before `merge()` consumes the inputs. **Depends on steps 1-2 (new signature must exist).**

4. **Modify `crates/netfyr-cli/src/apply.rs`**: Same pattern as step 3 — compute `managed_entities` from policy inputs before merge, pass to `generate_diff`. **Depends on steps 1-2 (new signature must exist). Independent of step 3.**

Steps 3 and 4 can be done in parallel since they are in different crates and independent of each other.

## Risks and Mitigations

### 1. `merge()` consumes inputs, but managed_entities must be computed from inputs first

- **Risk**: `merge(inputs)` takes `Vec<PolicyInput>` by value (line 254 of lib.rs: `pub fn merge(inputs: Vec<PolicyInput>)`). The managed_entities computation needs to iterate over the inputs' state sets before they're consumed by merge.
- **Mitigation**: Compute managed_entities before calling merge. The code order in both reconciler.rs and apply.rs must be: (1) build inputs, (2) compute managed_entities from `&inputs`, (3) call `merge(inputs)`. This is straightforward — just ensure the managed_entities binding comes before the merge call.

### 2. managed_entities computed from produced state doesn't cover factory-targeted entities before production

- **Risk**: The spec says managed_entities should include entities "explicitly targeted by at least one active policy (via its selector)" including factory policies that haven't produced state yet (e.g., DHCPv4 before lease acquisition). Computing from `PolicyInput.state_set` only captures entities where state has been produced.
- **Mitigation**: This is an inherent limitation of the current approach and is acknowledged in the spec's language. For the daemon case, factory policies that haven't produced state yet won't have entries in the produced_states list, so their target entities won't be in managed_entities. This means those entities can't be removed — which is actually the correct behavior (you shouldn't remove an entity you haven't managed yet). A future enhancement can compute managed_entities from Policy selectors directly.

### 3. Existing test count is high — mechanical update risk

- **Risk**: 18+ existing tests in diff.rs and 18+ in report.rs need the new parameter added to `generate_diff` calls. This is mechanical but error-prone — missing one test causes a compile error (which is safe) but adding the wrong managed set could cause a test to pass incorrectly.
- **Mitigation**: For tests that only exercise Add or Modify behavior, an empty `HashSet::new()` is safe — the managed_entities set doesn't affect those code paths. For tests that exercise Remove behavior, the test's actual-state entities must be in the managed set. Create a helper function `fn managed(keys: &[(&str, &str)]) -> HashSet<EntityKey>` in the test module to reduce boilerplate and make the managed set explicit in each test.

### 4. DiffReport unchanged_entities behavior with managed entities

- **Risk**: Could unmanaged entities accidentally appear in `unchanged_entities`? An entity in actual-only (not in desired, not managed) should be completely invisible.
- **Mitigation**: The current `DiffReport::new` computes unchanged as `desired_keys ∩ actual_keys - operated_keys`. Since unmanaged actual-only entities are by definition NOT in desired_keys, they can never appear in the intersection. No code change needed, but this should be verified by a test (the new `test_mixed_managed_unmanaged` test in diff.rs covers this at the diff level; an additional report-level test could be added if desired).

### 5. CLI apply.rs uses `effective_state` as a reference, not owned value

- **Risk**: On line 101, `let effective_state = &reconciliation.effective_state;` creates a reference. The `generate_diff` call on line 110 passes `effective_state` (which is `&&StateSet`). After the change, the call adds `&managed_entities`. Need to verify the borrow checker is happy with the lifetimes.
- **Mitigation**: `managed_entities` is computed before `merge(inputs)` and lives until the end of the function. `effective_state` borrows from `reconciliation` which also lives until the end. No lifetime issues.

## Test Strategy

### Unit tests for managed_entities behavior in `diff.rs`

**New test scenarios** (acceptance criteria from spec):

1. **Unmanaged entity ignored**: actual has entity not in managed_entities, desired is empty. Verify: no operations, entity not in diff at all.
2. **Managed entity removed**: actual has entity that IS in managed_entities, desired is empty. Verify: 1 Remove operation with correct Unset fields.
3. **Empty desired with mixed managed/unmanaged**: actual has 3 entities, only 2 in managed_entities. Verify: exactly 2 Remove operations, third entity absent.
4. **Mixed operations with managed filter**: desired has eth0 (modified mtu), eth2 (new). Actual has eth0, eth1, eth3. managed_entities = {eth0, eth1, eth2}. Verify: Modify eth0, Remove eth1, Add eth2. eth3 completely absent.

### Existing tests updated mechanically

All 18 existing tests in diff.rs and 18 in report.rs need the new parameter. The changes are mechanical — adding `&HashSet::new()` for non-Remove tests, or `&managed(...)` for Remove tests. No behavioral changes to existing test assertions.

### Test infrastructure

- Add a helper function `fn managed(keys: &[(&str, &str)]) -> HashSet<(String, String)>` in the diff.rs test module.
- Reuse existing helpers (`make_state`, `fv`, `find_change`, `addr_list`).
- No mocks or new test fixtures needed.

### Integration-level verification

The daemon and CLI callers don't have new unit tests for managed_entities computation specifically (the reconciler tests already test dry_run with empty stores). The managed_entities computation is simple enough (flat_map + collect) that it's covered by the diff-level unit tests. If desired, a reconciler-level test could verify that dry_run with policies doesn't remove unmanaged system interfaces, but this would require netlink access (integration test territory).
