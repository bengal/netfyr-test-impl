//! `BackendRegistry`: maps entity types to `NetworkBackend` implementations and
//! dispatches operations to the correct backend.

use std::collections::HashMap;
use std::sync::Arc;

use netfyr_state::{union, EntityType, Selector, StateDiff, StateSet};

use crate::{ApplyReport, BackendError, DiffOpKind, FailedOperation, NetworkBackend};

// ── BackendRegistry ───────────────────────────────────────────────────────────

/// Routes entity-type-specific operations to the correct `NetworkBackend`.
///
/// Internally stores a `HashMap<EntityType, Arc<dyn NetworkBackend>>` so that
/// look-up is O(1). A backend that handles N entity types is stored under N keys,
/// all sharing the same `Arc` allocation.
#[derive(Default)]
pub struct BackendRegistry {
    backends: HashMap<EntityType, Arc<dyn NetworkBackend>>,
}

impl BackendRegistry {
    /// Returns a new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a backend for all of its `supported_entities()`.
    ///
    /// The check is all-or-nothing: if *any* entity type is already registered to
    /// a *different* backend, the call returns an error and the registry is left
    /// unchanged.
    ///
    /// Registering the same `Arc` twice for the same entity type is a no-op (the
    /// arc's allocation address is used for identity comparison).
    pub fn register(&mut self, backend: Arc<dyn NetworkBackend>) -> Result<(), BackendError> {
        let new_ptr = Arc::as_ptr(&backend) as *const ();
        let entity_types = backend.supported_entities();

        // Check for conflicts before mutating.
        for entity_type in entity_types {
            if let Some(existing) = self.backends.get(entity_type) {
                let existing_ptr = Arc::as_ptr(existing) as *const ();
                if existing_ptr != new_ptr {
                    return Err(BackendError::Internal(format!(
                        "entity type '{entity_type}' is already registered to a different backend",
                    )));
                }
            }
        }

        // No conflicts — insert all.
        for entity_type in entity_types {
            self.backends
                .insert(entity_type.clone(), Arc::clone(&backend));
        }

        Ok(())
    }

    /// Look up the backend registered for `entity_type`, if any.
    pub fn get(&self, entity_type: &EntityType) -> Option<Arc<dyn NetworkBackend>> {
        self.backends.get(entity_type).map(Arc::clone)
    }

    /// Returns all registered entity types in unspecified order.
    pub fn supported_entities(&self) -> Vec<EntityType> {
        self.backends.keys().cloned().collect()
    }

    /// Query entities of a specific type via the registered backend.
    ///
    /// Returns `BackendError::UnsupportedEntityType` if no backend is registered
    /// for the given entity type.
    pub async fn query(
        &self,
        entity_type: &EntityType,
        selector: Option<&Selector>,
    ) -> Result<StateSet, BackendError> {
        let backend = self
            .backends
            .get(entity_type)
            .ok_or_else(|| BackendError::UnsupportedEntityType(entity_type.clone()))?;
        backend.query(entity_type, selector).await
    }

    /// Query all registered backends and merge their results into one `StateSet`.
    ///
    /// Each unique backend (deduplicated by `Arc` allocation address) is queried
    /// once. Results are merged with `netfyr_state::union`. A `ConflictError` from
    /// `union` is converted to `BackendError::Internal` — this should not happen if
    /// backends cover disjoint entity types, but is handled gracefully.
    pub async fn query_all(&self) -> Result<StateSet, BackendError> {
        let unique_backends = self.unique_backends();
        let mut merged = StateSet::new();
        for backend in unique_backends {
            let result = backend.query_all().await?;
            merged = union(&merged, &result)
                .map_err(|e| BackendError::Internal(format!("conflict merging state: {e}")))?;
        }
        Ok(merged)
    }

    /// Apply a `StateDiff` across all registered backends.
    ///
    /// The diff is partitioned by entity type. Known entity types are dispatched to
    /// their backend; unknown ones produce `FailedOperation` entries. All results are
    /// merged into a single `ApplyReport`. This method always returns `Ok` — every
    /// failure is captured in the report.
    pub async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError> {
        // Partition ops by entity type.
        let mut partitioned: HashMap<String, Vec<_>> = HashMap::new();
        for op in diff.ops() {
            partitioned
                .entry(op.entity_type().to_string())
                .or_default()
                .push(op.clone());
        }

        let mut merged = ApplyReport::new();

        for (entity_type, ops) in partitioned {
            match self.backends.get(&entity_type) {
                Some(backend) => {
                    let sub_diff = StateDiff::new(ops);
                    match backend.apply(&sub_diff).await {
                        Ok(report) => merged.merge(report),
                        Err(e) => {
                            // Systemic backend failure: record every op in this batch as failed.
                            let msg = e.to_string();
                            for op in sub_diff.ops() {
                                merged.failed.push(FailedOperation {
                                    operation: DiffOpKind::from(op),
                                    entity_type: op.entity_type().to_string(),
                                    selector: op.selector().clone(),
                                    error: BackendError::Internal(msg.clone()),
                                    fields: vec![],
                                });
                            }
                        }
                    }
                }
                None => {
                    // No backend registered for this entity type.
                    for op in &ops {
                        merged.failed.push(FailedOperation {
                            operation: DiffOpKind::from(op),
                            entity_type: op.entity_type().to_string(),
                            selector: op.selector().clone(),
                            error: BackendError::UnsupportedEntityType(entity_type.clone()),
                            fields: vec![],
                        });
                    }
                }
            }
        }

        Ok(merged)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Collects one `Arc` per unique backend (deduplicated by allocation address).
    fn unique_backends(&self) -> Vec<Arc<dyn NetworkBackend>> {
        let mut seen: Vec<*const ()> = Vec::new();
        let mut unique: Vec<Arc<dyn NetworkBackend>> = Vec::new();
        for arc in self.backends.values() {
            // Cast to thin pointer (data address only) to strip the vtable component
            // of the fat pointer. Two Arcs cloned from the same source share the same
            // allocation address regardless of vtable.
            let ptr = Arc::as_ptr(arc) as *const ();
            if !seen.contains(&ptr) {
                seen.push(ptr);
                unique.push(Arc::clone(arc));
            }
        }
        unique
    }
}
