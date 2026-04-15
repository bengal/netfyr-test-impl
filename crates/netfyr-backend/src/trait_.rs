//! The `NetworkBackend` async trait.

use async_trait::async_trait;
use netfyr_state::{EntityType, Selector, StateDiff, StateSet};

use crate::{ApplyReport, BackendError, DryRunReport};

// ── NetworkBackend ────────────────────────────────────────────────────────────

/// Uniform interface for interacting with a kernel subsystem that manages a
/// specific set of network entity types.
///
/// Implementors must store the list of supported entity types (e.g., as a
/// `Vec<EntityType>` field) and return a slice from `supported_entities`.
///
/// The `async-trait` macro desugars each async method to return
/// `Pin<Box<dyn Future + Send>>`, which enables `dyn NetworkBackend` trait
/// objects across async boundaries.
#[async_trait]
pub trait NetworkBackend: Send + Sync {
    /// Query entities of a specific type, optionally filtered by selector.
    ///
    /// Returns a `StateSet` containing the current system state for matching
    /// entities. Returns `BackendError::UnsupportedEntityType` when the entity
    /// type is not handled by this backend.
    async fn query(
        &self,
        entity_type: &EntityType,
        selector: Option<&Selector>,
    ) -> Result<StateSet, BackendError>;

    /// Query all entities supported by this backend.
    ///
    /// Returns a `StateSet` containing the current system state across all
    /// entity types this backend handles.
    async fn query_all(&self) -> Result<StateSet, BackendError>;

    /// Apply a `StateDiff` to the system.
    ///
    /// Executes each add/modify/remove operation and returns a report that
    /// categorises every operation as succeeded, failed, or skipped. Individual
    /// operation failures are captured in the report rather than returned as
    /// `Err`; `Err` is reserved for systemic failures (e.g., cannot reach the
    /// kernel subsystem at all).
    async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError>;

    /// Simulate applying a `StateDiff` without making any system changes.
    ///
    /// Returns a report of what would happen, including per-field before/after
    /// values.
    async fn dry_run(&self, diff: &StateDiff) -> Result<DryRunReport, BackendError>;

    /// Return the list of entity types this backend can handle.
    ///
    /// Implementors must store the list as an owned collection and return a
    /// slice; constructing the list on the fly is not possible because the
    /// method returns a borrowed reference.
    fn supported_entities(&self) -> &[EntityType];
}
