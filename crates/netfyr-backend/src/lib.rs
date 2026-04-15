//! netfyr-backend: trait-based abstraction layer between the reconciliation engine
//! and kernel I/O. Provides `NetworkBackend`, report types, `BackendError`, and
//! `BackendRegistry`.

pub mod registry;
pub mod report;
pub mod trait_;

pub use registry::BackendRegistry;
pub use report::{
    AppliedOperation, ApplyReport, DiffOpKind, DryRunReport, FailedOperation, FieldChange,
    FieldChangeKind, PlannedChange, SkippedOperation,
};
pub use trait_::NetworkBackend;

use netfyr_state::{EntityType, Selector};

// ── BackendError ──────────────────────────────────────────────────────────────

/// Errors produced by `NetworkBackend` implementations and the `BackendRegistry`.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The requested entity type is not handled by this backend.
    #[error("unsupported entity type: {0}")]
    UnsupportedEntityType(EntityType),

    /// A query operation failed for the given entity type.
    #[error("query failed for entity type {entity_type}")]
    QueryFailed {
        entity_type: EntityType,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// An apply operation failed for the given operation description.
    #[error("apply failed for operation: {operation}")]
    ApplyFailed {
        operation: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The requested entity was not found.
    // Selector is boxed to keep BackendError's in-line size small (clippy::result_large_err).
    #[error("entity not found: {entity_type} {selector:?}")]
    NotFound {
        entity_type: EntityType,
        selector: Box<Selector>,
    },

    /// The backend lacks permission to perform the operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}
