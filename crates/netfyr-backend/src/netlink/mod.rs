//! Netlink-based `NetworkBackend` implementation for Linux.
//!
//! Provides `NetlinkBackend`, which queries and applies changes to kernel
//! networking state via the `rtnetlink` crate.

pub mod apply;
pub mod ethernet;
pub mod query;

use async_trait::async_trait;
use netfyr_state::{EntityType, Selector, StateDiff, StateSet};

use crate::{ApplyReport, BackendError, DryRunReport, NetworkBackend};

use query::establish_connection;

// ── NetlinkBackend ────────────────────────────────────────────────────────────

/// `NetworkBackend` implementation backed by Linux netlink (rtnetlink).
///
/// Currently supports the `"ethernet"` entity type.  A new netlink connection
/// is opened per query call — see [`query::establish_connection`] for rationale.
pub struct NetlinkBackend {
    supported_entities: Vec<EntityType>,
}

impl NetlinkBackend {
    /// Create a new `NetlinkBackend` with the default supported entity types.
    pub fn new() -> Self {
        Self {
            supported_entities: vec!["ethernet".to_string()],
        }
    }
}

impl Default for NetlinkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkBackend for NetlinkBackend {
    fn supported_entities(&self) -> &[EntityType] {
        &self.supported_entities
    }

    async fn query(
        &self,
        entity_type: &EntityType,
        selector: Option<&Selector>,
    ) -> Result<StateSet, BackendError> {
        match entity_type.as_str() {
            "ethernet" => {
                let handle = establish_connection().await?;
                ethernet::query_ethernet(&handle, selector).await
            }
            _ => Err(BackendError::UnsupportedEntityType(entity_type.clone())),
        }
    }

    async fn query_all(&self) -> Result<StateSet, BackendError> {
        // Iterates all supported entity types and merges results.
        let mut merged = StateSet::new();
        for entity_type in &self.supported_entities {
            let result = self.query(entity_type, None).await?;
            // Merge by inserting — StateSet::insert overwrites on same key.
            for state in result.iter() {
                merged.insert(state.clone());
            }
        }
        Ok(merged)
    }

    async fn apply(&self, diff: &StateDiff) -> Result<ApplyReport, BackendError> {
        let handle = establish_connection().await?;
        apply::apply_ethernet(&handle, diff).await
    }

    async fn dry_run(&self, diff: &StateDiff) -> Result<DryRunReport, BackendError> {
        let handle = establish_connection().await?;
        apply::dry_run_ethernet(&handle, diff).await
    }
}
