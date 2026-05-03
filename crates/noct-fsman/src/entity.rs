use crate::NodeId;

/// Filesystem entity type.
#[derive(Debug, Clone, Copy)]
pub enum EntityType {
	Directory,
	File,
	// Symlinks, hardlinks and FIFO nodes are not currently planned to support.
	// I'll add them as I make support from filesystems' side and ...
	// ... some API endpoints.
}

/// Filesystem entity information.
#[derive(Debug)]
pub struct EntityInfo {
    pub node_id: NodeId,
    pub entity_type: EntityType,
    pub size: u64,
    pub created_at: noct_time::repr::Time,
    pub modified_at: noct_time::repr::Time,
}