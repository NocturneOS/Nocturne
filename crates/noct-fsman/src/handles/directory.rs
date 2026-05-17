use alloc::string::String;

use crate::{NodeId, entity::EntityInfo};

pub struct DirectoryHandle {
	pub handle_id: u64
}

pub struct DirectoryEntry {
	pub node_id: NodeId,
	pub name: String,
	pub info: EntityInfo
}
