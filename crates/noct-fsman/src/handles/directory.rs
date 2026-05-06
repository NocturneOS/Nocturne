use alloc::string::String;

use crate::entity::EntityInfo;

pub struct DirectoryHandle;

pub struct DirectoryEntry {
	name: String,
	info: EntityInfo
}
