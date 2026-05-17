use iso9660_simple::ISODirectoryEntry;

pub struct DirectoryHandleEntity {
    pub(crate) id: usize,
    pub(crate) directory_entry: ISODirectoryEntry,
    pub(crate) iterator_position: usize
}

pub struct FileHandleEntity {
    pub(crate) id: usize,
    pub(crate) file_entry: ISODirectoryEntry
}