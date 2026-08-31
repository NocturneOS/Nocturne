use alloc::string::String;

pub struct FileHandleEntity {
    pub(crate) id: usize,
    pub(crate) file_path: String,
}

pub struct DirectoryHandleEntity {
    pub(crate) id: usize,
    pub(crate) directory_path: String,
    pub(crate) iterator_position: usize,
}