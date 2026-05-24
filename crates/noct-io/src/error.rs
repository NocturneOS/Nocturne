#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    AlreadyExists,
    DiskNotRecognized,
    EndOfIterator,
    InvalidEntity,
    InvalidHandle,
    InvalidMode,
    InvalidSeek,
    InvalidPath,
    IoError,
    NotFound,
    PermissionDenied,
    ReadOnly,
    Unknown,
    UnsupportedOperation,
}