#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    AlreadyExists,
    DiskNotRecognized,
    EndOfIterator,
    InvalidEntity,
    InvalidHandle,
    InvalidMode,
    InvalidSeek,
    IoError,
    NotFound,
    PermissionDenied,
    ReadOnly,
    Unknown,
    UnsupportedOperation,
}