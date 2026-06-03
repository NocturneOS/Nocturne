pub use num_derive::{FromPrimitive, ToPrimitive};
pub use num_traits::{FromPrimitive, ToPrimitive};

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
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
    UnsupportedOperation,
    MemoryError,
    Unknown,
}