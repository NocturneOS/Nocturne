pub use num_derive::{FromPrimitive, ToPrimitive};
pub use num_traits::{FromPrimitive, ToPrimitive};

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
pub enum Error {
    /// Entity already exists
    AlreadyExists,
    /// Attempted access on non-existent drive.
    NoDrive,
    /// Filesystem is not recognized on specific drive.
    FilesystemNotRecognized,
    /// Iterator ended
    EndOfIterator,
    /// Tried access an entity that has different properties.
    /// For example treating file as a directory.
    InvalidEntity,
    /// Trying to do some operations with non-existent handle.
    /// For example using handle of closed file to read data.
    InvalidHandle,
    /// Invalid combinations of open mode flags.
    InvalidMode,
    /// Tried to seek beyond disk bounds or integer overflow happened.
    InvalidSeek,
    /// Invalid path.
    InvalidPath,
    /// Serious error - hardware or filesystem fault
    IoError,
    /// Entity not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// Raised on writing operations where filesystem is read-only.
    ReadOnly,
    /// Treat this mostly as unimplemented feature.
    UnsupportedOperation,
    /// Attempted access beyond memory buffer, hardware memory exceptions, null pointer usage.
    MemoryError,
    /// No space on disk.
    NoSpace,
    /// A kind of error that hasn't documented here yet.
    Unknown,
}