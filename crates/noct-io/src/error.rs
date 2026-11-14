pub use num_derive::{FromPrimitive, ToPrimitive};
pub use num_traits::{FromPrimitive, ToPrimitive};

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
pub enum Error {
    /// Used to clear process' errno
    None = 0,
    /// Entity already exists
    AlreadyExists = 1,
    /// Attempted access on non-existent drive.
    NoDrive = 2,
    /// Filesystem is not recognized on specific drive.
    FilesystemNotRecognized = 3,
    /// Iterator ended
    EndOfIterator = 4,
    /// Invalid argument
    InvalidArgument = 5,
    /// Tried access an entity that has different properties.
    /// For example treating file as a directory.
    InvalidEntity,
    /// Trying to do some operations with non-existent handle.
    /// For example using handle of closed file to read data.
    InvalidHandle = 7,
    /// Invalid combinations of open mode flags.
    InvalidMode,
    /// Tried to seek beyond disk bounds or integer overflow happened.
    InvalidSeek = 9,
    /// Invalid path.
    InvalidPath,
    /// Serious error - hardware or filesystem fault
    IoError = 11,
    /// Entity not found
    NotFound = 12,
    /// Permission denied
    PermissionDenied = 13,
    /// This function is not supported
    NotSupported = 14,
    /// This function is not implemented
    Unimplemented = 15,
    /// Raised on writing operations where filesystem is read-only.
    ReadOnly = 16,
    /// No available memory
    NoMemory = 17,
    /// No space on disk.
    NoSpace = 18,
    /// Attempted access beyond memory buffer, hardware memory exceptions, null pointer usage.
    MemoryError = 19,
    /// Operation not permitted
    NotPermitted = 20,
    /// Resource is busy.
    Busy = 21,
    /// Wrong executable format or unsupported architecture.
    ExecFormat = 22,
    /// No child process with the given PID to wait for.
    NoChild = 23,
    /// A kind of error that hasn't documented here yet.
    Unknown = 0xFFFF,
}
