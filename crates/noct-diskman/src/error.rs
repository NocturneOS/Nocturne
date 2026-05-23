pub type DiskManResult<T> = core::result::Result<T, DiskManError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiskManError {
    DiskNotFound,
    ReadError,
    WriteError,
    ControlError,
    LocationOutOfBounds,
    UnsupportedOperation,
}
