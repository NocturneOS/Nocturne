pub type ATAResult<T> = Result<T, AtaError>;
pub type ATAIOResult<T> = Result<T, AtaIoError>;

#[derive(Debug, Clone)]
pub enum AtaError {
    TimedOut,
    NoDrive,
    ErrorSet(u8),
}

#[derive(Debug, Clone)]
pub enum AtaIoError {
    InvalidBuffer,
    InvalidLBA,
    ControllerError(AtaError),
    UnsupportedOperation,
    DMAControllerNotInitialized,
}
