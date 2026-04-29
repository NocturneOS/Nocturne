pub type ATAResult<T> = Result<T, ATAError>;
pub type ATAIOResult<T> = Result<T, ATAIOError>;

#[derive(Debug, Clone)]
pub enum ATAError {
    TimedOut,
    NoDrive,
    ErrorSet(u8)
}

#[derive(Debug, Clone)]
pub enum ATAIOError {
    InvalidBuffer,
    InvalidLBA,
    ControllerError(ATAError),
    UnsupportedOperation,
    DMAControllerNotInitialized
}