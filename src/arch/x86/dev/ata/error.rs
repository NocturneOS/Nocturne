pub type ATAResult<T> = Result<T, ATAError>;

#[derive(Debug, Clone)]
pub enum ATAError {
    TimedOut,
    NoDrive,
    ErrorSet(u8)
}