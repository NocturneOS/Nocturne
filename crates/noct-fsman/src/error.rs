#[derive(Debug, Clone, Copy)]
pub enum FilesystemError {
	NotFound,
	AlreadyExists,
	PermissionDenied,
	IoError,
	UnsupportedOperation,
}

pub type FilesystemResult<T> = Result<T, FilesystemError>;