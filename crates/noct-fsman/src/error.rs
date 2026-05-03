#[derive(Debug, Clone, Copy)]
pub enum FilesystemError {
	AlreadyExists,
	DiskNotRecognized,
	InvalidSeek,
	IoError,
	NotFound,
	PermissionDenied,
	UnsupportedOperation,
}

pub type FilesystemResult<T> = Result<T, FilesystemError>;