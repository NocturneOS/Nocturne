#[derive(Debug, Clone, Copy)]
pub enum FilesystemError {
	AlreadyExists,
	DiskNotRecognized,
	InvalidSeek,
	InvalidEntity,
	IoError,
	NotFound,
	PermissionDenied,
	UnsupportedOperation,
	EndOfIterator,
	Unknown
}

pub type FilesystemResult<T> = Result<T, FilesystemError>;