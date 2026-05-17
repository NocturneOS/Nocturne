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
	EndOfIterator
}

pub type FilesystemResult<T> = Result<T, FilesystemError>;