#[derive(Debug, Clone, Copy)]
pub enum FilesystemError {
	AlreadyExists,
	DiskNotRecognized,
	EndOfIterator,
	InvalidEntity,
	InvalidHandle,
	InvalidMode,
	InvalidSeek,
	IoError,
	NotFound,
	PermissionDenied,
	Unknown,
	UnsupportedOperation,
}

pub type FilesystemResult<T> = Result<T, FilesystemError>;