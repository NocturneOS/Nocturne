use noct_io::error::Error;

pub fn getdirents(fd: usize, ptr: usize, count: usize, _: usize, _: usize) -> Result<usize, Error> {
    todo!("getdirents syscall")
}