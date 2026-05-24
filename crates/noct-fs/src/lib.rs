#![no_std]

use alloc::vec::Vec;

extern crate alloc;

pub fn read_file(path: &str) -> noct_io::Result<Vec<u8>> {
    // TODO: 0. Canonicalize that path, parse path to get disk id and full path
    //       1. Get file info (size)
    //       2. Allocate contiguous Vec with that size
    //       3. Read whole file into it
    //       4. Return that Vec
    todo!()
}