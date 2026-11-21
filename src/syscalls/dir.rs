use core::ffi::c_char;

use noct_fsman::NodeId;
use noct_io::error::Error;

use crate::mem::usermem::{verify_array_ptr_mut, verify_ptr_range, verify_ptr_range_mut};

#[repr(C)]
struct InternalDirEntry {
    /// Node ID - like inode in UNIX.
    node_id: NodeId,

    /// Name - 256 chars (bytes) MAX.
    name: [u8; 256],
}

pub fn getdirents(fd: usize, ptr: usize, count: usize, _: usize, _: usize) -> Result<usize, Error> {
    let buffer = verify_array_ptr_mut::<InternalDirEntry>(ptr, count).ok_or(Error::MemoryError)?;

    let ents = {
        let proc = noct_sched::this_process();
        let mut res = proc.resources.lock();

        let f = res.find_mut(fd).ok_or(Error::NotFound)?;

        let dh = f.res.as_directory_handle_mut().unwrap();

        dh.read_n(count)?
    };

    for (n, i) in ents.iter().enumerate() {
        let mut raw_name: [u8; 256] = [0; 256];

        unsafe { i.name.as_ptr().copy_to_nonoverlapping(raw_name.as_mut_ptr(), i.name.len()) };

        unsafe {
            buffer.add(n).write(InternalDirEntry {
                node_id: i.info.node_id,
                name: raw_name,
            })
        };
    }

    Ok(ents.len())
}
