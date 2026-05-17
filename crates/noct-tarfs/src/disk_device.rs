use alloc::{borrow::ToOwned, string::String};
use no_std_io::io::{Read, Seek};

pub struct DiskDevice {
    pub disk: String,
    position: u64,
}

impl DiskDevice {
    pub fn new(disk: &str) -> Self {
        DiskDevice {
            disk: disk.to_owned(),
            position: 0,
        }
    }
}

impl Read for DiskDevice {
    fn read(&mut self, buffer: &mut [u8]) -> no_std_io::io::Result<usize> {
        let read_size = noct_diskman::read_bytes(&self.disk, self.position as _, buffer);

        if let Ok(read_size) = read_size {
            self.position += read_size as u64;

            Ok(read_size as _)
        } else {
            Err(no_std_io::io::ErrorKind::Other.into())
        }
    }
}

impl Seek for DiskDevice {
    fn seek(&mut self, pos: no_std_io::io::SeekFrom) -> no_std_io::io::Result<u64> {
        match pos {
            no_std_io::io::SeekFrom::Start(pos) => {
                self.position = pos;
            }
            no_std_io::io::SeekFrom::End(_pos) => {
                todo!(
                    "Implement getting info about disk and use disk's max position to determine offset against disk's end"
                );
            }
            no_std_io::io::SeekFrom::Current(pos) => {
                self.position = (self.position as i64 + pos).try_into().unwrap();
            }
        };

        Ok(self.position)
    }
}

impl tarfs::Device for DiskDevice {}
