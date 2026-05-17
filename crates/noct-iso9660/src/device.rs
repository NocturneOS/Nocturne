use alloc::string::{String, ToString};
use noct_logger::qemu_log;

pub struct Device {
    disk_id: String,
}

impl Device {
    pub fn new(disk_id: &str) -> Self {
        Self {
            disk_id: disk_id.to_string(),
        }
    }
}

impl iso9660_simple::Read for Device {
    fn read(&mut self, position: usize, buffer: &mut [u8]) -> Option<()> {
        let result = noct_diskman::read_bytes(&self.disk_id, position as _, buffer)
            .map(|_| ())
            .ok();

        result
    }
}