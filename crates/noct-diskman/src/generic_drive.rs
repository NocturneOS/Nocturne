use core::ffi::c_void;

use alloc::string::String;

use crate::structures::Drive;

pub type ReadFn =
    extern "C" fn(priv_data: *mut c_void, location: u64, size: u64, buffer: *mut u8) -> i64;
pub type WriteFn =
    extern "C" fn(priv_data: *mut c_void, location: u64, size: u64, buffer: *const u8) -> i64;
pub type ControlFn = extern "C" fn(
    priv_data: *mut c_void,
    command: u32,
    parameters: *const u8,
    param_len: usize,
    buffer: *mut u8,
    buffer_len: usize,
) -> i64;

pub struct GenericDrive {
    pub(crate) driver_name: String,
    pub(crate) id: String,

    pub(crate) private_data: *mut c_void,

    pub(crate) read: ReadFn,
    pub(crate) write: WriteFn,

    /// May be null.
    pub(crate) control: ControlFn,
}

impl Drive for GenericDrive {
    fn get_name(&self) -> &str {
        &self.driver_name
    }

    fn get_id(&self) -> &str {
        &self.id
    }

    fn read(&mut self, location: u64, buffer: &mut [u8]) -> i64 {
        let buf = buffer.as_mut_ptr();

        (self.read)(self.private_data, location, buffer.len() as _, buf)
    }

    fn write(&mut self, location: u64, buffer: &[u8]) -> i64 {
        let buf = buffer.as_ptr();

        (self.write)(self.private_data, location, buffer.len() as _, buf)
    }

    fn control(
        &mut self,
        command: crate::structures::Command,
        command_parameters: &[u8],
        data: &mut [u8],
    ) -> i64 {
        (self.control)(
            self.private_data,
            command as _,
            command_parameters.as_ptr(),
            command_parameters.len(),
            data.as_mut_ptr(),
            data.len(),
        )
    }
}

unsafe impl Sync for GenericDrive {}
unsafe impl Send for GenericDrive {}
