use alloc::{boxed::Box, vec::Vec};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::Filesystem;

lazy_static! {
    pub static ref STORE: spin::Mutex<Vec<Box<dyn Filesystem>>> =
        Mutex::new(Vec::new());
}

pub fn register_filesystem(fs: Box<dyn Filesystem>) {
    STORE.lock().push(fs);
}