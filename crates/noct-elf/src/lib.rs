#![no_std]

extern crate alloc;

pub mod load;

use crate::load::LoadedSegments;

#[derive(Debug)]
pub struct ProgramImage {
    pub loaded_segments: LoadedSegments,
}

impl ProgramImage {
    pub fn new() -> Self {
        Self {
            loaded_segments: LoadedSegments::new(),
        }
    }
}
