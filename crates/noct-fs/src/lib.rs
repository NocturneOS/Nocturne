#![no_std]

use alloc::vec::Vec;
use noct_fsman::{entity::{self, EntityType}, handles::file::{FileHandle, FileOpenMode}};
use noct_io::{Read, error::Error};

extern crate alloc;

pub mod parser;

// Important note: Only absolute paths supported when developing kernel.
// When interacting with user programs via syscalls like `open`, relative paths are supported.

pub fn open_file(path: &str, mode: FileOpenMode) -> noct_io::Result<FileHandle> {
    let info = parser::PathParserBuilder::new()
        .build()
        .parse(path)
        .ok_or(noct_io::error::Error::InvalidPath)?;

    let handle = noct_fsman::mount::get_handle(info.disk_id())
        .ok_or(noct_io::error::Error::InvalidHandle)?;

    handle.open(info.path(), mode)
}

pub fn info(path: &str) -> noct_io::Result<entity::EntityInfo> {
    let info = parser::PathParserBuilder::new()
        .build()
        .parse(path)
        .ok_or(noct_io::error::Error::InvalidPath)?;

    let handle = noct_fsman::mount::get_handle(info.disk_id())
        .ok_or(noct_io::error::Error::InvalidHandle)?;

    handle.info(info.path())
}

pub fn read_file(path: &str) -> noct_io::Result<Vec<u8>> {
    let info = info(path)?;

    if info.entity_type != EntityType::File {
        return Err(Error::InvalidEntity);
    }

    let mut buffer: Vec<u8> = alloc::vec![0u8; info.size as _];

    let mut handle = open_file(path, FileOpenMode::Read)?;

    handle.read(&mut buffer)?;

    Ok(buffer)
}
