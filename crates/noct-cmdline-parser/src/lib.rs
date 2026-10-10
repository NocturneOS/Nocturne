#![no_std]

use core::str;

use alloc::{
    collections::BTreeMap,
    string::String,
    vec::Vec,
};

extern crate alloc;

pub struct CmdlineParser {
    cmdline: String,
}

impl CmdlineParser {
    pub const fn new(cmdline: String) -> Self {
        Self { cmdline }
    }

    fn parse_name(&self) -> Option<String> {
        todo!()
    }

    fn parse_value(&self) -> Option<String> {
        todo!()
    }

    pub fn parse(&self) -> Cmdline {
        todo!()
    }
}

#[derive(Debug)]
pub struct Cmdline {
    stems: BTreeMap<String, String>,
}

impl Cmdline {
    pub fn get_str(&self, key: &str) -> Option<&String> {
        self.stems.get(key)
    }

    pub fn get_usize(&self, key: &str) -> Option<Result<usize, <usize as str::FromStr>::Err>> {
        self.stems.get(key).map(|x| x.parse::<usize>())
    }

    pub fn get_isize(&self, key: &str) -> Option<Result<isize, <isize as str::FromStr>::Err>> {
        self.stems.get(key).map(|x| x.parse::<isize>())
    }

    // TODO: Specify normal E type for Result<T, E>
    pub fn get_array(&self, key: &str) -> Option<Result<Vec<&str>, ()>> {
        self.stems
            .get(key)
            .map(|x| Ok(x.split(',').collect::<Vec<_>>()))
    }
}
