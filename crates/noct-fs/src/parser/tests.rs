use alloc::{borrow::ToOwned, string::String};

use crate::parser::PathParserBuilder;

macro_rules! make_test {
    ($source:tt,$disk_id_:tt,$path_:tt) => {
        let parser = PathParserBuilder::new().build();

        let Some(result) = parser.parse($source) else {
            panic!("Expected valid path")
        };

        assert_eq!(result.disk_id, $disk_id_);
        assert_eq!(result.path, $path_);
    }
}

#[test]
pub fn absolute_path_with_root_path() {
    make_test!("disk0:/", "disk0", "/");
}

#[test]
pub fn absolute_path_with_a_lot_of_roots() {
    make_test!("disk0://////", "disk0", "/");
}

#[test]
pub fn absolute_path_without_root() {
    make_test!("disk0:", "disk0", "/");
}

#[test]
pub fn only_disk_id() {
    let parser = PathParserBuilder::new().build();

    assert!(parser.parse("disk0").is_none());
}

#[test]
pub fn absolute_path_with_simple_path() {
    make_test!("disk0:/abc/def/123", "disk0", "/abc/def/123");
    make_test!("disk0:/abc/def/123/", "disk0", "/abc/def/123");
}

#[test]
pub fn invalid_disk_name() {
    let parser = PathParserBuilder::new().build();

    assert!(parser.parse("../disk0:/abc/123").is_none());
    assert!(parser.parse("/disk0:/abc/123").is_none());
    assert!(parser.parse("disk0/../1:/abc/123").is_none());
}

#[test]
pub fn absolute_path_with_complex_path() {
    make_test!("disk0:/abc/../def///123/", "disk0", "/def/123");
    make_test!("disk0:/abc/../../..///123/", "disk0", "/123");

    // Note: The colon (:) symbol is allowed in paths.
    make_test!("disk0:/abc:/././.123/", "disk0", "/abc:/.123");
}

#[test]
pub fn disk_with_partition_and_any_path() {
    make_test!("disk0.1:/a/b/c/", "disk0.1", "/a/b/c");
    make_test!("disk0.1.2:/a/b/c/", "disk0.1.2", "/a/b/c");
    make_test!("disk0.1.2.3:/a/b/c/", "disk0.1.2.3", "/a/b/c");
}

#[test]
pub fn pathinfo_into_string() {
    fn make(cwd: &str, path: &str) -> String {
        let parser = PathParserBuilder::new().cwd(cwd.to_owned()).build();

        let result = parser.parse(path).unwrap().into_string();

        result
    }

    assert_eq!(make("disk0:/user/me/", "a/b/c"), "disk0:/user/me/a/b/c");
    assert_eq!(make("disk0:/user/me/..", "a/b/c"), "disk0:/user/a/b/c");
    assert_eq!(make("disk0:/../../../user/me/../../", "a/b/./../c"), "disk0:/a/c");
    assert_eq!(make("disk0:/user/me/..", "a/b/./././c"), "disk0:/user/a/b/c");
}