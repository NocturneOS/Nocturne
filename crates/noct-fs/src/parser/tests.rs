use alloc::{borrow::ToOwned, string::String};

use crate::parser::{PathParser, PathParserBuilder};

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
pub fn resolve_absolute_path() {
    assert_eq!(
        PathParser::resolve("disk0:/a/../b", "disk1:/x").unwrap(),
        "disk0:/b"
    );
}

#[test]
pub fn resolve_path_relative_to_disk_root() {
    assert_eq!(
        PathParser::resolve("/a/./b", "disk0:/home/me").unwrap(),
        "disk0:/a/b"
    );

    assert_eq!(PathParser::resolve("/", "disk0:/home/me").unwrap(), "disk0:/");
}

#[test]
pub fn resolve_relative_path() {
    assert_eq!(
        PathParser::resolve("../a/b", "disk0:/home/me").unwrap(),
        "disk0:/home/a/b"
    );

    assert_eq!(PathParser::resolve(".", "disk0:/home/me").unwrap(), "disk0:/home/me");
}

#[test]
pub fn resolve_never_escapes_disk_root() {
    assert_eq!(
        PathParser::resolve("../../../a", "disk0:/").unwrap(),
        "disk0:/a"
    );
}

#[test]
pub fn resolve_rejects_empty_path() {
    assert!(PathParser::resolve("", "disk0:/").is_none());
    assert!(PathParser::resolve("   ", "disk0:/").is_none());
}

#[test]
pub fn resolve_requires_disk_id_in_cwd() {
    assert!(PathParser::resolve("/a", "no-disk-id").is_none());
    assert!(PathParser::resolve("a", "").is_none());
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