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
}