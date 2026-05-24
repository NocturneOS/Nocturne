use crate::parser::PathParserBuilder;

#[test]
pub fn absolute_path_with_root_path() {
    let parser = PathParserBuilder::new().build();

    let Some(result) = parser.parse("disk0:/") else {
        panic!("Expected valid path")
    };

    assert_eq!(result.disk_id, "disk0");
    assert_eq!(result.path, "/");
}

#[test]
pub fn absolute_path_with_a_lot_of_roots() {
    let parser = PathParserBuilder::new().build();

    let Some(result) = parser.parse("disk0://///") else {
        panic!("Expected valid path")
    };

    assert_eq!(result.disk_id, "disk0");
    assert_eq!(result.path, "/");
}

#[test]
pub fn absolute_path_without_root() {
    let parser = PathParserBuilder::new().build();

    let Some(result) = parser.parse("disk0:") else {
        panic!("Expected valid path")
    };

    assert_eq!(result.disk_id, "disk0");
    assert_eq!(result.path, "/");
}

#[test]
pub fn only_disk_id() {
    let parser = PathParserBuilder::new().build();

    assert!(parser.parse("disk0").is_none());
}

#[test]
pub fn absolute_path_with_simple_path() {
    let parser = PathParserBuilder::new().build();

    let Some(result) = parser.parse("disk0:/abc/def/123") else {
        panic!("Expected valid path")
    };

    assert_eq!(result.disk_id, "disk0");
    assert_eq!(result.path, "/abc/def/123");
}

#[test]
pub fn absolute_path_with_simple_path_and_trailing_slash() {
    let parser = PathParserBuilder::new().build();

    let Some(result) = parser.parse("disk0:/abc/def/123/") else {
        panic!("Expected valid path")
    };

    assert_eq!(result.disk_id, "disk0");
    assert_eq!(result.path, "/abc/def/123");
}

#[test]
pub fn invalid_disk_name() {
    let parser = PathParserBuilder::new().build();

    assert!(parser.parse("../disk0:/abc/123").is_none());
    assert!(parser.parse("/disk0:/abc/123").is_none());
    assert!(parser.parse("disk0/../1:/abc/123").is_none());
}