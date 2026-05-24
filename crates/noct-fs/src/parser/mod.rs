use alloc::{borrow::ToOwned, string::String, vec::Vec};

#[cfg(test)]
pub mod tests;

/// A structure that holds everything to locate entities across filesystems and disks.
pub struct PathInfo {
    disk_id: String,
    path: String
}

impl PathInfo {
    pub fn into_string(self) -> String {
        self.disk_id + ":" + &self.path
    }

    pub fn disk_id(&self) -> &str {
        &self.disk_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// A builder structure for PathParser
pub struct PathParserBuilder {
    cwd: Option<String>
}

impl PathParserBuilder {
    pub fn new() -> PathParserBuilder {
        Self::default()
    }

    pub fn cwd(mut self, cwd: String) -> PathParserBuilder {
        // If provided CWD is not empty, set it.
        if !cwd.trim().is_empty() {
            self.cwd = cwd.into();
        }

        self
    }

    pub fn build(self) -> PathParser {
        PathParser { builder_data: self }
    }
}

impl Default for PathParserBuilder {
    fn default() -> Self {
        Self { cwd: Default::default() }
    }
}

pub struct PathParser {
    builder_data: PathParserBuilder
}

impl PathParser {
    /// Parses path.
    // Path format: `disk0.1:/Photos/DC0000/IMG_0001.jpg`
    //               ------- ---------------------------
    // Disk ID (DiskMan) -^          ^- Path itself
    pub fn parse(&self, path: &str) -> Option<PathInfo> {
        // If absolute path is passed, just parse it and return its info!
        if let Some((disk_id, path)) = Self::parse_absolute_path(path) {
            return Some(PathInfo {
                disk_id: disk_id.to_owned(),
                path: String::from("/") + &Self::canonicalize(path),
            })
        }

        // Now, code deals with relative paths.

        // It's a problem if CWD is not passed, because we can't get full path.
        if self.builder_data.cwd.is_none() {
            return None;
        }

        let full_path = self.builder_data.cwd.clone().unwrap() + "/" + path;

        // Parse full path now.
        let Some((disk_id, path)) = full_path.split_once(':') else {
            return None;
        };

        let canonicalized = Self::canonicalize(path);

        Some(PathInfo {
            disk_id: disk_id.to_owned(),
            path: "/".to_owned() + &canonicalized
        })
    }

    fn canonicalize(path: &str) -> String {
        if path.trim().is_empty() {
            return String::new();
        }

        let mut stems: Vec<&str> = Vec::new();

        for i in path.split('/') {
            let trimmed = i.trim();

            if matches!(trimmed, "" | ".") {
                continue;
            }

            if trimmed == ".." {
                stems.pop();
                continue;
            }

            stems.push(trimmed);
        }

        stems.join("/").trim_end_matches('/').to_owned()
    }

    fn parse_absolute_path(path: &str) -> Option<(&str, &str)> {
        // Ok: disk_id:path
        // Note: `path` stems can contain ':', so do `split_once` instead of ordinary `split`
        let Some((disk_id, path)) = path.split_once(':') else {
            return None;
        };

        // Not ok: ../.././disk_id:/path
        if disk_id.contains('/') {
            return None;
        }

        Some((disk_id, path))
    }
}
