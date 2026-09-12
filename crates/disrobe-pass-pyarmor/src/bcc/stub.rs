use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StubInfo {
    pub(crate) module: Option<String>,
    pub(crate) py_path: Option<String>,
    pub(crate) serial: Option<String>,
    pub(crate) has_pyarmor_call: bool,
    pub(crate) has_assert_armored: bool,
}

const MAX_PACKAGE_DEPTH: usize = 64;

pub(crate) fn analyze_stub(wrapper_text: &str, wrapper_path: &Path) -> StubInfo {
    let serial: Option<String> = parse_serial(wrapper_text);
    let has_pyarmor_call: bool = wrapper_text.contains("__pyarmor__(");
    let has_assert_armored: bool = wrapper_text.contains("__assert_armored__(");
    let (module, py_path): (Option<String>, Option<String>) = derive_module_path(wrapper_path);
    StubInfo {
        module,
        py_path,
        serial,
        has_pyarmor_call,
        has_assert_armored,
    }
}

fn parse_serial(text: &str) -> Option<String> {
    let marker: &str = "pyarmor_runtime_";
    let start: usize = text.find(marker)? + marker.len();
    let rest: &[u8] = text.as_bytes().get(start..)?;
    let end: usize = rest
        .iter()
        .position(|b: &u8| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn derive_module_path(wrapper_path: &Path) -> (Option<String>, Option<String>) {
    let Some(stem): Option<&str> = wrapper_path.file_stem().and_then(|s| s.to_str()) else {
        return (None, None);
    };
    let is_init: bool = stem == "__init__";
    let mut segments: Vec<String> = Vec::new();
    let mut dir: Option<&Path> = wrapper_path.parent();
    let mut depth: usize = 0;
    while let Some(current) = dir {
        if depth >= MAX_PACKAGE_DEPTH || !is_package_dir(current) {
            break;
        }
        let Some(name): Option<&str> = current.file_name().and_then(|s| s.to_str()) else {
            break;
        };
        segments.push(name.to_owned());
        dir = current.parent();
        depth += 1;
    }
    segments.reverse();
    if !is_init {
        segments.push(stem.to_owned());
    }
    if segments.is_empty() {
        return (None, None);
    }
    let module: String = segments.join(".");
    let py_path: String = if is_init {
        format!("{}/__init__.py", segments.join("/"))
    } else {
        format!("{}.py", segments.join("/"))
    };
    (Some(module), Some(py_path))
}

fn is_package_dir(dir: &Path) -> bool {
    dir.join("__init__.py").is_file() || dir.join("__init__.pyc").is_file()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn serial_and_markers_are_parsed() {
        let text: &str = "from pyarmor_runtime_015009 import __pyarmor__\n__pyarmor__(__name__, __file__, b'PY')\n";
        assert_eq!(parse_serial(text), Some("015009".to_owned()));
        assert!(text.contains("__pyarmor__("));
    }

    #[test]
    fn assert_armored_marker_detected() {
        let info: StubInfo = analyze_stub(
            "__assert_armored__(__name__)\n",
            Path::new("nowhere/mod.py"),
        );
        assert!(info.has_assert_armored);
        assert!(!info.has_pyarmor_call);
        assert_eq!(info.serial, None);
    }

    #[test]
    fn missing_serial_is_none() {
        assert_eq!(parse_serial("import os\n"), None);
    }
}
