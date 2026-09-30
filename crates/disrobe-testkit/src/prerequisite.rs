use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const OPTIONAL_LIST: &str = "tests/optional.toml";
pub const NOT_MEASURED_DIR: &str = "not-measured";
const MAX_OPTIONAL_LIST_BYTES: u64 = 256 * 1024;
const MAX_RECORD_NAME: usize = 160;
const PLATFORMS: [&str; 3] = ["linux", "macos", "windows"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Available<T> {
    Present(T),
    NotMeasured { record: PathBuf },
}

impl<T> Available<T> {
    #[must_use]
    pub fn present(self) -> Option<T> {
        match self {
            Self::Present(value) => Some(value),
            Self::NotMeasured { .. } => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrerequisiteError {
    #[error(
        "{test} requires {what}, which is missing; install it, or list `{test}` under [optional] in {OPTIONAL_LIST} with the reason CI cannot provide it"
    )]
    Missing { test: String, what: String },
    #[error("no workspace root (a directory holding Cargo.lock) above {}", start.display())]
    NoWorkspace { start: PathBuf },
    #[error("{} is larger than {MAX_OPTIONAL_LIST_BYTES} bytes", path.display())]
    OptionalListTooLarge { path: PathBuf },
    #[error("reading {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{} is not a table of test names to reasons under [optional]: {detail}", path.display())]
    OptionalList { path: PathBuf, detail: String },
    #[error("{} lists `{test}` as optional without a reason", path.display())]
    EmptyReason { path: PathBuf, test: String },
    #[error("writing the not-measured record {}: {source}", path.display())]
    Record {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub fn require<T>(
    test: &str,
    what: &str,
    found: Option<T>,
) -> Result<Available<T>, PrerequisiteError> {
    if let Some(value) = found {
        return Ok(Available::Present(value));
    }
    let start: PathBuf =
        std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(|| PathBuf::from("."), PathBuf::from);
    let root: PathBuf = workspace_root(&start)?;
    let target: PathBuf =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    resolve_missing(&root, &target, test, what)
}

fn workspace_root(start: &Path) -> Result<PathBuf, PrerequisiteError> {
    start
        .ancestors()
        .find(|dir: &&Path| dir.join("Cargo.lock").is_file())
        .map(Path::to_path_buf)
        .ok_or_else(|| PrerequisiteError::NoWorkspace {
            start: start.to_path_buf(),
        })
}

fn resolve_missing<T>(
    root: &Path,
    target: &Path,
    test: &str,
    what: &str,
) -> Result<Available<T>, PrerequisiteError> {
    let optional: BTreeMap<String, String> = optional_tests(&root.join(OPTIONAL_LIST))?;
    let Some(reason): Option<&String> = optional.get(test) else {
        return Err(PrerequisiteError::Missing {
            test: test.to_owned(),
            what: what.to_owned(),
        });
    };
    let directory: PathBuf = target.join(NOT_MEASURED_DIR);
    let record: PathBuf = directory.join(format!("{}.txt", record_name(test)));
    std::fs::create_dir_all(&directory)
        .and_then(|()| {
            std::fs::write(
                &record,
                format!("test = {test}\nmissing = {what}\nreason = {reason}\n"),
            )
        })
        .map_err(|source: std::io::Error| PrerequisiteError::Record {
            path: record.clone(),
            source,
        })?;
    Ok(Available::NotMeasured { record })
}

fn optional_tests(path: &Path) -> Result<BTreeMap<String, String>, PrerequisiteError> {
    let metadata: std::fs::Metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(source) => {
            return Err(PrerequisiteError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.len() > MAX_OPTIONAL_LIST_BYTES {
        return Err(PrerequisiteError::OptionalListTooLarge {
            path: path.to_path_buf(),
        });
    }
    let text: String = std::fs::read_to_string(path).map_err(|source: std::io::Error| {
        PrerequisiteError::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    parse_optional(path, &text, std::env::consts::OS)
}

fn parse_optional(
    path: &Path,
    text: &str,
    os: &str,
) -> Result<BTreeMap<String, String>, PrerequisiteError> {
    let table: toml::Table = text
        .parse::<toml::Table>()
        .map_err(|error: toml::de::Error| malformed(path, error.to_string()))?;
    if let Some(extra) = table
        .keys()
        .find(|key: &&String| key.as_str() != "optional")
    {
        return Err(malformed(path, format!("unexpected key `{extra}`")));
    }
    let entries: &toml::Table = match table.get("optional") {
        None => return Ok(BTreeMap::new()),
        Some(value) => value
            .as_table()
            .ok_or_else(|| malformed(path, "[optional] is not a table".to_owned()))?,
    };
    let mut optional: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in entries {
        if let Some(platform) = value.as_table() {
            if !PLATFORMS.contains(&key.as_str()) {
                return Err(malformed(
                    path,
                    format!("[optional.{key}] names no platform; use one of {PLATFORMS:?}"),
                ));
            }
            if key == os {
                for (test, reason) in platform {
                    insert_reason(path, &mut optional, test, reason)?;
                }
            }
            continue;
        }
        insert_reason(path, &mut optional, key, value)?;
    }
    Ok(optional)
}

fn insert_reason(
    path: &Path,
    optional: &mut BTreeMap<String, String>,
    test: &str,
    reason: &toml::Value,
) -> Result<(), PrerequisiteError> {
    let reason: &str = reason
        .as_str()
        .ok_or_else(|| malformed(path, format!("the reason for `{test}` is not a string")))?
        .trim();
    if reason.is_empty() {
        return Err(PrerequisiteError::EmptyReason {
            path: path.to_path_buf(),
            test: test.to_owned(),
        });
    }
    optional.insert(test.to_owned(), reason.to_owned());
    Ok(())
}

fn malformed(path: &Path, detail: String) -> PrerequisiteError {
    PrerequisiteError::OptionalList {
        path: path.to_path_buf(),
        detail,
    }
}

fn record_name(test: &str) -> String {
    test.chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(MAX_RECORD_NAME)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Available, OPTIONAL_LIST, PrerequisiteError, parse_optional, record_name, resolve_missing,
    };
    use std::path::{Path, PathBuf};

    fn workspace(optional: Option<&str>) -> Result<tempfile::TempDir, std::io::Error> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        std::fs::write(root.path().join("Cargo.lock"), "")?;
        if let Some(text) = optional {
            std::fs::create_dir_all(root.path().join("tests"))?;
            std::fs::write(root.path().join(OPTIONAL_LIST), text)?;
        }
        Ok(root)
    }

    #[test]
    fn a_missing_required_tool_fails_and_names_the_tool() -> Result<(), std::io::Error> {
        let root: tempfile::TempDir = workspace(None)?;
        let target: PathBuf = root.path().join("target");
        let outcome: Result<Available<()>, PrerequisiteError> =
            resolve_missing(root.path(), &target, "crate::suite::case", "luac 5.5");
        let Err(error) = outcome else {
            return Err(std::io::Error::other("a required miss must fail"));
        };
        let message: String = error.to_string();
        assert!(
            message.contains("crate::suite::case") && message.contains("luac 5.5"),
            "{message}"
        );
        assert!(
            !target.exists(),
            "a required miss must not write a not-measured record"
        );
        Ok(())
    }

    #[test]
    fn an_optional_miss_writes_a_not_measured_record() -> Result<(), Box<dyn std::error::Error>> {
        let root: tempfile::TempDir = workspace(Some(
            "[optional]\n\"crate::suite::case\" = \"CI has no Lua 5.5\"\n",
        ))?;
        let target: PathBuf = root.path().join("target");
        let outcome: Available<()> =
            resolve_missing(root.path(), &target, "crate::suite::case", "luac 5.5")?;
        let Available::NotMeasured { record } = outcome else {
            return Err("an optional miss must be recorded as not measured".into());
        };
        let text: String = std::fs::read_to_string(&record)?;
        assert!(text.contains("missing = luac 5.5") && text.contains("reason = CI has no Lua 5.5"));
        assert!(record.starts_with(target.join("not-measured")));
        Ok(())
    }

    #[test]
    fn an_optional_entry_without_a_reason_or_outside_the_table_is_rejected() {
        let path: &Path = Path::new(OPTIONAL_LIST);
        assert!(matches!(
            parse_optional(path, "[optional]\n\"a::b\" = \"  \"\n", "linux"),
            Err(PrerequisiteError::EmptyReason { .. })
        ));
        assert!(matches!(
            parse_optional(path, "[skip]\n\"a::b\" = \"reason\"\n", "linux"),
            Err(PrerequisiteError::OptionalList { .. })
        ));
        assert!(matches!(
            parse_optional(path, "optional = 1\n", "linux"),
            Err(PrerequisiteError::OptionalList { .. })
        ));
    }

    #[test]
    fn a_platform_section_applies_only_on_that_platform() -> Result<(), PrerequisiteError> {
        let path: &Path = Path::new(OPTIONAL_LIST);
        let text: &str = "[optional]\n\"a::all\" = \"everywhere\"\n[optional.windows]\n\"a::gnu\" = \"CI provides gcc only on Linux\"\n";
        let windows: std::collections::BTreeMap<String, String> =
            parse_optional(path, text, "windows")?;
        let linux: std::collections::BTreeMap<String, String> =
            parse_optional(path, text, "linux")?;
        assert!(windows.contains_key("a::all") && windows.contains_key("a::gnu"));
        assert!(linux.contains_key("a::all") && !linux.contains_key("a::gnu"));
        assert!(matches!(
            parse_optional(path, "[optional.solaris]\n\"a::b\" = \"r\"\n", "linux"),
            Err(PrerequisiteError::OptionalList { .. })
        ));
        Ok(())
    }

    #[test]
    fn record_names_keep_only_portable_characters() {
        assert_eq!(record_name("crate::suite/case 1"), "crate__suite_case_1");
    }
}
