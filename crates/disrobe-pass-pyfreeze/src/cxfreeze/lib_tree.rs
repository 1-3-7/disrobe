use std::path::{Path, PathBuf};

use crate::common::pyc::{PycFingerprint, fingerprint};
use crate::error::{Error, Result};
use crate::read_file_prefix;
use crate::recover::looks_like_bytecode;

pub const MAX_TREE_DEPTH: usize = 32;
pub const MAX_TREE_ENTRIES: usize = 200_000;

const PYC_HEADER_PROBE_BYTES: u64 = 16;

#[derive(Debug, Clone)]
pub struct LibTreeEntry {
    pub relative_name: String,
    pub disk_path: PathBuf,
    pub size: u64,
    pub python_version: Option<(u8, u8)>,
}

#[derive(Debug, Clone, Default)]
pub struct LibTreeWalk {
    pub entries: Vec<LibTreeEntry>,
    pub symlinks_skipped: usize,
}

pub fn walk(root: &Path, excluded: &[&Path]) -> Result<LibTreeWalk> {
    let mut walk: LibTreeWalk = LibTreeWalk::default();
    if !root.is_dir() {
        return Ok(walk);
    }
    visit(root, root, excluded, 0, &mut walk)?;
    walk.entries
        .sort_by(|left: &LibTreeEntry, right: &LibTreeEntry| {
            left.relative_name.cmp(&right.relative_name)
        });
    Ok(walk)
}

fn visit(
    root: &Path,
    current: &Path,
    excluded: &[&Path],
    depth: usize,
    walk: &mut LibTreeWalk,
) -> Result<()> {
    if depth >= MAX_TREE_DEPTH {
        return Err(Error::QuotaExceeded {
            entry: relative_name(root, current),
            reason: format!("cx_Freeze library tree nesting exceeds depth cap {MAX_TREE_DEPTH}"),
        });
    }
    let read: std::fs::ReadDir = std::fs::read_dir(current)?;
    for item in read {
        let entry: std::fs::DirEntry = item?;
        let path: PathBuf = entry.path();
        if excluded.iter().any(|skip: &&Path| path == **skip) {
            continue;
        }
        let file_type: std::fs::FileType = entry.file_type()?;
        if file_type.is_symlink() {
            walk.symlinks_skipped = walk.symlinks_skipped.saturating_add(1);
            continue;
        }
        if file_type.is_dir() {
            visit(root, &path, excluded, depth.saturating_add(1), walk)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if walk.entries.len() >= MAX_TREE_ENTRIES {
            return Err(Error::QuotaExceeded {
                entry: relative_name(root, &path),
                reason: format!("cx_Freeze library tree file count exceeds cap {MAX_TREE_ENTRIES}"),
            });
        }
        let metadata: std::fs::Metadata = entry.metadata()?;
        let name: String = relative_name(root, &path);
        let python_version: Option<(u8, u8)> = if looks_like_bytecode(&name) {
            probe_python_version(&path)
        } else {
            None
        };
        walk.entries.push(LibTreeEntry {
            relative_name: name,
            disk_path: path,
            size: metadata.len(),
            python_version,
        });
    }
    Ok(())
}

fn relative_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative: &Path| relative.to_string_lossy().replace('\\', "/"),
    )
}

fn probe_python_version(path: &Path) -> Option<(u8, u8)> {
    let header: Vec<u8> = read_file_prefix(path, PYC_HEADER_PROBE_BYTES).ok()?;
    let print: PycFingerprint = fingerprint(&header)?;
    Some((print.python_major, print.python_minor))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> disrobe_core::scratch::ScratchDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0x1CE0_0000);
        let purpose: String = format!(
            "disrobe-cxfreeze-tree-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
    }

    fn write(root: &Path, relative: &str, body: &[u8]) -> PathBuf {
        let path: PathBuf = root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, body).expect("write file");
        path
    }

    #[test]
    fn walk_returns_a_deterministic_sorted_relative_name_sequence() {
        let dir: disrobe_core::scratch::ScratchDir = scratch("sorted");
        let root: &Path = dir.path();
        for relative in [
            "zeta.pyc",
            "alpha/__init__.pyc",
            "alpha/beta/gamma.pyc",
            "alpha/aaa.pyc",
            "mid.txt",
        ] {
            write(root, relative, b"body");
        }
        let first: LibTreeWalk = walk(root, &[]).expect("walk");
        let second: LibTreeWalk = walk(root, &[]).expect("walk again");
        let names: Vec<String> = first
            .entries
            .iter()
            .map(|entry: &LibTreeEntry| entry.relative_name.clone())
            .collect();
        assert_eq!(
            names,
            vec![
                "alpha/__init__.pyc".to_owned(),
                "alpha/aaa.pyc".to_owned(),
                "alpha/beta/gamma.pyc".to_owned(),
                "mid.txt".to_owned(),
                "zeta.pyc".to_owned(),
            ],
            "the walk must publish one sorted forward-slash name sequence"
        );
        let repeat: Vec<String> = second
            .entries
            .iter()
            .map(|entry: &LibTreeEntry| entry.relative_name.clone())
            .collect();
        assert_eq!(names, repeat, "two walks of one tree must agree");
    }

    #[test]
    fn walk_skips_every_excluded_path() {
        let dir: disrobe_core::scratch::ScratchDir = scratch("exclude");
        let root: &Path = dir.path();
        let zip: PathBuf = write(root, "library.zip", b"PK\x05\x06");
        write(root, "pkg/mod.pyc", b"body");
        let walk: LibTreeWalk = walk(root, &[zip.as_path()]).expect("walk");
        let names: Vec<&str> = walk
            .entries
            .iter()
            .map(|entry: &LibTreeEntry| entry.relative_name.as_str())
            .collect();
        assert_eq!(names, vec!["pkg/mod.pyc"]);
    }

    #[test]
    fn walk_refuses_a_tree_deeper_than_the_depth_cap() {
        let dir: disrobe_core::scratch::ScratchDir = scratch("deep");
        let root: &Path = dir.path();
        let mut relative: String = String::new();
        for level in 0..=MAX_TREE_DEPTH {
            use std::fmt::Write as _;
            write!(relative, "d{level}/").expect("write to a string cannot fail");
        }
        relative.push_str("leaf.pyc");
        write(root, &relative, b"body");
        let error: Error = walk(root, &[]).expect_err("a tree past the depth cap must be refused");
        let Error::QuotaExceeded { reason, .. } = error else {
            panic!("depth overflow must be a typed quota refusal, got {error:?}");
        };
        assert!(
            reason.contains("depth cap"),
            "the refusal must name the depth cap; got {reason}"
        );
    }

    #[test]
    fn walk_records_the_python_version_of_a_real_pyc_header() {
        let dir: disrobe_core::scratch::ScratchDir = scratch("version");
        let root: &Path = dir.path();
        let magic: u32 = disrobe_py_marshal::magic_for(disrobe_py_marshal::PyVersion::PY312)
            .expect("known magic");
        let mut body: Vec<u8> = magic.to_le_bytes().to_vec();
        body.resize(64, 0);
        write(root, "pkg/mod.pyc", &body);
        write(root, "pkg/data.bin", &body);
        let walk: LibTreeWalk = walk(root, &[]).expect("walk");
        let module: &LibTreeEntry = walk
            .entries
            .iter()
            .find(|entry: &&LibTreeEntry| entry.relative_name == "pkg/mod.pyc")
            .expect("the bytecode file must be walked");
        assert_eq!(module.python_version, Some((3, 12)));
        assert_eq!(module.size, 64);
        let data: &LibTreeEntry = walk
            .entries
            .iter()
            .find(|entry: &&LibTreeEntry| entry.relative_name == "pkg/data.bin")
            .expect("the resource file must be walked");
        assert_eq!(
            data.python_version, None,
            "a file that is not bytecode carries no Python version"
        );
    }

    #[test]
    fn walk_of_a_missing_root_is_an_empty_result_not_an_error() {
        let dir: disrobe_core::scratch::ScratchDir = scratch("absent");
        let missing: PathBuf = dir.path().join("no-such-lib");
        let walk: LibTreeWalk = walk(&missing, &[]).expect("an absent root is not a failure");
        assert!(walk.entries.is_empty());
        assert_eq!(walk.symlinks_skipped, 0);
    }
}
