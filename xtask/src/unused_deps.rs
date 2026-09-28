use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
    resolve: Resolve,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    manifest_path: String,
    dependencies: Vec<Dependency>,
    features: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct Dependency {
    name: String,
    rename: Option<String>,
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<NodeDep>,
}

#[derive(Deserialize)]
struct NodeDep {
    name: String,
    pkg: String,
    dep_kinds: Vec<DepKind>,
}

#[derive(Deserialize)]
struct DepKind {
    kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Finding {
    Unused { package: String, dependency: String },
    TestOnly { package: String, dependency: String },
}

impl Finding {
    pub(crate) fn render(&self) -> String {
        match self {
            Self::Unused {
                package,
                dependency,
            } => format!(
                "{package} declares `{dependency}` in [dependencies], but no source, build script, \
                 test or feature uses it; remove it"
            ),
            Self::TestOnly {
                package,
                dependency,
            } => format!(
                "{package} declares `{dependency}` in [dependencies], but only its tests, benches or \
                 examples use it; move it to [dev-dependencies]"
            ),
        }
    }
}

pub(crate) fn find(root: &Path) -> Result<Vec<Finding>> {
    let output: std::process::Output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
        .wrap_err("spawning cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).wrap_err("parsing cargo metadata json")?;
    let members: BTreeSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let packages: BTreeMap<&str, &Package> = metadata
        .packages
        .iter()
        .map(|package: &Package| (package.id.as_str(), package))
        .collect();
    let mut findings: Vec<Finding> = Vec::new();
    for node in &metadata.resolve.nodes {
        if !members.contains(node.id.as_str()) {
            continue;
        }
        let Some(package) = packages.get(node.id.as_str()) else {
            continue;
        };
        let crate_dir: PathBuf = Path::new(&package.manifest_path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let library_text: String = sources(&crate_dir, &["src"], &["build.rs"])?;
        let test_text: String = sources(&crate_dir, &["tests", "benches", "examples"], &[])?;
        let forwarded: BTreeSet<&str> = forwarded_keys(package);
        for dep in &node.deps {
            let normal: bool = dep
                .dep_kinds
                .iter()
                .any(|kind: &DepKind| kind.kind.is_none());
            if !normal {
                continue;
            }
            let Some(key) = manifest_key(package, &packages, dep) else {
                continue;
            };
            if forwarded.contains(key.as_str()) {
                continue;
            }
            if mentions(&library_text, &dep.name) {
                continue;
            }
            let finding: Finding = if mentions(&test_text, &dep.name) {
                Finding::TestOnly {
                    package: package.name.clone(),
                    dependency: key,
                }
            } else {
                Finding::Unused {
                    package: package.name.clone(),
                    dependency: key,
                }
            };
            findings.push(finding);
        }
    }
    findings.sort();
    Ok(findings)
}

fn manifest_key(
    package: &Package,
    packages: &BTreeMap<&str, &Package>,
    dep: &NodeDep,
) -> Option<String> {
    let target: &str = packages.get(dep.pkg.as_str())?.name.as_str();
    package
        .dependencies
        .iter()
        .filter(|declared: &&Dependency| declared.kind.is_none())
        .find(|declared: &&Dependency| {
            declared.name == target
                && declared
                    .rename
                    .as_deref()
                    .is_none_or(|rename: &str| rename.replace('-', "_") == dep.name)
        })
        .map(|declared: &Dependency| {
            declared
                .rename
                .clone()
                .unwrap_or_else(|| declared.name.clone())
        })
}

fn forwarded_keys(package: &Package) -> BTreeSet<&str> {
    package
        .features
        .values()
        .flatten()
        .filter_map(|value: &String| {
            value.strip_prefix("dep:").or_else(|| {
                value
                    .split_once('/')
                    .map(|(key, _)| key.trim_end_matches('?'))
            })
        })
        .collect()
}

pub(crate) fn mentions(text: &str, crate_name: &str) -> bool {
    let bytes: &[u8] = text.as_bytes();
    let mut from: usize = 0;
    while let Some(found) = text[from..].find(crate_name) {
        let start: usize = from + found;
        let end: usize = start + crate_name.len();
        from = end;
        let before_ok: bool = start == 0
            || !bytes
                .get(start - 1)
                .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_');
        if !before_ok {
            continue;
        }
        let rest: &str = &text[end..];
        if rest.starts_with("::") || rest.starts_with('!') {
            return true;
        }
        let prefix: &str = text[..start].trim_end();
        if prefix.ends_with("use") || prefix.ends_with("extern crate") {
            return true;
        }
    }
    false
}

fn sources(crate_dir: &Path, dirs: &[&str], files: &[&str]) -> Result<String> {
    let mut text: String = String::new();
    for file in files {
        let path: PathBuf = crate_dir.join(file);
        if path.is_file() {
            text.push_str(&read_text_bounded(&path, MAX_SOURCE_BYTES)?);
            text.push('\n');
        }
    }
    for dir in dirs {
        let mut stack: Vec<PathBuf> = vec![crate_dir.join(dir)];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path: PathBuf = entry.path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|name| name == "fixtures") {
                        continue;
                    }
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    text.push_str(&read_text_bounded(&path, MAX_SOURCE_BYTES)?);
                    text.push('\n');
                }
            }
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::mentions;

    #[test]
    fn a_crate_counts_as_used_only_through_a_path_use_or_macro() {
        assert!(mentions("let x = serde_json::to_string(&v);", "serde_json"));
        assert!(mentions("use md5::{Digest, Md5};", "md5"));
        assert!(mentions("extern crate alloc_crate;", "alloc_crate"));
        assert!(mentions("anyhow!(\"x\")", "anyhow"));
        assert!(!mentions("let bytes = 3;", "bytes"));
        assert!(!mentions("my_serde_json::x", "serde_json"));
        assert!(!mentions("// serde_json is not used", "serde_json"));
    }
}
