use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use eyre::{Result, WrapErr, bail};

use crate::artifact_map;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PathKind {
    Legal,
    Generated,
    Fixture,
    Test,
    Doc,
    Config,
    Source,
}

impl PathKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Legal => "legal",
            Self::Generated => "generated",
            Self::Fixture => "fixture",
            Self::Test => "test",
            Self::Doc => "doc",
            Self::Config => "config",
            Self::Source => "source",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Rule {
    Prefix(&'static str),
    Contains(&'static str),
    NameStartsWith(&'static str),
    Name(&'static str),
    Extension(&'static str),
}

impl Rule {
    fn matches(self, path: &str) -> bool {
        let name: &str = path.rsplit('/').next().unwrap_or(path);
        match self {
            Self::Prefix(prefix) => path.starts_with(prefix),
            Self::Contains(fragment) => path.contains(fragment),
            Self::NameStartsWith(start) => name.starts_with(start),
            Self::Name(exact) => name == exact,
            Self::Extension(extension) => name
                .rsplit_once('.')
                .is_some_and(|(_, found): (&str, &str)| found.eq_ignore_ascii_case(extension)),
        }
    }
}

const RULES: &[(PathKind, Rule)] = &[
    (PathKind::Legal, Rule::NameStartsWith("LICENSE")),
    (PathKind::Legal, Rule::NameStartsWith("NOTICE")),
    (PathKind::Legal, Rule::NameStartsWith("COPYING")),
    (PathKind::Fixture, Rule::Prefix("corpus/")),
    (
        PathKind::Fixture,
        Rule::Prefix("playground/public/samples/"),
    ),
    (PathKind::Fixture, Rule::Contains("/tests/fixtures/")),
    (PathKind::Fixture, Rule::Contains("/tests/golden/")),
    (PathKind::Fixture, Rule::Contains("/tests/data/")),
    (PathKind::Fixture, Rule::Contains("/corpus/")),
    (PathKind::Fixture, Rule::Contains("/snapshots/")),
    (PathKind::Test, Rule::Contains("/tests/")),
    (PathKind::Test, Rule::Prefix("fuzz/")),
    (PathKind::Test, Rule::Extension("proptest-regressions")),
    (PathKind::Doc, Rule::Prefix("docs/")),
    (PathKind::Doc, Rule::Prefix("evidence/")),
    (PathKind::Doc, Rule::Extension("md")),
    (PathKind::Config, Rule::Prefix(".github/")),
    (PathKind::Config, Rule::Prefix(".devcontainer/")),
    (PathKind::Config, Rule::Prefix(".config/")),
    (PathKind::Config, Rule::Prefix(".githooks/")),
    (PathKind::Config, Rule::Prefix("hooks/")),
    (PathKind::Config, Rule::Prefix("xtask/data/")),
    (PathKind::Config, Rule::Name("justfile")),
    (PathKind::Config, Rule::Name(".gitignore")),
    (PathKind::Config, Rule::Name(".gitattributes")),
    (PathKind::Config, Rule::Extension("toml")),
    (PathKind::Config, Rule::Extension("yml")),
    (PathKind::Config, Rule::Extension("yaml")),
    (PathKind::Config, Rule::Extension("lock")),
    (PathKind::Source, Rule::Prefix("crates/")),
    (PathKind::Source, Rule::Prefix("xtask/")),
    (PathKind::Source, Rule::Prefix("benches/")),
    (PathKind::Source, Rule::Prefix("bindings/")),
    (PathKind::Source, Rule::Prefix("editors/")),
    (PathKind::Source, Rule::Prefix("plugins/")),
    (PathKind::Source, Rule::Prefix("playground/")),
    (PathKind::Source, Rule::Prefix("scripts/")),
    (PathKind::Source, Rule::Prefix("schemas/")),
];

pub(crate) fn classify(path: &str) -> Option<PathKind> {
    if RULES[..3]
        .iter()
        .any(|(_, rule): &(PathKind, Rule)| rule.matches(path))
    {
        return Some(PathKind::Legal);
    }
    if artifact_map::is_generated(path) {
        return Some(PathKind::Generated);
    }
    RULES
        .iter()
        .find(|(_, rule): &&(PathKind, Rule)| rule.matches(path))
        .map(|(kind, _): &(PathKind, Rule)| *kind)
}

pub(crate) struct Inventory {
    pub(crate) kinds: BTreeMap<String, PathKind>,
    pub(crate) unclassified: Vec<String>,
    pub(crate) ignored_but_tracked: Vec<String>,
}

pub(crate) fn inventory(root: &Path) -> Result<Inventory> {
    let tracked: Vec<String> = git_paths(root, &["ls-files", "-z"])?;
    let ignored_but_tracked: Vec<String> =
        git_paths(root, &["ls-files", "-ci", "--exclude-standard", "-z"])?;
    let mut kinds: BTreeMap<String, PathKind> = BTreeMap::new();
    let mut unclassified: Vec<String> = Vec::new();
    for path in tracked {
        match classify(&path) {
            Some(kind) => {
                kinds.insert(path, kind);
            }
            None => unclassified.push(path),
        }
    }
    Ok(Inventory {
        kinds,
        unclassified,
        ignored_but_tracked,
    })
}

fn git_paths(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let output: std::process::Output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .wrap_err_with(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!("git {} exited with {}", args.join(" "), output.status);
    }
    let listing: String = String::from_utf8(output.stdout).wrap_err("git output is not utf-8")?;
    Ok(listing
        .split('\0')
        .filter(|path: &&str| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let inventory: Inventory = inventory(root)?;
    if !inventory.unclassified.is_empty() || !inventory.ignored_but_tracked.is_empty() {
        bail!(
            "tracked-paths: {} unclassified and {} tracked-but-ignored path(s):\n  {}",
            inventory.unclassified.len(),
            inventory.ignored_but_tracked.len(),
            inventory
                .unclassified
                .iter()
                .chain(&inventory.ignored_but_tracked)
                .map(String::as_str)
                .collect::<Vec<&str>>()
                .join("\n  ")
        );
    }
    let mut out: String = String::new();
    for (path, kind) in &inventory.kinds {
        out.push_str(kind.label());
        out.push('\t');
        out.push_str(path);
        out.push('\n');
    }
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PathKind, classify};

    #[test]
    fn each_kind_is_reached_and_an_unknown_root_file_is_not_classified() {
        let cases: [(&str, Option<PathKind>); 9] = [
            ("corpus/LICENSE", Some(PathKind::Legal)),
            ("docs/errors/README.md", Some(PathKind::Generated)),
            (
                "crates/disrobe-bytes/tests/fixtures/a.bin",
                Some(PathKind::Fixture),
            ),
            ("crates/disrobe-bytes/tests/reader.rs", Some(PathKind::Test)),
            ("docs/src/intro.md", Some(PathKind::Doc)),
            ("crates/disrobe-bytes/Cargo.toml", Some(PathKind::Config)),
            ("crates/disrobe-bytes/src/lib.rs", Some(PathKind::Source)),
            ("README.md", Some(PathKind::Doc)),
            ("stray.bin", None),
        ];
        for (path, expected) in cases {
            assert_eq!(classify(path), expected, "{path}");
        }
    }
}
