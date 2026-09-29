use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::doc_region::{self, Mode, RegionSyntax};
use crate::fileio::read_text_bounded;

const SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- bounds:",
    close: "<!-- /bounds -->",
};
const TABLE_SLUG: &str = "table";
const DOC: &str = "docs/src/input-bounds.md";
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DECLARATION_LINES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Bound {
    crate_name: String,
    file: String,
    name: String,
    ty: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Recursion,
    Work,
    Output,
    Size,
    Count,
    Other,
}

impl Kind {
    fn of(name: &str) -> Self {
        let has = |words: &[&str]| words.iter().any(|word: &&str| name.contains(word));
        if has(&["DEPTH", "RECURS", "NEST"]) {
            Self::Recursion
        } else if has(&["STEP", "WORK", "BUDGET", "FUEL", "OPS", "ITER", "ROUND"]) {
            Self::Work
        } else if has(&["OUTPUT", "RENDER", "EMIT"]) {
            Self::Output
        } else if has(&["BYTE", "SIZE", "LEN", "KIB", "MIB", "GIB"]) {
            Self::Size
        } else if has(&[
            "COUNT", "ENTRIES", "ITEMS", "NODES", "FILES", "MEMBERS", "RECORDS",
        ]) {
            Self::Count
        } else {
            Self::Other
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Recursion => "recursion",
            Self::Work => "work",
            Self::Output => "output",
            Self::Size => "size",
            Self::Count => "count",
            Self::Other => "other",
        }
    }
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let bounds: Vec<Bound> = survey(root)?;
    let rendered: String = render(&bounds);
    let path: PathBuf = root.join(DOC);
    let text: String = doc_region::read_doc(&path)?;
    if !text.contains(&format!("{}{TABLE_SLUG} -->", SYNTAX.open_prefix)) {
        bail!("{DOC} carries no `<!-- bounds:{TABLE_SLUG} -->` region for the input-bound table");
    }
    let updated: String = doc_region::rewrite(SYNTAX, &text, &|slug: &str| {
        if slug == TABLE_SLUG {
            Ok(rendered.clone())
        } else {
            bail!("unknown input-bound region `{slug}`")
        }
    })?;
    match mode {
        Mode::Write => {
            if updated != text {
                std::fs::write(&path, &updated)
                    .wrap_err_with(|| format!("writing {}", path.display()))?;
            }
        }
        Mode::Check => {
            if updated != text {
                bail!("{DOC} is stale; run `cargo run -p xtask -- regen`");
            }
        }
    }
    let crates: usize = bounds
        .iter()
        .map(|bound: &Bound| bound.crate_name.as_str())
        .collect::<std::collections::BTreeSet<&str>>()
        .len();
    println!(
        "xtask input-bounds: {} bound constant(s) over {crates} crate(s) listed in {DOC}",
        bounds.len()
    );
    Ok(())
}

fn survey(root: &Path) -> Result<Vec<Bound>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(&crates_dir)
        .wrap_err_with(|| format!("listing {}", crates_dir.display()))?
        .filter_map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry.ok().map(|e: std::fs::DirEntry| e.path())
        })
        .filter(|path: &PathBuf| path.join("src").is_dir())
        .collect();
    crate_dirs.sort();
    let mut out: Vec<Bound> = Vec::new();
    for dir in crate_dirs {
        let crate_name: String = dir
            .file_name()
            .map(|n: &std::ffi::OsStr| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for file in production_sources(&dir.join("src"))? {
            let text: String = read_text_bounded(&file, MAX_SOURCE_BYTES)?;
            let label: String = doc_region::label(root, &file);
            for (name, ty, value) in declarations(&text) {
                out.push(Bound {
                    crate_name: crate_name.clone(),
                    file: label.clone(),
                    name,
                    ty,
                    value,
                });
            }
        }
    }
    out.sort();
    Ok(out)
}

fn production_sources(src: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(src) {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", src.display()))?;
        let path: &Path = entry.path();
        let is_test_file: bool = path
            .components()
            .any(|part: std::path::Component<'_>| part.as_os_str() == "tests")
            || path
                .file_name()
                .is_some_and(|name: &std::ffi::OsStr| name == "tests.rs");
        if entry.file_type().is_file()
            && path
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext == "rs")
            && !is_test_file
        {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn declarations(text: &str) -> Vec<(String, String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<(String, String, String)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = strip_visibility(line).strip_prefix("const ") else {
            continue;
        };
        let Some((name, after_name)) = rest.split_once(':') else {
            continue;
        };
        if !is_bound_name(name) {
            continue;
        }
        let mut declaration: String = after_name.to_owned();
        let mut next: usize = index + 1;
        while !declaration.contains(';')
            && next < lines.len()
            && next <= index + MAX_DECLARATION_LINES
        {
            declaration.push(' ');
            declaration.push_str(lines[next].trim());
            next += 1;
        }
        let Some((ty, value)) = declaration.split_once('=') else {
            continue;
        };
        let Some(value) = value.split(';').next() else {
            continue;
        };
        out.push((
            name.to_owned(),
            collapse_whitespace(ty),
            collapse_whitespace(value),
        ));
    }
    out
}

fn strip_visibility(line: &str) -> &str {
    for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return rest;
        }
    }
    line
}

fn is_bound_name(name: &str) -> bool {
    let well_formed: bool = !name.is_empty()
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    well_formed
        && (name.starts_with("MAX_")
            || name.ends_with("_LIMIT")
            || name.ends_with("_BUDGET")
            || name.ends_with("_CAP"))
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn render(bounds: &[Bound]) -> String {
    let mut per_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for bound in bounds {
        *per_kind.entry(Kind::of(&bound.name).label()).or_insert(0) += 1;
    }
    let summary: String = per_kind
        .iter()
        .map(|(kind, count): (&&str, &usize)| format!("{kind} {count}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut out: String = format!(
        "\n{} bounds ({summary}).\n\n| Crate | Constant | Kind | Type | Value | File |\n| --- | --- | --- | --- | --- | --- |\n",
        bounds.len()
    );
    let rows: Vec<String> = bounds
        .iter()
        .map(|bound: &Bound| {
            format!(
                "| `{}` | `{}` | {} | `{}` | `{}` | `{}` |\n",
                bound.crate_name,
                bound.name,
                Kind::of(&bound.name).label(),
                bound.ty.replace('|', "\\|"),
                bound.value.replace('|', "\\|"),
                bound.file
            )
        })
        .collect();
    out.push_str(&rows.concat());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_level_bounds_are_found_across_lines_and_visibilities() {
        let text: &str = "const MAX_DEPTH: usize = 64;\npub(crate) const SCAN_BUDGET: u64 =\n    1 << 20;\n    const MAX_INNER: usize = 1;\nconst OTHER: usize = 2;\npub const MAX_BYTES: u64 = 16 * 1024;\n";
        let found: Vec<(String, String, String)> = declarations(text);
        assert_eq!(
            found,
            vec![
                ("MAX_DEPTH".to_owned(), "usize".to_owned(), "64".to_owned()),
                (
                    "SCAN_BUDGET".to_owned(),
                    "u64".to_owned(),
                    "1 << 20".to_owned()
                ),
                (
                    "MAX_BYTES".to_owned(),
                    "u64".to_owned(),
                    "16 * 1024".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn kinds_follow_the_name() {
        assert_eq!(Kind::of("MAX_STRUCT_DEPTH"), Kind::Recursion);
        assert_eq!(Kind::of("MAX_CARVE_STEPS"), Kind::Work);
        assert_eq!(Kind::of("MAX_RENDERED_STRUCTURE_BYTES"), Kind::Output);
        assert_eq!(Kind::of("MAX_SOURCE_BYTES"), Kind::Size);
        assert_eq!(Kind::of("MAX_MEMORY_REGIONS"), Kind::Other);
        assert_eq!(Kind::of("MAX_ENTRIES"), Kind::Count);
    }

    #[test]
    fn a_pipe_in_a_value_cannot_break_the_table() {
        let bound: Bound = Bound {
            crate_name: "disrobe-a".to_owned(),
            file: "crates/disrobe-a/src/lib.rs".to_owned(),
            name: "MAX_X".to_owned(),
            ty: "usize".to_owned(),
            value: "A | B".to_owned(),
        };
        let rendered: String = render(&[bound]);
        assert!(rendered.contains("`A \\| B`"), "{rendered}");
    }
}
