mod consequence;
mod finder;
mod prepare;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::doc_region::{self, Mode};
use crate::fileio::read_text_bounded;
use consequence::{Class, Consequence, CrateScan, ModulePath};

const DOC: &str = "docs/src/input-bounds.md";
const PREAMBLE: &str = "# Input bounds

Every parser treats its input as hostile. Counts, sizes, recursion depth, work and output are capped by named constants. `cargo xtask regen` generates this page from every module-level constant in `crates/*/src` whose name starts with `MAX_` or ends with `_LIMIT`, `_BUDGET` or `_CAP`, and `cargo xtask regen --check` fails when it is stale. The kind column is derived from the constant name.

The exceeded column states what happens when input goes past the bound. It comes from a syntax-tree scan of the defining crate's non-test sources: each read of the constant is traced through comparisons, local bindings, struct fields, same-crate function parameters, function results and derived constants to the branch taken when the bound is exceeded. The column reports the strongest outcome over all reads, in this order:

- **error**: a typed error is returned. The column names the error variant and its `DR-` diagnostic code when the variant carries one; `untyped` marks a string error.
- **recorded**: the input is truncated or refused and a flag or refusal record says so.
- **panic**: an assertion or panic fires.
- **delegated**: the bound is passed to a function the scan could not follow.
- **silent**: a loop stops, a value is clamped or work is skipped with no error and no record.
- **unclassified**: the scan found a read but could not attribute an outcome to it.
- **allocation**: the bound only sizes a buffer or a capacity reservation.
- **unused**: the defining crate never reads the constant.

The scan does not resolve types or trait dispatch, so an outcome names the construct it found rather than proving the behaviour.
";
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

type VariantCodes = BTreeSet<(String, String, String)>;
const MAX_DECLARATION_LINES: usize = 8;
const MAX_DETAILS_PER_CELL: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Bound {
    crate_name: String,
    file: String,
    name: String,
    ty: String,
    value: String,
    consequences: Vec<Consequence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    class: Class,
    details: Vec<String>,
}

#[derive(Debug, Clone)]
struct Source {
    label: String,
    text: String,
}

#[derive(Debug, Default)]
struct Codes {
    by_variant: BTreeMap<(String, String), BTreeMap<String, BTreeSet<String>>>,
}

impl Codes {
    fn add(&mut self, crate_name: &str, codes: VariantCodes) {
        for (owner, variant, code) in codes {
            self.by_variant
                .entry((owner, variant))
                .or_default()
                .entry(crate_name.to_owned())
                .or_default()
                .insert(code);
        }
    }

    fn resolve(&self, crate_name: &str, owner: &str, variant: &str) -> Option<&str> {
        if owner == "Self" {
            let found: BTreeSet<&str> = self
                .by_variant
                .iter()
                .filter(|((_, name), _): &(&(String, String), _)| name == variant)
                .filter_map(|(_, crates): (_, &BTreeMap<String, BTreeSet<String>>)| {
                    crates.get(crate_name)
                })
                .flatten()
                .map(String::as_str)
                .collect();
            return single(found);
        }
        let crates: &BTreeMap<String, BTreeSet<String>> = self
            .by_variant
            .get(&(owner.to_owned(), variant.to_owned()))?;
        if let Some(local) = crates.get(crate_name) {
            return single(local.iter().map(String::as_str).collect());
        }
        single(crates.values().flatten().map(String::as_str).collect())
    }
}

fn single(found: BTreeSet<&str>) -> Option<&str> {
    let mut values: std::collections::btree_set::IntoIter<&str> = found.into_iter();
    let first: &str = values.next()?;
    values.next().is_none().then_some(first)
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
    let (bounds, codes): (Vec<Bound>, Codes) = survey(root)?;
    let verdicts: Vec<Verdict> = bounds
        .iter()
        .map(|bound: &Bound| verdict(bound, &codes))
        .collect();
    let rendered: String = render(&bounds, &verdicts);
    let path: PathBuf = root.join(DOC);
    let text: String = doc_region::read_doc(&path)?;
    let updated: String = format!("{PREAMBLE}{rendered}");
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
        .collect::<BTreeSet<&str>>()
        .len();
    println!(
        "xtask input-bounds: {} bound constant(s) over {crates} crate(s) listed in {DOC} ({})",
        bounds.len(),
        class_summary(&verdicts)
    );
    Ok(())
}

fn survey(root: &Path) -> Result<(Vec<Bound>, Codes)> {
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
    let mut codes: Codes = Codes::default();
    for dir in crate_dirs {
        let crate_name: String = dir
            .file_name()
            .map(|n: &std::ffi::OsStr| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut sources: Vec<Source> = Vec::new();
        for file in production_sources(&dir.join("src"))? {
            sources.push(Source {
                label: doc_region::label(root, &file),
                text: read_text_bounded(&file, MAX_SOURCE_BYTES)?,
            });
        }
        let (bounds, crate_codes): (Vec<Bound>, VariantCodes) =
            survey_crate(&crate_name, &sources)?;
        out.extend(bounds);
        codes.add(&crate_name, crate_codes);
    }
    out.sort();
    Ok((out, codes))
}

fn survey_crate(crate_name: &str, sources: &[Source]) -> Result<(Vec<Bound>, VariantCodes)> {
    let mut declared: Vec<(usize, String, String, String)> = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        for (name, ty, value) in declarations(&source.text) {
            declared.push((index, name, ty, value));
        }
    }
    let mut files: Vec<syn::File> = Vec::new();
    for source in sources {
        files.push(
            prepare::parse(&source.text)
                .map_err(|error: syn::Error| eyre::eyre!("{error}"))
                .wrap_err_with(|| format!("parsing {}", source.label))?,
        );
    }
    let keys: BTreeSet<(usize, String)> = declared
        .iter()
        .map(|(index, name, _, _): &(usize, String, String, String)| (*index, name.clone()))
        .collect();
    let modules: Vec<ModulePath> = sources
        .iter()
        .map(|source: &Source| module_path(&source.label))
        .collect();
    let texts: Vec<&str> = sources
        .iter()
        .map(|source: &Source| source.text.as_str())
        .collect();
    let scan: CrateScan = consequence::scan_crate(&files, &texts, &modules, &keys);
    let bounds: Vec<Bound> = declared
        .into_iter()
        .map(
            |(index, name, ty, value): (usize, String, String, String)| {
                let consequences: Vec<Consequence> = scan
                    .consequences
                    .get(&(index, name.clone()))
                    .cloned()
                    .unwrap_or_default();
                Bound {
                    crate_name: crate_name.to_owned(),
                    file: sources[index].label.clone(),
                    name,
                    ty,
                    value,
                    consequences,
                }
            },
        )
        .collect();
    Ok((bounds, scan.codes))
}

fn module_path(label: &str) -> ModulePath {
    let path: &Path = Path::new(label);
    let name_of = |path: Option<&Path>| -> String {
        path.and_then(Path::file_name)
            .map(|name: &std::ffi::OsStr| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let stem: String = path
        .file_stem()
        .map(|stem: &std::ffi::OsStr| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let directory: Option<&Path> = path.parent();
    let root: bool = matches!(stem.as_str(), "lib" | "main") && name_of(directory) == "src";
    if matches!(stem.as_str(), "mod" | "lib" | "main") {
        ModulePath {
            own: name_of(directory),
            parent: name_of(directory.and_then(Path::parent)),
            root,
        }
    } else {
        ModulePath {
            own: stem,
            parent: name_of(directory),
            root,
        }
    }
}

fn verdict(bound: &Bound, codes: &Codes) -> Verdict {
    let class: Class = bound
        .consequences
        .iter()
        .map(|c: &Consequence| c.class)
        .min()
        .unwrap_or(Class::Unused);
    let details: BTreeSet<String> = bound
        .consequences
        .iter()
        .filter(|c: &&Consequence| c.class == class)
        .map(|c: &Consequence| {
            let coded: Option<(&String, &String, &str)> =
                c.variants
                    .iter()
                    .find_map(|(owner, variant): &(String, String)| {
                        codes
                            .resolve(&bound.crate_name, owner, variant)
                            .map(|code: &str| (owner, variant, code))
                    });
            match coded {
                Some((owner, variant, code)) => format!("`{owner}::{variant}` ({code})"),
                None => c.detail.clone(),
            }
        })
        .collect();
    Verdict {
        class,
        details: details.into_iter().collect(),
    }
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

fn class_summary(verdicts: &[Verdict]) -> String {
    Class::ALL
        .iter()
        .map(|class: &Class| {
            let count: usize = verdicts
                .iter()
                .filter(|verdict: &&Verdict| verdict.class == *class)
                .count();
            format!("{} {count}", class.label())
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn details_cell(verdict: &Verdict) -> String {
    let shown: Vec<&str> = verdict
        .details
        .iter()
        .take(MAX_DETAILS_PER_CELL)
        .map(String::as_str)
        .collect();
    let hidden: usize = verdict.details.len().saturating_sub(MAX_DETAILS_PER_CELL);
    let text: String = shown.join("; ");
    if hidden > 0 {
        cell(&format!("{text}; {hidden} more"))
    } else {
        cell(&text)
    }
}

fn render(bounds: &[Bound], verdicts: &[Verdict]) -> String {
    let mut per_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for bound in bounds {
        *per_kind.entry(Kind::of(&bound.name).label()).or_insert(0) += 1;
    }
    let summary: String = per_kind
        .iter()
        .map(|(kind, count): (&&str, &usize)| format!("{kind} {count}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut out: Vec<String> = vec![format!(
        "\n{} bounds ({summary}).\n\nExceeded: {}.\n\n| Crate | Constant | Kind | Exceeded | Type | Value | File |\n| --- | --- | --- | --- | --- | --- | --- |\n",
        bounds.len(),
        class_summary(verdicts)
    )];
    let mut stops: Vec<String> = Vec::new();
    let mut panics: Vec<String> = Vec::new();
    for (bound, verdict) in bounds.iter().zip(verdicts) {
        let details: String = details_cell(verdict);
        out.push(format!(
            "| `{}` | `{}` | {} | {}: {} | `{}` | `{}` | `{}` |\n",
            bound.crate_name,
            bound.name,
            Kind::of(&bound.name).label(),
            verdict.class.label(),
            details,
            cell(&bound.ty),
            cell(&bound.value),
            bound.file
        ));
        let row: String = format!(
            "| `{}` | `{}` | {details} | `{}` |\n",
            bound.crate_name, bound.name, bound.file
        );
        match verdict.class {
            Class::Silent => stops.push(row),
            Class::Panic => panics.push(row),
            Class::Error
            | Class::Record
            | Class::Delegated
            | Class::Unresolved
            | Class::Capacity
            | Class::Unused => {}
        }
    }
    for (heading, intro, rows) in [
        (
            "Silent stops",
            "stop a loop, clamp a value or skip work with no typed error and no record when input exceeds them. Each is a defect: a parser recovers or refuses with a label, and malformed input is a typed error.",
            &stops,
        ),
        (
            "Panics",
            "panic when input exceeds them. Each is a defect: malformed input is a typed error, never a panic.",
            &panics,
        ),
    ] {
        out.push(format!("\n## {heading}\n\n{} bounds {intro}\n", rows.len()));
        if !rows.is_empty() {
            out.push("\n| Crate | Constant | Use | File |\n| --- | --- | --- | --- |\n".to_owned());
            out.extend(rows.iter().cloned());
        }
    }
    out.concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 16;
const MAX_STEPS: usize = 32;
const MAX_NAME_LEN: usize = 64;
const MAX_PREALLOC: usize = 128;
const MAX_READ_BYTES: usize = 256;
const MAX_UNUSED: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("DR-FIX-0001: nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("DR-FIX-0002: name longer than {limit}")]
    NameTooLong { limit: usize },
}

pub struct Report {
    pub truncated: bool,
    pub items: Vec<u8>,
}

pub fn nest(levels: &[u8]) -> Result<usize, FixtureError> {
    let mut depth: usize = 0;
    for level in levels {
        if depth > MAX_DEPTH {
            return Err(FixtureError::TooDeep);
        }
        depth += usize::from(*level);
    }
    Ok(depth)
}

pub fn collect(input: &[u8], report: &mut Report) {
    for byte in input {
        if report.items.len() >= MAX_ITEMS {
            report.truncated = true;
            break;
        }
        report.items.push(*byte);
    }
}

pub fn walk(input: &[u8]) -> usize {
    let mut steps: usize = 0;
    for _ in input {
        if steps >= MAX_STEPS {
            break;
        }
        steps += 1;
    }
    steps
}

fn check_name(name: &str, limit: usize) -> Result<(), FixtureError> {
    if name.len() > limit {
        return Err(FixtureError::NameTooLong { limit });
    }
    Ok(())
}

pub fn name(name: &str) -> Result<(), FixtureError> {
    check_name(name, MAX_NAME_LEN)
}

pub fn buffer(count: usize) -> Vec<u8> {
    Vec::with_capacity(count.min(MAX_PREALLOC))
}

pub fn read(input: &[u8]) -> Result<Vec<u8>, other::Error> {
    other::read_bounded(input, MAX_READ_BYTES)?;
    Ok(input.to_vec())
}
"#;

    fn classify(text: &str) -> Result<Vec<(String, Verdict)>> {
        let sources: Vec<Source> = vec![Source {
            label: "crates/disrobe-fixture/src/lib.rs".to_owned(),
            text: text.to_owned(),
        }];
        let (bounds, crate_codes): (Vec<Bound>, VariantCodes) =
            survey_crate("disrobe-fixture", &sources)?;
        let mut codes: Codes = Codes::default();
        codes.add("disrobe-fixture", crate_codes);
        Ok(bounds
            .iter()
            .map(|bound: &Bound| (bound.name.clone(), verdict(bound, &codes)))
            .collect())
    }

    fn verdict_of<'v>(verdicts: &'v [(String, Verdict)], name: &str) -> Result<&'v Verdict> {
        verdicts
            .iter()
            .find_map(|(bound, verdict): &(String, Verdict)| (bound == name).then_some(verdict))
            .ok_or_else(|| eyre::eyre!("{name} missing from {verdicts:?}"))
    }

    #[test]
    fn input_bounds_classifier_names_each_consequence() -> Result<()> {
        let verdicts: Vec<(String, Verdict)> = classify(FIXTURE)?;
        let expected: [(&str, Class, &str); 7] = [
            (
                "MAX_DEPTH",
                Class::Error,
                "`FixtureError::TooDeep` (DR-FIX-0001)",
            ),
            ("MAX_ITEMS", Class::Record, "flag `truncated`"),
            ("MAX_STEPS", Class::Silent, "`break` in `walk`"),
            (
                "MAX_NAME_LEN",
                Class::Error,
                "`FixtureError::NameTooLong` (DR-FIX-0002)",
            ),
            (
                "MAX_PREALLOC",
                Class::Capacity,
                "`with_capacity` in `buffer`",
            ),
            (
                "MAX_READ_BYTES",
                Class::Delegated,
                "`other::read_bounded()?`",
            ),
            ("MAX_UNUSED", Class::Unused, "no use in the crate"),
        ];
        for (name, class, detail) in expected {
            let verdict: &Verdict = verdict_of(&verdicts, name)?;
            assert_eq!(verdict.class, class, "{name}: {verdict:?}");
            assert_eq!(verdict.details, vec![detail.to_owned()], "{name}");
        }
        Ok(())
    }

    #[test]
    fn input_bounds_error_turned_into_break_becomes_a_silent_stop() -> Result<()> {
        let mutated: String = FIXTURE.replacen("return Err(FixtureError::TooDeep);", "break;", 1);
        assert_ne!(mutated, FIXTURE);
        let before: Vec<(String, Verdict)> = classify(FIXTURE)?;
        let after: Vec<(String, Verdict)> = classify(&mutated)?;
        assert_eq!(verdict_of(&before, "MAX_DEPTH")?.class, Class::Error);
        let changed: &Verdict = verdict_of(&after, "MAX_DEPTH")?;
        assert_eq!(changed.class, Class::Silent, "{changed:?}");
        assert_eq!(changed.details, vec!["`break` in `nest`".to_owned()]);
        let page = |verdicts: &[(String, Verdict)]| -> String {
            let bounds: Vec<Bound> = verdicts
                .iter()
                .map(|(name, _): &(String, Verdict)| Bound {
                    crate_name: "disrobe-fixture".to_owned(),
                    file: "crates/disrobe-fixture/src/lib.rs".to_owned(),
                    name: name.clone(),
                    ty: "usize".to_owned(),
                    value: "1".to_owned(),
                    consequences: Vec::new(),
                })
                .collect();
            let only: Vec<Verdict> = verdicts
                .iter()
                .map(|(_, verdict): &(String, Verdict)| verdict.clone())
                .collect();
            render(&bounds, &only)
        };
        let stale: String = page(&before);
        let fresh: String = page(&after);
        assert_ne!(stale, fresh);
        assert!(
            fresh.contains("\n## Silent stops\n\n2 bounds")
                && fresh.contains("| `disrobe-fixture` | `MAX_DEPTH` | `break` in `nest` |"),
            "{fresh}"
        );
        Ok(())
    }

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
            consequences: Vec::new(),
        };
        let verdict: Verdict = Verdict {
            class: Class::Unused,
            details: vec!["no use in the crate".to_owned()],
        };
        let rendered: String = render(&[bound], &[verdict]);
        assert!(rendered.contains("`A \\| B`"), "{rendered}");
    }
}
