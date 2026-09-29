use std::collections::BTreeSet;
use std::path::Path;

use eyre::Result;

use crate::fileio::read_bytes_bounded;

const MAX_SCANNED_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) const RUST_SOURCE_CEILING: usize = 74;

const WORD_TELLS: [&str; 27] = [
    "honest",
    "honestly",
    "genuinely",
    "robust",
    "comprehensive",
    "seamless",
    "seamlessly",
    "leverage",
    "leverages",
    "leveraging",
    "utilize",
    "utilizes",
    "utilizing",
    "powerful",
    "cutting-edge",
    "delve",
    "delves",
    "facilitate",
    "facilitates",
    "boasts",
    "best-in-class",
    "clean-room",
    "chatgpt",
    "to be clear",
    "it is worth noting",
    "it's worth noting",
    "out of the box",
];

const ATTRIBUTION_TELLS: [&str; 5] = [
    "co-authored-by:",
    "generated with [claude",
    "generated with claude",
    "as an ai language model",
    "ported from",
];

const PROSE_ONLY_TELLS: [&str; 2] = ["\u{2014}", "\u{1f916}"];

#[derive(Debug, Default)]
pub(crate) struct TellScan {
    pub(crate) prose_hits: Vec<String>,
    pub(crate) rust_hits: usize,
}

pub(crate) fn scan(root: &Path, files: &BTreeSet<String>) -> Result<TellScan> {
    let mut result: TellScan = TellScan::default();
    for file in files {
        let surface: Surface = surface(file);
        if surface == Surface::None {
            continue;
        }
        let path: std::path::PathBuf = root.join(file);
        if !path.is_file() {
            continue;
        }
        let bytes: Vec<u8> = read_bytes_bounded(&path, MAX_SCANNED_BYTES)?;
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        match surface {
            Surface::Prose => {
                for (line_number, line) in text.lines().enumerate() {
                    for tell in line_tells(line, true) {
                        result
                            .prose_hits
                            .push(format!("{file}:{}: {tell}", line_number + 1));
                    }
                }
            }
            Surface::CrateManifest => {
                for (line_number, line) in text.lines().enumerate() {
                    if line.trim_start().starts_with("description") {
                        for tell in line_tells(line, true) {
                            result
                                .prose_hits
                                .push(format!("{file}:{}: {tell}", line_number + 1));
                        }
                    }
                }
            }
            Surface::RustSource => {
                result.rust_hits += text
                    .lines()
                    .map(|line: &str| line_tells(line, false).len())
                    .sum::<usize>();
            }
            Surface::None => {}
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Prose,
    CrateManifest,
    RustSource,
    None,
}

fn surface(file: &str) -> Surface {
    let prose: bool = matches!(file, "README.md" | "SECURITY.md" | "CHANGELOG.md")
        || (file.starts_with("docs/src/") && has_extension(file, "md"));
    if prose {
        return Surface::Prose;
    }
    let parts: Vec<&str> = file.split('/').collect();
    match parts.as_slice() {
        ["crates", _, "Cargo.toml"] => Surface::CrateManifest,
        ["crates", _, rest @ ..] if has_extension(file, "rs") && !rest.is_empty() => {
            Surface::RustSource
        }
        _ => Surface::None,
    }
}

fn has_extension(file: &str, extension: &str) -> bool {
    Path::new(file)
        .extension()
        .is_some_and(|found: &std::ffi::OsStr| found.eq_ignore_ascii_case(extension))
}

fn line_tells(line: &str, prose: bool) -> Vec<&'static str> {
    let lower: String = line.to_lowercase();
    let mut found: Vec<&'static str> = Vec::new();
    for tell in WORD_TELLS.iter().chain(ATTRIBUTION_TELLS.iter()) {
        if contains_phrase(&lower, tell) {
            found.push(tell);
        }
    }
    if prose {
        for tell in PROSE_ONLY_TELLS {
            if line.contains(tell) {
                found.push(tell);
            }
        }
    }
    found
}

fn contains_phrase(haystack: &str, phrase: &str) -> bool {
    let bytes: &[u8] = haystack.as_bytes();
    let mut from: usize = 0;
    while let Some(offset) = haystack[from..].find(phrase) {
        let start: usize = from + offset;
        let end: usize = start + phrase.len();
        let bounded_before: bool = start == 0 || !is_word_byte(bytes[start - 1]);
        let bounded_after: bool = end == bytes.len() || !is_word_byte(bytes[end]);
        if bounded_before && bounded_after {
            return true;
        }
        from = start + 1;
        while !haystack.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_tell_class_is_found_in_prose() {
        assert_eq!(
            line_tells("A robust, comprehensive tool.", true),
            vec!["robust", "comprehensive"]
        );
        assert_eq!(
            line_tells("Co-Authored-By: someone", true),
            vec!["co-authored-by:"]
        );
        assert_eq!(
            line_tells("Recovers source \u{2014} fast.", true),
            vec!["\u{2014}"]
        );
        assert_eq!(
            line_tells("It is worth noting that it works.", true),
            vec!["it is worth noting"]
        );
    }

    #[test]
    fn word_boundaries_and_code_surfaces_are_respected() {
        assert!(line_tells("the honestest robustness", true).is_empty());
        assert_eq!(line_tells("leverage_ratio", true), vec!["leverage"]);
        assert!(line_tells("fn walls \u{2014} here", false).is_empty());
        assert_eq!(line_tells("fn walls_honestly()", false), vec!["honestly"]);
        assert_eq!(line_tells("// fails honestly", false), vec!["honestly"]);
    }

    #[test]
    fn surfaces_are_classified_by_path() {
        assert_eq!(surface("README.md"), Surface::Prose);
        assert_eq!(surface("docs/src/cli/reference.md"), Surface::Prose);
        assert_eq!(
            surface("crates/disrobe-cli/Cargo.toml"),
            Surface::CrateManifest
        );
        assert_eq!(
            surface("crates/disrobe-cli/src/main.rs"),
            Surface::RustSource
        );
        assert_eq!(surface("xtask/src/prose_tells.rs"), Surface::None);
        assert_eq!(surface("docs/theme/llms.txt"), Surface::None);
    }

    #[test]
    fn a_probe_page_with_a_tell_is_reported() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        std::fs::create_dir_all(root.path().join("docs/src"))?;
        std::fs::write(
            root.path().join("docs/src/probe.md"),
            "A seamless experience.\n",
        )?;
        let files: BTreeSet<String> = BTreeSet::from(["docs/src/probe.md".to_owned()]);
        assert_eq!(
            scan(root.path(), &files)?.prose_hits,
            vec!["docs/src/probe.md:1: seamless"]
        );
        Ok(())
    }
}
