use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::fileio::read_text_bounded;

const MAX_SECURITY_MD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FUZZ_CARGO_TOML_BYTES: u64 = 64 * 1024;

const FUZZING_SECTION_HEADING: &str = "## Fuzzing and panic-safety coverage";
const ITEM1_START_MARKER: &str = "1. **Continuous coverage-guided fuzzing**";
const ITEM2_START_MARKER: &str = "2. **Property-based tests**";

pub(crate) fn run(root: &Path) -> Result<()> {
    let fuzz_dir: PathBuf = root.join("fuzz");
    let cargo_toml_path: PathBuf = fuzz_dir.join("Cargo.toml");
    let targets_dir: PathBuf = fuzz_dir.join("fuzz_targets");
    let security_path: PathBuf = root.join("SECURITY.md");

    let cargo_bins: BTreeSet<String> = read_cargo_toml_bin_filenames(&cargo_toml_path)?;
    let dir_targets: BTreeSet<String> = read_fuzz_targets_dir(&targets_dir)?;
    let security_md: String = read_text_bounded(&security_path, MAX_SECURITY_MD_BYTES)
        .wrap_err_with(|| format!("reading {}", security_path.display()))?;

    let mut drift: Vec<String> = Vec::new();
    check_bin_dir_consistency(&dir_targets, &cargo_bins, &mut drift);

    let real_targets: BTreeSet<String> = dir_targets.intersection(&cargo_bins).cloned().collect();
    check_documented_targets(&real_targets, &security_md, &mut drift)?;

    if drift.is_empty() {
        println!(
            "xtask regen: fuzz-target scope cross-check ok ({} real target(s) match SECURITY.md's fuzzing-coverage item 1)",
            real_targets.len()
        );
        Ok(())
    } else {
        bail!(
            "SECURITY.md's fuzzing-scope documentation drifted from the real fuzz/fuzz_targets/ directory; update the doc by hand:\n  {}",
            drift.join("\n  ")
        )
    }
}

fn read_cargo_toml_bin_filenames(cargo_toml_path: &Path) -> Result<BTreeSet<String>> {
    let raw: String = read_text_bounded(cargo_toml_path, MAX_FUZZ_CARGO_TOML_BYTES)
        .wrap_err_with(|| format!("reading {}", cargo_toml_path.display()))?;
    let parsed: toml::Table = raw
        .parse::<toml::Table>()
        .wrap_err_with(|| format!("parsing {}", cargo_toml_path.display()))?;
    let bins: &Vec<toml::Value> = parsed
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| eyre!("{} has no [[bin]] entries", cargo_toml_path.display()))?;

    let mut filenames: BTreeSet<String> = BTreeSet::new();
    for bin in bins {
        let path_str: &str = bin
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                eyre!(
                    "a [[bin]] entry in {} has no `path` string",
                    cargo_toml_path.display()
                )
            })?;
        let filename: &str = Path::new(path_str)
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| {
                eyre!(
                    "[[bin]] path `{path_str}` in {} has no file name",
                    cargo_toml_path.display()
                )
            })?;
        filenames.insert(filename.to_owned());
    }
    Ok(filenames)
}

fn read_fuzz_targets_dir(targets_dir: &Path) -> Result<BTreeSet<String>> {
    if !targets_dir.is_dir() {
        bail!("{} is not a directory", targets_dir.display());
    }
    let mut filenames: BTreeSet<String> = BTreeSet::new();
    for entry in walkdir::WalkDir::new(targets_dir).min_depth(1).max_depth(1) {
        let dirent: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", targets_dir.display()))?;
        let path: &Path = dirent.path();
        if !path.is_file() || path.extension().and_then(OsStr::to_str) != Some("rs") {
            continue;
        }
        let filename: &str = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| eyre!("non-utf8 fuzz target filename {}", path.display()))?;
        filenames.insert(filename.to_owned());
    }
    Ok(filenames)
}

fn check_bin_dir_consistency(
    dir_targets: &BTreeSet<String>,
    cargo_bins: &BTreeSet<String>,
    drift: &mut Vec<String>,
) {
    for filename in dir_targets.difference(cargo_bins) {
        drift.push(format!(
            "fuzz/fuzz_targets/{filename} exists on disk but has no matching [[bin]] entry in fuzz/Cargo.toml"
        ));
    }
    for filename in cargo_bins.difference(dir_targets) {
        drift.push(format!(
            "fuzz/Cargo.toml declares a [[bin]] whose path resolves to fuzz/fuzz_targets/{filename}, but that file does not exist"
        ));
    }
}

fn check_documented_targets(
    real_targets: &BTreeSet<String>,
    security_md: &str,
    drift: &mut Vec<String>,
) -> Result<()> {
    let documented: BTreeSet<String> = documented_fuzz_target_filenames(security_md)?;

    for filename in real_targets.difference(&documented) {
        drift.push(format!(
            "fuzz target `{filename}` is wired into fuzz/Cargo.toml and present under fuzz/fuzz_targets/, but is not named in SECURITY.md's \"Fuzzing and panic-safety coverage\" item 1"
        ));
    }
    for filename in documented.difference(real_targets) {
        drift.push(format!(
            "SECURITY.md's \"Fuzzing and panic-safety coverage\" item 1 names fuzz target `{filename}`, but no such target exists under fuzz/fuzz_targets/ wired into fuzz/Cargo.toml anymore"
        ));
    }
    Ok(())
}

fn documented_fuzz_target_filenames(security_md: &str) -> Result<BTreeSet<String>> {
    let heading_start: usize = security_md
        .find(FUZZING_SECTION_HEADING)
        .ok_or_else(|| eyre!("SECURITY.md is missing the heading `{FUZZING_SECTION_HEADING}`"))?;
    let after_heading: &str = &security_md[heading_start..];
    let item1_start: usize = after_heading
        .find(ITEM1_START_MARKER)
        .ok_or_else(|| eyre!("SECURITY.md's fuzzing section is missing `{ITEM1_START_MARKER}`"))?;
    let after_item1: &str = &after_heading[item1_start..];
    let item1_end: usize = after_item1.find(ITEM2_START_MARKER).ok_or_else(|| {
        eyre!("SECURITY.md's fuzzing section is missing `{ITEM2_START_MARKER}` after item 1")
    })?;
    let item1_text: &str = &after_item1[..item1_end];

    Ok(backtick_rs_filenames(item1_text))
}

fn backtick_rs_filenames(section: &str) -> BTreeSet<String> {
    section
        .split('`')
        .enumerate()
        .filter(|(index, _): &(usize, &str)| index % 2 == 1)
        .map(|(_, token): (usize, &str)| token.to_owned())
        .filter(|token: &String| token.to_ascii_lowercase().ends_with(".rs"))
        .map(|token: String| {
            Path::new(&token)
                .file_name()
                .and_then(OsStr::to_str)
                .map(str::to_owned)
                .unwrap_or(token)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name: &&str| (*name).to_owned()).collect()
    }

    #[test]
    fn backtick_rs_filenames_extracts_only_dot_rs_tokens() {
        let section: &str = "via `cargo-fuzz` / libFuzzer, defined in `fuzz/Cargo.toml`: `chain_driver.rs` and `chain_spec_parser.rs`. Both drive `disrobe-core` (the `chain` feature).";
        let found: BTreeSet<String> = backtick_rs_filenames(section);
        assert_eq!(found, set(&["chain_driver.rs", "chain_spec_parser.rs"]));
    }

    #[test]
    fn backtick_rs_filenames_normalizes_path_qualified_mentions() {
        let section: &str = "see `fuzz/fuzz_targets/chain_driver.rs` for the harness.";
        let found: BTreeSet<String> = backtick_rs_filenames(section);
        assert_eq!(found, set(&["chain_driver.rs"]));
    }

    #[test]
    fn documented_fuzz_target_filenames_scopes_to_item_one_only() -> core::result::Result<(), String>
    {
        let security_md: String = format!(
            "intro text\n\n{FUZZING_SECTION_HEADING}\n\nparagraph.\n\n{ITEM1_START_MARKER} via `cargo-fuzz`: `chain_driver.rs` and `chain_spec_parser.rs`.\n\n{ITEM2_START_MARKER} via `proptest`, six files: `crates/disrobe-bytes/tests/properties.rs`.\n"
        );
        let found: BTreeSet<String> =
            documented_fuzz_target_filenames(&security_md).map_err(|e| e.to_string())?;
        assert_eq!(found, set(&["chain_driver.rs", "chain_spec_parser.rs"]));
        assert!(!found.contains("properties.rs"));
        Ok(())
    }

    #[test]
    fn documented_fuzz_target_filenames_errors_on_missing_heading() {
        let security_md: &str = "no fuzzing section here";
        assert!(documented_fuzz_target_filenames(security_md).is_err());
    }

    #[test]
    fn check_bin_dir_consistency_flags_both_directions() {
        let dir_targets: BTreeSet<String> = set(&["chain_driver.rs", "orphan_on_disk.rs"]);
        let cargo_bins: BTreeSet<String> = set(&["chain_driver.rs", "orphan_in_manifest.rs"]);
        let mut drift: Vec<String> = Vec::new();
        check_bin_dir_consistency(&dir_targets, &cargo_bins, &mut drift);
        assert_eq!(drift.len(), 2);
        assert!(
            drift
                .iter()
                .any(|line: &String| line.contains("orphan_on_disk.rs"))
        );
        assert!(
            drift
                .iter()
                .any(|line: &String| line.contains("orphan_in_manifest.rs"))
        );
    }

    #[test]
    fn check_bin_dir_consistency_accepts_matching_sets() {
        let targets: BTreeSet<String> = set(&["chain_driver.rs", "chain_spec_parser.rs"]);
        let mut drift: Vec<String> = Vec::new();
        check_bin_dir_consistency(&targets, &targets, &mut drift);
        assert!(drift.is_empty(), "drift: {drift:?}");
    }

    #[test]
    fn check_documented_targets_flags_added_target_missing_from_docs()
    -> core::result::Result<(), String> {
        let real_targets: BTreeSet<String> = set(&["chain_driver.rs", "new_target.rs"]);
        let security_md: String = format!(
            "{FUZZING_SECTION_HEADING}\n\n{ITEM1_START_MARKER} `chain_driver.rs`.\n\n{ITEM2_START_MARKER} `proptest`.\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_documented_targets(&real_targets, &security_md, &mut drift)
            .map_err(|e| e.to_string())?;
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("new_target.rs"));
        Ok(())
    }

    #[test]
    fn check_documented_targets_flags_removed_target_still_in_docs()
    -> core::result::Result<(), String> {
        let real_targets: BTreeSet<String> = set(&["chain_driver.rs"]);
        let security_md: String = format!(
            "{FUZZING_SECTION_HEADING}\n\n{ITEM1_START_MARKER} `chain_driver.rs` and `chain_spec_parser.rs`.\n\n{ITEM2_START_MARKER} `proptest`.\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_documented_targets(&real_targets, &security_md, &mut drift)
            .map_err(|e| e.to_string())?;
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("chain_spec_parser.rs"));
        Ok(())
    }

    #[test]
    fn check_documented_targets_accepts_exact_match() -> core::result::Result<(), String> {
        let real_targets: BTreeSet<String> = set(&["chain_driver.rs", "chain_spec_parser.rs"]);
        let security_md: String = format!(
            "{FUZZING_SECTION_HEADING}\n\n{ITEM1_START_MARKER} `chain_driver.rs` and `chain_spec_parser.rs`.\n\n{ITEM2_START_MARKER} `proptest`.\n"
        );
        let mut drift: Vec<String> = Vec::new();
        check_documented_targets(&real_targets, &security_md, &mut drift)
            .map_err(|e| e.to_string())?;
        assert!(drift.is_empty(), "drift: {drift:?}");
        Ok(())
    }
}
