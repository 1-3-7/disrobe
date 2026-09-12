use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::fileio::read_text_bounded;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_SEED_BYTES: usize = 512 * 1024;
const CONFIG_RELATIVE: &str = "fuzz/seeds.toml";
const TRUNCATION_PREFIX_BYTES: [usize; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096];
const TRUNCATION_DIVISORS: [usize; 3] = [2, 4, 8];
const SKIP_EXTENSIONS: [&str; 10] = [
    "md", "txt", "toml", "json", "sh", "ps1", "java", "cs", "py", "rs",
];

#[derive(Debug)]
struct TargetSeeds {
    name: String,
    sources: Vec<String>,
}

#[derive(Debug, Default)]
struct SeedTally {
    real_samples: usize,
    derived_prefixes: usize,
    unreadable_sources: usize,
}

pub(crate) fn run(root: &Path, only: Option<&str>) -> Result<()> {
    let targets: Vec<TargetSeeds> = read_config(root)?;
    let selected: Vec<&TargetSeeds> = targets
        .iter()
        .filter(|target: &&TargetSeeds| only.is_none_or(|name: &str| name == target.name))
        .collect();
    if selected.is_empty() {
        bail!("{CONFIG_RELATIVE} declares no target matching the requested name");
    }
    for target in selected {
        let out_dir: PathBuf = root.join("fuzz").join("corpus").join(&target.name);
        fs::create_dir_all(&out_dir).wrap_err_with(|| format!("creating {}", out_dir.display()))?;
        let tally: SeedTally = materialize(root, target, &out_dir)?;
        let total: usize = fs::read_dir(&out_dir)
            .wrap_err_with(|| format!("reading {}", out_dir.display()))?
            .flatten()
            .count();
        println!(
            "xtask fuzz-seeds: {} seeded from {} committed sample(s) plus {} derived truncation(s), {} seed(s) on disk, {} unreadable source(s) skipped",
            target.name,
            tally.real_samples,
            tally.derived_prefixes,
            total,
            tally.unreadable_sources
        );
    }
    Ok(())
}

fn read_config(root: &Path) -> Result<Vec<TargetSeeds>> {
    let path: PathBuf = root.join(CONFIG_RELATIVE);
    let raw: String = read_text_bounded(&path, MAX_CONFIG_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let parsed: toml::Table = raw
        .parse::<toml::Table>()
        .wrap_err_with(|| format!("parsing {}", path.display()))?;
    let Some(entries): Option<&Vec<toml::Value>> =
        parsed.get("target").and_then(toml::Value::as_array)
    else {
        bail!("{CONFIG_RELATIVE} declares no [[target]] entries");
    };
    let mut targets: Vec<TargetSeeds> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(name): Option<&str> = entry.get("name").and_then(toml::Value::as_str) else {
            bail!("{CONFIG_RELATIVE} has a [[target]] with no name");
        };
        let Some(list): Option<&Vec<toml::Value>> =
            entry.get("sources").and_then(toml::Value::as_array)
        else {
            bail!("{CONFIG_RELATIVE} target {name} declares no sources");
        };
        let mut sources: Vec<String> = Vec::with_capacity(list.len());
        for item in list {
            let Some(text): Option<&str> = item.as_str() else {
                bail!("{CONFIG_RELATIVE} target {name} has a non-string source");
            };
            sources.push(text.to_owned());
        }
        targets.push(TargetSeeds {
            name: name.to_owned(),
            sources,
        });
    }
    Ok(targets)
}

fn materialize(root: &Path, target: &TargetSeeds, out_dir: &Path) -> Result<SeedTally> {
    let mut tally: SeedTally = SeedTally::default();
    write_seed(out_dir, &[])?;
    for source in &target.sources {
        let base: PathBuf = root.join(source);
        if !base.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&base)
            .min_depth(1)
            .sort_by_file_name()
        {
            let Ok(dirent): walkdir::Result<walkdir::DirEntry> = entry else {
                tally.unreadable_sources = tally.unreadable_sources.saturating_add(1);
                continue;
            };
            let path: &Path = dirent.path();
            if !path.is_file() || is_skipped_extension(path) {
                continue;
            }
            let Ok(whole): std::io::Result<Vec<u8>> = fs::read(path) else {
                tally.unreadable_sources = tally.unreadable_sources.saturating_add(1);
                continue;
            };
            let payload: &[u8] = whole.get(..whole.len().min(MAX_SEED_BYTES)).unwrap_or(&[]);
            if payload.is_empty() {
                continue;
            }
            if write_seed(out_dir, payload)? {
                tally.real_samples = tally.real_samples.saturating_add(1);
            }
            for cut in truncation_lengths(payload.len()) {
                let Some(prefix): Option<&[u8]> = payload.get(..cut) else {
                    continue;
                };
                if write_seed(out_dir, prefix)? {
                    tally.derived_prefixes = tally.derived_prefixes.saturating_add(1);
                }
            }
        }
    }
    Ok(tally)
}

fn is_skipped_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|raw: &std::ffi::OsStr| raw.to_str())
        .is_some_and(|extension: &str| {
            let folded: String = extension.to_ascii_lowercase();
            SKIP_EXTENSIONS.contains(&folded.as_str())
        })
}

fn truncation_lengths(length: usize) -> BTreeSet<usize> {
    let mut cuts: BTreeSet<usize> = BTreeSet::new();
    for candidate in TRUNCATION_PREFIX_BYTES {
        if candidate > 0 && candidate < length {
            cuts.insert(candidate);
        }
    }
    for divisor in TRUNCATION_DIVISORS {
        let candidate: usize = length / divisor;
        if candidate > 0 && candidate < length {
            cuts.insert(candidate);
        }
    }
    cuts
}

fn write_seed(out_dir: &Path, payload: &[u8]) -> Result<bool> {
    let digest: blake3::Hash = blake3::hash(payload);
    let name: String = digest.to_hex().as_str().chars().take(32).collect();
    let destination: PathBuf = out_dir.join(name);
    if destination.exists() {
        return Ok(false);
    }
    fs::write(&destination, payload)
        .wrap_err_with(|| format!("writing {}", destination.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_lengths_stay_inside_the_payload() {
        let cuts: BTreeSet<usize> = truncation_lengths(100);
        assert!(cuts.iter().all(|cut: &usize| *cut > 0 && *cut < 100));
        assert!(cuts.contains(&50));
        assert!(cuts.contains(&1));
    }

    #[test]
    fn truncation_lengths_of_a_single_byte_payload_are_empty() {
        assert!(truncation_lengths(1).is_empty());
        assert!(truncation_lengths(0).is_empty());
    }

    #[test]
    fn skipped_extensions_are_case_folded() {
        assert!(is_skipped_extension(Path::new("a/b/NOTES.MD")));
        assert!(!is_skipped_extension(Path::new("a/b/hello.pe64.exe")));
    }
}
