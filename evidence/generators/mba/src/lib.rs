#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub mod corpus;
pub mod datasets;
pub mod equiv;
pub mod error;
pub mod forward;
pub mod ingest;
pub mod parse;
pub mod plan;
pub mod rng;
pub mod term;

use std::path::{Path, PathBuf};

use corpus::{Entry, render, sort_entries};
use error::{GeneratorError, GeneratorResult};
use ingest::{DatasetSpec, Ingested, ingest_tool_rows};
use term::Width;

pub const CORPUS_RELATIVE_DIR: &str = "evidence/corpus/mba";
pub const CASES_FILE: &str = "cases.jsonl";
pub const TRUTH_FILE: &str = "truth.jsonl";
pub const EXTERNAL_TOOL_FILE: &str = "external/mba-obfuscator.jsonl";
pub const EXTERNAL_TOOL_NAME: &str = "MBA-Obfuscator (ICICS 2021), pinned upstream commit";

pub const EXTERNAL_TOOL_WIDTHS: [Width; 2] = [Width::W8, Width::W64];

#[must_use]
pub fn corpus_dir(root: &Path) -> PathBuf {
    root.join(CORPUS_RELATIVE_DIR)
}

fn read_text(path: &Path) -> GeneratorResult<String> {
    std::fs::read_to_string(path).map_err(|source: std::io::Error| GeneratorError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn write_text(path: &Path, contents: &str) -> GeneratorResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source: std::io::Error| GeneratorError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    std::fs::write(path, contents.as_bytes()).map_err(|source: std::io::Error| GeneratorError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[must_use]
pub fn external_tool_spec() -> DatasetSpec {
    DatasetSpec {
        source: corpus::SOURCE_EXTERNAL_OBFUSCATOR.to_owned(),
        generator: EXTERNAL_TOOL_NAME.to_owned(),
        transform: "external".to_owned(),
        id_prefix: "toolobf".to_owned(),
        widths: EXTERNAL_TOOL_WIDTHS.to_vec(),
    }
}

pub fn assemble(root: &Path, jobs: usize) -> GeneratorResult<(Vec<Entry>, Vec<String>)> {
    let mut entries: Vec<Entry> = plan::generate_in_house(jobs)?;
    let mut rejects: Vec<String> = Vec::new();
    let tool_path: PathBuf = corpus_dir(root).join(EXTERNAL_TOOL_FILE);
    if tool_path.is_file() {
        let text: String = read_text(&tool_path)?;
        let ingested: Ingested = ingest_tool_rows(&text, &external_tool_spec());
        entries.extend(ingested.entries);
        rejects.extend(ingested.rejects);
    }
    sort_entries(&mut entries);
    Ok((entries, rejects))
}

pub fn write_corpus(directory: &Path, entries: &[Entry]) -> GeneratorResult<()> {
    let (cases, truths): (String, String) = render(entries)?;
    write_text(&directory.join(CASES_FILE), &cases)?;
    write_text(&directory.join(TRUTH_FILE), &truths)
}

pub fn check_corpus(directory: &Path, entries: &[Entry]) -> GeneratorResult<()> {
    let (cases, truths): (String, String) = render(entries)?;
    for (name, rendered) in [(CASES_FILE, &cases), (TRUTH_FILE, &truths)] {
        let path: PathBuf = directory.join(name);
        let committed: String = read_text(&path)?;
        if committed != *rendered {
            return Err(GeneratorError::Drift {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}
