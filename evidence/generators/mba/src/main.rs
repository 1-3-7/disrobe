#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use disrobe_evidence_mba::corpus::Entry;
use disrobe_evidence_mba::datasets::ingest_directory;
use disrobe_evidence_mba::error::{GeneratorError, GeneratorResult};
use disrobe_evidence_mba::ingest::Ingested;
use disrobe_evidence_mba::{assemble, check_corpus, corpus_dir, write_corpus};

const DEFAULT_DATASET_LIMIT: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Generate,
    Check,
    Datasets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    command: Command,
    root: PathBuf,
    jobs: usize,
    input: Option<PathBuf>,
    out: Option<PathBuf>,
    limit: usize,
}

fn usage() -> String {
    [
        "usage: disrobe-evidence-mba <generate|check|datasets> [options]",
        "  --root <dir>    repository root (default: the current directory)",
        "  --jobs <n>      generation worker count (default: 4)",
        "  --input <dir>   dataset cache directory, for the datasets command",
        "  --out <dir>     output directory, for the datasets command",
        "  --limit <n>     lines taken per dataset file (default: 200)",
    ]
    .join("\n")
}

fn parse_options(arguments: &[String]) -> GeneratorResult<Options> {
    let Some(head) = arguments.first() else {
        return Err(GeneratorError::Invalid { detail: usage() });
    };
    let command: Command = match head.as_str() {
        "generate" => Command::Generate,
        "check" => Command::Check,
        "datasets" => Command::Datasets,
        other => {
            return Err(GeneratorError::Invalid {
                detail: format!("unknown command {other:?}\n{}", usage()),
            });
        }
    };
    let mut options: Options = Options {
        command,
        root: PathBuf::from("."),
        jobs: 4,
        input: None,
        out: None,
        limit: DEFAULT_DATASET_LIMIT,
    };
    let mut index: usize = 1;
    while let Some(flag) = arguments.get(index) {
        let Some(value) = arguments.get(index + 1) else {
            return Err(GeneratorError::Invalid {
                detail: format!("flag {flag} needs a value\n{}", usage()),
            });
        };
        match flag.as_str() {
            "--root" => options.root = PathBuf::from(value),
            "--jobs" => {
                options.jobs = value
                    .parse::<usize>()
                    .map_err(|_| GeneratorError::Invalid {
                        detail: format!("--jobs needs a positive integer, got {value:?}"),
                    })?;
            }
            "--input" => options.input = Some(PathBuf::from(value)),
            "--out" => options.out = Some(PathBuf::from(value)),
            "--limit" => {
                options.limit = value
                    .parse::<usize>()
                    .map_err(|_| GeneratorError::Invalid {
                        detail: format!("--limit needs a positive integer, got {value:?}"),
                    })?;
            }
            other => {
                return Err(GeneratorError::Invalid {
                    detail: format!("unknown flag {other:?}\n{}", usage()),
                });
            }
        }
        index += 2;
    }
    Ok(options)
}

fn report(entries: &[Entry], rejects: &[String]) {
    let mut in_house: usize = 0;
    let mut external: usize = 0;
    let mut dataset: usize = 0;
    for entry in entries {
        match entry.case.source.as_str() {
            "in-house" => in_house += 1,
            "external-obfuscator" => external += 1,
            _ => dataset += 1,
        }
    }
    println!(
        "entries {} (external-obfuscator {external}, public-dataset {dataset}, in-house {in_house}), rejected {}",
        entries.len(),
        rejects.len()
    );
    for reject in rejects.iter().take(20) {
        eprintln!("rejected {reject}");
    }
    if rejects.len() > 20 {
        eprintln!("rejected {} more", rejects.len() - 20);
    }
}

fn run(options: &Options) -> GeneratorResult<()> {
    match options.command {
        Command::Generate => {
            let (entries, rejects): (Vec<Entry>, Vec<String>) =
                assemble(&options.root, options.jobs)?;
            report(&entries, &rejects);
            write_corpus(&corpus_dir(&options.root), &entries)
        }
        Command::Check => {
            let (entries, rejects): (Vec<Entry>, Vec<String>) =
                assemble(&options.root, options.jobs)?;
            report(&entries, &rejects);
            check_corpus(&corpus_dir(&options.root), &entries)
        }
        Command::Datasets => {
            let Some(input) = options.input.as_ref() else {
                return Err(GeneratorError::Invalid {
                    detail: "the datasets command needs --input <dir>".to_owned(),
                });
            };
            let Some(out) = options.out.as_ref() else {
                return Err(GeneratorError::Invalid {
                    detail: "the datasets command needs --out <dir>".to_owned(),
                });
            };
            let ingested: Ingested = ingest_directory(input, options.limit)?;
            report(&ingested.entries, &ingested.rejects);
            write_corpus(out, &ingested.entries)
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let options: Options = match parse_options(&arguments) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let resolved: PathBuf = resolve_root(&options.root);
    let effective: Options = Options {
        root: resolved,
        ..options
    };
    match run(&effective) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn resolve_root(candidate: &Path) -> PathBuf {
    std::fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf())
}
