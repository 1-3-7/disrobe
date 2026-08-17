#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]
use std::path::PathBuf;

use super::batch::{self, BatchOptions};
use super::chain_v1::{self, ChainRunOptions};
use super::emit::{EmitKind, EmitSpec};
use super::output::OutputFormat;

#[derive(Clone, Debug, Default)]
pub(crate) struct BatchArgs {
    pub(crate) max_depth: Option<usize>,
    pub(crate) include: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) jobs: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AutoOptions {
    pub(crate) dry_run: bool,
    pub(crate) redact: bool,
    pub(crate) capture_stages: bool,
    pub(crate) i_have_authorization: bool,
}

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    max_depth: Option<u8>,
    emit_kinds: Vec<String>,
    fmt: OutputFormat,
    options: AutoOptions,
    batch_args: BatchArgs,
) -> miette::Result<()> {
    let AutoOptions {
        dry_run,
        redact,
        capture_stages,
        i_have_authorization,
    } = options;
    let emit_spec: EmitSpec = EmitSpec::parse(&emit_kinds)?;
    let emit_recovery: bool = emit_spec.contains(EmitKind::Recovery);
    let other_kinds: bool = emit_spec.iter().any(|k: EmitKind| k != EmitKind::Recovery);
    if other_kinds {
        return Err(miette::miette!(
            "DR-CLI-0164: `auto --emit` is not supported (except `recovery`); the chain engine writes a single chain.json. Run the matching per-language subcommand (e.g. `disrobe py decompile --emit ...`) to request structured emit artifacts."
        ));
    }
    let cap: u8 = max_depth.unwrap_or(8);

    if input.is_dir() {
        if dry_run {
            return Err(miette::miette!(
                "DR-CLI-0346: `auto --dry-run` is a single-file plan-only mode; it does not apply to directory batch runs"
            ));
        }
        let out_root: PathBuf = out.unwrap_or_else(|| default_batch_out(&input));
        let opts: BatchOptions = BatchOptions {
            out_root,
            chain_arg: format!("auto:{cap}"),
            max_depth: batch_args.max_depth,
            include: batch_args.include,
            exclude: batch_args.exclude,
            jobs: batch_args.jobs.max(1),
            redact,
            capture_stages,
            i_have_authorization,
        };
        return batch::run_dir(input, opts, fmt);
    }

    let chain_arg: String = if dry_run {
        format!("?:{cap}")
    } else {
        format!("auto:{cap}")
    };
    chain_v1::run_with_disk(
        input,
        out,
        chain_arg,
        None,
        fmt,
        ChainRunOptions {
            write_to_disk: !dry_run,
            redact,
            capture_stages,
            emit_recovery,
            i_have_authorization,
        },
    )
}

fn default_batch_out(dir: &std::path::Path) -> PathBuf {
    let stem: &str = dir
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .filter(|s: &&str| !s.is_empty())
        .unwrap_or("batch");
    PathBuf::from(format!("./out/{stem}-batch"))
}
