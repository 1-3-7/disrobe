#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use super::chain_v1;
use super::emit::EmitSpec;
use super::output::OutputFormat;

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    max_depth: Option<u8>,
    emit_kinds: Vec<String>,
    dry_run: bool,
    fmt: OutputFormat,
    capture_stages: bool,
) -> miette::Result<()> {
    let emit_spec: EmitSpec = EmitSpec::parse(&emit_kinds)?;
    if !emit_spec.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0164: `auto --emit` is not supported; the chain engine writes a single chain.json. Run the matching per-language subcommand (e.g. `disrobe py decompile --emit ...`) to request structured emit artifacts."
        ));
    }
    let cap: u8 = max_depth.unwrap_or(8);
    let chain_arg: String = if dry_run {
        format!("?:{cap}")
    } else {
        format!("auto:{cap}")
    };
    chain_v1::run_with_disk(input, out, chain_arg, None, fmt, !dry_run, capture_stages)
}
