#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use super::chain_v1;
use super::output::OutputFormat;

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    max_depth: Option<u8>,
    _emit_kinds: Vec<String>,
    dry_run: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let cap: u8 = max_depth.unwrap_or(8);
    let chain_arg: String = if dry_run {
        format!("?:{cap}")
    } else {
        format!("auto:{cap}")
    };
    chain_v1::run_with_disk(input, out, chain_arg, None, fmt, !dry_run)
}
