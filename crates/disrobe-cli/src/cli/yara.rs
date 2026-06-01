use std::path::PathBuf;

use disrobe_core::{YaraLoaderReport, parse_yara_report};

use crate::cli::output::{self, OutputFormat};

pub(crate) fn run(path: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-YARA-0050: cannot read ruleset: {e}"))?;
    let text: String = String::from_utf8(bytes)
        .map_err(|e| miette::miette!("DR-YARA-0051: ruleset is not valid UTF-8: {e}"))?;
    let uri: String = path.display().to_string();
    let report: YaraLoaderReport = parse_yara_report(&text, Some(&uri))
        .map_err(|e| miette::miette!("DR-YARA-0052: parse failed: {e}"))?;
    output::emit(fmt, &report, || {
        if report.ruleset.rules.is_empty() {
            println!("no rules parsed");
        } else {
            for r in &report.ruleset.rules {
                let tags: String = r.tags.join(",");
                println!(
                    "{}\t{} tags=[{}] strings={} cond={}B",
                    r.name,
                    r.modifiers.join("+"),
                    tags,
                    r.strings.len(),
                    r.condition.len(),
                );
            }
        }
    })
}
