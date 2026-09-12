use std::path::PathBuf;

use disrobe_core::yara_gen::{self, GenerateOptions, GeneratedRule};
use disrobe_core::{YaraLoaderReport, parse_yara_report};

use crate::cli::output::{self, OutputFormat};

#[derive(clap::Subcommand, Debug)]
pub(crate) enum YaraCmd {
    #[command(about = "parse a YARA ruleset (.yar/.yara) into a typed AST; read-only, no matching")]
    Parse {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    #[command(
        about = "synthesize a candidate YARA rule from an artifact (high-signal strings + magic bytes + byte pattern); output round-trips through the parser"
    )]
    Generate {
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        #[arg(
            long,
            default_value = "disrobe_generated",
            help = "rule name (YARA identifier)"
        )]
        name: String,
        #[arg(
            long,
            help = "embed this sha256 in the rule meta (not computed from clock)"
        )]
        sha256: Option<String>,
        #[arg(
            long,
            help = "embed this date string in the rule meta (e.g. 2026-06-10)"
        )]
        date: Option<String>,
        #[arg(
            long,
            default_value_t = 20,
            value_name = "N",
            help = "maximum number of high-signal strings to include"
        )]
        max_strings: usize,
    },
}

pub(crate) fn run(action: YaraCmd, fmt: OutputFormat) -> miette::Result<()> {
    match action {
        YaraCmd::Parse { path } => run_parse(path, fmt),
        YaraCmd::Generate {
            input,
            name,
            sha256,
            date,
            max_strings,
        } => run_generate(input, name, sha256, date, max_strings, fmt),
    }
}

fn run_parse(path: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
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

fn run_generate(
    input: PathBuf,
    name: String,
    sha256: Option<String>,
    date: Option<String>,
    max_strings: usize,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-YARA-0053: cannot read input: {e}"))?;
    let opts: GenerateOptions = GenerateOptions {
        name,
        sha256,
        date,
        max_strings: max_strings.max(1),
    };
    let generated: GeneratedRule = yara_gen::generate(&bytes, &opts)
        .map_err(|e| miette::miette!("DR-YARA-0054: rule generation failed: {e}"))?;
    output::emit(fmt, &generated, || {
        print!("{}", generated.source);
    })
}
