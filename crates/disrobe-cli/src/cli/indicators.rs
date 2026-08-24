use std::path::PathBuf;

use disrobe_core::interop::{ArtifactSchema, IndicatorAggregator, IndicatorBundle};
use disrobe_core::ioc::{self, IocReport};

use crate::cli::output::OutputFormat;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum IndicatorsFormat {
    #[default]
    Text,
    Json,
}

const fn schema_label(schema: ArtifactSchema) -> &'static str {
    match schema {
        ArtifactSchema::Recon => "recon",
        ArtifactSchema::Ioc => "ioc",
        ArtifactSchema::Prowl => "prowl",
    }
}

pub(crate) fn analyze_target(
    bytes: &[u8],
    uri: &str,
) -> Result<(IocReport, IndicatorBundle), String> {
    let report: IocReport = ioc::report(bytes, Some(uri));
    let encoded: String = serde_json::to_string(&report)
        .map_err(|_| "the static indicator report could not be serialized".to_string())?;
    let mut aggregator: IndicatorAggregator = IndicatorAggregator::new();
    if aggregator.ingest_json(&encoded) != Some(ArtifactSchema::Ioc) {
        return Err("the static indicator report was not recognized by the aggregator".to_string());
    }
    Ok((report, aggregator.finish()))
}

fn render_text(bundle: &IndicatorBundle) {
    if bundle.indicators.is_empty() {
        println!("no indicators");
    } else {
        for ind in &bundle.indicators {
            println!(
                "{}\t{}\t[{}]\t{}",
                ind.class.label(),
                ind.value,
                ind.sources.join(","),
                ind.kinds.join(",")
            );
        }
    }
    println!(
        "\n{} indicator(s) from {} artifact(s): {}",
        bundle.total,
        bundle.ingested.len(),
        bundle.ingested.join(", ")
    );
}

pub(crate) fn run(
    inputs: Vec<PathBuf>,
    targets_only: bool,
    format: IndicatorsFormat,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if inputs.is_empty() {
        return Err(miette::miette!(
            "DR-IND-0060: pass at least one disrobe recon/ioc/prowl JSON artifact"
        ));
    }
    let mut agg: IndicatorAggregator = IndicatorAggregator::new();
    for path in &inputs {
        let text: String = std::fs::read_to_string(path)
            .map_err(|e| miette::miette!("DR-IND-0061: cannot read `{}`: {e}", path.display()))?;
        match agg.ingest_json(&text) {
            Some(schema) => {
                eprintln!("ingested {} as {}", path.display(), schema_label(schema));
            }
            None => {
                return Err(miette::miette!(
                    "DR-IND-0062: `{}` is not a recognized disrobe recon/ioc/prowl artifact",
                    path.display()
                ));
            }
        }
    }

    if targets_only {
        for target in agg.network_values() {
            println!("{target}");
        }
        return Ok(());
    }

    let bundle: IndicatorBundle = agg.finish();
    let effective: IndicatorsFormat = if fmt.is_machine() {
        IndicatorsFormat::Json
    } else {
        format
    };
    match effective {
        IndicatorsFormat::Text => {
            render_text(&bundle);
            Ok(())
        }
        IndicatorsFormat::Json => {
            let s: String = serde_json::to_string_pretty(&bundle)
                .map_err(|e| miette::miette!("DR-IND-0063: json serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::interop::{IndicatorClass, UnifiedIndicator};
    use disrobe_core::scratch::ScratchFile;

    fn tmp_file(stem: &str, content: &str) -> (ScratchFile, PathBuf) {
        let purpose: String = format!("disrobe-ind-{stem}");
        let (scratch, file): (ScratchFile, std::fs::File) =
            ScratchFile::create(&purpose, "json").expect("create scratch file");
        drop(file);
        let p: PathBuf = scratch.path().to_path_buf();
        std::fs::write(&p, content).expect("write tmp");
        (scratch, p)
    }

    const RECON_DOC: &str = r#"{"schema":"disrobe.recon/v0","files_scanned":1,"bytes_scanned":1,"non_utf8_files":0,"total":1,"findings":[{"category":"url","rule_id":"r","value":"https://recon.example/x","line":1,"column":1,"offset":0,"severity":"note"}]}"#;
    const PROWL_DOC: &str = r#"{"schema":"disrobe.prowl/v0","targets":["recon.example"],"sources":["wayback"],"url_total":1,"ioc_total":0,"urls":[{"url":"https://recon.example/y","source":"wayback"}],"iocs":[]}"#;

    #[test]
    fn aggregates_files_across_schemas() {
        let (_recon_scratch, recon): (ScratchFile, PathBuf) = tmp_file("recon", RECON_DOC);
        let (_prowl_scratch, prowl): (ScratchFile, PathBuf) = tmp_file("prowl", PROWL_DOC);
        let mut agg: IndicatorAggregator = IndicatorAggregator::new();
        let r: String = std::fs::read_to_string(&recon).unwrap();
        let p: String = std::fs::read_to_string(&prowl).unwrap();
        assert_eq!(agg.ingest_json(&r), Some(ArtifactSchema::Recon));
        assert_eq!(agg.ingest_json(&p), Some(ArtifactSchema::Prowl));
        let bundle: IndicatorBundle = agg.finish();
        assert!(
            bundle
                .indicators
                .iter()
                .any(|i: &UnifiedIndicator| i.class == IndicatorClass::Url
                    && i.value == "https://recon.example/x"),
            "{:?}",
            bundle.indicators
        );
    }

    #[test]
    fn unknown_input_errors() {
        let (_junk_scratch, junk): (ScratchFile, PathBuf) =
            tmp_file("junk", r#"{"unrelated":true}"#);
        let err: miette::Report = run(
            vec![junk],
            false,
            IndicatorsFormat::Json,
            OutputFormat::Text,
        )
        .expect_err("must reject unknown artifact");
        assert!(format!("{err}").contains("DR-IND-0062"));
    }
}
