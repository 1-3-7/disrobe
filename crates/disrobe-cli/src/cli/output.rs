#![allow(clippy::print_stdout)]
use std::io::Write as _;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Sarif,
}

impl OutputFormat {
    pub(crate) const fn from_flags(json: bool, ndjson: bool, sarif: bool) -> Self {
        if sarif {
            Self::Sarif
        } else if ndjson {
            Self::Ndjson
        } else if json {
            Self::Json
        } else {
            Self::Text
        }
    }

    pub(crate) const fn is_machine(self) -> bool {
        !matches!(self, Self::Text)
    }
}

fn write_stdout_line(s: &str) -> miette::Result<()> {
    let stdout: std::io::Stdout = std::io::stdout();
    let mut h: std::io::StdoutLock<'_> = stdout.lock();
    h.write_all(s.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
    h.write_all(b"\n")
        .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
    Ok(())
}

pub(crate) fn emit<T: serde::Serialize, F: FnOnce()>(
    fmt: OutputFormat,
    value: &T,
    text_fallback: F,
) -> miette::Result<()> {
    match fmt {
        OutputFormat::Text => {
            text_fallback();
            Ok(())
        }
        OutputFormat::Json => {
            let s: String = serde_json::to_string_pretty(value)
                .map_err(|e| miette::miette!("DR-CLI-0091: json serialize: {e}"))?;
            write_stdout_line(&s)
        }
        OutputFormat::Ndjson => {
            let s: String = serde_json::to_string(value)
                .map_err(|e| miette::miette!("DR-CLI-0091: ndjson serialize: {e}"))?;
            write_stdout_line(&s)
        }
        OutputFormat::Sarif => emit_sarif(value),
    }
}

pub(crate) fn emit_sarif_log(log: &crate::cli::sarif::SarifLog) -> miette::Result<()> {
    let s: String = serde_json::to_string_pretty(log)
        .map_err(|e| miette::miette!("DR-CLI-0094: sarif envelope serialize: {e}"))?;
    write_stdout_line(&s)
}

fn emit_sarif<T: serde::Serialize>(value: &T) -> miette::Result<()> {
    use crate::cli::sarif::{Driver, SarifLog};
    let payload: serde_json::Value = serde_json::to_value(value)
        .map_err(|e| miette::miette!("DR-CLI-0093: sarif inner serialize: {e}"))?;
    let log: SarifLog = SarifLog::new(Driver::disrobe(Vec::new()), sarif_results_from(&payload));
    emit_sarif_log(&log)
}

fn finding_region(f: &serde_json::Value) -> Option<crate::cli::sarif::Region> {
    let offset: u64 = f.get("offset").and_then(serde_json::Value::as_u64)?;
    Some(crate::cli::sarif::Region::at_byte_offset(offset))
}

fn sarif_results_from(payload: &serde_json::Value) -> Vec<crate::cli::sarif::SarifResult> {
    use crate::cli::sarif::{
        ArtifactLocation, Location, Message, PhysicalLocation, SarifLevel, SarifResult,
    };
    let Some(findings): Option<&Vec<serde_json::Value>> =
        payload.get("findings").and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    findings
        .iter()
        .map(|f: &serde_json::Value| {
            let rule_id: String = f
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("DR-UNKNOWN")
                .to_owned();
            let text: String = f
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("disrobe finding")
                .to_owned();
            let level: SarifLevel = match f.get("level").and_then(|v| v.as_str()) {
                Some("error") => SarifLevel::Error,
                Some("warning") => SarifLevel::Warning,
                _ => SarifLevel::Note,
            };
            let region: Option<crate::cli::sarif::Region> = finding_region(f);
            let locations: Vec<Location> = f
                .get("uri")
                .and_then(|v| v.as_str())
                .map(|u: &str| {
                    vec![Location {
                        physical_location: PhysicalLocation {
                            artifact_location: ArtifactLocation { uri: u.to_owned() },
                            region,
                        },
                    }]
                })
                .unwrap_or_default();
            SarifResult {
                rule_id,
                level,
                message: Message { text },
                locations,
            }
        })
        .collect()
}
