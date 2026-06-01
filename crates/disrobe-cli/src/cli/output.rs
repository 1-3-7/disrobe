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
            let stdout: std::io::Stdout = std::io::stdout();
            let mut h: std::io::StdoutLock<'_> = stdout.lock();
            h.write_all(s.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
            h.write_all(b"\n")
                .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
            Ok(())
        }
        OutputFormat::Ndjson => {
            let s: String = serde_json::to_string(value)
                .map_err(|e| miette::miette!("DR-CLI-0091: ndjson serialize: {e}"))?;
            let stdout: std::io::Stdout = std::io::stdout();
            let mut h: std::io::StdoutLock<'_> = stdout.lock();
            h.write_all(s.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
            h.write_all(b"\n")
                .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
            Ok(())
        }
        OutputFormat::Sarif => emit_sarif(value),
    }
}

fn emit_sarif<T: serde::Serialize>(value: &T) -> miette::Result<()> {
    let payload: serde_json::Value = serde_json::to_value(value)
        .map_err(|e| miette::miette!("DR-CLI-0093: sarif inner serialize: {e}"))?;
    let envelope: serde_json::Value = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "disrobe",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/1-3-7/disrobe",
                    "rules": []
                }
            },
            "results": sarif_results_from(&payload),
            "properties": { "disrobe": payload }
        }]
    });
    let s: String = serde_json::to_string_pretty(&envelope)
        .map_err(|e| miette::miette!("DR-CLI-0094: sarif envelope serialize: {e}"))?;
    let stdout: std::io::Stdout = std::io::stdout();
    let mut h: std::io::StdoutLock<'_> = stdout.lock();
    h.write_all(s.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
    h.write_all(b"\n")
        .map_err(|e| miette::miette!("DR-CLI-0092: stdout write: {e}"))?;
    Ok(())
}

fn sarif_results_from(payload: &serde_json::Value) -> serde_json::Value {
    let mut results: Vec<serde_json::Value> = Vec::new();
    if let Some(findings) = payload.get("findings").and_then(|v| v.as_array()) {
        for f in findings {
            let rule_id: &str = f
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("DR-UNKNOWN");
            let message: String = f
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("disrobe finding")
                .to_owned();
            let uri: Option<&str> = f.get("uri").and_then(|v| v.as_str());
            let level: &str = f.get("level").and_then(|v| v.as_str()).unwrap_or("note");
            let mut entry: serde_json::Value = serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": message }
            });
            if let Some(u) = uri {
                entry["locations"] = serde_json::json!([{
                    "physicalLocation": { "artifactLocation": { "uri": u } }
                }]);
            }
            results.push(entry);
        }
    }
    serde_json::Value::Array(results)
}
