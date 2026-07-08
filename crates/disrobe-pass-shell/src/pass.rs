use disrobe_core::debug::DebugLog;
use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::bash::{
    IndirectionReport, NodeBashObfuscateReport, peel_indirection, reverse_node_bash_obfuscate,
};
use crate::detect::{Detection, Dialect, Family, detect};
use crate::format_wire::format_identity;
use crate::pdf::PdfReport;
use crate::xlm::{XlmRecovery, XlmSheet};

pub const PASS_INPUT_PATH_CAP: &str = "raw.shell";

#[derive(Debug, Default, Clone, Copy)]
pub struct ShellPass;

impl LegacyPass for ShellPass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("shell.dialect-detected", 1)];

    fn id(&self) -> PassId {
        "disrobe-pass-shell"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let dbg: DebugLog = DebugLog::for_scope("shell");
        dbg.section("shell.pass");
        let input: PassInput = decode_pass_input(&artifact.envelope);
        dbg.kv("input_len", || input.bytes.len().to_string());
        let detection: Detection = detect(&input.bytes);
        dbg.kv("dialect", || format!("{:?}", detection.dialect));
        dbg.kv("family", || format!("{:?}", detection.family));
        dbg.kv("confidence", || detection.confidence.to_string());
        if detection.confidence < 0.5 {
            dbg.line(|| format!("confidence {} below 0.5 threshold", detection.confidence));
            return Err(CoreError::PassFailure(
                "DR-SHELL-PASS: dialect below threshold".to_owned(),
            ));
        }
        let source: String = std::str::from_utf8(&input.bytes).map_or_else(
            |_| {
                format!(
                    "/* non-utf8 shell payload of {} bytes */",
                    input.bytes.len()
                )
            },
            format_identity,
        );
        let (recovered, recovery_steps, recovery_walls): (
            Option<String>,
            Vec<String>,
            Vec<String>,
        ) = match detection.dialect {
            Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh
                if detection.family == Family::NodeBashObfuscate =>
            {
                match reverse_node_bash_obfuscate(&source) {
                    Some(NodeBashObfuscateReport {
                        output,
                        mut steps,
                        walls,
                        chunk_count,
                        ..
                    }) if output != source => {
                        steps.insert(0, format!("node-bash-obfuscate:chunks={chunk_count}"));
                        let mut merged_walls: Vec<String> = walls;
                        match peel_indirection(&output) {
                            Ok(IndirectionReport {
                                steps: inner_steps,
                                output: peeled,
                                walls: inner_walls,
                                ..
                            }) if !inner_steps.is_empty() && peeled != output => {
                                steps.extend(inner_steps);
                                merged_walls.extend(inner_walls);
                                (Some(peeled), steps, merged_walls)
                            }
                            _ => (Some(output), steps, merged_walls),
                        }
                    }
                    _ => (None, Vec::new(), Vec::new()),
                }
            }
            Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh => {
                match peel_indirection(&source) {
                    Ok(IndirectionReport {
                        steps,
                        output,
                        walls,
                        ..
                    }) if !steps.is_empty() && output != source => (Some(output), steps, walls),
                    _ => (None, Vec::new(), Vec::new()),
                }
            }
            _ => (None, Vec::new(), Vec::new()),
        };
        let xlm: Option<XlmRecovery> = if detection.dialect == Dialect::Xlm {
            crate::xlm::recover_xlm(&input.bytes)
        } else {
            None
        };
        let (recovered, recovery_steps): (Option<String>, Vec<String>) = match &xlm {
            Some(report) => {
                let mut steps: Vec<String> = recovery_steps;
                steps.push(format!("xlm.formulas={}", report.total_formulas()));
                (Some(render_xlm(report)), steps)
            }
            None => (recovered, recovery_steps),
        };
        let pdf: Option<PdfReport> = if detection.dialect == Dialect::Pdf {
            crate::pdf::analyze_pdf(&input.bytes)
        } else {
            None
        };
        let (recovered, recovery_steps): (Option<String>, Vec<String>) = match &pdf {
            Some(report) => {
                let mut steps: Vec<String> = recovery_steps;
                steps.push(format!("pdf.objects={}", report.object_count));
                if !report.javascript.is_empty() {
                    steps.push(format!("pdf.javascript={}", report.javascript.len()));
                }
                if !report.actions.is_empty() {
                    steps.push(format!("pdf.actions={}", report.actions.len()));
                }
                if !report.embedded_files.is_empty() {
                    steps.push(format!(
                        "pdf.embedded_files={}",
                        report.embedded_files.len()
                    ));
                }
                (Some(render_pdf(report)), steps)
            }
            None => (recovered, recovery_steps),
        };
        dbg.kv("recovery_steps", || recovery_steps.len().to_string());
        dbg.kv("recovered", || recovered.is_some().to_string());
        let report: ShellPassReport = ShellPassReport {
            source_path: input.source_path,
            dialect: format!("{:?}", detection.dialect),
            family: format!("{:?}", detection.family),
            confidence: detection.confidence,
            source,
            recovered,
            recovery_steps,
            recovery_walls,
            xlm,
            pdf,
        };
        let payload: Vec<u8> = serde_json::to_vec(&report)
            .map_err(|e| CoreError::PassFailure(format!("DR-SHELL-PASS encode: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Surface, payload, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

#[derive(Debug, Clone)]
pub struct PassInput {
    pub source_path: String,
    pub bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        bytes: envelope_bytes.to_vec(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellPassReport {
    pub source_path: String,
    pub dialect: String,
    pub family: String,
    pub confidence: f32,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recovered: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub recovery_steps: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub recovery_walls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub xlm: Option<XlmRecovery>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pdf: Option<PdfReport>,
}

fn render_xlm(report: &XlmRecovery) -> String {
    let mut out: String = String::new();
    for entry in &report.entry_points {
        out.push_str(&format!("' entry: {} -> {}\n", entry.name, entry.target));
    }
    for sheet in &report.sheets {
        out.push_str(&format!(
            "' ===== {} sheet: {} =====\n",
            sheet.kind, sheet.name
        ));
        render_sheet(sheet, &mut out);
    }
    out.truncate(out.trim_end().len());
    out
}

fn render_pdf(report: &PdfReport) -> String {
    let mut out: String = String::new();
    let version: String = report.pdf_version.clone().unwrap_or_else(|| "?".to_owned());
    out.push_str(&format!(
        "%PDF-{version} objects={} xref={}{} recovered_by_scan={}\n",
        report.object_count,
        if report.xref_table { "table" } else { "" },
        if report.xref_stream { "stream" } else { "" },
        report.recovered_by_scan,
    ));
    if let Some(encryption) = &report.encryption {
        out.push_str(&format!(
            "encrypted: {} decrypted={}\n",
            encryption.handler, encryption.decrypted
        ));
    }
    if report.open_action {
        out.push_str("open-action: present\n");
    }
    for entry in &report.name_obfuscation {
        out.push_str(&format!(
            "name-obfuscation: {} -> {}\n",
            entry.raw, entry.decoded
        ));
    }
    for finding in &report.javascript {
        out.push_str(&format!("== javascript [{}]", finding.origin));
        if !finding.deobfuscation.is_empty() {
            out.push_str(&format!(" ({})", finding.deobfuscation.join(",")));
        }
        out.push('\n');
        out.push_str(&finding.script);
        out.push('\n');
    }
    for action in &report.actions {
        out.push_str(&format!("== action {} [{}]", action.kind, action.origin));
        if !action.target.is_empty() {
            out.push_str(&format!(" -> {}", action.target));
        }
        out.push('\n');
    }
    for file in &report.embedded_files {
        out.push_str(&format!(
            "== embedded-file {} ({} bytes) sha256={}",
            file.name, file.bytes, file.sha256
        ));
        if let Some(subtype) = &file.subtype {
            out.push_str(&format!(" subtype={subtype}"));
        }
        out.push('\n');
    }
    out.truncate(out.trim_end().len());
    out
}

fn render_sheet(sheet: &XlmSheet, out: &mut String) {
    for cell in &sheet.cells {
        out.push_str(&sheet.name);
        out.push('!');
        out.push_str(&cell.cell);
        out.push('\t');
        out.push_str(&cell.formula);
        out.push('\n');
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;

    fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: body.to_vec(),
            source_hash: [0u8; 32],
            detected_format: None,
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        Envelope::new(Rung::Raw, hot, vec![])
            .encode()
            .expect("encode envelope")
    }

    #[test]
    fn shell_pass_metadata_advertises_capabilities() {
        let p: ShellPass = ShellPass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-shell");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn pass_run_envelope_roundtrip() {
        let body: &[u8] = b"#!/bin/bash\necho hi\n";
        let bytes: Vec<u8> = synth_envelope("script.sh", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = ShellPass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Surface);
        assert_eq!(out.root_hash, [7u8; 32]);
        let report: ShellPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.source_path, "script.sh");
        assert_eq!(report.dialect, "Bash");
        assert!(report.source.contains("echo hi"));
    }

    #[test]
    fn pass_recovers_base64_dropper() {
        let body: &[u8] = b"#!/bin/bash\necho aWQ= | base64 -d | bash\n";
        let bytes: Vec<u8> = synth_envelope("dropper.sh", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = ShellPass.run(&input).expect("run");
        let report: ShellPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        let recovered: String = report.recovered.expect("recovery present");
        assert!(recovered.contains("id"), "recovered={recovered}");
        assert!(
            report
                .recovery_steps
                .iter()
                .any(|s: &String| s == "base64-decode"),
            "steps={:?}",
            report.recovery_steps
        );
    }

    #[test]
    fn pass_recovers_node_bash_obfuscate() {
        let body: &[u8] =
            include_bytes!("../../../corpus/shell/bash/node-bash-obfuscate/obfuscated_chunk4.sh");
        let bytes: Vec<u8> = synth_envelope("out.sh", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = ShellPass.run(&input).expect("run");
        let report: ShellPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.family, "NodeBashObfuscate");
        let recovered: String = report.recovered.expect("recovery present");
        assert!(
            recovered.contains("GREETING='hello world'") && recovered.contains("for i in 1 2 3"),
            "recovered={recovered}"
        );
        assert!(
            report
                .recovery_steps
                .iter()
                .any(|s: &String| s.starts_with("node-bash-obfuscate:chunks=")),
            "steps={:?}",
            report.recovery_steps
        );
    }

    #[test]
    fn pass_surfaces_pdf_javascript_and_report() {
        let body: &[u8] = include_bytes!("../../../corpus/shell/pdf/openaction_table.pdf");
        let bytes: Vec<u8> = synth_envelope("sample.pdf", body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let out: Artifact = ShellPass.run(&input).expect("run");
        let report: ShellPassReport = serde_json::from_slice(&out.envelope).expect("decode report");
        assert_eq!(report.dialect, "Pdf");
        let pdf: &crate::pdf::PdfReport = report.pdf.as_ref().expect("pdf report present");
        assert!(
            pdf.javascript
                .iter()
                .any(|f: &crate::pdf::JsFinding| f.script.contains("OPENACTION_TABLE_MARKER")),
            "javascript surfaced"
        );
        let recovered: String = report.recovered.expect("rendered recovery");
        assert!(recovered.contains("OPENACTION_TABLE_MARKER"));
    }

    #[test]
    fn shell_pass_run_rejects_unrecognized_input() {
        let bytes: Vec<u8> = synth_envelope("junk.bin", &[0u8; 16]);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [7u8; 32],
        );
        let err: CoreError = ShellPass.run(&input).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SHELL-PASS"));
    }
}
