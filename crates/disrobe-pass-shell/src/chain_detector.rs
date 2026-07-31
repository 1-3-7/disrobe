#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput, FAMILY_SOURCE,
    ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use serde::Serialize;

use crate::detect::{Detection, Dialect, Family, detect as detect_shell};
use crate::format_wire::format_identity;
use crate::pdf::PdfReport;
use crate::xlm::XlmRecovery;

pub const PASS_ID: PassId = "shell.deob";

const RECOVERY_MANIFEST_CHILD: &str = "shell-recovery-manifest.json";
const RECOVERY_MANIFEST_SCHEMA: &str = "disrobe.shell.recovery-manifest/v0";

const TAG_POWERSHELL: &str = "shell-powershell";
const TAG_BASH: &str = "shell-bash";
const TAG_DASH: &str = "shell-dash";
const TAG_KSH: &str = "shell-ksh";
const TAG_ZSH: &str = "shell-zsh";
const TAG_BATCH: &str = "shell-batch";
const TAG_VBA: &str = "shell-vba";
const TAG_VBS: &str = "shell-vbs";
const TAG_WSH: &str = "shell-wsh";
const TAG_PDF: &str = "shell-pdf";

#[derive(Debug)]
pub struct ShellDetector;

impl Detector for ShellDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: Detection = detect_shell(ctx.bytes);
        verdict_for(&detection)
    }
}

#[derive(Debug)]
pub struct ShellPass;

impl Pass for ShellPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ShellDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Bash,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let detection: Detection = detect_shell(bytes);
        if verdict_for(&detection).is_none() {
            return Err(CoreError::PassFailure(
                "DR-SHELL-0902: shell.deob: input dialect unknown or below confidence threshold"
                    .to_string(),
            ));
        }
        let source_text: String = recovered_source(&detection, bytes)?;
        Ok(Artifact::new(
            Rung::Surface,
            source_text.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        Ok(recovery_manifest_child(bytes).into_iter().collect())
    }
}

fn recovered_source(detection: &Detection, bytes: &[u8]) -> CoreResult<String> {
    if detection.dialect == Dialect::Pdf {
        let report: PdfReport = crate::pdf::analyze_pdf(bytes).ok_or_else(|| {
            CoreError::PassFailure(
                "DR-SHELL-0924: shell.deob: pdf structure could not be parsed; the residual wall is the malformed pdf itself"
                    .to_owned(),
            )
        })?;
        return Ok(crate::pdf::render_report(&report));
    }
    if detection.dialect == Dialect::Xlm {
        let recovered: Option<String> = crate::xlm::recover_xlm(bytes)
            .and_then(|report: XlmRecovery| crate::xlm::render_source(&report));
        return recovered.ok_or_else(|| {
            CoreError::PassFailure(
                "DR-SHELL-0925: shell.deob: xlm macro sheet detected but no recoverable formulas or entry points were found; the residual wall is the workbook itself"
                    .to_owned(),
            )
        });
    }
    if detection.dialect == Dialect::Batch {
        let decoded: core::result::Result<&str, core::str::Utf8Error> = std::str::from_utf8(bytes);
        if let Ok(text) = decoded {
            return Ok(crate::batch::deobfuscate_batch(text, &[]).output);
        }
    }
    if detection.dialect == Dialect::Vba {
        let modules: Vec<RecoveredVbaModule> = recover_vba_modules(bytes);
        if !modules.is_empty() {
            return Ok(render_vba_modules(&modules));
        }
    }
    let text: &str = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return Ok(format!(
                "/* non-utf8 shell payload of {} bytes */",
                bytes.len()
            ));
        }
    };
    match detection.dialect {
        Dialect::Vbs | Dialect::Wsh => Ok(crate::vba::deobfuscate_vbs(text).output),
        _ => reverse_for_family(detection.family, text),
    }
}

const fn residual_code_for_family(family: Family) -> Option<(&'static str, &'static str)> {
    let pair: (&'static str, &'static str) = match family {
        Family::InvokeObfuscationToken => ("DR-SHELL-0910", "Invoke-Obfuscation token"),
        Family::InvokeObfuscationAst => ("DR-SHELL-0911", "Invoke-Obfuscation AST"),
        Family::InvokeObfuscationString => ("DR-SHELL-0912", "Invoke-Obfuscation string"),
        Family::InvokeObfuscationEncoding => ("DR-SHELL-0913", "Invoke-Obfuscation encoding"),
        Family::InvokeObfuscationCompress => ("DR-SHELL-0914", "Invoke-Obfuscation compress"),
        Family::InvokeObfuscationLauncher => ("DR-SHELL-0915", "Invoke-Obfuscation launcher"),
        Family::InvokeStealth => ("DR-SHELL-0916", "Invoke-Stealth"),
        Family::PowerHell => ("DR-SHELL-0917", "PowerHell"),
        Family::Chameleon => ("DR-SHELL-0918", "Chameleon"),
        Family::Psobf => ("DR-SHELL-0919", "psobf"),
        Family::IseSteroids => ("DR-SHELL-0920", "ISESteroids"),
        Family::BashfuscatorToken
        | Family::BashfuscatorString
        | Family::BashfuscatorObfuscate
        | Family::BashfuscatorCompress => ("DR-SHELL-0921", "Bashfuscator"),
        Family::BashIndirection => ("DR-SHELL-0922", "bash indirection"),
        Family::NodeBashObfuscate => ("DR-SHELL-0923", "node-bash-obfuscate"),
        Family::Plain
        | Family::Unknown
        | Family::BatchRandom
        | Family::BatchSetIndirection
        | Family::VbaMacro
        | Family::VbsWshObfuscated => return None,
    };
    Some(pair)
}

fn reverse_failed(family: Family, err: &crate::error::Error) -> CoreError {
    let (code, label): (&'static str, &'static str) =
        residual_code_for_family(family).unwrap_or(("DR-SHELL-0909", "shell"));
    CoreError::PassFailure(format!("{code}: shell.deob: {label} reverse failed: {err}"))
}

fn recover_nothing_wall(family: Family) -> CoreError {
    let (code, label): (&'static str, &'static str) =
        residual_code_for_family(family).unwrap_or(("DR-SHELL-0909", "shell"));
    CoreError::PassFailure(format!(
        "{code}: shell.deob: {label} detected but statically unrecoverable (input passed through unchanged); the residual wall is the obfuscated artifact itself"
    ))
}

fn guard_recovered(family: Family, text: &str, recovered: String) -> CoreResult<String> {
    if recovered == text {
        return Err(recover_nothing_wall(family));
    }
    Ok(recovered)
}

fn reverse_for_family(family: Family, text: &str) -> CoreResult<String> {
    use crate::bash::{peel_indirection, reverse_bashfuscator_auto, reverse_node_bash_obfuscate};
    use crate::powershell::{
        reverse_ast, reverse_chameleon, reverse_compress, reverse_encoding, reverse_invoke_stealth,
        reverse_isesteroids, reverse_launcher, reverse_powerhell, reverse_psobf, reverse_string,
        reverse_token,
    };
    match family {
        Family::InvokeObfuscationToken => guard_recovered(family, text, reverse_token(text).output),
        Family::InvokeObfuscationAst => guard_recovered(family, text, reverse_ast(text).output),
        Family::InvokeObfuscationString => {
            guard_recovered(family, text, reverse_string(text).output)
        }
        Family::InvokeObfuscationEncoding => {
            let report: crate::powershell::ReverseReport = reverse_encoding(text)
                .map_err(|e: crate::error::Error| reverse_failed(family, &e))?;
            guard_recovered(family, text, report.output)
        }
        Family::InvokeObfuscationCompress => {
            let report: crate::powershell::ReverseReport = reverse_compress(text)
                .map_err(|e: crate::error::Error| reverse_failed(family, &e))?;
            guard_recovered(family, text, report.output)
        }
        Family::InvokeObfuscationLauncher => {
            guard_recovered(family, text, reverse_launcher(text).output)
        }
        Family::InvokeStealth => guard_recovered(family, text, reverse_invoke_stealth(text).output),
        Family::PowerHell => {
            let report: crate::powershell::powerhell::PowerHellReport = reverse_powerhell(text)
                .map_err(|e: crate::error::Error| reverse_failed(family, &e))?;
            guard_recovered(family, text, report.output)
        }
        Family::Chameleon => guard_recovered(family, text, reverse_chameleon(text).output),
        Family::Psobf => {
            let report: crate::powershell::psobf::PsobfReport =
                reverse_psobf(text).map_err(|e: crate::error::Error| reverse_failed(family, &e))?;
            guard_recovered(family, text, report.output)
        }
        Family::IseSteroids => guard_recovered(family, text, reverse_isesteroids(text).output),
        Family::BashfuscatorToken
        | Family::BashfuscatorString
        | Family::BashfuscatorObfuscate
        | Family::BashfuscatorCompress => {
            let report: crate::bash::BashfuscatorReport = reverse_bashfuscator_auto(text)
                .map_err(|e: crate::error::Error| reverse_failed(family, &e))?;
            guard_recovered(family, text, report.output)
        }
        Family::BashIndirection => {
            let report: crate::bash::IndirectionReport = peel_indirection(text)
                .map_err(|e: crate::error::Error| reverse_failed(family, &e))?;
            guard_recovered(family, text, report.output)
        }
        Family::NodeBashObfuscate => {
            let report: crate::bash::NodeBashObfuscateReport =
                reverse_node_bash_obfuscate(text).ok_or_else(|| recover_nothing_wall(family))?;
            guard_recovered(family, text, report.output)
        }
        Family::Plain
        | Family::Unknown
        | Family::BatchRandom
        | Family::BatchSetIndirection
        | Family::VbaMacro
        | Family::VbsWshObfuscated => Ok(format_identity(text)),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveredVbaModule {
    pub name: String,
    pub source: String,
}

fn recover_vba_modules(bytes: &[u8]) -> Vec<RecoveredVbaModule> {
    let mut modules: Vec<RecoveredVbaModule> = crate::vba::extract_from_bytes(bytes)
        .map(|project: crate::vba::ExtractedProject| {
            project
                .modules
                .into_iter()
                .filter(|m: &crate::vba::ExtractedModule| !m.recovered_source.trim().is_empty())
                .map(|m: crate::vba::ExtractedModule| RecoveredVbaModule {
                    name: m.name,
                    source: m.recovered_source.replace("\r\n", "\n"),
                })
                .collect::<Vec<RecoveredVbaModule>>()
        })
        .unwrap_or_default();
    for recovered in recover_vba_from_pcode(bytes) {
        match modules
            .iter_mut()
            .find(|m: &&mut RecoveredVbaModule| m.name.eq_ignore_ascii_case(&recovered.name))
        {
            Some(existing) => existing.source = recovered.source,
            None => modules.push(recovered),
        }
    }
    modules
}

fn recover_vba_from_pcode(bytes: &[u8]) -> Vec<RecoveredVbaModule> {
    let Ok(report): crate::error::Result<crate::vba::StompReport> =
        crate::vba::analyze_stomp(bytes)
    else {
        return Vec::new();
    };
    report
        .modules
        .into_iter()
        .filter(|m: &crate::vba::ModuleStompReport| {
            matches!(
                m.verdict,
                crate::vba::StompVerdict::Stomped | crate::vba::StompVerdict::PCodeOnly
            ) && !m.recovered_source.trim().is_empty()
        })
        .map(|m: crate::vba::ModuleStompReport| RecoveredVbaModule {
            name: m.module,
            source: m.recovered_source.replace("\r\n", "\n"),
        })
        .collect()
}

fn render_vba_modules(modules: &[RecoveredVbaModule]) -> String {
    let mut out: String = String::new();
    for module in modules {
        out.push_str(&format!("' ===== module: {} =====\n", module.name));
        out.push_str(module.source.trim_end());
        out.push_str("\n\n");
    }
    out.truncate(out.trim_end().len());
    out
}

fn recovery_breadcrumbs(detection: &Detection, text: &str) -> (Vec<String>, Vec<String>) {
    match detection.dialect {
        Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh
            if detection.family == Family::NodeBashObfuscate =>
        {
            match crate::bash::reverse_node_bash_obfuscate(text) {
                Some(crate::bash::NodeBashObfuscateReport {
                    output,
                    mut steps,
                    walls,
                    chunk_count,
                    ..
                }) if output != text => {
                    steps.insert(0, format!("node-bash-obfuscate:chunks={chunk_count}"));
                    let mut merged_walls: Vec<String> = walls;
                    if let Ok(crate::bash::IndirectionReport {
                        steps: inner_steps,
                        output: peeled,
                        walls: inner_walls,
                        ..
                    }) = crate::bash::peel_indirection(&output)
                        && !inner_steps.is_empty()
                        && peeled != output
                    {
                        steps.extend(inner_steps);
                        merged_walls.extend(inner_walls);
                    }
                    (steps, merged_walls)
                }
                _ => (Vec::new(), Vec::new()),
            }
        }
        Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh => {
            match crate::bash::peel_indirection(text) {
                Ok(crate::bash::IndirectionReport {
                    steps,
                    output,
                    walls,
                    ..
                }) if !steps.is_empty() && output != text => (steps, walls),
                _ => (Vec::new(), Vec::new()),
            }
        }
        _ => (Vec::new(), Vec::new()),
    }
}

fn recovery_manifest_child(bytes: &[u8]) -> Option<ChildArtifact> {
    let manifest: serde_json::Value = build_recovery_manifest(bytes)?;
    let json: Vec<u8> = serde_json::to_vec_pretty(&manifest).ok()?;
    Some(ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path: RECOVERY_MANIFEST_CHILD.to_string(),
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes: json,
    })
}

fn build_recovery_manifest(bytes: &[u8]) -> Option<serde_json::Value> {
    let detection: Detection = detect_shell(bytes);
    verdict_for(&detection)?;
    let xlm: Option<XlmRecovery> = if detection.dialect == Dialect::Xlm {
        crate::xlm::recover_xlm(bytes)
    } else {
        None
    };
    let pdf: Option<PdfReport> = if detection.dialect == Dialect::Pdf {
        crate::pdf::analyze_pdf(bytes)
    } else {
        None
    };
    let (steps, walls): (Vec<String>, Vec<String>) = match std::str::from_utf8(bytes) {
        Ok(text) => recovery_breadcrumbs(&detection, text),
        Err(_) => (Vec::new(), Vec::new()),
    };
    if xlm.is_none() && pdf.is_none() && steps.is_empty() && walls.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "schema": RECOVERY_MANIFEST_SCHEMA,
        "steps": steps,
        "walls": walls,
        "xlm": xlm,
        "pdf": pdf,
    }))
}

pub static SHELL_PASS: ShellPass = ShellPass;

const fn family_dispatch_bypasses_reverse_for_family(dialect: Dialect) -> bool {
    matches!(
        dialect,
        Dialect::Batch | Dialect::Vba | Dialect::Xlm | Dialect::Vbs | Dialect::Wsh | Dialect::Pdf
    )
}

fn verdict_for(d: &Detection) -> Option<DetectVerdict> {
    if d.confidence < 0.5 {
        return None;
    }
    if !family_dispatch_bypasses_reverse_for_family(d.dialect)
        && matches!(d.family, Family::Plain | Family::Unknown)
    {
        return None;
    }
    let (tag, marker): (&'static str, &'static str) = match d.dialect {
        Dialect::PowerShell => (TAG_POWERSHELL, "powershell-dialect"),
        Dialect::Bash => (TAG_BASH, "bash-dialect"),
        Dialect::Dash => (TAG_DASH, "dash-dialect"),
        Dialect::Ksh => (TAG_KSH, "ksh-dialect"),
        Dialect::Zsh => (TAG_ZSH, "zsh-dialect"),
        Dialect::Batch => (TAG_BATCH, "batch-dialect"),
        Dialect::Vba => (TAG_VBA, "vba-dialect"),
        Dialect::Xlm => (TAG_VBA, "xlm-dialect"),
        Dialect::Vbs => (TAG_VBS, "vbs-dialect"),
        Dialect::Wsh => (TAG_WSH, "wsh-dialect"),
        Dialect::Pdf => (TAG_PDF, "pdf-document"),
        Dialect::Unknown => return None,
    };
    Some(DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_SOURCE,
        d.confidence,
        35,
        vec![marker],
        format!(
            "shell dialect={dialect:?} family={family:?}",
            dialect = d.dialect,
            family = d.family,
        ),
    ))
}

#[derive(Debug)]
pub struct ShellObfuscatorEntry {
    pub family: Family,
    pub id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub quality: SupportQuality,
}

impl CatalogEntry for ShellObfuscatorEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const CATALOG_COUNT: usize = 20;

static CATALOG: [ShellObfuscatorEntry; CATALOG_COUNT] = [
    ShellObfuscatorEntry {
        family: Family::InvokeObfuscationToken,
        id: "ps-invoke-obfuscation-token",
        display_name: "Invoke-Obfuscation (token)",
        aliases: &["invoke-obfuscation", "io-token"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::InvokeObfuscationAst,
        id: "ps-invoke-obfuscation-ast",
        display_name: "Invoke-Obfuscation (AST)",
        aliases: &["io-ast"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::InvokeObfuscationString,
        id: "ps-invoke-obfuscation-string",
        display_name: "Invoke-Obfuscation (string)",
        aliases: &["io-string"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::InvokeObfuscationEncoding,
        id: "ps-invoke-obfuscation-encoding",
        display_name: "Invoke-Obfuscation (encoding)",
        aliases: &["io-encoding", "encodedcommand"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::InvokeObfuscationCompress,
        id: "ps-invoke-obfuscation-compress",
        display_name: "Invoke-Obfuscation (compress)",
        aliases: &["io-compress"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::InvokeObfuscationLauncher,
        id: "ps-invoke-obfuscation-launcher",
        display_name: "Invoke-Obfuscation (launcher)",
        aliases: &["io-launcher"],
        quality: SupportQuality::Partial,
    },
    ShellObfuscatorEntry {
        family: Family::InvokeStealth,
        id: "ps-invoke-stealth",
        display_name: "Invoke-Stealth",
        aliases: &["invoke-stealth"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::PowerHell,
        id: "ps-powerhell",
        display_name: "PowerHell",
        aliases: &["powerhell", "power-hell"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::Chameleon,
        id: "ps-chameleon",
        display_name: "Chameleon",
        aliases: &["chameleon"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::Psobf,
        id: "ps-psobf",
        display_name: "psobf",
        aliases: &["psobf", "taurusomar"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::IseSteroids,
        id: "ps-isesteroids",
        display_name: "ISESteroids",
        aliases: &["isesteroids"],
        quality: SupportQuality::Partial,
    },
    ShellObfuscatorEntry {
        family: Family::BashfuscatorToken,
        id: "bash-bashfuscator-token",
        display_name: "Bashfuscator (token)",
        aliases: &["bashfuscator", "bf-token"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::BashfuscatorString,
        id: "bash-bashfuscator-string",
        display_name: "Bashfuscator (string)",
        aliases: &["bf-string"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::BashfuscatorObfuscate,
        id: "bash-bashfuscator-obfuscate",
        display_name: "Bashfuscator (obfuscate)",
        aliases: &["bf-obfuscate"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::BashfuscatorCompress,
        id: "bash-bashfuscator-compress",
        display_name: "Bashfuscator (compress)",
        aliases: &["bf-compress"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::BashIndirection,
        id: "bash-indirection",
        display_name: "Bash indirection (IFS/eval)",
        aliases: &["bash-ifs", "bash-eval"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::NodeBashObfuscate,
        id: "bash-node-bash-obfuscate",
        display_name: "node-bash-obfuscate (chunk-table eval)",
        aliases: &["bash-obfuscate", "node-bash-obfuscate"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::BatchRandom,
        id: "batch-random",
        display_name: "Batch obfuscation (%random%)",
        aliases: &["batch-random"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::BatchSetIndirection,
        id: "batch-set-indirection",
        display_name: "Batch obfuscation (set indirection)",
        aliases: &["batch-set"],
        quality: SupportQuality::Full,
    },
    ShellObfuscatorEntry {
        family: Family::VbaMacro,
        id: "vba-macro",
        display_name: "VBA macro (p-code decompile + stomping)",
        aliases: &["vba", "vba-stomp"],
        quality: SupportQuality::Full,
    },
];

const fn catalog_id_for_family(family: Family) -> Option<&'static str> {
    let id: &'static str = match family {
        Family::InvokeObfuscationToken => "ps-invoke-obfuscation-token",
        Family::InvokeObfuscationAst => "ps-invoke-obfuscation-ast",
        Family::InvokeObfuscationString => "ps-invoke-obfuscation-string",
        Family::InvokeObfuscationEncoding => "ps-invoke-obfuscation-encoding",
        Family::InvokeObfuscationCompress => "ps-invoke-obfuscation-compress",
        Family::InvokeObfuscationLauncher => "ps-invoke-obfuscation-launcher",
        Family::InvokeStealth => "ps-invoke-stealth",
        Family::PowerHell => "ps-powerhell",
        Family::Chameleon => "ps-chameleon",
        Family::Psobf => "ps-psobf",
        Family::IseSteroids => "ps-isesteroids",
        Family::BashfuscatorToken => "bash-bashfuscator-token",
        Family::BashfuscatorString => "bash-bashfuscator-string",
        Family::BashfuscatorObfuscate => "bash-bashfuscator-obfuscate",
        Family::BashfuscatorCompress => "bash-bashfuscator-compress",
        Family::BashIndirection => "bash-indirection",
        Family::NodeBashObfuscate => "bash-node-bash-obfuscate",
        Family::BatchRandom => "batch-random",
        Family::BatchSetIndirection => "batch-set-indirection",
        Family::VbaMacro | Family::VbsWshObfuscated => "vba-macro",
        Family::Plain | Family::Unknown => return None,
    };
    Some(id)
}

impl ObfuscatorCatalog for ShellDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static ShellObfuscatorEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let detection: Detection = detect_shell(ctx.bytes);
        let entry_id: &'static str = catalog_id_for_family(detection.family)?;
        Some(DetectorOutput::new(
            entry_id,
            detection.confidence,
            detection.markers,
        ))
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    fn corpus_shell(relative: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("shell")
            .join(relative)
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(ShellDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_bash_shebang() {
        let bytes: &[u8] = b"#!/bin/bash\neval${IFS}echo${IFS}hello\n";
        let v: DetectVerdict = Detector::detect(&ShellDetector, &ctx(bytes)).expect("must detect");
        assert_eq!(v.format_tag, TAG_BASH);
    }

    #[test]
    fn detect_misses_empty() {
        assert!(Detector::detect(&ShellDetector, &ctx(b"")).is_none());
    }

    #[test]
    fn detect_misses_clean_bash_shebang() {
        let bytes: &[u8] = b"#!/bin/bash\necho hello\n";
        assert!(
            Detector::detect(&ShellDetector, &ctx(bytes)).is_none(),
            "a clean, non-obfuscated bash script carries no reversible family and must not \
             be claimed by the chain detector, matching the js.deob/py.deob convention"
        );
    }

    #[test]
    fn pass_output_kind_is_shell_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match SHELL_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::Bash);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_returns_bash_source_not_json() {
        let bytes: Vec<u8> = b"#!/bin/bash\neval${IFS}echo${IFS}hello\n".to_vec();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = SHELL_PASS.run(&a).expect("classify must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(
            !s.trim_start().starts_with('{') && !s.contains("\"dialect\""),
            "shell chain output must be source text, not the extract json; got {s:?}",
        );
        assert!(
            s.contains("echo hello"),
            "must contain the real, IFS-substituted shell source; got {s:?}"
        );
        match SHELL_PASS.output_kind(&out) {
            OutputKind::Source { language, .. } => assert_eq!(language, Language::Bash),
            other => panic!("expected Source, got {other:?}"),
        }
    }

    #[test]
    fn pass_run_recovers_real_node_bash_obfuscate_to_source() {
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(corpus_shell(
            "bash/node-bash-obfuscate/obfuscated_chunk4.sh",
        )) else {
            eprintln!("SKIP: node-bash-obfuscate fixture missing");
            return;
        };
        let detection: Detection = detect_shell(&bytes);
        assert_eq!(detection.family, Family::NodeBashObfuscate);
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = SHELL_PASS
            .run(&a)
            .expect("node-bash-obfuscate chain run must recover");
        assert_eq!(out.rung, Rung::Surface);
        let recovered: &str = std::str::from_utf8(&out.envelope).expect("utf8 recovered source");
        assert!(
            recovered.contains("GREETING='hello world'")
                && recovered.contains("for i in 1 2 3; do"),
            "chain output must be the recovered plaintext bash script; got {:?}",
            recovered.chars().take(200).collect::<String>(),
        );
        assert!(
            !recovered.contains("eval \"$"),
            "chain output must not leave the eval chunk table intact; got {:?}",
            recovered.chars().take(200).collect::<String>(),
        );
    }

    #[test]
    fn pass_run_deobfuscates_real_batch_to_text() {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("shell")
            .join("batch")
            .join("seta")
            .join("hello.bat");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&fixture) else {
            eprintln!("SKIP: batch fixture missing at {}", fixture.display());
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = SHELL_PASS.run(&a).expect("batch deob must succeed");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 source");
        assert!(
            !s.trim_start().starts_with('{') && !s.contains("\"batch\""),
            "batch chain output must be the deobfuscated script, not json; got {:?}",
            s.chars().take(160).collect::<String>(),
        );
        assert!(
            s.contains("set PORT=4443"),
            "batch deob must fold the real `set /a` arithmetic in the chain output; got {:?}",
            s.chars().take(200).collect::<String>(),
        );
    }

    #[test]
    fn pass_run_rejects_unknown_bytes() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = SHELL_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SHELL-0902"));
    }

    #[test]
    fn pass_run_genuine_encoding_deob_still_surfaces() {
        let src: &[u8] = b"powershell -NoP -W Hidden -EncodedCommand QQBBAEEAQQBBAEEA";
        let detection: Detection = detect_shell(src);
        assert_eq!(detection.family, Family::InvokeObfuscationEncoding);
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let out: Artifact = SHELL_PASS
            .run(&a)
            .expect("a decodable EncodedCommand must deobfuscate to a Surface artifact");
        assert_eq!(out.rung, Rung::Surface);
        let recovered: String = String::from_utf8(out.envelope).expect("utf8 source");
        assert_ne!(
            recovered.trim(),
            std::str::from_utf8(src).expect("utf8").trim(),
            "genuine recovery must transform the input, not echo it back"
        );
        assert!(
            recovered.contains("AAAA"),
            "EncodedCommand QQBBAEEAQQBBAEEA decodes to the utf16-le payload AAAA; got {recovered:?}"
        );
    }

    #[test]
    fn pass_run_walls_detected_obfuscator_that_recovers_nothing() {
        let src: &[u8] = b"# PowerHell launcher\nIEX $payload\n";
        let detection: Detection = detect_shell(src);
        assert_eq!(
            detection.dialect,
            Dialect::PowerShell,
            "PowerHell banner with IEX must classify as PowerShell"
        );
        assert_eq!(
            detection.family,
            Family::PowerHell,
            "the PowerHell banner must select the PowerHell reverser"
        );
        assert!(
            verdict_for(&detection).is_some(),
            "must clear the detector gate"
        );
        let reversed: CoreResult<String> =
            reverse_for_family(detection.family, std::str::from_utf8(src).expect("utf8"));
        assert!(
            reversed.is_err(),
            "PowerHell with no embedded base64 blob recovers nothing and must not echo the input as success"
        );
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let err: CoreError = SHELL_PASS.run(&a).expect_err(
            "a detected obfuscator family that reverses to the input verbatim must wall, not emit the obfuscated bytes as a successful Surface artifact",
        );
        let text: String = format!("{err}");
        assert!(
            text.contains("DR-SHELL-0917") && text.contains("statically unrecoverable"),
            "wall must carry the residual reason code and be honest about why recovery failed; got: {text}"
        );
    }

    #[test]
    fn pass_run_walls_when_encoding_reverse_errors() {
        let src: &[u8] = b"powershell -NoP -W Hidden -EncodedCommand QQBBAEEAQ";
        let detection: Detection = detect_shell(src);
        assert_eq!(detection.family, Family::InvokeObfuscationEncoding);
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let err: CoreError = SHELL_PASS.run(&a).expect_err(
            "an EncodedCommand whose base64 body fails to decode must propagate the failure, not pass the obfuscated launcher through as success",
        );
        let text: String = format!("{err}");
        assert!(
            text.contains("DR-SHELL-0913") && text.contains("reverse failed"),
            "the error channel must wall with the encoding residual code; got: {text}"
        );
    }

    #[test]
    fn catalog_lists_obfuscator_families() {
        let entries: Vec<&'static dyn CatalogEntry> = ShellDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        let mut ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CATALOG_COUNT, "catalog ids must be unique");
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn catalog_detects_powershell_encoded_obfuscation() {
        let src: &[u8] = b"powershell -NoP -W Hidden -EncodedCommand QQBBAEEAQQBBAEEA";
        let out: DetectorOutput = ObfuscatorCatalog::detect(&ShellDetector, &ctx(src))
            .expect("an EncodedCommand payload is an Invoke-Obfuscation encoding layer");
        assert_eq!(out.entry_id, "ps-invoke-obfuscation-encoding");
        assert!(out.confidence >= 0.5, "confidence={}", out.confidence);
        let entry: &dyn CatalogEntry = ShellDetector
            .catalog()
            .into_iter()
            .find(|e: &&dyn CatalogEntry| e.id() == out.entry_id)
            .expect("detected id in catalog");
        assert_eq!(entry.support_quality(), SupportQuality::Full);
    }

    #[test]
    fn catalog_detects_batch_random_obfuscation() {
        let src: &[u8] = b"@echo off\nset r=%random:~0,4%\necho %r%\n";
        let out: DetectorOutput = ObfuscatorCatalog::detect(&ShellDetector, &ctx(src))
            .expect("a %random% batch script is a batch obfuscation layer");
        assert_eq!(out.entry_id, "batch-random");
    }

    #[test]
    fn catalog_detect_skips_plain_script() {
        let src: &[u8] = b"#!/bin/bash\necho hello\n";
        assert!(
            ObfuscatorCatalog::detect(&ShellDetector, &ctx(src)).is_none(),
            "a plain bash script carries no obfuscator and must not be cataloged"
        );
    }

    fn corpus_bytes(relative: &str) -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("shell")
            .join(relative);
        std::fs::read(&path).ok()
    }

    fn chain_recovered(bytes: &[u8]) -> String {
        let a: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
        let out: Artifact = SHELL_PASS.run(&a).expect("chain run must succeed");
        assert_eq!(out.rung, Rung::Surface);
        String::from_utf8(out.envelope).expect("utf8 source")
    }

    #[test]
    fn chain_powershell_matches_cli_encoding_reverse_and_deobfuscates() {
        let Some(bytes): Option<Vec<u8>> =
            corpus_bytes("powershell/invoke-obfuscation/encoding/hello.ps1")
        else {
            eprintln!("SKIP: powershell encoding fixture missing");
            return;
        };
        let obf: &str = std::str::from_utf8(&bytes).expect("utf8");
        let detection: Detection = detect_shell(&bytes);
        assert_eq!(detection.dialect, Dialect::PowerShell);
        assert_eq!(detection.family, Family::InvokeObfuscationEncoding);
        let cli_equivalent: String =
            reverse_for_family(detection.family, obf).expect("encoding reverse must recover");
        let chained: String = chain_recovered(&bytes);
        assert_eq!(
            chained, cli_equivalent,
            "chain must emit the same deobfuscated PowerShell the CLI reverse_for_family produces"
        );
        assert_ne!(
            chained.trim(),
            obf.trim(),
            "chain must not pass the EncodedCommand PowerShell through unchanged"
        );
        assert!(
            chained.contains("Write-Host") && chained.contains("hello world"),
            "deobfuscated PowerShell must decode to the Write-Host payload; got {chained:?}"
        );
    }

    #[test]
    fn chain_bash_matches_cli_bashfuscator_reverse_and_deobfuscates() {
        let Some(bytes): Option<Vec<u8>> = corpus_bytes("bash/bashfuscator/token/hello.sh") else {
            eprintln!("SKIP: bash bashfuscator fixture missing");
            return;
        };
        let obf: &str = std::str::from_utf8(&bytes).expect("utf8");
        let detection: Detection = detect_shell(&bytes);
        assert_eq!(detection.dialect, Dialect::Bash);
        assert!(
            matches!(
                detection.family,
                Family::BashfuscatorToken
                    | Family::BashfuscatorString
                    | Family::BashfuscatorObfuscate
                    | Family::BashfuscatorCompress
            ),
            "real Bashfuscator output must be classified as a Bashfuscator family; got {:?}",
            detection.family
        );
        let cli_equivalent: String =
            reverse_for_family(detection.family, obf).expect("bashfuscator reverse must recover");
        let chained: String = chain_recovered(&bytes);
        assert_eq!(
            chained, cli_equivalent,
            "chain must emit the same recovery the CLI bashfuscator reverse produces"
        );
        assert_ne!(
            chained.trim(),
            obf.trim(),
            "chain must not pass the obfuscated bash through unchanged"
        );
        assert!(
            chained.to_ascii_lowercase().contains("hello world"),
            "recovered bash must surface the hello-world payload; got {chained:?}"
        );
    }

    #[test]
    fn chain_vbs_matches_cli_deobfuscate_vbs_and_deobfuscates() {
        let Some(bytes): Option<Vec<u8>> = corpus_bytes("vbs/chr_chain/hello.vbs") else {
            eprintln!("SKIP: vbs chr_chain fixture missing");
            return;
        };
        let obf: &str = std::str::from_utf8(&bytes).expect("utf8");
        let detection: Detection = detect_shell(&bytes);
        assert_eq!(detection.dialect, Dialect::Vbs);
        let cli_equivalent: String = crate::vba::deobfuscate_vbs(obf).output;
        let chained: String = chain_recovered(&bytes);
        assert_eq!(
            chained, cli_equivalent,
            "chain must emit the same deobfuscated VBS the CLI deobfuscate_vbs produces"
        );
        assert_ne!(
            chained.trim(),
            obf.trim(),
            "chain must not pass the Chr()-obfuscated VBS through unchanged"
        );
        assert!(
            chained.to_ascii_lowercase().contains("wscript"),
            "deobfuscated VBS must reveal the WScript.Echo payload; got {chained:?}"
        );
    }

    fn stomp_module1_source(raw: &[u8]) -> Option<Vec<u8>> {
        use std::io::{Seek as _, SeekFrom, Write as _};

        let project: crate::vba::ExtractedProject = crate::vba::extract_from_bytes(raw).ok()?;
        let text_offset: usize = project
            .modules
            .iter()
            .find(|m: &&crate::vba::ExtractedModule| m.name.eq_ignore_ascii_case("Module1"))
            .and_then(|m: &crate::vba::ExtractedModule| m.text_offset)?;
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(raw.to_vec());
        let mut comp: cfb::CompoundFile<std::io::Cursor<Vec<u8>>> =
            cfb::CompoundFile::open(cursor).ok()?;
        let mut stream: cfb::Stream<std::io::Cursor<Vec<u8>>> =
            comp.open_stream("/VBA/Module1").ok()?;
        let len: u64 = stream.len();
        let source_start: u64 = text_offset as u64;
        if source_start >= len {
            return None;
        }
        let new_len: u64 = source_start.checked_add(1)?;
        stream.seek(SeekFrom::Start(source_start)).ok()?;
        stream.write_all(&[0x01]).ok()?;
        stream.set_len(new_len).ok()?;
        stream.flush().ok()?;
        drop(stream);
        Some(comp.into_inner().into_inner())
    }

    #[test]
    fn chain_stomped_vba_recovers_from_pcode_when_source_is_gone() {
        let Some(raw): Option<Vec<u8>> = corpus_bytes("vba/vbaProject.bin") else {
            eprintln!("SKIP: vbaProject.bin fixture missing");
            return;
        };
        let Some(stomped): Option<Vec<u8>> = stomp_module1_source(&raw) else {
            eprintln!("SKIP: could not synthesize a stomped Module1 source stream");
            return;
        };
        let project: crate::vba::ExtractedProject =
            crate::vba::extract_from_bytes(&stomped).expect("re-extract stomped project");
        let module1_source_empty: bool = project
            .modules
            .iter()
            .find(|m: &&crate::vba::ExtractedModule| m.name.eq_ignore_ascii_case("Module1"))
            .is_none_or(|m: &crate::vba::ExtractedModule| m.recovered_source.trim().is_empty());
        assert!(
            module1_source_empty,
            "stomp helper must leave Module1 source unrecoverable so the p-code fallback is exercised"
        );
        let chained: String = chain_recovered(&stomped);
        assert!(
            chained.contains("MsgBox") && chained.contains("hello world"),
            "stomped VBA must recover MsgBox \"hello world\" from p-code on the chain; got {chained:?}"
        );
        let cli_equivalent: Vec<RecoveredVbaModule> = recover_vba_from_pcode(&stomped);
        assert!(
            !cli_equivalent.is_empty()
                && cli_equivalent
                    .iter()
                    .any(|m: &RecoveredVbaModule| m.source.contains("MsgBox")),
            "the shared p-code fallback the CLI uses must also recover the behavior"
        );
    }

    #[test]
    fn chain_pdf_recovers_javascript_and_manifest_carries_full_report() {
        let Some(bytes): Option<Vec<u8>> = corpus_bytes("pdf/openaction_table.pdf") else {
            eprintln!("SKIP: pdf openaction_table fixture missing");
            return;
        };
        let detection: Detection = detect_shell(&bytes);
        assert_eq!(detection.dialect, Dialect::Pdf);
        assert!(
            verdict_for(&detection).is_some(),
            "a real pdf document must clear the shell chain detector gate"
        );
        let chained: String = chain_recovered(&bytes);
        assert!(
            chained.contains("OPENACTION_TABLE_MARKER"),
            "chain must surface the pdf's embedded javascript; got {chained:?}"
        );
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = SHELL_PASS
            .extract_children(&a)
            .expect("recovery manifest child must emit");
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == RECOVERY_MANIFEST_CHILD)
            .expect("recovery manifest sidecar must appear for a pdf with javascript");
        assert!(
            manifest.handle.is_terminal(),
            "manifest is a terminal sidecar"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is json");
        assert_eq!(parsed["schema"], RECOVERY_MANIFEST_SCHEMA);
        assert!(
            parsed["pdf"]["javascript"]
                .as_array()
                .is_some_and(|v: &Vec<serde_json::Value>| !v.is_empty()),
            "manifest must carry the full structured pdf report: {parsed}"
        );
    }

    fn xlm_record(rt: u16, data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&rt.to_le_bytes());
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn xlm_bof(dt: u16) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0x0600u16.to_le_bytes());
        data.extend_from_slice(&dt.to_le_bytes());
        data.extend_from_slice(&0x0DBBu16.to_le_bytes());
        data.extend_from_slice(&0x07CCu16.to_le_bytes());
        data.extend_from_slice(&0x0000_00C1u32.to_le_bytes());
        data.extend_from_slice(&0x0000_0006u32.to_le_bytes());
        xlm_record(0x0809, &data)
    }

    fn xlm_eof() -> Vec<u8> {
        xlm_record(0x000A, &[])
    }

    fn xlm_boundsheet(lb_ply_pos: u32, name: &str) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&lb_ply_pos.to_le_bytes());
        data.push(0x00);
        data.push(0x01);
        data.push(name.len() as u8);
        data.push(0x00);
        data.extend_from_slice(name.as_bytes());
        xlm_record(0x0085, &data)
    }

    fn xlm_formula(row: u16, col: u16, rgce: &[u8]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&row.to_le_bytes());
        data.extend_from_slice(&col.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(rgce.len() as u16).to_le_bytes());
        data.extend_from_slice(rgce);
        xlm_record(0x0006, &data)
    }

    fn xlm_dimensions() -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        xlm_record(0x0200, &data)
    }

    fn xlm_p_str(text: &str) -> Vec<u8> {
        let mut b: Vec<u8> = vec![0x17, text.chars().count() as u8, 0x00];
        b.extend_from_slice(text.as_bytes());
        b
    }

    fn xlm_p_funcvar(cparams: u8, tab: u16, command: bool) -> Vec<u8> {
        let mut b: Vec<u8> = vec![0x22, cparams];
        let field: u16 = (tab & 0x7FFF) | if command { 0x8000 } else { 0 };
        b.extend_from_slice(&field.to_le_bytes());
        b
    }

    fn build_minimal_xlm_workbook() -> Vec<u8> {
        use std::io::Write as _;

        let mut globals: Vec<u8> = Vec::new();
        globals.extend_from_slice(&xlm_bof(0x0005));
        globals.extend_from_slice(&xlm_record(0x0042, &0x04B0u16.to_le_bytes()));
        let placeholder: Vec<u8> = xlm_boundsheet(0, "Macro1");
        globals.extend_from_slice(&placeholder);
        globals.extend_from_slice(&xlm_eof());

        let boundsheet_pos: usize =
            xlm_bof(0x0005).len() + xlm_record(0x0042, &0x04B0u16.to_le_bytes()).len();
        let lb_ply_pos: u32 = globals.len() as u32;
        let fixed: Vec<u8> = xlm_boundsheet(lb_ply_pos, "Macro1");
        globals.splice(boundsheet_pos..boundsheet_pos + placeholder.len(), fixed);

        let mut rgce: Vec<u8> = xlm_p_str("calc.exe");
        rgce.extend_from_slice(&xlm_p_funcvar(1, 0x006E, false));
        let mut sheet: Vec<u8> = Vec::new();
        sheet.extend_from_slice(&xlm_bof(0x0040));
        sheet.extend_from_slice(&xlm_dimensions());
        sheet.extend_from_slice(&xlm_formula(0, 0, &rgce));
        sheet.extend_from_slice(&xlm_eof());

        let mut stream: Vec<u8> = globals;
        stream.extend_from_slice(&sheet);

        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut comp: cfb::CompoundFile<std::io::Cursor<Vec<u8>>> =
            cfb::CompoundFile::create_with_version(cfb::Version::V3, cursor).expect("create cfb");
        {
            let mut cfb_stream: cfb::Stream<std::io::Cursor<Vec<u8>>> = comp
                .create_stream("Workbook")
                .expect("create workbook stream");
            cfb_stream.write_all(&stream).expect("write workbook");
            cfb_stream.flush().expect("flush stream");
        }
        comp.into_inner().into_inner()
    }

    #[test]
    fn chain_xlm_recovers_macro_formula_from_biff8_workbook() {
        let xls: Vec<u8> = build_minimal_xlm_workbook();
        let detection: Detection = detect_shell(&xls);
        assert_eq!(detection.dialect, Dialect::Xlm);
        let chained: String = chain_recovered(&xls);
        assert!(
            chained.contains("EXEC") && chained.contains("calc.exe"),
            "chain must recover the real xlm macro-sheet formula; got {chained:?}"
        );
        let a: Artifact = Artifact::new(Rung::Raw, xls, [0u8; 32]);
        let children: Vec<ChildArtifact> = SHELL_PASS
            .extract_children(&a)
            .expect("recovery manifest child must emit");
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == RECOVERY_MANIFEST_CHILD)
            .expect("recovery manifest sidecar must appear for an xlm macro workbook");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is json");
        assert!(
            parsed["xlm"]["sheets"]
                .as_array()
                .is_some_and(|v: &Vec<serde_json::Value>| !v.is_empty()),
            "manifest must carry the full structured xlm recovery: {parsed}"
        );
    }

    #[test]
    fn chain_bash_base64_pipe_dropper_recovers_to_plaintext() {
        let src: &[u8] = b"#!/bin/bash\necho aWQ= | base64 -d | bash\n";
        let chained: String = chain_recovered(src);
        assert!(
            chained.contains("id"),
            "chain must recover the base64-piped dropper payload; got {chained:?}"
        );
        assert_ne!(
            chained.trim(),
            std::str::from_utf8(src).expect("utf8").trim(),
            "chain must not pass the base64 pipe through unchanged"
        );
    }

    #[test]
    fn extract_children_recovery_manifest_carries_bash_indirection_steps() {
        let src: &[u8] = b"#!/bin/bash\necho aWQ= | base64 -d | bash\n";
        let a: Artifact = Artifact::new(Rung::Raw, src.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = SHELL_PASS
            .extract_children(&a)
            .expect("recovery manifest child must emit");
        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == RECOVERY_MANIFEST_CHILD)
            .expect("recovery manifest sidecar must appear for a bash indirection chain");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest is json");
        assert!(
            parsed["steps"]
                .as_array()
                .is_some_and(|s: &Vec<serde_json::Value>| s
                    .iter()
                    .any(|v: &serde_json::Value| v == "base64-decode")),
            "manifest must record the base64-decode peel step: {parsed}"
        );
    }
}
