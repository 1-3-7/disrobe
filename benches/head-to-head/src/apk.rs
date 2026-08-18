use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::fmt::Write as _;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    AndroidDecompileOutput, BackendPreference, ClassFile, DecompiledClass, JadxOutcome,
    JadxRefusal, android_decompile_dex, decompile_class_with_inners, parse_classfile,
    run_jadx_on_bytes_detailed,
};
use disrobe_tool_process::opened_file_matches_path;
use eyre::{Result, WrapErr};
use serde_json::{Value, json};

use crate::apkleaks_capture::sha256_hex;
use crate::tool::{
    MAX_FIXTURE_BYTES, MAX_TEXT_BYTES, MAX_TOOL_CAPTURE_BYTES, MAX_TREE_FILES, MAX_TREE_TEXT_BYTES,
    MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_BYTES, MAX_ZIP_TOTAL_BYTES, TOOL_TIMEOUT, bounded_error_text,
    find_on_path, read_bounded_file, read_bounded_string, require_pinned_version, require_success,
    run, version_of, version_of_checked,
};

pub fn measure(root: &Path) -> Result<(String, Value)> {
    let id: String = "apk-jadx-cfr".to_owned();
    let dex_path: PathBuf = root
        .join("corpus")
        .join("jvm")
        .join("dex")
        .join("EdgeCases.dex");
    let jar_path: PathBuf = root
        .join("corpus")
        .join("jvm")
        .join("megafile")
        .join("EdgeCases-baseline.jar");
    let original_src: PathBuf = root
        .join("corpus")
        .join("jvm")
        .join("megafile")
        .join("EdgeCases.java");

    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        return Ok((
            id,
            skipped("javac not on PATH; the shared recompile oracle is unavailable"),
        ));
    };

    let dex_bytes: Vec<u8> = read_bounded_file(&dex_path, MAX_FIXTURE_BYTES)
        .wrap_err_with(|| format!("reading {}", dex_path.display()))?;
    let jar_bytes: Vec<u8> = read_bounded_file(&jar_path, MAX_FIXTURE_BYTES)
        .wrap_err_with(|| format!("reading {}", jar_path.display()))?;
    let dex_sha256: String = sha256_hex(&dex_bytes);
    let jar_sha256: String = sha256_hex(&jar_bytes);
    let dataset: String = dataset_description(&dex_sha256, &jar_sha256);
    let original: String = read_bounded_string(&original_src, MAX_TEXT_BYTES)
        .wrap_err_with(|| format!("reading {}", original_src.display()))?;
    let denominator: usize = main_class_method_ranges(&original).len().max(1);

    let dex_leg: Leg = Leg {
        key: "dex",
        label: "DEX leg",
        disrobe_name: "disrobe (in-house Dalvik, DEX input)",
        disrobe: score_disrobe_dex(&javac, &dex_bytes, denominator),
        competitor_name: "jadx (DEX input)",
        competitor_short: "jadx",
        competitor: jadx_outcome(&javac, &dex_bytes, denominator),
    };

    let jar_leg: Leg = Leg {
        key: "jar",
        label: "JAR leg",
        disrobe_name: "disrobe (in-house JVM, JAR input)",
        disrobe: score_disrobe_jar(&javac, &jar_bytes, denominator),
        competitor_name: "cfr (JAR input)",
        competitor_short: "cfr",
        competitor: cfr_outcome(root, &javac, &jar_path, denominator),
    };

    if crate::requirement_enabled("DISROBE_REQUIRE_JADX") {
        require_competitor_result("jadx", &dex_leg.competitor)
            .map_err(|error: String| eyre::eyre!(error))?;
    }
    if crate::requirement_enabled("DISROBE_REQUIRE_CFR") {
        require_competitor_result("cfr", &jar_leg.competitor)
            .map_err(|error: String| eyre::eyre!(error))?;
    }

    let legs: [Leg; 2] = [dex_leg, jar_leg];
    let tools: Vec<Value> = legs.iter().flat_map(Leg::to_json_rows).collect();

    let value: Value = json!({
        "id": id,
        "title": "APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean emitted methods under real javac)",
        "status": "ok",
        "ecosystem": "android",
        "dataset": dataset,
        "oracle": "real javac (JDK), per-method recompile error-free against a STUBBED (empty) classpath so a wrong recovered signature cannot resolve against the original classes. The scorer first compiles the complete recovered source set. If a parse failure prevents attribution, it isolates only the implicated balanced method, field-initializer, or type region and reruns javac under a 64-round ceiling. A method in an isolated method or type region is unclean. Every other method is scored from the compiler diagnostics after attribution resumes. An unmapped parse failure certifies nothing.",
        "metric": format!("clean / emitted methods across the recovered source set. The original main class declares {denominator} methods (counted at runtime); each decompiler also emits nested, sibling, synthetic accessor, lambda, and bridge methods, so each tool's emitted count differs by design. The result reports both the recompile-clean rate and absolute clean-method count. A source set whose parse failure cannot be isolated reports its emitted-method count without a rate."),
        "reproduce": "cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr",
        "fairness": [
            "identical input bytes per leg: disrobe and jadx both decompile EdgeCases.dex; disrobe and cfr both decompile the EdgeCases-baseline.jar (cfr cannot read DEX)",
            "same scorer for every tool: one source-only function performs the complete compile, diagnostic mapping, bounded region isolation, and final method scoring without receiving a tool identity",
            "same certification rule for every tool: whole-set attribution is preferred; a parse failure costs only methods in the implicated balanced method or type region when javac reaches attribution after that region is replaced by a neutral declaration-preserving stub or named type shell",
            "every tool's complete emitted source set enters the same compiler invocation. Region isolation preserves line count and peer declarations, and runs only after javac proves that the original set cannot reach attribution",
            "stubbed classpath: no original-jar leak (the section-0.4 #1 defect is fixed)",
            "a tool that produces no EdgeCases source at all is a miss, never an excluded sample"
        ],
        "tools": tools,
        "honest_note": measured_summary(&legs),
    });
    Ok((id, value))
}

fn require_competitor_result(
    tool: &str,
    outcome: &CompetitorOutcome,
) -> std::result::Result<(), String> {
    match outcome {
        CompetitorOutcome::Absent { reason } => {
            Err(format!("required {tool} measurement was skipped: {reason}"))
        }
        CompetitorOutcome::Scored {
            score: ToolScore::Missing { detail, .. },
            ..
        } => Err(format!("required {tool} measurement failed: {detail}")),
        CompetitorOutcome::Scored { .. } => Ok(()),
    }
}

const IN_PROCESS_VERSION: &str = "n/a (in-process)";
const OK_STATUS: &str = "ok";
const UNCERTIFIED_STATUS: &str = "uncertified";
const METRIC: &str = "recompile-clean emitted methods (clean / emitted)";
const SHARED_ORACLE: &str = "All rows use the same stubbed real-`javac` oracle and are recompile-only. The scorer compiles the complete recovered source set first. If a parse failure prevents attribution, it isolates implicated balanced method, field-initializer, or type regions under a 64-round ceiling, then reruns javac. Methods inside isolated method or type regions are unclean; peer methods are scored only after javac reaches attribution. An unmapped or over-budget failure certifies nothing. The scorer receives source only, so the same rule binds `disrobe` and every competitor. A leg states no lead unless both sides are certified.";
const ATTRIBUTION_PROBE_FILE: &str = "TypeCheckReached.java";
const ATTRIBUTION_PROBE_SOURCE: &str = "final class TypeCheckReached {\n    static final Object \
                                        VALUE = typeCheckReachedSymbolThatCannotResolve;\n}\n";
const MAX_JAVA_DIAGNOSTICS: usize = 100_000;
const DIAGNOSTIC_LIMIT: &str = "100000";

fn dataset_description(dex_sha256: &str, jar_sha256: &str) -> String {
    format!(
        "corpus/jvm/dex/EdgeCases.dex (SHA-256 {dex_sha256}) for the DEX leg; \
         corpus/jvm/megafile/EdgeCases-baseline.jar (SHA-256 {jar_sha256}) for the JAR leg; both \
         committed, fully offline"
    )
}

#[derive(Debug)]
enum CompetitorOutcome {
    Scored { version: String, score: ToolScore },
    Absent { reason: String },
}

fn jadx_outcome(javac: &Path, dex_bytes: &[u8], denominator: usize) -> CompetitorOutcome {
    let Some(jadx): Option<PathBuf> = find_on_path("jadx") else {
        return CompetitorOutcome::Absent {
            reason: "jadx is not on PATH".to_owned(),
        };
    };
    CompetitorOutcome::Scored {
        version: version_of(&jadx, &["--version"]),
        score: score_jadx(javac, dex_bytes, denominator),
    }
}

fn cfr_outcome(
    root: &Path,
    javac: &Path,
    jar_path: &Path,
    denominator: usize,
) -> CompetitorOutcome {
    let Some(cfr): Option<CfrInvoke> = resolve_cfr(root) else {
        return CompetitorOutcome::Absent {
            reason: "cfr is not on PATH and evidence/competitors/jars/cfr.jar is absent; install \
                     it with evidence/competitors/install-linux.sh"
                .to_owned(),
        };
    };
    CompetitorOutcome::Scored {
        version: cfr_version(&cfr),
        score: score_cfr(javac, jar_path, &cfr, denominator),
    }
}

#[derive(Debug)]
struct Leg {
    key: &'static str,
    label: &'static str,
    disrobe_name: &'static str,
    disrobe: ToolScore,
    competitor_name: &'static str,
    competitor_short: &'static str,
    competitor: CompetitorOutcome,
}

impl Leg {
    fn to_json_rows(&self) -> Vec<Value> {
        let mut competitor: Value = match &self.competitor {
            CompetitorOutcome::Scored { version, score } => {
                score.to_json(self.competitor_name, version)
            }
            CompetitorOutcome::Absent { reason } => skipped_tool(self.competitor_name, reason),
        };
        competitor["leg"] = Value::String(self.key.to_owned());
        competitor["role"] = Value::String("competitor".to_owned());
        let mut disrobe: Value = self.disrobe.to_json(self.disrobe_name, IN_PROCESS_VERSION);
        disrobe["leg"] = Value::String(self.key.to_owned());
        disrobe["role"] = Value::String("disrobe".to_owned());
        vec![disrobe, competitor]
    }

    fn sentence(&self) -> String {
        let ours: String = score_phrase(&self.disrobe);
        let (version, theirs): (&str, &ToolScore) = match &self.competitor {
            CompetitorOutcome::Absent { reason } => {
                return format!(
                    "{label}: NOT MEASURED against `{short}`, because {reason}. `disrobe` recovers \
                     {ours} on this leg, and no `{short}` figure is published for it.",
                    label = self.label,
                    short = self.competitor_short,
                );
            }
            CompetitorOutcome::Scored { version, score } => (version.as_str(), score),
        };
        let theirs_phrase: String = score_phrase(theirs);
        if !self.disrobe.is_certified() || !theirs.is_certified() {
            return format!(
                "{label}: `disrobe` recovers {ours}; `{short}` ({version}) recovers \
                 {theirs_phrase}. No lead is stated, because the compiler did not certify both \
                 sides.",
                label = self.label,
                short = self.competitor_short,
            );
        }
        format!(
            "{label}: `disrobe` recovers {ours}; `{short}` ({version}) recovers {theirs_phrase}. \
             {counts}; {rates}.",
            label = self.label,
            short = self.competitor_short,
            counts = count_verdict(self.disrobe.clean(), self.competitor_short, theirs.clean()),
            rates = rate_verdict(self.disrobe.rate(), self.competitor_short, theirs.rate()),
        )
    }
}

fn measured_summary(legs: &[Leg]) -> String {
    let mut sentences: Vec<String> = legs.iter().map(Leg::sentence).collect();
    sentences.push(SHARED_ORACLE.to_owned());
    sentences.join(" ")
}

fn score_phrase(score: &ToolScore) -> String {
    match score {
        ToolScore::Certified {
            clean,
            emitted,
            class_level_defects: 0,
            ..
        } => format!("{clean} clean of {emitted} emitted ({:.1}%)", score.rate()),
        ToolScore::Certified {
            clean,
            emitted,
            class_level_defects,
            ..
        } => format!(
            "{clean} clean of {emitted} emitted ({:.1}%), beside {class_level_defects} compiler \
             {} outside any method",
            score.rate(),
            defects(*class_level_defects)
        ),
        ToolScore::Uncertified {
            emitted,
            cause:
                UncertifiedCause::Compiler {
                    first_defect_line: Some(first_defect_line),
                },
            ..
        } => format!(
            "{emitted} emitted {}, none of them certified, because javac stopped at a defect on \
             line {first_defect_line} of the recovered file",
            methods(*emitted)
        ),
        ToolScore::Uncertified {
            emitted,
            cause:
                UncertifiedCause::Compiler {
                    first_defect_line: None,
                },
            detail,
            ..
        }
        | ToolScore::Uncertified {
            emitted,
            cause: UncertifiedCause::ProducerExit,
            detail,
            ..
        } => format!(
            "{emitted} emitted {}, none of them certified ({detail})",
            methods(*emitted)
        ),
        ToolScore::Missing { detail, .. } => format!("nothing scorable ({detail})"),
    }
}

const fn defects(count: usize) -> &'static str {
    if count == 1 { "defect" } else { "defects" }
}

fn count_verdict(ours: usize, competitor_short: &str, theirs: usize) -> String {
    match ours.cmp(&theirs) {
        Ordering::Greater => {
            let delta: usize = ours - theirs;
            format!("`disrobe` leads by {delta} clean {}", methods(delta))
        }
        Ordering::Less => {
            let delta: usize = theirs - ours;
            format!(
                "`{competitor_short}` leads by {delta} clean {}",
                methods(delta)
            )
        }
        Ordering::Equal => format!("both tools recover {ours} clean {}", methods(ours)),
    }
}

fn rate_verdict(ours: f64, competitor_short: &str, theirs: f64) -> String {
    let shown_ours: String = format!("{ours:.1}");
    let shown_theirs: String = format!("{theirs:.1}");
    if shown_ours == shown_theirs {
        return format!("the clean rates are level at {shown_ours}%");
    }
    if ours > theirs {
        return format!("`disrobe` leads on clean rate, {shown_ours}% to {shown_theirs}%");
    }
    format!("`{competitor_short}` leads on clean rate, {shown_theirs}% to {shown_ours}%")
}

const fn methods(count: usize) -> &'static str {
    if count == 1 { "method" } else { "methods" }
}

#[derive(Debug)]
enum ToolScore {
    Certified {
        clean: usize,
        emitted: usize,
        class_level_defects: usize,
        original: usize,
        detail: String,
    },
    Uncertified {
        emitted: usize,
        cause: UncertifiedCause,
        original: usize,
        detail: String,
    },
    Missing {
        original: usize,
        detail: String,
    },
}

#[derive(Debug)]
enum UncertifiedCause {
    Compiler { first_defect_line: Option<usize> },
    ProducerExit,
}

impl ToolScore {
    const fn miss(original: usize, detail: String) -> Self {
        Self::Missing { original, detail }
    }

    const fn status(&self) -> &'static str {
        match self {
            Self::Certified { .. } => OK_STATUS,
            Self::Uncertified { .. } => UNCERTIFIED_STATUS,
            Self::Missing { .. } => "miss",
        }
    }

    const fn is_certified(&self) -> bool {
        matches!(self, Self::Certified { .. })
    }

    const fn clean(&self) -> usize {
        match self {
            Self::Certified { clean, .. } => *clean,
            Self::Uncertified { .. } | Self::Missing { .. } => 0,
        }
    }

    fn rate(&self) -> f64 {
        match self {
            Self::Certified { clean, emitted, .. } => {
                100.0 * *clean as f64 / (*emitted).max(1) as f64
            }
            Self::Uncertified { .. } | Self::Missing { .. } => 0.0,
        }
    }

    const fn original(&self) -> usize {
        match self {
            Self::Certified { original, .. }
            | Self::Uncertified { original, .. }
            | Self::Missing { original, .. } => *original,
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Certified { detail, .. }
            | Self::Uncertified { detail, .. }
            | Self::Missing { detail, .. } => detail,
        }
    }

    fn to_json(&self, name: &str, version: &str) -> Value {
        let mut row: Value = json!({
            "name": name,
            "version": version,
            "metric": METRIC,
            "original_methods": self.original(),
            "status": self.status(),
            "detail": self.detail(),
        });
        match self {
            Self::Certified {
                clean,
                emitted,
                class_level_defects,
                ..
            } => {
                row["value"] = json!(self.rate());
                row["clean"] = json!(clean);
                row["emitted"] = json!(emitted);
                row["class_level_defects"] = json!(class_level_defects);
                row["display"] = Value::String(format!(
                    "{clean} clean / {emitted} emitted ({:.1}%)",
                    self.rate()
                ));
            }
            Self::Uncertified { emitted, cause, .. } => {
                row["emitted"] = json!(emitted);
                match cause {
                    UncertifiedCause::Compiler { first_defect_line } => {
                        row["uncertified_stage"] = Value::String("compiler".to_owned());
                        if let Some(first_defect_line) = first_defect_line {
                            row["first_defect_line"] = json!(first_defect_line);
                        }
                    }
                    UncertifiedCause::ProducerExit => {
                        row["uncertified_stage"] = Value::String("producer".to_owned());
                        row["producer_exit"] = Value::Bool(true);
                    }
                }
                row["display"] = Value::String(uncertified_display(*emitted));
            }
            Self::Missing { .. } => {
                row["value"] = json!(0.0);
                row["clean"] = json!(0);
                row["emitted"] = json!(0);
                row["display"] = Value::String("0 clean / 0 emitted (0.0%)".to_owned());
            }
        }
        row
    }
}

fn uncertified_display(emitted: usize) -> String {
    format!("not certified: {emitted} methods emitted")
}

fn score_disrobe_dex(javac: &Path, dex_bytes: &[u8], denominator: usize) -> ToolScore {
    let Ok(out): disrobe_pass_jvm::Result<AndroidDecompileOutput> =
        android_decompile_dex(dex_bytes, BackendPreference::PreferInHouse)
    else {
        return ToolScore::miss(
            denominator,
            "disrobe in-house DEX decompile returned an error".to_owned(),
        );
    };
    score_source_set(javac, &out.sources, denominator)
}

fn score_disrobe_jar(javac: &Path, jar_bytes: &[u8], denominator: usize) -> ToolScore {
    match disrobe_jar_source(jar_bytes) {
        Ok(source) => score_source(javac, &source, denominator),
        Err(defect) => ToolScore::miss(denominator, defect),
    }
}

fn disrobe_jar_source(jar_bytes: &[u8]) -> std::result::Result<String, String> {
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(jar_bytes) else {
        return Err("could not read classes from the baseline jar".to_owned());
    };
    let Some((_n, bytes)): Option<&(String, Vec<u8>)> =
        classes.iter().find(|(n, _)| n == "EdgeCases.class")
    else {
        return Err("EdgeCases.class absent from the baseline jar".to_owned());
    };
    let Ok(cf): disrobe_pass_jvm::Result<ClassFile> = parse_classfile(bytes) else {
        return Err("disrobe failed to parse EdgeCases.class".to_owned());
    };
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(n, _)| n.contains('$'))
        .filter_map(|(n, b)| parse_classfile(b).ok().map(|c| (n.clone(), c)))
        .collect();
    let decompiled: DecompiledClass = decompile_class_with_inners(&cf, &inners);
    Ok(decompiled.source)
}

fn score_jadx(javac: &Path, dex_bytes: &[u8], denominator: usize) -> ToolScore {
    let out: AndroidDecompileOutput = match run_jadx_on_bytes_detailed(dex_bytes, "EdgeCases.dex") {
        Ok(JadxOutcome::Recovered(out)) => out,
        Ok(JadxOutcome::ProducerFailed {
            status: _,
            stderr,
            emitted_methods,
            ..
        }) if emitted_methods > 0 => {
            let bounded_stderr: String = bounded_error_text(&stderr);
            let detail: String = if bounded_stderr.is_empty() {
                format!("jadx exited nonzero after emitting {emitted_methods} methods")
            } else {
                format!(
                    "jadx exited nonzero after emitting {emitted_methods} methods: {bounded_stderr}"
                )
            };
            return ToolScore::Uncertified {
                emitted: emitted_methods,
                cause: UncertifiedCause::ProducerExit,
                original: denominator,
                detail,
            };
        }
        Ok(JadxOutcome::ProducerFailed {
            status: _, stderr, ..
        }) => {
            let bounded_stderr: String = bounded_error_text(&stderr);
            return ToolScore::miss(
                denominator,
                format!("jadx exited nonzero before emitting a method: {bounded_stderr}"),
            );
        }
        Ok(JadxOutcome::Refused(refusal)) => {
            let detail: String = match refusal {
                JadxRefusal::OutputLimit {
                    kind,
                    actual,
                    limit,
                } => format!("jadx output {kind} {actual} exceeds the limit {limit}"),
                JadxRefusal::InvalidInputFileName => "jadx input filename is invalid".to_owned(),
                JadxRefusal::UnsafeOutputPath { detail } => detail,
                _ => "jadx refused the input or output".to_owned(),
            };
            return ToolScore::miss(denominator, detail);
        }
        Ok(_) => {
            return ToolScore::miss(
                denominator,
                "jadx returned an unsupported detailed outcome".to_owned(),
            );
        }
        Err(error) => {
            return ToolScore::miss(
                denominator,
                format!("jadx failed: {}", bounded_error_text(&error.to_string())),
            );
        }
    };
    if main_class_file(&out.sources).is_none() {
        return ToolScore::miss(denominator, "jadx produced no EdgeCases source".to_owned());
    }
    score_source_set(javac, &out.sources, denominator)
}

fn score_cfr(javac: &Path, jar_path: &Path, cfr: &CfrInvoke, denominator: usize) -> ToolScore {
    let work: ScratchDir = match ScratchDir::create("disrobe_h2h_cfr") {
        Ok(work) => work,
        Err(error) => {
            return ToolScore::miss(
                denominator,
                format!("could not create cfr work dir: {error}"),
            );
        }
    };
    let out_dir: PathBuf = work.path().join("out");
    let result: Result<BTreeMap<String, String>, String> = cfr.run(jar_path, &out_dir);
    let score: ToolScore = match result {
        Ok(sources) if main_class_file(&sources).is_some() => {
            score_source_set(javac, &sources, denominator)
        }
        Ok(_) => ToolScore::miss(denominator, "cfr produced no EdgeCases source".to_owned()),
        Err(e) => ToolScore::miss(denominator, format!("cfr failed: {e}")),
    };
    if let Err(error) = work.close() {
        return ToolScore::miss(denominator, format!("cfr work cleanup failed: {error}"));
    }
    score
}

fn score_source(javac: &Path, source: &str, original: usize) -> ToolScore {
    if source.trim().is_empty() {
        return ToolScore::miss(original, "empty recovered source".to_owned());
    }
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    sources.insert(MAIN_CLASS_FILE.to_owned(), source.to_owned());
    score_source_set(javac, &sources, original)
}

fn validate_source_set(sources: &BTreeMap<String, String>) -> std::result::Result<(), String> {
    validate_source_set_with_limits(sources, MAX_TREE_FILES, MAX_TEXT_BYTES, MAX_TREE_TEXT_BYTES)
}

fn validate_source_set_with_limits(
    sources: &BTreeMap<String, String>,
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: usize,
) -> std::result::Result<(), String> {
    if sources.len() > max_files {
        return Err(format!(
            "recovered source set contains {} files, exceeding the {max_files} file limit",
            sources.len()
        ));
    }
    let mut total_bytes: usize = 0;
    for (source, text) in sources {
        let path: &Path = Path::new(source);
        if source.is_empty()
            || source.split(['/', '\\']).any(|component: &str| {
                component.is_empty() || matches!(component, "." | "..") || component.contains(':')
            })
            || path
                .components()
                .any(|component: std::path::Component<'_>| {
                    !matches!(component, std::path::Component::Normal(_))
                })
        {
            return Err(format!(
                "recovered source path is not a safe relative path: {source}"
            ));
        }
        let file_bytes: usize = text.len();
        if u64::try_from(file_bytes).map_or(true, |bytes: u64| bytes > max_file_bytes) {
            return Err(format!(
                "recovered source {source} contains {file_bytes} bytes, exceeding the {max_file_bytes} byte file limit"
            ));
        }
        total_bytes = total_bytes.checked_add(file_bytes).ok_or_else(|| {
            "recovered source set byte count overflowed the platform size".to_owned()
        })?;
        if total_bytes > max_total_bytes {
            return Err(format!(
                "recovered source set contains {total_bytes} bytes, exceeding the {max_total_bytes} byte aggregate limit"
            ));
        }
    }
    Ok(())
}

fn score_source_set(
    javac: &Path,
    sources: &BTreeMap<String, String>,
    original: usize,
) -> ToolScore {
    if let Err(error) = validate_source_set(sources) {
        return ToolScore::miss(original, error);
    }
    let Some(main): Option<&String> = main_class_file(sources) else {
        return ToolScore::miss(
            original,
            format!("no {MAIN_CLASS_FILE} among the recovered sources"),
        );
    };
    if main.trim().is_empty() {
        return ToolScore::miss(original, "empty recovered source".to_owned());
    }
    let regions: Vec<SourceMethodRegion> = source_method_regions(sources);
    if regions.is_empty() {
        return ToolScore::miss(original, "recovered source contains no methods".to_owned());
    }
    let verdict: OracleVerdict = match javac_verdict_over_set(javac, sources) {
        Ok(verdict) => verdict,
        Err(error) => return score_initial_javac_failure(original, regions.len(), error),
    };
    if verdict.type_checked
        && !verdict
            .diagnostics
            .iter()
            .any(source_diagnostic_is_parse_failure)
    {
        return score_source_method_regions(original, &regions, &verdict, &BTreeSet::new());
    }
    score_parse_isolated_source_regions(javac, sources, original, &regions, verdict)
}

fn score_initial_javac_failure(original: usize, emitted: usize, error: String) -> ToolScore {
    ToolScore::Uncertified {
        emitted,
        cause: UncertifiedCause::Compiler {
            first_defect_line: None,
        },
        original,
        detail: format!("javac oracle failed before attribution: {error}"),
    }
}

#[derive(Debug)]
struct OracleVerdict {
    diagnostics: Vec<SourceDiagnostic>,
    type_checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceDiagnostic {
    source: String,
    line: usize,
    column: usize,
    code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceMethodRegion {
    source: String,
    start: usize,
    end: usize,
    start_column: usize,
    end_column: usize,
    body_start: Option<usize>,
    body_end: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFieldRegion {
    source: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceTypeRegion {
    source: String,
    start: usize,
    end: usize,
}

#[cfg(test)]
fn score_method_ranges(
    original: usize,
    ranges: &[(usize, usize)],
    diagnostics: std::result::Result<OracleVerdict, String>,
) -> ToolScore {
    let verdict: OracleVerdict = match diagnostics {
        Ok(verdict) => verdict,
        Err(error) => return ToolScore::miss(original, format!("javac oracle failed: {error}")),
    };
    let emitted: usize = ranges.len();
    if !verdict.type_checked {
        let Some(first_defect_line): Option<usize> = verdict
            .diagnostics
            .first()
            .map(|diagnostic: &SourceDiagnostic| diagnostic.line)
        else {
            return ToolScore::miss(
                original,
                "javac neither type-checked the recovered file nor reported where it stopped"
                    .to_owned(),
            );
        };
        let detail: String = format!(
            "javac stopped at a defect on line {first_defect_line} of the recovered file and never type-checked it, so none of the {emitted} recovered main-EdgeCases methods can be certified clean and none can be called unclean either (the original main class declares {original} methods)"
        );
        return ToolScore::Uncertified {
            emitted,
            cause: UncertifiedCause::Compiler {
                first_defect_line: Some(first_defect_line),
            },
            original,
            detail,
        };
    }
    let errors: Vec<usize> = verdict
        .diagnostics
        .into_iter()
        .map(|diagnostic: SourceDiagnostic| diagnostic.line)
        .collect();
    let in_a_method = |line: usize| -> bool {
        ranges
            .iter()
            .any(|(start, end): &(usize, usize)| line >= *start && line < *end)
    };
    let class_level_defects: usize = errors
        .iter()
        .filter(|line: &&usize| !in_a_method(**line))
        .count();
    let clean: usize = ranges
        .iter()
        .filter(|(start, end): &&(usize, usize)| {
            !errors.iter().any(|&l: &usize| l >= *start && l < *end)
        })
        .count();
    let outside: String = if class_level_defects == 0 {
        String::new()
    } else {
        format!(
            ", beside {class_level_defects} compiler {} outside any method, which belong to the recovered class structure rather than to one method",
            defects(class_level_defects)
        )
    };
    let detail: String = format!(
        "{clean} of {emitted} recovered main-EdgeCases methods compile clean under javac against a stubbed classpath{outside} (the original main class declares {original} methods; decompilers also emit synthetic accessor/lambda/bridge methods, so emitted counts differ per tool by design)"
    );
    ToolScore::Certified {
        clean,
        emitted,
        class_level_defects,
        original,
        detail,
    }
}

fn score_parse_isolated_source_regions(
    javac: &Path,
    sources: &BTreeMap<String, String>,
    original: usize,
    regions: &[SourceMethodRegion],
    mut verdict: OracleVerdict,
) -> ToolScore {
    let emitted: usize = regions.len();
    let mut isolated: BTreeSet<usize> = BTreeSet::new();
    let field_regions: Vec<SourceFieldRegion> = source_field_regions(sources);
    let mut isolated_fields: BTreeSet<usize> = BTreeSet::new();
    let type_regions: Vec<SourceTypeRegion> = source_type_regions(sources);
    let mut isolated_types: BTreeSet<usize> = BTreeSet::new();
    let mut rounds: usize = 0;
    let isolation_started: Instant = Instant::now();
    loop {
        rounds = rounds.saturating_add(1);
        if rounds > MAX_REGION_ISOLATION_ROUNDS {
            let first_defect_line: Option<usize> = verdict
                .diagnostics
                .first()
                .map(|diagnostic: &SourceDiagnostic| diagnostic.line);
            return ToolScore::Uncertified {
                emitted,
                cause: UncertifiedCause::Compiler { first_defect_line },
                original,
                detail: format!(
                    "javac still could not type-check the recovered source after {MAX_REGION_ISOLATION_ROUNDS} bounded region-isolation rounds"
                ),
            };
        }
        if isolation_started.elapsed() >= MAX_REGION_ISOLATION_TIME {
            let first_defect_line: Option<usize> = verdict
                .diagnostics
                .first()
                .map(|diagnostic: &SourceDiagnostic| diagnostic.line);
            return ToolScore::Uncertified {
                emitted,
                cause: UncertifiedCause::Compiler { first_defect_line },
                original,
                detail: format!(
                    "javac still could not type-check the recovered source within the {MAX_REGION_ISOLATION_TIME:?} region-isolation time budget"
                ),
            };
        }
        let mut implicated: Vec<usize> = verdict
            .diagnostics
            .iter()
            .filter_map(|diagnostic: &SourceDiagnostic| {
                diagnostic_region_index(diagnostic, regions)
            })
            .filter(|index: &usize| !isolated.contains(index))
            .collect();
        let mut implicated_fields: Vec<usize> = verdict
            .diagnostics
            .iter()
            .filter_map(|diagnostic: &SourceDiagnostic| {
                diagnostic_field_region_index(diagnostic, &field_regions)
            })
            .filter(|index: &usize| !isolated_fields.contains(index))
            .collect();
        let implicated_types: Vec<usize> = verdict
            .diagnostics
            .iter()
            .filter(|diagnostic: &&SourceDiagnostic| {
                diagnostic_region_index(diagnostic, regions).is_none()
                    && diagnostic_field_region_index(diagnostic, &field_regions).is_none()
            })
            .filter_map(|diagnostic: &SourceDiagnostic| {
                diagnostic_type_region_index(diagnostic, &type_regions)
            })
            .filter(|index: &usize| !isolated_types.contains(index))
            .min_by_key(|index: &usize| {
                type_regions
                    .get(*index)
                    .map_or(usize::MAX, |region: &SourceTypeRegion| {
                        region.end - region.start
                    })
            })
            .into_iter()
            .collect();
        if !implicated_types.is_empty() {
            implicated.clear();
            implicated_fields.clear();
        }
        if implicated.is_empty() && implicated_fields.is_empty() && implicated_types.is_empty() {
            let Some(first_defect): Option<&SourceDiagnostic> = verdict.diagnostics.first() else {
                return ToolScore::miss(
                    original,
                    "javac neither type-checked the recovered file nor reported where it stopped"
                        .to_owned(),
                );
            };
            let first_defect_line: usize = first_defect.line;
            return ToolScore::Uncertified {
                emitted,
                cause: UncertifiedCause::Compiler {
                    first_defect_line: Some(first_defect_line),
                },
                original,
                detail: format!(
                    "javac stopped at a defect in {} on line {first_defect_line} outside every recoverable method region, so none of the {emitted} emitted methods can be certified",
                    first_defect.source
                ),
            };
        }
        if implicated_types.iter().any(|index: &usize| {
            type_regions
                .get(*index)
                .is_some_and(|region: &SourceTypeRegion| {
                    sources
                        .get(&region.source)
                        .is_none_or(|source: &String| !java_type_shell_supported(source, region))
                })
        }) {
            let first_defect_line: Option<usize> = verdict
                .diagnostics
                .first()
                .map(|diagnostic: &SourceDiagnostic| diagnostic.line);
            return ToolScore::Uncertified {
                emitted,
                cause: UncertifiedCause::Compiler { first_defect_line },
                original,
                detail: "javac stopped in a type whose public declaration contract cannot be preserved by a neutral shell"
                    .to_owned(),
            };
        }
        isolated.extend(implicated);
        for field_index in &implicated_fields {
            let Some(field_region): Option<&SourceFieldRegion> = field_regions.get(*field_index)
            else {
                continue;
            };
            isolated.extend(
                regions
                    .iter()
                    .enumerate()
                    .filter(|(_index, method): &(usize, &SourceMethodRegion)| {
                        method.source == field_region.source
                            && method.start >= field_region.start
                            && method.end <= field_region.end
                    })
                    .map(|(index, _method): (usize, &SourceMethodRegion)| index),
            );
        }
        isolated_fields.extend(implicated_fields);
        for type_index in implicated_types {
            isolated_types.insert(type_index);
            let Some(type_region): Option<&SourceTypeRegion> = type_regions.get(type_index) else {
                continue;
            };
            isolated.extend(
                regions
                    .iter()
                    .enumerate()
                    .filter(|(_index, method): &(usize, &SourceMethodRegion)| {
                        method.source == type_region.source
                            && method.start >= type_region.start
                            && method.end <= type_region.end
                    })
                    .map(|(index, _method): (usize, &SourceMethodRegion)| index),
            );
        }
        let candidate: BTreeMap<String, String> = neutralize_source_regions(
            sources,
            regions,
            &isolated,
            &field_regions,
            &isolated_fields,
            &type_regions,
            &isolated_types,
        );
        let Some(remaining): Option<Duration> =
            MAX_REGION_ISOLATION_TIME.checked_sub(isolation_started.elapsed())
        else {
            return ToolScore::Uncertified {
                emitted,
                cause: UncertifiedCause::Compiler {
                    first_defect_line: verdict
                        .diagnostics
                        .first()
                        .map(|diagnostic: &SourceDiagnostic| diagnostic.line),
                },
                original,
                detail: format!(
                    "javac still could not type-check the recovered source within the {MAX_REGION_ISOLATION_TIME:?} region-isolation time budget"
                ),
            };
        };
        let timeout: Duration = isolation_retry_timeout(remaining);
        verdict = match javac_verdict_over_set_with_timeout(javac, &candidate, timeout) {
            Ok(candidate_verdict) => candidate_verdict,
            Err(error) => return score_isolation_retry_failure(original, emitted, &verdict, error),
        };
        if verdict.type_checked {
            break;
        }
    }
    score_source_method_regions(original, regions, &verdict, &isolated)
}

fn score_isolation_retry_failure(
    original: usize,
    emitted: usize,
    verdict: &OracleVerdict,
    error: String,
) -> ToolScore {
    let first_defect_line: Option<usize> = verdict
        .diagnostics
        .first()
        .map(|diagnostic: &SourceDiagnostic| diagnostic.line);
    ToolScore::Uncertified {
        emitted,
        cause: UncertifiedCause::Compiler { first_defect_line },
        original,
        detail: format!(
            "javac isolation retry failed before attribution could resume: {error}; the {emitted} emitted methods remain uncertified"
        ),
    }
}

fn score_source_method_regions(
    original: usize,
    regions: &[SourceMethodRegion],
    verdict: &OracleVerdict,
    isolated: &BTreeSet<usize>,
) -> ToolScore {
    let emitted: usize = regions.len();
    let failed: BTreeSet<usize> = verdict
        .diagnostics
        .iter()
        .filter_map(|diagnostic: &SourceDiagnostic| diagnostic_region_index(diagnostic, regions))
        .chain(isolated.iter().copied())
        .collect();
    let class_level_defects: usize = verdict
        .diagnostics
        .iter()
        .filter(|diagnostic: &&SourceDiagnostic| {
            diagnostic_region_index(diagnostic, regions).is_none()
        })
        .count();
    let clean: usize = emitted.saturating_sub(failed.len());
    ToolScore::Certified {
        clean,
        emitted,
        class_level_defects,
        original,
        detail: format!(
            "{clean} of {emitted} emitted methods compile clean under javac after source-region parse failures are isolated with the same bounded rule for every tool (the original main class declares {original} methods)"
        ),
    }
}

fn diagnostic_region_index(
    diagnostic: &SourceDiagnostic,
    regions: &[SourceMethodRegion],
) -> Option<usize> {
    regions
        .iter()
        .enumerate()
        .filter(|(_index, region): &(usize, &SourceMethodRegion)| {
            source_name_matches(&region.source, &diagnostic.source)
                && diagnostic_in_method_region(diagnostic, region)
        })
        .max_by_key(|(_index, region): &(usize, &SourceMethodRegion)| region.source.len())
        .map(|(index, _region): (usize, &SourceMethodRegion)| index)
}

const fn diagnostic_in_method_region(
    diagnostic: &SourceDiagnostic,
    region: &SourceMethodRegion,
) -> bool {
    if diagnostic.line < region.start || diagnostic.line >= region.end {
        return false;
    }
    if diagnostic.column == 0 {
        return true;
    }
    if diagnostic.line == region.start && diagnostic.column < region.start_column {
        return false;
    }
    if diagnostic.line.saturating_add(1) == region.end && diagnostic.column >= region.end_column {
        return false;
    }
    true
}

fn diagnostic_field_region_index(
    diagnostic: &SourceDiagnostic,
    regions: &[SourceFieldRegion],
) -> Option<usize> {
    regions
        .iter()
        .enumerate()
        .filter(|(_index, region): &(usize, &SourceFieldRegion)| {
            source_name_matches(&region.source, &diagnostic.source)
                && diagnostic.line >= region.start
                && diagnostic.line < region.end
        })
        .max_by_key(|(_index, region): &(usize, &SourceFieldRegion)| region.source.len())
        .map(|(index, _region): (usize, &SourceFieldRegion)| index)
}

fn diagnostic_type_region_index(
    diagnostic: &SourceDiagnostic,
    regions: &[SourceTypeRegion],
) -> Option<usize> {
    regions
        .iter()
        .enumerate()
        .filter(|(_index, region): &(usize, &SourceTypeRegion)| {
            source_name_matches(&region.source, &diagnostic.source)
                && diagnostic.line >= region.start
                && diagnostic.line < region.end
        })
        .max_by_key(|(_index, region): &(usize, &SourceTypeRegion)| {
            (
                region.source.len(),
                std::cmp::Reverse(region.end - region.start),
            )
        })
        .map(|(index, _region): (usize, &SourceTypeRegion)| index)
}

fn source_name_matches(source: &str, diagnostic_source: &str) -> bool {
    let normalized: String = source.replace('\\', "/");
    let normalized_diagnostic: String = diagnostic_source.replace('\\', "/");
    normalized == normalized_diagnostic
        || normalized.ends_with(&format!("/{normalized_diagnostic}"))
        || normalized_diagnostic.ends_with(&format!("/{normalized}"))
}

fn neutralize_source_regions(
    sources: &BTreeMap<String, String>,
    regions: &[SourceMethodRegion],
    isolated: &BTreeSet<usize>,
    field_regions: &[SourceFieldRegion],
    isolated_fields: &BTreeSet<usize>,
    type_regions: &[SourceTypeRegion],
    isolated_types: &BTreeSet<usize>,
) -> BTreeMap<String, String> {
    let mut by_source: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
    for index in isolated {
        let Some(region): Option<&SourceMethodRegion> = regions.get(*index) else {
            continue;
        };
        let Some(source_ranges): Option<&mut BTreeSet<usize>> =
            by_source.get_mut(region.source.as_str())
        else {
            by_source.insert(region.source.as_str(), BTreeSet::from([*index]));
            continue;
        };
        source_ranges.insert(*index);
    }
    sources
        .iter()
        .map(|(name, source): (&String, &String)| {
            let ranges: Vec<&SourceMethodRegion> = by_source
                .get(name.as_str())
                .into_iter()
                .flat_map(|indices: &BTreeSet<usize>| indices.iter())
                .filter_map(|index: &usize| regions.get(*index))
                .collect();
            let field_ranges: Vec<(usize, usize)> = isolated_fields
                .iter()
                .filter_map(|index: &usize| field_regions.get(*index))
                .filter(|region: &&SourceFieldRegion| region.source == *name)
                .map(|region: &SourceFieldRegion| (region.start, region.end))
                .collect();
            let method_neutralized: String = neutralize_method_regions(source, &ranges);
            let field_neutralized: String =
                neutralize_field_regions(&method_neutralized, &field_ranges);
            let type_ranges: Vec<(usize, usize)> = isolated_types
                .iter()
                .filter_map(|index: &usize| type_regions.get(*index))
                .filter(|region: &&SourceTypeRegion| region.source == *name)
                .map(|region: &SourceTypeRegion| (region.start, region.end))
                .collect();
            (
                name.clone(),
                neutralize_type_regions(&field_neutralized, &type_ranges),
            )
        })
        .collect()
}

fn neutralize_method_regions(source: &str, ranges: &[&SourceMethodRegion]) -> String {
    const STUB: &str = "throw null;";

    let mut neutralized: String = source.to_owned();
    for region in ranges {
        let (Some(body_start), Some(body_end)): (Option<usize>, Option<usize>) =
            (region.body_start, region.body_end)
        else {
            continue;
        };
        let Some(body): Option<&str> = source.get(body_start..body_end) else {
            continue;
        };
        let mut replacement: String = body
            .bytes()
            .map(|byte: u8| match byte {
                b'\n' => '\n',
                b'\r' => '\r',
                _ => ' ',
            })
            .collect();
        let line_capacity: usize = replacement.find(['\r', '\n']).unwrap_or(replacement.len());
        if line_capacity >= STUB.len() {
            replacement.replace_range(..STUB.len(), STUB);
        }
        neutralized.replace_range(body_start..body_end, &replacement);
    }
    neutralized
}

fn neutralize_field_regions(source: &str, ranges: &[(usize, usize)]) -> String {
    let trailing_newline: bool = source.ends_with('\n');
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let structural: String = java_structure_source(source);
    let structural_lines: Vec<&str> = structural.lines().collect();
    for (start, end) in ranges {
        let first: usize = start.saturating_sub(1);
        let last: usize = end.saturating_sub(1).min(lines.len());
        let mut delimiter_depth: usize = 0;
        let Some((equals_line, equals_column)): Option<(usize, usize)> =
            (first..last).find_map(|line_index: usize| {
                structural_lines
                    .get(line_index)
                    .and_then(|line: &&str| top_level_assignment_column(line, &mut delimiter_depth))
                    .map(|column: usize| (line_index, column))
            })
        else {
            continue;
        };
        let Some(prefix): Option<&str> = lines
            .get(equals_line)
            .and_then(|line: &String| line.get(..equals_column))
        else {
            continue;
        };
        lines[equals_line] = java_constant_field_stub(prefix).map_or_else(
            || format!("{prefix};"),
            |literal: &str| format!("{prefix}= {literal};"),
        );
        for line in lines.iter_mut().take(last).skip(equals_line + 1) {
            line.clear();
        }
    }
    let mut neutralized: String = lines.join("\n");
    if trailing_newline {
        neutralized.push('\n');
    }
    neutralized
}

fn java_constant_field_stub(prefix: &str) -> Option<&'static str> {
    let declaration: &str = java_declaration_after_annotations(prefix);
    let tokens: Vec<&str> = declaration.split_ascii_whitespace().collect();
    if !tokens.contains(&"static") || !tokens.contains(&"final") {
        return None;
    }
    let type_name: &str = tokens.iter().rev().nth(1).copied()?;
    match type_name {
        "boolean" => Some("false"),
        "char" => Some("'\\0'"),
        "byte" | "short" | "int" => Some("0"),
        "long" => Some("0L"),
        "float" => Some("0.0f"),
        "double" => Some("0.0d"),
        "String" | "java.lang.String" => Some("\"\""),
        _ => None,
    }
}

fn neutralize_type_regions(source: &str, ranges: &[(usize, usize)]) -> String {
    let trailing_newline: bool = source.ends_with('\n');
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let structural: String = java_structure_source(source);
    let structural_lines: Vec<&str> = structural.lines().collect();
    let method_ranges: Vec<(usize, usize)> = class_method_ranges(source);
    let field_ranges: Vec<(usize, usize)> = field_initializer_ranges(source);
    let multiline_field_ranges: Vec<(usize, usize)> = multiline_field_ranges(source);
    let member_ranges: Vec<(usize, usize)> = merge_line_ranges(
        method_ranges
            .iter()
            .chain(field_ranges.iter())
            .chain(multiline_field_ranges.iter())
            .copied(),
    );
    for (start, end) in ranges {
        let first: usize = start.saturating_sub(1);
        let last: usize = end.saturating_sub(1).min(lines.len());
        let Some((open_line, open_column)): Option<(usize, usize)> =
            (first..=last.min(lines.len().saturating_sub(1))).find_map(|line_index: usize| {
                structural_lines
                    .get(line_index)
                    .and_then(|line: &&str| line.find('{'))
                    .map(|column: usize| (line_index, column))
            })
        else {
            continue;
        };
        let header: String = structural_lines
            .iter()
            .take(open_line)
            .skip(first)
            .copied()
            .chain(
                structural_lines
                    .get(open_line)
                    .and_then(|line: &&str| line.get(..open_column)),
            )
            .collect::<Vec<&str>>()
            .join(" ");
        let Some(type_name): Option<String> = java_type_name(&header).map(str::to_owned) else {
            continue;
        };
        let indentation_end: usize = lines[first].len() - lines[first].trim_start().len();
        let indentation: String = lines[first][..indentation_end].to_owned();
        let closing_index: usize = if last <= first {
            first
        } else {
            last.saturating_sub(1)
        };
        let is_enum: bool = header
            .split_ascii_whitespace()
            .any(|token: &str| token == "enum");
        let shell_header: String = if is_enum {
            header.replacen(
                "enum",
                if indentation.is_empty() {
                    "class"
                } else {
                    "static class"
                },
                1,
            )
        } else {
            header.clone()
        };
        if open_line == closing_index {
            let structural_line: &str =
                structural_lines.get(open_line).copied().unwrap_or_default();
            let Some(close_column): Option<usize> =
                matching_brace_column(structural_line, open_column)
            else {
                continue;
            };
            let suffix: &str = lines[open_line]
                .get(close_column.saturating_add(1)..)
                .unwrap_or_default();
            let shell: String = if is_enum {
                let body: &str = structural_line
                    .get(open_column.saturating_add(1)..close_column)
                    .unwrap_or_default();
                let constants: Vec<String> = top_level_enum_constants(body)
                    .into_iter()
                    .filter_map(java_simple_enum_constant)
                    .map(|constant: &str| {
                        format!("static final {type_name} {constant} = new {type_name}();")
                    })
                    .collect();
                format!("{} {{ {} }}", shell_header.trim_end(), constants.join(" "))
            } else {
                format!("{} {{}}", shell_header.trim_end())
            };
            lines[open_line] = format!("{indentation}{shell}{suffix}");
            continue;
        }
        lines[first] = format!("{indentation}{shell_header} {{");
        for (line_index, line) in lines
            .iter_mut()
            .enumerate()
            .take(closing_index)
            .skip(first + 1)
        {
            let line_number: usize = line_index + 1;
            let enum_constant: Option<&str> = java_simple_enum_constant(
                structural_lines
                    .get(line_index)
                    .copied()
                    .unwrap_or_default(),
            );
            if is_enum && let Some(constant) = enum_constant {
                let member_indentation_end: usize =
                    line.len().saturating_sub(line.trim_start().len());
                let member_indentation: &str = &line[..member_indentation_end];
                *line = format!(
                    "{member_indentation}static final {type_name} {constant} = new {type_name}();"
                );
                continue;
            }
            let member_declaration: bool = line_in_ranges(&member_ranges, line_number)
                || structural_lines
                    .get(line_index)
                    .is_some_and(|structural_line: &&str| java_field_declaration(structural_line));
            if !member_declaration {
                line.clear();
            }
        }
        if let Some(closing_line) = lines.get_mut(closing_index) {
            *closing_line = format!("{indentation}}}");
        }
    }
    let mut neutralized: String = lines.join("\n");
    if trailing_newline {
        neutralized.push('\n');
    }
    neutralized
}

fn matching_brace_column(line: &str, open_column: usize) -> Option<usize> {
    let mut depth: usize = 0;
    for (column, character) in line
        .char_indices()
        .skip_while(|(column, _)| *column < open_column)
    {
        match character {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(column);
                }
            }
            _ => {}
        }
    }
    None
}

fn java_type_shell_supported(source: &str, region: &SourceTypeRegion) -> bool {
    let structural: String = java_structure_source(source);
    let lines: Vec<&str> = structural.lines().collect();
    let first: usize = region.start.saturating_sub(1);
    let last: usize = region.end.saturating_sub(1).min(lines.len());
    let header: String = lines
        .iter()
        .take(last)
        .skip(first)
        .copied()
        .take_while(|line: &&str| !line.contains('{'))
        .chain(
            lines
                .iter()
                .take(last)
                .skip(first)
                .find_map(|line: &&str| line.split_once('{').map(|(prefix, _rest)| prefix)),
        )
        .collect::<Vec<&str>>()
        .join(" ");
    !header
        .split_ascii_whitespace()
        .any(|token: &str| matches!(token.trim_start_matches('@'), "record" | "interface"))
}

fn java_simple_enum_constant(line: &str) -> Option<&str> {
    let candidate: &str = line
        .trim()
        .split_once(['(', '{', ',', ';'])
        .map_or_else(|| line.trim(), |(prefix, _)| prefix.trim());
    (!candidate.is_empty()
        && candidate
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')))
    .then_some(candidate)
}

fn top_level_enum_constants(body: &str) -> Vec<&str> {
    let mut constants: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut paren_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut quote: Option<char> = None;
    let mut escaped: bool = false;
    for (index, character) in body.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            continue;
        }
        match character {
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0 && brace_depth == 0 && bracket_depth == 0 => {
                constants.push(body.get(start..index).unwrap_or_default());
                start = index.saturating_add(character.len_utf8());
            }
            _ => {}
        }
    }
    if start < body.len() {
        constants.push(body.get(start..).unwrap_or_default());
    }
    constants
}

fn java_type_name(header: &str) -> Option<&str> {
    let tokens: Vec<&str> = header
        .split(|character: char| {
            !character.is_ascii_alphanumeric()
                && character != '_'
                && character != '$'
                && character != '@'
        })
        .filter(|token: &&str| !token.is_empty())
        .collect();
    tokens
        .windows(2)
        .find(|pair: &&[&str]| {
            matches!(
                pair[0],
                "class" | "interface" | "enum" | "record" | "@interface"
            )
        })
        .map(|pair: &[&str]| pair[1])
}

fn java_field_declaration(line: &str) -> bool {
    let Some(declaration): Option<&str> = line.trim().strip_suffix(';') else {
        return false;
    };
    if declaration.contains(['(', ')', '=']) {
        return false;
    }
    let mut tokens = declaration.split_ascii_whitespace().filter(|token: &&str| {
        !matches!(
            *token,
            "public" | "protected" | "private" | "static" | "final" | "transient" | "volatile"
        ) && !token.starts_with('@')
    });
    let Some(_type_token): Option<&str> = tokens.next() else {
        return false;
    };
    tokens.next().is_some()
}

fn multiline_field_ranges(source: &str) -> Vec<(usize, usize)> {
    let structural: String = java_structure_source(source);
    let method_ranges: Vec<(usize, usize)> = merge_line_ranges(class_method_ranges(source));
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (index, line) in structural.lines().enumerate() {
        let line_number: usize = index + 1;
        if line_in_ranges(&method_ranges, line_number) {
            start = None;
            continue;
        }
        if start.is_none() && line.trim().is_empty() {
            continue;
        }
        if start.is_none() {
            start = Some(line_number);
        }
        if line.contains(';') {
            let first: usize = start.unwrap_or(line_number);
            let candidate: String = structural
                .lines()
                .skip(first.saturating_sub(1))
                .take(line_number.saturating_sub(first).saturating_add(1))
                .collect::<Vec<&str>>()
                .join(" ");
            if !candidate.contains(['(', ')', '=', '{', '}']) && java_field_declaration(&candidate)
            {
                ranges.push((first, line_number + 1));
            }
            start = None;
        }
    }
    ranges
}

const MAIN_CLASS_FILE: &str = "EdgeCases.java";
const MAX_REGION_ISOLATION_ROUNDS: usize = 64;
const MAX_REGION_ISOLATION_TIME: Duration = Duration::from_secs(30);

fn isolation_retry_timeout(remaining: Duration) -> Duration {
    let half: Duration = remaining
        .checked_div(2)
        .map_or(Duration::ZERO, |value: Duration| value);
    if half < Duration::from_millis(1) {
        Duration::from_millis(1)
    } else {
        half
    }
}

fn main_class_file(sources: &BTreeMap<String, String>) -> Option<&String> {
    sources
        .iter()
        .find(|(path, _): &(&String, &String)| {
            let normalized: String = path.replace('\\', "/");
            normalized == MAIN_CLASS_FILE || normalized.ends_with(&format!("/{MAIN_CLASS_FILE}"))
        })
        .map(|(_path, source): (&String, &String)| source)
}

fn source_method_regions(sources: &BTreeMap<String, String>) -> Vec<SourceMethodRegion> {
    sources
        .iter()
        .flat_map(|(source_name, source): (&String, &String)| {
            java_regions(source)
                .into_iter()
                .filter(|region: &JavaRegion| region.kind == JavaBraceKind::Method)
                .map(move |region: JavaRegion| SourceMethodRegion {
                    source: source_name.clone(),
                    start: region.start_line,
                    end: region.end_line,
                    start_column: region.start_column,
                    end_column: region.end_column,
                    body_start: region.body_start,
                    body_end: region.body_end,
                })
        })
        .collect()
}

fn source_field_regions(sources: &BTreeMap<String, String>) -> Vec<SourceFieldRegion> {
    sources
        .iter()
        .flat_map(|(source_name, source): (&String, &String)| {
            field_initializer_ranges(source)
                .into_iter()
                .map(move |(start, end): (usize, usize)| SourceFieldRegion {
                    source: source_name.clone(),
                    start,
                    end,
                })
        })
        .collect()
}

fn source_type_regions(sources: &BTreeMap<String, String>) -> Vec<SourceTypeRegion> {
    sources
        .iter()
        .flat_map(|(source_name, source): (&String, &String)| {
            java_regions(source)
                .into_iter()
                .filter(|region: &JavaRegion| region.kind == JavaBraceKind::Type)
                .map(move |region: JavaRegion| SourceTypeRegion {
                    source: source_name.clone(),
                    start: region.start_line,
                    end: region.end_line,
                })
        })
        .collect()
}

fn classes_from_jar(jar_bytes: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    classes_from_jar_with_limits(
        jar_bytes,
        MAX_ZIP_ENTRIES,
        MAX_ZIP_ENTRY_BYTES,
        MAX_ZIP_TOTAL_BYTES,
    )
}

fn classes_from_jar_with_limits(
    jar_bytes: &[u8],
    max_entries: usize,
    max_entry_bytes: u64,
    max_total_bytes: u64,
) -> Option<Vec<(String, Vec<u8>)>> {
    let reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(jar_bytes);
    let mut z: zip::ZipArchive<std::io::Cursor<&[u8]>> = zip::ZipArchive::new(reader).ok()?;
    if z.len() > max_entries {
        return None;
    }
    let mut total_bytes: u64 = 0;
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..z.len() {
        let entry: zip::read::ZipFile<'_> = z.by_index(i).ok()?;
        if Path::new(entry.name())
            .extension()
            .is_some_and(|extension: &std::ffi::OsStr| extension == "class")
        {
            let entry_size: u64 = entry.size();
            if entry_size > max_entry_bytes {
                return None;
            }
            let name: String = entry.name().to_owned();
            let mut bytes: Vec<u8> = Vec::new();
            let mut limited: std::io::Take<zip::read::ZipFile<'_>> =
                entry.take(max_entry_bytes.saturating_add(1));
            let read_len: usize = limited.read_to_end(&mut bytes).ok()?;
            let read_len_u64: u64 = u64::try_from(read_len).unwrap_or(u64::MAX);
            if read_len_u64 > max_entry_bytes {
                return None;
            }
            let next_total: u64 = total_bytes.checked_add(read_len_u64)?;
            if next_total > max_total_bytes {
                return None;
            }
            total_bytes = next_total;
            out.push((name, bytes));
        }
    }
    Some(out)
}

#[cfg(test)]
fn javac_verdict(javac: &Path, source: &str) -> std::result::Result<OracleVerdict, String> {
    let mut single: BTreeMap<String, String> = BTreeMap::new();
    single.insert(MAIN_CLASS_FILE.to_owned(), source.to_owned());
    javac_verdict_over_set(javac, &single)
}

fn javac_verdict_over_set(
    javac: &Path,
    sources: &BTreeMap<String, String>,
) -> std::result::Result<OracleVerdict, String> {
    javac_verdict_over_set_with_timeout(javac, sources, TOOL_TIMEOUT)
}

fn javac_verdict_over_set_with_timeout(
    javac: &Path,
    sources: &BTreeMap<String, String>,
    timeout: Duration,
) -> std::result::Result<OracleVerdict, String> {
    validate_source_set(sources)?;
    let scratch: ScratchDir = ScratchDir::create("disrobe_h2h_javac")
        .map_err(|error: std::io::Error| format!("could not create javac workspace: {error}"))?;
    let dir: &Path = scratch.path();
    let mut written: Vec<PathBuf> = Vec::with_capacity(sources.len());
    for (relative, text) in sources {
        let path: PathBuf = dir.join(relative.replace('\\', "/"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error: std::io::Error| {
                format!("could not create javac source directory: {error}")
            })?;
        }
        std::fs::write(&path, text)
            .map_err(|error: std::io::Error| format!("could not write javac source: {error}"))?;
        written.push(path);
    }
    if written.is_empty() {
        return Err("no recovered source to compile".to_owned());
    }
    let stub: PathBuf = dir.join("cp");
    std::fs::create_dir(&stub)
        .map_err(|error: std::io::Error| format!("could not create javac classpath: {error}"))?;
    let borrowed: Vec<&Path> = written.iter().map(PathBuf::as_path).collect();
    let out: disrobe_core::subprocess::CapturedOutput =
        compile(javac, &stub, &dir.join("out"), &borrowed, timeout)?;
    if out.exit_code == Some(0) {
        require_emitted_edgecases_class(dir)?;
        return Ok(OracleVerdict {
            diagnostics: Vec::new(),
            type_checked: true,
        });
    }
    let diagnostics: String = combined_output(&out);
    let source_diagnostics: Vec<SourceDiagnostic> = failed_javac_diagnostics(&diagnostics)
        .map_err(|error: String| {
            format!(
                "javac exited with {}: {error}",
                out.exit_code
                    .map_or_else(|| "no exit code".to_owned(), |code: i32| code.to_string())
            )
        })?;
    let type_checked: bool = type_check_was_reached(javac, dir, &stub, &borrowed, timeout)?;
    Ok(OracleVerdict {
        diagnostics: source_diagnostics,
        type_checked,
    })
}

fn type_check_was_reached(
    javac: &Path,
    dir: &Path,
    stub: &Path,
    source_paths: &[&Path],
    timeout: Duration,
) -> std::result::Result<bool, String> {
    let probe_work: ScratchDir =
        ScratchDir::create("disrobe_h2h_probe").map_err(|error: std::io::Error| {
            format!("could not create the type-check probe: {error}")
        })?;
    let probe_path: PathBuf = probe_work.path().join(ATTRIBUTION_PROBE_FILE);
    std::fs::write(&probe_path, ATTRIBUTION_PROBE_SOURCE).map_err(|error: std::io::Error| {
        format!("could not write the type-check probe: {error}")
    })?;
    let mut with_probe: Vec<&Path> = source_paths.to_vec();
    with_probe.push(&probe_path);
    let out: disrobe_core::subprocess::CapturedOutput =
        compile(javac, stub, &dir.join("probe-out"), &with_probe, timeout)?;
    if out.exit_code == Some(0) {
        return Err(
            "the type-check probe compiled without reporting its unresolvable symbol, so it can no \
             longer tell a parsed file from an unparsed one"
                .to_owned(),
        );
    }
    attribution_probe_reported(&combined_output(&out))
}

fn attribution_probe_reported(diagnostics: &str) -> std::result::Result<bool, String> {
    let parsed: Vec<SourceDiagnostic> = failed_javac_diagnostics(diagnostics)?;
    Ok(parsed.iter().any(|diagnostic: &SourceDiagnostic| {
        source_name_matches(ATTRIBUTION_PROBE_FILE, &diagnostic.source)
    }))
}

fn compile(
    javac: &Path,
    stub: &Path,
    out_dir: &Path,
    sources: &[&Path],
    timeout: Duration,
) -> std::result::Result<disrobe_core::subprocess::CapturedOutput, String> {
    std::fs::create_dir_all(out_dir).map_err(|error: std::io::Error| {
        format!("could not create the javac output directory: {error}")
    })?;
    let mut args: Vec<std::ffi::OsString> = vec![
        "-nowarn".into(),
        "-proc:none".into(),
        "-XDrawDiagnostics".into(),
        "-Xmaxerrs".into(),
        DIAGNOSTIC_LIMIT.into(),
        "-cp".into(),
        stub.as_os_str().to_owned(),
        "-d".into(),
        out_dir.as_os_str().to_owned(),
    ];
    for source in sources {
        args.push(source.as_os_str().to_owned());
    }
    let captured: Option<disrobe_core::subprocess::CapturedOutput> =
        disrobe_core::subprocess::run_captured(javac, &args, timeout, MAX_TOOL_CAPTURE_BYTES)
            .map_err(|error: std::io::Error| format!("could not start javac: {error}"))?;
    captured.ok_or_else(|| {
        format!(
            "javac exceeded the {} second execution limit",
            timeout.as_secs()
        )
    })
}

fn combined_output(out: &disrobe_core::subprocess::CapturedOutput) -> String {
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stderr);
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    format!("{stderr}\n{stdout}")
}

fn require_emitted_edgecases_class(dir: &Path) -> std::result::Result<(), String> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry: walkdir::DirEntry = entry
            .map_err(|error: walkdir::Error| format!("could not inspect javac output: {error}"))?;
        let path: &Path = entry.path();
        if entry.file_type().is_file()
            && path
                .file_name()
                .and_then(|name: &std::ffi::OsStr| name.to_str())
                == Some("EdgeCases.class")
        {
            return Ok(());
        }
    }
    Err("javac exited successfully without emitting EdgeCases.class".to_owned())
}

#[cfg(test)]
fn failed_javac_error_lines(diagnostics: &str) -> std::result::Result<Vec<usize>, String> {
    let error_lines: Vec<usize> = failed_javac_diagnostics(diagnostics)?
        .into_iter()
        .filter(|diagnostic: &SourceDiagnostic| {
            source_name_matches(MAIN_CLASS_FILE, &diagnostic.source)
        })
        .map(|diagnostic: SourceDiagnostic| diagnostic.line)
        .collect();
    if error_lines.is_empty() {
        return Err("javac emitted no parseable EdgeCases.java diagnostic".to_owned());
    }
    Ok(error_lines)
}

fn failed_javac_diagnostics(
    diagnostics: &str,
) -> std::result::Result<Vec<SourceDiagnostic>, String> {
    failed_javac_diagnostics_with_limit(diagnostics, MAX_JAVA_DIAGNOSTICS)
}

fn failed_javac_diagnostics_with_limit(
    diagnostics: &str,
    max_diagnostics: usize,
) -> std::result::Result<Vec<SourceDiagnostic>, String> {
    let mut parsed_diagnostics: Vec<SourceDiagnostic> = Vec::new();
    for line in diagnostics.lines() {
        let Some((before, rest)): Option<(&str, &str)> = line.rsplit_once(".java:") else {
            continue;
        };
        let Some((number, after_line)): Option<(&str, &str)> = rest.split_once(':') else {
            return Err("unparseable EdgeCases.java diagnostic".to_owned());
        };
        let parsed: usize =
            number
                .trim()
                .parse::<usize>()
                .map_err(|error: std::num::ParseIntError| {
                    format!("unparseable EdgeCases.java diagnostic line: {error}")
                })?;
        let path: &str = before.trim();
        if path.is_empty() {
            return Err("unparseable javac source path".to_owned());
        }
        let (column, message): (usize, &str) = after_line.split_once(':').map_or(
            (0, after_line),
            |(candidate, message): (&str, &str)| {
                candidate
                    .trim()
                    .parse::<usize>()
                    .map_or((0, after_line), |column: usize| (column, message))
            },
        );
        let code: String = message
            .split_once(':')
            .map_or(message, |(code, _detail): (&str, &str)| code)
            .trim()
            .to_owned();
        if parsed_diagnostics.len() >= max_diagnostics {
            return Err(format!(
                "javac reported more than the {max_diagnostics} diagnostic limit"
            ));
        }
        parsed_diagnostics.push(SourceDiagnostic {
            source: format!("{path}.java"),
            line: parsed,
            column,
            code,
        });
    }
    parsed_diagnostics.sort();
    parsed_diagnostics.dedup();
    if parsed_diagnostics.is_empty() {
        return Err("javac emitted no parseable Java source diagnostic".to_owned());
    }
    Ok(parsed_diagnostics)
}

fn source_diagnostic_is_parse_failure(diagnostic: &SourceDiagnostic) -> bool {
    [
        "expected",
        "illegal.start",
        "premature.eof",
        "not.stmt",
        "without.if",
        "without.try",
        "try.without",
        "invalid.meth.decl",
        "enum.constant.expected",
        "record.header.expected",
        "class.interface.or.enum.expected",
    ]
    .iter()
    .any(|fragment: &&str| diagnostic.code.contains(fragment))
}

fn main_class_method_ranges(src: &str) -> Vec<(usize, usize)> {
    method_ranges_at_depth(src, Some(1))
}

fn class_method_ranges(src: &str) -> Vec<(usize, usize)> {
    method_ranges_at_depth(src, None)
}

fn method_ranges_at_depth(src: &str, required_depth: Option<usize>) -> Vec<(usize, usize)> {
    java_regions(src)
        .into_iter()
        .filter(|region: &JavaRegion| {
            region.kind == JavaBraceKind::Method
                && required_depth.is_none_or(|required: usize| region.type_depth == required)
        })
        .map(|region: JavaRegion| (region.start_line, region.end_line))
        .collect()
}

fn java_regions(src: &str) -> Vec<JavaRegion> {
    let structural: String = java_structure_source(src);
    let bytes: &[u8] = structural.as_bytes();
    let mut line_starts: Vec<usize> = vec![0];
    line_starts.extend(
        bytes
            .iter()
            .enumerate()
            .filter_map(|(index, byte): (usize, &u8)| (*byte == b'\n').then_some(index + 1)),
    );
    let mut out: Vec<JavaRegion> = Vec::new();
    let mut stack: Vec<JavaBrace> = Vec::new();
    let mut type_names: Vec<Option<String>> = Vec::new();
    let mut header_boundary: usize = 0;
    for (offset, byte) in bytes.iter().enumerate() {
        match *byte {
            b'{' => {
                let relative_header_start: usize = bytes[header_boundary..offset]
                    .iter()
                    .position(|candidate: &u8| !candidate.is_ascii_whitespace())
                    .map_or(0, |relative: usize| relative);
                let header_start: usize = header_boundary + relative_header_start;
                let header: &str = structural[header_start..offset].trim();
                let inside_type: bool = !type_names.is_empty();
                let parent_type_name: Option<&str> =
                    type_names.iter().rev().find_map(Option::as_deref);
                let type_depth: usize = type_names.len();
                let kind: JavaBraceKind = if java_type_header(header) {
                    JavaBraceKind::Type
                } else if inside_type
                    && (java_method_header(header, parent_type_name)
                        || parent_type_name.is_some_and(|type_name: &str| {
                            java_compact_constructor_header(header, type_name)
                        }))
                {
                    JavaBraceKind::Method
                } else {
                    JavaBraceKind::Other
                };
                let start_line: usize =
                    line_starts.partition_point(|start: &usize| *start <= header_start);
                let start_column: usize = header_start
                    .saturating_sub(*line_starts.get(start_line.saturating_sub(1)).unwrap_or(&0))
                    .saturating_add(1);
                let type_name: Option<String> = (kind == JavaBraceKind::Type)
                    .then(|| java_type_name(header).map(str::to_owned))
                    .flatten();
                if kind == JavaBraceKind::Type {
                    type_names.push(type_name);
                }
                stack.push(JavaBrace {
                    kind,
                    start_line,
                    start_column,
                    body_start: offset.saturating_add(1),
                    type_depth,
                });
                header_boundary = offset.saturating_add(1);
            }
            b'}' => {
                let Some(brace): Option<JavaBrace> = stack.pop() else {
                    header_boundary = offset.saturating_add(1);
                    continue;
                };
                if brace.kind == JavaBraceKind::Type {
                    type_names.pop();
                }
                let close_line: usize =
                    line_starts.partition_point(|start: &usize| *start <= offset);
                let end_column: usize = offset
                    .saturating_sub(*line_starts.get(close_line.saturating_sub(1)).unwrap_or(&0))
                    .saturating_add(2);
                out.push(JavaRegion {
                    kind: brace.kind,
                    start_line: brace.start_line,
                    end_line: close_line + 1,
                    start_column: brace.start_column,
                    end_column,
                    body_start: Some(brace.body_start),
                    body_end: Some(offset),
                    type_depth: brace.type_depth,
                });
                header_boundary = offset.saturating_add(1);
            }
            b';' if stack
                .last()
                .is_some_and(|brace: &JavaBrace| brace.kind == JavaBraceKind::Type) =>
            {
                let relative_header_start: usize = bytes[header_boundary..offset]
                    .iter()
                    .position(|candidate: &u8| !candidate.is_ascii_whitespace())
                    .map_or(0, |relative: usize| relative);
                let header_start: usize = header_boundary + relative_header_start;
                let header: &str = structural[header_start..offset].trim();
                let parent_type_name: Option<&str> =
                    type_names.iter().rev().find_map(Option::as_deref);
                if java_method_header(header, parent_type_name) {
                    let start_line: usize =
                        line_starts.partition_point(|start: &usize| *start <= header_start);
                    let end_line: usize =
                        line_starts.partition_point(|start: &usize| *start <= offset) + 1;
                    let start_column: usize = header_start
                        .saturating_sub(
                            *line_starts.get(start_line.saturating_sub(1)).unwrap_or(&0),
                        )
                        .saturating_add(1);
                    let end_column: usize = offset
                        .saturating_sub(*line_starts.get(end_line.saturating_sub(2)).unwrap_or(&0))
                        .saturating_add(2);
                    let type_depth: usize = type_names.len();
                    out.push(JavaRegion {
                        kind: JavaBraceKind::Method,
                        start_line,
                        end_line,
                        start_column,
                        end_column,
                        body_start: None,
                        body_end: None,
                        type_depth,
                    });
                }
                header_boundary = offset.saturating_add(1);
            }
            b';' => header_boundary = offset.saturating_add(1),
            _ => {}
        }
    }
    let end_line: usize = structural.lines().count().saturating_add(1);
    let end_column: usize = structural.rsplit_once('\n').map_or_else(
        || structural.len().saturating_add(1),
        |(_prefix, tail): (&str, &str)| tail.len().saturating_add(1),
    );
    out.extend(
        stack
            .into_iter()
            .filter(|brace: &JavaBrace| brace.kind == JavaBraceKind::Method)
            .map(|brace: JavaBrace| JavaRegion {
                kind: JavaBraceKind::Method,
                start_line: brace.start_line,
                end_line,
                start_column: brace.start_column,
                end_column,
                body_start: Some(brace.body_start),
                body_end: Some(structural.len()),
                type_depth: brace.type_depth,
            }),
    );
    out.sort_unstable_by_key(|region: &JavaRegion| (region.start_line, region.end_line));
    out
}

fn field_initializer_ranges(src: &str) -> Vec<(usize, usize)> {
    let structural: String = java_structure_source(src);
    let method_ranges: Vec<(usize, usize)> = merge_line_ranges(class_method_ranges(src));
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    let mut delimiter_depth: usize = 0;
    let mut brace_depth: usize = 0;
    for (index, line) in structural.lines().enumerate() {
        let line_number: usize = index + 1;
        let inside_method: bool = line_in_ranges(&method_ranges, line_number);
        if inside_method && start.is_none() {
            start = None;
            delimiter_depth = 0;
            continue;
        }
        let assignment: Option<usize> = top_level_assignment_column(line, &mut delimiter_depth);
        if start.is_none() && assignment.is_some() {
            start = Some(line_number);
        }
        if let Some(field_start) = start {
            let scan_start: usize = assignment.map_or(0, |column: usize| column + 1);
            for byte in line.as_bytes().iter().skip(scan_start) {
                match *byte {
                    b'{' => brace_depth = brace_depth.saturating_add(1),
                    b'}' => brace_depth = brace_depth.saturating_sub(1),
                    b';' if brace_depth == 0 => {
                        ranges.push((field_start, line_number + 1));
                        start = None;
                        break;
                    }
                    _ => {}
                }
            }
            if start.is_none() {
                brace_depth = 0;
                delimiter_depth = 0;
            }
        }
    }
    ranges
}

fn merge_line_ranges(ranges: impl IntoIterator<Item = (usize, usize)>) -> Vec<(usize, usize)> {
    let mut ordered: Vec<(usize, usize)> = ranges.into_iter().collect();
    ordered.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ordered.len());
    for (start, end) in ordered {
        let Some((_previous_start, previous_end)): Option<&mut (usize, usize)> = merged.last_mut()
        else {
            merged.push((start, end));
            continue;
        };
        if start <= *previous_end {
            *previous_end = (*previous_end).max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn line_in_ranges(ranges: &[(usize, usize)], line: usize) -> bool {
    let insertion: usize = ranges.partition_point(|(start, _end): &(usize, usize)| *start <= line);
    insertion
        .checked_sub(1)
        .and_then(|index: usize| ranges.get(index))
        .is_some_and(|(_start, end): &(usize, usize)| line < *end)
}

fn top_level_assignment_column(line: &str, delimiter_depth: &mut usize) -> Option<usize> {
    let bytes: &[u8] = line.as_bytes();
    let mut assignment: Option<usize> = None;
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'(' | b'[' => *delimiter_depth = delimiter_depth.saturating_add(1),
            b')' | b']' => *delimiter_depth = delimiter_depth.saturating_sub(1),
            b'=' if *delimiter_depth == 0
                && !matches!(
                    index
                        .checked_sub(1)
                        .and_then(|previous: usize| bytes.get(previous))
                        .copied(),
                    Some(b'=' | b'!' | b'<' | b'>')
                )
                && !matches!(bytes.get(index + 1).copied(), Some(b'=' | b'>')) =>
            {
                assignment.get_or_insert(index);
            }
            _ => {}
        }
    }
    assignment
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaBraceKind {
    Type,
    Method,
    Other,
}

#[derive(Debug, Clone)]
struct JavaBrace {
    kind: JavaBraceKind,
    start_line: usize,
    start_column: usize,
    body_start: usize,
    type_depth: usize,
}

#[derive(Debug, Clone, Copy)]
struct JavaRegion {
    kind: JavaBraceKind,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    body_start: Option<usize>,
    body_end: Option<usize>,
    type_depth: usize,
}

fn java_type_header(header: &str) -> bool {
    ["@interface", "class", "interface", "enum", "record"]
        .iter()
        .flat_map(|keyword: &&str| {
            header
                .match_indices(*keyword)
                .map(move |(index, _match): (usize, &str)| (index, *keyword))
        })
        .filter(|(index, keyword): &(usize, &str)| {
            let before_valid: bool =
                header[..*index]
                    .chars()
                    .next_back()
                    .is_none_or(|character: char| {
                        !character.is_ascii_alphanumeric()
                            && character != '_'
                            && character != '$'
                            && (*keyword == "@interface" || character != '@')
                    });
            let after: usize = index.saturating_add(keyword.len());
            let after_valid: bool = header[after..]
                .chars()
                .next()
                .is_none_or(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_' && character != '$'
                });
            before_valid && after_valid
        })
        .any(|(index, _keyword): (usize, &str)| java_type_prefix_supported(&header[..index]))
}

fn java_type_prefix_supported(mut prefix: &str) -> bool {
    loop {
        prefix = prefix.trim_start();
        if prefix.is_empty() {
            return true;
        }
        if let Some(annotation) = prefix.strip_prefix('@') {
            let name_end: usize = annotation
                .find(|character: char| {
                    !character.is_ascii_alphanumeric()
                        && character != '_'
                        && character != '$'
                        && character != '.'
                })
                .unwrap_or(annotation.len());
            if name_end == 0 {
                return false;
            }
            prefix = annotation[name_end..].trim_start();
            if let Some(arguments) = prefix.strip_prefix('(') {
                let mut depth: usize = 1;
                let mut end: Option<usize> = None;
                for (index, character) in arguments.char_indices() {
                    match character {
                        '(' => depth = depth.saturating_add(1),
                        ')' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                end = Some(index + character.len_utf8());
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let Some(end) = end else {
                    return false;
                };
                prefix = &arguments[end..];
            }
            continue;
        }
        let token_end: usize = prefix.find(char::is_whitespace).unwrap_or(prefix.len());
        let token: &str = &prefix[..token_end];
        if !matches!(
            token,
            "public"
                | "protected"
                | "private"
                | "static"
                | "abstract"
                | "final"
                | "strictfp"
                | "sealed"
                | "non-sealed"
        ) {
            return false;
        }
        prefix = &prefix[token_end..];
    }
}

fn java_method_header(header: &str, parent_type_name: Option<&str>) -> bool {
    let declaration: String = java_declaration_without_annotations(header);
    let declaration: &str = declaration.as_str();
    let Some(open): Option<usize> = declaration.find('(') else {
        return false;
    };
    if !declaration[open..].contains(')')
        || declaration.contains("->")
        || declaration[..open].contains('=')
    {
        return false;
    }
    let before: &str = declaration[..open].trim_end();
    let name_start: usize = before
        .char_indices()
        .rev()
        .find(|(_index, character): &(usize, char)| {
            !character.is_ascii_alphanumeric() && *character != '_' && *character != '$'
        })
        .map_or(0, |(index, character): (usize, char)| {
            index + character.len_utf8()
        });
    let Some(name): Option<&str> = before
        .get(name_start..)
        .filter(|name: &&str| !name.is_empty())
    else {
        return false;
    };
    let leading: &str = declaration.trim_start();
    if ["return", "throw", "new", "assert", "case", "yield"]
        .iter()
        .any(|keyword: &&str| {
            leading == *keyword
                || leading
                    .strip_prefix(*keyword)
                    .is_some_and(|rest: &str| rest.starts_with(char::is_whitespace))
        })
    {
        return false;
    }
    let separated_as_declaration: bool = name_start > 0
        && before[..name_start]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace);
    if !separated_as_declaration && parent_type_name != Some(name) {
        return false;
    }
    !matches!(
        name,
        "if" | "for"
            | "while"
            | "switch"
            | "catch"
            | "synchronized"
            | "try"
            | "do"
            | "this"
            | "super"
    )
}

fn java_declaration_without_annotations(header: &str) -> String {
    let mut declaration: String = String::with_capacity(header.len());
    let mut remaining: &str = header;
    while let Some(at) = remaining.find('@') {
        declaration.push_str(&remaining[..at]);
        let annotation: &str = &remaining[at + 1..];
        let name_end: usize = annotation
            .find(|character: char| {
                !character.is_ascii_alphanumeric()
                    && character != '_'
                    && character != '$'
                    && character != '.'
            })
            .unwrap_or(annotation.len());
        if name_end == 0 {
            declaration.push('@');
            remaining = annotation;
            continue;
        }
        let after_name: &str = &annotation[name_end..];
        let whitespace: usize = after_name
            .len()
            .saturating_sub(after_name.trim_start().len());
        let mut consumed: usize = name_end.saturating_add(whitespace);
        let after_whitespace: &str = &annotation[consumed..];
        if let Some(arguments) = after_whitespace.strip_prefix('(') {
            let mut depth: usize = 1;
            let mut end: Option<usize> = None;
            for (index, character) in arguments.char_indices() {
                match character {
                    '(' => depth = depth.saturating_add(1),
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            end = Some(index + character.len_utf8());
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                declaration.push_str(&remaining[at..]);
                return declaration;
            };
            consumed = consumed.saturating_add(1).saturating_add(end);
        }
        declaration.push(' ');
        remaining = &annotation[consumed..];
    }
    declaration.push_str(remaining);
    declaration
}

fn java_declaration_after_annotations(mut header: &str) -> &str {
    loop {
        header = header.trim_start();
        let Some(after_at): Option<&str> = header.strip_prefix('@') else {
            return header;
        };
        let name_end: usize = after_at
            .find(|character: char| {
                !character.is_ascii_alphanumeric()
                    && character != '_'
                    && character != '$'
                    && character != '.'
            })
            .unwrap_or(after_at.len());
        let mut remainder: &str = after_at[name_end..].trim_start();
        if let Some(arguments) = remainder.strip_prefix('(') {
            let mut depth: usize = 1;
            let mut end: Option<usize> = None;
            for (index, character) in arguments.char_indices() {
                match character {
                    '(' => depth = depth.saturating_add(1),
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            end = Some(index + character.len_utf8());
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                return header;
            };
            remainder = &arguments[end..];
        }
        header = remainder;
    }
}

fn java_compact_constructor_header(header: &str, type_name: &str) -> bool {
    if header.contains(['(', ')', '=', ';']) || header.contains("->") {
        return false;
    }
    header
        .split(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '$'
        })
        .rfind(|token: &&str| !token.is_empty())
        == Some(type_name)
}

fn java_structure_source(source: &str) -> String {
    let mut bytes: Vec<u8> = source.as_bytes().to_vec();
    let mut index: usize = 0;
    let mut state: JavaLexState = JavaLexState::Code;
    while index < bytes.len() {
        let current: u8 = bytes[index];
        let next: Option<u8> = bytes.get(index + 1).copied();
        match state {
            JavaLexState::Code if current == b'/' && next == Some(b'/') => {
                bytes[index] = b' ';
                bytes[index + 1] = b' ';
                index += 2;
                state = JavaLexState::LineComment;
            }
            JavaLexState::Code if current == b'/' && next == Some(b'*') => {
                bytes[index] = b' ';
                bytes[index + 1] = b' ';
                index += 2;
                state = JavaLexState::BlockComment;
            }
            JavaLexState::Code
                if current == b'"' && next == Some(b'"') && bytes.get(index + 2) == Some(&b'"') =>
            {
                bytes[index..index + 3].fill(b' ');
                index += 3;
                state = JavaLexState::TextBlock;
            }
            JavaLexState::Code if current == b'"' => {
                bytes[index] = b' ';
                index += 1;
                state = JavaLexState::String;
            }
            JavaLexState::Code if current == b'\'' => {
                bytes[index] = b' ';
                index += 1;
                state = JavaLexState::Character;
            }
            JavaLexState::Code => index += 1,
            JavaLexState::LineComment if current == b'\n' => {
                index += 1;
                state = JavaLexState::Code;
            }
            JavaLexState::LineComment => {
                bytes[index] = b' ';
                index += 1;
            }
            JavaLexState::BlockComment if current == b'*' && next == Some(b'/') => {
                bytes[index] = b' ';
                bytes[index + 1] = b' ';
                index += 2;
                state = JavaLexState::Code;
            }
            JavaLexState::String | JavaLexState::Character | JavaLexState::TextBlock
                if current == b'\\' =>
            {
                bytes[index] = b' ';
                if index + 1 < bytes.len() {
                    if bytes[index + 1] != b'\n' {
                        bytes[index + 1] = b' ';
                    }
                    index += 2;
                } else {
                    index += 1;
                }
            }
            JavaLexState::String if current == b'"' => {
                bytes[index] = b' ';
                index += 1;
                state = JavaLexState::Code;
            }
            JavaLexState::Character if current == b'\'' => {
                bytes[index] = b' ';
                index += 1;
                state = JavaLexState::Code;
            }
            JavaLexState::TextBlock
                if current == b'"' && next == Some(b'"') && bytes.get(index + 2) == Some(&b'"') =>
            {
                bytes[index..index + 3].fill(b' ');
                index += 3;
                state = JavaLexState::Code;
            }
            JavaLexState::BlockComment
            | JavaLexState::String
            | JavaLexState::Character
            | JavaLexState::TextBlock => {
                if current != b'\n' {
                    bytes[index] = b' ';
                }
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaLexState {
    Code,
    LineComment,
    BlockComment,
    String,
    Character,
    TextBlock,
}

fn skipped(reason: &str) -> Value {
    json!({
        "title": "APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean emitted methods under real javac)",
        "status": "skipped",
        "reason": reason,
        "ecosystem": "android",
        "reproduce": "cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr",
        "tools": [],
    })
}

fn skipped_tool(name: &str, reason: &str) -> Value {
    json!({
        "name": name,
        "version": "n/a",
        "metric": "recompile-clean emitted methods (clean / emitted)",
        "display": "skipped",
        "status": "skipped",
        "detail": reason,
    })
}

#[derive(Debug)]
enum CfrInvoke {
    Binary(PathBuf),
    Jar { java: PathBuf, jar: PathBuf },
}

impl CfrInvoke {
    fn run(&self, jar_path: &Path, out_dir: &Path) -> Result<BTreeMap<String, String>, String> {
        let out_str: String = out_dir.to_string_lossy().into_owned();
        let jar_str: String = jar_path.to_string_lossy().into_owned();
        let output: disrobe_core::subprocess::CapturedOutput = match self {
            Self::Binary(bin) => run(bin, &[&jar_str, "--outputdir", &out_str])?,
            Self::Jar { java, jar } => {
                let jar_arg: String = jar.to_string_lossy().into_owned();
                run(java, &["-jar", &jar_arg, &jar_str, "--outputdir", &out_str])?
            }
        };
        let _: disrobe_core::subprocess::CapturedOutput = require_success(output, "cfr")?;
        collect_edgecases_java(out_dir)
    }
}

fn collect_edgecases_java(out_dir: &Path) -> Result<BTreeMap<String, String>, String> {
    collect_edgecases_java_with_limits(out_dir, MAX_TREE_FILES, MAX_TREE_TEXT_BYTES)
}

const MAX_CFR_TREE_ENTRIES: usize = 100_000;
const MAX_CFR_TREE_DEPTH: usize = 64;

fn collect_edgecases_java_with_limits(
    out_dir: &Path,
    max_files: usize,
    max_bytes: usize,
) -> Result<BTreeMap<String, String>, String> {
    let max_bytes_u64: u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut file_count: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut main_count: usize = 0;
    let mut entry_count: usize = 0;
    for entry in walkdir::WalkDir::new(out_dir).sort_by_file_name() {
        let entry: walkdir::DirEntry = entry
            .map_err(|error: walkdir::Error| format!("could not inspect cfr output: {error}"))?;
        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_CFR_TREE_ENTRIES {
            return Err(format!(
                "cfr output tree exceeds {MAX_CFR_TREE_ENTRIES} entries"
            ));
        }
        if entry.depth() > MAX_CFR_TREE_DEPTH {
            return Err(format!(
                "cfr output tree exceeds depth {MAX_CFR_TREE_DEPTH}"
            ));
        }
        let path: &Path = entry.path();
        let metadata: Metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("could not inspect cfr output entry: {error}"))?;
        if metadata_is_reparse_or_symlink(&metadata) {
            return Err(format!(
                "cfr output contains a reparse point: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            if entry.depth() == MAX_CFR_TREE_DEPTH {
                return Err(format!(
                    "cfr output tree reaches maximum depth {MAX_CFR_TREE_DEPTH}"
                ));
            }
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "cfr output contains a special file: {}",
                path.display()
            ));
        }
        if file_count >= max_files {
            return Err(format!("cfr output file count exceeds {max_files}"));
        }
        file_count += 1;
        let size: u64 = metadata.len();
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| "cfr output byte count overflowed".to_owned())?;
        if total_bytes > max_bytes_u64 {
            return Err(format!("cfr output exceeds {max_bytes} bytes"));
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("java") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("EdgeCases.java") {
            main_count = main_count.saturating_add(1);
            if main_count > 1 {
                return Err("cfr output contains multiple EdgeCases.java files".to_owned());
            }
        }
        let relative: &Path = path
            .strip_prefix(out_dir)
            .map_err(|error| format!("cfr output path escaped its destination: {error}"))?;
        let source_name: String = relative.to_string_lossy().replace('\\', "/");
        let mut file: File = open_cfr_source(out_dir, path)?;
        let mut bytes: Vec<u8> = Vec::new();
        file.by_ref()
            .take(MAX_TEXT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read cfr source: {error}"))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TEXT_BYTES {
            return Err(format!("cfr source exceeds {MAX_TEXT_BYTES} bytes"));
        }
        let source: String = String::from_utf8(bytes)
            .map_err(|error| format!("cfr source is not valid UTF-8: {error}"))?;
        if sources.insert(source_name.clone(), source).is_some() {
            return Err(format!("cfr output repeats source path {source_name}"));
        }
    }
    if main_count == 0 {
        return Err("cfr produced no EdgeCases.java source".to_owned());
    }
    Ok(sources)
}

fn open_cfr_source(root: &Path, path: &Path) -> Result<File, String> {
    let canonical_root: PathBuf = std::fs::canonicalize(root)
        .map_err(|error| format!("could not resolve cfr output root: {error}"))?;
    if cfr_path_contains_reparse_component(root, path)? {
        return Err(format!(
            "cfr source contains a reparse point: {}",
            path.display()
        ));
    }
    let canonical_before: PathBuf = std::fs::canonicalize(path)
        .map_err(|error| format!("could not resolve cfr source: {error}"))?;
    if !canonical_before.starts_with(&canonical_root) {
        return Err(format!(
            "cfr source escaped its output root: {}",
            path.display()
        ));
    }
    let before: Metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect cfr source: {error}"))?;
    if metadata_is_reparse_or_symlink(&before) || !before.is_file() {
        return Err(format!(
            "cfr source is not a regular file: {}",
            path.display()
        ));
    }
    let file: File = open_cfr_source_file(path)
        .map_err(|error| format!("could not open cfr source: {error}"))?;
    let opened: Metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect opened cfr source: {error}"))?;
    let after: Metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect cfr source again: {error}"))?;
    let canonical_after: PathBuf = std::fs::canonicalize(path)
        .map_err(|error| format!("could not resolve reopened cfr source: {error}"))?;
    let reparse_after: bool = cfr_path_contains_reparse_component(root, path)?;
    if metadata_is_reparse_or_symlink(&opened)
        || !opened.is_file()
        || metadata_is_reparse_or_symlink(&after)
        || !after.is_file()
        || canonical_after != canonical_before
        || !canonical_after.starts_with(&canonical_root)
        || reparse_after
        || !same_cfr_opened_identity(path, &file)?
    {
        return Err(format!(
            "cfr source changed during safe open: {}",
            path.display()
        ));
    }
    Ok(file)
}

fn cfr_path_contains_reparse_component(root: &Path, path: &Path) -> Result<bool, String> {
    let relative: &Path = path
        .strip_prefix(root)
        .map_err(|error| format!("cfr source path escaped its destination: {error}"))?;
    let mut current: PathBuf = root.to_owned();
    let root_metadata: Metadata = std::fs::symlink_metadata(&current)
        .map_err(|error| format!("could not inspect cfr output root: {error}"))?;
    if metadata_is_reparse_or_symlink(&root_metadata) {
        return Ok(true);
    }
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata: Metadata = std::fs::symlink_metadata(&current)
            .map_err(|error| format!("could not inspect cfr output component: {error}"))?;
        if metadata_is_reparse_or_symlink(&metadata) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_cfr_source_file(path: &Path) -> std::io::Result<File> {
    let mut options: OpenOptions = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000);
    }
    #[cfg(all(unix, any(target_os = "android", target_os = "linux")))]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x20_000);
    }
    #[cfg(all(
        unix,
        any(
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        )
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x100);
    }
    options.open(path)
}

fn metadata_is_reparse_or_symlink(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn same_cfr_opened_identity(path: &Path, file: &File) -> Result<bool, String> {
    opened_file_matches_path(path, file)
        .map_err(|error| format!("could not validate cfr source identity: {error}"))
}

fn resolve_cfr(root: &Path) -> Option<CfrInvoke> {
    if crate::requirement_enabled("DISROBE_REQUIRE_CFR") {
        let jar: PathBuf = root
            .join("evidence")
            .join("competitors")
            .join("jars")
            .join("cfr.jar");
        let java: PathBuf = find_on_path("java")?;
        return jar.is_file().then_some(CfrInvoke::Jar { java, jar });
    }
    if let Some(bin) = find_on_path("cfr") {
        return Some(CfrInvoke::Binary(bin));
    }
    let jar: PathBuf = root
        .join("evidence")
        .join("competitors")
        .join("jars")
        .join("cfr.jar");
    if jar.is_file()
        && let Some(java) = find_on_path("java")
    {
        return Some(CfrInvoke::Jar { java, jar });
    }
    None
}

fn cfr_version(cfr: &CfrInvoke) -> String {
    match cfr {
        CfrInvoke::Binary(bin) => version_of(bin, &["--version"]),
        CfrInvoke::Jar { java, jar } => {
            let jar_arg: String = jar.to_string_lossy().into_owned();
            version_of(java, &["-jar", &jar_arg, "--version"])
        }
    }
}

fn cfr_version_checked(cfr: &CfrInvoke) -> std::result::Result<String, String> {
    match cfr {
        CfrInvoke::Binary(bin) => version_of_checked(bin, &["--version"]),
        CfrInvoke::Jar { java, jar } => {
            let jar_arg: String = jar.to_string_lossy().into_owned();
            version_of_checked(java, &["-jar", &jar_arg, "--version"])
        }
    }
}

pub fn require_pinned_versions(root: &Path) -> Result<(), String> {
    if crate::requirement_enabled("DISROBE_REQUIRE_JADX") {
        let jadx: PathBuf = find_on_path("jadx").ok_or_else(|| "jadx is not on PATH".to_owned())?;
        let version: String = version_of_checked(&jadx, &["--version"])?;
        require_pinned_version(root, "jadx", &version)?;
    }
    if crate::requirement_enabled("DISROBE_REQUIRE_CFR") {
        let cfr: CfrInvoke = resolve_cfr(root)
            .ok_or_else(|| "pinned CFR jar and java are unavailable".to_owned())?;
        let version: String = cfr_version_checked(&cfr)?;
        require_pinned_version(root, "cfr", &version)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ToolScore {
        fn measured(clean: usize, emitted: usize, original: usize, detail: String) -> Self {
            Self::Certified {
                clean,
                emitted,
                class_level_defects: 0,
                original,
                detail,
            }
        }
    }

    const SAMPLE: &str = "package p;\npublic class EdgeCases {\n  public int a() {\n    return 1;\n  }\n  static class Inner {\n    void hidden() {}\n  }\n  private void b(int x) {\n    System.out.println(x);\n  }\n}\nclass EdgeCases$1 {\n  void synthetic() {}\n}\n";
    const SAMPLE_MAIN_CLASS: &str = "public class EdgeCases {\n  public int a() {\n    return 1;\n  }\n  static class Inner {\n    void hidden() {}\n  }\n  private void b(int x) {\n    System.out.println(x);\n  }\n}\n";

    #[test]
    fn dataset_description_tracks_each_fixture_digest() {
        let first: String = dataset_description("dex-a", "jar-a");
        let changed_dex: String = dataset_description("dex-b", "jar-a");
        let changed_jar: String = dataset_description("dex-a", "jar-b");
        assert!(first.contains("SHA-256 dex-a"));
        assert!(first.contains("SHA-256 jar-a"));
        assert_ne!(first, changed_dex);
        assert_ne!(first, changed_jar);
    }

    #[test]
    fn main_class_method_ranges_counts_only_depth_one_members() {
        let ranges: Vec<(usize, usize)> = main_class_method_ranges(SAMPLE_MAIN_CLASS);
        assert_eq!(
            ranges.len(),
            2,
            "only EdgeCases.a and EdgeCases.b are depth-1 members; Inner.hidden sits one level \
             deeper and is not a main-class method"
        );
    }

    #[test]
    fn source_set_validation_rejects_every_ingress_limit_and_unsafe_path() {
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert("A.java".to_owned(), "1234".to_owned());
        sources.insert("nested/B.java".to_owned(), "5678".to_owned());
        assert!(validate_source_set_with_limits(&sources, 2, 4, 8).is_ok());
        assert!(validate_source_set_with_limits(&sources, 1, 4, 8).is_err());
        assert!(validate_source_set_with_limits(&sources, 2, 3, 8).is_err());
        assert!(validate_source_set_with_limits(&sources, 2, 4, 7).is_err());

        for unsafe_path in [
            "../A.java",
            "/A.java",
            "\\A.java",
            "C:/A.java",
            "C:\\A.java",
            "C:A.java",
            "A.java:stream",
            "nested/./A.java",
            "nested/../A.java",
        ] {
            let unsafe_sources: BTreeMap<String, String> =
                BTreeMap::from([(unsafe_path.to_owned(), String::new())]);
            assert!(validate_source_set_with_limits(&unsafe_sources, 1, 1, 1).is_err());
        }
    }

    #[test]
    fn javac_diagnostic_parser_refuses_work_past_its_limit() {
        let diagnostics: &str =
            "A.java:1:1: compiler.err.expected\nA.java:2:1: compiler.err.expected\n";
        assert!(failed_javac_diagnostics_with_limit(diagnostics, 2).is_ok());
        assert!(failed_javac_diagnostics_with_limit(diagnostics, 1).is_err());
    }

    #[test]
    fn merged_line_ranges_preserve_half_open_membership_boundaries() {
        let merged: Vec<(usize, usize)> =
            merge_line_ranges([(5, 8), (1, 3), (2, 6), (10, 11), (11, 13)]);
        assert_eq!(merged, vec![(1, 8), (10, 13)]);
        assert!(!line_in_ranges(&merged, 0));
        assert!(line_in_ranges(&merged, 1));
        assert!(line_in_ranges(&merged, 7));
        assert!(!line_in_ranges(&merged, 8));
        assert!(!line_in_ranges(&merged, 9));
        assert!(line_in_ranges(&merged, 10));
        assert!(line_in_ranges(&merged, 12));
        assert!(!line_in_ranges(&merged, 13));
    }

    #[test]
    fn method_region_scan_accepts_package_private_and_multiline_declarations() {
        let source: &str = "class EdgeCases {\n    int first() { return 1; }\n    public\n    int second()\n    {\n        return 2;\n    }\n}\n";
        assert_eq!(class_method_ranges(source).len(), 2);
    }

    #[test]
    fn method_region_scan_ignores_braces_inside_literals_and_comments() {
        let source: &str = "class EdgeCases {\n    int first() {\n        String brace = \"}\";\n        return 1;\n    }\n    int second() {\n        /* { } */\n        return 2;\n    }\n}\n";
        assert_eq!(class_method_ranges(source).len(), 2);
    }

    #[test]
    fn method_region_scan_ignores_braces_after_an_escaped_text_block_delimiter() {
        let source: &str = r#"class EdgeCases {
    int first() {
        String text = """
            \""" } {
            """;
        return 1;
    }
    int second() { return 2; }
}
"#;
        assert_eq!(class_method_ranges(source).len(), 2);
    }

    #[test]
    fn method_region_scan_includes_compact_record_constructors() {
        let source: &str = "record Point(int x) {\n    Point {\n        if (x < 0) throw new IllegalArgumentException();\n    }\n    int value() { return x; }\n}\n";
        assert_eq!(class_method_ranges(source).len(), 2);
    }

    #[test]
    fn the_main_class_is_selected_by_name_not_by_whichever_file_sorts_first() {
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert(
            "EdgeCases$_0.java".to_owned(),
            "public class EdgeCases$_0 {\n    public static int m() {\n        return 1;\n    }\n}\n"
                .to_owned(),
        );
        sources.insert(
            "EdgeCases.java".to_owned(),
            "public class EdgeCases {\n    public int real() {\n        return 2;\n    }\n}\n"
                .to_owned(),
        );
        let selected: &String = main_class_file(&sources)
            .unwrap_or_else(|| unreachable!("the sample carries an EdgeCases.java"));
        assert!(
            selected.contains("public int real()"),
            "the scored file has to be the main class. `EdgeCases$_0.java` sorts first and its text \
             contains `class EdgeCases` as a substring, so a substring search silently scores a \
             synthetic sibling and reports its method count as the main class: {selected}"
        );
        assert!(!selected.contains("EdgeCases$_0"));
    }

    #[test]
    fn a_source_set_without_the_main_class_is_a_miss() -> core::result::Result<(), String> {
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert(
            "Other.java".to_owned(),
            "public class Other {\n    public int a() {\n        return 1;\n    }\n}\n".to_owned(),
        );
        let scratch: ScratchDir = ScratchDir::create("disrobe_h2h_no_main")
            .map_err(|error: std::io::Error| error.to_string())?;
        let missing: PathBuf = scratch.path().join("javac-that-does-not-exist");
        let score: ToolScore = score_source_set(&missing, &sources, 2);
        assert_eq!(score.status(), "miss");
        assert!(
            score.detail().contains("EdgeCases.java"),
            "the miss has to name the file it could not find: {}",
            score.detail()
        );
        Ok(())
    }

    #[test]
    fn initial_javac_failure_is_uncertified_with_known_region_count() {
        let score: ToolScore = score_initial_javac_failure(7, 3, "initial timeout".to_owned());
        assert!(matches!(
            score,
            ToolScore::Uncertified {
                emitted: 3,
                cause: UncertifiedCause::Compiler {
                    first_defect_line: None,
                },
                original: 7,
                ..
            }
        ));
        assert!(score.to_json("t", "v").get("first_defect_line").is_none());
    }

    #[test]
    fn producer_exit_is_uncertified_without_a_fabricated_compiler_line() {
        let score: ToolScore = ToolScore::Uncertified {
            emitted: 295,
            cause: UncertifiedCause::ProducerExit,
            original: 114,
            detail: "jadx exited nonzero after emitting 295 methods".to_owned(),
        };
        let row: Value = score.to_json("jadx", "1.5.5");
        assert_eq!(row["uncertified_stage"], "producer");
        assert_eq!(row["producer_exit"], true);
        assert!(row.get("producer_exit_status").is_none());
        assert!(row.get("first_defect_line").is_none());
        assert_eq!(row["emitted"], 295);
        assert_eq!(
            score_phrase(&score),
            "295 emitted methods, none of them certified (jadx exited nonzero after emitting 295 methods)"
        );
        assert!(!score_phrase(&score).contains("status"));
    }

    #[test]
    fn initial_javac_failure_callsite_preserves_regions() {
        let sources: BTreeMap<String, String> = BTreeMap::from([(
            MAIN_CLASS_FILE.to_owned(),
            "class EdgeCases { int first() { return 1; } }\n".to_owned(),
        )]);
        let missing: PathBuf = PathBuf::from("javac-that-does-not-exist");
        let score: ToolScore = score_source_set(&missing, &sources, 1);
        assert!(matches!(
            score,
            ToolScore::Uncertified {
                emitted: 1,
                original: 1,
                ..
            }
        ));
    }

    #[test]
    fn tool_score_rate_is_clean_over_emitted() {
        let score: ToolScore = ToolScore::measured(3, 4, 4, "sample arithmetic".to_owned());
        assert!((score.rate() - 75.0).abs() < f64::EPSILON);
        let miss: ToolScore = ToolScore::miss(4, "sample miss".to_owned());
        assert!(miss.rate().abs() < f64::EPSILON);
    }

    #[test]
    fn apk_rows_carry_stable_leg_and_role_identities() {
        let rows: Vec<Value> = dex_leg(
            ToolScore::measured(129, 132, 106, "measured".to_owned()),
            scored("1.5.5", 128, 130),
        )
        .to_json_rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["leg"], "dex");
        assert_eq!(rows[0]["role"], "disrobe");
        assert_eq!(rows[1]["leg"], "dex");
        assert_eq!(rows[1]["role"], "competitor");
    }

    #[test]
    fn an_unavailable_javac_is_uncertified() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_h2h_missing_javac")
            .map_err(|error: std::io::Error| error.to_string())?;
        let missing: PathBuf = scratch.path().join("javac-that-does-not-exist");
        let score: ToolScore = score_source(&missing, SAMPLE, 2);
        assert_eq!(score.status(), "uncertified");
        assert_eq!(score.clean(), 0);
        assert!(
            score.detail().contains("could not start javac"),
            "a failed compiler spawn must not be counted as all-clean: {}",
            score.detail()
        );
        Ok(())
    }

    #[test]
    fn compiler_success_requires_an_emitted_main_class() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_h2h_compiler_output")
            .map_err(|error: std::io::Error| error.to_string())?;
        assert!(
            require_emitted_edgecases_class(scratch.path()).is_err(),
            "an empty compiler output directory cannot certify recovered source"
        );
        let package: PathBuf = scratch.path().join("p");
        std::fs::create_dir(&package).map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(package.join("EdgeCases.class"), b"class")
            .map_err(|error: std::io::Error| error.to_string())?;
        require_emitted_edgecases_class(scratch.path())?;
        Ok(())
    }

    #[test]
    fn failed_javac_requires_parseable_edgecases_lines() -> core::result::Result<(), String> {
        assert!(
            failed_javac_error_lines("error: compilation failed").is_err(),
            "a nonzero compiler result with no source diagnostic cannot score clean methods"
        );
        assert!(
            failed_javac_error_lines("EdgeCases.java:not-a-line: error").is_err(),
            "an unparseable source diagnostic cannot score clean methods"
        );
        let lines: Vec<usize> = failed_javac_error_lines(
            "/tmp/EdgeCases.java:3: error: incompatible types\nC:\\tmp\\EdgeCases.java:11: error: cannot find symbol",
        )?;
        assert_eq!(lines, vec![3, 11]);
        let diagnostics: Vec<SourceDiagnostic> = failed_javac_diagnostics(
            "C:\\tmp\\EdgeCases$Nested.java:7: error: illegal start of expression\n/tmp/EdgeCases.java:3: error: incompatible types",
        )?;
        assert_eq!(
            diagnostics,
            vec![
                SourceDiagnostic {
                    source: "/tmp/EdgeCases.java".to_owned(),
                    line: 3,
                    column: 0,
                    code: "error".to_owned(),
                },
                SourceDiagnostic {
                    source: "C:\\tmp\\EdgeCases$Nested.java".to_owned(),
                    line: 7,
                    column: 0,
                    code: "error".to_owned(),
                },
            ]
        );
        Ok(())
    }

    fn type_checked(error_lines: Vec<usize>) -> OracleVerdict {
        OracleVerdict {
            diagnostics: error_lines
                .into_iter()
                .map(|line: usize| SourceDiagnostic {
                    source: MAIN_CLASS_FILE.to_owned(),
                    line,
                    column: 0,
                    code: String::new(),
                })
                .collect(),
            type_checked: true,
        }
    }

    fn never_type_checked(error_lines: Vec<usize>) -> OracleVerdict {
        OracleVerdict {
            diagnostics: error_lines
                .into_iter()
                .map(|line: usize| SourceDiagnostic {
                    source: MAIN_CLASS_FILE.to_owned(),
                    line,
                    column: 0,
                    code: String::new(),
                })
                .collect(),
            type_checked: false,
        }
    }

    #[test]
    fn a_diagnostic_inside_a_method_costs_that_method_only() {
        let ranges: Vec<(usize, usize)> = vec![(3, 6), (10, 13)];
        let partial: ToolScore = score_method_ranges(2, &ranges, Ok(type_checked(vec![3])));
        assert_eq!(partial.status(), "ok");
        assert_eq!(partial.clean(), 1);
        assert!(
            matches!(
                partial,
                ToolScore::Certified {
                    emitted: 2,
                    class_level_defects: 0,
                    ..
                }
            ),
            "one bad method leaves the other scored: {partial:?}"
        );
    }

    #[test]
    fn required_competitor_rejects_skipped_or_missing_results() {
        let absent: CompetitorOutcome = CompetitorOutcome::Absent {
            reason: "not installed".to_owned(),
        };
        assert!(require_competitor_result("cfr", &absent).is_err());
        let missing: CompetitorOutcome = CompetitorOutcome::Scored {
            version: "0.152".to_owned(),
            score: ToolScore::Missing {
                original: 1,
                detail: "no EdgeCases source".to_owned(),
            },
        };
        assert!(require_competitor_result("cfr", &missing).is_err());
        let uncertified: CompetitorOutcome = CompetitorOutcome::Scored {
            version: "0.152".to_owned(),
            score: ToolScore::Uncertified {
                emitted: 1,
                cause: UncertifiedCause::Compiler {
                    first_defect_line: Some(1),
                },
                original: 1,
                detail: "compiler stopped before type checking".to_owned(),
            },
        };
        assert!(require_competitor_result("cfr", &uncertified).is_ok());
    }

    #[test]
    fn a_diagnostic_outside_every_method_costs_no_method_and_zeroes_no_tool() {
        let ranges: Vec<(usize, usize)> = vec![(3, 6), (10, 13)];
        let outside: ToolScore = score_method_ranges(2, &ranges, Ok(type_checked(vec![2])));
        assert_eq!(
            outside.status(),
            "ok",
            "a defect in the class structure of a file the compiler type-checked says nothing about \
             the methods it did check, so it cannot delete the whole measurement: {outside:?}"
        );
        assert_eq!(outside.clean(), 2);
        assert!(
            matches!(
                outside,
                ToolScore::Certified {
                    emitted: 2,
                    class_level_defects: 1,
                    ..
                }
            ),
            "the defect is still published, as a class-level count beside the methods: {outside:?}"
        );
        assert!(
            outside.detail().contains("outside any method"),
            "the row has to name the defect it did not charge to a method: {}",
            outside.detail()
        );
    }

    #[test]
    fn a_file_the_compiler_never_type_checked_certifies_nothing_and_zeroes_nothing() {
        let ranges: Vec<(usize, usize)> = vec![(3, 6), (10, 13)];
        let score: ToolScore = score_method_ranges(2, &ranges, Ok(never_type_checked(vec![2, 4])));
        assert_eq!(score.status(), "uncertified");
        assert!(
            matches!(
                score,
                ToolScore::Uncertified {
                    emitted: 2,
                    cause: UncertifiedCause::Compiler {
                        first_defect_line: Some(2),
                    },
                    ..
                }
            ),
            "the tool emitted two methods and that count is what gets published: {score:?}"
        );
        assert!(
            !score.to_json("t", "v").as_object().is_some_and(
                |row: &serde_json::Map<String, Value>| row.contains_key("clean")
                    || row.contains_key("value")
            ),
            "a file that was never type-checked must publish neither a clean count nor a rate, \
             because the compiler established neither"
        );
        assert_eq!(
            score.to_json("t", "v")["display"],
            Value::String("not certified: 2 methods emitted".to_owned()),
            "the row states what the tool produced, never that it produced nothing"
        );
    }

    #[test]
    fn the_uncertified_rule_reads_the_same_whichever_side_trips_it() {
        let ranges: Vec<(usize, usize)> = vec![(3, 6), (10, 13)];
        let ours: ToolScore = score_method_ranges(2, &ranges, Ok(never_type_checked(vec![2])));
        let theirs: ToolScore = score_method_ranges(2, &ranges, Ok(never_type_checked(vec![2])));
        assert_eq!(ours.status(), theirs.status());
        assert_eq!(score_phrase(&ours), score_phrase(&theirs));

        let sentence: String = dex_leg(
            ours,
            CompetitorOutcome::Scored {
                version: "1.5.5".to_owned(),
                score: ToolScore::measured(128, 130, 106, "measured".to_owned()),
            },
        )
        .sentence();
        assert!(
            sentence.contains("No lead is stated"),
            "a leg the compiler certified on one side only cannot carry a verdict: {sentence}"
        );
        assert!(
            !sentence.contains("leads by"),
            "a leg the compiler certified on one side only cannot claim a lead: {sentence}"
        );
        assert!(
            sentence.contains("2 emitted methods, none of them certified"),
            "the uncertified side still reports what it emitted: {sentence}"
        );
    }

    #[test]
    fn the_published_note_states_the_rule_it_scored_by() {
        assert!(
            SHARED_ORACLE.contains("compiles the complete recovered source set first"),
            "a reader cannot check a rule the published note does not state"
        );
        assert!(
            SHARED_ORACLE.contains("same rule binds `disrobe` and every competitor"),
            "the note has to say the rule binds both sides, not only the competitor"
        );
        assert!(
            SHARED_ORACLE.contains("64-round ceiling"),
            "the note has to disclose the bounded isolation ceiling"
        );
    }

    const JAVAC: crate::published::CompetitorTool = crate::published::CompetitorTool {
        program: "javac",
        require_var: "DISROBE_REQUIRE_JAVAC",
        install_hint: "install a JDK and put javac on PATH",
    };

    fn javac_or_announce(graded: &str) -> Option<PathBuf> {
        let found: Option<PathBuf> = find_on_path("javac");
        if found.is_none() {
            crate::published::enforce_requirement(
                &JAVAC,
                graded,
                "javac is not on PATH",
                crate::published::requirement_for(&JAVAC),
            );
        }
        found
    }

    fn insert_after_line(source: &str, line: usize, inserted: &str) -> String {
        let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
        lines.insert(line, inserted.to_owned());
        lines.join("\n")
    }

    #[test]
    fn one_seeded_defect_costs_one_recovered_method_of_the_real_jar()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the seeded-defect check over the recovered baseline jar")
        else {
            return Ok(());
        };
        let root: PathBuf = crate::published::checked_workspace_root();
        let jar: Vec<u8> = read_bounded_file(
            &root
                .join("corpus")
                .join("jvm")
                .join("megafile")
                .join("EdgeCases-baseline.jar"),
            MAX_FIXTURE_BYTES,
        )
        .map_err(|error: eyre::Report| error.to_string())?;
        let source: String = disrobe_jar_source(&jar)?;

        let ToolScore::Certified {
            clean: baseline_clean,
            emitted,
            ..
        } = score_source(&javac, &source, 106)
        else {
            return Err(
                "the recovered baseline jar has to compile for a seeded defect to mean anything"
                    .to_owned(),
            );
        };
        assert_eq!(
            baseline_clean, emitted,
            "the unmodified recovered class compiles clean, so every emitted method is certified"
        );

        let ranges: Vec<(usize, usize)> = main_class_method_ranges(&source);
        let Some((first_method_start, _end)): Option<&(usize, usize)> = ranges.first() else {
            return Err("the recovered class declares no method to seed".to_owned());
        };
        let seeded: String = insert_after_line(
            &source,
            *first_method_start,
            "        int seededTypeDefect = \"this is not an int\";",
        );
        let ToolScore::Certified {
            clean: seeded_clean,
            emitted: seeded_emitted,
            class_level_defects,
            ..
        } = score_source(&javac, &seeded, 106)
        else {
            return Err(
                "one bad statement inside a method body still parses, so the file stays \
                        certifiable"
                    .to_owned(),
            );
        };
        assert_eq!(
            seeded_emitted, emitted,
            "seeding a defect changes what compiles, never how many methods were recovered"
        );
        assert_eq!(class_level_defects, 0, "the defect sits inside a method");
        assert_eq!(
            seeded_clean,
            baseline_clean - 1,
            "one broken method costs exactly one clean method. A rule that zeroes the tool here \
             would report a decompiler that recovered {emitted} methods as recovering nothing"
        );
        Ok(())
    }

    #[test]
    fn a_seeded_defect_outside_every_method_costs_no_method_of_the_real_jar()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> = javac_or_announce(
            "the class-level seeded-defect check over the recovered baseline jar",
        ) else {
            return Ok(());
        };
        let root: PathBuf = crate::published::checked_workspace_root();
        let jar: Vec<u8> = read_bounded_file(
            &root
                .join("corpus")
                .join("jvm")
                .join("megafile")
                .join("EdgeCases-baseline.jar"),
            MAX_FIXTURE_BYTES,
        )
        .map_err(|error: eyre::Report| error.to_string())?;
        let source: String = disrobe_jar_source(&jar)?;
        let ToolScore::Certified {
            clean: baseline_clean,
            ..
        } = score_source(&javac, &source, 106)
        else {
            return Err("the recovered baseline jar has to compile first".to_owned());
        };

        let seeded: String = insert_after_line(
            &source,
            1,
            "    private NoSuchTypeAnywhere seededClassLevelDefect;",
        );
        let ToolScore::Certified {
            clean,
            class_level_defects,
            ..
        } = score_source(&javac, &seeded, 106)
        else {
            return Err(
                "an unresolvable field type parses, so the file is still type-checked".to_owned(),
            );
        };
        assert_eq!(
            class_level_defects, 1,
            "the defect belongs to the class structure and is published as such"
        );
        assert_eq!(
            clean, baseline_clean,
            "a defect outside every method costs no method and, above all, does not zero the tool"
        );
        Ok(())
    }

    #[test]
    fn the_type_check_probe_separates_a_parse_failure_from_a_resolution_failure()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the probe that decides whether javac reached type checking")
        else {
            return Ok(());
        };

        let unparseable: &str = "public class EdgeCases {\n    public int a() {\n        return 1;\n    }\n    enum \
             Broken extends Object {\n        private Broken() { }\n    }\n}\n";
        let resolvable_only: &str = "public class EdgeCases {\n    private MissingType field;\n    \
                                     public int a() {\n        return 1;\n    }\n}\n";

        let stopped: OracleVerdict = javac_verdict(&javac, unparseable)?;
        assert!(
            !stopped.type_checked,
            "javac cannot type-check a file it failed to parse, so the probe must say so"
        );
        let unresolved: OracleVerdict = javac_verdict(&javac, resolvable_only)?;
        assert!(
            unresolved.type_checked,
            "a file that parses and only fails to resolve a name was type-checked, so its methods \
             stay scorable"
        );
        assert!(
            !unresolved.diagnostics.is_empty(),
            "the unresolved field is still a diagnostic the scorer has to see"
        );

        let ranges: Vec<(usize, usize)> = main_class_method_ranges(unparseable);
        let refused: ToolScore = score_method_ranges(1, &ranges, Ok(stopped));
        assert_eq!(
            refused.status(),
            "uncertified",
            "real javac stopping at a parse defect must not be published as clean methods"
        );
        Ok(())
    }

    #[test]
    fn a_parse_defect_inside_one_method_costs_only_that_method() -> core::result::Result<(), String>
    {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the direct-method region scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    public int broken() {\n        return ( ;\n    }\n    public int last() {\n        return first();\n    }\n}\n";
        let ToolScore::Certified {
            clean,
            emitted,
            class_level_defects,
            ..
        } = score_source(&javac, source, 3)
        else {
            return Err(
                "a method-local parse defect must leave peer methods certifiable".to_owned(),
            );
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2);
        assert_eq!(class_level_defects, 0);
        Ok(())
    }

    #[test]
    fn a_nested_type_parse_defect_costs_its_method_without_erasing_main_methods()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the nested-type region scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    static class Nested {\n        public int broken() {\n            return ( ;\n        }\n    }\n    public int last() {\n        return first();\n    }\n}\n";
        assert_eq!(class_method_ranges(source), vec![(2, 5), (6, 9), (10, 13)]);
        let score: ToolScore = score_source(&javac, source, 3);
        let ToolScore::Certified {
            clean,
            emitted,
            class_level_defects,
            ..
        } = score
        else {
            return Err(format!(
                "a nested-type parse defect must leave main methods certifiable: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2);
        assert_eq!(class_level_defects, 0);
        Ok(())
    }

    #[test]
    fn a_nested_type_header_defect_costs_its_methods_without_erasing_main_methods()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the nested-type header region scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    enum Nested extends Object {\n        VALUE;\n        public int nested() {\n            return 2;\n        }\n    }\n    public int last() {\n        return first();\n    }\n}\n";
        let mut source_map: BTreeMap<String, String> = BTreeMap::new();
        source_map.insert(MAIN_CLASS_FILE.to_owned(), source.to_owned());
        assert_eq!(
            source_type_regions(&source_map)
                .into_iter()
                .map(|region: SourceTypeRegion| (region.start, region.end))
                .collect::<Vec<(usize, usize)>>(),
            vec![(1, 15), (5, 11)]
        );
        let isolated_source: String = neutralize_type_regions(source, &[(5, 11)]);
        let isolated_verdict: OracleVerdict = javac_verdict(&javac, &isolated_source)?;
        assert!(
            isolated_verdict.type_checked,
            "isolated nested type must parse: {isolated_verdict:?}\n{isolated_source}"
        );
        let score: ToolScore = score_source(&javac, source, 3);
        let ToolScore::Certified {
            clean,
            emitted,
            detail,
            ..
        } = score
        else {
            return Err(format!(
                "a nested-type header defect must leave main methods certifiable: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2, "{detail}");
        Ok(())
    }

    #[test]
    fn a_nested_type_header_defect_preserves_member_signatures_for_clean_callers()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the nested-type dependency scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    enum Nested extends Object {\n        VALUE;\n        public int nested() {\n            return 2;\n        }\n    }\n    public int last() {\n        return new Nested().nested();\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 3);
        let ToolScore::Certified {
            clean,
            emitted,
            detail,
            ..
        } = score
        else {
            return Err(format!(
                "a nested-type header defect must not erase callable member declarations: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2, "{detail}");
        Ok(())
    }

    #[test]
    fn a_nested_type_header_defect_preserves_field_signatures_for_clean_callers()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the nested-type field dependency scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    enum Nested extends Object {\n        VALUE;\n        static int recovered;\n        public int nested() {\n            return 2;\n        }\n    }\n    public int last() {\n        return Nested.recovered;\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 3);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "a nested-type header defect must not erase referenced fields: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2);
        Ok(())
    }

    #[test]
    fn a_multiline_nested_type_header_defect_isolated_by_its_complete_header()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the multiline nested-type header scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    enum\n        Nested\n        extends Object {\n        VALUE;\n        public int nested() {\n            return 2;\n        }\n    }\n    public int last() {\n        return new Nested().nested();\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 3);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "a multiline nested-type header defect must remain attributable: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2);
        Ok(())
    }

    #[test]
    fn a_multifile_parse_defect_costs_only_its_method() -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the multi-file region scoring regression")
        else {
            return Ok(());
        };
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert(
            MAIN_CLASS_FILE.to_owned(),
            "public class EdgeCases {\n    public int first() {\n        return 1;\n    }\n    public int last() {\n        return first();\n    }\n}\n"
                .to_owned(),
        );
        sources.insert(
            "EdgeCases$Nested.java".to_owned(),
            "class EdgeCases$Nested {\n    public int broken() {\n        return ( ;\n    }\n}\n"
                .to_owned(),
        );
        assert_eq!(source_method_regions(&sources).len(), 3);
        let score: ToolScore = score_source_set(&javac, &sources, 3);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "a sibling-source parse defect must leave peer methods certifiable: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2);
        Ok(())
    }

    #[test]
    fn duplicate_source_basenames_are_attributed_by_their_complete_relative_path()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the package-qualified diagnostic scoring regression")
        else {
            return Ok(());
        };
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert(
            MAIN_CLASS_FILE.to_owned(),
            "public class EdgeCases {\n    public int clean() { return 1; }\n}\n".to_owned(),
        );
        sources.insert(
            "Peer.java".to_owned(),
            "class Peer {\n\n    int clean() { return 1; }\n}\n".to_owned(),
        );
        sources.insert(
            "b/Peer.java".to_owned(),
            "package b;\nclass Peer {\n    int broken() { return ( ; }\n}\n".to_owned(),
        );
        let regions: Vec<SourceMethodRegion> = source_method_regions(&sources);
        let diagnostic: SourceDiagnostic = SourceDiagnostic {
            source: "C:/scratch/b/Peer.java".to_owned(),
            line: 3,
            column: 0,
            code: String::new(),
        };
        let Some(region_index): Option<usize> = diagnostic_region_index(&diagnostic, &regions)
        else {
            return Err("the package-qualified diagnostic matched no method".to_owned());
        };
        assert_eq!(regions[region_index].source, "b/Peer.java");
        let score: ToolScore = score_source_set(&javac, &sources, 3);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "package-qualified diagnostics must remain attributable: {score:?}"
            ));
        };
        assert_eq!(emitted, 3);
        assert_eq!(clean, 2);
        Ok(())
    }

    #[test]
    fn a_field_initializer_parse_defect_costs_no_method() -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the field-initializer region scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    private int broken = ( ;\n    public int first() {\n        return 1;\n    }\n    public int last() {\n        return first();\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 2);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "a field initializer parse defect must leave methods certifiable: {score:?}"
            ));
        };
        assert_eq!(emitted, 2);
        assert_eq!(clean, 2);
        Ok(())
    }

    #[test]
    fn a_field_initializer_parse_defect_isolates_contained_anonymous_methods()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the anonymous field-method isolation regression")
        else {
            return Ok(());
        };
        let source: &str = "class EdgeCases {\n    private Runnable broken = ((new Runnable() {\n        public void run() {}\n    });\n    public int peer() {\n        return 1;\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 2);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "an anonymous method inside an isolated field must remain accounted for: {score:?}"
            ));
        };
        assert_eq!((clean, emitted), (1, 2));
        Ok(())
    }

    #[test]
    fn an_annotated_field_initializer_isolated_at_its_declaration_assignment()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the annotated field-initializer scoring regression")
        else {
            return Ok(());
        };
        let source: &str = "public class EdgeCases {\n    @SuppressWarnings(value = \"unused\")\n    private int broken = ( ;\n    public int first() {\n        return 1;\n    }\n    public int last() {\n        return first();\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 2);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "an annotation argument must not be mistaken for a field initializer: {score:?}"
            ));
        };
        assert_eq!(emitted, 2);
        assert_eq!(clean, 2);
        Ok(())
    }

    #[test]
    fn braced_field_initializers_remain_one_complete_region() {
        let source: &str = "class EdgeCases {\n    int[] broken = new int[] {\n        ( ;\n    };\n    int clean() { return 1; }\n}\n";
        assert_eq!(field_initializer_ranges(source), vec![(2, 5)]);
    }

    #[test]
    fn annotations_with_arguments_do_not_hide_methods() {
        let source: &str = "class EdgeCases {\n    @SuppressWarnings(value = \"unused\")\n    int visible() { return 1; }\n    public @SuppressWarnings(value = \"unused\") int interspersed() { return 2; }\n}\n";
        assert_eq!(class_method_ranges(source), vec![(2, 4), (4, 5)]);
    }

    #[test]
    fn anonymous_and_enum_constant_bodies_contribute_methods() {
        let source: &str = "enum EdgeCases {\n    VALUE { int enumMethod() { return 1; } };\n    final Runnable task = new Runnable() { public void run() {} };\n    int direct() { return 2; }\n}\n";
        assert_eq!(class_method_ranges(source).len(), 3);
    }

    #[test]
    fn control_flow_calls_and_anonymous_construction_are_not_method_declarations() {
        let source: &str = "class EdgeCases {\n    static {\n        helper();\n        helper ();\n        for (Object value : values()) { helper(); }\n        if (helper()) { helper(); }\n        if (String.class == Object.class) { helper(); }\n        Runnable task = new Runnable() { public void run() { helper(); } };\n    }\n    static boolean helper() { return true; }\n    static Object[] values() { return new Object[0]; }\n}\n";
        assert_eq!(
            class_method_ranges(source),
            vec![(8, 9), (10, 11), (11, 12)]
        );
    }

    #[test]
    fn declaration_only_and_unclosed_methods_remain_in_the_denominator() {
        let declarations: &str =
            "interface EdgeCases {\n    int value();\n    default int body() { return 1; }\n}\n";
        assert_eq!(class_method_ranges(declarations).len(), 2);
        let unclosed: &str = "class EdgeCases {\n    int broken() { return 1;\n";
        assert_eq!(class_method_ranges(unclosed).len(), 1);
    }

    #[test]
    fn unnamed_malformed_nested_type_does_not_end_the_enclosing_type_scope() {
        let source: &str =
            "class EdgeCases {\n    class {\n    }\n    int after() { return 1; }\n}\n";
        assert_eq!(main_class_method_ranges(source), vec![(4, 5)]);
    }

    #[test]
    fn annotated_type_declarations_remain_structural_regions() {
        let source: &str = "class EdgeCases {\n    public @SuppressWarnings(value = \"x\") static class Nested {\n        int value() { return 1; }\n    }\n}\n";
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert(MAIN_CLASS_FILE.to_owned(), source.to_owned());
        assert_eq!(source_type_regions(&sources).len(), 2);
        assert_eq!(source_method_regions(&sources).len(), 1);
    }

    #[test]
    fn one_line_method_isolation_preserves_its_peer() -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> = javac_or_announce("one-line method isolation") else {
            return Ok(());
        };
        let source: &str =
            "class EdgeCases { int broken() { return ( ; } int healthy() { return 2; } }\n";
        let score: ToolScore = score_source(&javac, source, 2);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "one-line methods must remain independently scorable: {score:?}"
            ));
        };
        assert_eq!((clean, emitted), (1, 2));
        Ok(())
    }

    #[test]
    fn constant_field_isolation_preserves_switch_callers() -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> = javac_or_announce("constant field isolation") else {
            return Ok(());
        };
        let source: &str = "class EdgeCases {\n    static final int FLAG = ( ;\n    int caller(int value) {\n        return switch (value) { case FLAG -> 1; default -> 0; };\n    }\n}\n";
        let score: ToolScore = score_source(&javac, source, 1);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "constant field isolation must preserve callers: {score:?}"
            ));
        };
        assert_eq!((clean, emitted), (1, 1));
        Ok(())
    }

    #[test]
    fn generic_nested_fields_survive_type_shelling() -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> = javac_or_announce("generic field type shell") else {
            return Ok(());
        };
        let source: &str = "class EdgeCases {\n    enum Nested extends Object {\n        VALUE;\n        static java.util.Map<String, Integer> recovered;\n        int broken() { return 1; }\n    }\n    int caller() { return Nested.recovered.size(); }\n}\n";
        let score: ToolScore = score_source(&javac, source, 2);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "generic field signatures must survive type shelling: {score:?}"
            ));
        };
        assert_eq!((clean, emitted), (1, 2));
        Ok(())
    }

    #[test]
    fn compact_nested_type_shell_preserves_outer_source() {
        let source: &str = "class EdgeCases {\n    static class Nested { int broken() { return ; } }\n    int caller() { return 1; }\n}\n";
        let isolated: String = neutralize_type_regions(source, &[(2, 2)]);
        assert!(isolated.contains("static class Nested {}"), "{isolated}");
        assert!(isolated.contains("int caller()"), "{isolated}");
        assert!(!isolated.contains("return ;"), "{isolated}");
    }

    #[test]
    fn enum_constants_with_arguments_and_bodies_are_shellable() {
        let constants: Vec<&str> =
            top_level_enum_constants("A(1, 2) { void helper() { int x = 1, y = 2; } }, B;");
        assert_eq!(constants.len(), 2);
        assert_eq!(java_simple_enum_constant(constants[0]), Some("A"));
        assert_eq!(java_simple_enum_constant("B;"), Some("B"));
        let source: &str = "class EdgeCases {\n    enum Nested { A(1, 2) { void helper() { int x = 1, y = 2; } }, B; int broken() { return ; } }\n    int caller() { return 1; }\n}\n";
        let isolated: String = neutralize_type_regions(source, &[(2, 2)]);
        assert!(
            isolated.contains("static final Nested A = new Nested();"),
            "{isolated}"
        );
        assert!(
            isolated.contains("static final Nested B = new Nested();"),
            "{isolated}"
        );
    }

    #[test]
    fn multiline_field_declarations_remain_in_nested_type_shells() {
        let source: &str = "class EdgeCases {\n    enum Nested { VALUE;\n        static\n        java.util.Map<String, Integer> recovered;\n        int broken() { return ; }\n    }\n    int caller() { return Nested.recovered.size(); }\n}\n";
        let ranges: Vec<(usize, usize)> = multiline_field_ranges(source);
        assert!(ranges.contains(&(3, 5)), "{ranges:?}");
        let isolated: String = neutralize_type_regions(source, &[(2, 7)]);
        assert!(isolated.contains("recovered;"), "{isolated}");
    }

    #[test]
    fn enum_constants_and_inherited_contracts_survive_type_shelling()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> = javac_or_announce("enum contract type shell") else {
            return Ok(());
        };
        let source: &str = "class EdgeCases {\n    interface Marker {}\n    static class Base {}\n    enum Nested extends Base implements Marker {\n        VALUE;\n    }\n    Marker caller() { return Nested.VALUE; }\n}\n";
        let original_verdict: OracleVerdict = javac_verdict(&javac, source)?;
        assert!(
            original_verdict
                .diagnostics
                .iter()
                .any(source_diagnostic_is_parse_failure),
            "the invalid enum header must be classified as syntax: {original_verdict:?}"
        );
        let isolated: String = neutralize_type_regions(source, &[(4, 7)]);
        let isolated_verdict: OracleVerdict = javac_verdict(&javac, &isolated)?;
        assert!(
            isolated_verdict.type_checked,
            "enum shell must retain constants and contracts: {isolated_verdict:?}\n{isolated}"
        );
        assert!(
            isolated_verdict.diagnostics.is_empty(),
            "enum shell must compile without caller diagnostics: {isolated_verdict:?}\n{isolated}"
        );
        let mut source_map: BTreeMap<String, String> = BTreeMap::new();
        source_map.insert(MAIN_CLASS_FILE.to_owned(), source.to_owned());
        assert_eq!(
            source_method_regions(&source_map)
                .iter()
                .map(|region: &SourceMethodRegion| (region.start, region.end))
                .collect::<Vec<(usize, usize)>>(),
            vec![(7, 8)]
        );
        assert_eq!(
            source_type_regions(&source_map)
                .iter()
                .map(|region: &SourceTypeRegion| (region.start, region.end))
                .collect::<Vec<(usize, usize)>>(),
            vec![(1, 9), (2, 3), (3, 4), (4, 7)]
        );
        let score: ToolScore = score_source(&javac, source, 1);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "enum contracts must survive type shelling: {score:?}"
            ));
        };
        assert_eq!((clean, emitted), (1, 1));
        Ok(())
    }

    #[test]
    fn record_shells_without_component_contracts_fail_closed() {
        let Some(javac): Option<PathBuf> = javac_or_announce("record component type shell") else {
            return;
        };
        let source: &str = "class EdgeCases {\n    record Nested(int value) extends Object {}\n    int caller() { return new Nested(1).value(); }\n}\n";
        let score: ToolScore = score_source(&javac, source, 1);
        assert!(
            matches!(score, ToolScore::Uncertified { .. }),
            "a shell that cannot preserve record components must fail closed: {score:?}"
        );
    }

    #[test]
    fn attribution_probe_detection_uses_its_diagnostic_source() {
        let Some(javac): Option<PathBuf> = javac_or_announce("attribution probe source matching")
        else {
            return;
        };
        let source: &str = "@SuppressWarnings(value = \"TypeCheckReached.java:\"\nclass EdgeCases {\n    int first() { return 1; }\n    int last() { return 2; }\n}\n";
        let score: ToolScore = score_source(&javac, source, 2);
        assert!(
            !matches!(score, ToolScore::Certified { clean: 2, .. }),
            "a probe filename printed from malformed source cannot certify unparsed methods: {score:?}"
        );
    }

    #[test]
    fn attribution_probe_detection_rejects_filename_text_outside_a_diagnostic_header() {
        let spoofed: &str = "EdgeCases.java:2:3: compiler.err.expected\n    String value = \"TypeCheckReached.java:2:3: compiler.err.cant.resolve\";";
        assert!(!attribution_probe_reported(spoofed).unwrap_or_else(
            |_error: String| unreachable!("the EdgeCases diagnostic is parseable")
        ));
        let reported: &str =
            "C:\\work\\TypeCheckReached.java:2:3: compiler.err.cant.resolve.location";
        assert!(
            attribution_probe_reported(reported)
                .unwrap_or_else(|_error: String| unreachable!("the probe diagnostic is parseable"))
        );
    }

    #[test]
    fn attribution_probe_does_not_overwrite_recovered_source_with_same_name()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the attribution-probe collision regression")
        else {
            return Ok(());
        };
        let scratch: ScratchDir =
            ScratchDir::create("disrobe_h2h_probe_collision").map_err(|error| error.to_string())?;
        let source_path: PathBuf = scratch.path().join(ATTRIBUTION_PROBE_FILE);
        let source: &str = "class TypeCheckReached { int recovered() { return 1; } }";
        std::fs::write(&source_path, source).map_err(|error| error.to_string())?;
        let stub: PathBuf = scratch.path().join("cp");
        std::fs::create_dir(&stub).map_err(|error| error.to_string())?;
        let source_paths: Vec<&Path> = vec![source_path.as_path()];
        let _type_checked: bool =
            type_check_was_reached(&javac, scratch.path(), &stub, &source_paths, TOOL_TIMEOUT)?;
        let recovered: String =
            std::fs::read_to_string(&source_path).map_err(|error| error.to_string())?;
        assert_eq!(recovered, source);
        Ok(())
    }

    #[test]
    fn more_than_one_hundred_diagnostics_cannot_hide_unclean_methods()
    -> core::result::Result<(), String> {
        let Some(javac): Option<PathBuf> =
            javac_or_announce("the diagnostic-limit scoring regression")
        else {
            return Ok(());
        };
        let mut source: String = "public class EdgeCases {\n".to_owned();
        for index in 0..128_usize {
            writeln!(
                source,
                "    public MissingType{index} broken{index}() {{ return null; }}"
            )
            .unwrap_or_else(|_error: std::fmt::Error| unreachable!("String writes cannot fail"));
        }
        source.push_str("    public int clean() { return 1; }\n}\n");
        let score: ToolScore = score_source(&javac, &source, 129);
        let ToolScore::Certified { clean, emitted, .. } = score else {
            return Err(format!(
                "a parsed unit with 128 diagnostics must remain certifiable: {score:?}"
            ));
        };
        assert_eq!(emitted, 129);
        assert_eq!(clean, 1);
        Ok(())
    }

    #[test]
    fn isolation_retry_timeout_divides_remaining_budget() {
        assert_eq!(
            isolation_retry_timeout(Duration::from_mins(1)),
            Duration::from_secs(30)
        );
        assert_eq!(
            isolation_retry_timeout(Duration::from_millis(1)),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn isolation_retry_timeout_preserves_emitted_count_as_uncertified() {
        let verdict: OracleVerdict = OracleVerdict {
            diagnostics: vec![SourceDiagnostic {
                source: MAIN_CLASS_FILE.to_owned(),
                line: 7,
                column: 3,
                code: "compiler.err.expected".to_owned(),
            }],
            type_checked: false,
        };
        let score: ToolScore = score_isolation_retry_failure(
            3,
            17,
            &verdict,
            "javac exceeded the 1ms execution limit".to_owned(),
        );
        assert!(matches!(
            score,
            ToolScore::Uncertified {
                emitted: 17,
                cause: UncertifiedCause::Compiler {
                    first_defect_line: Some(7),
                },
                original: 3,
                ..
            }
        ));
    }

    #[test]
    fn isolation_retry_failure_at_callsite_preserves_emitted_count() {
        let mut sources: BTreeMap<String, String> = BTreeMap::new();
        sources.insert(
            MAIN_CLASS_FILE.to_owned(),
            "public class EdgeCases {\n    public int broken() {\n        return (;\n    }\n}\n"
                .to_owned(),
        );
        let regions: Vec<SourceMethodRegion> = source_method_regions(&sources);
        let verdict: OracleVerdict = OracleVerdict {
            diagnostics: vec![SourceDiagnostic {
                source: MAIN_CLASS_FILE.to_owned(),
                line: 3,
                column: 16,
                code: "compiler.err.expected".to_owned(),
            }],
            type_checked: false,
        };
        let score: ToolScore = score_parse_isolated_source_regions(
            Path::new("javac-isolation-retry-missing"),
            &sources,
            3,
            &regions,
            verdict,
        );
        assert!(matches!(
            score,
            ToolScore::Uncertified {
                emitted: 1,
                original: 3,
                ..
            }
        ));
    }

    fn dex_leg(disrobe: ToolScore, competitor: CompetitorOutcome) -> Leg {
        Leg {
            key: "dex",
            label: "DEX leg",
            disrobe_name: "disrobe (in-house Dalvik, DEX input)",
            disrobe,
            competitor_name: "jadx (DEX input)",
            competitor_short: "jadx",
            competitor,
        }
    }

    fn scored(version: &str, clean: usize, emitted: usize) -> CompetitorOutcome {
        CompetitorOutcome::Scored {
            version: version.to_owned(),
            score: ToolScore::measured(clean, emitted, 106, "measured".to_owned()),
        }
    }

    #[test]
    fn every_figure_in_the_summary_moves_with_the_measurement() {
        let first: String = dex_leg(
            ToolScore::measured(129, 132, 106, "measured".to_owned()),
            scored("1.5.5", 128, 130),
        )
        .sentence();
        assert_eq!(
            first,
            "DEX leg: `disrobe` recovers 129 clean of 132 emitted (97.7%); `jadx` (1.5.5) \
             recovers 128 clean of 130 emitted (98.5%). `disrobe` leads by 1 clean method; `jadx` \
             leads on clean rate, 98.5% to 97.7%."
        );

        let improved: String = dex_leg(
            ToolScore::measured(130, 132, 106, "measured".to_owned()),
            scored("1.5.5", 128, 130),
        )
        .sentence();
        assert_eq!(
            improved,
            "DEX leg: `disrobe` recovers 130 clean of 132 emitted (98.5%); `jadx` (1.5.5) \
             recovers 128 clean of 130 emitted (98.5%). `disrobe` leads by 2 clean methods; the \
             clean rates are level at 98.5%."
        );
        assert_ne!(
            first, improved,
            "a one-method change in what disrobe recovers has to change the published sentence. \
             A summary that reads the same after the measurement moved is a figure the reader \
             cannot tell apart from a literal"
        );
    }

    #[test]
    fn the_whole_summary_is_assembled_from_the_rows_beside_it() {
        let legs: [Leg; 2] = [
            dex_leg(
                ToolScore::measured(129, 132, 106, "measured".to_owned()),
                scored("1.5.5", 128, 130),
            ),
            Leg {
                key: "jar",
                label: "JAR leg",
                disrobe_name: "disrobe (in-house JVM, JAR input)",
                disrobe: ToolScore::measured(131, 131, 106, "measured".to_owned()),
                competitor_name: "cfr (JAR input)",
                competitor_short: "cfr",
                competitor: CompetitorOutcome::Scored {
                    version: "CFR 0.152".to_owned(),
                    score: ToolScore::measured(105, 106, 106, "measured".to_owned()),
                },
            },
        ];
        assert_eq!(
            measured_summary(&legs),
            format!(
                "DEX leg: `disrobe` recovers 129 clean of 132 emitted (97.7%); `jadx` (1.5.5) \
                 recovers 128 clean of 130 emitted (98.5%). `disrobe` leads by 1 clean method; \
                 `jadx` leads on clean rate, 98.5% to 97.7%. JAR leg: `disrobe` recovers 131 clean \
                 of 131 emitted (100.0%); `cfr` (CFR 0.152) recovers 105 clean of 106 emitted \
                 (99.1%). `disrobe` leads by 26 clean methods; `disrobe` leads on clean rate, \
                 100.0% to 99.1%. {SHARED_ORACLE}"
            )
        );
    }

    #[test]
    fn a_losing_leg_is_reported_as_a_loss() {
        let sentence: String = dex_leg(
            ToolScore::measured(100, 132, 106, "measured".to_owned()),
            scored("1.5.5", 128, 130),
        )
        .sentence();
        assert!(
            sentence.contains("`jadx` leads by 28 clean methods"),
            "the competitor leads this leg and the summary states so, got: {sentence}"
        );
    }

    #[test]
    fn an_absent_competitor_gets_no_figure_at_all() {
        let sentence: String = dex_leg(
            ToolScore::measured(129, 132, 106, "measured".to_owned()),
            CompetitorOutcome::Absent {
                reason: "jadx is not on PATH".to_owned(),
            },
        )
        .sentence();
        assert!(
            sentence.contains("NOT MEASURED against `jadx`"),
            "an unrun competitor must be marked, not narrated, got: {sentence}"
        );
        assert!(
            sentence.contains("no `jadx` figure is published for it"),
            "the sentence has to say the competitor side carries no number, got: {sentence}"
        );
        for printed in ["128", "130", "98.5", "leads"] {
            assert!(
                !sentence.contains(printed),
                "`{printed}` appears in a leg where jadx never ran. A competitor that was not \
                 measured cannot be given a number or a verdict, because a reader cannot tell one \
                 from a measurement, got: {sentence}"
            );
        }
    }

    #[test]
    fn a_side_that_produced_nothing_gets_no_lead_claim() {
        let sentence: String = dex_leg(
            ToolScore::miss(
                106,
                "disrobe in-house DEX decompile returned an error".to_owned(),
            ),
            scored("1.5.5", 128, 130),
        )
        .sentence();
        assert!(
            sentence.contains("No lead is stated"),
            "a leg with an empty side must not carry a comparison, got: {sentence}"
        );
        assert!(
            !sentence.contains("leads by"),
            "a leg with an empty side must not claim a lead, got: {sentence}"
        );
    }

    #[test]
    fn classes_from_jar_rejects_entry_count_cap() -> core::result::Result<(), String> {
        let jar: Vec<u8> = jar_with_entries(&[
            ("A.class", b"abcd".as_slice()),
            ("B.class", b"efgh".as_slice()),
        ])?;
        let classes: Option<Vec<(String, Vec<u8>)>> =
            classes_from_jar_with_limits(&jar, 1, 64, 128);
        assert!(classes.is_none(), "two entries must exceed a one-entry cap");
        Ok(())
    }

    #[test]
    fn cfr_collector_rejects_output_file_count_cap() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-h2h-cfr-output-cap")
            .map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(scratch.path().join("first.txt"), b"first")
            .map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(scratch.path().join("second.txt"), b"second")
            .map_err(|error: std::io::Error| error.to_string())?;
        let result: std::result::Result<BTreeMap<String, String>, String> =
            collect_edgecases_java_with_limits(scratch.path(), 1, 64);
        assert!(
            result.is_err(),
            "two CFR output files must exceed one-file cap"
        );
        Ok(())
    }

    #[test]
    fn cfr_collector_rejects_duplicate_main_sources() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-h2h-cfr-duplicate")
            .map_err(|error: std::io::Error| error.to_string())?;
        for directory in ["a", "b"] {
            let path: PathBuf = scratch.path().join(directory);
            std::fs::create_dir_all(&path).map_err(|error: std::io::Error| error.to_string())?;
            std::fs::write(path.join("EdgeCases.java"), SAMPLE_MAIN_CLASS)
                .map_err(|error: std::io::Error| error.to_string())?;
        }
        let result: std::result::Result<BTreeMap<String, String>, String> =
            collect_edgecases_java_with_limits(scratch.path(), 8, 4096);
        assert!(
            result.is_err(),
            "duplicate main sources must not be selected by traversal order"
        );
        Ok(())
    }

    #[test]
    fn cfr_collector_returns_the_complete_java_source_set() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-h2h-cfr-complete-set")
            .map_err(|error: std::io::Error| error.to_string())?;
        let package: PathBuf = scratch.path().join("sample");
        std::fs::create_dir_all(&package).map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(package.join("EdgeCases.java"), SAMPLE_MAIN_CLASS)
            .map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(package.join("Peer.java"), "package sample; class Peer {}\n")
            .map_err(|error: std::io::Error| error.to_string())?;

        let sources: BTreeMap<String, String> =
            collect_edgecases_java_with_limits(scratch.path(), 8, 4096)?;

        assert_eq!(
            sources.keys().cloned().collect::<Vec<String>>(),
            vec![
                "sample/EdgeCases.java".to_owned(),
                "sample/Peer.java".to_owned()
            ]
        );
        Ok(())
    }

    #[test]
    fn cfr_collector_rejects_aggregate_byte_cap() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-h2h-cfr-byte-cap")
            .map_err(|error: std::io::Error| error.to_string())?;
        std::fs::write(
            scratch.path().join("EdgeCases.java"),
            b"class EdgeCases { int value; }\n",
        )
        .map_err(|error: std::io::Error| error.to_string())?;
        let result: std::result::Result<BTreeMap<String, String>, String> =
            collect_edgecases_java_with_limits(scratch.path(), 8, 8);
        assert!(
            result.is_err(),
            "CFR output must enforce the aggregate byte cap"
        );
        Ok(())
    }

    #[test]
    fn classes_from_jar_rejects_entry_size_cap() -> core::result::Result<(), String> {
        let jar: Vec<u8> = jar_with_entries(&[("A.class", b"abcdef".as_slice())])?;
        let classes: Option<Vec<(String, Vec<u8>)>> = classes_from_jar_with_limits(&jar, 8, 5, 128);
        assert!(
            classes.is_none(),
            "six bytes must exceed a five-byte class cap"
        );
        Ok(())
    }

    fn jar_with_entries(entries: &[(&str, &[u8])]) -> core::result::Result<Vec<u8>, String> {
        use std::io::Write as _;

        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut zip: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, payload) in entries {
            zip.start_file(*name, options).map_err(|e| e.to_string())?;
            zip.write_all(payload).map_err(|e| e.to_string())?;
        }
        let cursor: std::io::Cursor<Vec<u8>> = zip.finish().map_err(|e| e.to_string())?;
        Ok(cursor.into_inner())
    }
}
