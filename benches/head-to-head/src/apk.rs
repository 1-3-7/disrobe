use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    AndroidDecompileOutput, BackendPreference, ClassFile, DecompiledClass, android_decompile_dex,
    decompile_class_with_inners, parse_classfile, run_jadx_on_bytes,
};
use eyre::{Result, WrapErr};
use serde_json::{Value, json};

use crate::apkleaks_capture::sha256_hex;
use crate::tool::{
    MAX_FIXTURE_BYTES, MAX_TEXT_BYTES, MAX_TREE_FILES, MAX_TREE_TEXT_BYTES, MAX_ZIP_ENTRIES,
    MAX_ZIP_ENTRY_BYTES, MAX_ZIP_TOTAL_BYTES, bounded_error_text, find_on_path, read_bounded_file,
    read_bounded_string, require_pinned_version, require_success, run, version_of,
    version_of_checked,
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
        "title": "APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean main-class methods under real javac)",
        "status": "ok",
        "ecosystem": "android",
        "dataset": dataset,
        "oracle": "real javac (JDK), per-method recompile error-free against a STUBBED (empty) classpath so a wrong recovered signature cannot resolve against the original classes. A method is certified clean only from a file javac type-checked end to end; javac reports no method-level result for a file it stopped parsing, so such a file certifies nothing rather than scoring zero",
        "metric": format!("clean / emitted main-EdgeCases methods, from files the compiler type-checked. The original main class declares {denominator} methods (counted at runtime); each decompiler also emits synthetic accessor/lambda/bridge methods, so the per-tool EMITTED count differs by design. The comparable number is the recompile-clean RATE (clean/emitted) plus the absolute clean-method count, both shown. A tool whose recovered file javac stopped parsing publishes its emitted-method count and no rate at all."),
        "reproduce": "cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr",
        "fairness": [
            "identical input bytes per leg: disrobe and jadx both decompile EdgeCases.dex; disrobe and cfr both decompile the EdgeCases-baseline.jar (cfr cannot read DEX)",
            "same oracle scores every tool: the same javac run and the same error-line map over each tool's recovered MAIN EdgeCases class",
            "same certification rule for every tool: clean methods are counted only from a file javac type-checked, and a file javac stopped parsing certifies no method for either side and faults none either",
            "every tool's whole emitted source set is compiled together, exactly as that tool wrote it, and only the main EdgeCases class's own methods are scored. Nothing is cut out of any tool's output before the compiler sees it, so a tool that emits its synthetic types beside the main class and a tool that nests them inside it are compiled on the same terms",
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
const METRIC: &str = "recompile-clean main-class methods (clean / emitted)";
const SHARED_ORACLE: &str = "All rows use the same stubbed real-`javac` oracle and are recompile-only. A method counts \
     clean only when javac type-checked the whole recovered file: a file the compiler stopped \
     parsing certifies nothing, for either side, and is reported with the method count its tool \
     did emit rather than as a zero. The same rule scores `disrobe` and every competitor, and a \
     leg states no lead unless the compiler certified both of its sides.";
const ATTRIBUTION_PROBE_FILE: &str = "TypeCheckReached.java";
const ATTRIBUTION_PROBE_SOURCE: &str = "final class TypeCheckReached {\n    static final Object \
                                        VALUE = typeCheckReachedSymbolThatCannotResolve;\n}\n";
const ATTRIBUTION_PROBE_DIAGNOSTIC: &str = "TypeCheckReached.java:";
const DIAGNOSTIC_LIMIT: &str = "1000000";

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
            first_defect_line,
            ..
        } => format!(
            "{emitted} emitted {}, none of them certified, because javac stopped at a defect on \
             line {first_defect_line} of the recovered file",
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
        first_defect_line: usize,
        original: usize,
        detail: String,
    },
    Missing {
        original: usize,
        detail: String,
    },
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
            Self::Uncertified {
                emitted,
                first_defect_line,
                ..
            } => {
                row["emitted"] = json!(emitted);
                row["first_defect_line"] = json!(first_defect_line);
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
    let out: AndroidDecompileOutput = match run_jadx_on_bytes(dex_bytes, "EdgeCases.dex") {
        Ok(out) => out,
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
    let result: Result<String, String> = cfr.run(jar_path, &out_dir);
    let score: ToolScore = match result {
        Ok(source) if !source.is_empty() => score_source(javac, &source, denominator),
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
    let ranges: Vec<(usize, usize)> = main_class_method_ranges(source);
    if ranges.is_empty() {
        return ToolScore::miss(
            original,
            "recovered source contains no main-EdgeCases methods".to_owned(),
        );
    }
    score_method_ranges(original, &ranges, javac_verdict(javac, source))
}

fn score_source_set(
    javac: &Path,
    sources: &BTreeMap<String, String>,
    original: usize,
) -> ToolScore {
    let Some(main): Option<&String> = main_class_file(sources) else {
        return ToolScore::miss(
            original,
            format!("no {MAIN_CLASS_FILE} among the recovered sources"),
        );
    };
    if main.trim().is_empty() {
        return ToolScore::miss(original, "empty recovered source".to_owned());
    }
    let ranges: Vec<(usize, usize)> = main_class_method_ranges(main);
    if ranges.is_empty() {
        return ToolScore::miss(
            original,
            "recovered source contains no main-EdgeCases methods".to_owned(),
        );
    }
    score_method_ranges(original, &ranges, javac_verdict_over_set(javac, sources))
}

#[derive(Debug)]
struct OracleVerdict {
    error_lines: Vec<usize>,
    type_checked: bool,
}

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
        let Some(first_defect_line): Option<usize> = verdict.error_lines.first().copied() else {
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
            first_defect_line,
            original,
            detail,
        };
    }
    let errors: Vec<usize> = verdict.error_lines;
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

const MAIN_CLASS_FILE: &str = "EdgeCases.java";

fn main_class_file(sources: &BTreeMap<String, String>) -> Option<&String> {
    sources
        .iter()
        .find(|(path, _): &(&String, &String)| {
            let normalized: String = path.replace('\\', "/");
            normalized == MAIN_CLASS_FILE || normalized.ends_with(&format!("/{MAIN_CLASS_FILE}"))
        })
        .map(|(_path, source): (&String, &String)| source)
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

fn javac_verdict(javac: &Path, source: &str) -> std::result::Result<OracleVerdict, String> {
    let mut single: BTreeMap<String, String> = BTreeMap::new();
    single.insert(MAIN_CLASS_FILE.to_owned(), source.to_owned());
    javac_verdict_over_set(javac, &single)
}

fn javac_verdict_over_set(
    javac: &Path,
    sources: &BTreeMap<String, String>,
) -> std::result::Result<OracleVerdict, String> {
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
        compile(javac, &stub, &dir.join("out"), &borrowed)?;
    if out.exit_code == Some(0) {
        require_emitted_edgecases_class(dir)?;
        return Ok(OracleVerdict {
            error_lines: Vec::new(),
            type_checked: true,
        });
    }
    let diagnostics: String = combined_output(&out);
    let error_lines: Vec<usize> =
        failed_javac_error_lines(&diagnostics).map_err(|error: String| {
            format!(
                "javac exited with {}: {error}",
                out.exit_code
                    .map_or_else(|| "no exit code".to_owned(), |code: i32| code.to_string())
            )
        })?;
    let type_checked: bool = type_check_was_reached(javac, dir, &stub, &borrowed)?;
    Ok(OracleVerdict {
        error_lines,
        type_checked,
    })
}

fn type_check_was_reached(
    javac: &Path,
    dir: &Path,
    stub: &Path,
    source_paths: &[&Path],
) -> std::result::Result<bool, String> {
    let probe_path: PathBuf = dir.join(ATTRIBUTION_PROBE_FILE);
    std::fs::write(&probe_path, ATTRIBUTION_PROBE_SOURCE).map_err(|error: std::io::Error| {
        format!("could not write the type-check probe: {error}")
    })?;
    let mut with_probe: Vec<&Path> = source_paths.to_vec();
    with_probe.push(&probe_path);
    let out: disrobe_core::subprocess::CapturedOutput =
        compile(javac, stub, &dir.join("probe-out"), &with_probe)?;
    if out.exit_code == Some(0) {
        return Err(
            "the type-check probe compiled without reporting its unresolvable symbol, so it can no \
             longer tell a parsed file from an unparsed one"
                .to_owned(),
        );
    }
    Ok(combined_output(&out).contains(ATTRIBUTION_PROBE_DIAGNOSTIC))
}

fn compile(
    javac: &Path,
    stub: &Path,
    out_dir: &Path,
    sources: &[&Path],
) -> std::result::Result<disrobe_core::subprocess::CapturedOutput, String> {
    std::fs::create_dir_all(out_dir).map_err(|error: std::io::Error| {
        format!("could not create the javac output directory: {error}")
    })?;
    let mut args: Vec<std::ffi::OsString> = vec![
        "-nowarn".into(),
        "-proc:none".into(),
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
    run(javac, &args).map_err(|error: String| format!("could not start javac: {error}"))
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

fn failed_javac_error_lines(diagnostics: &str) -> std::result::Result<Vec<usize>, String> {
    let mut error_lines: Vec<usize> = Vec::new();
    for line in diagnostics.lines() {
        let Some((_before, rest)): Option<(&str, &str)> = line.rsplit_once("EdgeCases.java:")
        else {
            continue;
        };
        let Some((number, _after)): Option<(&str, &str)> = rest.split_once(':') else {
            return Err("unparseable EdgeCases.java diagnostic".to_owned());
        };
        let parsed: usize =
            number
                .trim()
                .parse::<usize>()
                .map_err(|error: std::num::ParseIntError| {
                    format!("unparseable EdgeCases.java diagnostic line: {error}")
                })?;
        error_lines.push(parsed);
    }
    error_lines.sort_unstable();
    error_lines.dedup();
    if error_lines.is_empty() {
        return Err("javac emitted no parseable EdgeCases.java diagnostic".to_owned());
    }
    Ok(error_lines)
}

fn main_class_method_ranges(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 0;
    let mut depth: i32 = 0;
    while i < lines.len() {
        let trimmed: &str = lines[i].trim();
        let is_type_decl: bool = ["class ", "interface ", "enum ", "record ", "@interface "]
            .iter()
            .any(|kw: &&str| trimmed.contains(kw));
        let is_member: bool = depth == 1
            && trimmed.contains('(')
            && (trimmed.contains(" static ")
                || trimmed.starts_with("public ")
                || trimmed.starts_with("private ")
                || trimmed.starts_with("protected ")
                || trimmed.starts_with("static"))
            && trimmed.contains('{')
            && !trimmed.starts_with("//")
            && !is_type_decl;
        if is_member {
            let start: usize = i + 1;
            let mut d: i32 =
                trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
            let mut j: usize = i + 1;
            while j < lines.len() && d > 0 {
                d += lines[j].matches('{').count() as i32;
                d -= lines[j].matches('}').count() as i32;
                j += 1;
            }
            out.push((start, j + 1));
            i = j;
        } else {
            depth += lines[i].matches('{').count() as i32;
            depth -= lines[i].matches('}').count() as i32;
            i += 1;
        }
    }
    out
}

fn skipped(reason: &str) -> Value {
    json!({
        "title": "APK / DEX decompilation: disrobe vs JADX vs CFR (recompile-clean main-class methods under real javac)",
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
        "metric": "recompile-clean main-class methods (clean / emitted)",
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
    fn run(&self, jar_path: &Path, out_dir: &Path) -> Result<String, String> {
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

fn collect_edgecases_java(out_dir: &Path) -> Result<String, String> {
    collect_edgecases_java_with_limits(out_dir, MAX_TREE_FILES, MAX_TREE_TEXT_BYTES)
}

fn collect_edgecases_java_with_limits(
    out_dir: &Path,
    max_files: usize,
    max_bytes: usize,
) -> Result<String, String> {
    let max_bytes_u64: u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut file_count: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut source: Option<String> = None;
    for entry in walkdir::WalkDir::new(out_dir).sort_by_file_name() {
        let entry: walkdir::DirEntry = entry
            .map_err(|error: walkdir::Error| format!("could not inspect cfr output: {error}"))?;
        if !entry.file_type().is_file() {
            continue;
        }
        if file_count >= max_files {
            return Err(format!("cfr output file count exceeds {max_files}"));
        }
        file_count += 1;
        let size: u64 = entry
            .metadata()
            .map_err(|error: walkdir::Error| format!("could not stat cfr output: {error}"))?
            .len();
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| "cfr output byte count overflowed".to_owned())?;
        if total_bytes > max_bytes_u64 {
            return Err(format!("cfr output exceeds {max_bytes} bytes"));
        }
        let path: &Path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) != Some("EdgeCases.java") {
            continue;
        }
        if source.is_some() {
            return Err("cfr output contains multiple EdgeCases.java files".to_owned());
        }
        source =
            Some(read_bounded_string(path, MAX_TEXT_BYTES).map_err(|error| error.to_string())?);
    }
    source.ok_or_else(|| "cfr produced no EdgeCases.java source".to_owned())
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
    fn an_unavailable_javac_is_a_miss() -> core::result::Result<(), String> {
        let scratch: ScratchDir = ScratchDir::create("disrobe_h2h_missing_javac")
            .map_err(|error: std::io::Error| error.to_string())?;
        let missing: PathBuf = scratch.path().join("javac-that-does-not-exist");
        let score: ToolScore = score_source(&missing, SAMPLE, 2);
        assert_eq!(score.status(), "miss");
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
        Ok(())
    }

    const fn type_checked(error_lines: Vec<usize>) -> OracleVerdict {
        OracleVerdict {
            error_lines,
            type_checked: true,
        }
    }

    const fn never_type_checked(error_lines: Vec<usize>) -> OracleVerdict {
        OracleVerdict {
            error_lines,
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
                first_defect_line: 1,
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
                    first_defect_line: 2,
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
            SHARED_ORACLE.contains("A method counts clean only when javac type-checked the whole"),
            "a reader cannot check a rule the published note does not state"
        );
        assert!(
            SHARED_ORACLE.contains("for either side"),
            "the note has to say the rule binds both sides, not only the competitor"
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
            !unresolved.error_lines.is_empty(),
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
        let result: std::result::Result<String, String> =
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
        let result: std::result::Result<String, String> =
            collect_edgecases_java_with_limits(scratch.path(), 8, 4096);
        assert!(
            result.is_err(),
            "duplicate main sources must not be selected by traversal order"
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
        let result: std::result::Result<String, String> =
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
