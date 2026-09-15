#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

#[allow(unreachable_pub)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_jvm::{ClassFile, decompile_class_with_inners, parse_classfile};

const PUBLISHED_HEADING: &str = "JVM classfile (EdgeCases corpus, per-method real-javac recompile)";
const PUBLISHED_RECOMPILE_BAR: &str = "per-method";
const PUBLISHED_EXECUTION_BAR: &str = "per-method, execution-verified";

const PER_METHOD_TOTAL: usize = 131;
const EXECUTION_EQUIVALENT_FLOOR: usize = 117;

const OBSERVATION_TIMEOUT_MS: u64 = 5_000;

const STUB_BLOCKED: &[(&str, &str)] = &[
    (
        "describeShape",
        "reads Circle.area / Square.area / Triangle.area, which the single-unit recovery emits as \
         signature stubs returning 0.0",
    ),
    (
        "totalArea",
        "sums Shape::area over stub implementations, so the observation measures the stub, not the \
         method body",
    ),
    (
        "runWorker",
        "calls CounterWorker.call, a stub returning null, so the unboxing throws and the catch \
         reports -1",
    ),
    (
        "callInner",
        "calls Outer.makeInner, a stub returning null, so Inner.sum throws instead of adding",
    ),
    (
        "centerOfMass",
        "builds a Vector2D whose stub toString returns null, so no observable value survives",
    ),
];

const BEHAVIOUR_DIVERGENT: &[(&str, &str)] = &[
    (
        "countVowels",
        "does not terminate: the loop increment var2++ is emitted inside the innermost vowel branch \
         only, so any non-u character leaves the index unchanged",
    ),
    (
        "maxOrMin",
        "does not terminate: the loop increment var3++ sits inside the wantMax-and-greater branch \
         only, and the wantMax=false arm drops the best=xs[i] assignment entirely",
    ),
    (
        "classify",
        "nests the Long / String / int[] / List instanceof tests inside the first arm's else \
         instead of sequencing them, so every non-Integer input falls through to \"other\"",
    ),
    (
        "dispatchByType",
        "drops the leading if (o == null) return \"null\" guard and emits no case null arm, so a \
         null input throws NullPointerException out of the switch",
    ),
    (
        "nestedAnon",
        "the inlined anonymous Runnable declares private int local without the captured seed \
         initializer, so the counter accumulates from 0 rather than from the argument",
    ),
    (
        "closureCaptureLoop",
        "the inlined anonymous Iterator loses the inner = Collections.emptyIterator() field \
         initializer, so hasNext dereferences null",
    ),
    (
        "lambda$closureCaptureLoop$0",
        "the recovered per-stage iterator is off by one: it yields 1,2,3 where the original yields \
         0,1,2 for the same capture",
    ),
    (
        "lambda$closureCaptureLoop$1",
        "same lost inner field initializer as closureCaptureLoop, reached through the flattening \
         iterator body",
    ),
];

const NOT_DRIVEN: &[(&str, &str)] = &[(
    "main",
    "its stdout is not self-reproducible: two runs of the ORIGINAL disagree on the Map.copyOf line \
     because immutable-collection iteration order is salted per jvm run, so a raw comparison would \
     be unsound. Every call main makes is driven individually by this differential",
)];

const CONTROL_TARGET: &str = "            var3 = -2147483648;\n            return var3;";

const CONTROL_MUTANT: &str = "            var3 = -2147483648;\n            EdgeCases.CTR.incrementAndGet();\n            return var3;";

const PROBE_SRC: &str = include_str!("fixtures/EdgeProbe.java");

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    for part in parts {
        p.push(part);
    }
    p
}

#[derive(Debug)]
struct Jdk {
    javac: PathBuf,
    java: PathBuf,
}

fn jdk() -> Jdk {
    let javac: PathBuf = common::find_on_path("javac").unwrap_or_else(|| {
        panic!(
            "javac is required: this differential compiles the original and the recovered java \
             with a real compiler and runs both. CI provisions a jdk with actions/setup-java, so a \
             missing javac is a broken environment, not a reason to report a green run"
        )
    });
    let java: PathBuf = common::find_on_path("java").unwrap_or_else(|| {
        panic!(
            "java is required: this differential executes both compiled programs and compares \
             observable behavior"
        )
    });
    Jdk { javac, java }
}

fn classes_from_jar(jar_path: &Path) -> Vec<(String, Vec<u8>)> {
    let f: std::fs::File = std::fs::File::open(jar_path)
        .unwrap_or_else(|e: std::io::Error| panic!("open {}: {e}", jar_path.display()));
    let mut z: zip::ZipArchive<std::fs::File> = zip::ZipArchive::new(f).expect("read jar");
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("jar entry");
        if std::path::Path::new(entry.name())
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("class"))
        {
            let name: String = entry.name().to_string();
            let mut bytes: Vec<u8> = Vec::new();
            entry.read_to_end(&mut bytes).expect("read class entry");
            out.push((name, bytes));
        }
    }
    out
}

fn recovered_edgecases_source() -> String {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let classes: Vec<(String, Vec<u8>)> = classes_from_jar(&jar);
    let (_name, bytes): &(String, Vec<u8>) = classes
        .iter()
        .find(|(name, _bytes)| name == "EdgeCases.class")
        .expect("EdgeCases.class in the tracked baseline jar");
    let cf: ClassFile = parse_classfile(bytes).expect("parse EdgeCases");
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(name, _bytes)| name.contains('$'))
        .filter_map(|(name, inner)| {
            parse_classfile(inner)
                .ok()
                .map(|parsed: ClassFile| (name.clone(), parsed))
        })
        .collect();
    decompile_class_with_inners(&cf, &inners).source
}

fn member_identifiers(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<String> = Vec::new();
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
            && !is_type_decl;
        if is_member {
            out.push(identifier_of(trimmed));
            let mut d: i32 =
                trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
            let mut j: usize = i + 1;
            while j < lines.len() && d > 0 {
                d += lines[j].matches('{').count() as i32;
                d -= lines[j].matches('}').count() as i32;
                j += 1;
            }
            i = j;
        } else {
            depth += lines[i].matches('{').count() as i32;
            depth -= lines[i].matches('}').count() as i32;
            i += 1;
        }
    }
    out
}

fn identifier_of(label: &str) -> String {
    let head: &str = label.split('(').next().unwrap_or(label);
    head.split_whitespace()
        .last()
        .unwrap_or(head)
        .trim_start_matches('*')
        .to_owned()
}

fn observation_key(identifier: &str) -> String {
    if identifier == "EdgeCases" {
        return "<init>".to_owned();
    }
    identifier.strip_prefix("synthLambda$").map_or_else(
        || identifier.to_owned(),
        |rest: &str| format!("lambda${rest}"),
    )
}

fn javac(jdk: &Jdk, classpath: &Path, out_dir: &Path, sources: &[PathBuf]) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).expect("create output directory");
    let mut cmd: Command = Command::new(&jdk.javac);
    cmd.arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(classpath)
        .arg("-d")
        .arg(out_dir);
    for source in sources {
        cmd.arg(source);
    }
    let out: Output = cmd.output().expect("run javac");
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn write_source(dir: &Path, name: &str, body: &str) -> PathBuf {
    std::fs::create_dir_all(dir).expect("create source directory");
    let path: PathBuf = dir.join(name);
    std::fs::write(&path, body).expect("write java source");
    path
}

fn run_probe(jdk: &Jdk, classpath: &[&Path]) -> BTreeMap<String, String> {
    let joined: std::ffi::OsString =
        std::env::join_paths(classpath.iter().copied()).expect("join classpath");
    let out: Output = Command::new(&jdk.java)
        .arg("-cp")
        .arg(&joined)
        .arg("EdgeProbe")
        .arg(OBSERVATION_TIMEOUT_MS.to_string())
        .output()
        .expect("run the behavior probe");
    let stdout: String = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    assert!(
        out.status.success(),
        "the behavior probe did not run to completion on classpath {}: {}\n{stdout}",
        PathBuf::from(&joined).display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let observations: BTreeMap<String, String> = stdout
        .lines()
        .filter_map(|line: &str| {
            line.split_once('=')
                .map(|(k, v): (&str, &str)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    assert!(
        observations.len() > 150,
        "the probe produced only {} observations, so it stopped early:\n{stdout}",
        observations.len()
    );
    observations
}

#[derive(Debug)]
struct Differential {
    recovered_source: String,
    identifiers: Vec<String>,
    divergent_keys: BTreeSet<String>,
    observed_keys: BTreeSet<String>,
    detail: Vec<String>,
}

fn measure(jdk: &Jdk, recovered_source: &str, purpose: &str) -> Differential {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let original_dir: PathBuf = root.join("original");
    let recovered_dir: PathBuf = root.join("recovered");
    let probe_dir: PathBuf = root.join("probe");
    let source_dir: PathBuf = root.join("src");

    let original_source: PathBuf = corpus(&["megafile", "EdgeCases.java"]);
    javac(jdk, &original_dir, &original_dir, &[original_source])
        .unwrap_or_else(|e: String| panic!("the original corpus source did not compile: {e}"));

    let recovered_path: PathBuf = write_source(&source_dir, "EdgeCases.java", recovered_source);
    javac(jdk, &original_dir, &recovered_dir, &[recovered_path]).unwrap_or_else(|e: String| {
        panic!("the recovered EdgeCases did not recompile under real javac: {e}")
    });

    let probe_path: PathBuf = write_source(&source_dir, "EdgeProbe.java", PROBE_SRC);
    javac(jdk, &original_dir, &probe_dir, &[probe_path])
        .unwrap_or_else(|e: String| panic!("the behavior probe did not compile: {e}"));

    let reference: BTreeMap<String, String> =
        run_probe(jdk, &[probe_dir.as_path(), original_dir.as_path()]);
    let candidate: BTreeMap<String, String> =
        run_probe(jdk, &[probe_dir.as_path(), recovered_dir.as_path()]);

    let mut divergent_keys: BTreeSet<String> = BTreeSet::new();
    let mut observed_keys: BTreeSet<String> = BTreeSet::new();
    let mut detail: Vec<String> = Vec::new();
    for (name, want) in &reference {
        let key: &str = name.split('#').next().unwrap_or(name);
        observed_keys.insert(key.to_owned());
        match candidate.get(name) {
            Some(got) if got == want => {}
            Some(got) => {
                divergent_keys.insert(key.to_owned());
                detail.push(format!("{name}: original `{want}` vs recovered `{got}`"));
            }
            None => {
                divergent_keys.insert(key.to_owned());
                detail.push(format!("{name}: missing from the recovered run"));
            }
        }
    }

    Differential {
        recovered_source: recovered_source.to_owned(),
        identifiers: member_identifiers(recovered_source),
        divergent_keys,
        observed_keys,
        detail,
    }
}

fn published_bar(label: &str) -> serde_json::Value {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(PUBLISHED_HEADING));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{PUBLISHED_HEADING}`, found {}",
        found.len()
    );
    found.remove(0)
}

#[test]
fn recovered_methods_execute_equivalently_under_a_real_jvm() {
    let jdk: Jdk = jdk();
    let recovered_source: String = recovered_edgecases_source();
    let result: Differential = measure(
        &jdk,
        &recovered_source,
        &format!("disrobe_jvm_execution_diff_{}", std::process::id()),
    );

    assert_eq!(
        result.identifiers.len(),
        PER_METHOD_TOTAL,
        "the EdgeCases top-level member count drifted to {}; this partition is denominator-pinned \
         against the published per-method figure",
        result.identifiers.len()
    );

    let stub_blocked: BTreeSet<&str> = STUB_BLOCKED.iter().map(|(m, _r)| *m).collect();
    let divergent: BTreeSet<&str> = BEHAVIOUR_DIVERGENT.iter().map(|(m, _r)| *m).collect();
    let not_driven: BTreeSet<&str> = NOT_DRIVEN.iter().map(|(m, _r)| *m).collect();

    let mut equivalent_labels: usize = 0;
    let mut stub_labels: usize = 0;
    let mut divergent_labels: usize = 0;
    let mut not_driven_labels: usize = 0;
    let mut equivalent_keys: BTreeSet<String> = BTreeSet::new();
    let mut unexplained: Vec<String> = Vec::new();
    let mut unobserved: Vec<String> = Vec::new();

    for identifier in &result.identifiers {
        let key: String = observation_key(identifier);
        let k: &str = key.as_str();
        if not_driven.contains(k) {
            not_driven_labels += 1;
            continue;
        }
        if !result.observed_keys.contains(k) {
            unobserved.push(identifier.clone());
            continue;
        }
        if result.divergent_keys.contains(k) {
            if stub_blocked.contains(k) {
                stub_labels += 1;
            } else if divergent.contains(k) {
                divergent_labels += 1;
            } else {
                unexplained.push(identifier.clone());
            }
            continue;
        }
        equivalent_labels += 1;
        equivalent_keys.insert(key);
    }

    eprintln!(
        "JVM PER-METHOD EXECUTION DIFFERENTIAL (EdgeCases, real javac plus real jvm):\n  \
         execution-equivalent {equivalent_labels}/{PER_METHOD_TOTAL}\n  \
         javac-clean but behavior DIVERGENT {divergent_labels}/{PER_METHOD_TOTAL}\n  \
         javac-clean, not executable in isolation {}/{PER_METHOD_TOTAL} \
         ({stub_labels} measure a nested-type stub, {not_driven_labels} not self-reproducible)\n  \
         equivalent membership: {:?}",
        stub_labels + not_driven_labels,
        equivalent_keys
    );
    for line in &result.detail {
        eprintln!("  divergence: {line}");
    }

    assert!(
        unobserved.is_empty(),
        "these recovered members are neither driven by the probe nor listed in NOT_DRIVEN, so the \
         partition does not account for them: {unobserved:?}"
    );
    assert!(
        unexplained.is_empty(),
        "these recovered members behave differently from the original and are in no pinned bucket, \
         which is a NEW compiling-but-wrong recovery: {unexplained:?}\nfull divergence detail:\n{}",
        result.detail.join("\n")
    );

    for (method, reason) in STUB_BLOCKED.iter().chain(BEHAVIOUR_DIVERGENT.iter()) {
        assert!(
            result.divergent_keys.contains(*method),
            "`{method}` is pinned as not execution-equivalent ({reason}) but now matches the \
             original; move it into the equivalent set and raise \
             EXECUTION_EQUIVALENT_FLOOR, because these lists only ever shrink"
        );
    }
    for (method, _reason) in NOT_DRIVEN {
        assert!(
            !result.observed_keys.contains(*method),
            "`{method}` is pinned as not driven but the probe now observes it; move it into the \
             measured partition"
        );
    }

    assert_eq!(
        equivalent_labels + divergent_labels + stub_labels + not_driven_labels,
        PER_METHOD_TOTAL,
        "the three-way partition does not add up to the published denominator"
    );
    assert!(
        equivalent_labels >= EXECUTION_EQUIVALENT_FLOOR,
        "execution-equivalent recovery regressed: {equivalent_labels}/{PER_METHOD_TOTAL} < floor \
         {EXECUTION_EQUIVALENT_FLOOR}/{PER_METHOD_TOTAL}"
    );

    let recompile_bar: serde_json::Value = published_bar(PUBLISHED_RECOMPILE_BAR);
    let published_den: u64 = recompile_bar["den"]
        .as_u64()
        .expect("the per-method bar must carry a denominator");
    assert_eq!(
        published_den,
        u64::try_from(PER_METHOD_TOTAL).expect("total fits u64"),
        "recovery.json publishes a per-method denominator of {published_den} while this \
         differential partitions {PER_METHOD_TOTAL} members; the {PUBLISHED_EXECUTION_BAR} bar \
         must share that denominator"
    );
    let execution_bar: serde_json::Value = published_bar(PUBLISHED_EXECUTION_BAR);
    let published_num: u64 = execution_bar["num"]
        .as_u64()
        .expect("the execution-verified bar must carry a numerator");
    assert_eq!(
        published_num,
        u64::try_from(equivalent_labels).expect("equivalent count fits u64"),
        "recovery.json publishes {published_num} execution-equivalent methods while this \
         differential measured {equivalent_labels}; the chart states a behavioral result the JVM \
         did not produce"
    );
    assert_eq!(
        execution_bar["den"].as_u64(),
        Some(published_den),
        "the execution-verified bar must share the recompile bar's denominator, or the two tiers \
         are published over different populations and cannot be compared"
    );
    let published_pct: f64 = execution_bar["value"]
        .as_f64()
        .expect("the execution-verified bar must carry a percentage");
    let measured_pct: f64 = equivalent_labels as f64 * 100.0 / PER_METHOD_TOTAL as f64;
    assert!(
        (published_pct - measured_pct).abs() < 0.01,
        "recovery.json plots {published_pct}% for {published_num} of {published_den}, but the \
         measured rate is {measured_pct}%; the percentage and the counts beside it disagree"
    );
    let detail: &str = execution_bar["detail"]
        .as_str()
        .expect("the execution-verified bar must carry a detail");
    assert!(
        detail.contains(&format!(
            "{divergent_labels} methods are javac-clean and measurably"
        )),
        "the published detail does not state that {divergent_labels} of the residual are known \
         divergent, so a reader takes the whole residual for merely ungraded and the two \
         populations are conflated"
    );

    assert!(
        result
            .recovered_source
            .contains("public static int countVowels"),
        "the recovered source no longer contains the member this partition was measured against"
    );
}

#[test]
fn the_execution_differential_reports_a_double_counted_exception_path() {
    let jdk: Jdk = jdk();
    let recovered_source: String = recovered_edgecases_source();
    let sites: usize = recovered_source.matches(CONTROL_TARGET).count();
    assert_eq!(
        sites, 1,
        "the mutation-kill control targets divSafe's recovered catch tail and found {sites} sites \
         instead of one, so it either moved or is no longer unique and must be re-pinned"
    );
    let mutant: String = recovered_source.replace(CONTROL_TARGET, CONTROL_MUTANT);
    assert_ne!(
        mutant, recovered_source,
        "the control mutation did not apply"
    );

    let result: Differential = measure(
        &jdk,
        &mutant,
        &format!("disrobe_jvm_execution_control_{}", std::process::id()),
    );

    assert!(
        result.divergent_keys.contains("divSafe"),
        "injecting a second CTR.incrementAndGet on divSafe's exception path, the exact shape of \
         the inlined-finally defect this crate once shipped, produced a program real javac accepts \
         and this differential called equivalent, so it measures nothing; divergences were: {:?}",
        result.detail
    );
    let exception_path: Vec<&String> = result
        .detail
        .iter()
        .filter(|line: &&String| line.starts_with("divSafe#throws:"))
        .collect();
    assert!(
        !exception_path.is_empty(),
        "the control diverged somewhere other than divSafe's exception path, so it is not the \
         defect shape being tested: {:?}",
        result.detail
    );
    assert!(
        !result
            .detail
            .iter()
            .any(|line: &String| line.starts_with("divSafe#ok:")),
        "the control also changed the normal-return path, so it is a coarser mutation than the \
         inlined-finally defect: {:?}",
        result.detail
    );
    eprintln!("MUTATION-KILL CONTROL: {}", exception_path[0]);
}
