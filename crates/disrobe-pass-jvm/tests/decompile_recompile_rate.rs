#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::classfile::{Attribute, MethodInfo};
use disrobe_pass_jvm::{ClassFile, DecompiledClass, decompile_class, parse_classfile};

/// Markers the renderer emits when it cannot faithfully reconstruct a fragment;
/// any of these in a method body means that body is not a clean semantic
/// recovery. Used to compute the honest per-method success fraction.
const INVALIDITY_MARKERS: &[&str] = &[
    "goto L",
    "(stack reset)",
    "irreducible",
    "/*cmp*/",
    "/*invokedynamic*/",
    "/*ldc*/",
    " ?;",
    "(?",
    "?)",
    "?,",
    ", ?",
    "/* monitorenter",
    "/* monitorexit",
    "<init>(",
];

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

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn classes_from_jar(jar_path: &PathBuf) -> Option<Vec<(String, Vec<u8>)>> {
    let f: std::fs::File = std::fs::File::open(jar_path).ok()?;
    let mut z: zip::ZipArchive<std::fs::File> = zip::ZipArchive::new(f).expect("zip read");
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if entry.name().ends_with(".class") {
            let name: String = entry.name().to_string();
            let mut bytes: Vec<u8> = Vec::new();
            entry.read_to_end(&mut bytes).expect("read class");
            out.push((name, bytes));
        }
    }
    Some(out)
}

/// Measures the per-method fidelity of the in-house `.class -> Java`
/// decompiler against the real `javac` baseline: a method is "lifted" when its
/// body renders with zero residual fallback markers (`goto`, stack-reset,
/// irreducible). This is a self-consistency ceiling; the recompile gate below
/// is the non-circular check.
#[test]
fn report_in_house_method_lift_rate() {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!("skip: baseline jar absent");
        return;
    };
    let mut method_total: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut residual_markers: usize = 0;
    for (_name, bytes) in &classes {
        let cf: ClassFile = parse_classfile(bytes).expect("parse");
        let d: DecompiledClass = decompile_class(&cf);
        method_total += d.method_count;
        fully_lifted += d.fully_lifted_methods;
        residual_markers += d.source.matches("goto L").count();
        residual_markers += d.source.matches("(stack reset)").count();
        residual_markers += d.source.matches("irreducible").count();
    }
    let pct: f64 = fully_lifted as f64 * 100.0 / method_total.max(1) as f64;
    eprintln!(
        "in-house decompiler: {fully_lifted}/{method_total} methods fully lifted ({pct:.1}%); \
         residual fallback markers: {residual_markers}"
    );
}

fn all_corpus_classes() -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(cs) = classes_from_jar(&corpus(&["megafile", "EdgeCases-baseline.jar"])) {
        out.extend(cs);
    }
    for single in [
        &["proguard", "Hello-baseline.class"][..],
        &["proguard", "Hello-obf.class"][..],
    ] {
        if let Ok(bytes) = std::fs::read(corpus(single)) {
            out.push((single.join("/"), bytes));
        }
    }
    out
}

fn method_count(cf: &ClassFile) -> usize {
    cf.methods
        .iter()
        .filter(|m: &&MethodInfo| has_code(cf, m))
        .count()
}

fn has_code(cf: &ClassFile, method: &MethodInfo) -> bool {
    method
        .attributes
        .iter()
        .any(|a: &Attribute| cf.utf8_at(a.name_index).is_ok_and(|n: &str| n == "Code"))
}

/// Splits a decompiled class body into one fragment per method by brace-depth
/// scanning from each member signature, so each fragment can be independently
/// scored for invalidity markers. This yields the honest per-method recovery
/// fraction across the whole corpus rather than an all-or-nothing class gate.
fn method_fragments(source: &str) -> Vec<String> {
    let mut frags: Vec<String> = Vec::new();
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut depth: i32 = 1;
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            if depth == 0 && j > start {
                frags.push(source[start..j - 1].to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    frags
}

/// Honest per-method recovery fraction across the corpus: a method body counts
/// as recovered when its decompiled fragment contains no invalidity marker.
#[test]
fn report_per_method_clean_recovery() {
    let classes: Vec<(String, Vec<u8>)> = all_corpus_classes();
    if classes.is_empty() {
        eprintln!("skip: no corpus classes");
        return;
    }
    let mut total: usize = 0;
    let mut clean: usize = 0;
    for (_name, bytes) in &classes {
        let Ok(cf): Result<ClassFile, _> = parse_classfile(bytes) else {
            continue;
        };
        let d: DecompiledClass = decompile_class(&cf);
        let mut frags: Vec<String> = method_fragments(&d.source);
        let inner_frags: Vec<String> = frags
            .iter()
            .flat_map(|f: &String| method_fragments(f))
            .collect();
        frags.extend(inner_frags);
        let methods: usize = method_count(&cf);
        let bad_fragments: usize = frags
            .iter()
            .filter(|f: &&String| INVALIDITY_MARKERS.iter().any(|m: &&str| f.contains(m)))
            .count();
        total += methods;
        clean += methods.saturating_sub(bad_fragments.min(methods));
    }
    let pct: f64 = clean as f64 * 100.0 / total.max(1) as f64;
    eprintln!("per-method clean recovery across corpus: {clean}/{total} ({pct:.1}%)");
}

/// Non-circular recompile gate: emit every decompiled class to a `.java` file
/// and attempt a single bulk `javac` compile. Reports how many top-level
/// compilation units are accepted. Pure measurement; never fails (the bar is
/// reported, not asserted, because cross-referencing nested types needs the
/// whole-program emit which is out of scope for the body-structuring work).
#[test]
fn report_decompiled_recompile_acceptance() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH");
        return;
    };
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!("skip: baseline jar absent");
        return;
    };
    let dir: PathBuf = std::env::temp_dir().join("disrobe_decompile_recompile");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for (name, bytes) in &classes {
        if name.contains('$') {
            continue;
        }
        let cf: ClassFile = parse_classfile(bytes).expect("parse");
        let d: DecompiledClass = decompile_class(&cf);
        let simple: &str = name
            .trim_end_matches(".class")
            .rsplit('/')
            .next()
            .unwrap_or("X");
        sources.insert(simple.to_string(), d.source);
    }

    let mut compiled_ok: usize = 0;
    let total: usize = sources.len();
    for (simple, src) in &sources {
        let path: PathBuf = dir.join(format!("{simple}.java"));
        std::fs::write(&path, src).expect("write java");
        let out: std::process::Output = Command::new(&javac)
            .arg("-nowarn")
            .arg("-proc:none")
            .arg("-d")
            .arg(&dir)
            .arg(&path)
            .output()
            .expect("javac");
        if out.status.success() {
            compiled_ok += 1;
        }
    }
    let pct: f64 = compiled_ok as f64 * 100.0 / total.max(1) as f64;
    eprintln!("decompiled top-level units recompiled by javac: {compiled_ok}/{total} ({pct:.1}%)");
}
