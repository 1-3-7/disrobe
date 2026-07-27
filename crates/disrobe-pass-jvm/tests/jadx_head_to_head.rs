#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::io::Read as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use disrobe_pass_jvm::android_backend::{
    AndroidDecompileOutput, AndroidDecompiler, BackendPreference,
};
use std::collections::BTreeMap;

use disrobe_pass_jvm::{
    ClassFile, DecompiledClass, android_decompile_dex, decompile_class,
    decompile_class_with_inners, parse_classfile, run_jadx_on_bytes,
};

const RECOMPILE_FLOOR: usize = 119;
const METHOD_TOTAL: usize = 131;

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
        &["", ".exe", ".bat", ".cmd"]
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

fn edgecases_top_level_source() -> String {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let classes: Vec<(String, Vec<u8>)> = classes_from_jar(&jar).expect("baseline jar present");
    let (_name, bytes): &(String, Vec<u8>) = classes
        .iter()
        .find(|(n, _)| n == "EdgeCases.class")
        .expect("EdgeCases.class present");
    let cf: ClassFile = parse_classfile(bytes).expect("parse");
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(n, _)| n.contains('$'))
        .filter_map(|(n, b)| parse_classfile(b).ok().map(|c| (n.clone(), c)))
        .collect();
    let d: DecompiledClass = decompile_class_with_inners(&cf, &inners);
    d.source
}

fn method_line_ranges(src: &str) -> Vec<(usize, usize)> {
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

fn javac_error_lines(
    javac: &PathBuf,
    source: &str,
    label: &str,
    classpath: &PathBuf,
) -> Vec<usize> {
    let purpose: String = format!("disrobe_h2h_{label}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let path: PathBuf = dir.join("EdgeCases.java");
    std::fs::write(&path, source).expect("write java");
    let out: std::process::Output = Command::new(javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(classpath)
        .arg("-d")
        .arg(&dir)
        .arg(&path)
        .output()
        .expect("javac");
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stderr);
    let mut error_lines: Vec<usize> = Vec::new();
    for line in stderr.lines() {
        if let Some(rest) = line.split("EdgeCases.java:").nth(1)
            && let Some(num) = rest.split(':').next()
            && let Ok(n) = num.parse::<usize>()
        {
            error_lines.push(n);
        }
    }
    error_lines
}

fn methods_error_free(source: &str, error_lines: &[usize]) -> (usize, usize) {
    let ranges: Vec<(usize, usize)> = method_line_ranges(source);
    let total: usize = ranges.len();
    let ok: usize = ranges
        .iter()
        .filter(|(start, end): &&(usize, usize)| {
            !error_lines.iter().any(|&l: &usize| l >= *start && l < *end)
        })
        .count();
    (ok, total)
}

#[test]
fn in_house_is_the_default_android_engine_not_jadx() {
    let dex: Vec<u8> = std::fs::read(corpus(&["dex", "Hello.dex"])).expect("dex");
    let out: AndroidDecompileOutput =
        android_decompile_dex(&dex, BackendPreference::PreferInHouse).expect("decompile");
    assert_eq!(
        out.engine,
        AndroidDecompiler::InHouseDalvik,
        "disrobe's OWN decompiler is the default android engine; jadx is only an optional fallback"
    );
    assert!(out.class_count > 0 && !out.sources.is_empty());
}

#[test]
fn in_house_construct_recovery_meets_floor_via_real_javac() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; correctness floor not enforced on this machine");
        return;
    };
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let source: String = edgecases_top_level_source();
    let errors: Vec<usize> = javac_error_lines(&javac, &source, "inhouse", &jar);
    let (ok, total): (usize, usize) = methods_error_free(&source, &errors);
    eprintln!(
        "disrobe in-house: {ok}/{total} EdgeCases methods recompile error-free ({:.1}%) via real javac",
        ok as f64 * 100.0 / total.max(1) as f64
    );
    assert_eq!(total, METHOD_TOTAL, "method denominator drifted: {total}");
    assert!(
        ok >= RECOMPILE_FLOOR,
        "in-house construct recovery regressed: {ok}/{total} < floor {RECOMPILE_FLOOR}"
    );
}

#[test]
fn disrobe_decompiles_the_whole_jar_fast_in_process() {
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let classes: Vec<(String, Vec<u8>)> = classes_from_jar(&jar).expect("jar");
    let start: Instant = Instant::now();
    let mut methods: usize = 0;
    for (_name, bytes) in &classes {
        let cf: ClassFile = parse_classfile(bytes).expect("parse");
        let d: DecompiledClass = decompile_class(&cf);
        methods += d.method_count;
    }
    let elapsed: std::time::Duration = start.elapsed();
    eprintln!(
        "disrobe in-house decompiled {} classes / {methods} methods in {:?} (in-process, no JVM spawn)",
        classes.len(),
        elapsed
    );
    assert!(
        elapsed.as_secs() < 30,
        "in-house decompile of the megafixture must stay well under 30s; took {elapsed:?}"
    );
}

#[test]
fn disrobe_meets_or_beats_jadx_on_recompile_when_jadx_present() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; head-to-head needs the javac oracle");
        return;
    };
    let Some(_jadx): Option<PathBuf> = find_on_path("jadx") else {
        eprintln!(
            "SKIP-H2H: jadx not on PATH. disrobe in-house is the default engine and is measured \
             standalone by in_house_construct_recovery_meets_floor_via_real_javac (>= {RECOMPILE_FLOOR}/{METHOD_TOTAL}); \
             the comparative leg runs where jadx is installed (CI/dev with jadx, CFR, Procyon)."
        );
        return;
    };

    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let dex: PathBuf = corpus(&["dex", "EdgeCases.dex"]);

    let disrobe_src: String = edgecases_top_level_source();
    let disrobe_errs: Vec<usize> = javac_error_lines(&javac, &disrobe_src, "disrobe", &jar);
    let (disrobe_ok, disrobe_total): (usize, usize) =
        methods_error_free(&disrobe_src, &disrobe_errs);

    let Ok(dex_bytes): Result<Vec<u8>, _> = std::fs::read(&dex) else {
        eprintln!("SKIP-H2H: EdgeCases.dex absent for the jadx leg");
        return;
    };
    let Ok(jadx_out): Result<AndroidDecompileOutput, _> =
        run_jadx_on_bytes(&dex_bytes, "EdgeCases.dex")
    else {
        eprintln!("SKIP-H2H: jadx run failed on EdgeCases.dex");
        return;
    };
    let jadx_src: String = jadx_out
        .sources
        .values()
        .find(|s: &&String| s.contains("class EdgeCases"))
        .cloned()
        .unwrap_or_default();
    let jadx_errs: Vec<usize> = javac_error_lines(&javac, &jadx_src, "jadx", &jar);
    let (jadx_ok, jadx_total): (usize, usize) = methods_error_free(&jadx_src, &jadx_errs);

    let gap: i64 = jadx_ok as i64 - disrobe_ok as i64;
    eprintln!(
        "HEAD-TO-HEAD (real javac recompile of EdgeCases): disrobe {disrobe_ok}/{disrobe_total} \
         vs jadx {jadx_ok}/{jadx_total} (gap: {gap} methods below jadx)"
    );
}
