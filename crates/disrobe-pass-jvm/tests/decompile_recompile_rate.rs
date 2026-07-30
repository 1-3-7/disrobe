#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::bytecode::{
    Instruction, Operands, class_internal_name_at, disassemble, parse_code_attribute, resolve_ref,
};
use disrobe_pass_jvm::classfile::{Attribute, MethodInfo};
use disrobe_pass_jvm::{
    ClassFile, DecompiledClass, decompile_class, decompile_class_with_inners, parse_classfile,
};

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

const PER_METHOD_JAVAC_OK_FLOOR: usize = 131;
const PER_METHOD_JAVAC_TOTAL: usize = 131;

const PUBLISHED_HEADING: &str = "JVM classfile (EdgeCases corpus, per-method real-javac recompile)";
const PUBLISHED_BAR: &str = "per-method";

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
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
            .is_some_and(|h: &str| h.contains(heading_needle));
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
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

#[test]
fn published_per_method_bar_matches_the_floors_this_crate_enforces() {
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let num: u64 = bar["num"]
        .as_u64()
        .expect("the per-method bar must carry a numerator");
    let den: u64 = bar["den"]
        .as_u64()
        .expect("the per-method bar must carry a denominator");
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the per-method bar must carry a numeric value");
    assert_eq!(
        num,
        u64::try_from(PER_METHOD_JAVAC_OK_FLOOR).expect("floor fits u64"),
        "xtask/data/recovery.json publishes {num} methods recompiling clean and every document \
         renders that number, but this crate enforces {PER_METHOD_JAVAC_OK_FLOOR}"
    );
    assert_eq!(
        den,
        u64::try_from(PER_METHOD_JAVAC_TOTAL).expect("total fits u64"),
        "recovery.json publishes a denominator of {den} top-level methods; this crate pins \
         {PER_METHOD_JAVAC_TOTAL}, and report_per_method_javac_recompile fails if the corpus \
         drifts from it"
    );
    let derived: f64 = 100.0 * num as f64 / den as f64;
    assert!(
        (derived - value).abs() < 0.05,
        "the published value {value} disagrees with its own {num}/{den} = {derived:.4}"
    );
}

const GAP_METHOD_TOTAL: usize = 7;
const GAP_METHOD_OK_FLOOR: usize = 7;
const FLOOR_PROVENANCE: &str = "floor is the honest count of top-level methods that recompile clean \
     under real javac attribution; an earlier 130/131 was a parse-mask artifact (one empty try {} \
     short-circuited javac before the attribution phase, hiding the real type errors); the 119->122 \
     gain came from splitting reused primitive/reference slot ranges and expanding unbound instance \
     method references into explicit receiver-cast lambdas so erased generic SAMs still resolve; the \
     122->126 gain came from inlining anonymous inner classes at their instantiation site as \
     new-interface-body expressions with captured constructor args substituted for val$ fields, plus \
     typing a slot object when its constructed and inferred reference types disagree; the 126->127 \
     gain came from casting primitive method-reference params when the erased SAM signature is Object, \
     so foldLeft/reduce/tap emit real boxing lambdas instead of raw Integer::sum / AtomicInteger::addAndGet refs; \
     the 128->129 gain came from flattening nested record-deconstruction switches: walking each \
     typeSwitch-dispatched record component depth-first so deepPattern's Pair(Integer i, String s) / \
     Pair(Integer i, Integer j) / Pair(String a, String b) sibling patterns lift instead of leaving the \
     second accessor unresolved; the 129->130 gain came from reconstructing the javac-9+ try-with-resources \
     idiom (single Throwable handler doing primary-capture, null-checked close, addSuppressed sub-try, \
     primary-rethrow) back into try(resource){body}, which exposed and fixed two real structuring defects: \
     try-body blocks carry an exception edge so the single-successor walk dropped everything after the first \
     block, and loop headers inside a try misclassified as do-while(true) because the exception edge inflated \
     the successor count; plus extending reused-slot splitting to xload_n/xstore_n short forms and threading \
     invokedynamic return types through reference inference so makeConcat results type as String; \
     the pickWord lookupswitch->switch-expression lift (9afa2306) generated compilable Java for pickWord \
     but unmasked 25 latent defects in other methods that were previously hidden because pickWord's \
     __unresolved__ token caused javac to absorb those errors; the 100->131 recovery (now a full clean \
     recompile of every top-level method) fixed them by class: resolving a pattern-switch subject back to \
     the parameter it was copied from so the selector reads `switch (arg0)` and the sealed permitted-subtype \
     switch proves exhaustive; emitting the sealed/permits clause on inner type stubs (skipping enums, whose \
     permitted subclasses are unnameable anonymous bodies); giving final inner-stub fields a typed default \
     initializer so the synthetic empty constructor satisfies definite assignment; threading the method \
     Exceptions attribute into the signature as a real throws clause so Future.get / Thread.sleep / \
     sneaky-throw callers type-check; emitting the loop-exhausted terminal after a while loop whose exit is a \
     shared pure-return tail only rendered on the in-loop path; hoisting a loop-captured local to a fresh \
     final declaration at its single in-block assignment so the lambda capture is effectively final; and \
     duplicating the shared return-other tail after an instanceof if-else-if chain whose merged fallthrough \
     the generic structurer buries, gated on a Region-tree fall-through analysis so the duplicate is never \
     unreachable; floor is the full 131 measured under real javac attribution";

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
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_decompile_recompile")
            .expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();

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

fn method_line_ranges(src: &str) -> Vec<(String, usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out: Vec<(String, usize, usize)> = Vec::new();
    let mut i: usize = 0;
    let mut depth: i32 = 0;
    while i < lines.len() {
        let trimmed: &str = lines[i].trim();
        let is_type_decl: bool = ["class ", "interface ", "enum ", "record ", "@interface "]
            .iter()
            .any(|kw: &&str| trimmed.contains(kw));
        let is_member: bool = depth == 1
            && (trimmed.contains('(')
                && (trimmed.contains(" static ")
                    || trimmed.starts_with("public ")
                    || trimmed.starts_with("private ")
                    || trimmed.starts_with("protected ")
                    || trimmed.starts_with("static")))
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
            out.push((trimmed.to_string(), start, j + 1));
            i = j;
        } else {
            depth += lines[i].matches('{').count() as i32;
            depth -= lines[i].matches('}').count() as i32;
            i += 1;
        }
    }
    out
}

fn javac_error_files(stderr: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in stderr.lines() {
        let Some((path, _rest)): Option<(&str, &str)> = line.split_once(".java:") else {
            continue;
        };
        let Some(file_name): Option<&str> = std::path::Path::new(path)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
        else {
            continue;
        };
        let simple: String = file_name.trim_end_matches(".java").to_owned();
        out.insert(simple);
    }
    out
}

#[test]
fn report_multi_class_javac_recompile() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH");
        return;
    };
    let jar: PathBuf = corpus(&["proguard", "Hello-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!("skip: baseline jar absent");
        return;
    };
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for (name, bytes) in &classes {
        if name.contains('$') {
            continue;
        }
        let cf: ClassFile = parse_classfile(bytes).expect("parse");
        let d: DecompiledClass = decompile_class(&cf);
        let simple: String = cf
            .this_class_name()
            .expect("this class")
            .rsplit('/')
            .next()
            .expect("simple name")
            .to_owned();
        sources.insert(simple, d.source);
    }
    let total: usize = sources.len();
    assert_eq!(total, 2, "Hello-baseline.jar class denominator drifted");

    let purpose: String = format!("disrobe_multi_class_recompile_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut paths: Vec<PathBuf> = Vec::with_capacity(total);
    for (simple, src) in &sources {
        let path: PathBuf = dir.join(format!("{simple}.java"));
        std::fs::write(&path, src).expect("write java");
        paths.push(path);
    }

    let mut cmd: Command = Command::new(&javac);
    cmd.arg("-nowarn").arg("-proc:none").arg("-d").arg(&dir);
    for path in &paths {
        cmd.arg(path);
    }
    let out: std::process::Output = cmd.output().expect("javac");
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stderr);
    let error_files: BTreeSet<String> = javac_error_files(&stderr);
    let ok: usize = total.saturating_sub(error_files.len().min(total));
    let pct: f64 = ok as f64 * 100.0 / total.max(1) as f64;
    eprintln!("MULTI-CLASS JAVAC RECOMPILE (Hello-baseline.jar): {ok}/{total} classes ({pct:.1}%)");
    assert!(
        out.status.success() && ok == total,
        "multi-class javac recompile failed: {ok}/{total} classes; stderr:\n{stderr}"
    );
}

#[test]
fn report_per_method_javac_recompile() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "\n========================================================================\n\
             SKIPPED: javac not on PATH. The per-method recompile floor (>= {PER_METHOD_JAVAC_OK_FLOOR} \
             of {PER_METHOD_JAVAC_TOTAL})\n\
             did NOT run and is NOT enforced on this machine. A green result here is a\n\
             SKIP, not a measured pass. Install a JDK (actions/setup-java in CI).\n\
             ========================================================================\n"
        );
        return;
    };
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!("skip: baseline jar absent");
        return;
    };
    let Some((_n, bytes)): Option<&(String, Vec<u8>)> =
        classes.iter().find(|(n, _)| n == "EdgeCases.class")
    else {
        eprintln!("skip: EdgeCases.class absent");
        return;
    };
    let cf: ClassFile = parse_classfile(bytes).expect("parse");
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(n, _)| n.contains('$'))
        .filter_map(|(n, b)| parse_classfile(b).ok().map(|c| (n.clone(), c)))
        .collect();
    let d: DecompiledClass = decompile_class_with_inners(&cf, &inners);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_per_method_recompile")
            .expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let path: PathBuf = dir.join("EdgeCases.java");
    std::fs::write(&path, &d.source).expect("write");

    let out: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(&jar)
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

    let ranges: Vec<(String, usize, usize)> = method_line_ranges(&d.source);
    let total: usize = ranges.len();
    let mut ok: usize = 0;
    for (_label, start, end) in &ranges {
        let has_error: bool = error_lines.iter().any(|&l| l >= *start && l < *end);
        if !has_error {
            ok += 1;
        }
    }
    let pct: f64 = ok as f64 * 100.0 / total.max(1) as f64;
    eprintln!(
        "PER-METHOD JAVAC RECOMPILE (EdgeCases top-level): {ok}/{total} methods error-free \
         ({pct:.1}%); total javac errors: {}",
        error_lines.len()
    );
    assert_eq!(
        total, PER_METHOD_JAVAC_TOTAL,
        "EdgeCases top-level method count drifted: {total} != {PER_METHOD_JAVAC_TOTAL}; \
         the recompile floor is denominator-pinned, recheck the corpus"
    );
    assert!(
        ok >= PER_METHOD_JAVAC_OK_FLOOR,
        "per-method javac recompile regressed: {ok}/{total} error-free < floor \
         {PER_METHOD_JAVAC_OK_FLOOR}/{PER_METHOD_JAVAC_TOTAL}; {FLOOR_PROVENANCE}"
    );
}

const VERIFY_LOADER_SRC: &str = "import java.io.File;\n\
public class Load {\n\
    public static void main(String[] a) throws Exception {\n\
        File dir = new File(a[0]);\n\
        int ok = 0, fail = 0;\n\
        File[] files = dir.listFiles();\n\
        if (files != null) for (File f : files) {\n\
            String n = f.getName();\n\
            if (!n.endsWith(\".class\")) continue;\n\
            if (n.equals(\"Load.class\")) continue;\n\
            String load = n.substring(0, n.length() - 6);\n\
            try { Class.forName(load, true, Load.class.getClassLoader()); ok++; }\n\
            catch (Throwable t) { fail++; System.out.println(\"FAIL \" + load + \": \" + t); }\n\
        }\n\
        System.out.println(\"verify_ok=\" + ok + \" verify_fail=\" + fail);\n\
    }\n\
}\n";

#[test]
fn recompiled_class_links_under_jvm_verifier() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "SKIP whole-unit -Xverify:all gate: javac not on PATH; the recompiled EdgeCases \
             classfile is NOT attested to load under the real JVM verifier on this machine"
        );
        return;
    };
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP whole-unit -Xverify:all gate: java not on PATH");
        return;
    };
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let Some(classes): Option<Vec<(String, Vec<u8>)>> = classes_from_jar(&jar) else {
        eprintln!("skip: baseline jar absent");
        return;
    };
    let Some((_n, bytes)): Option<&(String, Vec<u8>)> =
        classes.iter().find(|(n, _)| n == "EdgeCases.class")
    else {
        eprintln!("skip: EdgeCases.class absent");
        return;
    };
    let cf: ClassFile = parse_classfile(bytes).expect("parse");
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(n, _)| n.contains('$'))
        .filter_map(|(n, b)| parse_classfile(b).ok().map(|c| (n.clone(), c)))
        .collect();
    let d: DecompiledClass = decompile_class_with_inners(&cf, &inners);

    let purpose: String = format!("disrobe_verify_gate_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    std::fs::write(dir.join("EdgeCases.java"), &d.source).expect("write java");

    let compiled: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(&jar)
        .arg("-d")
        .arg(&dir)
        .arg(dir.join("EdgeCases.java"))
        .output()
        .expect("javac");
    assert!(
        compiled.status.success(),
        "recompiled EdgeCases did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let loader: PathBuf = dir.join("Load.java");
    std::fs::write(&loader, VERIFY_LOADER_SRC).expect("write loader");
    let loader_built: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&dir)
        .arg(&loader)
        .output()
        .expect("javac loader");
    assert!(
        loader_built.status.success(),
        "verifier loader did not compile: {}",
        String::from_utf8_lossy(&loader_built.stderr)
    );

    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&dir)
        .arg("Load")
        .arg(&dir)
        .output()
        .expect("java -Xverify:all");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    let fail: usize = stdout
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("verify_fail="))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let ok: usize = stdout
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("verify_ok="))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(0);
    eprintln!("WHOLE-UNIT -Xverify:all (recompiled EdgeCases): verify_ok={ok} verify_fail={fail}");
    assert!(
        run.status.success() && fail == 0,
        "recompiled EdgeCases classes failed the real JVM verifier (verify_fail={fail}); a \
         javac-clean compile can still emit a classfile the JVM rejects (e.g. a synthetic \
         lambda$ helper colliding with javac's regenerated synthetic produces a duplicate \
         method ClassFormatError); stdout:\n{stdout}"
    );
}

fn decompile_gapcases() -> Option<String> {
    let jar: PathBuf = corpus(&["megafile", "GapCases-baseline.jar"]);
    let classes: Vec<(String, Vec<u8>)> = classes_from_jar(&jar)?;
    let (_n, bytes): &(String, Vec<u8>) = classes.iter().find(|(n, _)| n == "GapCases.class")?;
    let cf: ClassFile = parse_classfile(bytes).expect("parse GapCases");
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(n, _)| n.contains('$'))
        .filter_map(|(n, b)| parse_classfile(b).ok().map(|c| (n.clone(), c)))
        .collect();
    Some(decompile_class_with_inners(&cf, &inners).source)
}

#[test]
fn report_gapcases_family_recovery() {
    let Some(src): Option<String> = decompile_gapcases() else {
        eprintln!("skip: GapCases-baseline.jar absent");
        return;
    };

    let present: &[&str] = &[
        "assert arg0 > 0;",
        "assert arg0 > 0L : \"must be positive\";",
        "case \"one\":",
        "case \"two\":",
        "case \"three\":",
        "case \"x\":",
        "case \"y\":",
        "case \"Aa\":",
        "case \"BB\":",
        "case CALM:",
        "case HAPPY:",
        "case ANGRY:",
        "case WINTER:",
        "case SPRING:",
        "case SUMMER:",
    ];
    for token in present {
        assert!(
            src.contains(token),
            "family fidelity: decompiled GapCases is missing the recovered construct `{token}`; \
             a recompile-clean grade alone would silently pass while an int-labelled switch or a \
             raw AssertionError guard is emitted, so the ungraded families (switch-on-String, \
             switch-on-enum, assert) must be token-asserted. Source:\n{src}"
        );
    }

    let leaked: &[&str] = &[
        ".ordinal()",
        ".hashCode()",
        "$SwitchMap",
        "$assertionsDisabled",
    ];
    for token in leaked {
        assert!(
            !src.contains(token),
            "family fidelity: decompiled GapCases leaked compiler-plumbing token `{token}`; the \
             enum ordinal indirection, the String hashCode two-pass, the synthetic $SwitchMap map, \
             and the $assertionsDisabled guard must all be reconstructed away. Source:\n{src}"
        );
    }

    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "\n========================================================================\n\
             SKIPPED javac recompile of GapCases: javac not on PATH. Token fidelity was\n\
             checked, but the per-method recompile floor (>= {GAP_METHOD_OK_FLOOR} of\n\
             {GAP_METHOD_TOTAL}) did NOT run and is NOT enforced on this machine.\n\
             ========================================================================\n"
        );
        return;
    };
    let jar: PathBuf = corpus(&["megafile", "GapCases-baseline.jar"]);
    let purpose: String = format!("disrobe_gapcases_recompile_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let path: PathBuf = dir.join("GapCases.java");
    std::fs::write(&path, &src).expect("write");

    let out: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(&jar)
        .arg("-d")
        .arg(&dir)
        .arg(&path)
        .output()
        .expect("javac");
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stderr);

    let mut error_lines: Vec<usize> = Vec::new();
    for line in stderr.lines() {
        if let Some(rest) = line.split("GapCases.java:").nth(1)
            && let Some(num) = rest.split(':').next()
            && let Ok(n) = num.parse::<usize>()
        {
            error_lines.push(n);
        }
    }

    let ranges: Vec<(String, usize, usize)> = method_line_ranges(&src);
    let total: usize = ranges.len();
    let mut ok: usize = 0;
    for (_label, start, end) in &ranges {
        let has_error: bool = error_lines.iter().any(|&l| l >= *start && l < *end);
        if !has_error {
            ok += 1;
        }
    }
    eprintln!(
        "GAPCASES FAMILY RECOMPILE (switch-on-String, switch-on-enum, assert): {ok}/{total} \
         methods error-free; total javac errors: {}",
        error_lines.len()
    );
    assert_eq!(
        total, GAP_METHOD_TOTAL,
        "GapCases top-level method count drifted: {total} != {GAP_METHOD_TOTAL}; the family \
         recompile floor is denominator-pinned, recheck the fixture"
    );
    assert!(
        out.status.success() && ok >= GAP_METHOD_OK_FLOOR,
        "GapCases family recompile regressed: {ok}/{total} error-free < floor \
         {GAP_METHOD_OK_FLOOR}/{GAP_METHOD_TOTAL}; the assert / switch-on-String / switch-on-enum \
         reconstruction no longer produces javac-clean output. stderr:\n{stderr}"
    );
}

const ANNOTATION_PROBE_SRC: &str = r#"import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
public class AnnotationProbe {
    public static void main(String[] args) throws Exception {
        Class<?> target = Class.forName("EdgeCases$TaggedBox");
        Class<? extends Annotation> tagType = Class.forName("EdgeCases$Tagged")
            .asSubclass(Annotation.class);
        System.out.println("default:" + tagType.getDeclaredMethod("priority").getDefaultValue());
        Annotation[] tags = target.getDeclaredAnnotationsByType(tagType);
        for (Annotation tag : tags) {
            Method text = tag.annotationType().getDeclaredMethod("value");
            Method priority = tag.annotationType().getDeclaredMethod("priority");
            System.out.println(text.invoke(tag) + ":" + priority.invoke(tag));
        }
    }
}
"#;

fn run_annotation_probe(java: &PathBuf, classpath: std::ffi::OsString) -> String {
    let out: std::process::Output = Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(classpath)
        .arg("AnnotationProbe")
        .output()
        .expect("java annotation probe");
    assert!(
        out.status.success(),
        "annotation probe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n")
}

#[test]
fn repeatable_class_annotations_recompile_with_reflection_equivalence() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; annotation recovery gate NOT enforced");
        return;
    };
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP: java not on PATH; annotation reflection gate NOT enforced");
        return;
    };
    let jar: PathBuf = corpus(&["megafile", "EdgeCases-baseline.jar"]);
    let classes: Vec<(String, Vec<u8>)> =
        classes_from_jar(&jar).expect("tracked EdgeCases-baseline.jar");
    let (_name, bytes): &(String, Vec<u8>) = classes
        .iter()
        .find(|(name, _bytes)| name == "EdgeCases.class")
        .expect("EdgeCases.class in baseline jar");
    let cf: ClassFile = parse_classfile(bytes).expect("parse EdgeCases");
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(name, _bytes)| name.contains('$'))
        .filter_map(|(name, inner_bytes)| {
            parse_classfile(inner_bytes)
                .ok()
                .map(|inner| (name.clone(), inner))
        })
        .collect();
    let (_tagged_name, tagged_bytes): &(String, Vec<u8>) = classes
        .iter()
        .find(|(name, _bytes)| name == "EdgeCases$Tagged.class")
        .expect("EdgeCases$Tagged.class in baseline jar");
    let tagged_cf: ClassFile = parse_classfile(tagged_bytes).expect("parse EdgeCases$Tagged");
    let tagged_source: String = decompile_class(&tagged_cf).source;
    assert!(tagged_source.contains("@interface EdgeCases$Tagged"));
    assert!(!tagged_source.contains("extends java.lang.annotation.Annotation"));
    let source: String = decompile_class_with_inners(&cf, &inners).source;

    for token in [
        "@java.lang.annotation.Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)",
        "@EdgeCases.TaggedSet(value = {@EdgeCases.Tagged(value = \"alpha\", priority = 1), @EdgeCases.Tagged(value = \"beta\", priority = 2)})",
        "@java.lang.SafeVarargs\n    public static <T> java.util.List<T> safeVarargs(T... arg0)",
    ] {
        assert!(
            source.contains(token),
            "decompiled EdgeCases dropped declaration annotation `{token}`"
        );
    }

    let purpose: String = format!("disrobe_annotation_equivalence_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let original_dir: PathBuf = root.join("original");
    let recovered_dir: PathBuf = root.join("recovered");
    let standalone_dir: PathBuf = root.join("standalone");
    std::fs::create_dir_all(&original_dir).expect("mkdir original");
    std::fs::create_dir_all(&recovered_dir).expect("mkdir recovered");
    std::fs::create_dir_all(&standalone_dir).expect("mkdir standalone");

    let tagged_path: PathBuf = standalone_dir.join("EdgeCases$Tagged.java");
    std::fs::write(&tagged_path, &tagged_source).expect("write recovered annotation declaration");
    let tagged_built: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(&jar)
        .arg("-d")
        .arg(&standalone_dir)
        .arg(&tagged_path)
        .output()
        .expect("javac recovered annotation declaration");
    assert!(
        tagged_built.status.success(),
        "standalone annotation declaration did not compile: {}",
        String::from_utf8_lossy(&tagged_built.stderr)
    );

    let probe_path: PathBuf = original_dir.join("AnnotationProbe.java");
    std::fs::write(&probe_path, ANNOTATION_PROBE_SRC).expect("write annotation probe");
    let probe_built: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&original_dir)
        .arg(&probe_path)
        .output()
        .expect("javac annotation probe");
    assert!(
        probe_built.status.success(),
        "annotation probe did not compile: {}",
        String::from_utf8_lossy(&probe_built.stderr)
    );

    let source_path: PathBuf = recovered_dir.join("EdgeCases.java");
    std::fs::write(&source_path, &source).expect("write recovered EdgeCases");
    let recovered_built: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(&jar)
        .arg("-d")
        .arg(&recovered_dir)
        .arg(&source_path)
        .output()
        .expect("javac recovered EdgeCases");
    assert!(
        recovered_built.status.success(),
        "annotated recovered EdgeCases did not compile: {}",
        String::from_utf8_lossy(&recovered_built.stderr)
    );

    let original_cp: std::ffi::OsString =
        std::env::join_paths([original_dir.as_path(), jar.as_path()]).expect("original classpath");
    let recovered_cp: std::ffi::OsString =
        std::env::join_paths([recovered_dir.as_path(), original_dir.as_path()])
            .expect("recovered classpath");
    let original: String = run_annotation_probe(&java, original_cp);
    let recovered: String = run_annotation_probe(&java, recovered_cp);
    assert_eq!(original, "default:0\nalpha:1\nbeta:2\n");
    assert_eq!(recovered, original);
}

const CLASS_RETENTION_SRC: &str = r"import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
@Retention(RetentionPolicy.CLASS)
@interface ClassMark {
    int value();
}
@ClassMark(7)
class ClassMarked {}
";

fn javap_verbose(javap: &PathBuf, classpath: &PathBuf, class_name: &str) -> String {
    let out: std::process::Output = Command::new(javap)
        .arg("-v")
        .arg("-classpath")
        .arg(classpath)
        .arg(class_name)
        .output()
        .expect("javap verbose");
    assert!(
        out.status.success(),
        "javap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn runtime_invisible_class_annotation_recompiles_to_the_same_bucket() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; invisible annotation gate NOT enforced");
        return;
    };
    let Some(javap): Option<PathBuf> = find_on_path("javap") else {
        eprintln!("SKIP: javap not on PATH; invisible annotation gate NOT enforced");
        return;
    };
    let purpose: String = format!("disrobe_invisible_annotation_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let original_dir: PathBuf = root.join("original");
    let recovered_dir: PathBuf = root.join("recovered");
    std::fs::create_dir_all(&original_dir).expect("mkdir original");
    std::fs::create_dir_all(&recovered_dir).expect("mkdir recovered");
    let original_path: PathBuf = original_dir.join("ClassMarked.java");
    std::fs::write(&original_path, CLASS_RETENTION_SRC).expect("write class-retention source");
    let original_built: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&original_dir)
        .arg(&original_path)
        .output()
        .expect("javac class-retention source");
    assert!(
        original_built.status.success(),
        "class-retention fixture did not compile: {}",
        String::from_utf8_lossy(&original_built.stderr)
    );
    let original_bytes: Vec<u8> =
        std::fs::read(original_dir.join("ClassMarked.class")).expect("read original class");
    let original_cf: ClassFile = parse_classfile(&original_bytes).expect("parse original class");
    let recovered_source: String = decompile_class(&original_cf).source;
    assert!(recovered_source.contains("@ClassMark(value = 7)"));
    let recovered_path: PathBuf = recovered_dir.join("ClassMarked.java");
    std::fs::write(&recovered_path, recovered_source).expect("write recovered class");
    let recovered_built: std::process::Output = Command::new(&javac)
        .arg("-cp")
        .arg(&original_dir)
        .arg("-d")
        .arg(&recovered_dir)
        .arg(&recovered_path)
        .output()
        .expect("javac recovered class");
    assert!(
        recovered_built.status.success(),
        "recovered class-retention source did not compile: {}",
        String::from_utf8_lossy(&recovered_built.stderr)
    );
    for output in [
        javap_verbose(&javap, &original_dir, "ClassMarked"),
        javap_verbose(&javap, &recovered_dir, "ClassMarked"),
    ] {
        assert!(output.contains("RuntimeInvisibleAnnotations:"));
        assert!(!output.contains("RuntimeVisibleAnnotations:"));
    }
}

const MEMBER_ANNOTATION_SRC: &str = r#"import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
@interface MemberMark {
    String value();
    int rank();
}

@Retention(RetentionPolicy.CLASS)
@Target({ElementType.FIELD, ElementType.METHOD})
@interface HiddenMark {
    int value();
}

public class MemberAnnotated {
    @MemberMark(value = "field", rank = 1)
    @HiddenMark(11)
    public String value = "ready";

    @MemberMark(value = "method", rank = 2)
    @HiddenMark(22)
    public String read() {
        return value;
    }

    public static class Nested {
        @MemberMark(value = "nested-field", rank = 3)
        @HiddenMark(33)
        public String value = "nested";

        @MemberMark(value = "nested-method", rank = 4)
        @HiddenMark(44)
        public String read() {
            return value;
        }
    }

    public interface Contract {
        @MemberMark(value = "interface-field", rank = 5)
        @HiddenMark(55)
        int CODE = 7;
        boolean ENABLED = true;
        byte SMALL = -7;
        short LIMIT = 32000;
        char LETTER = 'Z';
        long EPOCH = 7L;
        float RATIO = 1.5f;
        double SCALE = 2.5;
        String LABEL = "contract";

        @MemberMark(value = "interface-method", rank = 6)
        @HiddenMark(66)
        String read();
    }

    public enum State {
        @MemberMark(value = "enum-constant", rank = 7)
        @HiddenMark(77)
        START,
        STOP
    }

    public enum EmptyState {
        ;

        @MemberMark(value = "empty-enum-method", rank = 9)
        @HiddenMark(99)
        public int code() {
            return 9;
        }
    }

    public enum ArgumentState {
        START(1);

        private final int code;

        ArgumentState(int code) {
            this.code = code;
        }
    }

    public Runnable task(String value) {
        return new Runnable() {
            @MemberMark(value = "val$value", rank = 8)
            @HiddenMark(88)
            public void run() {
                System.out.print(value);
            }
        };
    }
}

enum TopState {
    @MemberMark(value = "top-enum-constant", rank = 10)
    @HiddenMark(100)
    START,
    STOP;

    static int values(int value) {
        return value;
    }

    static int valueOf(int value) {
        return value + 1;
    }
}

enum ArgumentState {
    START(1);

    private final int code;

    ArgumentState(int code) {
        this.code = code;
    }
}

enum BodyState {
    START {
        int code() {
            return 1;
        }
    };

    abstract int code();
}

enum InitializedState {
    START;

    static {
        System.setProperty("member.annotation.initialized", "true");
    }
}
"#;

const MEMBER_PROBE_SRC: &str = r#"public class MemberProbe {
    public static void main(String[] args) throws Exception {
        Class<?> target = Class.forName("MemberAnnotated");
        MemberMark field = target.getField("value").getAnnotation(MemberMark.class);
        MemberMark method = target.getMethod("read").getAnnotation(MemberMark.class);
        Class<?> nested = Class.forName("MemberAnnotated$Nested");
        MemberMark nestedField = nested.getField("value").getAnnotation(MemberMark.class);
        MemberMark nestedMethod = nested.getMethod("read").getAnnotation(MemberMark.class);
        Class<?> contract = Class.forName("MemberAnnotated$Contract");
        MemberMark interfaceField = contract.getField("CODE").getAnnotation(MemberMark.class);
        MemberMark interfaceMethod = contract.getMethod("read").getAnnotation(MemberMark.class);
        Class<?> state = Class.forName("MemberAnnotated$State");
        MemberMark enumConstant = state.getField("START").getAnnotation(MemberMark.class);
        Class<?> emptyState = Class.forName("MemberAnnotated$EmptyState");
        MemberMark emptyEnumMethod = emptyState.getMethod("code").getAnnotation(MemberMark.class);
        Class<?> topState = Class.forName("TopState");
        MemberMark topEnumConstant = topState.getField("START").getAnnotation(MemberMark.class);
        MemberMark anonymousMethod = new MemberAnnotated().task("captured").getClass()
            .getMethod("run").getAnnotation(MemberMark.class);
        System.out.println(field.value() + ":" + field.rank());
        System.out.println(method.value() + ":" + method.rank());
        System.out.println(nestedField.value() + ":" + nestedField.rank());
        System.out.println(nestedMethod.value() + ":" + nestedMethod.rank());
        System.out.println(interfaceField.value() + ":" + interfaceField.rank());
        System.out.println("interface-value:" + contract.getField("CODE").getInt(null));
        System.out.println("interface-values:" + contract.getField("ENABLED").getBoolean(null)
            + ":" + contract.getField("SMALL").getByte(null)
            + ":" + contract.getField("LIMIT").getShort(null)
            + ":" + contract.getField("LETTER").getChar(null)
            + ":" + contract.getField("EPOCH").getLong(null)
            + ":" + contract.getField("RATIO").getFloat(null)
            + ":" + contract.getField("SCALE").getDouble(null)
            + ":" + contract.getField("LABEL").get(null));
        System.out.println(interfaceMethod.value() + ":" + interfaceMethod.rank());
        System.out.println(enumConstant.value() + ":" + enumConstant.rank());
        System.out.println(emptyEnumMethod.value() + ":" + emptyEnumMethod.rank());
        System.out.println(topEnumConstant.value() + ":" + topEnumConstant.rank());
        System.out.println("enum-overloads:" + TopState.values(10) + ":" + TopState.valueOf(10));
        System.out.println(anonymousMethod.value() + ":" + anonymousMethod.rank());
    }
}
"#;

fn semantic_method_code(cf: &ClassFile, method_name: &str) -> Vec<String> {
    let method: &MethodInfo = cf
        .methods
        .iter()
        .find(|method: &&MethodInfo| {
            cf.utf8_at(method.name_index)
                .is_ok_and(|name: &str| name == method_name)
        })
        .expect("method present");
    let code_attr: &Attribute = method
        .attributes
        .iter()
        .find(|attr: &&Attribute| {
            cf.utf8_at(attr.name_index)
                .is_ok_and(|name: &str| name == "Code")
        })
        .expect("Code attribute present");
    let code: disrobe_pass_jvm::bytecode::CodeAttribute =
        parse_code_attribute(&code_attr.info).expect("parse Code attribute");
    disassemble(&code.code)
        .expect("disassemble method")
        .iter()
        .map(|insn: &Instruction| {
            let operand: String = match &insn.operands {
                Operands::ConstPool(index) => resolve_ref(cf, *index)
                    .or_else(|| class_internal_name_at(cf, *index))
                    .unwrap_or_else(|| format!("cp:{index}")),
                Operands::InvokeInterface { index, count } => format!(
                    "{}:{count}",
                    resolve_ref(cf, *index).unwrap_or_else(|| format!("cp:{index}"))
                ),
                other => format!("{other:?}"),
            };
            format!("{:02x}:{operand}", insn.opcode)
        })
        .collect()
}

fn run_member_probe(java: &PathBuf, classpath: std::ffi::OsString) -> String {
    let out: std::process::Output = Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(classpath)
        .arg("MemberProbe")
        .output()
        .expect("java member probe");
    assert!(
        out.status.success(),
        "member annotation probe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n")
}

fn hidden_mark_values(javap_output: &str) -> Vec<i32> {
    let mut values: Vec<i32> = Vec::new();
    let mut inside_hidden_mark: bool = false;
    for line in javap_output.lines() {
        let trimmed: &str = line.trim();
        if trimmed == "HiddenMark(" {
            inside_hidden_mark = true;
            continue;
        }
        if inside_hidden_mark
            && let Some(value) = trimmed.strip_prefix("value=")
            && let Ok(parsed) = value.parse::<i32>()
        {
            values.push(parsed);
            inside_hidden_mark = false;
        }
    }
    values
}

#[test]
fn member_annotations_recompile_with_retention_and_runtime_equivalence() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; member annotation gate NOT enforced");
        return;
    };
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP: java not on PATH; member annotation gate NOT enforced");
        return;
    };
    let Some(javap): Option<PathBuf> = find_on_path("javap") else {
        eprintln!("SKIP: javap not on PATH; member annotation gate NOT enforced");
        return;
    };
    let purpose: String = format!("disrobe_member_annotation_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let original_dir: PathBuf = root.join("original");
    let recovered_dir: PathBuf = root.join("recovered");
    std::fs::create_dir_all(&original_dir).expect("mkdir original");
    std::fs::create_dir_all(&recovered_dir).expect("mkdir recovered");

    let original_path: PathBuf = original_dir.join("MemberAnnotated.java");
    std::fs::write(&original_path, MEMBER_ANNOTATION_SRC).expect("write member source");
    let original_built: std::process::Output = Command::new(&javac)
        .arg("-g:none")
        .arg("-d")
        .arg(&original_dir)
        .arg(&original_path)
        .output()
        .expect("javac member source");
    assert!(
        original_built.status.success(),
        "member annotation fixture did not compile: {}",
        String::from_utf8_lossy(&original_built.stderr)
    );
    let original_bytes: Vec<u8> = std::fs::read(original_dir.join("MemberAnnotated.class"))
        .expect("read original member class");
    let original_cf: ClassFile =
        parse_classfile(&original_bytes).expect("parse original member class");
    let mut inners: BTreeMap<String, ClassFile> = BTreeMap::new();
    for name in [
        "MemberAnnotated$1.class",
        "MemberAnnotated$ArgumentState.class",
        "MemberAnnotated$Contract.class",
        "MemberAnnotated$EmptyState.class",
        "MemberAnnotated$Nested.class",
        "MemberAnnotated$State.class",
    ] {
        let bytes: Vec<u8> =
            std::fs::read(original_dir.join(name)).expect("read original nested member class");
        inners.insert(
            name.to_string(),
            parse_classfile(&bytes).expect("parse original nested member class"),
        );
    }
    let recovered_source: String = decompile_class_with_inners(&original_cf, &inners).source;
    for token in [
        "@MemberMark(value = \"field\", rank = 1)\n    @HiddenMark(value = 11)\n    public String value",
        "@MemberMark(value = \"method\", rank = 2)\n    @HiddenMark(value = 22)\n    public String read()",
        "@MemberMark(value = \"nested-field\", rank = 3)\n        @HiddenMark(value = 33)\n        public String value",
        "@MemberMark(value = \"nested-method\", rank = 4)\n        @HiddenMark(value = 44)\n        public String read()",
        "@MemberMark(value = \"interface-field\", rank = 5)\n        @HiddenMark(value = 55)\n        public static final int CODE = 7;",
        "@MemberMark(value = \"interface-method\", rank = 6)\n        @HiddenMark(value = 66)\n        public abstract String read();",
        "@MemberMark(value = \"enum-constant\", rank = 7)\n        @HiddenMark(value = 77)\n        START,",
        "public static enum EmptyState {\n        ;",
        "@MemberMark(value = \"empty-enum-method\", rank = 9)",
        "private static final int disrobe_unresolved_enum_constants = 0;",
        "@MemberMark(value = \"val$value\", rank = 8)",
    ] {
        assert!(
            recovered_source.contains(token),
            "decompiled member declaration dropped annotation sequence `{token}`; source:\n{recovered_source}"
        );
    }

    let top_state_bytes: Vec<u8> =
        std::fs::read(original_dir.join("TopState.class")).expect("read original top enum");
    let top_state_cf: ClassFile =
        parse_classfile(&top_state_bytes).expect("parse original top enum");
    let recovered_top_state: String = decompile_class(&top_state_cf).source;
    assert!(
        recovered_top_state.contains(
            "@MemberMark(value = \"top-enum-constant\", rank = 10)\n    @HiddenMark(value = 100)\n    START,"
        ),
        "decompiled top enum dropped constant annotations; source:\n{recovered_top_state}"
    );
    assert!(recovered_top_state.contains("static int values(int arg0)"));
    assert!(recovered_top_state.contains("static int valueOf(int arg0)"));
    for name in ["ArgumentState", "BodyState", "InitializedState"] {
        let bytes: Vec<u8> =
            std::fs::read(original_dir.join(format!("{name}.class"))).expect("read enum class");
        let cf: ClassFile = parse_classfile(&bytes).expect("parse enum class");
        let source: String = decompile_class(&cf).source;
        assert!(
            source.contains("<unresolved-enum-constants>;"),
            "enum source-only constant state was not rejected: {source}"
        );
        assert!(!source.contains("sealed enum"));
        assert!(!source.contains(" permits "));
    }

    let recovered_path: PathBuf = recovered_dir.join("MemberAnnotated.java");
    std::fs::write(&recovered_path, &recovered_source).expect("write recovered member source");
    let recovered_top_state_path: PathBuf = recovered_dir.join("TopState.java");
    std::fs::write(&recovered_top_state_path, &recovered_top_state)
        .expect("write recovered top enum source");
    let recovered_built: std::process::Output = Command::new(&javac)
        .arg("-g:none")
        .arg("-cp")
        .arg(&original_dir)
        .arg("-d")
        .arg(&recovered_dir)
        .arg(&recovered_path)
        .arg(&recovered_top_state_path)
        .output()
        .expect("javac recovered member source");
    assert!(
        recovered_built.status.success(),
        "recovered member annotation source did not compile: {}",
        String::from_utf8_lossy(&recovered_built.stderr)
    );

    let probe_path: PathBuf = original_dir.join("MemberProbe.java");
    std::fs::write(&probe_path, MEMBER_PROBE_SRC).expect("write member probe");
    let probe_built: std::process::Output = Command::new(&javac)
        .arg("-cp")
        .arg(&original_dir)
        .arg("-d")
        .arg(&original_dir)
        .arg(&probe_path)
        .output()
        .expect("javac member probe");
    assert!(
        probe_built.status.success(),
        "member probe did not compile: {}",
        String::from_utf8_lossy(&probe_built.stderr)
    );
    let original_output: String = run_member_probe(&java, original_dir.clone().into_os_string());
    let recovered_cp: std::ffi::OsString =
        std::env::join_paths([recovered_dir.as_path(), original_dir.as_path()])
            .expect("recovered member classpath");
    let recovered_output: String = run_member_probe(&java, recovered_cp);
    assert_eq!(
        original_output,
        "field:1\nmethod:2\nnested-field:3\nnested-method:4\ninterface-field:5\ninterface-value:7\ninterface-values:true:-7:32000:Z:7:1.5:2.5:contract\ninterface-method:6\nenum-constant:7\nempty-enum-method:9\ntop-enum-constant:10\nenum-overloads:10:11\nval$value:8\n"
    );
    assert_eq!(recovered_output, original_output);

    for (class_name, expected_values) in [
        ("MemberAnnotated", vec![11, 22]),
        ("MemberAnnotated$1", vec![88]),
        ("MemberAnnotated$Contract", vec![55, 66]),
        ("MemberAnnotated$EmptyState", vec![99]),
        ("MemberAnnotated$Nested", vec![33, 44]),
        ("MemberAnnotated$State", vec![77]),
        ("TopState", vec![100]),
    ] {
        for classpath in [&original_dir, &recovered_dir] {
            let verbose: String = javap_verbose(&javap, classpath, class_name);
            assert_eq!(
                hidden_mark_values(&verbose),
                expected_values,
                "class-retention annotation payload drifted for {class_name}"
            );
        }
    }

    let recovered_bytes: Vec<u8> = std::fs::read(recovered_dir.join("MemberAnnotated.class"))
        .expect("read recovered member class");
    let recovered_cf: ClassFile =
        parse_classfile(&recovered_bytes).expect("parse recovered member class");
    assert_eq!(
        semantic_method_code(&recovered_cf, "read"),
        semantic_method_code(&original_cf, "read")
    );
}
