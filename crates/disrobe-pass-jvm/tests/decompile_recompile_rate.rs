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

    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_multi_class_recompile_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
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

    let dir: PathBuf = std::env::temp_dir().join("disrobe_per_method_recompile");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
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

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_verify_gate_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
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
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_gapcases_recompile_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
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
