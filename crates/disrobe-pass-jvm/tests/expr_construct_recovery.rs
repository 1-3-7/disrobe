#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::io::Read as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{ClassFile, DecompiledClass, decompile_class, parse_classfile};

const METHOD_TOTAL: usize = 11;
const METHOD_OK_FLOOR: usize = 11;

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

fn decompile_battery() -> Option<String> {
    let jar: PathBuf = corpus(&["megafile", "ExprCases-baseline.jar"]);
    let f: std::fs::File = std::fs::File::open(&jar).ok()?;
    let mut z: zip::ZipArchive<std::fs::File> = zip::ZipArchive::new(f).expect("zip read");
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if entry.name() != "ExprCases.class" {
            continue;
        }
        let mut bytes: Vec<u8> = Vec::new();
        entry.read_to_end(&mut bytes).expect("read class");
        let cf: ClassFile = parse_classfile(&bytes).expect("parse ExprCases");
        let d: DecompiledClass = decompile_class(&cf);
        return Some(d.source);
    }
    None
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

#[test]
fn expr_constructs_recovered_no_holes() {
    let Some(src): Option<String> = decompile_battery() else {
        eprintln!("skip: ExprCases-baseline.jar absent");
        return;
    };

    assert!(
        !src.contains("__unresolved__"),
        "nested-ternary / switch-expression-yield recovery regressed: an __unresolved__ hole is \
         back in the decompiled battery (recovered source would fail javac). Source:\n{src}"
    );

    let present: &[&str] = &[
        "return (arg0 > 0 ? (arg1 > 0 ? arg2 : arg3) : arg4);",
        "return (arg0 > 0 ? arg4 : (arg1 > 0 ? arg2 : arg3));",
        "return (arg0 > 0 ? (arg1 > 0 ? arg2 : arg3) : (arg4 > 0 ? arg5 : arg6));",
        "(arg0 > 100 ? \"huge\" : (arg0 > 10 ? \"big\" : (arg0 > 0 ? \"small\" : \"neg\")))",
        "case 1, 7 -> 0;",
        "yield var1;",
    ];
    for token in present {
        assert!(
            src.contains(token),
            "construct fidelity: decompiled ExprCases is missing the recovered construct `{token}`; \
             a nested ternary or a switch-expression yield arm no longer lifts. Source:\n{src}"
        );
    }
    assert!(
        src.contains("-> {"),
        "construct fidelity: the block-bodied switch-expression arm (`case ... -> {{ ...; yield ...; }}`) \
         did not recover. Source:\n{src}"
    );
}

#[test]
fn expr_constructs_recompile_and_verify() {
    let Some(src): Option<String> = decompile_battery() else {
        eprintln!("skip: ExprCases-baseline.jar absent");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "\n========================================================================\n\
             SKIPPED javac recompile of ExprCases: javac not on PATH. Token fidelity was\n\
             checked, but the per-method recompile floor (>= {METHOD_OK_FLOOR} of\n\
             {METHOD_TOTAL}) did NOT run and is NOT enforced on this machine.\n\
             ========================================================================\n"
        );
        return;
    };

    let purpose: String = format!("disrobe_expr_construct_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let path: PathBuf = dir.join("ExprCases.java");
    std::fs::write(&path, &src).expect("write");

    let out: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("--release")
        .arg("21")
        .arg("-d")
        .arg(&dir)
        .arg(&path)
        .output()
        .expect("javac");
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stderr);

    let mut error_lines: Vec<usize> = Vec::new();
    for line in stderr.lines() {
        if let Some(rest) = line.split("ExprCases.java:").nth(1)
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
        "EXPR CONSTRUCT RECOMPILE (nested ternary, switch-expression yield): {ok}/{total} methods \
         error-free; total javac errors: {}",
        error_lines.len()
    );
    assert_eq!(
        total, METHOD_TOTAL,
        "ExprCases method count drifted: {total} != {METHOD_TOTAL}; the recompile floor is \
         denominator-pinned, recheck the fixture"
    );
    assert!(
        out.status.success() && ok >= METHOD_OK_FLOOR,
        "ExprCases construct recompile regressed: {ok}/{total} error-free < floor \
         {METHOD_OK_FLOOR}/{METHOD_TOTAL}; the nested-ternary or switch-expression-yield \
         reconstruction no longer produces javac-clean output. stderr:\n{stderr}"
    );

    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP -Xverify:all gate: java not on PATH");
        return;
    };

    let loader: PathBuf = dir.join("Load.java");
    std::fs::write(
        &loader,
        "public class Load {\n\
         \x20   public static void main(String[] a) throws Exception {\n\
         \x20       Class.forName(\"ExprCases\", true, Load.class.getClassLoader());\n\
         \x20       System.out.println(\"verify_ok=1 verify_fail=0\");\n\
         \x20   }\n\
         }\n",
    )
    .expect("write loader");
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
    let verified: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(&dir)
        .arg("Load")
        .output()
        .expect("java -Xverify:all");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&verified.stdout);
    let fail: usize = stdout
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("verify_fail="))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    eprintln!("EXPR CONSTRUCT -Xverify:all (recompiled ExprCases): verify_fail={fail}");
    assert!(
        verified.status.success() && fail == 0,
        "recompiled ExprCases failed the real JVM verifier (verify_fail={fail}); stdout:\n{stdout}\n\
         stderr:\n{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}
