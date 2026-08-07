#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{ClassFile, DecompiledClass, decompile_class, parse_classfile};

const TRY_FINALLY_RETURN_SRC: &str = "public class TryFinallyReturn {\n\
    static int CTR = 0;\n\
    static int retInTry(int a, int b) {\n\
        try {\n\
            CTR = a + b;\n\
            return a * b;\n\
        } finally {\n\
            CTR++;\n\
        }\n\
    }\n\
    static void voidTry(int a) {\n\
        try {\n\
            CTR = a;\n\
            return;\n\
        } finally {\n\
            CTR++;\n\
        }\n\
    }\n\
    static String strRet(String s) {\n\
        try {\n\
            return s.trim();\n\
        } finally {\n\
            CTR++;\n\
        }\n\
    }\n\
    static long longRet(long a) {\n\
        try {\n\
            return a * 2L;\n\
        } finally {\n\
            CTR++;\n\
        }\n\
    }\n\
    static int noReturnTry(int a) {\n\
        int r = 0;\n\
        try {\n\
            r = a * a;\n\
        } finally {\n\
            CTR++;\n\
        }\n\
        return r;\n\
    }\n\
    static int finallyReturns(int a) {\n\
        try {\n\
            CTR = a;\n\
            return a * 2;\n\
        } finally {\n\
            return a + 1;\n\
        }\n\
    }\n\
    static void voidFinallyReturns(int a) {\n\
        try {\n\
            CTR = a;\n\
        } finally {\n\
            return;\n\
        }\n\
    }\n\
    static String strFinallyReturns(String s) {\n\
        try {\n\
            return s.trim();\n\
        } finally {\n\
            return s;\n\
        }\n\
    }\n\
    static int multiReturnTry(int a) {\n\
        try {\n\
            if (a >= 1) { return a; }\n\
            return -a;\n\
        } finally {\n\
            CTR++;\n\
        }\n\
    }\n\
    static long longFinallyReturns(long a) {\n\
        try {\n\
            return a * 2L;\n\
        } finally {\n\
            return a + 1L;\n\
        }\n\
    }\n\
    static float floatFinallyReturns(float a) {\n\
        try {\n\
            return a * 2.0f;\n\
        } finally {\n\
            return a + 1.0f;\n\
        }\n\
    }\n\
    static double doubleFinallyReturns(double a) {\n\
        try {\n\
            return a * 2.0;\n\
        } finally {\n\
            return a + 1.0;\n\
        }\n\
    }\n\
    static Object objFinallyReturns(Object o) {\n\
        try {\n\
            return o.toString();\n\
        } finally {\n\
            return o;\n\
        }\n\
    }\n\
    static int emptyFinally(int a) {\n\
        try {\n\
            return a * 3;\n\
        } finally {\n\
        }\n\
    }\n\
}\n";

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
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

fn require_jdk_tools() -> (PathBuf, PathBuf) {
    let javac: PathBuf = find_on_path("javac")
        .unwrap_or_else(|| panic!("try-finally return gate requires javac and javap on PATH"));
    let javap: PathBuf = find_on_path("javap")
        .unwrap_or_else(|| panic!("try-finally return gate requires javac and javap on PATH"));
    (javac, javap)
}

fn normalize_javap(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let trimmed: &str = line.trim_end();
        if trimmed.is_empty()
            || trimmed.starts_with("Classfile")
            || trimmed.starts_with("Last modified")
            || trimmed.contains("SHA-256")
            || trimmed.contains("MD5")
            || trimmed.starts_with("Compiled from")
            || trimmed.trim_start().starts_with("flags:")
        {
            continue;
        }
        let mut cleaned: String = String::with_capacity(trimmed.len());
        let mut chars = trimmed.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '#' {
                while chars.peek().is_some_and(|d: &char| d.is_ascii_digit()) {
                    let _ = chars.next();
                }
                cleaned.push('#');
            } else {
                cleaned.push(c);
            }
        }
        out.push(cleaned);
    }
    out
}

fn javap_code(javap: &PathBuf, class_dir: &PathBuf, class: &str) -> String {
    let out: std::process::Output = Command::new(javap)
        .arg("-c")
        .arg("-p")
        .arg("-cp")
        .arg(class_dir)
        .arg(class)
        .output()
        .expect("javap");
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "javap failed for {class}; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Code:"),
        "javap produced no bytecode for {class}; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

#[test]
fn javap_code_fails_closed_when_the_tool_rejects_its_arguments() {
    let test_binary: PathBuf = std::env::current_exe().expect("current test binary");
    let class_dir: PathBuf = std::env::temp_dir();
    let result: Result<String, Box<dyn std::any::Any + Send>> =
        std::panic::catch_unwind(|| javap_code(&test_binary, &class_dir, "NoSuchClass"));
    assert!(
        result.is_err(),
        "a failing javap process returned an empty comparison input instead of failing the gate"
    );
}

#[test]
fn try_finally_with_return_recompiles_to_equivalent_bytecode() {
    let (javac, javap): (PathBuf, PathBuf) = require_jdk_tools();

    let purpose: String = format!("disrobe_tf_return_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let orig_dir: PathBuf = dir.join("orig");
    let rec_dir: PathBuf = dir.join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let src_path: PathBuf = orig_dir.join("TryFinallyReturn.java");
    std::fs::write(&src_path, TRY_FINALLY_RETURN_SRC).expect("write src");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&orig_dir)
        .arg(&src_path)
        .output()
        .expect("javac orig");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let class_bytes: Vec<u8> =
        std::fs::read(orig_dir.join("TryFinallyReturn.class")).expect("read class");
    let cf: ClassFile = parse_classfile(&class_bytes).expect("parse");
    let decompiled: DecompiledClass = decompile_class(&cf);

    assert!(
        !decompiled.source.contains("(stack reset)"),
        "decompiled output left a lifting hole:\n{}",
        decompiled.source
    );
    assert!(
        !decompiled.source.contains("catch (Throwable"),
        "a finally whose body returns was rendered as a catch clause, which is different java \
         than the class declares:\n{}",
        decompiled.source
    );

    let rec_src: PathBuf = rec_dir.join("TryFinallyReturn.java");
    std::fs::write(&rec_src, &decompiled.source).expect("write rec");
    let recompile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&rec_dir)
        .arg(&rec_src)
        .output()
        .expect("javac rec");
    assert!(
        recompile.status.success(),
        "recovered try/finally source did not recompile under real javac:\n{}\n---source---\n{}",
        String::from_utf8_lossy(&recompile.stderr),
        decompiled.source
    );

    let orig_code: Vec<String> =
        normalize_javap(&javap_code(&javap, &orig_dir, "TryFinallyReturn"));
    let rec_code: Vec<String> = normalize_javap(&javap_code(&javap, &rec_dir, "TryFinallyReturn"));
    assert_eq!(
        orig_code, rec_code,
        "recompiled try/finally bytecode is not instruction/exception-table equivalent to the \
         original.\n--- recovered source ---\n{}",
        decompiled.source
    );
}

const UNMODELLED_FINALLY_SRC: &str = "public class UnmodelledFinally {\n\
    static int CTR = 0;\n\
    static int finallyWithIf(int a) {\n\
        try {\n\
            return a * 2;\n\
        } finally {\n\
            if (a > 0) { CTR++; } else { CTR--; }\n\
        }\n\
    }\n\
    static int finallyBreaks(int[] xs) {\n\
        int acc = 0;\n\
        for (int x : xs) {\n\
            try {\n\
                acc += x;\n\
            } finally {\n\
                if (acc > 5) { break; }\n\
            }\n\
        }\n\
        return acc;\n\
    }\n\
    static int finallyContinues(int[] xs) {\n\
        int acc = 0;\n\
        for (int x : xs) {\n\
            try {\n\
                acc += x;\n\
            } finally {\n\
                if (acc > 5) { continue; }\n\
                acc += 100;\n\
            }\n\
        }\n\
        return acc;\n\
    }\n\
    static int finallyNestedTry(int a, int b) {\n\
        try {\n\
            return a / b;\n\
        } finally {\n\
            try {\n\
                CTR += a / b;\n\
            } catch (ArithmeticException ex) {\n\
                CTR = -1;\n\
            }\n\
        }\n\
    }\n\
    static int finallyThrows(int a) {\n\
        try {\n\
            return a;\n\
        } finally {\n\
            if (a < 0) { throw new IllegalStateException(\"neg\"); }\n\
        }\n\
    }\n\
}\n";

const UNMODELLED_FINALLY_METHODS: &[&str] = &[
    "finallyWithIf",
    "finallyBreaks",
    "finallyContinues",
    "finallyNestedTry",
    "finallyThrows",
];

#[test]
fn a_finally_shape_the_structurer_cannot_model_is_refused_rather_than_turned_into_a_catch() {
    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();

    let purpose: String = format!("disrobe_unmodelled_finally_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let orig_dir: PathBuf = dir.join("orig");
    let rec_dir: PathBuf = dir.join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let src_path: PathBuf = orig_dir.join("UnmodelledFinally.java");
    std::fs::write(&src_path, UNMODELLED_FINALLY_SRC).expect("write src");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&orig_dir)
        .arg(&src_path)
        .output()
        .expect("javac orig");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let class_bytes: Vec<u8> =
        std::fs::read(orig_dir.join("UnmodelledFinally.class")).expect("read class");
    let cf: ClassFile = parse_classfile(&class_bytes).expect("parse");
    let decompiled: DecompiledClass = decompile_class(&cf);

    assert!(
        !decompiled.source.contains("catch (Throwable"),
        "a compiler-inserted finally was rendered as a catch clause, which changes what the \
         method does with a pending exception:\n{}",
        decompiled.source
    );
    for method in UNMODELLED_FINALLY_METHODS {
        assert!(
            decompiled.source.contains(method),
            "method {method} vanished from the recovered class:\n{}",
            decompiled.source
        );
    }
    assert_eq!(
        decompiled.source.matches("not recovered:").count(),
        UNMODELLED_FINALLY_METHODS.len(),
        "every finally shape the structurer cannot model must name its own refusal reason:\n{}",
        decompiled.source
    );

    let rec_src: PathBuf = rec_dir.join("UnmodelledFinally.java");
    std::fs::write(&rec_src, &decompiled.source).expect("write rec");
    let recompile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&rec_dir)
        .arg(&rec_src)
        .output()
        .expect("javac rec");
    assert!(
        recompile.status.success(),
        "a refused method must still leave the class compilable:\n{}\n---source---\n{}",
        String::from_utf8_lossy(&recompile.stderr),
        decompiled.source
    );
}

#[test]
fn try_finally_return_gate_fails_when_jdk_tools_are_unavailable() {
    let test_binary: PathBuf = std::env::current_exe().expect("current test binary");
    let output: std::process::Output = Command::new(test_binary)
        .arg("--exact")
        .arg("try_finally_with_return_recompiles_to_equivalent_bytecode")
        .arg("--test-threads=1")
        .env("PATH", "")
        .output()
        .expect("run try-finally return gate without JDK tools");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the try-finally return gate passed without JDK tools; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        format!("{stdout}\n{stderr}")
            .contains("try-finally return gate requires javac and javap on PATH"),
        "the try-finally return gate failed for an unrelated reason; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
