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
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn try_finally_with_return_recompiles_to_equivalent_bytecode() {
    let (Some(javac), Some(javap)): (Option<PathBuf>, Option<PathBuf>) =
        (find_on_path("javac"), find_on_path("javap"))
    else {
        eprintln!(
            "skip: javac/javap not on PATH; try/finally-return equivalence gate not enforced"
        );
        return;
    };

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
