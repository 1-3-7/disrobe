#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{ClassFile, decompile_class, parse_classfile};

const FIXTURE: &str = r"public class ForMulti {
    static String valueMulti(String s) {
        try { return s.substring(Integer.parseInt(s)); }
        catch (NumberFormatException | IndexOutOfBoundsException e) { return e.getClass().getSimpleName(); }
    }
    static void voidMulti(Runnable r) {
        try { r.run(); }
        catch (RuntimeException | Error e) { System.out.println(e); }
    }
    static int distinctCatch(String s) {
        try { return Integer.parseInt(s); }
        catch (NumberFormatException e) { return -1; }
        catch (IllegalStateException e) { return -2; }
    }
    static int arraySum(int[] xs) { int a = 0; for (int x : xs) a += x; return a; }
    static double doubleSum(double[] xs) { double a = 0; for (double x : xs) a += x; return a; }
    static int strLens(String[] arr) { int t = 0; for (String s : arr) t += s.length(); return t; }
    static int objIter(java.util.List xs) { int a = 0; for (Object o : xs) a += o.hashCode(); return a; }
    static int genericIter(java.util.List<Integer> xs) { int a = 0; for (Integer x : xs) a += x; return a; }
}
";

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

fn method_body(source: &str, signature_fragment: &str) -> String {
    let start: usize = source
        .find(signature_fragment)
        .unwrap_or_else(|| panic!("method `{signature_fragment}` missing from:\n{source}"));
    let open: usize = source[start..].find('{').expect("method open brace") + start;
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 0;
    let mut i: usize = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source[open..=i].to_string();
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unterminated method body for `{signature_fragment}`");
}

fn compile_and_decompile(javac: &PathBuf) -> String {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_foreach_multicatch_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let src: PathBuf = dir.join("ForMulti.java");
    std::fs::write(&src, FIXTURE).expect("write fixture");
    let compiled: std::process::Output = Command::new(javac)
        .arg("-d")
        .arg(&dir)
        .arg(&src)
        .output()
        .expect("javac fixture");
    assert!(
        compiled.status.success(),
        "fixture did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes: Vec<u8> = std::fs::read(dir.join("ForMulti.class")).expect("read ForMulti.class");
    let cf: ClassFile = parse_classfile(&bytes).expect("parse ForMulti");
    decompile_class(&cf).source
}

#[test]
fn multi_catch_union_and_distinct_catches_recover() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; multi-catch recovery not enforced");
        return;
    };
    let source: String = compile_and_decompile(&javac);

    let value_multi: String = method_body(&source, "valueMulti(");
    assert!(
        value_multi.contains("catch (NumberFormatException | IndexOutOfBoundsException"),
        "value-returning multi-catch must recover a union catch; got:\n{value_multi}"
    );
    assert!(
        value_multi.contains("try {") && value_multi.contains("return arg0.substring("),
        "the protected `return` must sit inside the try body, not escape it; got:\n{value_multi}"
    );
    let try_at: usize = value_multi.find("try {").expect("try in valueMulti");
    let after_try: &str = value_multi[try_at + "try {".len()..].trim_start();
    assert!(
        !after_try.starts_with('}'),
        "valueMulti emitted an empty try body; got:\n{value_multi}"
    );

    let void_multi: String = method_body(&source, "voidMulti(");
    assert!(
        void_multi.contains("catch (RuntimeException | Error"),
        "void multi-catch must recover a union catch; got:\n{void_multi}"
    );

    let distinct: String = method_body(&source, "distinctCatch(");
    assert!(
        distinct.contains("catch (NumberFormatException")
            && distinct.contains("catch (IllegalStateException"),
        "distinct handler blocks must stay as separate catches; got:\n{distinct}"
    );
    assert!(
        !distinct.contains("NumberFormatException | IllegalStateException"),
        "distinct catches must not be merged into a union; got:\n{distinct}"
    );
}

#[test]
fn enhanced_for_lowerings_recover_or_degrade() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; enhanced-for recovery not enforced");
        return;
    };
    let source: String = compile_and_decompile(&javac);

    for (sig, needle) in [
        ("arraySum(", "for (int "),
        ("doubleSum(", "for (double "),
        ("strLens(", "for (String "),
        ("objIter(", "for (Object "),
    ] {
        let body: String = method_body(&source, sig);
        assert!(
            body.contains(needle) && body.contains(": arg0)"),
            "{sig} must reconstruct an enhanced-for `{needle}... : arg0)`; got:\n{body}"
        );
        assert!(
            !body.contains(".hasNext()") && !body.contains(".length;"),
            "{sig} enhanced-for must not leave the lowered iterator/index scaffolding; got:\n{body}"
        );
    }

    let generic: String = method_body(&source, "genericIter(");
    assert!(
        generic.contains("for (Integer") && generic.contains(": arg0)"),
        "a Signature-backed generic collection must recover its typed enhanced-for; got:\n{generic}"
    );
    assert!(
        !generic.contains(".iterator()") && !generic.contains(".hasNext()"),
        "a typed enhanced-for must not retain iterator scaffolding; got:\n{generic}"
    );
}

#[test]
fn recovered_foreach_multicatch_recompiles_clean() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; recompile gate not enforced");
        return;
    };
    let source: String = compile_and_decompile(&javac);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_foreach_multicatch_recompile_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path: PathBuf = dir.join("ForMulti.java");
    std::fs::write(&path, &source).expect("write recovered source");
    let out: std::process::Output = Command::new(&javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(&dir)
        .arg(&path)
        .output()
        .expect("javac recovered");
    assert!(
        out.status.success(),
        "recovered ForMulti did not recompile clean:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&out.stderr)
    );
}
