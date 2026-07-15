#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{ClassFile, decompile_class, parse_classfile};

const FIXTURE: &str = r"public class NarrowArgs {
    static int takeByte(byte b) { return b; }
    static int takeChar(char c) { return c; }
    static int takeShort(short s) { return s; }
    static int takeAll(byte b, char c, short s) { return b + c + s; }
    static String append(char c) {
        StringBuilder sb = new StringBuilder();
        sb.append((char) 65);
        sb.append(c);
        return sb.toString();
    }
    public static void main(String[] args) {
        System.out.println(takeByte((byte) -1));
        System.out.println(takeChar((char) 65535));
        System.out.println(takeShort((short) 40000));
        System.out.println(takeByte((byte) 200));
        System.out.println(takeChar((char) 65));
        System.out.println(takeShort((short) -1));
        System.out.println(takeAll((byte) 127, (char) 1000, (short) -500));
        System.out.println(append((char) 66));
    }
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

fn javac(javac_path: &PathBuf, dir: &PathBuf, file: &PathBuf) -> (bool, String) {
    let out: std::process::Output = Command::new(javac_path)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(dir)
        .arg(file)
        .output()
        .expect("javac");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_class(java_path: &PathBuf, dir: &PathBuf, class: &str) -> (bool, String) {
    let out: std::process::Output = Command::new(java_path)
        .arg("-cp")
        .arg(dir)
        .arg(class)
        .output()
        .expect("java");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn narrow_typed_constant_arguments_keep_their_cast_and_recompile() {
    let Some(javac_path): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "SKIP: javac not on PATH; narrow-argument cast recompile-and-eval gate NOT enforced. \
             CORPUS-BLOCKED for byte/char/short constant arguments to invoked methods."
        );
        return;
    };
    let Some(java_path): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP: java not on PATH; narrow-argument cast eval gate NOT enforced.");
        return;
    };
    let root: PathBuf =
        std::env::temp_dir().join(format!("disrobe_narrow_arg_{}", std::process::id()));
    let gold: PathBuf = root.join("gold");
    let recov: PathBuf = root.join("recov");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&gold).expect("mkdir gold");
    std::fs::create_dir_all(&recov).expect("mkdir recov");

    let gold_src: PathBuf = gold.join("NarrowArgs.java");
    std::fs::write(&gold_src, FIXTURE).expect("write fixture");
    let (gold_ok, gold_err): (bool, String) = javac(&javac_path, &gold, &gold_src);
    assert!(gold_ok, "reference fixture did not compile: {gold_err}");
    let (gold_run_ok, gold_out): (bool, String) = run_class(&java_path, &gold, "NarrowArgs");
    assert!(gold_run_ok, "reference fixture did not run: {gold_out}");

    let gold_bytes: Vec<u8> =
        std::fs::read(gold.join("NarrowArgs.class")).expect("read gold class");
    let gold_cf: ClassFile = parse_classfile(&gold_bytes).expect("parse gold");
    let recovered: String = decompile_class(&gold_cf).source;

    let recov_src: PathBuf = recov.join("NarrowArgs.java");
    std::fs::write(&recov_src, &recovered).expect("write recovered");
    let (recov_ok, recov_err): (bool, String) = javac(&javac_path, &recov, &recov_src);
    assert!(
        recov_ok,
        "recovered NarrowArgs did not recompile under real javac; a byte/char/short constant \
         argument lost its narrowing cast (method invocation forbids implicit constant narrowing). \
         javac: {recov_err}\nrecovered source:\n{recovered}"
    );

    let (recov_run_ok, recov_out): (bool, String) = run_class(&java_path, &recov, "NarrowArgs");
    assert!(
        recov_run_ok,
        "recovered NarrowArgs did not run: {recov_out}"
    );

    assert_eq!(
        gold_out, recov_out,
        "recovered NarrowArgs evaluated to different values than the reference; \
         a narrowing cast on an invoked argument was dropped or mis-typed.\nrecovered source:\n{recovered}"
    );
}
