#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{ClassFile, decompile_class, parse_classfile};

const PREC_FIXTURE: &str = r#"public class PrecCases {
    static int subAssoc(int a, int b, int c) { return a - (b - c); }
    static int divAssoc(int a, int b, int c) { return a / (b / c); }
    static int modAssoc(int a, int b, int c) { return a % (b % c); }
    static int subChain(int a, int b, int c) { return a - b - c; }
    static int orAnd(int a, int b, int c) { return (a | b) & c; }
    static int shiftAdd(int a, int b, int c) { return a << (b + c); }
    static int addShift(int a, int b, int c) { return a + (b << c); }
    static int addUshr(int a, int b, int c) { return a + (b >>> c); }
    static int negBin(int a, int b) { return -(a - b); }
    static int negChain(int a, int b, int c) { return -a - (b - c); }
    static int mulAdd(int a, int b, int c) { return a * (b + c); }
    static int subAdd(int a, int b, int c) { return a - (b + c); }
    static int xorOr(int a, int b, int c) { return (a ^ b) | c; }
    static int shiftShift(int a, int b, int c) { return a >> (b >> c); }
    static int nested(int a, int b, int c, int d, int e) { return a > 0 ? (b > 0 ? c : d) : e; }
    static int ternOperand(int a, int b, int c) { return 100 - (a > 0 ? b : c); }
    static long longSub(long a, long b, long c) { return a - (b - c); }
    static long longMul(long a, long b, long c) { return a * (b - c); }
    static boolean andOr(int a, int b, int c) { return a > 0 && b > 0 || c > 0; }
    static boolean orAnd2(int a, int b, int c) { return a > 0 || b > 0 && c > 0; }
    static boolean deep(int a, int b, int c, int d) { return (a > 0 || b > 0) && (c > 0 || d > 0); }
    public static void main(String[] x) {
        System.out.println(subAssoc(20, 8, 3));
        System.out.println(divAssoc(64, 8, 2));
        System.out.println(modAssoc(23, 10, 4));
        System.out.println(subChain(20, 8, 3));
        System.out.println(orAnd(5, 2, 3));
        System.out.println(shiftAdd(1, 2, 3));
        System.out.println(addShift(1, 2, 3));
        System.out.println(addUshr(1, -1, 1));
        System.out.println(negBin(5, 8));
        System.out.println(negChain(5, 8, 3));
        System.out.println(mulAdd(2, 3, 4));
        System.out.println(subAdd(20, 8, 3));
        System.out.println(xorOr(6, 3, 8));
        System.out.println(shiftShift(1024, 3, 1));
        System.out.println(nested(1, -1, 7, 9, 4));
        System.out.println(ternOperand(20, 1, -5));
        System.out.println(longSub(20L, 8L, 3L));
        System.out.println(longMul(4L, 3L, 10L));
        for (int m = 0; m < 16; m++) {
            int a = ((m & 1) != 0) ? 1 : -1;
            int b = ((m & 2) != 0) ? 1 : -1;
            int c = ((m & 4) != 0) ? 1 : -1;
            int d = ((m & 8) != 0) ? 1 : -1;
            System.out.println(andOr(a, b, c) + "," + orAnd2(a, b, c) + "," + deep(a, b, c, d));
        }
    }
}
"#;

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

fn javac(javac: &PathBuf, dir: &PathBuf, file: &PathBuf) -> (bool, String) {
    let out: std::process::Output = Command::new(javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(dir)
        .arg(file)
        .output()
        .expect("javac runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_probe(java: &PathBuf, dir: &PathBuf) -> (bool, String) {
    let out: std::process::Output = Command::new(java)
        .arg("-cp")
        .arg(dir)
        .arg("PrecCases")
        .output()
        .expect("java runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
    )
}

#[test]
fn precedence_parenthesization_recompiles_to_same_jvm_output() {
    let (Some(javac_p), Some(java_p)): (Option<PathBuf>, Option<PathBuf>) =
        (find_on_path("javac"), find_on_path("java"))
    else {
        eprintln!(
            "SKIP: no JDK on PATH; the recompile-and-eval precedence gate is NOT enforced on \
             this machine."
        );
        return;
    };

    let purpose: String = format!("disrobe_prec_recompile_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let gold: PathBuf = root.join("gold");
    let recov: PathBuf = root.join("recov");
    std::fs::create_dir_all(&gold).expect("mkdir gold");
    std::fs::create_dir_all(&recov).expect("mkdir recov");

    let gold_src: PathBuf = gold.join("PrecCases.java");
    std::fs::write(&gold_src, PREC_FIXTURE).expect("write fixture");
    let (gold_ok, gold_err): (bool, String) = javac(&javac_p, &gold, &gold_src);
    assert!(gold_ok, "reference fixture did not compile: {gold_err}");
    let (gold_run_ok, gold_out): (bool, String) = run_probe(&java_p, &gold);
    assert!(gold_run_ok, "reference fixture did not run under the JVM");

    let gold_bytes: Vec<u8> = std::fs::read(gold.join("PrecCases.class")).expect("read gold class");
    let cf: ClassFile = parse_classfile(&gold_bytes).expect("parse gold");
    let recovered: String = decompile_class(&cf).source;

    let load_bearing: &[&str] = &[
        "(arg0 - (arg1 - arg2))",
        "(arg0 / (arg1 / arg2))",
        "(arg0 % (arg1 % arg2))",
        "((arg0 | arg1) & arg2)",
        "(arg0 << (arg1 + arg2))",
        "(arg0 + (arg1 << arg2))",
        "(arg0 + (arg1 >>> arg2))",
        "(-(arg0 - arg1))",
        "(arg0 * (arg1 + arg2))",
        "(arg0 - (arg1 + arg2))",
        "((arg0 ^ arg1) | arg2)",
        "(arg0 >> (arg1 >> arg2))",
        "(arg0 > 0 ? (arg1 > 0 ? arg2 : arg3) : arg4)",
        "(100 - (arg0 > 0 ? arg1 : arg2))",
    ];
    for token in load_bearing {
        assert!(
            recovered.contains(token),
            "a load-bearing parenthesization `{token}` is missing from the recovered source; a \
             dropped paren would silently change the computed value. recovered:\n{recovered}"
        );
    }

    let recov_src: PathBuf = recov.join("PrecCases.java");
    std::fs::write(&recov_src, &recovered).expect("write recovered");
    let (recov_ok, recov_err): (bool, String) = javac(&javac_p, &recov, &recov_src);
    assert!(
        recov_ok,
        "recovered PrecCases did not recompile under real javac: {recov_err}\nrecovered:\n{recovered}"
    );
    let (recov_run_ok, recov_out): (bool, String) = run_probe(&java_p, &recov);
    assert!(
        recov_run_ok,
        "recovered PrecCases did not run under the JVM"
    );

    let gold_lines: Vec<&str> = gold_out.trim().lines().collect();
    let recov_lines: Vec<&str> = recov_out.trim().lines().collect();
    assert_eq!(
        gold_lines.len(),
        recov_lines.len(),
        "recovered program printed a different number of lines than the reference; the operator \
         tree was reshaped by parenthesization. recovered:\n{recovered}"
    );
    for (i, (g, r)) in gold_lines.iter().zip(recov_lines.iter()).enumerate() {
        assert_eq!(
            g, r,
            "line {i}: recovered JVM output `{r}` differs from the reference `{g}`; a \
             missing or wrong parenthesization changed the evaluated value. recovered:\n{recovered}"
        );
    }
}
