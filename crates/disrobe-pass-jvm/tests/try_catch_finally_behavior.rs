#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::{ClassFile, DecompiledClass, decompile_class, parse_classfile};

const TCF_SRC: &str = r#"public class TcfShapes {
    static int CTR = 0;

    static int divSafe(int n, int d) {
        try {
            return n / d;
        } catch (ArithmeticException ex) {
            return Integer.MIN_VALUE;
        } finally {
            CTR++;
        }
    }

    static int catchFallsThrough(int n, int d) {
        int r = 0;
        try {
            r = n / d;
        } catch (ArithmeticException ex) {
            r = -1;
        } finally {
            CTR++;
        }
        return r;
    }

    static void voidCatch(int n, int d) {
        try {
            CTR += n / d;
        } catch (ArithmeticException ex) {
            CTR += 100;
        } finally {
            CTR++;
        }
    }

    static String twoCatches(String s) {
        try {
            return String.valueOf(s.length() / Integer.parseInt(s));
        } catch (NumberFormatException ex) {
            return "nfe";
        } catch (ArithmeticException ex) {
            return "ae";
        } finally {
            CTR++;
        }
    }

    static String multiCatchFinally(String s) {
        try {
            return s.substring(Integer.parseInt(s));
        } catch (NumberFormatException | IndexOutOfBoundsException ex) {
            return "bad";
        } finally {
            CTR++;
        }
    }

    static int catchRethrows(int n, int d) {
        try {
            return n / d;
        } catch (ArithmeticException ex) {
            throw new IllegalStateException("boom");
        } finally {
            CTR++;
        }
    }

    static int nestedFinally(int n, int d) {
        try {
            try {
                return n / d;
            } catch (ArithmeticException ex) {
                return -1;
            } finally {
                CTR++;
            }
        } finally {
            CTR += 10;
        }
    }

    static int tcfInLoop(int[] xs, int d) {
        int acc = 0;
        for (int x : xs) {
            try {
                acc += x / d;
            } catch (ArithmeticException ex) {
                acc -= 1;
                continue;
            } finally {
                CTR++;
            }
        }
        return acc;
    }

    static int catchReturnsInBranch(int n, int d) {
        try {
            return n / d;
        } catch (ArithmeticException ex) {
            if (n > 0) { return 1; }
            return 2;
        } finally {
            CTR++;
        }
    }

    static long longCatch(long a, long b) {
        try {
            return a / b;
        } catch (ArithmeticException ex) {
            return -1L;
        } finally {
            CTR++;
        }
    }

    static String catchWritesThenFallsThrough(String s) {
        String out = "none";
        try {
            out = s.substring(4);
        } catch (IndexOutOfBoundsException ex) {
            out = "oob";
        } finally {
            CTR++;
        }
        return out;
    }

    static int emptyCatch(int n, int d) {
        int r = 7;
        try {
            r = n / d;
        } catch (ArithmeticException ex) {
        } finally {
            CTR++;
        }
        return r;
    }
}
"#;

const PROBE_SRC: &str = r#"public class Probe {
    static StringBuilder SB = new StringBuilder();
    static int MARK = 0;

    static void mark() {
        MARK = TcfShapes.CTR;
    }

    static void say(String name, Object value) {
        SB.append(name).append('=').append(value).append(",ctr=")
          .append(TcfShapes.CTR - MARK).append('\n');
    }

    public static void main(String[] args) {
        mark(); say("divSafe", TcfShapes.divSafe(10, 0));
        mark(); say("divSafeOk", TcfShapes.divSafe(10, 2));
        mark(); say("catchFallsThrough", TcfShapes.catchFallsThrough(9, 0));
        mark(); say("catchFallsThroughOk", TcfShapes.catchFallsThrough(9, 3));
        mark(); TcfShapes.voidCatch(9, 0); say("voidCatch", "v");
        mark(); say("twoCatchesNfe", TcfShapes.twoCatches("abc"));
        mark(); say("twoCatchesAe", TcfShapes.twoCatches("0"));
        mark(); say("twoCatchesOk", TcfShapes.twoCatches("2"));
        mark(); say("multiCatchFinally", TcfShapes.multiCatchFinally("abc"));
        mark();
        String rethrown = "none";
        try {
            TcfShapes.catchRethrows(1, 0);
        } catch (IllegalStateException ex) {
            rethrown = ex.getMessage();
        }
        say("catchRethrows", rethrown);
        mark(); say("nestedFinally", TcfShapes.nestedFinally(4, 0));
        mark(); say("nestedFinallyOk", TcfShapes.nestedFinally(4, 2));
        mark(); say("tcfInLoop", TcfShapes.tcfInLoop(new int[]{1, 2, 3}, 0));
        mark(); say("tcfInLoopOk", TcfShapes.tcfInLoop(new int[]{4, 6}, 2));
        mark(); say("catchReturnsInBranch", TcfShapes.catchReturnsInBranch(5, 0));
        mark(); say("catchReturnsInBranchNeg", TcfShapes.catchReturnsInBranch(-5, 0));
        mark(); say("longCatch", TcfShapes.longCatch(8L, 0L));
        mark(); say("catchWritesThenFallsThrough", TcfShapes.catchWritesThenFallsThrough("ab"));
        mark(); say("catchWritesThenFallsThroughOk", TcfShapes.catchWritesThenFallsThrough("abcdef"));
        mark(); say("emptyCatch", TcfShapes.emptyCatch(3, 0));
        System.out.print(SB);
    }
}
"#;

const TCF_OBSERVED_SHAPES: &[&str] = &[
    "divSafe",
    "divSafeOk",
    "catchFallsThrough",
    "catchFallsThroughOk",
    "voidCatch",
    "twoCatchesNfe",
    "twoCatchesAe",
    "twoCatchesOk",
    "multiCatchFinally",
    "catchRethrows",
    "nestedFinally",
    "nestedFinallyOk",
    "tcfInLoop",
    "tcfInLoopOk",
    "catchReturnsInBranch",
    "catchReturnsInBranchNeg",
    "longCatch",
    "catchWritesThenFallsThrough",
    "catchWritesThenFallsThroughOk",
    "emptyCatch",
];

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

fn compile(javac: &PathBuf, dir: &PathBuf, name: &str, source: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).expect("mkdir");
    let path: PathBuf = dir.join(format!("{name}.java"));
    std::fs::write(&path, source).expect("write source");
    let out: std::process::Output = Command::new(javac)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-cp")
        .arg(dir)
        .arg("-d")
        .arg(dir)
        .arg(&path)
        .output()
        .expect("javac");
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn build_shapes_and_probe(javac: &PathBuf, dir: &PathBuf, shapes: &str) -> Result<(), String> {
    compile(javac, dir, "TcfShapes", shapes)?;
    compile(javac, dir, "Probe", PROBE_SRC)
}

fn run_probe(java: &PathBuf, dir: &PathBuf) -> String {
    let out: std::process::Output = Command::new(java)
        .arg("-cp")
        .arg(dir)
        .arg("Probe")
        .output()
        .expect("java");
    assert!(
        out.status.success(),
        "the probe did not run to completion under the jvm: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n")
}

fn observations(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter_map(|line: &str| {
            line.split_once('=')
                .map(|(k, v): (&str, &str)| (k.to_owned(), v.to_owned()))
        })
        .collect()
}

fn divergent(
    reference: &BTreeMap<String, String>,
    other: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (name, want) in reference {
        match other.get(name) {
            Some(got) if got == want => {}
            Some(got) => out.push(format!("{name}: reference `{want}` vs candidate `{got}`")),
            None => out.push(format!("{name}: missing from the candidate run")),
        }
    }
    out
}

#[derive(Debug)]
struct Jdk {
    javac: PathBuf,
    java: PathBuf,
}

fn jdk() -> Jdk {
    let (Some(javac), Some(java)): (Option<PathBuf>, Option<PathBuf>) =
        (find_on_path("javac"), find_on_path("java"))
    else {
        panic!("try-catch-finally behavior gate requires javac and java on PATH");
    };
    Jdk { javac, java }
}

#[test]
fn the_behavior_gate_fails_when_jdk_tools_are_unavailable() {
    let test_binary: PathBuf = std::env::current_exe().expect("current test binary");
    let output: std::process::Output = Command::new(test_binary)
        .arg("--exact")
        .arg("try_catch_finally_recovers_with_the_same_observable_behavior")
        .arg("--test-threads=1")
        .env("PATH", "")
        .output()
        .expect("run behavior gate without JDK tools");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the behavior gate passed without JDK tools, so a green run proves nothing; stdout:\n\
         {stdout}\nstderr:\n{stderr}"
    );
    assert!(
        format!("{stdout}\n{stderr}")
            .contains("try-catch-finally behavior gate requires javac and java on PATH"),
        "the behavior gate failed for an unrelated reason; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn try_catch_finally_recovers_with_the_same_observable_behavior() {
    let jdk: Jdk = jdk();
    let purpose: String = format!("disrobe_tcf_behavior_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let gold: PathBuf = root.join("gold");
    let recov: PathBuf = root.join("recov");

    build_shapes_and_probe(&jdk.javac, &gold, TCF_SRC)
        .unwrap_or_else(|e: String| panic!("reference fixture did not compile: {e}"));

    let class_bytes: Vec<u8> = std::fs::read(gold.join("TcfShapes.class")).expect("read class");
    let cf: ClassFile = parse_classfile(&class_bytes).expect("parse");
    let decompiled: DecompiledClass = decompile_class(&cf);

    assert!(
        !decompiled.source.contains("(stack reset)"),
        "decompiled output left a lifting hole:\n{}",
        decompiled.source
    );

    build_shapes_and_probe(&jdk.javac, &recov, &decompiled.source).unwrap_or_else(|e: String| {
        panic!(
            "recovered TcfShapes did not recompile under real javac: {e}\n---recovered---\n{}",
            decompiled.source
        )
    });

    let gold_out: BTreeMap<String, String> = observations(&run_probe(&jdk.java, &gold));
    let recov_out: BTreeMap<String, String> = observations(&run_probe(&jdk.java, &recov));

    let seen: BTreeSet<&str> = gold_out.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = TCF_OBSERVED_SHAPES.iter().copied().collect();
    assert_eq!(
        seen, expected,
        "the observed shape membership drifted; this floor is a membership list, not a count"
    );

    let diffs: Vec<String> = divergent(&gold_out, &recov_out);
    assert!(
        diffs.is_empty(),
        "recovered java behaves differently from the original on {} of {} observations:\n{}\n\
         ---recovered---\n{}",
        diffs.len(),
        TCF_OBSERVED_SHAPES.len(),
        diffs.join("\n"),
        decompiled.source
    );
}

#[test]
fn the_behavior_gate_reports_a_double_counted_exception_path() {
    let jdk: Jdk = jdk();
    let mutant: String = TCF_SRC.replace(
        "        } catch (ArithmeticException ex) {\n            return Integer.MIN_VALUE;\n",
        "        } catch (ArithmeticException ex) {\n            CTR++;\n            return \
         Integer.MIN_VALUE;\n",
    );
    assert_ne!(
        mutant, TCF_SRC,
        "the mutation-kill control did not apply; the catch body it targets moved"
    );

    let purpose: String = format!("disrobe_tcf_control_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let gold: PathBuf = root.join("gold");
    let bad: PathBuf = root.join("bad");

    build_shapes_and_probe(&jdk.javac, &gold, TCF_SRC)
        .unwrap_or_else(|e: String| panic!("reference fixture did not compile: {e}"));
    build_shapes_and_probe(&jdk.javac, &bad, &mutant)
        .unwrap_or_else(|e: String| panic!("control fixture did not compile: {e}"));

    let gold_out: BTreeMap<String, String> = observations(&run_probe(&jdk.java, &gold));
    let bad_out: BTreeMap<String, String> = observations(&run_probe(&jdk.java, &bad));

    let diffs: Vec<String> = divergent(&gold_out, &bad_out);
    assert!(
        diffs.iter().any(|d: &String| d.starts_with("divSafe:")),
        "a program that increments the counter twice on the exception path was NOT reported as \
         divergent, so this gate measures nothing; diffs were: {diffs:?}"
    );
}
