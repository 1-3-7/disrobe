#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_jvm::{
    Attribute, ClassFile, CodeAttribute, ConstantPoolEntry, DecompiledClass, Dex2JarResult,
    ExceptionEntry, Instruction, MethodInfo, Operands, decompile_class, decompile_classfile_bytes,
    disassemble, parse_classfile, parse_code_attribute, translate_dex_bytes,
};

const D8_FINALLY_NESTED_DEX: &[u8] =
    include_bytes!("fixtures/d8_finally_nested/D8FinallyNested.dex");
const D8_FINALLY_NESTED_SOURCE: &str =
    include_str!("fixtures/d8_finally_nested/D8FinallyNested.java");
const D8_FINALLY_NESTED_SHA256: &str =
    "ac26dac355869a4c524da3963c0d98b6bbe98cc70afb47510b844c169389b1b9";
const KOTLIN_FINALLY_NESTED_CLASS: &[u8] =
    include_bytes!("fixtures/kotlin_finally_nested/FinallyNested.class");
const KOTLIN_FINALLY_NESTED_SHA256: &str =
    "dc36235c74f7cb530204b1d1e5d97184169ba4858f1e6a1a07dd06970d971942";
const JVM_PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const JVM_PROCESS_CAPTURE_LIMIT: usize = 1_048_576;
const KOTLIN_FINALLY_RUNNER_SOURCE: &str = "public final class Runner {\n\
    public static void main(String[] args) {\n\
        int value = Integer.parseInt(args[0]);\n\
        int divisor = Integer.parseInt(args[1]);\n\
        try {\n\
            System.out.print(\"value:\" + probe.FinallyNested.compute(value, divisor));\n\
        } catch (Throwable error) {\n\
            System.out.print(\"throw:\" + error.getClass().getName());\n\
        }\n\
    }\n\
}\n";
const D8_FINALLY_RUNNER_SOURCE: &str = "public final class Runner {\n\
    public static void main(String[] args) {\n\
        int left = Integer.parseInt(args[0]);\n\
        int right = Integer.parseInt(args[1]);\n\
        int seed = Integer.parseInt(args[2]);\n\
        D8FinallyNested.counter = seed;\n\
        try {\n\
            int value = D8FinallyNested.run(left, right);\n\
            System.out.print(\"value:\" + value + \":counter:\" + D8FinallyNested.counter);\n\
        } catch (Throwable error) {\n\
            System.out.print(\"throw:\" + error.getClass().getName() + \":counter:\" + D8FinallyNested.counter);\n\
        }\n\
    }\n\
}\n";

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

fn compile_d8_finally_runtime(javac: &PathBuf, directory: &PathBuf, sources: &[PathBuf]) {
    let mut command: Command = Command::new(javac);
    command
        .arg("-proc:none")
        .arg("-g:none")
        .arg("-cp")
        .arg(directory)
        .arg("-d")
        .arg(directory);
    command.args(sources);
    let output: std::process::Output = command.output().expect("run javac");
    assert!(
        output.status.success(),
        "D8 finally runtime source failed to compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_d8_finally_runtime(
    java: &PathBuf,
    directory: &PathBuf,
    left: i32,
    right: i32,
    seed: i32,
) -> String {
    let output: std::process::Output = Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(directory)
        .arg("Runner")
        .arg(left.to_string())
        .arg(right.to_string())
        .arg(seed.to_string())
        .output()
        .expect("run D8 finally runtime");
    assert!(
        output.status.success(),
        "D8 finally runtime failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("runtime output is UTF-8")
}

fn run_bounded(program: &Path, args: &[OsString], operation: &str) -> CapturedOutput {
    run_captured(
        program,
        args,
        JVM_PROCESS_TIMEOUT,
        JVM_PROCESS_CAPTURE_LIMIT,
    )
    .unwrap_or_else(|error: std::io::Error| panic!("failed to launch {operation}: {error}"))
    .unwrap_or_else(|| panic!("{operation} exceeded its wall-clock bound"))
}

fn compile_kotlin_finally_runtime(javac: &Path, directory: &Path, sources: &[PathBuf]) {
    let mut args: Vec<OsString> = vec![
        OsString::from("-proc:none"),
        OsString::from("-g:none"),
        OsString::from("-cp"),
        directory.as_os_str().to_os_string(),
        OsString::from("-d"),
        directory.as_os_str().to_os_string(),
    ];
    args.extend(
        sources
            .iter()
            .map(|source: &PathBuf| source.as_os_str().to_os_string()),
    );
    let output: CapturedOutput = run_bounded(javac, &args, "javac Kotlin finally runtime");
    assert_eq!(
        output.exit_code,
        Some(0),
        "Kotlin finally runtime source failed to compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_kotlin_finally_runtime(java: &Path, directory: &Path, value: i32, divisor: i32) -> String {
    let args: [OsString; 6] = [
        OsString::from("-Xverify:all"),
        OsString::from("-cp"),
        directory.as_os_str().to_os_string(),
        OsString::from("Runner"),
        OsString::from(value.to_string()),
        OsString::from(divisor.to_string()),
    ];
    let output: CapturedOutput = run_bounded(java, &args, "Kotlin finally runtime");
    assert_eq!(
        output.exit_code,
        Some(0),
        "Kotlin finally runtime failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Kotlin finally runtime output is UTF-8")
}

fn without_annotation_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line: &&str| !line.trim_start().starts_with('@'))
        .collect::<Vec<&str>>()
        .join("\n")
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

fn javap_member_code(raw: &str, signature_fragment: &str) -> Option<Vec<String>> {
    let mut members: Vec<(String, Vec<String>)> = Vec::new();
    for line in raw.lines() {
        let trimmed: &str = line.trim_end();
        let declares_member: bool =
            trimmed.starts_with("  ") && !trimmed.starts_with("   ") && trimmed.ends_with(';');
        if declares_member {
            members.push((trimmed.to_owned(), Vec::new()));
        } else if let Some((_, body)) = members.last_mut() {
            body.push(trimmed.to_owned());
        }
    }
    members
        .into_iter()
        .find(|(header, _): &(String, Vec<String>)| header.contains(signature_fragment))
        .map(|(header, body): (String, Vec<String>)| {
            let mut text: String = header;
            for line in body {
                text.push('\n');
                text.push_str(&line);
            }
            normalize_javap(&text)
        })
}

fn method_body(source: &str, signature_fragment: &str) -> Option<String> {
    let start: usize = source.find(signature_fragment)?;
    let open: usize = source[start..].find('{')? + start;
    let mut depth: usize = 0;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth = depth.checked_add(1)?,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return source.get(open..=open + offset).map(str::to_owned);
                }
            }
            _ => {}
        }
    }
    None
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

const FINALLY_RETURN_KINDS: &[(&str, &str, &str)] = &[
    ("ireturn", " finallyReturns(", "int"),
    ("lreturn", " longFinallyReturns(", "long"),
    ("freturn", " floatFinallyReturns(", "float"),
    ("dreturn", " doubleFinallyReturns(", "double"),
    ("areturn", " objFinallyReturns(", "reference"),
    ("return", " voidFinallyReturns(", "void"),
];

#[test]
fn a_finally_returning_each_jvm_return_kind_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("TryFinallyReturn", TRY_FINALLY_RETURN_SRC);
    let mut equivalent: Vec<&str> = Vec::new();
    let mut divergent: Vec<String> = Vec::new();
    for (opcode, fragment, kind) in FINALLY_RETURN_KINDS {
        let body: String = assert_finally_recovered(&recompiled.source, fragment);
        let finally_at: usize = body
            .find("finally {")
            .unwrap_or_else(|| panic!("the recovered {kind} method has no finally block:\n{body}"));
        let finally_tail: &str = body
            .get(finally_at..)
            .unwrap_or_else(|| panic!("the recovered {kind} finally block is truncated:\n{body}"));
        assert!(
            finally_tail.contains("return"),
            "the recovered {kind} finally block does not return, so the {opcode} shape was not \
             recovered:\n{body}"
        );
        let original: Vec<String> = javap_member_code(&recompiled.original_javap, fragment)
            .unwrap_or_else(|| {
                panic!("the {kind} return-kind method is missing from the original javap")
            });
        let recovered: Vec<String> = javap_member_code(&recompiled.recovered_javap, fragment)
            .unwrap_or_else(|| {
                panic!("the {kind} return-kind method is missing from the recompiled javap")
            });
        let marker: String = format!(": {opcode}");
        assert!(
            original.iter().any(|line: &String| line.ends_with(&marker)),
            "the {kind} fixture never reaches {opcode}, so this row certifies nothing:\n{}",
            original.join("\n")
        );
        if original == recovered {
            equivalent.push(kind);
        } else {
            divergent.push(format!("{kind} ({opcode})"));
        }
    }
    eprintln!(
        "FINALLY RETURN KIND RECOMPILE: {}/{} return kinds byte-equivalent under javac",
        equivalent.len(),
        FINALLY_RETURN_KINDS.len()
    );
    assert!(
        divergent.is_empty(),
        "a finally returning these kinds did not recompile to equivalent bytecode: {}\n\
         --- recovered source ---\n{}",
        divergent.join(", "),
        recompiled.source
    );
    assert_eq!(
        equivalent.len(),
        FINALLY_RETURN_KINDS.len(),
        "only {} of {} JVM return kinds were certified byte-equivalent",
        equivalent.len(),
        FINALLY_RETURN_KINDS.len()
    );
}

const FINALLY_IF_SRC: &str = "public class FinallyIf {\n\
    static int CTR = 0;\n\
    static int run(int a) {\n\
        try {\n\
            return a * 2;\n\
        } finally {\n\
            if (a > 0) { CTR++; } else { CTR--; }\n\
        }\n\
    }\n\
}\n";

const FINALLY_LOOKUP_SWITCH_SRC: &str = "public class FinallyLookupSwitch {\n\
    static int CTR = 0;\n\
    static int run(int a) {\n\
        try {\n\
            return a * 2;\n\
        } finally {\n\
            switch (a) {\n\
                case 0: CTR += 1; break;\n\
                case 100: CTR += 10; break;\n\
                default: CTR -= 1;\n\
            }\n\
        }\n\
    }\n\
}\n";

const FINALLY_TABLE_SWITCH_SRC: &str = "public class FinallyTableSwitch {\n\
    static int CTR = 0;\n\
    static int run(int a) {\n\
        try {\n\
            return a * 2;\n\
        } finally {\n\
            switch (a) {\n\
                case 0: CTR += 1; break;\n\
                case 1: CTR += 10; break;\n\
                case 2: CTR += 100; break;\n\
                default: CTR -= 1;\n\
            }\n\
        }\n\
    }\n\
}\n";

#[test]
fn finally_if_else_recompiles_to_equivalent_bytecode() {
    let (javac, javap): (PathBuf, PathBuf) = require_jdk_tools();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_finally_if").expect("scratch");
    let orig_dir: PathBuf = scratch.path().join("orig");
    let rec_dir: PathBuf = scratch.path().join("rec");
    std::fs::create_dir_all(&orig_dir).expect("original directory");
    std::fs::create_dir_all(&rec_dir).expect("recovered directory");
    let source_path: PathBuf = orig_dir.join("FinallyIf.java");
    std::fs::write(&source_path, FINALLY_IF_SRC).expect("source fixture");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&orig_dir)
        .arg(&source_path)
        .output()
        .expect("compile fixture");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let class_bytes: Vec<u8> =
        std::fs::read(orig_dir.join("FinallyIf.class")).expect("class fixture");
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse class fixture");
    let decompiled: DecompiledClass = decompile_class(&class_file);
    let body: String = method_body(&decompiled.source, " run(").expect("recovered run method");

    assert!(!body.contains("not recovered:"), "method refused:\n{body}");
    assert!(
        !body.contains("catch (Throwable"),
        "finally became catch:\n{body}"
    );
    assert!(
        !body.contains("stack reset"),
        "method has lifting hole:\n{body}"
    );
    assert!(body.contains("finally {"), "finally missing:\n{body}");
    assert!(body.contains("if ("), "finally condition missing:\n{body}");
    assert!(body.contains("else {"), "finally else arm missing:\n{body}");

    let recovered_source: PathBuf = rec_dir.join("FinallyIf.java");
    std::fs::write(&recovered_source, &decompiled.source).expect("recovered source");
    let recompile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&rec_dir)
        .arg(&recovered_source)
        .output()
        .expect("recompile recovered source");
    assert!(
        recompile.status.success(),
        "recovered source failed to compile: {}\n{}",
        String::from_utf8_lossy(&recompile.stderr),
        decompiled.source
    );
    let original_code: Vec<String> = normalize_javap(&javap_code(&javap, &orig_dir, "FinallyIf"));
    let recovered_code: Vec<String> = normalize_javap(&javap_code(&javap, &rec_dir, "FinallyIf"));
    assert_eq!(
        original_code, recovered_code,
        "recompiled finally-if bytecode differs from the original:\n{}",
        decompiled.source
    );
}

#[test]
fn finally_with_a_lookup_switch_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyLookupSwitch", FINALLY_LOOKUP_SWITCH_SRC);
    assert!(
        recompiled.original_javap.contains("lookupswitch"),
        "the sparse-switch recovery fixture did not compile to lookupswitch:\n{}",
        recompiled.original_javap
    );
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(body.contains("switch ("), "finally switch missing:\n{body}");
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled finally-switch bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_with_a_table_switch_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyTableSwitch", FINALLY_TABLE_SWITCH_SRC);
    assert!(
        recompiled.original_javap.contains("tableswitch"),
        "the dense-switch recovery fixture did not compile to tableswitch:\n{}",
        recompiled.original_javap
    );
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(body.contains("switch ("), "finally switch missing:\n{body}");
    for key in [0, 1, 2] {
        assert!(
            body.contains(&format!("case {key}:")),
            "finally switch key {key} missing:\n{body}"
        );
    }
    assert!(
        body.contains("default:"),
        "finally default missing:\n{body}"
    );
    assert!(
        body.contains("return "),
        "finally continuation missing:\n{body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled finally-switch bytecode differs from the original:\n{}",
        recompiled.source
    );
}

fn compiled_table_switch_fixture() -> Vec<u8> {
    let (javac, _): (PathBuf, PathBuf) = require_jdk_tools();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_finally_table_switch_mutation")
            .expect("scratch");
    let directory: PathBuf = scratch.path().join("orig");
    std::fs::create_dir_all(&directory).expect("fixture directory");
    let source_path: PathBuf = directory.join("FinallyTableSwitch.java");
    std::fs::write(&source_path, FINALLY_TABLE_SWITCH_SRC).expect("fixture source");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&directory)
        .arg(&source_path)
        .output()
        .expect("compile fixture");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    std::fs::read(directory.join("FinallyTableSwitch.class")).expect("fixture class")
}

fn table_switch_header(code_offset: usize, pc: u32) -> usize {
    let pc: usize = usize::try_from(pc).expect("tableswitch pc");
    let padding: usize = (4 - ((pc + 1) % 4)) % 4;
    code_offset + pc + 1 + padding
}

fn table_switch_sites(table: &MethodTableSite) -> Vec<Instruction> {
    disassemble(&table.code)
        .expect("fixture bytecode")
        .into_iter()
        .filter(|instruction: &Instruction| instruction.opcode == 0xAA)
        .collect()
}

fn assert_mutated_table_switch_refused(class_bytes: &[u8]) {
    let class_file: ClassFile = parse_classfile(class_bytes).expect("parse mutated fixture");
    let decompiled: DecompiledClass = decompile_class(&class_file);
    let body: String = method_body(&decompiled.source, " run(").expect("mutated run method");
    assert!(
        body.contains("not recovered:"),
        "a mismatched tableswitch copy was recovered:\n{body}"
    );
    assert!(
        !body.contains("catch (Throwable"),
        "a mismatched tableswitch finally became a Throwable catch:\n{body}"
    );
}

#[test]
fn finally_table_switch_rejects_mismatched_dense_domains() {
    let mut class_bytes: Vec<u8> = compiled_table_switch_fixture();
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse fixture");
    let table: MethodTableSite = method_exception_table(&class_bytes, &class_file, "run");
    let switches: Vec<Instruction> = table_switch_sites(&table);
    let [_, copy]: [&Instruction; 2] = switches
        .iter()
        .collect::<Vec<&Instruction>>()
        .try_into()
        .expect("one tableswitch per finally copy");
    let header: usize = table_switch_header(table.code_offset, copy.pc);
    let low_offset: usize = header + 4;
    let high_offset: usize = header + 8;
    let low: i32 = i32::from_be_bytes(
        class_bytes[low_offset..low_offset + 4]
            .try_into()
            .expect("tableswitch low"),
    );
    let high: i32 = i32::from_be_bytes(
        class_bytes[high_offset..high_offset + 4]
            .try_into()
            .expect("tableswitch high"),
    );
    class_bytes[low_offset..low_offset + 4]
        .copy_from_slice(&low.checked_add(1).expect("shifted low").to_be_bytes());
    class_bytes[high_offset..high_offset + 4]
        .copy_from_slice(&high.checked_add(1).expect("shifted high").to_be_bytes());
    assert_mutated_table_switch_refused(&class_bytes);
}

#[test]
fn finally_table_switch_rejects_ambiguous_case_targets() {
    let mut class_bytes: Vec<u8> = compiled_table_switch_fixture();
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse fixture");
    let table: MethodTableSite = method_exception_table(&class_bytes, &class_file, "run");
    let switches: Vec<Instruction> = table_switch_sites(&table);
    let [_, copy]: [&Instruction; 2] = switches
        .iter()
        .collect::<Vec<&Instruction>>()
        .try_into()
        .expect("one tableswitch per finally copy");
    let Operands::TableSwitch { offsets, .. } = &copy.operands else {
        panic!("dense switch operand missing")
    };
    assert_ne!(offsets[0], offsets[1], "fixture case targets must differ");
    let first_target: usize = table_switch_header(table.code_offset, copy.pc) + 12;
    let second_target: [u8; 4] = class_bytes[first_target + 4..first_target + 8]
        .try_into()
        .expect("second case target");
    class_bytes[first_target..first_target + 4].copy_from_slice(&second_target);
    assert_mutated_table_switch_refused(&class_bytes);
}

const FINALLY_THROW_SRC: &str = "public class FinallyThrow {\n\
    static int CTR = 0;\n\
    static int run(int a) {\n\
        try {\n\
            return a;\n\
        } finally {\n\
            if (a < 0) { throw new IllegalStateException(\"neg\"); }\n\
        }\n\
    }\n\
}\n";

#[test]
fn finally_that_throws_recompiles_to_equivalent_bytecode() {
    let (javac, javap): (PathBuf, PathBuf) = require_jdk_tools();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_finally_throw").expect("scratch");
    let orig_dir: PathBuf = scratch.path().join("orig");
    let rec_dir: PathBuf = scratch.path().join("rec");
    std::fs::create_dir_all(&orig_dir).expect("original directory");
    std::fs::create_dir_all(&rec_dir).expect("recovered directory");
    let source_path: PathBuf = orig_dir.join("FinallyThrow.java");
    std::fs::write(&source_path, FINALLY_THROW_SRC).expect("source fixture");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&orig_dir)
        .arg(&source_path)
        .output()
        .expect("compile fixture");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let class_bytes: Vec<u8> =
        std::fs::read(orig_dir.join("FinallyThrow.class")).expect("class fixture");
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse class fixture");
    let decompiled: DecompiledClass = decompile_class(&class_file);
    let body: String = method_body(&decompiled.source, " run(").expect("recovered run method");

    assert!(!body.contains("not recovered:"), "method refused:\n{body}");
    assert!(
        !body.contains("catch (Throwable"),
        "finally became catch:\n{body}"
    );
    assert!(
        !body.contains("stack reset"),
        "method has lifting hole:\n{body}"
    );
    assert!(body.contains("finally {"), "finally missing:\n{body}");
    assert!(
        body.contains("throw new IllegalStateException"),
        "finally throw missing:\n{body}"
    );
    assert!(body.contains("if ("), "finally condition missing:\n{body}");

    let recovered_source: PathBuf = rec_dir.join("FinallyThrow.java");
    std::fs::write(&recovered_source, &decompiled.source).expect("recovered source");
    let recompile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&rec_dir)
        .arg(&recovered_source)
        .output()
        .expect("recompile recovered source");
    assert!(
        recompile.status.success(),
        "recovered source failed to compile: {}\n{}",
        String::from_utf8_lossy(&recompile.stderr),
        decompiled.source
    );
    let original_code: Vec<String> =
        normalize_javap(&javap_code(&javap, &orig_dir, "FinallyThrow"));
    let recovered_code: Vec<String> =
        normalize_javap(&javap_code(&javap, &rec_dir, "FinallyThrow"));
    assert_eq!(
        original_code, recovered_code,
        "recompiled finally-throw bytecode differs from the original:\n{}",
        decompiled.source
    );
}

const FINALLY_BREAK_SRC: &str = "public class FinallyBreak {\n\
    static int CTR = 0;\n\
    static int forEach(int[] xs) {\n\
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
    static int indexed(int[] xs) {\n\
        int acc = 0;\n\
        for (int i = 0; i < xs.length; i++) {\n\
            try {\n\
                acc += xs[i];\n\
            } finally {\n\
                if (acc > 5) { break; }\n\
            }\n\
        }\n\
        return acc;\n\
    }\n\
}\n";

const FINALLY_THROW_VOID_SRC: &str = "public class FinallyThrowVoid {\n\
    static int CTR = 0;\n\
    static void run(int a) {\n\
        try {\n\
            CTR = a;\n\
        } finally {\n\
            if (a < 0) { throw new IllegalStateException(\"neg\"); }\n\
        }\n\
    }\n\
}\n";

const FINALLY_CONTINUE_SRC: &str = "public class FinallyContinue {\n\
    static int run(int[] xs) {\n\
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
}\n";

const FINALLY_CONDITIONAL_CONTINUE_SRC: &str = "public class FinallyConditionalContinue {\n\
    static int run(int limit, boolean take) {\n\
        int i = 0;\n\
        while (i < limit) {\n\
            try {\n\
                i += 2;\n\
            } finally {\n\
                if (take) { i++; continue; }\n\
            }\n\
        }\n\
        return i;\n\
    }\n\
}\n";

const FINALLY_NESTED_TRY_SRC: &str = "public class FinallyNestedTry {\n\
    static int CTR = 0;\n\
    static int run(int a, int b) {\n\
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
}\n";

const FINALLY_NESTED_MULTI_CATCH_SRC: &str = "public class FinallyNestedMultiCatch {\n\
    static int CTR = 0;\n\
    static Class<?> EXTRA = IllegalStateException.class;\n\
    static int run(int a, int b) {\n\
        try {\n\
            return a / b;\n\
        } finally {\n\
            try {\n\
                CTR += a / b;\n\
            } catch (ArithmeticException | NullPointerException ex) {\n\
                CTR = -1;\n\
            }\n\
        }\n\
    }\n\
}\n";

const FINALLY_NESTED_CATCH_READ_SRC: &str = "public class FinallyNestedCatchRead {\n\
    static int CTR = 0;\n\
    static int run(int a, int b) {\n\
        try {\n\
            return a / b;\n\
        } finally {\n\
            try {\n\
                CTR += a / b;\n\
            } catch (ArithmeticException ex) {\n\
                CTR = ex.hashCode();\n\
            }\n\
        }\n\
    }\n\
    static int multi(int a, int b) {\n\
        try {\n\
            return a / b;\n\
        } finally {\n\
            try {\n\
                CTR += a / b;\n\
            } catch (ArithmeticException | NullPointerException ex) {\n\
                CTR = ex.hashCode();\n\
            }\n\
        }\n\
    }\n\
}\n";

const FINALLY_THROW_ALWAYS_SRC: &str = "public class FinallyThrowAlways {\n\
    static int CTR = 0;\n\
    static int value(int a) {\n\
        try {\n\
            return a;\n\
        } finally {\n\
            throw new IllegalStateException(\"always\");\n\
        }\n\
    }\n\
    static void unit(int a) {\n\
        try {\n\
            CTR = a;\n\
        } finally {\n\
            throw new IllegalStateException(\"always\");\n\
        }\n\
    }\n\
    static String text(String s) {\n\
        try {\n\
            return s.trim();\n\
        } finally {\n\
            throw new IllegalStateException(\"always\");\n\
        }\n\
    }\n\
    static long counted(long a) {\n\
        try {\n\
            return a * 2L;\n\
        } finally {\n\
            CTR++;\n\
            throw new IllegalStateException(\"always\");\n\
        }\n\
    }\n\
}\n";

struct MethodTableSite {
    code_offset: usize,
    entries_offset: usize,
    entries: Vec<ExceptionEntry>,
    code: Vec<u8>,
}

fn method_exception_table(bytes: &[u8], class_file: &ClassFile, name: &str) -> MethodTableSite {
    let method: &MethodInfo = class_file
        .methods
        .iter()
        .find(|method: &&MethodInfo| class_file.utf8_at(method.name_index).ok() == Some(name))
        .expect("fixture method");
    let attribute: &Attribute = method
        .attributes
        .iter()
        .find(|attribute: &&Attribute| {
            class_file.utf8_at(attribute.name_index).ok() == Some("Code")
        })
        .expect("fixture Code attribute");
    let code: CodeAttribute = parse_code_attribute(&attribute.info).expect("fixture Code payload");
    let matches: Vec<usize> = bytes
        .windows(attribute.info.len())
        .enumerate()
        .filter(|(_, window): &(usize, &[u8])| *window == attribute.info.as_slice())
        .map(|(offset, _): (usize, &[u8])| offset)
        .collect();
    let [info_offset]: [usize; 1] = matches
        .as_slice()
        .try_into()
        .expect("Code payload appears exactly once");
    MethodTableSite {
        code_offset: info_offset + 2 + 2 + 4,
        entries_offset: info_offset + 2 + 2 + 4 + code.code.len() + 2,
        entries: code.exception_table,
        code: code.code,
    }
}

fn class_constant_index(class_file: &ClassFile, name: &str) -> u16 {
    class_file
        .constant_pool
        .iter()
        .enumerate()
        .find_map(|(index, entry): (usize, &ConstantPoolEntry)| match entry {
            ConstantPoolEntry::Class { name_index }
                if class_file.utf8_at(*name_index).ok() == Some(name) =>
            {
                u16::try_from(index).ok()
            }
            _ => None,
        })
        .expect("fixture class constant")
}

struct RecompiledClass {
    source: String,
    original: Vec<String>,
    recovered: Vec<String>,
    original_javap: String,
    recovered_javap: String,
}

fn recompile_recovered_class(class: &str, source: &str) -> RecompiledClass {
    let (javac, javap): (PathBuf, PathBuf) = require_jdk_tools();
    let purpose: String = format!("disrobe_{class}_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let orig_dir: PathBuf = scratch.path().join("orig");
    let rec_dir: PathBuf = scratch.path().join("rec");
    std::fs::create_dir_all(&orig_dir).expect("original directory");
    std::fs::create_dir_all(&rec_dir).expect("recovered directory");
    let source_path: PathBuf = orig_dir.join(format!("{class}.java"));
    std::fs::write(&source_path, source).expect("source fixture");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&orig_dir)
        .arg(&source_path)
        .output()
        .expect("compile fixture");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let class_bytes: Vec<u8> =
        std::fs::read(orig_dir.join(format!("{class}.class"))).expect("class fixture");
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse class fixture");
    let decompiled: DecompiledClass = decompile_class(&class_file);
    let recovered_source: PathBuf = rec_dir.join(format!("{class}.java"));
    std::fs::write(&recovered_source, &decompiled.source).expect("recovered source");
    let recompile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&rec_dir)
        .arg(&recovered_source)
        .output()
        .expect("recompile recovered source");
    assert!(
        recompile.status.success(),
        "recovered source failed to compile: {}\n{}",
        String::from_utf8_lossy(&recompile.stderr),
        decompiled.source
    );
    let original_javap: String = javap_code(&javap, &orig_dir, class);
    let recovered_javap: String = javap_code(&javap, &rec_dir, class);
    RecompiledClass {
        original: normalize_javap(&original_javap),
        recovered: normalize_javap(&recovered_javap),
        original_javap,
        recovered_javap,
        source: decompiled.source,
    }
}

fn nested_catch_parameter(body: &str, catch_type: &str) -> String {
    let marker: String = format!("catch ({catch_type} ");
    let found: usize = body
        .find(&marker)
        .unwrap_or_else(|| panic!("no {catch_type} catch clause in the recovered body:\n{body}"));
    let start: usize = found + marker.len();
    let rest: &str = body
        .get(start..)
        .unwrap_or_else(|| panic!("truncated catch clause in the recovered body:\n{body}"));
    let end: usize = rest
        .find(')')
        .unwrap_or_else(|| panic!("unterminated catch clause in the recovered body:\n{body}"));
    let clause: &str = rest
        .get(..end)
        .unwrap_or_else(|| panic!("unterminated catch clause in the recovered body:\n{body}"));
    let parameter: &str = clause.split_whitespace().next_back().unwrap_or_else(|| {
        panic!("the recovered {catch_type} catch clause has no parameter name:\n{body}")
    });
    parameter.to_owned()
}

fn assert_finally_recovered(source: &str, signature_fragment: &str) -> String {
    let body: String =
        method_body(source, signature_fragment).expect("recovered method not present");
    assert!(
        !body.contains("not recovered:"),
        "method {signature_fragment} refused:\n{body}"
    );
    assert!(
        !body.contains("catch (Throwable"),
        "finally became catch in {signature_fragment}:\n{body}"
    );
    assert!(
        !body.contains("stack reset"),
        "method {signature_fragment} has lifting hole:\n{body}"
    );
    assert!(
        body.contains("finally {"),
        "finally missing in {signature_fragment}:\n{body}"
    );
    body
}

#[test]
fn finally_that_breaks_out_of_a_loop_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass = recompile_recovered_class("FinallyBreak", FINALLY_BREAK_SRC);
    for fragment in [" forEach(", " indexed("] {
        let body: String = assert_finally_recovered(&recompiled.source, fragment);
        assert!(
            body.contains("break;"),
            "the finally body's loop exit was not recovered as a break in {fragment}:\n{body}"
        );
    }
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled finally-break bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_that_throws_from_a_void_method_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyThrowVoid", FINALLY_THROW_VOID_SRC);
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(
        body.contains("throw new IllegalStateException"),
        "finally throw missing:\n{body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled void finally-throw bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_with_a_nested_catch_that_reads_its_exception_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyNestedCatchRead", FINALLY_NESTED_CATCH_READ_SRC);
    for fragment in [" run(", " multi("] {
        let body: String = assert_finally_recovered(&recompiled.source, fragment);
        let parameter: String = nested_catch_parameter(&body, "ArithmeticException");
        assert!(
            body.contains(&format!("{parameter}.hashCode()")),
            "the nested catch parameter is not read in the recovered finally {fragment}:\n{body}"
        );
    }
    let multi_body: String = assert_finally_recovered(&recompiled.source, " multi(");
    assert!(
        multi_body.contains("NullPointerException"),
        "the nested multi-catch lost an alternative in the recovered finally:\n{multi_body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled nested-catch-read finally bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_that_always_throws_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyThrowAlways", FINALLY_THROW_ALWAYS_SRC);
    for fragment in [" value(", " unit(", " text(", " counted("] {
        let body: String = assert_finally_recovered(&recompiled.source, fragment);
        assert!(
            body.contains("throw new IllegalStateException"),
            "the unconditional finally throw was not recovered in {fragment}:\n{body}"
        );
        assert!(
            !body.contains("if ("),
            "an unconditional finally throw grew a condition in {fragment}:\n{body}"
        );
    }
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled always-throwing finally bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_that_continues_an_enclosing_loop_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyContinue", FINALLY_CONTINUE_SRC);
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(
        body.contains("continue;"),
        "finally continue missing:\n{body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled finally-continue bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_continue_only_latch_is_not_hoisted_to_the_normal_loop_path() {
    let recompiled: RecompiledClass = recompile_recovered_class(
        "FinallyConditionalContinue",
        FINALLY_CONDITIONAL_CONTINUE_SRC,
    );
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(
        body.contains("continue;"),
        "conditional finally continue missing:\n{body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "a continue-only latch became a universal loop update:\n{}",
        recompiled.source
    );
}

#[test]
fn finally_with_a_nested_try_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyNestedTry", FINALLY_NESTED_TRY_SRC);
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(
        body.contains("catch (ArithmeticException"),
        "nested catch missing from the finally body:\n{body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled nested-try finally bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn kotlin_fallthrough_finally_with_nested_try_matches_the_compiled_runtime() {
    let digest: sha2::digest::Output<sha2::Sha256> =
        <sha2::Sha256 as sha2::Digest>::digest(KOTLIN_FINALLY_NESTED_CLASS);
    assert_eq!(
        format!("{digest:x}"),
        KOTLIN_FINALLY_NESTED_SHA256,
        "the Kotlin 2.4.10 fixture changed"
    );

    let class_file: ClassFile =
        parse_classfile(KOTLIN_FINALLY_NESTED_CLASS).expect("parse Kotlin fixture");
    let first: DecompiledClass = decompile_class(&class_file);
    let second: DecompiledClass = decompile_class(&class_file);
    assert_eq!(
        first.source, second.source,
        "Kotlin recovery is not deterministic"
    );
    let body: String = assert_finally_recovered(&first.source, " compute(");
    assert!(
        body.contains("catch (ArithmeticException"),
        "Kotlin's nested typed catch is missing from the finally body:\n{body}"
    );

    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();
    let java: PathBuf = find_on_path("java")
        .unwrap_or_else(|| panic!("Kotlin finally runtime gate requires java on PATH"));
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_kotlin_finally_nested")
            .expect("create Kotlin finally scratch directory");
    let original_dir: PathBuf = scratch.path().join("original");
    let recovered_dir: PathBuf = scratch.path().join("recovered");
    let mutated_dir: PathBuf = scratch.path().join("mutated");
    for directory in [&original_dir, &recovered_dir, &mutated_dir] {
        std::fs::create_dir_all(directory.join("probe")).expect("create runtime directory");
    }
    std::fs::write(
        original_dir.join("probe").join("FinallyNested.class"),
        KOTLIN_FINALLY_NESTED_CLASS,
    )
    .expect("write Kotlin fixture class");
    let original_runner: PathBuf = original_dir.join("Runner.java");
    std::fs::write(&original_runner, KOTLIN_FINALLY_RUNNER_SOURCE)
        .expect("write original runtime runner");
    compile_kotlin_finally_runtime(&javac, &original_dir, &[original_runner]);

    let compilable_source: String = without_annotation_lines(&first.source);
    let recovered_source: PathBuf = recovered_dir.join("FinallyNested.java");
    let recovered_runner: PathBuf = recovered_dir.join("Runner.java");
    std::fs::write(&recovered_source, &compilable_source).expect("write recovered Kotlin source");
    std::fs::write(&recovered_runner, KOTLIN_FINALLY_RUNNER_SOURCE)
        .expect("write recovered runtime runner");
    compile_kotlin_finally_runtime(
        &javac,
        &recovered_dir,
        &[recovered_source, recovered_runner],
    );

    let cases: &[(i32, i32, &str)] = &[
        (2, 5, "value:52"),
        (2, 0, "value:-1"),
        (0, 5, "throw:java.lang.ArithmeticException"),
    ];
    for &(value, divisor, expected) in cases {
        let authored: String = run_kotlin_finally_runtime(&java, &original_dir, value, divisor);
        let regenerated: String = run_kotlin_finally_runtime(&java, &recovered_dir, value, divisor);
        assert_eq!(
            authored, expected,
            "unexpected Kotlin compiler runtime result"
        );
        assert_eq!(
            regenerated, authored,
            "recovered Kotlin finally changed runtime behavior for ({value}, {divisor})"
        );
    }

    let mutation_count: usize = compilable_source.matches(" = -1;").count();
    assert_eq!(mutation_count, 1, "nested catch assignment was not unique");
    let mutated_source_text: String = compilable_source.replacen(" = -1;", " = -2;", 1);
    let mutated_source: PathBuf = mutated_dir.join("FinallyNested.java");
    let mutated_runner: PathBuf = mutated_dir.join("Runner.java");
    std::fs::write(&mutated_source, mutated_source_text).expect("write mutated Kotlin source");
    std::fs::write(&mutated_runner, KOTLIN_FINALLY_RUNNER_SOURCE)
        .expect("write mutated runtime runner");
    compile_kotlin_finally_runtime(&javac, &mutated_dir, &[mutated_source, mutated_runner]);
    let mutated: String = run_kotlin_finally_runtime(&java, &mutated_dir, 2, 0);
    assert_eq!(
        mutated, "value:-2",
        "catch mutation was not runtime-visible"
    );
}

#[test]
fn finally_with_a_nested_multi_catch_recompiles_to_equivalent_bytecode() {
    let recompiled: RecompiledClass =
        recompile_recovered_class("FinallyNestedMultiCatch", FINALLY_NESTED_MULTI_CATCH_SRC);
    let body: String = assert_finally_recovered(&recompiled.source, " run(");
    assert!(
        body.contains("ArithmeticException | NullPointerException"),
        "nested multi-catch missing from the finally body:\n{body}"
    );
    assert_eq!(
        recompiled.original, recompiled.recovered,
        "recompiled nested multi-catch finally bytecode differs from the original:\n{}",
        recompiled.source
    );
}

#[test]
fn a_mismatched_nested_multi_catch_copy_is_refused_by_name() {
    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_finally_multicatch_mismatch")
            .expect("scratch");
    let directory: PathBuf = scratch.path().join("orig");
    std::fs::create_dir_all(&directory).expect("fixture directory");
    let source_path: PathBuf = directory.join("FinallyNestedMultiCatch.java");
    std::fs::write(&source_path, FINALLY_NESTED_MULTI_CATCH_SRC).expect("fixture source");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&directory)
        .arg(&source_path)
        .output()
        .expect("compile fixture");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let mut class_bytes: Vec<u8> =
        std::fs::read(directory.join("FinallyNestedMultiCatch.class")).expect("fixture class");
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse fixture");
    let table: MethodTableSite = method_exception_table(&class_bytes, &class_file, "run");
    let replacement: u16 = class_constant_index(&class_file, "java/lang/IllegalStateException");
    let arithmetic_entries: Vec<usize> = table
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry): &(usize, &ExceptionEntry)| {
            class_file.class_name(entry.catch_type).ok() == Some("java/lang/ArithmeticException")
        })
        .map(|(index, _): (usize, &ExceptionEntry)| index)
        .collect();
    let [_, handler_copy]: [usize; 2] = arithmetic_entries
        .as_slice()
        .try_into()
        .expect("one arithmetic row per finally copy");
    let catch_type_offset: usize = table.entries_offset + handler_copy * 8 + 6;
    class_bytes[catch_type_offset..catch_type_offset + 2]
        .copy_from_slice(&replacement.to_be_bytes());
    let mutated: ClassFile = parse_classfile(&class_bytes).expect("parse mutated fixture");
    let decompiled: DecompiledClass = decompile_class(&mutated);
    let body: String = method_body(&decompiled.source, " run(").expect("mutated run method");
    assert!(
        body.contains("not recovered:"),
        "mismatched multi-catch handler sets were treated as one finally copy:\n{body}"
    );
    assert!(
        !body.contains("catch (Throwable"),
        "mismatched multi-catch handler sets became a Throwable catch:\n{body}"
    );
}

#[test]
fn a_nested_catch_parameter_that_escapes_its_finally_copy_is_refused() {
    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_finally_catch_escape").expect("scratch");
    let directory: PathBuf = scratch.path().join("orig");
    std::fs::create_dir_all(&directory).expect("fixture directory");
    let source_path: PathBuf = directory.join("FinallyNestedCatchRead.java");
    std::fs::write(&source_path, FINALLY_NESTED_CATCH_READ_SRC).expect("fixture source");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&directory)
        .arg(&source_path)
        .output()
        .expect("compile fixture");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let mut class_bytes: Vec<u8> =
        std::fs::read(directory.join("FinallyNestedCatchRead.class")).expect("fixture class");
    let class_file: ClassFile = parse_classfile(&class_bytes).expect("parse fixture");
    let intact: DecompiledClass = decompile_class(&class_file);
    let intact_body: String = method_body(&intact.source, " run(").expect("intact run method");
    assert!(
        !intact_body.contains("not recovered:"),
        "the unmutated fixture must recover, otherwise this gate cannot fail:\n{intact_body}"
    );
    let table: MethodTableSite = method_exception_table(&class_bytes, &class_file, "run");
    let handler_pcs: Vec<u16> = table
        .entries
        .iter()
        .filter(|entry: &&ExceptionEntry| {
            class_file.class_name(entry.catch_type).ok() == Some("java/lang/ArithmeticException")
        })
        .map(|entry: &ExceptionEntry| entry.handler_pc)
        .collect();
    let [normal_copy, _]: [u16; 2] = handler_pcs
        .as_slice()
        .try_into()
        .expect("one arithmetic row per finally copy");
    let store_offset: usize = table.code_offset + usize::from(normal_copy);
    assert_eq!(
        (class_bytes[store_offset], class_bytes[store_offset + 1]),
        (0x4E, 0x2D),
        "the javac layout this mutation targets changed: expected astore_3 then aload_3"
    );
    class_bytes[store_offset] = 0x4D;
    class_bytes[store_offset + 1] = 0x2C;
    let mutated: ClassFile = parse_classfile(&class_bytes).expect("parse mutated fixture");
    let decompiled: DecompiledClass = decompile_class(&mutated);
    let body: String = method_body(&decompiled.source, " run(").expect("mutated run method");
    assert!(
        body.contains("not recovered:"),
        "a nested catch parameter sharing a slot that lives outside its copy was folded anyway:\n{body}"
    );
    assert!(
        !body.contains("catch (Throwable"),
        "an escaping nested catch parameter became a Throwable catch:\n{body}"
    );
}

#[test]
fn d8_nested_finally_with_discarded_catches_matches_the_compiled_runtime() {
    let digest: sha2::digest::Output<sha2::Sha256> =
        <sha2::Sha256 as sha2::Digest>::digest(D8_FINALLY_NESTED_DEX);
    assert_eq!(
        format!("{digest:x}"),
        D8_FINALLY_NESTED_SHA256,
        "the externally compiled D8 fixture changed"
    );

    let translated: Dex2JarResult =
        translate_dex_bytes(D8_FINALLY_NESTED_DEX).expect("translate the D8 fixture");
    let original: &Vec<u8> = translated
        .jar_entries
        .get("D8FinallyNested.class")
        .expect("the translated D8 fixture carries its authored class");
    let recovered: DecompiledClass =
        decompile_classfile_bytes(original).expect("decompile the translated D8 class");
    assert!(
        recovered.source.contains("finally {")
            && recovered.source.contains("catch (ArithmeticException"),
        "D8's nested typed catch did not survive inside the finally body:\n{}",
        recovered.source
    );
    assert!(
        !recovered.source.contains("not recovered:")
            && !recovered.source.contains("catch (Throwable"),
        "D8's nested finally crossed the refusal floor:\n{}",
        recovered.source
    );

    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();
    let java: PathBuf = find_on_path("java")
        .unwrap_or_else(|| panic!("D8 finally runtime gate requires java on PATH"));
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_d8_finally_nested")
            .expect("create D8 finally scratch directory");
    let original_dir: PathBuf = scratch.path().join("original");
    let recovered_dir: PathBuf = scratch.path().join("recovered");
    std::fs::create_dir_all(&original_dir).expect("create original runtime directory");
    std::fs::create_dir_all(&recovered_dir).expect("create recovered runtime directory");
    std::fs::write(original_dir.join("D8FinallyNested.class"), original)
        .expect("write translated D8 class");
    let original_runner: PathBuf = original_dir.join("Runner.java");
    std::fs::write(&original_runner, D8_FINALLY_RUNNER_SOURCE).expect("write original runner");
    compile_d8_finally_runtime(&javac, &original_dir, &[original_runner]);
    let recovered_source: PathBuf = recovered_dir.join("D8FinallyNested.java");
    let recovered_runner: PathBuf = recovered_dir.join("Runner.java");
    std::fs::write(&recovered_source, &recovered.source).expect("write recovered D8 source");
    std::fs::write(&recovered_runner, D8_FINALLY_RUNNER_SOURCE).expect("write recovered runner");
    compile_d8_finally_runtime(
        &javac,
        &recovered_dir,
        &[recovered_source, recovered_runner],
    );

    let cases: &[(i32, i32, i32, &str)] = &[
        (6, 2, 10, "value:3:counter:13"),
        (1, 0, 7, "throw:java.lang.ArithmeticException:counter:-1"),
        (-9, 3, 2, "value:-3:counter:-1"),
    ];
    for &(left, right, seed, expected) in cases {
        let authored: String = run_d8_finally_runtime(&java, &original_dir, left, right, seed);
        let regenerated: String = run_d8_finally_runtime(&java, &recovered_dir, left, right, seed);
        assert_eq!(
            authored, expected,
            "the pinned D8 artifact no longer matches its authored source for ({left}, {right}, {seed})\n{D8_FINALLY_NESTED_SOURCE}"
        );
        assert_eq!(
            regenerated, authored,
            "the recovered D8 finally changed runtime behavior for ({left}, {right}, {seed})\n{}",
            recovered.source
        );
    }
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
    static int finallyNestedTryUsesCatch(int a, int b) {\n\
        try {\n\
            return a / b;\n\
        } finally {\n\
            try {\n\
                CTR += a / b;\n\
            } catch (ArithmeticException ex) {\n\
                CTR = ex.hashCode();\n\
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
    static void finallyThrowsVoid(int a) {\n\
        try {\n\
            CTR = a;\n\
        } finally {\n\
            if (a < 0) { throw new IllegalStateException(\"neg\"); }\n\
        }\n\
    }\n\
    static int finallyThrowsAlways(int a) {\n\
        try {\n\
            return a;\n\
        } finally {\n\
            throw new IllegalStateException(\"always\");\n\
        }\n\
    }\n\
    static int finallyLoops(int a) {\n\
        try {\n\
            return a;\n\
        } finally {\n\
            for (int i = 0; i < a; i++) { CTR++; }\n\
        }\n\
    }\n\
    static int finallySpins(int a) {\n\
        try {\n\
            return a;\n\
        } finally {\n\
            while (true) { CTR++; }\n\
        }\n\
    }\n\
}\n";

const UNMODELLED_FINALLY_METHODS: &[(&str, &str)] = &[
    (
        "finallyLoops",
        "a compiler-inserted finally handler with internal control flow has no source form this \
         structurer can build",
    ),
    (
        "finallySpins",
        "a compiler-inserted finally handler forms no foldable chain",
    ),
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
    for &(method, reason) in UNMODELLED_FINALLY_METHODS {
        let body: String =
            method_body(&decompiled.source, &format!(" {method}(")).unwrap_or_else(|| {
                panic!(
                    "method {method} vanished from the recovered class:\n{}",
                    decompiled.source
                )
            });
        assert!(
            body.contains(reason),
            "method {method} no longer refuses with its recorded reason {reason:?}:\n{body}"
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

const AUTHOR_THROWABLE_SRC: &str = "public class AuthorThrowable {\n\
    static int CTR = 0;\n\
    static int caught(int a) {\n\
        try {\n\
            return 100 / a;\n\
        } catch (Throwable t) {\n\
            CTR++;\n\
            return -1;\n\
        }\n\
    }\n\
}\n";

#[test]
fn an_author_written_throwable_catch_still_renders_as_a_catch() {
    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();

    let purpose: String = format!("disrobe_author_throwable_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    std::fs::create_dir_all(&dir).expect("mkdir");

    let src_path: PathBuf = dir.join("AuthorThrowable.java");
    std::fs::write(&src_path, AUTHOR_THROWABLE_SRC).expect("write src");
    let compile: std::process::Output = Command::new(&javac)
        .arg("-proc:none")
        .arg("-d")
        .arg(&dir)
        .arg(&src_path)
        .output()
        .expect("javac orig");
    assert!(
        compile.status.success(),
        "fixture failed to compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let class_bytes: Vec<u8> =
        std::fs::read(dir.join("AuthorThrowable.class")).expect("read class");
    let cf: ClassFile = parse_classfile(&class_bytes).expect("parse");
    let decompiled: DecompiledClass = decompile_class(&cf);

    assert!(
        decompiled.source.contains("catch (Throwable"),
        "an author-written catch (Throwable) must still render as a catch, not be refused as an \
         unmodellable finally:\n{}",
        decompiled.source
    );
    assert!(
        !decompiled.source.contains("not recovered:"),
        "an author-written catch (Throwable) must not be refused:\n{}",
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
