#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::bytecode::{
    Instruction, Operands, class_internal_name_at, disassemble, parse_code_attribute, resolve_ref,
};
use disrobe_pass_jvm::classfile::{Attribute, MethodInfo};
use disrobe_pass_jvm::{ClassFile, decompile_class, parse_classfile};

const BOOL_FIXTURE: &str = r"public class BoolArrCases {
    static int countTrue(boolean[] flags) {
        int n = 0;
        for (int i = 0; i < flags.length; i++) {
            boolean f = flags[i];
            if (f) { n++; }
        }
        return n;
    }
    static int countForEach(boolean[] flags) {
        int n = 0;
        for (boolean f : flags) {
            if (f) { n++; }
        }
        return n;
    }
    static boolean firstOr(boolean[] flags, boolean fallback) {
        if (flags.length == 0) { return fallback; }
        boolean head = flags[0];
        return head;
    }
    static int sumByteIndexed(byte[] data) {
        int n = 0;
        for (int i = 0; i < data.length; i++) {
            int v = data[i];
            n += v;
        }
        return n;
    }
    static int sumShortIndexed(short[] data) {
        int n = 0;
        for (int i = 0; i < data.length; i++) {
            int v = data[i];
            n += v;
        }
        return n;
    }
    static int sumCharIndexed(char[] data) {
        int n = 0;
        for (int i = 0; i < data.length; i++) {
            int v = data[i];
            n += v;
        }
        return n;
    }
    static int countGrid(boolean[][] grid) {
        int n = 0;
        for (int i = 0; i < grid.length; i++) {
            for (int j = 0; j < grid[i].length; j++) {
                boolean f = grid[i][j];
                if (f) { n++; }
            }
        }
        return n;
    }
    static boolean cubeElement(boolean[][][] cube, int i, int j, int k) {
        boolean f = cube[i][j][k];
        return f;
    }
    static boolean multiNewGrid(int n) {
        boolean[][] grid = new boolean[n][n];
        grid[0][0] = true;
        boolean f = grid[0][0];
        return f;
    }
    static int sumByteGrid(byte[][] grid, int i, int j) {
        int v = grid[i][j];
        return v;
    }
}
";

const BOOL_COND_FIXTURE: &str = r#"public class BoolCondCases {
    static boolean FLAG = false;
    static boolean gt(int a, int b) {
        boolean r = a > b;
        return r;
    }
    static boolean negated(int a) {
        boolean r = !(a > 0);
        return r;
    }
    static boolean nullCheck(Object o) {
        boolean r = o == null;
        return r;
    }
    static boolean ternary(int a) {
        boolean r = a > 0 ? true : false;
        return r;
    }
    static boolean branchAssigned(int a) {
        boolean r;
        if (a > 0) {
            r = true;
        } else {
            r = false;
        }
        return r;
    }
    static boolean viaField(int a) {
        boolean r = a > 0;
        FLAG = r;
        return FLAG;
    }
    static boolean fromCall(String s) {
        boolean r = s.isEmpty();
        return r;
    }
    static int countPositive(int[] xs) {
        int n = 0;
        for (int x : xs) {
            boolean p = x > 0;
            if (p) { n++; }
        }
        return n;
    }
    static String describe(int a) {
        boolean r = a > 0;
        return "v=" + r;
    }
    static boolean widened(int a) {
        int t = a + 1;
        boolean r = t > 0;
        return r;
    }
}
"#;

const BOOL_COND_METHODS: &[&str] = &[
    "gt",
    "negated",
    "nullCheck",
    "ternary",
    "branchAssigned",
    "viaField",
    "fromCall",
    "countPositive",
    "describe",
    "widened",
];

const BOOL_METHODS: &[&str] = &[
    "countTrue",
    "countForEach",
    "firstOr",
    "sumByteIndexed",
    "sumShortIndexed",
    "sumCharIndexed",
    "countGrid",
    "cubeElement",
    "multiNewGrid",
    "sumByteGrid",
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

fn require_javac() -> PathBuf {
    find_on_path("javac")
        .unwrap_or_else(|| panic!("boolean-array typing gate requires javac on PATH"))
}

fn canon_insn(cf: &ClassFile, insn: &Instruction) -> String {
    let m: &str = insn.mnemonic;
    for ty in ['a', 'i', 'l', 'f', 'd'] {
        for op in ["load", "store"] {
            let base: String = format!("{ty}{op}");
            if m == base
                && let Operands::Local(s) = insn.operands
            {
                return format!("{ty}{op} {s}");
            }
            for n in 0u16..=3 {
                if m == format!("{base}_{n}") {
                    return format!("{ty}{op} {n}");
                }
            }
        }
    }
    match &insn.operands {
        Operands::None => m.to_string(),
        Operands::Byte(v) | Operands::Short(v) => format!("push {v}"),
        Operands::Local(s) => format!("{m} {s}"),
        Operands::Branch(off) => format!("{m} @{off}"),
        Operands::ConstPool(i) => {
            let r: String = resolve_ref(cf, *i)
                .or_else(|| class_internal_name_at(cf, *i))
                .unwrap_or_else(|| format!("cp{i}"));
            format!("{m} {r}")
        }
        Operands::Iinc { index, delta } => format!("iinc {index} {delta}"),
        Operands::NewArray(t) => format!("newarray {t}"),
        Operands::InvokeInterface { index, count } => {
            let r: String = resolve_ref(cf, *index).unwrap_or_else(|| format!("cp{index}"));
            format!("invokeinterface {r} {count}")
        }
        Operands::InvokeDynamic(i) => format!("invokedynamic cp{i}"),
        Operands::MultiANewArray { index, dimensions } => {
            let r: String =
                class_internal_name_at(cf, *index).unwrap_or_else(|| format!("cp{index}"));
            format!("multianewarray {r} {dimensions}")
        }
        Operands::TableSwitch {
            default,
            low,
            high,
            offsets,
        } => format!("tableswitch d@{default} {low}..{high} {offsets:?}"),
        Operands::LookupSwitch { default, pairs } => format!("lookupswitch d@{default} {pairs:?}"),
    }
}

fn method_stream(cf: &ClassFile, method_name: &str) -> Option<Vec<String>> {
    let method: &MethodInfo = cf.methods.iter().find(|mm: &&MethodInfo| {
        cf.utf8_at(mm.name_index)
            .is_ok_and(|n: &str| n == method_name)
    })?;
    let code_attr: &Attribute = method
        .attributes
        .iter()
        .find(|a: &&Attribute| cf.utf8_at(a.name_index).is_ok_and(|n: &str| n == "Code"))?;
    let code: disrobe_pass_jvm::bytecode::CodeAttribute =
        parse_code_attribute(&code_attr.info).ok()?;
    let insns: Vec<Instruction> = disassemble(&code.code).ok()?;
    Some(
        insns
            .iter()
            .map(|i: &Instruction| canon_insn(cf, i))
            .collect(),
    )
}

fn javac(javac: &PathBuf, dir: &PathBuf, file: &PathBuf) -> (bool, String) {
    let out: std::process::Output = Command::new(javac)
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

fn compile_and_parse(
    javac_path: &PathBuf,
    dir: &PathBuf,
    class: &str,
    source: &str,
) -> Result<ClassFile, String> {
    std::fs::create_dir_all(dir).expect("mkdir");
    let src: PathBuf = dir.join(format!("{class}.java"));
    std::fs::write(&src, source).expect("write source");
    let (ok, err): (bool, String) = javac(javac_path, dir, &src);
    if !ok {
        return Err(err);
    }
    let bytes: Vec<u8> = std::fs::read(dir.join(format!("{class}.class"))).expect("read class");
    parse_classfile(&bytes).map_err(|e: disrobe_pass_jvm::Error| e.to_string())
}

fn divergent_methods(gold: &ClassFile, other: &ClassFile, methods: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in methods {
        let gold_stream: Vec<String> =
            method_stream(gold, name).unwrap_or_else(|| panic!("reference method {name} missing"));
        match method_stream(other, name) {
            Some(other_stream) if other_stream == gold_stream => {}
            Some(_) => out.push((*name).to_owned()),
            None => out.push(format!("{name} (missing)")),
        }
    }
    out
}

fn recovered_stream_divergence(
    javac_path: &PathBuf,
    purpose: &str,
    class: &str,
    fixture: &str,
    methods: &[&str],
) -> (Vec<String>, String) {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let gold: PathBuf = root.join("gold");
    let recov: PathBuf = root.join("recov");

    let gold_cf: ClassFile = compile_and_parse(javac_path, &gold, class, fixture)
        .unwrap_or_else(|e: String| panic!("reference fixture did not compile: {e}"));
    let recovered: String = decompile_class(&gold_cf).source;
    let recov_cf: ClassFile = compile_and_parse(javac_path, &recov, class, &recovered)
        .unwrap_or_else(|e: String| {
            panic!(
                "recovered {class} did not recompile under real javac: {e}\nrecovered source:\n\
                 {recovered}"
            )
        });
    (divergent_methods(&gold_cf, &recov_cf, methods), recovered)
}

#[test]
fn boolean_array_elements_recompile_to_equivalent_bytecode() {
    let javac_path: PathBuf = require_javac();
    let purpose: String = format!("disrobe_bool_arr_{}", std::process::id());
    let (diverged, recovered): (Vec<String>, String) = recovered_stream_divergence(
        &javac_path,
        &purpose,
        "BoolArrCases",
        BOOL_FIXTURE,
        BOOL_METHODS,
    );
    assert!(
        diverged.is_empty(),
        "these methods did not recompile to an equivalent instruction stream: {diverged:?}; \
         a boolean[] baload element mis-typed as int changes the recovered local type. \
         recovered source:\n{recovered}"
    );
}

#[test]
fn conditional_derived_booleans_recompile_to_equivalent_bytecode() {
    let javac_path: PathBuf = require_javac();
    let purpose: String = format!("disrobe_bool_cond_{}", std::process::id());
    let (diverged, recovered): (Vec<String>, String) = recovered_stream_divergence(
        &javac_path,
        &purpose,
        "BoolCondCases",
        BOOL_COND_FIXTURE,
        BOOL_COND_METHODS,
    );
    assert!(
        diverged.is_empty(),
        "these methods did not recompile to an equivalent instruction stream: {diverged:?}; \
         a boolean produced by a comparison must recover as a boolean local, not an int. \
         recovered source:\n{recovered}"
    );
}

#[test]
fn the_boolean_typing_gate_reports_an_int_local_standing_in_for_a_boolean() {
    let javac_path: PathBuf = require_javac();
    let mutant: String = BOOL_COND_FIXTURE.replace(
        "    static boolean gt(int a, int b) {\n        boolean r = a > b;\n        return r;\n",
        "    static boolean gt(int a, int b) {\n        int r = a > b ? 1 : 0;\n        return r \
         != 0;\n",
    );
    assert_ne!(
        mutant, BOOL_COND_FIXTURE,
        "the mutation-kill control did not apply; the method it targets moved"
    );

    let purpose: String = format!("disrobe_bool_cond_control_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let gold_cf: ClassFile = compile_and_parse(
        &javac_path,
        &root.join("gold"),
        "BoolCondCases",
        BOOL_COND_FIXTURE,
    )
    .unwrap_or_else(|e: String| panic!("reference fixture did not compile: {e}"));
    let bad_cf: ClassFile =
        compile_and_parse(&javac_path, &root.join("bad"), "BoolCondCases", &mutant)
            .unwrap_or_else(|e: String| panic!("control fixture did not compile: {e}"));

    let diverged: Vec<String> = divergent_methods(&gold_cf, &bad_cf, BOOL_COND_METHODS);
    assert!(
        diverged.iter().any(|m: &String| m == "gt"),
        "a boolean local replaced by an int local was NOT reported as divergent, so this gate \
         measures nothing; diffs were: {diverged:?}"
    );
}

#[test]
fn boolean_array_gate_fails_when_javac_is_unavailable() {
    let test_binary: PathBuf = std::env::current_exe().expect("current test binary");
    let output: std::process::Output = Command::new(test_binary)
        .arg("--exact")
        .arg("boolean_array_elements_recompile_to_equivalent_bytecode")
        .arg("--test-threads=1")
        .env("PATH", "")
        .output()
        .expect("run boolean-array gate without javac");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the boolean-array gate passed without javac; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        format!("{stdout}\n{stderr}").contains("boolean-array typing gate requires javac on PATH"),
        "the boolean-array gate failed for an unrelated reason; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
