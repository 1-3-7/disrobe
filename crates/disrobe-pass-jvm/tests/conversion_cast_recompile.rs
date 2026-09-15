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

const CONV_FIXTURE: &str = r"public class ConvCases {
    static long i2l(int x) { return (long) x; }
    static float i2f(int x) { return (float) x; }
    static double i2d(int x) { return (double) x; }
    static int l2i(long x) { return (int) x; }
    static float l2f(long x) { return (float) x; }
    static double l2d(long x) { return (double) x; }
    static int f2i(float x) { return (int) x; }
    static long f2l(float x) { return (long) x; }
    static double f2d(float x) { return (double) x; }
    static int d2i(double x) { return (int) x; }
    static long d2l(double x) { return (long) x; }
    static float d2f(double x) { return (float) x; }
    static byte i2b(int x) { return (byte) x; }
    static char i2c(int x) { return (char) x; }
    static short i2s(int x) { return (short) x; }
    static int chain(int x) { return (int) (byte) (x * 260 + 1); }
    static long roundTrip(float f, double d, int i) {
        return (long) f + (long) d + (long) (byte) i + (long) (short) i + (long) (char) i;
    }
}
";

const CONV_METHODS: &[&str] = &[
    "i2l",
    "i2f",
    "i2d",
    "l2i",
    "l2f",
    "l2d",
    "f2i",
    "f2l",
    "f2d",
    "d2i",
    "d2l",
    "d2f",
    "i2b",
    "i2c",
    "i2s",
    "chain",
    "roundTrip",
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

#[test]
fn conversion_casts_recompile_to_equivalent_bytecode() {
    let Some(javac_path): Option<PathBuf> = find_on_path("javac") else {
        eprintln!(
            "SKIP: javac not on PATH; conversion-cast byte-equivalence gate NOT enforced. \
             CORPUS-BLOCKED for i2b/i2c/i2s/i2l/f2l/d2i and the other numeric conversions."
        );
        return;
    };
    let purpose: String = format!("disrobe_conv_cast_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let gold: PathBuf = root.join("gold");
    let recov: PathBuf = root.join("recov");
    std::fs::create_dir_all(&gold).expect("mkdir gold");
    std::fs::create_dir_all(&recov).expect("mkdir recov");

    let gold_src: PathBuf = gold.join("ConvCases.java");
    std::fs::write(&gold_src, CONV_FIXTURE).expect("write fixture");
    let (gold_ok, gold_err): (bool, String) = javac(&javac_path, &gold, &gold_src);
    assert!(gold_ok, "reference fixture did not compile: {gold_err}");
    let gold_bytes: Vec<u8> = std::fs::read(gold.join("ConvCases.class")).expect("read gold class");
    let gold_cf: ClassFile = parse_classfile(&gold_bytes).expect("parse gold");

    let recovered: String = decompile_class(&gold_cf).source;

    let recov_src: PathBuf = recov.join("ConvCases.java");
    std::fs::write(&recov_src, &recovered).expect("write recovered");
    let (recov_ok, recov_err): (bool, String) = javac(&javac_path, &recov, &recov_src);
    assert!(
        recov_ok,
        "recovered ConvCases did not recompile under real javac: {recov_err}\nrecovered source:\n{recovered}"
    );
    let recov_bytes: Vec<u8> =
        std::fs::read(recov.join("ConvCases.class")).expect("read recovered class");
    let recov_cf: ClassFile = parse_classfile(&recov_bytes).expect("parse recovered");

    for name in CONV_METHODS {
        let gold_stream: Vec<String> =
            method_stream(&gold_cf, name).unwrap_or_else(|| panic!("gold method {name} missing"));
        let recov_stream: Vec<String> = method_stream(&recov_cf, name)
            .unwrap_or_else(|| panic!("recovered method {name} missing"));
        assert_eq!(
            gold_stream, recov_stream,
            "conversion method `{name}` did not recompile to an equivalent instruction stream; \
             a mis-mapped numeric-conversion opcode changes the recovered cast type. \
             recovered source:\n{recovered}"
        );
    }
}
