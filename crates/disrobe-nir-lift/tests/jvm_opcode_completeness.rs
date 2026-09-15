#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{jvm_function_address, lift_classfile};
use disrobe_pass_jvm::{
    Attribute, ClassFile, Instruction, MethodInfo, disassemble, parse_classfile,
    parse_code_attribute,
};

const STRINGER_CLASS: &[u8] = include_bytes!("../../../corpus/jvm/stringer/StringerClassic.class");

const BROAD_SOURCE: &str = r#"public class Broad {
    static int[] arr = new int[4];
    int field;
    static volatile int svalue;

    public static long arith(int a, int b) {
        long r = (long) (a + b - a * b);
        r ^= (a & b) | (a << 2);
        r %= (b == 0 ? 1 : b);
        double d = (double) r / 3.0;
        return (long) (d + r);
    }

    public static int loop(int n) {
        int acc = 0;
        for (int i = 0; i < n; i++) {
            acc += i * 2;
        }
        return acc;
    }

    public static int table(int x) {
        switch (x) {
            case 0: return 10;
            case 1: return 11;
            case 2: return 12;
            case 3: return 13;
            default: return -1;
        }
    }

    public static int lookup(int x) {
        switch (x) {
            case 10: return 1;
            case 100: return 2;
            case 1000: return 3;
            default: return 0;
        }
    }

    public static synchronized void sync(Object o) {
        synchronized (o) {
            svalue++;
        }
    }

    public static Object cast(Object o) {
        if (o instanceof String) {
            return (String) o;
        }
        throw new IllegalStateException("bad");
    }

    public static String build(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append(s);
        sb.append(s.length());
        return sb.toString();
    }

    public static int caller(int a, int b) {
        long x = arith(a, b);
        int y = table(a) + lookup(b) + loop(a);
        return (int) x + y;
    }

    public int len(Object[] xs) {
        return xs.length + this.field;
    }
}
"#;

#[derive(Debug, Default)]
struct NirStats {
    total: usize,
    unmodeled: usize,
    opcodes: BTreeSet<u8>,
    mnemonics: BTreeSet<String>,
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("-version").output().is_ok()
}

fn method_code(class: &ClassFile, info: &MethodInfo) -> Option<Vec<u8>> {
    for attribute in &info.attributes {
        let attribute: &Attribute = attribute;
        if class.utf8_at(attribute.name_index).ok() == Some("Code") {
            let code: disrobe_pass_jvm::CodeAttribute =
                parse_code_attribute(&attribute.info).ok()?;
            return Some(code.code);
        }
    }
    None
}

fn method_streams(class_bytes: &[u8]) -> Vec<(u64, Vec<Instruction>)> {
    let class: ClassFile = parse_classfile(class_bytes).expect("parse classfile");
    let mut out: Vec<(u64, Vec<Instruction>)> = Vec::new();
    for (index, info) in class.methods.iter().enumerate() {
        let method_index: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        let base: u64 = jvm_function_address(method_index);
        let Some(code): Option<Vec<u8>> = method_code(&class, info) else {
            continue;
        };
        let insns: Vec<Instruction> = disassemble(&code).expect("disassemble method body");
        out.push((base, insns));
    }
    out
}

fn disrobe_offset_mnemonics(class_bytes: &[u8]) -> Vec<Vec<(u32, String)>> {
    let mut streams: Vec<Vec<(u32, String)>> = method_streams(class_bytes)
        .into_iter()
        .map(|(_, insns): (u64, Vec<Instruction>)| {
            insns
                .iter()
                .map(|insn: &Instruction| (insn.pc, insn.mnemonic.to_owned()))
                .collect::<Vec<(u32, String)>>()
        })
        .collect();
    streams.sort();
    streams
}

fn parse_instruction_line(trimmed: &str) -> Option<(u32, String)> {
    let (offset_text, rest): (&str, &str) = trimmed.split_once(": ")?;
    if offset_text.is_empty() || !offset_text.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    let offset: u32 = offset_text.parse().ok()?;
    let mnemonic: &str = rest.split_whitespace().next()?;
    let first: u8 = mnemonic.bytes().next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    if !mnemonic
        .bytes()
        .all(|b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some((offset, mnemonic.to_owned()))
}

fn javap_offset_mnemonics(javap_stdout: &str) -> Vec<Vec<(u32, String)>> {
    let mut methods: Vec<Vec<(u32, String)>> = Vec::new();
    let mut current: Option<Vec<(u32, String)>> = None;
    for line in javap_stdout.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed == "Code:" {
            if let Some(done) = current.replace(Vec::new()) {
                methods.push(done);
            }
            continue;
        }
        let Some(pair): Option<(u32, String)> = parse_instruction_line(trimmed) else {
            continue;
        };
        if let Some(stream) = current.as_mut() {
            stream.push(pair);
        }
    }
    if let Some(done) = current.take() {
        methods.push(done);
    }
    methods.sort();
    methods
}

fn nir_invariants(class_bytes: &[u8]) -> NirStats {
    let module: NirModule = lift_classfile(class_bytes).expect("lift classfile to NIR");
    let disasm_by_base: BTreeMap<u64, Vec<Instruction>> =
        method_streams(class_bytes).into_iter().collect();
    let mut stats: NirStats = NirStats::default();
    for function in &module.functions {
        let function: &NirFunction = function;
        let disasm: &Vec<Instruction> = disasm_by_base
            .get(&function.address)
            .expect("disassembly for every lifted function base");
        assert_eq!(
            function.instructions.len(),
            disasm.len(),
            "NIR and disassembly must be one to one for {}",
            function.name
        );
        for (nir, raw) in function.instructions.iter().zip(disasm.iter()) {
            let nir: &NirInstr = nir;
            let raw: &Instruction = raw;
            stats.total += 1;
            stats.opcodes.insert(raw.opcode);
            stats.mnemonics.insert(raw.mnemonic.to_owned());
            assert_eq!(
                nir.address,
                function.address.saturating_add(u64::from(raw.pc)),
                "lifted address must track the bytecode offset"
            );
            match &nir.op {
                NirOp::Nop => assert_eq!(
                    raw.opcode, 0x00,
                    "only a real nop lifts to Nop, saw {} at offset {}",
                    raw.mnemonic, raw.pc
                ),
                NirOp::Unmodeled { opcode, offset } => {
                    assert_eq!(*opcode, raw.opcode, "Unmodeled must carry the real opcode");
                    assert_eq!(*offset, raw.pc, "Unmodeled must carry the real offset");
                    stats.unmodeled += 1;
                }
                _ => assert_ne!(
                    raw.opcode, 0x00,
                    "a real nop must never lift to a modeled op"
                ),
            }
        }
    }
    stats
}

#[test]
fn committed_class_surfaces_unmodeled_opcodes_without_silent_nop() {
    let stats: NirStats = nir_invariants(STRINGER_CLASS);
    assert!(stats.total > 0, "fixture must lift to instructions");
    assert!(
        stats.unmodeled >= 1,
        "the committed class exercises unmodeled opcodes: {stats:?}"
    );
}

#[test]
fn jvm_lift_agrees_with_javap_and_surfaces_unmodeled_opcodes() {
    if !tool_available("javac") || !tool_available("javap") {
        eprintln!("skipping javap agreement: JDK javac/javap not on PATH");
        return;
    }

    let dir: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("jvm_opcode_completeness");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let source: PathBuf = dir.join("Broad.java");
    std::fs::write(&source, BROAD_SOURCE).expect("write java source");

    let javac: Output = Command::new("javac")
        .arg("-d")
        .arg(&dir)
        .arg(&source)
        .output()
        .expect("run javac");
    assert!(
        javac.status.success(),
        "javac failed: {}",
        String::from_utf8_lossy(&javac.stderr)
    );

    let class_path: PathBuf = dir.join("Broad.class");
    let class_bytes: Vec<u8> = std::fs::read(&class_path).expect("read compiled class");

    let javap: Output = Command::new("javap")
        .arg("-c")
        .arg("-p")
        .arg(&class_path)
        .output()
        .expect("run javap");
    assert!(
        javap.status.success(),
        "javap failed: {}",
        String::from_utf8_lossy(&javap.stderr)
    );
    let javap_text: String = String::from_utf8_lossy(&javap.stdout).into_owned();

    let lifted: Vec<Vec<(u32, String)>> = disrobe_offset_mnemonics(&class_bytes);
    let expected: Vec<Vec<(u32, String)>> = javap_offset_mnemonics(&javap_text);
    assert_eq!(
        lifted, expected,
        "disrobe lifted (offset, mnemonic) stream must equal javap -c"
    );

    let stats: NirStats = nir_invariants(&class_bytes);
    assert!(
        stats.unmodeled >= 20,
        "a broad method set must surface many unmodeled opcodes: {stats:?}"
    );
    assert!(
        stats.opcodes.len() >= 25,
        "the opcode range must be non-vacuous: {} distinct",
        stats.opcodes.len()
    );
    for mnemonic in [
        "tableswitch",
        "lookupswitch",
        "athrow",
        "monitorenter",
        "monitorexit",
        "invokestatic",
        "invokevirtual",
        "invokespecial",
        "iinc",
        "checkcast",
        "instanceof",
        "arraylength",
        "new",
        "getstatic",
        "putstatic",
        "getfield",
        "i2l",
        "dup",
        "goto",
    ] {
        assert!(
            stats.mnemonics.contains(mnemonic),
            "opcode range must include {mnemonic}"
        );
    }
}
