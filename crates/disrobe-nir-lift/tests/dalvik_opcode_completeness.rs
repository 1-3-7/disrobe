#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{dalvik_function_address, lift_dex};
use disrobe_pass_jvm::{CodeItem, DalvikInsn, DexFile, decode_method, parse_code_items, parse_dex};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGE_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGE_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");
const WIDGET_R8_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/obfuscators/r8/Widget-r8.dex");

const FIXTURES: [(&str, &[u8]); 4] = [
    ("Hello.dex", HELLO_DEX),
    ("EdgeCases.dex", EDGE_DEX),
    ("EdgeCasesKt.dex", EDGE_KT_DEX),
    ("obfuscators/r8/Widget-r8.dex", WIDGET_R8_DEX),
];

const PAYLOAD_PSEUDO: [&str; 6] = [
    "packed-switch-data",
    "sparse-switch-data",
    "array-data",
    "packed-switch-payload",
    "sparse-switch-payload",
    "fill-array-data-payload",
];

#[derive(Debug, Default)]
struct NirStats {
    total: usize,
    unmodeled: usize,
    nop: usize,
    opcodes: BTreeSet<u8>,
    mnemonics: BTreeSet<String>,
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn raw_streams(bytes: &[u8]) -> BTreeMap<u64, Vec<DalvikInsn>> {
    let dex: DexFile = parse_dex(bytes).expect("parse dex");
    let items: Vec<CodeItem> = parse_code_items(&dex, bytes);
    let mut out: BTreeMap<u64, Vec<DalvikInsn>> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let method_index: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        let base: u64 = dalvik_function_address(method_index);
        out.insert(base, decode_method(&item.insns));
    }
    out
}

fn nir_invariants(bytes: &[u8]) -> NirStats {
    let module: NirModule = lift_dex(bytes).expect("lift dex to NIR");
    let raw_by_base: BTreeMap<u64, Vec<DalvikInsn>> = raw_streams(bytes);

    let mut stats: NirStats = NirStats::default();
    for function in &module.functions {
        let function: &NirFunction = function;
        let raw: &Vec<DalvikInsn> = raw_by_base
            .get(&function.address)
            .expect("a decoded instruction stream for every lifted function base");
        assert_eq!(
            function.instructions.len(),
            raw.len(),
            "NIR and decoded instruction stream must be one to one for {}",
            function.name
        );
        for (nir, insn) in function.instructions.iter().zip(raw.iter()) {
            let nir: &NirInstr = nir;
            let insn: &DalvikInsn = insn;
            stats.total += 1;
            stats.opcodes.insert(insn.op);
            stats.mnemonics.insert(insn.mnemonic.to_owned());
            assert_eq!(
                nir.address,
                function.address.saturating_add(u64::from(insn.pc)),
                "lifted address must track the bytecode offset for {}",
                function.name
            );
            match &nir.op {
                NirOp::Nop => {
                    stats.nop += 1;
                    assert_eq!(
                        insn.op, 0x00,
                        "only a real nop lifts to Nop, saw {} at offset {} in {}",
                        insn.mnemonic, insn.pc, function.name
                    );
                }
                NirOp::Unmodeled { opcode, offset } => {
                    assert_eq!(
                        *opcode, insn.op,
                        "Unmodeled must carry the real opcode in {}",
                        function.name
                    );
                    assert_eq!(
                        *offset, insn.pc,
                        "Unmodeled must carry the real offset in {}",
                        function.name
                    );
                    stats.unmodeled += 1;
                }
                _ => assert_ne!(
                    insn.op, 0x00,
                    "a real nop must never lift to a modeled op in {}",
                    function.name
                ),
            }
        }
    }
    stats
}

fn merged_stats() -> NirStats {
    let mut merged: NirStats = NirStats::default();
    for (name, bytes) in FIXTURES {
        let stats: NirStats = nir_invariants(bytes);
        assert!(stats.total > 0, "{name} must lift to instructions");
        merged.total += stats.total;
        merged.unmodeled += stats.unmodeled;
        merged.nop += stats.nop;
        merged.opcodes.extend(stats.opcodes);
        merged.mnemonics.extend(stats.mnemonics);
    }
    merged
}

#[test]
fn committed_dex_surfaces_unmodeled_without_silent_nop() {
    let merged: NirStats = merged_stats();
    assert!(
        merged.unmodeled >= 200,
        "unmodeled dalvik opcodes must be surfaced, not collapsed to Nop: {}",
        merged.unmodeled
    );
    assert!(
        merged.opcodes.len() >= 60,
        "the opcode range must be non-vacuous: {} distinct",
        merged.opcodes.len()
    );
    for mnemonic in [
        "move",
        "move-result",
        "move-exception",
        "move-object/from16",
        "new-instance",
        "new-array",
        "filled-new-array",
        "const-string",
        "const/4",
        "if-eq",
        "if-eqz",
        "aget",
        "aput",
        "iget",
        "iput",
        "sget",
        "invoke-virtual",
        "invoke-static",
        "invoke-direct",
        "invoke-interface",
        "monitor-enter",
        "monitor-exit",
        "packed-switch",
        "check-cast",
        "instance-of",
        "array-length",
        "cmp-long",
        "int-to-long",
        "goto",
        "throw",
        "return-void",
    ] {
        assert!(
            merged.mnemonics.contains(mnemonic),
            "opcode range must include {mnemonic}: {:?}",
            merged.mnemonics
        );
    }
}

#[test]
fn move_wide_and_quick_forms_surface_as_unmodeled_not_nop() {
    let mut saw_move: bool = false;
    let mut saw_range_invoke: bool = false;
    for (_, bytes) in FIXTURES {
        let module: NirModule = lift_dex(bytes).expect("lift dex to NIR");
        for function in &module.functions {
            for instr in &function.instructions {
                let instr: &NirInstr = instr;
                if instr.mnemonic.starts_with("move") && !instr.mnemonic.starts_with("move-result")
                {
                    saw_move = true;
                    assert!(
                        instr.op.is_unmodeled(),
                        "a register move must never collapse to a silent Nop: {}",
                        instr.mnemonic
                    );
                }
                if instr.mnemonic.starts_with("invoke") && instr.mnemonic.ends_with("/range") {
                    saw_range_invoke = true;
                    assert!(
                        matches!(instr.op, NirOp::Call { .. } | NirOp::IndirectCall),
                        "a range invoke must lift to a call, saw {:?} for {}",
                        instr.op,
                        instr.mnemonic
                    );
                }
            }
        }
    }
    assert!(saw_move, "fixtures exercise register move forms");
    assert!(saw_range_invoke, "fixtures exercise a range invoke form");
}

fn disrobe_offset_opcodes(bytes: &[u8]) -> Vec<Vec<(u32, u8)>> {
    let mut streams: Vec<Vec<(u32, u8)>> = raw_streams(bytes)
        .into_values()
        .map(|insns: Vec<DalvikInsn>| {
            insns
                .iter()
                .map(|insn: &DalvikInsn| (insn.pc, insn.op))
                .collect::<Vec<(u32, u8)>>()
        })
        .filter(|stream: &Vec<(u32, u8)>| !stream.is_empty())
        .collect();
    streams.sort();
    streams
}

fn parse_dexdump_instruction(line: &str) -> Option<(u32, u8, String)> {
    let (left, right): (&str, &str) = line.split_once('|')?;
    let right: &str = right.trim_start();
    if right.starts_with('[') {
        return None;
    }
    let (offset_text, rest): (&str, &str) = right.split_once(": ")?;
    let offset_text: &str = offset_text.trim();
    if offset_text.is_empty() || !offset_text.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return None;
    }
    let offset: u32 = u32::from_str_radix(offset_text, 16).ok()?;
    let mnemonic: &str = rest.split_whitespace().next()?;
    let (_, raw): (&str, &str) = left.split_once(": ")?;
    let first_unit: &str = raw.split_whitespace().next()?;
    if first_unit.len() < 2 {
        return None;
    }
    let opcode: u8 = u8::from_str_radix(first_unit.get(0..2)?, 16).ok()?;
    Some((offset, opcode, mnemonic.to_owned()))
}

fn dexdump_offset_opcodes(listing: &str) -> Vec<Vec<(u32, u8)>> {
    let mut methods: Vec<Vec<(u32, u8)>> = Vec::new();
    let mut current: Option<Vec<(u32, u8)>> = None;
    for line in listing.lines() {
        if line.contains("|[") {
            if let Some(done) = current.replace(Vec::new())
                && !done.is_empty()
            {
                methods.push(done);
            }
            continue;
        }
        let Some((offset, opcode, mnemonic)): Option<(u32, u8, String)> =
            parse_dexdump_instruction(line)
        else {
            continue;
        };
        if PAYLOAD_PSEUDO.contains(&mnemonic.as_str()) {
            continue;
        }
        if let Some(stream) = current.as_mut() {
            stream.push((offset, opcode));
        }
    }
    if let Some(done) = current.take()
        && !done.is_empty()
    {
        methods.push(done);
    }
    methods.sort();
    methods
}

fn run_dexdump(path: &Path) -> Output {
    Command::new("dexdump")
        .arg("-d")
        .arg(path)
        .output()
        .expect("run dexdump -d")
}

#[test]
fn dalvik_lift_agrees_with_dexdump() {
    if !tool_available("dexdump") {
        eprintln!("skipping dexdump agreement: Android build-tools dexdump not on PATH");
        return;
    }
    let mut corpus: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    corpus.pop();
    corpus.pop();
    corpus.push("corpus");
    corpus.push("jvm");
    corpus.push("dex");

    for (name, bytes) in FIXTURES {
        let path: PathBuf = corpus.join(name.rsplit('/').next().unwrap_or(name));
        let output: Output = run_dexdump(&path);
        assert!(
            output.status.success(),
            "dexdump -d failed for {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listing: String = String::from_utf8_lossy(&output.stdout).into_owned();
        let expected: Vec<Vec<(u32, u8)>> = dexdump_offset_opcodes(&listing);
        let lifted: Vec<Vec<(u32, u8)>> = disrobe_offset_opcodes(bytes);
        assert_eq!(
            lifted, expected,
            "disrobe decoded (offset, opcode) stream must equal dexdump -d for {name}"
        );
    }
}
