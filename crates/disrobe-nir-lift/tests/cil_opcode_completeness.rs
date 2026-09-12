#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{cil_function_address, lift_dotnet_pe};
use disrobe_pass_dotnet::{
    AssemblyModel, ClrHeader, Instruction, MetadataRoot, PeImage, Resolver, parse as parse_pe,
    parse_clr_header, parse_metadata_root, parse_method_body,
};

const CIL_PROBE: &[u8] = include_bytes!("../../../corpus/dotnet/cil/CilProbe.dll");
const EDGE_BASELINE: &[u8] =
    include_bytes!("../../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
const CONSTRUCTS: &[u8] = include_bytes!("../../../corpus/dotnet/constructs/Constructs.dll");

const FIXTURES: [(&str, &[u8]); 3] = [
    ("cil/CilProbe.dll", CIL_PROBE),
    ("megafile/EdgeCases.baseline.dll", EDGE_BASELINE),
    ("constructs/Constructs.dll", CONSTRUCTS),
];

fn fixture_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("dotnet");
    for segment in rel.split('/') {
        path.push(segment);
    }
    path
}

fn raw_by_address(bytes: &[u8]) -> BTreeMap<u64, Vec<Instruction>> {
    let pe: PeImage = parse_pe(bytes).expect("pe");
    let clr: ClrHeader = parse_clr_header(bytes, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(bytes, &pe, &clr).expect("root");
    let resolver: Resolver = Resolver::build(bytes, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();

    let mut out: BTreeMap<u64, Vec<Instruction>> = BTreeMap::new();
    let mut index: u32 = 0;
    for ty in &model.types {
        for method in &ty.methods {
            let address: u64 = cil_function_address(index);
            index = index.saturating_add(1);
            if method.rva == 0 {
                continue;
            }
            let slice: &[u8] = pe
                .slice_at_rva_to_end(bytes, method.rva)
                .expect("method body");
            if let Ok(body) = parse_method_body(slice) {
                out.insert(address, body.instructions);
            }
        }
    }
    out
}

#[derive(Debug, Default)]
struct NirStats {
    total: usize,
    unmodeled: usize,
    nop: usize,
    opcodes: BTreeSet<u16>,
    mnemonics: BTreeSet<String>,
    modeled_mnemonics: BTreeSet<String>,
    unmodeled_mnemonics: BTreeSet<String>,
}

fn nir_invariants(bytes: &[u8]) -> NirStats {
    let module: NirModule = lift_dotnet_pe(bytes).expect("lift .NET PE to NIR");
    let raw_by_base: BTreeMap<u64, Vec<Instruction>> = raw_by_address(bytes);

    let mut stats: NirStats = NirStats::default();
    for function in &module.functions {
        let function: &NirFunction = function;
        let raw: &Vec<Instruction> = raw_by_base
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
            let insn: &Instruction = insn;
            stats.total += 1;
            stats.opcodes.insert(insn.opcode);
            stats.mnemonics.insert(insn.name.clone());
            assert_eq!(
                nir.address,
                function.address.saturating_add(u64::from(insn.offset)),
                "lifted address must track the bytecode offset for {}",
                function.name
            );
            match &nir.op {
                NirOp::Nop => {
                    stats.nop += 1;
                    assert_eq!(
                        insn.opcode, 0x00,
                        "only a real nop lifts to Nop, saw {} at offset {} in {}",
                        insn.name, insn.offset, function.name
                    );
                }
                NirOp::Unmodeled { opcode, offset } => {
                    assert_eq!(
                        u16::from(*opcode),
                        insn.opcode & 0x00FF,
                        "Unmodeled must carry the real opcode low byte in {}",
                        function.name
                    );
                    assert_eq!(
                        *offset, insn.offset,
                        "Unmodeled must carry the real offset in {}",
                        function.name
                    );
                    stats.unmodeled_mnemonics.insert(insn.name.clone());
                    stats.unmodeled += 1;
                }
                _ => {
                    assert_ne!(
                        insn.opcode, 0x00,
                        "a real nop must never lift to a modeled op in {}",
                        function.name
                    );
                    stats.modeled_mnemonics.insert(insn.name.clone());
                }
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
        merged.modeled_mnemonics.extend(stats.modeled_mnemonics);
        merged.unmodeled_mnemonics.extend(stats.unmodeled_mnemonics);
    }
    merged
}

#[test]
fn committed_cil_surfaces_unmodeled_without_silent_nop() {
    let merged: NirStats = merged_stats();
    assert!(
        merged.unmodeled >= 200,
        "unmodeled CIL opcodes must be surfaced, not collapsed to Nop: {}",
        merged.unmodeled
    );
    assert!(
        merged.opcodes.len() >= 60,
        "the opcode range must be non-vacuous: {} distinct",
        merged.opcodes.len()
    );
    for mnemonic in [
        "call",
        "callvirt",
        "newobj",
        "add",
        "sub",
        "mul",
        "br",
        "br.s",
        "brtrue.s",
        "brfalse.s",
        "ret",
        "ldstr",
        "ldc.i4.s",
        "ldfld",
        "stfld",
        "ldelem.u1",
        "stelem.i1",
    ] {
        assert!(
            merged.modeled_mnemonics.contains(mnemonic),
            "modeled opcode range must include {mnemonic}: {:?}",
            merged.modeled_mnemonics
        );
    }
    for mnemonic in [
        "ldarg.0",
        "ldloc.0",
        "stloc.0",
        "dup",
        "pop",
        "box",
        "unbox.any",
        "isinst",
        "castclass",
        "newarr",
        "ldtoken",
        "conv.u1",
        "ceq",
        "cgt",
        "clt",
        "ldftn",
        "initobj",
        "constrained.",
    ] {
        assert!(
            merged.unmodeled_mnemonics.contains(mnemonic),
            "unmodeled opcode range must include {mnemonic}: {:?}",
            merged.unmodeled_mnemonics
        );
    }
}

#[test]
fn two_byte_prefix_opcodes_surface_as_unmodeled_not_nop() {
    let mut saw_two_byte: bool = false;
    for (_, bytes) in FIXTURES {
        let module: NirModule = lift_dotnet_pe(bytes).expect("lift .NET PE to NIR");
        let raw_by_base: BTreeMap<u64, Vec<Instruction>> = raw_by_address(bytes);
        for function in &module.functions {
            let raw: &Vec<Instruction> = raw_by_base
                .get(&function.address)
                .expect("decoded stream for function base");
            for (nir, insn) in function.instructions.iter().zip(raw.iter()) {
                let nir: &NirInstr = nir;
                let insn: &Instruction = insn;
                if insn.opcode < 0xFE00 {
                    continue;
                }
                if matches!(nir.op, NirOp::Return | NirOp::Interrupt) {
                    continue;
                }
                saw_two_byte = true;
                assert!(
                    nir.op.is_unmodeled(),
                    "a 0xFE-prefixed CIL opcode ({}) must never collapse to a silent Nop, saw {:?}",
                    insn.name,
                    nir.op
                );
                assert_eq!(
                    nir.op.unmodeled_opcode(),
                    Some((insn.opcode & 0x00FF) as u8),
                    "the extended opcode {} must surface carrying its sub-opcode byte",
                    insn.name
                );
            }
        }
    }
    assert!(
        saw_two_byte,
        "fixtures exercise the 0xFE two-byte prefix opcode space"
    );
}

fn ilspycmd_available() -> bool {
    Command::new("ilspycmd")
        .env("DOTNET_ROLL_FORWARD", "Major")
        .arg("--version")
        .output()
        .is_ok_and(|o: Output| o.status.success())
}

fn parse_il_line(trimmed: &str) -> Option<(u32, String)> {
    let rest: &str = trimmed.strip_prefix("IL_")?;
    let (hex, after): (&str, &str) = rest.split_once(": ")?;
    if hex.is_empty() || !hex.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return None;
    }
    let offset: u32 = u32::from_str_radix(hex, 16).ok()?;
    let mnemonic: &str = after.split_whitespace().next()?;
    Some((offset, mnemonic.to_owned()))
}

fn ilspycmd_offset_mnemonics(listing: &str) -> Vec<Vec<(u32, String)>> {
    let mut methods: Vec<Vec<(u32, String)>> = Vec::new();
    let mut current: Option<Vec<(u32, String)>> = None;
    for line in listing.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with(".method") {
            if let Some(done) = current.replace(Vec::new())
                && !done.is_empty()
            {
                methods.push(done);
            }
            continue;
        }
        if let Some(pair) = parse_il_line(trimmed)
            && let Some(stream) = current.as_mut()
        {
            stream.push(pair);
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

fn disrobe_offset_mnemonics(bytes: &[u8]) -> Vec<Vec<(u32, String)>> {
    let mut streams: Vec<Vec<(u32, String)>> = raw_by_address(bytes)
        .into_values()
        .map(|insns: Vec<Instruction>| {
            insns
                .iter()
                .map(|insn: &Instruction| (insn.offset, insn.name.clone()))
                .collect::<Vec<(u32, String)>>()
        })
        .filter(|stream: &Vec<(u32, String)>| !stream.is_empty())
        .collect();
    streams.sort();
    streams
}

#[test]
fn cil_lift_agrees_with_ilspycmd() {
    if !ilspycmd_available() {
        eprintln!("skipping ilspycmd agreement: no runnable ilspycmd on PATH");
        return;
    }
    for (rel, bytes) in FIXTURES {
        let path: PathBuf = fixture_path(rel);
        let output: Output = Command::new("ilspycmd")
            .env("DOTNET_ROLL_FORWARD", "Major")
            .arg("-il")
            .arg(&path)
            .output()
            .expect("run ilspycmd -il");
        assert!(
            output.status.success(),
            "ilspycmd -il failed for {rel}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listing: String = String::from_utf8_lossy(&output.stdout).into_owned();
        let expected: Vec<Vec<(u32, String)>> = ilspycmd_offset_mnemonics(&listing);
        assert!(
            !expected.is_empty(),
            "ilspycmd -il must decode instructions for {rel}"
        );
        let lifted: Vec<Vec<(u32, String)>> = disrobe_offset_mnemonics(bytes);
        assert_eq!(
            lifted, expected,
            "disrobe decoded (offset, mnemonic) stream must equal ilspycmd -il for {rel}"
        );
    }
}
