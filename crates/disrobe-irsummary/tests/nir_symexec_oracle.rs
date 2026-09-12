#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_irsummary::{Location, NirSummary, summarize_function};
use disrobe_mba::{Expr, Width};
use disrobe_nir::{NirFunction, NirModule};
use disrobe_nir_lift::lift_wasm_module;
use disrobe_pass_native::build_disasm_payload;
use disrobe_pass_native::stub_emu::cpu::NoopHost;
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, Memory, Perm, Reg};
use disrobe_query::disasm_to_nir;
use iced_x86::code_asm::{CodeAssembler, CodeLabel, dword_ptr, eax, ecx, edi, edx, esi, rsp};
use object::write::{
    Object as WriteObject, Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags, SymbolSection,
};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolKind as WriteSymbolKind, SymbolScope,
};

const CODE_BASE: u64 = 0x1000;
const STACK_TOP: u64 = 0x2_0FF0;
const RET_SENTINEL: u64 = 0xDEAD_0000;
const SCRATCH_DISP: i64 = -8;

fn diamond_bytes() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut else_arm: CodeLabel = asm.create_label();
    let mut join: CodeLabel = asm.create_label();
    asm.cmp(edi, esi).unwrap();
    asm.jg(else_arm).unwrap();
    asm.mov(eax, edi).unwrap();
    asm.add(eax, esi).unwrap();
    asm.jmp(join).unwrap();
    asm.set_label(&mut else_arm).unwrap();
    asm.mov(eax, edi).unwrap();
    asm.sub(eax, esi).unwrap();
    asm.set_label(&mut join).unwrap();
    asm.add(eax, 1u32).unwrap();
    asm.ret().unwrap();
    asm.assemble(CODE_BASE).expect("assemble diamond")
}

fn sequential_bytes() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut skip_first: CodeLabel = asm.create_label();
    let mut skip_second: CodeLabel = asm.create_label();
    asm.mov(eax, edi).unwrap();
    asm.cmp(edi, esi).unwrap();
    asm.jle(skip_first).unwrap();
    asm.add(eax, 100u32).unwrap();
    asm.set_label(&mut skip_first).unwrap();
    asm.cmp(edx, ecx).unwrap();
    asm.jle(skip_second).unwrap();
    asm.add(eax, 7u32).unwrap();
    asm.set_label(&mut skip_second).unwrap();
    asm.mov(dword_ptr(rsp - 8), eax).unwrap();
    asm.ret().unwrap();
    asm.assemble(CODE_BASE).expect("assemble sequential")
}

fn wrap_elf(code: &[u8]) -> Vec<u8> {
    let mut obj: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text: object::write::SectionId =
        obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let offset: u64 = obj.append_section_data(text, code, 16);
    let sym: WriteSymbol = WriteSymbol {
        name: b"target".to_vec(),
        value: offset,
        size: code.len() as u64,
        kind: WriteSymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: WriteSymbolFlags::None,
    };
    obj.add_symbol(sym);
    obj.write().expect("elf write")
}

fn lift_native(code: &[u8]) -> NirFunction {
    let elf: Vec<u8> = wrap_elf(code);
    let payload = build_disasm_payload(&elf).expect("disasm payload");
    let module: NirModule = disasm_to_nir(&payload);
    module
        .function_by_name("target")
        .expect("target function lifted to nir")
        .clone()
}

fn run_concrete(code: &[u8], inputs: [u32; 4]) -> (u64, u64) {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    cpu.mem.map(CODE_BASE, 0x1000, Perm::RWX).expect("map code");
    cpu.mem.write_unchecked(CODE_BASE, code);
    cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
    cpu.mem
        .write_u64(STACK_TOP, RET_SENTINEL)
        .expect("seed return address");
    cpu.regs.set(Reg::Rsp, STACK_TOP);
    cpu.regs.set(Reg::Rdi, u64::from(inputs[0]));
    cpu.regs.set(Reg::Rsi, u64::from(inputs[1]));
    cpu.regs.set(Reg::Rdx, u64::from(inputs[2]));
    cpu.regs.set(Reg::Rcx, u64::from(inputs[3]));
    cpu.regs.rip = CODE_BASE;
    let mut host: NoopHost = NoopHost;
    let exit: ExitReason = cpu.run(&mut host, 1000).expect("run");
    match exit {
        ExitReason::JumpedOutOfRange { to, .. } if to == RET_SENTINEL => {}
        other => panic!("expected clean return to sentinel, got {other:?}"),
    }
    let scratch_addr: u64 = STACK_TOP.wrapping_add(SCRATCH_DISP as u64);
    let scratch: u64 = read_u32_or_zero(&cpu.mem, scratch_addr);
    (cpu.regs.read_sized(Reg::Rax, 32), scratch)
}

fn read_u32_or_zero(mem: &Memory, addr: u64) -> u64 {
    mem.read_u32(addr).map_or(0, u64::from)
}

fn concretize(summary: &NirSummary, output: &Expr, inputs: [u32; 4]) -> u64 {
    let pairs: [(&str, u32); 4] = [
        ("rdi", inputs[0]),
        ("rsi", inputs[1]),
        ("rdx", inputs[2]),
        ("rcx", inputs[3]),
    ];
    let max_input_var: u32 = summary.input_seeds.values().copied().max().unwrap_or(0);
    let max_cond_var: u32 = summary
        .branches
        .iter()
        .map(|b: &_| b.condition_var)
        .max()
        .unwrap_or(0);
    let extent: u32 = output
        .max_var()
        .unwrap_or(0)
        .max(max_input_var)
        .max(max_cond_var);
    let mut env: Vec<u64> = vec![0u64; extent as usize + 1];
    for (reg, value) in pairs {
        if let Some(seed) = summary.input_seeds.get(reg) {
            env[*seed as usize] = u64::from(value);
        }
    }
    for branch in &summary.branches {
        let truth: bool = branch.predicate.evaluate(&env, summary.width);
        env[branch.condition_var as usize] = u64::from(truth);
    }
    output.eval(&env, Width::W32)
}

#[test]
fn nir_symexec_matches_stub_emu_on_native_lifted_diamond() {
    let code: Vec<u8> = diamond_bytes();
    let function: NirFunction = lift_native(&code);
    let summary: NirSummary = summarize_function(&function).expect("diamond nir must summarize");

    let rax: &Expr = summary
        .outputs
        .get(&Location::Register("rax".to_owned()))
        .expect("rax output present");
    assert!(
        contains_ite(rax),
        "the join-merged rax must carry a path-dependent Ite, got {rax}"
    );

    let vectors: [(u32, u32); 8] = [
        (0, 0),
        (5, 3),
        (3, 5),
        (10, 10),
        (255, 1),
        (1, 255),
        (200, 100),
        (1, 2),
    ];
    let mut saw_then: bool = false;
    let mut saw_else: bool = false;
    for (a, b) in vectors {
        let inputs: [u32; 4] = [a, b, 0, 0];
        let (concrete, _): (u64, u64) = run_concrete(&code, inputs);
        let symbolic: u64 = concretize(&summary, rax, inputs);
        assert_eq!(
            symbolic, concrete,
            "nir symexec disagrees with stub_emu at rdi={a:#x} rsi={b:#x}"
        );
        if (a as i32) > (b as i32) {
            saw_else = true;
        } else {
            saw_then = true;
        }
    }
    assert!(
        saw_then && saw_else,
        "oracle must exercise both branch arms"
    );
}

#[test]
fn nir_symexec_matches_stub_emu_on_native_lifted_sequential_stack_cell() {
    let code: Vec<u8> = sequential_bytes();
    let function: NirFunction = lift_native(&code);
    let summary: NirSummary = summarize_function(&function).expect("sequential nir must summarize");

    let scratch: &Expr = summary
        .outputs
        .iter()
        .find_map(|(loc, expr): (&Location, &Expr)| match loc {
            Location::Memory(_) => Some(expr),
            Location::Register(_) => None,
        })
        .expect("a stack memory output cell");

    let vectors: [[u32; 4]; 5] = [
        [5, 3, 9, 2],
        [3, 5, 2, 9],
        [9, 1, 1, 1],
        [10, 10, 10, 10],
        [2, 1, 1, 2],
    ];
    for inputs in vectors {
        let (_, concrete): (u64, u64) = run_concrete(&code, inputs);
        let symbolic: u64 = concretize(&summary, scratch, inputs);
        assert_eq!(
            symbolic, concrete,
            "nir symexec stack cell disagrees with stub_emu at inputs {inputs:?}"
        );
    }
}

const NETWORK_CONST_WAT: &str = r#"
(module
  (func (export "compute") (param i32) (result i32)
    (i32.add
      (i32.mul (local.get 0) (i32.const 7))
      (i32.const 11))))
"#;

#[test]
fn same_engine_summarizes_a_non_x86_wasm_frontend() {
    let bytes: Vec<u8> =
        wat::parse_str(NETWORK_CONST_WAT.replace('\n', " ")).expect("assemble wat");
    let module: NirModule = lift_wasm_module(&bytes).expect("lift wasm module");
    let function: &NirFunction = module
        .functions
        .iter()
        .find(|f: &&NirFunction| f.name.contains("compute") || f.name.contains("func"))
        .or_else(|| module.functions.first())
        .expect("a lifted wasm function");

    let summary: NirSummary =
        summarize_function(function).expect("the SAME engine must summarize lifted wasm");

    assert!(
        !summary.outputs.is_empty(),
        "the wasm summary must bind at least one output location"
    );

    let independent_consts: BTreeSet<u64> = decode_wasm_i32_consts(&bytes);
    assert!(
        !independent_consts.is_empty(),
        "the fixture must contain i32.const operands"
    );

    let engine_consts: BTreeSet<u64> = summary.const_values();
    assert_eq!(
        engine_consts, independent_consts,
        "constants referenced by the same engine over wasm must equal an independent i32.const decode"
    );
}

fn decode_wasm_i32_consts(bytes: &[u8]) -> BTreeSet<u64> {
    use wasmparser::{Operator, Parser, Payload};

    let mut consts: BTreeSet<u64> = BTreeSet::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("wasm payload") {
            let mut reader = body.get_operators_reader().expect("operators reader");
            while !reader.eof() {
                if let Ok(Operator::I32Const { value }) = reader.read() {
                    consts.insert(u64::from(value as u32));
                }
            }
        }
    }
    consts
}

fn contains_ite(expr: &Expr) -> bool {
    match expr {
        Expr::Ite(_, _, _) => true,
        Expr::Const(_) | Expr::Var(_) => false,
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) | Expr::Mem(inner, _) => {
            contains_ite(inner)
        }
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
            contains_ite(left) || contains_ite(right)
        }
    }
}
