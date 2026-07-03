#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use disrobe_irsummary::{
    Location, NirSummary, emit_llvm_function, emit_optimized_llvm_function, llvm_int_ty,
    summarize_function,
};
use disrobe_mba::{Expr, Width};
use disrobe_nir::{BinaryOp, NirFunction, NirInstr, NirModule, NirOp, SourceLang, SourceRef};

use disrobe_pass_native::build_disasm_payload;
use disrobe_pass_native::stub_emu::cpu::NoopHost;
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, Perm, Reg};
use disrobe_query::disasm_to_nir;

use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, edi, esi};
use object::write::{
    Object as WriteObject, Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags, SymbolSection,
};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolKind as WriteSymbolKind, SymbolScope,
};

const CODE_BASE: u64 = 0x1000;
const STACK_TOP: u64 = 0x2_0FF0;
const RET_SENTINEL: u64 = 0xDEAD_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Atom {
    Literal(i128),
    Value(u32),
}

#[derive(Debug)]
struct Backing {
    cells: BTreeMap<u64, u64>,
}

impl Backing {
    fn load(&self, addr: u64, width: Width) -> u64 {
        self.cells.get(&addr).copied().unwrap_or(0) & width.mask()
    }
}

#[derive(Debug)]
struct IndependentVm {
    values: BTreeMap<u32, u64>,
    width: Width,
    ret: Option<u64>,
}

fn parse_atom(token: &str) -> Atom {
    let trimmed: &str = token.trim_end_matches(',').trim();
    trimmed.strip_prefix("%v").map_or_else(
        || Atom::Literal(trimmed.parse::<i128>().expect("integer literal")),
        |rest: &str| Atom::Value(rest.parse::<u32>().expect("value id")),
    )
}

impl IndependentVm {
    fn new(args: &BTreeMap<u32, u64>, width: Width) -> Self {
        Self {
            values: args.clone(),
            width,
            ret: None,
        }
    }

    fn resolve(&self, atom: Atom, width: Width) -> u64 {
        match atom {
            Atom::Literal(value) => (value as u64) & width.mask(),
            Atom::Value(id) => {
                *self
                    .values
                    .get(&id)
                    .unwrap_or_else(|| panic!("undefined %v{id} referenced before assignment"))
                    & width.mask()
            }
        }
    }

    fn execute(&mut self, ir: &str, backing: &Backing) {
        for raw in ir.lines() {
            let line: &str = raw.trim();
            if line.is_empty()
                || line.starts_with("define")
                || line.starts_with("entry:")
                || line == "}"
            {
                continue;
            }
            if let Some(rest) = line.strip_prefix("ret ") {
                self.ret = Some(self.exec_ret(rest));
                continue;
            }
            self.exec_assign(line, backing);
        }
    }

    fn exec_ret(&self, rest: &str) -> u64 {
        let mut parts = rest.split_whitespace();
        let ty: &str = parts.next().expect("ret type");
        let width: Width = ty_to_width(ty);
        let operand: &str = parts.next().expect("ret operand");
        let atom: Atom = parse_atom(operand);
        self.resolve(atom, width)
    }

    fn exec_assign(&mut self, line: &str, backing: &Backing) {
        let (lhs, rhs): (&str, &str) = line.split_once(" = ").expect("ssa assignment");
        let dest: u32 = lhs
            .trim()
            .strip_prefix("%v")
            .expect("ssa dest name")
            .parse::<u32>()
            .expect("ssa dest id");
        let value: u64 = self.eval_rhs(rhs.trim(), backing);
        self.values.insert(dest, value);
    }

    fn eval_rhs(&self, rhs: &str, backing: &Backing) -> u64 {
        let mut tokens = rhs.split_whitespace();
        let opcode: &str = tokens.next().expect("opcode");
        match opcode {
            "add" | "sub" | "mul" | "and" | "or" | "xor" | "shl" | "lshr" => {
                let ty: &str = tokens.next().expect("binop type");
                let width: Width = ty_to_width(ty);
                let rest: String = tokens.collect::<Vec<&str>>().join(" ");
                let (a_tok, b_tok): (&str, &str) =
                    rest.split_once(',').expect("two binop operands");
                let a: u64 = self.resolve(parse_atom(a_tok), width);
                let b: u64 = self.resolve(parse_atom(b_tok), width);
                apply_binop(opcode, a, b, width)
            }
            "icmp" => {
                let predicate: String = tokens.next().expect("icmp predicate").to_owned();
                let ty: &str = tokens.next().expect("icmp type");
                let width: Width = ty_to_width(ty);
                let rest: String = tokens.collect::<Vec<&str>>().join(" ");
                let (a_tok, b_tok): (&str, &str) = rest.split_once(',').expect("two icmp operands");
                let a: u64 = self.resolve(parse_atom(a_tok), width);
                let b: u64 = self.resolve(parse_atom(b_tok), width);
                u64::from(apply_icmp(&predicate, a, b, width))
            }
            "select" => {
                let cond_ty: &str = tokens.next().expect("i1");
                assert_eq!(cond_ty, "i1", "select condition is i1");
                let cond_tok: &str = tokens.next().expect("select cond");
                let cond: u64 = self.resolve(parse_atom(cond_tok), Width::W8);
                let then_ty: &str = tokens.next().expect("then type");
                let width: Width = ty_to_width(then_ty);
                let then_tok: &str = tokens.next().expect("then value");
                let then_value: u64 = self.resolve(parse_atom(then_tok), width);
                let _else_ty: &str = tokens.next().expect("else type");
                let else_tok: &str = tokens.next().expect("else value");
                let else_value: u64 = self.resolve(parse_atom(else_tok), width);
                if cond != 0 { then_value } else { else_value }
            }
            "trunc" => {
                let src_ty: &str = tokens.next().expect("trunc src type");
                let src_width: Width = ty_to_width(src_ty);
                let src_tok: &str = tokens.next().expect("trunc src");
                let value: u64 = self.resolve(parse_atom(src_tok), src_width);
                let _to: &str = tokens.next().expect("to");
                let dst_ty: &str = tokens.next().expect("trunc dst type");
                let dst_width: Width = ty_to_width(dst_ty);
                value & dst_width.mask()
            }
            "zext" => {
                let src_ty: &str = tokens.next().expect("zext src type");
                let src_width: Width = ty_to_width(src_ty);
                let src_tok: &str = tokens.next().expect("zext src");
                self.resolve(parse_atom(src_tok), src_width)
            }
            "inttoptr" => {
                let src_ty: &str = tokens.next().expect("inttoptr src type");
                let src_width: Width = ty_to_width(src_ty);
                let src_tok: &str = tokens.next().expect("inttoptr src");
                self.resolve(parse_atom(src_tok), src_width)
            }
            "load" => {
                let load_ty: &str = tokens.next().expect("load type");
                let load_width: Width = ty_to_width(load_ty.trim_end_matches(','));
                let _ptr_ty: &str = tokens.next().expect("ptr type");
                let ptr_tok: &str = tokens.next().expect("ptr operand");
                let addr: u64 = self.resolve(parse_atom(ptr_tok), self.width);
                backing.load(addr, load_width)
            }
            other => panic!("independent evaluator does not handle opcode `{other}`"),
        }
    }
}

fn apply_binop(opcode: &str, a: u64, b: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    let result: u64 = match opcode {
        "add" => a.wrapping_add(b),
        "sub" => a.wrapping_sub(b),
        "mul" => a.wrapping_mul(b),
        "and" => a & b,
        "or" => a | b,
        "xor" => a ^ b,
        "shl" => {
            if b >= bits {
                0
            } else {
                a.wrapping_shl(b as u32)
            }
        }
        "lshr" => {
            let masked: u64 = a & width.mask();
            if b >= bits {
                0
            } else {
                masked.wrapping_shr(b as u32)
            }
        }
        other => panic!("unknown binop {other}"),
    };
    result & width.mask()
}

fn apply_icmp(predicate: &str, a: u64, b: u64, width: Width) -> bool {
    let bits: u32 = width.bits();
    let sign_extend = |value: u64| -> i64 {
        if bits >= 64 {
            value as i64
        } else {
            let shift: u32 = 64 - bits;
            (((value & width.mask()) << shift) as i64) >> shift
        }
    };
    let au: u64 = a & width.mask();
    let bu: u64 = b & width.mask();
    match predicate {
        "eq" => au == bu,
        "ne" => au != bu,
        "ult" => au < bu,
        "ule" => au <= bu,
        "ugt" => au > bu,
        "uge" => au >= bu,
        "slt" => sign_extend(a) < sign_extend(b),
        "sle" => sign_extend(a) <= sign_extend(b),
        "sgt" => sign_extend(a) > sign_extend(b),
        "sge" => sign_extend(a) >= sign_extend(b),
        other => panic!("unknown icmp predicate {other}"),
    }
}

fn ty_to_width(ty: &str) -> Width {
    let bits: u32 = ty
        .trim()
        .strip_prefix('i')
        .expect("integer type")
        .parse::<u32>()
        .expect("type width");
    Width::from_bits(bits).expect("supported width")
}

fn arg_slot_ids(summary: &NirSummary) -> Vec<u32> {
    let distinct: std::collections::BTreeSet<u32> = summary.input_seeds.values().copied().collect();
    let base: u32 = 0xF000_0000;
    (0..distinct.len() as u32)
        .map(|slot: u32| base + slot)
        .collect()
}

fn arg_var_order(summary: &NirSummary) -> Vec<u32> {
    let distinct: std::collections::BTreeSet<u32> = summary.input_seeds.values().copied().collect();
    distinct.into_iter().collect()
}

fn run_roundtrip(summary: &NirSummary, output: &Expr, samples: &[Vec<u64>], backing: &Backing) {
    let module = emit_llvm_function("probe", summary).expect("emit");
    let slot_ids: Vec<u32> = arg_slot_ids(summary);
    let var_order: Vec<u32> = arg_var_order(summary);
    let width: Width = summary.width;
    let mem_fn = |addr: u64, w: Width| -> u64 { backing.load(addr, w) };

    for sample in samples {
        let mut arg_values: BTreeMap<u32, u64> = BTreeMap::new();
        let extent: u32 = output.max_var().map_or(0, |v: u32| v + 1);
        let mut env: Vec<u64> = vec![0u64; extent.max(1) as usize];
        for (idx, var) in var_order.iter().enumerate() {
            let value: u64 = sample.get(idx).copied().unwrap_or(0);
            arg_values.insert(slot_ids[idx], value);
            if (*var as usize) < env.len() {
                env[*var as usize] = value;
            }
        }
        let mut vm: IndependentVm = IndependentVm::new(&arg_values, width);
        vm.execute(module.text(), backing);
        let emitted: u64 = vm.ret.expect("emitted module must return");
        let reference: u64 = output.eval_with_mem(&env, &mem_fn, width) & width.mask();
        assert_eq!(
            emitted,
            reference,
            "emitted IR disagrees with Expr::eval for sample {sample:?}\n{}",
            module.text()
        );
    }
}

const fn empty_backing() -> Backing {
    Backing {
        cells: BTreeMap::new(),
    }
}

fn instr(address: u64, op: NirOp, mnemonic: &str, operands: &[&str], lang: SourceLang) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
        reads_memory: operands.iter().any(|o: &&str| o.contains('[')),
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(lang, address),
    }
}

fn function(lang: SourceLang, instrs: Vec<NirInstr>) -> NirFunction {
    let end: u64 = instrs.last().map_or(0, |i: &NirInstr| i.address + 1);
    NirFunction {
        name: "t".to_owned(),
        address: instrs.first().map_or(0, |i: &NirInstr| i.address),
        end,
        is_export: false,
        instructions: instrs,
        source: SourceRef::labelled(lang, 0, "t"),
    }
}

#[test]
fn roundtrip_arithmetic_const_var_binary() {
    let lang: SourceLang = SourceLang::NativeX86;
    let func: NirFunction = function(
        lang,
        vec![
            instr(0, NirOp::Nop, "mov", &["eax", "edi"], lang),
            instr(
                1,
                NirOp::BinOp { op: BinaryOp::Add },
                "add",
                &["eax", "esi"],
                lang,
            ),
            instr(
                2,
                NirOp::BinOp { op: BinaryOp::Xor },
                "xor",
                &["eax", "0x2a"],
                lang,
            ),
            instr(3, NirOp::Return, "ret", &[], lang),
        ],
    );
    let summary: NirSummary = summarize_function(&func).expect("summary");
    let output: Expr = summary
        .outputs
        .get(&Location::Register("rax".to_owned()))
        .expect("rax")
        .clone();
    let samples: Vec<Vec<u64>> = vec![
        vec![0, 0],
        vec![9, 4],
        vec![255, 1],
        vec![0xFFFF_FFFF, 0xFFFF_FFFF],
    ];
    run_roundtrip(&summary, &output, &samples, &empty_backing());
}

#[test]
fn roundtrip_unary_not_and_neg() {
    let width: Width = Width::W32;
    let output: Expr = Expr::add(Expr::not(Expr::var(0)), Expr::neg(Expr::var(1)));
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    input_seeds.insert("a".to_owned(), 0);
    input_seeds.insert("b".to_owned(), 1);
    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    outputs.insert(Location::Register("rax".to_owned()), output.clone());
    let summary: NirSummary = NirSummary {
        outputs,
        branches: Vec::new(),
        width,
        input_seeds,
    };
    let samples: Vec<Vec<u64>> = vec![vec![0, 0], vec![1, 2], vec![0xDEAD, 0xBEEF]];
    run_roundtrip(&summary, &output, &samples, &empty_backing());
}

#[test]
fn roundtrip_select_from_ite() {
    let width: Width = Width::W32;
    let output: Expr = Expr::ite(Expr::var(0), Expr::var(1), Expr::konst(7));
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    input_seeds.insert("c".to_owned(), 0);
    input_seeds.insert("t".to_owned(), 1);
    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    outputs.insert(Location::Register("rax".to_owned()), output.clone());
    let summary: NirSummary = NirSummary {
        outputs,
        branches: Vec::new(),
        width,
        input_seeds,
    };
    let samples: Vec<Vec<u64>> = vec![vec![0, 99], vec![1, 99], vec![5, 12], vec![0, 0]];
    run_roundtrip(&summary, &output, &samples, &empty_backing());
}

#[test]
fn roundtrip_slice_and_compose() {
    let width: Width = Width::W32;
    let slice: Expr = Expr::slice(Expr::var(0), 4, 12);
    let compose: Expr = Expr::compose(Expr::var(0), Expr::var(1), 8);
    let output: Expr = Expr::add(slice, compose);
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    input_seeds.insert("a".to_owned(), 0);
    input_seeds.insert("b".to_owned(), 1);
    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    outputs.insert(Location::Register("rax".to_owned()), output.clone());
    let summary: NirSummary = NirSummary {
        outputs,
        branches: Vec::new(),
        width,
        input_seeds,
    };
    let samples: Vec<Vec<u64>> = vec![vec![0, 0], vec![0xABCD, 0x12], vec![0xFFFF_FFFF, 0xFF]];
    run_roundtrip(&summary, &output, &samples, &empty_backing());
}

#[test]
fn roundtrip_memory_load() {
    let width: Width = Width::W64;
    let address: Expr = Expr::add(Expr::var(0), Expr::konst(16));
    let output: Expr = Expr::mem(address, Width::W32);
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    input_seeds.insert("ptr".to_owned(), 0);
    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    outputs.insert(Location::Register("rax".to_owned()), output.clone());
    let summary: NirSummary = NirSummary {
        outputs,
        branches: Vec::new(),
        width,
        input_seeds,
    };
    let mut cells: BTreeMap<u64, u64> = BTreeMap::new();
    cells.insert(0x1010, 0xCAFE_F00D);
    cells.insert(0x2010, 0x0000_0042);
    let backing: Backing = Backing { cells };
    let samples: Vec<Vec<u64>> = vec![vec![0x1000], vec![0x2000], vec![0x3000]];
    run_roundtrip(&summary, &output, &samples, &backing);
}

#[test]
fn cse_shares_repeated_subexpression() {
    let width: Width = Width::W32;
    let shared: Expr = Expr::mul(Expr::var(0), Expr::var(1));
    let output: Expr = Expr::add(shared.clone(), shared);
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    input_seeds.insert("a".to_owned(), 0);
    input_seeds.insert("b".to_owned(), 1);
    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    outputs.insert(Location::Register("rax".to_owned()), output.clone());
    let summary: NirSummary = NirSummary {
        outputs,
        branches: Vec::new(),
        width,
        input_seeds,
    };
    let module = emit_llvm_function("cse", &summary).expect("emit");
    let mul_count: usize = module
        .text()
        .lines()
        .filter(|l: &&str| l.contains(" = mul "))
        .count();
    assert_eq!(
        mul_count,
        1,
        "shared product must emit one mul:\n{}",
        module.text()
    );
    run_roundtrip(
        &summary,
        &output,
        &[vec![3, 5], vec![7, 11]],
        &empty_backing(),
    );
}

#[test]
fn int_type_mapping_matches_width() {
    assert_eq!(llvm_int_ty(Width::W8), "i8");
    assert_eq!(llvm_int_ty(Width::W16), "i16");
    assert_eq!(llvm_int_ty(Width::W32), "i32");
    assert_eq!(llvm_int_ty(Width::W64), "i64");
}

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

fn run_concrete_eax(bytes: &[u8], edi_in: u32, esi_in: u32) -> u64 {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    cpu.mem.map(CODE_BASE, 0x1000, Perm::RWX).expect("map code");
    cpu.mem.write_unchecked(CODE_BASE, bytes);
    cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
    cpu.mem
        .write_u64(STACK_TOP, RET_SENTINEL)
        .expect("seed ret");
    cpu.regs.set(Reg::Rsp, STACK_TOP);
    cpu.regs.set(Reg::Rdi, u64::from(edi_in));
    cpu.regs.set(Reg::Rsi, u64::from(esi_in));
    cpu.regs.rip = CODE_BASE;
    let mut host: NoopHost = NoopHost;
    let exit: ExitReason = cpu.run(&mut host, 1000).expect("run");
    match exit {
        ExitReason::JumpedOutOfRange { to, .. } if to == RET_SENTINEL => {}
        other => panic!("expected clean return, got {other:?}"),
    }
    cpu.regs.read_sized(Reg::Rax, 32)
}

#[test]
fn emitted_diamond_from_production_lift_matches_stub_emu_concrete_execution() {
    let bytes: Vec<u8> = diamond_bytes();
    let func: NirFunction = lift_native(&bytes);
    let summary: NirSummary = summarize_function(&func).expect("diamond summary");
    let module = emit_llvm_function("diamond", &summary).expect("emit diamond");

    assert!(
        module.text().contains("select i1"),
        "the merged diamond must lower to a select:\n{}",
        module.text()
    );

    let width: Width = summary.width;
    let slot_ids: Vec<u32> = arg_slot_ids(&summary);
    let var_order: Vec<u32> = arg_var_order(&summary);
    let rdi_seed: u32 = *summary.input_seeds.get("rdi").expect("rdi seed");
    let rsi_seed: u32 = *summary.input_seeds.get("rsi").expect("rsi seed");

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
    let backing: Backing = empty_backing();

    for (edi_in, esi_in) in vectors {
        let mut arg_values: BTreeMap<u32, u64> = BTreeMap::new();
        for (idx, var) in var_order.iter().enumerate() {
            let value: u64 = if *var == rdi_seed {
                u64::from(edi_in)
            } else if *var == rsi_seed {
                u64::from(esi_in)
            } else {
                0
            };
            arg_values.insert(slot_ids[idx], value);
        }

        let mut vm: IndependentVm = IndependentVm::new(&arg_values, width);
        vm.execute(module.text(), &backing);
        let emitted: u64 = vm.ret.expect("diamond module returns");
        let concrete: u64 = run_concrete_eax(&bytes, edi_in, esi_in);
        assert_eq!(
            emitted,
            concrete,
            "emitted IR disagrees with stub_emu at edi={edi_in} esi={esi_in}\n{}",
            module.text()
        );
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let path_var: String = std::env::var("PATH").ok()?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE".to_owned())
            .split(';')
            .map(|s: &str| s.trim().to_owned())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in path_var.split(if cfg!(windows) { ';' } else { ':' }) {
        for ext in &exts {
            let candidate: PathBuf = PathBuf::from(dir).join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[test]
fn emitted_module_assembles_and_runs_under_real_llvm_if_available() {
    let (Some(llvm_as), Some(lli)): (Option<PathBuf>, Option<PathBuf>) =
        (which("llvm-as"), which("lli"))
    else {
        eprintln!("skipping real-LLVM leg: llvm-as / lli not found on PATH");
        return;
    };

    let func: NirFunction = function(
        SourceLang::NativeX86,
        vec![
            instr(0, NirOp::Nop, "mov", &["eax", "edi"], SourceLang::NativeX86),
            instr(
                1,
                NirOp::BinOp { op: BinaryOp::Add },
                "add",
                &["eax", "esi"],
                SourceLang::NativeX86,
            ),
            instr(2, NirOp::Return, "ret", &[], SourceLang::NativeX86),
        ],
    );
    let summary: NirSummary = summarize_function(&func).expect("summary");
    let module = emit_llvm_function("addfn", &summary).expect("emit");
    let width: Width = summary.width;
    let ty: &str = llvm_int_ty(width);

    let var_order: Vec<u32> = arg_var_order(&summary);
    let rdi_seed: u32 = *summary.input_seeds.get("rdi").expect("rdi seed");
    let rsi_seed: u32 = *summary.input_seeds.get("rsi").expect("rsi seed");
    let (a, b): (u64, u64) = (40, 2);

    let call_args: String = var_order
        .iter()
        .map(|var: &u32| {
            let value: u64 = if *var == rdi_seed {
                a
            } else if *var == rsi_seed {
                b
            } else {
                0
            };
            format!("{ty} {value}")
        })
        .collect::<Vec<String>>()
        .join(", ");

    let harness: String = format!(
        "{}\ndefine i32 @main() {{\nentry:\n  %r = call {ty} @{}({call_args})\n  %t = trunc {ty} %r to i32\n  ret i32 %t\n}}\n",
        module.text(),
        module.function_name()
    );

    let dir: PathBuf = std::env::temp_dir().join(format!("disrobe_llvmir_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let ll_path: PathBuf = dir.join("module.ll");
    let bc_path: PathBuf = dir.join("module.bc");
    std::fs::write(&ll_path, harness.as_bytes()).expect("write ll");

    let assemble = Command::new(&llvm_as)
        .arg(&ll_path)
        .arg("-o")
        .arg(&bc_path)
        .output()
        .expect("run llvm-as");
    assert!(
        assemble.status.success(),
        "llvm-as rejected emitted IR:\n{}\n--- ir ---\n{harness}",
        String::from_utf8_lossy(&assemble.stderr)
    );

    let executed = Command::new(&lli).arg(&bc_path).output().expect("run lli");
    let code: i32 = executed.status.code().expect("exit code");
    let expected: i32 = ((a.wrapping_add(b)) & 0xFF) as i32;
    assert_eq!(
        code,
        expected,
        "lli exit code must equal (a+b) low byte; stderr:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn summary_from(width: Width, seeds: &[(&str, u32)], output: Expr) -> NirSummary {
    let mut input_seeds: BTreeMap<String, u32> = BTreeMap::new();
    for (name, var) in seeds {
        input_seeds.insert((*name).to_owned(), *var);
    }
    let mut outputs: BTreeMap<Location, Expr> = BTreeMap::new();
    outputs.insert(Location::Register("rax".to_owned()), output);
    NirSummary {
        outputs,
        branches: Vec::new(),
        width,
        input_seeds,
    }
}

const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z: u64 = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn random_vectors(arg_count: usize, count: usize, width: Width, seed: u64) -> Vec<Vec<u64>> {
    let mut state: u64 = seed;
    let mut out: Vec<Vec<u64>> = Vec::with_capacity(count);
    let edges: [u64; 5] = [0, 1, width.mask(), width.mask() >> 1, 0xA5A5_A5A5_A5A5_A5A5];
    for index in 0..count {
        let mut row: Vec<u64> = Vec::with_capacity(arg_count);
        for slot in 0..arg_count {
            let value: u64 = if index < edges.len() {
                edges[index]
            } else {
                splitmix64(&mut state).wrapping_add(slot as u64)
            };
            row.push(value & width.mask());
        }
        out.push(row);
    }
    out
}

fn eval_module(text: &str, summary: &NirSummary, sample: &[u64], backing: &Backing) -> u64 {
    let slot_ids: Vec<u32> = arg_slot_ids(summary);
    let mut arg_values: BTreeMap<u32, u64> = BTreeMap::new();
    for (idx, slot) in slot_ids.iter().enumerate() {
        arg_values.insert(*slot, sample.get(idx).copied().unwrap_or(0));
    }
    let mut vm: IndependentVm = IndependentVm::new(&arg_values, summary.width);
    vm.execute(text, backing);
    vm.ret.expect("module returns")
}

fn assert_optimizer_preserves(
    label: &str,
    summary: &NirSummary,
    backing: &Backing,
    expect_strict_shrink: bool,
) -> (usize, usize) {
    let original = emit_llvm_function(label, summary).expect("emit original");
    let optimized = emit_optimized_llvm_function(label, summary).expect("emit optimized");

    let arg_count: usize = arg_var_order(summary).len();
    let vectors: Vec<Vec<u64>> = random_vectors(arg_count.max(1), 256, summary.width, 0x1234_5678);
    for sample in &vectors {
        let from_original: u64 = eval_module(original.text(), summary, sample, backing);
        let from_optimized: u64 = eval_module(optimized.text(), summary, sample, backing);
        assert_eq!(
            from_original,
            from_optimized,
            "[{label}] optimized IR disagrees with original at {sample:?}\n[original]\n{}\n[optimized]\n{}",
            original.text(),
            optimized.text()
        );
    }

    assert!(
        optimized.instruction_count() <= original.instruction_count(),
        "[{label}] optimizer must never grow the module: {} -> {}",
        original.instruction_count(),
        optimized.instruction_count()
    );
    if expect_strict_shrink {
        assert!(
            optimized.instruction_count() < original.instruction_count(),
            "[{label}] obfuscated fixture must strictly shrink: {} to {}\n[optimized]\n{}",
            original.instruction_count(),
            optimized.instruction_count(),
            optimized.text()
        );
    }
    (original.instruction_count(), optimized.instruction_count())
}

#[test]
fn optimizer_constant_folds_to_a_single_literal() {
    let output: Expr = Expr::add(
        Expr::mul(Expr::konst(6), Expr::konst(7)),
        Expr::xor(Expr::konst(0xF0), Expr::konst(0x0F)),
    );
    let summary: NirSummary = summary_from(Width::W32, &[("a", 0)], output);
    let (before, after): (usize, usize) =
        assert_optimizer_preserves("const_fold", &summary, &empty_backing(), true);
    assert_eq!(after, 0, "fully-constant output folds to a ret literal");
    assert!(before > 0);
}

#[test]
fn optimizer_kills_additive_and_multiplicative_identities() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let output: Expr = Expr::add(
        Expr::add(Expr::mul(x.clone(), Expr::konst(1)), Expr::konst(0)),
        Expr::or(Expr::and(y, Expr::konst(0)), Expr::xor(x, Expr::konst(0))),
    );
    let summary: NirSummary = summary_from(Width::W64, &[("a", 0), ("b", 1)], output);
    assert_optimizer_preserves("identities", &summary, &empty_backing(), true);
}

#[test]
fn optimizer_collapses_double_not() {
    let output: Expr = Expr::not(Expr::not(Expr::add(Expr::var(0), Expr::var(1))));
    let summary: NirSummary = summary_from(Width::W32, &[("a", 0), ("b", 1)], output);
    let original = emit_llvm_function("dnot", &summary).expect("emit");
    assert!(original.text().contains("xor"));
    assert_optimizer_preserves("dnot", &summary, &empty_backing(), true);
}

#[test]
fn optimizer_folds_self_inverse_pairs() {
    let x: Expr = Expr::var(0);
    let output: Expr = Expr::add(
        Expr::xor(x.clone(), x.clone()),
        Expr::sub(Expr::and(x.clone(), x.clone()), x),
    );
    let summary: NirSummary = summary_from(Width::W32, &[("a", 0)], output);
    let (_, after): (usize, usize) =
        assert_optimizer_preserves("self_inverse", &summary, &empty_backing(), true);
    assert_eq!(after, 0, "x^x plus (x&x)-x folds to the zero literal");
}

#[test]
fn optimizer_collapses_constant_condition_select() {
    let output: Expr = Expr::ite(Expr::konst(1), Expr::var(0), Expr::var(1));
    let summary: NirSummary = summary_from(Width::W32, &[("a", 0), ("b", 1)], output);
    let original = emit_llvm_function("selc", &summary).expect("emit");
    assert!(original.text().contains("select i1"));
    let optimized = emit_optimized_llvm_function("selc", &summary).expect("emit opt");
    assert!(
        !optimized.text().contains("select i1"),
        "constant-true select must collapse to its then arm:\n{}",
        optimized.text()
    );
    assert_optimizer_preserves("selc", &summary, &empty_backing(), true);
}

#[test]
fn optimizer_collapses_equal_arm_select() {
    let shared: Expr = Expr::add(Expr::var(0), Expr::konst(3));
    let output: Expr = Expr::ite(Expr::var(1), shared.clone(), shared);
    let summary: NirSummary = summary_from(Width::W32, &[("a", 0), ("c", 1)], output);
    let optimized = emit_optimized_llvm_function("seleq", &summary).expect("emit opt");
    assert!(
        !optimized.text().contains("select i1"),
        "equal-arm select must collapse:\n{}",
        optimized.text()
    );
    assert_optimizer_preserves("seleq", &summary, &empty_backing(), true);
}

#[test]
fn optimizer_collapses_zext_trunc_over_byte_load() {
    let address: Expr = Expr::add(Expr::var(0), Expr::konst(8));
    let output: Expr = Expr::slice(Expr::mem(address, Width::W8), 0, 8);
    let summary: NirSummary = summary_from(Width::W32, &[("ptr", 0)], output);
    let mut cells: BTreeMap<u64, u64> = BTreeMap::new();
    cells.insert(0x1008, 0x42);
    cells.insert(0x2008, 0xFF);
    let backing: Backing = Backing { cells };
    assert_optimizer_preserves("zext_trunc_load", &summary, &backing, true);
}

#[test]
fn optimizer_preserves_genuine_arithmetic_without_growth() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let output: Expr = Expr::add(Expr::mul(x.clone(), y.clone()), Expr::sub(x, y));
    let summary: NirSummary = summary_from(Width::W64, &[("a", 0), ("b", 1)], output);
    assert_optimizer_preserves("genuine_arith", &summary, &empty_backing(), false);
}

fn mba_obfuscated_output() -> Expr {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let xor_xy: Expr = Expr::xor(x.clone(), y.clone());
    let and_xy: Expr = Expr::and(x.clone(), y.clone());
    let core: Expr = Expr::add(xor_xy, Expr::mul(Expr::konst(2), and_xy));
    let with_neutrals: Expr = Expr::add(
        Expr::or(core, Expr::konst(0)),
        Expr::and(Expr::mul(x, Expr::konst(0)), Expr::konst(0xFF)),
    );
    let identity_chain: Expr =
        Expr::xor(Expr::not(Expr::not(with_neutrals)), Expr::sub(y.clone(), y));
    Expr::ite(Expr::konst(1), identity_chain.clone(), identity_chain)
}

#[test]
fn optimizer_strictly_shrinks_mba_laden_fixture() {
    let summary: NirSummary =
        summary_from(Width::W64, &[("a", 0), ("b", 1)], mba_obfuscated_output());
    let (before, after): (usize, usize) =
        assert_optimizer_preserves("mba_laden", &summary, &empty_backing(), true);
    assert!(
        after * 2 <= before,
        "obfuscated MBA fixture should shed most of its instructions: {before} -> {after}"
    );
}

#[test]
fn optimizer_is_idempotent_at_fixed_point() {
    let summary: NirSummary =
        summary_from(Width::W64, &[("a", 0), ("b", 1)], mba_obfuscated_output());
    let once = emit_optimized_llvm_function("idem", &summary).expect("opt once");
    let twice = once.optimized();
    assert_eq!(
        once.instruction_count(),
        twice.instruction_count(),
        "a second optimization pass must not change a fixed point"
    );
    assert_eq!(once.text(), twice.text());
}

#[test]
fn optimizer_matches_original_on_lifted_diamond() {
    let bytes: Vec<u8> = diamond_bytes();
    let func: NirFunction = lift_native(&bytes);
    let summary: NirSummary = summarize_function(&func).expect("diamond summary");
    assert_optimizer_preserves("lifted_diamond", &summary, &empty_backing(), false);
}
