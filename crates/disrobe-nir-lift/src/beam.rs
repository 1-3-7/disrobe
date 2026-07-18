use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_beam::chunks::ImportEntry;
use disrobe_pass_beam::{
    BeamFile, Chunks, CodeChunk, Disassembly, Instruction, Operand, Term, disassemble,
};

use crate::error::{LiftError, Result};

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;

pub fn lift_beam_module(bytes: &[u8]) -> Result<NirModule> {
    let beam: BeamFile =
        BeamFile::parse(bytes).map_err(|e| LiftError::Source(format!("beam decode: {e}")))?;
    build_module(bytes, &beam)
}

#[must_use]
pub const fn function_address(function_index: u32) -> u64 {
    (function_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

fn usize_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

struct ImportTable {
    by_name: BTreeMap<String, u64>,
    next: u64,
}

impl ImportTable {
    const fn new() -> Self {
        Self {
            by_name: BTreeMap::new(),
            next: IMPORT_BASE,
        }
    }

    fn address_of(&mut self, symbol: &str) -> u64 {
        if let Some(addr) = self.by_name.get(symbol) {
            return *addr;
        }
        let addr: u64 = self.next;
        self.next = self.next.saturating_add(1);
        self.by_name.insert(symbol.to_owned(), addr);
        addr
    }

    fn into_sorted(self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self.by_name.into_iter().collect();
        out.sort_by_key(|(_, addr): &(String, u64)| *addr);
        out
    }
}

struct FunctionSpan {
    name: String,
    arity: u32,
    entry_label: u32,
    start: usize,
    end: usize,
}

fn build_module(source: &[u8], beam: &BeamFile) -> Result<NirModule> {
    let chunks: &Chunks = &beam.chunks;
    let code: &CodeChunk = chunks
        .code
        .as_ref()
        .ok_or_else(|| LiftError::Source("beam: no Code chunk".to_owned()))?;
    let module_name: &str = chunks
        .atoms
        .module_name()
        .ok_or_else(|| LiftError::Source("beam: no module atom".to_owned()))?;

    let disasm: Disassembly =
        disassemble(code).map_err(|e| LiftError::Source(format!("beam disasm: {e}")))?;
    let instrs: &[Instruction] = &disasm.instructions;
    if instrs.is_empty() {
        return Err(LiftError::Empty);
    }

    let label_to_mfa: BTreeMap<u32, (String, u32)> = build_label_mfa(instrs, chunks);
    let spans: Vec<FunctionSpan> = split_functions(instrs, chunks);
    if spans.is_empty() {
        return Err(LiftError::Empty);
    }

    let label_address: BTreeMap<u32, u64> = build_label_address(instrs, &spans);

    let source_hash: [u8; 32] = *blake3::hash(source).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Beam);
    let mut imports: ImportTable = ImportTable::new();

    let ctx: ResolveCtx<'_> = ResolveCtx {
        chunks,
        module: module_name,
        label_to_mfa: &label_to_mfa,
        label_address: &label_address,
    };

    for (index, span) in spans.iter().enumerate() {
        let function_index: u32 = usize_u32(index);
        register_symbol(span, function_index, &mut module);
        let function: NirFunction = lift_function(instrs, span, function_index, &ctx, &mut imports);
        module.functions.push(function);
    }

    if module.functions.iter().all(|f| f.instructions.is_empty()) {
        return Err(LiftError::Empty);
    }

    for (symbol, address) in imports.into_sorted() {
        module.symbols.push(NirSymbol {
            address,
            name: symbol,
            kind: SymbolKind::Import,
        });
    }

    Ok(module)
}

struct ResolveCtx<'a> {
    chunks: &'a Chunks,
    module: &'a str,
    label_to_mfa: &'a BTreeMap<u32, (String, u32)>,
    label_address: &'a BTreeMap<u32, u64>,
}

impl ResolveCtx<'_> {
    fn import_mfa(&self, index: u32) -> Option<String> {
        let entry: &ImportEntry = self.chunks.imports.get(index as usize)?;
        let module: &str = self.chunks.atoms.get(entry.module_atom_index)?;
        let function: &str = self.chunks.atoms.get(entry.function_atom_index)?;
        Some(format!("{module}:{function}/{}", entry.arity))
    }

    fn bif_name(&self, index: u32) -> Option<String> {
        let entry: &ImportEntry = self.chunks.imports.get(index as usize)?;
        self.chunks
            .atoms
            .get(entry.function_atom_index)
            .map(str::to_owned)
    }

    fn local_mfa(&self, label: u32) -> Option<String> {
        let (name, arity): &(String, u32) = self.label_to_mfa.get(&label)?;
        Some(format!("{}:{name}/{arity}", self.module))
    }

    fn target_of(&self, label: u32) -> Option<u64> {
        if label == 0 {
            return None;
        }
        self.label_address.get(&label).copied()
    }
}

fn build_label_mfa(instrs: &[Instruction], chunks: &Chunks) -> BTreeMap<u32, (String, u32)> {
    let mut map: BTreeMap<u32, (String, u32)> = BTreeMap::new();
    let mut current: Option<(String, u32)> = None;
    for instr in instrs {
        match instr.name {
            "func_info" => {
                let fun_atom: u32 = atom_index(instr.operands.get(1));
                let arity: u32 = literal_u32(instr.operands.get(2));
                let name: String = chunks
                    .atoms
                    .get(fun_atom)
                    .map_or("?", |value: &str| value)
                    .to_owned();
                current = Some((name, arity));
            }
            "label" => {
                if let (Some((name, arity)), Some(label)) =
                    (&current, label_value(instr.operands.first()))
                {
                    map.insert(label, (name.clone(), *arity));
                }
            }
            _ => {}
        }
    }
    map
}

fn split_functions(instrs: &[Instruction], chunks: &Chunks) -> Vec<FunctionSpan> {
    let mut spans: Vec<FunctionSpan> = Vec::new();
    let mut idx: usize = 0;
    while idx < instrs.len() {
        if instrs[idx].name != "func_info" {
            idx += 1;
            continue;
        }
        let func_info: &Instruction = &instrs[idx];
        let fun_atom: u32 = atom_index(func_info.operands.get(1));
        let arity: u32 = literal_u32(func_info.operands.get(2));
        let name: String = chunks
            .atoms
            .get(fun_atom)
            .map_or("__unknown__", |value: &str| value)
            .to_owned();
        let start: usize = back_to_preamble(instrs, idx);
        let end: usize = next_func_boundary(instrs, idx + 1);
        let entry_label: u32 = instrs[idx + 1..end]
            .iter()
            .find(|i: &&Instruction| i.name == "label")
            .and_then(|i: &Instruction| label_value(i.operands.first()))
            .map_or(0, |value: u32| value);
        spans.push(FunctionSpan {
            name,
            arity,
            entry_label,
            start,
            end,
        });
        idx = end;
    }
    spans
}

fn back_to_preamble(instrs: &[Instruction], func_info_at: usize) -> usize {
    let mut start: usize = func_info_at;
    while start > 0 {
        let prev: &str = instrs[start - 1].name;
        if prev == "label" || prev == "line" {
            start -= 1;
        } else {
            break;
        }
    }
    start
}

fn next_func_boundary(instrs: &[Instruction], from: usize) -> usize {
    let mut cursor: usize = from;
    while cursor < instrs.len() {
        if instrs[cursor].name == "func_info" {
            return back_to_preamble(instrs, cursor);
        }
        cursor += 1;
    }
    instrs.len()
}

fn build_label_address(instrs: &[Instruction], spans: &[FunctionSpan]) -> BTreeMap<u32, u64> {
    let mut map: BTreeMap<u32, u64> = BTreeMap::new();
    for (index, span) in spans.iter().enumerate() {
        let base: u64 = function_address(usize_u32(index));
        for (local, instr) in instrs[span.start..span.end].iter().enumerate() {
            if instr.name != "label" {
                continue;
            }
            let Some(label) = label_value(instr.operands.first()) else {
                continue;
            };
            let address: u64 = base.saturating_add(usize_u64(local));
            map.insert(label, address);
        }
    }
    map
}

fn function_label(name: &str, arity: u32) -> String {
    format!("{name}/{arity}")
}

fn register_symbol(span: &FunctionSpan, function_index: u32, module: &mut NirModule) {
    module.symbols.push(NirSymbol {
        address: function_address(function_index),
        name: function_label(&span.name, span.arity),
        kind: SymbolKind::Function,
    });
}

fn lift_function(
    instrs: &[Instruction],
    span: &FunctionSpan,
    function_index: u32,
    ctx: &ResolveCtx<'_>,
    imports: &mut ImportTable,
) -> NirFunction {
    let base: u64 = function_address(function_index);
    let body: &[Instruction] = &instrs[span.start..span.end];
    let mut instructions: Vec<NirInstr> = Vec::with_capacity(body.len());

    for (local, instr) in body.iter().enumerate() {
        if instr.name == "int_code_end" {
            continue;
        }
        let address: u64 = base.saturating_add(usize_u64(local));
        let (op, operands): (NirOp, Vec<String>) = classify(instr, ctx, imports);
        let reads_memory: bool = is_load(instr.name);
        let writes_memory: bool = is_store(instr.name);
        instructions.push(NirInstr {
            address,
            op,
            mnemonic: instr.name.to_owned(),
            operands,
            reads_memory,
            writes_memory,
            byte_width: false,
            source: SourceRef::new(SourceLang::Beam, address),
        });
    }

    let end: u64 = base.saturating_add(usize_u64(body.len()).saturating_add(1));
    NirFunction {
        name: function_label(&span.name, span.arity),
        address: base,
        end,
        is_export: false,
        instructions,
        source: SourceRef::labelled(
            SourceLang::Beam,
            base,
            format!("arity={} entry_label={}", span.arity, span.entry_label),
        ),
    }
}

fn classify(
    instr: &Instruction,
    ctx: &ResolveCtx<'_>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let ops: &[Operand] = &instr.operands;
    match instr.name {
        "return" => (NirOp::Return, Vec::new()),
        "call" | "call_only" | "call_last" => classify_local_call(ops.get(1), ctx, imports),
        "call_ext" | "call_ext_only" | "call_ext_last" => {
            classify_ext_call(ops.get(1), ctx, imports)
        }
        "apply" | "apply_last" | "call_fun" | "call_fun2" | "make_fun" | "make_fun2"
        | "make_fun3" => (NirOp::IndirectCall, Vec::new()),
        "gc_bif1" | "gc_bif2" | "gc_bif3" => classify_bif(ops.get(2), ctx, imports),
        "bif0" => classify_bif(ops.first(), ctx, imports),
        "bif1" | "bif2" | "bif3" => classify_bif(ops.get(1), ctx, imports),
        "int_band" | "int_bor" | "int_bxor" | "int_bsl" | "int_bsr" | "int_div" | "int_rem"
        | "int_bnot" | "m_plus" | "m_minus" | "m_times" | "m_div" | "fadd" | "fsub" | "fmul"
        | "fdiv" | "fnegate" => (
            NirOp::BinOp {
                op: word_op(instr.name),
            },
            Vec::new(),
        ),
        "jump" => (
            NirOp::Branch {
                target: branch_target(ops.first(), ctx),
            },
            Vec::new(),
        ),
        "select_val" | "select_tuple_arity" => (
            NirOp::CondBranch {
                target: branch_target(ops.get(1), ctx),
            },
            Vec::new(),
        ),
        "move" | "fmove" | "swap" => (NirOp::Const, move_operands(ops, ctx)),
        "put" | "put_list" | "put_tuple" | "put_tuple2" | "put_map_assoc" | "put_map_exact"
        | "put_string" | "put_literal" | "put_record" => (NirOp::Const, Vec::new()),
        "get_tuple_element"
        | "get_list"
        | "get_hd"
        | "get_tl"
        | "get_map_elements"
        | "get_record_field"
        | "get_record_elements" => (NirOp::Load, Vec::new()),
        "set_tuple_element" | "update_record" => (NirOp::Store, Vec::new()),
        "badmatch" | "if_end" | "case_end" | "try_case_end" | "badrecord" | "raise"
        | "raw_raise" => (NirOp::Interrupt, Vec::new()),
        _ if is_test(instr.name) => (
            NirOp::CondBranch {
                target: branch_target(ops.first(), ctx),
            },
            Vec::new(),
        ),
        _ => (NirOp::Nop, Vec::new()),
    }
}

fn named_call(name: Option<String>, imports: &mut ImportTable) -> (NirOp, Vec<String>) {
    let Some(name) = name else {
        return (NirOp::IndirectCall, Vec::new());
    };
    let address: u64 = imports.address_of(&name);
    (
        NirOp::Call {
            target: Some(address),
        },
        vec![name],
    )
}

fn classify_local_call(
    label_op: Option<&Operand>,
    ctx: &ResolveCtx<'_>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let Some(label): Option<u32> = label_value(label_op) else {
        return (NirOp::IndirectCall, Vec::new());
    };
    named_call(ctx.local_mfa(label), imports)
}

fn classify_ext_call(
    index_op: Option<&Operand>,
    ctx: &ResolveCtx<'_>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let Some(index): Option<u32> = value_u32(index_op) else {
        return (NirOp::IndirectCall, Vec::new());
    };
    named_call(ctx.import_mfa(index), imports)
}

fn classify_bif(
    name_op: Option<&Operand>,
    ctx: &ResolveCtx<'_>,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let Some(index): Option<u32> = value_u32(name_op) else {
        return (NirOp::Nop, Vec::new());
    };
    let Some(name) = ctx.bif_name(index) else {
        return (NirOp::Nop, Vec::new());
    };
    if let Some(op) = arithmetic_bif(&name) {
        return (NirOp::BinOp { op }, Vec::new());
    }
    named_call(Some(name), imports)
}

fn move_operands(ops: &[Operand], ctx: &ResolveCtx<'_>) -> Vec<String> {
    render_constant(ops.first(), ctx).into_iter().collect()
}

fn render_constant(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> Option<String> {
    match op {
        Some(Operand::Atom(0)) => Some("nil".to_owned()),
        Some(Operand::Atom(index)) => ctx.chunks.atoms.get(*index).map(str::to_owned),
        Some(Operand::SignedInteger(v)) => Some(v.to_string()),
        Some(Operand::Literal(v)) => Some(v.to_string()),
        Some(Operand::Character(c)) => Some(c.to_string()),
        Some(Operand::LiteralIndex(index)) => render_literal(*index, ctx),
        Some(Operand::BigInteger { sign, magnitude_be }) => {
            let digits: String = big_to_decimal(magnitude_be);
            Some(if *sign == 1 {
                format!("-{digits}")
            } else {
                digits
            })
        }
        _ => None,
    }
}

fn render_literal(index: u32, ctx: &ResolveCtx<'_>) -> Option<String> {
    let term: &Term = ctx
        .chunks
        .literals
        .as_ref()
        .and_then(|c| c.literals.get(index as usize))?;
    Some(render_term(term))
}

fn render_term(term: &Term) -> String {
    match term {
        Term::SmallInt(v) => v.to_string(),
        Term::Int(v) => v.to_string(),
        Term::Float(f) => f.to_string(),
        Term::Atom(a) => a.clone(),
        Term::Nil => "[]".to_owned(),
        Term::String(bytes) | Term::Binary(bytes) => string_from_bytes(bytes),
        Term::BigInt { sign, magnitude_le } => {
            let mut be: Vec<u8> = magnitude_le.clone();
            be.reverse();
            let digits: String = big_to_decimal(&be);
            if *sign == 1 {
                format!("-{digits}")
            } else {
                digits
            }
        }
        Term::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(render_term).collect();
            format!("{{{}}}", inner.join(","))
        }
        Term::List { elements, tail } => {
            let mut inner: Vec<String> = elements.iter().map(render_term).collect();
            if !matches!(**tail, Term::Nil) {
                inner.push(format!("|{}", render_term(tail)));
            }
            format!("[{}]", inner.join(","))
        }
        _ => "<term>".to_owned(),
    }
}

fn string_from_bytes(bytes: &[u8]) -> String {
    core::str::from_utf8(bytes).map_or_else(
        |_| {
            bytes
                .iter()
                .map(|b: &u8| b.to_string())
                .collect::<Vec<String>>()
                .join(",")
        },
        str::to_owned,
    )
}

const MAX_BIG_DECIMAL_BYTES: usize = 1024;

fn big_to_hex(magnitude_be: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(2 + magnitude_be.len() * 2);
    out.push_str("0x");
    for &byte in magnitude_be {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn big_to_decimal(magnitude_be: &[u8]) -> String {
    if magnitude_be.len() > MAX_BIG_DECIMAL_BYTES {
        return big_to_hex(magnitude_be);
    }
    let mut digits: Vec<u8> = vec![0];
    for &byte in magnitude_be {
        let mut carry: u32 = u32::from(byte);
        for digit in &mut digits {
            let value: u32 = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits.last().is_some_and(|value: &u8| *value == 0) {
        digits.pop();
    }
    digits
        .iter()
        .rev()
        .map(|d: &u8| (b'0' + d) as char)
        .collect()
}

fn branch_target(op: Option<&Operand>, ctx: &ResolveCtx<'_>) -> Option<u64> {
    label_value(op).and_then(|label: u32| ctx.target_of(label))
}

fn arithmetic_bif(name: &str) -> Option<BinaryOp> {
    Some(match name {
        "+" => BinaryOp::Add,
        "-" => BinaryOp::Sub,
        "*" => BinaryOp::Mul,
        "/" | "div" => BinaryOp::Div,
        "rem" => BinaryOp::Rem,
        "band" => BinaryOp::And,
        "bor" => BinaryOp::Or,
        "bxor" => BinaryOp::Xor,
        "bsl" => BinaryOp::Shl,
        "bsr" => BinaryOp::Shr,
        "bnot" => BinaryOp::Not,
        _ => return None,
    })
}

fn word_op(name: &str) -> BinaryOp {
    match name {
        "int_band" => BinaryOp::And,
        "int_bor" => BinaryOp::Or,
        "int_bxor" => BinaryOp::Xor,
        "int_bsl" => BinaryOp::Shl,
        "int_bsr" => BinaryOp::Shr,
        "int_div" | "m_div" | "fdiv" => BinaryOp::Div,
        "int_rem" => BinaryOp::Rem,
        "int_bnot" => BinaryOp::Not,
        "m_minus" | "fsub" => BinaryOp::Sub,
        "m_times" | "fmul" => BinaryOp::Mul,
        "fnegate" => BinaryOp::Neg,
        _ => BinaryOp::Add,
    }
}

const fn is_test(name: &str) -> bool {
    matches!(
        name.as_bytes(),
        b"is_lt"
            | b"is_ge"
            | b"is_eq"
            | b"is_ne"
            | b"is_eq_exact"
            | b"is_ne_exact"
            | b"is_integer"
            | b"is_float"
            | b"is_number"
            | b"is_atom"
            | b"is_pid"
            | b"is_reference"
            | b"is_port"
            | b"is_nil"
            | b"is_binary"
            | b"is_list"
            | b"is_nonempty_list"
            | b"is_tuple"
            | b"test_arity"
            | b"is_function"
            | b"is_boolean"
            | b"is_function2"
            | b"is_bitstr"
            | b"is_map"
            | b"is_tagged_tuple"
            | b"has_map_fields"
    )
}

const fn is_load(name: &str) -> bool {
    matches!(
        name.as_bytes(),
        b"get_tuple_element"
            | b"get_list"
            | b"get_hd"
            | b"get_tl"
            | b"get_map_elements"
            | b"get_record_field"
            | b"get_record_elements"
    )
}

const fn is_store(name: &str) -> bool {
    matches!(name.as_bytes(), b"set_tuple_element" | b"update_record")
}

const fn atom_index(op: Option<&Operand>) -> u32 {
    match op {
        Some(Operand::Atom(i)) => *i,
        _ => 0,
    }
}

fn label_value(op: Option<&Operand>) -> Option<u32> {
    match op {
        Some(Operand::Label(l)) => Some(*l),
        Some(Operand::Literal(v)) => u32::try_from(*v).ok(),
        _ => None,
    }
}

fn literal_u32(op: Option<&Operand>) -> u32 {
    match op {
        Some(Operand::Literal(v)) => u32::try_from(*v).map_or(0, |converted: u32| converted),
        _ => 0,
    }
}

fn value_u32(op: Option<&Operand>) -> Option<u32> {
    match op {
        Some(Operand::Literal(v)) => u32::try_from(*v).ok(),
        Some(Operand::SignedInteger(v)) => u32::try_from(*v).ok(),
        Some(
            Operand::Atom(v)
            | Operand::XReg(v)
            | Operand::YReg(v)
            | Operand::Label(v)
            | Operand::Character(v)
            | Operand::LiteralIndex(v)
            | Operand::FpReg(v),
        ) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disrobe_pass_beam::chunks::AtomTable;

    #[test]
    fn big_decimal_renders_small_magnitudes_and_caps_oversized_ones() {
        assert_eq!(big_to_decimal(&[0x01, 0x00]), "256");
        assert_eq!(big_to_decimal(&[0xff]), "255");
        let oversized: Vec<u8> = vec![0xab; MAX_BIG_DECIMAL_BYTES + 1];
        let rendered: String = big_to_decimal(&oversized);
        assert!(
            rendered.starts_with("0x"),
            "an oversized magnitude falls back to hex instead of the quadratic decimal path"
        );
        assert_eq!(rendered.len(), 2 + oversized.len() * 2);
    }

    fn empty_chunks() -> Chunks {
        Chunks {
            atoms: AtomTable {
                atoms: vec!["mod".to_owned()],
            },
            code: None,
            strings: None,
            attributes: None,
            compile_info: None,
            dbgi: None,
            docs: None,
            exports: Vec::new(),
            imports: Vec::new(),
            locals: Vec::new(),
            literals: None,
            line: None,
            funs: Vec::new(),
            other: BTreeMap::new(),
        }
    }

    fn chunks_with_import() -> Chunks {
        Chunks {
            atoms: AtomTable {
                atoms: vec!["mod".to_owned(), "io".to_owned(), "format".to_owned()],
            },
            code: None,
            strings: None,
            attributes: None,
            compile_info: None,
            dbgi: None,
            docs: None,
            exports: Vec::new(),
            imports: vec![ImportEntry {
                module_atom_index: 2,
                function_atom_index: 3,
                arity: 1,
            }],
            locals: Vec::new(),
            literals: None,
            line: None,
            funs: Vec::new(),
            other: BTreeMap::new(),
        }
    }

    #[test]
    fn missing_labels_do_not_resolve_to_zero() {
        let chunks: Chunks = empty_chunks();
        let label_to_mfa: BTreeMap<u32, (String, u32)> =
            BTreeMap::from([(0, ("zero".to_owned(), 0))]);
        let label_address: BTreeMap<u32, u64> = BTreeMap::from([(0, 7)]);
        let ctx: ResolveCtx<'_> = ResolveCtx {
            chunks: &chunks,
            module: "mod",
            label_to_mfa: &label_to_mfa,
            label_address: &label_address,
        };
        let mut imports: ImportTable = ImportTable::new();
        let (op, operands): (NirOp, Vec<String>) = classify_local_call(None, &ctx, &mut imports);

        assert_eq!(usize_u32(usize::MAX), u32::MAX);
        assert_eq!(usize_u64(7), 7);
        assert_eq!(branch_target(None, &ctx), None);
        assert_eq!(op, NirOp::IndirectCall);
        assert!(operands.is_empty());
    }

    #[test]
    fn invalid_external_call_operands_do_not_resolve_to_first_import() {
        let chunks: Chunks = chunks_with_import();
        let label_to_mfa: BTreeMap<u32, (String, u32)> = BTreeMap::new();
        let label_address: BTreeMap<u32, u64> = BTreeMap::new();
        let ctx: ResolveCtx<'_> = ResolveCtx {
            chunks: &chunks,
            module: "mod",
            label_to_mfa: &label_to_mfa,
            label_address: &label_address,
        };
        let operands: [Operand; 2] = [
            Operand::SignedInteger(-1),
            Operand::Literal(u64::from(u32::MAX) + 1),
        ];

        for operand in &operands {
            let mut imports: ImportTable = ImportTable::new();
            let (op, rendered): (NirOp, Vec<String>) =
                classify_ext_call(Some(operand), &ctx, &mut imports);

            assert_eq!(op, NirOp::IndirectCall);
            assert!(rendered.is_empty());
        }
    }
}
