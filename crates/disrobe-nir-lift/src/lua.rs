use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_lua::decompile::opcode::{Decoded, Op, decode};
use disrobe_pass_lua::read_auto;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaProto};

use crate::error::{LiftError, Result};
use crate::{usize_to_u32_saturating, usize_to_u64_saturating};

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;
const MAX_REGISTERS: usize = 256;
const MAX_LUA_PROTO_DEPTH: usize = 256;
const MAX_LUA_PROTOS: usize = 262_144;

pub fn lift_lua_chunk(bytes: &[u8]) -> Result<NirModule> {
    let chunk: LuaChunk =
        read_auto(bytes).map_err(|e| LiftError::Source(format!("lua decode: {e}")))?;
    build_module(bytes, &chunk)
}

#[must_use]
pub const fn function_address(proto_index: u32) -> u64 {
    (proto_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

struct ProtoEntry<'a> {
    proto: &'a LuaProto,
    index: u32,
    is_main: bool,
}

fn enumerate_protos(chunk: &LuaChunk) -> Result<Vec<ProtoEntry<'_>>> {
    enumerate_protos_with_limits(chunk, MAX_LUA_PROTO_DEPTH, MAX_LUA_PROTOS)
}

fn enumerate_protos_with_limits(
    chunk: &LuaChunk,
    max_depth: usize,
    max_count: usize,
) -> Result<Vec<ProtoEntry<'_>>> {
    let mut out: Vec<ProtoEntry<'_>> = Vec::new();
    let mut next: u32 = 0;
    collect_protos(
        &chunk.main,
        true,
        0usize,
        max_depth,
        max_count,
        &mut next,
        &mut out,
    )?;
    Ok(out)
}

fn collect_protos<'a>(
    proto: &'a LuaProto,
    is_main: bool,
    depth: usize,
    max_depth: usize,
    max_count: usize,
    next: &mut u32,
    out: &mut Vec<ProtoEntry<'a>>,
) -> Result<()> {
    if depth > max_depth {
        return Err(LiftError::DepthExceeded { limit: max_depth });
    }
    if out.len() >= max_count {
        return Err(LiftError::AstSizeExceeded { limit: max_count });
    }
    let index: u32 = *next;
    let Some(next_index): Option<u32> = (*next).checked_add(1) else {
        return Err(LiftError::Source("lua proto count exceeds u32".to_owned()));
    };
    *next = next_index;
    out.push(ProtoEntry {
        proto,
        index,
        is_main,
    });
    let child_depth: usize = depth.saturating_add(1usize);
    for sub in &proto.protos {
        collect_protos(sub, false, child_depth, max_depth, max_count, next, out)?;
    }
    Ok(())
}

fn proto_label(index: u32, is_main: bool) -> String {
    if is_main {
        "<main>".to_owned()
    } else {
        format!("<proto:{index}>")
    }
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

fn build_module(source: &[u8], chunk: &LuaChunk) -> Result<NirModule> {
    let source_hash: [u8; 32] = *blake3::hash(source).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Lua);

    let entries: Vec<ProtoEntry<'_>> = enumerate_protos(chunk)?;
    if entries.is_empty() {
        return Err(LiftError::Empty);
    }

    let mut imports: ImportTable = ImportTable::new();

    for entry in &entries {
        register_proto_symbol(entry, &mut module);
        let function: NirFunction = lift_proto(entry, chunk.dialect, &mut imports);
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

fn register_proto_symbol(entry: &ProtoEntry<'_>, module: &mut NirModule) {
    let kind: SymbolKind = if entry.is_main {
        SymbolKind::Export
    } else {
        SymbolKind::Function
    };
    module.symbols.push(NirSymbol {
        address: function_address(entry.index),
        name: proto_label(entry.index, entry.is_main),
        kind,
    });
}

fn const_string(proto: &LuaProto, index: u32) -> Option<String> {
    match proto.constants.get(index as usize)? {
        LuaConstant::Str(s) => Some(s.clone()),
        _ => None,
    }
}

fn jump_target(dialect: LuaDialect, here: u32, decoded: &Decoded) -> Option<u32> {
    let offset: i64 = match dialect {
        LuaDialect::Lua54 => i64::from(decoded.sj),
        _ => i64::from(decoded.sbx),
    };
    let target: i64 = i64::from(here) + 1 + offset;
    u32::try_from(target).ok()
}

fn forloop_target(dialect: LuaDialect, here: u32, decoded: &Decoded) -> Option<u32> {
    match dialect {
        LuaDialect::Lua54 => {
            let back: i64 = i64::from(here) + 1 - i64::from(decoded.bx);
            u32::try_from(back).ok()
        }
        _ => jump_target(dialect, here, decoded),
    }
}

const fn is_compare_skip(op: Op) -> bool {
    matches!(
        op,
        Op::Eq
            | Op::Lt
            | Op::Le
            | Op::EqK
            | Op::EqI
            | Op::LtI
            | Op::LeI
            | Op::GtI
            | Op::GeI
            | Op::Test
            | Op::TestSet
    )
}

const fn binary_op(op: Op) -> Option<BinaryOp> {
    Some(match op {
        Op::Add | Op::AddI | Op::AddK | Op::Concat => BinaryOp::Add,
        Op::Sub | Op::SubK => BinaryOp::Sub,
        Op::Mul | Op::MulK | Op::Pow | Op::PowK => BinaryOp::Mul,
        Op::Div | Op::DivK | Op::IDiv | Op::IDivK => BinaryOp::Div,
        Op::Mod | Op::ModK => BinaryOp::Rem,
        Op::BAnd | Op::BAndK => BinaryOp::And,
        Op::BOr | Op::BOrK => BinaryOp::Or,
        Op::BXor | Op::BXorK | Op::BNot => BinaryOp::Xor,
        Op::Shl | Op::ShlI => BinaryOp::Shl,
        Op::Shr | Op::ShrI => BinaryOp::Shr,
        Op::Unm => BinaryOp::Neg,
        Op::Not | Op::Len => BinaryOp::Not,
        _ => return None,
    })
}

const fn is_load(op: Op) -> bool {
    matches!(
        op,
        Op::GetGlobal
            | Op::GetUpval
            | Op::GetTable
            | Op::GetTabUp
            | Op::GetField
            | Op::GetI
            | Op::Self_
    )
}

const fn is_store(op: Op) -> bool {
    matches!(
        op,
        Op::SetGlobal
            | Op::SetUpval
            | Op::SetTable
            | Op::SetTabUp
            | Op::SetField
            | Op::SetI
            | Op::SetList
    )
}

const fn is_const(op: Op) -> bool {
    matches!(
        op,
        Op::LoadK
            | Op::LoadKx
            | Op::LoadBool
            | Op::LoadFalse
            | Op::LFalseSkip
            | Op::LoadTrue
            | Op::LoadNil
            | Op::LoadI
            | Op::LoadF
            | Op::NewTable
            | Op::Closure
    )
}

fn access_name(proto: &LuaProto, op: Op, decoded: &Decoded) -> Option<String> {
    match op {
        Op::GetGlobal | Op::SetGlobal | Op::LoadK | Op::LoadKx => const_string(proto, decoded.bx),
        Op::GetField | Op::SetField | Op::Self_ | Op::GetTabUp => const_string(proto, decoded.c),
        Op::SetTabUp => const_string(proto, decoded.b),
        _ => None,
    }
}

struct RegisterNames {
    slots: Vec<Option<String>>,
}

impl RegisterNames {
    fn new() -> Self {
        Self {
            slots: vec![None; MAX_REGISTERS],
        }
    }

    fn set(&mut self, reg: u32, name: Option<String>) {
        if let Some(slot) = self.slots.get_mut(reg as usize) {
            *slot = name;
        }
    }

    fn get(&self, reg: u32) -> Option<String> {
        self.slots.get(reg as usize).and_then(Clone::clone)
    }
}

fn lift_proto(
    entry: &ProtoEntry<'_>,
    dialect: LuaDialect,
    imports: &mut ImportTable,
) -> NirFunction {
    let proto: &LuaProto = entry.proto;
    let base: u64 = function_address(entry.index);
    let count: usize = proto.code.len();

    let mut decoded_all: Vec<Decoded> = Vec::with_capacity(count);
    for raw in &proto.code {
        decoded_all.push(decode(*raw, dialect));
    }

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(count);
    let mut names: RegisterNames = RegisterNames::new();

    for pc in 0..count {
        let decoded: Decoded = decoded_all[pc];
        let op: Op = decoded.op;
        let here: u32 = usize_to_u32_saturating(pc);
        let address: u64 = base.saturating_add(u64::from(here));
        let raw: u32 = proto.code.get(pc).copied().unwrap_or_default();
        let unmodeled: NirOp = NirOp::Unmodeled {
            opcode: opcode_byte(raw, dialect),
            offset: here,
        };

        let branch_target: Option<u64> = resolve_target(dialect, here, &decoded, count, base);
        let cond_target: Option<u64> = if is_compare_skip(op) {
            decoded_all
                .get(pc + 1)
                .filter(|n| n.op == Op::Jmp)
                .and_then(|jmp: &Decoded| jump_target(dialect, here + 1, jmp))
                .filter(|&t| (t as usize) < count)
                .map(|t| base.saturating_add(u64::from(t)))
        } else {
            None
        };

        let (nir_op, operands): (NirOp, Vec<String>) = classify(
            proto,
            op,
            &decoded,
            branch_target,
            cond_target,
            unmodeled,
            &mut names,
            imports,
        );
        let (reads_memory, writes_memory): (bool, bool) = (is_load(op), is_store(op));

        instructions.push(NirInstr {
            address,
            op: nir_op,
            mnemonic: op.mnemonic().to_owned(),
            operands,
            reads_memory,
            writes_memory,
            byte_width: false,
            source: SourceRef::new(SourceLang::Lua, address),
        });
    }

    let end: u64 = base.saturating_add(usize_to_u64_saturating(count).saturating_add(1));
    NirFunction {
        name: proto_label(entry.index, entry.is_main),
        address: base,
        end,
        is_export: entry.is_main,
        instructions,
        source: SourceRef::labelled(
            SourceLang::Lua,
            base,
            format!(
                "params={} consts={} dialect={:?}",
                proto.num_params,
                proto.constants.len(),
                dialect
            ),
        ),
    }
}

fn resolve_target(
    dialect: LuaDialect,
    here: u32,
    decoded: &Decoded,
    count: usize,
    base: u64,
) -> Option<u64> {
    let target: Option<u32> = match decoded.op {
        Op::Jmp | Op::ForPrep => jump_target(dialect, here, decoded),
        Op::ForLoop | Op::TForLoop => forloop_target(dialect, here, decoded),
        _ => return None,
    };
    target
        .filter(|&t| (t as usize) < count)
        .map(|t| base.saturating_add(u64::from(t)))
}

const fn opcode_byte(raw: u32, dialect: LuaDialect) -> u8 {
    let mask: u32 = match dialect {
        LuaDialect::Lua54 => 0x7F,
        _ => 0x3F,
    };
    (raw & mask) as u8
}

fn classify(
    proto: &LuaProto,
    op: Op,
    decoded: &Decoded,
    branch_target: Option<u64>,
    cond_target: Option<u64>,
    unmodeled: NirOp,
    names: &mut RegisterNames,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    match op {
        Op::Return | Op::Return0 | Op::Return1 => {
            names.set(decoded.a, None);
            (NirOp::Return, Vec::new())
        }
        Op::Jmp | Op::ForPrep => (
            NirOp::Branch {
                target: branch_target,
            },
            Vec::new(),
        ),
        Op::ForLoop | Op::TForLoop | Op::TForCall => (
            NirOp::CondBranch {
                target: branch_target,
            },
            Vec::new(),
        ),
        Op::Call | Op::TailCall => classify_call(decoded, names, imports),
        Op::Move => {
            let src: Option<String> = names.get(decoded.b);
            names.set(decoded.a, src);
            (unmodeled, Vec::new())
        }
        _ if is_compare_skip(op) => (
            NirOp::CondBranch {
                target: cond_target,
            },
            Vec::new(),
        ),
        _ if binary_op(op).is_some() => {
            names.set(decoded.a, None);
            let bop: BinaryOp = binary_op(op).map_or(BinaryOp::Add, |value: BinaryOp| value);
            (NirOp::BinOp { op: bop }, Vec::new())
        }
        _ if is_load(op) => {
            let name: Option<String> = access_name(proto, op, decoded);
            names.set(decoded.a, name.clone());
            (NirOp::Load, name.into_iter().collect())
        }
        _ if is_store(op) => {
            let name: Option<String> = access_name(proto, op, decoded);
            (NirOp::Store, name.into_iter().collect())
        }
        _ if is_const(op) => {
            let operand: Vec<String> = const_operand(proto, op, decoded);
            let name: Option<String> = if matches!(op, Op::LoadK | Op::LoadKx) {
                const_string(proto, decoded.bx)
            } else {
                None
            };
            names.set(decoded.a, name);
            (NirOp::Const, operand)
        }
        _ => {
            names.set(decoded.a, None);
            (unmodeled, Vec::new())
        }
    }
}

fn classify_call(
    decoded: &Decoded,
    names: &mut RegisterNames,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let callee: Option<String> = names.get(decoded.a);
    names.set(decoded.a, None);
    match callee {
        Some(name) if !name.is_empty() => {
            let address: u64 = imports.address_of(&name);
            (
                NirOp::Call {
                    target: Some(address),
                },
                vec![name],
            )
        }
        _ => (NirOp::IndirectCall, Vec::new()),
    }
}

fn const_operand(proto: &LuaProto, op: Op, decoded: &Decoded) -> Vec<String> {
    match op {
        Op::LoadK | Op::LoadKx => proto
            .constants
            .get(decoded.bx as usize)
            .map_or_else(Vec::new, |c| vec![render_constant(c)]),
        Op::LoadBool | Op::LoadTrue => vec!["true".to_owned()],
        Op::LoadFalse | Op::LFalseSkip => vec!["false".to_owned()],
        Op::LoadNil => vec!["nil".to_owned()],
        Op::LoadI | Op::LoadF => vec![decoded.sbx.to_string()],
        Op::NewTable => vec!["{}".to_owned()],
        Op::Closure => vec![format!("closure[{}]", decoded.bx)],
        _ => Vec::new(),
    }
}

fn render_constant(constant: &LuaConstant) -> String {
    match constant {
        LuaConstant::Nil => "nil".to_owned(),
        LuaConstant::Bool(b) => b.to_string(),
        LuaConstant::Integer(i) => i.to_string(),
        LuaConstant::Number(n) => n.to_string(),
        LuaConstant::Str(s) => s.clone(),
        LuaConstant::ClosureRef(i) => format!("closure[{i}]"),
        LuaConstant::Import(parts) => parts.join("."),
        LuaConstant::Vector(v) => format!("vector{v:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_proto(protos: Vec<LuaProto>) -> LuaProto {
        LuaProto {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2,
            code: Vec::new(),
            constants: Vec::new(),
            protos,
            source_lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    fn chunk(main: LuaProto) -> LuaChunk {
        LuaChunk {
            dialect: LuaDialect::Lua54,
            version_byte: 0x54,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 8,
            size_of_lua_number: 8,
            integral_number: false,
            main,
        }
    }

    #[test]
    fn proto_enumeration_rejects_excessive_depth() {
        let mut proto: LuaProto = empty_proto(Vec::new());
        for _depth in 0usize..=MAX_LUA_PROTO_DEPTH {
            proto = empty_proto(vec![proto]);
        }
        let result: Result<NirModule> = build_module(b"depth", &chunk(proto));
        assert!(matches!(
            result,
            Err(LiftError::DepthExceeded {
                limit: MAX_LUA_PROTO_DEPTH
            })
        ));
    }

    #[test]
    fn proto_enumeration_rejects_excessive_count() {
        let main: LuaProto = empty_proto(vec![empty_proto(Vec::new()), empty_proto(Vec::new())]);
        let lua_chunk: LuaChunk = chunk(main);
        let result: Result<Vec<ProtoEntry<'_>>> =
            enumerate_protos_with_limits(&lua_chunk, MAX_LUA_PROTO_DEPTH, 2usize);
        assert!(matches!(
            result,
            Err(LiftError::AstSizeExceeded { limit: 2usize })
        ));
    }
}
