use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_as3::abc::{self, AbcFile, DisasmLine, MethodBody, MethodInfo, TraitInfo};
use disrobe_pass_as3::swf::{self, DoAbc, Swf};

use crate::error::{LiftError, Result};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;

const TRAIT_KIND_METHOD: u8 = 1;
const TRAIT_KIND_GETTER: u8 = 2;
const TRAIT_KIND_SETTER: u8 = 3;
const TRAIT_KIND_FUNCTION: u8 = 5;

pub fn lift_swf_abc(bytes: &[u8]) -> Result<NirModule> {
    let swf: Swf = swf::parse(bytes).map_err(|e| LiftError::Source(format!("swf parse: {e}")))?;
    let blobs: Vec<DoAbc> = swf.collect_do_abc();
    if blobs.is_empty() {
        return Err(LiftError::Empty);
    }
    let mut abcs: Vec<AbcFile> = Vec::with_capacity(blobs.len());
    for blob in &blobs {
        let abc: AbcFile = abc::parse(&blob.abc_bytes)
            .map_err(|e| LiftError::Source(format!("abc parse: {e}")))?;
        abcs.push(abc);
    }
    build_module(bytes, &abcs)
}

pub fn lift_abc(bytes: &[u8]) -> Result<NirModule> {
    let abc: AbcFile =
        abc::parse(bytes).map_err(|e| LiftError::Source(format!("abc parse: {e}")))?;
    build_module(bytes, std::slice::from_ref(&abc))
}

#[must_use]
pub const fn function_address(method_index: u32) -> u64 {
    (method_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

struct MethodEntry {
    name: String,
    body_pos: usize,
    abc_index: usize,
    is_export: bool,
}

fn build_module(source: &[u8], abcs: &[AbcFile]) -> Result<NirModule> {
    let source_hash: [u8; 32] = *blake3::hash(source).as_bytes();
    let mut module: NirModule = NirModule::new(source_hash, SourceLang::Avm2);

    let entries: Vec<MethodEntry> = enumerate_methods(abcs);
    if entries.is_empty() {
        return Err(LiftError::Empty);
    }

    let mut imports: ImportTable = ImportTable::new();

    for (index, entry) in entries.iter().enumerate() {
        let method_index: u32 = usize_to_u32_saturating(index);
        register_method_symbol(entry, method_index, &mut module);
        let abc: &AbcFile = &abcs[entry.abc_index];
        let body: &MethodBody = &abc.method_bodies[entry.body_pos];
        let function: NirFunction = lift_body(entry, method_index, abc, body, &mut imports);
        module.functions.push(function);
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

fn enumerate_methods(abcs: &[AbcFile]) -> Vec<MethodEntry> {
    let mut entries: Vec<MethodEntry> = Vec::new();
    for (abc_index, abc) in abcs.iter().enumerate() {
        let names: BTreeMap<u32, String> = method_names(abc);
        let exported: BTreeMap<u32, bool> = exported_methods(abc);
        for (body_pos, body) in abc.method_bodies.iter().enumerate() {
            let name: String = names
                .get(&body.method)
                .cloned()
                .unwrap_or_else(|| method_fallback_name(abc, body.method));
            let is_export: bool = exported
                .get(&body.method)
                .is_some_and(|value: &bool| *value);
            entries.push(MethodEntry {
                name,
                body_pos,
                abc_index,
                is_export,
            });
        }
    }
    entries
}

fn method_names(abc: &AbcFile) -> BTreeMap<u32, String> {
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    for trait_owner in trait_groups(abc) {
        for trait_info in trait_owner {
            if !is_method_trait(trait_info.kind) {
                continue;
            }
            let label: String = trait_label(abc, trait_info);
            names.entry(trait_info.method_index).or_insert(label);
        }
    }
    for (method_index, info) in abc.methods.iter().enumerate() {
        let key: u32 = usize_to_u32_saturating(method_index);
        if info.name_index != 0
            && let Ok(name) = abc.cpool.string_at(info.name_index)
            && !name.is_empty()
        {
            names.entry(key).or_insert_with(|| name.to_owned());
        }
    }
    names
}

fn exported_methods(abc: &AbcFile) -> BTreeMap<u32, bool> {
    let mut exported: BTreeMap<u32, bool> = BTreeMap::new();
    for inst in &abc.instances {
        for trait_info in &inst.traits {
            if is_method_trait(trait_info.kind) {
                exported.insert(trait_info.method_index, true);
            }
        }
        exported.insert(inst.iinit, true);
    }
    for script in &abc.scripts {
        for trait_info in &script.traits {
            if is_method_trait(trait_info.kind) {
                exported.insert(trait_info.method_index, true);
            }
        }
    }
    exported
}

fn trait_groups(abc: &AbcFile) -> Vec<&[TraitInfo]> {
    let mut groups: Vec<&[TraitInfo]> = Vec::new();
    for inst in &abc.instances {
        groups.push(inst.traits.as_slice());
    }
    for class in &abc.classes {
        groups.push(class.traits.as_slice());
    }
    for script in &abc.scripts {
        groups.push(script.traits.as_slice());
    }
    groups
}

const fn is_method_trait(kind: u8) -> bool {
    matches!(
        kind & 0x0F,
        TRAIT_KIND_METHOD | TRAIT_KIND_GETTER | TRAIT_KIND_SETTER | TRAIT_KIND_FUNCTION
    )
}

fn trait_label(abc: &AbcFile, trait_info: &TraitInfo) -> String {
    match abc.cpool.render_multiname_property(trait_info.name_index) {
        Ok(name) if !name.is_empty() && name != "*" => name,
        _ => format!("method#{}", trait_info.method_index),
    }
}

fn method_fallback_name(abc: &AbcFile, method: u32) -> String {
    if let Some(info) = abc.methods.get(method as usize)
        && info.name_index != 0
        && let Ok(name) = abc.cpool.string_at(info.name_index)
        && !name.is_empty()
    {
        return name.to_owned();
    }
    format!("method#{method}")
}

fn register_method_symbol(entry: &MethodEntry, method_index: u32, module: &mut NirModule) {
    let kind: SymbolKind = if entry.is_export {
        SymbolKind::Export
    } else {
        SymbolKind::Function
    };
    module.symbols.push(NirSymbol {
        address: function_address(method_index),
        name: entry.name.clone(),
        kind,
    });
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

fn lift_body(
    entry: &MethodEntry,
    method_index: u32,
    abc: &AbcFile,
    body: &MethodBody,
    imports: &mut ImportTable,
) -> NirFunction {
    let base: u64 = function_address(method_index);
    let lines: Vec<DisasmLine> = abc::disasm(&body.code).unwrap_or_else(|_| Vec::with_capacity(0));
    let sizes: Vec<usize> = instruction_sizes(&lines, body.code.len());

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(lines.len());
    for (ordinal, line) in lines.iter().enumerate() {
        let address: u64 = base.saturating_add(line.offset as u64);
        let end_offset: usize = line.offset.saturating_add(sizes[ordinal]);
        let (op, operand_list): (NirOp, Vec<String>) =
            classify(line, base, end_offset, abc, imports);
        let (reads_memory, writes_memory): (bool, bool) = memory_facets(line.opcode);
        let byte_width: bool = false;
        let mnemonic: String = match &op {
            NirOp::BinOp { op: binary_op } => binary_op.mnemonic().to_owned(),
            _ => line.mnemonic.to_owned(),
        };
        instructions.push(NirInstr {
            address,
            op,
            mnemonic,
            operands: operand_list,
            reads_memory,
            writes_memory,
            byte_width,
            source: SourceRef::new(SourceLang::Avm2, address),
        });
    }

    let end: u64 = base.saturating_add(body.code.len() as u64);
    NirFunction {
        name: entry.name.clone(),
        address: base,
        end,
        is_export: entry.is_export,
        instructions,
        source: SourceRef::labelled(
            SourceLang::Avm2,
            base,
            format!("locals={}", body.local_count),
        ),
    }
}

fn instruction_sizes(lines: &[DisasmLine], code_len: usize) -> Vec<usize> {
    let mut sizes: Vec<usize> = Vec::with_capacity(lines.len());
    for (ordinal, line) in lines.iter().enumerate() {
        let next: usize = lines
            .get(ordinal + 1)
            .map_or(code_len, |n: &DisasmLine| n.offset);
        sizes.push(next.saturating_sub(line.offset));
    }
    sizes
}

fn classify(
    line: &DisasmLine,
    base: u64,
    end_offset: usize,
    abc: &AbcFile,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    if let Some(binary_op) = binary_op(line.opcode) {
        return (NirOp::BinOp { op: binary_op }, Vec::new());
    }
    match line.opcode {
        0x47 | 0x48 => (NirOp::Return, Vec::new()),
        0x03 => (NirOp::Interrupt, Vec::new()),
        0x10 => {
            let target: Option<u64> =
                branch_target(line, end_offset).map(|t: usize| base.saturating_add(t as u64));
            (NirOp::Branch { target }, Vec::new())
        }
        0x0C..=0x0F | 0x11..=0x1A => {
            let target: Option<u64> =
                branch_target(line, end_offset).map(|t: usize| base.saturating_add(t as u64));
            (NirOp::CondBranch { target }, Vec::new())
        }
        0x1B => (NirOp::CondBranch { target: None }, Vec::new()),
        0x2C => (NirOp::Const, vec![string_operand(line, abc)]),
        0x24 | 0x25 | 0x2D | 0x2E | 0x2F | 0x20 | 0x21 | 0x26 | 0x27 | 0x28 => {
            (NirOp::Const, const_operand(line, abc))
        }
        0xD0..=0xD3 | 0x62 | 0x60 | 0x5D | 0x5E | 0x64 | 0x65 | 0x66 | 0x6C => {
            (NirOp::Load, access_operand(line, abc))
        }
        0xD4..=0xD7 | 0x63 | 0x61 | 0x68 | 0x6D => (NirOp::Store, access_operand(line, abc)),
        0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x49 | 0x4A | 0x4C | 0x4E | 0x4F | 0x40 => {
            classify_call(line, abc, imports)
        }
        _ => (NirOp::Nop, Vec::new()),
    }
}

fn classify_call(
    line: &DisasmLine,
    abc: &AbcFile,
    imports: &mut ImportTable,
) -> (NirOp, Vec<String>) {
    let symbol: String = match line.opcode {
        0x46 | 0x4F | 0x4C | 0x4A | 0x45 | 0x4E => multiname_operand(line, abc),
        0x40 => method_index_name(line, abc, "function"),
        0x43 => method_index_name(line, abc, "method"),
        0x44 => method_index_name(line, abc, "static"),
        _ => abc::opcode_mnemonic(line.opcode).to_owned(),
    };
    if symbol.is_empty() {
        return (NirOp::IndirectCall, Vec::new());
    }
    let address: u64 = imports.address_of(&symbol);
    (
        NirOp::Call {
            target: Some(address),
        },
        vec![symbol],
    )
}

fn branch_target(line: &DisasmLine, end_offset: usize) -> Option<usize> {
    let rel: i64 = *line.operands.first()?;
    let absolute: i64 = i64::try_from(end_offset).ok()? + rel;
    usize::try_from(absolute).ok()
}

fn string_operand(line: &DisasmLine, abc: &AbcFile) -> String {
    let Some(idx) = line
        .operands
        .first()
        .and_then(|v: &i64| u32::try_from(*v).ok())
    else {
        return String::new();
    };
    abc.cpool
        .string_at(idx)
        .map_or("", |value: &str| value)
        .to_owned()
}

fn const_operand(line: &DisasmLine, abc: &AbcFile) -> Vec<String> {
    match line.opcode {
        0x24 | 0x25 => line
            .operands
            .first()
            .map_or_else(Vec::new, |v: &i64| vec![v.to_string()]),
        0x2D => pool_value(line, abc, PoolKind::Int),
        0x2E => pool_value(line, abc, PoolKind::Uint),
        0x2F => pool_value(line, abc, PoolKind::Double),
        0x20 => vec!["null".to_owned()],
        0x21 => vec!["undefined".to_owned()],
        0x26 => vec!["true".to_owned()],
        0x27 => vec!["false".to_owned()],
        0x28 => vec!["NaN".to_owned()],
        _ => Vec::new(),
    }
}

enum PoolKind {
    Int,
    Uint,
    Double,
}

fn pool_value(line: &DisasmLine, abc: &AbcFile, kind: PoolKind) -> Vec<String> {
    let Some(idx) = line
        .operands
        .first()
        .and_then(|v: &i64| usize::try_from(*v).ok())
    else {
        return Vec::new();
    };
    let value: Option<String> = match kind {
        PoolKind::Int => abc.cpool.integers.get(idx).map(i32::to_string),
        PoolKind::Uint => abc.cpool.uintegers.get(idx).map(u32::to_string),
        PoolKind::Double => abc.cpool.doubles.get(idx).map(f64::to_string),
    };
    value.map_or_else(Vec::new, |v: String| vec![v])
}

fn access_operand(line: &DisasmLine, abc: &AbcFile) -> Vec<String> {
    match line.opcode {
        0xD0..=0xD3 => vec![format!("local{}", line.opcode - 0xD0)],
        0xD4..=0xD7 => vec![format!("local{}", line.opcode - 0xD4)],
        0x62 | 0x63 => line
            .operands
            .first()
            .map_or_else(Vec::new, |v: &i64| vec![format!("local{v}")]),
        0x6C | 0x6D => line
            .operands
            .first()
            .map_or_else(Vec::new, |v: &i64| vec![format!("slot{v}")]),
        0x64 => vec!["globalscope".to_owned()],
        0x65 => line
            .operands
            .first()
            .map_or_else(Vec::new, |v: &i64| vec![format!("scope{v}")]),
        _ => {
            let name: String = multiname_operand(line, abc);
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
    }
}

fn multiname_operand(line: &DisasmLine, abc: &AbcFile) -> String {
    let Some(idx) = line
        .operands
        .first()
        .and_then(|v: &i64| u32::try_from(*v).ok())
    else {
        return String::new();
    };
    abc.cpool
        .render_multiname_property(idx)
        .unwrap_or_else(|_| String::with_capacity(0))
}

fn method_index_name(line: &DisasmLine, abc: &AbcFile, prefix: &str) -> String {
    let Some(idx) = line
        .operands
        .first()
        .and_then(|v: &i64| u32::try_from(*v).ok())
    else {
        return format!("{prefix}#?");
    };
    if let Some(info) = abc.methods.get(idx as usize) {
        let info: &MethodInfo = info;
        if info.name_index != 0
            && let Ok(name) = abc.cpool.string_at(info.name_index)
            && !name.is_empty()
        {
            return name.to_owned();
        }
    }
    format!("{prefix}#{idx}")
}

const fn binary_op(opcode: u8) -> Option<BinaryOp> {
    Some(match opcode {
        0xA0 | 0xC5 => BinaryOp::Add,
        0xA1 | 0xC6 => BinaryOp::Sub,
        0xA2 | 0xC7 => BinaryOp::Mul,
        0xA3 => BinaryOp::Div,
        0xA4 => BinaryOp::Rem,
        0xA8 => BinaryOp::And,
        0xA9 => BinaryOp::Or,
        0xAA => BinaryOp::Xor,
        0xA5 => BinaryOp::Shl,
        0xA6 | 0xA7 => BinaryOp::Shr,
        0x90 | 0xC4 => BinaryOp::Neg,
        0x96 | 0x97 => BinaryOp::Not,
        _ => return None,
    })
}

const fn memory_facets(opcode: u8) -> (bool, bool) {
    let reads: bool = matches!(
        opcode,
        0x35 | 0x36 | 0x37 | 0x38 | 0x39 | 0x60 | 0x66 | 0x6C
    );
    let writes: bool = matches!(opcode, 0x3A | 0x3B | 0x3C | 0x3D | 0x3E | 0x61 | 0x6D);
    (reads, writes)
}
