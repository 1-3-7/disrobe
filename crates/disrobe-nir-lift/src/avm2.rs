use std::collections::{BTreeMap, BTreeSet};

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

    let entries: Vec<MethodEntry> = enumerate_methods(abcs)?;
    if entries.is_empty() {
        return Err(LiftError::Empty);
    }

    let mut imports: ImportTable = ImportTable::new();

    for (index, entry) in entries.iter().enumerate() {
        let method_index: u32 = usize_to_u32_saturating(index);
        register_method_symbol(entry, method_index, &mut module);
        let abc: &AbcFile = &abcs[entry.abc_index];
        let body: &MethodBody = &abc.method_bodies[entry.body_pos];
        let function: NirFunction = lift_body(entry, method_index, abc, body, &mut imports)?;
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

fn enumerate_methods(abcs: &[AbcFile]) -> Result<Vec<MethodEntry>> {
    let mut entries: Vec<MethodEntry> = Vec::new();
    for (abc_index, abc) in abcs.iter().enumerate() {
        let names: BTreeMap<u32, String> = method_names(abc);
        let exported: BTreeMap<u32, bool> = exported_methods(abc);
        for (body_pos, body) in abc.method_bodies.iter().enumerate() {
            let owner: usize = usize::try_from(body.method).map_err(|_| {
                LiftError::Source(format!(
                    "avm2 abc {abc_index} method body {body_pos} owner {} is out of range",
                    body.method
                ))
            })?;
            if owner >= abc.methods.len() {
                return Err(LiftError::Source(format!(
                    "avm2 abc {abc_index} method body {body_pos} owner {} is out of range",
                    body.method
                )));
            }
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
    Ok(entries)
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
) -> Result<NirFunction> {
    let base: u64 = function_address(method_index);
    let lines: Vec<DisasmLine> =
        abc::disasm(&body.code).map_err(|error: disrobe_pass_as3::Error| {
            LiftError::Source(format!(
                "avm2 abc {} method {} disassembly: {error}",
                entry.abc_index, entry.name
            ))
        })?;
    let unknown_opcode: Result<()> = lines
        .iter()
        .find(|line: &&DisasmLine| line.mnemonic == "<unknown>")
        .map_or(Ok(()), |line: &DisasmLine| {
            Err(LiftError::Source(format!(
                "avm2 abc {} method {} unknown opcode 0x{:02x} at byte {}",
                entry.abc_index, entry.name, line.opcode, line.offset
            )))
        });
    unknown_opcode?;
    let sizes: Vec<usize> = instruction_sizes(&lines, body.code.len());
    validate_body_semantics(entry, abc, body, &lines, &sizes)?;

    let mut instructions: Vec<NirInstr> = Vec::with_capacity(lines.len());
    for (ordinal, line) in lines.iter().enumerate() {
        let address: u64 = base.saturating_add(line.offset as u64);
        let end_offset: usize = line.offset.saturating_add(sizes[ordinal]);
        let (op, operand_list): (NirOp, Vec<String>) =
            classify(entry, line, base, end_offset, abc, imports)?;
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
    Ok(NirFunction {
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
    })
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

fn body_semantic_error(entry: &MethodEntry, line: &DisasmLine, reason: &str) -> LiftError {
    LiftError::Source(format!(
        "avm2 abc {} method {} {} at byte {}",
        entry.abc_index, entry.name, reason, line.offset
    ))
}

fn required_operand(
    entry: &MethodEntry,
    line: &DisasmLine,
    position: usize,
    label: &str,
) -> Result<u32> {
    let Some(value): Option<&i64> = line.operands.get(position) else {
        return Err(body_semantic_error(
            entry,
            line,
            &format!("missing {label}"),
        ));
    };
    u32::try_from(*value).map_err(|_| body_semantic_error(entry, line, &format!("invalid {label}")))
}

fn require_zero_based_index(
    entry: &MethodEntry,
    line: &DisasmLine,
    position: usize,
    pool_len: usize,
    label: &str,
) -> Result<u32> {
    let index: u32 = required_operand(entry, line, position, label)?;
    let index_usize: usize = usize::try_from(index)
        .map_err(|_| body_semantic_error(entry, line, &format!("invalid {label}")))?;
    if index_usize >= pool_len {
        return Err(body_semantic_error(
            entry,
            line,
            &format!("{label} is out of range"),
        ));
    }
    Ok(index)
}

fn require_local_index(
    entry: &MethodEntry,
    line: &DisasmLine,
    position: usize,
    local_count: u32,
) -> Result<u32> {
    let index: u32 = required_operand(entry, line, position, "local register index")?;
    if index >= local_count {
        return Err(body_semantic_error(
            entry,
            line,
            "local register index is out of range",
        ));
    }
    Ok(index)
}

fn checked_relative_target(origin: usize, relative: i64) -> Option<usize> {
    let origin: i64 = i64::try_from(origin).ok()?;
    let target: i64 = origin.checked_add(relative)?;
    usize::try_from(target).ok()
}

fn require_target(
    entry: &MethodEntry,
    line: &DisasmLine,
    origin: usize,
    relative: i64,
    boundaries: &BTreeSet<usize>,
) -> Result<()> {
    let Some(target): Option<usize> = checked_relative_target(origin, relative) else {
        return Err(body_semantic_error(
            entry,
            line,
            "control-flow target is out of range",
        ));
    };
    if !boundaries.contains(&target) {
        return Err(body_semantic_error(
            entry,
            line,
            "control-flow target is not an instruction boundary",
        ));
    }
    Ok(())
}

fn validate_body_semantics(
    entry: &MethodEntry,
    abc: &AbcFile,
    body: &MethodBody,
    lines: &[DisasmLine],
    sizes: &[usize],
) -> Result<()> {
    let boundaries: BTreeSet<usize> = lines.iter().map(|line: &DisasmLine| line.offset).collect();
    for (ordinal, line) in lines.iter().enumerate() {
        let end_offset: usize = line.offset.saturating_add(sizes[ordinal]);
        match line.opcode {
            0x0C..=0x1A => {
                let Some(relative): Option<i64> = line.operands.first().copied() else {
                    return Err(body_semantic_error(entry, line, "missing branch target"));
                };
                require_target(entry, line, end_offset, relative, &boundaries)?;
            }
            0x1B => {
                let Some(default_relative): Option<i64> = line.operands.first().copied() else {
                    return Err(body_semantic_error(
                        entry,
                        line,
                        "missing switch default target",
                    ));
                };
                require_target(entry, line, line.offset, default_relative, &boundaries)?;
                for relative in line.operands.iter().skip(2) {
                    require_target(entry, line, line.offset, *relative, &boundaries)?;
                }
            }
            0x06 | 0x2C | 0xF1 => {
                let index: u32 = required_operand(entry, line, 0, "string index")?;
                abc.cpool.string_at(index).map_err(|error| {
                    body_semantic_error(entry, line, &format!("invalid string index: {error}"))
                })?;
            }
            0xEF => {
                let index: u32 = required_operand(entry, line, 1, "debug string index")?;
                abc.cpool.string_at(index).map_err(|error| {
                    body_semantic_error(
                        entry,
                        line,
                        &format!("invalid debug string index: {error}"),
                    )
                })?;
                let debug_register: u32 =
                    required_operand(entry, line, 2, "debug local register index")?;
                if debug_register >= body.local_count {
                    return Err(body_semantic_error(
                        entry,
                        line,
                        "debug local register index is out of range",
                    ));
                }
            }
            0x08 | 0x62 | 0x63 | 0x92 | 0x94 | 0xC2 | 0xC3 => {
                let _: u32 = require_local_index(entry, line, 0, body.local_count)?;
            }
            0x32 => {
                let _: u32 = require_local_index(entry, line, 0, body.local_count)?;
                let _: u32 = require_local_index(entry, line, 1, body.local_count)?;
            }
            0xD0..=0xD3 => {
                let index: u32 = u32::from(line.opcode - 0xD0);
                if index >= body.local_count {
                    return Err(body_semantic_error(
                        entry,
                        line,
                        "implicit local register index is out of range",
                    ));
                }
            }
            0xD4..=0xD7 => {
                let index: u32 = u32::from(line.opcode - 0xD4);
                if index >= body.local_count {
                    return Err(body_semantic_error(
                        entry,
                        line,
                        "implicit local register index is out of range",
                    ));
                }
            }
            0x2D => {
                let _: u32 = require_zero_based_index(
                    entry,
                    line,
                    0,
                    abc.cpool.integers.len(),
                    "integer index",
                )?;
            }
            0x2E => {
                let _: u32 = require_zero_based_index(
                    entry,
                    line,
                    0,
                    abc.cpool.uintegers.len(),
                    "unsigned integer index",
                )?;
            }
            0x2F => {
                let _: u32 = require_zero_based_index(
                    entry,
                    line,
                    0,
                    abc.cpool.doubles.len(),
                    "double index",
                )?;
            }
            0x31 => {
                let _: u32 = require_zero_based_index(
                    entry,
                    line,
                    0,
                    abc.cpool.namespaces.len(),
                    "namespace index",
                )?;
            }
            0x40 | 0x44 => {
                let _: u32 =
                    require_zero_based_index(entry, line, 0, abc.methods.len(), "method index")?;
            }
            0x58 => {
                let _: u32 =
                    require_zero_based_index(entry, line, 0, abc.classes.len(), "class index")?;
            }
            0x5A => {
                let _: u32 = require_zero_based_index(
                    entry,
                    line,
                    0,
                    body.exceptions.len(),
                    "exception index",
                )?;
            }
            0x04
            | 0x05
            | 0x45
            | 0x46
            | 0x4A
            | 0x4C
            | 0x4E
            | 0x4F
            | 0x59
            | 0x5D..=0x61
            | 0x66
            | 0x68
            | 0x6A
            | 0x80
            | 0x86
            | 0xB2 => {
                let index: u32 = required_operand(entry, line, 0, "multiname index")?;
                let _: String = abc.cpool.render_multiname(index).map_err(|error| {
                    body_semantic_error(entry, line, &format!("invalid multiname index: {error}"))
                })?;
            }
            _ => {}
        }
    }
    for exception in &body.exceptions {
        let from: usize = usize::try_from(exception.from).map_err(|_| {
            LiftError::Source(format!(
                "avm2 abc {} method {} exception start is out of range",
                entry.abc_index, entry.name
            ))
        })?;
        let to: usize = usize::try_from(exception.to).map_err(|_| {
            LiftError::Source(format!(
                "avm2 abc {} method {} exception end is out of range",
                entry.abc_index, entry.name
            ))
        })?;
        let target: usize = usize::try_from(exception.target).map_err(|_| {
            LiftError::Source(format!(
                "avm2 abc {} method {} exception target is out of range",
                entry.abc_index, entry.name
            ))
        })?;
        let valid_end: bool = to == body.code.len() || boundaries.contains(&to);
        if from >= to || !boundaries.contains(&from) || !valid_end || !boundaries.contains(&target)
        {
            return Err(LiftError::Source(format!(
                "avm2 abc {} method {} exception range is invalid",
                entry.abc_index, entry.name
            )));
        }
        let _: String = abc
            .cpool
            .render_multiname(exception.exc_type)
            .map_err(|error| {
                LiftError::Source(format!(
                    "avm2 abc {} method {} exception type is invalid: {error}",
                    entry.abc_index, entry.name
                ))
            })?;
        let _: String = abc
            .cpool
            .render_multiname(exception.var_name)
            .map_err(|error| {
                LiftError::Source(format!(
                    "avm2 abc {} method {} exception name is invalid: {error}",
                    entry.abc_index, entry.name
                ))
            })?;
    }
    Ok(())
}

fn classify(
    entry: &MethodEntry,
    line: &DisasmLine,
    base: u64,
    end_offset: usize,
    abc: &AbcFile,
    imports: &mut ImportTable,
) -> Result<(NirOp, Vec<String>)> {
    if let Some(binary_op) = binary_op(line.opcode) {
        return Ok((NirOp::BinOp { op: binary_op }, Vec::new()));
    }
    let classified: (NirOp, Vec<String>) = match line.opcode {
        0x47 | 0x48 => (NirOp::Return, Vec::new()),
        0x03 => (NirOp::Interrupt, Vec::new()),
        0x10 => {
            let target_offset: usize = branch_target(entry, line, end_offset)?;
            let target: Option<u64> = Some(base.saturating_add(target_offset as u64));
            (NirOp::Branch { target }, Vec::new())
        }
        0x0C..=0x0F | 0x11..=0x1A => {
            let target_offset: usize = branch_target(entry, line, end_offset)?;
            let target: Option<u64> = Some(base.saturating_add(target_offset as u64));
            (NirOp::CondBranch { target }, Vec::new())
        }
        0x1B => (NirOp::CondBranch { target: None }, Vec::new()),
        0x2C => (NirOp::Const, vec![string_operand(entry, line, abc)?]),
        0x24 | 0x25 | 0x2D | 0x2E | 0x2F | 0x20 | 0x21 | 0x26 | 0x27 | 0x28 => {
            (NirOp::Const, const_operand(entry, line, abc)?)
        }
        0xD0..=0xD3 | 0x62 | 0x60 | 0x5D | 0x5E | 0x64 | 0x65 | 0x66 | 0x6C => {
            (NirOp::Load, access_operand(entry, line, abc)?)
        }
        0xD4..=0xD7 | 0x63 | 0x61 | 0x68 | 0x6D => {
            (NirOp::Store, access_operand(entry, line, abc)?)
        }
        0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x49 | 0x4A | 0x4C | 0x4E | 0x4F | 0x40 => {
            classify_call(entry, line, abc, imports)?
        }
        opcode if is_effect_free(opcode) => (NirOp::Nop, Vec::new()),
        opcode => (
            NirOp::Unmodeled {
                opcode,
                offset: usize_to_u32_saturating(line.offset),
            },
            Vec::new(),
        ),
    };
    Ok(classified)
}

const EFFECT_FREE_OPCODES: [u8; 7] = [0x02, 0x09, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3];

const fn is_effect_free(opcode: u8) -> bool {
    let mut index: usize = 0;
    while index < EFFECT_FREE_OPCODES.len() {
        if EFFECT_FREE_OPCODES[index] == opcode {
            return true;
        }
        index = index.saturating_add(1);
    }
    false
}

fn classify_call(
    entry: &MethodEntry,
    line: &DisasmLine,
    abc: &AbcFile,
    imports: &mut ImportTable,
) -> Result<(NirOp, Vec<String>)> {
    let symbol: String = match line.opcode {
        0x46 | 0x4F | 0x4C | 0x4A | 0x45 | 0x4E => multiname_operand(entry, line, abc)?,
        0x40 => method_index_name(entry, line, abc, "function")?,
        0x43 => {
            let dispatch_id: u32 = required_operand(entry, line, 0, "dispatch id")?;
            format!("method#{dispatch_id}")
        }
        0x44 => method_index_name(entry, line, abc, "static")?,
        _ => abc::opcode_mnemonic(line.opcode).to_owned(),
    };
    if symbol.is_empty() {
        return Ok((NirOp::IndirectCall, Vec::new()));
    }
    let address: u64 = imports.address_of(&symbol);
    Ok((
        NirOp::Call {
            target: Some(address),
        },
        vec![symbol],
    ))
}

fn branch_target(entry: &MethodEntry, line: &DisasmLine, end_offset: usize) -> Result<usize> {
    let Some(relative): Option<i64> = line.operands.first().copied() else {
        return Err(body_semantic_error(entry, line, "missing branch target"));
    };
    checked_relative_target(end_offset, relative)
        .ok_or_else(|| body_semantic_error(entry, line, "branch target is out of range"))
}

fn string_operand(entry: &MethodEntry, line: &DisasmLine, abc: &AbcFile) -> Result<String> {
    let index: u32 = required_operand(entry, line, 0, "string index")?;
    abc.cpool
        .string_at(index)
        .map(str::to_owned)
        .map_err(|error| {
            body_semantic_error(entry, line, &format!("invalid string index: {error}"))
        })
}

fn const_operand(entry: &MethodEntry, line: &DisasmLine, abc: &AbcFile) -> Result<Vec<String>> {
    let operands: Vec<String> = match line.opcode {
        0x24 | 0x25 => line
            .operands
            .first()
            .map_or_else(Vec::new, |v: &i64| vec![v.to_string()]),
        0x2D => pool_value(entry, line, abc, PoolKind::Int)?,
        0x2E => pool_value(entry, line, abc, PoolKind::Uint)?,
        0x2F => pool_value(entry, line, abc, PoolKind::Double)?,
        0x20 => vec!["null".to_owned()],
        0x21 => vec!["undefined".to_owned()],
        0x26 => vec!["true".to_owned()],
        0x27 => vec!["false".to_owned()],
        0x28 => vec!["NaN".to_owned()],
        _ => Vec::new(),
    };
    Ok(operands)
}

enum PoolKind {
    Int,
    Uint,
    Double,
}

fn pool_value(
    entry: &MethodEntry,
    line: &DisasmLine,
    abc: &AbcFile,
    kind: PoolKind,
) -> Result<Vec<String>> {
    let raw_index: u32 = required_operand(entry, line, 0, "constant pool index")?;
    let index: usize = usize::try_from(raw_index)
        .map_err(|_| body_semantic_error(entry, line, "constant pool index is out of range"))?;
    let value: Option<String> = match kind {
        PoolKind::Int => abc.cpool.integers.get(index).map(i32::to_string),
        PoolKind::Uint => abc.cpool.uintegers.get(index).map(u32::to_string),
        PoolKind::Double => abc.cpool.doubles.get(index).map(f64::to_string),
    };
    value
        .map(|value: String| vec![value])
        .ok_or_else(|| body_semantic_error(entry, line, "constant pool index is out of range"))
}

fn access_operand(entry: &MethodEntry, line: &DisasmLine, abc: &AbcFile) -> Result<Vec<String>> {
    let operands: Vec<String> = match line.opcode {
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
            let name: String = multiname_operand(entry, line, abc)?;
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
    };
    Ok(operands)
}

fn multiname_operand(entry: &MethodEntry, line: &DisasmLine, abc: &AbcFile) -> Result<String> {
    let index: u32 = required_operand(entry, line, 0, "multiname index")?;
    abc.cpool.render_multiname_property(index).map_err(|error| {
        body_semantic_error(entry, line, &format!("invalid multiname index: {error}"))
    })
}

fn method_index_name(
    entry: &MethodEntry,
    line: &DisasmLine,
    abc: &AbcFile,
    prefix: &str,
) -> Result<String> {
    let index: u32 = required_operand(entry, line, 0, "method index")?;
    let index_usize: usize = usize::try_from(index)
        .map_err(|_| body_semantic_error(entry, line, "method index is out of range"))?;
    let Some(info): Option<&MethodInfo> = abc.methods.get(index_usize) else {
        return Err(body_semantic_error(
            entry,
            line,
            "method index is out of range",
        ));
    };
    if info.name_index != 0 {
        let name: &str = abc.cpool.string_at(info.name_index).map_err(|error| {
            body_semantic_error(entry, line, &format!("invalid method name index: {error}"))
        })?;
        if !name.is_empty() {
            return Ok(name.to_owned());
        }
    }
    Ok(format!("{prefix}#{index}"))
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
