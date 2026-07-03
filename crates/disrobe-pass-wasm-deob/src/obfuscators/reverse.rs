use std::collections::BTreeSet;

use serde::Serialize;
use walrus::ir::{BinaryOp, Const, Instr, Value, Visitor, VisitorMut, dfs_in_order};
use walrus::{ExportItem, FunctionId, FunctionKind, Module, ModuleConfig};

use crate::error::{Error, Result};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct DemangleStats {
    pub exports_demangled: usize,
    pub names_attached: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DeadFunctionStats {
    pub before: usize,
    pub after: usize,
    pub removed: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CanonicalizeStats {
    pub identity_ops_folded: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DataDecryptStats {
    pub segments_decrypted: usize,
    pub bytes_decrypted: usize,
}

pub fn decrypt_data_sections(wasm: &[u8], key: u8) -> Result<(Vec<u8>, DataDecryptStats)> {
    let mut module: Module = parse_module(wasm)?;
    let mut stats: DataDecryptStats = DataDecryptStats::default();
    let data_ids: Vec<walrus::DataId> = module.data.iter().map(walrus::Data::id).collect();
    for did in data_ids {
        let data: &mut walrus::Data = module.data.get_mut(did);
        if data.value.is_empty() {
            continue;
        }
        for byte in &mut data.value {
            *byte ^= key;
        }
        stats.segments_decrypted += 1;
        stats.bytes_decrypted += data.value.len();
    }
    Ok((module.emit_wasm(), stats))
}

#[must_use]
pub fn demangle_symbol(mangled: &str) -> Option<String> {
    if let Some(name) = demangle_itanium(mangled) {
        return Some(name);
    }
    if mangled.starts_with("_Z") {
        return None;
    }
    let trimmed: &str = mangled.trim_start_matches('_');
    if trimmed.is_empty() || trimmed == mangled {
        return None;
    }
    if trimmed.bytes().all(is_ident_byte) {
        return Some(trimmed.to_owned());
    }
    None
}

fn demangle_itanium(mangled: &str) -> Option<String> {
    let rest: &str = mangled.strip_prefix("_Z")?;
    let bytes: &[u8] = rest.as_bytes();
    let mut cursor: usize = 0;
    let mut len: usize = 0;
    while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
        len = len
            .checked_mul(10)?
            .checked_add(usize::from(bytes[cursor] - b'0'))?;
        cursor += 1;
    }
    if len == 0 || cursor == 0 {
        return None;
    }
    let end: usize = cursor.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    let ident: &str = rest.get(cursor..end)?;
    if !ident.bytes().all(is_ident_byte) {
        return None;
    }
    Some(ident.to_owned())
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

pub fn demangle_names(wasm: &[u8]) -> Result<(Vec<u8>, DemangleStats)> {
    let mut module: Module = parse_module(wasm)?;
    let mut stats: DemangleStats = DemangleStats::default();

    let renames: Vec<(walrus::ExportId, String)> = module
        .exports
        .iter()
        .filter_map(|export| {
            let demangled: String = demangle_symbol(&export.name)?;
            if demangled == export.name {
                return None;
            }
            Some((export.id(), demangled))
        })
        .collect();

    for (export_id, demangled) in renames {
        let item: ExportItem = {
            let export: &mut walrus::Export = module.exports.get_mut(export_id);
            export.name.clone_from(&demangled);
            export.item
        };
        stats.exports_demangled += 1;
        if let ExportItem::Function(fid) = item {
            let func: &mut walrus::Function = module.funcs.get_mut(fid);
            if func.name.is_none() {
                func.name = Some(demangled);
                stats.names_attached += 1;
            }
        }
    }

    Ok((module.emit_wasm(), stats))
}

pub fn strip_dead_functions(wasm: &[u8]) -> Result<(Vec<u8>, DeadFunctionStats)> {
    let mut module: Module = parse_module(wasm)?;
    let before: usize = module.funcs.iter().count();

    let mut reachable: BTreeSet<FunctionId> = BTreeSet::new();
    let mut worklist: Vec<FunctionId> = Vec::new();

    for export in module.exports.iter() {
        if let ExportItem::Function(fid) = export.item {
            if reachable.insert(fid) {
                worklist.push(fid);
            }
        }
    }
    if let Some(start) = module.start {
        if reachable.insert(start) {
            worklist.push(start);
        }
    }
    for element in module.elements.iter() {
        for fid in element_function_ids(element) {
            if reachable.insert(fid) {
                worklist.push(fid);
            }
        }
    }

    while let Some(fid) = worklist.pop() {
        let callees: Vec<FunctionId> = direct_callees(&module, fid);
        for callee in callees {
            if reachable.insert(callee) {
                worklist.push(callee);
            }
        }
    }

    let removable: Vec<FunctionId> = module
        .funcs
        .iter()
        .filter(|func| matches!(func.kind, FunctionKind::Local(_)))
        .map(walrus::Function::id)
        .filter(|fid| !reachable.contains(fid))
        .collect();

    let removed: usize = removable.len();
    for fid in removable {
        module.funcs.delete(fid);
    }

    let after: usize = module.funcs.iter().count();
    Ok((
        module.emit_wasm(),
        DeadFunctionStats {
            before,
            after,
            removed,
        },
    ))
}

fn element_function_ids(element: &walrus::Element) -> Vec<FunctionId> {
    match &element.items {
        walrus::ElementItems::Functions(ids) => ids.clone(),
        walrus::ElementItems::Expressions(_, exprs) => exprs
            .iter()
            .filter_map(|expr| match expr {
                walrus::ConstExpr::RefFunc(fid) => Some(*fid),
                _ => None,
            })
            .collect(),
    }
}

fn direct_callees(module: &Module, fid: FunctionId) -> Vec<FunctionId> {
    let FunctionKind::Local(local): &FunctionKind = &module.funcs.get(fid).kind else {
        return Vec::new();
    };
    let mut collector: CalleeCollector = CalleeCollector { out: Vec::new() };
    dfs_in_order(&mut collector, local, local.entry_block());
    collector.out
}

struct CalleeCollector {
    out: Vec<FunctionId>,
}

impl Visitor<'_> for CalleeCollector {
    fn visit_call(&mut self, instr: &walrus::ir::Call) {
        self.out.push(instr.func);
    }

    fn visit_ref_func(&mut self, instr: &walrus::ir::RefFunc) {
        self.out.push(instr.func);
    }
}

pub fn canonicalize_substitutions(wasm: &[u8]) -> Result<(Vec<u8>, CanonicalizeStats)> {
    let mut module: Module = parse_module(wasm)?;
    let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    let mut folder: SubstFolder = SubstFolder::default();
    for id in local_ids {
        let FunctionKind::Local(local): &mut FunctionKind = &mut module.funcs.get_mut(id).kind
        else {
            continue;
        };
        let entry: walrus::ir::InstrSeqId = local.entry_block();
        walrus::ir::dfs_pre_order_mut(&mut folder, local, entry);
    }
    Ok((module.emit_wasm(), folder.stats))
}

#[derive(Default)]
struct SubstFolder {
    stats: CanonicalizeStats,
}

impl VisitorMut for SubstFolder {
    fn start_instr_seq_mut(&mut self, seq: &mut walrus::ir::InstrSeq) {
        let mut idx: usize = 0;
        while idx + 1 < seq.instrs.len() {
            if is_identity_pair(&seq.instrs[idx].0, &seq.instrs[idx + 1].0) {
                seq.instrs.remove(idx + 1);
                seq.instrs.remove(idx);
                self.stats.identity_ops_folded += 1;
                idx = idx.saturating_sub(1);
                continue;
            }
            idx += 1;
        }
    }
}

const fn is_identity_pair(first: &Instr, second: &Instr) -> bool {
    let Instr::Const(Const {
        value: Value::I32(k),
    }): &Instr = first
    else {
        return false;
    };
    let Instr::Binop(binop): &Instr = second else {
        return false;
    };
    match *k {
        0 => matches!(
            binop.op,
            BinaryOp::I32Add
                | BinaryOp::I32Sub
                | BinaryOp::I32Or
                | BinaryOp::I32Xor
                | BinaryOp::I32Shl
                | BinaryOp::I32ShrU
                | BinaryOp::I32ShrS
                | BinaryOp::I32Rotl
                | BinaryOp::I32Rotr
        ),
        1 => matches!(binop.op, BinaryOp::I32Mul),
        -1 => matches!(binop.op, BinaryOp::I32And),
        _ => false,
    }
}

fn parse_module(wasm: &[u8]) -> Result<Module> {
    let mut config: ModuleConfig = ModuleConfig::new();
    config.generate_producers_section(false);
    Module::from_buffer_with_config(wasm, &config)
        .map_err(|e| Error::Parse(format!("DR-WASMDEOB-REVERSE: walrus parse: {e}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn itanium_simple_function() {
        assert_eq!(demangle_symbol("_Z3foov").as_deref(), Some("foo"));
        assert_eq!(demangle_symbol("_Z6decodePh").as_deref(), Some("decode"));
    }

    #[test]
    fn underscore_prefix_only() {
        assert_eq!(demangle_symbol("_main").as_deref(), Some("main"));
        assert_eq!(
            demangle_symbol("__wbindgen_init").as_deref(),
            Some("wbindgen_init")
        );
    }

    #[test]
    fn clean_name_returns_none() {
        assert_eq!(demangle_symbol("main"), None);
        assert_eq!(demangle_symbol("run"), None);
    }

    #[test]
    fn malformed_itanium_rejected() {
        assert_eq!(demangle_symbol("_Z0v"), None);
        assert_eq!(demangle_symbol("_Z99x"), None);
    }
}
