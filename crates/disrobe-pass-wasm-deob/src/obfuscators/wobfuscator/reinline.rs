use std::collections::BTreeMap;

use walrus::ir::{BinaryOp, Binop, Instr, VisitorMut};
use walrus::{FunctionId, ImportKind, Module, ModuleConfig};

use crate::error::{Error, Result};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReinlineStats {
    pub ops_reinlined: usize,
    pub imports_dropped: usize,
}

pub fn reinline_imported_ops(wasm: &[u8]) -> Result<(Vec<u8>, ReinlineStats)> {
    let mut module: Module = Module::from_buffer_with_config(wasm, &lenient_config())
        .map_err(|e| Error::Parse(format!("walrus parse: {e}")))?;
    let op_map: BTreeMap<FunctionId, BinaryOp> = collect_op_imports(&module);
    if op_map.is_empty() {
        return Ok((module.emit_wasm(), ReinlineStats::default()));
    }

    let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    let mut rewriter: CallRewriter<'_> = CallRewriter {
        op_map: &op_map,
        rewrites: 0,
    };
    for id in local_ids {
        let walrus::FunctionKind::Local(local): &mut walrus::FunctionKind =
            &mut module.funcs.get_mut(id).kind
        else {
            continue;
        };
        let entry: walrus::ir::InstrSeqId = local.entry_block();
        walrus::ir::dfs_pre_order_mut(&mut rewriter, local, entry);
    }
    let ops_reinlined: usize = rewriter.rewrites;

    let mut imports_dropped: usize = 0;
    for fid in op_map.keys() {
        if function_is_uncalled(&module, *fid)
            && let Some(import_id) = import_id_for_func(&module, *fid)
        {
            module.imports.delete(import_id);
            module.funcs.delete(*fid);
            imports_dropped += 1;
        }
    }

    Ok((
        module.emit_wasm(),
        ReinlineStats {
            ops_reinlined,
            imports_dropped,
        },
    ))
}

fn lenient_config() -> ModuleConfig {
    let mut cfg: ModuleConfig = ModuleConfig::new();
    cfg.generate_producers_section(false);
    cfg
}

fn collect_op_imports(module: &Module) -> BTreeMap<FunctionId, BinaryOp> {
    let mut out: BTreeMap<FunctionId, BinaryOp> = BTreeMap::new();
    for import in module.imports.iter() {
        let ImportKind::Function(fid): ImportKind = import.kind else {
            continue;
        };
        let Some(op): Option<BinaryOp> = op_for_import_name(&import.name) else {
            continue;
        };
        if function_signature_is_i32_binary(module, fid) {
            out.insert(fid, op);
        }
    }
    out
}

fn function_signature_is_i32_binary(module: &Module, fid: FunctionId) -> bool {
    let ty_id: walrus::TypeId = module.funcs.get(fid).ty();
    let ty: &walrus::Type = module.types.get(ty_id);
    ty.params() == [walrus::ValType::I32, walrus::ValType::I32]
        && ty.results() == [walrus::ValType::I32]
}

fn op_for_import_name(name: &str) -> Option<BinaryOp> {
    Some(match name {
        "op_add" => BinaryOp::I32Add,
        "op_sub" => BinaryOp::I32Sub,
        "op_mul" => BinaryOp::I32Mul,
        "op_and" => BinaryOp::I32And,
        "op_or" => BinaryOp::I32Or,
        "op_xor" => BinaryOp::I32Xor,
        "op_shl" => BinaryOp::I32Shl,
        "op_shr_u" => BinaryOp::I32ShrU,
        "op_shr_s" => BinaryOp::I32ShrS,
        _ => return None,
    })
}

struct CallRewriter<'a> {
    op_map: &'a BTreeMap<FunctionId, BinaryOp>,
    rewrites: usize,
}

impl VisitorMut for CallRewriter<'_> {
    fn start_instr_seq_mut(&mut self, seq: &mut walrus::ir::InstrSeq) {
        for (instr, _loc) in &mut seq.instrs {
            let Instr::Call(call): &Instr = instr else {
                continue;
            };
            let Some(op): Option<&BinaryOp> = self.op_map.get(&call.func) else {
                continue;
            };
            *instr = Instr::Binop(Binop { op: *op });
            self.rewrites += 1;
        }
    }
}

fn function_is_uncalled(module: &Module, target: FunctionId) -> bool {
    let mut counter: CallCounter = CallCounter { target, count: 0 };
    for (_id, func) in module.funcs.iter_local() {
        walrus::ir::dfs_in_order(&mut counter, func, func.entry_block());
    }
    counter.count == 0
}

struct CallCounter {
    target: FunctionId,
    count: usize,
}

impl walrus::ir::Visitor<'_> for CallCounter {
    fn visit_call(&mut self, instr: &walrus::ir::Call) {
        if instr.func == self.target {
            self.count += 1;
        }
    }
}

fn import_id_for_func(module: &Module, fid: FunctionId) -> Option<walrus::ImportId> {
    module.imports.iter().find_map(|import| {
        if matches!(import.kind, ImportKind::Function(f) if f == fid) {
            Some(import.id())
        } else {
            None
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn assemble(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("assemble wat")
    }

    #[test]
    fn reinlines_imported_binary_ops_and_drops_dead_imports() {
        let wat: &str = r#"
            (module
              (type $bin (func (param i32 i32) (result i32)))
              (import "env" "op_xor" (func $op_xor (type $bin)))
              (import "env" "op_and" (func $op_and (type $bin)))
              (func $mix (export "mix") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                call $op_xor
                local.get 0
                local.get 1
                call $op_and
                i32.add))
        "#;
        let bytes: Vec<u8> = assemble(wat);
        let (recovered, stats): (Vec<u8>, ReinlineStats) =
            reinline_imported_ops(&bytes).expect("reinline");
        assert_eq!(stats.ops_reinlined, 2, "both op calls reinlined");
        assert_eq!(stats.imports_dropped, 2, "both dead op imports dropped");
        let module: Module = Module::from_buffer(&recovered).expect("recovered round-trips");
        assert_eq!(
            module.imports.iter().count(),
            0,
            "no imports remain after reinline"
        );
        assert!(
            wasmparser::validate(&recovered).is_ok(),
            "recovered module must validate"
        );
    }

    #[test]
    fn leaves_unrelated_imports_alone() {
        let wat: &str = r#"
            (module
              (import "env" "log" (func $log (param i32)))
              (func $f (export "f") (param i32) (result i32)
                local.get 0
                call $log
                local.get 0))
        "#;
        let bytes: Vec<u8> = assemble(wat);
        let (recovered, stats): (Vec<u8>, ReinlineStats) =
            reinline_imported_ops(&bytes).expect("reinline");
        assert_eq!(stats.ops_reinlined, 0);
        assert_eq!(stats.imports_dropped, 0);
        let module: Module = Module::from_buffer(&recovered).expect("round-trips");
        assert_eq!(module.imports.iter().count(), 1, "log import preserved");
    }
}
