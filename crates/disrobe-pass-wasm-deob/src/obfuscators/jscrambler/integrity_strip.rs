use walrus::ir::Visitor;
use walrus::{FunctionId, Module, ModuleConfig, ValType};

use crate::error::{Error, Result};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityStripStats {
    pub imports_removed: usize,
    pub call_sites_rewritten: usize,
}

pub fn strip_integrity_imports(
    wasm: &[u8],
    prefixes: &[&str],
) -> Result<(Vec<u8>, IntegrityStripStats)> {
    let mut module: Module = Module::from_buffer_with_config(wasm, &lenient_config())
        .map_err(|e| Error::Parse(format!("walrus parse: {e}")))?;
    let targets: Vec<FunctionId> = collect_target_funcs(&module, prefixes);
    let call_sites: usize = count_call_sites(&module, &targets);
    let stats: IntegrityStripStats = IntegrityStripStats {
        imports_removed: targets.len(),
        call_sites_rewritten: call_sites,
    };
    for fid in targets {
        let result_tys: Vec<ValType> = {
            let ty_id: walrus::TypeId = module.funcs.get(fid).ty();
            module.types.get(ty_id).results().to_vec()
        };
        module
            .replace_imported_func(fid, move |(body, _args)| {
                for ty in &result_tys {
                    push_zero(body, *ty);
                }
            })
            .map_err(|e| Error::Parse(format!("replace_imported_func: {e}")))?;
    }
    let bytes: Vec<u8> = module.emit_wasm();
    Ok((bytes, stats))
}

fn lenient_config() -> ModuleConfig {
    let mut cfg: ModuleConfig = ModuleConfig::new();
    cfg.generate_producers_section(false);
    cfg
}

fn push_zero(body: &mut walrus::InstrSeqBuilder<'_>, ty: ValType) {
    match ty {
        ValType::I32 => {
            body.i32_const(0);
        }
        ValType::I64 => {
            body.i64_const(0);
        }
        ValType::F32 => {
            body.f32_const(0.0);
        }
        ValType::F64 => {
            body.f64_const(0.0);
        }
        _ => {
            body.unreachable();
        }
    }
}

fn collect_target_funcs(module: &Module, prefixes: &[&str]) -> Vec<FunctionId> {
    let mut out: Vec<FunctionId> = Vec::new();
    for import in module.imports.iter() {
        if !prefixes.iter().any(|p| import.name.starts_with(p)) {
            continue;
        }
        if let walrus::ImportKind::Function(fid) = import.kind {
            out.push(fid);
        }
    }
    out
}

fn count_call_sites(module: &Module, targets: &[FunctionId]) -> usize {
    if targets.is_empty() {
        return 0;
    }
    let mut counter: CallCounter<'_> = CallCounter { targets, count: 0 };
    for (_id, func) in module.funcs.iter_local() {
        walrus::ir::dfs_in_order(&mut counter, func, func.entry_block());
    }
    counter.count
}

struct CallCounter<'a> {
    targets: &'a [FunctionId],
    count: usize,
}

impl<'a> Visitor<'a> for CallCounter<'a> {
    fn visit_call(&mut self, instr: &walrus::ir::Call) {
        if self.targets.contains(&instr.func) {
            self.count += 1;
        }
    }
}
