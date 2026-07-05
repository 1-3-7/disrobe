use serde::{Deserialize, Serialize};

use crate::bytecode::{self, CodeAttribute, Instruction};
use crate::classfile::{ClassFile, MethodInfo};
use crate::decompile_struct::{
    BasicBlock, Cfg, Dominators, NaturalLoop, Region, Structurer, SwitchKey, build_cfg,
    compute_dominators, find_natural_loops,
};
use crate::sccp::{SccpReport, simplify_flattened_cfg};

const MIN_DISPATCH_PREDS: usize = 2;
const MAX_METHOD_INSNS: usize = 200_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CffReport {
    pub methods_scanned: u32,
    pub flattened_methods: u32,
    pub methods_fully_structured: u32,
    pub dispatchers_unflattened: u32,
    pub edges_redirected: u32,
    pub dead_branches_folded: u32,
    pub dispatcher_blocks_bypassed: u32,
    pub residual_switch_regions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodCff {
    pub flattened: bool,
    pub fully_structured: bool,
    pub report: SccpReport,
    pub residual_switch_regions: u32,
}

#[must_use]
pub fn unflatten_class(cf: &ClassFile) -> CffReport {
    let mut out: CffReport = CffReport::default();
    for method in &cf.methods {
        let Some(code): Option<CodeAttribute> = method_code(cf, method) else {
            continue;
        };
        out.methods_scanned += 1;
        let Some(result): Option<MethodCff> = unflatten_method(cf, &code) else {
            continue;
        };
        if !result.flattened {
            continue;
        }
        out.flattened_methods += 1;
        out.dispatchers_unflattened +=
            u32::try_from(result.report.dispatchers_unflattened).unwrap_or(u32::MAX);
        out.edges_redirected += u32::try_from(result.report.edges_redirected).unwrap_or(u32::MAX);
        out.dead_branches_folded +=
            u32::try_from(result.report.dead_branches_folded).unwrap_or(u32::MAX);
        out.dispatcher_blocks_bypassed +=
            u32::try_from(result.report.dispatcher_blocks_bypassed).unwrap_or(u32::MAX);
        out.residual_switch_regions += result.residual_switch_regions;
        if result.fully_structured {
            out.methods_fully_structured += 1;
        }
    }
    out
}

#[must_use]
pub fn unflatten_method(cf: &ClassFile, code: &CodeAttribute) -> Option<MethodCff> {
    let insns: Vec<Instruction> = bytecode::disassemble(&code.code).ok()?;
    if insns.is_empty() || insns.len() > MAX_METHOD_INSNS {
        return None;
    }
    let mut cfg: Cfg = build_cfg(&insns, code, |idx: u16| {
        bytecode::class_internal_name_at(cf, idx)
    })
    .ok()?;
    let flattened: bool = has_state_dispatcher(&cfg, &insns);
    let report: SccpReport = simplify_flattened_cfg(&mut cfg, &insns);
    let (fully_structured, residual_switch_regions): (bool, u32) = verify_structured(&cfg, &insns);
    Some(MethodCff {
        flattened,
        fully_structured,
        report,
        residual_switch_regions,
    })
}

fn verify_structured(cfg: &Cfg, insns: &[Instruction]) -> (bool, u32) {
    let dom: Dominators = compute_dominators(cfg);
    let loops: Vec<NaturalLoop> = find_natural_loops(cfg, &dom);
    let mut structurer: Structurer<'_> = Structurer::new(cfg, &dom, &loops, insns);
    let region: Region = structurer.structure();
    let residual: u32 = u32::try_from(count_switch_regions(&region)).unwrap_or(u32::MAX);
    let fully_structured: bool = !structurer.had_irreducible && residual == 0;
    (fully_structured, residual)
}

fn count_switch_regions(region: &Region) -> usize {
    match region {
        Region::Switch { cases, default, .. } => {
            1 + cases
                .iter()
                .map(|(_, r): &(SwitchKey, Region)| count_switch_regions(r))
                .sum::<usize>()
                + default
                    .as_deref()
                    .map_or(0, |d: &Region| count_switch_regions(d))
        }
        Region::Sequence(items) => items.iter().map(count_switch_regions).sum(),
        Region::IfThen { then_body, .. } => count_switch_regions(then_body),
        Region::IfThenElse {
            then_body,
            else_body,
            ..
        } => count_switch_regions(then_body) + count_switch_regions(else_body),
        Region::While { body, .. } | Region::DoWhile { body, .. } => count_switch_regions(body),
        Region::Try { try_body, handlers }
        | Region::TryFinally {
            try_body, handlers, ..
        } => {
            count_switch_regions(try_body)
                + handlers
                    .iter()
                    .map(|(_, r): &(Option<String>, Region)| count_switch_regions(r))
                    .sum::<usize>()
        }
        Region::TryWithResources { try_body, .. } => count_switch_regions(try_body),
        Region::Synchronized { body, .. } => count_switch_regions(body),
        Region::LabeledLoop { body, .. } => count_switch_regions(body),
        Region::Block(_)
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Irreducible { .. } => 0,
    }
}

fn has_state_dispatcher(cfg: &Cfg, insns: &[Instruction]) -> bool {
    cfg.blocks.iter().any(|block: &BasicBlock| {
        if block.predecessors.len() < MIN_DISPATCH_PREDS {
            return false;
        }
        let (_, end_idx): (usize, usize) = block.insn_range;
        let Some(last): Option<&Instruction> = end_idx.checked_sub(1).and_then(|i| insns.get(i))
        else {
            return false;
        };
        if !matches!(last.opcode, 0xAA | 0xAB) {
            return false;
        }
        end_idx
            .checked_sub(2)
            .and_then(|i| insns.get(i))
            .is_some_and(|load: &Instruction| matches!(load.opcode, 0x15 | 0x1A..=0x1D))
    })
}

fn method_code(cf: &ClassFile, method: &MethodInfo) -> Option<CodeAttribute> {
    for attr in &method.attributes {
        let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
            continue;
        };
        if name == "Code"
            && let Ok(code) = bytecode::parse_code_attribute(&attr.info)
        {
            return Some(code);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
