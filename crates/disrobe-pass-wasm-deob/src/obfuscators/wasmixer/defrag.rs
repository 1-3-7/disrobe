use std::collections::{BTreeMap, BTreeSet};

use walrus::ir::{Const, Instr, Value, Visitor, VisitorMut};
use walrus::{
    ElementId, ElementItems, ElementKind, ExportItem, FunctionId, Module, ModuleConfig, TableId,
};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::types::{AccessPattern, BaseOrigin};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DefragStats {
    pub fragments_inlined: usize,
    pub functions_dropped: usize,
    pub elements_pruned: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeapRegion {
    pub base: BaseOrigin,
    pub alignment: u32,
    pub min_offset: i32,
    pub max_offset: i32,
    pub element_width: u32,
    pub access_count: usize,
    pub strided: bool,
}

impl HeapRegion {
    #[inline]
    #[must_use]
    pub fn byte_span(&self) -> u32 {
        let lo: i64 = i64::from(self.min_offset);
        let hi: i64 = i64::from(self.max_offset) + i64::from(self.element_width);
        u32::try_from(hi.saturating_sub(lo).max(0)).unwrap_or(u32::MAX)
    }
}

#[must_use]
pub fn recover_heap_regions(patterns: &[AccessPattern]) -> Vec<HeapRegion> {
    let mut clusters: BTreeMap<(BaseOrigin, u32), Vec<&AccessPattern>> = BTreeMap::new();
    for pattern in patterns {
        if matches!(pattern.base_origin, BaseOrigin::Unknown) {
            continue;
        }
        clusters
            .entry((pattern.base_origin, pattern.alignment))
            .or_default()
            .push(pattern);
    }

    let mut regions: Vec<HeapRegion> = Vec::with_capacity(clusters.len());
    for ((base, alignment), members) in clusters {
        if members.is_empty() {
            continue;
        }
        let element_width: u32 = modal_width(&members);
        let mut offsets: Vec<i32> = members.iter().map(|p| p.offset_class).collect();
        offsets.sort_unstable();
        let min_offset: i32 = *offsets.first().unwrap_or(&0);
        let max_offset: i32 = *offsets.last().unwrap_or(&0);
        let strided: bool =
            members.iter().any(|p| p.is_indexed) || offsets_are_strided(&offsets, element_width);
        regions.push(HeapRegion {
            base,
            alignment,
            min_offset,
            max_offset,
            element_width,
            access_count: members.len(),
            strided,
        });
    }
    regions
}

fn modal_width(members: &[&AccessPattern]) -> u32 {
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for member in members {
        *counts.entry(member.width.max(1)).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)))
        .map_or(4, |(width, _)| width)
}

fn offsets_are_strided(sorted_offsets: &[i32], stride: u32) -> bool {
    if sorted_offsets.len() < 3 {
        return false;
    }
    let stride_i: i32 = i32::try_from(stride).unwrap_or(i32::MAX);
    if stride_i == 0 {
        return false;
    }
    sorted_offsets
        .windows(2)
        .all(|pair| pair[1].saturating_sub(pair[0]) == stride_i)
}

pub fn defragment(bytes: &[u8]) -> Result<(Vec<u8>, DefragStats)> {
    let mut module: Module = Module::from_buffer_with_config(bytes, &lenient_config())
        .map_err(|e| Error::Parse(format!("walrus parse: {e}")))?;

    let table_maps: TableIndexMaps = build_table_index_maps(&module);
    let usage: ModuleUsage = collect_usage(&module, &table_maps);
    let single_caller_targets: BTreeMap<FunctionId, FunctionId> = usage
        .indirect_call_sites
        .iter()
        .fold(BTreeMap::new(), |mut acc, site| {
            let total: u32 = usage
                .direct_call_counts
                .get(&site.target)
                .copied()
                .unwrap_or(0)
                + usage
                    .indirect_call_counts
                    .get(&site.target)
                    .copied()
                    .unwrap_or(0);
            if total == 1 && !usage.exported.contains(&site.target) {
                acc.insert(site.target, site.target);
            }
            acc
        });

    let fragments_inlined: usize =
        rewrite_indirect_call_sites(&mut module, &table_maps, &single_caller_targets);

    let elements_pruned: usize = prune_dead_elements(&mut module, &single_caller_targets);
    let post_usage: ModuleUsage = collect_usage(&module, &table_maps);
    let functions_dropped: usize =
        drop_orphan_functions(&mut module, &single_caller_targets, &post_usage);

    Ok((
        module.emit_wasm(),
        DefragStats {
            fragments_inlined,
            functions_dropped,
            elements_pruned,
        },
    ))
}

fn lenient_config() -> ModuleConfig {
    let mut cfg: ModuleConfig = ModuleConfig::new();
    cfg.generate_producers_section(false);
    cfg
}

#[derive(Debug, Default)]
struct ModuleUsage {
    direct_call_counts: BTreeMap<FunctionId, u32>,
    indirect_call_counts: BTreeMap<FunctionId, u32>,
    indirect_call_sites: Vec<IndirectSite>,
    exported: BTreeSet<FunctionId>,
}

#[derive(Debug, Clone, Copy)]
struct IndirectSite {
    target: FunctionId,
}

#[derive(Debug, Default)]
struct TableIndexMaps {
    by_table: BTreeMap<TableId, BTreeMap<i64, FunctionId>>,
}

impl TableIndexMaps {
    fn lookup(&self, table: TableId, idx: i64) -> Option<FunctionId> {
        self.by_table.get(&table)?.get(&idx).copied()
    }
}

fn build_table_index_maps(module: &Module) -> TableIndexMaps {
    let mut maps: TableIndexMaps = TableIndexMaps::default();
    for element in module.elements.iter() {
        let ElementKind::Active { table, offset }: &ElementKind = &element.kind else {
            continue;
        };
        let ElementItems::Functions(funcs): &ElementItems = &element.items else {
            continue;
        };
        let base: i64 = constexpr_to_i64(offset);
        let entries: &mut BTreeMap<i64, FunctionId> = maps.by_table.entry(*table).or_default();
        for (i, fid) in funcs.iter().enumerate() {
            let key: i64 = base.saturating_add(i64::try_from(i).unwrap_or(i64::MAX));
            entries.insert(key, *fid);
        }
    }
    maps
}

fn constexpr_to_i64(expr: &walrus::ConstExpr) -> i64 {
    match expr {
        walrus::ConstExpr::Value(Value::I32(n)) => i64::from(*n),
        walrus::ConstExpr::Value(Value::I64(n)) => *n,
        _ => 0,
    }
}

fn collect_usage(module: &Module, table_maps: &TableIndexMaps) -> ModuleUsage {
    let mut usage: ModuleUsage = ModuleUsage::default();
    for export in module.exports.iter() {
        if let ExportItem::Function(fid) = export.item {
            usage.exported.insert(fid);
        }
    }
    for (_id, func) in module.funcs.iter_local() {
        let mut visitor: CallScanner<'_> = CallScanner {
            table_maps,
            usage: &mut usage,
            last_const_i32: None,
        };
        walrus::ir::dfs_in_order(&mut visitor, func, func.entry_block());
    }
    usage
}

struct CallScanner<'a> {
    table_maps: &'a TableIndexMaps,
    usage: &'a mut ModuleUsage,
    last_const_i32: Option<i32>,
}

impl<'instr> Visitor<'instr> for CallScanner<'_> {
    fn visit_instr(&mut self, instr: &'instr Instr, _loc: &walrus::ir::InstrLocId) {
        match instr {
            Instr::Const(Const {
                value: Value::I32(n),
            }) => {
                self.last_const_i32 = Some(*n);
                return;
            }
            Instr::Call(call) => {
                *self.usage.direct_call_counts.entry(call.func).or_default() += 1;
            }
            Instr::CallIndirect(ci) => {
                if let Some(n) = self.last_const_i32
                    && let Some(target) = self.table_maps.lookup(ci.table, i64::from(n))
                {
                    *self.usage.indirect_call_counts.entry(target).or_default() += 1;
                    self.usage.indirect_call_sites.push(IndirectSite { target });
                }
            }
            _ => {}
        }
        self.last_const_i32 = None;
    }
}

fn rewrite_indirect_call_sites(
    module: &mut Module,
    table_maps: &TableIndexMaps,
    eligible: &BTreeMap<FunctionId, FunctionId>,
) -> usize {
    let local_ids: Vec<walrus::FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    let mut rewriter: IndirectRewriter<'_> = IndirectRewriter {
        table_maps,
        eligible,
        rewrites: 0,
    };
    for id in local_ids {
        let func_kind: &mut walrus::FunctionKind = &mut module.funcs.get_mut(id).kind;
        let walrus::FunctionKind::Local(local_func): &mut walrus::FunctionKind = func_kind else {
            continue;
        };
        let entry: walrus::ir::InstrSeqId = local_func.entry_block();
        walrus::ir::dfs_pre_order_mut(&mut rewriter, local_func, entry);
    }
    rewriter.rewrites
}

struct IndirectRewriter<'a> {
    table_maps: &'a TableIndexMaps,
    eligible: &'a BTreeMap<FunctionId, FunctionId>,
    rewrites: usize,
}

impl VisitorMut for IndirectRewriter<'_> {
    fn start_instr_seq_mut(&mut self, seq: &mut walrus::ir::InstrSeq) {
        let mut idx: usize = 0;
        while idx + 1 < seq.instrs.len() {
            let pair: (&Instr, &Instr) = (&seq.instrs[idx].0, &seq.instrs[idx + 1].0);
            let (Instr::Const(c), Instr::CallIndirect(ci)): (&Instr, &Instr) = pair else {
                idx += 1;
                continue;
            };
            let Value::I32(n): Value = c.value else {
                idx += 1;
                continue;
            };
            let Some(target): Option<FunctionId> = self.table_maps.lookup(ci.table, i64::from(n))
            else {
                idx += 1;
                continue;
            };
            if !self.eligible.contains_key(&target) {
                idx += 1;
                continue;
            }
            let (_, loc): (Instr, walrus::ir::InstrLocId) = seq.instrs.remove(idx);
            seq.instrs[idx] = (Instr::Call(walrus::ir::Call { func: target }), loc);
            self.rewrites += 1;
        }
    }
}

fn drop_orphan_functions(
    module: &mut Module,
    rewritten_targets: &BTreeMap<FunctionId, FunctionId>,
    post_usage: &ModuleUsage,
) -> usize {
    let mut dropped: usize = 0usize;
    let candidates: Vec<FunctionId> = rewritten_targets.keys().copied().collect();
    for fid in candidates {
        let direct: u32 = post_usage
            .direct_call_counts
            .get(&fid)
            .copied()
            .unwrap_or(0);
        let indirect: u32 = post_usage
            .indirect_call_counts
            .get(&fid)
            .copied()
            .unwrap_or(0);
        if direct + indirect == 0 && !post_usage.exported.contains(&fid) {
            module.funcs.delete(fid);
            dropped += 1;
        }
    }
    dropped
}

fn prune_dead_elements(
    module: &mut Module,
    rewritten_targets: &BTreeMap<FunctionId, FunctionId>,
) -> usize {
    let mut pruned: usize = 0usize;
    let element_ids: Vec<ElementId> = module.elements.iter().map(walrus::Element::id).collect();
    for eid in element_ids {
        let drop_element: bool = {
            let element: &walrus::Element = module.elements.get(eid);
            let ElementItems::Functions(funcs): &ElementItems = &element.items else {
                continue;
            };
            !funcs.is_empty() && funcs.iter().all(|f| rewritten_targets.contains_key(f))
        };
        if drop_element {
            module.elements.delete(eid);
            pruned += 1;
        }
    }
    pruned
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defrag_stats_default_is_zero() {
        let stats: DefragStats = DefragStats::default();
        assert_eq!(stats.fragments_inlined, 0);
        assert_eq!(stats.functions_dropped, 0);
        assert_eq!(stats.elements_pruned, 0);
    }

    #[test]
    fn constexpr_to_i64_i32_value() {
        let expr: walrus::ConstExpr = walrus::ConstExpr::Value(Value::I32(7));
        assert_eq!(constexpr_to_i64(&expr), 7);
    }

    #[test]
    fn constexpr_to_i64_i64_value() {
        let expr: walrus::ConstExpr = walrus::ConstExpr::Value(Value::I64(-3));
        assert_eq!(constexpr_to_i64(&expr), -3);
    }

    fn access(base: BaseOrigin, alignment: u32, offset: i32, width: u32) -> AccessPattern {
        use crate::types::LoadKind;
        AccessPattern {
            load_kind: Some(LoadKind::I32),
            store_kind: None,
            width,
            alignment,
            offset_class: offset,
            base_origin: base,
            is_indexed: false,
        }
    }

    #[test]
    fn heap_recovery_ignores_unknown_base() {
        let patterns: Vec<AccessPattern> = vec![
            access(BaseOrigin::Unknown, 4, 0, 4),
            access(BaseOrigin::Unknown, 4, 4, 4),
        ];
        assert!(recover_heap_regions(&patterns).is_empty());
    }

    #[test]
    fn heap_recovery_clusters_by_base_and_alignment() {
        let p: BaseOrigin = BaseOrigin::Param(0);
        let patterns: Vec<AccessPattern> = vec![
            access(p, 4, 0, 4),
            access(p, 4, 4, 4),
            access(p, 4, 8, 4),
            access(p, 1, 0, 1),
        ];
        let regions: Vec<HeapRegion> = recover_heap_regions(&patterns);
        assert_eq!(regions.len(), 2, "two alignment clusters under one base");
        let aligned: &HeapRegion = regions
            .iter()
            .find(|r| r.alignment == 4)
            .expect("4-byte region");
        assert_eq!(aligned.access_count, 3);
        assert_eq!(aligned.element_width, 4);
        assert_eq!(aligned.min_offset, 0);
        assert_eq!(aligned.max_offset, 8);
        assert!(aligned.strided, "0/4/8 stride-4 region is strided");
        assert_eq!(aligned.byte_span(), 12);
    }

    #[test]
    fn heap_recovery_modal_width_breaks_ties_low() {
        let p: BaseOrigin = BaseOrigin::Global(2);
        let patterns: Vec<AccessPattern> =
            vec![access(p, 8, 0, 8), access(p, 8, 8, 4), access(p, 8, 16, 4)];
        let regions: Vec<HeapRegion> = recover_heap_regions(&patterns);
        assert_eq!(regions.len(), 1);
        assert_eq!(
            regions[0].element_width, 4,
            "modal width is 4 (two of three)"
        );
    }
}
