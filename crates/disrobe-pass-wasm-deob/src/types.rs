use serde::Serialize;

use crate::gc_types::GcTypeGraph;
use crate::ssa::LocalId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum LoadKind {
    I32,
    I64,
    F32,
    F64,
    I32_8U,
    I32_8S,
    I32_16U,
    I32_16S,
    I64_8U,
    I64_8S,
    I64_16U,
    I64_16S,
    I64_32U,
    I64_32S,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum StoreKind {
    I32,
    I64,
    F32,
    F64,
    I32_8,
    I32_16,
    I64_8,
    I64_16,
    I64_32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum BaseOrigin {
    Local(LocalId),
    Global(u32),
    Param(u32),
    Heap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct AccessPattern {
    pub load_kind: Option<LoadKind>,
    pub store_kind: Option<StoreKind>,
    pub width: u32,
    pub alignment: u32,
    pub offset_class: i32,
    pub base_origin: BaseOrigin,
    pub is_indexed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FieldRecord {
    pub offset: i32,
    pub width: u32,
    pub kind: WasmValType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum RecoveredType {
    Scalar(WasmValType),
    Struct { fields: Vec<FieldRecord> },
    Array { elem_size: u32, count: Option<u32> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredTypes {
    pub memory_aggregates: Vec<(BaseOrigin, RecoveredType)>,
    pub gc_graph: GcTypeGraph,
}

impl RecoveredTypes {
    #[inline]
    #[must_use]
    pub const fn new(
        memory_aggregates: Vec<(BaseOrigin, RecoveredType)>,
        gc_graph: GcTypeGraph,
    ) -> Self {
        Self {
            memory_aggregates,
            gc_graph,
        }
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memory_aggregates.is_empty() && self.gc_graph.is_empty()
    }
}

pub fn classify_aggregates(patterns: &[AccessPattern]) -> Vec<(BaseOrigin, RecoveredType)> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<BaseOrigin, Vec<&AccessPattern>> = BTreeMap::new();
    for p in patterns {
        groups.entry(p.base_origin).or_default().push(p);
    }

    let mut out: Vec<(BaseOrigin, RecoveredType)> = Vec::with_capacity(groups.len());
    for (base, members) in groups {
        if members.is_empty() {
            continue;
        }
        if members.iter().any(|p| p.is_indexed) {
            let elem_size: u32 = members.first().map_or(4, |p| p.width);
            out.push((
                base,
                RecoveredType::Array {
                    elem_size,
                    count: None,
                },
            ));
            continue;
        }
        if members.len() == 1 {
            let p: &AccessPattern = members[0];
            out.push((base, RecoveredType::Scalar(width_to_valtype(p.width))));
            continue;
        }
        let mut offsets: Vec<i32> = members.iter().map(|p| p.offset_class).collect();
        offsets.sort_unstable();
        offsets.dedup();
        let strided: bool = is_strided(&offsets, members.first().map_or(4, |p| p.width));
        if strided {
            let elem_size: u32 = members.first().map_or(4, |p| p.width);
            let count: u32 = u32::try_from(offsets.len()).unwrap_or(u32::MAX);
            out.push((
                base,
                RecoveredType::Array {
                    elem_size,
                    count: Some(count),
                },
            ));
            continue;
        }
        let mut fields: Vec<FieldRecord> = members
            .iter()
            .map(|p| FieldRecord {
                offset: p.offset_class,
                width: p.width,
                kind: width_to_valtype(p.width),
            })
            .collect();
        fields.sort_by_key(|f| f.offset);
        fields.dedup_by_key(|f| f.offset);
        out.push((base, RecoveredType::Struct { fields }));
    }
    out
}

fn is_strided(offsets: &[i32], stride: u32) -> bool {
    if offsets.len() < 2 {
        return false;
    }
    let stride_i: i32 = i32::try_from(stride).unwrap_or(i32::MAX);
    if stride_i == 0 {
        return false;
    }
    let Some(&first): Option<&i32> = offsets.first() else {
        return false;
    };
    offsets.iter().enumerate().all(|(i, off)| {
        let step: i32 = i32::try_from(i)
            .unwrap_or(i32::MAX)
            .saturating_mul(stride_i);
        *off == first.saturating_add(step)
    })
}

const fn width_to_valtype(width: u32) -> WasmValType {
    match width {
        8 => WasmValType::I64,
        16 => WasmValType::V128,
        _ => WasmValType::I32,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn pat(base: BaseOrigin, offset: i32, width: u32) -> AccessPattern {
        AccessPattern {
            load_kind: Some(LoadKind::I32),
            store_kind: None,
            width,
            alignment: width,
            offset_class: offset,
            base_origin: base,
            is_indexed: false,
        }
    }

    #[test]
    fn single_access_yields_scalar() {
        let p: AccessPattern = pat(BaseOrigin::Local(LocalId(0)), 0, 4);
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&[p]);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].1, RecoveredType::Scalar(WasmValType::I32)));
    }

    #[test]
    fn strided_accesses_yield_array() {
        let base: BaseOrigin = BaseOrigin::Local(LocalId(0));
        let patterns: Vec<AccessPattern> = vec![pat(base, 0, 4), pat(base, 4, 4), pat(base, 8, 4)];
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&patterns);
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].1,
            RecoveredType::Array {
                elem_size: 4,
                count: Some(3)
            }
        ));
    }

    #[test]
    fn distinct_offsets_yield_struct() {
        let base: BaseOrigin = BaseOrigin::Local(LocalId(0));
        let patterns: Vec<AccessPattern> = vec![pat(base, 0, 4), pat(base, 4, 4), pat(base, 12, 4)];
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&patterns);
        assert_eq!(out.len(), 1);
        match &out[0].1 {
            RecoveredType::Struct { fields } => {
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].offset, 0);
                assert_eq!(fields[1].offset, 4);
                assert_eq!(fields[2].offset, 12);
            }
            other => panic!("expected struct, got {other:?}"),
        }
    }

    #[test]
    fn indexed_access_yields_array_unknown_count() {
        let mut p: AccessPattern = pat(BaseOrigin::Local(LocalId(0)), 0, 4);
        p.is_indexed = true;
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&[p]);
        assert!(matches!(out[0].1, RecoveredType::Array { count: None, .. }));
    }
}
