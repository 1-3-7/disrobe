use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use wasmparser::{
    AbstractHeapType, ArrayType, CompositeInnerType, FieldType, HeapType, Operator, Parser,
    Payload, StorageType, StructType, SubType, ValType,
};

use crate::error::{Error, Result};

pub type TypeIdx = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum GcRefKind {
    AnyRef,
    EqRef,
    StructRef,
    ArrayRef,
    I31Ref,
    FuncRef,
    ExternRef,
    NoneRef,
    NoFuncRef,
    NoExternRef,
    ExnRef,
    NoExnRef,
    ContRef,
    NoContRef,
    Concrete(TypeIdx),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum GcStorageKind {
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    V128,
    Ref(GcRefKind),
    NullableRef(GcRefKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct GcFieldRecord {
    pub storage: GcStorageKind,
    pub mutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StructTypeRecord {
    pub type_index: TypeIdx,
    pub fields: BTreeMap<u32, GcFieldRecord>,
    pub super_type: Option<TypeIdx>,
    pub is_final: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ArrayTypeRecord {
    pub type_index: TypeIdx,
    pub element: GcFieldRecord,
    pub super_type: Option<TypeIdx>,
    pub is_final: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GcTypeGraph {
    pub structs: BTreeMap<TypeIdx, StructTypeRecord>,
    pub arrays: BTreeMap<TypeIdx, ArrayTypeRecord>,
    pub used_struct_types: BTreeSet<TypeIdx>,
    pub used_array_types: BTreeSet<TypeIdx>,
    pub observed_ref_kinds: BTreeSet<GcRefKind>,
}

impl GcTypeGraph {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty()
            && self.arrays.is_empty()
            && self.used_struct_types.is_empty()
            && self.used_array_types.is_empty()
            && self.observed_ref_kinds.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn struct_count(&self) -> usize {
        self.structs.len()
    }

    #[inline]
    #[must_use]
    pub fn array_count(&self) -> usize {
        self.arrays.len()
    }
}

pub fn recover_gc_types(input: &[u8]) -> Result<GcTypeGraph> {
    let mut graph: GcTypeGraph = GcTypeGraph::default();
    let mut type_cursor: TypeIdx = 0;

    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| parse_err(&e))?;
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group: wasmparser::RecGroup = group.map_err(|e| parse_err(&e))?;
                    for sub in group.into_types() {
                        record_type(&mut graph, type_cursor, &sub);
                        type_cursor = type_cursor.saturating_add(1);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let reader: wasmparser::OperatorsReader<'_> =
                    body.get_operators_reader().map_err(|e| parse_err(&e))?;
                for op in reader {
                    let op: Operator<'_> = op.map_err(|e| parse_err(&e))?;
                    track_op(&mut graph, &op);
                }
            }
            _ => {}
        }
    }
    Ok(graph)
}

fn record_type(graph: &mut GcTypeGraph, idx: TypeIdx, sub: &SubType) {
    let super_type: Option<TypeIdx> = sub.supertype_idx.and_then(|p| p.as_module_index());
    let is_final: bool = sub.is_final;
    match &sub.composite_type.inner {
        CompositeInnerType::Struct(st) => {
            let record: StructTypeRecord = build_struct_record(idx, st, super_type, is_final);
            graph.structs.insert(idx, record);
        }
        CompositeInnerType::Array(at) => {
            let record: ArrayTypeRecord = build_array_record(idx, *at, super_type, is_final);
            graph.arrays.insert(idx, record);
        }
        CompositeInnerType::Func(_) | CompositeInnerType::Cont(_) => {}
    }
}

fn build_struct_record(
    idx: TypeIdx,
    st: &StructType,
    super_type: Option<TypeIdx>,
    is_final: bool,
) -> StructTypeRecord {
    let mut fields: BTreeMap<u32, GcFieldRecord> = BTreeMap::new();
    for (i, ft) in st.fields.iter().enumerate() {
        let key: u32 = u32::try_from(i).unwrap_or(u32::MAX);
        fields.insert(key, field_record(*ft));
    }
    StructTypeRecord {
        type_index: idx,
        fields,
        super_type,
        is_final,
    }
}

#[inline]
fn build_array_record(
    idx: TypeIdx,
    at: ArrayType,
    super_type: Option<TypeIdx>,
    is_final: bool,
) -> ArrayTypeRecord {
    ArrayTypeRecord {
        type_index: idx,
        element: field_record(at.0),
        super_type,
        is_final,
    }
}

#[inline]
fn field_record(ft: FieldType) -> GcFieldRecord {
    GcFieldRecord {
        storage: storage_kind(ft.element_type),
        mutable: ft.mutable,
    }
}

#[inline]
fn storage_kind(ty: StorageType) -> GcStorageKind {
    match ty {
        StorageType::I8 => GcStorageKind::I8,
        StorageType::I16 => GcStorageKind::I16,
        StorageType::Val(v) => valtype_to_storage(v),
    }
}

fn valtype_to_storage(v: ValType) -> GcStorageKind {
    match v {
        ValType::I32 => GcStorageKind::I32,
        ValType::I64 => GcStorageKind::I64,
        ValType::F32 => GcStorageKind::F32,
        ValType::F64 => GcStorageKind::F64,
        ValType::V128 => GcStorageKind::V128,
        ValType::Ref(rt) => {
            let kind: GcRefKind = heap_type_to_ref_kind(rt.heap_type());
            if rt.is_nullable() {
                GcStorageKind::NullableRef(kind)
            } else {
                GcStorageKind::Ref(kind)
            }
        }
    }
}

fn heap_type_to_ref_kind(ht: HeapType) -> GcRefKind {
    match ht {
        HeapType::Abstract { ty, .. } => match ty {
            AbstractHeapType::Any => GcRefKind::AnyRef,
            AbstractHeapType::Eq => GcRefKind::EqRef,
            AbstractHeapType::Struct => GcRefKind::StructRef,
            AbstractHeapType::Array => GcRefKind::ArrayRef,
            AbstractHeapType::I31 => GcRefKind::I31Ref,
            AbstractHeapType::Func => GcRefKind::FuncRef,
            AbstractHeapType::Extern => GcRefKind::ExternRef,
            AbstractHeapType::None => GcRefKind::NoneRef,
            AbstractHeapType::NoFunc => GcRefKind::NoFuncRef,
            AbstractHeapType::NoExtern => GcRefKind::NoExternRef,
            AbstractHeapType::Exn => GcRefKind::ExnRef,
            AbstractHeapType::NoExn => GcRefKind::NoExnRef,
            AbstractHeapType::Cont => GcRefKind::ContRef,
            AbstractHeapType::NoCont => GcRefKind::NoContRef,
        },
        HeapType::Concrete(idx) => idx
            .as_module_index()
            .map_or(GcRefKind::AnyRef, GcRefKind::Concrete),
        HeapType::Exact(idx) => idx
            .as_module_index()
            .map_or(GcRefKind::AnyRef, GcRefKind::Concrete),
    }
}

fn track_op(graph: &mut GcTypeGraph, op: &Operator<'_>) {
    match op {
        Operator::StructNew { struct_type_index }
        | Operator::StructNewDefault { struct_type_index } => {
            graph.used_struct_types.insert(*struct_type_index);
            graph
                .observed_ref_kinds
                .insert(GcRefKind::Concrete(*struct_type_index));
        }
        Operator::StructGet {
            struct_type_index, ..
        }
        | Operator::StructGetS {
            struct_type_index, ..
        }
        | Operator::StructGetU {
            struct_type_index, ..
        }
        | Operator::StructSet {
            struct_type_index, ..
        } => {
            graph.used_struct_types.insert(*struct_type_index);
        }
        Operator::ArrayNew { array_type_index }
        | Operator::ArrayNewDefault { array_type_index }
        | Operator::ArrayNewFixed {
            array_type_index, ..
        }
        | Operator::ArrayNewData {
            array_type_index, ..
        }
        | Operator::ArrayNewElem {
            array_type_index, ..
        } => {
            graph.used_array_types.insert(*array_type_index);
            graph
                .observed_ref_kinds
                .insert(GcRefKind::Concrete(*array_type_index));
        }
        Operator::ArrayGet {
            array_type_index, ..
        }
        | Operator::ArrayGetS {
            array_type_index, ..
        }
        | Operator::ArrayGetU {
            array_type_index, ..
        }
        | Operator::ArraySet {
            array_type_index, ..
        } => {
            graph.used_array_types.insert(*array_type_index);
        }
        Operator::RefI31 => {
            graph.observed_ref_kinds.insert(GcRefKind::I31Ref);
        }
        Operator::RefNull { hty }
        | Operator::RefTestNonNull { hty }
        | Operator::RefTestNullable { hty }
        | Operator::RefCastNonNull { hty }
        | Operator::RefCastNullable { hty } => {
            graph.observed_ref_kinds.insert(heap_type_to_ref_kind(*hty));
        }
        _ => {}
    }
}

#[inline]
fn parse_err(e: &wasmparser::BinaryReaderError) -> Error {
    Error::Parse(format!("{e}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const GC_STRUCT_ARRAY_WAT: &str = r#"
        (module
          (type $point (struct (field $x (mut i32)) (field $y i32)))
          (type $row (array (mut i32)))
          (func (export "make_pt") (result (ref $point))
            i32.const 1
            i32.const 2
            struct.new $point)
          (func (export "make_row") (result (ref $row))
            i32.const 7
            i32.const 3
            array.new $row)
          (func (export "i31") (result (ref i31))
            i32.const 42
            ref.i31))
    "#;

    #[test]
    fn struct_and_array_recovered_from_wat() {
        let bytes: Vec<u8> = wat::parse_str(GC_STRUCT_ARRAY_WAT).expect("parse wat");
        let graph: GcTypeGraph = recover_gc_types(&bytes).expect("recover");
        assert_eq!(graph.struct_count(), 1);
        assert_eq!(graph.array_count(), 1);
        let pt: &StructTypeRecord = graph.structs.values().next().expect("one struct");
        assert_eq!(pt.fields.len(), 2);
        let f0: &GcFieldRecord = pt.fields.get(&0).expect("field 0");
        assert!(matches!(f0.storage, GcStorageKind::I32));
        assert!(f0.mutable);
        let f1: &GcFieldRecord = pt.fields.get(&1).expect("field 1");
        assert!(!f1.mutable);
        let row: &ArrayTypeRecord = graph.arrays.values().next().expect("one array");
        assert!(matches!(row.element.storage, GcStorageKind::I32));
        assert!(row.element.mutable);
        assert!(graph.observed_ref_kinds.contains(&GcRefKind::I31Ref));
    }

    #[test]
    fn empty_module_yields_empty_graph() {
        let bytes: Vec<u8> = wat::parse_str("(module)").expect("parse wat");
        let graph: GcTypeGraph = recover_gc_types(&bytes).expect("recover");
        assert!(graph.is_empty());
    }

    #[test]
    fn non_wasm_input_rejected() {
        let err: Error = recover_gc_types(b"not a wasm at all").expect_err("must err");
        assert!(matches!(err, Error::Parse(_)));
    }
}
