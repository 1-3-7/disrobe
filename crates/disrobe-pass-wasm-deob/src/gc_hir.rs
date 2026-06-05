use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde::Serialize;

use crate::gc_types::{
    ArrayTypeRecord, GcFieldRecord, GcRefKind, GcStorageKind, GcTypeGraph, StructTypeRecord,
    TypeIdx,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcHirModule {
    pub structs: BTreeMap<TypeIdx, GcHirStruct>,
    pub arrays: BTreeMap<TypeIdx, GcHirArray>,
    pub abstract_refs: BTreeSet<GcRefKind>,
    pub rust_source: String,
    pub ts_source: String,
}

impl GcHirModule {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty() && self.arrays.is_empty() && self.abstract_refs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcHirStruct {
    pub type_index: TypeIdx,
    pub rust_name: String,
    pub super_type: Option<TypeIdx>,
    pub is_final: bool,
    pub fields: Vec<GcHirField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcHirArray {
    pub type_index: TypeIdx,
    pub rust_name: String,
    pub super_type: Option<TypeIdx>,
    pub is_final: bool,
    pub element_ty: GcHirTy,
    pub element_mutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcHirField {
    pub index: u32,
    pub rust_name: String,
    pub ty: GcHirTy,
    pub mutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum GcHirTy {
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    V128,
    BoxedStruct { target: TypeIdx, nullable: bool },
    BoxedArray { target: TypeIdx, nullable: bool },
    AnyRef { nullable: bool },
    EqRef { nullable: bool },
    I31Ref { nullable: bool },
    FuncRef { nullable: bool },
    ExternRef { nullable: bool },
    Abstract { kind: GcRefKind, nullable: bool },
}

#[must_use]
pub fn lift_gc_module(graph: &GcTypeGraph) -> GcHirModule {
    let struct_set: BTreeSet<TypeIdx> =
        graph.structs.keys().copied().collect::<BTreeSet<TypeIdx>>();
    let array_set: BTreeSet<TypeIdx> = graph.arrays.keys().copied().collect::<BTreeSet<TypeIdx>>();

    let mut structs: BTreeMap<TypeIdx, GcHirStruct> = BTreeMap::new();
    for (idx, record) in &graph.structs {
        structs.insert(*idx, lift_struct(*idx, record, &struct_set, &array_set));
    }

    let mut arrays: BTreeMap<TypeIdx, GcHirArray> = BTreeMap::new();
    for (idx, record) in &graph.arrays {
        arrays.insert(*idx, lift_array(*idx, record, &struct_set, &array_set));
    }

    let abstract_refs: BTreeSet<GcRefKind> = graph
        .observed_ref_kinds
        .iter()
        .filter(|k: &&GcRefKind| !matches!(k, GcRefKind::Concrete(_)))
        .copied()
        .collect::<BTreeSet<GcRefKind>>();

    let rust_source: String = emit_rust(&structs, &arrays, &abstract_refs);
    let ts_source: String = emit_ts(&structs, &arrays, &abstract_refs);

    GcHirModule {
        structs,
        arrays,
        abstract_refs,
        rust_source,
        ts_source,
    }
}

fn lift_struct(
    idx: TypeIdx,
    record: &StructTypeRecord,
    structs: &BTreeSet<TypeIdx>,
    arrays: &BTreeSet<TypeIdx>,
) -> GcHirStruct {
    let mut fields: Vec<GcHirField> = Vec::with_capacity(record.fields.len());
    for (i, fr) in &record.fields {
        fields.push(GcHirField {
            index: *i,
            rust_name: format!("f{i}"),
            ty: lift_field_ty(fr, structs, arrays),
            mutable: fr.mutable,
        });
    }
    GcHirStruct {
        type_index: idx,
        rust_name: format!("Struct{idx}"),
        super_type: record.super_type,
        is_final: record.is_final,
        fields,
    }
}

fn lift_array(
    idx: TypeIdx,
    record: &ArrayTypeRecord,
    structs: &BTreeSet<TypeIdx>,
    arrays: &BTreeSet<TypeIdx>,
) -> GcHirArray {
    GcHirArray {
        type_index: idx,
        rust_name: format!("Array{idx}"),
        super_type: record.super_type,
        is_final: record.is_final,
        element_ty: lift_field_ty(&record.element, structs, arrays),
        element_mutable: record.element.mutable,
    }
}

fn lift_field_ty(
    fr: &GcFieldRecord,
    structs: &BTreeSet<TypeIdx>,
    arrays: &BTreeSet<TypeIdx>,
) -> GcHirTy {
    match fr.storage {
        GcStorageKind::I8 => GcHirTy::I8,
        GcStorageKind::I16 => GcHirTy::I16,
        GcStorageKind::I32 => GcHirTy::I32,
        GcStorageKind::I64 => GcHirTy::I64,
        GcStorageKind::F32 => GcHirTy::F32,
        GcStorageKind::F64 => GcHirTy::F64,
        GcStorageKind::V128 => GcHirTy::V128,
        GcStorageKind::Ref(kind) => ref_kind_to_hir(kind, false, structs, arrays),
        GcStorageKind::NullableRef(kind) => ref_kind_to_hir(kind, true, structs, arrays),
    }
}

fn ref_kind_to_hir(
    kind: GcRefKind,
    nullable: bool,
    structs: &BTreeSet<TypeIdx>,
    arrays: &BTreeSet<TypeIdx>,
) -> GcHirTy {
    match kind {
        GcRefKind::AnyRef => GcHirTy::AnyRef { nullable },
        GcRefKind::EqRef => GcHirTy::EqRef { nullable },
        GcRefKind::I31Ref => GcHirTy::I31Ref { nullable },
        GcRefKind::FuncRef => GcHirTy::FuncRef { nullable },
        GcRefKind::ExternRef => GcHirTy::ExternRef { nullable },
        GcRefKind::Concrete(target) => {
            if structs.contains(&target) {
                GcHirTy::BoxedStruct { target, nullable }
            } else if arrays.contains(&target) {
                GcHirTy::BoxedArray { target, nullable }
            } else {
                GcHirTy::AnyRef { nullable }
            }
        }
        other => GcHirTy::Abstract {
            kind: other,
            nullable,
        },
    }
}

fn emit_rust(
    structs: &BTreeMap<TypeIdx, GcHirStruct>,
    arrays: &BTreeMap<TypeIdx, GcHirArray>,
    abstract_refs: &BTreeSet<GcRefKind>,
) -> String {
    let mut out: String = String::with_capacity(512);
    out.push_str("use std::sync::Arc;\n\n");
    for kind in abstract_refs {
        let _: std::fmt::Result = writeln!(
            out,
            "pub struct {alias};",
            alias = abstract_alias_rust(*kind)
        );
    }
    if !abstract_refs.is_empty() {
        out.push('\n');
    }
    for s in structs.values() {
        emit_rust_struct(s, &mut out);
    }
    for a in arrays.values() {
        emit_rust_array(a, &mut out);
    }
    out
}

fn emit_rust_struct(s: &GcHirStruct, out: &mut String) {
    let _: std::fmt::Result = writeln!(out, "#[derive(Debug, Clone)]");
    let _: std::fmt::Result = writeln!(out, "pub struct {name} {{", name = s.rust_name);
    for f in &s.fields {
        let _: std::fmt::Result = writeln!(
            out,
            "    pub {name}: {ty},",
            name = f.rust_name,
            ty = render_rust_ty(&f.ty)
        );
    }
    out.push_str("}\n\n");
    if let Some(parent) = s.super_type {
        let _: std::fmt::Result = writeln!(
            out,
            "pub trait SuperOf{name} {{ fn as_super(&self) -> Arc<Struct{parent}>; }}\n",
            name = s.rust_name
        );
    }
}

fn emit_rust_array(a: &GcHirArray, out: &mut String) {
    let _: std::fmt::Result = writeln!(out, "#[derive(Debug, Clone)]");
    let _: std::fmt::Result = writeln!(
        out,
        "pub struct {name}(pub Vec<{elem}>);\n",
        name = a.rust_name,
        elem = render_rust_ty(&a.element_ty)
    );
}

fn render_rust_ty(ty: &GcHirTy) -> String {
    match ty {
        GcHirTy::I8 => "i8".to_owned(),
        GcHirTy::I16 => "i16".to_owned(),
        GcHirTy::I32 => "i32".to_owned(),
        GcHirTy::I64 => "i64".to_owned(),
        GcHirTy::F32 => "f32".to_owned(),
        GcHirTy::F64 => "f64".to_owned(),
        GcHirTy::V128 => "u128".to_owned(),
        GcHirTy::BoxedStruct { target, nullable } => {
            wrap_nullable(&format!("Box<Struct{target}>"), *nullable)
        }
        GcHirTy::BoxedArray { target, nullable } => {
            wrap_nullable(&format!("Box<Array{target}>"), *nullable)
        }
        GcHirTy::AnyRef { nullable } => wrap_nullable("Box<AnyRef>", *nullable),
        GcHirTy::EqRef { nullable } => wrap_nullable("Box<EqRef>", *nullable),
        GcHirTy::I31Ref { nullable } => wrap_nullable("i32", *nullable),
        GcHirTy::FuncRef { nullable } => wrap_nullable("fn() -> ()", *nullable),
        GcHirTy::ExternRef { nullable } => wrap_nullable("Box<ExternRef>", *nullable),
        GcHirTy::Abstract { kind, nullable } => {
            wrap_nullable(&format!("Box<{}>", abstract_alias_rust(*kind)), *nullable)
        }
    }
}

#[inline]
fn wrap_nullable(inner: &str, nullable: bool) -> String {
    if nullable {
        format!("Option<{inner}>")
    } else {
        inner.to_owned()
    }
}

fn emit_ts(
    structs: &BTreeMap<TypeIdx, GcHirStruct>,
    arrays: &BTreeMap<TypeIdx, GcHirArray>,
    _abstract_refs: &BTreeSet<GcRefKind>,
) -> String {
    let mut out: String = String::with_capacity(512);
    for s in structs.values() {
        let _: std::fmt::Result = writeln!(out, "export interface {name} {{", name = s.rust_name);
        for f in &s.fields {
            let prefix: &str = if f.mutable { "" } else { "readonly " };
            let _: std::fmt::Result = writeln!(
                out,
                "  {prefix}{name}: {ty};",
                name = f.rust_name,
                ty = render_ts_ty(&f.ty)
            );
        }
        out.push_str("}\n\n");
    }
    for a in arrays.values() {
        let modifier: &str = if a.element_mutable { "" } else { "readonly " };
        let _: std::fmt::Result = writeln!(
            out,
            "export type {name} = {modifier}{elem}[];\n",
            name = a.rust_name,
            elem = render_ts_ty(&a.element_ty)
        );
    }
    out
}

fn render_ts_ty(ty: &GcHirTy) -> String {
    match ty {
        GcHirTy::I8 | GcHirTy::I16 | GcHirTy::I32 | GcHirTy::F32 | GcHirTy::F64 => {
            "number".to_owned()
        }
        GcHirTy::I64 | GcHirTy::V128 => "bigint".to_owned(),
        GcHirTy::BoxedStruct { target, nullable } => wrap_ts(&format!("Struct{target}"), *nullable),
        GcHirTy::BoxedArray { target, nullable } => wrap_ts(&format!("Array{target}"), *nullable),
        GcHirTy::AnyRef { nullable } => wrap_ts("unknown", *nullable),
        GcHirTy::EqRef { nullable } => wrap_ts("unknown", *nullable),
        GcHirTy::I31Ref { nullable } => wrap_ts("number", *nullable),
        GcHirTy::FuncRef { nullable } => wrap_ts("Function", *nullable),
        GcHirTy::ExternRef { nullable } => wrap_ts("unknown", *nullable),
        GcHirTy::Abstract { nullable, .. } => wrap_ts("unknown", *nullable),
    }
}

#[inline]
fn wrap_ts(inner: &str, nullable: bool) -> String {
    if nullable {
        format!("{inner} | null")
    } else {
        inner.to_owned()
    }
}

#[inline]
const fn abstract_alias_rust(kind: GcRefKind) -> &'static str {
    match kind {
        GcRefKind::AnyRef => "AnyRef",
        GcRefKind::EqRef => "EqRef",
        GcRefKind::StructRef => "StructRef",
        GcRefKind::ArrayRef => "ArrayRef",
        GcRefKind::I31Ref => "I31Ref",
        GcRefKind::FuncRef => "FuncRef",
        GcRefKind::ExternRef => "ExternRef",
        GcRefKind::NoneRef => "NoneRef",
        GcRefKind::NoFuncRef => "NoFuncRef",
        GcRefKind::NoExternRef => "NoExternRef",
        GcRefKind::ExnRef => "ExnRef",
        GcRefKind::NoExnRef => "NoExnRef",
        GcRefKind::ContRef => "ContRef",
        GcRefKind::NoContRef => "NoContRef",
        GcRefKind::Concrete(_) => "AnyRef",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::gc_types::recover_gc_types;

    const GC_WAT: &str = r#"
        (module
          (type $point (struct (field $x (mut i32)) (field $y i32)))
          (type $row (array (mut i32)))
          (func (export "make_pt") (result (ref $point))
            i32.const 1 i32.const 2 struct.new $point)
          (func (export "make_row") (result (ref $row))
            i32.const 7 i32.const 3 array.new $row)
          (func (export "i31") (result (ref i31))
            i32.const 42 ref.i31))
    "#;

    #[test]
    fn lifts_struct_and_array_to_typed_rust_and_ts() {
        let bytes: Vec<u8> = wat::parse_str(GC_WAT).expect("parse wat");
        let graph: GcTypeGraph = recover_gc_types(&bytes).expect("graph");
        let hir: GcHirModule = lift_gc_module(&graph);
        assert_eq!(hir.structs.len(), 1);
        assert_eq!(hir.arrays.len(), 1);
        let s: &GcHirStruct = hir.structs.values().next().expect("struct");
        assert_eq!(s.fields.len(), 2);
        assert!(s.fields[0].mutable);
        assert!(!s.fields[1].mutable);
        assert!(hir.rust_source.contains("pub struct Struct0"));
        assert!(hir.rust_source.contains("pub f0: i32"));
        assert!(hir.rust_source.contains("pub struct Array1"));
        assert!(hir.ts_source.contains("export interface Struct0"));
        assert!(hir.ts_source.contains("readonly f1: number"));
        assert!(hir.ts_source.contains("export type Array1"));
    }
}
