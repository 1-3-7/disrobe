use std::collections::BTreeSet;
use std::fmt::Arguments;

use wasmparser::{
    CompositeInnerType, ConstExpr, Data, DataKind, Element, ElementItems, ElementKind,
    ExternalKind, Global, Operator, PackedIndex, Parser, Payload, RefType, StorageType, TableInit,
    TableType, TypeRef, ValType,
};

use crate::lift_wat::{FeatureReqs, RenderMode, WatFunc, render_func_in_module, val_type_str};
use crate::signature::FunctionSig;

const DATA_ESCAPE_PREALLOC_CAP: usize = 1 << 20;

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut impl std::fmt::Write, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

fn push_format_line(output: &mut impl std::fmt::Write, args: Arguments<'_>) {
    push_format(output, args);
    match output.write_char('\n') {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Default)]
struct ModuleScaffold {
    type_decls: Vec<String>,
    imports: Vec<String>,
    memories: Vec<String>,
    tables: Vec<String>,
    globals: Vec<String>,
    tags: Vec<String>,
    exports: Vec<String>,
    elements: Vec<String>,
    data: Vec<String>,
    start: Option<u32>,
    declared_funcs: BTreeSet<u32>,
    imported_func_count: u32,
    func_type_indices: Vec<u32>,
    func_types: Vec<(Vec<ValType>, Vec<ValType>)>,
}

#[must_use]
pub fn lift_module_faithful_wat(bytes: &[u8]) -> Option<String> {
    crate::debug::dbg_section("faithful-lift");
    let scaffold: ModuleScaffold = collect_scaffold(bytes)?;
    let module_sigs: Vec<(Vec<ValType>, Vec<ValType>)> = scaffold.func_signatures();
    crate::debug::dbg_kv("scaffold", || {
        format!(
            "type_decls={} imported_funcs={} declared_funcs={} func_types={} globals={} memories={} tables={}",
            scaffold.type_decls.len(),
            scaffold.imported_func_count,
            scaffold.declared_funcs.len(),
            scaffold.func_types.len(),
            scaffold.globals.len(),
            scaffold.memories.len(),
            scaffold.tables.len()
        )
    });

    let mut bodies: String = String::new();
    let mut reqs: FeatureReqs = FeatureReqs::default();
    let mut defined_index: u32 = scaffold.imported_func_count;
    let sigs: Vec<FunctionSig> = scaffold.defined_signatures();
    let mut sig_iter: std::slice::Iter<'_, FunctionSig> = sigs.iter();
    let mut bodies_lifted: u32 = 0;

    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(Payload::CodeSectionEntry(body)) = payload else {
            continue;
        };
        let sig: &FunctionSig = sig_iter.next()?;
        let rendered: WatFunc = render_func_in_module(
            &body,
            sig,
            defined_index,
            RenderMode::WholeModule,
            &module_sigs,
            &scaffold.func_types,
        );
        reqs.merge(&rendered.reqs);
        bodies.push_str(&rendered.text);
        defined_index = defined_index.checked_add(1)?;
        bodies_lifted += 1;
    }

    crate::debug::dbg_kv("bodies", || {
        format!("function_bodies_lifted={bodies_lifted}")
    });
    Some(assemble(&scaffold, &bodies, &reqs))
}

fn assemble(scaffold: &ModuleScaffold, bodies: &str, reqs: &FeatureReqs) -> String {
    let mut out: String = String::from("(module\n");
    for decl in &scaffold.type_decls {
        push_line!(out, "  {decl}");
    }
    for tag in &scaffold.tags {
        push_line!(out, "  {tag}");
    }
    for imp in &scaffold.imports {
        push_line!(out, "  {imp}");
    }
    for mem in &scaffold.memories {
        push_line!(out, "  {mem}");
    }
    for table in &scaffold.tables {
        push_line!(out, "  {table}");
    }
    for global in &scaffold.globals {
        push_line!(out, "  {global}");
    }
    emit_declared_funcs(&mut out, scaffold, reqs);
    out.push_str(bodies);
    for export in &scaffold.exports {
        push_line!(out, "  {export}");
    }
    for elem in &scaffold.elements {
        push_line!(out, "  {elem}");
    }
    for data in &scaffold.data {
        push_line!(out, "  {data}");
    }
    if let Some(start) = scaffold.start {
        push_line!(out, "  (start $f{start})");
    }
    out.push_str(")\n");
    out
}

fn emit_declared_funcs(mut out: &mut String, scaffold: &ModuleScaffold, reqs: &FeatureReqs) {
    let mut declared: BTreeSet<u32> = scaffold.declared_funcs.clone();
    for idx in reqs.ref_func_indices() {
        declared.insert(*idx);
    }
    if declared.is_empty() {
        return;
    }
    out.push_str("  (elem declare func");
    for idx in &declared {
        push_text!(out, " $f{idx}");
    }
    out.push_str(")\n");
}

impl ModuleScaffold {
    fn func_signatures(&self) -> Vec<(Vec<ValType>, Vec<ValType>)> {
        self.func_type_indices
            .iter()
            .map(|ti| {
                self.func_types
                    .get(*ti as usize)
                    .cloned()
                    .unwrap_or_else(|| (vec![ValType::I32], vec![ValType::I32]))
            })
            .collect()
    }

    fn defined_signatures(&self) -> Vec<FunctionSig> {
        let imported: usize = self.imported_func_count as usize;
        self.func_type_indices
            .iter()
            .skip(imported)
            .enumerate()
            .map(|(offset, ti)| {
                let (params, results): (Vec<ValType>, Vec<ValType>) = self
                    .func_types
                    .get(*ti as usize)
                    .cloned()
                    .unwrap_or_else(|| (vec![ValType::I32], vec![ValType::I32]));
                FunctionSig {
                    name: format!("func_{offset}"),
                    params,
                    results,
                    exported: false,
                    imported: false,
                    local_names: Vec::new(),
                }
            })
            .collect()
    }
}

fn collect_scaffold(bytes: &[u8]) -> Option<ModuleScaffold> {
    let mut scaffold: ModuleScaffold = ModuleScaffold::default();
    let mut data_index: u32 = 0;
    let mut elem_index: u32 = 0;
    let mut memory_index: u32 = 0;
    let mut table_index: u32 = 0;
    let mut global_index: u32 = 0;

    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload): Result<Payload<'_>, _> = payload else {
            return None;
        };
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group: wasmparser::RecGroup = group.ok()?;
                    collect_types(&group, &mut scaffold);
                }
            }
            Payload::ImportSection(reader) => {
                for imp in reader.into_imports() {
                    let imp: wasmparser::Import<'_> = imp.ok()?;
                    collect_import(
                        &imp,
                        &mut scaffold,
                        &mut memory_index,
                        &mut table_index,
                        &mut global_index,
                    );
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    scaffold.func_type_indices.push(ty.ok()?);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table: wasmparser::Table<'_> = table.ok()?;
                    scaffold
                        .tables
                        .push(render_table(table_index, &table.ty, &table.init)?);
                    table_index = table_index.checked_add(1)?;
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem: wasmparser::MemoryType = mem.ok()?;
                    scaffold.memories.push(render_memory(memory_index, &mem));
                    memory_index = memory_index.checked_add(1)?;
                }
            }
            Payload::TagSection(reader) => {
                for tag in reader {
                    let tag: wasmparser::TagType = tag.ok()?;
                    let idx: usize = scaffold.tags.len();
                    let params: Vec<ValType> = scaffold
                        .func_types
                        .get(tag.func_type_idx as usize)
                        .map(|(p, _)| p.clone())
                        .unwrap_or_default();
                    scaffold.tags.push(render_tag(idx, &params));
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let global: Global<'_> = global.ok()?;
                    scaffold.globals.push(render_global(global_index, &global)?);
                    global_index = global_index.checked_add(1)?;
                }
            }
            Payload::ExportSection(reader) => {
                for exp in reader {
                    let exp: wasmparser::Export<'_> = exp.ok()?;
                    scaffold.exports.push(render_export(&exp));
                }
            }
            Payload::StartSection { func, .. } => {
                scaffold.start = Some(func);
            }
            Payload::ElementSection(reader) => {
                for elem in reader {
                    let elem: Element<'_> = elem.ok()?;
                    let mut declared: BTreeSet<u32> = BTreeSet::new();
                    let rendered: String = render_element(elem_index, &elem, &mut declared)?;
                    scaffold.declared_funcs.extend(declared);
                    scaffold.elements.push(rendered);
                    elem_index = elem_index.checked_add(1)?;
                }
            }
            Payload::DataSection(reader) => {
                for item in reader {
                    let item: Data<'_> = item.ok()?;
                    scaffold.data.push(render_data(data_index, &item)?);
                    data_index = data_index.checked_add(1)?;
                }
            }
            _ => {}
        }
    }
    Some(scaffold)
}

fn collect_types(group: &wasmparser::RecGroup, scaffold: &mut ModuleScaffold) {
    let group_base: usize = scaffold.func_types.len();
    let mut members: Vec<String> = Vec::new();
    for sub in group.types() {
        let idx: usize = scaffold.func_types.len();
        members.push(render_sub_type(idx, sub, group_base, scaffold));
    }
    if group.is_explicit_rec_group() {
        let mut rec: String = String::from("(rec");
        for decl in &members {
            push_text!(rec, " {decl}");
        }
        rec.push(')');
        scaffold.type_decls.push(rec);
    } else {
        scaffold.type_decls.extend(members);
    }
}

fn render_sub_type(
    idx: usize,
    sub: &wasmparser::SubType,
    group_base: usize,
    scaffold: &mut ModuleScaffold,
) -> String {
    let body: String = match &sub.composite_type.inner {
        CompositeInnerType::Func(ft) => {
            let params: Vec<ValType> = ft.params().to_vec();
            let results: Vec<ValType> = ft.results().to_vec();
            scaffold.func_types.push((params.clone(), results.clone()));
            render_func_body(&params, &results)
        }
        CompositeInnerType::Struct(st) => {
            scaffold.func_types.push((Vec::new(), Vec::new()));
            render_struct_body(st, group_base)
        }
        CompositeInnerType::Array(at) => {
            scaffold.func_types.push((Vec::new(), Vec::new()));
            render_array_body(at, group_base)
        }
        CompositeInnerType::Cont(ct) => {
            let referenced: u32 = resolve_type_index(ct.0, group_base).unwrap_or(idx as u32);
            let signature: (Vec<ValType>, Vec<ValType>) = scaffold
                .func_types
                .get(referenced as usize)
                .cloned()
                .unwrap_or_default();
            scaffold.func_types.push(signature);
            format!("(cont $t{referenced})")
        }
    };
    let composite: String = if sub.composite_type.shared {
        format!("(shared {body})")
    } else {
        body
    };
    format!("(type $t{idx} {})", wrap_sub(sub, group_base, &composite))
}

fn wrap_sub(sub: &wasmparser::SubType, group_base: usize, composite: &str) -> String {
    if sub.is_final && sub.supertype_idx.is_none() {
        return composite.to_owned();
    }
    let mut s: String = String::from("(sub ");
    if sub.is_final {
        s.push_str("final ");
    }
    if let Some(super_idx) = sub
        .supertype_idx
        .and_then(|p| resolve_type_index(p, group_base))
    {
        push_text!(s, "$t{super_idx} ");
    }
    s.push_str(composite);
    s.push(')');
    s
}

fn resolve_type_index(packed: PackedIndex, group_base: usize) -> Option<u32> {
    if let Some(module_idx) = packed.as_module_index() {
        return Some(module_idx);
    }
    let rel: u32 = packed.as_rec_group_index()?;
    u32::try_from(group_base).ok()?.checked_add(rel)
}

fn render_func_body(params: &[ValType], results: &[ValType]) -> String {
    let mut s: String = String::from("(func");
    for ty in params {
        push_text!(s, " (param {})", val_type_str(*ty));
    }
    for ty in results {
        push_text!(s, " (result {})", val_type_str(*ty));
    }
    s.push(')');
    s
}

fn render_struct_body(st: &wasmparser::StructType, group_base: usize) -> String {
    let mut s: String = String::from("(struct");
    for field in &st.fields {
        push_text!(s, " (field {})", field_type_str(field, group_base));
    }
    s.push(')');
    s
}

fn render_array_body(at: &wasmparser::ArrayType, group_base: usize) -> String {
    format!("(array {})", field_type_str(&at.0, group_base))
}

fn field_type_str(field: &wasmparser::FieldType, group_base: usize) -> String {
    let inner: String = storage_type_str(field.element_type, group_base);
    if field.mutable {
        format!("(mut {inner})")
    } else {
        inner
    }
}

fn storage_type_str(ty: StorageType, group_base: usize) -> String {
    match ty {
        StorageType::I8 => "i8".to_owned(),
        StorageType::I16 => "i16".to_owned(),
        StorageType::Val(v) => val_type_str_in_group(v, group_base),
    }
}

fn val_type_str_in_group(ty: ValType, group_base: usize) -> String {
    match ty {
        ValType::Ref(r) => ref_type_str_in_group(r, group_base),
        other => val_type_str(other),
    }
}

fn ref_type_str_in_group(r: RefType, group_base: usize) -> String {
    use wasmparser::HeapType;
    let (HeapType::Concrete(idx) | HeapType::Exact(idx)) = r.heap_type() else {
        return val_type_str(ValType::Ref(r));
    };
    match resolve_unpacked_index(idx, group_base) {
        Some(i) if r.is_nullable() => format!("(ref null $t{i})"),
        Some(i) => format!("(ref $t{i})"),
        None => val_type_str(ValType::Ref(r)),
    }
}

fn resolve_unpacked_index(idx: wasmparser::UnpackedIndex, group_base: usize) -> Option<u32> {
    if let Some(module_idx) = idx.as_module_index() {
        return Some(module_idx);
    }
    let rel: u32 = idx.as_rec_group_index()?;
    u32::try_from(group_base).ok()?.checked_add(rel)
}

fn collect_import(
    imp: &wasmparser::Import<'_>,
    scaffold: &mut ModuleScaffold,
    memory_index: &mut u32,
    table_index: &mut u32,
    global_index: &mut u32,
) {
    let module: &str = imp.module;
    let field: &str = imp.name;
    match imp.ty {
        TypeRef::Func(type_index) | TypeRef::FuncExact(type_index) => {
            let abs: u32 = scaffold.imported_func_count;
            scaffold.func_type_indices.push(type_index);
            scaffold.imported_func_count = scaffold.imported_func_count.saturating_add(1);
            scaffold.imports.push(format!(
                "(import \"{module}\" \"{field}\" (func $f{abs} (type $t{type_index})))"
            ));
        }
        TypeRef::Memory(mem) => {
            scaffold.imports.push(format!(
                "(import \"{module}\" \"{field}\" (memory {}))",
                memory_limits(&mem)
            ));
            *memory_index = memory_index.saturating_add(1);
        }
        TypeRef::Table(table) => {
            scaffold.imports.push(format!(
                "(import \"{module}\" \"{field}\" (table {} {}))",
                table_limits(&table),
                ref_type_keyword(table.element_type)
            ));
            *table_index = table_index.saturating_add(1);
        }
        TypeRef::Global(global) => {
            let ty: String = val_type_str(global.content_type);
            let body: String = if global.mutable {
                format!("(mut {ty})")
            } else {
                ty
            };
            scaffold.imports.push(format!(
                "(import \"{module}\" \"{field}\" (global $g{} {body}))",
                *global_index
            ));
            *global_index = global_index.saturating_add(1);
        }
        TypeRef::Tag(tag) => {
            let params: Vec<ValType> = scaffold
                .func_types
                .get(tag.func_type_idx as usize)
                .map(|(p, _)| p.clone())
                .unwrap_or_default();
            let idx: usize = scaffold.tags.len();
            let mut s: String = format!("(import \"{module}\" \"{field}\" (tag $tag{idx} (param");
            for ty in &params {
                push_text!(s, " {}", val_type_str(*ty));
            }
            s.push_str(")))");
            scaffold.tags.push(s);
        }
    }
}

fn render_memory(idx: u32, mem: &wasmparser::MemoryType) -> String {
    format!("(memory $m{idx} {})", memory_limits(mem))
}

fn memory_limits(mem: &wasmparser::MemoryType) -> String {
    let prefix: &str = if mem.memory64 { "i64 " } else { "" };
    let page: String = mem.page_size_log2.map_or_else(String::new, |log2| {
        format!(
            " (pagesize {})",
            1u64.checked_shl(log2).unwrap_or(1u64 << 63)
        )
    });
    match (mem.maximum, mem.shared) {
        (Some(max), true) => format!("{prefix}{} {max} shared{page}", mem.initial),
        (Some(max), false) => format!("{prefix}{} {max}{page}", mem.initial),
        (None, _) => format!("{prefix}{}{page}", mem.initial),
    }
}

fn table_limits(table: &TableType) -> String {
    let prefix: &str = if table.table64 { "i64 " } else { "" };
    table.maximum.map_or_else(
        || format!("{prefix}{}", table.initial),
        |max| format!("{prefix}{} {max}", table.initial),
    )
}

fn render_table(idx: u32, ty: &TableType, init: &TableInit<'_>) -> Option<String> {
    let limits: String = table_limits(ty);
    let elem: String = ref_type_keyword(ty.element_type);
    let name: String = table_target_name(idx);
    match init {
        TableInit::RefNull => Some(format!("(table {name} {limits} {elem})")),
        TableInit::Expr(expr) => {
            let init_str: String = render_const_expr(expr)?;
            Some(format!("(table {name} {limits} {elem} ({init_str}))"))
        }
    }
}

fn render_global(idx: u32, global: &Global<'_>) -> Option<String> {
    let ty: String = val_type_str(global.ty.content_type);
    let init: String = render_const_expr(&global.init_expr)?;
    if global.ty.mutable {
        Some(format!("(global $g{idx} (mut {ty}) ({init}))"))
    } else {
        Some(format!("(global $g{idx} {ty} ({init}))"))
    }
}

fn render_tag(idx: usize, params: &[ValType]) -> String {
    let mut s: String = format!("(tag $tag{idx} (param");
    for ty in params {
        push_text!(s, " {}", val_type_str(*ty));
    }
    s.push_str("))");
    s
}

fn render_export(exp: &wasmparser::Export<'_>) -> String {
    let kind: &str = match exp.kind {
        ExternalKind::Func | ExternalKind::FuncExact => "func",
        ExternalKind::Table => "table",
        ExternalKind::Memory => "memory",
        ExternalKind::Global => "global",
        ExternalKind::Tag => "tag",
    };
    let target: String = match exp.kind {
        ExternalKind::Func | ExternalKind::FuncExact => format!("$f{}", exp.index),
        ExternalKind::Table => table_target_name(exp.index),
        ExternalKind::Memory => format!("$m{}", exp.index),
        ExternalKind::Global => format!("$g{}", exp.index),
        ExternalKind::Tag => format!("$tag{}", exp.index),
    };
    format!("(export \"{}\" ({kind} {target}))", exp.name)
}

fn table_target_name(index: u32) -> String {
    if index == 0 {
        "$dr_tbl_func".to_owned()
    } else {
        "$dr_tbl_ext".to_owned()
    }
}

fn render_element(idx: u32, elem: &Element<'_>, declared: &mut BTreeSet<u32>) -> Option<String> {
    let items: Vec<String> = element_items(&elem.items, declared)?;
    match &elem.kind {
        ElementKind::Passive => {
            let kw: &str = items_keyword(&elem.items);
            Some(format!("(elem $e{idx} {kw} {})", items.join(" ")))
        }
        ElementKind::Declared => {
            for item in &items {
                if let Some(stripped) = item.strip_prefix("(ref.func ") {
                    if let Some(n) = stripped.strip_suffix(')') {
                        if let Some(rest) = n.strip_prefix("$f") {
                            if let Ok(parsed) = rest.parse::<u32>() {
                                declared.insert(parsed);
                            }
                        }
                    }
                }
            }
            Some(format!("(elem $e{idx} declare func)"))
        }
        ElementKind::Active {
            table_index,
            offset_expr,
        } => {
            let offset: String = render_const_expr(offset_expr)?;
            let table: String = table_target_name(table_index.unwrap_or(0));
            let kw: &str = items_keyword(&elem.items);
            Some(format!(
                "(elem $e{idx} (table {table}) ({offset}) {kw} {})",
                items.join(" ")
            ))
        }
    }
}

fn items_keyword(items: &ElementItems<'_>) -> &'static str {
    match items {
        ElementItems::Functions(_) => "func",
        ElementItems::Expressions(ref_type, _) => ref_type_static_keyword(*ref_type),
    }
}

fn ref_type_static_keyword(ty: RefType) -> &'static str {
    if ty == RefType::FUNCREF {
        "funcref"
    } else if ty == RefType::EXTERNREF {
        "externref"
    } else {
        "funcref"
    }
}

fn element_items(items: &ElementItems<'_>, declared: &mut BTreeSet<u32>) -> Option<Vec<String>> {
    match items {
        ElementItems::Functions(reader) => {
            let mut out: Vec<String> = Vec::new();
            for f in reader.clone() {
                let idx: u32 = f.ok()?;
                declared.insert(idx);
                out.push(format!("$f{idx}"));
            }
            Some(out)
        }
        ElementItems::Expressions(_, reader) => {
            let mut out: Vec<String> = Vec::new();
            for expr in reader.clone() {
                let expr: ConstExpr<'_> = expr.ok()?;
                out.push(format!("({})", render_const_expr(&expr)?));
            }
            Some(out)
        }
    }
}

fn render_data(idx: u32, data: &Data<'_>) -> Option<String> {
    let payload: String = encode_data_bytes(data.data);
    match &data.kind {
        DataKind::Passive => Some(format!("(data $d{idx} \"{payload}\")")),
        DataKind::Active {
            memory_index,
            offset_expr,
        } => {
            let offset: String = render_const_expr(offset_expr)?;
            Some(format!(
                "(data $d{idx} (memory {memory_index}) ({offset}) \"{payload}\")"
            ))
        }
    }
}

fn encode_data_bytes(bytes: &[u8]) -> String {
    let capacity: usize = bytes
        .len()
        .checked_mul(4)
        .unwrap_or(DATA_ESCAPE_PREALLOC_CAP)
        .min(DATA_ESCAPE_PREALLOC_CAP);
    let mut s: String = String::with_capacity(capacity);
    for byte in bytes {
        push_text!(s, "\\{byte:02x}");
    }
    s
}

fn render_const_expr(expr: &ConstExpr<'_>) -> Option<String> {
    let mut reader: wasmparser::OperatorsReader<'_> = expr.get_operators_reader();
    let mut parts: Vec<String> = Vec::new();
    loop {
        let op: Operator<'_> = reader.read().ok()?;
        match op {
            Operator::End => break,
            other => parts.push(const_op_str(&other)?),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(" "))
}

fn const_op_str(op: &Operator<'_>) -> Option<String> {
    Some(match op {
        Operator::I32Const { value } => format!("i32.const {value}"),
        Operator::I64Const { value } => format!("i64.const {value}"),
        Operator::F32Const { value } => format!("f32.const {}", const_f32(value.bits())),
        Operator::F64Const { value } => format!("f64.const {}", const_f64(value.bits())),
        Operator::V128Const { value } => {
            let mut s: String = String::from("v128.const i8x16");
            for byte in value.bytes() {
                push_text!(s, " {byte}");
            }
            s
        }
        Operator::GlobalGet { global_index } => format!("global.get $g{global_index}"),
        Operator::RefNull { hty } => format!("ref.null {}", heap_null_keyword(*hty)),
        Operator::RefFunc { function_index } => format!("ref.func $f{function_index}"),
        Operator::RefI31 => "ref.i31".to_owned(),
        Operator::I32Add => "i32.add".to_owned(),
        Operator::I32Sub => "i32.sub".to_owned(),
        Operator::I32Mul => "i32.mul".to_owned(),
        Operator::I64Add => "i64.add".to_owned(),
        Operator::I64Sub => "i64.sub".to_owned(),
        Operator::I64Mul => "i64.mul".to_owned(),
        _ => return None,
    })
}

fn heap_null_keyword(hty: wasmparser::HeapType) -> String {
    use wasmparser::{AbstractHeapType, HeapType};
    match hty {
        HeapType::Abstract { ty, .. } => match ty {
            AbstractHeapType::Func => "func".to_owned(),
            AbstractHeapType::Extern => "extern".to_owned(),
            AbstractHeapType::Any => "any".to_owned(),
            AbstractHeapType::Eq => "eq".to_owned(),
            AbstractHeapType::Struct => "struct".to_owned(),
            AbstractHeapType::Array => "array".to_owned(),
            AbstractHeapType::I31 => "i31".to_owned(),
            AbstractHeapType::None => "none".to_owned(),
            AbstractHeapType::NoFunc => "nofunc".to_owned(),
            AbstractHeapType::NoExtern => "noextern".to_owned(),
            _ => "func".to_owned(),
        },
        HeapType::Concrete(idx) => idx
            .as_module_index()
            .map_or_else(|| "func".to_owned(), |i| format!("$t{i}")),
        HeapType::Exact(idx) => idx
            .as_module_index()
            .map_or_else(|| "func".to_owned(), |i| format!("$t{i}")),
    }
}

fn ref_type_keyword(ty: RefType) -> String {
    use wasmparser::{AbstractHeapType, HeapType};
    match ty.heap_type() {
        HeapType::Abstract { ty: aht, .. } => {
            let base: &str = match aht {
                AbstractHeapType::Func => "funcref",
                AbstractHeapType::Extern => "externref",
                AbstractHeapType::Any => "anyref",
                AbstractHeapType::Eq => "eqref",
                AbstractHeapType::Struct => "structref",
                AbstractHeapType::Array => "arrayref",
                AbstractHeapType::I31 => "i31ref",
                AbstractHeapType::None => "nullref",
                AbstractHeapType::NoFunc => "nullfuncref",
                AbstractHeapType::NoExtern => "nullexternref",
                _ => "funcref",
            };
            base.to_owned()
        }
        HeapType::Concrete(idx) | HeapType::Exact(idx) => idx.as_module_index().map_or_else(
            || "funcref".to_owned(),
            |i| {
                if ty.is_nullable() {
                    format!("(ref null $t{i})")
                } else {
                    format!("(ref $t{i})")
                }
            },
        ),
    }
}

fn const_f32(bits: u32) -> String {
    let v: f32 = f32::from_bits(bits);
    if v.is_nan() {
        "nan".to_owned()
    } else if v.is_infinite() {
        if v < 0.0 {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        }
    } else {
        format!("{v:?}")
    }
}

fn const_f64(bits: u64) -> String {
    let v: f64 = f64::from_bits(bits);
    if v.is_nan() {
        "nan".to_owned()
    } else if v.is_infinite() {
        if v < 0.0 {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        }
    } else {
        format!("{v:?}")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn lift(wat: &str) -> String {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("input wat parses");
        lift_module_faithful_wat(&bytes).expect("faithful lift produced output")
    }

    fn reassembles(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("lifted wat reassembles to wasm")
    }

    #[test]
    fn reproduces_global_with_real_init_and_reads_it() {
        const SRC: &str = r#"(module
            (global $g i32 (i32.const 42))
            (func (export "read") (result i32) global.get $g))"#;
        let out: String = lift(SRC);
        assert!(out.contains("(global $g0 i32 (i32.const 42))"), "{out}");
        assert!(out.contains("global.get $g0"), "{out}");
        let _: Vec<u8> = reassembles(&out);
    }

    #[test]
    fn reproduces_active_data_bytes_verbatim() {
        const SRC: &str = r#"(module
            (memory 1)
            (data (i32.const 8) "\01\02\fe\ff")
            (func (export "load") (result i32)
                i32.const 8 i32.load))"#;
        let out: String = lift(SRC);
        assert!(out.contains("(memory $m0 1)"), "{out}");
        assert!(out.contains("(memory 0) (i32.const 8)"), "{out}");
        assert!(out.contains("\\01\\02\\fe\\ff"), "{out}");
        let _: Vec<u8> = reassembles(&out);
    }

    #[test]
    fn reproduces_calls_between_defined_functions() {
        const SRC: &str = r#"(module
            (func $double (param i32) (result i32)
                local.get 0 local.get 0 i32.add)
            (func (export "quad") (param i32) (result i32)
                local.get 0 call $double call $double))"#;
        let out: String = lift(SRC);
        assert!(out.contains("call $f0"), "{out}");
        assert!(out.contains("(export \"quad\" (func $f1))"), "{out}");
        let _: Vec<u8> = reassembles(&out);
    }

    #[test]
    fn reproduces_func_import_declaration() {
        const SRC: &str = r#"(module
            (import "env" "log" (func $log (param i32)))
            (func (export "f") (param i32) (result i32)
                local.get 0 call $log local.get 0))"#;
        let out: String = lift(SRC);
        assert!(out.contains("(import \"env\" \"log\" (func $f0"), "{out}");
        assert!(out.contains("call $f0"), "{out}");
        let _: Vec<u8> = reassembles(&out);
    }

    #[test]
    fn reproduces_memory_maximum_and_export() {
        const SRC: &str = r#"(module
            (memory (export "mem") 2 16)
            (func (export "g") (result i32) i32.const 0 i32.load))"#;
        let out: String = lift(SRC);
        assert!(out.contains("(memory $m0 2 16)"), "{out}");
        assert!(out.contains("(export \"mem\" (memory $m0))"), "{out}");
        let _: Vec<u8> = reassembles(&out);
    }

    #[test]
    fn reproduces_table_with_active_elem() {
        const SRC: &str = r#"(module
            (table 4 funcref)
            (elem (i32.const 0) $a $b)
            (func $a (result i32) i32.const 1)
            (func $b (result i32) i32.const 2)
            (func (export "call") (param i32) (result i32)
                local.get 0 call_indirect (result i32)))"#;
        let out: String = lift(SRC);
        assert!(out.contains("(table $dr_tbl_func 4 funcref)"), "{out}");
        assert!(
            out.contains("(elem $e0 (table $dr_tbl_func) (i32.const 0) func $f0 $f1)"),
            "{out}"
        );
        let _: Vec<u8> = reassembles(&out);
    }

    #[test]
    fn reproduces_negative_i64_global() {
        const SRC: &str = r#"(module
            (global $g i64 (i64.const -7))
            (func (export "r") (result i64) global.get $g))"#;
        let out: String = lift(SRC);
        assert!(out.contains("(global $g0 i64 (i64.const -7))"), "{out}");
        let _: Vec<u8> = reassembles(&out);
    }
}
