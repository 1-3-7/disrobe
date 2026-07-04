use std::fmt::Arguments;

use wasmparser::{BlockType, Catch, FunctionBody, Operator, ValType};

use crate::lift::{LiftCoverage, LiftResult, LiftTarget};
use crate::op_names::operator_mnemonic;
use crate::signature::{FunctionSig, MAX_FUNCTION_LOCALS};
use crate::ssa::{binop_kind, unop_kind};

const LIFTED_STACK_POINTER_INIT: u32 = 65536;
const MAX_SYNTHETIC_STRUCT_FIELDS: u32 = 4096;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenderMode {
    SingleFunction,
    WholeModule,
}

#[must_use]
pub(crate) fn lift_function_body_wat(body: &FunctionBody<'_>, sig: &FunctionSig) -> LiftResult {
    let func: WatFunc = render_func(body, sig, 0, RenderMode::SingleFunction);
    let mut out: String = String::with_capacity(func.text.len() + 96);
    out.push_str(&module_prelude(&func.globals_used, &func.reqs));
    if func.has_calls {
        out.push_str("  (type $stub (func))\n");
    }
    emit_ref_func_targets(&mut out, &func.reqs);
    out.push_str(&func.text);
    if sig.exported {
        push_line!(out, "  (export \"{}\" (func $f0))", sig.name);
    }
    out.push_str(")\n");
    LiftResult {
        target: LiftTarget::Wat,
        pseudo_source: out,
        blocks_emitted: func.blocks_emitted,
        coverage: func.coverage,
    }
}

fn module_prelude(globals_used: &[(u32, ValType)], reqs: &FeatureReqs) -> String {
    let mut out: String = String::from("(module\n");
    emit_gc_type_decls(&mut out, reqs);
    emit_tag_decls(&mut out, reqs);
    let mut seen: Vec<u32> = Vec::new();
    let mut sorted: Vec<(u32, ValType)> = globals_used.to_vec();
    sorted.sort_by_key(|(idx, _)| *idx);
    for (idx, ty) in sorted {
        if seen.contains(&idx) {
            continue;
        }
        seen.push(idx);
        let t: String = val_type_str(ty);
        let init: String = match ty {
            ValType::I32 => format!("i32.const {LIFTED_STACK_POINTER_INIT}"),
            _ => format!("{t}.const 0"),
        };
        push_line!(out, "  (global $g{idx} (mut {t}) ({init}))");
    }
    let idx64: fn(&FeatureReqs, u32) -> &'static str =
        |r: &FeatureReqs, m: u32| if r.memory64.contains(&m) { "i64 " } else { "" };
    if reqs.shared_memory {
        push_line!(out, "  (memory $m0 {}1 16 shared)", idx64(reqs, 0));
    } else {
        push_line!(out, "  (memory $m0 {}1 16)", idx64(reqs, 0));
    }
    for mem in &reqs.extra_memories {
        push_line!(out, "  (memory $m{mem} {}1 16)", idx64(reqs, *mem));
    }
    out.push_str("  (table $dr_tbl_func 1 funcref)\n");
    if reqs.externref_table {
        out.push_str("  (table $dr_tbl_ext 1 externref)\n");
    }
    for seg in &reqs.data_segments {
        push_line!(out, "  (data $d{seg} \"\\00\\00\\00\\00\")");
    }
    for seg in &reqs.elem_segments {
        push_line!(out, "  (elem $e{seg} funcref)");
    }
    out
}

fn emit_gc_type_decls(mut out: &mut String, reqs: &FeatureReqs) {
    for (idx, field_count) in &reqs.struct_types {
        push_text!(out, "  (type $t{idx} (struct");
        let field_types: Option<&std::collections::BTreeMap<u32, ValType>> =
            reqs.struct_field_types.get(idx);
        for field in 0..(*field_count).max(1) {
            let ty: ValType = field_types
                .and_then(|m| m.get(&field))
                .copied()
                .unwrap_or(ValType::I32);
            push_text!(out, " (field (mut {}))", val_type_str(ty));
        }
        out.push_str("))\n");
    }
    for idx in &reqs.array_types {
        let elem: String = reqs
            .array_elem_types
            .get(idx)
            .map_or_else(|| "i32".to_owned(), |ty| val_type_str(*ty));
        push_line!(out, "  (type $t{idx} (array (mut {elem})))");
    }
    for (idx, (params, results)) in &reqs.func_types {
        push_text!(out, "  (type $t{idx} (func");
        for ty in params {
            push_text!(out, " (param {})", val_type_str(*ty));
        }
        for ty in results {
            push_text!(out, " (result {})", val_type_str(*ty));
        }
        out.push_str("))\n");
    }
    for (idx, func_type_index) in &reqs.cont_types {
        push_line!(out, "  (type $t{idx} (cont $t{func_type_index}))");
    }
}

fn emit_tag_decls(mut out: &mut String, reqs: &FeatureReqs) {
    for (idx, params) in &reqs.tags {
        push_text!(out, "  (tag $tag{idx} (param");
        for ty in params {
            push_text!(out, " {}", val_type_str(*ty));
        }
        out.push_str("))\n");
    }
}

fn emit_ref_func_targets(mut out: &mut String, reqs: &FeatureReqs) {
    if reqs.ref_func_indices.is_empty() {
        return;
    }
    for idx in &reqs.ref_func_indices {
        if let Some(type_index) = reqs.cont_func_targets.get(idx) {
            let empty: (Vec<ValType>, Vec<ValType>) = (Vec::new(), Vec::new());
            let (_, results): &(Vec<ValType>, Vec<ValType>) =
                reqs.func_types.get(type_index).unwrap_or(&empty);
            push_text!(out, "  (func $rf{idx} (type $t{type_index})");
            for ty in results {
                push_text!(out, " ({}.const 0)", val_type_str(*ty));
            }
            out.push_str(")\n");
        } else if let Some((t, (_, results))) = reqs.func_types.iter().next() {
            push_text!(out, "  (func $rf{idx} (type $t{t})");
            for ty in results {
                push_text!(out, " ({}.const 0)", val_type_str(*ty));
            }
            out.push_str(")\n");
        } else {
            push_line!(out, "  (func $rf{idx})");
        }
    }
    out.push_str("  (elem declare func");
    for idx in &reqs.ref_func_indices {
        push_text!(out, " $rf{idx}");
    }
    out.push_str(")\n");
}

#[must_use]
pub fn wat_module_header(globals_used: &[(u32, ValType)]) -> String {
    let mut out: String = String::from("(module\n");
    let mut seen: Vec<u32> = Vec::new();
    let mut sorted: Vec<(u32, ValType)> = globals_used.to_vec();
    sorted.sort_by_key(|(idx, _)| *idx);
    for (idx, ty) in sorted {
        if seen.contains(&idx) {
            continue;
        }
        seen.push(idx);
        let t: String = val_type_str(ty);
        push_line!(out, "  (global $g{idx} (mut {t}) ({t}.const 0))");
    }
    out.push_str("  (memory 1)\n");
    out.push_str("  (table 1 funcref)\n");
    out
}

pub(crate) struct WatFunc {
    pub(crate) text: String,
    pub(crate) globals_used: Vec<(u32, ValType)>,
    pub(crate) blocks_emitted: usize,
    pub(crate) has_calls: bool,
    pub(crate) coverage: LiftCoverage,
    pub(crate) reqs: FeatureReqs,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct FeatureReqs {
    shared_memory: bool,
    memory64: std::collections::BTreeSet<u32>,
    extra_memories: std::collections::BTreeSet<u32>,
    data_segments: std::collections::BTreeSet<u32>,
    elem_segments: std::collections::BTreeSet<u32>,
    funcref_table: bool,
    externref_table: bool,
    ref_func_indices: std::collections::BTreeSet<u32>,
    tags: std::collections::BTreeMap<u32, Vec<ValType>>,
    struct_types: std::collections::BTreeMap<u32, u32>,
    struct_field_types: std::collections::BTreeMap<u32, std::collections::BTreeMap<u32, ValType>>,
    array_types: std::collections::BTreeSet<u32>,
    array_elem_types: std::collections::BTreeMap<u32, ValType>,
    func_types: std::collections::BTreeMap<u32, (Vec<ValType>, Vec<ValType>)>,
    cont_types: std::collections::BTreeMap<u32, u32>,
    cont_func_targets: std::collections::BTreeMap<u32, u32>,
}

impl FeatureReqs {
    pub(crate) const fn ref_func_indices(&self) -> &std::collections::BTreeSet<u32> {
        &self.ref_func_indices
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        self.shared_memory |= other.shared_memory;
        self.memory64.extend(&other.memory64);
        self.extra_memories.extend(&other.extra_memories);
        self.funcref_table |= other.funcref_table;
        self.externref_table |= other.externref_table;
        self.data_segments.extend(&other.data_segments);
        self.elem_segments.extend(&other.elem_segments);
        self.ref_func_indices.extend(&other.ref_func_indices);
        for (idx, params) in &other.tags {
            self.tags.entry(*idx).or_insert_with(|| params.clone());
        }
        for (idx, fields) in &other.struct_types {
            let entry: &mut u32 = self.struct_types.entry(*idx).or_default();
            *entry = (*entry).max(*fields);
        }
        for (idx, fields) in &other.struct_field_types {
            let entry: &mut std::collections::BTreeMap<u32, ValType> =
                self.struct_field_types.entry(*idx).or_default();
            for (field, ty) in fields {
                entry.entry(*field).or_insert(*ty);
            }
        }
        self.array_types.extend(&other.array_types);
        for (idx, elem) in &other.array_elem_types {
            self.array_elem_types.entry(*idx).or_insert(*elem);
        }
        for (idx, sig) in &other.func_types {
            self.func_types.entry(*idx).or_insert_with(|| sig.clone());
        }
        for (idx, func_idx) in &other.cont_types {
            self.cont_types.entry(*idx).or_insert(*func_idx);
        }
        for (idx, type_idx) in &other.cont_func_targets {
            self.cont_func_targets.entry(*idx).or_insert(*type_idx);
        }
    }

    fn record_func_type(&mut self, idx: u32) {
        self.func_types
            .entry(idx)
            .or_insert_with(|| (vec![ValType::I32], vec![ValType::I32]));
    }

    fn note_memory(&mut self, idx: u32) {
        if idx != 0 {
            self.extra_memories.insert(idx);
        }
    }

    fn record_cont_type(&mut self, cont_type_index: u32) -> u32 {
        let func_type_index: u32 = fallback_cont_func_type_index(cont_type_index);
        self.func_types
            .entry(func_type_index)
            .or_insert_with(|| (Vec::new(), Vec::new()));
        self.cont_types
            .entry(cont_type_index)
            .or_insert(func_type_index);
        func_type_index
    }

    fn record_struct_field_index(&mut self, struct_type_index: u32, field_index: u32) -> bool {
        let Some(field_count): Option<u32> = field_index.checked_add(1) else {
            return false;
        };
        if field_count > MAX_SYNTHETIC_STRUCT_FIELDS {
            return false;
        }
        self.record_struct_field_count(struct_type_index, field_count);
        true
    }

    fn record_struct_field_count(&mut self, struct_type_index: u32, field_count: u32) {
        let bounded: u32 = field_count.clamp(1, MAX_SYNTHETIC_STRUCT_FIELDS);
        let entry: &mut u32 = self.struct_types.entry(struct_type_index).or_default();
        *entry = (*entry).max(bounded);
    }
}

const fn fallback_cont_func_type_index(cont_type_index: u32) -> u32 {
    match cont_type_index.checked_sub(1) {
        Some(index) => index,
        None => 1,
    }
}

#[must_use]
pub fn lift_module_to_wat(
    funcs: &[(FunctionBody<'_>, FunctionSig)],
    defined_offset: u32,
) -> String {
    let mut globals: Vec<(u32, ValType)> = Vec::new();
    let mut bodies: String = String::new();
    let mut exports: String = String::new();
    let mut imports: String = String::new();
    let total: u32 = defined_offset.saturating_add(u32::try_from(funcs.len()).unwrap_or(u32::MAX));

    for i in 0..defined_offset {
        push_line!(
            imports,
            "  (func $f{i} (param i32) (result i32) i32.const 0)"
        );
    }
    let mut module_sigs: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
    for _ in 0..defined_offset {
        module_sigs.push((vec![ValType::I32], vec![ValType::I32]));
    }
    for (_, sig) in funcs {
        module_sigs.push((sig.params.clone(), sig.results.clone()));
    }
    let mut reqs: FeatureReqs = FeatureReqs::default();
    for (offset, (body, sig)) in funcs.iter().enumerate() {
        let global_index: u32 =
            defined_offset.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX));
        let f: WatFunc = render_func_in_module(
            body,
            sig,
            global_index,
            RenderMode::WholeModule,
            &module_sigs,
            &[],
        );
        for g in f.globals_used {
            if !globals.iter().any(|(i, _)| *i == g.0) {
                globals.push(g);
            }
        }
        reqs.merge(&f.reqs);
        bodies.push_str(&f.text);
        if sig.exported {
            push_line!(
                exports,
                "  (export \"{}\" (func $f{global_index}))",
                sig.name
            );
        }
    }
    let _ = total;
    let mut out: String = module_prelude(&globals, &reqs);
    out.push_str(&imports);
    emit_elem_declare_for_real_funcs(&mut out, &reqs);
    out.push_str(&bodies);
    out.push_str(&exports);
    out.push_str(")\n");
    out
}

fn emit_elem_declare_for_real_funcs(mut out: &mut String, reqs: &FeatureReqs) {
    if reqs.ref_func_indices.is_empty() {
        return;
    }
    out.push_str("  (elem declare func");
    for idx in &reqs.ref_func_indices {
        push_text!(out, " $f{idx}");
    }
    out.push_str(")\n");
}

fn render_func(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    func_index: u32,
    mode: RenderMode,
) -> WatFunc {
    render_func_in_module(body, sig, func_index, mode, &[], &[])
}

pub(crate) fn render_func_in_module(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    func_index: u32,
    mode: RenderMode,
    module_sigs: &[(Vec<ValType>, Vec<ValType>)],
    block_func_types: &[(Vec<ValType>, Vec<ValType>)],
) -> WatFunc {
    let mut text: String = String::with_capacity(256);
    push_text!(text, "  (func $f{func_index}");
    for (i, ty) in sig.params.iter().enumerate() {
        push_text!(text, " (param $p{i} {})", val_type_str(*ty));
    }
    if let Some(ret) = sig.results.first() {
        push_text!(text, " (result {})", val_type_str(*ret));
    }
    text.push('\n');

    let locals: Vec<ValType> = read_local_decls(body).unwrap_or_default();
    let param_count: usize = sig.params.len();
    for (i, ty) in locals.iter().enumerate() {
        push_line!(
            text,
            "    (local $l{} {})",
            param_count + i,
            val_type_str(*ty)
        );
    }

    let mut globals_used: Vec<(u32, ValType)> = Vec::new();
    let mut blocks_emitted: usize = 1;
    let mut has_calls: bool = false;
    let mut coverage: LiftCoverage = LiftCoverage::default();
    let mut reqs: FeatureReqs = FeatureReqs::default();
    if render_operators(
        body,
        sig,
        &mut text,
        &mut globals_used,
        &mut blocks_emitted,
        &mut has_calls,
        &mut coverage,
        &mut reqs,
        mode,
        module_sigs,
        block_func_types,
    )
    .is_err()
    {
        coverage.record_untranslated("<operator-decode-failure>");
        text.push_str("    unreachable\n");
    }
    text.push_str("  )\n");
    WatFunc {
        text,
        globals_used,
        blocks_emitted,
        has_calls,
        coverage,
        reqs,
    }
}

fn read_local_decls(body: &FunctionBody<'_>) -> Result<Vec<ValType>, ()> {
    let reader: wasmparser::LocalsReader<'_> = body.get_locals_reader().map_err(|_| ())?;
    let mut out: Vec<ValType> = Vec::new();
    for item in reader {
        let (count, ty): (u32, ValType) = item.map_err(|_| ())?;
        let remaining: usize = MAX_FUNCTION_LOCALS.saturating_sub(out.len());
        let take: usize = (count as usize).min(remaining);
        out.extend(std::iter::repeat_n(ty, take));
        if out.len() >= MAX_FUNCTION_LOCALS {
            break;
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn render_operators(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    mut out: &mut String,
    globals_used: &mut Vec<(u32, ValType)>,
    blocks_emitted: &mut usize,
    has_calls: &mut bool,
    coverage: &mut LiftCoverage,
    reqs: &mut FeatureReqs,
    mode: RenderMode,
    module_sigs: &[(Vec<ValType>, Vec<ValType>)],
    block_func_types: &[(Vec<ValType>, Vec<ValType>)],
) -> Result<(), ()> {
    let reader: wasmparser::OperatorsReader<'_> = body.get_operators_reader().map_err(|_| ())?;
    let mut ops: Vec<Operator<'_>> = Vec::new();
    for op in reader {
        ops.push(op.map_err(|_| ())?);
    }
    let mut local_types: Vec<ValType> = sig.params.clone();
    local_types.extend(read_local_decls(body).unwrap_or_default());
    prescan_memory64(&ops, sig, &local_types, reqs);
    prescan_struct_arities(&ops, &local_types, reqs);
    prescan_br_on_cast_types(&ops, reqs);
    prescan_array_elem_types(&ops, &local_types, reqs);
    prescan_tag_arities(&ops, &local_types, reqs);
    prescan_catch_tags(&ops, sig, reqs);
    prescan_cont_func_targets(&ops, reqs);
    prescan_signature_ref_types(sig, reqs);
    if matches!(mode, RenderMode::WholeModule) {
        prescan_callref_func_types(&ops, module_sigs, reqs);
    }
    let op_count: usize = ops.len();
    let mut depth: usize = 2;
    for (i, op) in ops.iter().enumerate() {
        let is_final_end: bool = i + 1 == op_count && matches!(op, Operator::End);
        if is_final_end {
            break;
        }
        if matches!(
            op,
            Operator::End
                | Operator::Else
                | Operator::Catch { .. }
                | Operator::CatchAll
                | Operator::Delegate { .. }
        ) {
            depth = depth.saturating_sub(1);
        }
        let rendered: Rendered = render_op(
            op,
            sig,
            globals_used,
            blocks_emitted,
            has_calls,
            reqs,
            mode,
            block_func_types,
        );
        match rendered {
            Rendered::Translated(Some(line)) => {
                coverage.record_translated();
                let pad: String = "  ".repeat(depth);
                push_line!(out, "{pad}{line}");
            }
            Rendered::Translated(None) => coverage.record_translated(),
            Rendered::Untranslated => {
                coverage.record_untranslated(operator_mnemonic(op));
                let pad: String = "  ".repeat(depth);
                push_line!(out, "{pad}unreachable");
            }
        }
        if matches!(
            op,
            Operator::Block { .. }
                | Operator::Loop { .. }
                | Operator::If { .. }
                | Operator::Else
                | Operator::TryTable { .. }
                | Operator::Try { .. }
                | Operator::Catch { .. }
                | Operator::CatchAll
        ) {
            depth += 1;
        }
    }
    Ok(())
}

fn prescan_memory64(
    ops: &[Operator<'_>],
    sig: &FunctionSig,
    local_types: &[ValType],
    reqs: &mut FeatureReqs,
) {
    for (i, op) in ops.iter().enumerate() {
        if let Some((mem, addr_depth)) = memory_addressed_op(op) {
            if addr_operand_is_i64(ops, i, addr_depth, local_types) {
                reqs.memory64.insert(mem);
            }
            continue;
        }
        match op {
            Operator::MemorySize { mem } | Operator::MemoryGrow { mem } => {
                if memory_index_result_is_i64(sig) {
                    reqs.memory64.insert(*mem);
                }
            }
            _ => {}
        }
    }
}

const fn memory_addressed_op(op: &Operator<'_>) -> Option<(u32, usize)> {
    let (memarg, addr_depth): (wasmparser::MemArg, usize) = match op {
        Operator::I32Load { memarg }
        | Operator::I64Load { memarg }
        | Operator::F32Load { memarg }
        | Operator::F64Load { memarg }
        | Operator::I32Load8U { memarg }
        | Operator::I32Load8S { memarg }
        | Operator::I32Load16U { memarg }
        | Operator::I32Load16S { memarg }
        | Operator::I64Load8U { memarg }
        | Operator::I64Load8S { memarg }
        | Operator::I64Load16U { memarg }
        | Operator::I64Load16S { memarg }
        | Operator::I64Load32U { memarg }
        | Operator::I64Load32S { memarg }
        | Operator::V128Load { memarg } => (*memarg, 0),
        Operator::I32Store { memarg }
        | Operator::I64Store { memarg }
        | Operator::F32Store { memarg }
        | Operator::F64Store { memarg }
        | Operator::I32Store8 { memarg }
        | Operator::I32Store16 { memarg }
        | Operator::I64Store8 { memarg }
        | Operator::I64Store16 { memarg }
        | Operator::I64Store32 { memarg }
        | Operator::V128Store { memarg } => (*memarg, 1),
        _ => return None,
    };
    Some((memarg.memory, addr_depth))
}

fn addr_operand_is_i64(
    ops: &[Operator<'_>],
    op_idx: usize,
    addr_depth: usize,
    local_types: &[ValType],
) -> bool {
    let mut cursor: usize = op_idx;
    let mut skipped: usize = 0;
    while cursor > 0 {
        cursor -= 1;
        let Some(ty): Option<ValType> = value_type_of(&ops[cursor], local_types) else {
            return false;
        };
        if skipped == addr_depth {
            return ty == ValType::I64;
        }
        skipped += 1;
    }
    false
}

fn memory_index_result_is_i64(sig: &FunctionSig) -> bool {
    matches!(sig.results.first(), Some(ValType::I64))
}

fn prescan_struct_arities(ops: &[Operator<'_>], local_types: &[ValType], reqs: &mut FeatureReqs) {
    for (i, op) in ops.iter().enumerate() {
        match op {
            Operator::StructNew { struct_type_index } => {
                let arity: u32 = preceding_value_run(ops, i);
                reqs.record_struct_field_count(*struct_type_index, arity);
                record_struct_new_field_types(ops, i, arity, *struct_type_index, local_types, reqs);
            }
            Operator::StructNewDefault { struct_type_index } => {
                reqs.struct_types.entry(*struct_type_index).or_insert(1);
            }
            Operator::StructGet {
                struct_type_index,
                field_index,
            }
            | Operator::StructGetS {
                struct_type_index,
                field_index,
            }
            | Operator::StructGetU {
                struct_type_index,
                field_index,
            }
            | Operator::StructSet {
                struct_type_index,
                field_index,
            } => {
                let field_index_is_bounded: bool =
                    reqs.record_struct_field_index(*struct_type_index, *field_index);
                if let Operator::StructSet {
                    struct_type_index,
                    field_index,
                } = op
                {
                    if field_index_is_bounded && let Some(cursor) = i.checked_sub(1) {
                        if let Some(ty) = value_type_of(&ops[cursor], local_types) {
                            reqs.struct_field_types
                                .entry(*struct_type_index)
                                .or_default()
                                .entry(*field_index)
                                .or_insert(ty);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn record_struct_new_field_types(
    ops: &[Operator<'_>],
    new_idx: usize,
    arity: u32,
    type_index: u32,
    local_types: &[ValType],
    reqs: &mut FeatureReqs,
) {
    let count: usize = arity.min(MAX_SYNTHETIC_STRUCT_FIELDS) as usize;
    let Some(start): Option<usize> = new_idx.checked_sub(count) else {
        return;
    };
    for offset in 0..count {
        let Some(ty): Option<ValType> = value_type_of(&ops[start + offset], local_types) else {
            continue;
        };
        let field: u32 = u32::try_from(offset).unwrap_or(u32::MAX);
        reqs.struct_field_types
            .entry(type_index)
            .or_default()
            .entry(field)
            .or_insert(ty);
    }
}

fn prescan_cont_func_targets(ops: &[Operator<'_>], reqs: &mut FeatureReqs) {
    for (i, op) in ops.iter().enumerate() {
        let Operator::ContNew { cont_type_index } = op else {
            continue;
        };
        let func_type_index: u32 = fallback_cont_func_type_index(*cont_type_index);
        let mut cursor: usize = i;
        while cursor > 0 {
            cursor -= 1;
            if let Operator::RefFunc { function_index } = ops[cursor] {
                reqs.cont_func_targets
                    .entry(function_index)
                    .or_insert(func_type_index);
                break;
            }
            if !produces_one_value(&ops[cursor]) {
                break;
            }
        }
    }
}

fn prescan_callref_func_types(
    ops: &[Operator<'_>],
    module_sigs: &[(Vec<ValType>, Vec<ValType>)],
    reqs: &mut FeatureReqs,
) {
    for (i, op) in ops.iter().enumerate() {
        let type_index: u32 = match op {
            Operator::CallRef { type_index } | Operator::ReturnCallRef { type_index } => {
                *type_index
            }
            _ => continue,
        };
        let Some(func_index): Option<u32> = preceding_ref_func(ops, i) else {
            continue;
        };
        let Some((params, results)): Option<&(Vec<ValType>, Vec<ValType>)> =
            module_sigs.get(func_index as usize)
        else {
            continue;
        };
        reqs.func_types
            .insert(type_index, (params.clone(), results.clone()));
    }
}

fn preceding_ref_func(ops: &[Operator<'_>], call_idx: usize) -> Option<u32> {
    let mut cursor: usize = call_idx;
    while cursor > 0 {
        cursor -= 1;
        if let Operator::RefFunc { function_index } = ops[cursor] {
            return Some(function_index);
        }
        if !produces_one_value(&ops[cursor]) {
            return None;
        }
    }
    None
}

fn prescan_signature_ref_types(sig: &FunctionSig, reqs: &mut FeatureReqs) {
    for ty in sig.params.iter().chain(sig.results.iter()) {
        let ValType::Ref(r) = ty else {
            continue;
        };
        if let wasmparser::HeapType::Concrete(idx) = r.heap_type() {
            if let Some(i) = idx.as_module_index() {
                if !reqs.array_types.contains(&i) && !reqs.func_types.contains_key(&i) {
                    reqs.struct_types.entry(i).or_insert(1);
                }
            }
        }
    }
}

fn prescan_br_on_cast_types(ops: &[Operator<'_>], reqs: &mut FeatureReqs) {
    for op in ops {
        let refs: [wasmparser::RefType; 2] = match op {
            Operator::BrOnCast {
                from_ref_type,
                to_ref_type,
                ..
            }
            | Operator::BrOnCastFail {
                from_ref_type,
                to_ref_type,
                ..
            } => [*from_ref_type, *to_ref_type],
            _ => continue,
        };
        for r in refs {
            if let wasmparser::HeapType::Concrete(idx) = r.heap_type() {
                if let Some(i) = idx.as_module_index() {
                    if !reqs.array_types.contains(&i) && !reqs.func_types.contains_key(&i) {
                        reqs.struct_types.entry(i).or_insert(1);
                    }
                }
            }
        }
    }
}

fn prescan_array_elem_types(ops: &[Operator<'_>], local_types: &[ValType], reqs: &mut FeatureReqs) {
    for (i, op) in ops.iter().enumerate() {
        let (idx, elem_offset): (u32, usize) = match op {
            Operator::ArrayNew { array_type_index } => (*array_type_index, 2),
            Operator::ArrayNewFixed {
                array_type_index, ..
            } => (*array_type_index, 1),
            _ => continue,
        };
        reqs.array_types.insert(idx);
        let Some(cursor): Option<usize> = i.checked_sub(elem_offset) else {
            continue;
        };
        if let Some(ty) = value_type_of(&ops[cursor], local_types) {
            reqs.array_elem_types.entry(idx).or_insert(ty);
        }
    }
}

fn prescan_tag_arities(ops: &[Operator<'_>], local_types: &[ValType], reqs: &mut FeatureReqs) {
    for (i, op) in ops.iter().enumerate() {
        let Operator::Throw { tag_index } = op else {
            continue;
        };
        let params: Vec<ValType> = preceding_value_types(ops, i, local_types);
        reqs.tags.entry(*tag_index).or_insert(params);
    }
}

fn prescan_catch_tags(ops: &[Operator<'_>], sig: &FunctionSig, reqs: &mut FeatureReqs) {
    let mut frames: Vec<Vec<ValType>> = vec![sig.results.clone()];
    for op in ops {
        match op {
            Operator::Block { blockty } | Operator::Loop { blockty } | Operator::If { blockty } => {
                frames.push(block_result_types(*blockty));
            }
            Operator::TryTable { try_table } => {
                for catch in &try_table.catches {
                    if let Catch::One { tag, label } | Catch::OneRef { tag, label } = catch {
                        let from_top: usize = *label as usize;
                        let resolved: Vec<ValType> = frames
                            .len()
                            .checked_sub(from_top + 1)
                            .and_then(|idx| frames.get(idx))
                            .cloned()
                            .unwrap_or_default();
                        reqs.tags.entry(*tag).or_insert(resolved);
                    }
                }
                frames.push(block_result_types(try_table.ty));
            }
            Operator::Try { blockty } => {
                frames.push(block_result_types(*blockty));
            }
            Operator::Catch { tag_index } => {
                reqs.tags.entry(*tag_index).or_default();
            }
            Operator::Delegate { .. } => {
                frames.pop();
            }
            Operator::End => {
                frames.pop();
            }
            _ => {}
        }
    }
}

fn block_result_types(blockty: BlockType) -> Vec<ValType> {
    match blockty {
        BlockType::Empty | BlockType::FuncType(_) => Vec::new(),
        BlockType::Type(t) => vec![t],
    }
}

fn preceding_value_types(
    ops: &[Operator<'_>],
    idx: usize,
    local_types: &[ValType],
) -> Vec<ValType> {
    let mut types: Vec<ValType> = Vec::new();
    let mut cursor: usize = idx;
    while cursor > 0 {
        cursor -= 1;
        match value_type_of(&ops[cursor], local_types) {
            Some(ty) => types.push(ty),
            None => break,
        }
    }
    types.reverse();
    types
}

fn value_type_of(op: &Operator<'_>, local_types: &[ValType]) -> Option<ValType> {
    match op {
        Operator::I32Const { .. } => Some(ValType::I32),
        Operator::I64Const { .. } => Some(ValType::I64),
        Operator::F32Const { .. } => Some(ValType::F32),
        Operator::F64Const { .. } => Some(ValType::F64),
        Operator::V128Const { .. } => Some(ValType::V128),
        Operator::LocalGet { local_index } => local_types.get(*local_index as usize).copied(),
        _ => None,
    }
}

fn preceding_value_run(ops: &[Operator<'_>], idx: usize) -> u32 {
    let mut count: u32 = 0;
    let mut cursor: usize = idx;
    while cursor > 0 {
        cursor -= 1;
        if produces_one_value(&ops[cursor]) {
            count += 1;
        } else {
            break;
        }
    }
    count
}

const fn produces_one_value(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::I32Const { .. }
            | Operator::I64Const { .. }
            | Operator::F32Const { .. }
            | Operator::F64Const { .. }
            | Operator::V128Const { .. }
            | Operator::LocalGet { .. }
            | Operator::GlobalGet { .. }
            | Operator::RefNull { .. }
            | Operator::RefFunc { .. }
            | Operator::RefI31
    )
}

enum Rendered {
    Translated(Option<String>),
    Untranslated,
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn render_op(
    op: &Operator<'_>,
    sig: &FunctionSig,
    globals_used: &mut Vec<(u32, ValType)>,
    blocks_emitted: &mut usize,
    has_calls: &mut bool,
    reqs: &mut FeatureReqs,
    mode: RenderMode,
    block_func_types: &[(Vec<ValType>, Vec<ValType>)],
) -> Rendered {
    if let Some((kind, _)) = binop_kind(op) {
        return Rendered::Translated(Some(op_mnemonic(kind).to_owned()));
    }
    if let Some((unop, _)) = unop_kind(op) {
        return Rendered::Translated(Some(unop_mnemonic(unop).to_owned()));
    }
    if let Some(line) = render_mem_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_simd_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_atomic_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_bulk_memory_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_table_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_ref_op(op, reqs, mode) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_gc_op(op, has_calls, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_exception_op(op, blocks_emitted, block_func_types) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_stack_switching_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_extended_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    let line: String = match op {
        Operator::Nop => return Rendered::Translated(None),
        Operator::Unreachable => "unreachable".to_owned(),
        Operator::Return => "return".to_owned(),
        Operator::Drop => "drop".to_owned(),
        Operator::Select | Operator::TypedSelect { .. } => "select".to_owned(),
        Operator::Block { blockty } => {
            *blocks_emitted += 1;
            format!("block{}", block_type_suffix(*blockty, block_func_types))
        }
        Operator::Loop { blockty } => {
            *blocks_emitted += 1;
            format!("loop{}", block_type_suffix(*blockty, block_func_types))
        }
        Operator::If { blockty } => {
            *blocks_emitted += 1;
            format!("if{}", block_type_suffix(*blockty, block_func_types))
        }
        Operator::Else => "else".to_owned(),
        Operator::End => "end".to_owned(),
        Operator::Br { relative_depth } => format!("br {relative_depth}"),
        Operator::BrIf { relative_depth } => format!("br_if {relative_depth}"),
        Operator::BrTable { targets } => match render_br_table(targets) {
            Ok(s) => s,
            Err(()) => return Rendered::Untranslated,
        },
        Operator::Call { function_index } => {
            *has_calls = true;
            format!("call $f{function_index}")
        }
        Operator::CallIndirect { type_index, .. } => {
            *has_calls = true;
            format!("call_indirect (type {type_index})")
        }
        Operator::ReturnCall { function_index } => {
            *has_calls = true;
            format!("return_call $f{function_index}")
        }
        Operator::ReturnCallIndirect { type_index, .. } => {
            *has_calls = true;
            format!("return_call_indirect (type {type_index})")
        }
        Operator::LocalGet { local_index } => {
            format!("local.get ${}", local_ref(*local_index, sig))
        }
        Operator::LocalSet { local_index } => {
            format!("local.set ${}", local_ref(*local_index, sig))
        }
        Operator::LocalTee { local_index } => {
            format!("local.tee ${}", local_ref(*local_index, sig))
        }
        Operator::GlobalGet { global_index } => {
            note_global(*global_index, globals_used);
            format!("global.get $g{global_index}")
        }
        Operator::GlobalSet { global_index } => {
            note_global(*global_index, globals_used);
            format!("global.set $g{global_index}")
        }
        Operator::I32Const { value } => format!("i32.const {value}"),
        Operator::I64Const { value } => format!("i64.const {value}"),
        Operator::F32Const { value } => {
            format!("f32.const {}", wat_f32(f32::from_bits(value.bits())))
        }
        Operator::F64Const { value } => {
            format!("f64.const {}", wat_f64(f64::from_bits(value.bits())))
        }
        Operator::MemorySize { mem } => {
            reqs.note_memory(*mem);
            format!("memory.size{}", memory_operand(*mem))
        }
        Operator::MemoryGrow { mem } => {
            reqs.note_memory(*mem);
            format!("memory.grow{}", memory_operand(*mem))
        }
        _ => return Rendered::Untranslated,
    };
    Rendered::Translated(Some(line))
}

fn render_br_table(targets: &wasmparser::BrTable<'_>) -> Result<String, ()> {
    let mut s: String = String::from("br_table");
    for tgt in targets.targets() {
        let depth: u32 = tgt.map_err(|_| ())?;
        push_text!(s, " {depth}");
    }
    push_text!(s, " {}", targets.default());
    Ok(s)
}

fn memory_operand(memory: u32) -> String {
    if memory == 0 {
        String::new()
    } else {
        format!(" $m{memory}")
    }
}

fn memarg_align_bytes(align: u32) -> u64 {
    1u64.checked_shl(align).unwrap_or(1u64 << 63)
}

fn format_memarg(mnemonic: &str, memarg: wasmparser::MemArg, reqs: &mut FeatureReqs) -> String {
    reqs.note_memory(memarg.memory);
    format!(
        "{mnemonic}{} offset={} align={}",
        memory_operand(memarg.memory),
        memarg.offset,
        memarg_align_bytes(u32::from(memarg.align))
    )
}

fn render_mem_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    let (mnemonic, memarg): (&str, wasmparser::MemArg) = match op {
        Operator::I32Load { memarg } => ("i32.load", *memarg),
        Operator::I64Load { memarg } => ("i64.load", *memarg),
        Operator::F32Load { memarg } => ("f32.load", *memarg),
        Operator::F64Load { memarg } => ("f64.load", *memarg),
        Operator::I32Load8U { memarg } => ("i32.load8_u", *memarg),
        Operator::I32Load8S { memarg } => ("i32.load8_s", *memarg),
        Operator::I32Load16U { memarg } => ("i32.load16_u", *memarg),
        Operator::I32Load16S { memarg } => ("i32.load16_s", *memarg),
        Operator::I64Load8U { memarg } => ("i64.load8_u", *memarg),
        Operator::I64Load8S { memarg } => ("i64.load8_s", *memarg),
        Operator::I64Load16U { memarg } => ("i64.load16_u", *memarg),
        Operator::I64Load16S { memarg } => ("i64.load16_s", *memarg),
        Operator::I64Load32U { memarg } => ("i64.load32_u", *memarg),
        Operator::I64Load32S { memarg } => ("i64.load32_s", *memarg),
        Operator::I32Store { memarg } => ("i32.store", *memarg),
        Operator::I64Store { memarg } => ("i64.store", *memarg),
        Operator::F32Store { memarg } => ("f32.store", *memarg),
        Operator::F64Store { memarg } => ("f64.store", *memarg),
        Operator::I32Store8 { memarg } => ("i32.store8", *memarg),
        Operator::I32Store16 { memarg } => ("i32.store16", *memarg),
        Operator::I64Store8 { memarg } => ("i64.store8", *memarg),
        Operator::I64Store16 { memarg } => ("i64.store16", *memarg),
        Operator::I64Store32 { memarg } => ("i64.store32", *memarg),
        _ => return None,
    };
    Some(format_memarg(mnemonic, memarg, reqs))
}

fn render_simd_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    if let Some((mnemonic, memarg)) = simd_mem_mnemonic(op) {
        return Some(format_memarg(mnemonic, memarg, reqs));
    }
    if let Some((mnemonic, memarg, lane)) = simd_lane_mem_mnemonic(op) {
        reqs.note_memory(memarg.memory);
        return Some(format!(
            "{mnemonic}{} offset={} align={} {lane}",
            memory_operand(memarg.memory),
            memarg.offset,
            memarg_align_bytes(u32::from(memarg.align))
        ));
    }
    Some(match op {
        Operator::V128Const { value } => {
            let mut s: String = String::from("v128.const i8x16");
            for byte in value.bytes() {
                push_text!(s, " {byte}");
            }
            s
        }
        Operator::I8x16Shuffle { lanes } => {
            let mut s: String = String::from("i8x16.shuffle");
            for lane in lanes {
                push_text!(s, " {lane}");
            }
            s
        }
        Operator::I8x16Splat => "i8x16.splat".to_owned(),
        Operator::I16x8Splat => "i16x8.splat".to_owned(),
        Operator::I32x4Splat => "i32x4.splat".to_owned(),
        Operator::I64x2Splat => "i64x2.splat".to_owned(),
        Operator::F32x4Splat => "f32x4.splat".to_owned(),
        Operator::F64x2Splat => "f64x2.splat".to_owned(),
        Operator::I8x16Add => "i8x16.add".to_owned(),
        Operator::I8x16Sub => "i8x16.sub".to_owned(),
        Operator::I16x8Add => "i16x8.add".to_owned(),
        Operator::I32x4Add => "i32x4.add".to_owned(),
        Operator::I32x4Mul => "i32x4.mul".to_owned(),
        Operator::I64x2Add => "i64x2.add".to_owned(),
        Operator::F32x4Add => "f32x4.add".to_owned(),
        Operator::F32x4Mul => "f32x4.mul".to_owned(),
        Operator::F64x2Add => "f64x2.add".to_owned(),
        Operator::I8x16Swizzle => "i8x16.swizzle".to_owned(),
        Operator::V128Not => "v128.not".to_owned(),
        Operator::V128And => "v128.and".to_owned(),
        Operator::V128Or => "v128.or".to_owned(),
        Operator::V128Xor => "v128.xor".to_owned(),
        Operator::V128Bitselect => "v128.bitselect".to_owned(),
        Operator::F32x4RelaxedMadd => "f32x4.relaxed_madd".to_owned(),
        Operator::F32x4RelaxedNmadd => "f32x4.relaxed_nmadd".to_owned(),
        Operator::F64x2RelaxedMadd => "f64x2.relaxed_madd".to_owned(),
        Operator::F64x2RelaxedNmadd => "f64x2.relaxed_nmadd".to_owned(),
        Operator::I8x16RelaxedSwizzle => "i8x16.relaxed_swizzle".to_owned(),
        _ => return render_simd_generic(op),
    })
}

#[allow(clippy::too_many_lines)]
fn render_simd_generic(op: &Operator<'_>) -> Option<String> {
    Some(match op {
        Operator::F32x4ExtractLane { lane } => format!("f32x4.extract_lane {lane}"),
        Operator::F32x4ReplaceLane { lane } => format!("f32x4.replace_lane {lane}"),
        Operator::F64x2ExtractLane { lane } => format!("f64x2.extract_lane {lane}"),
        Operator::F64x2ReplaceLane { lane } => format!("f64x2.replace_lane {lane}"),
        Operator::I16x8ExtractLaneS { lane } => format!("i16x8.extract_lane_s {lane}"),
        Operator::I16x8ExtractLaneU { lane } => format!("i16x8.extract_lane_u {lane}"),
        Operator::I16x8ReplaceLane { lane } => format!("i16x8.replace_lane {lane}"),
        Operator::I32x4ExtractLane { lane } => format!("i32x4.extract_lane {lane}"),
        Operator::I32x4ReplaceLane { lane } => format!("i32x4.replace_lane {lane}"),
        Operator::I64x2ExtractLane { lane } => format!("i64x2.extract_lane {lane}"),
        Operator::I64x2ReplaceLane { lane } => format!("i64x2.replace_lane {lane}"),
        Operator::I8x16ExtractLaneS { lane } => format!("i8x16.extract_lane_s {lane}"),
        Operator::I8x16ExtractLaneU { lane } => format!("i8x16.extract_lane_u {lane}"),
        Operator::I8x16ReplaceLane { lane } => format!("i8x16.replace_lane {lane}"),
        Operator::I8x16Eq => "i8x16.eq".to_owned(),
        Operator::I8x16Ne => "i8x16.ne".to_owned(),
        Operator::I8x16LtS => "i8x16.lt_s".to_owned(),
        Operator::I8x16LtU => "i8x16.lt_u".to_owned(),
        Operator::I8x16GtS => "i8x16.gt_s".to_owned(),
        Operator::I8x16GtU => "i8x16.gt_u".to_owned(),
        Operator::I8x16LeS => "i8x16.le_s".to_owned(),
        Operator::I8x16LeU => "i8x16.le_u".to_owned(),
        Operator::I8x16GeS => "i8x16.ge_s".to_owned(),
        Operator::I8x16GeU => "i8x16.ge_u".to_owned(),
        Operator::I16x8Eq => "i16x8.eq".to_owned(),
        Operator::I16x8Ne => "i16x8.ne".to_owned(),
        Operator::I16x8LtS => "i16x8.lt_s".to_owned(),
        Operator::I16x8LtU => "i16x8.lt_u".to_owned(),
        Operator::I16x8GtS => "i16x8.gt_s".to_owned(),
        Operator::I16x8GtU => "i16x8.gt_u".to_owned(),
        Operator::I16x8LeS => "i16x8.le_s".to_owned(),
        Operator::I16x8LeU => "i16x8.le_u".to_owned(),
        Operator::I16x8GeS => "i16x8.ge_s".to_owned(),
        Operator::I16x8GeU => "i16x8.ge_u".to_owned(),
        Operator::I32x4Eq => "i32x4.eq".to_owned(),
        Operator::I32x4Ne => "i32x4.ne".to_owned(),
        Operator::I32x4LtS => "i32x4.lt_s".to_owned(),
        Operator::I32x4LtU => "i32x4.lt_u".to_owned(),
        Operator::I32x4GtS => "i32x4.gt_s".to_owned(),
        Operator::I32x4GtU => "i32x4.gt_u".to_owned(),
        Operator::I32x4LeS => "i32x4.le_s".to_owned(),
        Operator::I32x4LeU => "i32x4.le_u".to_owned(),
        Operator::I32x4GeS => "i32x4.ge_s".to_owned(),
        Operator::I32x4GeU => "i32x4.ge_u".to_owned(),
        Operator::I64x2Eq => "i64x2.eq".to_owned(),
        Operator::I64x2Ne => "i64x2.ne".to_owned(),
        Operator::I64x2LtS => "i64x2.lt_s".to_owned(),
        Operator::I64x2GtS => "i64x2.gt_s".to_owned(),
        Operator::I64x2LeS => "i64x2.le_s".to_owned(),
        Operator::I64x2GeS => "i64x2.ge_s".to_owned(),
        Operator::F32x4Eq => "f32x4.eq".to_owned(),
        Operator::F32x4Ne => "f32x4.ne".to_owned(),
        Operator::F32x4Lt => "f32x4.lt".to_owned(),
        Operator::F32x4Gt => "f32x4.gt".to_owned(),
        Operator::F32x4Le => "f32x4.le".to_owned(),
        Operator::F32x4Ge => "f32x4.ge".to_owned(),
        Operator::F64x2Eq => "f64x2.eq".to_owned(),
        Operator::F64x2Ne => "f64x2.ne".to_owned(),
        Operator::F64x2Lt => "f64x2.lt".to_owned(),
        Operator::F64x2Gt => "f64x2.gt".to_owned(),
        Operator::F64x2Le => "f64x2.le".to_owned(),
        Operator::F64x2Ge => "f64x2.ge".to_owned(),
        Operator::V128AndNot => "v128.andnot".to_owned(),
        Operator::V128AnyTrue => "v128.any_true".to_owned(),
        Operator::I8x16Abs => "i8x16.abs".to_owned(),
        Operator::I8x16Neg => "i8x16.neg".to_owned(),
        Operator::I8x16Popcnt => "i8x16.popcnt".to_owned(),
        Operator::I8x16AllTrue => "i8x16.all_true".to_owned(),
        Operator::I8x16Bitmask => "i8x16.bitmask".to_owned(),
        Operator::I8x16NarrowI16x8S => "i8x16.narrow_i16x8_s".to_owned(),
        Operator::I8x16NarrowI16x8U => "i8x16.narrow_i16x8_u".to_owned(),
        Operator::I8x16Shl => "i8x16.shl".to_owned(),
        Operator::I8x16ShrS => "i8x16.shr_s".to_owned(),
        Operator::I8x16ShrU => "i8x16.shr_u".to_owned(),
        Operator::I8x16AddSatS => "i8x16.add_sat_s".to_owned(),
        Operator::I8x16AddSatU => "i8x16.add_sat_u".to_owned(),
        Operator::I8x16SubSatS => "i8x16.sub_sat_s".to_owned(),
        Operator::I8x16SubSatU => "i8x16.sub_sat_u".to_owned(),
        Operator::I8x16MinS => "i8x16.min_s".to_owned(),
        Operator::I8x16MinU => "i8x16.min_u".to_owned(),
        Operator::I8x16MaxS => "i8x16.max_s".to_owned(),
        Operator::I8x16MaxU => "i8x16.max_u".to_owned(),
        Operator::I8x16AvgrU => "i8x16.avgr_u".to_owned(),
        Operator::I16x8ExtAddPairwiseI8x16S => "i16x8.extadd_pairwise_i8x16_s".to_owned(),
        Operator::I16x8ExtAddPairwiseI8x16U => "i16x8.extadd_pairwise_i8x16_u".to_owned(),
        Operator::I16x8Abs => "i16x8.abs".to_owned(),
        Operator::I16x8Neg => "i16x8.neg".to_owned(),
        Operator::I16x8Q15MulrSatS => "i16x8.q15mulr_sat_s".to_owned(),
        Operator::I16x8AllTrue => "i16x8.all_true".to_owned(),
        Operator::I16x8Bitmask => "i16x8.bitmask".to_owned(),
        Operator::I16x8NarrowI32x4S => "i16x8.narrow_i32x4_s".to_owned(),
        Operator::I16x8NarrowI32x4U => "i16x8.narrow_i32x4_u".to_owned(),
        Operator::I16x8ExtendLowI8x16S => "i16x8.extend_low_i8x16_s".to_owned(),
        Operator::I16x8ExtendHighI8x16S => "i16x8.extend_high_i8x16_s".to_owned(),
        Operator::I16x8ExtendLowI8x16U => "i16x8.extend_low_i8x16_u".to_owned(),
        Operator::I16x8ExtendHighI8x16U => "i16x8.extend_high_i8x16_u".to_owned(),
        Operator::I16x8Shl => "i16x8.shl".to_owned(),
        Operator::I16x8ShrS => "i16x8.shr_s".to_owned(),
        Operator::I16x8ShrU => "i16x8.shr_u".to_owned(),
        Operator::I16x8AddSatS => "i16x8.add_sat_s".to_owned(),
        Operator::I16x8AddSatU => "i16x8.add_sat_u".to_owned(),
        Operator::I16x8Sub => "i16x8.sub".to_owned(),
        Operator::I16x8SubSatS => "i16x8.sub_sat_s".to_owned(),
        Operator::I16x8SubSatU => "i16x8.sub_sat_u".to_owned(),
        Operator::I16x8Mul => "i16x8.mul".to_owned(),
        Operator::I16x8MinS => "i16x8.min_s".to_owned(),
        Operator::I16x8MinU => "i16x8.min_u".to_owned(),
        Operator::I16x8MaxS => "i16x8.max_s".to_owned(),
        Operator::I16x8MaxU => "i16x8.max_u".to_owned(),
        Operator::I16x8AvgrU => "i16x8.avgr_u".to_owned(),
        Operator::I16x8ExtMulLowI8x16S => "i16x8.extmul_low_i8x16_s".to_owned(),
        Operator::I16x8ExtMulHighI8x16S => "i16x8.extmul_high_i8x16_s".to_owned(),
        Operator::I16x8ExtMulLowI8x16U => "i16x8.extmul_low_i8x16_u".to_owned(),
        Operator::I16x8ExtMulHighI8x16U => "i16x8.extmul_high_i8x16_u".to_owned(),
        Operator::I32x4ExtAddPairwiseI16x8S => "i32x4.extadd_pairwise_i16x8_s".to_owned(),
        Operator::I32x4ExtAddPairwiseI16x8U => "i32x4.extadd_pairwise_i16x8_u".to_owned(),
        Operator::I32x4Abs => "i32x4.abs".to_owned(),
        Operator::I32x4Neg => "i32x4.neg".to_owned(),
        Operator::I32x4AllTrue => "i32x4.all_true".to_owned(),
        Operator::I32x4Bitmask => "i32x4.bitmask".to_owned(),
        Operator::I32x4ExtendLowI16x8S => "i32x4.extend_low_i16x8_s".to_owned(),
        Operator::I32x4ExtendHighI16x8S => "i32x4.extend_high_i16x8_s".to_owned(),
        Operator::I32x4ExtendLowI16x8U => "i32x4.extend_low_i16x8_u".to_owned(),
        Operator::I32x4ExtendHighI16x8U => "i32x4.extend_high_i16x8_u".to_owned(),
        Operator::I32x4Shl => "i32x4.shl".to_owned(),
        Operator::I32x4ShrS => "i32x4.shr_s".to_owned(),
        Operator::I32x4ShrU => "i32x4.shr_u".to_owned(),
        Operator::I32x4Sub => "i32x4.sub".to_owned(),
        Operator::I32x4MinS => "i32x4.min_s".to_owned(),
        Operator::I32x4MinU => "i32x4.min_u".to_owned(),
        Operator::I32x4MaxS => "i32x4.max_s".to_owned(),
        Operator::I32x4MaxU => "i32x4.max_u".to_owned(),
        Operator::I32x4DotI16x8S => "i32x4.dot_i16x8_s".to_owned(),
        Operator::I32x4ExtMulLowI16x8S => "i32x4.extmul_low_i16x8_s".to_owned(),
        Operator::I32x4ExtMulHighI16x8S => "i32x4.extmul_high_i16x8_s".to_owned(),
        Operator::I32x4ExtMulLowI16x8U => "i32x4.extmul_low_i16x8_u".to_owned(),
        Operator::I32x4ExtMulHighI16x8U => "i32x4.extmul_high_i16x8_u".to_owned(),
        Operator::I64x2Abs => "i64x2.abs".to_owned(),
        Operator::I64x2Neg => "i64x2.neg".to_owned(),
        Operator::I64x2AllTrue => "i64x2.all_true".to_owned(),
        Operator::I64x2Bitmask => "i64x2.bitmask".to_owned(),
        Operator::I64x2ExtendLowI32x4S => "i64x2.extend_low_i32x4_s".to_owned(),
        Operator::I64x2ExtendHighI32x4S => "i64x2.extend_high_i32x4_s".to_owned(),
        Operator::I64x2ExtendLowI32x4U => "i64x2.extend_low_i32x4_u".to_owned(),
        Operator::I64x2ExtendHighI32x4U => "i64x2.extend_high_i32x4_u".to_owned(),
        Operator::I64x2Shl => "i64x2.shl".to_owned(),
        Operator::I64x2ShrS => "i64x2.shr_s".to_owned(),
        Operator::I64x2ShrU => "i64x2.shr_u".to_owned(),
        Operator::I64x2Sub => "i64x2.sub".to_owned(),
        Operator::I64x2Mul => "i64x2.mul".to_owned(),
        Operator::I64x2ExtMulLowI32x4S => "i64x2.extmul_low_i32x4_s".to_owned(),
        Operator::I64x2ExtMulHighI32x4S => "i64x2.extmul_high_i32x4_s".to_owned(),
        Operator::I64x2ExtMulLowI32x4U => "i64x2.extmul_low_i32x4_u".to_owned(),
        Operator::I64x2ExtMulHighI32x4U => "i64x2.extmul_high_i32x4_u".to_owned(),
        Operator::F32x4Ceil => "f32x4.ceil".to_owned(),
        Operator::F32x4Floor => "f32x4.floor".to_owned(),
        Operator::F32x4Trunc => "f32x4.trunc".to_owned(),
        Operator::F32x4Nearest => "f32x4.nearest".to_owned(),
        Operator::F32x4Abs => "f32x4.abs".to_owned(),
        Operator::F32x4Neg => "f32x4.neg".to_owned(),
        Operator::F32x4Sqrt => "f32x4.sqrt".to_owned(),
        Operator::F32x4Sub => "f32x4.sub".to_owned(),
        Operator::F32x4Div => "f32x4.div".to_owned(),
        Operator::F32x4Min => "f32x4.min".to_owned(),
        Operator::F32x4Max => "f32x4.max".to_owned(),
        Operator::F32x4PMin => "f32x4.pmin".to_owned(),
        Operator::F32x4PMax => "f32x4.pmax".to_owned(),
        Operator::F64x2Ceil => "f64x2.ceil".to_owned(),
        Operator::F64x2Floor => "f64x2.floor".to_owned(),
        Operator::F64x2Trunc => "f64x2.trunc".to_owned(),
        Operator::F64x2Nearest => "f64x2.nearest".to_owned(),
        Operator::F64x2Abs => "f64x2.abs".to_owned(),
        Operator::F64x2Neg => "f64x2.neg".to_owned(),
        Operator::F64x2Sqrt => "f64x2.sqrt".to_owned(),
        Operator::F64x2Sub => "f64x2.sub".to_owned(),
        Operator::F64x2Mul => "f64x2.mul".to_owned(),
        Operator::F64x2Div => "f64x2.div".to_owned(),
        Operator::F64x2Min => "f64x2.min".to_owned(),
        Operator::F64x2Max => "f64x2.max".to_owned(),
        Operator::F64x2PMin => "f64x2.pmin".to_owned(),
        Operator::F64x2PMax => "f64x2.pmax".to_owned(),
        Operator::I32x4TruncSatF32x4S => "i32x4.trunc_sat_f32x4_s".to_owned(),
        Operator::I32x4TruncSatF32x4U => "i32x4.trunc_sat_f32x4_u".to_owned(),
        Operator::F32x4ConvertI32x4S => "f32x4.convert_i32x4_s".to_owned(),
        Operator::F32x4ConvertI32x4U => "f32x4.convert_i32x4_u".to_owned(),
        Operator::I32x4TruncSatF64x2SZero => "i32x4.trunc_sat_f64x2_s_zero".to_owned(),
        Operator::I32x4TruncSatF64x2UZero => "i32x4.trunc_sat_f64x2_u_zero".to_owned(),
        Operator::F64x2ConvertLowI32x4S => "f64x2.convert_low_i32x4_s".to_owned(),
        Operator::F64x2ConvertLowI32x4U => "f64x2.convert_low_i32x4_u".to_owned(),
        Operator::F32x4DemoteF64x2Zero => "f32x4.demote_f64x2_zero".to_owned(),
        Operator::F64x2PromoteLowF32x4 => "f64x2.promote_low_f32x4".to_owned(),
        Operator::I32x4RelaxedTruncF32x4S => "i32x4.relaxed_trunc_f32x4_s".to_owned(),
        Operator::I32x4RelaxedTruncF32x4U => "i32x4.relaxed_trunc_f32x4_u".to_owned(),
        Operator::I32x4RelaxedTruncF64x2SZero => "i32x4.relaxed_trunc_f64x2_s_zero".to_owned(),
        Operator::I32x4RelaxedTruncF64x2UZero => "i32x4.relaxed_trunc_f64x2_u_zero".to_owned(),
        Operator::I8x16RelaxedLaneselect => "i8x16.relaxed_laneselect".to_owned(),
        Operator::I16x8RelaxedLaneselect => "i16x8.relaxed_laneselect".to_owned(),
        Operator::I32x4RelaxedLaneselect => "i32x4.relaxed_laneselect".to_owned(),
        Operator::I64x2RelaxedLaneselect => "i64x2.relaxed_laneselect".to_owned(),
        Operator::F32x4RelaxedMin => "f32x4.relaxed_min".to_owned(),
        Operator::F32x4RelaxedMax => "f32x4.relaxed_max".to_owned(),
        Operator::F64x2RelaxedMin => "f64x2.relaxed_min".to_owned(),
        Operator::F64x2RelaxedMax => "f64x2.relaxed_max".to_owned(),
        Operator::I16x8RelaxedQ15mulrS => "i16x8.relaxed_q15mulr_s".to_owned(),
        Operator::I16x8RelaxedDotI8x16I7x16S => "i16x8.relaxed_dot_i8x16_i7x16_s".to_owned(),
        Operator::I32x4RelaxedDotI8x16I7x16AddS => "i32x4.relaxed_dot_i8x16_i7x16_add_s".to_owned(),
        _ => return None,
    })
}

const fn simd_mem_mnemonic(op: &Operator<'_>) -> Option<(&'static str, wasmparser::MemArg)> {
    Some(match op {
        Operator::V128Load { memarg } => ("v128.load", *memarg),
        Operator::V128Store { memarg } => ("v128.store", *memarg),
        Operator::V128Load8x8S { memarg } => ("v128.load8x8_s", *memarg),
        Operator::V128Load8x8U { memarg } => ("v128.load8x8_u", *memarg),
        Operator::V128Load16x4S { memarg } => ("v128.load16x4_s", *memarg),
        Operator::V128Load16x4U { memarg } => ("v128.load16x4_u", *memarg),
        Operator::V128Load32x2S { memarg } => ("v128.load32x2_s", *memarg),
        Operator::V128Load32x2U { memarg } => ("v128.load32x2_u", *memarg),
        Operator::V128Load8Splat { memarg } => ("v128.load8_splat", *memarg),
        Operator::V128Load16Splat { memarg } => ("v128.load16_splat", *memarg),
        Operator::V128Load32Splat { memarg } => ("v128.load32_splat", *memarg),
        Operator::V128Load64Splat { memarg } => ("v128.load64_splat", *memarg),
        Operator::V128Load32Zero { memarg } => ("v128.load32_zero", *memarg),
        Operator::V128Load64Zero { memarg } => ("v128.load64_zero", *memarg),
        _ => return None,
    })
}

const fn simd_lane_mem_mnemonic(
    op: &Operator<'_>,
) -> Option<(&'static str, wasmparser::MemArg, u8)> {
    Some(match op {
        Operator::V128Load8Lane { memarg, lane } => ("v128.load8_lane", *memarg, *lane),
        Operator::V128Load16Lane { memarg, lane } => ("v128.load16_lane", *memarg, *lane),
        Operator::V128Load32Lane { memarg, lane } => ("v128.load32_lane", *memarg, *lane),
        Operator::V128Load64Lane { memarg, lane } => ("v128.load64_lane", *memarg, *lane),
        Operator::V128Store8Lane { memarg, lane } => ("v128.store8_lane", *memarg, *lane),
        Operator::V128Store16Lane { memarg, lane } => ("v128.store16_lane", *memarg, *lane),
        Operator::V128Store32Lane { memarg, lane } => ("v128.store32_lane", *memarg, *lane),
        Operator::V128Store64Lane { memarg, lane } => ("v128.store64_lane", *memarg, *lane),
        _ => return None,
    })
}

fn render_atomic_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    if let Some((mnemonic, memarg)) = atomic_mem_mnemonic(op) {
        reqs.shared_memory = true;
        return Some(format_memarg(mnemonic, memarg, reqs));
    }
    match op {
        Operator::AtomicFence => {
            reqs.shared_memory = true;
            Some("atomic.fence".to_owned())
        }
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
const fn atomic_mem_mnemonic(op: &Operator<'_>) -> Option<(&'static str, wasmparser::MemArg)> {
    Some(match op {
        Operator::MemoryAtomicNotify { memarg } => ("memory.atomic.notify", *memarg),
        Operator::MemoryAtomicWait32 { memarg } => ("memory.atomic.wait32", *memarg),
        Operator::MemoryAtomicWait64 { memarg } => ("memory.atomic.wait64", *memarg),
        Operator::I32AtomicLoad { memarg } => ("i32.atomic.load", *memarg),
        Operator::I64AtomicLoad { memarg } => ("i64.atomic.load", *memarg),
        Operator::I32AtomicLoad8U { memarg } => ("i32.atomic.load8_u", *memarg),
        Operator::I32AtomicLoad16U { memarg } => ("i32.atomic.load16_u", *memarg),
        Operator::I64AtomicLoad8U { memarg } => ("i64.atomic.load8_u", *memarg),
        Operator::I64AtomicLoad16U { memarg } => ("i64.atomic.load16_u", *memarg),
        Operator::I64AtomicLoad32U { memarg } => ("i64.atomic.load32_u", *memarg),
        Operator::I32AtomicStore { memarg } => ("i32.atomic.store", *memarg),
        Operator::I64AtomicStore { memarg } => ("i64.atomic.store", *memarg),
        Operator::I32AtomicStore8 { memarg } => ("i32.atomic.store8", *memarg),
        Operator::I32AtomicStore16 { memarg } => ("i32.atomic.store16", *memarg),
        Operator::I64AtomicStore8 { memarg } => ("i64.atomic.store8", *memarg),
        Operator::I64AtomicStore16 { memarg } => ("i64.atomic.store16", *memarg),
        Operator::I64AtomicStore32 { memarg } => ("i64.atomic.store32", *memarg),
        Operator::I32AtomicRmwAdd { memarg } => ("i32.atomic.rmw.add", *memarg),
        Operator::I64AtomicRmwAdd { memarg } => ("i64.atomic.rmw.add", *memarg),
        Operator::I32AtomicRmw8AddU { memarg } => ("i32.atomic.rmw8.add_u", *memarg),
        Operator::I32AtomicRmw16AddU { memarg } => ("i32.atomic.rmw16.add_u", *memarg),
        Operator::I32AtomicRmwSub { memarg } => ("i32.atomic.rmw.sub", *memarg),
        Operator::I64AtomicRmwSub { memarg } => ("i64.atomic.rmw.sub", *memarg),
        Operator::I32AtomicRmwAnd { memarg } => ("i32.atomic.rmw.and", *memarg),
        Operator::I64AtomicRmwAnd { memarg } => ("i64.atomic.rmw.and", *memarg),
        Operator::I32AtomicRmwOr { memarg } => ("i32.atomic.rmw.or", *memarg),
        Operator::I64AtomicRmwOr { memarg } => ("i64.atomic.rmw.or", *memarg),
        Operator::I32AtomicRmwXor { memarg } => ("i32.atomic.rmw.xor", *memarg),
        Operator::I64AtomicRmwXor { memarg } => ("i64.atomic.rmw.xor", *memarg),
        Operator::I32AtomicRmwXchg { memarg } => ("i32.atomic.rmw.xchg", *memarg),
        Operator::I64AtomicRmwXchg { memarg } => ("i64.atomic.rmw.xchg", *memarg),
        Operator::I32AtomicRmwCmpxchg { memarg } => ("i32.atomic.rmw.cmpxchg", *memarg),
        Operator::I64AtomicRmwCmpxchg { memarg } => ("i64.atomic.rmw.cmpxchg", *memarg),
        _ => return None,
    })
}

fn render_bulk_memory_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::MemoryCopy { dst_mem, src_mem } => {
            reqs.note_memory(*dst_mem);
            reqs.note_memory(*src_mem);
            if *dst_mem == 0 && *src_mem == 0 {
                "memory.copy".to_owned()
            } else {
                format!("memory.copy $m{dst_mem} $m{src_mem}")
            }
        }
        Operator::MemoryFill { mem } => {
            reqs.note_memory(*mem);
            format!("memory.fill{}", memory_operand(*mem))
        }
        Operator::MemoryInit { data_index, mem } => {
            reqs.note_memory(*mem);
            reqs.data_segments.insert(*data_index);
            format!("memory.init{} $d{data_index}", memory_operand(*mem))
        }
        Operator::DataDrop { data_index } => {
            reqs.data_segments.insert(*data_index);
            format!("data.drop $d{data_index}")
        }
        _ => return None,
    })
}

fn render_table_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::TableGet { table } => {
            table_target(*table, reqs);
            format!("table.get {}", table_name(*table))
        }
        Operator::TableSet { table } => {
            table_target(*table, reqs);
            format!("table.set {}", table_name(*table))
        }
        Operator::TableSize { table } => {
            table_target(*table, reqs);
            format!("table.size {}", table_name(*table))
        }
        Operator::TableGrow { table } => {
            table_target(*table, reqs);
            format!("table.grow {}", table_name(*table))
        }
        Operator::TableFill { table } => {
            table_target(*table, reqs);
            format!("table.fill {}", table_name(*table))
        }
        Operator::TableCopy {
            dst_table,
            src_table,
        } => {
            table_target(*dst_table, reqs);
            table_target(*src_table, reqs);
            format!(
                "table.copy {} {}",
                table_name(*dst_table),
                table_name(*src_table)
            )
        }
        Operator::TableInit { table, elem_index } => {
            table_target(*table, reqs);
            reqs.elem_segments.insert(*elem_index);
            format!("table.init {} $e{elem_index}", table_name(*table))
        }
        Operator::ElemDrop { elem_index } => {
            reqs.funcref_table = true;
            reqs.elem_segments.insert(*elem_index);
            format!("elem.drop $e{elem_index}")
        }
        _ => return None,
    })
}

const fn table_target(table: u32, reqs: &mut FeatureReqs) {
    if table == 0 {
        reqs.funcref_table = true;
    } else {
        reqs.externref_table = true;
    }
}

const fn table_name(table: u32) -> &'static str {
    if table == 0 {
        "$dr_tbl_func"
    } else {
        "$dr_tbl_ext"
    }
}

fn render_ref_op(op: &Operator<'_>, reqs: &mut FeatureReqs, mode: RenderMode) -> Option<String> {
    Some(match op {
        Operator::RefIsNull => "ref.is_null".to_owned(),
        Operator::RefNull {
            hty: wasmparser::HeapType::Abstract { shared: _, ty },
        } => format!("ref.null {}", abstract_heap_keyword(*ty)),
        Operator::RefNull {
            hty: wasmparser::HeapType::Concrete(idx) | wasmparser::HeapType::Exact(idx),
        } => idx
            .as_module_index()
            .map_or_else(|| "ref.null func".to_owned(), |i| format!("ref.null $t{i}")),
        Operator::RefFunc { function_index } => {
            reqs.ref_func_indices.insert(*function_index);
            match mode {
                RenderMode::SingleFunction => format!("ref.func $rf{function_index}"),
                RenderMode::WholeModule => format!("ref.func $f{function_index}"),
            }
        }
        _ => return None,
    })
}

fn render_gc_op(op: &Operator<'_>, has_calls: &mut bool, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::AnyConvertExtern => "any.convert_extern".to_owned(),
        Operator::ExternConvertAny => "extern.convert_any".to_owned(),
        Operator::RefAsNonNull => "ref.as_non_null".to_owned(),
        Operator::CallRef { type_index } => {
            *has_calls = true;
            reqs.record_func_type(*type_index);
            format!("call_ref $t{type_index}")
        }
        Operator::ReturnCallRef { type_index } => {
            *has_calls = true;
            reqs.record_func_type(*type_index);
            format!("return_call_ref $t{type_index}")
        }
        Operator::StructNew { struct_type_index } => format!("struct.new $t{struct_type_index}"),
        Operator::StructNewDefault { struct_type_index } => {
            format!("struct.new_default $t{struct_type_index}")
        }
        Operator::StructGet {
            struct_type_index,
            field_index,
        } => return render_struct_field_op(reqs, "struct.get", *struct_type_index, *field_index),
        Operator::StructGetS {
            struct_type_index,
            field_index,
        } => return render_struct_field_op(reqs, "struct.get_s", *struct_type_index, *field_index),
        Operator::StructGetU {
            struct_type_index,
            field_index,
        } => return render_struct_field_op(reqs, "struct.get_u", *struct_type_index, *field_index),
        Operator::StructSet {
            struct_type_index,
            field_index,
        } => return render_struct_field_op(reqs, "struct.set", *struct_type_index, *field_index),
        Operator::ArrayNew { array_type_index } => {
            reqs.array_types.insert(*array_type_index);
            format!("array.new $t{array_type_index}")
        }
        Operator::ArrayNewDefault { array_type_index } => {
            reqs.array_types.insert(*array_type_index);
            format!("array.new_default $t{array_type_index}")
        }
        Operator::ArrayNewFixed {
            array_type_index,
            array_size,
        } => {
            reqs.array_types.insert(*array_type_index);
            format!("array.new_fixed $t{array_type_index} {array_size}")
        }
        Operator::ArrayGet { array_type_index } => format!("array.get $t{array_type_index}"),
        Operator::ArrayGetS { array_type_index } => format!("array.get_s $t{array_type_index}"),
        Operator::ArrayGetU { array_type_index } => format!("array.get_u $t{array_type_index}"),
        Operator::ArraySet { array_type_index } => format!("array.set $t{array_type_index}"),
        Operator::ArrayLen => "array.len".to_owned(),
        Operator::RefI31 => "ref.i31".to_owned(),
        Operator::I31GetS => "i31.get_s".to_owned(),
        Operator::I31GetU => "i31.get_u".to_owned(),
        _ => return None,
    })
}

fn render_struct_field_op(
    reqs: &mut FeatureReqs,
    opcode: &str,
    struct_type_index: u32,
    field_index: u32,
) -> Option<String> {
    if !reqs.record_struct_field_index(struct_type_index, field_index) {
        return None;
    }
    Some(format!("{opcode} $t{struct_type_index} {field_index}"))
}

#[allow(clippy::too_many_lines)]
fn render_extended_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::RefEq => "ref.eq".to_owned(),
        Operator::RefTestNonNull { hty } => format!("ref.test {}", heap_ref_str(*hty, false)),
        Operator::RefTestNullable { hty } => format!("ref.test {}", heap_ref_str(*hty, true)),
        Operator::RefCastNonNull { hty } => format!("ref.cast {}", heap_ref_str(*hty, false)),
        Operator::RefCastNullable { hty } => format!("ref.cast {}", heap_ref_str(*hty, true)),
        Operator::RefI31Shared => "ref.i31_shared".to_owned(),
        Operator::ArrayNewData {
            array_type_index,
            array_data_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            reqs.data_segments.insert(*array_data_index);
            format!("array.new_data $t{array_type_index} $d{array_data_index}")
        }
        Operator::ArrayNewElem {
            array_type_index,
            array_elem_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            reqs.elem_segments.insert(*array_elem_index);
            format!("array.new_elem $t{array_type_index} $e{array_elem_index}")
        }
        Operator::ArrayFill { array_type_index } => {
            reqs.array_types.insert(*array_type_index);
            format!("array.fill $t{array_type_index}")
        }
        Operator::ArrayCopy {
            array_type_index_dst,
            array_type_index_src,
        } => {
            reqs.array_types.insert(*array_type_index_dst);
            reqs.array_types.insert(*array_type_index_src);
            format!("array.copy $t{array_type_index_dst} $t{array_type_index_src}")
        }
        Operator::ArrayInitData {
            array_type_index,
            array_data_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            reqs.data_segments.insert(*array_data_index);
            format!("array.init_data $t{array_type_index} $d{array_data_index}")
        }
        Operator::ArrayInitElem {
            array_type_index,
            array_elem_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            reqs.elem_segments.insert(*array_elem_index);
            format!("array.init_elem $t{array_type_index} $e{array_elem_index}")
        }
        Operator::BrOnNull { relative_depth } => format!("br_on_null {relative_depth}"),
        Operator::BrOnNonNull { relative_depth } => format!("br_on_non_null {relative_depth}"),
        Operator::BrOnCast {
            relative_depth,
            from_ref_type,
            to_ref_type,
        } => format!(
            "br_on_cast {relative_depth} {} {}",
            ref_type_str(*from_ref_type),
            ref_type_str(*to_ref_type)
        ),
        Operator::BrOnCastFail {
            relative_depth,
            from_ref_type,
            to_ref_type,
        } => format!(
            "br_on_cast_fail {relative_depth} {} {}",
            ref_type_str(*from_ref_type),
            ref_type_str(*to_ref_type)
        ),
        Operator::MemoryDiscard { mem } => {
            reqs.note_memory(*mem);
            format!("memory.discard{}", memory_operand(*mem))
        }
        Operator::I64Add128 => "i64.add128".to_owned(),
        Operator::I64Sub128 => "i64.sub128".to_owned(),
        Operator::I64MulWideS => "i64.mul_wide_s".to_owned(),
        Operator::I64MulWideU => "i64.mul_wide_u".to_owned(),
        Operator::GlobalAtomicGet {
            ordering,
            global_index,
        } => {
            note_global(*global_index, &mut Vec::new());
            format!(
                "global.atomic.get {} $g{global_index}",
                ordering_str(*ordering)
            )
        }
        Operator::GlobalAtomicSet {
            ordering,
            global_index,
        } => format!(
            "global.atomic.set {} $g{global_index}",
            ordering_str(*ordering)
        ),
        Operator::GlobalAtomicRmwAdd {
            ordering,
            global_index,
        }
        | Operator::GlobalAtomicRmwSub {
            ordering,
            global_index,
        }
        | Operator::GlobalAtomicRmwAnd {
            ordering,
            global_index,
        }
        | Operator::GlobalAtomicRmwOr {
            ordering,
            global_index,
        }
        | Operator::GlobalAtomicRmwXor {
            ordering,
            global_index,
        }
        | Operator::GlobalAtomicRmwXchg {
            ordering,
            global_index,
        } => format!(
            "global.atomic.rmw.{} {} $g{global_index}",
            atomic_rmw_suffix(op),
            ordering_str(*ordering)
        ),
        Operator::GlobalAtomicRmwCmpxchg {
            ordering,
            global_index,
        } => format!(
            "global.atomic.rmw.cmpxchg {} $g{global_index}",
            ordering_str(*ordering)
        ),
        _ => return render_shared_aggregate_atomic(op, reqs),
    })
}

fn render_shared_aggregate_atomic(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::StructAtomicGet {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicGetS {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicGetU {
            ordering,
            struct_type_index,
            field_index,
        } => {
            if !reqs.record_struct_field_index(*struct_type_index, *field_index) {
                return None;
            }
            format!(
                "struct.atomic.{} {} $t{struct_type_index} {field_index}",
                struct_atomic_get_suffix(op),
                ordering_str(*ordering)
            )
        }
        Operator::StructAtomicSet {
            ordering,
            struct_type_index,
            field_index,
        } => {
            if !reqs.record_struct_field_index(*struct_type_index, *field_index) {
                return None;
            }
            format!(
                "struct.atomic.set {} $t{struct_type_index} {field_index}",
                ordering_str(*ordering)
            )
        }
        Operator::StructAtomicRmwAdd {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicRmwSub {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicRmwAnd {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicRmwOr {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicRmwXor {
            ordering,
            struct_type_index,
            field_index,
        }
        | Operator::StructAtomicRmwXchg {
            ordering,
            struct_type_index,
            field_index,
        } => {
            if !reqs.record_struct_field_index(*struct_type_index, *field_index) {
                return None;
            }
            format!(
                "struct.atomic.rmw.{} {} $t{struct_type_index} {field_index}",
                atomic_rmw_suffix(op),
                ordering_str(*ordering)
            )
        }
        Operator::StructAtomicRmwCmpxchg {
            ordering,
            struct_type_index,
            field_index,
        } => {
            if !reqs.record_struct_field_index(*struct_type_index, *field_index) {
                return None;
            }
            format!(
                "struct.atomic.rmw.cmpxchg {} $t{struct_type_index} {field_index}",
                ordering_str(*ordering)
            )
        }
        Operator::ArrayAtomicGet {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicGetS {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicGetU {
            ordering,
            array_type_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            format!(
                "array.atomic.{} {} $t{array_type_index}",
                array_atomic_get_suffix(op),
                ordering_str(*ordering)
            )
        }
        Operator::ArrayAtomicSet {
            ordering,
            array_type_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            format!(
                "array.atomic.set {} $t{array_type_index}",
                ordering_str(*ordering)
            )
        }
        Operator::ArrayAtomicRmwAdd {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicRmwSub {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicRmwAnd {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicRmwOr {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicRmwXor {
            ordering,
            array_type_index,
        }
        | Operator::ArrayAtomicRmwXchg {
            ordering,
            array_type_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            format!(
                "array.atomic.rmw.{} {} $t{array_type_index}",
                atomic_rmw_suffix(op),
                ordering_str(*ordering)
            )
        }
        Operator::ArrayAtomicRmwCmpxchg {
            ordering,
            array_type_index,
        } => {
            reqs.array_types.insert(*array_type_index);
            format!(
                "array.atomic.rmw.cmpxchg {} $t{array_type_index}",
                ordering_str(*ordering)
            )
        }
        Operator::TableAtomicGet {
            ordering,
            table_index,
        } => {
            table_target(*table_index, reqs);
            format!(
                "table.atomic.get {} {}",
                ordering_str(*ordering),
                table_name(*table_index)
            )
        }
        Operator::TableAtomicSet {
            ordering,
            table_index,
        } => {
            table_target(*table_index, reqs);
            format!(
                "table.atomic.set {} {}",
                ordering_str(*ordering),
                table_name(*table_index)
            )
        }
        Operator::TableAtomicRmwXchg {
            ordering,
            table_index,
        } => {
            table_target(*table_index, reqs);
            format!(
                "table.atomic.rmw.xchg {} {}",
                ordering_str(*ordering),
                table_name(*table_index)
            )
        }
        Operator::TableAtomicRmwCmpxchg {
            ordering,
            table_index,
        } => {
            table_target(*table_index, reqs);
            format!(
                "table.atomic.rmw.cmpxchg {} {}",
                ordering_str(*ordering),
                table_name(*table_index)
            )
        }
        _ => return None,
    })
}

const fn ordering_str(ordering: wasmparser::Ordering) -> &'static str {
    match ordering {
        wasmparser::Ordering::SeqCst => "seq_cst",
        wasmparser::Ordering::AcqRel => "acq_rel",
    }
}

fn atomic_rmw_suffix(op: &Operator<'_>) -> &'static str {
    let name: String = format!("{op:?}");
    if name.contains("Add") {
        "add"
    } else if name.contains("Sub") {
        "sub"
    } else if name.contains("And") {
        "and"
    } else if name.contains("Or") {
        "or"
    } else if name.contains("Xor") {
        "xor"
    } else {
        "xchg"
    }
}

const fn struct_atomic_get_suffix(op: &Operator<'_>) -> &'static str {
    match op {
        Operator::StructAtomicGetS { .. } => "get_s",
        Operator::StructAtomicGetU { .. } => "get_u",
        _ => "get",
    }
}

const fn array_atomic_get_suffix(op: &Operator<'_>) -> &'static str {
    match op {
        Operator::ArrayAtomicGetS { .. } => "get_s",
        Operator::ArrayAtomicGetU { .. } => "get_u",
        _ => "get",
    }
}

fn heap_ref_str(hty: wasmparser::HeapType, nullable: bool) -> String {
    use wasmparser::HeapType;
    match hty {
        HeapType::Concrete(idx) => idx.as_module_index().map_or_else(
            || "anyref".to_owned(),
            |i| {
                if nullable {
                    format!("(ref null $t{i})")
                } else {
                    format!("(ref $t{i})")
                }
            },
        ),
        HeapType::Exact(idx) => idx.as_module_index().map_or_else(
            || "anyref".to_owned(),
            |i| {
                if nullable {
                    format!("(ref null $t{i})")
                } else {
                    format!("(ref $t{i})")
                }
            },
        ),
        HeapType::Abstract { ty, .. } => {
            let kw: &str = abstract_ref_keyword(ty, nullable);
            if nullable {
                kw.to_owned()
            } else {
                format!("(ref {})", abstract_heap_keyword(ty))
            }
        }
    }
}

fn render_exception_op(
    op: &Operator<'_>,
    blocks_emitted: &mut usize,
    block_func_types: &[(Vec<ValType>, Vec<ValType>)],
) -> Option<String> {
    Some(match op {
        Operator::Throw { tag_index } => format!("throw $tag{tag_index}"),
        Operator::ThrowRef => "throw_ref".to_owned(),
        Operator::TryTable { try_table } => {
            *blocks_emitted += 1;
            let mut s: String = format!(
                "try_table{}",
                block_type_suffix(try_table.ty, block_func_types)
            );
            for catch in &try_table.catches {
                push_text!(s, " {}", catch_clause(catch));
            }
            s
        }
        Operator::Try { blockty } => {
            *blocks_emitted += 1;
            format!("try{}", block_type_suffix(*blockty, block_func_types))
        }
        Operator::Catch { tag_index } => format!("catch $tag{tag_index}"),
        Operator::CatchAll => "catch_all".to_owned(),
        Operator::Delegate { relative_depth } => format!("delegate {relative_depth}"),
        Operator::Rethrow { relative_depth } => format!("rethrow {relative_depth}"),
        _ => return None,
    })
}

fn render_stack_switching_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::ContNew { cont_type_index } => {
            reqs.record_cont_type(*cont_type_index);
            format!("cont.new $t{cont_type_index}")
        }
        Operator::ContBind {
            argument_index,
            result_index,
        } => {
            reqs.record_cont_type(*argument_index);
            reqs.record_cont_type(*result_index);
            format!("cont.bind $t{argument_index} $t{result_index}")
        }
        Operator::Suspend { tag_index } => {
            reqs.tags.entry(*tag_index).or_default();
            format!("suspend $tag{tag_index}")
        }
        Operator::Resume {
            cont_type_index,
            resume_table,
        } => {
            reqs.record_cont_type(*cont_type_index);
            let mut s: String = format!("resume $t{cont_type_index}");
            for handle in &resume_table.handlers {
                push_text!(s, " {}", resume_handle_clause(handle, reqs));
            }
            s
        }
        Operator::ResumeThrow {
            cont_type_index,
            tag_index,
            resume_table,
        } => {
            reqs.record_cont_type(*cont_type_index);
            reqs.tags.entry(*tag_index).or_default();
            let mut s: String = format!("resume_throw $t{cont_type_index} $tag{tag_index}");
            for handle in &resume_table.handlers {
                push_text!(s, " {}", resume_handle_clause(handle, reqs));
            }
            s
        }
        Operator::Switch {
            cont_type_index,
            tag_index,
        } => {
            reqs.record_cont_type(*cont_type_index);
            reqs.tags.entry(*tag_index).or_default();
            format!("switch $t{cont_type_index} $tag{tag_index}")
        }
        _ => return None,
    })
}

fn resume_handle_clause(handle: &wasmparser::Handle, reqs: &mut FeatureReqs) -> String {
    match handle {
        wasmparser::Handle::OnLabel { tag, label } => {
            reqs.tags.entry(*tag).or_default();
            format!("(on $tag{tag} {label})")
        }
        wasmparser::Handle::OnSwitch { tag } => {
            reqs.tags.entry(*tag).or_default();
            format!("(on $tag{tag} switch)")
        }
    }
}

fn catch_clause(catch: &Catch) -> String {
    match catch {
        Catch::One { tag, label } => format!("(catch $tag{tag} {label})"),
        Catch::OneRef { tag, label } => format!("(catch_ref $tag{tag} {label})"),
        Catch::All { label } => format!("(catch_all {label})"),
        Catch::AllRef { label } => format!("(catch_all_ref {label})"),
    }
}

const fn abstract_heap_keyword(ty: wasmparser::AbstractHeapType) -> &'static str {
    use wasmparser::AbstractHeapType;
    match ty {
        AbstractHeapType::Any => "any",
        AbstractHeapType::Eq => "eq",
        AbstractHeapType::Struct => "struct",
        AbstractHeapType::Array => "array",
        AbstractHeapType::I31 => "i31",
        AbstractHeapType::Extern => "extern",
        AbstractHeapType::Func => "func",
        AbstractHeapType::None => "none",
        AbstractHeapType::NoFunc => "nofunc",
        AbstractHeapType::NoExtern => "noextern",
        AbstractHeapType::Exn => "exn",
        AbstractHeapType::NoExn => "noexn",
        AbstractHeapType::Cont => "cont",
        AbstractHeapType::NoCont => "nocont",
    }
}

fn note_global(global_index: u32, globals_used: &mut Vec<(u32, ValType)>) {
    if !globals_used.iter().any(|(i, _)| *i == global_index) {
        globals_used.push((global_index, ValType::I32));
    }
}

fn local_ref(local_index: u32, sig: &FunctionSig) -> String {
    if (local_index as usize) < sig.params.len() {
        format!("p{local_index}")
    } else {
        format!("l{local_index}")
    }
}

fn wat_f32(v: f32) -> String {
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

fn wat_f64(v: f64) -> String {
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

fn block_type_suffix(
    blockty: BlockType,
    block_func_types: &[(Vec<ValType>, Vec<ValType>)],
) -> String {
    match blockty {
        BlockType::Empty => String::new(),
        BlockType::Type(ty) => format!(" (result {})", val_type_str(ty)),
        BlockType::FuncType(idx) => match block_func_types.get(idx as usize) {
            Some((params, results)) => {
                let mut s: String = String::new();
                for ty in params {
                    push_text!(s, " (param {})", val_type_str(*ty));
                }
                for ty in results {
                    push_text!(s, " (result {})", val_type_str(*ty));
                }
                s
            }
            None => String::new(),
        },
    }
}

pub(crate) fn val_type_str(ty: ValType) -> String {
    match ty {
        ValType::I64 => "i64".to_owned(),
        ValType::F32 => "f32".to_owned(),
        ValType::F64 => "f64".to_owned(),
        ValType::V128 => "v128".to_owned(),
        ValType::I32 => "i32".to_owned(),
        ValType::Ref(r) => ref_type_str(r),
    }
}

fn ref_type_str(r: wasmparser::RefType) -> String {
    use wasmparser::HeapType;
    match r.heap_type() {
        HeapType::Concrete(idx) => idx.as_module_index().map_or_else(
            || "anyref".to_owned(),
            |i| {
                if r.is_nullable() {
                    format!("(ref null $t{i})")
                } else {
                    format!("(ref $t{i})")
                }
            },
        ),
        HeapType::Exact(idx) => idx.as_module_index().map_or_else(
            || "anyref".to_owned(),
            |i| {
                if r.is_nullable() {
                    format!("(ref null $t{i})")
                } else {
                    format!("(ref $t{i})")
                }
            },
        ),
        HeapType::Abstract { ty, .. } => abstract_ref_keyword(ty, r.is_nullable()).to_owned(),
    }
}

const fn abstract_ref_keyword(ty: wasmparser::AbstractHeapType, nullable: bool) -> &'static str {
    use wasmparser::AbstractHeapType;
    match ty {
        AbstractHeapType::Any => "anyref",
        AbstractHeapType::Eq => "eqref",
        AbstractHeapType::Struct => "structref",
        AbstractHeapType::Array => "arrayref",
        AbstractHeapType::I31 => "i31ref",
        AbstractHeapType::Func => "funcref",
        AbstractHeapType::Extern => "externref",
        AbstractHeapType::None => "nullref",
        AbstractHeapType::NoFunc => "nullfuncref",
        AbstractHeapType::NoExtern => "nullexternref",
        AbstractHeapType::Exn => "exnref",
        AbstractHeapType::NoExn => "nullexnref",
        AbstractHeapType::Cont => {
            if nullable {
                "(ref null cont)"
            } else {
                "(ref cont)"
            }
        }
        AbstractHeapType::NoCont => "nullcontref",
    }
}

const fn op_mnemonic(kind: crate::ssa::OpKind) -> &'static str {
    use crate::ssa::OpKind;
    match kind {
        OpKind::I32Add => "i32.add",
        OpKind::I32Sub => "i32.sub",
        OpKind::I32Mul => "i32.mul",
        OpKind::I32DivS => "i32.div_s",
        OpKind::I32DivU => "i32.div_u",
        OpKind::I32RemS => "i32.rem_s",
        OpKind::I32RemU => "i32.rem_u",
        OpKind::I32And => "i32.and",
        OpKind::I32Or => "i32.or",
        OpKind::I32Xor => "i32.xor",
        OpKind::I32Shl => "i32.shl",
        OpKind::I32ShrU => "i32.shr_u",
        OpKind::I32ShrS => "i32.shr_s",
        OpKind::I32Rotl => "i32.rotl",
        OpKind::I32Rotr => "i32.rotr",
        OpKind::I32Eq => "i32.eq",
        OpKind::I32Ne => "i32.ne",
        OpKind::I32LtS => "i32.lt_s",
        OpKind::I32LtU => "i32.lt_u",
        OpKind::I32GtS => "i32.gt_s",
        OpKind::I32GtU => "i32.gt_u",
        OpKind::I32LeS => "i32.le_s",
        OpKind::I32LeU => "i32.le_u",
        OpKind::I32GeS => "i32.ge_s",
        OpKind::I32GeU => "i32.ge_u",
        OpKind::I64Add => "i64.add",
        OpKind::I64Sub => "i64.sub",
        OpKind::I64Mul => "i64.mul",
        OpKind::I64DivS => "i64.div_s",
        OpKind::I64DivU => "i64.div_u",
        OpKind::I64RemS => "i64.rem_s",
        OpKind::I64RemU => "i64.rem_u",
        OpKind::I64And => "i64.and",
        OpKind::I64Or => "i64.or",
        OpKind::I64Xor => "i64.xor",
        OpKind::I64Shl => "i64.shl",
        OpKind::I64ShrU => "i64.shr_u",
        OpKind::I64ShrS => "i64.shr_s",
        OpKind::I64Rotl => "i64.rotl",
        OpKind::I64Rotr => "i64.rotr",
        OpKind::I64Eq => "i64.eq",
        OpKind::I64Ne => "i64.ne",
        OpKind::I64LtS => "i64.lt_s",
        OpKind::I64LtU => "i64.lt_u",
        OpKind::I64GtS => "i64.gt_s",
        OpKind::I64GtU => "i64.gt_u",
        OpKind::I64LeS => "i64.le_s",
        OpKind::I64LeU => "i64.le_u",
        OpKind::I64GeS => "i64.ge_s",
        OpKind::I64GeU => "i64.ge_u",
        OpKind::F32Add => "f32.add",
        OpKind::F32Sub => "f32.sub",
        OpKind::F32Mul => "f32.mul",
        OpKind::F32Div => "f32.div",
        OpKind::F32Min => "f32.min",
        OpKind::F32Max => "f32.max",
        OpKind::F32Copysign => "f32.copysign",
        OpKind::F32Eq => "f32.eq",
        OpKind::F32Ne => "f32.ne",
        OpKind::F32Lt => "f32.lt",
        OpKind::F32Gt => "f32.gt",
        OpKind::F32Le => "f32.le",
        OpKind::F32Ge => "f32.ge",
        OpKind::F64Add => "f64.add",
        OpKind::F64Sub => "f64.sub",
        OpKind::F64Mul => "f64.mul",
        OpKind::F64Div => "f64.div",
        OpKind::F64Min => "f64.min",
        OpKind::F64Max => "f64.max",
        OpKind::F64Copysign => "f64.copysign",
        OpKind::F64Eq => "f64.eq",
        OpKind::F64Ne => "f64.ne",
        OpKind::F64Lt => "f64.lt",
        OpKind::F64Gt => "f64.gt",
        OpKind::F64Le => "f64.le",
        OpKind::F64Ge => "f64.ge",
    }
}

const fn unop_mnemonic(op: crate::ssa::UnOp) -> &'static str {
    use crate::ssa::UnOp;
    match op {
        UnOp::I32Eqz => "i32.eqz",
        UnOp::I64Eqz => "i64.eqz",
        UnOp::I32Clz => "i32.clz",
        UnOp::I32Ctz => "i32.ctz",
        UnOp::I32Popcnt => "i32.popcnt",
        UnOp::I64Clz => "i64.clz",
        UnOp::I64Ctz => "i64.ctz",
        UnOp::I64Popcnt => "i64.popcnt",
        UnOp::F32Abs => "f32.abs",
        UnOp::F32Neg => "f32.neg",
        UnOp::F32Ceil => "f32.ceil",
        UnOp::F32Floor => "f32.floor",
        UnOp::F32Trunc => "f32.trunc",
        UnOp::F32Nearest => "f32.nearest",
        UnOp::F32Sqrt => "f32.sqrt",
        UnOp::F64Abs => "f64.abs",
        UnOp::F64Neg => "f64.neg",
        UnOp::F64Ceil => "f64.ceil",
        UnOp::F64Floor => "f64.floor",
        UnOp::F64Trunc => "f64.trunc",
        UnOp::F64Nearest => "f64.nearest",
        UnOp::F64Sqrt => "f64.sqrt",
        UnOp::I32WrapI64 => "i32.wrap_i64",
        UnOp::I64ExtendI32S => "i64.extend_i32_s",
        UnOp::I64ExtendI32U => "i64.extend_i32_u",
        UnOp::I32Extend8S => "i32.extend8_s",
        UnOp::I32Extend16S => "i32.extend16_s",
        UnOp::I64Extend8S => "i64.extend8_s",
        UnOp::I64Extend16S => "i64.extend16_s",
        UnOp::I64Extend32S => "i64.extend32_s",
        UnOp::I32TruncF32S => "i32.trunc_f32_s",
        UnOp::I32TruncF32U => "i32.trunc_f32_u",
        UnOp::I32TruncF64S => "i32.trunc_f64_s",
        UnOp::I32TruncF64U => "i32.trunc_f64_u",
        UnOp::I64TruncF32S => "i64.trunc_f32_s",
        UnOp::I64TruncF32U => "i64.trunc_f32_u",
        UnOp::I64TruncF64S => "i64.trunc_f64_s",
        UnOp::I64TruncF64U => "i64.trunc_f64_u",
        UnOp::I32TruncSatF32S => "i32.trunc_sat_f32_s",
        UnOp::I32TruncSatF32U => "i32.trunc_sat_f32_u",
        UnOp::I32TruncSatF64S => "i32.trunc_sat_f64_s",
        UnOp::I32TruncSatF64U => "i32.trunc_sat_f64_u",
        UnOp::I64TruncSatF32S => "i64.trunc_sat_f32_s",
        UnOp::I64TruncSatF32U => "i64.trunc_sat_f32_u",
        UnOp::I64TruncSatF64S => "i64.trunc_sat_f64_s",
        UnOp::I64TruncSatF64U => "i64.trunc_sat_f64_u",
        UnOp::F32ConvertI32S => "f32.convert_i32_s",
        UnOp::F32ConvertI32U => "f32.convert_i32_u",
        UnOp::F32ConvertI64S => "f32.convert_i64_s",
        UnOp::F32ConvertI64U => "f32.convert_i64_u",
        UnOp::F64ConvertI32S => "f64.convert_i32_s",
        UnOp::F64ConvertI32U => "f64.convert_i32_u",
        UnOp::F64ConvertI64S => "f64.convert_i64_s",
        UnOp::F64ConvertI64U => "f64.convert_i64_u",
        UnOp::F32DemoteF64 => "f32.demote_f64",
        UnOp::F64PromoteF32 => "f64.promote_f32",
        UnOp::I32ReinterpretF32 => "i32.reinterpret_f32",
        UnOp::I64ReinterpretF64 => "i64.reinterpret_f64",
        UnOp::F32ReinterpretI32 => "f32.reinterpret_i32",
        UnOp::F64ReinterpretI64 => "f64.reinterpret_i64",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use wasmparser::{Parser, Payload};

    fn sig(name: &str, params: Vec<ValType>, results: Vec<ValType>) -> FunctionSig {
        FunctionSig {
            name: name.to_owned(),
            params,
            results,
            exported: true,
            imported: false,
            local_names: Vec::new(),
        }
    }

    fn lift_first(wat: &str, s: &FunctionSig) -> LiftResult {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("wat parse");
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Ok(Payload::CodeSectionEntry(body)) = payload {
                return lift_function_body_wat(&body, s);
            }
        }
        panic!("no code section");
    }

    const ADD: &str =
        r"(module (func (param i32) (param i32) (result i32) local.get 0 local.get 1 i32.add))";
    const FIB: &str = r"
      (module (func (param i32) (result i32)
        local.get 0 i32.const 2 i32.lt_s
        if (result i32) local.get 0
        else local.get 0 i32.const 1 i32.sub i32.const 0 i32.add
        end))";
    const FLOATS: &str =
        r"(module (func (result f64) f64.const 3.5 f64.const 2.0 f64.mul f64.sqrt))";

    #[test]
    fn add_reparses_with_real_param_types() {
        let s: FunctionSig = sig("add", vec![ValType::I32, ValType::I32], vec![ValType::I32]);
        let out: LiftResult = lift_first(ADD, &s);
        assert!(
            out.pseudo_source
                .contains("(func $f0 (param $p0 i32) (param $p1 i32) (result i32)")
        );
        assert!(out.pseudo_source.contains("i32.add"));
        let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&out.pseudo_source);
        assert!(
            reparsed.is_ok(),
            "WAT must reparse: {:?}\n{}",
            reparsed.err(),
            out.pseudo_source
        );
    }

    #[test]
    fn if_else_reparses_as_real_control_flow() {
        let s: FunctionSig = sig("fib", vec![ValType::I32], vec![ValType::I32]);
        let out: LiftResult = lift_first(FIB, &s);
        assert!(out.pseudo_source.contains("if (result i32)"));
        assert!(out.pseudo_source.contains("else"));
        assert!(out.pseudo_source.contains("end"));
        let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&out.pseudo_source);
        assert!(
            reparsed.is_ok(),
            "if/else WAT must reparse: {:?}\n{}",
            reparsed.err(),
            out.pseudo_source
        );
    }

    #[test]
    fn float_consts_reparse() {
        let s: FunctionSig = sig("fl", Vec::new(), vec![ValType::F64]);
        let out: LiftResult = lift_first(FLOATS, &s);
        let reparsed: Result<Vec<u8>, wat::Error> = wat::parse_str(&out.pseudo_source);
        assert!(
            reparsed.is_ok(),
            "float WAT must reparse:\n{}",
            out.pseudo_source
        );
    }

    #[test]
    fn module_header_declares_memory_and_globals() {
        let header: String = wat_module_header(&[(0, ValType::I32), (2, ValType::I64)]);
        assert!(header.contains("(global $g0 (mut i32)"));
        assert!(header.contains("(global $g2 (mut i64)"));
        assert!(header.contains("(memory 1)"));
    }

    #[test]
    fn max_cont_type_index_does_not_overflow_fallback() {
        let mut reqs: FeatureReqs = FeatureReqs::default();
        let func_type_index: u32 = reqs.record_cont_type(u32::MAX);
        assert_eq!(func_type_index, u32::MAX - 1);
        assert!(reqs.func_types.contains_key(&(u32::MAX - 1)));
        assert_eq!(reqs.cont_types.get(&u32::MAX), Some(&(u32::MAX - 1)));
    }

    #[test]
    fn huge_struct_field_index_is_not_materialized() {
        let mut reqs: FeatureReqs = FeatureReqs::default();
        let mut has_calls: bool = false;
        let rendered: Option<String> = render_gc_op(
            &Operator::StructGet {
                struct_type_index: 0,
                field_index: u32::MAX,
            },
            &mut has_calls,
            &mut reqs,
        );
        assert!(rendered.is_none());
        assert!(reqs.struct_types.is_empty());

        let mut out: String = String::new();
        emit_gc_type_decls(&mut out, &reqs);
        assert!(out.is_empty());
    }

    #[test]
    fn bounded_struct_field_index_records_exact_count() {
        let mut reqs: FeatureReqs = FeatureReqs::default();
        let mut has_calls: bool = false;
        let field_index: u32 = MAX_SYNTHETIC_STRUCT_FIELDS - 1;
        let rendered: Option<String> = render_gc_op(
            &Operator::StructSet {
                struct_type_index: 7,
                field_index,
            },
            &mut has_calls,
            &mut reqs,
        );
        assert_eq!(rendered, Some(format!("struct.set $t7 {field_index}")));
        assert_eq!(
            reqs.struct_types.get(&7),
            Some(&MAX_SYNTHETIC_STRUCT_FIELDS)
        );
    }

    fn leb_u32(mut value: u32, out: &mut Vec<u8>) {
        loop {
            let mut byte: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn module_with_huge_locals(count: u32) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.push(0x01);
        leb_u32(count, &mut body);
        body.push(0x7f);
        body.push(0x0b);

        let mut code_section: Vec<u8> = Vec::new();
        code_section.push(0x01);
        leb_u32(
            u32::try_from(body.len()).expect("body fits u32"),
            &mut code_section,
        );
        code_section.extend_from_slice(&body);

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"\0asm");
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        out.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        out.push(0x0a);
        leb_u32(
            u32::try_from(code_section.len()).expect("code section fits u32"),
            &mut out,
        );
        out.extend_from_slice(&code_section);
        out
    }

    #[test]
    fn untrusted_locals_count_is_clamped_not_oom() {
        let bytes: Vec<u8> = module_with_huge_locals(u32::MAX);
        let mut bodies: Vec<(FunctionBody<'_>, FunctionSig)> = Vec::new();
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Ok(Payload::CodeSectionEntry(body)) = payload {
                bodies.push((body, sig("dos", Vec::new(), Vec::new())));
            }
        }
        assert_eq!(bodies.len(), 1, "code section must yield one body");

        let locals: Vec<ValType> = read_local_decls(&bodies[0].0).expect("locals decode");
        assert!(
            locals.len() <= MAX_FUNCTION_LOCALS,
            "locals must be clamped to the ceiling, got {}",
            locals.len()
        );
        assert_eq!(locals.len(), MAX_FUNCTION_LOCALS);

        let wat: String = lift_module_to_wat(&bodies, 0);
        assert!(wat.starts_with("(module"));
    }
}
