use std::fmt::Write;

use wasmparser::{BlockType, FunctionBody, Operator, ValType};

use crate::lift::{LiftCoverage, LiftResult, LiftTarget};
use crate::op_names::operator_mnemonic;
use crate::signature::{FunctionSig, MAX_FUNCTION_LOCALS};
use crate::ssa::{binop_kind, unop_kind};

/// Re-prints one structured WebAssembly function as a validating `(module ...)` in text form.
#[must_use]
pub(crate) fn lift_function_body_wat(body: &FunctionBody<'_>, sig: &FunctionSig) -> LiftResult {
    let func: WatFunc = render_func(body, sig, 0);
    let mut out: String = String::with_capacity(func.text.len() + 96);
    out.push_str(&module_prelude(&func.globals_used, &func.reqs));
    if func.has_calls {
        out.push_str("  (type $stub (func))\n");
    }
    emit_ref_func_targets(&mut out, &func.reqs);
    out.push_str(&func.text);
    if sig.exported {
        let _ = writeln!(out, "  (export \"{}\" (func $f0))", sig.name);
    }
    out.push_str(")\n");
    LiftResult {
        target: LiftTarget::Wat,
        pseudo_source: out,
        blocks_emitted: func.blocks_emitted,
        coverage: func.coverage,
    }
}

/// Module header sized to a function's feature requirements.
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
        let _ = writeln!(out, "  (global $g{idx} (mut {t}) ({t}.const 0))");
    }
    if reqs.shared_memory {
        out.push_str("  (memory 1 16 shared)\n");
    } else {
        out.push_str("  (memory 1 16)\n");
    }
    out.push_str("  (table $t0 1 funcref)\n");
    if reqs.externref_table {
        out.push_str("  (table $tref 1 externref)\n");
    }
    for seg in &reqs.data_segments {
        let _ = writeln!(out, "  (data $d{seg} \"\\00\\00\\00\\00\")");
    }
    for seg in &reqs.elem_segments {
        let _ = writeln!(out, "  (elem $e{seg} funcref)");
    }
    out
}

/// Synthesizes the `(type ...)` decls every gc / function-ref operator references.
fn emit_gc_type_decls(out: &mut String, reqs: &FeatureReqs) {
    for (idx, field_count) in &reqs.struct_types {
        let _ = write!(out, "  (type $t{idx} (struct");
        for _ in 0..(*field_count).max(1) {
            out.push_str(" (field (mut i32))");
        }
        out.push_str("))\n");
    }
    for idx in &reqs.array_types {
        let _ = writeln!(out, "  (type $t{idx} (array (mut i32)))");
    }
    for (idx, (params, results)) in &reqs.func_types {
        let _ = write!(out, "  (type $t{idx} (func");
        for ty in params {
            let _ = write!(out, " (param {})", val_type_str(*ty));
        }
        for ty in results {
            let _ = write!(out, " (result {})", val_type_str(*ty));
        }
        out.push_str("))\n");
    }
}

/// Synthesizes the `(tag ...)` decls every `throw` / `try_table` catch references.
fn emit_tag_decls(out: &mut String, reqs: &FeatureReqs) {
    for (idx, params) in &reqs.tags {
        let _ = write!(out, "  (tag $tag{idx} (param");
        for ty in params {
            let _ = write!(out, " {}", val_type_str(*ty));
        }
        out.push_str("))\n");
    }
}

/// Declares `ref.func` target functions plus an `(elem declare ...)`.
fn emit_ref_func_targets(out: &mut String, reqs: &FeatureReqs) {
    if reqs.ref_func_indices.is_empty() {
        return;
    }
    for idx in &reqs.ref_func_indices {
        if let Some((t, (_, results))) = reqs.func_types.iter().next() {
            let _ = write!(out, "  (func $rf{idx} (type $t{t})");
            for ty in results {
                let _ = write!(out, " ({}.const 0)", val_type_str(*ty));
            }
            out.push_str(")\n");
        } else {
            let _ = writeln!(out, "  (func $rf{idx})");
        }
    }
    out.push_str("  (elem declare func");
    for idx in &reqs.ref_func_indices {
        let _ = write!(out, " $rf{idx}");
    }
    out.push_str(")\n");
}

/// Module header covering every global and table observed across the functions.
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
        let _ = writeln!(out, "  (global $g{idx} (mut {t}) ({t}.const 0))");
    }
    out.push_str("  (memory 1)\n");
    out.push_str("  (table 1 funcref)\n");
    out
}

struct WatFunc {
    text: String,
    globals_used: Vec<(u32, ValType)>,
    blocks_emitted: usize,
    has_calls: bool,
    coverage: LiftCoverage,
    reqs: FeatureReqs,
}

/// Module-context requirements a re-printed function needs to validate.
#[derive(Debug, Default, Clone)]
struct FeatureReqs {
    shared_memory: bool,
    data_segments: std::collections::BTreeSet<u32>,
    elem_segments: std::collections::BTreeSet<u32>,
    funcref_table: bool,
    externref_table: bool,
    ref_func_indices: std::collections::BTreeSet<u32>,
    tags: std::collections::BTreeMap<u32, Vec<ValType>>,
    struct_types: std::collections::BTreeMap<u32, u32>,
    array_types: std::collections::BTreeSet<u32>,
    func_types: std::collections::BTreeMap<u32, (Vec<ValType>, Vec<ValType>)>,
}

impl FeatureReqs {
    fn merge(&mut self, other: &Self) {
        self.shared_memory |= other.shared_memory;
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
        self.array_types.extend(&other.array_types);
        for (idx, sig) in &other.func_types {
            self.func_types.entry(*idx).or_insert_with(|| sig.clone());
        }
    }

    fn record_func_type(&mut self, idx: u32) {
        self.func_types
            .entry(idx)
            .or_insert_with(|| (vec![ValType::I32], vec![ValType::I32]));
    }
}

/// Assembles every defined function body into one validating `(module ...)`.
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
        let _ = writeln!(
            imports,
            "  (func $f{i} (param i32) (result i32) i32.const 0)"
        );
    }
    let mut reqs: FeatureReqs = FeatureReqs::default();
    for (offset, (body, sig)) in funcs.iter().enumerate() {
        let global_index: u32 =
            defined_offset.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX));
        let f: WatFunc = render_func(body, sig, global_index);
        for g in f.globals_used {
            if !globals.iter().any(|(i, _)| *i == g.0) {
                globals.push(g);
            }
        }
        reqs.merge(&f.reqs);
        bodies.push_str(&f.text);
        if sig.exported {
            let _ = writeln!(
                exports,
                "  (export \"{}\" (func $f{global_index}))",
                sig.name
            );
        }
    }
    let _ = total;
    let mut out: String = module_prelude(&globals, &reqs);
    out.push_str(&imports);
    out.push_str(&bodies);
    out.push_str(&exports);
    out.push_str(")\n");
    out
}

fn render_func(body: &FunctionBody<'_>, sig: &FunctionSig, func_index: u32) -> WatFunc {
    let mut text: String = String::with_capacity(256);
    let _ = write!(text, "  (func $f{func_index}");
    for (i, ty) in sig.params.iter().enumerate() {
        let _ = write!(text, " (param $p{i} {})", val_type_str(*ty));
    }
    if let Some(ret) = sig.results.first() {
        let _ = write!(text, " (result {})", val_type_str(*ret));
    }
    text.push('\n');

    let locals: Vec<ValType> = read_local_decls(body).unwrap_or_default();
    let param_count: usize = sig.params.len();
    for (i, ty) in locals.iter().enumerate() {
        let _ = writeln!(
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
    out: &mut String,
    globals_used: &mut Vec<(u32, ValType)>,
    blocks_emitted: &mut usize,
    has_calls: &mut bool,
    coverage: &mut LiftCoverage,
    reqs: &mut FeatureReqs,
) -> Result<(), ()> {
    let reader: wasmparser::OperatorsReader<'_> = body.get_operators_reader().map_err(|_| ())?;
    let mut ops: Vec<Operator<'_>> = Vec::new();
    for op in reader {
        ops.push(op.map_err(|_| ())?);
    }
    let op_count: usize = ops.len();
    let mut depth: usize = 2;
    for (i, op) in ops.iter().enumerate() {
        let is_final_end: bool = i + 1 == op_count && matches!(op, Operator::End);
        if is_final_end {
            break;
        }
        if matches!(op, Operator::End | Operator::Else) {
            depth = depth.saturating_sub(1);
        }
        let rendered: Rendered = render_op(op, sig, globals_used, blocks_emitted, has_calls, reqs);
        match rendered {
            Rendered::Translated(Some(line)) => {
                coverage.record_translated();
                let pad: String = "  ".repeat(depth);
                let _ = writeln!(out, "{pad}{line}");
            }
            Rendered::Translated(None) => coverage.record_translated(),
            Rendered::Untranslated => {
                coverage.record_untranslated(operator_mnemonic(op));
                let pad: String = "  ".repeat(depth);
                let _ = writeln!(out, "{pad}unreachable");
            }
        }
        if matches!(
            op,
            Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } | Operator::Else
        ) {
            depth += 1;
        }
    }
    Ok(())
}

/// Outcome of re-printing one operator: translated (with optional text) or untranslated.
enum Rendered {
    Translated(Option<String>),
    Untranslated,
}

#[allow(clippy::too_many_lines)]
fn render_op(
    op: &Operator<'_>,
    sig: &FunctionSig,
    globals_used: &mut Vec<(u32, ValType)>,
    blocks_emitted: &mut usize,
    has_calls: &mut bool,
    reqs: &mut FeatureReqs,
) -> Rendered {
    if let Some((kind, _)) = binop_kind(op) {
        return Rendered::Translated(Some(op_mnemonic(kind).to_owned()));
    }
    if let Some((unop, _)) = unop_kind(op) {
        return Rendered::Translated(Some(unop_mnemonic(unop).to_owned()));
    }
    if let Some(line) = render_mem_op(op) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_simd_op(op) {
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
    if let Some(line) = render_ref_op(op, reqs) {
        return Rendered::Translated(Some(line));
    }
    if let Some(line) = render_gc_op(op, has_calls, reqs) {
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
            format!("block{}", block_result_suffix(*blockty))
        }
        Operator::Loop { blockty } => {
            *blocks_emitted += 1;
            format!("loop{}", block_result_suffix(*blockty))
        }
        Operator::If { blockty } => {
            *blocks_emitted += 1;
            format!("if{}", block_result_suffix(*blockty))
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
        Operator::MemorySize { .. } => "memory.size".to_owned(),
        Operator::MemoryGrow { .. } => "memory.grow".to_owned(),
        _ => return Rendered::Untranslated,
    };
    Rendered::Translated(Some(line))
}

fn render_br_table(targets: &wasmparser::BrTable<'_>) -> Result<String, ()> {
    let mut s: String = String::from("br_table");
    for tgt in targets.targets() {
        let depth: u32 = tgt.map_err(|_| ())?;
        let _ = write!(s, " {depth}");
    }
    let _ = write!(s, " {}", targets.default());
    Ok(s)
}

fn render_mem_op(op: &Operator<'_>) -> Option<String> {
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
    Some(format!(
        "{mnemonic} offset={} align={}",
        memarg.offset,
        1u32 << memarg.align
    ))
}

/// Re-prints fixed-width SIMD / v128 operators.
fn render_simd_op(op: &Operator<'_>) -> Option<String> {
    if let Some((mnemonic, memarg)) = simd_mem_mnemonic(op) {
        return Some(format!(
            "{mnemonic} offset={} align={}",
            memarg.offset,
            1u32 << memarg.align
        ));
    }
    if let Some((mnemonic, memarg, lane)) = simd_lane_mem_mnemonic(op) {
        return Some(format!(
            "{mnemonic} offset={} align={} {lane}",
            memarg.offset,
            1u32 << memarg.align
        ));
    }
    Some(match op {
        Operator::V128Const { value } => {
            let mut s: String = String::from("v128.const i8x16");
            for byte in value.bytes() {
                let _ = write!(s, " {byte}");
            }
            s
        }
        Operator::I8x16Shuffle { lanes } => {
            let mut s: String = String::from("i8x16.shuffle");
            for lane in lanes {
                let _ = write!(s, " {lane}");
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
        _ => return None,
    })
}

const fn simd_mem_mnemonic(op: &Operator<'_>) -> Option<(&'static str, wasmparser::MemArg)> {
    Some(match op {
        Operator::V128Load { memarg } => ("v128.load", *memarg),
        Operator::V128Store { memarg } => ("v128.store", *memarg),
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

/// Re-prints atomic operators, flagging the module as needing shared memory.
fn render_atomic_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    if let Some((mnemonic, memarg)) = atomic_mem_mnemonic(op) {
        reqs.shared_memory = true;
        return Some(format!(
            "{mnemonic} offset={} align={}",
            memarg.offset,
            1u32 << memarg.align
        ));
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

/// Re-prints bulk-memory operators, recording any passive data segment referenced.
fn render_bulk_memory_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::MemoryCopy { .. } => "memory.copy".to_owned(),
        Operator::MemoryFill { .. } => "memory.fill".to_owned(),
        Operator::MemoryInit { data_index, .. } => {
            reqs.data_segments.insert(*data_index);
            format!("memory.init $d{data_index}")
        }
        Operator::DataDrop { data_index } => {
            reqs.data_segments.insert(*data_index);
            format!("data.drop $d{data_index}")
        }
        _ => return None,
    })
}

/// Re-prints table operators against the synthetic `$t0`/`$tref` tables.
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
    if table == 0 { "$t0" } else { "$tref" }
}

/// Re-prints reference operators; records `ref.func` targets for the elem-declare.
fn render_ref_op(op: &Operator<'_>, reqs: &mut FeatureReqs) -> Option<String> {
    Some(match op {
        Operator::RefIsNull => "ref.is_null".to_owned(),
        Operator::RefNull {
            hty: wasmparser::HeapType::Abstract { shared: _, ty },
        } => format!("ref.null {}", abstract_heap_keyword(*ty)),
        Operator::RefNull { .. } => "ref.null func".to_owned(),
        Operator::RefFunc { function_index } => {
            reqs.ref_func_indices.insert(*function_index);
            format!("ref.func $rf{function_index}")
        }
        _ => return None,
    })
}

/// Re-prints garbage-collection and typed-function-reference operators.
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
        _ => return None,
    })
}

const fn abstract_heap_keyword(ty: wasmparser::AbstractHeapType) -> &'static str {
    use wasmparser::AbstractHeapType;
    match ty {
        AbstractHeapType::Extern => "extern",
        AbstractHeapType::Func => "func",
        _ => "func",
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

const fn block_result_suffix(blockty: BlockType) -> &'static str {
    match blockty {
        BlockType::Type(ValType::I64) => " (result i64)",
        BlockType::Type(ValType::F32) => " (result f32)",
        BlockType::Type(ValType::F64) => " (result f64)",
        BlockType::Type(_) => " (result i32)",
        BlockType::Empty | BlockType::FuncType(_) => "",
    }
}

fn val_type_str(ty: ValType) -> String {
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
