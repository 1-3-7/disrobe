use std::fmt::Write;

use wasmparser::{BlockType, FunctionBody, Operator, ValType};

use crate::lift::{LiftResult, LiftTarget};
use crate::signature::FunctionSig;
use crate::ssa::{binop_kind, unop_kind};

/// Re-prints one (already-structured) WebAssembly function as a complete, validating
/// `(module ...)` in text form.
///
/// Because the input operator stream is itself structured WASM, faithfully re-emitting it
/// round-trips through `wat::parse_str`. The function is named `$f0`; any
/// `call`/`call_indirect` is preserved by index so the module validates.
#[must_use]
pub(crate) fn lift_function_body_wat(body: &FunctionBody<'_>, sig: &FunctionSig) -> LiftResult {
    let func: WatFunc = render_func(body, sig, 0);
    let mut out: String = String::with_capacity(func.text.len() + 96);
    out.push_str(&wat_module_header(&func.globals_used));
    if func.has_calls {
        out.push_str("  (type $stub (func))\n");
    }
    out.push_str(&func.text);
    if sig.exported {
        let _ = writeln!(out, "  (export \"{}\" (func $f0))", sig.name);
    }
    out.push_str(")\n");
    LiftResult {
        target: LiftTarget::Wat,
        pseudo_source: out,
        blocks_emitted: func.blocks_emitted,
    }
}

/// Module header `(module ... (memory 1) (table ...))` covering every global / table
/// observed across the supplied functions.
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
        let t: &str = val_type_str(ty);
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
}

/// Assembles every defined function body into ONE validating `(module ...)`.
///
/// Shares memory, globals, and a table, with exports for the originally-exported
/// functions. Functions are named `$f<index>` and `call <n>` is preserved verbatim so
/// direct calls (including recursion) resolve. `defined_offset` is the count of imported
/// functions (the global index of the first defined function), so call indices line up.
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
    for (offset, (body, sig)) in funcs.iter().enumerate() {
        let global_index: u32 =
            defined_offset.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX));
        let f: WatFunc = render_func(body, sig, global_index);
        for g in f.globals_used {
            if !globals.iter().any(|(i, _)| *i == g.0) {
                globals.push(g);
            }
        }
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
    let mut out: String = wat_module_header(&globals);
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
    match render_operators(
        body,
        sig,
        &mut text,
        &mut globals_used,
        &mut blocks_emitted,
        &mut has_calls,
    ) {
        Ok(()) => {}
        Err(()) => {
            text.push_str("    unreachable\n");
        }
    }
    text.push_str("  )\n");
    WatFunc {
        text,
        globals_used,
        blocks_emitted,
        has_calls,
    }
}

fn read_local_decls(body: &FunctionBody<'_>) -> Result<Vec<ValType>, ()> {
    let reader: wasmparser::LocalsReader<'_> = body.get_locals_reader().map_err(|_| ())?;
    let mut out: Vec<ValType> = Vec::new();
    for item in reader {
        let (count, ty): (u32, ValType) = item.map_err(|_| ())?;
        for _ in 0..count {
            out.push(ty);
        }
    }
    Ok(out)
}

fn render_operators(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    out: &mut String,
    globals_used: &mut Vec<(u32, ValType)>,
    blocks_emitted: &mut usize,
    has_calls: &mut bool,
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
        let line: Option<String> = render_op(op, sig, globals_used, blocks_emitted, has_calls)?;
        if let Some(line) = line {
            let pad: String = "  ".repeat(depth);
            let _ = writeln!(out, "{pad}{line}");
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

#[allow(clippy::too_many_lines)]
fn render_op(
    op: &Operator<'_>,
    sig: &FunctionSig,
    globals_used: &mut Vec<(u32, ValType)>,
    blocks_emitted: &mut usize,
    has_calls: &mut bool,
) -> Result<Option<String>, ()> {
    if let Some((kind, _)) = binop_kind(op) {
        return Ok(Some(op_mnemonic(kind).to_owned()));
    }
    if let Some((unop, _)) = unop_kind(op) {
        return Ok(Some(unop_mnemonic(unop).to_owned()));
    }
    if let Some(line) = render_mem_op(op) {
        return Ok(Some(line));
    }
    let line: String = match op {
        Operator::Nop => return Ok(None),
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
        Operator::BrTable { targets } => render_br_table(targets)?,
        Operator::Call { function_index } => {
            *has_calls = true;
            format!("call $f{function_index}")
        }
        Operator::CallIndirect { type_index, .. } => {
            *has_calls = true;
            format!("call_indirect (type {type_index})")
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
        _ => return Err(()),
    };
    Ok(Some(line))
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

const fn val_type_str(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        _ => "i32",
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
}
