use std::fmt::Write;

use serde::Serialize;
use wasmparser::ValType;

use crate::signature::FunctionSig;
use crate::ssa::{OpKind, UnOp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LiftTarget {
    Rust,
    TypeScript,
    Wat,
    C,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiftResult {
    pub target: LiftTarget,
    pub pseudo_source: String,
    pub blocks_emitted: usize,
}

/// Self-contained Rust runtime prelude that the lifted function bodies call into.
///
/// Prepending this to any concatenation of lifted Rust functions yields a single
/// compilable translation unit (`rustc --crate-type lib`).
#[must_use]
pub const fn rust_runtime_prelude() -> &'static str {
    RUST_PRELUDE
}

/// Self-contained TypeScript runtime prelude.
#[must_use]
pub const fn typescript_runtime_prelude() -> &'static str {
    TS_PRELUDE
}

/// Lifts a single function body to compilable high-level source for `target`.
///
/// Uses the recovered signature `sig` and module-wide `callees` to emit real
/// param/return types and real `call` targets. Rust / TypeScript / C go through the
/// structured operator-stream translator; WAT re-prints the (already structured) operators.
///
/// This is the production entry point: it consumes the WASM operator stream directly
/// (WASM is a structured stack machine), so the emitted control flow is correct by
/// construction without needing CFG/SSA reconstruction.
#[must_use]
pub fn lift_function_body(
    body: &wasmparser::FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    target: LiftTarget,
) -> LiftResult {
    match target {
        LiftTarget::Rust => lift_body_high(body, sig, callees, LiftTarget::Rust, HighLang::Rust),
        LiftTarget::TypeScript => lift_body_high(
            body,
            sig,
            callees,
            LiftTarget::TypeScript,
            HighLang::TypeScript,
        ),
        LiftTarget::C => crate::lift_c::lift_function_body_c(body, sig, callees),
        LiftTarget::Wat => crate::lift_wat::lift_function_body_wat(body, sig),
    }
}

fn lift_body_high(
    body: &wasmparser::FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    target: LiftTarget,
    lang: HighLang,
) -> LiftResult {
    match crate::structured::lift_body_structured(body, sig, callees, lang) {
        Ok((source, blocks_emitted)) => LiftResult {
            target,
            pseudo_source: source,
            blocks_emitted,
        },
        Err(e) => LiftResult {
            target,
            pseudo_source: unliftable_stub(sig, target, &e.to_string()),
            blocks_emitted: 0,
        },
    }
}

fn unliftable_stub(sig: &FunctionSig, target: LiftTarget, reason: &str) -> String {
    let mut s: String = String::new();
    match target {
        LiftTarget::Rust => {
            let _ = writeln!(s, "/// not lifted: {reason}");
            let _ = write!(s, "pub fn {}(", sig.name);
            for (i, ty) in sig.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                let _ = write!(s, "p{i}: {}", rust_type(*ty));
            }
            s.push(')');
            if let Some(ret) = sig.results.first() {
                let _ = write!(s, " -> {}", rust_type(*ret));
            }
            s.push_str(" {\n");
            for i in 0..sig.params.len() {
                let _ = writeln!(s, "    let _ = p{i};");
            }
            if let Some(ret) = sig.results.first() {
                let _ = writeln!(s, "    {}", zero_literal(*ret, target));
            }
            s.push_str("}\n");
        }
        LiftTarget::TypeScript => {
            let _ = writeln!(s, "// not lifted: {reason}");
            let _ = write!(s, "export function {}(", sig.name);
            for (i, ty) in sig.params.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                let _ = write!(s, "p{i}: {}", ts_type(*ty));
            }
            let ret: &str = sig.results.first().map_or("void", |t| ts_type(*t));
            let _ = writeln!(s, "): {ret} {{");
            if let Some(ret) = sig.results.first() {
                let _ = writeln!(s, "    return {};", zero_literal(*ret, target));
            }
            s.push_str("}\n");
        }
        LiftTarget::Wat | LiftTarget::C => unreachable!("handled separately"),
    }
    s
}

/// High-level lift targets that share the structured operator-stream translator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HighLang {
    Rust,
    TypeScript,
    C,
}

/// Resolves WebAssembly function indices to emitted source identifiers and signatures.
///
/// Lets `call` lift to a real, correctly-arg-counted call of the corresponding lifted
/// function rather than a dangling `func_<idx>`. Indices not present fall back to
/// `func_<idx>` with a 1-arg / i32-result guess.
#[derive(Debug, Clone, Default)]
pub struct CalleeNames {
    names: Vec<String>,
    signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
    type_signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
}

impl CalleeNames {
    #[inline]
    #[must_use]
    pub const fn new(names: Vec<String>) -> Self {
        Self {
            names,
            signatures: Vec::new(),
            type_signatures: Vec::new(),
        }
    }

    #[inline]
    #[must_use]
    pub const fn with_signatures(
        names: Vec<String>,
        signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
        type_signatures: Vec<(Vec<ValType>, Vec<ValType>)>,
    ) -> Self {
        Self {
            names,
            signatures,
            type_signatures,
        }
    }

    #[must_use]
    pub(crate) fn resolve(&self, function_index: u32) -> String {
        self.names
            .get(function_index as usize)
            .cloned()
            .unwrap_or_else(|| format!("func_{function_index}"))
    }

    #[must_use]
    pub(crate) fn signature(&self, function_index: u32) -> (Vec<ValType>, Vec<ValType>) {
        self.signatures
            .get(function_index as usize)
            .cloned()
            .unwrap_or_else(|| (vec![ValType::I32], vec![ValType::I32]))
    }

    #[must_use]
    pub(crate) fn type_signature(&self, type_index: u32) -> (Vec<ValType>, Vec<ValType>) {
        self.type_signatures
            .get(type_index as usize)
            .cloned()
            .unwrap_or_else(|| (vec![ValType::I32], vec![ValType::I32]))
    }
}

const fn rust_type(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "u128",
        ValType::Ref(_) => "usize",
        ValType::I32 => "i32",
    }
}

const fn ts_type(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 | ValType::V128 => "bigint",
        ValType::I32 | ValType::F32 | ValType::F64 | ValType::Ref(_) => "number",
    }
}

fn zero_literal(ty: ValType, target: LiftTarget) -> String {
    match (target, ty) {
        (LiftTarget::Rust, ValType::I64) => "0i64".to_owned(),
        (LiftTarget::Rust, ValType::F32) => "0.0f32".to_owned(),
        (LiftTarget::Rust, ValType::F64) => "0.0f64".to_owned(),
        (LiftTarget::Rust, ValType::V128) => "0u128".to_owned(),
        (LiftTarget::Rust, _) => "0i32".to_owned(),
        (LiftTarget::TypeScript, ValType::I64 | ValType::V128) => "0n".to_owned(),
        (_, _) => "0".to_owned(),
    }
}

pub(crate) const fn rust_op_fn_name(kind: OpKind) -> &'static str {
    match kind {
        OpKind::I32Add => "wasm_i32_add",
        OpKind::I32Sub => "wasm_i32_sub",
        OpKind::I32Mul => "wasm_i32_mul",
        OpKind::I32DivS => "wasm_i32_div_s",
        OpKind::I32DivU => "wasm_i32_div_u",
        OpKind::I32RemS => "wasm_i32_rem_s",
        OpKind::I32RemU => "wasm_i32_rem_u",
        OpKind::I32And => "wasm_i32_and",
        OpKind::I32Or => "wasm_i32_or",
        OpKind::I32Xor => "wasm_i32_xor",
        OpKind::I32Shl => "wasm_i32_shl",
        OpKind::I32ShrU => "wasm_i32_shr_u",
        OpKind::I32ShrS => "wasm_i32_shr_s",
        OpKind::I32Rotl => "wasm_i32_rotl",
        OpKind::I32Rotr => "wasm_i32_rotr",
        OpKind::I32Eq => "wasm_i32_eq",
        OpKind::I32Ne => "wasm_i32_ne",
        OpKind::I32LtS => "wasm_i32_lt_s",
        OpKind::I32LtU => "wasm_i32_lt_u",
        OpKind::I32GtS => "wasm_i32_gt_s",
        OpKind::I32GtU => "wasm_i32_gt_u",
        OpKind::I32LeS => "wasm_i32_le_s",
        OpKind::I32LeU => "wasm_i32_le_u",
        OpKind::I32GeS => "wasm_i32_ge_s",
        OpKind::I32GeU => "wasm_i32_ge_u",
        OpKind::I64Add => "wasm_i64_add",
        OpKind::I64Sub => "wasm_i64_sub",
        OpKind::I64Mul => "wasm_i64_mul",
        OpKind::I64DivS => "wasm_i64_div_s",
        OpKind::I64DivU => "wasm_i64_div_u",
        OpKind::I64RemS => "wasm_i64_rem_s",
        OpKind::I64RemU => "wasm_i64_rem_u",
        OpKind::I64And => "wasm_i64_and",
        OpKind::I64Or => "wasm_i64_or",
        OpKind::I64Xor => "wasm_i64_xor",
        OpKind::I64Shl => "wasm_i64_shl",
        OpKind::I64ShrU => "wasm_i64_shr_u",
        OpKind::I64ShrS => "wasm_i64_shr_s",
        OpKind::I64Rotl => "wasm_i64_rotl",
        OpKind::I64Rotr => "wasm_i64_rotr",
        OpKind::I64Eq => "wasm_i64_eq",
        OpKind::I64Ne => "wasm_i64_ne",
        OpKind::I64LtS => "wasm_i64_lt_s",
        OpKind::I64LtU => "wasm_i64_lt_u",
        OpKind::I64GtS => "wasm_i64_gt_s",
        OpKind::I64GtU => "wasm_i64_gt_u",
        OpKind::I64LeS => "wasm_i64_le_s",
        OpKind::I64LeU => "wasm_i64_le_u",
        OpKind::I64GeS => "wasm_i64_ge_s",
        OpKind::I64GeU => "wasm_i64_ge_u",
        OpKind::F32Add => "wasm_f32_add",
        OpKind::F32Sub => "wasm_f32_sub",
        OpKind::F32Mul => "wasm_f32_mul",
        OpKind::F32Div => "wasm_f32_div",
        OpKind::F32Min => "wasm_f32_min",
        OpKind::F32Max => "wasm_f32_max",
        OpKind::F32Copysign => "wasm_f32_copysign",
        OpKind::F32Eq => "wasm_f32_eq",
        OpKind::F32Ne => "wasm_f32_ne",
        OpKind::F32Lt => "wasm_f32_lt",
        OpKind::F32Gt => "wasm_f32_gt",
        OpKind::F32Le => "wasm_f32_le",
        OpKind::F32Ge => "wasm_f32_ge",
        OpKind::F64Add => "wasm_f64_add",
        OpKind::F64Sub => "wasm_f64_sub",
        OpKind::F64Mul => "wasm_f64_mul",
        OpKind::F64Div => "wasm_f64_div",
        OpKind::F64Min => "wasm_f64_min",
        OpKind::F64Max => "wasm_f64_max",
        OpKind::F64Copysign => "wasm_f64_copysign",
        OpKind::F64Eq => "wasm_f64_eq",
        OpKind::F64Ne => "wasm_f64_ne",
        OpKind::F64Lt => "wasm_f64_lt",
        OpKind::F64Gt => "wasm_f64_gt",
        OpKind::F64Le => "wasm_f64_le",
        OpKind::F64Ge => "wasm_f64_ge",
    }
}

pub(crate) const fn rust_unop_fn_name(op: UnOp) -> &'static str {
    match op {
        UnOp::I32Eqz => "wasm_i32_eqz",
        UnOp::I64Eqz => "wasm_i64_eqz",
        UnOp::I32Clz => "wasm_i32_clz",
        UnOp::I32Ctz => "wasm_i32_ctz",
        UnOp::I32Popcnt => "wasm_i32_popcnt",
        UnOp::I64Clz => "wasm_i64_clz",
        UnOp::I64Ctz => "wasm_i64_ctz",
        UnOp::I64Popcnt => "wasm_i64_popcnt",
        UnOp::F32Abs => "wasm_f32_abs",
        UnOp::F32Neg => "wasm_f32_neg",
        UnOp::F32Ceil => "wasm_f32_ceil",
        UnOp::F32Floor => "wasm_f32_floor",
        UnOp::F32Trunc => "wasm_f32_trunc",
        UnOp::F32Nearest => "wasm_f32_nearest",
        UnOp::F32Sqrt => "wasm_f32_sqrt",
        UnOp::F64Abs => "wasm_f64_abs",
        UnOp::F64Neg => "wasm_f64_neg",
        UnOp::F64Ceil => "wasm_f64_ceil",
        UnOp::F64Floor => "wasm_f64_floor",
        UnOp::F64Trunc => "wasm_f64_trunc",
        UnOp::F64Nearest => "wasm_f64_nearest",
        UnOp::F64Sqrt => "wasm_f64_sqrt",
        UnOp::I32WrapI64 => "wasm_i32_wrap_i64",
        UnOp::I64ExtendI32S => "wasm_i64_extend_i32_s",
        UnOp::I64ExtendI32U => "wasm_i64_extend_i32_u",
        UnOp::I32Extend8S => "wasm_i32_extend8_s",
        UnOp::I32Extend16S => "wasm_i32_extend16_s",
        UnOp::I64Extend8S => "wasm_i64_extend8_s",
        UnOp::I64Extend16S => "wasm_i64_extend16_s",
        UnOp::I64Extend32S => "wasm_i64_extend32_s",
        UnOp::I32TruncF32S => "wasm_i32_trunc_f32_s",
        UnOp::I32TruncF32U => "wasm_i32_trunc_f32_u",
        UnOp::I32TruncF64S => "wasm_i32_trunc_f64_s",
        UnOp::I32TruncF64U => "wasm_i32_trunc_f64_u",
        UnOp::I64TruncF32S => "wasm_i64_trunc_f32_s",
        UnOp::I64TruncF32U => "wasm_i64_trunc_f32_u",
        UnOp::I64TruncF64S => "wasm_i64_trunc_f64_s",
        UnOp::I64TruncF64U => "wasm_i64_trunc_f64_u",
        UnOp::F32ConvertI32S => "wasm_f32_convert_i32_s",
        UnOp::F32ConvertI32U => "wasm_f32_convert_i32_u",
        UnOp::F32ConvertI64S => "wasm_f32_convert_i64_s",
        UnOp::F32ConvertI64U => "wasm_f32_convert_i64_u",
        UnOp::F64ConvertI32S => "wasm_f64_convert_i32_s",
        UnOp::F64ConvertI32U => "wasm_f64_convert_i32_u",
        UnOp::F64ConvertI64S => "wasm_f64_convert_i64_s",
        UnOp::F64ConvertI64U => "wasm_f64_convert_i64_u",
        UnOp::F32DemoteF64 => "wasm_f32_demote_f64",
        UnOp::F64PromoteF32 => "wasm_f64_promote_f32",
        UnOp::I32ReinterpretF32 => "wasm_i32_reinterpret_f32",
        UnOp::I64ReinterpretF64 => "wasm_i64_reinterpret_f64",
        UnOp::F32ReinterpretI32 => "wasm_f32_reinterpret_i32",
        UnOp::F64ReinterpretI64 => "wasm_f64_reinterpret_i64",
    }
}

const RUST_PRELUDE: &str = include_str!("prelude/rust.rs.txt");
const TS_PRELUDE: &str = include_str!("prelude/typescript.ts.txt");
