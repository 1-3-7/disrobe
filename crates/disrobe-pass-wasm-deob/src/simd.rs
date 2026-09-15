use serde::Serialize;
use wasmparser::{Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SimdLane {
    I8x16,
    I16x8,
    I32x4,
    I64x2,
    F32x4,
    F64x2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SimdFlavor {
    Standard,
    Relaxed,
    V128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimdOpRecord {
    pub mnemonic: &'static str,
    pub flavor: SimdFlavor,
    pub lane: Option<SimdLane>,
    pub rust_lift: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SimdReport {
    pub ops: Vec<SimdOpRecord>,
    pub uses_v128: bool,
    pub uses_relaxed: bool,
}

impl SimdReport {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    #[inline]
    #[must_use]
    pub const fn op_count(&self) -> usize {
        self.ops.len()
    }

    #[inline]
    #[must_use]
    pub fn relaxed_count(&self) -> usize {
        self.ops
            .iter()
            .filter(|o: &&SimdOpRecord| matches!(o.flavor, SimdFlavor::Relaxed))
            .count()
    }
}

pub fn scan_simd(input: &[u8]) -> Result<SimdReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-SIMD: not a wasm module".to_owned(),
        ));
    }
    let mut report: SimdReport = SimdReport::default();
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let reader: wasmparser::OperatorsReader<'_> = body
                .get_operators_reader()
                .map_err(|e| Error::Parse(format!("{e}")))?;
            for op in reader {
                let op: Operator<'_> = op.map_err(|e| Error::Parse(format!("{e}")))?;
                if let Some(rec) = classify_simd(&op) {
                    if matches!(rec.flavor, SimdFlavor::V128 | SimdFlavor::Standard) {
                        report.uses_v128 = true;
                    }
                    if matches!(rec.flavor, SimdFlavor::Relaxed) {
                        report.uses_relaxed = true;
                    }
                    report.ops.push(rec);
                }
            }
        }
    }
    Ok(report)
}

fn classify_simd(op: &Operator<'_>) -> Option<SimdOpRecord> {
    let (mnemonic, flavor, lane): (&'static str, SimdFlavor, Option<SimdLane>) = match op {
        Operator::V128Load { .. } => ("v128.load", SimdFlavor::V128, None),
        Operator::V128Store { .. } => ("v128.store", SimdFlavor::V128, None),
        Operator::V128Const { .. } => ("v128.const", SimdFlavor::V128, None),
        Operator::V128Not => ("v128.not", SimdFlavor::V128, None),
        Operator::V128And => ("v128.and", SimdFlavor::V128, None),
        Operator::V128Or => ("v128.or", SimdFlavor::V128, None),
        Operator::V128Xor => ("v128.xor", SimdFlavor::V128, None),
        Operator::V128Bitselect => ("v128.bitselect", SimdFlavor::V128, None),
        Operator::I8x16Splat => ("i8x16.splat", SimdFlavor::Standard, Some(SimdLane::I8x16)),
        Operator::I8x16Add => ("i8x16.add", SimdFlavor::Standard, Some(SimdLane::I8x16)),
        Operator::I8x16Sub => ("i8x16.sub", SimdFlavor::Standard, Some(SimdLane::I8x16)),
        Operator::I16x8Splat => ("i16x8.splat", SimdFlavor::Standard, Some(SimdLane::I16x8)),
        Operator::I16x8Add => ("i16x8.add", SimdFlavor::Standard, Some(SimdLane::I16x8)),
        Operator::I32x4Splat => ("i32x4.splat", SimdFlavor::Standard, Some(SimdLane::I32x4)),
        Operator::I32x4Add => ("i32x4.add", SimdFlavor::Standard, Some(SimdLane::I32x4)),
        Operator::I32x4Mul => ("i32x4.mul", SimdFlavor::Standard, Some(SimdLane::I32x4)),
        Operator::I64x2Splat => ("i64x2.splat", SimdFlavor::Standard, Some(SimdLane::I64x2)),
        Operator::I64x2Add => ("i64x2.add", SimdFlavor::Standard, Some(SimdLane::I64x2)),
        Operator::F32x4Splat => ("f32x4.splat", SimdFlavor::Standard, Some(SimdLane::F32x4)),
        Operator::F32x4Add => ("f32x4.add", SimdFlavor::Standard, Some(SimdLane::F32x4)),
        Operator::F32x4Mul => ("f32x4.mul", SimdFlavor::Standard, Some(SimdLane::F32x4)),
        Operator::F64x2Splat => ("f64x2.splat", SimdFlavor::Standard, Some(SimdLane::F64x2)),
        Operator::F64x2Add => ("f64x2.add", SimdFlavor::Standard, Some(SimdLane::F64x2)),
        Operator::I8x16Swizzle => ("i8x16.swizzle", SimdFlavor::Standard, Some(SimdLane::I8x16)),
        Operator::I8x16Shuffle { .. } => {
            ("i8x16.shuffle", SimdFlavor::Standard, Some(SimdLane::I8x16))
        }
        Operator::I8x16RelaxedSwizzle => (
            "i8x16.relaxed_swizzle",
            SimdFlavor::Relaxed,
            Some(SimdLane::I8x16),
        ),
        Operator::I32x4RelaxedTruncF32x4S => (
            "i32x4.relaxed_trunc_f32x4_s",
            SimdFlavor::Relaxed,
            Some(SimdLane::I32x4),
        ),
        Operator::I32x4RelaxedTruncF32x4U => (
            "i32x4.relaxed_trunc_f32x4_u",
            SimdFlavor::Relaxed,
            Some(SimdLane::I32x4),
        ),
        Operator::F32x4RelaxedMadd => (
            "f32x4.relaxed_madd",
            SimdFlavor::Relaxed,
            Some(SimdLane::F32x4),
        ),
        Operator::F32x4RelaxedNmadd => (
            "f32x4.relaxed_nmadd",
            SimdFlavor::Relaxed,
            Some(SimdLane::F32x4),
        ),
        Operator::F64x2RelaxedMadd => (
            "f64x2.relaxed_madd",
            SimdFlavor::Relaxed,
            Some(SimdLane::F64x2),
        ),
        Operator::F64x2RelaxedNmadd => (
            "f64x2.relaxed_nmadd",
            SimdFlavor::Relaxed,
            Some(SimdLane::F64x2),
        ),
        Operator::I8x16RelaxedLaneselect => (
            "i8x16.relaxed_laneselect",
            SimdFlavor::Relaxed,
            Some(SimdLane::I8x16),
        ),
        Operator::I16x8RelaxedLaneselect => (
            "i16x8.relaxed_laneselect",
            SimdFlavor::Relaxed,
            Some(SimdLane::I16x8),
        ),
        Operator::I32x4RelaxedLaneselect => (
            "i32x4.relaxed_laneselect",
            SimdFlavor::Relaxed,
            Some(SimdLane::I32x4),
        ),
        Operator::I64x2RelaxedLaneselect => (
            "i64x2.relaxed_laneselect",
            SimdFlavor::Relaxed,
            Some(SimdLane::I64x2),
        ),
        _ => return None,
    };
    let rust_lift: String = rust_lift_for(mnemonic, flavor);
    Some(SimdOpRecord {
        mnemonic,
        flavor,
        lane,
        rust_lift,
    })
}

fn rust_lift_for(mnemonic: &str, flavor: SimdFlavor) -> String {
    let portable_alt: &'static str = match mnemonic {
        "i32x4.add" => "core::simd::i32x4::splat(0)",
        "f32x4.add" => "core::simd::f32x4::splat(0.0)",
        _ => "core::simd::u8x16::splat(0)",
    };
    let conservative: &str = match flavor {
        SimdFlavor::Relaxed => "/* relaxed-simd: conservative lift, semantics underspecified */",
        _ => "",
    };
    let intrinsic: String = match mnemonic {
        "v128.load" => "std::arch::wasm32::v128_load(ptr as *const v128)".to_owned(),
        "v128.store" => "std::arch::wasm32::v128_store(ptr as *mut v128, value)".to_owned(),
        "v128.and" => "std::arch::wasm32::v128_and(a, b)".to_owned(),
        "v128.or" => "std::arch::wasm32::v128_or(a, b)".to_owned(),
        "v128.xor" => "std::arch::wasm32::v128_xor(a, b)".to_owned(),
        "v128.not" => "std::arch::wasm32::v128_not(a)".to_owned(),
        "v128.bitselect" => "std::arch::wasm32::v128_bitselect(a, b, mask)".to_owned(),
        "i32x4.add" => "std::arch::wasm32::i32x4_add(a, b)".to_owned(),
        "f32x4.add" => "std::arch::wasm32::f32x4_add(a, b)".to_owned(),
        "f32x4.mul" => "std::arch::wasm32::f32x4_mul(a, b)".to_owned(),
        "f32x4.relaxed_madd" => "std::arch::wasm32::f32x4_relaxed_madd(a, b, c)".to_owned(),
        _ => format!("/* portable fallback */ {portable_alt}"),
    };
    format!("{conservative}{intrinsic}")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SIMD_WAT: &str = r#"
        (module
          (memory 1)
          (func (export "splat_add") (result v128)
            i32.const 1
            i32x4.splat
            i32.const 2
            i32x4.splat
            i32x4.add))
    "#;

    const RELAXED_WAT: &str = r#"
        (module
          (memory 1)
          (func (export "madd") (param v128 v128 v128) (result v128)
            local.get 0 local.get 1 local.get 2
            f32x4.relaxed_madd))
    "#;

    #[test]
    fn detects_standard_simd_ops_and_lifts_intrinsics() {
        let bytes: Vec<u8> = wat::parse_str(SIMD_WAT).expect("wat");
        let report: SimdReport = scan_simd(&bytes).expect("scan");
        assert!(report.uses_v128);
        assert!(!report.uses_relaxed);
        let add: &SimdOpRecord = report
            .ops
            .iter()
            .find(|o: &&SimdOpRecord| o.mnemonic == "i32x4.add")
            .expect("i32x4.add present");
        assert!(add.rust_lift.contains("i32x4_add"));
    }

    #[test]
    fn detects_relaxed_simd_and_marks_conservatively() {
        let bytes: Vec<u8> = wat::parse_str(RELAXED_WAT).expect("wat");
        let report: SimdReport = scan_simd(&bytes).expect("scan");
        assert!(report.uses_relaxed);
        assert!(report.relaxed_count() >= 1);
        let madd: &SimdOpRecord = report
            .ops
            .iter()
            .find(|o: &&SimdOpRecord| o.mnemonic == "f32x4.relaxed_madd")
            .expect("madd present");
        assert!(madd.rust_lift.contains("relaxed_madd"));
        assert!(madd.rust_lift.contains("conservative lift"));
    }
}
