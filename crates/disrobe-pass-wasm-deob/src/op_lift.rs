use wasmparser::{MemArg, Operator, ValType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SimdMemKind {
    Load,
    LoadLane,
    Store,
    StoreLane,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SimdMem {
    pub(crate) helper: &'static str,
    pub(crate) kind: SimdMemKind,
    pub(crate) memarg: MemArg,
    pub(crate) lane: Option<u8>,
}

pub(crate) const fn simd_load_store(op: &Operator<'_>) -> Option<SimdMem> {
    let (helper, kind, memarg, lane): (&'static str, SimdMemKind, MemArg, Option<u8>) = match op {
        Operator::V128Load { memarg } => ("wasm_load_v128", SimdMemKind::Load, *memarg, None),
        Operator::V128Store { memarg } => ("wasm_store_v128", SimdMemKind::Store, *memarg, None),
        Operator::V128Load8x8S { memarg } => {
            ("wasm_load_v128_8x8_s", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load8x8U { memarg } => {
            ("wasm_load_v128_8x8_u", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load16x4S { memarg } => {
            ("wasm_load_v128_16x4_s", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load16x4U { memarg } => {
            ("wasm_load_v128_16x4_u", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load32x2S { memarg } => {
            ("wasm_load_v128_32x2_s", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load32x2U { memarg } => {
            ("wasm_load_v128_32x2_u", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load8Splat { memarg } => {
            ("wasm_load_v128_8_splat", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load16Splat { memarg } => {
            ("wasm_load_v128_16_splat", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load32Splat { memarg } => {
            ("wasm_load_v128_32_splat", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load64Splat { memarg } => {
            ("wasm_load_v128_64_splat", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load32Zero { memarg } => {
            ("wasm_load_v128_32_zero", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load64Zero { memarg } => {
            ("wasm_load_v128_64_zero", SimdMemKind::Load, *memarg, None)
        }
        Operator::V128Load8Lane { memarg, lane } => (
            "wasm_load_v128_8_lane",
            SimdMemKind::LoadLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Load16Lane { memarg, lane } => (
            "wasm_load_v128_16_lane",
            SimdMemKind::LoadLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Load32Lane { memarg, lane } => (
            "wasm_load_v128_32_lane",
            SimdMemKind::LoadLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Load64Lane { memarg, lane } => (
            "wasm_load_v128_64_lane",
            SimdMemKind::LoadLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Store8Lane { memarg, lane } => (
            "wasm_store_v128_8_lane",
            SimdMemKind::StoreLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Store16Lane { memarg, lane } => (
            "wasm_store_v128_16_lane",
            SimdMemKind::StoreLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Store32Lane { memarg, lane } => (
            "wasm_store_v128_32_lane",
            SimdMemKind::StoreLane,
            *memarg,
            Some(*lane),
        ),
        Operator::V128Store64Lane { memarg, lane } => (
            "wasm_store_v128_64_lane",
            SimdMemKind::StoreLane,
            *memarg,
            Some(*lane),
        ),
        _ => return None,
    };
    Some(SimdMem {
        helper,
        kind,
        memarg,
        lane,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SimdShape {
    Un,
    Bin,
    Tern,
    Shift,
    ExtractLane(ValType),
    ReplaceLane(ValType),
    Shuffle,
    ToI32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SimdDesc {
    pub(crate) helper: &'static str,
    pub(crate) shape: SimdShape,
}

const fn sd(helper: &'static str, shape: SimdShape) -> SimdDesc {
    SimdDesc { helper, shape }
}

#[allow(clippy::too_many_lines)]
pub(crate) const fn simd_descriptor(op: &Operator<'_>) -> Option<SimdDesc> {
    Some(match op {
        Operator::I8x16Shuffle { .. } => sd("wasm_i8x16_shuffle", SimdShape::Shuffle),
        Operator::I8x16ExtractLaneS { .. } => sd(
            "wasm_i8x16_extract_lane_s",
            SimdShape::ExtractLane(ValType::I32),
        ),
        Operator::I8x16ExtractLaneU { .. } => sd(
            "wasm_i8x16_extract_lane_u",
            SimdShape::ExtractLane(ValType::I32),
        ),
        Operator::I8x16ReplaceLane { .. } => sd(
            "wasm_i8x16_replace_lane",
            SimdShape::ReplaceLane(ValType::I32),
        ),
        Operator::I16x8ExtractLaneS { .. } => sd(
            "wasm_i16x8_extract_lane_s",
            SimdShape::ExtractLane(ValType::I32),
        ),
        Operator::I16x8ExtractLaneU { .. } => sd(
            "wasm_i16x8_extract_lane_u",
            SimdShape::ExtractLane(ValType::I32),
        ),
        Operator::I16x8ReplaceLane { .. } => sd(
            "wasm_i16x8_replace_lane",
            SimdShape::ReplaceLane(ValType::I32),
        ),
        Operator::I32x4ExtractLane { .. } => sd(
            "wasm_i32x4_extract_lane",
            SimdShape::ExtractLane(ValType::I32),
        ),
        Operator::I32x4ReplaceLane { .. } => sd(
            "wasm_i32x4_replace_lane",
            SimdShape::ReplaceLane(ValType::I32),
        ),
        Operator::I64x2ExtractLane { .. } => sd(
            "wasm_i64x2_extract_lane",
            SimdShape::ExtractLane(ValType::I64),
        ),
        Operator::I64x2ReplaceLane { .. } => sd(
            "wasm_i64x2_replace_lane",
            SimdShape::ReplaceLane(ValType::I64),
        ),
        Operator::F32x4ExtractLane { .. } => sd(
            "wasm_f32x4_extract_lane",
            SimdShape::ExtractLane(ValType::F32),
        ),
        Operator::F32x4ReplaceLane { .. } => sd(
            "wasm_f32x4_replace_lane",
            SimdShape::ReplaceLane(ValType::F32),
        ),
        Operator::F64x2ExtractLane { .. } => sd(
            "wasm_f64x2_extract_lane",
            SimdShape::ExtractLane(ValType::F64),
        ),
        Operator::F64x2ReplaceLane { .. } => sd(
            "wasm_f64x2_replace_lane",
            SimdShape::ReplaceLane(ValType::F64),
        ),
        Operator::I8x16Swizzle => sd("wasm_i8x16_swizzle", SimdShape::Bin),
        Operator::I8x16Eq => sd("wasm_i8x16_eq", SimdShape::Bin),
        Operator::I8x16Ne => sd("wasm_i8x16_ne", SimdShape::Bin),
        Operator::I8x16LtS => sd("wasm_i8x16_lt_s", SimdShape::Bin),
        Operator::I8x16LtU => sd("wasm_i8x16_lt_u", SimdShape::Bin),
        Operator::I8x16GtS => sd("wasm_i8x16_gt_s", SimdShape::Bin),
        Operator::I8x16GtU => sd("wasm_i8x16_gt_u", SimdShape::Bin),
        Operator::I8x16LeS => sd("wasm_i8x16_le_s", SimdShape::Bin),
        Operator::I8x16LeU => sd("wasm_i8x16_le_u", SimdShape::Bin),
        Operator::I8x16GeS => sd("wasm_i8x16_ge_s", SimdShape::Bin),
        Operator::I8x16GeU => sd("wasm_i8x16_ge_u", SimdShape::Bin),
        Operator::I16x8Eq => sd("wasm_i16x8_eq", SimdShape::Bin),
        Operator::I16x8Ne => sd("wasm_i16x8_ne", SimdShape::Bin),
        Operator::I16x8LtS => sd("wasm_i16x8_lt_s", SimdShape::Bin),
        Operator::I16x8LtU => sd("wasm_i16x8_lt_u", SimdShape::Bin),
        Operator::I16x8GtS => sd("wasm_i16x8_gt_s", SimdShape::Bin),
        Operator::I16x8GtU => sd("wasm_i16x8_gt_u", SimdShape::Bin),
        Operator::I16x8LeS => sd("wasm_i16x8_le_s", SimdShape::Bin),
        Operator::I16x8LeU => sd("wasm_i16x8_le_u", SimdShape::Bin),
        Operator::I16x8GeS => sd("wasm_i16x8_ge_s", SimdShape::Bin),
        Operator::I16x8GeU => sd("wasm_i16x8_ge_u", SimdShape::Bin),
        Operator::I32x4Eq => sd("wasm_i32x4_eq", SimdShape::Bin),
        Operator::I32x4Ne => sd("wasm_i32x4_ne", SimdShape::Bin),
        Operator::I32x4LtS => sd("wasm_i32x4_lt_s", SimdShape::Bin),
        Operator::I32x4LtU => sd("wasm_i32x4_lt_u", SimdShape::Bin),
        Operator::I32x4GtS => sd("wasm_i32x4_gt_s", SimdShape::Bin),
        Operator::I32x4GtU => sd("wasm_i32x4_gt_u", SimdShape::Bin),
        Operator::I32x4LeS => sd("wasm_i32x4_le_s", SimdShape::Bin),
        Operator::I32x4LeU => sd("wasm_i32x4_le_u", SimdShape::Bin),
        Operator::I32x4GeS => sd("wasm_i32x4_ge_s", SimdShape::Bin),
        Operator::I32x4GeU => sd("wasm_i32x4_ge_u", SimdShape::Bin),
        Operator::I64x2Eq => sd("wasm_i64x2_eq", SimdShape::Bin),
        Operator::I64x2Ne => sd("wasm_i64x2_ne", SimdShape::Bin),
        Operator::I64x2LtS => sd("wasm_i64x2_lt_s", SimdShape::Bin),
        Operator::I64x2GtS => sd("wasm_i64x2_gt_s", SimdShape::Bin),
        Operator::I64x2LeS => sd("wasm_i64x2_le_s", SimdShape::Bin),
        Operator::I64x2GeS => sd("wasm_i64x2_ge_s", SimdShape::Bin),
        Operator::F32x4Eq => sd("wasm_f32x4_eq", SimdShape::Bin),
        Operator::F32x4Ne => sd("wasm_f32x4_ne", SimdShape::Bin),
        Operator::F32x4Lt => sd("wasm_f32x4_lt", SimdShape::Bin),
        Operator::F32x4Gt => sd("wasm_f32x4_gt", SimdShape::Bin),
        Operator::F32x4Le => sd("wasm_f32x4_le", SimdShape::Bin),
        Operator::F32x4Ge => sd("wasm_f32x4_ge", SimdShape::Bin),
        Operator::F64x2Eq => sd("wasm_f64x2_eq", SimdShape::Bin),
        Operator::F64x2Ne => sd("wasm_f64x2_ne", SimdShape::Bin),
        Operator::F64x2Lt => sd("wasm_f64x2_lt", SimdShape::Bin),
        Operator::F64x2Gt => sd("wasm_f64x2_gt", SimdShape::Bin),
        Operator::F64x2Le => sd("wasm_f64x2_le", SimdShape::Bin),
        Operator::F64x2Ge => sd("wasm_f64x2_ge", SimdShape::Bin),
        Operator::V128AnyTrue => sd("wasm_v128_any_true", SimdShape::ToI32),
        Operator::I8x16Abs => sd("wasm_i8x16_abs", SimdShape::Un),
        Operator::I8x16Neg => sd("wasm_i8x16_neg", SimdShape::Un),
        Operator::I8x16Popcnt => sd("wasm_i8x16_popcnt", SimdShape::Un),
        Operator::I8x16AllTrue => sd("wasm_i8x16_all_true", SimdShape::ToI32),
        Operator::I8x16Bitmask => sd("wasm_i8x16_bitmask", SimdShape::ToI32),
        Operator::I8x16NarrowI16x8S => sd("wasm_i8x16_narrow_i16x8_s", SimdShape::Bin),
        Operator::I8x16NarrowI16x8U => sd("wasm_i8x16_narrow_i16x8_u", SimdShape::Bin),
        Operator::I8x16Shl => sd("wasm_i8x16_shl", SimdShape::Shift),
        Operator::I8x16ShrS => sd("wasm_i8x16_shr_s", SimdShape::Shift),
        Operator::I8x16ShrU => sd("wasm_i8x16_shr_u", SimdShape::Shift),
        Operator::I8x16AddSatS => sd("wasm_i8x16_add_sat_s", SimdShape::Bin),
        Operator::I8x16AddSatU => sd("wasm_i8x16_add_sat_u", SimdShape::Bin),
        Operator::I8x16SubSatS => sd("wasm_i8x16_sub_sat_s", SimdShape::Bin),
        Operator::I8x16SubSatU => sd("wasm_i8x16_sub_sat_u", SimdShape::Bin),
        Operator::I8x16MinS => sd("wasm_i8x16_min_s", SimdShape::Bin),
        Operator::I8x16MinU => sd("wasm_i8x16_min_u", SimdShape::Bin),
        Operator::I8x16MaxS => sd("wasm_i8x16_max_s", SimdShape::Bin),
        Operator::I8x16MaxU => sd("wasm_i8x16_max_u", SimdShape::Bin),
        Operator::I8x16AvgrU => sd("wasm_i8x16_avgr_u", SimdShape::Bin),
        Operator::I16x8ExtAddPairwiseI8x16S => {
            sd("wasm_i16x8_extadd_pairwise_i8x16_s", SimdShape::Un)
        }
        Operator::I16x8ExtAddPairwiseI8x16U => {
            sd("wasm_i16x8_extadd_pairwise_i8x16_u", SimdShape::Un)
        }
        Operator::I16x8Abs => sd("wasm_i16x8_abs", SimdShape::Un),
        Operator::I16x8Neg => sd("wasm_i16x8_neg", SimdShape::Un),
        Operator::I16x8Q15MulrSatS => sd("wasm_i16x8_q15mulr_sat_s", SimdShape::Bin),
        Operator::I16x8AllTrue => sd("wasm_i16x8_all_true", SimdShape::ToI32),
        Operator::I16x8Bitmask => sd("wasm_i16x8_bitmask", SimdShape::ToI32),
        Operator::I16x8NarrowI32x4S => sd("wasm_i16x8_narrow_i32x4_s", SimdShape::Bin),
        Operator::I16x8NarrowI32x4U => sd("wasm_i16x8_narrow_i32x4_u", SimdShape::Bin),
        Operator::I16x8ExtendLowI8x16S => sd("wasm_i16x8_extend_low_i8x16_s", SimdShape::Un),
        Operator::I16x8ExtendHighI8x16S => sd("wasm_i16x8_extend_high_i8x16_s", SimdShape::Un),
        Operator::I16x8ExtendLowI8x16U => sd("wasm_i16x8_extend_low_i8x16_u", SimdShape::Un),
        Operator::I16x8ExtendHighI8x16U => sd("wasm_i16x8_extend_high_i8x16_u", SimdShape::Un),
        Operator::I16x8Shl => sd("wasm_i16x8_shl", SimdShape::Shift),
        Operator::I16x8ShrS => sd("wasm_i16x8_shr_s", SimdShape::Shift),
        Operator::I16x8ShrU => sd("wasm_i16x8_shr_u", SimdShape::Shift),
        Operator::I16x8AddSatS => sd("wasm_i16x8_add_sat_s", SimdShape::Bin),
        Operator::I16x8AddSatU => sd("wasm_i16x8_add_sat_u", SimdShape::Bin),
        Operator::I16x8SubSatS => sd("wasm_i16x8_sub_sat_s", SimdShape::Bin),
        Operator::I16x8SubSatU => sd("wasm_i16x8_sub_sat_u", SimdShape::Bin),
        Operator::I16x8MinS => sd("wasm_i16x8_min_s", SimdShape::Bin),
        Operator::I16x8MinU => sd("wasm_i16x8_min_u", SimdShape::Bin),
        Operator::I16x8MaxS => sd("wasm_i16x8_max_s", SimdShape::Bin),
        Operator::I16x8MaxU => sd("wasm_i16x8_max_u", SimdShape::Bin),
        Operator::I16x8AvgrU => sd("wasm_i16x8_avgr_u", SimdShape::Bin),
        Operator::I16x8ExtMulLowI8x16S => sd("wasm_i16x8_extmul_low_i8x16_s", SimdShape::Bin),
        Operator::I16x8ExtMulHighI8x16S => sd("wasm_i16x8_extmul_high_i8x16_s", SimdShape::Bin),
        Operator::I16x8ExtMulLowI8x16U => sd("wasm_i16x8_extmul_low_i8x16_u", SimdShape::Bin),
        Operator::I16x8ExtMulHighI8x16U => sd("wasm_i16x8_extmul_high_i8x16_u", SimdShape::Bin),
        Operator::I32x4ExtAddPairwiseI16x8S => {
            sd("wasm_i32x4_extadd_pairwise_i16x8_s", SimdShape::Un)
        }
        Operator::I32x4ExtAddPairwiseI16x8U => {
            sd("wasm_i32x4_extadd_pairwise_i16x8_u", SimdShape::Un)
        }
        Operator::I32x4Abs => sd("wasm_i32x4_abs", SimdShape::Un),
        Operator::I32x4Neg => sd("wasm_i32x4_neg", SimdShape::Un),
        Operator::I32x4AllTrue => sd("wasm_i32x4_all_true", SimdShape::ToI32),
        Operator::I32x4Bitmask => sd("wasm_i32x4_bitmask", SimdShape::ToI32),
        Operator::I32x4ExtendLowI16x8S => sd("wasm_i32x4_extend_low_i16x8_s", SimdShape::Un),
        Operator::I32x4ExtendHighI16x8S => sd("wasm_i32x4_extend_high_i16x8_s", SimdShape::Un),
        Operator::I32x4ExtendLowI16x8U => sd("wasm_i32x4_extend_low_i16x8_u", SimdShape::Un),
        Operator::I32x4ExtendHighI16x8U => sd("wasm_i32x4_extend_high_i16x8_u", SimdShape::Un),
        Operator::I32x4Shl => sd("wasm_i32x4_shl", SimdShape::Shift),
        Operator::I32x4ShrS => sd("wasm_i32x4_shr_s", SimdShape::Shift),
        Operator::I32x4ShrU => sd("wasm_i32x4_shr_u", SimdShape::Shift),
        Operator::I32x4MinS => sd("wasm_i32x4_min_s", SimdShape::Bin),
        Operator::I32x4MinU => sd("wasm_i32x4_min_u", SimdShape::Bin),
        Operator::I32x4MaxS => sd("wasm_i32x4_max_s", SimdShape::Bin),
        Operator::I32x4MaxU => sd("wasm_i32x4_max_u", SimdShape::Bin),
        Operator::I32x4DotI16x8S => sd("wasm_i32x4_dot_i16x8_s", SimdShape::Bin),
        Operator::I32x4ExtMulLowI16x8S => sd("wasm_i32x4_extmul_low_i16x8_s", SimdShape::Bin),
        Operator::I32x4ExtMulHighI16x8S => sd("wasm_i32x4_extmul_high_i16x8_s", SimdShape::Bin),
        Operator::I32x4ExtMulLowI16x8U => sd("wasm_i32x4_extmul_low_i16x8_u", SimdShape::Bin),
        Operator::I32x4ExtMulHighI16x8U => sd("wasm_i32x4_extmul_high_i16x8_u", SimdShape::Bin),
        Operator::I64x2Abs => sd("wasm_i64x2_abs", SimdShape::Un),
        Operator::I64x2Neg => sd("wasm_i64x2_neg", SimdShape::Un),
        Operator::I64x2AllTrue => sd("wasm_i64x2_all_true", SimdShape::ToI32),
        Operator::I64x2Bitmask => sd("wasm_i64x2_bitmask", SimdShape::ToI32),
        Operator::I64x2ExtendLowI32x4S => sd("wasm_i64x2_extend_low_i32x4_s", SimdShape::Un),
        Operator::I64x2ExtendHighI32x4S => sd("wasm_i64x2_extend_high_i32x4_s", SimdShape::Un),
        Operator::I64x2ExtendLowI32x4U => sd("wasm_i64x2_extend_low_i32x4_u", SimdShape::Un),
        Operator::I64x2ExtendHighI32x4U => sd("wasm_i64x2_extend_high_i32x4_u", SimdShape::Un),
        Operator::I64x2Shl => sd("wasm_i64x2_shl", SimdShape::Shift),
        Operator::I64x2ShrS => sd("wasm_i64x2_shr_s", SimdShape::Shift),
        Operator::I64x2ShrU => sd("wasm_i64x2_shr_u", SimdShape::Shift),
        Operator::I64x2ExtMulLowI32x4S => sd("wasm_i64x2_extmul_low_i32x4_s", SimdShape::Bin),
        Operator::I64x2ExtMulHighI32x4S => sd("wasm_i64x2_extmul_high_i32x4_s", SimdShape::Bin),
        Operator::I64x2ExtMulLowI32x4U => sd("wasm_i64x2_extmul_low_i32x4_u", SimdShape::Bin),
        Operator::I64x2ExtMulHighI32x4U => sd("wasm_i64x2_extmul_high_i32x4_u", SimdShape::Bin),
        Operator::F32x4Ceil => sd("wasm_f32x4_ceil", SimdShape::Un),
        Operator::F32x4Floor => sd("wasm_f32x4_floor", SimdShape::Un),
        Operator::F32x4Trunc => sd("wasm_f32x4_trunc", SimdShape::Un),
        Operator::F32x4Nearest => sd("wasm_f32x4_nearest", SimdShape::Un),
        Operator::F32x4Min => sd("wasm_f32x4_min", SimdShape::Bin),
        Operator::F32x4Max => sd("wasm_f32x4_max", SimdShape::Bin),
        Operator::F32x4PMin => sd("wasm_f32x4_p_min", SimdShape::Bin),
        Operator::F32x4PMax => sd("wasm_f32x4_p_max", SimdShape::Bin),
        Operator::F64x2Ceil => sd("wasm_f64x2_ceil", SimdShape::Un),
        Operator::F64x2Floor => sd("wasm_f64x2_floor", SimdShape::Un),
        Operator::F64x2Trunc => sd("wasm_f64x2_trunc", SimdShape::Un),
        Operator::F64x2Nearest => sd("wasm_f64x2_nearest", SimdShape::Un),
        Operator::F64x2Min => sd("wasm_f64x2_min", SimdShape::Bin),
        Operator::F64x2Max => sd("wasm_f64x2_max", SimdShape::Bin),
        Operator::F64x2PMin => sd("wasm_f64x2_p_min", SimdShape::Bin),
        Operator::F64x2PMax => sd("wasm_f64x2_p_max", SimdShape::Bin),
        Operator::I32x4TruncSatF32x4S => sd("wasm_i32x4_trunc_sat_f32x4_s", SimdShape::Un),
        Operator::I32x4TruncSatF32x4U => sd("wasm_i32x4_trunc_sat_f32x4_u", SimdShape::Un),
        Operator::F32x4ConvertI32x4S => sd("wasm_f32x4_convert_i32x4_s", SimdShape::Un),
        Operator::F32x4ConvertI32x4U => sd("wasm_f32x4_convert_i32x4_u", SimdShape::Un),
        Operator::I32x4TruncSatF64x2SZero => sd("wasm_i32x4_trunc_sat_f64x2_s_zero", SimdShape::Un),
        Operator::I32x4TruncSatF64x2UZero => sd("wasm_i32x4_trunc_sat_f64x2_u_zero", SimdShape::Un),
        Operator::F64x2ConvertLowI32x4S => sd("wasm_f64x2_convert_low_i32x4_s", SimdShape::Un),
        Operator::F64x2ConvertLowI32x4U => sd("wasm_f64x2_convert_low_i32x4_u", SimdShape::Un),
        Operator::F32x4DemoteF64x2Zero => sd("wasm_f32x4_demote_f64x2_zero", SimdShape::Un),
        Operator::F64x2PromoteLowF32x4 => sd("wasm_f64x2_promote_low_f32x4", SimdShape::Un),
        Operator::I8x16RelaxedSwizzle => sd("wasm_i8x16_relaxed_swizzle", SimdShape::Bin),
        Operator::I32x4RelaxedTruncF32x4S => sd("wasm_i32x4_relaxed_trunc_f32x4_s", SimdShape::Un),
        Operator::I32x4RelaxedTruncF32x4U => sd("wasm_i32x4_relaxed_trunc_f32x4_u", SimdShape::Un),
        Operator::I32x4RelaxedTruncF64x2SZero => {
            sd("wasm_i32x4_relaxed_trunc_f64x2_s_zero", SimdShape::Un)
        }
        Operator::I32x4RelaxedTruncF64x2UZero => {
            sd("wasm_i32x4_relaxed_trunc_f64x2_u_zero", SimdShape::Un)
        }
        Operator::F32x4RelaxedMadd => sd("wasm_f32x4_relaxed_madd", SimdShape::Tern),
        Operator::F32x4RelaxedNmadd => sd("wasm_f32x4_relaxed_nmadd", SimdShape::Tern),
        Operator::F64x2RelaxedMadd => sd("wasm_f64x2_relaxed_madd", SimdShape::Tern),
        Operator::F64x2RelaxedNmadd => sd("wasm_f64x2_relaxed_nmadd", SimdShape::Tern),
        Operator::I8x16RelaxedLaneselect => sd("wasm_i8x16_relaxed_laneselect", SimdShape::Tern),
        Operator::I16x8RelaxedLaneselect => sd("wasm_i16x8_relaxed_laneselect", SimdShape::Tern),
        Operator::I32x4RelaxedLaneselect => sd("wasm_i32x4_relaxed_laneselect", SimdShape::Tern),
        Operator::I64x2RelaxedLaneselect => sd("wasm_i64x2_relaxed_laneselect", SimdShape::Tern),
        Operator::F32x4RelaxedMin => sd("wasm_f32x4_relaxed_min", SimdShape::Bin),
        Operator::F32x4RelaxedMax => sd("wasm_f32x4_relaxed_max", SimdShape::Bin),
        Operator::F64x2RelaxedMin => sd("wasm_f64x2_relaxed_min", SimdShape::Bin),
        Operator::F64x2RelaxedMax => sd("wasm_f64x2_relaxed_max", SimdShape::Bin),
        Operator::I16x8RelaxedQ15mulrS => sd("wasm_i16x8_relaxed_q15mulr_s", SimdShape::Bin),
        Operator::I16x8RelaxedDotI8x16I7x16S => {
            sd("wasm_i16x8_relaxed_dot_i8x16_i7x16_s", SimdShape::Bin)
        }
        Operator::I32x4RelaxedDotI8x16I7x16AddS => {
            sd("wasm_i32x4_relaxed_dot_i8x16_i7x16_add_s", SimdShape::Tern)
        }
        _ => return None,
    })
}

pub(crate) const fn simd_lane_immediate(op: &Operator<'_>) -> Option<u8> {
    match op {
        Operator::I8x16ExtractLaneS { lane }
        | Operator::I8x16ExtractLaneU { lane }
        | Operator::I8x16ReplaceLane { lane }
        | Operator::I16x8ExtractLaneS { lane }
        | Operator::I16x8ExtractLaneU { lane }
        | Operator::I16x8ReplaceLane { lane }
        | Operator::I32x4ExtractLane { lane }
        | Operator::I32x4ReplaceLane { lane }
        | Operator::I64x2ExtractLane { lane }
        | Operator::I64x2ReplaceLane { lane }
        | Operator::F32x4ExtractLane { lane }
        | Operator::F32x4ReplaceLane { lane }
        | Operator::F64x2ExtractLane { lane }
        | Operator::F64x2ReplaceLane { lane } => Some(*lane),
        _ => None,
    }
}

pub(crate) const fn simd_shuffle_lanes(op: &Operator<'_>) -> Option<[u8; 16]> {
    match op {
        Operator::I8x16Shuffle { lanes } => Some(*lanes),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicShape {
    Load,
    Store,
    Rmw,
    Cmpxchg,
    Wait,
    Notify,
    Fence,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AtomicDesc {
    pub(crate) helper: &'static str,
    pub(crate) shape: AtomicShape,
    pub(crate) result: ValType,
}

const fn ad(helper: &'static str, shape: AtomicShape, result: ValType) -> AtomicDesc {
    AtomicDesc {
        helper,
        shape,
        result,
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) const fn atomic_descriptor(op: &Operator<'_>) -> Option<AtomicDesc> {
    Some(match op {
        Operator::MemoryAtomicNotify { .. } => ad(
            "wasm_memory_atomic_notify",
            AtomicShape::Notify,
            ValType::I32,
        ),
        Operator::MemoryAtomicWait32 { .. } => {
            ad("wasm_memory_atomic_wait32", AtomicShape::Wait, ValType::I32)
        }
        Operator::MemoryAtomicWait64 { .. } => {
            ad("wasm_memory_atomic_wait64", AtomicShape::Wait, ValType::I32)
        }
        Operator::AtomicFence => ad("wasm_atomic_fence", AtomicShape::Fence, ValType::I32),
        Operator::I32AtomicLoad { .. } => {
            ad("wasm_i32_atomic_load", AtomicShape::Load, ValType::I32)
        }
        Operator::I64AtomicLoad { .. } => {
            ad("wasm_i64_atomic_load", AtomicShape::Load, ValType::I64)
        }
        Operator::I32AtomicLoad8U { .. } => {
            ad("wasm_i32_atomic_load8_u", AtomicShape::Load, ValType::I32)
        }
        Operator::I32AtomicLoad16U { .. } => {
            ad("wasm_i32_atomic_load16_u", AtomicShape::Load, ValType::I32)
        }
        Operator::I64AtomicLoad8U { .. } => {
            ad("wasm_i64_atomic_load8_u", AtomicShape::Load, ValType::I64)
        }
        Operator::I64AtomicLoad16U { .. } => {
            ad("wasm_i64_atomic_load16_u", AtomicShape::Load, ValType::I64)
        }
        Operator::I64AtomicLoad32U { .. } => {
            ad("wasm_i64_atomic_load32_u", AtomicShape::Load, ValType::I64)
        }
        Operator::I32AtomicStore { .. } => {
            ad("wasm_i32_atomic_store", AtomicShape::Store, ValType::I32)
        }
        Operator::I64AtomicStore { .. } => {
            ad("wasm_i64_atomic_store", AtomicShape::Store, ValType::I64)
        }
        Operator::I32AtomicStore8 { .. } => {
            ad("wasm_i32_atomic_store8", AtomicShape::Store, ValType::I32)
        }
        Operator::I32AtomicStore16 { .. } => {
            ad("wasm_i32_atomic_store16", AtomicShape::Store, ValType::I32)
        }
        Operator::I64AtomicStore8 { .. } => {
            ad("wasm_i64_atomic_store8", AtomicShape::Store, ValType::I64)
        }
        Operator::I64AtomicStore16 { .. } => {
            ad("wasm_i64_atomic_store16", AtomicShape::Store, ValType::I64)
        }
        Operator::I64AtomicStore32 { .. } => {
            ad("wasm_i64_atomic_store32", AtomicShape::Store, ValType::I64)
        }
        Operator::I32AtomicRmwAdd { .. } => {
            ad("wasm_i32_atomic_rmw_add", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmwAdd { .. } => {
            ad("wasm_i64_atomic_rmw_add", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmw8AddU { .. } => {
            ad("wasm_i32_atomic_rmw8_add_u", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I32AtomicRmw16AddU { .. } => ad(
            "wasm_i32_atomic_rmw16_add_u",
            AtomicShape::Rmw,
            ValType::I32,
        ),
        Operator::I64AtomicRmw8AddU { .. } => {
            ad("wasm_i64_atomic_rmw8_add_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I64AtomicRmw16AddU { .. } => ad(
            "wasm_i64_atomic_rmw16_add_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I64AtomicRmw32AddU { .. } => ad(
            "wasm_i64_atomic_rmw32_add_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I32AtomicRmwSub { .. } => {
            ad("wasm_i32_atomic_rmw_sub", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmwSub { .. } => {
            ad("wasm_i64_atomic_rmw_sub", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmw8SubU { .. } => {
            ad("wasm_i32_atomic_rmw8_sub_u", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I32AtomicRmw16SubU { .. } => ad(
            "wasm_i32_atomic_rmw16_sub_u",
            AtomicShape::Rmw,
            ValType::I32,
        ),
        Operator::I64AtomicRmw8SubU { .. } => {
            ad("wasm_i64_atomic_rmw8_sub_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I64AtomicRmw16SubU { .. } => ad(
            "wasm_i64_atomic_rmw16_sub_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I64AtomicRmw32SubU { .. } => ad(
            "wasm_i64_atomic_rmw32_sub_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I32AtomicRmwAnd { .. } => {
            ad("wasm_i32_atomic_rmw_and", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmwAnd { .. } => {
            ad("wasm_i64_atomic_rmw_and", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmw8AndU { .. } => {
            ad("wasm_i32_atomic_rmw8_and_u", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I32AtomicRmw16AndU { .. } => ad(
            "wasm_i32_atomic_rmw16_and_u",
            AtomicShape::Rmw,
            ValType::I32,
        ),
        Operator::I64AtomicRmw8AndU { .. } => {
            ad("wasm_i64_atomic_rmw8_and_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I64AtomicRmw16AndU { .. } => ad(
            "wasm_i64_atomic_rmw16_and_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I64AtomicRmw32AndU { .. } => ad(
            "wasm_i64_atomic_rmw32_and_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I32AtomicRmwOr { .. } => {
            ad("wasm_i32_atomic_rmw_or", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmwOr { .. } => {
            ad("wasm_i64_atomic_rmw_or", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmw8OrU { .. } => {
            ad("wasm_i32_atomic_rmw8_or_u", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I32AtomicRmw16OrU { .. } => {
            ad("wasm_i32_atomic_rmw16_or_u", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmw8OrU { .. } => {
            ad("wasm_i64_atomic_rmw8_or_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I64AtomicRmw16OrU { .. } => {
            ad("wasm_i64_atomic_rmw16_or_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I64AtomicRmw32OrU { .. } => {
            ad("wasm_i64_atomic_rmw32_or_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmwXor { .. } => {
            ad("wasm_i32_atomic_rmw_xor", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmwXor { .. } => {
            ad("wasm_i64_atomic_rmw_xor", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmw8XorU { .. } => {
            ad("wasm_i32_atomic_rmw8_xor_u", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I32AtomicRmw16XorU { .. } => ad(
            "wasm_i32_atomic_rmw16_xor_u",
            AtomicShape::Rmw,
            ValType::I32,
        ),
        Operator::I64AtomicRmw8XorU { .. } => {
            ad("wasm_i64_atomic_rmw8_xor_u", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I64AtomicRmw16XorU { .. } => ad(
            "wasm_i64_atomic_rmw16_xor_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I64AtomicRmw32XorU { .. } => ad(
            "wasm_i64_atomic_rmw32_xor_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I32AtomicRmwXchg { .. } => {
            ad("wasm_i32_atomic_rmw_xchg", AtomicShape::Rmw, ValType::I32)
        }
        Operator::I64AtomicRmwXchg { .. } => {
            ad("wasm_i64_atomic_rmw_xchg", AtomicShape::Rmw, ValType::I64)
        }
        Operator::I32AtomicRmw8XchgU { .. } => ad(
            "wasm_i32_atomic_rmw8_xchg_u",
            AtomicShape::Rmw,
            ValType::I32,
        ),
        Operator::I32AtomicRmw16XchgU { .. } => ad(
            "wasm_i32_atomic_rmw16_xchg_u",
            AtomicShape::Rmw,
            ValType::I32,
        ),
        Operator::I64AtomicRmw8XchgU { .. } => ad(
            "wasm_i64_atomic_rmw8_xchg_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I64AtomicRmw16XchgU { .. } => ad(
            "wasm_i64_atomic_rmw16_xchg_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I64AtomicRmw32XchgU { .. } => ad(
            "wasm_i64_atomic_rmw32_xchg_u",
            AtomicShape::Rmw,
            ValType::I64,
        ),
        Operator::I32AtomicRmwCmpxchg { .. } => ad(
            "wasm_i32_atomic_rmw_cmpxchg",
            AtomicShape::Cmpxchg,
            ValType::I32,
        ),
        Operator::I64AtomicRmwCmpxchg { .. } => ad(
            "wasm_i64_atomic_rmw_cmpxchg",
            AtomicShape::Cmpxchg,
            ValType::I64,
        ),
        Operator::I32AtomicRmw8CmpxchgU { .. } => ad(
            "wasm_i32_atomic_rmw8_cmpxchg_u",
            AtomicShape::Cmpxchg,
            ValType::I32,
        ),
        Operator::I32AtomicRmw16CmpxchgU { .. } => ad(
            "wasm_i32_atomic_rmw16_cmpxchg_u",
            AtomicShape::Cmpxchg,
            ValType::I32,
        ),
        Operator::I64AtomicRmw8CmpxchgU { .. } => ad(
            "wasm_i64_atomic_rmw8_cmpxchg_u",
            AtomicShape::Cmpxchg,
            ValType::I64,
        ),
        Operator::I64AtomicRmw16CmpxchgU { .. } => ad(
            "wasm_i64_atomic_rmw16_cmpxchg_u",
            AtomicShape::Cmpxchg,
            ValType::I64,
        ),
        Operator::I64AtomicRmw32CmpxchgU { .. } => ad(
            "wasm_i64_atomic_rmw32_cmpxchg_u",
            AtomicShape::Cmpxchg,
            ValType::I64,
        ),
        _ => return None,
    })
}

pub(crate) const fn atomic_memarg(op: &Operator<'_>) -> Option<MemArg> {
    match op {
        Operator::MemoryAtomicNotify { memarg }
        | Operator::MemoryAtomicWait32 { memarg }
        | Operator::MemoryAtomicWait64 { memarg }
        | Operator::I32AtomicLoad { memarg }
        | Operator::I64AtomicLoad { memarg }
        | Operator::I32AtomicLoad8U { memarg }
        | Operator::I32AtomicLoad16U { memarg }
        | Operator::I64AtomicLoad8U { memarg }
        | Operator::I64AtomicLoad16U { memarg }
        | Operator::I64AtomicLoad32U { memarg }
        | Operator::I32AtomicStore { memarg }
        | Operator::I64AtomicStore { memarg }
        | Operator::I32AtomicStore8 { memarg }
        | Operator::I32AtomicStore16 { memarg }
        | Operator::I64AtomicStore8 { memarg }
        | Operator::I64AtomicStore16 { memarg }
        | Operator::I64AtomicStore32 { memarg }
        | Operator::I32AtomicRmwAdd { memarg }
        | Operator::I64AtomicRmwAdd { memarg }
        | Operator::I32AtomicRmw8AddU { memarg }
        | Operator::I32AtomicRmw16AddU { memarg }
        | Operator::I64AtomicRmw8AddU { memarg }
        | Operator::I64AtomicRmw16AddU { memarg }
        | Operator::I64AtomicRmw32AddU { memarg }
        | Operator::I32AtomicRmwSub { memarg }
        | Operator::I64AtomicRmwSub { memarg }
        | Operator::I32AtomicRmw8SubU { memarg }
        | Operator::I32AtomicRmw16SubU { memarg }
        | Operator::I64AtomicRmw8SubU { memarg }
        | Operator::I64AtomicRmw16SubU { memarg }
        | Operator::I64AtomicRmw32SubU { memarg }
        | Operator::I32AtomicRmwAnd { memarg }
        | Operator::I64AtomicRmwAnd { memarg }
        | Operator::I32AtomicRmw8AndU { memarg }
        | Operator::I32AtomicRmw16AndU { memarg }
        | Operator::I64AtomicRmw8AndU { memarg }
        | Operator::I64AtomicRmw16AndU { memarg }
        | Operator::I64AtomicRmw32AndU { memarg }
        | Operator::I32AtomicRmwOr { memarg }
        | Operator::I64AtomicRmwOr { memarg }
        | Operator::I32AtomicRmw8OrU { memarg }
        | Operator::I32AtomicRmw16OrU { memarg }
        | Operator::I64AtomicRmw8OrU { memarg }
        | Operator::I64AtomicRmw16OrU { memarg }
        | Operator::I64AtomicRmw32OrU { memarg }
        | Operator::I32AtomicRmwXor { memarg }
        | Operator::I64AtomicRmwXor { memarg }
        | Operator::I32AtomicRmw8XorU { memarg }
        | Operator::I32AtomicRmw16XorU { memarg }
        | Operator::I64AtomicRmw8XorU { memarg }
        | Operator::I64AtomicRmw16XorU { memarg }
        | Operator::I64AtomicRmw32XorU { memarg }
        | Operator::I32AtomicRmwXchg { memarg }
        | Operator::I64AtomicRmwXchg { memarg }
        | Operator::I32AtomicRmw8XchgU { memarg }
        | Operator::I32AtomicRmw16XchgU { memarg }
        | Operator::I64AtomicRmw8XchgU { memarg }
        | Operator::I64AtomicRmw16XchgU { memarg }
        | Operator::I64AtomicRmw32XchgU { memarg }
        | Operator::I32AtomicRmwCmpxchg { memarg }
        | Operator::I64AtomicRmwCmpxchg { memarg }
        | Operator::I32AtomicRmw8CmpxchgU { memarg }
        | Operator::I32AtomicRmw16CmpxchgU { memarg }
        | Operator::I64AtomicRmw8CmpxchgU { memarg }
        | Operator::I64AtomicRmw16CmpxchgU { memarg }
        | Operator::I64AtomicRmw32CmpxchgU { memarg } => Some(*memarg),
        _ => None,
    }
}
