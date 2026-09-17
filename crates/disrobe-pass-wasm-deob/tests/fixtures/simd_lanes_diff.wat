(module
  (memory 1)
  (func (export "i16x8_abs") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i16x8.abs
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_add") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.add
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_add_sat_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.add_sat_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_add_sat_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.add_sat_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_all_true") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i16x8.all_true
    )

  (func (export "i16x8_avgr_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.avgr_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_bitmask") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i16x8.bitmask
    )

  (func (export "i16x8_eq") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.eq
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extadd_pairwise_i8x16_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extadd_pairwise_i8x16_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extadd_pairwise_i8x16_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extadd_pairwise_i8x16_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extend_high_i8x16_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extend_high_i8x16_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extend_high_i8x16_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extend_high_i8x16_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extend_low_i8x16_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extend_low_i8x16_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extend_low_i8x16_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extend_low_i8x16_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extmul_high_i8x16_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i16x8.extmul_high_i8x16_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extmul_high_i8x16_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i16x8.extmul_high_i8x16_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extmul_low_i8x16_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i16x8.extmul_low_i8x16_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_extmul_low_i8x16_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i16x8.extmul_low_i8x16_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_ge_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.ge_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_ge_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.ge_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_gt_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.gt_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_gt_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.gt_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_le_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.le_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_le_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.le_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_lt_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.lt_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_lt_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.lt_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_max_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.max_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_max_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.max_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_min_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.min_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_min_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.min_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_mul") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.mul
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_narrow_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i16x8.narrow_i32x4_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_narrow_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i16x8.narrow_i32x4_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_ne") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.ne
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_neg") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i16x8.neg
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_q15mulr_sat_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.q15mulr_sat_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_shl") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.shl
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_shr_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.shr_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_shr_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.shr_u
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_sub") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.sub
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_sub_sat_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.sub_sat_s
    i16x8.extract_lane_s 0
    )

  (func (export "i16x8_sub_sat_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.sub_sat_u
    i16x8.extract_lane_s 0
    )

  (func (export "i32x4_abs") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i32x4.abs
    i32x4.extract_lane 0
    )

  (func (export "i32x4_add") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.add
    i32x4.extract_lane 0
    )

  (func (export "i32x4_all_true") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i32x4.all_true
    )

  (func (export "i32x4_bitmask") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i32x4.bitmask
    )

  (func (export "i32x4_dot_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i32x4.dot_i16x8_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_eq") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.eq
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extadd_pairwise_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i32x4.extadd_pairwise_i16x8_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extadd_pairwise_i16x8_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i32x4.extadd_pairwise_i16x8_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extend_high_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i32x4.extend_high_i16x8_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extend_high_i16x8_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i32x4.extend_high_i16x8_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extend_low_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i32x4.extend_low_i16x8_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extend_low_i16x8_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i32x4.extend_low_i16x8_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extmul_high_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i32x4.extmul_high_i16x8_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extmul_high_i16x8_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i32x4.extmul_high_i16x8_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extmul_low_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i32x4.extmul_low_i16x8_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_extmul_low_i16x8_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i32x4.extmul_low_i16x8_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_ge_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.ge_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_ge_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.ge_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_gt_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.gt_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_gt_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.gt_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_le_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.le_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_le_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.le_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_lt_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.lt_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_lt_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.lt_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_max_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.max_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_max_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.max_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_min_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.min_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_min_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.min_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_mul") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.mul
    i32x4.extract_lane 0
    )

  (func (export "i32x4_ne") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.ne
    i32x4.extract_lane 0
    )

  (func (export "i32x4_neg") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i32x4.neg
    i32x4.extract_lane 0
    )

  (func (export "i32x4_shl") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.shl
    i32x4.extract_lane 0
    )

  (func (export "i32x4_shr_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.shr_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_shr_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.shr_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_sub") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.sub
    i32x4.extract_lane 0
    )

  (func (export "i64x2_abs") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    i64x2.abs
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_add") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.add
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_all_true") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    i64x2.all_true
    )

  (func (export "i64x2_bitmask") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    i64x2.bitmask
    )

  (func (export "i64x2_eq") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.eq
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extend_high_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i64x2.extend_high_i32x4_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extend_high_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i64x2.extend_high_i32x4_u
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extend_low_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i64x2.extend_low_i32x4_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extend_low_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    i64x2.extend_low_i32x4_u
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extmul_high_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i64x2.extmul_high_i32x4_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extmul_high_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i64x2.extmul_high_i32x4_u
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extmul_low_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i64x2.extmul_low_i32x4_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_extmul_low_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i64x2.extmul_low_i32x4_u
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_ge_s") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.ge_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_gt_s") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.gt_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_le_s") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.le_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_lt_s") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.lt_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_mul") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.mul
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_ne") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.ne
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_neg") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    i64x2.neg
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_shl") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64x2.shl
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_shr_s") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64x2.shr_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_shr_u") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64x2.shr_u
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i64x2_sub") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.splat
    i64x2.sub
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "i8x16_abs") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i8x16.abs
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_add") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.add
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_add_sat_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.add_sat_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_add_sat_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.add_sat_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_all_true") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i8x16.all_true
    )

  (func (export "i8x16_avgr_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.avgr_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_bitmask") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i8x16.bitmask
    )

  (func (export "i8x16_eq") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.eq
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_ge_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.ge_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_ge_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.ge_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_gt_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.gt_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_gt_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.gt_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_le_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.le_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_le_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.le_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_lt_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.lt_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_lt_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.lt_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_max_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.max_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_max_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.max_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_min_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.min_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_min_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.min_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_narrow_i16x8_s") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i8x16.narrow_i16x8_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_narrow_i16x8_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i8x16.narrow_i16x8_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_ne") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.ne
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_neg") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i8x16.neg
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_popcnt") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i8x16.popcnt
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_shl") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.shl
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_shr_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.shr_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_shr_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.shr_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_sub") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.sub
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_sub_sat_s") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.sub_sat_s
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_sub_sat_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.sub_sat_u
    i8x16.extract_lane_s 0
    )

  (func (export "i8x16_swizzle") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.swizzle
    i8x16.extract_lane_s 0
    )

  (func (export "v128_and") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    v128.and
    i32x4.extract_lane 0
    )

  (func (export "v128_andnot") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    v128.andnot
    i32x4.extract_lane 0
    )

  (func (export "v128_any_true") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    v128.any_true
    )

  (func (export "v128_bitselect") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    local.get 0
    i32x4.splat
    v128.bitselect
    i32x4.extract_lane 0
    )

  (func (export "v128_not") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    v128.not
    i32x4.extract_lane 0
    )

  (func (export "v128_or") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    v128.or
    i32x4.extract_lane 0
    )

  (func (export "v128_xor") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    v128.xor
    i32x4.extract_lane 0
    )

  (func (export "f32x4_add") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.add
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_sub") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.sub
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_mul") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.mul
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_div") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.div
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_min") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.min
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_max") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.max
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_pmin") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.pmin
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_pmax") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.pmax
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_abs") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.abs
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_neg") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.neg
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_sqrt") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.sqrt
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_ceil") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.ceil
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_floor") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.floor
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_trunc") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.trunc
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_nearest") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.nearest
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_eq") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.eq
    i32x4.extract_lane 0
    )

  (func (export "f32x4_ne") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.ne
    i32x4.extract_lane 0
    )

  (func (export "f32x4_lt") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.lt
    i32x4.extract_lane 0
    )

  (func (export "f32x4_gt") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.gt
    i32x4.extract_lane 0
    )

  (func (export "f32x4_le") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.le
    i32x4.extract_lane 0
    )

  (func (export "f32x4_ge") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f32x4.ge
    i32x4.extract_lane 0
    )

  (func (export "f64x2_add") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.add
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_sub") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.sub
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_mul") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.mul
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_div") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.div
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_min") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.min
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_max") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.max
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_pmin") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.pmin
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_pmax") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.pmax
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_abs") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.abs
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_neg") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.neg
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_sqrt") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.sqrt
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_ceil") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.ceil
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_floor") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.floor
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_trunc") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.trunc
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_nearest") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.nearest
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_eq") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.eq
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "f64x2_ne") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.ne
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "f64x2_lt") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.lt
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "f64x2_gt") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.gt
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "f64x2_le") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.le
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "f64x2_ge") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f64x2.ge
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "f32x4_convert_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    f32x4.convert_i32x4_s
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f32x4_convert_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    f32x4.convert_i32x4_u
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f64x2_convert_low_i32x4_s") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    f64x2.convert_low_i32x4_s
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f64x2_convert_low_i32x4_u") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    f64x2.convert_low_i32x4_u
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "f32x4_demote_f64x2_zero") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    f32x4.demote_f64x2_zero
    f32x4.extract_lane 0
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f64x2_promote_low_f32x4") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    f64x2.promote_low_f32x4
    f64x2.extract_lane 0
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "i32x4_trunc_sat_f32x4_s") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    i32x4.trunc_sat_f32x4_s
    i32x4.extract_lane 0
    )

  (func (export "i32x4_trunc_sat_f32x4_u") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    i32x4.trunc_sat_f32x4_u
    i32x4.extract_lane 0
    )

  (func (export "i32x4_trunc_sat_f64x2_s_zero") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    i32x4.trunc_sat_f64x2_s_zero
    i32x4.extract_lane 0
    )

  (func (export "i32x4_trunc_sat_f64x2_u_zero") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    i32x4.trunc_sat_f64x2_u_zero
    i32x4.extract_lane 0
    )

  (func (export "i8x16_replace_lane") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.replace_lane 1
    i8x16.extract_lane_s 1
    )

  (func (export "i16x8_replace_lane") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.replace_lane 1
    i16x8.extract_lane_s 1
    )

  (func (export "i32x4_replace_lane") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.replace_lane 1
    i32x4.extract_lane 1
    )

  (func (export "i64x2_replace_lane") (param i32 i32) (result i32)
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    local.get 1
    i64.extend_i32_s
    i64x2.replace_lane 1
    i64x2.extract_lane 1
    i32.wrap_i64
    )

  (func (export "f32x4_replace_lane") (param i32 i32) (result i32)
    local.get 0
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.splat
    local.get 1
    f32.convert_i32_s
    f32.const 1024
    f32.div
    f32x4.replace_lane 1
    f32x4.extract_lane 1
    f32.const 1024
    f32.mul
    i32.trunc_sat_f32_s
    )

  (func (export "f64x2_replace_lane") (param i32 i32) (result i32)
    local.get 0
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.splat
    local.get 1
    f64.convert_i32_s
    f64.const 1024
    f64.div
    f64x2.replace_lane 1
    f64x2.extract_lane 1
    f64.const 1024
    f64.mul
    i32.trunc_sat_f64_s
    )

  (func (export "i8x16_extract_lane_u") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    i8x16.extract_lane_u 0
    )

  (func (export "i16x8_extract_lane_u") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    i16x8.extract_lane_u 0
    )

  (func (export "v128_const") (param i32 i32) (result i32)
    v128.const i32x4 5 -7 1234567 -2147483648
    local.get 0
    i32x4.splat
    i32x4.add
    i32x4.extract_lane 2
    )

  (func (export "v128_load8_splat") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    v128.load8_splat
    i8x16.extract_lane_s 0
    )

  (func (export "v128_load16_splat") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    v128.load16_splat
    i16x8.extract_lane_s 0
    )

  (func (export "v128_load32_splat") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    v128.load32_splat
    i32x4.extract_lane 0
    )

  (func (export "v128_load64_splat") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load64_splat
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "v128_load32_zero") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    v128.load32_zero
    i32x4.extract_lane 0
    )

  (func (export "v128_load64_zero") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load64_zero
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "v128_load8x8_s") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load8x8_s
    i16x8.extract_lane_s 0
    )

  (func (export "v128_load8x8_u") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load8x8_u
    i16x8.extract_lane_s 0
    )

  (func (export "v128_load16x4_s") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load16x4_s
    i32x4.extract_lane 0
    )

  (func (export "v128_load16x4_u") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load16x4_u
    i32x4.extract_lane 0
    )

  (func (export "v128_load32x2_s") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load32x2_s
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "v128_load32x2_u") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    v128.load32x2_u
    i64x2.extract_lane 0
    i32.wrap_i64
    )

  (func (export "v128_load8_lane") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    local.get 1
    i32x4.splat
    v128.load8_lane 3
    i8x16.extract_lane_s 3
    )

  (func (export "v128_load16_lane") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    local.get 1
    i32x4.splat
    v128.load16_lane 3
    i16x8.extract_lane_s 3
    )

  (func (export "v128_load32_lane") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i32.store
    i32.const 0
    local.get 1
    i32x4.splat
    v128.load32_lane 3
    i32x4.extract_lane 3
    )

  (func (export "v128_load64_lane") (param i32 i32) (result i32)
    i32.const 0
    local.get 0
    i64.extend_i32_s
    i64.store
    i32.const 0
    local.get 1
    i32x4.splat
    v128.load64_lane 1
    i64x2.extract_lane 1
    i32.wrap_i64
    )

  (func (export "v128_store8_lane") (param i32 i32) (result i32)
    i32.const 32
    local.get 0
    i32x4.splat
    v128.store8_lane 3
    i32.const 32
    i32.load8_u
    )

  (func (export "v128_store16_lane") (param i32 i32) (result i32)
    i32.const 32
    local.get 0
    i32x4.splat
    v128.store16_lane 3
    i32.const 32
    i32.load16_u
    )

  (func (export "v128_store32_lane") (param i32 i32) (result i32)
    i32.const 32
    local.get 0
    i32x4.splat
    v128.store32_lane 3
    i32.const 32
    i32.load
    )

  (func (export "v128_store64_lane") (param i32 i32) (result i32)
    i32.const 32
    local.get 0
    i64.extend_i32_s
    i64x2.splat
    v128.store64_lane 1
    i32.const 32
    i64.load
    i32.wrap_i64
    )

)
