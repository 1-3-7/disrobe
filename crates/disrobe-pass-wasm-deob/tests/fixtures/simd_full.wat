(module
  (memory 1)
  (func
    i32.const 0
    v128.load offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load8x8_s offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load8x8_u offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load16x4_s offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load16x4_u offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load32x2_s offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load32x2_u offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load8_splat offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load16_splat offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load32_splat offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load64_splat offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load32_zero offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.load64_zero offset=0 align=1
    drop
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.store offset=0 align=1
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.load8_lane offset=0 align=1 0
    drop
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.load16_lane offset=0 align=1 0
    drop
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.load32_lane offset=0 align=1 0
    drop
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.load64_lane offset=0 align=1 0
    drop
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.store8_lane offset=0 align=1 0
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.store16_lane offset=0 align=1 0
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.store32_lane offset=0 align=1 0
  )
  (func
    i32.const 0
    v128.const i32x4 0 0 0 0
    v128.store64_lane offset=0 align=1 0
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.shuffle 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.extract_lane_s 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.extract_lane_u 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i8x16.replace_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extract_lane_s 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extract_lane_u 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i16x8.replace_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extract_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i32x4.replace_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.extract_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64.const 0
    i64x2.replace_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.extract_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32.const 0
    f32x4.replace_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.extract_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64.const 0
    f64x2.replace_lane 0
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.swizzle
    drop
  )
  (func
    i32.const 0
    i8x16.splat
    drop
  )
  (func
    i32.const 0
    i16x8.splat
    drop
  )
  (func
    i32.const 0
    i32x4.splat
    drop
  )
  (func
    i64.const 0
    i64x2.splat
    drop
  )
  (func
    f32.const 0
    f32x4.splat
    drop
  )
  (func
    f64.const 0
    f64x2.splat
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.eq
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.ne
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.lt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.lt_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.gt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.gt_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.le_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.le_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.ge_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.ge_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.eq
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.ne
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.lt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.lt_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.gt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.gt_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.le_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.le_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.ge_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.ge_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.eq
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.ne
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.lt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.lt_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.gt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.gt_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.le_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.le_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.ge_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.ge_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.eq
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.ne
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.lt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.gt_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.le_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.ge_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.eq
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.ne
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.lt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.gt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.le
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.ge
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.eq
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.ne
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.lt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.gt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.le
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.ge
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.not
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.and
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.andnot
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.or
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.xor
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.bitselect
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.any_true
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.abs
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.neg
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.popcnt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.all_true
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i8x16.bitmask
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.narrow_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.narrow_i16x8_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i8x16.shl
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i8x16.shr_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i8x16.shr_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.add
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.add_sat_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.add_sat_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.sub
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.sub_sat_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.sub_sat_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.min_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.min_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.max_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.max_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.avgr_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extadd_pairwise_i8x16_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extadd_pairwise_i8x16_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.abs
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.neg
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.q15mulr_sat_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.all_true
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.bitmask
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.narrow_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.narrow_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extend_low_i8x16_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extend_high_i8x16_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extend_low_i8x16_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i16x8.extend_high_i8x16_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i16x8.shl
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i16x8.shr_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i16x8.shr_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.add
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.add_sat_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.add_sat_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.sub
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.sub_sat_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.sub_sat_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.mul
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.min_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.min_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.max_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.max_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.avgr_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.extmul_low_i8x16_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.extmul_high_i8x16_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.extmul_low_i8x16_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.extmul_high_i8x16_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extadd_pairwise_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extadd_pairwise_i16x8_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.abs
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.neg
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.all_true
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.bitmask
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extend_low_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extend_high_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extend_low_i16x8_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.extend_high_i16x8_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i32x4.shl
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i32x4.shr_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i32x4.shr_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.add
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.sub
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.mul
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.min_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.min_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.max_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.max_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.dot_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.extmul_low_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.extmul_high_i16x8_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.extmul_low_i16x8_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.extmul_high_i16x8_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.abs
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.neg
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.all_true
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.bitmask
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.extend_low_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.extend_high_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.extend_low_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i64x2.extend_high_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i64x2.shl
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i64x2.shr_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32.const 0
    i64x2.shr_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.add
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.sub
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.mul
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.extmul_low_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.extmul_high_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.extmul_low_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.extmul_high_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.ceil
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.floor
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.trunc
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.nearest
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.abs
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.neg
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.sqrt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.add
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.sub
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.mul
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.div
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.min
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.max
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.pmin
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.pmax
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.ceil
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.floor
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.trunc
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.nearest
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.abs
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.neg
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.sqrt
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.add
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.sub
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.mul
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.div
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.min
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.max
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.pmin
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.pmax
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.trunc_sat_f32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.trunc_sat_f32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.convert_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.convert_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.trunc_sat_f64x2_s_zero
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.trunc_sat_f64x2_u_zero
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.convert_low_i32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.convert_low_i32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f32x4.demote_f64x2_zero
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    f64x2.promote_low_f32x4
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.relaxed_swizzle
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_trunc_f32x4_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_trunc_f32x4_u
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_trunc_f64x2_s_zero
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_trunc_f64x2_u_zero
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.relaxed_madd
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.relaxed_nmadd
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.relaxed_madd
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.relaxed_nmadd
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i8x16.relaxed_laneselect
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.relaxed_laneselect
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_laneselect
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i64x2.relaxed_laneselect
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.relaxed_min
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f32x4.relaxed_max
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.relaxed_min
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    f64x2.relaxed_max
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.relaxed_q15mulr_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i16x8.relaxed_dot_i8x16_i7x16_s
    drop
  )
  (func
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_dot_i8x16_i7x16_add_s
    drop
  )
)
