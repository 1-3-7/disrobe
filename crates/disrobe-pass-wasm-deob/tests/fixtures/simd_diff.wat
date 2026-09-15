(module
  (memory 1)
  (func (export "lane_arith") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.add
    local.get 0
    i32x4.splat
    i32x4.mul
    i32x4.extract_lane 0)

  (func (export "lane_minmax") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.min_s
    i16x8.extract_lane_s 0)

  (func (export "lane_maxu") (param i32 i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 1
    i16x8.splat
    i16x8.max_u
    i16x8.extract_lane_s 0)

  (func (export "lane_cmp") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    i32x4.lt_s
    i32x4.bitmask)

  (func (export "lane_shift") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.shl
    local.get 1
    i32x4.shr_u
    i32x4.extract_lane 0)

  (func (export "lane_replace") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.replace_lane 3
    i8x16.extract_lane_u 3)

  (func (export "lane_shuffle") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.shuffle 0 1 2 3 16 17 18 19 4 5 6 7 20 21 22 23
    i8x16.extract_lane_s 4)

  (func (export "lane_narrow") (param i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 0
    i16x8.splat
    i8x16.narrow_i16x8_s
    i8x16.extract_lane_s 0)

  (func (export "lane_extend") (param i32) (result i32)
    local.get 0
    i8x16.splat
    i16x8.extend_low_i8x16_u
    i16x8.extract_lane_s 0)

  (func (export "lane_dot") (param i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 0
    i16x8.splat
    i32x4.dot_i16x8_s
    i32x4.extract_lane 0)

  (func (export "lane_alltrue") (param i32) (result i32)
    local.get 0
    i32x4.splat
    i32x4.all_true)

  (func (export "lane_anytrue") (param i32) (result i32)
    local.get 0
    i8x16.splat
    v128.any_true)

  (func (export "lane_bitwise") (param i32 i32) (result i32)
    local.get 0
    i32x4.splat
    local.get 1
    i32x4.splat
    v128.and
    local.get 1
    i32x4.splat
    v128.xor
    i32x4.extract_lane 0)

  (func (export "lane_extmul") (param i32) (result i32)
    local.get 0
    i16x8.splat
    local.get 0
    i16x8.splat
    i32x4.extmul_low_i16x8_s
    i32x4.extract_lane 0)

  (func (export "lane_avgr") (param i32 i32) (result i32)
    local.get 0
    i8x16.splat
    local.get 1
    i8x16.splat
    i8x16.avgr_u
    i8x16.extract_lane_u 0)

  (func (export "lane_abs_neg") (param i32) (result i32)
    local.get 0
    i32x4.splat
    i32x4.neg
    i32x4.abs
    i32x4.extract_lane 0)

  (func (export "lane_memory") (param i32) (result i32)
    i32.const 0
    local.get 0
    i32x4.splat
    v128.store
    i32.const 0
    v128.load
    i32x4.extract_lane 0))
