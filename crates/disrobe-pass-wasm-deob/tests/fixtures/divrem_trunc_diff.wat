(module
  (func (export "i32_div_s") (param i32 i32) (result i32)
    (i32.div_s (local.get 0) (local.get 1)))

  (func (export "i32_div_u") (param i32 i32) (result i32)
    (i32.div_u (local.get 0) (local.get 1)))

  (func (export "i32_rem_s") (param i32 i32) (result i32)
    (i32.rem_s (local.get 0) (local.get 1)))

  (func (export "i32_rem_u") (param i32 i32) (result i32)
    (i32.rem_u (local.get 0) (local.get 1)))

  (func $wide (param i32 i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_s (local.get 0)) (i64.const 32))
      (i64.extend_i32_u (local.get 1))))

  (func $fold (param i64) (result i32)
    (i32.xor
      (i32.wrap_i64 (local.get 0))
      (i32.wrap_i64 (i64.shr_s (local.get 0) (i64.const 32)))))

  (func (export "i64_div_s") (param i32 i32) (result i32)
    (call $fold
      (i64.div_s
        (call $wide (local.get 0) (local.get 1))
        (call $wide (local.get 1) (local.get 0)))))

  (func (export "i64_div_u") (param i32 i32) (result i32)
    (call $fold
      (i64.div_u
        (call $wide (local.get 0) (local.get 1))
        (call $wide (local.get 1) (local.get 0)))))

  (func (export "i64_rem_s") (param i32 i32) (result i32)
    (call $fold
      (i64.rem_s
        (call $wide (local.get 0) (local.get 1))
        (call $wide (local.get 1) (local.get 0)))))

  (func (export "i64_rem_u") (param i32 i32) (result i32)
    (call $fold
      (i64.rem_u
        (call $wide (local.get 0) (local.get 1))
        (call $wide (local.get 1) (local.get 0)))))

  (func (export "i32_trunc_f32_s") (param i32 i32) (result i32)
    (i32.trunc_f32_s
      (f32.div (f32.convert_i32_s (local.get 0)) (f32.const 3))))

  (func (export "i32_trunc_f32_u") (param i32 i32) (result i32)
    (i32.trunc_f32_u
      (f32.div (f32.convert_i32_u (local.get 0)) (f32.const 3))))

  (func (export "i32_trunc_f64_s") (param i32 i32) (result i32)
    (i32.trunc_f64_s
      (f64.div (f64.convert_i32_s (local.get 0)) (f64.const 3))))

  (func (export "i32_trunc_f64_u") (param i32 i32) (result i32)
    (i32.trunc_f64_u
      (f64.div (f64.convert_i32_u (local.get 0)) (f64.const 3))))

  (func (export "i64_trunc_f32_s") (param i32 i32) (result i32)
    (call $fold
      (i64.trunc_f32_s
        (f32.mul (f32.convert_i32_s (local.get 0)) (f32.const 1024)))))

  (func (export "i64_trunc_f32_u") (param i32 i32) (result i32)
    (call $fold
      (i64.trunc_f32_u
        (f32.mul (f32.convert_i32_u (local.get 0)) (f32.const 1024)))))

  (func (export "i64_trunc_f64_s") (param i32 i32) (result i32)
    (call $fold
      (i64.trunc_f64_s
        (f64.mul (f64.convert_i32_s (local.get 0)) (f64.const 1000)))))

  (func (export "i64_trunc_f64_u") (param i32 i32) (result i32)
    (call $fold
      (i64.trunc_f64_u
        (f64.mul (f64.convert_i32_u (local.get 0)) (f64.const 1000))))))
