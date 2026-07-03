(module
  (type (;0;) (func (param f32) (result i32)))
  (type (;1;) (func (param f64) (result i32)))
  (type (;2;) (func (param f32) (result i64)))
  (type (;3;) (func (param f64) (result i64)))
  (type (;4;) (func (param f64 f32) (result i32)))
  (memory (;0;) 1)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "i32_from_f32_s" (func 0))
  (export "i32_from_f32_u" (func 1))
  (export "i32_from_f64_s" (func 2))
  (export "i32_from_f64_u" (func 3))
  (export "i64_from_f32_s" (func 4))
  (export "i64_from_f32_u" (func 5))
  (export "i64_from_f64_s" (func 6))
  (export "i64_from_f64_u" (func 7))
  (export "mixed" (func 8))
  (func (;0;) (type 0) (param f32) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f32.store offset=12
    local.get 1
    f32.load offset=12
    i32.trunc_sat_f32_s
    return
  )
  (func (;1;) (type 0) (param f32) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f32.store offset=12
    local.get 1
    f32.load offset=12
    i32.trunc_sat_f32_u
    return
  )
  (func (;2;) (type 1) (param f64) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f64.store offset=8
    local.get 1
    f64.load offset=8
    i32.trunc_sat_f64_s
    return
  )
  (func (;3;) (type 1) (param f64) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f64.store offset=8
    local.get 1
    f64.load offset=8
    i32.trunc_sat_f64_u
    return
  )
  (func (;4;) (type 2) (param f32) (result i64)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f32.store offset=12
    local.get 1
    f32.load offset=12
    i64.trunc_sat_f32_s
    return
  )
  (func (;5;) (type 2) (param f32) (result i64)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f32.store offset=12
    local.get 1
    f32.load offset=12
    i64.trunc_sat_f32_u
    return
  )
  (func (;6;) (type 3) (param f64) (result i64)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f64.store offset=8
    local.get 1
    f64.load offset=8
    i64.trunc_sat_f64_s
    return
  )
  (func (;7;) (type 3) (param f64) (result i64)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 1
    local.get 1
    local.get 0
    f64.store offset=8
    local.get 1
    f64.load offset=8
    i64.trunc_sat_f64_u
    return
  )
  (func (;8;) (type 4) (param f64 f32) (result i32)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.set 2
    local.get 2
    local.get 0
    f64.store offset=8
    local.get 2
    local.get 1
    f32.store offset=4
    local.get 2
    f64.load offset=8
    i32.trunc_sat_f64_s
    local.get 2
    f32.load offset=4
    i32.trunc_sat_f32_u
    i32.add
    return
  )
)
