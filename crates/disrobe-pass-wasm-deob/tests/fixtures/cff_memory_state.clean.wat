(module
  (func $classify_memory (export "classify_memory") (param i32) (result i32)
    local.get 0
    i32.const 3
    i32.mul
    i32.const 7
    i32.add
    i32.const 4
    local.get 0
    i32.sub
    local.get 0
    i32.const 8
    i32.gt_s
    select
  )
)
