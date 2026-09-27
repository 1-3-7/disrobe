(module
  (table 1 1 funcref)
  (memory 2)
  (global (mut i32) (i32.const 66560))
  (export "memory" (memory 0))
  (func $classify (export "classify") (param i32) (result i32)
    local.get 0
    i32.const 2
    i32.add
    i32.const 5
    i32.mul
    local.get 0
    i32.const -1
    i32.add
    local.get 0
    i32.const 4
    i32.gt_s
    select
  )
)
