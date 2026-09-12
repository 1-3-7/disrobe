(module
  (type (func (param i32) (result i32)))
  (table 1 1 funcref)
  (memory 2)
  (global (mut i32) i32.const 66560)
  (export "memory" (memory 0))
  (export "classify" (func 0))
  (func (type 0) (param i32) (result i32)
    local.get 0
    i32.const 3
    i32.mul
    i32.const 3
    i32.add
    local.get 0
    i32.const -6
    i32.add
    local.get 0
    i32.const 10
    i32.gt_s
    select
  )
)
