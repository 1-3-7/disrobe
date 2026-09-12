(module
  (type (;0;) (func (param i32) (result i32)))
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2)
  (global (;0;) (mut i32) i32.const 66560)
  (export "memory" (memory 0))
  (export "classify" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
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
