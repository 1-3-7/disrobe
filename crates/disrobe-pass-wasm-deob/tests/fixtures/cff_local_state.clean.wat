(module
  (type (;0;) (func (param i32) (result i32)))
  (export "classify_local" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add
    i32.const 3
    i32.mul
    local.get 0
    i32.const 1
    i32.add
    i32.const 7
    i32.sub
    local.get 0
    i32.const 10
    i32.gt_s
    select
  )
)
