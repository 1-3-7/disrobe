(module
  (func (export "nested_dispatch") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.add
    i32.const 2
    i32.mul
    i32.const 3
    i32.add
    i32.const 3
    i32.mul
    local.get 0
    i32.const 1
    i32.add
    i32.const 2
    i32.mul
    i32.const 3
    i32.add
    i32.const 7
    i32.sub
    local.get 0
    i32.const 10
    i32.gt_s
    select
  )
)
