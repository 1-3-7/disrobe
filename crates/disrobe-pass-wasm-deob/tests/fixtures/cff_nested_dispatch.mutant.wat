(module
  (func $nested_dispatch (export "nested_dispatch") (param i32) (result i32)
    (local i32)
    local.get 0
    i32.const 1
    i32.add
    i32.const 6
    i32.mul
    i32.const 4
    i32.sub
    local.set 1
    local.get 0
    i32.const 7
    i32.gt_s
    if (result i32)
      local.get 1
      i32.const 100
      i32.add
    else
      local.get 1
      i32.const 2
      i32.mul
    end
  )
)
