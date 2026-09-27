(module
  (func $classify_local (export "classify_local") (param i32) (result i32)
    (local i32)
    local.get 0
    i32.const 3
    i32.sub
    local.set 1
    local.get 0
    i32.const 6
    i32.gt_s
    if (result i32)
      local.get 1
      i32.const 4
      i32.mul
    else
      i32.const 5
      local.get 1
      local.get 1
      i32.add
      i32.sub
    end
  )
)
