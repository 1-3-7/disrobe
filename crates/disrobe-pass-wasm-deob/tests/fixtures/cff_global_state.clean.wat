(module
  (func $classify_global (export "classify_global") (param i32) (result i32)
    local.get 0
    i32.const 7
    i32.gt_s
    if
      local.get 0
      i32.const 5
      i32.mul
      i32.const 30
      i32.sub
      return
    end
    local.get 0
    local.get 0
    i32.add
    i32.const -11
    i32.add
  )
)
