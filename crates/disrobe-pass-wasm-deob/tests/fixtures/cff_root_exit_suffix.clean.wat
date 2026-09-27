(module
  (func $scale_then_leave (export "scale_then_leave") (param i32) (result i32)
    local.get 0
    i32.const 3
    i32.mul
    i32.const -5
    i32.add
  )
)
