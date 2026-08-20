(module
  (type (;0;) (func (param i32) (result i32)))
  (export "scale_then_leave" (func 0))
  (func (;0;) (type 0) (param i32) (result i32)
    local.get 0
    i32.const 2
    i32.mul
    i32.const 1
    i32.add
  )
)
