(module
  (type $guard (func))
  (import "jsc" "__jscrambler_integrity" (func $guard (type $guard)))
  (func $f (export "f") (param i32 i32) (result i32)
    call $guard
    block (result i32)
      local.get 0
      local.get 1
      i32.add
      i32.const 3
      i32.mul
      i32.const 0
      br_if 0
      return
    end)
  (func $compute_alt (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.sub))
