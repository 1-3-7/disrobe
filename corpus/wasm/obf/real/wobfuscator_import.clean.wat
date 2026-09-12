(module
  (func $mix (export "mix") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.xor
    local.get 0
    local.get 1
    i32.and
    i32.add))
