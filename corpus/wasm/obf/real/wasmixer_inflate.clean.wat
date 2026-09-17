(module
  (type $bin (func (param i32 i32) (result i32)))
  (func $run (export "run") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
    local.get 1
    i32.mul
    local.get 0
    i32.sub))
