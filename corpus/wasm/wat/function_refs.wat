(module
  (type $ft (func (param i32) (result i32)))
  (func $square (param i32) (result i32)
    local.get 0
    local.get 0
    i32.mul)
  (func (export "go") (param i32) (result i32)
    local.get 0
    ref.func $square
    call_ref $ft))
