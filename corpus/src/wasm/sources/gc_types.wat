(module
  (type $point (struct (field $x (mut i32)) (field $y i32)))
  (type $row (array (mut i32)))
  (func (export "make_point") (result (ref $point))
    i32.const 1
    i32.const 2
    struct.new $point)
  (func (export "make_row") (result (ref $row))
    i32.const 7
    i32.const 3
    array.new $row)
  (func (export "make_i31") (result (ref i31))
    i32.const 42
    ref.i31)
  (func (export "read_x") (param (ref $point)) (result i32)
    local.get 0
    struct.get $point $x))
