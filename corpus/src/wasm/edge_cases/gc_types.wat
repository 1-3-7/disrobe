(module
  (type $point (struct (field $x i32) (field $y i32)))
  (type $points (array (mut (ref $point))))
  (type $tagged (struct (field $tag i32) (field $payload anyref)))

  (func $new_point (export "new_point") (param $x i32) (param $y i32) (result (ref $point))
    local.get $x
    local.get $y
    struct.new $point
  )

  (func $get_x (export "get_x") (param $p (ref $point)) (result i32)
    local.get $p
    struct.get $point $x
  )

  (func $make_array (export "make_array") (param $len i32) (param $p (ref $point)) (result (ref $points))
    local.get $p
    local.get $len
    array.new $points
  )

  (func $wrap_i31 (export "wrap_i31") (param $value i32) (result i31ref)
    local.get $value
    ref.i31
  )

  (func $unwrap_i31 (export "unwrap_i31") (param $r i31ref) (result i32)
    local.get $r
    i31.get_s
  )
)
