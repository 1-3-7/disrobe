(module
  (memory $primary 1)
  (memory $secondary 1)
  (data (memory $primary) (i32.const 0) "primary")
  (data (memory $secondary) (i32.const 0) "secondary")
  (func $read_primary (export "read_primary") (param $offset i32) (result i32)
    local.get $offset
    i32.load8_u $primary
  )
  (func $read_secondary (export "read_secondary") (param $offset i32) (result i32)
    local.get $offset
    i32.load8_u $secondary
  )
  (func $copy_across (export "copy_across") (param $dst i32) (param $src i32) (param $len i32)
    local.get $dst
    local.get $src
    local.get $len
    memory.copy $primary $secondary
  )
)
