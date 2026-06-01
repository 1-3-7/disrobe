(module
  (memory 1)
  (table $t 4 funcref)

  (func $a (result i32) i32.const 1)
  (func $b (result i32) i32.const 2)
  (func $c (result i32) i32.const 3)

  (data $active_data (i32.const 0) "active-data")
  (data $passive_data "passive-data")

  (elem $active_elem (table $t) (i32.const 0) func $a $b)
  (elem $passive_elem funcref (ref.func $c))
  (elem $declared_elem declare func $a $b $c)

  (func $boot_elem (export "boot_elem") (param $offset i32) (param $src i32) (param $len i32)
    local.get $offset
    local.get $src
    local.get $len
    table.init $t $passive_elem
  )
  (func $drop_data (export "drop_data")
    data.drop $passive_data
  )
  (func $drop_elem (export "drop_elem")
    elem.drop $passive_elem
  )
)
