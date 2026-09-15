(module
  (memory 1 16)
  (data $seed "deadbeefcafebabe")
  (data $passive "passive-payload")

  (func $init_active (export "init_active")
    i32.const 0
    i32.const 0
    i32.const 16
    memory.init $seed
  )
  (func $init_passive (export "init_passive") (param $dst i32) (param $offset i32) (param $len i32)
    local.get $dst
    local.get $offset
    local.get $len
    memory.init $passive
  )
  (func $copy_region (export "copy_region") (param $dst i32) (param $src i32) (param $len i32)
    local.get $dst
    local.get $src
    local.get $len
    memory.copy
  )
  (func $fill_region (export "fill_region") (param $dst i32) (param $value i32) (param $len i32)
    local.get $dst
    local.get $value
    local.get $len
    memory.fill
  )
  (func $drop_passive (export "drop_passive")
    data.drop $passive
  )
)
