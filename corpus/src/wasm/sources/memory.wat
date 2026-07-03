(module
  (memory (export "mem") 1)
  (data (i32.const 0) "\de\ad\be\ef\ca\fe\ba\be")
  (func $load_u32 (export "load_u32") (param $offset i32) (result i32)
    local.get $offset
    i32.load)
  (func $store_u32 (export "store_u32") (param $offset i32) (param $value i32)
    local.get $offset
    local.get $value
    i32.store)
  (func $checksum (export "checksum") (param $start i32) (param $count i32) (result i32)
    (local $i i32) (local $sum i32) (local $addr i32)
    i32.const 0
    local.set $i
    i32.const 0
    local.set $sum
    block $exit
      loop $loop
        local.get $i
        local.get $count
        i32.ge_s
        br_if $exit
        local.get $start
        local.get $i
        i32.const 4
        i32.mul
        i32.add
        local.tee $addr
        i32.load
        local.get $sum
        i32.xor
        local.set $sum
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $loop
      end
    end
    local.get $sum))
