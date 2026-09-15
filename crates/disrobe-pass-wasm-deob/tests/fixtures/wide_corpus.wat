(module
  (memory 1)
  (func $wide (param i64 i64) (result i64)
    local.get 0
    local.get 1
    i64.mul_wide_s
    drop
    local.get 0
    local.get 1
    i64.mul_wide_u
    drop
    local.get 0
    local.get 0
    local.get 1
    local.get 1
    i64.add128
    drop
    local.get 0
    local.get 0
    local.get 1
    local.get 1
    i64.sub128
    drop
    i64.const 0)
  (func $tc (param i32) (result i32)
    local.get 0
    return_call $tc)
  (func $disc (param i32 i32)
    local.get 0
    local.get 1
    memory.discard))
