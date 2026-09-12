(module
  (memory 1 1 shared)

  (func (export "wn_wait32_not_equal") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (memory.atomic.wait32
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i32.xor (local.get 1) (i32.const 1))
      (i64.const 2000000000)))

  (func (export "wn_wait32_timeout_zero") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (memory.atomic.wait32
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)
      (i64.const 0)))

  (func (export "wn_wait32_timeout_short") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (memory.atomic.wait32
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)
      (i64.const 1000000)))

  (func (export "wn_wait32_offset_not_equal") (param i32 i32) (result i32)
    (i32.atomic.store offset=8
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (memory.atomic.wait32 offset=8
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i32.xor (local.get 1) (i32.const 1))
      (i64.const 2000000000)))

  (func (export "wn_wait64_not_equal") (param i32 i32) (result i32)
    (i64.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i64.extend_i32_s (local.get 1)))
    (memory.atomic.wait64
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i64.xor (i64.extend_i32_s (local.get 1)) (i64.const 1))
      (i64.const 2000000000)))

  (func (export "wn_wait64_timeout_zero") (param i32 i32) (result i32)
    (i64.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i64.extend_i32_s (local.get 1)))
    (memory.atomic.wait64
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i64.extend_i32_s (local.get 1))
      (i64.const 0)))

  (func (export "wn_wait64_timeout_short") (param i32 i32) (result i32)
    (i64.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i64.extend_i32_s (local.get 1)))
    (memory.atomic.wait64
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i64.extend_i32_s (local.get 1))
      (i64.const 1000000)))

  (func (export "wn_notify_argument_count") (param i32 i32) (result i32)
    (memory.atomic.notify
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "wn_notify_zero_count") (param i32 i32) (result i32)
    (memory.atomic.notify
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i32.const 0)))

  (func (export "wn_notify_max_count") (param i32 i32) (result i32)
    (memory.atomic.notify
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i32.const -1)))

  (func (export "wn_notify_offset") (param i32 i32) (result i32)
    (memory.atomic.notify offset=8
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "wn_fence_then_wait") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (atomic.fence)
    (memory.atomic.wait32
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (i32.xor (local.get 1) (i32.const 1))
      (i64.const 2000000000)))

  (func (export "wn_wait_then_notify_then_load") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (drop
      (memory.atomic.wait32
        (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
        (local.get 1)
        (i64.const 0)))
    (drop
      (memory.atomic.notify
        (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
        (i32.const 1)))
    (i32.atomic.load
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)))))
