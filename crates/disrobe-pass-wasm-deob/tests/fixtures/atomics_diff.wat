(module
  (memory 1 1 shared)

  (func (export "at_store_load") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (i32.atomic.load
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))))

  (func (export "at_store_load_offset") (param i32 i32) (result i32)
    (i32.atomic.store offset=4
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1))
    (i32.atomic.load offset=4
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))))

  (func (export "at_rmw_add") (param i32 i32) (result i32)
    (i32.atomic.rmw.add
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "at_rmw_sub") (param i32 i32) (result i32)
    (i32.atomic.rmw.sub
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "at_rmw_and") (param i32 i32) (result i32)
    (i32.atomic.rmw.and
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "at_rmw_or") (param i32 i32) (result i32)
    (i32.atomic.rmw.or
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "at_rmw_xor") (param i32 i32) (result i32)
    (i32.atomic.rmw.xor
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "at_rmw_xchg") (param i32 i32) (result i32)
    (i32.atomic.rmw.xchg
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)))

  (func (export "at_rmw_cmpxchg") (param i32 i32) (result i32)
    (i32.atomic.rmw.cmpxchg
      (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8))
      (local.get 1)
      (i32.xor (local.get 1) (i32.const 1518500249))))

  (func (export "at_rmw8_add_u") (param i32 i32) (result i32)
    (i32.atomic.rmw8.add_u
      (i32.add (i32.and (local.get 0) (i32.const 15)) (i32.const 200))
      (local.get 1)))

  (func (export "at_rmw8_xchg_u") (param i32 i32) (result i32)
    (i32.atomic.rmw8.xchg_u
      (i32.add (i32.and (local.get 0) (i32.const 15)) (i32.const 200))
      (local.get 1)))

  (func (export "at_rmw8_cmpxchg_u") (param i32 i32) (result i32)
    (i32.atomic.rmw8.cmpxchg_u
      (i32.add (i32.and (local.get 0) (i32.const 15)) (i32.const 200))
      (local.get 1)
      (i32.xor (local.get 1) (i32.const 91))))

  (func (export "at_rmw16_or_u") (param i32 i32) (result i32)
    (i32.atomic.rmw16.or_u
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 2)) (i32.const 300))
      (local.get 1)))

  (func (export "at_rmw16_sub_u") (param i32 i32) (result i32)
    (i32.atomic.rmw16.sub_u
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 2)) (i32.const 300))
      (local.get 1)))

  (func (export "at_load8_u") (param i32 i32) (result i32)
    (i32.atomic.store8
      (i32.add (i32.and (local.get 0) (i32.const 15)) (i32.const 400))
      (local.get 1))
    (i32.atomic.load8_u
      (i32.add (i32.and (local.get 0) (i32.const 15)) (i32.const 400))))

  (func (export "at_load16_u") (param i32 i32) (result i32)
    (i32.atomic.store16
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 2)) (i32.const 500))
      (local.get 1))
    (i32.atomic.load16_u
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 2)) (i32.const 500))))

  (func (export "at_i64_store_load") (param i32 i32) (result i32)
    (i64.atomic.store
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 600))
      (i64.extend_i32_s (local.get 1)))
    (i32.wrap_i64
      (i64.atomic.load
        (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 600)))))

  (func (export "at_i64_rmw_add") (param i32 i32) (result i32)
    (i32.wrap_i64
      (i64.atomic.rmw.add
        (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 704))
        (i64.extend_i32_s (local.get 1)))))

  (func (export "at_i64_rmw_cmpxchg") (param i32 i32) (result i32)
    (i32.wrap_i64
      (i64.atomic.rmw.cmpxchg
        (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 704))
        (i64.extend_i32_s (local.get 1))
        (i64.extend_i32_u (local.get 0)))))

  (func (export "at_i64_rmw8_and_u") (param i32 i32) (result i32)
    (i32.wrap_i64
      (i64.atomic.rmw8.and_u
        (i32.add (i32.and (local.get 0) (i32.const 15)) (i32.const 800))
        (i64.extend_i32_s (local.get 1)))))

  (func (export "at_i64_rmw16_xor_u") (param i32 i32) (result i32)
    (i32.wrap_i64
      (i64.atomic.rmw16.xor_u
        (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 2)) (i32.const 900))
        (i64.extend_i32_s (local.get 1)))))

  (func (export "at_i64_rmw32_xchg_u") (param i32 i32) (result i32)
    (i32.wrap_i64
      (i64.atomic.rmw32.xchg_u
        (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1000))
        (i64.extend_i32_s (local.get 1)))))

  (func (export "at_i64_load32_u") (param i32 i32) (result i32)
    (i64.atomic.store32
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1100))
      (i64.extend_i32_s (local.get 1)))
    (i32.wrap_i64
      (i64.atomic.load32_u
        (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1100)))))

  (func (export "at_fence_then_load") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1200))
      (local.get 1))
    (atomic.fence)
    (i32.atomic.load
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1200))))

  (func (export "at_notify") (param i32 i32) (result i32)
    (memory.atomic.notify
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1300))
      (local.get 1)))

  (func (export "at_wait32_mismatch") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1400))
      (local.get 1))
    (memory.atomic.wait32
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1400))
      (i32.xor (local.get 1) (i32.const -1))
      (i64.const 0)))

  (func (export "at_wait32_match") (param i32 i32) (result i32)
    (i32.atomic.store
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1500))
      (local.get 1))
    (memory.atomic.wait32
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1500))
      (local.get 1)
      (i64.const 0)))

  (func (export "at_wait64_mismatch") (param i32 i32) (result i32)
    (i64.atomic.store
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1600))
      (i64.extend_i32_s (local.get 1)))
    (memory.atomic.wait64
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1600))
      (i64.extend_i32_s (i32.xor (local.get 1) (i32.const -1)))
      (i64.const 0)))

  (func (export "at_wait64_match") (param i32 i32) (result i32)
    (i64.atomic.store
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1704))
      (i64.extend_i32_s (local.get 1)))
    (memory.atomic.wait64
      (i32.add (i32.mul (i32.and (local.get 0) (i32.const 15)) (i32.const 8)) (i32.const 1704))
      (i64.extend_i32_s (local.get 1))
      (i64.const 0))))
