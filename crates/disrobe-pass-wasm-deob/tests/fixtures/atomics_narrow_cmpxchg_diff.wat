(module
  (memory 1 1 shared)

  (func (export "i32_cmpxchg8") (param $delta i32) (result i32)
    (local $old i32)
    (i32.atomic.store8 (i32.const 0) (i32.const 128))
    (local.set $old
      (i32.atomic.rmw8.cmpxchg_u
        (i32.const 0)
        (i32.xor (i32.const 384) (local.get $delta))
        (i32.const 261)))
    (i32.or
      (i32.eq (local.get $old) (i32.const 128))
      (i32.shl
        (i32.eq
          (i32.atomic.load8_u (i32.const 0))
          (select
            (i32.const 5)
            (i32.const 128)
            (i32.eqz (i32.and (local.get $delta) (i32.const 255)))))
        (i32.const 1))))

  (func (export "i32_cmpxchg16") (param $delta i32) (result i32)
    (local $old i32)
    (i32.atomic.store16 (i32.const 4) (i32.const 32768))
    (local.set $old
      (i32.atomic.rmw16.cmpxchg_u
        (i32.const 4)
        (i32.xor (i32.const 98304) (local.get $delta))
        (i32.const 65541)))
    (i32.or
      (i32.eq (local.get $old) (i32.const 32768))
      (i32.shl
        (i32.eq
          (i32.atomic.load16_u (i32.const 4))
          (select
            (i32.const 5)
            (i32.const 32768)
            (i32.eqz (i32.and (local.get $delta) (i32.const 65535)))))
        (i32.const 1))))

  (func (export "i64_cmpxchg8") (param $delta i32) (result i32)
    (local $old i64)
    (i64.atomic.store8 (i32.const 8) (i64.const 128))
    (local.set $old
      (i64.atomic.rmw8.cmpxchg_u
        (i32.const 8)
        (i64.xor (i64.const 384) (i64.extend_i32_u (local.get $delta)))
        (i64.const 261)))
    (i32.or
      (i64.eq (local.get $old) (i64.const 128))
      (i32.shl
        (i64.eq
          (i64.atomic.load8_u (i32.const 8))
          (select
            (i64.const 5)
            (i64.const 128)
            (i32.eqz (i32.and (local.get $delta) (i32.const 255)))))
        (i32.const 1))))

  (func (export "i64_cmpxchg16") (param $delta i32) (result i32)
    (local $old i64)
    (i64.atomic.store16 (i32.const 12) (i64.const 32768))
    (local.set $old
      (i64.atomic.rmw16.cmpxchg_u
        (i32.const 12)
        (i64.xor (i64.const 98304) (i64.extend_i32_u (local.get $delta)))
        (i64.const 65541)))
    (i32.or
      (i64.eq (local.get $old) (i64.const 32768))
      (i32.shl
        (i64.eq
          (i64.atomic.load16_u (i32.const 12))
          (select
            (i64.const 5)
            (i64.const 32768)
            (i32.eqz (i32.and (local.get $delta) (i32.const 65535)))))
        (i32.const 1))))

  (func (export "i64_cmpxchg32") (param $delta i32) (result i32)
    (local $old i64)
    (i64.atomic.store32 (i32.const 16) (i64.const 2147483648))
    (local.set $old
      (i64.atomic.rmw32.cmpxchg_u
        (i32.const 16)
        (i64.xor (i64.const 6442450944) (i64.extend_i32_u (local.get $delta)))
        (i64.const 4294967301)))
    (i32.or
      (i64.eq (local.get $old) (i64.const 2147483648))
      (i32.shl
        (i64.eq
          (i64.atomic.load32_u (i32.const 16))
          (select
            (i64.const 5)
            (i64.const 2147483648)
            (i32.eqz (local.get $delta))))
        (i32.const 1)))))
