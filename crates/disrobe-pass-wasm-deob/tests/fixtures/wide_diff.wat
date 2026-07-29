(module
  (func (export "mul_wide_s_lo") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 1
    i64.extend_i32_u
    i64.or
    local.get 1
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 0
    i64.extend_i32_u
    i64.or
    i64.mul_wide_s
    local.set $hi
    local.set $lo
    local.get $lo
    i32.wrap_i64
    local.get $lo
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "mul_wide_s_hi") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 1
    i64.extend_i32_u
    i64.or
    local.get 1
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 0
    i64.extend_i32_u
    i64.or
    i64.mul_wide_s
    local.set $hi
    local.set $lo
    local.get $hi
    i32.wrap_i64
    local.get $hi
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "mul_wide_u_lo") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 1
    i64.extend_i32_u
    i64.or
    local.get 1
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 0
    i64.extend_i32_u
    i64.or
    i64.mul_wide_u
    local.set $hi
    local.set $lo
    local.get $lo
    i32.wrap_i64
    local.get $lo
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "mul_wide_u_hi") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 1
    i64.extend_i32_u
    i64.or
    local.get 1
    i64.extend_i32_s
    i64.const 32
    i64.shl
    local.get 0
    i64.extend_i32_u
    i64.or
    i64.mul_wide_u
    local.set $hi
    local.set $lo
    local.get $hi
    i32.wrap_i64
    local.get $hi
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "add128_lo") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_u
    local.get 1
    i64.extend_i32_s
    local.get 1
    i64.extend_i32_u
    local.get 0
    i64.extend_i32_s
    i64.add128
    local.set $hi
    local.set $lo
    local.get $lo
    i32.wrap_i64
    local.get $lo
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "add128_hi") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_u
    local.get 1
    i64.extend_i32_s
    local.get 1
    i64.extend_i32_u
    local.get 0
    i64.extend_i32_s
    i64.add128
    local.set $hi
    local.set $lo
    local.get $hi
    i32.wrap_i64
    local.get $hi
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "add128_carry") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    i64.const -1
    i64.const 0
    local.get 0
    i64.extend_i32_u
    local.get 1
    i64.extend_i32_s
    i64.add128
    local.set $hi
    local.set $lo
    local.get $hi
    i32.wrap_i64
    local.get $lo
    i32.wrap_i64
    i32.xor)

  (func (export "sub128_lo") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_u
    local.get 1
    i64.extend_i32_s
    local.get 1
    i64.extend_i32_u
    local.get 0
    i64.extend_i32_s
    i64.sub128
    local.set $hi
    local.set $lo
    local.get $lo
    i32.wrap_i64
    local.get $lo
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "sub128_hi") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    local.get 0
    i64.extend_i32_u
    local.get 1
    i64.extend_i32_s
    local.get 1
    i64.extend_i32_u
    local.get 0
    i64.extend_i32_s
    i64.sub128
    local.set $hi
    local.set $lo
    local.get $hi
    i32.wrap_i64
    local.get $hi
    i64.const 32
    i64.shr_s
    i32.wrap_i64
    i32.xor)

  (func (export "sub128_borrow") (param i32 i32) (result i32)
    (local $lo i64) (local $hi i64)
    i64.const 0
    i64.const 0
    local.get 0
    i64.extend_i32_u
    local.get 1
    i64.extend_i32_s
    i64.sub128
    local.set $hi
    local.set $lo
    local.get $hi
    i32.wrap_i64
    local.get $lo
    i32.wrap_i64
    i32.xor))
