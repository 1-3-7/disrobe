(module
  (func $max (export "max") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.gt_s
    if (result i32)
      local.get $a
    else
      local.get $b
    end)
  (func $sign (export "sign") (param $x i32) (result i32)
    local.get $x
    i32.const 0
    i32.gt_s
    if (result i32)
      i32.const 1
    else
      local.get $x
      i32.const 0
      i32.lt_s
      if (result i32)
        i32.const -1
      else
        i32.const 0
      end
    end)
  (func $clamp (export "clamp") (param $x i32) (param $lo i32) (param $hi i32) (result i32)
    (local $r i32)
    local.get $x
    local.set $r
    local.get $r
    local.get $lo
    i32.lt_s
    if
      local.get $lo
      local.set $r
    end
    local.get $r
    local.get $hi
    i32.gt_s
    if
      local.get $hi
      local.set $r
    end
    local.get $r)
  (func $bit_merge (export "bit_merge") (param $a i32) (param $b i32) (result i32)
    (local $t i32)
    local.get $a
    local.get $b
    i32.and
    local.set $t
    local.get $t
    i32.const 7
    i32.gt_u
    if (result i32)
      local.get $t
      i32.const 1
      i32.shl
    else
      local.get $t
    end)
  (func $accum_block (export "accum_block") (param $x i32) (result i64)
    (local $w i64)
    local.get $x
    i64.extend_i32_s
    local.set $w
    local.get $w
    i64.const 10
    i64.mul
    local.set $w
    local.get $w
    local.get $w
    i64.const 1
    i64.add
    i64.mul)
  (func $fmaxsel (export "fmaxsel") (param $a f64) (param $b f64) (result f64)
    local.get $a
    local.get $b
    f64.gt
    if (result f64)
      local.get $a
    else
      local.get $b
    end))
