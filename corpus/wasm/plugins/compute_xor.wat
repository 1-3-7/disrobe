(module
  (memory (export "memory") 1)
  (func (export "run") (param $len i32) (result i32)
    (local $i i32)
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8
          (local.get $i)
          (i32.xor (i32.load8_u (local.get $i)) (i32.const 0xff)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (local.get $len)))
