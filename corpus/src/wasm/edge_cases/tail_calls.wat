(module
  (func $sum_acc (export "sum_acc") (param $n i32) (param $acc i32) (result i32)
    (if (i32.eqz (local.get $n))
      (then local.get $acc return)
    )
    (return_call $sum_acc
      (i32.sub (local.get $n) (i32.const 1))
      (i32.add (local.get $acc) (local.get $n))
    )
  )

  (func $sum (export "sum") (param $n i32) (result i32)
    local.get $n
    i32.const 0
    return_call $sum_acc
  )

  (type $reducer (func (param i32 i32) (result i32)))
  (table 1 funcref)
  (elem (i32.const 0) $sum_acc)

  (func $indirect_tail (export "indirect_tail") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.const 0
    return_call_indirect (type $reducer)
  )
)
