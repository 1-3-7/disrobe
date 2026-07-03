(module
  (func $hot (export "hot") (param $n i32) (result i32)
    (local $i i32)
    (local $sum i32)
    (loop $body
      local.get $i
      local.get $n
      i32.lt_s
      (@metadata.code.branch_hint "\01")
      if
        local.get $sum
        local.get $i
        i32.add
        local.set $sum
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $body
      end
    )
    local.get $sum
  )
)
