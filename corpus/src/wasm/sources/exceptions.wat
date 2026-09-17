(module
  (tag $oops (param i32))
  (func $may_throw (export "may_throw") (param $x i32) (result i32)
    local.get $x
    i32.const 0
    i32.lt_s
    if
      local.get $x
      throw $oops
    end
    local.get $x
    i32.const 2
    i32.mul)
  (func $guarded (export "guarded") (param $x i32) (result i32)
    block $caught (result i32)
      try_table (catch $oops $caught)
        local.get $x
        call $may_throw
        return
      end
      unreachable
    end))
