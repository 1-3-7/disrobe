(module
  (tag $err_int (param i32))
  (tag $err_pair (param i32 i64))

  (func $maybe_throw (export "maybe_throw") (param $kind i32)
    (if (i32.eq (local.get $kind) (i32.const 1))
      (then
        i32.const 42
        throw $err_int
      )
    )
    (if (i32.eq (local.get $kind) (i32.const 2))
      (then
        i32.const 99
        i64.const 12345
        throw $err_pair
      )
    )
  )

  (func $catch_via_try_table (export "catch_via_try_table") (param $kind i32) (result i32)
    (block $on_int (result i32)
      (try_table (catch $err_int $on_int)
        local.get $kind
        call $maybe_throw
      )
      i32.const 0
      return
    )
  )

  (func $rethrow_chain (export "rethrow_chain") (param $kind i32) (result i32)
    (block $caught (result i32)
      (try_table (catch_all $caught)
        local.get $kind
        call $maybe_throw
      )
      i32.const 0
      return
    )
    drop
    i32.const -1
  )
)
