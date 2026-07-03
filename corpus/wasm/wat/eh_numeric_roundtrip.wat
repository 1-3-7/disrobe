(module
  (tag $err (param i32))
  (tag $err2 (param i64))

  (func $catch_returns_payload (export "catch_returns_payload") (param $x i32) (result i32)
    block $on_err (result i32)
      try_table (result i32) (catch $err $on_err)
        local.get $x
        i32.const 10
        i32.lt_s
        if (result i32)
          local.get $x
          throw $err
        else
          local.get $x
          i32.const 100
          i32.add
        end
      end
      return
    end)

  (func $catch_all_default (export "catch_all_default") (param $x i32) (result i32)
    block $h
      try_table (catch_all $h)
        local.get $x
        i32.const 0
        i32.eq
        if (result i32)
          i32.const 7
          throw $err
        else
          local.get $x
          i32.const 2
          i32.mul
        end
        return
      end
    end
    i32.const -1)

  (func $nested_try_table (export "nested_try_table") (param $x i32) (result i32)
    block $outer (result i32)
      try_table (result i32) (catch $err $outer)
        block $inner (result i32)
          try_table (result i32) (catch $err $inner)
            local.get $x
            i32.const 5
            i32.gt_s
            if (result i32)
              local.get $x
              throw $err
            else
              local.get $x
              i32.const 1000
              i32.add
            end
          end
          return
        end
        i32.const 1
        i32.add
        throw $err
      end
    end)

  (func $i64_payload (export "i64_payload") (param $x i64) (result i64)
    block $h (result i64)
      try_table (result i64) (catch $err2 $h)
        local.get $x
        i64.const 0
        i64.lt_s
        if (result i64)
          local.get $x
          throw $err2
        else
          local.get $x
          i64.const 1
          i64.add
        end
      end
      return
    end)

  (func $legacy_try_catch (export "legacy_try_catch") (param $x i32) (result i32)
    try (result i32)
      local.get $x
      i32.const 0
      i32.lt_s
      if (result i32)
        local.get $x
        throw $err
      else
        local.get $x
        i32.const 3
        i32.mul
      end
    catch $err
    end)

  (func $legacy_catch_all (export "legacy_catch_all") (param $x i32) (result i32)
    try (result i32)
      local.get $x
      i32.const 42
      i32.eq
      if (result i32)
        i32.const 1
        throw $err
      else
        local.get $x
        i32.const 1
        i32.sub
      end
    catch_all
      i32.const -5
    end)

  (func $legacy_rethrow_caught (export "legacy_rethrow_caught") (param $x i32) (result i32)
    try (result i32)
      try (result i32)
        local.get $x
        i32.const 0
        i32.eq
        if (result i32)
          i32.const 9
          throw $err
        else
          local.get $x
          i32.const 10
          i32.add
        end
      catch $err
        drop
        i32.const 9
        throw $err
      end
    catch $err
      drop
      i32.const 1234
    end)

  (func $no_throw_path (export "no_throw_path") (param $x i32) (param $y i32) (result i32)
    block $h (result i32)
      try_table (result i32) (catch $err $h)
        local.get $x
        local.get $y
        i32.add
      end
      return
    end
    drop
    i32.const 0)

  (func $legacy_delegate (export "legacy_delegate") (param $x i32) (result i32)
    try $t (result i32)
      try (result i32)
        local.get $x
        i32.const 0
        i32.eq
        if (result i32)
          i32.const 99
          throw $err
        else
          local.get $x
          i32.const 4
          i32.mul
        end
      delegate 0
    catch $err
      drop
      i32.const -1
    end)

  (func $legacy_rethrow_op (export "legacy_rethrow_op") (param $x i32) (result i32)
    try (result i32)
      try (result i32)
        local.get $x
        i32.const 0
        i32.eq
        if (result i32)
          i32.const 5
          throw $err
        else
          local.get $x
          i32.const 2
          i32.mul
        end
      catch $err
        drop
        rethrow 0
      end
    catch $err
      drop
      i32.const 77
    end))
