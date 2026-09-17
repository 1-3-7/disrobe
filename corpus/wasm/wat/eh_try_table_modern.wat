(module
  (tag $e0 (param i32))
  (tag $e1 (param i64))

  (func $catch_ref_reads_payload (export "catch_ref_reads_payload") (param $x i32) (result i32)
    block $done (result i32)
      block $handler (result i32 exnref)
        try_table (result i32) (catch_ref $e0 $handler)
          local.get $x
          i32.const 3
          i32.lt_s
          if (result i32)
            local.get $x
            throw $e0
          else
            local.get $x
            i32.const 10
            i32.mul
          end
        end
        br $done
      end
      drop
      i32.const 100
      i32.add
    end)

  (func $catch_all_ref_swallows (export "catch_all_ref_swallows") (param $x i32) (result i32)
    block $done (result i32)
      block $any (result exnref)
        try_table (result i32) (catch_all_ref $any)
          local.get $x
          i32.const 0
          i32.eq
          if (result i32)
            i32.const 5
            throw $e0
          else
            local.get $x
            i32.const 2
            i32.add
          end
        end
        br $done
      end
      drop
      i32.const -1
    end)

  (func $multi_catch (export "multi_catch") (param $x i32) (result i32)
    block $done (result i32)
      block $h1 (result i64)
        block $h0 (result i32)
          try_table (result i32) (catch $e0 $h0) (catch $e1 $h1)
            local.get $x
            i32.const 1
            i32.eq
            if (result i32)
              local.get $x
              throw $e0
            else
              local.get $x
              i32.const 2
              i32.eq
              if (result i32)
                i64.const 99
                throw $e1
              else
                local.get $x
                i32.const 7
                i32.add
              end
            end
          end
          br $done
        end
        br $done
      end
      i32.wrap_i64
    end)

  (func $rethrow_via_throw_ref (export "rethrow_via_throw_ref") (param $x i32) (result i32)
    block $done (result i32)
      block $handler (result i32 exnref)
        try_table (result i32) (catch_ref $e0 $handler)
          local.get $x
          i32.const 0
          i32.lt_s
          if (result i32)
            local.get $x
            throw $e0
          else
            local.get $x
            i32.const 1000
            i32.add
          end
        end
        br $done
      end
      throw_ref
    end))
