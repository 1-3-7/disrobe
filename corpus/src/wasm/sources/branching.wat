(module
  (func $classify (export "classify") (param $x i32) (result i32)
    block $default
      block $three
        block $two
          block $one
            block $zero
              local.get $x
              br_table $zero $one $two $three $default
            end
            i32.const 100
            return
          end
          i32.const 101
          return
        end
        i32.const 102
        return
      end
      i32.const 103
      return
    end
    i32.const 999)
  (func $sum_to (export "sum_to") (param $n i32) (result i32)
    (local $i i32) (local $acc i32)
    i32.const 0
    local.set $i
    i32.const 0
    local.set $acc
    block $exit
      loop $loop
        local.get $i
        local.get $n
        i32.ge_s
        br_if $exit
        local.get $acc
        local.get $i
        i32.add
        local.set $acc
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $loop
      end
    end
    local.get $acc))
