(module $wasmixer_ondemand.wasm
  (type (;0;) (func (param i32 i32) (result i32)))
  (memory (;0;) 17)
  (global $__stack_pointer (;0;) (mut i32) i32.const 1048576)
  (global (;1;) i32 i32.const 1048576)
  (global (;2;) i32 i32.const 1048606)
  (global (;3;) i32 i32.const 1048608)
  (export "memory" (memory 0))
  (export "dec_load" (func $dec_load))
  (export "ENC" (global 1))
  (export "__data_end" (global 2))
  (export "__heap_base" (global 3))
  (func $dec_load (;0;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32)
    local.get 0
    i32.const 1048576
    i32.add
    local.set 2
    block ;; label = @1
      local.get 1
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 1
      i32.const 3
      i32.and
      local.set 3
      i32.const 0
      local.set 4
      block ;; label = @2
        local.get 1
        i32.const 4
        i32.lt_u
        br_if 0 (;@2;)
        local.get 1
        i32.const 2147483644
        i32.and
        local.set 5
        i32.const 0
        local.set 4
        loop ;; label = @3
          local.get 2
          local.get 4
          i32.add
          local.tee 1
          local.get 1
          i32.load8_u
          i32.const 75
          i32.xor
          i32.store8
          local.get 1
          i32.const 1
          i32.add
          local.tee 6
          local.get 6
          i32.load8_u
          i32.const 75
          i32.xor
          i32.store8
          local.get 1
          i32.const 2
          i32.add
          local.tee 6
          local.get 6
          i32.load8_u
          i32.const 75
          i32.xor
          i32.store8
          local.get 1
          i32.const 3
          i32.add
          local.tee 1
          local.get 1
          i32.load8_u
          i32.const 75
          i32.xor
          i32.store8
          local.get 5
          local.get 4
          i32.const 4
          i32.add
          local.tee 4
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 3
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 4
      local.get 0
      i32.add
      i32.const 1048576
      i32.add
      local.set 1
      loop ;; label = @2
        local.get 1
        local.get 1
        i32.load8_u
        i32.const 75
        i32.xor
        i32.store8
        local.get 1
        i32.const 1
        i32.add
        local.set 1
        local.get 3
        i32.const -1
        i32.add
        local.tee 3
        br_if 0 (;@2;)
      end
    end
    local.get 2
  )
  (data $.data (;0;) (i32.const 1048576) "/\2289$).d<*8&d$%f/.&*%/f/.(92;?")
  (@producers
    (processed-by "rustc" "1.95.0 (59807616e 2026-04-14)")
  )
  (@custom "target_features" (after data) "\08+\0bbulk-memory+\0fbulk-memory-opt+\16call-indirect-overlong+\0amultivalue+\0fmutable-globals+\13nontrapping-fptoint+\0freference-types+\08sign-ext")
)
