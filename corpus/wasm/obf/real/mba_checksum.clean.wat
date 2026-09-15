(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func (param i32 i32 i32) (result i32)))
  (memory (;0;) 1)
  (global (;0;) (mut i32) i32.const 65536)
  (export "memory" (memory 0))
  (export "mix" (func 0))
  (export "blend" (func 1))
  (export "checksum" (func 2))
  (func (;0;) (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.add
    i32.const 5
    i32.mul
    local.get 0
    i32.xor
    i32.const 1103515245
    i32.mul
    i32.const 12345
    i32.add
  )
  (func (;1;) (type 1) (param i32 i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.add
    local.get 2
    i32.add
    i32.const -1640531535
    i32.mul
  )
  (func (;2;) (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32)
    block ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i32.const 3
      i32.and
      local.set 2
      i32.const 0
      local.set 3
      block ;; label = @2
        local.get 1
        i32.const 4
        i32.lt_u
        br_if 0 (;@2;)
        i32.const 0
        local.set 4
        i32.const 0
        local.get 1
        i32.const -4
        i32.and
        i32.sub
        local.set 5
        i32.const 2
        local.set 1
        i32.const 5
        local.set 6
        i32.const 1
        local.set 7
        i32.const 4
        local.set 8
        i32.const 6
        local.set 3
        loop ;; label = @3
          local.get 3
          local.get 1
          local.get 6
          local.get 7
          local.get 4
          local.get 0
          local.get 8
          i32.add
          i32.mul
          i32.const 4
          i32.add
          i32.mul
          i32.add
          i32.mul
          i32.add
          local.get 3
          i32.const -3
          i32.add
          i32.mul
          local.set 0
          local.get 8
          i32.const 4
          i32.add
          local.set 8
          local.get 7
          i32.const 4
          i32.add
          local.set 7
          local.get 6
          i32.const 4
          i32.add
          local.set 6
          local.get 1
          i32.const 4
          i32.add
          local.set 1
          local.get 4
          i32.const 4
          i32.add
          local.set 4
          local.get 5
          local.get 3
          i32.const 4
          i32.add
          local.tee 3
          i32.add
          i32.const 6
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        i32.const -6
        i32.add
        local.set 3
      end
      loop ;; label = @2
        local.get 0
        local.get 3
        i32.add
        i32.const 3
        i32.add
        local.get 3
        i32.mul
        local.set 0
        local.get 3
        i32.const 1
        i32.add
        local.set 3
        local.get 2
        i32.const -1
        i32.add
        local.tee 2
        br_if 0 (;@2;)
      end
    end
    local.get 0
  )
)
