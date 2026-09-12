(module
  (type $ft (func (param i32) (result i32)))
  (type $point (struct (field (mut i32)) (field (mut i32))))
  (type $arr (array (mut i32)))
  (table $t 4 funcref)
  (table $te 2 externref)
  (memory 1)
  (data $d "abcdef")
  (elem $e func $cb)
  (tag $oops (param i32))
  (func $cb (param i32) (result i32) local.get 0)

  (func (export "tbl") (param i32) (result i32)
    local.get 0
    table.get $t
    drop
    local.get 0
    ref.func $cb
    table.set $t
    table.size $t
    drop
    local.get 0
    ref.func $cb
    local.get 0
    table.grow $t
    drop
    local.get 0
    ref.func $cb
    local.get 0
    table.fill $t
    local.get 0
    local.get 0
    local.get 0
    table.copy $t $t
    local.get 0
    local.get 0
    local.get 0
    table.init $t $e
    elem.drop $e
    i32.const 0)

  (func (export "refeq") (param i32) (result i32)
    ref.null any
    ref.null any
    ref.eq)

  (func (export "arrops") (param i32) (result i32)
    local.get 0
    array.new_default $arr
    drop
    i32.const 0
    i32.const 0
    i32.const 4
    array.new_data $arr $d
    drop
    i32.const 0
    i32.const 0
    i32.const 1
    array.new_elem $arr $e
    drop
    i32.const 0)

  (func (export "arrbulk") (param (ref $arr)) (param (ref $arr))
    local.get 0
    i32.const 0
    i32.const 7
    i32.const 2
    array.fill $arr
    local.get 0
    i32.const 0
    local.get 1
    i32.const 0
    i32.const 2
    array.copy $arr $arr
    local.get 0
    i32.const 0
    i32.const 0
    i32.const 2
    array.init_data $arr $d
    local.get 0
    i32.const 0
    i32.const 0
    i32.const 1
    array.init_elem $arr $e)

  (func (export "casts") (param anyref) (result i32)
    local.get 0
    ref.test (ref $point)
    drop
    local.get 0
    ref.test (ref null $point)
    drop
    local.get 0
    ref.cast (ref null $point)
    drop
    local.get 0
    ref.cast (ref $point)
    ref.is_null)

  (func (export "extconv") (param anyref) (result i32)
    local.get 0
    extern.convert_any
    any.convert_extern
    ref.is_null)

  (func (export "bron") (param (ref null $ft)) (result i32)
    block $b (result (ref $ft))
      local.get 0
      br_on_non_null $b
      i32.const 0
      return
    end
    i32.const 1
    call_ref $ft
    drop
    i32.const 7)

  (func (export "bronnull") (param (ref null $ft)) (result i32)
    block $b
      local.get 0
      br_on_null $b
      drop
      i32.const 1
      return
    end
    i32.const 0))
