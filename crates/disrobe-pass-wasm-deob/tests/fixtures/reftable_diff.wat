(module
  (type $ft (func (param i32) (result i32)))
  (table $t 0 4096 funcref)
  (table $t2 0 4096 funcref)
  (elem $e funcref (ref.null func) (ref.null func) (ref.null func) (ref.null func))
  (elem declare func $triple)

  (func $triple (param i32) (result i32)
    (i32.mul (local.get 0) (i32.const 3)))

  (func (export "tbl_grow") (param i32 i32) (result i32)
    (table.grow $t (ref.null func) (i32.and (local.get 0) (i32.const 3))))

  (func (export "tbl_grow2") (param i32 i32) (result i32)
    (table.grow $t2 (ref.null func) (i32.and (local.get 1) (i32.const 3))))

  (func (export "tbl_size") (param i32 i32) (result i32)
    (i32.add (table.size $t) (table.size $t2)))

  (func (export "tbl_set_get") (param i32 i32) (result i32)
    (table.set $t (i32.and (local.get 0) (i32.const 15)) (ref.null func))
    (i32.add
      (ref.is_null (table.get $t (i32.and (local.get 0) (i32.const 15))))
      (table.size $t)))

  (func (export "tbl_fill") (param i32 i32) (result i32)
    (table.fill $t
      (i32.and (local.get 0) (i32.const 15))
      (ref.null func)
      (i32.and (local.get 1) (i32.const 3)))
    (ref.is_null (table.get $t (i32.and (local.get 0) (i32.const 15)))))

  (func (export "tbl_copy") (param i32 i32) (result i32)
    (table.copy $t $t2
      (i32.and (local.get 0) (i32.const 15))
      (i32.and (local.get 1) (i32.const 15))
      (i32.const 2))
    (ref.is_null (table.get $t (i32.and (local.get 0) (i32.const 15)))))

  (func (export "tbl_init") (param i32 i32) (result i32)
    (table.init $t $e
      (i32.and (local.get 0) (i32.const 15))
      (i32.const 0)
      (i32.and (local.get 1) (i32.const 3)))
    (ref.is_null (table.get $t (i32.and (local.get 0) (i32.const 15)))))

  (func (export "ref_null_is_null") (param i32 i32) (result i32)
    (i32.add
      (ref.is_null (ref.null func))
      (ref.is_null (ref.null extern))))

  (func (export "ref_func_call_ref") (param i32 i32) (result i32)
    (call_ref $ft (local.get 0) (ref.func $triple)))

  (func (export "i31_get_s") (param i32 i32) (result i32)
    (i31.get_s (ref.i31 (local.get 0))))

  (func (export "i31_get_u") (param i32 i32) (result i32)
    (i31.get_u (ref.i31 (local.get 0))))

  (func (export "tbl_elem_drop") (param i32 i32) (result i32)
    (elem.drop $e)
    (table.size $t)))
