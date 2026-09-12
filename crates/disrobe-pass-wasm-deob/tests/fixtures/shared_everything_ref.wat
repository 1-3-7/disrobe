(module
  (global $g (mut i32) (i32.const 0))
  (table $t 0 4096 funcref)

  (func (export "s_tbl_grow") (param i32 i32) (result i32)
    (table.grow $t (ref.null func) (i32.and (local.get 0) (i32.const 3))))

  (func (export "s_global_set_get") (param i32 i32) (result i32)
    (global.set $g (local.get 1))
    (global.get $g))

  (func (export "s_global_rmw_add") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (global.set $g (i32.add (local.get $old) (local.get 1)))
    (local.get $old))

  (func (export "s_global_rmw_sub") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (global.set $g (i32.sub (local.get $old) (local.get 1)))
    (local.get $old))

  (func (export "s_global_rmw_and") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (global.set $g (i32.and (local.get $old) (local.get 1)))
    (local.get $old))

  (func (export "s_global_rmw_or") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (global.set $g (i32.or (local.get $old) (local.get 1)))
    (local.get $old))

  (func (export "s_global_rmw_xor") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (global.set $g (i32.xor (local.get $old) (local.get 1)))
    (local.get $old))

  (func (export "s_global_rmw_xchg") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (global.set $g (local.get 1))
    (local.get $old))

  (func (export "s_global_cmpxchg") (param i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $g))
    (if (i32.eq (local.get $old) (local.get 0))
      (then (global.set $g (local.get 1))))
    (local.get $old))

  (func (export "s_global_after_rmw") (param i32 i32) (result i32)
    (global.get $g))

  (func (export "s_tbl_atomic_set_get") (param i32 i32) (result i32)
    (table.set $t
      (i32.and (local.get 0) (i32.const 15))
      (ref.null func))
    (ref.is_null (table.get $t (i32.and (local.get 0) (i32.const 15)))))

  (func (export "s_tbl_atomic_xchg") (param i32 i32) (result i32)
    (local $old funcref)
    (local.set $old (table.get $t (i32.and (local.get 0) (i32.const 15))))
    (table.set $t (i32.and (local.get 0) (i32.const 15)) (ref.null func))
    (ref.is_null (local.get $old)))

  (func (export "s_tbl_atomic_cmpxchg") (param i32 i32) (result i32)
    (local $old funcref)
    (local.set $old (table.get $t (i32.and (local.get 0) (i32.const 15))))
    (if (ref.is_null (local.get $old))
      (then (table.set $t (i32.and (local.get 0) (i32.const 15)) (ref.null func))))
    (ref.is_null (local.get $old)))

  (func (export "s_i31_shared_s") (param i32 i32) (result i32)
    (i31.get_s (ref.i31 (local.get 0))))

  (func (export "s_i31_shared_u") (param i32 i32) (result i32)
    (i31.get_u (ref.i31 (local.get 0))))

  (func (export "s_fence") (param i32 i32) (result i32)
    (global.get $g)))
