(component
  (core module $inner
    (func $add (export "add") (param i32 i32) (result i32)
      local.get 0
      local.get 1
      i32.add
    )
  )

  (core instance $i (instantiate $inner))

  (func $add_lifted (export "add") (param "a" s32) (param "b" s32) (result s32)
    (canon lift (core func $i "add"))
  )
)
