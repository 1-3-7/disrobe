(component
  (import "host" (instance $host
    (export "log" (func (param "msg" string)))
  ))

  (core module $core
    (import "host" "log" (func $log (param i32 i32)))
    (memory (export "memory") 1)
    (func (export "say_hi")
      i32.const 0
      i32.const 5
      call $log
    )
    (data (i32.const 0) "hello")
  )

  (core func $log_lowered (canon lower (func $host "log") (memory $i "memory")))

  (core instance $i (instantiate $core
    (with "host" (instance
      (export "log" (func $log_lowered))
    ))
  ))

  (func $say (export "say") (canon lift (core func $i "say_hi")))
)
