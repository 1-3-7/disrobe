(module
  (type $ft (func))
  (type $ct (cont $ft))
  (tag $t)
  (func $worker
    (suspend $t)
    (return))
  (func (export "main")
    (cont.new $ct (ref.func $worker))
    (resume $ct (on $t 0))
    (return)))
