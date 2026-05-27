(module
  (type $ft0 (func (param i32) (result (ref extern))))
  (type $ft1 (func (param (ref extern) (ref extern)) (result (ref extern))))
  (import "wasm:js-string" "fromCharCode" (func (type $ft0)))
  (import "wasm:js-string" "concat" (func (type $ft1))))
