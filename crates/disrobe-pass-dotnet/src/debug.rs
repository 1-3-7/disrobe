disrobe_core::debug_scope!("dotnet", line, kv);

#[cfg(not(target_arch = "wasm32"))]
disrobe_core::debug_scope!(@item enabled);

#[cfg(not(target_arch = "wasm32"))]
disrobe_core::debug_scope!(@item section);

#[cfg(not(target_arch = "wasm32"))]
disrobe_core::debug_scope!(@item kv_guarded);

#[cfg(not(target_arch = "wasm32"))]
disrobe_core::debug_scope!(@item hex);
